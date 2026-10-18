//! Ordinary certificate references versus actual exclusive credential CA use.

use super::{ReferenceSearch, ref_catalogue::Memo};
use crate::{
    binary::{self, BinaryXml, Location},
    certificate::{Agreement, DigestProvider},
    digest,
    material::{
        ArtifactUses, ExclusiveFindingKind,
        exclusivity::{self, CaError, CaFact, ReferenceCa},
    },
    prepare::{Preparation, Prepared},
    timestamp::TimestampScope,
    unsigned,
    xml::{Access, Xml},
};
use core::ops::Range;
use structured_asn1::digest::Digest;
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_pkix::Certificate;

/// One original ordinary Cert reference and all exclusive-credential CA comparisons.
pub struct CertificateRoleRow<N> {
    property: usize,
    entry: usize,
    node: N,
    search: ReferenceSearch,
    range: Range<usize>,
}
impl<N: Copy> CertificateRoleRow<N> {
    /// Original property ordinal in the same preparation.
    #[must_use]
    pub fn property(&self) -> usize {
        self.property
    }
    /// Original Cert ordinal within the property.
    #[must_use]
    pub fn entry(&self) -> usize {
        self.entry
    }
    /// Original Cert node, preserving source identity.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Completed search or an explicit unavailable method/value outcome.
    #[must_use]
    pub fn search(&self) -> ReferenceSearch {
        self.search
    }
}

/// Actual exclusive credential certificate and its current reference agreement.
pub struct CertificateRoleComparison<'certificate, 'document> {
    certificate: &'certificate Certificate<'document>,
    kind: ExclusiveFindingKind,
    agreement: Agreement,
}
impl<'certificate, 'document> CertificateRoleComparison<'certificate, 'document> {
    /// Actual original certificate from the complete participant/status census.
    #[must_use]
    pub fn certificate(&self) -> &'certificate Certificate<'document> {
        self.certificate
    }
    /// Asserted forbidden CA versus insufficient old-certificate CA evidence.
    #[must_use]
    pub fn kind(&self) -> ExclusiveFindingKind {
        self.kind
    }
    /// A match with `ForbiddenCa` violates Annex A.1.1; an unstated CA match
    /// remains indeterminate. Neither unsupported nor malformed means Differs.
    #[must_use]
    pub fn agreement(&self) -> Agreement {
        self.agreement
    }
}

/// Only the exclusive credential CA prohibition of Annex A.1.1. Root coverage,
/// signer exclusion, credential reference completeness, status and incorporation
/// remain separate. TSA-only or shared credential/TSA CAs are not prohibited.
pub struct CertificateRoles<'prepared, 'certificate, 'document, N, D, G> {
    prepared: &'prepared Preparation<N, D, G>,
    rows: OwnedVec<CertificateRoleRow<N>>,
    comparisons: OwnedVec<CertificateRoleComparison<'certificate, 'document>>,
}
impl<'p, 'c, 'd, N: Copy, D, G> CertificateRoles<'p, 'c, 'd, N, D, G> {
    /// Same complete original preparation.
    #[must_use]
    pub fn prepared(&self) -> &'p Preparation<N, D, G> {
        self.prepared
    }
    /// All ordinary certificate references, without dropping unsupported entries.
    #[must_use]
    pub fn rows(&self) -> &[CertificateRoleRow<N>] {
        &self.rows
    }
    /// All exclusive actual CA candidate comparisons for this original row.
    #[must_use]
    pub fn comparisons(&self, row: usize) -> Option<&[CertificateRoleComparison<'c, 'd>]> {
        self.comparisons.get(self.rows.get(row)?.range.clone())
    }
}

/// Original source, classification and provider failures are terminal causes.
pub enum CertificateRoleError<'certificate, 'document, PE> {
    /// A subset/archive/foreign participant census cannot prove exclusivity.
    Scope,
    /// Current metadata/catalogue work or capacity refusal.
    Resource(MemoryError),
    /// Lazy CA query failed in this original certificate's binary source.
    Certificate {
        /// Actual original certificate whose CA query failed.
        certificate: &'certificate Certificate<'document>,
        /// Unchanged PKIX cause and original binary offset/field.
        cause: structured_pkix::Error,
    },
    /// Existing selected-provider digest driver refused.
    Digest(digest::Error<structured_cms::stream::RangesError, PE>),
}
impl<PE: core::fmt::Debug> core::fmt::Debug for CertificateRoleError<'_, '_, PE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Scope => f.write_str("Scope"),
            Self::Resource(cause) => f.debug_tuple("Resource").field(cause).finish(),
            Self::Certificate { cause, .. } => f.debug_tuple("Certificate").field(cause).finish(),
            Self::Digest(cause) => f.debug_tuple("Digest").field(cause).finish(),
        }
    }
}

/// Complete certificate-role comparisons or an unchanged terminal cause.
pub type CertificateRoleResult<'p, 'c, 'd, X, PE> = binary::BinaryResult<
    CertificateRoles<'p, 'c, 'd, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    X,
    CertificateRoleError<'c, 'd, PE>,
>;

fn compare_role_candidates<'c, 'd, 'q, X: Xml, P: Digest<'q>, W: Work>(
    memo: &mut Memo<'q, 'd, P, W>,
    candidates: &mut Option<OwnedVec<ReferenceCa<'c, 'd>, W>>,
    artifacts: &ArtifactUses<'_, '_, '_, 'c, 'd, X::Id, X::Document, X::Generation>,
    comparisons: &mut OwnedVec<CertificateRoleComparison<'c, 'd>, W>,
    identity: crate::certificate::FormatDigest<P::Identity>,
    expected: &[u8],
    work: &W,
) -> Result<(), digest::Error<CertificateRoleError<'c, 'd, P::Error>, P::Error>> {
    let method = memo
        .method(identity, work)
        .map_err(|cause| digest::Error::Source(CertificateRoleError::Digest(cause)))?;
    if candidates.is_none() {
        *candidates = Some(
            exclusivity::reference_certificate_candidates(artifacts, work).map_err(|cause| {
                digest::Error::Source(match cause {
                    CaError::Resource(cause) => CertificateRoleError::Resource(cause),
                    CaError::Certificate(certificate, cause) => {
                        CertificateRoleError::Certificate { certificate, cause }
                    }
                })
            })?,
        );
    }
    for (ordinal, candidate) in candidates
        .as_ref()
        .expect("initialized candidates")
        .iter()
        .enumerate()
    {
        work.charge_work(1).map_err(digest::Error::Resource)?;
        let agreement = memo
            .compare(
                ordinal,
                candidate.certificate.as_bytes(),
                method,
                expected,
                work,
            )
            .map_err(|cause| digest::Error::Source(CertificateRoleError::Digest(cause)))?;
        let kind = match candidate.fact {
            CaFact::Asserted => ExclusiveFindingKind::ForbiddenCa,
            CaFact::Unstated => ExclusiveFindingKind::UnstatedCa,
            CaFact::NotAsserted => unreachable!("non-CA is not an exclusion candidate"),
        };
        comparisons
            .try_push(CertificateRoleComparison {
                certificate: candidate.certificate,
                kind,
                agreement,
            })
            .map_err(digest::Error::Resource)?;
    }
    Ok(())
}

pub(super) fn role_error<'c, 'd, PE>(
    cause: digest::Error<CertificateRoleError<'c, 'd, PE>, PE>,
) -> CertificateRoleError<'c, 'd, PE> {
    match cause {
        digest::Error::Source(cause) => cause,
        digest::Error::Provider(cause) => {
            CertificateRoleError::Digest(digest::Error::Provider(cause))
        }
        digest::Error::Resource(cause) => CertificateRoleError::Resource(cause),
        digest::Error::Stream(cause) => CertificateRoleError::Digest(digest::Error::Stream(cause)),
        digest::Error::OutputWidth { expected, actual } => {
            CertificateRoleError::Digest(digest::Error::OutputWidth { expected, actual })
        }
    }
}

/// Compare ordinary certificate references with exclusively credential CA
/// certificates from the COMPLETE actual actor/status closure. Annex A.1.1
/// permits TSA references; this deliberately differs from the ordinary values
/// prohibition in §§5.4.2–5.4.3. One existing lazy BC kernel classifies each
/// distinct actual candidate once; one full-identity digest memo serves all refs.
/// Method/declared-value validation precedes lazy certificate scans/allocation.
/// No parse, credential/signature/path authentication or XML acquisition repeats.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// # Panics
/// Only for a violated private mandatory-reference or CA-candidate invariant.
pub fn check_certificate_reference_roles<
    'p,
    'c,
    'd,
    'q,
    X: BinaryXml,
    P: DigestProvider<'q, X>,
    W: Work,
>(
    xml: &X,
    prepared: &'p Prepared<X>,
    artifacts: &ArtifactUses<'_, '_, '_, 'c, 'd, X::Id, X::Document, X::Generation>,
    provider: &'q P,
    work: &W,
) -> CertificateRoleResult<'p, 'c, 'd, X, P::Error> {
    let source = prepared.bound().containers();
    let location = Location {
        snapshot: source.snapshot(),
        node: source.signature(),
    };
    let access = Access::new(xml, location.snapshot, work);
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    let failed = |cause| binary::Error::Callback { location, cause };
    let required = artifacts.inputs().requirements();
    if required.scope().location().snapshot != location.snapshot
        || !matches!(required.scope(), TimestampScope::All(_))
        || !access
            .equal_id(required.signature(), location.node)
            .map_err(|cause| failed(CertificateRoleError::Resource(cause)))?
    {
        return Err(failed(CertificateRoleError::Scope));
    }
    let mut candidates: Option<OwnedVec<ReferenceCa<'c, 'd>, W>> = None;
    let mut memo = Memo::<P, W>::new(provider, work);
    let mut rows = work.vector();
    let mut comparisons = work.vector();
    for (property, refs) in prepared.validation_references().iter().enumerate() {
        work.charge_work(1)
            .map_err(|cause| failed(CertificateRoleError::Resource(cause)))?;
        if refs.role() != unsigned::Role::CertificateReferences {
            continue;
        }
        for (entry, reference) in refs.entries().iter().enumerate() {
            work.charge_work(1)
                .map_err(|cause| failed(CertificateRoleError::Resource(cause)))?;
            let (method, value) = reference.digest().expect("mandatory CertDigest");
            let start = comparisons.len();
            let checked = digest::check_with(
                xml,
                digest::Reference {
                    snapshot: refs.snapshot(),
                    method,
                    value,
                },
                provider,
                work,
                |identity, expected, work| {
                    compare_role_candidates::<X, P, W>(
                        &mut memo,
                        &mut candidates,
                        artifacts,
                        &mut comparisons,
                        identity,
                        expected,
                        work,
                    )
                },
            )
            .map_err(|cause| cause.map_callback(role_error))?;
            let search = match checked {
                digest::Checked::Value(()) => ReferenceSearch::Compared,
                digest::Checked::Answer(answer) => ReferenceSearch::Unavailable(answer),
            };
            rows.try_push(CertificateRoleRow {
                property,
                entry,
                node: reference.node(),
                search,
                range: start..comparisons.len(),
            })
            .map_err(|cause| failed(CertificateRoleError::Resource(cause)))?;
        }
    }
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    Ok(CertificateRoles {
        prepared,
        rows: rows.into_owned(),
        comparisons: comparisons.into_owned(),
    })
}
