//! Ordinary revocation references versus actual exclusive credential CA targets.

use super::{
    CertificateRoleError, ReferenceKind, ReferenceSearch,
    ref_catalogue::{CandidatePools, Memo},
    ref_envelope::basic_payload,
    ref_roles::role_error,
    ref_status_required::{
        self, CredentialRequired, CredentialStatusSource, PathStatusSource, Required,
    },
};
use crate::{
    binary::{self, BinaryXml, Location},
    certificate::{Agreement, FormatDigest},
    digest::{self, StreamingDigest},
    material::{
        self, ArtifactRef, ArtifactSource, ArtifactUses, ExclusiveFindingKind,
        exclusivity::{self, CaError, CaFact, ReferenceStatus},
    },
    prepare::{Preparation, Prepared},
    timestamp::{CarriedMaterial, TimestampScope},
    unsigned,
    xml::{Access, Xml},
};
use core::ops::Range;
use structured_asn1::memory::{MemoryError, OwnedMap, OwnedVec, Work};
use structured_pkix::{Certificate, ocsp::Response};

/// Whole-envelope absence is an unproven relation, never a hash of a basic payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusRoleAgreement {
    /// Completed whole CRL/envelope comparison or explicit unavailable capability.
    Compared(Agreement),
    /// An actual basic response has no matching original whole envelope in the
    /// supplied source pools. Its exclusion cannot be established by this query.
    EnvelopeUnprovided,
}

/// Digest fact for an actual contributing required status source.
pub struct StatusSourceComparison {
    source: usize,
    agreement: StatusRoleAgreement,
}
impl StatusSourceComparison {
    /// Ordinal in the same report's original required-source catalogue.
    #[must_use]
    pub fn source(&self) -> usize {
        self.source
    }
    /// Whole-value comparison or an explicit missing-envelope obligation.
    #[must_use]
    pub fn agreement(&self) -> StatusRoleAgreement {
        self.agreement
    }
}

/// One actual exclusive credential CA status target and a reference comparison.
pub struct StatusRoleComparison<'certificate, 'document, N, D, G> {
    artifact: ArtifactRef<'certificate, 'document>,
    target: &'certificate Certificate<'document>,
    kind: ExclusiveFindingKind,
    agreement: StatusRoleAgreement,
    envelope: Option<(ArtifactSource, Location<N, D, G>)>,
}
impl<'c, 'd, N: Copy, D: Copy, G: Copy> StatusRoleComparison<'c, 'd, N, D, G> {
    /// Actual contributing complete/delta CRL or basic response, not its signer.
    #[must_use]
    pub fn artifact(&self) -> ArtifactRef<'c, 'd> {
        self.artifact
    }
    /// Actual exclusive credential target CA whose status is referenced.
    #[must_use]
    pub fn target(&self) -> &'c Certificate<'d> {
        self.target
    }
    /// Asserted forbidden CA versus indeterminate old-certificate CA evidence.
    #[must_use]
    pub fn kind(&self) -> ExclusiveFindingKind {
        self.kind
    }
    /// Digest fact or the outstanding whole-envelope obligation.
    #[must_use]
    pub fn agreement(&self) -> StatusRoleAgreement {
        self.agreement
    }
    /// First original whole envelope containing this exact known basic body.
    /// None for a CRL or missing envelope; no serialization fabricates a source.
    #[must_use]
    pub fn envelope(&self) -> Option<(ArtifactSource, Location<N, D, G>)> {
        self.envelope
    }
}

/// One original CRLRef/OCSPRef/open-format entry and its candidate comparisons.
pub struct StatusRoleRow<N> {
    property: usize,
    entry: usize,
    node: N,
    search: ReferenceSearch,
    range: Range<usize>,
    root_range: Range<usize>,
    credential_range: Range<usize>,
    role: unsigned::Role,
}
impl<N: Copy> StatusRoleRow<N> {
    /// Original property ordinal in this preparation.
    #[must_use]
    pub fn property(&self) -> usize {
        self.property
    }
    /// Original entry ordinal in that property.
    #[must_use]
    pub fn entry(&self) -> usize {
        self.entry
    }
    /// Original reference element.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Complete digest search or explicit identifier/format/method obligation.
    #[must_use]
    pub fn search(&self) -> ReferenceSearch {
        self.search
    }
    /// Original ordinary versus attribute revocation-reference property role.
    #[must_use]
    pub fn role(&self) -> unsigned::Role {
        self.role
    }
}

/// Required signer-path sources and A.1.2(5) comparisons from the complete
/// actual actor/status closure. This is not full identifier/reference validity,
/// status usability, anchor-reference exclusion or a grade.
pub struct RevocationRoles<'prepared, 'certificate, 'document, N, D, G> {
    prepared: &'prepared Preparation<N, D, G>,
    rows: OwnedVec<StatusRoleRow<N>>,
    comparisons: OwnedVec<StatusRoleComparison<'certificate, 'document, N, D, G>>,
    root_sources: OwnedVec<PathStatusSource<'certificate, 'document>>,
    root_comparisons: OwnedVec<StatusSourceComparison>,
    root_present: bool,
    credential_sources: OwnedVec<CredentialStatusSource<'certificate, 'document>>,
    credential_comparisons: OwnedVec<StatusSourceComparison>,
    credential_present: bool,
}
impl<'p, 'c, 'd, N: Copy, D, G> RevocationRoles<'p, 'c, 'd, N, D, G> {
    /// Same complete original preparation.
    #[must_use]
    pub fn prepared(&self) -> &'p Preparation<N, D, G> {
        self.prepared
    }
    /// All ordinary/attribute revocation references, retaining unsupported rows.
    #[must_use]
    pub fn rows(&self) -> &[StatusRoleRow<N>] {
        &self.rows
    }
    /// Every relevant actual target/status comparison for this original row.
    #[must_use]
    pub fn comparisons(&self, row: usize) -> Option<&[StatusRoleComparison<'c, 'd, N, D, G>]> {
        self.comparisons.get(self.rows.get(row)?.range.clone())
    }
    /// Evaluated complete/delta/OCSP contributors of the actual root path.
    /// Unavailable rows may prevent lazy collection; an empty catalogue alone
    /// does not prove that the path has no required sources.
    #[must_use]
    pub fn root_sources(&self) -> &[PathStatusSource<'c, 'd>] {
        &self.root_sources
    }
    /// Compatible root-source comparisons for the same original reference row.
    #[must_use]
    pub fn root_comparisons(&self, row: usize) -> Option<&[StatusSourceComparison]> {
        self.root_comparisons
            .get(self.rows.get(row)?.root_range.clone())
    }
    /// A.1.2(1–2)'s required-source presence for each written ordinary property.
    /// No optional property means no activated obligation. This does not prove
    /// identifier correctness, anchor-reference exclusion, status/trust or grade.
    #[must_use]
    pub fn all_root_sources_referenced(&self) -> bool {
        self.root_present
    }
    /// Evaluated credential path status contributors; anchors have no lookup.
    /// Optional absence/unavailable rows may leave lazy collection unperformed;
    /// an empty catalogue alone is not proof that no contributors are required.
    #[must_use]
    pub fn credential_sources(&self) -> &[CredentialStatusSource<'c, 'd>] {
        &self.credential_sources
    }
    /// Every compatible credential-source comparison for the original row.
    #[must_use]
    pub fn credential_comparisons(&self, row: usize) -> Option<&[StatusSourceComparison]> {
        self.credential_comparisons
            .get(self.rows.get(row)?.credential_range.clone())
    }
    /// A.1.4(1–2)'s required-source presence, including ordinary alternatives.
    /// Optional absence activates no obligation. This does not prove identifier
    /// correctness, trust-anchor exclusions, status usability or baseline grade.
    #[must_use]
    pub fn all_credential_sources_referenced(&self) -> bool {
        self.credential_present
    }
}

/// Terminal XML/provider/admission and original target CA classification causes.
pub type RevocationRoleResult<'p, 'c, 'd, X, PE> = binary::BinaryResult<
    RevocationRoles<'p, 'c, 'd, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    X,
    CertificateRoleError<'c, 'd, PE>,
>;

#[derive(Clone, Copy)]
struct Envelope<'source, N, D, G> {
    bytes: &'source [u8],
    origin: ArtifactSource,
    location: Location<N, D, G>,
}

type EnvelopeIndex<'s, N, D, G, W> = OwnedMap<&'s [u8], Envelope<'s, N, D, G>, W>;
type XmlEnvelope<'s, X> =
    Envelope<'s, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
type XmlEnvelopeIndex<'s, X, W> =
    EnvelopeIndex<'s, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, W>;
type ArtifactAnswer<'s, X> = (StatusRoleAgreement, Option<XmlEnvelope<'s, X>>);
type OriginalRow<'a, X> = (
    usize,
    &'a super::ReferenceProperty<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    usize,
);
type StatusResult<'c, 'd, T, E> = Result<T, digest::Error<CertificateRoleError<'c, 'd, E>, E>>;
type LocatedEnvelopes<'s, X, W> = OwnedMap<usize, Option<XmlEnvelope<'s, X>>, W>;
type RoleComparisons<'c, 'd, X, W> = OwnedVec<
    StatusRoleComparison<'c, 'd, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    W,
>;

fn insert_envelope<'source, N: Copy, D: Copy, G: Copy, W: Work>(
    index: &mut OwnedMap<&'source [u8], Envelope<'source, N, D, G>, W>,
    response: &structured_pkix::ocsp::ResponseBytes<'source>,
    origin: ArtifactSource,
    location: Location<N, D, G>,
    work: &W,
) -> Result<(), MemoryError> {
    let Some(payload) = basic_payload(response, work)? else {
        return Ok(());
    };
    if index.get(&payload, work)?.is_none() {
        index.try_insert(
            payload,
            Envelope {
                bytes: response.as_bytes(),
                origin,
                location,
            },
        )?;
    }
    Ok(())
}

fn envelope_index<'source, N: Copy, D: Copy, G: Copy, W: Work>(
    pools: CandidatePools<'_, 'source, N, D, G>,
    work: &W,
) -> Result<EnvelopeIndex<'source, N, D, G, W>, MemoryError> {
    let mut index = work.map();
    for (ordinal, value) in pools.xml.values().iter().enumerate() {
        work.charge_work(1)?;
        if let material::Value::Ocsp(Response::Successful(response)) = &value.value {
            insert_envelope(
                &mut index,
                response,
                ArtifactSource::Xml(ordinal),
                value.location,
                work,
            )?;
        }
    }
    if let Some(tokens) = pools.tokens {
        for response in tokens.responses() {
            work.charge_work(1)?;
            let source = &tokens.view.sources()[response.origin.token];
            insert_envelope(
                &mut index,
                &response.value,
                ArtifactSource::TokenRevocation(response.origin),
                source.location(),
                work,
            )?;
        }
    }
    Ok(index)
}

struct StatusComparisons<
    'provider,
    'source,
    'certificate,
    'document,
    X: Xml,
    P: StreamingDigest<X>,
    W: Work,
> {
    memo: Memo<'provider, 'source, X, P, W>,
    candidates: Option<OwnedVec<ReferenceStatus<'certificate, 'document>, W>>,
    envelopes: Option<XmlEnvelopeIndex<'source, X, W>>,
    located: LocatedEnvelopes<'source, X, W>,
    comparisons: RoleComparisons<'certificate, 'document, X, W>,
    required: Option<Required<'certificate, 'document, W>>,
    root_comparisons: OwnedVec<StatusSourceComparison, W>,
    credential_required: Option<CredentialRequired<'certificate, 'document, W>>,
    credential_comparisons: OwnedVec<StatusSourceComparison, W>,
    attribute_requested: bool,
    covered: OwnedVec<bool, W>,
    crl_ids: OwnedMap<&'document [u8], usize, W>,
    ocsp_ids: OwnedMap<&'document [u8], usize, W>,
    next_id: usize,
}
impl<'provider, 'source, 'c, 'd, X: Xml, P: StreamingDigest<X>, W: Work>
    StatusComparisons<'provider, 'source, 'c, 'd, X, P, W>
{
    fn new(provider: &'provider P, work: &W) -> Self {
        Self {
            memo: Memo::new(provider, work),
            candidates: None,
            envelopes: None,
            located: work.map(),
            comparisons: work.vector(),
            required: None,
            root_comparisons: work.vector(),
            credential_required: None,
            credential_comparisons: work.vector(),
            attribute_requested: false,
            covered: work.vector(),
            crl_ids: work.map(),
            ocsp_ids: work.map(),
            next_id: 0,
        }
    }
    fn envelope(
        &mut self,
        ordinal: usize,
        body: &[u8],
        pools: CandidatePools<'_, 'source, X::Id, X::Document, X::Generation>,
        work: &W,
    ) -> Result<Option<XmlEnvelope<'source, X>>, MemoryError> {
        if let Some(&found) = self.located.get(&ordinal, work)? {
            return Ok(found);
        }
        if self.envelopes.is_none() {
            self.envelopes = Some(envelope_index(pools, work)?);
        }
        let found = self
            .envelopes
            .as_ref()
            .expect("initialized envelope index")
            .get(&body, work)?
            .copied();
        self.located.try_insert(ordinal, found)?;
        Ok(found)
    }
    fn agreement(
        &mut self,
        artifact: ArtifactRef<'c, 'd>,
        method: usize,
        expected: &[u8],
        pools: CandidatePools<'_, 'source, X::Id, X::Document, X::Generation>,
        work: &W,
    ) -> StatusResult<'c, 'd, ArtifactAnswer<'source, X>, P::Error> {
        let (bytes, ids) = match artifact {
            ArtifactRef::Crl(crl) => (crl.as_bytes(), &mut self.crl_ids),
            ArtifactRef::Ocsp(basic) => (basic.as_bytes(), &mut self.ocsp_ids),
            ArtifactRef::Certificate(_) => unreachable!("private status candidate"),
        };
        let ordinal =
            if let Some(&ordinal) = ids.get(&bytes, work).map_err(digest::Error::Resource)? {
                ordinal
            } else {
                let ordinal = self.next_id;
                self.next_id = ordinal
                    .checked_add(1)
                    .ok_or(digest::Error::Resource(MemoryError::WorkExceeded))?;
                ids.try_insert(bytes, ordinal)
                    .map_err(digest::Error::Resource)?;
                ordinal
            };
        let envelope = match artifact {
            ArtifactRef::Ocsp(_) => self
                .envelope(ordinal, bytes, pools, work)
                .map_err(digest::Error::Resource)?,
            _ => None,
        };
        let bytes = match artifact {
            ArtifactRef::Crl(_) => Some(bytes),
            _ => envelope.map(|value| value.bytes),
        };
        let agreement = if let Some(bytes) = bytes {
            StatusRoleAgreement::Compared(
                self.memo
                    .compare(ordinal, bytes, method, expected, work)
                    .map_err(|cause| digest::Error::Source(CertificateRoleError::Digest(cause)))?,
            )
        } else {
            StatusRoleAgreement::EnvelopeUnprovided
        };
        Ok((agreement, envelope))
    }
    fn compare_root(
        &mut self,
        kind: ReferenceKind,
        method: usize,
        expected: &[u8],
        pools: CandidatePools<'_, 'source, X::Id, X::Document, X::Generation>,
        work: &W,
    ) -> Result<(), digest::Error<CertificateRoleError<'c, 'd, P::Error>, P::Error>> {
        let count = self
            .required
            .as_ref()
            .expect("prepared root requirements")
            .sources
            .len();
        for ordinal in 0..count {
            work.charge_work(1).map_err(digest::Error::Resource)?;
            let artifact = self.required.as_ref().expect("root sources").sources[ordinal].artifact;
            if !compatible(kind, artifact) {
                continue;
            }
            self.root_comparisons
                .try_reserve(1)
                .map_err(digest::Error::Resource)?;
            let (agreement, _) = self.agreement(artifact, method, expected, pools, work)?;
            if agreement == StatusRoleAgreement::Compared(Agreement::Matches) {
                self.covered[ordinal] = true;
            }
            self.root_comparisons
                .try_push(StatusSourceComparison {
                    source: ordinal,
                    agreement,
                })
                .map_err(digest::Error::Resource)?;
        }
        Ok(())
    }
    fn compare(
        &mut self,
        selection: (ReferenceKind, unsigned::Role),
        identity: FormatDigest<P::Identity>,
        expected: &[u8],
        artifacts: &ArtifactUses<'_, '_, '_, 'c, 'd, X::Id, X::Document, X::Generation>,
        pools: CandidatePools<'_, 'source, X::Id, X::Document, X::Generation>,
        work: &W,
    ) -> Result<(), digest::Error<CertificateRoleError<'c, 'd, P::Error>, P::Error>> {
        let (kind, role) = selection;
        let method = self
            .memo
            .method(identity, work)
            .map_err(|cause| digest::Error::Source(CertificateRoleError::Digest(cause)))?;
        self.compare_credentials((kind, role), method, expected, artifacts, pools, work)?;
        if role != unsigned::Role::RevocationReferences {
            return Ok(());
        }
        if self.required.is_none() {
            let required =
                ref_status_required::collect(artifacts, work).map_err(digest::Error::Resource)?;
            self.covered
                .try_reserve_exact(required.sources.len())
                .map_err(digest::Error::Resource)?;
            for _ in &required.sources {
                self.covered
                    .try_push(false)
                    .map_err(digest::Error::Resource)?;
            }
            self.required = Some(required);
        }
        self.compare_root(kind, method, expected, pools, work)?;
        if self.candidates.is_none() {
            self.candidates = Some(
                exclusivity::reference_status_candidates(artifacts, work).map_err(|cause| {
                    digest::Error::Source(match cause {
                        CaError::Resource(cause) => CertificateRoleError::Resource(cause),
                        CaError::Certificate(certificate, cause) => {
                            CertificateRoleError::Certificate { certificate, cause }
                        }
                    })
                })?,
            );
        }
        let count = self
            .candidates
            .as_ref()
            .expect("initialized actual status candidates")
            .len();
        for ordinal in 0..count {
            work.charge_work(1).map_err(digest::Error::Resource)?;
            let candidate = &self.candidates.as_ref().expect("initialized candidates")[ordinal];
            let artifact = candidate.artifact;
            let target = candidate.certificate;
            let ca = candidate.fact;
            if !compatible(kind, artifact) {
                continue;
            }
            self.comparisons
                .try_reserve(1)
                .map_err(digest::Error::Resource)?;
            let (agreement, envelope) = self.agreement(artifact, method, expected, pools, work)?;
            let kind = match ca {
                CaFact::Asserted => ExclusiveFindingKind::ForbiddenCa,
                CaFact::Unstated => ExclusiveFindingKind::UnstatedCa,
                CaFact::NotAsserted => unreachable!("non-CA is not an exclusion candidate"),
            };
            self.comparisons
                .try_push(StatusRoleComparison {
                    artifact,
                    target,
                    kind,
                    agreement,
                    envelope: envelope.map(|value| (value.origin, value.location)),
                })
                .map_err(digest::Error::Resource)?;
        }
        Ok(())
    }
    fn compare_credentials(
        &mut self,
        (kind, role): (ReferenceKind, unsigned::Role),
        method: usize,
        expected: &[u8],
        artifacts: &ArtifactUses<'_, '_, '_, 'c, 'd, X::Id, X::Document, X::Generation>,
        pools: CandidatePools<'_, 'source, X::Id, X::Document, X::Generation>,
        work: &W,
    ) -> StatusResult<'c, 'd, (), P::Error> {
        if !self.attribute_requested {
            return Ok(());
        }
        if self.credential_required.is_none() {
            self.credential_required = Some(
                ref_status_required::collect_credentials(artifacts, work)
                    .map_err(digest::Error::Resource)?,
            );
        }
        let count = self
            .credential_required
            .as_ref()
            .expect("collected credential statuses")
            .sources
            .len();
        for ordinal in 0..count {
            work.charge_work(1).map_err(digest::Error::Resource)?;
            let artifact = self
                .credential_required
                .as_ref()
                .expect("credential statuses")
                .sources[ordinal]
                .source
                .artifact;
            if !compatible(kind, artifact) {
                continue;
            }
            self.credential_comparisons
                .try_reserve(1)
                .map_err(digest::Error::Resource)?;
            let (agreement, _) = self.agreement(artifact, method, expected, pools, work)?;
            if agreement == StatusRoleAgreement::Compared(Agreement::Matches) {
                let source = &mut self
                    .credential_required
                    .as_mut()
                    .expect("credential statuses")
                    .sources[ordinal];
                match role {
                    unsigned::Role::RevocationReferences => source.ordinary = true,
                    unsigned::Role::AttributeRevocationReferences => source.attribute = true,
                    _ => unreachable!("private revocation property roles"),
                }
            }
            self.credential_comparisons
                .try_push(StatusSourceComparison {
                    source: ordinal,
                    agreement,
                })
                .map_err(digest::Error::Resource)?;
        }
        Ok(())
    }
    fn row(
        &mut self,
        xml: &X,
        (property, refs, entry): OriginalRow<'_, X>,
        artifacts: &ArtifactUses<'_, '_, '_, 'c, 'd, X::Id, X::Document, X::Generation>,
        pools: CandidatePools<'_, 'source, X::Id, X::Document, X::Generation>,
        provider: &P,
        work: &W,
    ) -> binary::BinaryResult<StatusRoleRow<X::Id>, X, CertificateRoleError<'c, 'd, P::Error>>
    where
        X: BinaryXml,
    {
        let reference = &refs.entries()[entry];
        let start = self.comparisons.len();
        let root_start = self.root_comparisons.len();
        let credential_start = self.credential_comparisons.len();
        let search = if reference.kind() == ReferenceKind::Other {
            ReferenceSearch::OtherFormat
        } else if let Some((method, value)) = reference.digest() {
            match digest::check_with(
                xml,
                digest::Reference {
                    snapshot: refs.snapshot(),
                    method,
                    value,
                },
                provider,
                work,
                |identity, expected, work| {
                    self.compare(
                        (reference.kind(), refs.role()),
                        identity,
                        expected,
                        artifacts,
                        pools,
                        work,
                    )
                },
            )
            .map_err(|cause| cause.map_callback(role_error))?
            {
                digest::Checked::Value(()) => ReferenceSearch::Compared,
                digest::Checked::Answer(answer) => ReferenceSearch::Unavailable(answer),
            }
        } else {
            ReferenceSearch::IdentifierOnly
        };
        Ok(StatusRoleRow {
            property,
            entry,
            node: reference.node(),
            search,
            role: refs.role(),
            range: start..self.comparisons.len(),
            root_range: root_start..self.root_comparisons.len(),
            credential_range: credential_start..self.credential_comparisons.len(),
        })
    }
}

fn compatible(kind: ReferenceKind, artifact: ArtifactRef<'_, '_>) -> bool {
    matches!(
        (kind, artifact),
        (ReferenceKind::Crl, ArtifactRef::Crl(_)) | (ReferenceKind::Ocsp, ArtifactRef::Ocsp(_))
    )
}

/// Check Annex A.1.2(5) using actual revocation TARGET CA facts and all actor
/// purposes, not the authentication signer's CA bit. External complete/delta
/// CRLs can be compared directly; OCSP must locate an original WHOLE envelope
/// containing the exact basic response in the XML/token pools. Missing envelopes
/// stay explicitly unproven, never replaced with a payload hash/re-encoding.
/// Method/width checks precede lazy classification and source indexing; one
/// memo and one body/source index serve every original reference. Neither XML,
/// ASN.1, signature, path nor status authentication repeats. A late refusal drops
/// the report. Unsupported methods and identifier-only/open references retain
/// their obligations; this report cannot assert all reference requirements.
/// Also retains every actual signer-path complete/delta/OCSP contributor and
/// checks its required presence independently for each written property under
/// A.1.2(1–2). All sources share the same exact-kind/byte identity memo, including
/// artifacts reused by different path members. Optional absent properties do
/// not allocate or activate this requirement. Hash identity alone does not
/// validate mandatory issuer/responder/time fields or trust-anchor exclusions.
/// A.1.4(1–2)'s credential sources are derived through the same path/status
/// walker when the attribute-reference property is written. Ordinary matches
/// satisfy its alternatives without erasing A.1.2(5)'s separate prohibitions;
/// repeated attribute copies expose the SHOULD NOT advisory. Complete/delta
/// and whole OCSP comparisons share the same memo across both property roles.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// # Panics
/// Only for a violated privately constructed immutable candidate/source ordinal.
pub fn check_revocation_reference_roles<
    'p,
    'c,
    'd,
    X: BinaryXml,
    P: StreamingDigest<X>,
    W: Work,
>(
    xml: &X,
    prepared: &'p Prepared<X>,
    artifacts: &ArtifactUses<'_, '_, '_, 'c, 'd, X::Id, X::Document, X::Generation>,
    view: &material::View<'_, X::Id, X::Document, X::Generation>,
    tokens: Option<&CarriedMaterial<'_, X::Id, X::Document, X::Generation>>,
    provider: &P,
    work: &W,
) -> RevocationRoleResult<'p, 'c, 'd, X, P::Error> {
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
    let resource = |cause| failed(CertificateRoleError::Resource(cause));
    let required = artifacts.inputs().requirements();
    let pools = CandidatePools { xml: view, tokens };
    if required.scope().location().snapshot != location.snapshot
        || !matches!(required.scope(), TimestampScope::All(_))
        || !access
            .equal_id(required.signature(), location.node)
            .map_err(resource)?
        || !pools.same_source(location, &access).map_err(resource)?
    {
        return Err(failed(CertificateRoleError::Scope));
    }
    let mut state = StatusComparisons::<X, P, W>::new(provider, work);
    for property in prepared.validation_references() {
        work.charge_work(1).map_err(resource)?;
        state.attribute_requested |=
            property.role() == unsigned::Role::AttributeRevocationReferences;
    }
    let mut rows = work.vector();
    let mut root_present = true;
    for (property, refs) in prepared.validation_references().iter().enumerate() {
        work.charge_work(1).map_err(resource)?;
        if !matches!(
            refs.role(),
            unsigned::Role::RevocationReferences | unsigned::Role::AttributeRevocationReferences
        ) {
            continue;
        }
        if refs.role() == unsigned::Role::RevocationReferences {
            for covered in &mut state.covered {
                work.charge_work(1).map_err(resource)?;
                *covered = false;
            }
        }
        for entry in 0..refs.entries().len() {
            work.charge_work(1).map_err(resource)?;
            let row = state.row(
                xml,
                (property, refs, entry),
                artifacts,
                pools,
                provider,
                work,
            )?;
            rows.try_push(row).map_err(resource)?;
        }
        if refs.role() == unsigned::Role::AttributeRevocationReferences {
            continue;
        }
        if let Some(required) = &state.required {
            root_present &= !required.missing_input;
            for &covered in &state.covered {
                work.charge_work(1).map_err(resource)?;
                root_present &= covered;
            }
        } else {
            root_present = false;
        }
    }
    let mut credential_present = !state.attribute_requested;
    if let Some(required) = &state.credential_required {
        credential_present = !required.missing_input;
        for source in &required.sources {
            work.charge_work(1).map_err(resource)?;
            credential_present &= source.ordinary || source.attribute;
        }
    }
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    Ok(RevocationRoles {
        prepared,
        rows: rows.into_owned(),
        comparisons: state.comparisons.into_owned(),
        root_sources: state.required.map_or_else(
            || work.vector().into_owned(),
            |required| required.sources.into_owned(),
        ),
        root_comparisons: state.root_comparisons.into_owned(),
        root_present,
        credential_sources: state.credential_required.map_or_else(
            || work.vector().into_owned(),
            |required| required.sources.into_owned(),
        ),
        credential_comparisons: state.credential_comparisons.into_owned(),
        credential_present,
    })
}
