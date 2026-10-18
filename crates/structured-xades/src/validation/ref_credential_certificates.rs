//! Credential certificate required sets and the protected/ordinary alternatives.

use super::{ReferenceDigestError, ReferenceSearch, ref_catalogue::Memo};
use crate::{
    Xades,
    binary::{self, BinaryXml, Location},
    certificate::{Agreement, DigestProvider, FormatDigest},
    digest,
    prepare::{Preparation, Prepared},
    unsigned,
    xml::{Access, Xml},
};
use core::ops::Range;
use structured_asn1::digest::Digest;
use structured_asn1::memory::{MemoryError, OwnedMap, OwnedVec, Work};
use structured_ltv::material::PathCertificate;
use structured_ltv::pki::{Participant, ParticipantAuthority, ParticipantRequirements};
use structured_ltv::timestamp::TimestampScope;
use structured_pkix::Certificate;

/// Source of an original certificate reference; protected and ordinary copies
/// are normative alternatives, not caller-supplied presence flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialReferencePlace {
    /// Original ordinal in protected `SigningCertificateV2`.
    Protected(usize),
    /// Original property/entry ordinals in `CompleteCertificateRefsV2`.
    Ordinary {
        /// Ordinal of the original ordinary property.
        property: usize,
        /// Ordinal within that property's original list.
        entry: usize,
    },
    /// Original property/entry ordinals in `AttributeCertificateRefsV2`.
    Attribute {
        /// Ordinal of the original attribute property.
        property: usize,
        /// Ordinal within that property's original list.
        entry: usize,
    },
}

/// One certificate actually required by a credential authority path.
pub struct CredentialCertificate<'view, 'document> {
    participant: usize,
    role: PathCertificate,
    certificate: &'view Certificate<'document>,
    ordinary: bool,
    protected: bool,
    attribute: bool,
}
impl<'v, 'd> CredentialCertificate<'v, 'd> {
    /// Original credential participant/authority ordinal in the complete census.
    #[must_use]
    pub fn participant(&self) -> usize {
        self.participant
    }
    /// Existing anchor or original issuer-to-subject member ordinal.
    #[must_use]
    pub fn role(&self) -> PathCertificate {
        self.role
    }
    /// Exact original certificate; no decoding, normalization or copy repeats.
    #[must_use]
    pub fn certificate(&self) -> &'v Certificate<'d> {
        self.certificate
    }
    /// Matching original protected/ordinary/attribute reference presence.
    #[must_use]
    pub fn presence(&self) -> (bool, bool, bool) {
        (self.protected, self.ordinary, self.attribute)
    }
    /// A.1.3's SHOULD NOT duplication; this is not an unconditional rejection.
    #[must_use]
    pub fn redundant_attribute_reference(&self) -> bool {
        self.attribute && (self.ordinary || self.protected)
    }
}

/// One original reference, retaining every candidate comparison.
pub struct CredentialCertificateRow<N> {
    place: CredentialReferencePlace,
    node: N,
    search: ReferenceSearch,
    range: Range<usize>,
}
impl<N: Copy> CredentialCertificateRow<N> {
    /// Original protected/ordinary/attribute role and ordinals.
    #[must_use]
    pub fn place(&self) -> CredentialReferencePlace {
        self.place
    }
    /// Original Cert element.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Completed comparison or exact unavailable algorithm/value outcome.
    #[must_use]
    pub fn search(&self) -> ReferenceSearch {
        self.search
    }
}

/// Only A.1.3(1–2)'s required X.509 reference presence, not credential trust,
/// optional status-authority references, identifier correctness or a grade.
pub struct CredentialCertificateReferences<'p, 'v, 'd, N, D, G> {
    prepared: &'p Preparation<N, D, G>,
    candidates: OwnedVec<CredentialCertificate<'v, 'd>>,
    rows: OwnedVec<CredentialCertificateRow<N>>,
    comparisons: OwnedVec<Agreement>,
    present: bool,
    covered: bool,
}
impl<'p, 'v, 'd, N, D, G> CredentialCertificateReferences<'p, 'v, 'd, N, D, G> {
    /// Same immutable original preparation.
    #[must_use]
    pub fn prepared(&self) -> &'p Preparation<N, D, G> {
        self.prepared
    }
    /// Whether the optional original attribute-reference property was written.
    #[must_use]
    pub fn property_present(&self) -> bool {
        self.present
    }
    /// Actual credential path certificate obligations; shared paths keep each
    /// attribution while their exact bytes share hash work.
    #[must_use]
    pub fn candidates(&self) -> &[CredentialCertificate<'v, 'd>] {
        &self.candidates
    }
    /// Every considered original reference in processing order.
    #[must_use]
    pub fn rows(&self) -> &[CredentialCertificateRow<N>] {
        &self.rows
    }
    /// One agreement per candidate, in the same candidate order.
    #[must_use]
    pub fn comparisons(&self, row: usize) -> Option<&[Agreement]> {
        self.comparisons.get(self.rows.get(row)?.range.clone())
    }
    /// Necessary required-set presence only. An absent optional property does
    /// not activate its obligations. Unsupported comparisons never prove it.
    #[must_use]
    pub fn all_required_referenced(&self) -> bool {
        self.covered
    }
}

/// Original source/provider/resource failures remain terminal and located.
pub type CredentialCertificateResult<'p, 'v, 'd, X, E> = binary::BinaryResult<
    CredentialCertificateReferences<
        'p,
        'v,
        'd,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    X,
    ReferenceDigestError<E>,
>;

fn candidates<'v, 'd, N: Copy, D: Copy, G: Copy, W: Work>(
    required: &ParticipantRequirements<'v, 'd, N, D, G, Xades>,
    work: &W,
) -> Result<OwnedVec<CredentialCertificate<'v, 'd>, W>, MemoryError> {
    let mut values = work.vector();
    let mut push = |participant, role, certificate| {
        values.try_push(CredentialCertificate {
            participant,
            role,
            certificate,
            ordinary: false,
            protected: false,
            attribute: false,
        })
    };
    for (ordinal, entry) in required.entries().iter().enumerate() {
        work.charge_work(1)?;
        if !matches!(entry.participant(), Participant::Credential { .. }) {
            continue;
        }
        match entry.authority() {
            ParticipantAuthority::Path(path) => {
                if let Some(certificate) = path.anchor().certificate() {
                    push(ordinal, PathCertificate::Anchor, certificate)?;
                }
                for (member, value) in path.members().iter().enumerate() {
                    work.charge_work(1)?;
                    push(
                        ordinal,
                        PathCertificate::Member(member),
                        value.certificate(),
                    )?;
                }
            }
            ParticipantAuthority::Anchor(anchor) => {
                if let Some(certificate) = anchor.anchor().certificate() {
                    push(ordinal, PathCertificate::Anchor, certificate)?;
                }
            }
            ParticipantAuthority::CertificateFree => (),
        }
    }
    Ok(values)
}

struct CredentialScan<'provider, 'view, 'document, P: Digest<'provider>, W: Work> {
    memo: Memo<'provider, 'document, P, W>,
    candidates: Option<OwnedVec<CredentialCertificate<'view, 'document>, W>>,
    ids: OwnedVec<usize, W>,
    comparisons: OwnedVec<Agreement, W>,
}
impl<'q, 'v, 'd, P: Digest<'q>, W: Work> CredentialScan<'q, 'v, 'd, P, W> {
    fn compare<N: Copy, D: Copy, G: Copy>(
        &mut self,
        identity: FormatDigest<P::Identity>,
        expected: &[u8],
        place: CredentialReferencePlace,
        required: &ParticipantRequirements<'v, 'd, N, D, G, Xades>,
        work: &W,
    ) -> Result<(), digest::Error<structured_cms::stream::RangesError, P::Error>> {
        let method = self.memo.method(identity, work)?;
        if self.candidates.is_none() {
            let values = candidates(required, work).map_err(digest::Error::Resource)?;
            let mut index: OwnedMap<&[u8], usize, W> = work.map();
            for (ordinal, candidate) in values.iter().enumerate() {
                work.charge_work(1).map_err(digest::Error::Resource)?;
                let bytes = candidate.certificate.as_bytes();
                let id =
                    if let Some(&id) = index.get(&bytes, work).map_err(digest::Error::Resource)? {
                        id
                    } else {
                        index
                            .try_insert(bytes, ordinal)
                            .map_err(digest::Error::Resource)?;
                        ordinal
                    };
                self.ids.try_push(id).map_err(digest::Error::Resource)?;
            }
            self.candidates = Some(values);
        }
        let values = self
            .candidates
            .as_mut()
            .expect("initialized credential paths");
        for (ordinal, candidate) in values.iter_mut().enumerate() {
            work.charge_work(1).map_err(digest::Error::Resource)?;
            self.comparisons
                .try_reserve(1)
                .map_err(digest::Error::Resource)?;
            let agreement = self.memo.compare(
                self.ids[ordinal],
                candidate.certificate.as_bytes(),
                method,
                expected,
                work,
            )?;
            if agreement == Agreement::Matches {
                match place {
                    CredentialReferencePlace::Protected(_) => candidate.protected = true,
                    CredentialReferencePlace::Ordinary { .. } => candidate.ordinary = true,
                    CredentialReferencePlace::Attribute { .. } => candidate.attribute = true,
                }
            }
            self.comparisons
                .try_push(agreement)
                .map_err(digest::Error::Resource)?;
        }
        Ok(())
    }
}

/// Check the mandatory credential signer/ancestor/existing-anchor reference set
/// from actual complete participant paths, honoring the normative protected and
/// ordinary-reference alternatives. No caller-written presence flags, new path
/// validation, key selection, certificate copies or hash engine are introduced.
/// Method syntax/width gates precede lazy path catalogues. One provider-identity
/// memo pays for each exact certificate once even across shared authorities.
/// A.1.3(1–2)'s repeated-reference SHOULD NOT remains a separate advisory fact.
/// This is not complete identifier/credential/status/trust or baseline acceptance.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// # Panics
/// Only if a privately constructed immutable candidate index changes.
pub fn check_credential_certificate_references<
    'p,
    'v,
    'd,
    'q,
    X: BinaryXml,
    P: DigestProvider<'q, X>,
    W: Work,
>(
    xml: &X,
    prepared: &'p Prepared<X>,
    required: &ParticipantRequirements<'v, 'd, X::Id, X::Document, X::Generation, Xades>,
    provider: &'q P,
    work: &W,
) -> CredentialCertificateResult<'p, 'v, 'd, X, P::Error> {
    let source = prepared.bound().containers();
    let location = Location {
        snapshot: source.snapshot(),
        node: source.signature(),
    };
    let access = Access::new(xml, location.snapshot, work);
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    if required.scope().location().snapshot != location.snapshot
        || !matches!(required.scope(), TimestampScope::All(_))
        || !access
            .equal_id(required.signature(), location.node)
            .map_err(|cause| binary::Error::Callback {
                location,
                cause: ReferenceDigestError::Digest(digest::Error::Resource(cause)),
            })?
    {
        return Err(binary::Error::Callback {
            location,
            cause: ReferenceDigestError::Foreign,
        });
    }
    process(xml, prepared, required, provider, &access, location)
}

fn process<'p, 'v, 'd, 'q, X: BinaryXml, P: DigestProvider<'q, X>, W: Work>(
    xml: &X,
    prepared: &'p Prepared<X>,
    required: &ParticipantRequirements<'v, 'd, X::Id, X::Document, X::Generation, Xades>,
    provider: &'q P,
    access: &Access<'_, X, W>,
    location: Location<X::Id, X::Document, X::Generation>,
) -> CredentialCertificateResult<'p, 'v, 'd, X, P::Error> {
    let work = access.execution();
    let resource = |cause| binary::Error::Callback {
        location,
        cause: ReferenceDigestError::Digest(digest::Error::Resource(cause)),
    };
    let mut present = false;
    for property in prepared.validation_references() {
        work.charge_work(1).map_err(resource)?;
        present |= property.role() == unsigned::Role::AttributeCertificateReferences;
    }
    let mut state = CredentialScan {
        memo: Memo::new(provider, work),
        candidates: None,
        ids: work.vector(),
        comparisons: work.vector(),
    };
    let mut rows = work.vector();
    if present {
        let mut row = |place, node, method, value| {
            work.charge_work(1).map_err(resource)?;
            rows.try_reserve(1).map_err(resource)?;
            let start = state.comparisons.len();
            let search = match digest::check_with(
                xml,
                digest::Reference {
                    snapshot: location.snapshot,
                    method,
                    value,
                },
                provider,
                work,
                |identity, expected, work| state.compare(identity, expected, place, required, work),
            )
            .map_err(|cause| cause.map_callback(ReferenceDigestError::Digest))?
            {
                digest::Checked::Value(()) => ReferenceSearch::Compared,
                digest::Checked::Answer(answer) => ReferenceSearch::Unavailable(answer),
            };
            rows.try_push(CredentialCertificateRow {
                place,
                node,
                search,
                range: start..state.comparisons.len(),
            })
            .map_err(resource)
        };
        for (entry, reference) in prepared.certificates().entries().iter().enumerate() {
            row(
                CredentialReferencePlace::Protected(entry),
                reference.node(),
                reference.method(),
                reference.digest(),
            )?;
        }
        for (property, references) in prepared.validation_references().iter().enumerate() {
            work.charge_work(1).map_err(resource)?;
            for (entry, reference) in references.entries().iter().enumerate() {
                work.charge_work(1).map_err(resource)?;
                let place = match references.role() {
                    unsigned::Role::CertificateReferences => {
                        CredentialReferencePlace::Ordinary { property, entry }
                    }
                    unsigned::Role::AttributeCertificateReferences => {
                        CredentialReferencePlace::Attribute { property, entry }
                    }
                    _ => continue,
                };
                let (method, value) = reference.digest().expect("certificate digest is mandatory");
                row(place, reference.node(), method, value)?;
            }
        }
    }
    let mut covered = !present || state.candidates.is_some();
    let candidates = state.candidates.unwrap_or_else(|| work.vector());
    for candidate in &candidates {
        work.charge_work(1).map_err(resource)?;
        covered &= candidate.ordinary || candidate.protected || candidate.attribute;
    }
    access
        .query(location.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    Ok(CredentialCertificateReferences {
        prepared,
        candidates: candidates.into_owned(),
        rows: rows.into_owned(),
        comparisons: state.comparisons.into_owned(),
        present,
        covered,
    })
}
