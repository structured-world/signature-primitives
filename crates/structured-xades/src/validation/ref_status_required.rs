//! Actual path status inputs required by Annex A.1.2 and A.1.4.

use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_ltv::material::{
    ArtifactRef, ArtifactUses,
    status::{self, StatusPart},
};
use structured_ltv::pki::{Participant, ParticipantAuthority, PathStatuses};

/// One original source contributing to a non-anchor checked-path status result.
pub struct PathStatusSource<'certificate, 'document> {
    pub(super) artifact: ArtifactRef<'certificate, 'document>,
    member: usize,
    contributor: usize,
}
impl<'c, 'd> PathStatusSource<'c, 'd> {
    /// Exact complete/delta CRL or authenticated basic OCSP response.
    /// The latter still needs its original whole envelope for digest comparison.
    #[must_use]
    pub fn artifact(&self) -> ArtifactRef<'c, 'd> {
        self.artifact
    }
    /// Actual non-anchor member in issuer-to-subject order.
    #[must_use]
    pub fn member(&self) -> usize {
        self.member
    }
    /// Contributing reason-source ordinal (zero for a single OCSP response).
    #[must_use]
    pub fn contributor(&self) -> usize {
        self.contributor
    }
}

pub(super) struct Required<'c, 'd, W: Work> {
    pub(super) sources: OwnedVec<PathStatusSource<'c, 'd>, W>,
    pub(super) missing_input: bool,
}
pub(super) fn collect<'c, 'd, N: Copy, D: Copy, G: Copy, W: Work>(
    artifacts: &ArtifactUses<'_, '_, '_, 'c, 'd, N, D, G>,
    work: &W,
) -> Result<Required<'c, 'd, W>, MemoryError> {
    work.charge_work(1)?;
    let inputs = artifacts.inputs();
    let root = inputs
        .requirements()
        .entries()
        .first()
        .expect("constructed signer requirement");
    assert!(
        matches!(root.participant(), Participant::Signer(_)),
        "signer is first"
    );
    let mut sources = work.vector();
    let mut missing_input = false;
    if let ParticipantAuthority::Path(path) = root.authority() {
        let statuses = inputs
            .authorities()
            .roots()
            .first()
            .expect("signer status root");
        assert!(
            core::ptr::eq(statuses.path(), path),
            "constructed root association"
        );
        missing_input = append_path(statuses, work, |source| sources.try_push(source))?;
    }
    Ok(Required {
        sources,
        missing_input,
    })
}

// Both normative required sets enumerate exactly the same complete/delta and
// OCSP source model, retaining negative readings and the non-anchor boundary.
fn append_path<'c, 'd, W: Work>(
    statuses: &PathStatuses<'_, 'c, 'd>,
    work: &W,
    mut record: impl FnMut(PathStatusSource<'c, 'd>) -> Result<(), MemoryError>,
) -> Result<bool, MemoryError> {
    let mut missing_input = false;
    for (member, entry) in statuses.entries().iter().enumerate() {
        work.charge_work(1)?;
        let Some(source) = status::member_source(entry) else {
            // A responder exemption is not a revocation value for a signature
            // or credential obligation. Do not fabricate referenced material.
            missing_input = true;
            continue;
        };
        // EN319132-1 A.1.2(1–2) and the delta clause require every actual
        // contributing complete/delta value. The anchor is not a member.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
        status::visit_artifacts_in(source, work, |artifact, contributor, part| {
            if part != StatusPart::SigningCertificate {
                record(PathStatusSource {
                    artifact,
                    member,
                    contributor,
                })?;
            }
            Ok::<_, MemoryError>(())
        })?;
    }
    Ok(missing_input)
}

/// One actual credential participant's non-anchor status contributor.
pub struct CredentialStatusSource<'c, 'd> {
    participant: usize,
    pub(super) source: PathStatusSource<'c, 'd>,
    pub(super) ordinary: bool,
    pub(super) attribute: bool,
}
impl<'c, 'd> CredentialStatusSource<'c, 'd> {
    /// Original credential/authority ordinal in the complete participant census.
    #[must_use]
    pub fn participant(&self) -> usize {
        self.participant
    }
    /// Actual member/contributor and original binary artifact.
    #[must_use]
    pub fn source(&self) -> &PathStatusSource<'c, 'd> {
        &self.source
    }
    /// Matching ordinary and attribute reference presence, respectively.
    #[must_use]
    pub fn presence(&self) -> (bool, bool) {
        (self.ordinary, self.attribute)
    }
    /// A.1.4's SHOULD NOT duplication advisory, not an unconditional rejection.
    #[must_use]
    pub fn redundant_attribute_reference(&self) -> bool {
        self.ordinary && self.attribute
    }
}

pub(super) struct CredentialRequired<'c, 'd, W: Work> {
    pub(super) sources: OwnedVec<CredentialStatusSource<'c, 'd>, W>,
    pub(super) missing_input: bool,
}

pub(super) fn collect_credentials<'c, 'd, N: Copy, D: Copy, G: Copy, W: Work>(
    artifacts: &ArtifactUses<'_, '_, '_, 'c, 'd, N, D, G>,
    work: &W,
) -> Result<CredentialRequired<'c, 'd, W>, MemoryError> {
    let inputs = artifacts.inputs();
    let mut roots = inputs.authorities().roots().iter();
    let mut sources = work.vector();
    let mut missing_input = false;
    for (participant, entry) in inputs.requirements().entries().iter().enumerate() {
        work.charge_work(1)?;
        let ParticipantAuthority::Path(path) = entry.authority() else {
            continue;
        };
        // There is one status root per PATH entry, not per participant. Direct
        // anchors and certificate-free credential authorities have no lookup.
        let statuses = roots
            .next()
            .expect("constructed complete path/status pairing");
        assert!(
            core::ptr::eq(statuses.path(), path),
            "same constructed path receipt"
        );
        if !matches!(entry.participant(), Participant::Credential { .. }) {
            continue;
        }
        // EN319132-1 A.1.4(1–2), including its complete/delta contributor clause.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
        missing_input |= append_path(statuses, work, |source| {
            sources.try_push(CredentialStatusSource {
                participant,
                source,
                ordinary: false,
                attribute: false,
            })
        })?;
    }
    Ok(CredentialRequired {
        sources,
        missing_input,
    })
}
