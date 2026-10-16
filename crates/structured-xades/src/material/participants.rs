//! Complete participant X.509 material for one original archive input.

use super::status::{AuthorityMaterial, archived_authorities};
use super::{ArchiveError, Archived, ArtifactRef, Index, IndexError};
use crate::pki::{Participant, ParticipantAuthority, ParticipantClosure};
use crate::timestamp::{ElementCoverage, Role, TimestampScope, Verified};
use crate::xml::{Access, Xml};
use structured_asn1::memory::{HashWork, MemoryError, OwnedVec, Work};

/// Direct credential anchor's distinct certificate-material obligation.
pub struct AnchorMaterial<N, D, G> {
    participant: Participant<N>,
    certificate: Option<Archived<N, D, G>>,
}

impl<N: Copy, D, G> AnchorMaterial<N, D, G> {
    /// Original authenticated credential using this direct anchor.
    #[must_use]
    pub fn participant(&self) -> Participant<N> {
        self.participant
    }

    /// Existing anchor certificate's actual archive availability. `None` means
    /// this explicit anchor has no certificate, not an unsuccessful lookup.
    #[must_use]
    pub fn certificate(&self) -> Option<&Archived<N, D, G>> {
        self.certificate.as_ref()
    }
}

/// Every participant's reached X.509 artifacts under the SAME original archive.
/// Source requirements and negative status facts remain available in `inputs`.
/// This does not decide status usability, trust, exclusive material placement,
/// credential-format-specific material, chronology or an attained baseline level.
pub struct ParticipantMaterial<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G> {
    inputs: &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G>,
    authorities: AuthorityMaterial<'closure, 'view, 'certificate, 'document, N, D, G>,
    anchors: OwnedVec<AnchorMaterial<N, D, G>>,
    all_covered: bool,
}

impl<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G>
    ParticipantMaterial<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G>
{
    /// Complete source-bound actor and status-authority input set.
    #[must_use]
    pub fn inputs(
        &self,
    ) -> &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G> {
        self.inputs
    }

    /// Original certificates and every complete/delta/OCSP authority artifact.
    #[must_use]
    pub fn authorities(
        &self,
    ) -> &AuthorityMaterial<'closure, 'view, 'certificate, 'document, N, D, G> {
        &self.authorities
    }

    /// Direct anchors, never substituted with non-anchor revocation inputs.
    #[must_use]
    pub fn anchors(&self) -> &[AnchorMaterial<N, D, G>] {
        &self.anchors
    }

    /// Whether every required X.509 artifact has an exact covered copy before
    /// this archive. This is NOT complete credential-format or level acceptance.
    #[must_use]
    pub fn all_x509_artifacts_covered(&self) -> bool {
        self.all_covered
    }
}

/// Foreign archive evidence cannot satisfy another original obligation set.
#[derive(Debug)]
pub enum ParticipantArchiveError<E, N> {
    /// Different source, selected signature, archive role or archive property.
    Foreign {
        /// Original required archive property.
        expected: N,
        /// Supplied token's actual original property.
        actual: N,
    },
    /// Exact source/index/coverage/material processing cause.
    Material(ArchiveError<E, N>),
    /// Actor traversal, identity comparison or retained capacity refused.
    Resource {
        /// Original required archive property.
        archive: N,
        /// Current-operation refusal, not missing material.
        cause: MemoryError,
    },
}

/// Participant archive report in the XML owner's original identity domain.
pub type ParticipantArchiveResult<'closure, 'requirements, 'view, 'certificate, 'document, X> =
    Result<
        ParticipantMaterial<
            'closure,
            'requirements,
            'view,
            'certificate,
            'document,
            <X as Xml>::Id,
            <X as Xml>::Document,
            <X as Xml>::Generation,
        >,
        ParticipantArchiveError<<X as Xml>::Error, <X as Xml>::Id>,
    >;

/// Match the complete participant closure to its one particular original archive,
/// then reuse the exact artifact/coverage kernel for every reached authority and
/// existing direct-anchor certificate. EN319132-1 §5.4.2/§5.4.3/§6.3(aa) distinguishes
/// existing anchor certificate material from non-anchor status obligations.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Own/later token material cannot repair preceding input, and a successful token
/// for a different archive cannot be substituted. No parsing, provider, status or
/// signature work is repeated. Late refusal drops every partial report.
pub fn archived_participants<
    'closure,
    'requirements,
    'view,
    'certificate,
    'document,
    X: Xml,
    W: Work,
    Q: Work,
    C: Work,
>(
    inputs: &'closure ParticipantClosure<
        'requirements,
        'view,
        'certificate,
        'document,
        X::Id,
        X::Document,
        X::Generation,
    >,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    coverage: &ElementCoverage<X::Id, X::Document, X::Generation, C>,
    evidence: &Verified<X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, Q>,
) -> ParticipantArchiveResult<'closure, 'requirements, 'view, 'certificate, 'document, X> {
    let required = inputs.requirements();
    let scope = required.scope();
    let archive = scope.location();
    let foreign = || ParticipantArchiveError::Foreign {
        expected: archive.node,
        actual: evidence.property(),
    };
    if !matches!(scope, TimestampScope::BeforeArchive(_))
        || archive.snapshot != access.snapshot()
        || archive.snapshot != evidence.token().snapshot
    {
        return Err(foreign());
    }
    let resource = |cause| ParticipantArchiveError::Resource {
        archive: archive.node,
        cause,
    };
    let mut anchors = access
        .query(archive.node, |_, _, work| Ok(work.vector()))
        .map_err(|cause| {
            ParticipantArchiveError::Material(ArchiveError::Index(IndexError::Access(cause)))
        })?;
    let cost = archive
        .node
        .hash_work()
        .and_then(|cost| {
            cost.checked_add(evidence.property().hash_work()?)
                .ok_or(MemoryError::WorkExceeded)
        })
        .and_then(|cost| {
            cost.checked_add(required.signature().hash_work()?)
                .ok_or(MemoryError::WorkExceeded)
        })
        .and_then(|cost| {
            cost.checked_add(evidence.signature().hash_work()?)
                .ok_or(MemoryError::WorkExceeded)
        })
        .map_err(resource)?;
    access.execution().charge_work(cost).map_err(resource)?;
    if archive.node != evidence.property()
        || required.signature() != evidence.signature()
        || evidence.role() != Role::Archive
    {
        return Err(foreign());
    }
    coverage
        .require_evidence(evidence, archive.node, access)
        .map_err(|cause| ParticipantArchiveError::Material(ArchiveError::Coverage(cause)))?;
    let authorities = archived_authorities(inputs.authorities(), index, coverage, evidence, access)
        .map_err(ParticipantArchiveError::Material)?;
    let mut all_covered = authorities.all_artifacts_covered();
    for entry in required.entries() {
        access.execution().charge_work(1).map_err(resource)?;
        let ParticipantAuthority::Anchor(anchor) = entry.authority() else {
            continue;
        };
        let certificate = match anchor.anchor().certificate() {
            Some(certificate) => {
                let value = index
                    .archived(
                        ArtifactRef::Certificate(certificate),
                        coverage,
                        evidence,
                        access,
                    )
                    .map_err(ParticipantArchiveError::Material)?;
                if !matches!(value, Archived::Present(_)) {
                    all_covered = false;
                }
                Some(value)
            }
            None => None,
        };
        anchors
            .try_push(AnchorMaterial {
                participant: entry.participant(),
                certificate,
            })
            .map_err(resource)?;
    }
    Ok(ParticipantMaterial {
        inputs,
        authorities,
        anchors: anchors.into_owned(),
        all_covered,
    })
}
