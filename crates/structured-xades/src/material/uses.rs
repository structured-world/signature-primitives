//! Exact artifact uses across all reached actors, independent of path receipts.

use super::ArtifactRef;
use super::index::Key;
use super::status::{ArtifactVisitError, member_source, visit_artifacts};
use crate::pki::{AuthorityUses, ParticipantAuthority, ParticipantClosure, Uses, UsesError};
use crate::xml::{Access, Xml};
use structured_asn1::memory::{MemoryError, OwnedMap, OwnedVec, Work};

/// An original certificate/status value with ALL its actual actor purposes.
/// Exact kind and original DER identify an artifact; two checked paths or
/// separately parsed copies do not make the same certificate exclusive to one.
pub struct ArtifactUse<'certificate, 'document> {
    pub(super) artifact: ArtifactRef<'certificate, 'document>,
    pub(super) uses: Uses,
    pub(super) targets: Option<usize>,
}

impl<'certificate, 'document> ArtifactUse<'certificate, 'document> {
    /// First original value carrying this exact kind/DER identity.
    #[must_use]
    pub fn artifact(&self) -> ArtifactRef<'certificate, 'document> {
        self.artifact
    }
    /// Union of every reached actor's uses, including status-authority uses.
    #[must_use]
    pub fn uses(&self) -> Uses {
        self.uses
    }
}

/// Complete X.509/CRL/OCSP artifact census for the same participant requirements.
/// Credential-format-specific data remain separate. This does not assert CA
/// status, allowed placement, freshness or baseline grade.
pub struct ArtifactUses<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G> {
    inputs: &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G>,
    entries: OwnedVec<ArtifactUse<'certificate, 'document>>,
    pub(super) targets: OwnedVec<StatusTarget>,
}

// A status artifact applies to THIS certificate, not its authentication signer.
// Both ordinals refer to the same immutable artifact catalogue; no source bytes
// or parsed certificates are copied to preserve this relation.
pub(super) struct StatusTarget {
    pub(super) certificate: usize,
    pub(super) next: Option<usize>,
}

impl<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G>
    ArtifactUses<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G>
{
    /// Same source-derived actor/status input closure, without another query.
    #[must_use]
    pub fn inputs(
        &self,
    ) -> &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G> {
        self.inputs
    }
    /// Every distinct artifact once in first-encounter order.
    #[must_use]
    pub fn entries(&self) -> &[ArtifactUse<'certificate, 'document>] {
        &self.entries
    }
}

/// Original source/role association and resource failures remain terminal.
pub type ArtifactUsesResult<'closure, 'requirements, 'view, 'certificate, 'document, X> = Result<
    ArtifactUses<
        'closure,
        'requirements,
        'view,
        'certificate,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    UsesError<<X as Xml>::Error, <X as Xml>::Id>,
>;

struct Census<'certificate, 'document, W: Work> {
    index: OwnedMap<Key<'document>, usize, W>,
    entries: OwnedVec<ArtifactUse<'certificate, 'document>, W>,
    targets: OwnedVec<StatusTarget, W>,
}

impl<'certificate, 'document, W: Work> Census<'certificate, 'document, W> {
    fn record(
        &mut self,
        artifact: ArtifactRef<'certificate, 'document>,
        uses: Uses,
        work: &W,
    ) -> Result<usize, MemoryError> {
        work.charge_work(1)?;
        let key = artifact.identity();
        if let Some(&index) = self.index.get(&key, work)? {
            self.entries[index].uses.merge(uses);
            return Ok(index);
        }
        let index = self.entries.len();
        self.index.try_insert(key, index)?;
        self.entries.try_push(ArtifactUse {
            artifact,
            uses,
            targets: None,
        })?;
        Ok(index)
    }
}

/// Merge purposes by exact original artifact identity AFTER role propagation.
/// EN319132-1 §§5.4.2(5)/5.4.3(4) concern exclusive certificate/status uses,
/// which cannot be inferred from path identity or the first occurrence alone.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Reuses the archive index's key/hash admission and status source visitor.
/// Complete/delta contributors, actual OCSP/CRL signers and existing direct
/// anchors participate. No parse, provider, signature or normalization repeats.
/// Current Work pays even when the original role census used another account;
/// partial metadata and scratch index are released on every refusal.
pub fn artifact_uses<'closure, 'requirements, 'view, 'certificate, 'document, X: Xml, W: Work>(
    authorities: &AuthorityUses<
        'closure,
        'requirements,
        'view,
        'certificate,
        'document,
        X::Id,
        X::Document,
        X::Generation,
    >,
    access: &Access<'_, X, W>,
) -> ArtifactUsesResult<'closure, 'requirements, 'view, 'certificate, 'document, X> {
    let inputs = authorities.inputs();
    let requirements = inputs.requirements();
    if requirements.scope().location().snapshot != access.snapshot() {
        return Err(UsesError::Foreign);
    }
    access
        .query(requirements.signature(), |_, _, _| Ok(()))
        .map_err(UsesError::Access)?;
    let work = access.execution();
    let resource = |cause| UsesError::Closure(crate::pki::AuthorityClosureError::Resource(cause));
    let mut census = Census {
        index: work.map(),
        entries: work.vector(),
        targets: work.vector(),
    };
    for authority in authorities.entries() {
        work.charge_work(1).map_err(resource)?;
        let path = authority.node().statuses.path();
        let uses = authority.uses();
        if let Some(certificate) = path.anchor().certificate() {
            census
                .record(ArtifactRef::Certificate(certificate), uses, work)
                .map_err(resource)?;
        }
        for member in path.members() {
            census
                .record(ArtifactRef::Certificate(member.certificate()), uses, work)
                .map_err(resource)?;
        }
        for input in authority.node().statuses.entries() {
            work.charge_work(1).map_err(resource)?;
            let Some(source) = member_source(input) else {
                continue;
            };
            let certificate = census
                .record(ArtifactRef::Certificate(source.target()), uses, work)
                .map_err(resource)?;
            visit_artifacts(
                source,
                requirements.signature(),
                access,
                |artifact, _, _| {
                    let index = census.record(artifact, uses, work)?;
                    if !matches!(artifact, ArtifactRef::Certificate(_)) {
                        let next = census.entries[index].targets;
                        let target = census.targets.len();
                        census
                            .targets
                            .try_push(StatusTarget { certificate, next })?;
                        census.entries[index].targets = Some(target);
                    }
                    Ok::<_, MemoryError>(())
                },
            )
            .map_err(|cause| match cause {
                ArtifactVisitError::Access(cause) => UsesError::Access(cause),
                ArtifactVisitError::Resource(cause) | ArtifactVisitError::Visitor(cause) => {
                    resource(cause)
                }
            })?;
        }
    }
    for entry in requirements.entries() {
        work.charge_work(1).map_err(resource)?;
        let ParticipantAuthority::Anchor(anchor) = entry.authority() else {
            continue;
        };
        if let Some(certificate) = anchor.anchor().certificate() {
            census
                .record(
                    ArtifactRef::Certificate(certificate),
                    Uses::participant(entry.participant()),
                    work,
                )
                .map_err(resource)?;
        }
    }
    Ok(ArtifactUses {
        inputs,
        entries: census.entries.into_owned(),
        targets: census.targets.into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::material::fixture;
    use crate::pki::Participant;
    use alloc::sync::Arc;
    use structured_asn1::{
        Parser,
        memory::{Memory, MemoryAccount},
    };
    use structured_pkix::{Certificate, Version};

    fn funded() -> Memory {
        Memory::new(Arc::new(MemoryAccount::new(65_536, 1_000_000)))
    }

    #[test]
    fn independent_parsed_copies_merge_roles_by_original_der() {
        // Distinct source allocations and parser sessions still denote ONE
        // artifact; a changed serial is another artifact even with the same key.
        let first_bytes = fixture::certificate(1, Version::V1, None);
        let copy_bytes = first_bytes.clone();
        let changed_bytes = fixture::certificate(2, Version::V1, None);
        assert_ne!(first_bytes.as_ptr(), copy_bytes.as_ptr());
        let source = funded();
        let first_parser = Parser::der(source.clone());
        let copy_parser = Parser::der(source.clone());
        let first = Certificate::read(&first_parser, &first_bytes, 100).unwrap();
        let copy = Certificate::read(&copy_parser, &copy_bytes, 900).unwrap();
        let changed = Certificate::read(&copy_parser, &changed_bytes, 1800).unwrap();
        let source_used = source.used();
        let work = funded();
        let mut census = Census {
            index: work.map(),
            entries: work.vector(),
            targets: work.vector(),
        };
        let timestamp = Uses::participant(Participant::Timestamp {
            property: 0usize,
            token: 1,
        });
        let signature = Uses::participant(Participant::Signer(0usize));
        let credential = Uses::participant(Participant::Credential {
            signature: 0usize,
            node: 3,
            authority: 0,
        });
        census
            .record(ArtifactRef::Certificate(&first), timestamp, &work)
            .unwrap();
        census
            .record(ArtifactRef::Certificate(&copy), signature, &work)
            .unwrap();
        census
            .record(ArtifactRef::Certificate(&copy), credential, &work)
            .unwrap();
        census
            .record(ArtifactRef::Certificate(&changed), credential, &work)
            .unwrap();
        assert_eq!(census.entries.len(), 2);
        assert!(census.entries[0].uses.signature());
        assert!(census.entries[0].uses.credential());
        assert!(census.entries[0].uses.timestamp());
        assert!(!census.entries[1].uses.signature());
        assert!(census.entries[1].uses.credential());
        assert!(!census.entries[1].uses.timestamp());
        assert!(matches!(census.entries[0].artifact,
            ArtifactRef::Certificate(value) if core::ptr::eq(value, &raw const first)));
        drop(census);
        assert_eq!(work.used(), 0);
        assert_eq!(source.used(), source_used);
    }

    #[test]
    fn refused_merge_preserves_first_roles_and_releases_scratch() {
        // Refuse before inspecting/mutating an already seen artifact. A denied
        // additional role cannot partially change classification or source data.
        let bytes = fixture::certificate(1, Version::V1, None);
        let source = funded();
        let parser = Parser::der(source.clone());
        let value = Certificate::read(&parser, &bytes, 100).unwrap();
        let source_used = source.used();
        let work = funded();
        let mut census = Census {
            index: work.map(),
            entries: work.vector(),
            targets: work.vector(),
        };
        census
            .record(
                ArtifactRef::Certificate(&value),
                Uses::participant(Participant::Timestamp {
                    property: 0usize,
                    token: 1,
                }),
                &work,
            )
            .unwrap();
        work.charge_work(u64::try_from(work.work_remaining()).unwrap())
            .unwrap();
        let held = work.used();
        assert_eq!(
            census.record(
                ArtifactRef::Certificate(&value),
                Uses::participant(Participant::Signer(0usize)),
                &work
            ),
            Err(MemoryError::WorkExceeded)
        );
        assert_eq!(census.entries.len(), 1);
        assert!(census.entries[0].uses.timestamp());
        assert!(!census.entries[0].uses.signature());
        assert_eq!(work.used(), held);
        drop(census);
        assert_eq!(work.used(), 0);
        assert_eq!(source.used(), source_used);
    }
}
