//! Exact artifact uses across all reached actors, independent of path receipts.

use super::ArtifactRef;
use super::index::ArtifactKey;
use super::status::{ArtifactVisitError, member_source, visit_artifacts};
use crate::pki::{
    AuthorityClosureError, AuthorityUses, ParticipantAuthority, ParticipantClosure, Uses, UsesError,
};
use crate::source::{Query, ScopeError};
use structured_asn1::memory::{MemoryError, OwnedMap, OwnedVec, Work};

/// An original certificate/status value with ALL its actual actor purposes.
/// Exact kind and original DER identify an artifact; two checked paths or
/// separately parsed copies do not make the same certificate exclusive to one.
pub struct ArtifactUse<'certificate, 'document> {
    artifact: ArtifactRef<'certificate, 'document>,
    uses: Uses,
    targets: Option<usize>,
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
pub struct ArtifactUses<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G, I> {
    inputs: &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G, I>,
    entries: OwnedVec<ArtifactUse<'certificate, 'document>>,
    targets: OwnedVec<StatusTarget>,
}

// A status artifact applies to THIS certificate, not its authentication signer.
// Both ordinals refer to the same immutable artifact catalogue; no source bytes
// or parsed certificates are copied to preserve this relation.
struct StatusTarget {
    certificate: usize,
    next: Option<usize>,
}

impl<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G, I>
    ArtifactUses<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G, I>
{
    /// Same source-derived actor/status input closure, without another query.
    #[must_use]
    pub fn inputs(
        &self,
    ) -> &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G, I>
    {
        self.inputs
    }
    /// Every distinct artifact once in first-encounter order.
    #[must_use]
    pub fn entries(&self) -> &[ArtifactUse<'certificate, 'document>] {
        &self.entries
    }
    /// The certificates whose status the CRL/OCSP entry at `ordinal` reports,
    /// as ordinals into [`Self::entries`]; empty for a certificate entry.
    /// Each step is constant time; a caller paying per target admits it.
    ///
    /// # Panics
    /// When `ordinal` is not an ordinal of [`Self::entries`].
    #[must_use]
    pub fn targets(&self, ordinal: usize) -> Targets<'_> {
        Targets {
            targets: &self.targets,
            next: self.entries[ordinal].targets,
        }
    }
}

/// Status targets of one artifact, most recently recorded first.
pub struct Targets<'a> {
    targets: &'a [StatusTarget],
    next: Option<usize>,
}

impl Iterator for Targets<'_> {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        let target = &self.targets[self.next?];
        self.next = target.next;
        Some(target.certificate)
    }
}

impl core::iter::FusedIterator for Targets<'_> {}

/// Original source/role association and resource failures remain terminal.
pub type ArtifactUsesResult<'closure, 'requirements, 'view, 'certificate, 'document, Q, I> = Result<
    ArtifactUses<
        'closure,
        'requirements,
        'view,
        'certificate,
        'document,
        <Q as Query>::Id,
        <Q as Query>::Document,
        <Q as Query>::Generation,
        I,
    >,
    UsesError<<Q as Query>::Id>,
>;

struct Census<'certificate, 'document, W: Work> {
    index: OwnedMap<ArtifactKey<'document>, usize, W>,
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
pub fn artifact_uses<'closure, 'requirements, 'view, 'certificate, 'document, Q: Query, I>(
    authorities: &AuthorityUses<
        'closure,
        'requirements,
        'view,
        'certificate,
        'document,
        Q::Id,
        Q::Document,
        Q::Generation,
        I,
    >,
    query: &Q,
) -> ArtifactUsesResult<'closure, 'requirements, 'view, 'certificate, 'document, Q, I> {
    let inputs = authorities.inputs();
    let requirements = inputs.requirements();
    if requirements.scope().location().snapshot != query.snapshot() {
        return Err(UsesError::Foreign);
    }
    query
        .admit(requirements.signature(), 1)
        .map_err(UsesError::Scope)?;
    let work = query.execution();
    let resource = |cause| UsesError::Closure(AuthorityClosureError::Resource(cause));
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
            visit_artifacts(source, requirements.signature(), query, |artifact, _, _| {
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
            })
            .map_err(|cause| match cause {
                ArtifactVisitError::Scope(ScopeError::Resource { cause, .. })
                | ArtifactVisitError::Visitor(cause) => resource(cause),
                ArtifactVisitError::Scope(cause) => UsesError::Scope(cause),
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
mod tests;
