//! Actual per-TSA validation material, not a global timestamp-purpose union.
use super::{Index, Placement};
use crate::xml::{Access, Snapshot, Xml};
use structured_asn1::memory::{HashWork, MemoryError, OwnedVec, Work};
use structured_ltv::material::status::{ArtifactVisitError, member_source, visit_artifacts};
use structured_ltv::material::{ArtifactKey, ArtifactRef, IndexError};
use structured_ltv::pki::{
    AuthorityVisitError, Participant, ParticipantAuthority, ParticipantClosure, UsesError,
};
use structured_ltv::source::ScopeError;
use structured_ltv::timestamp::TimestampScope;

/// Why required original X.509 material has no eligible copy for this TSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampPlacementFailure {
    /// No exact copy was incorporated in either frozen source pool.
    Missing,
    /// Copies exist, but only in other containers/other timestamp tokens.
    OutsideTimestampContainers,
}

/// One actual token's missing/misplaced artifact; no signed bytes are copied.
pub struct TimestampPlacementFinding<'certificate, 'document, N> {
    /// Original timestamp property requiring this artifact.
    pub property: N,
    /// Exact original token; material in a sibling token is not self-carried.
    pub token: N,
    /// Exact original certificate/whole CRL/basic-response identity.
    pub artifact: ArtifactRef<'certificate, 'document>,
    /// Missing and misplaced remain distinct.
    pub cause: TimestampPlacementFailure,
}

/// ONLY §6.3(x)'s eligible placement for all actual X.509 TSA dependencies.
/// This is not usable revocation, historical trust, chronology, format-specific
/// material or a complete B-LT/B-LTA verdict. Original inputs remain borrowed.
pub struct TimestampPlacement<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G> {
    inputs: &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G>,
    findings: OwnedVec<TimestampPlacementFinding<'certificate, 'document, N>>,
    snapshot: Snapshot<D, G>,
}
impl<'closure, 'requirements, 'view, 'certificate, 'document, N, D: Copy, G: Copy>
    TimestampPlacement<'closure, 'requirements, 'view, 'certificate, 'document, N, D, G>
{
    /// Same complete original participant/status input census.
    #[must_use]
    pub fn inputs(
        &self,
    ) -> &'closure ParticipantClosure<'requirements, 'view, 'certificate, 'document, N, D, G> {
        self.inputs
    }
    /// Every missing/misplaced exact artifact once per actual TSA root.
    #[must_use]
    pub fn findings(&self) -> &[TimestampPlacementFinding<'certificate, 'document, N>] {
        &self.findings
    }
    /// Original immutable XML generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
}

/// Input/source/current-operation refusal, never a missing-material finding.
#[derive(Debug)]
pub enum TimestampPlacementError<N> {
    /// A preceding-archive subset omits the current/later TSA and is insufficient.
    Scope,
    /// Source generation or selected signature/index was substituted.
    Index(IndexError<N>),
    /// Original actor-authority traversal/current storage refusal.
    Uses(UsesError<N>),
}

/// Placement result in the original XML identity/error domain.
pub type TimestampPlacementResult<'closure, 'requirements, 'view, 'certificate, 'document, X> =
    Result<
        TimestampPlacement<
            'closure,
            'requirements,
            'view,
            'certificate,
            'document,
            <X as Xml>::Id,
            <X as Xml>::Document,
            <X as Xml>::Generation,
        >,
        TimestampPlacementError<<X as Xml>::Id>,
    >;

#[derive(Hash, PartialEq, Eq)]
struct Seen<'document> {
    root: usize,
    artifact: ArtifactKey<'document>,
}
impl HashWork for Seen<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        self.artifact
            .hash_work()?
            .checked_add(1)
            .ok_or(MemoryError::WorkExceeded)
    }
}

fn allowed<N: Copy, E>(
    placement: Placement<N>,
    property: N,
    token: N,
    equal: &mut impl FnMut(N, N) -> Result<bool, E>,
) -> Result<bool, E> {
    match placement {
        // §6.3(x) names these properties; their URI is only a hint.
        Placement::General(_) | Placement::Timestamp(_) => Ok(true),
        Placement::TimestampToken {
            property: actual_property,
            token: actual_token,
            ..
        } => Ok(equal(actual_property, property)? && equal(actual_token, token)?),
        _ => Ok(false),
    }
}

fn availability<X: Xml, W: Work, Q: Work>(
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    artifact: ArtifactRef<'_, '_>,
    signature: X::Id,
    property: X::Id,
    token: X::Id,
    access: &Access<'_, X, Q>,
) -> Result<Option<TimestampPlacementFailure>, IndexError<X::Id>> {
    let mut present = false;
    for occurrence in index.artifact(artifact, access)? {
        let occurrence = occurrence?;
        present = true;
        let eligible = allowed(
            occurrence.placement(),
            property,
            token,
            &mut |left, right| {
                access
                    .equal_id(left, right)
                    .map_err(|cause| IndexError::Resource { signature, cause })
            },
        )?;
        if eligible {
            return Ok(None);
        }
    }
    Ok(Some(if present {
        TimestampPlacementFailure::OutsideTimestampContainers
    } else {
        TimestampPlacementFailure::Missing
    }))
}

/// Require §6.3(x)'s actual copies in timestamp/general validation data or in
/// THAT timestamp itself. Shared roots/status authorities follow the SAME paid
/// iterative dependency kernel, retaining per-token attribution across cycles.
/// Complete/delta CRLs, OCSP whole-envelope identity and embedded signers reuse
/// the common original-artifact visitor/index. No parse/hash/crypto repeats.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Current Work admits identity/hash/probe/traversal/report capacity before use.
/// A late refusal drops all partial findings/scratch, not a successful prefix.
pub fn timestamp_placement<
    'closure,
    'requirements,
    'view,
    'certificate,
    'document,
    X: Xml,
    W: Work,
    Q: Work,
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
    access: &Access<'_, X, Q>,
) -> TimestampPlacementResult<'closure, 'requirements, 'view, 'certificate, 'document, X> {
    let required = inputs.requirements();
    if !matches!(required.scope(), TimestampScope::All(_)) {
        return Err(TimestampPlacementError::Scope);
    }
    let signature = required.signature();
    if required.scope().location().snapshot != access.snapshot() {
        return Err(TimestampPlacementError::Index(IndexError::Foreign {
            signature,
        }));
    }
    index
        .require_signature(signature, access)
        .map_err(TimestampPlacementError::Index)?;
    let work = access.execution();
    let resource =
        |cause| TimestampPlacementError::Index(IndexError::Resource { signature, cause });
    let mut actors = work.vector();
    for entry in required.entries() {
        work.charge_work(1).map_err(resource)?;
        if matches!(entry.authority(), ParticipantAuthority::Path(_)) {
            actors
                .try_push(match entry.participant() {
                    Participant::Timestamp { property, token } => Some((property, token)),
                    _ => None,
                })
                .map_err(resource)?;
        }
    }
    let mut seen = work.map();
    let mut findings = work.vector();
    inputs
        .authorities()
        .visit_roots(work, |root, node| {
            let Some((property, token)) = actors[root] else {
                return Ok(());
            };
            let mut record = |artifact: ArtifactRef<'certificate, 'document>| {
                let key = Seen {
                    root,
                    artifact: artifact.identity(),
                };
                if seen.try_insert(key, ()).map_err(resource)?.is_some() {
                    return Ok(());
                }
                if let Some(cause) =
                    availability(index, artifact, signature, property, token, access)
                        .map_err(TimestampPlacementError::Index)?
                {
                    findings
                        .try_push(TimestampPlacementFinding {
                            property,
                            token,
                            artifact,
                            cause,
                        })
                        .map_err(resource)?;
                }
                Ok(())
            };
            let path = node.statuses.path();
            if let Some(certificate) = path.anchor().certificate() {
                record(ArtifactRef::Certificate(certificate))?;
            }
            for member in path.members() {
                work.charge_work(1).map_err(resource)?;
                record(ArtifactRef::Certificate(member.certificate()))?;
            }
            for input in node.statuses.entries() {
                work.charge_work(1).map_err(resource)?;
                if let Some(source) = member_source(input) {
                    visit_artifacts(source, signature, access, |artifact, _, _| record(artifact))
                        .map_err(|cause| match cause {
                        ArtifactVisitError::Scope(ScopeError::Resource { cause, .. }) => {
                            resource(cause)
                        }
                        ArtifactVisitError::Scope(cause) => {
                            TimestampPlacementError::Uses(UsesError::Scope(cause))
                        }
                        ArtifactVisitError::Visitor(cause) => cause,
                    })?;
                }
            }
            Ok(())
        })
        .map_err(|cause| match cause {
            AuthorityVisitError::Processing(cause) => {
                TimestampPlacementError::Uses(UsesError::Closure(cause))
            }
            AuthorityVisitError::Visitor(cause) => cause,
        })?;
    Ok(TimestampPlacement {
        inputs,
        findings: findings.into_owned(),
        snapshot: access.snapshot(),
    })
}

#[cfg(test)]
mod tests;
