//! Mandatory copies in a present signature's certificate/status containers.

use super::catalogue::{ContainerKind, container_kind};
use super::status::{ArtifactVisitError, StatusPart, member_source, visit_artifacts};
use super::{ArtifactRef, Index, IndexError, Placement};
use crate::pki::{
    CounterPaths, Participant, ParticipantAuthority, ParticipantClosure, ParticipantRequirements,
};
use crate::prepare::Prepared;
use crate::timestamp::TimestampScope;
use crate::xml::{Access, Snapshot, Xml};
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, OwnedVec, Work};

/// Why a mandatory copy in a present container could not be established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionalFailure {
    /// No exact copy is incorporated anywhere in the indexed signature.
    Missing,
    /// Exact copies exist, but none satisfies this container's mandatory rule.
    Elsewhere,
}

/// One unsatisfied conditional requirement, with the actual actor and artifact.
pub struct ConditionalFinding<'certificate, 'document, N> {
    /// Original property whose presence activates this requirement.
    pub property: N,
    /// Actual participant; a credential's signing authority is not the root signer.
    pub participant: Participant<N>,
    /// Exact certificate or contributing complete/delta/OCSP artifact.
    pub artifact: ArtifactRef<'certificate, 'document>,
    /// Absence and an ineligible copy are distinct from processing refusal.
    pub cause: ConditionalFailure,
}

/// Container-specific obligations of the root and ALL actual counters. This supplements
/// the whole participant incorporation, exclusivity and TSA-placement reports.
/// It does not assert a child's baseline, format-specific credential material,
/// usable status, chronology, trust or an attained level.
pub struct ConditionalPlacement<'certificate, 'document, N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    findings: OwnedVec<ConditionalFinding<'certificate, 'document, N>>,
}

impl<'certificate, 'document, N: Copy, D: Copy, G: Copy>
    ConditionalPlacement<'certificate, 'document, N, D, G>
{
    /// Exact source generation under which the obligations were derived.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original signature owning the checked properties.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Missing/misplaced copies in property, then original actor/artifact order.
    #[must_use]
    pub fn findings(&self) -> &[ConditionalFinding<'certificate, 'document, N>] {
        &self.findings
    }
}

/// Scope/source/current-operation refusal; none is a missing-material fact.
#[derive(Debug)]
pub enum ConditionalError<E, N> {
    /// An archive antecedent subset cannot establish whole-signature conditions.
    Scope,
    /// Original signature, source, lookup or storage/work refusal.
    Index(IndexError<E, N>),
    /// Original child unsigned/material container structure or access refusal.
    Property(crate::properties::Error<E, N>),
}

/// Result in the original XML identity/error domain.
pub type ConditionalResult<'certificate, 'document, X> = Result<
    ConditionalPlacement<
        'certificate,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    ConditionalError<<X as Xml>::Error, <X as Xml>::Id>,
>;

// A direct copy in this property is mandatory. Only ordinary signature
// CertificateValues/RevocationValues permit the owning KeyInfo alternative.
#[derive(Clone, Copy)]
enum CopyRule<N> {
    Property(N),
    PropertyOrKeyInfo { property: N, signature: N },
}

fn eligible<N: Copy, E>(
    rule: CopyRule<N>,
    placement: Placement<N>,
    embedded: bool,
    mut equal: impl FnMut(N, N) -> Result<bool, E>,
) -> Result<bool, E> {
    if embedded {
        return Ok(false);
    }
    match (rule, placement) {
        (CopyRule::Property(property), Placement::Attribute(actual))
        | (CopyRule::PropertyOrKeyInfo { property, .. }, Placement::Signature(actual)) => {
            equal(property, actual)
        }
        (CopyRule::PropertyOrKeyInfo { signature, .. }, Placement::KeyInfo(actual)) => {
            equal(signature, actual)
        }
        _ => Ok(false),
    }
}

/// Check mandatory copies in root and counter `CertificateValues`,
/// `RevocationValues`, `AttrAuthoritiesCertValues` and `AttributeRevocationValues`.
/// EN319132-1 §§5.4.2(1–3)/5.4.3(1–2) allow the owning `KeyInfo` alternative;
/// §§5.4.4(1)/5.4.5(1) require the actual credential SIGNER's certificate/status
/// in its attribute container even if another copy exists elsewhere.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Absent optional containers do not acquire an invented presence requirement:
/// §6.3(p/r/t/w/cc) permits the other incorporation service. Remaining path and
/// status-authority material uses the whole incorporation report; the more
/// specific TSA/exclusive-CA restrictions are separate. Duplication SHOULDs are
/// not upgraded into prohibitions. Counter material may be carried here but
/// does not replace the selected root's own obligations. Child sources come from
/// the COMPLETE actual counter-path receipt, including plain `XMLDSig` leaves;
/// their original properties reuse the retention role kernel without imposing
/// the root's B-level inventory/header rules. No parse/provider or
/// status evaluation is repeated; every original lookup and report allocation
/// is admitted before work. A late refusal drops the complete partial report.
///
/// # Panics
/// Only if a private construction invariant is violated: accepted checked paths
/// are nonempty, and their complete status roots follow Path requirements.
pub fn conditional_placement<'certificate, 'document, X: Xml, W: Work, Q: Work>(
    prepared: &Prepared<X>,
    inputs: &Inputs<'_, '_, 'certificate, 'document, X>,
    counters: &CounterPaths<'_, 'document, X::Id, X::Document, X::Generation>,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    access: &Access<'_, X, Q>,
) -> ConditionalResult<'certificate, 'document, X> {
    let required = inputs.requirements();
    if !matches!(required.scope(), TimestampScope::All(_)) {
        return Err(ConditionalError::Scope);
    }
    let signature = prepared.bound().containers().signature();
    let resource = |cause| ConditionalError::Index(IndexError::Resource { signature, cause });
    if prepared.bound().containers().snapshot() != access.snapshot()
        || required.scope().location().snapshot != access.snapshot()
        || counters.snapshot() != access.snapshot()
        || !access
            .equal_id(required.signature(), signature)
            .map_err(resource)?
        || !access
            .equal_id(counters.signature(), signature)
            .map_err(resource)?
    {
        return Err(ConditionalError::Index(IndexError::Foreign { signature }));
    }
    index
        .require_signature(signature, access)
        .map_err(ConditionalError::Index)?;
    let owners = Owners::build(required, access.execution()).map_err(resource)?;
    owners.require_counters(inputs, counters, signature, access)?;
    let mut findings = access.execution().vector();
    let mut record = |owner, property, kind| {
        check_property(
            inputs,
            &owners,
            (owner, property, kind),
            index,
            access,
            &mut findings,
        )
    };
    for entry in prepared.unsigned().entries() {
        access.execution().charge_work(1).map_err(resource)?;
        if let Some(kind) = ContainerKind::inventory(entry.role) {
            record(signature, entry.node, kind)?;
        }
    }
    for actor in counters.actors() {
        access.execution().charge_work(1).map_err(resource)?;
        let Some(layout) = actor.containers() else {
            continue;
        };
        let [parent, _] = crate::unsigned::containers(access, layout.unsigned())
            .map_err(ConditionalError::Property)?;
        let Some(parent) = parent else {
            continue;
        };
        for child in access.children(parent) {
            let node = child.map_err(|cause| {
                ConditionalError::Property(crate::properties::Error::Child(cause))
            })?;
            if let Some(kind) = container_kind(access, node).map_err(ConditionalError::Property)? {
                record(layout.signature(), node, kind)?;
            }
        }
    }
    index
        .require_signature(signature, access)
        .map_err(ConditionalError::Index)?;
    Ok(ConditionalPlacement {
        snapshot: access.snapshot(),
        signature,
        findings: findings.into_owned(),
    })
}

type Inputs<'requirements, 'view, 'certificate, 'document, X> = ParticipantClosure<
    'requirements,
    'view,
    'certificate,
    'document,
    <X as Xml>::Id,
    <X as Xml>::Document,
    <X as Xml>::Generation,
>;

struct ActorLink {
    requirement: usize,
    root: Option<usize>,
    next: Option<usize>,
}

// One current-operation index avoids scanning every unrelated actor for every
// counter's properties. Links borrow neither temporary XML views nor a parser.
struct Owners<N: HashWork, W: Work> {
    heads: OwnedMap<N, (usize, usize), W>,
    links: OwnedVec<ActorLink, W>,
    counters: usize,
}

impl<N: Copy + Eq + HashWork, W: Work> Owners<N, W> {
    fn build<D: Copy, G: Copy>(
        required: &ParticipantRequirements<'_, '_, N, D, G>,
        work: &W,
    ) -> Result<Self, MemoryError> {
        let mut result = Self {
            heads: work.map(),
            links: work.vector(),
            counters: 0,
        };
        let mut root = 0;
        for (requirement, entry) in required.entries().iter().enumerate() {
            work.charge_work(1)?;
            let path = if matches!(entry.authority(), ParticipantAuthority::Path(_)) {
                let index = root;
                root += 1;
                Some(index)
            } else {
                None
            };
            let owner = match entry.participant() {
                Participant::Signer(owner)
                | Participant::Credential {
                    signature: owner, ..
                } => owner,
                Participant::Counter {
                    signature: owner, ..
                } => {
                    result.counters += 1;
                    owner
                }
                Participant::Timestamp { .. } => continue,
            };
            let previous = result.heads.get(&owner, work)?.copied();
            let ordinal = result.links.len();
            result.links.try_push(ActorLink {
                requirement,
                root: path,
                next: None,
            })?;
            let head = if let Some((head, tail)) = previous {
                result.links[tail].next = Some(ordinal);
                head
            } else {
                ordinal
            };
            result.heads.try_insert(owner, (head, ordinal))?;
        }
        Ok(result)
    }

    fn require_counters<X: Xml<Id = N>, Q: Work>(
        &self,
        inputs: &Inputs<'_, '_, '_, '_, X>,
        counters: &CounterPaths<'_, '_, N, X::Document, X::Generation>,
        signature: N,
        access: &Access<'_, X, Q>,
    ) -> Result<(), ConditionalError<X::Error, N>> {
        let foreign = || ConditionalError::Index(IndexError::Foreign { signature });
        let resource = |cause| ConditionalError::Index(IndexError::Resource { signature, cause });
        if self.counters != counters.actors().len() {
            return Err(foreign());
        }
        for actor in counters.actors() {
            access.execution().charge_work(1).map_err(resource)?;
            let original = actor.signer().counter().original();
            let mut next = self
                .heads
                .get(&original.child(), access.execution())
                .map_err(resource)?
                .map(|&(head, _)| head);
            let mut found = false;
            while let Some(ordinal) = next {
                access.execution().charge_work(1).map_err(resource)?;
                let link = &self.links[ordinal];
                next = link.next;
                let entry = &inputs.requirements().entries()[link.requirement];
                if let Participant::Counter { property, .. } = entry.participant() {
                    let ParticipantAuthority::Path(path) = entry.authority() else {
                        return Err(foreign());
                    };
                    if !core::ptr::eq(path, actor.signer().path())
                        || !access
                            .equal_id(property, original.node())
                            .map_err(resource)?
                    {
                        return Err(foreign());
                    }
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(foreign());
            }
        }
        Ok(())
    }
}

fn check_property<'certificate, 'document, X: Xml, W: Work, Q: Work>(
    inputs: &Inputs<'_, '_, 'certificate, 'document, X>,
    owners: &Owners<X::Id, Q>,
    (owner, property, kind): (X::Id, X::Id, ContainerKind),
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    access: &Access<'_, X, Q>,
    findings: &mut OwnedVec<ConditionalFinding<'certificate, 'document, X::Id>, Q>,
) -> Result<(), ConditionalError<X::Error, X::Id>> {
    let signature = inputs.requirements().signature();
    let resource = |cause| ConditionalError::Index(IndexError::Resource { signature, cause });
    let mut record = |participant, artifact, rule| {
        if let Some(cause) = availability(index, artifact, rule, signature, access)? {
            findings
                .try_push(ConditionalFinding {
                    property,
                    participant,
                    artifact,
                    cause,
                })
                .map_err(resource)?;
        }
        Ok(())
    };
    let mut next = owners
        .heads
        .get(&owner, access.execution())
        .map_err(resource)?
        .map(|&(head, _)| head);
    while let Some(ordinal) = next {
        access.execution().charge_work(1).map_err(resource)?;
        let link = &owners.links[ordinal];
        next = link.next;
        let entry = &inputs.requirements().entries()[link.requirement];
        let participant = entry.participant();
        let ordinary = matches!(
            participant,
            Participant::Signer(_) | Participant::Counter { .. }
        );
        if ordinary == kind.attribute() {
            continue;
        }
        match entry.authority() {
            ParticipantAuthority::Path(_) => {
                let statuses =
                    inputs.authorities().roots()[link.root.expect("Path actor has a status root")];
                let properties = if kind.certificates() {
                    [Some(property), None]
                } else {
                    [None, Some(property)]
                };
                path_copies(
                    statuses,
                    participant,
                    properties,
                    owner,
                    access,
                    &mut record,
                )?;
            }
            ParticipantAuthority::Anchor(anchor) => {
                if kind.certificates()
                    && let Some(certificate) = anchor.anchor().certificate()
                {
                    record(
                        participant,
                        ArtifactRef::Certificate(certificate),
                        copy_rule(property, owner, ordinary),
                    )?;
                }
            }
            ParticipantAuthority::CertificateFree => {}
        }
    }
    Ok(())
}

fn availability<X: Xml, W: Work, Q: Work>(
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    artifact: ArtifactRef<'_, '_>,
    rule: CopyRule<X::Id>,
    signature: X::Id,
    access: &Access<'_, X, Q>,
) -> Result<Option<ConditionalFailure>, ConditionalError<X::Error, X::Id>> {
    let resource = |cause| ConditionalError::Index(IndexError::Resource { signature, cause });
    let mut present = false;
    for occurrence in index
        .artifact(artifact, access)
        .map_err(ConditionalError::Index)?
    {
        let occurrence = occurrence.map_err(ConditionalError::Index)?;
        present = true;
        if eligible(
            rule,
            occurrence.placement(),
            occurrence.embedded_certificate().is_some(),
            |left, right| access.equal_id(left, right).map_err(resource),
        )? {
            return Ok(None);
        }
    }
    Ok(Some(if present {
        ConditionalFailure::Elsewhere
    } else {
        ConditionalFailure::Missing
    }))
}

fn copy_rule<N: Copy>(property: N, signature: N, ordinary: bool) -> CopyRule<N> {
    if ordinary {
        CopyRule::PropertyOrKeyInfo {
            property,
            signature,
        }
    } else {
        CopyRule::Property(property)
    }
}

fn path_copies<'certificate, 'document, X: Xml, W: Work>(
    statuses: &crate::pki::PathStatuses<'_, 'certificate, 'document>,
    participant: Participant<X::Id>,
    [certificate, status]: [Option<X::Id>; 2],
    signature: X::Id,
    access: &Access<'_, X, W>,
    mut record: impl FnMut(
        Participant<X::Id>,
        ArtifactRef<'certificate, 'document>,
        CopyRule<X::Id>,
    ) -> Result<(), ConditionalError<X::Error, X::Id>>,
) -> Result<(), ConditionalError<X::Error, X::Id>> {
    let resource = |cause| ConditionalError::Index(IndexError::Resource { signature, cause });
    let work = access.execution();
    let path = statuses.path();
    let ordinary = matches!(
        participant,
        Participant::Signer(_) | Participant::Counter { .. }
    );
    let rule = |property| copy_rule(property, signature, ordinary);
    if let Some(property) = certificate {
        if ordinary && let Some(anchor) = path.anchor().certificate() {
            record(
                participant,
                ArtifactRef::Certificate(anchor),
                rule(property),
            )?;
        }
        let members = if ordinary {
            path.members()
        } else {
            path.members()
                .last_chunk::<1>()
                .expect("checked path has a target")
        };
        for member in members {
            work.charge_work(1).map_err(resource)?;
            record(
                participant,
                ArtifactRef::Certificate(member.certificate()),
                rule(property),
            )?;
        }
    }
    if let Some(property) = status {
        let entries = if ordinary {
            statuses.entries()
        } else {
            statuses
                .entries()
                .last_chunk::<1>()
                .expect("complete target status input")
        };
        for input in entries {
            work.charge_work(1).map_err(resource)?;
            let Some(source) = member_source(input) else {
                continue;
            };
            visit_artifacts(source, signature, access, |artifact, _, part| {
                // The authentication signer is not the status target.
                // Every complete/delta contributor is still required.
                if part == StatusPart::SigningCertificate {
                    return Ok(());
                }
                record(participant, artifact, rule(property))
            })
            .map_err(|cause| match cause {
                ArtifactVisitError::Access(cause) => {
                    ConditionalError::Index(IndexError::Access(cause))
                }
                ArtifactVisitError::Resource(cause) => resource(cause),
                ArtifactVisitError::Visitor(cause) => cause,
            })?;
        }
    }
    Ok(())
}
