//! Every actual credential's dependencies in a whole or historical PDF scope.

use super::Unified;
use crate::{
    basic::Basic,
    credential::{Complete, Group},
    query::Query,
    range::RangeSource,
    timestamp::{Node, Pades},
};
use structured_asn1::memory::{Memory, MemoryError, OwnedVec, Work};
use structured_cades::material::credentials::{Need, Provider};
use structured_ltv::{
    baseline::CredentialMaterial,
    material::{
        ArchiveError, Archived, Coverage, CoverageError, DependencyError, DependencyReport,
        DependencyVisit, IndexError, Missing,
    },
    pki::{CounterReceipts, CredentialGroup},
    source::{Query as _, ScopeError, Snapshot},
    timestamp::{CheckedActor, TimestampRequirements, TimestampScope},
};

/// Complete actual credential dependency report in the original PDF domain.
pub type CheckedReport<'a, 'r, 'm, 'd, 'p, D, G, E> =
    Report<'a, Complete<'r, 'm, 'd, 'p, D, G, E>, D, G>;

/// Exact historical input or ordinary whole-signature incorporation.
pub enum Scope<'a, 'c, 'd, D, G, W: Work = Memory> {
    /// No archive or `PoE` is implied.
    Whole,
    /// Both private receipts belong to one actual checked original input.
    Before {
        /// Exact source-derived covered items.
        coverage: &'a Coverage<Node, D, G, W, Pades>,
        /// Actual mathematically checked original token and authority binding.
        actor: &'a CheckedActor<'c, 'd, Node, D, G, Pades>,
    },
}
impl<D, G> Scope<'_, '_, '_, D, G> {
    /// Whole-source material only, with no implicit archive selection.
    #[must_use]
    pub fn whole() -> Self {
        Self::Whole
    }
}
/// All interpretation and availability facts for one original credential.
pub struct Entry {
    /// Actual original credential in its PDF enclosure.
    pub node: Node,
    /// Complete original dependency visitation result.
    pub dependencies: DependencyReport,
}
/// Same authenticated original receipt and all scope-required dependencies.
pub struct Report<'a, C, D, G> {
    credentials: &'a C,
    scope: TimestampScope<Node, D, G>,
    entries: OwnedVec<Entry>,
    complete: bool,
}
impl<C, D, G> Report<'_, C, D, G> {
    /// Every scope-required original credential, including negative results.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}
impl<C, D: Copy, G: Copy> CredentialMaterial for Report<'_, C, D, G> {
    type Id = Node;
    type Document = D;
    type Generation = G;
    type Credentials = C;
    fn scope(&self) -> TimestampScope<Node, D, G> {
        self.scope
    }
    fn snapshot(&self) -> Snapshot<D, G> {
        self.scope.location().snapshot
    }
    fn credentials(&self) -> &C {
        self.credentials
    }
    fn all_requirements_met(&self) -> bool {
        self.complete
    }
}
/// Original scope/lookup failure versus a handler's unchanged opaque cause.
#[derive(Debug)]
pub enum Error<E> {
    /// Another actual source, root, counter set or archive was supplied.
    Foreign {
        /// Actual selecting source node.
        node: Node,
    },
    /// Source generation or current admission refused.
    Scope(ScopeError<Node>),
    /// Original complete-counter scope membership refusal.
    Obligation(structured_ltv::timestamp::ObligationError<Node>),
    /// Original exact-artifact lookup refused.
    Index(IndexError<Node>),
    /// Original archive-input binding or material query refused.
    Archive(ArchiveError<Node>),
    /// Original coverage/evidence preflight refused.
    Coverage(CoverageError<Node>),
    /// Current work/storage refused before copying or dispatch.
    Resource {
        /// Actual original credential/root.
        node: Node,
        /// Original resource cause.
        cause: MemoryError,
    },
    /// Original carried reader context refused.
    Cms(structured_cms::Error),
    /// Original credential-format owner refused.
    Provider {
        /// Actual original credential.
        node: Node,
        /// Unchanged handler cause.
        cause: E,
    },
    /// A handler returned a visitor refusal without an actual failed visit.
    CallbackProtocol {
        /// Actual original credential.
        node: Node,
    },
}

fn dependency<D: Copy + Eq, G: Copy + Eq, E, S, W: Work, O: Work>(
    need: Need<'_, '_, '_, '_>,
    mapping: crate::binding::Mapping<'_, '_, D, G>,
    index: &Unified<'_, '_, D, G>,
    scope: &Scope<'_, '_, '_, D, G, W>,
    open: &structured_asn1::memory::OwnedMap<Node, (), O>,
    node: Node,
    query: &Query<'_, '_, S>,
) -> Result<Option<Missing>, Error<E>>
where
    S: RangeSource<Document = D, Generation = G>,
{
    match need {
        Need::Missing => Ok(Some(Missing::Absent)),
        Need::Known(artifact) => {
            if let Scope::Before { coverage, actor } = scope {
                return index
                    .index
                    .archived(artifact, coverage, actor.verified(), query)
                    .map(|value| match value {
                        Archived::Present(_) => None,
                        Archived::Missing => Some(Missing::Absent),
                        Archived::Uncovered => Some(Missing::Uncovered),
                    })
                    .map_err(Error::Archive);
            }
            let mut copies = index
                .index
                .artifact(artifact, query)
                .map_err(Error::Index)?;
            Ok(
                if copies.next().transpose().map_err(Error::Index)?.is_some() {
                    None
                } else {
                    Some(Missing::Absent)
                },
            )
        }
        Need::Open(location) => {
            if location.snapshot != mapping.cms {
                return Err(Error::Foreign { node });
            }
            let node = mapping.node(location.node);
            if open
                .get(&node, query.execution())
                .map_err(|cause| Error::Resource { node, cause })?
                .is_none()
            {
                return Ok(Some(Missing::Absent));
            }
            if let Scope::Before { coverage, actor } = scope {
                return coverage
                    .covers(actor.verified(), node, query)
                    .map(|covered| {
                        if covered {
                            None
                        } else {
                            Some(Missing::Uncovered)
                        }
                    })
                    .map_err(Error::Coverage);
            }
            Ok(None)
        }
    }
}

fn scope_binding<
    D: Copy + Eq,
    G: Copy + Eq,
    E,
    S: RangeSource<Document = D, Generation = G>,
    W: Work,
>(
    scope: &Scope<'_, '_, '_, D, G, W>,
    required: &TimestampRequirements<Node, D, G, Pades>,
    index: &Unified<'_, '_, D, G>,
    root: Node,
    query: &Query<'_, '_, S>,
) -> Result<(), Error<E>> {
    match (scope, required.scope()) {
        (Scope::Whole, TimestampScope::All(_)) if core::ptr::eq(required, index.required) => {}
        (Scope::Before { coverage, actor }, TimestampScope::BeforeArchive(location))
            if location == actor.verified().token() && actor.verified().signature() == root =>
        {
            coverage
                .require_evidence(actor.verified(), actor.verified().property(), query)
                .map_err(Error::Coverage)?;
        }
        _ => return Err(Error::Foreign { node: root }),
    }
    Ok(())
}

/// Checks all actual root credentials and each in-scope counter group. This
/// reuses the shared sticky visitor and exact index, not another credential
/// grammar or authenticator. A later DSS cannot satisfy an earlier input.
pub fn check<'a, 'r, 'm, 'd, 'p, D: Copy + Eq, G: Copy + Eq, E, P, S, W>(
    basic: &Basic<'_, '_, '_, 'm, 'd, '_, '_, 'p, D, G>,
    credentials: &'a Complete<'r, 'm, 'd, 'p, D, G, E>,
    required: &TimestampRequirements<Node, D, G, Pades>,
    index: &Unified<'_, 'd, D, G>,
    scope: &Scope<'_, '_, '_, D, G, W>,
    provider: &P,
    query: &Query<'_, '_, S>,
) -> Result<CheckedReport<'a, 'r, 'm, 'd, 'p, D, G, E>, Error<P::Error>>
where
    P: Provider<E>,
    S: RangeSource<Document = D, Generation = G>,
    W: Work,
{
    let bound = basic.binding();
    let root = bound.mapping.root;
    let snapshot = bound.mapping.snapshot;
    query.admit(root, 1).map_err(Error::Scope)?;
    if !query.belongs(bound.prepared().container.signature().owner().value.session)
        || !query.belongs(index.session)
        || query.snapshot() != snapshot
        || credentials.mapping.snapshot != snapshot
        || credentials.mapping.cms != bound.mapping.cms
        || credentials.mapping.root != root
        || required.signature() != root
        || required.scope().location().snapshot != snapshot
    {
        return Err(Error::Foreign { node: root });
    }
    index
        .index
        .require_signature(root, query)
        .map_err(Error::Index)?;
    scope_binding(scope, required, index, root, query)?;
    required
        .includes_counters(basic.counters(), query)
        .map_err(Error::Scope)?;
    let mut open = query.execution().map();
    for value in index.index.open() {
        query.admit(root, 1).map_err(Error::Scope)?;
        let node = bound.mapping.node(value.node);
        open.try_insert(node, ())
            .map_err(|cause| Error::Resource { node, cause })?;
    }
    let fields = bound.prepared().cms.signer().fields_source();
    let reader = fields.reader_in(query.execution()).map_err(Error::Cms)?;
    let mut entries = query.execution().vector();
    let mut complete = true;
    let mut visit = |group: &Group<'_, 'm, 'd, 'p, D, G, E>| -> Result<(), Error<P::Error>> {
        for credential in group.common.entries() {
            query.admit(root, 1).map_err(Error::Scope)?;
            let node = bound.mapping.node(credential.source().node);
            let mut visiting =
                DependencyVisit::new(credential.source().node, query.execution(), |need| {
                    dependency(need, bound.mapping, index, scope, &open, node, query)
                })
                .map_err(|cause| Error::Resource { node, cause })?;
            let answer = provider.visit(credential, index.index.open(), &reader, |need| {
                visiting.observe(need)
            });
            let dependencies = visiting
                .finish(answer)
                .map_err(|cause| dependency_error(node, cause))?;
            if dependencies.completeness != structured_ltv::material::Completeness::Complete
                || !dependencies.findings.is_empty()
            {
                complete = false;
            }
            entries
                .try_push(Entry { node, dependencies })
                .map_err(|cause| Error::Resource { node, cause })?;
        }
        Ok(())
    };
    if let Some(group) = &credentials.root {
        visit(group)?;
    }
    let mut counter = 0;
    for group in &credentials.counters {
        loop {
            query.admit(root, 1).map_err(Error::Scope)?;
            if counter == basic.counters().len() {
                return Err(Error::Foreign {
                    node: group.signature(),
                });
            }
            let ordinal = counter;
            counter += 1;
            if basic.counters().counter(ordinal).signature != group.signature() {
                continue;
            }
            if required
                .counter_in_scope(ordinal, query)
                .map_err(Error::Obligation)?
            {
                visit(group)?;
            }
            break;
        }
    }
    query.admit(root, 1).map_err(Error::Scope)?;
    Ok(Report {
        credentials,
        scope: required.scope(),
        entries: entries.into_owned(),
        complete,
    })
}

fn dependency_error<N, E>(node: Node, cause: DependencyError<N, Error<E>, E>) -> Error<E> {
    match cause {
        DependencyError::Processing { cause, .. } => cause,
        DependencyError::Resource { cause, .. } => Error::Resource { node, cause },
        DependencyError::Provider { cause, .. } => Error::Provider { node, cause },
        DependencyError::CallbackProtocol { .. } => Error::CallbackProtocol { node },
    }
}
