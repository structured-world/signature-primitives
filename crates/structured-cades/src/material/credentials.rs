//! Format-owner dependencies of every authenticated original credential.
//!
//! Reuses the original-artifact/coverage LTV core. Authentication receipts are
//! borrowed, never reconstructed from a public boolean or replayed signature.

use super::{Index, Open};
use crate::{
    Cades,
    counters::Paths,
    credential::{Checked, Complete},
    source::{DocumentId, Node, Original},
    timestamp::ArchiveChecked,
};
use structured_asn1::{
    Reader,
    memory::{MemoryError, OwnedMap, OwnedVec, Work},
};
use structured_ltv::{
    baseline::CredentialMaterial,
    material::{ArchiveError, Archived, ArtifactRef, IndexError},
    pki::{CounterReceipts, CredentialReceipts},
    source::{Query, Snapshot},
    timestamp::{ObligationError, TimestampRequirements, TimestampScope},
};

/// One dependency established by the credential's actual format owner.
#[derive(Clone, Copy)]
pub enum Need<'value, 'source, 'model, 'document> {
    /// Known certificate, complete CRL/delta, or whole carried OCSP artifact.
    Known(ArtifactRef<'value, 'source>),
    /// Exact original open catalogue enclosure, interpreted by that owner.
    Open(Original<'model, 'document>),
    /// A required dependency has no matching original material.
    Missing,
}

/// Completed format interpretation, separate from incorporated availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// Every actual dependency was visited and its format semantics checked.
    Complete,
    /// Selected handler cannot interpret the required format.
    Unsupported,
    /// A prefix is not a complete dependency census.
    Unprocessed,
    /// Readable material is unusable for this credential.
    Unusable,
    /// A required value violates its selected format syntax.
    Malformed,
}

/// Original handler refusal versus a visitor's unchanged refusal.
#[derive(Debug)]
pub enum VisitError<E, V> {
    /// Original format/source/resource cause.
    Processing(E),
    /// The supplied dependency visitor refused.
    Visitor(V),
}

/// Same format owner as authentication, using its actual retained evidence.
/// It discovers ALL credential-specific validation material, including the
/// credential's own status, using current Work before decoding/copy/allocation
/// or arithmetic. Certificate-free authentication does not waive this step.
/// EN319122-1 §§5.2.6.1, 5.4 and 6.3 require credential validation data in
/// addition to the issuer's X.509 path/status.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf>
pub trait Provider<E> {
    /// Original processing/resource cause, not a negative completeness result.
    type Error;
    /// Visit dependencies once without reauthenticating or acquiring sources.
    fn visit<'m, 'd, V>(
        &self,
        credential: &Checked<'m, 'd, '_, E>,
        open: &[Open<'d>],
        operation: &Reader<'d>,
        visitor: impl for<'value, 'source> FnMut(Need<'value, 'source, 'm, 'd>) -> Result<(), V>,
    ) -> Result<Completeness, VisitError<Self::Error, V>>;
}

/// Missing original copy and present-but-uncovered copy are distinct facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// No exact original copy exists.
    Absent,
    /// No exact copy is protected by this archive.
    Uncovered,
}

/// One missing dependency in original handler visitation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    /// Actual zero-based dependency ordinal.
    pub dependency: usize,
    /// Original incorporation or coverage cause.
    pub cause: Missing,
}

/// Actual authenticated credential, including all negative material facts.
pub struct Entry<'model, 'document> {
    source: Original<'model, 'document>,
    completeness: Completeness,
    findings: OwnedVec<Finding>,
}
impl<'m, 'd> Entry<'m, 'd> {
    /// Original protected credential enclosure.
    #[must_use]
    pub fn source(&self) -> Original<'m, 'd> {
        self.source
    }
    /// Actual format interpretation rather than successful copy lookup.
    #[must_use]
    pub fn completeness(&self) -> Completeness {
        self.completeness
    }
    /// All missing dependencies, preserving original visitation order.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}

/// Same complete credential receipt under one whole/archive source scope.
pub struct Report<'auth, 'receipt, 'model, 'document, 'path, E> {
    credentials: &'auth Complete<'receipt, 'model, 'document, 'path, E>,
    scope: TimestampScope<Node, DocumentId<'model, 'document>, ()>,
    entries: OwnedVec<Entry<'model, 'document>>,
    complete: bool,
}
impl<'m, 'd, E> Report<'_, '_, 'm, 'd, '_, E> {
    /// Every original credential required by this exact source scope.
    #[must_use]
    pub fn entries(&self) -> &[Entry<'m, 'd>] {
        &self.entries
    }
    /// Complete interpretation AND original incorporation/coverage.
    #[must_use]
    pub fn all_requirements_met(&self) -> bool {
        self.complete
    }
}
impl<'r, 'm, 'd, 'p, E> CredentialMaterial for Report<'_, 'r, 'm, 'd, 'p, E> {
    type Id = Node;
    type Document = DocumentId<'m, 'd>;
    type Generation = ();
    type Credentials = Complete<'r, 'm, 'd, 'p, E>;
    fn scope(&self) -> TimestampScope<Node, Self::Document, ()> {
        self.scope
    }
    fn snapshot(&self) -> Snapshot<Self::Document, ()> {
        self.credentials.snapshot()
    }
    fn credentials(&self) -> &Self::Credentials {
        self.credentials
    }
    fn all_requirements_met(&self) -> bool {
        self.complete
    }
}

/// A source/handler/resource failure never returns a successful partial report.
#[derive(Debug)]
pub enum Error<E> {
    /// Another document, signature, incomplete counter set or archive context.
    Foreign {
        /// Actual selecting enclosure.
        node: Node,
    },
    /// Original parser/current-operation refusal.
    Processing(crate::Error),
    /// Original full counter/scope membership refusal.
    Obligation(ObligationError<Node>),
    /// Exact original indexed lookup refused.
    Index(IndexError<Node>),
    /// Archive evidence or covered lookup refused.
    Archive(ArchiveError<Node>),
    /// Actual credential handler refused with its original cause.
    Provider {
        /// Original protected credential.
        node: Node,
        /// Unchanged opaque cause.
        cause: E,
    },
    /// Current work or retained report capacity refused before use.
    Resource {
        /// Original selecting enclosure.
        node: Node,
        /// Actual admission failure.
        cause: MemoryError,
    },
    /// Handler returned a visitor refusal without an actual refused callback.
    CallbackProtocol {
        /// Original credential enclosure.
        node: Node,
    },
}

/// Optional archive proof. Whole mode cannot impersonate a preceding archive;
/// construction retains the actual token's private mathematical receipt.
pub struct Scope<'a, 'm, 'd, 'p> {
    archive: Option<&'a ArchiveChecked<'m, 'd, 'p>>,
}
impl<'a, 'm, 'd, 'p> Scope<'a, 'm, 'd, 'p> {
    /// Whole original incorporation without archive implications.
    #[must_use]
    pub fn whole() -> Self {
        Self { archive: None }
    }
    /// Original archive whose exact input must cover the dependencies.
    #[must_use]
    pub fn before_archive(archive: &'a ArchiveChecked<'m, 'd, 'p>) -> Self {
        Self {
            archive: Some(archive),
        }
    }
    fn require<E, Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>, W: Work>(
        &self,
        required: &TimestampRequirements<Node, DocumentId<'m, 'd>, (), Cades>,
        index: &Index<'_, 'm, 'd, W>,
        query: &Q,
    ) -> Result<(), Error<E>> {
        let location = required.scope().location();
        if location.snapshot != query.snapshot() {
            return Err(Error::Foreign {
                node: location.node,
            });
        }
        index
            .require_signature(required.signature(), query)
            .map_err(Error::Index)?;
        match (required.scope(), self.archive) {
            (TimestampScope::All(_), None) => Ok(()),
            (TimestampScope::BeforeArchive(_), Some(archive)) => {
                let actor = archive.timestamp().actor().ok_or(Error::Foreign {
                    node: location.node,
                })?;
                let evidence = actor.verified();
                query
                    .admit(location.node, 3)
                    .map_err(|cause| Error::Index(IndexError::Scope(cause)))?;
                if evidence.signature() != required.signature()
                    || evidence.property() != location.node
                    || evidence.token().snapshot != location.snapshot
                {
                    return Err(Error::Foreign {
                        node: location.node,
                    });
                }
                archive
                    .coverage()
                    .require_evidence(evidence, location.node, query)
                    .map_err(|cause| Error::Archive(ArchiveError::Coverage(cause)))
            }
            _ => Err(Error::Foreign {
                node: location.node,
            }),
        }
    }
    fn missing<E, Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>, W: Work>(
        &self,
        need: Need<'_, '_, 'm, 'd>,
        index: &Index<'_, 'm, 'd, W>,
        open: &OwnedMap<Node, (), Q::Work>,
        query: &Q,
    ) -> Result<Option<Missing>, Error<E>> {
        match need {
            Need::Missing => Ok(Some(Missing::Absent)),
            Need::Known(artifact) => {
                if let Some(archive) = self.archive {
                    let actor = archive.timestamp().actor().ok_or(Error::Foreign {
                        node: index.signature(),
                    })?;
                    return index
                        .archived(artifact, archive.coverage(), actor.verified(), query)
                        .map(|answer| match answer {
                            Archived::Present(_) => None,
                            Archived::Missing => Some(Missing::Absent),
                            Archived::Uncovered => Some(Missing::Uncovered),
                        })
                        .map_err(Error::Archive);
                }
                let mut copies = index.artifact(artifact, query).map_err(Error::Index)?;
                copies
                    .next()
                    .transpose()
                    .map(|value| {
                        if value.is_some() {
                            None
                        } else {
                            Some(Missing::Absent)
                        }
                    })
                    .map_err(Error::Index)
            }
            Need::Open(location) => {
                if location.snapshot != query.snapshot() {
                    return Err(Error::Foreign {
                        node: location.node,
                    });
                }
                if open
                    .get(&location.node, query.execution())
                    .map_err(|cause| Error::Resource {
                        node: location.node,
                        cause,
                    })?
                    .is_none()
                {
                    return Ok(Some(Missing::Absent));
                }
                if let Some(archive) = self.archive {
                    let actor = archive.timestamp().actor().ok_or(Error::Foreign {
                        node: location.node,
                    })?;
                    return archive
                        .coverage()
                        .covers(actor.verified(), location.node, query)
                        .map(|covered| {
                            if covered {
                                None
                            } else {
                                Some(Missing::Uncovered)
                            }
                        })
                        .map_err(|cause| Error::Archive(ArchiveError::Coverage(cause)));
                }
                Ok(None)
            }
        }
    }
}

/// Check the complete original credential scope, using actual format receipts
/// and the shared exact-artifact index. A swallowed callback failure remains
/// terminal; later provider success cannot turn it into an empty complete set.
pub fn check<'a, 'r, 'm, 'd, 'p, E, P: Provider<E>, W: Work>(
    credentials: &'a Complete<'r, 'm, 'd, 'p, E>,
    counters: &Paths<'_, 'm, 'd, 'p>,
    required: &TimestampRequirements<Node, DocumentId<'m, 'd>, (), Cades>,
    index: &Index<'_, 'm, 'd, W>,
    scope: &Scope<'_, 'm, 'd, '_>,
    provider: &P,
    operation: &Reader<'d>,
) -> Result<Report<'a, 'r, 'm, 'd, 'p, E>, Error<P::Error>> {
    let document = credentials.snapshot().document.source();
    document
        .message()
        .require_session(operation, "cades.credential.material")
        .map_err(|cause| Error::Processing(crate::Error::Cms(cause)))?;
    let execution = operation.execution();
    let query = &structured_ltv::source::Scope::new(&document, credentials.snapshot(), &execution);
    scope.require(required, index, query)?;
    let node = credentials.signature();
    query
        .admit(node, 3)
        .map_err(|cause| Error::Index(IndexError::Scope(cause)))?;
    if credentials.snapshot() != query.snapshot()
        || counters.snapshot() != query.snapshot()
        || node != required.signature()
        || node != counters.signature()
    {
        return Err(Error::Foreign { node });
    }
    required
        .includes_counters(counters, query)
        .map_err(|cause| Error::Index(IndexError::Scope(cause)))?;
    let work = query.execution();
    let mut open = work.map();
    for entry in index.open() {
        work.charge_work(1).map_err(|cause| Error::Resource {
            node: entry.node,
            cause,
        })?;
        open.try_insert(entry.node, ())
            .map_err(|cause| Error::Resource {
                node: entry.node,
                cause,
            })?;
    }
    let mut selected = work.vector();
    for entry in credentials.report.root() {
        selected
            .try_push(entry)
            .map_err(|cause| Error::Resource { node, cause })?;
    }
    let mut group = 0;
    for ordinal in 0..counters.len() {
        work.charge_work(2)
            .map_err(|cause| Error::Resource { node, cause })?;
        let Some((signature, entries)) = credentials
            .report
            .counter(group, work)
            .map_err(|cause| Error::Resource { node, cause })?
        else {
            break;
        };
        if signature != counters.counter(ordinal).signature {
            continue;
        }
        if required
            .counter_in_scope(ordinal, query)
            .map_err(Error::Obligation)?
        {
            for entry in entries {
                selected
                    .try_push(entry)
                    .map_err(|cause| Error::Resource { node, cause })?;
            }
        }
        group += 1;
    }
    if group != credentials.report.counters() {
        return Err(Error::Foreign { node });
    }
    let mut entries = work.vector();
    entries
        .try_reserve_exact(selected.len())
        .map_err(|cause| Error::Resource { node, cause })?;
    let mut complete = true;
    for credential in selected {
        let entry = one(credential, index, scope, provider, operation, query, &open)?;
        if entry.completeness != Completeness::Complete || !entry.findings.is_empty() {
            complete = false;
        }
        entries
            .try_push(entry)
            .map_err(|cause| Error::Resource { node, cause })?;
    }
    query
        .admit(node, 1)
        .map_err(|cause| Error::Index(IndexError::Scope(cause)))?;
    Ok(Report {
        credentials,
        scope: required.scope(),
        entries: entries.into_owned(),
        complete,
    })
}

fn one<'m, 'd, E, P: Provider<E>, Q, W: Work>(
    credential: &Checked<'m, 'd, '_, E>,
    index: &Index<'_, 'm, 'd, W>,
    scope: &Scope<'_, 'm, 'd, '_>,
    provider: &P,
    operation: &Reader<'d>,
    query: &Q,
    open: &OwnedMap<Node, (), Q::Work>,
) -> Result<Entry<'m, 'd>, Error<P::Error>>
where
    Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
{
    let work = query.execution();
    let node = credential.source().node;
    let mut findings = work.vector();
    let mut ordinal = 0usize;
    let mut first = None;
    let answer = provider.visit(credential, index.open(), operation, |need| {
        if first.is_some() {
            return Err(());
        }
        let answer = (|| {
            work.charge_work(1)
                .map_err(|cause| Error::Resource { node, cause })?;
            let dependency = ordinal;
            ordinal = ordinal.checked_add(1).ok_or(Error::Resource {
                node,
                cause: MemoryError::WorkExceeded,
            })?;
            if let Some(cause) = scope.missing(need, index, open, query)? {
                findings
                    .try_push(Finding { dependency, cause })
                    .map_err(|cause| Error::Resource { node, cause })?;
            }
            Ok(())
        })();
        match answer {
            Ok(()) => Ok(()),
            Err(cause) => {
                first = Some(cause);
                Err(())
            }
        }
    });
    if let Some(cause) = first {
        return Err(cause);
    }
    let completeness = match answer {
        Ok(value) => value,
        Err(VisitError::Processing(cause)) => return Err(Error::Provider { node, cause }),
        Err(VisitError::Visitor(())) => return Err(Error::CallbackProtocol { node }),
    };
    Ok(Entry {
        source: credential.source(),
        completeness,
        findings: findings.into_owned(),
    })
}
