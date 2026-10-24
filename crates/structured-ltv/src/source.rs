//! Original source identity shared by every long-term validation fact.

use structured_asn1::memory::{HashWork, MemoryError, Work};

pub use structured_asn1::source::Snapshot;

/// One original node in its exact source generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location<N, D, G> {
    /// Exact original document and generation.
    pub snapshot: Snapshot<D, G>,
    /// Original node, such as an XML element or a CMS attribute.
    pub node: N,
}

/// A source owner's stable identities, independent of its document model.
///
/// An XML owner implements it over element identities, a CMS or PDF owner over
/// its own attribute, object or revision identities. Nothing here reads the
/// source; long-term validation only compares identities and generations.
pub trait Source {
    /// Stable node identity scoped to this document, independent of a borrow.
    /// Its trusted `HashWork` bound covers all hashing/equality bytes so identity
    /// indexes can admit their complete work before querying attacker input.
    type Id: Copy + Eq + HashWork;
    /// Stable document identity.
    type Document: Copy + Eq;
    /// Exact document generation.
    type Generation: Copy + Eq;

    /// Returns identity/generation in constant time, without allocation or I/O.
    fn snapshot(&self) -> Snapshot<Self::Document, Self::Generation>;
}

/// The expected snapshot changed or the current operation refused admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError<N> {
    /// Document identity or generation changed; previous evidence is unusable.
    Changed {
        /// Node associated with the attempted operation.
        node: N,
    },
    /// Admission failed before the operation.
    Resource {
        /// Original node associated with the attempted operation.
        node: N,
        /// Original execution refusal.
        cause: MemoryError,
    },
}

/// One current query over one expected source snapshot.
///
/// Every long-term validation check runs under the query that performs it:
/// retained facts are never prepaid work. A format layer implements this over
/// its own access guard, so its checks and these share one admission path;
/// [`Scope`] implements it over any [`Source`].
pub trait Query {
    /// Original node identity.
    type Id: Copy + Eq + HashWork;
    /// Stable document identity.
    type Document: Copy + Eq;
    /// Exact document generation.
    type Generation: Copy + Eq;
    /// Current execution funding this query.
    type Work: Work;

    /// The expected source snapshot of every fact checked in this query.
    fn snapshot(&self) -> Snapshot<Self::Document, Self::Generation>;

    /// The current execution; storage and work for results are admitted here.
    fn execution(&self) -> &Self::Work;

    /// Requires the live source at the expected snapshot, admits `units` of
    /// work, and requires the snapshot again.
    fn admit(&self, node: Self::Id, units: u64) -> Result<(), ScopeError<Self::Id>>;

    /// Compares two identities after admitting their complete `HashWork`.
    fn equal(&self, left: Self::Id, right: Self::Id) -> Result<bool, MemoryError> {
        equal_id(left, right, self.execution())
    }
}

/// The query of a [`Source`] that has no access guard of its own.
///
/// No clone, allocation or reference-count increment is needed to construct
/// it.
pub struct Scope<'a, S: Source, W: Work> {
    source: &'a S,
    snapshot: Snapshot<S::Document, S::Generation>,
    execution: &'a W,
}

impl<'a, S: Source, W: Work> Scope<'a, S, W> {
    /// Attaches the expected original snapshot and current operation.
    #[must_use]
    pub fn new(
        source: &'a S,
        snapshot: Snapshot<S::Document, S::Generation>,
        execution: &'a W,
    ) -> Self {
        Self {
            source,
            snapshot,
            execution,
        }
    }
}

impl<S: Source, W: Work> Query for Scope<'_, S, W> {
    type Id = S::Id;
    type Document = S::Document;
    type Generation = S::Generation;
    type Work = W;

    fn snapshot(&self) -> Snapshot<S::Document, S::Generation> {
        self.snapshot
    }

    fn execution(&self) -> &W {
        self.execution
    }

    fn admit(&self, node: S::Id, units: u64) -> Result<(), ScopeError<S::Id>> {
        if self.source.snapshot() != self.snapshot {
            return Err(ScopeError::Changed { node });
        }
        self.execution
            .charge_work(units)
            .map_err(|cause| ScopeError::Resource { node, cause })?;
        if self.source.snapshot() != self.snapshot {
            return Err(ScopeError::Changed { node });
        }
        Ok(())
    }
}

/// Compares two identities after admitting their complete `HashWork`.
pub fn equal_id<N: Copy + Eq + HashWork, W: Work>(
    left: N,
    right: N,
    execution: &W,
) -> Result<bool, MemoryError> {
    let cost = left
        .hash_work()?
        .checked_add(right.hash_work()?)
        .ok_or(MemoryError::WorkExceeded)?;
    execution.charge_work(cost)?;
    Ok(left == right)
}
