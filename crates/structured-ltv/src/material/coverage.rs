//! Original whole items covered by one checked timestamp input.

use crate::source::{Query, ScopeError, Snapshot, equal_id};
use crate::timestamp::{Purpose, Verified};
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, Work};

/// The original items one timestamp's prepared input covers in their entirety.
///
/// The format layer builds it from the same input selection its token check
/// used: `XAdES` from canonicalized elements, `CAdES` from `ats-hash-index-v3`.
/// Transformed or partial input grants no whole-item coverage. Selection alone
/// does not establish that the timestamp was checked.
pub struct Coverage<N: HashWork, D, G, W: Work> {
    snapshot: Snapshot<D, G>,
    signature: N,
    timestamp: N,
    purpose: Purpose,
    items: OwnedMap<N, bool, W>,
}

/// Source/current admission and foreign evidence are independent of absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageError<N> {
    /// Source generation or current operation refused.
    Scope(ScopeError<N>),
    /// Item index storage/work was not admitted.
    Resource {
        /// Original root/input node whose admission failed.
        node: N,
        /// Original capacity/work refusal.
        cause: MemoryError,
    },
    /// Input/evidence/current view refer to different signature/property/source.
    Foreign {
        /// Original requested item.
        node: N,
    },
}

impl<N: Copy + Eq + HashWork, D: Copy + Eq, G: Copy + Eq, W: Work> Coverage<N, D, G, W> {
    /// The coverage of one timestamp's input over `signature`.
    ///
    /// `items` maps each visited original item to whether it is itself a whole
    /// covered item; a `false` entry records a visited container that carries
    /// covered descendants but is not an item claim.
    #[must_use]
    pub fn new(
        snapshot: Snapshot<D, G>,
        signature: N,
        timestamp: N,
        purpose: Purpose,
        items: OwnedMap<N, bool, W>,
    ) -> Self {
        Self {
            snapshot,
            signature,
            timestamp,
            purpose,
            items,
        }
    }

    /// Tests prepared whole-item selection under a current source query.
    /// True alone is not proof that any timestamp was mathematically checked.
    pub fn selects<Q: Query<Id = N, Document = D, Generation = G>>(
        &self,
        node: N,
        query: &Q,
    ) -> Result<bool, CoverageError<N>> {
        if self.snapshot != query.snapshot() {
            return Err(CoverageError::Foreign { node });
        }
        query.admit(node, 1).map_err(CoverageError::Scope)?;
        self.items
            .get(&node, query.execution())
            .map(|value| value == Some(&true))
            .map_err(|cause| CoverageError::Resource { node, cause })
    }

    /// Binds item selection to the successful token evidence for this exact
    /// original input. This establishes mathematical coverage only;
    /// TSA/path/status/chronology acceptance remains separate.
    pub fn covers<Q: Query<Id = N, Document = D, Generation = G>>(
        &self,
        evidence: &Verified<N, D, G>,
        node: N,
        query: &Q,
    ) -> Result<bool, CoverageError<N>> {
        self.require_evidence(evidence, node, query)?;
        self.selects(node, query)
    }

    /// Requires `evidence` to be the checked token of exactly this input.
    pub fn require_evidence<Q: Query<Id = N, Document = D, Generation = G>>(
        &self,
        evidence: &Verified<N, D, G>,
        node: N,
        query: &Q,
    ) -> Result<(), CoverageError<N>> {
        if self.snapshot != query.snapshot() {
            return Err(CoverageError::Foreign { node });
        }
        query.admit(node, 1).map_err(CoverageError::Scope)?;
        self.require_identity(
            evidence.token().snapshot,
            evidence.signature(),
            evidence.property(),
            evidence.purpose(),
            node,
            query.execution(),
        )
    }

    fn require_identity<Q: Work>(
        &self,
        snapshot: Snapshot<D, G>,
        signature: N,
        timestamp: N,
        purpose: Purpose,
        node: N,
        execution: &Q,
    ) -> Result<(), CoverageError<N>> {
        let resource = |cause| CoverageError::Resource { node, cause };
        if snapshot != self.snapshot
            || !equal_id(signature, self.signature, execution).map_err(resource)?
            || !equal_id(timestamp, self.timestamp, execution).map_err(resource)?
            || purpose != self.purpose
        {
            return Err(CoverageError::Foreign { node });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
