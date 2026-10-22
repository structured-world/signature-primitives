//! Original whole items covered by one checked timestamp input.

use crate::source::{Query, ScopeError, Snapshot, equal_id};
use crate::timestamp::{Purpose, Verified};
use core::marker::PhantomData;
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, Work};

/// The original items one timestamp's prepared input covers in their entirety.
///
/// The format layer builds it from the same input selection its token check
/// used: `XAdES` from canonicalized elements, `CAdES` from `ats-hash-index-v3`.
/// Transformed or partial input grants no whole-item coverage. Selection alone
/// does not establish that the timestamp was checked. Only the holder of issuer
/// `I` builds it, and it binds only evidence of the same issuer.
pub struct Coverage<N: HashWork, D, G, W: Work, I> {
    snapshot: Snapshot<D, G>,
    signature: N,
    timestamp: N,
    token: Option<N>,
    purpose: Purpose,
    items: OwnedMap<N, bool, W>,
    issuer: PhantomData<I>,
}

#[derive(Clone, Copy)]
struct Identity<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    property: N,
    token: N,
    purpose: Purpose,
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
    /// Input/evidence/current view refer to different signature/property/token/source.
    Foreign {
        /// Original requested item.
        node: N,
    },
}

impl<N: Copy + Eq + HashWork, D: Copy + Eq, G: Copy + Eq, W: Work, I> Coverage<N, D, G, W, I> {
    /// Coverage shared by every checked token of ONE property over `signature`.
    /// The format issuer must establish that all those token values use the
    /// SAME original input selection (for example `XAdES` property-defined input).
    /// Use [`Self::for_token`] when selection depends on a particular member,
    /// as it does for successive historical `CAdES` archives in one Attribute.
    ///
    /// `items` maps each visited original item to whether it is itself a whole
    /// covered item; a `false` entry records a visited container that carries
    /// covered descendants but is not an item claim. Requiring the issuer value
    /// keeps a caller of the format from supplying a fabricated selection.
    #[must_use]
    pub fn new(
        _issuer: I,
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
            token: None,
            purpose,
            items,
            issuer: PhantomData,
        }
    }

    /// Exact token-bound selection when sibling tokens of the same property
    /// have DIFFERENT inputs. Another sibling's valid proof cannot authenticate
    /// this selection merely because its property, signature and source match.
    #[must_use]
    pub fn for_token(
        issuer: I,
        snapshot: Snapshot<D, G>,
        signature: N,
        property: N,
        token: N,
        purpose: Purpose,
        items: OwnedMap<N, bool, W>,
    ) -> Self {
        let mut result = Self::new(issuer, snapshot, signature, property, purpose, items);
        result.token = Some(token);
        result
    }

    /// Original identity of this input selection for material/census joins.
    /// Member-specific inputs use the TOKEN node, while a property-shared
    /// selection uses the property. Matching only the enclosing property would
    /// conflate successive archives carried by one multivalued Attribute.
    #[must_use]
    pub fn subject(&self) -> N {
        match self.token {
            Some(token) => token,
            None => self.timestamp,
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
        evidence: &Verified<N, D, G, I>,
        node: N,
        query: &Q,
    ) -> Result<bool, CoverageError<N>> {
        self.require_evidence(evidence, node, query)?;
        self.selects(node, query)
    }

    /// Requires `evidence` to be the checked token of exactly this input.
    pub fn require_evidence<Q: Query<Id = N, Document = D, Generation = G>>(
        &self,
        evidence: &Verified<N, D, G, I>,
        node: N,
        query: &Q,
    ) -> Result<(), CoverageError<N>> {
        if self.snapshot != query.snapshot() {
            return Err(CoverageError::Foreign { node });
        }
        query.admit(node, 1).map_err(CoverageError::Scope)?;
        self.require_identity(
            Identity {
                snapshot: evidence.token().snapshot,
                signature: evidence.signature(),
                property: evidence.property(),
                token: evidence.token().node,
                purpose: evidence.purpose(),
            },
            node,
            query.execution(),
        )
    }

    fn require_identity<Q: Work>(
        &self,
        identity: Identity<N, D, G>,
        node: N,
        execution: &Q,
    ) -> Result<(), CoverageError<N>> {
        let resource = |cause| CoverageError::Resource { node, cause };
        if identity.snapshot != self.snapshot
            || !equal_id(identity.signature, self.signature, execution).map_err(resource)?
            || !equal_id(identity.property, self.timestamp, execution).map_err(resource)?
            || identity.purpose != self.purpose
        {
            return Err(CoverageError::Foreign { node });
        }
        if let Some(token) = self.token
            && !equal_id(identity.token, token, execution).map_err(resource)?
        {
            return Err(CoverageError::Foreign { node });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
