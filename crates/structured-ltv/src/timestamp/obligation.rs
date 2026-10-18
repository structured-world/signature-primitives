//! Complete original timestamp obligations for one validation-data scope.

use super::Purpose;
use crate::pki::{CounterReceipts, TimestampPath};
use crate::source::{Location, Query, ScopeError};
use core::marker::PhantomData;
use structured_asn1::memory::OwnedVec;

/// Original source boundary of a set of timestamp obligations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampScope<N, D, G> {
    /// Whole selected signature; no archive-precedence assertion is made.
    All(Location<N, D, G>),
    /// Original archive timestamp, excluding its own and later unsigned tokens.
    BeforeArchive(Location<N, D, G>),
}

impl<N: Copy, D: Copy, G: Copy> TimestampScope<N, D, G> {
    /// Real enclosing signature/archive location for source checks and errors.
    #[must_use]
    pub fn location(self) -> Location<N, D, G> {
        match self {
            Self::All(location) | Self::BeforeArchive(location) => location,
        }
    }
}

/// One original token obligation; this is not a successful timestamp receipt.
#[derive(Debug, Clone, Copy)]
pub struct RequiredToken<N> {
    /// Actual root or nested signature whose input this token covers.
    pub signature: N,
    /// Original timestamp property.
    pub property: N,
    /// Original encapsulated token, independently of its decoded bytes.
    pub token: N,
    /// Kind of input selected for the token, never inferred from success.
    pub purpose: Purpose,
}

/// Complete original token set for one explicit protocol scope. Failed or
/// unreadable tokens cannot disappear behind a caller's successful subset:
/// only the holder of issuer `I` derives it from the original source.
pub struct TimestampRequirements<N, D, G, I> {
    signature: N,
    scope: TimestampScope<N, D, G>,
    entries: OwnedVec<RequiredToken<N>>,
    counters: Option<Counters<N>>,
    issuer: PhantomData<I>,
}

// The complete counter-source census and, for an archive scope, the aligned
// mask of the counters that archive's own input covers.
struct Counters<N> {
    signatures: OwnedVec<N>,
    covered: Option<OwnedVec<bool>>,
}

impl<N: Copy, D: Copy, G: Copy, I> TimestampRequirements<N, D, G, I> {
    /// The complete token obligations of one signature without countersignatures.
    ///
    /// The format layer derives `entries` from every original timestamp in
    /// `scope`, in source order, failed and unsupported ones included.
    #[must_use]
    pub fn new(
        _issuer: I,
        signature: N,
        scope: TimestampScope<N, D, G>,
        entries: OwnedVec<RequiredToken<N>>,
    ) -> Self {
        Self {
            signature,
            scope,
            entries,
            counters: None,
            issuer: PhantomData,
        }
    }

    /// The same obligations including every original countersignature's tokens.
    ///
    /// `signatures` lists every countersignature in source order. For an
    /// archive scope, `covered` marks the ones whose whole element that
    /// archive's own input covers; a later countersignature is not an earlier
    /// actor. A whole-signature scope takes `None`.
    #[must_use]
    pub fn with_counters(
        _issuer: I,
        signature: N,
        scope: TimestampScope<N, D, G>,
        entries: OwnedVec<RequiredToken<N>>,
        signatures: OwnedVec<N>,
        covered: Option<OwnedVec<bool>>,
    ) -> Self {
        Self {
            signature,
            scope,
            entries,
            counters: Some(Counters {
                signatures,
                covered,
            }),
            issuer: PhantomData,
        }
    }

    /// Original selected signature.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Actual whole-signature or preceding-archive scope.
    #[must_use]
    pub fn scope(&self) -> TimestampScope<N, D, G> {
        self.scope
    }
    /// Every original token in prepared property/token order.
    #[must_use]
    pub fn entries(&self) -> &[RequiredToken<N>] {
        &self.entries
    }
}

/// Checked TSA paths for every token in the SAME original scope. No token
/// authentication, temporal acceptance or application trust is repeated here.
pub struct TimestampPaths<'view, 'certificate, 'document, N, D, G, I> {
    required: &'view TimestampRequirements<N, D, G, I>,
    paths: &'view [&'view TimestampPath<'view, 'certificate, 'document, N, D, G, I>],
}

impl<'view, 'certificate, 'document, N, D, G, I>
    TimestampPaths<'view, 'certificate, 'document, N, D, G, I>
{
    /// Complete original token obligations; their scope cannot be relabelled.
    #[must_use]
    pub fn required(&self) -> &'view TimestampRequirements<N, D, G, I> {
        self.required
    }
    /// Actual paths in original obligation order, without copying.
    #[must_use]
    pub fn paths(
        &self,
    ) -> &'view [&'view TimestampPath<'view, 'certificate, 'document, N, D, G, I>] {
        self.paths
    }
}

/// Missing/wrong proofs cannot establish a successful partial token set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampPathFailure {
    /// Every original token requires one actual checked TSA path.
    Count,
    /// A supplied path belongs to a different original token or source.
    Source {
        /// Original obligation ordinal, not an ASN.1 or source offset.
        index: usize,
    },
}

/// Complete path association or explicit insufficient original proofs.
pub enum TimestampPathBinding<'view, 'certificate, 'document, N, D, G, I> {
    /// Every required token has its actual original TSA path.
    Bound(TimestampPaths<'view, 'certificate, 'document, N, D, G, I>),
    /// No complete proof set exists; no successful prefix is returned.
    Unproven(TimestampPathFailure),
}

/// A source, scope or census refusal, not a failed token assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationError<N> {
    /// Current source generation or operation refused.
    Scope(ScopeError<N>),
    /// The query, counter census or mask belongs to another source or scope.
    Foreign {
        /// Original enclosing signature/archive.
        node: N,
    },
}

impl<N> From<ScopeError<N>> for ObligationError<N> {
    fn from(cause: ScopeError<N>) -> Self {
        Self::Scope(cause)
    }
}

/// Association of complete paths with these obligations.
pub type PathBindingResult<'view, 'certificate, 'document, N, D, G, I> =
    Result<TimestampPathBinding<'view, 'certificate, 'document, N, D, G, I>, ObligationError<N>>;

impl<N: Copy + Eq, D: Copy + Eq, G: Copy + Eq, I> TimestampRequirements<N, D, G, I> {
    /// Whether the countersignature at this census ordinal is an actor of this
    /// scope: every counter for the whole signature, only covered ones before
    /// an archive.
    pub fn counter_in_scope<Q: Query<Id = N, Document = D, Generation = G>>(
        &self,
        ordinal: usize,
        query: &Q,
    ) -> Result<bool, ObligationError<N>> {
        let node = self.scope.location().node;
        if self.scope.location().snapshot != query.snapshot() {
            return Err(ObligationError::Foreign { node });
        }
        query.admit(node, 2)?;
        match self.scope {
            TimestampScope::All(_) => Ok(true),
            TimestampScope::BeforeArchive(_) => {
                let Some(covered) = self.counters.as_ref().and_then(|c| c.covered.as_ref()) else {
                    return Err(ObligationError::Foreign { node });
                };
                covered
                    .get(ordinal)
                    .copied()
                    .ok_or(ObligationError::Foreign { node })
            }
        }
    }

    /// Whether these obligations were derived from exactly this counter census.
    pub fn includes_counters<
        'p,
        'd,
        C: CounterReceipts<'p, 'd, Id = N>,
        Q: Query<Id = N, Document = D, Generation = G>,
    >(
        &self,
        counters: &C,
        query: &Q,
    ) -> Result<bool, ScopeError<N>>
    where
        'd: 'p,
    {
        let Some(expected) = &self.counters else {
            return Ok(counters.len() == 0);
        };
        if expected.signatures.len() != counters.len() {
            return Ok(false);
        }
        for (index, expected) in expected.signatures.iter().enumerate() {
            let node = counters.counter(index).signature;
            if !query
                .equal(*expected, node)
                .map_err(|cause| ScopeError::Resource { node, cause })?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Associate actual paths once per original token. The SAME source/purpose
    /// comparison governs all-token LT and preceding-archive requirements.
    /// Paths of another issuer cannot be associated.
    pub fn bind_paths<'view, 'certificate, 'document, Q>(
        &'view self,
        paths: &'view [&'view TimestampPath<'view, 'certificate, 'document, N, D, G, I>],
        query: &Q,
    ) -> PathBindingResult<'view, 'certificate, 'document, N, D, G, I>
    where
        Q: Query<Id = N, Document = D, Generation = G>,
    {
        let location = self.scope.location();
        if location.snapshot != query.snapshot() {
            return Err(ObligationError::Foreign {
                node: location.node,
            });
        }
        // One dispatch plus one unit per pass, as every other scoped query pays.
        query.admit(self.signature, 2)?;
        if paths.len() != self.entries.len() {
            return Ok(TimestampPathBinding::Unproven(TimestampPathFailure::Count));
        }
        let resource = |cause| ScopeError::Resource {
            node: location.node,
            cause,
        };
        for (index, path) in paths.iter().enumerate() {
            query.admit(self.signature, 2)?;
            let expected = &self.entries[index];
            let actual = path.actor().verified();
            if !query
                .equal(actual.signature(), expected.signature)
                .map_err(resource)?
                || !query
                    .equal(actual.property(), expected.property)
                    .map_err(resource)?
                || actual.token().snapshot != location.snapshot
                || !query
                    .equal(actual.token().node, expected.token)
                    .map_err(resource)?
                || actual.purpose() != expected.purpose
            {
                return Ok(TimestampPathBinding::Unproven(
                    TimestampPathFailure::Source { index },
                ));
            }
        }
        Ok(TimestampPathBinding::Bound(TimestampPaths {
            required: self,
            paths,
        }))
    }
}
