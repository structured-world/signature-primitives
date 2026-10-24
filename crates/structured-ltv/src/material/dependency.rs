//! Sticky, accounted dependency visitation shared by containing formats.

use super::ArtifactRef;
use crate::source::Location;
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

/// One dependency from the actual credential-format owner.
#[derive(Clone, Copy)]
pub enum Dependency<'value, 'source, N, D, G> {
    /// Exact certificate or status artifact, not a claimed digest/name match.
    Known(ArtifactRef<'value, 'source>),
    /// Actual original schema-open enclosure requiring format interpretation.
    Open(Location<N, D, G>),
    /// The handler established that required material is missing.
    Missing,
}
/// Completed format interpretation, independent of incorporated availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// All actual dependencies were visited and interpreted.
    Complete,
    /// The selected owner cannot interpret this required format.
    Unsupported,
    /// A prefix is not the complete original dependency census.
    Unprocessed,
    /// Readable material is unusable for this actual credential.
    Unusable,
    /// A required value violates its selected format syntax.
    Malformed,
}
/// Original handler failure versus its supplied visitor's unchanged refusal.
#[derive(Debug)]
pub enum VisitError<E, V> {
    /// Original source, resource or format-processing cause.
    Processing(E),
    /// The supplied dependency visitor refused.
    Visitor(V),
}
/// Missing and incorporated-but-uncovered are distinct negative facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// No exact original copy was incorporated.
    Absent,
    /// No exact original copy is inside this archive input.
    Uncovered,
}
/// One original dependency's unavailable required material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    /// Zero-based original dependency visitation ordinal.
    pub dependency: usize,
    /// Original incorporation or coverage cause.
    pub cause: Missing,
}
/// A complete visit's syntax and material findings, retaining no input copies.
pub struct DependencyReport {
    /// Actual handler's completed interpretation.
    pub completeness: Completeness,
    /// Every original missing dependency in visitation order.
    pub findings: OwnedVec<Finding>,
}
/// The supplied visitor refused; its original cause remains in the collector.
#[derive(Debug)]
pub struct DependencyRefused;
/// Refusal terminates the visit without returning a successful prefix.
#[derive(Debug)]
pub enum DependencyError<N, E, P> {
    /// Exact-artifact/source/coverage resolver refused.
    Processing {
        /// Actual original credential.
        node: N,
        /// Original resolver cause.
        cause: E,
    },
    /// Current work or retained report capacity refused before use.
    Resource {
        /// Actual original credential.
        node: N,
        /// Original resource cause.
        cause: MemoryError,
    },
    /// The format owner refused with its opaque original cause.
    Provider {
        /// Actual original credential.
        node: N,
        /// Original provider cause.
        cause: P,
    },
    /// A visitor refusal was returned without an actual refused observation.
    CallbackProtocol {
        /// Actual original credential.
        node: N,
    },
}

/// One synchronous visitor with a private sticky refusal. No dispatch, parser,
/// provider, acquisition or policy is supplied by this collector. The format
/// resolves each dependency against its own sealed whole/archive scope.
pub struct DependencyVisit<'w, N, D, G, W: Work, F, E> {
    node: N,
    work: &'w W,
    resolve: F,
    findings: OwnedVec<Finding, W>,
    ordinal: usize,
    first: Option<DependencyError<N, E, core::convert::Infallible>>,
    source: core::marker::PhantomData<(D, G)>,
}
impl<'w, N: Copy, D, G, W: Work, F, E> DependencyVisit<'w, N, D, G, W, F, E>
where
    F: for<'v, 's> FnMut(Dependency<'v, 's, N, D, G>) -> Result<Option<Missing>, E>,
{
    /// Metadata-only construction, with no allocation or provider call.
    pub fn new(node: N, work: &'w W, resolve: F) -> Result<Self, MemoryError> {
        work.charge_work(1)?;
        Ok(Self {
            node,
            work,
            resolve,
            findings: work.vector(),
            ordinal: 0,
            first: None,
            source: core::marker::PhantomData,
        })
    }
    /// Admits every callback before lookup/copy. A swallowed first refusal
    /// cannot become a complete empty report when the provider returns later.
    pub fn observe(&mut self, need: Dependency<'_, '_, N, D, G>) -> Result<(), DependencyRefused> {
        if self.first.is_some() {
            return Err(DependencyRefused);
        }
        let resource = |cause| DependencyError::Resource {
            node: self.node,
            cause,
        };
        let result = (|| {
            self.work.charge_work(1).map_err(resource)?;
            let dependency = self.ordinal;
            self.ordinal = dependency
                .checked_add(1)
                .ok_or_else(|| resource(MemoryError::WorkExceeded))?;
            if let Some(cause) =
                (self.resolve)(need).map_err(|cause| DependencyError::Processing {
                    node: self.node,
                    cause,
                })?
            {
                self.findings
                    .try_push(Finding { dependency, cause })
                    .map_err(resource)?;
            }
            Ok(())
        })();
        if let Err(cause) = result {
            self.first = Some(cause);
            return Err(DependencyRefused);
        }
        Ok(())
    }
    /// Preserve the first original callback failure before considering the
    /// handler's answer. All temporary prefix storage drops on refusal.
    pub fn finish<P>(
        self,
        answer: Result<Completeness, VisitError<P, DependencyRefused>>,
    ) -> Result<DependencyReport, DependencyError<N, E, P>> {
        if let Some(cause) = self.first {
            return Err(match cause {
                DependencyError::Processing { node, cause } => {
                    DependencyError::Processing { node, cause }
                }
                DependencyError::Resource { node, cause } => {
                    DependencyError::Resource { node, cause }
                }
                DependencyError::CallbackProtocol { node } => {
                    DependencyError::CallbackProtocol { node }
                }
                DependencyError::Provider { cause, .. } => match cause {},
            });
        }
        let completeness = match answer {
            Ok(value) => value,
            Err(VisitError::Processing(cause)) => {
                return Err(DependencyError::Provider {
                    node: self.node,
                    cause,
                });
            }
            Err(VisitError::Visitor(DependencyRefused)) => {
                return Err(DependencyError::CallbackProtocol { node: self.node });
            }
        };
        Ok(DependencyReport {
            completeness,
            findings: self.findings.into_owned(),
        })
    }
}
