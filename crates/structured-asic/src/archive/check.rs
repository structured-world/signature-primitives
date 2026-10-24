//! Exact existing timestamp receipts, independent of historical trust/material.

use super::{Error, Graph, OwnedVec, RangeSource, ResultOf, Work, resource};
use crate::{references::DigestReading, timestamp};
use structured_xades::certificate::Agreement;

/// Original timestamp occurrence has no successful-subset projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampState {
    /// This original occurrence has no exact completed receipt.
    Unchecked,
    /// Completed common checking did not establish mathematical evidence.
    Failed,
    /// Actual common mathematics covers this exact original manifest input.
    Proven,
}
/// Declared source hashes are independent of timestamp mathematics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectsState {
    /// Original object instructions were not executed.
    Unchecked,
    /// A declared hash or exact whole-input association was negative/incomplete.
    Failed,
    /// Every original declared object hash matched its actual source pass.
    Matches,
}
/// One original manifest/TST participant, preserving its complete common result.
pub struct TimestampCheck<'r, 'd, D, G> {
    node: usize,
    receipt: Option<&'r timestamp::Checked<'d, D, G>>,
    timestamp: TimestampState,
    objects: ObjectsState,
}
impl<'r, 'd, D: Copy, G: Copy> TimestampCheck<'r, 'd, D, G> {
    /// Original graph node index, never success/date order.
    #[must_use]
    pub fn node(&self) -> usize {
        self.node
    }
    /// Actual exact-input result, including all negative common facts.
    #[must_use]
    pub fn receipt(&self) -> Option<&'r timestamp::Checked<'d, D, G>> {
        self.receipt
    }
    /// Completed timestamp mathematics only, independent of historical trust.
    #[must_use]
    pub fn timestamp(&self) -> TimestampState {
        self.timestamp
    }
    /// Every original XML object declaration, independently of the TST result.
    #[must_use]
    pub fn objects(&self) -> ObjectsState {
        self.objects
    }
}

/// Whole original archive census and exact mathematical/input associations.
/// This is NOT validation-material completeness, historical `PoE`, trusted TSA
/// status, algorithm longevity, or an attained container/signature B level.
pub struct Mathematics<'g, 'r, 'd, 'v, 's, N, D, G, S: RangeSource> {
    graph: &'g Graph<'v, 's, N, D, G, S>,
    checks: OwnedVec<TimestampCheck<'r, 'd, S::Document, S::Generation>>,
    all_math: bool,
    all_objects: bool,
}
impl<'g, 'r, 'd, 'v, 's, N: Copy, D: Copy + Eq, G: Copy + Eq, S: RangeSource>
    Mathematics<'g, 'r, 'd, 'v, 's, N, D, G, S>
{
    /// Exact immutable graph used for this operation.
    #[must_use]
    pub fn graph(&self) -> &'g Graph<'v, 's, N, D, G, S> {
        self.graph
    }
    /// EVERY original node, including uninspected/missing/failed participants.
    #[must_use]
    pub fn checks(&self) -> &[TimestampCheck<'r, 'd, S::Document, S::Generation>] {
        &self.checks
    }
    /// All actual original TSTs established mathematics on their exact input.
    #[must_use]
    pub fn all_timestamp_math(&self) -> bool {
        self.all_math
    }
    /// All original XML declarations were checked and matched actual objects.
    #[must_use]
    pub fn all_object_digests(&self) -> bool {
        self.all_objects
    }
}

impl<'v, 's, N: Copy, D: Copy + Eq, G: Copy + Eq, S: RangeSource> Graph<'v, 's, N, D, G, S> {
    /// Joins only actual closed common TST receipts, requiring BOTH token and
    /// consumed-input identities. A separately checked arbitrary manifest or a
    /// later successful subset cannot fill another original occurrence.
    pub fn bind_timestamps<'g, 'r, 'd, W: Work>(
        &'g self,
        supplied: &[&'r timestamp::Checked<'d, S::Document, S::Generation>],
        work: &W,
    ) -> ResultOf<Mathematics<'g, 'r, 'd, 'v, 's, N, D, G, S>, S> {
        let execution = self.archive.session().query(work);
        self.archive
            .admit(&execution, self.archive.directory_span())
            .map_err(Error::Archive)?;
        let refusal = |cause| Error::Archive(resource(self.archive.directory_span(), cause));
        // Validate every supplied occurrence before allocation or selection.
        for check in supplied {
            self.archive
                .original(check.token(), &execution)
                .map_err(Error::Archive)?;
            self.archive
                .original(check.input(), &execution)
                .map_err(Error::Archive)?;
        }
        let mut by_input = execution.map();
        for (index, check) in supplied.iter().enumerate() {
            if by_input
                .try_insert((check.token().ordinal(), check.input().ordinal()), index)
                .map_err(refusal)?
                .is_some()
            {
                return Err(Error::DuplicateTimestamp(check.token()));
            }
        }
        let mut checks = execution.vector();
        checks
            .try_reserve_exact(self.nodes.len())
            .map_err(refusal)?;
        let mut all_math = !self.nodes.is_empty();
        let mut all_objects = !self.nodes.is_empty();
        for (index, node) in self.nodes.iter().enumerate() {
            let receipt = match node.timestamp {
                Some(token) => by_input
                    .get(&(token.ordinal(), node.member.ordinal()), &execution)
                    .map_err(refusal)?
                    .map(|index| supplied[*index]),
                None => None,
            };
            execution.charge_work(1).map_err(refusal)?;
            let timestamp = match receipt {
                None => TimestampState::Unchecked,
                Some(check) => {
                    if check.common().evidence().is_some() {
                        TimestampState::Proven
                    } else {
                        TimestampState::Failed
                    }
                }
            };
            let objects = match node
                .facts
                .and_then(|index| self.facts[index].object_digests())
            {
                None => ObjectsState::Unchecked,
                Some(answers) => {
                    let mut matched = !answers.is_empty();
                    for answer in answers {
                        execution.charge_work(1).map_err(refusal)?;
                        if *answer != DigestReading::Checked(Agreement::Matches) {
                            matched = false;
                        }
                    }
                    if matched {
                        ObjectsState::Matches
                    } else {
                        ObjectsState::Failed
                    }
                }
            };
            if timestamp != TimestampState::Proven {
                all_math = false;
            }
            if objects != ObjectsState::Matches {
                all_objects = false;
            }
            checks
                .try_push(TimestampCheck {
                    node: index,
                    receipt,
                    timestamp,
                    objects,
                })
                .map_err(refusal)?;
        }
        self.archive
            .admit(&execution, self.archive.directory_span())
            .map_err(Error::Archive)?;
        Ok(Mathematics {
            graph: self,
            checks: checks.into_owned(),
            all_math,
            all_objects,
        })
    }
}
