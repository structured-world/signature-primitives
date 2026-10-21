//! Per-source evidence and qualified absence coverage; no cache or fetcher.

use super::{
    Authenticated, BoundDelta, CombinedEntry, EntryLookup, Freshness, Reasons, RevocationTarget,
    ScopeFailure, ScopeOutcome,
};
use crate::temporal::{LeapTable, Reading};
use crate::{Certificate, Result, oid};
use structured_asn1::memory::{Memory, OwnedVec, Work};

/// Caller-provided acquisition fact for RFC5280 §6.3.3(a)'s endpoint rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceOrigin {
    /// Already cached source: only time strictly after nextUpdate needs refresh.
    Cached,
    /// Newly obtained replacement: nextUpdate must be strictly after now.
    Replacement,
}

/// Temporal/resource inputs, without a clock, fetching or age-policy defaults.
pub struct Evaluation<'p, E: Work = Memory> {
    /// Current caller-provided label, retaining subnanosecond precision.
    pub now: Reading,
    /// Complete authenticated UTC facts and explicit coverage supplied by caller.
    pub utc: &'p LeapTable<'p>,
    /// Current shared operation domain.
    pub execution: &'p E,
    /// Acquisition fact for the complete or updating delta source.
    pub origin: SourceOrigin,
}

/// Original authenticated complete/delta sources. This source descriptor alone
/// does not assert applicability, freshness or established absence coverage.
#[derive(Debug, Clone, Copy)]
pub enum EvidenceSource<'r, 'a> {
    /// Authenticated complete source.
    Complete(Authenticated<'r, 'a>),
    /// Authenticated and metadata-bound original pair; no reconstructed CRL.
    Delta {
        /// Original complete CRL.
        base: Authenticated<'r, 'a>,
        /// Original updating delta CRL.
        delta: Authenticated<'r, 'a>,
    },
}

/// Absence established for these reasons only. It is not a certificate trust
/// verdict. Sources were scoped, time-qualified and fully checked for critical
/// demands and entry conflicts before this private constructor could run.
#[derive(Debug)]
pub struct AbsenceEvidence<'r, 'a, T = Certificate<'a>> {
    target: &'r T,
    now: Reading,
    reasons: Reasons,
    source: EvidenceSource<'r, 'a>,
}
impl<T> Copy for AbsenceEvidence<'_, '_, T> {}
impl<T> Clone for AbsenceEvidence<'_, '_, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'r, 'a, T> AbsenceEvidence<'r, 'a, T> {
    /// Actual original certificate whose status was processed. This association
    /// comes from the same evaluation, not a later caller-supplied target.
    #[must_use]
    pub fn target(self) -> &'r T {
        self.target
    }
    /// Exact evaluation label, including its subnanosecond remainder.
    #[must_use]
    pub fn evaluated_at(self) -> Reading {
        self.now
    }
    /// Original sources, retaining exact signed-range provenance.
    #[must_use]
    pub fn source(self) -> EvidenceSource<'r, 'a> {
        self.source
    }
    /// Qualified reasons, potentially less than all reasons.
    #[must_use]
    pub fn reasons(self) -> Reasons {
        self.reasons
    }
}

fn current(freshness: Freshness, origin: SourceOrigin) -> bool {
    freshness == Freshness::Current
        || (freshness == Freshness::AtNextUpdate && origin == SourceOrigin::Cached)
}

/// Completed facts for one applicable authenticated complete CRL.
#[derive(Debug)]
pub struct CompleteFacts<'b, 'r, 'a, T = Certificate<'a>> {
    target: &'r T,
    now: Reading,
    source: &'b Authenticated<'r, 'a>,
    reasons: Reasons,
    freshness: Freshness,
    origin: SourceOrigin,
    entry: EntryLookup<'r, 'a>,
}
impl<T> Copy for CompleteFacts<'_, '_, '_, T> {}
impl<T> Clone for CompleteFacts<'_, '_, '_, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'b, 'r, 'a, T> CompleteFacts<'b, 'r, 'a, T> {
    /// Original certificate whose applicability and entries were evaluated,
    /// including negative, stale or conflicting outcomes without absence.
    #[must_use]
    pub fn target(self) -> &'r T {
        self.target
    }
    /// Exact original evaluation label, independent of its temporary context.
    #[must_use]
    pub fn evaluated_at(self) -> Reading {
        self.now
    }
    /// Original authenticated source.
    #[must_use]
    pub fn source(self) -> &'b Authenticated<'r, 'a> {
        self.source
    }
    /// Applicable reason scope, not yet a non-revocation claim.
    #[must_use]
    pub fn reasons(self) -> Reasons {
        self.reasons
    }
    /// UTC-qualified update facts, including unknown/missing expiry.
    #[must_use]
    pub fn freshness(self) -> Freshness {
        self.freshness
    }
    /// Full-list entry outcome, including unsupported/conflicting demands.
    #[must_use]
    pub fn entry(self) -> EntryLookup<'r, 'a> {
        self.entry
    }
    /// Mint qualified absence only for a usable update window and actual
    /// absence. Missing nextUpdate never creates an implicit expiry policy.
    #[must_use]
    pub fn absence(self) -> Option<AbsenceEvidence<'r, 'a, T>> {
        if !current(self.freshness, self.origin) || !matches!(self.entry, EntryLookup::Absent) {
            return None;
        }
        Some(AbsenceEvidence {
            target: self.target,
            now: self.now,
            reasons: self.reasons,
            source: EvidenceSource::Complete(*self.source),
        })
    }
}

/// Complete-source processing, separate from signature authentication/errors.
#[derive(Debug)]
pub enum CompleteEvidence<'b, 'r, 'a, T = Certificate<'a>> {
    /// Caller supplied an unpaired delta; it cannot establish standalone absence.
    DeltaNeedsBase,
    /// Candidate's issuer/DP/category/reasons do not cover this target.
    NotApplicable(ScopeFailure),
    /// All component facts retained, including unsuitable time/entry outcomes.
    Facts(CompleteFacts<'b, 'r, 'a, T>),
}
impl<T> Copy for CompleteEvidence<'_, '_, '_, T> {}
impl<T> Clone for CompleteEvidence<'_, '_, '_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'r, 'a> Authenticated<'r, 'a> {
    /// Compose applicability, time and full-list entry semantics over this
    /// original complete source. Caller supplies authenticated issuer path and
    /// same-anchor provenance as required by RFC5280 §6.3.3(f).
    pub fn evaluate<'b, T: RevocationTarget<'a>, E: Work>(
        &'b self,
        target: &'r T,
        time: &Evaluation<'_, E>,
    ) -> Result<CompleteEvidence<'b, 'r, 'a, T>> {
        if self
            .crl()
            .tbs()
            .extensions()
            .get(oid::DELTA_CRL_INDICATOR, time.execution)?
            .is_some()
        {
            return Ok(CompleteEvidence::DeltaNeedsBase);
        }
        let reasons = match self.scope(target, time.execution)? {
            ScopeOutcome::Applicable(reasons) => reasons,
            ScopeOutcome::NotApplicable(reason) => {
                return Ok(CompleteEvidence::NotApplicable(reason));
            }
        };
        let entry = self.entry(target, time.execution)?;
        let freshness = self.freshness(time.now, time.utc, time.execution)?;
        Ok(CompleteEvidence::Facts(CompleteFacts {
            target,
            now: time.now,
            source: self,
            reasons,
            entry,
            freshness,
            origin: time.origin,
        }))
    }
}

/// Component facts for an applicable bound complete/delta pair.
#[derive(Debug)]
pub struct DeltaFacts<'b, 'r, 'a, T = Certificate<'a>> {
    target: &'r T,
    now: Reading,
    pair: BoundDelta<'b, 'r, 'a>,
    reasons: Reasons,
    base_freshness: Freshness,
    delta_freshness: Freshness,
    origin: SourceOrigin,
    entry: CombinedEntry<'r, 'a>,
}
impl<'b, 'r, 'a, T> DeltaFacts<'b, 'r, 'a, T> {
    /// Original certificate processed by this metadata-bound source pair,
    /// independently of whether its entry/window establishes absence.
    #[must_use]
    pub fn target(&self) -> &'r T {
        self.target
    }
    /// Exact original evaluation label, without borrowing the evaluation context.
    #[must_use]
    pub fn evaluated_at(&self) -> Reading {
        self.now
    }
    /// Original metadata-bound pair.
    #[must_use]
    pub fn pair(&self) -> BoundDelta<'b, 'r, 'a> {
        self.pair
    }
    /// Base time facts; an expired base can still be updated by a current delta.
    #[must_use]
    pub fn base_freshness(&self) -> Freshness {
        self.base_freshness
    }
    /// Delta update window governs the combined list (RFC5280 §5.2.4).
    #[must_use]
    pub fn delta_freshness(&self) -> Freshness {
        self.delta_freshness
    }
    /// Original delta-first entry outcome and provenance.
    #[must_use]
    pub fn entry(&self) -> &CombinedEntry<'r, 'a> {
        &self.entry
    }
    /// Qualified absence/removal is partial until all reasons are covered.
    #[must_use]
    pub fn absence(&self) -> Option<AbsenceEvidence<'r, 'a, T>> {
        if !current(self.delta_freshness, self.origin)
            || matches!(
                self.base_freshness,
                Freshness::NotYetCurrent | Freshness::InvalidUpdateOrder | Freshness::Uncertain(_)
            )
            || !matches!(
                self.entry,
                CombinedEntry::Absent | CombinedEntry::Removed { .. }
            )
        {
            return None;
        }
        Some(AbsenceEvidence {
            target: self.target,
            now: self.now,
            reasons: self.reasons,
            source: EvidenceSource::Delta {
                base: *self.pair.base(),
                delta: *self.pair.delta(),
            },
        })
    }
}

/// Bound-pair processing outcome; no standalone delta absence is inferred.
#[derive(Debug)]
pub enum DeltaEvidence<'b, 'r, 'a, T = Certificate<'a>> {
    /// Pair scope does not cover the target.
    NotApplicable(ScopeFailure),
    /// Retained component facts and original delta-first result.
    Facts(DeltaFacts<'b, 'r, 'a, T>),
}
impl<'b, 'r, 'a> BoundDelta<'b, 'r, 'a> {
    /// Compose bound-pair scope, both source metadata/entries and temporal facts.
    /// No base expiry is silently used as the delta's expiry or vice versa.
    pub fn evaluate<T: RevocationTarget<'a>, E: Work>(
        self,
        target: &'r T,
        time: &Evaluation<'_, E>,
    ) -> Result<DeltaEvidence<'b, 'r, 'a, T>> {
        let reasons = match self.base().scope(target, time.execution)? {
            ScopeOutcome::Applicable(reasons) => reasons,
            ScopeOutcome::NotApplicable(reason) => return Ok(DeltaEvidence::NotApplicable(reason)),
        };
        let entry = self.entry(target, time.execution)?;
        let base_freshness = self.base().freshness(time.now, time.utc, time.execution)?;
        let delta_freshness = self.delta().freshness(time.now, time.utc, time.execution)?;
        Ok(DeltaEvidence::Facts(DeltaFacts {
            target,
            now: time.now,
            pair: self,
            reasons,
            entry,
            base_freshness,
            delta_freshness,
            origin: time.origin,
        }))
    }
}

/// Coverage admission never silently mixes targets or evaluation moments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageAdmission {
    /// New reason coverage and source provenance retained.
    Added,
    /// Source supplies no new reasons; no redundant storage is allocated.
    Redundant,
    /// Different original target certificate.
    DifferentTarget,
    /// Different evaluation label or subnanosecond remainder.
    DifferentTime,
    /// This request-scoped growing collection belongs to another operation
    /// domain; its allocator must not charge growth work to an earlier request.
    DifferentExecution,
}

/// Qualified absence coverage with accounted original-source contributors.
/// Complete reason coverage alone is not a whole certificate trust verdict;
/// caller still owns current-source selection and authenticated path provenance.
#[derive(Debug)]
pub struct Coverage<'r, 'a, T = Certificate<'a>> {
    reasons: Reasons,
    // Temporarily moved, never copied, while attaching the current growth
    // execution. Every returning path restores the independently owned buffer.
    sources: Option<OwnedVec<AbsenceEvidence<'r, 'a, T>>>,
}
impl<'r, 'a, T: RevocationTarget<'a>> Coverage<'r, 'a, T> {
    /// Retain the first qualified source; capacity remains charged until drop.
    pub fn new<W: Work>(first: AbsenceEvidence<'r, 'a, T>, execution: &W) -> Result<Self> {
        let mut sources = execution.vector();
        sources
            .try_push(first)
            .map_err(|reason| first.target.issuer().resource(reason))?;
        Ok(Self {
            reasons: first.reasons,
            sources: Some(sources.into_owned()),
        })
    }
    /// Current qualified reason coverage.
    #[must_use]
    pub fn reasons(&self) -> Reasons {
        self.reasons
    }
    /// Original target shared by every contributing reason source.
    ///
    /// # Panics
    /// Only if the private nonempty source invariant is violated.
    #[must_use]
    pub fn target(&self) -> &'r T {
        self.sources()[0].target()
    }
    /// Exact evaluation label shared by every contributing reason source.
    ///
    /// # Panics
    /// Only if the private nonempty source invariant is violated.
    #[must_use]
    pub fn evaluated_at(&self) -> Reading {
        self.sources()[0].evaluated_at()
    }
    /// Original evidence behind every contributing reason union.
    ///
    /// # Panics
    /// Only if the internal growth invariant is violated: each public return
    /// restores the owned source buffer before exposing this collection.
    #[must_use]
    pub fn sources(&self) -> &[AbsenceEvidence<'r, 'a, T>] {
        self.sources
            .as_deref()
            .expect("coverage growth restores its buffer")
    }
    /// Add compatible qualified coverage under the current operation account.
    /// Growing coverage is request-scoped: `execution` must share its original
    /// account. Later requests may inspect retained facts, but cannot grow this
    /// collection using a different work domain. No old-account fallback.
    ///
    /// # Panics
    /// Only if the internal owned-buffer or checked-account transfer invariant
    /// is violated. Resource refusals restore the original collection.
    pub fn add<W: Work>(
        &mut self,
        evidence: AbsenceEvidence<'r, 'a, T>,
        execution: &W,
    ) -> Result<CoverageAdmission> {
        if !self
            .sources
            .as_ref()
            .expect("coverage owns its buffer")
            .memory()
            .same_account(execution.memory())
        {
            return Ok(CoverageAdmission::DifferentExecution);
        }
        let first = &self.sources()[0];
        execution
            .charge_work(1)
            .map_err(|reason| evidence.target.issuer().resource(reason))?;
        if first.now != evidence.now {
            return Ok(CoverageAdmission::DifferentTime);
        }
        let left = first.target.encoded();
        let right = evidence.target.encoded();
        for target in [first.target, evidence.target] {
            target
                .execution_in(execution)
                .charge_work(1)
                .map_err(|reason| target.issuer().resource(reason))?;
        }
        if first.target.kind() != evidence.target.kind() || left.len() != right.len() {
            return Ok(CoverageAdmission::DifferentTarget);
        }
        if !core::ptr::eq(first.target, evidence.target) {
            for target in [first.target, evidence.target] {
                target
                    .execution_in(execution)
                    .charge_work(target.encoded().len() as u64)
                    .map_err(|reason| target.issuer().resource(reason))?;
            }
            if left != right {
                return Ok(CoverageAdmission::DifferentTarget);
            }
        }
        let union = self.reasons.union(evidence.reasons);
        if union == self.reasons {
            return Ok(CoverageAdmission::Redundant);
        }
        let sources = self.sources.take().expect("coverage owns its buffer");
        let Ok(mut scoped) = sources.with_execution(execution) else {
            unreachable!("the account was checked before any coverage work")
        };
        let admitted = scoped.try_push(evidence);
        self.sources = Some(scoped.into_owned());
        admitted.map_err(|reason| evidence.target.issuer().resource(reason))?;
        self.reasons = union;
        Ok(CoverageAdmission::Added)
    }
}
