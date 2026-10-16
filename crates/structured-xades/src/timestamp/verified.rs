//! Retained mathematical timestamp evidence with original XML input identity.

use super::Role;
use crate::binary::Location;
use structured_asn1::memory::{MemoryError, Work};
use structured_cms::timestamp::{BoundUncertainty, Evidence, earliest, latest};
use structured_pkix::temporal::{Instant, LeapTable};
use structured_pkix::{Certificate, path::WorkingKey};

/// Successfully checked token covering the input selected by the common kernel.
/// Construction is restricted to `Check::retain`; caller-written XML metadata
/// cannot relabel unrelated token evidence. This is not a TSA trust or B level.
#[derive(Debug)]
pub struct Verified<N, D, G> {
    pub(super) token: Location<N, D, G>,
    pub(super) signature: N,
    pub(super) property: N,
    pub(super) role: Role,
    pub(super) evidence: Evidence,
}

/// Successful mathematical timestamp check with its actual selected signer.
///
/// The certificate and effective key come from the same complete-check context,
/// not a later caller-supplied association. This still establishes no TSA path,
/// status or trust. Only [`super::Check::retain_actor`] constructs this binding.
/// Certificate/key borrows need not retain the provider or temporary context.
pub struct CheckedActor<'certificate, 'document, N, D, G> {
    pub(super) verified: Verified<N, D, G>,
    pub(super) certificate: &'certificate Certificate<'document>,
    pub(super) key: WorkingKey<'document>,
}

impl<'certificate, 'document, N, D, G> CheckedActor<'certificate, 'document, N, D, G> {
    /// Actual candidate used for the successful token signature/ESS checks.
    #[must_use]
    pub fn certificate(&self) -> &'certificate Certificate<'document> {
        self.certificate
    }

    /// Actual effective parameters supplied to that same selected provider.
    #[must_use]
    pub fn key(&self) -> WorkingKey<'document> {
        self.key
    }

    /// Independently retained mathematical evidence with original XML identity.
    #[must_use]
    pub fn verified(&self) -> &Verified<N, D, G> {
        &self.verified
    }

    /// Ends the borrowed signer association while moving independent evidence.
    /// This performs no copy/allocation and makes no subsequent TSA claim.
    #[must_use]
    pub fn into_verified(self) -> Verified<N, D, G> {
        self.verified
    }
}

/// Factual generation-time interval, not the document's signing-time interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    /// Earliest generation consistent with the authority's stated accuracy.
    pub earliest: Instant,
    /// Latest generation, including any subnanosecond rounding.
    pub latest: Instant,
}

/// Complete timestamp-generation interval relative to an explicit event label.
/// This temporal fact does not authenticate that event or associate a
/// certificate/status response with the timestamp's actual signing actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryRelation {
    /// Every possible generation instant is strictly before the event.
    Before,
    /// The authority stated an exact generation instant equal to the event.
    At,
    /// Every possible generation instant is strictly after the event.
    After,
    /// The complete interval touches or straddles the event; strict ordering
    /// cannot be established. Equality of just one endpoint is insufficient.
    Overlaps,
}

/// Current execution refusal is distinct from incomplete authenticated UTC facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalError {
    /// Admission failed before UTC table lookup or arithmetic.
    Resource(MemoryError),
    /// Existing RFC3161/UTC kernel could not establish a complete interval.
    Uncertain(BoundUncertainty),
}

impl<N: Copy, D: Copy, G: Copy> Verified<N, D, G> {
    /// Original token enclosure, not an offset in its decoded ASN.1 source.
    #[must_use]
    pub fn token(&self) -> Location<N, D, G> {
        self.token
    }
    /// Actual selected signature whose original input was covered.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original timestamp property, independently of its encapsulated token node.
    #[must_use]
    pub fn property(&self) -> N {
        self.property
    }
    /// Exact common input-selection role used during checking.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }
    /// Independently retained token facts and original ASN.1 source projection.
    #[must_use]
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
    /// Moves retained evidence without a second allocation or deep copy.
    #[must_use]
    pub fn into_evidence(self) -> Evidence {
        self.evidence
    }

    /// Derives the complete authority generation interval using the existing
    /// RFC3161/UTC arithmetic, funded by the current operation. Missing accuracy
    /// remains uncertainty, never an implicitly exact time. Caller policy is
    /// responsible for authenticating the supplied leap table.
    ///
    /// EN319132-1 §6.3(o) requires the signature timestamp to precede signer
    /// revocation/expiry; its bare genTime is insufficient when accuracy is
    /// stated. This helper supplies endpoints, not path/status acceptance.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn interval<W: Work>(
        &self,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<Interval, TemporalError> {
        interval(
            self.evidence.facts().gen_time(),
            self.evidence.facts().accuracy(),
            utc,
            execution,
        )
    }

    /// Compares the complete generation interval to an explicit event label.
    ///
    /// EN319132-1 §6.3(o) requires chronology relative to signer revocation/
    /// expiry. This helper never substitutes the bare genTime or claimed XML
    /// `SigningTime` for the interval, nor decides certificate/status/trust policy.
    /// Missing accuracy, invalid leap labels and absent UTC coverage remain
    /// uncertainty; all table work is admitted through current execution.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn relation<W: Work>(
        &self,
        boundary: Instant,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<BoundaryRelation, TemporalError> {
        relation(self.interval(utc, execution)?, boundary, utc, execution)
    }
}

fn relation<W: Work>(
    interval: Interval,
    boundary: Instant,
    utc: &LeapTable<'_>,
    execution: &W,
) -> Result<BoundaryRelation, TemporalError> {
    let bits = usize::BITS - utc.transitions().len().leading_zeros();
    execution
        .charge_work(16 + 3 * (u64::from(bits) + 1))
        .map_err(TemporalError::Resource)?;
    utc.shift(boundary, 0)
        .map_err(|cause| TemporalError::Uncertain(BoundUncertainty::Utc(cause)))?;
    Ok(if interval.latest < boundary {
        BoundaryRelation::Before
    } else if interval.earliest > boundary {
        BoundaryRelation::After
    } else if interval.earliest == boundary && interval.latest == boundary {
        BoundaryRelation::At
    } else {
        BoundaryRelation::Overlaps
    })
}

fn interval<W: Work>(
    reading: structured_pkix::temporal::Reading,
    accuracy: Option<structured_cms::timestamp::Accuracy>,
    utc: &LeapTable<'_>,
    execution: &W,
) -> Result<Interval, TemporalError> {
    // earliest uses one shift; latest uses upper_bound + one shift. Each
    // shift has three binary partition searches, with at most bit_length(n)+1
    // predicate calls apiece. 48 also admits fixed per-shift/scalar inspections.
    // Table construction/validation belongs to its caller, not this lookup.
    let count = utc.transitions().len();
    let bits = usize::BITS - count.leading_zeros();
    let cost = 48 + 9 * (u64::from(bits) + 1);
    execution
        .charge_work(cost)
        .map_err(TemporalError::Resource)?;
    let earliest = earliest(reading, accuracy, utc).map_err(TemporalError::Uncertain)?;
    let latest = latest(reading, accuracy, utc).map_err(TemporalError::Uncertain)?;
    Ok(Interval { earliest, latest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use structured_asn1::{
        Limits, Parser,
        memory::{Memory, MemoryAccount},
    };
    use structured_cms::timestamp::Accuracy;
    use structured_pkix::temporal::{Reading, Transition, Uncertainty};

    fn funded() -> Memory {
        Memory::new(Arc::new(MemoryAccount::new(4096, 10_000)))
    }

    #[test]
    fn accuracy_absence_never_creates_an_exact_interval_or_extends_utc_coverage() {
        // RFC3161 omitted Accuracy supplies no endpoint. It has priority over
        // UTC coverage; a stated accuracy still propagates the real UTC cause.
        let work = funded();
        let reading = Reading::from(Instant::new(100, 0).unwrap());
        let utc = LeapTable::new(0, 10, &[]).unwrap();
        assert_eq!(
            interval(reading, None, &utc, &work),
            Err(TemporalError::Uncertain(BoundUncertainty::AccuracyUnstated))
        );
        assert_eq!(
            interval(reading, Some(Accuracy::new(0, 0, 0)), &utc, &work),
            Err(TemporalError::Uncertain(BoundUncertainty::Utc(
                Uncertainty::OutsideCoverage
            )))
        );
    }

    #[test]
    fn generation_interval_uses_common_elapsed_utc_arithmetic_across_inserted_second() {
        // A one-second deviation around an inserted label spans the adjacent
        // ordinary seconds; POSIX addition would lose that inserted second.
        let work = funded();
        let changes = [Transition::new(78_796_800, 1)];
        let utc = LeapTable::new(78_710_400, 78_883_200, &changes).unwrap();
        let reading = Reading::from(Instant::leap_after(78_796_799, 0).unwrap());
        assert_eq!(
            interval(reading, Some(Accuracy::new(1, 0, 0)), &utc, &work).unwrap(),
            Interval {
                earliest: Instant::new(78_796_799, 0).unwrap(),
                latest: Instant::new(78_796_800, 0).unwrap(),
            }
        );
    }

    #[test]
    fn current_local_and_aggregate_refusals_precede_utc_lookup() {
        // Even an otherwise uncertain label must not bypass a current query's
        // local/aggregate ceiling through retained evidence's old account.
        let work = funded();
        let parser = Parser::new(
            structured_asn1::Encoding::Der,
            Limits {
                max_work: 0,
                ..Limits::default()
            },
            work,
        );
        let reader = parser.read(&[], 0).unwrap();
        let utc = LeapTable::new(0, 10, &[]).unwrap();
        let reading = Reading::from(Instant::new(100, 0).unwrap());
        assert!(matches!(
            interval(reading, None, &utc, &reader.execution()),
            Err(TemporalError::Resource(MemoryError::WorkExceeded))
        ));
        let aggregate = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        assert!(matches!(
            interval(reading, None, &utc, &aggregate),
            Err(TemporalError::Resource(MemoryError::WorkExceeded))
        ));
    }

    #[test]
    fn interval_chronology_does_not_turn_touching_accuracy_into_strict_order() {
        // A timestamp whose stated accuracy reaches revocation cannot prove
        // earlier existence just because its bare genTime precedes revocation.
        let utc = LeapTable::new(0, 100_000, &[]).unwrap();
        let work = funded();
        let boundary = Instant::new(100, 0).unwrap();
        for (first, last, expected) in [
            (90, 99, BoundaryRelation::Before),
            (90, 100, BoundaryRelation::Overlaps),
            (90, 110, BoundaryRelation::Overlaps),
            (100, 100, BoundaryRelation::At),
            (101, 110, BoundaryRelation::After),
        ] {
            let interval = Interval {
                earliest: Instant::new(first, 0).unwrap(),
                latest: Instant::new(last, 0).unwrap(),
            };
            assert_eq!(relation(interval, boundary, &utc, &work).unwrap(), expected);
        }
        let interval = Interval {
            earliest: Instant::new(99, 999_999_999).unwrap(),
            latest: Instant::new(99, 999_999_999).unwrap(),
        };
        assert_eq!(
            relation(interval, boundary, &utc, &work).unwrap(),
            BoundaryRelation::Before
        );
        let inserted = Instant::leap_after(86_399, 0).unwrap();
        assert!(matches!(
            relation(interval, inserted, &utc, &work),
            Err(TemporalError::Uncertain(BoundUncertainty::Utc(_)))
        ));
        let denied = Parser::new(
            structured_asn1::Encoding::Der,
            Limits {
                max_work: 0,
                ..Limits::default()
            },
            funded(),
        );
        let query = denied.read(&[], 0).unwrap();
        assert_eq!(
            relation(interval, inserted, &utc, &query.execution()),
            Err(TemporalError::Resource(MemoryError::WorkExceeded))
        );
        assert_eq!(work.used(), 0);
    }
}
