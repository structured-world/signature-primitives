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
