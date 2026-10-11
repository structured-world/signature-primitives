use super::{Instant, LeapTable, Transition, Uncertainty};

const SECOND: i128 = 1_000_000_000;
const MIDNIGHT: i64 = 1_483_228_800; // 2017-01-01 UTC.

fn normal(seconds: i64, nanos: u32) -> Instant {
    Instant::new(seconds, nanos).unwrap()
}

#[test]
fn insertion_is_distinct_and_elapsed_seconds_include_it() {
    // A leap second follows every fraction of :59 and precedes midnight.
    let entries = [Transition::new(MIDNIGHT, 1)];
    let table = LeapTable::new(MIDNIGHT - 100, MIDNIGHT + 100, &entries).unwrap();
    let before = normal(MIDNIGHT - 1, 0);
    let leap = Instant::leap_after(MIDNIGHT - 1, 0).unwrap();
    let after = normal(MIDNIGHT, 0);
    assert!(normal(MIDNIGHT - 1, 999_999_999) < leap);
    assert!(leap < after);
    assert_eq!(table.shift(before, SECOND), Ok(leap));
    assert_eq!(table.shift(leap, SECOND), Ok(after));
    assert_eq!(table.shift(after, -SECOND), Ok(leap));
    assert_eq!(table.shift(after, -2 * SECOND), Ok(before));
    assert_eq!(
        table.shift(before, SECOND / 2),
        Ok(normal(MIDNIGHT - 1, 500_000_000))
    );
    assert_eq!(
        table.shift(leap, SECOND / 2),
        Instant::leap_after(MIDNIGHT - 1, 500_000_000).ok_or(Uncertainty::OutOfRange)
    );
}

#[test]
fn deletion_skips_the_missing_second_in_both_directions() {
    // A negative leap removes :59, not :60; POSIX arithmetic cannot do this.
    let entries = [Transition::new(MIDNIGHT, -1)];
    let table = LeapTable::new(MIDNIGHT - 100, MIDNIGHT + 100, &entries).unwrap();
    assert_eq!(
        table.shift(normal(MIDNIGHT - 2, 0), SECOND),
        Ok(normal(MIDNIGHT, 0))
    );
    assert_eq!(
        table.shift(normal(MIDNIGHT, 0), -SECOND),
        Ok(normal(MIDNIGHT - 2, 0))
    );
    assert_eq!(
        table.shift(normal(MIDNIGHT - 1, 0), 0),
        Err(Uncertainty::NotInUtc)
    );
    assert_eq!(
        table.shift(Instant::leap_after(MIDNIGHT - 1, 0).unwrap(), 0),
        Err(Uncertainty::NotInUtc)
    );
}

#[test]
fn coverage_is_not_an_assumption_about_future_utc() {
    // Empty means no changes only inside the declared half-open coverage.
    let table = LeapTable::new(0, 10, &[]).unwrap();
    assert_eq!(
        table.shift(normal(9, 999_999_999), 1),
        Err(Uncertainty::OutsideCoverage)
    );
    assert_eq!(
        table.shift(normal(0, 0), -1),
        Err(Uncertainty::OutsideCoverage)
    );
    assert_eq!(
        table.shift(normal(10, 0), -SECOND),
        Err(Uncertainty::OutsideCoverage)
    );
    assert_eq!(table.shift(normal(5, 0), 0), Ok(normal(5, 0)));
    assert_eq!(
        table.shift(normal(5, 0), i128::MAX),
        Err(Uncertainty::OutOfRange)
    );
}

#[test]
fn table_rejects_conflicting_or_unrepresentable_facts() {
    // Validate borrowed facts once, before any timestamp can rely on them.
    assert!(LeapTable::new(10, 10, &[]).is_err());
    assert!(
        LeapTable::new(
            MIDNIGHT - 100,
            MIDNIGHT + 100,
            &[Transition::new(MIDNIGHT, 2)]
        )
        .is_err()
    );
    assert!(
        LeapTable::new(
            MIDNIGHT - 100,
            MIDNIGHT + 100,
            &[Transition::new(MIDNIGHT, 0)]
        )
        .is_err()
    );
    assert!(
        LeapTable::new(
            MIDNIGHT - 100,
            MIDNIGHT + 100,
            &[Transition::new(MIDNIGHT, 1), Transition::new(MIDNIGHT, 2)]
        )
        .is_err()
    );
    assert!(
        LeapTable::new(
            MIDNIGHT - 100,
            MIDNIGHT + 100,
            &[Transition::new(MIDNIGHT + 1, 1)]
        )
        .is_err()
    );
    assert!(LeapTable::new(MIDNIGHT, MIDNIGHT + 100, &[Transition::new(MIDNIGHT, 1)]).is_err());
    assert!(Instant::new(0, 1_000_000_000).is_none());
    assert!(Instant::leap_after(i64::MAX, 0).is_none());
}

#[test]
fn mixed_changes_round_trip_without_copying_the_table() {
    // Two opposite adjustments cancel cumulatively, not within either leap.
    let next_month = MIDNIGHT + 31 * 86_400;
    let entries = [Transition::new(MIDNIGHT, 1), Transition::new(next_month, 0)];
    let table = LeapTable::new(MIDNIGHT - 100, next_month + 100, &entries).unwrap();
    let at = normal(MIDNIGHT - 2, 123);
    let elapsed = i128::from(next_month - (MIDNIGHT - 2)) * SECOND;
    assert_eq!(table.shift(at, elapsed), Ok(normal(next_month, 123)));
    assert_eq!(table.shift(normal(next_month, 123), -elapsed), Ok(at));
    assert!(core::ptr::eq(
        table.transitions().as_ptr(),
        entries.as_ptr()
    ));
}

#[test]
fn parsed_leap_label_preserves_offset_and_subnanosecond_precision() {
    // Offset normalization must preserve :60 instead of collapsing midnight.
    let parse = |text: &str| {
        let der = crate::fixtures::generalized_time(text);
        let parser = structured_asn1::Parser::der(crate::fixtures::memory());
        let mut reader = parser.read(&der, 0).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        super::read_generalized(&reader, &element, "test").unwrap()
    };
    let leap = parse("20161231235960.9999999991Z");
    assert!(leap.start().is_leap_second());
    assert_eq!(leap, parse("20170101005960.9999999991+0100"));
    let changes = [Transition::new(MIDNIGHT, 1)];
    let table = LeapTable::new(MIDNIGHT - 100, MIDNIGHT + 100, &changes).unwrap();
    assert_eq!(leap.upper_bound(&table), Ok(normal(MIDNIGHT, 0)));

    // Rounding up :59 needs the facts too: it can land on :60, not midnight.
    let before = parse("20161231235959.9999999991Z");
    assert_eq!(
        before.upper_bound(&table),
        Ok(Instant::leap_after(MIDNIGHT - 1, 0).unwrap())
    );
    let no_change = LeapTable::new(MIDNIGHT - 100, MIDNIGHT + 100, &[]).unwrap();
    assert_eq!(before.upper_bound(&no_change), Ok(normal(MIDNIGHT, 0)));
    assert_eq!(leap.upper_bound(&no_change), Err(Uncertainty::NotInUtc));
}

#[test]
fn end_transition_and_nanosecond_edges_round_trip() {
    // A correction at the exclusive endpoint still describes the last day.
    let entries = [Transition::new(MIDNIGHT, 1)];
    let table = LeapTable::new(MIDNIGHT - 2, MIDNIGHT, &entries).unwrap();
    let leap = Instant::leap_after(MIDNIGHT - 1, 999_999_999).unwrap();
    assert_eq!(table.shift(leap, 0), Ok(leap));
    assert_eq!(table.shift(leap, 1), Err(Uncertainty::OutsideCoverage));
    for at in [normal(MIDNIGHT - 2, 0), normal(MIDNIGHT - 1, 7), leap] {
        for duration in [-SECOND, -1, 0, 1, SECOND] {
            if let Ok(moved) = table.shift(at, duration) {
                assert_eq!(table.shift(moved, -duration), Ok(at));
            }
        }
    }
    let negative = [Transition::new(MIDNIGHT, -1)];
    assert!(LeapTable::new(MIDNIGHT - 1, MIDNIGHT + 1, &negative).is_err());
}

#[test]
fn decimal_fraction_keeps_carry_beyond_fixed_precision() {
    // Truncating the decimal at eighteen digits loses a carry into the
    // nanosecond for fractional hours. Decimal multiplication must be exact.
    let der =
        crate::fixtures::generalized_time("2017010100.0000000000002777777777777777777777778Z");
    let parser = structured_asn1::Parser::der(crate::fixtures::memory());
    let mut reader = parser.read(&der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let reading = super::read_generalized(&reader, &element, "test").unwrap();
    assert_eq!(reading.start(), normal(MIDNIGHT, 1));
    assert!(reading.has_subnanosecond_remainder());
}
