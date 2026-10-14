//! Generation bounds use the existing UTC core, not a second calendar engine.

use structured_cms::timestamp::{Accuracy, BoundUncertainty, earliest, latest};
use structured_pkix::temporal::{Instant, LeapTable, Reading, Uncertainty};

#[test]
fn unstated_accuracy_precedes_missing_utc_coverage() {
    // An omitted complete Accuracy supplies no endpoint. Even unknown UTC
    // must not hide that primary limitation or imply a zero-width interval.
    let utc = LeapTable::new(0, 10, &[]).unwrap();
    let reading = Reading::from(Instant::new(20, 0).unwrap());
    assert_eq!(
        earliest(reading, None, &utc),
        Err(BoundUncertainty::AccuracyUnstated)
    );
    assert_eq!(
        latest(reading, None, &utc),
        Err(BoundUncertainty::AccuracyUnstated)
    );
}

#[test]
fn stated_zero_and_all_accuracy_units_keep_exact_endpoints() {
    // Missing parts of a present Accuracy default to zero; missing the whole
    // value is distinct. Every unit contributes to both factual endpoints.
    let utc = LeapTable::new(0, 100, &[]).unwrap();
    let reading = Reading::from(Instant::new(50, 0).unwrap());
    assert_eq!(
        earliest(reading, Some(Accuracy::new(0, 0, 0)), &utc),
        Ok(reading.start())
    );
    assert_eq!(
        latest(reading, Some(Accuracy::new(0, 0, 0)), &utc),
        Ok(reading.start())
    );
    let accuracy = Accuracy::new(1, 2, 3);
    assert_eq!(accuracy.nanos(), 1_002_003_000);
    assert_eq!(
        earliest(reading, Some(accuracy), &utc),
        Ok(Instant::new(48, 997_997_000).unwrap())
    );
    assert_eq!(
        latest(reading, Some(accuracy), &utc),
        Ok(Instant::new(51, 2_003_000).unwrap())
    );
    assert_eq!(
        latest(
            Reading::from(Instant::new(200, 0).unwrap()),
            Some(accuracy),
            &utc
        ),
        Err(BoundUncertainty::Utc(Uncertainty::OutsideCoverage))
    );
}

fn reading(label: &[u8]) -> Reading {
    // Shared decoding is the only calendar/parser implementation in this test.
    use std::sync::Arc;
    use structured_asn1::{
        Parser,
        memory::{Memory, MemoryAccount},
    };
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(4096, 65536))));
    let mut bytes = vec![0x18, u8::try_from(label.len()).unwrap()];
    bytes.extend_from_slice(label);
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    structured_pkix::temporal::read_generalized(&reader, &element, "tstInfo.genTime").unwrap()
}

#[test]
fn fine_precision_rounds_into_a_real_inserted_second_only_with_utc_facts() {
    // RFC3161 accuracy arithmetic must preserve the same leap/rounding core
    // as the timestamp reader rather than aliasing an inserted label to midnight.
    use structured_pkix::temporal::Transition;
    let day_end = 181 * 86400;
    let transitions = [Transition::new(day_end, 1)];
    let utc = LeapTable::new(0, day_end + 86400, &transitions).unwrap();
    let recorded = reading(b"19700630235959.9999999991Z");
    let zero = Some(Accuracy::new(0, 0, 0));
    assert_eq!(earliest(recorded, zero, &utc), Ok(recorded.start()));
    let upper = latest(recorded, zero, &utc).unwrap();
    assert!(upper.is_leap_second());
    assert_eq!(upper.seconds(), day_end - 1);
    assert_eq!(upper.nanos(), 0);
    let shifted = latest(recorded, Some(Accuracy::new(1, 0, 0)), &utc).unwrap();
    assert_eq!(shifted, Instant::new(day_end, 0).unwrap());
    let without_insertion = LeapTable::new(0, day_end + 86400, &[]).unwrap();
    assert_eq!(
        latest(recorded, zero, &without_insertion),
        Ok(Instant::new(day_end, 0).unwrap())
    );
}

#[test]
fn unstated_accuracy_stays_primary_for_fine_precision_and_deleted_utc_labels() {
    // Rounding and a contradictory UTC label must not manufacture an endpoint
    // or mask the separate absence of any supplied accuracy bound.
    use structured_pkix::temporal::Transition;
    let recorded = reading(b"19700101000009.9999999991Z");
    let utc = LeapTable::new(0, 10, &[]).unwrap();
    assert_eq!(
        latest(recorded, None, &utc),
        Err(BoundUncertainty::AccuracyUnstated)
    );
    assert_eq!(
        latest(recorded, Some(Accuracy::new(0, 0, 0)), &utc),
        Err(BoundUncertainty::Utc(Uncertainty::OutsideCoverage))
    );
    let day_end = 181 * 86400;
    let transitions = [Transition::new(day_end, -1)];
    let utc = LeapTable::new(0, day_end + 86400, &transitions).unwrap();
    let deleted = Reading::from(Instant::new(day_end - 1, 0).unwrap());
    assert_eq!(
        earliest(deleted, None, &utc),
        Err(BoundUncertainty::AccuracyUnstated)
    );
    assert_eq!(
        latest(deleted, None, &utc),
        Err(BoundUncertainty::AccuracyUnstated)
    );
    assert_eq!(
        latest(deleted, Some(Accuracy::new(0, 0, 0)), &utc),
        Err(BoundUncertainty::Utc(Uncertainty::NotInUtc))
    );
}

#[test]
fn widest_scalar_accuracy_does_not_wrap_or_claim_a_narrow_bound() {
    // Inspection retains the raw scalar values. Exact wide arithmetic cannot
    // narrow the interval by overflow, and is not itself schema acceptance.
    let accuracy = Accuracy::new(u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(accuracy.seconds(), u64::MAX);
    assert_eq!(accuracy.millis(), u64::MAX);
    assert_eq!(accuracy.micros(), u64::MAX);
    assert_eq!(accuracy.nanos(), u128::from(u64::MAX) * 1_001_001_000);
    let utc = LeapTable::new(0, 100, &[]).unwrap();
    let recorded = Reading::from(Instant::new(50, 0).unwrap());
    assert_eq!(
        earliest(recorded, Some(accuracy), &utc),
        Err(BoundUncertainty::Utc(Uncertainty::OutOfRange))
    );
    assert_eq!(
        latest(recorded, Some(accuracy), &utc),
        Err(BoundUncertainty::Utc(Uncertainty::OutOfRange))
    );
}

#[test]
fn accuracy_reader_distinguishes_absent_zero_and_readable_bounds_faults() {
    // Present empty SEQUENCE is stated zero. Written millis=0/1000 remain
    // original values plus faults, not absence, clamped values or parser refusal.
    use std::sync::Arc;
    use structured_asn1::{
        Parser,
        memory::{Memory, MemoryAccount},
    };
    use structured_cms::{
        ErrorCode,
        timestamp::{AccuracyReading, Component},
    };
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    for (bytes, millis, fault_count) in [
        (&[0x30, 0][..], None, 0),
        (&[0x30, 3, 0x80, 1, 0][..], Some(0), 1),
        (&[0x30, 4, 0x80, 2, 3, 0xe8][..], Some(1000), 1),
    ] {
        let mut parent = parser.read(bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let accuracy = AccuracyReading::read(&parent, &element).unwrap();
        assert!(accuracy.component(Component::Seconds).is_none());
        assert_eq!(
            accuracy
                .component(Component::Millis)
                .map(|part| part.value().as_u64().unwrap()),
            millis
        );
        assert_eq!(accuracy.deviation().unwrap().millis(), millis.unwrap_or(0));
        assert_eq!(accuracy.faults().len(), fault_count);
        if fault_count != 0 {
            assert_eq!(accuracy.faults()[0].code(), ErrorCode::MalformedValue);
            assert_eq!(accuracy.faults()[0].offset(), 402);
        }
        drop(accuracy);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn accuracy_reader_keeps_original_integer_views_and_diagnostic_ownership() {
    // Shared INTEGER recovery preserves the original TLV while the minimal
    // numeric view avoids repeat scans. Unknown/order faults retain exact offsets.
    use std::sync::Arc;
    use structured_asn1::{
        Parser,
        memory::{Memory, MemoryAccount},
    };
    use structured_cms::{
        ErrorCode,
        timestamp::{AccuracyReading, Component},
    };
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let bytes = [0x30, 9, 0x81, 2, 0, 1, 5, 0, 2, 1, 3];
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let accuracy = AccuracyReading::read(&parent, &element).unwrap();
    let micros = accuracy.component(Component::Micros).unwrap();
    assert_eq!(micros.element().contents(), &[0, 1]);
    assert_eq!(micros.value().as_bytes(), &[1]);
    assert_eq!(micros.element().as_bytes().as_ptr(), bytes[2..].as_ptr());
    assert_eq!(accuracy.deviation().unwrap(), Accuracy::new(3, 0, 1));
    assert_eq!(
        accuracy
            .faults()
            .iter()
            .map(|fault| (fault.code(), fault.offset()))
            .collect::<Vec<_>>(),
        vec![
            (
                ErrorCode::Encoding(structured_asn1::ErrorCode::IntegerNotMinimal),
                402
            ),
            (ErrorCode::UnknownField, 406),
            (ErrorCode::FieldOrder, 408),
        ]
    );
    let faults = accuracy.into_faults();
    let held = memory.used();
    drop(parent);
    drop(parser);
    assert_eq!(memory.used(), held);
    assert!(held > 0);
    drop(faults);
    assert_eq!(memory.used(), 0);
}

#[test]
fn accuracy_reader_never_replaces_negative_or_too_wide_values_with_a_number() {
    // A unique numeric reading remains reportable even when deviation cannot
    // fit; neither u64::MAX nor zero can silently stand for that original value.
    use std::sync::Arc;
    use structured_asn1::{
        Parser,
        memory::{Memory, MemoryAccount},
    };
    use structured_cms::timestamp::{AccuracyReading, Component, DeviationReason};
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(65536, 65536))));
    for (bytes, expected) in [
        (&[0x30, 3, 2, 1, 0xff][..], DeviationReason::Negative),
        (
            &[0x30, 11, 2, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0][..],
            DeviationReason::TooWide,
        ),
    ] {
        let mut parent = parser.read(bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let accuracy = AccuracyReading::read(&parent, &element).unwrap();
        let refusal = accuracy.deviation().unwrap_err();
        assert_eq!(refusal.component, Component::Seconds);
        assert_eq!(refusal.reason, expected);
        assert_eq!(refusal.span.start, 402);
        assert_eq!(
            accuracy
                .component(Component::Seconds)
                .unwrap()
                .element()
                .contents(),
            &bytes[4..]
        );
        assert_eq!(accuracy.faults().len(), 1);
    }
}

#[test]
fn accuracy_duplicate_recovery_keeps_original_spelling_and_refuses_conflicts() {
    // The reviewed donor contract compares whole encodings. Different BER
    // spellings are not silently collapsed merely because their numbers agree.
    use std::sync::Arc;
    use structured_asn1::{
        Parser,
        memory::{Memory, MemoryAccount},
    };
    use structured_cms::{ErrorCode, timestamp::AccuracyReading};
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let identical = [0x30, 6, 2, 1, 3, 2, 1, 3];
    let mut parent = parser.read(&identical, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let accuracy = AccuracyReading::read(&parent, &element).unwrap();
    assert_eq!(accuracy.deviation().unwrap(), Accuracy::new(3, 0, 0));
    assert_eq!(accuracy.faults()[0].code(), ErrorCode::DuplicateField);
    assert_eq!(accuracy.faults()[0].offset(), 405);
    drop(accuracy);
    for bytes in [
        &[0x30, 6, 2, 1, 3, 2, 1, 4][..],
        &[0x30, 7, 2, 1, 3, 2, 2, 0, 3][..],
    ] {
        let mut parent = parser.read(bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let refusal = AccuracyReading::read(&parent, &element).unwrap_err();
        assert_eq!(refusal.code(), ErrorCode::DuplicateField);
        assert_eq!(refusal.offset(), 405);
        assert_eq!(memory.used(), 0);
    }
}
