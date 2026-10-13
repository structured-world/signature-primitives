//! Public recovery preserves wire identity and refuses unfunded processing.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, ErrorCode, Limits, Parser};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

#[test]
fn recovery_keeps_original_bytes_and_the_unique_signed_value() {
    // Redundant 00/ff octets change conformance, not two's-complement value.
    // A required sign octet must remain in the minimal numeric view.
    for (raw, minimal, unsigned, signed) in [
        (&[0][..], &[0][..], Some(0), Some(0)),
        (&[0, 0, 1], &[1], Some(1), Some(1)),
        (&[0, 0, 0x80], &[0, 0x80], Some(128), Some(128)),
        (&[0xff, 0xff], &[0xff], None, Some(-1)),
        (&[0xff, 0xff, 0x80], &[0x80], None, Some(-128)),
        (&[0xff, 0xff, 0x7f], &[0xff, 0x7f], None, Some(-129)),
        (&[0, 0, 0], &[0], Some(0), Some(0)),
    ] {
        let bytes = [&[2, u8::try_from(raw.len()).unwrap()][..], raw].concat();
        let parser = Parser::der(memory(65536, 1_000_000));
        let mut reader = parser.read(&bytes, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let reading = reader.integer_reading(&element).unwrap();
        assert_eq!(reading.as_bytes(), raw);
        assert_eq!(reading.as_bytes().as_ptr(), element.contents().as_ptr());
        assert_eq!(reading.value().as_bytes(), minimal);
        assert_eq!(
            reading.value().as_bytes().as_ptr(),
            element.contents()[raw.len() - minimal.len()..].as_ptr()
        );
        assert_eq!(reading.value().as_u64(), unsigned);
        assert_eq!(reading.value().as_i64(), signed);
        assert_eq!(reading.value().is_negative(), signed.unwrap() < 0);
        if raw == minimal {
            assert!(reading.fault().is_none());
        } else {
            let fault = reading.fault().unwrap();
            assert_eq!(fault.code(), ErrorCode::IntegerNotMinimal);
            assert_eq!(fault.offset(), 400);
            assert_eq!(fault.path().indices(), &[0]);
            assert_eq!(
                reader.integer(&element).unwrap_err().code(),
                ErrorCode::IntegerNotMinimal
            );
        }
    }
}

#[test]
fn implicit_integer_and_numeric_width_remain_separate_from_faults() {
    // TSP accuracy uses primitive IMPLICIT tags. Padding recovery must not
    // overflow conversions or reject a valid 9-octet positive u64 sign byte.
    for (raw, unsigned, signed) in [
        (
            &[0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
            Some(u64::MAX),
            None,
        ),
        (&[0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], None, None),
        (&[0xff, 0x80, 0, 0, 0, 0, 0, 0, 0], None, Some(i64::MIN)),
    ] {
        let bytes = [&[0x80, u8::try_from(raw.len()).unwrap()][..], raw].concat();
        let parser = Parser::ber(memory(65536, 1_000_000));
        let mut reader = parser.read(&bytes, 900).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let reading = reader.integer_reading(&element).unwrap();
        assert!(reading.fault().is_some());
        assert_eq!(reading.value().as_u64(), unsigned);
        assert_eq!(reading.value().as_i64(), signed);
    }
}

#[test]
fn empty_and_constructed_integers_are_not_recovered() {
    // Recovery is limited to redundant sign padding; X.690 8.3.1 still
    // requires primitive construction and at least one content octet.
    for (bytes, code) in [
        (&[2, 0][..], ErrorCode::IntegerEmpty),
        (&[0x22, 3, 2, 1, 1], ErrorCode::WrongConstruction),
    ] {
        let parser = Parser::der(memory(65536, 1_000_000));
        let mut reader = parser.read(bytes, 700).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let error = reader.integer_reading(&element).unwrap_err();
        assert_eq!(error.code(), code);
        assert_eq!(error.offset(), 700);
    }
}

#[test]
fn recovery_diagnostic_owns_its_charge_and_moves_without_copying() {
    // Moving the retained fault keeps its original capacity charge alive
    // after readers/parser drop; dropping that fault releases the capacity.
    let execution = memory(65536, 1_000_000);
    let fault = {
        let parser = Parser::der(execution.clone());
        let mut reader = parser.read(&[2, 2, 0, 1], 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let reading = reader.integer_reading(&element).unwrap();
        let retained = execution.used();
        assert!(retained > 0);
        let (value, fault) = reading.into_parts();
        assert_eq!(value.as_u64(), Some(1));
        assert_eq!(execution.used(), retained);
        fault.unwrap()
    };
    assert!(execution.used() > 0);
    assert_eq!(fault.offset(), 400);
    drop(fault);
    assert_eq!(execution.used(), 0);
}

#[test]
fn unfunded_diagnostics_cannot_be_successful_recovery() {
    // The payload is borrowed; only a nonminimal value needs retained fault
    // storage. If that storage is refused, no successful reading escapes.
    let execution = memory(0, 1_000_000);
    let parser = Parser::der(execution.clone());
    for (bytes, minimal) in [(&[2, 1, 1][..], true), (&[2, 2, 0, 1], false)] {
        let mut reader = parser.read(bytes, 800).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let result = reader.integer_reading(&element);
        if minimal {
            assert_eq!(result.unwrap().value().as_u64(), Some(1));
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.offset(), 800);
        }
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn rebound_recovery_preserves_local_and_current_work_ceilings() {
    // Rebinding cannot reset the original parse ceiling; aggregate refusal
    // must charge neither the original domain nor an unexecuted padding scan.
    for local in [false, true] {
        let source = memory(65536, 1_000_000);
        let limits = Limits {
            max_work: if local { 2 } else { 1_000_000 },
            ..Limits::default()
        };
        let parser = Parser::new(Encoding::Der, limits, source.clone());
        let mut reader = parser.read(&[2, 4, 0, 0, 0, 1], 800).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let source_work = source.work_used();
        let execution = memory(65536, if local { 1_000_000 } else { 0 });
        let reader = reader.with_execution(&execution);
        let error = reader.integer_reading(&element).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), 800);
        assert_eq!(source.work_used(), source_work);
        if !local {
            assert_eq!(execution.work_used(), 0);
        }
    }
}

#[test]
fn long_padding_is_iterative_borrowed_and_not_rescanned_by_conversion() {
    // A 65537-byte payload can be recovered with only small diagnostic
    // storage. Repeated conversion reads the cached suffix, never the padding.
    let mut bytes = vec![2, 0x83, 1, 0, 1];
    bytes.resize(5 + 65536, 0);
    bytes.push(1);
    let execution = memory(1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let reading = reader.integer_reading(&element).unwrap();
    assert_eq!(reading.as_bytes().len(), 65537);
    assert_eq!(reading.value().as_bytes(), &[1]);
    assert_eq!(
        reading.value().as_bytes().as_ptr(),
        bytes[bytes.len() - 1..].as_ptr()
    );
    assert!(execution.used() <= 1024);
    let work = execution.work_used();
    for _ in 0..1000 {
        assert_eq!(reading.value().as_u64(), Some(1));
        assert_eq!(reading.value().as_i64(), Some(1));
    }
    assert_eq!(execution.work_used(), work);
    drop(reading);
    assert_eq!(execution.used(), 0);
}

#[test]
fn nested_fault_keeps_its_original_container_path() {
    // Recovery under an implicit primitive field inherits the producing
    // Reader's path and offset rather than reparsing a trimmed document.
    let parser = Parser::der(memory(65536, 1_000_000));
    let mut reader = parser.read(&[48, 4, 0x81, 2, 0, 1], 900).unwrap();
    let root = reader.next_element().unwrap().unwrap();
    let mut inside = reader.enter(&root).unwrap();
    let element = inside.next_element().unwrap().unwrap();
    let reading = inside.integer_reading(&element).unwrap();
    let fault = reading.fault().unwrap();
    assert_eq!(fault.offset(), 902);
    assert_eq!(fault.path().indices(), &[0, 0]);
    assert_eq!(reading.value().as_u32(), Some(1));
}

#[test]
fn nested_diagnostic_refusal_rolls_back_partial_path_storage() {
    // Sweep tight quotas across copying and growing a deep diagnostic path:
    // every refusal drops partial storage and leaves the producing path intact.
    let mut bytes = vec![2, 2, 0, 1];
    for _ in 0..8 {
        bytes = [&[48, u8::try_from(bytes.len()).unwrap()][..], &bytes].concat();
    }
    let source = memory(65536, 1_000_000);
    let parser = Parser::der(source.clone());
    let mut reader = parser.read(&bytes, 400).unwrap();
    for _ in 0..8 {
        let element = reader.next_element().unwrap().unwrap();
        reader = reader.enter(&element).unwrap();
    }
    let element = reader.next_element().unwrap().unwrap();
    let retained = source.used();
    let mut refused = false;
    let mut admitted = false;
    for storage in 0..=128 {
        let execution = memory(storage, 1_000_000);
        reader = reader.with_execution(&execution);
        match reader.integer_reading(&element) {
            Ok(reading) => {
                admitted = true;
                assert_eq!(reading.fault().unwrap().path().indices(), &[0; 9]);
            }
            Err(error) => {
                refused = true;
                assert!(error.is_resource());
                assert_eq!(error.offset(), 416);
            }
        }
        assert_eq!(execution.used(), 0);
        assert_eq!(source.used(), retained);
    }
    assert!(refused && admitted);
}
