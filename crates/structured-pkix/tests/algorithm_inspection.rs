//! Malformed inspection is retained without becoming a crypto identifier.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::{ErrorCode, algorithm};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65_536, 100_000)))
}

#[test]
fn constructed_null_keeps_original_inspection_and_strict_refusal() {
    // X.690 §8.8 requires primitive NULL: retaining its unique malformed
    // spelling is diagnostic recovery and must never produce a valid ID.
    for encoding in [Encoding::Ber, Encoding::Der] {
        for tag in [0x30, 0xa1] {
            let bytes = [tag, 5, 6, 1, 42, 0x25, 0];
            let memory = memory();
            let parser = Parser::new(encoding, Limits::default(), memory.clone());
            let mut parent = parser.read(&bytes, 400).unwrap();
            let element = parent.next_element().unwrap().unwrap();
            let strict = if tag == 0x30 {
                algorithm::read(&parent, &element, "algorithm")
            } else {
                algorithm::read_implicit(&parent, &element, 1, "algorithm")
            };
            let strict = strict.unwrap_err();
            let reading = if tag == 0x30 {
                algorithm::read_inspection(&parent, &element, "algorithm")
            } else {
                algorithm::read_implicit_inspection(&parent, &element, 1, "algorithm")
            }
            .unwrap();
            assert!(reading.identifier().is_none());
            assert_eq!(reading.algorithm().as_bytes(), &[42]);
            assert_eq!(reading.parameters(), Some(&[0x25, 0][..]));
            assert_eq!(
                reading.parameters_span(),
                Some(structured_asn1::Span {
                    start: 405,
                    length: 2
                })
            );
            assert!(!reading.has_null_parameter());
            assert_eq!(reading.parameters().unwrap().as_ptr(), bytes[5..].as_ptr());
            assert_eq!(reading.as_bytes(), bytes);
            assert_eq!(reading.offset(), 400);
            assert_eq!(reading.fault().unwrap(), &strict);
            assert_eq!(reading.fault().unwrap().offset(), 405);
            assert_eq!(memory.used(), 0);
        }
    }
}

#[test]
fn malformed_opaque_identity_does_not_acquire_null_or_default_semantics() {
    // Even two differently spelled malformed NULLs retain encoded identity;
    // two valid primitive NULLs still compare by their shared parsed value.
    let cases = [
        ([0x25, 0].as_slice(), [5, 0].as_slice(), false),
        ([0x25, 0].as_slice(), [0x25, 0].as_slice(), true),
        ([0x25, 0].as_slice(), [0x25, 0x81, 0].as_slice(), false),
        ([5, 0].as_slice(), [5, 0x81, 0].as_slice(), true),
        ([5, 0].as_slice(), [].as_slice(), false),
    ];
    for (left, right, expected) in cases {
        let make = |parameter: &[u8]| {
            let mut bytes = vec![0x30, u8::try_from(3 + parameter.len()).unwrap(), 6, 1, 42];
            bytes.extend_from_slice(parameter);
            bytes
        };
        let left = make(left);
        let right = make(right);
        let parser = Parser::ber(memory());
        let mut parent = parser.read(&left, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let left = algorithm::read_inspection(&parent, &element, "left").unwrap();
        let mut parent = parser.read(&right, 900).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let right = algorithm::read_inspection(&parent, &element, "right").unwrap();
        assert_eq!(left.same_written_in(&right, &parent).unwrap(), expected);
    }
}

#[test]
fn ambiguous_or_missing_fields_are_not_an_inspection_reading() {
    // An opaque parameter requires one unambiguous schema boundary and OID;
    // recovery cannot silently choose between multiple parameters.
    for bytes in [vec![0x30, 0], vec![0x30, 7, 6, 1, 42, 0x25, 0, 5, 0]] {
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        assert!(algorithm::read_inspection(&parent, &element, "algorithm").is_err());
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn foreign_inspection_query_refuses_before_work() {
    // Retained malformed bytes cannot turn a different parser session into
    // their producing reader merely because the aggregate account is shared.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let foreign = Parser::ber(memory.clone());
    let bytes = [0x30, 5, 6, 1, 42, 0x25, 0];
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let value = algorithm::read_inspection(&parent, &element, "algorithm").unwrap();
    let query = foreign.read(&[], 900).unwrap();
    let before = (memory.used(), memory.work_used());
    let error = value.same_written_in(&value, &query).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ForeignReader);
    assert_eq!(error.offset(), 400);
    assert_eq!((memory.used(), memory.work_used()), before);
}

#[test]
fn nonempty_null_and_nested_syntax_faults_never_produce_identifiers() {
    // Unique outer fields remain available even when the shared validator
    // finds malformed primitive contents or a malformed descendant.
    for parameter in [vec![5, 1, 0], vec![0x30, 2, 0x25, 0], vec![2, 2, 0, 1]] {
        let mut bytes = vec![0x30, u8::try_from(3 + parameter.len()).unwrap(), 6, 1, 42];
        bytes.extend_from_slice(&parameter);
        let parser = Parser::ber(memory());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let strict = algorithm::read(&parent, &element, "algorithm").unwrap_err();
        let value = algorithm::read_inspection(&parent, &element, "algorithm").unwrap();
        assert!(value.identifier().is_none());
        assert_eq!(value.parameters(), Some(parameter.as_slice()));
        assert_eq!(value.fault(), Some(&strict));
        assert!(!value.fault().unwrap().is_resource());
    }
}

#[test]
fn inherited_depth_and_storage_refusals_are_terminal_before_descendant_faults() {
    // The malformed descendant cannot hide a preceding stack/catalogue
    // admission refusal. No successful partial reading or leaked capacity.
    let bytes = [0x30, 9, 6, 1, 42, 0x30, 4, 0x30, 2, 0x25, 0];
    for (storage, depth) in [(0, 32), (65_536, 1), (65_536, 2)] {
        let memory = Memory::new(Arc::new(MemoryAccount::new(storage, 100_000)));
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_depth: depth,
                ..Limits::default()
            },
            memory.clone(),
        );
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let error = algorithm::read_inspection(&parent, &element, "algorithm").unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.field(), "algorithm");
        assert!(error.offset() >= 400);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn local_and_aggregate_work_refusals_cannot_be_retained_as_malformed() {
    // Rebinding keeps the original local ceiling; aggregate exhaustion is a
    // separate terminal reason. Neither yields a document-syntax diagnostic.
    let bytes = [0x30, 5, 6, 1, 42, 0x25, 0];
    for local in [false, true] {
        let memory = memory();
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: 100_000,
                ..Limits::default()
            },
            memory.clone(),
        );
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let parent = if local {
            parent
                .charge(100_000 - u64::try_from(memory.work_used()).unwrap())
                .unwrap();
            parent.with_execution(&self::memory())
        } else {
            memory.charge_work(memory.work_remaining() as u64).unwrap();
            parent
        };
        let before = parent.memory().work_used();
        let error = algorithm::read_inspection(&parent, &element, "algorithm").unwrap_err();
        assert!(error.is_resource());
        assert_eq!(parent.memory().work_used(), before);
        assert_eq!(parent.memory().used(), 0);
    }
}

#[test]
fn malformed_written_comparison_obeys_exact_local_and_aggregate_admission() {
    // Written identity costs metadata + one OID byte + two opaque parameter
    // bytes. Exhaustion before their scan is an error, never a mismatch.
    for aggregate in [false, true] {
        for available in [0, 3, 4] {
            let memory = memory();
            let parser = Parser::new(
                Encoding::Ber,
                Limits {
                    max_work: 100_000,
                    ..Limits::default()
                },
                memory.clone(),
            );
            let bytes = [0x30, 5, 6, 1, 42, 0x25, 0];
            let mut parent = parser.read(&bytes, 400).unwrap();
            let element = parent.next_element().unwrap().unwrap();
            let reading = algorithm::read_inspection(&parent, &element, "algorithm").unwrap();
            let drain = 100_000 - u64::try_from(memory.work_used()).unwrap() - available;
            if aggregate {
                memory.charge_work(drain).unwrap();
            } else {
                parent.charge(drain).unwrap();
            }
            let before = memory.work_used();
            let result = reading.same_written_in(&reading, &parent);
            if available == 4 {
                assert!(result.unwrap());
                assert_eq!(memory.work_used() - before, 4);
            } else {
                let error = result.unwrap_err();
                assert!(error.is_resource());
                assert_eq!(error.offset(), 400);
                assert!(memory.work_used() - before <= usize::try_from(available).unwrap());
            }
            assert_eq!(memory.used(), 0);
        }
    }
}

#[test]
fn indefinite_source_and_independent_diagnostic_keep_original_positions() {
    // The enclosing EOC is not part of the parameter, and retaining a scalar
    // diagnostic must not pin parser paths or lose the original fault offset.
    let memory = memory();
    let fault = {
        let parser = Parser::ber(memory.clone());
        let bytes = [0x30, 0x80, 6, 1, 42, 0x25, 0, 0, 0];
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let reading = algorithm::read_inspection(&parent, &element, "algorithm").unwrap();
        assert_eq!(reading.parameters(), Some(&[0x25, 0][..]));
        assert_eq!(
            reading.parameters_span(),
            Some(structured_asn1::Span {
                start: 405,
                length: 2
            })
        );
        assert_eq!(reading.as_bytes(), bytes);
        reading.fault().unwrap().clone()
    };
    assert_eq!(fault.offset(), 405);
    assert_eq!(fault.field(), "algorithm");
    assert_eq!(memory.used(), 0);
}

#[test]
fn well_formed_reading_exposes_the_existing_validated_api() {
    // ASN.1 syntax validation and provider/profile acceptance are distinct:
    // a well-formed parameter still requires the selected algorithm's rules.
    let bytes = [0x30, 6, 6, 1, 42, 5, 0x81, 0];
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let reading = algorithm::read_inspection(&parent, &element, "algorithm").unwrap();
    assert!(reading.fault().is_none());
    assert!(reading.has_null_parameter());
    let identifier = reading.identifier().unwrap();
    assert!(identifier.has_null_parameter());
    assert_eq!(identifier.as_bytes(), bytes);
    assert_eq!(identifier.parameters(), reading.parameters());
    assert!(identifier.same_session(&parent));
    let strict = algorithm::read(&parent, &element, "algorithm").unwrap();
    assert!(identifier.same_written_in(&strict, &parent).unwrap());
}
