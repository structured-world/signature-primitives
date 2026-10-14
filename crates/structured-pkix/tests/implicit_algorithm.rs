//! Trusted IMPLICIT schema tags must share the original algorithm reader.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::algorithm;

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

#[test]
fn original_context_tag_and_ber_parameters_are_not_serialized_to_sequence() {
    // Algorithm-specific equality needs the original BER parameters, including
    // their headers, and must not receive a fabricated canonical SEQUENCE.
    let encoded = [0xa1, 6, 6, 1, 42, 5, 0x81, 0];
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let identifier = algorithm::read_implicit(
        &reader,
        &element,
        1,
        "cmsAlgorithmProtection.signatureAlgorithm",
    )
    .unwrap();
    assert_eq!(identifier.as_bytes(), encoded);
    assert_eq!(identifier.as_bytes().as_ptr(), encoded.as_ptr());
    assert_eq!(identifier.algorithm().as_bytes(), [42]);
    assert_eq!(identifier.parameters(), Some(&[5, 0x81, 0][..]));
    assert!(algorithm::read(&reader, &element, "ordinary").is_err());
    assert!(algorithm::read_implicit(&reader, &element, 2, "mac").is_err());
}

#[test]
fn current_account_and_original_local_work_are_preserved() {
    // Rebinding funding cannot give nested parameter validation a fresh budget.
    let encoded = [0xa1, 3, 6, 1, 42];
    let old = memory();
    let current = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 3,
            ..Limits::default()
        },
        old.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let old_work = old.work_used();
    let reader = reader.with_execution(&current);
    let error = algorithm::read_implicit(&reader, &element, 1, "protected").unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "protected");
    assert_eq!(old.work_used(), old_work);
    assert_eq!(current.used(), 0);
}

#[test]
fn implicit_schema_refuses_wrong_class_construction_and_extra_components() {
    // Trusted schema tagging cannot relax the original AlgorithmIdentifier
    // cardinality or admit an unrelated application/private/primitive value.
    let parser = Parser::ber(memory());
    for encoded in [
        &[0x61, 3, 6, 1, 42][..],
        &[0xe1, 3, 6, 1, 42][..],
        &[0x81, 3, 6, 1, 42][..],
        &[0xa2, 3, 6, 1, 42][..],
        &[0xa1, 7, 6, 1, 42, 5, 0, 5, 0][..],
    ] {
        let mut reader = parser.read(encoded, 700).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let error = algorithm::read_implicit(&reader, &element, 1, "protected").unwrap_err();
        assert!(!error.is_resource());
        assert_eq!(error.field(), "protected");
        assert_eq!(error.offset(), 700);
    }
}

#[test]
fn ordinary_and_implicit_forms_share_parameter_validation_and_values() {
    // Schema tag choice changes only the original envelope handed to callers;
    // BER/DER parameter validation and algorithm fields use one semantic core.
    let execution = memory();
    let parser = Parser::ber(execution.clone());
    let sequence = [0x30, 6, 6, 1, 42, 2, 1, 7];
    let context = [0xa1, 6, 6, 1, 42, 2, 1, 7];
    let mut ordinary = parser.read(&sequence, 400).unwrap();
    let element = ordinary.next_element().unwrap().unwrap();
    let ordinary = algorithm::read(&ordinary, &element, "ordinary").unwrap();
    let mut implicit = parser.read(&context, 500).unwrap();
    let element = implicit.next_element().unwrap().unwrap();
    let implicit = algorithm::read_implicit(&implicit, &element, 1, "protected").unwrap();
    assert_eq!(ordinary.algorithm(), implicit.algorithm());
    assert_eq!(ordinary.parameters(), implicit.parameters());
    assert!(ordinary.matches(&implicit, &execution).unwrap());
    assert_eq!(ordinary.as_bytes(), sequence);
    assert_eq!(implicit.as_bytes(), context);
    let parser = Parser::der(execution);
    let sequence = [0x30, 6, 6, 1, 42, 5, 0x81, 0];
    let context = [0xa1, 6, 6, 1, 42, 5, 0x81, 0];
    let mut ordinary = parser.read(&sequence, 400).unwrap();
    let element = ordinary.next_element().unwrap().unwrap();
    let ordinary = algorithm::read(&ordinary, &element, "ordinary").unwrap_err();
    let mut implicit = parser.read(&context, 500).unwrap();
    let element = implicit.next_element().unwrap().unwrap();
    let implicit = algorithm::read_implicit(&implicit, &element, 1, "protected").unwrap_err();
    assert_eq!(ordinary.code(), implicit.code());
    assert!(!ordinary.is_resource());
    assert!(!implicit.is_resource());
}
