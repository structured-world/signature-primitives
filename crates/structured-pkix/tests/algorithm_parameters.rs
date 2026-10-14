//! Lazy algorithm parameters retain their actual producing provenance.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::{ErrorCode, algorithm};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

#[test]
fn parameter_reader_matches_immediate_reread_depth_and_whole_original_tlv() {
    // IMPLICIT tag choice must not add/drop a level when opening parameters.
    // The BER parameter header remains original and is interpreted as BER.
    for tag in [0x30, 0xa1] {
        let encoded = [tag, 6, 6, 1, 42, 5, 0x81, 0];
        let old = memory();
        let current = memory();
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_depth: 1,
                ..Limits::default()
            },
            old.clone(),
        );
        let mut reader = parser.read(&encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let identifier = if tag == 0x30 {
            algorithm::read(&reader, &element, "algorithm").unwrap()
        } else {
            algorithm::read_implicit(&reader, &element, 1, "protected").unwrap()
        };
        let old_work = old.work_used();
        let reader = reader.with_execution(&current);
        let mut parameters = identifier
            .parameters_reader_in(&reader, "parameters")
            .unwrap()
            .unwrap();
        assert_eq!(identifier.offset(), 400);
        assert_eq!(parameters.depth(), 1);
        assert_eq!(parameters.encoding(), Encoding::Ber);
        assert_eq!(parameters.offset(), 405);
        let parameter = parameters.next_element().unwrap().unwrap();
        assert_eq!(parameter.as_bytes(), &[5, 0x81, 0]);
        assert_eq!(parameter.as_bytes().as_ptr(), encoded[5..].as_ptr());
        assert!(parameters.is_empty());
        assert!(!parameters.enter(&parameter).unwrap_err().is_resource());
        assert_eq!(old.work_used(), old_work);
        assert!(current.work_used() > 0);
    }
}

#[test]
fn foreign_parser_refuses_before_lookup_or_account_work() {
    // Sharing aggregate Memory does not make a different parser session a
    // valid producer. Mismatch is processing misuse, not parameter absence.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let foreign = Parser::ber(memory.clone());
    let encoded = [0x30, 3, 6, 1, 42];
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let identifier = algorithm::read(&reader, &element, "algorithm").unwrap();
    let foreign = foreign.read(&[], 900).unwrap();
    let work = memory.work_used();
    let held = memory.used();
    let error = identifier
        .parameters_reader_in(&foreign, "parameters")
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ForeignReader);
    assert_eq!(error.offset(), 400);
    assert_eq!(memory.work_used(), work);
    assert_eq!(memory.used(), held);
    assert!(
        identifier
            .parameters_reader_in(&reader, "parameters")
            .unwrap()
            .is_none()
    );
    memory.charge_work(memory.work_remaining() as u64).unwrap();
    assert!(
        identifier
            .parameters_reader_in(&reader, "parameters")
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn indefinite_envelope_end_markers_are_not_parameter_bytes() {
    // Compact parameter ranges still end before the original outer EOC.
    // An absent parameter in an indefinite envelope remains genuinely absent.
    let parser = Parser::ber(memory());
    for (encoded, expected) in [
        (
            &[0x30, 0x80, 6, 1, 42, 5, 0x81, 0, 0, 0][..],
            Some(&[5, 0x81, 0][..]),
        ),
        (
            &[0xa1, 0x80, 6, 1, 42, 5, 0x81, 0, 0, 0][..],
            Some(&[5, 0x81, 0][..]),
        ),
        (&[0x30, 0x80, 6, 1, 42, 0, 0][..], None),
    ] {
        let mut reader = parser.read(encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let identifier = if encoded[0] == 0x30 {
            algorithm::read(&reader, &element, "algorithm").unwrap()
        } else {
            algorithm::read_implicit(&reader, &element, 1, "protected").unwrap()
        };
        assert_eq!(identifier.as_bytes(), encoded);
        assert_eq!(identifier.parameters(), expected);
        let parameters = identifier
            .parameters_reader_in(&reader, "parameters")
            .unwrap();
        if let Some(mut parameters) = parameters {
            assert_eq!(
                parameters.next_element().unwrap().unwrap().as_bytes(),
                expected.unwrap()
            );
            assert!(parameters.is_empty());
        } else {
            assert!(expected.is_none());
        }
    }
}

#[test]
fn deep_parameters_keep_exact_depth_encoding_and_original_local_ceiling() {
    // The parameter's third constructed level sits at depth four, not at a
    // new root. Funding a deferred read from another account cannot reset the
    // original session, including before any parameter-reader allocation.
    let encoded = [0x30, 12, 6, 1, 42, 0x30, 7, 0x30, 5, 0x30, 3, 2, 1, 7];
    let old = memory();
    let current = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 4,
            max_work: 4096,
            ..Limits::default()
        },
        old.clone(),
    );
    let mut reader = parser.read_as(&encoded, 400, Encoding::Der).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let identifier = algorithm::read(&reader, &element, "algorithm").unwrap();
    assert_eq!(identifier.encoding(), Encoding::Der);
    let reader = reader.with_execution(&current);
    let mut parameters = identifier
        .parameters_reader_in(&reader, "parameters")
        .unwrap()
        .unwrap();
    assert_eq!(parameters.depth(), 1);
    assert_eq!(parameters.encoding(), Encoding::Der);
    for expected in [2, 3, 4] {
        let element = parameters.next_element().unwrap().unwrap();
        parameters = parameters.enter(&element).unwrap();
        assert_eq!(parameters.depth(), expected);
    }
    let integer = parameters.next_element().unwrap().unwrap();
    assert_eq!(integer.span().start, 411);
    assert_eq!(parameters.integer(&integer).unwrap().as_u64(), Some(7));
    drop(parameters);
    while reader.charge(1).is_ok() {}
    let work = current.work_used();
    let held = current.used();
    let error = identifier
        .parameters_reader_in(&reader, "parameters")
        .unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 405);
    assert_eq!(error.field(), "parameters");
    assert_eq!(current.work_used(), work);
    assert_eq!(current.used(), held);
}
