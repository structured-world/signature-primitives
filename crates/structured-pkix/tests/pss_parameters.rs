//! PSS schema extraction preserves original values and producing execution.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Parser, Reader};
use structured_pkix::algorithm::{self, AlgorithmIdentifier, pss};
use structured_pkix::{ErrorCode, oid};

const SHA1: &[u8] = &[0x2b, 0x0e, 3, 2, 0x1a];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
const MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 8];

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 100_000_000)))
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if value.len() < 128 {
        bytes.push(u8::try_from(value.len()).unwrap());
    } else {
        bytes.extend_from_slice(&[0x81, u8::try_from(value.len()).unwrap()]);
    }
    bytes.extend_from_slice(value);
    bytes
}

fn alg(oid: &[u8], parameters: Option<&[u8]>) -> Vec<u8> {
    let mut fields = tlv(6, oid);
    fields.extend_from_slice(parameters.unwrap_or(&[]));
    tlv(0x30, &fields)
}

fn message(fields: &[u8]) -> Vec<u8> {
    alg(oid::RSASSA_PSS.as_bytes(), Some(&tlv(0x30, fields)))
}

fn identifier<'a>(parser: &'a Parser, bytes: &'a [u8]) -> (Reader<'a>, AlgorithmIdentifier<'a>) {
    let mut reader = parser.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let identifier = algorithm::read(&reader, &element, "signatureAlgorithm").unwrap();
    (reader, identifier)
}

#[test]
fn omitted_parameters_and_empty_parameters_are_different_facts() {
    // A key may omit restrictions; an empty written sequence names all four
    // defaults. Signature-role rejection of absence belongs to the consumer.
    let parser = Parser::der(memory());
    let absent = alg(oid::RSASSA_PSS.as_bytes(), None);
    let (reader, id) = identifier(&parser, &absent);
    assert!(pss::read_in(id, &reader).unwrap().is_none());
    let bytes = message(&[]);
    let (reader, id) = identifier(&parser, &bytes);
    let values = pss::read_in(id, &reader).unwrap().unwrap();
    assert!(values.hash().is_none());
    assert!(matches!(values.mask(), pss::Mask::DefaultMgf1Sha1));
    assert!(matches!(values.salt(), pss::Number::Default(20)));
    assert!(matches!(values.trailer(), pss::Number::Default(1)));
    assert_eq!(values.element().as_bytes().as_ptr(), bytes[13..].as_ptr());
    assert_eq!(values.element().span().start, 413);
}

#[test]
fn only_the_pss_identifier_and_sequence_parameter_are_accepted() {
    // NULL is a wrong PSS parameter type, not omitted restrictions. An
    // unrelated algorithm's SEQUENCE cannot be interpreted as PSS defaults.
    let parser = Parser::der(memory());
    for parameter in [&[5, 0][..], &[2, 1, 1][..], &[4, 0][..]] {
        let bytes = alg(oid::RSASSA_PSS.as_bytes(), Some(parameter));
        let (reader, id) = identifier(&parser, &bytes);
        let error = pss::inspect_in(id, &reader).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
        );
        assert_eq!(error.offset(), 413);
    }
    let bytes = alg(&[42, 3], Some(&[0x30, 0]));
    let (reader, id) = identifier(&parser, &bytes);
    let error = pss::read_in(id, &reader).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedField);
    assert_eq!(error.offset(), 400);
}

#[test]
fn hash_and_mgf_hash_remain_independent_original_identifiers() {
    // Different message/MGF hashes are a provider capability question. The
    // schema must not silently substitute one for the other or force equality.
    let hash = alg(SHA256, None);
    let mask_hash = alg(SHA1, Some(&[5, 0]));
    let mask = alg(MGF1, Some(&mask_hash));
    let mut fields = tlv(0xa0, &hash);
    fields.extend(tlv(0xa1, &mask));
    fields.extend(tlv(0xa2, &[2, 1, 32]));
    let bytes = message(&fields);
    let parser = Parser::ber(memory());
    let (reader, id) = identifier(&parser, &bytes);
    let values = pss::read_in(id, &reader).unwrap().unwrap();
    assert_eq!(
        values.hash().unwrap().value().algorithm().as_bytes(),
        SHA256
    );
    let pss::Mask::Mgf1 { function, hash } = values.mask() else {
        panic!("MGF1")
    };
    assert_eq!(function.value().algorithm().as_bytes(), MGF1);
    assert_eq!(hash.as_bytes(), mask_hash);
    assert!(hash.has_null_parameter());
    assert_eq!(values.salt().as_u64(), Some(32));
    let pss::Number::Written(salt) = values.salt() else {
        panic!("written salt")
    };
    assert_eq!(salt.value().as_bytes(), &[32]);
    assert_eq!(salt.element().as_bytes(), &[0xa2, 3, 2, 1, 32]);
    assert!(
        bytes
            .windows(mask_hash.len())
            .any(|part| part.as_ptr() == hash.as_bytes().as_ptr())
    );
}

#[test]
fn written_defaults_are_ber_values_and_located_der_inspection_faults() {
    // RFC4055 requires recognizing present defaults. Inspection retains their
    // meaning while distinguishing X.690 11.5 DER spelling from BER syntax.
    for null in [None, Some(&[5, 0][..])] {
        let hash = alg(SHA1, null);
        let mask = alg(MGF1, Some(&hash));
        let mut fields = tlv(0xa0, &hash);
        fields.extend(tlv(0xa1, &mask));
        fields.extend(tlv(0xa2, &[2, 1, 20]));
        fields.extend(tlv(0xa3, &[2, 1, 1]));
        let bytes = message(&fields);
        for encoding in [Encoding::Ber, Encoding::Der] {
            let account = memory();
            let parser = Parser::new(encoding, Limits::default(), account.clone());
            let (reader, id) = identifier(&parser, &bytes);
            let baseline = account.used();
            let reading = pss::inspect_in(id, &reader).unwrap().unwrap();
            assert_eq!(reading.parameters().salt().as_u64(), Some(20));
            if encoding.is_der() {
                let expected = if null.is_some() { 4 } else { 2 };
                assert_eq!(reading.faults().len(), expected);
                assert!(
                    reading
                        .faults()
                        .iter()
                        .all(|fault| fault.code() == ErrorCode::DefaultWritten)
                );
                let first = if null.is_some() {
                    415
                } else {
                    415 + fields.len() as u64 - 10
                };
                assert_eq!(reading.faults()[0].offset(), first);
                assert_eq!(
                    pss::read_in(id, &reader).unwrap_err().code(),
                    ErrorCode::DefaultWritten
                );
                assert!(account.used() > baseline);
            } else {
                assert_eq!(reading.faults(), []);
                assert!(pss::read_in(id, &reader).is_ok());
            }
            drop(reading);
            assert_eq!(account.used(), baseline);
        }
    }
}

#[test]
fn unknown_algorithms_and_wide_numbers_are_preserved_without_backend_limits() {
    // The old backend's u32/MAX_SALT boundary must not truncate a schema value.
    let hash = alg(&[42, 3], Some(&[4, 1, 9]));
    let mask = alg(&[42, 4], Some(&[4, 1, 7]));
    let mut fields = tlv(0xa0, &hash);
    fields.extend(tlv(0xa1, &mask));
    fields.extend(tlv(0xa2, &tlv(2, &[1; 20])));
    fields.extend(tlv(0xa3, &[2, 1, 2]));
    let bytes = message(&fields);
    let parser = Parser::der(memory());
    let (reader, id) = identifier(&parser, &bytes);
    let values = pss::read_in(id, &reader).unwrap().unwrap();
    assert_eq!(values.hash().unwrap().value().as_bytes(), hash);
    assert!(matches!(values.mask(), pss::Mask::Other(_)));
    assert_eq!(values.salt().as_u64(), None);
    let pss::Number::Written(salt) = values.salt() else {
        panic!("wide salt")
    };
    assert_eq!(salt.value().as_bytes(), &[1; 20]);
    assert_eq!(values.trailer().as_u64(), Some(2));
}

#[test]
fn absent_sha1_parameters_are_not_the_literal_asn1_default_value() {
    // RFC4055 §2.1 permits absent SHA1 parameters, but its named ASN.1
    // sha1Identifier DEFAULT includes NULL. Equivalent crypto identities do
    // not manufacture an optional component for X.690 11.5 value equality.
    let hash = alg(SHA1, None);
    let mask = alg(MGF1, Some(&hash));
    let mut fields = tlv(0xa0, &hash);
    fields.extend(tlv(0xa1, &mask));
    let bytes = message(&fields);
    let parser = Parser::der(memory());
    let (reader, id) = identifier(&parser, &bytes);
    let reading = pss::inspect_in(id, &reader).unwrap().unwrap();
    assert_eq!(reading.faults(), []);
    assert!(pss::read_in(id, &reader).is_ok());
}

#[test]
fn schema_rejects_duplicates_order_unknown_fields_and_wrapper_tails() {
    // Each wrapper contains exactly one value and fields occur once in order;
    // inspection cannot turn ambiguous structure into partial successful facts.
    for fields in [
        vec![0xa2, 3, 2, 1, 7, 0xa2, 3, 2, 1, 7],
        vec![0xa3, 3, 2, 1, 2, 0xa2, 3, 2, 1, 7],
        vec![0xa4, 0],
        vec![0x82, 1, 7],
        vec![0xa2, 0],
        vec![0xa2, 6, 2, 1, 7, 2, 1, 8],
        vec![0xa2, 3, 2, 1, 0xff],
        tlv(0xa1, &alg(MGF1, None)),
        tlv(0xa1, &alg(MGF1, Some(&[4, 0]))),
    ] {
        let bytes = message(&fields);
        let parser = Parser::ber(memory());
        let (reader, id) = identifier(&parser, &bytes);
        let error = pss::inspect_in(id, &reader).unwrap_err();
        assert!(!error.is_resource());
        assert!(error.offset() >= 413);
    }
}

#[test]
fn foreign_parser_and_exhausted_current_work_refuse_before_parameter_access() {
    // Sharing Memory does not establish a producing session. A new current
    // execution must fund even an otherwise cached empty/default parameter set.
    let account = memory();
    let parser = Parser::der(account.clone());
    let foreign = Parser::der(account.clone());
    let bytes = message(&[]);
    let (reader, id) = identifier(&parser, &bytes);
    let other = foreign.read(&[], 900).unwrap();
    let work = account.work_used();
    let error = pss::read_in(id, &other).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ForeignReader);
    assert_eq!(error.offset(), 400);
    assert_eq!(account.work_used(), work);
    let current = Memory::new(Arc::new(MemoryAccount::new(4096, 0)));
    let before = account.work_used();
    let error = pss::read_in(id, &reader.with_execution(&current)).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 400);
    assert_eq!(account.work_used(), before);
    assert_eq!(current.used(), 0);
}

#[test]
fn original_local_work_ceiling_survives_deferred_parameter_reading() {
    // Aggregate resources remain ample: only the producing parser's original
    // local ceiling is one unit short of this exact complete operation.
    let bytes = message(&tlv(0xa2, &[2, 1, 32]));
    let account = memory();
    let parser = Parser::der(account.clone());
    let (reader, id) = identifier(&parser, &bytes);
    pss::read_in(id, &reader).unwrap().unwrap();
    let total = account.work_used();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: u64::try_from(total - 1).unwrap(),
            ..Limits::default()
        },
        memory(),
    );
    let (reader, id) = identifier(&parser, &bytes);
    assert!(pss::read_in(id, &reader).unwrap_err().is_resource());
}

#[test]
fn indefinite_ber_wrappers_retain_original_ranges() {
    // BER length spellings change no parameter meaning, and both enclosing
    // EOCs must remain outside the INTEGER value and inside original coverage.
    let parameters = [0x30, 0x80, 0xa2, 0x80, 2, 0x81, 1, 32, 0, 0, 0, 0];
    let bytes = alg(oid::RSASSA_PSS.as_bytes(), Some(&parameters));
    let parser = Parser::ber(memory());
    let (reader, id) = identifier(&parser, &bytes);
    let reading = pss::inspect_in(id, &reader).unwrap().unwrap();
    assert_eq!(reading.faults(), []);
    assert_eq!(reading.parameters().element().as_bytes(), parameters);
    let pss::Number::Written(salt) = reading.parameters().salt() else {
        panic!("salt")
    };
    assert_eq!(salt.element().as_bytes(), &parameters[2..10]);
    assert_eq!(salt.value().as_bytes(), &[32]);
    assert_eq!(salt.element().span().start, 415);
}

#[test]
fn shorter_operation_does_not_shorten_original_input_views() {
    // A current query is temporary; schema views and retained faults must not
    // borrow its execution/Reader or lose the original document coordinates.
    let source = Parser::der(memory());
    let bytes = message(&[0xa2, 3, 2, 1, 20]);
    let (_, id) = identifier(&source, &bytes);
    let current = memory();
    let old_work = source.memory().work_used();
    let reading = {
        let query = Parser::der(current.clone());
        let root = query.read(&[], 900).unwrap();
        let execution = root.execution();
        let parent = execution
            .read_scoped_source(&source, &[], 900, Encoding::Der, 0)
            .unwrap();
        pss::inspect_in(id, &parent).unwrap().unwrap()
    };
    assert_eq!(reading.parameters().salt().as_u64(), Some(20));
    assert_eq!(reading.faults()[0].offset(), 415);
    assert_eq!(source.memory().work_used(), old_work);
    assert!(current.used() > 0);
    drop(reading);
    assert_eq!(current.used(), 0);
}

#[test]
fn scoped_query_depth_cannot_reset_to_the_source_allowance() {
    // The original identifier was already decoded under a wider source
    // allowance. Opening cached fields must still obey this narrower query.
    let source = Parser::der(memory());
    let bytes = message(&[0xa2, 3, 2, 1, 32]);
    let (_, id) = identifier(&source, &bytes);
    let query = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 2,
            ..Limits::default()
        },
        memory(),
    );
    let root = query.read(&[], 900).unwrap();
    let execution = root.execution();
    let parent = execution
        .read_scoped_source(&source, &[], 900, Encoding::Der, 0)
        .unwrap();
    let error = pss::read_in(id, &parent).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 417);
}

#[test]
fn diagnostic_capacity_refusal_is_terminal_and_releases_scratch() {
    // A readable DER default must never lose its fault when storage is tight.
    // Sweep capacities across parser scratch and the independent fault owner.
    let source = Parser::der(memory());
    let bytes = message(&[0xa2, 3, 2, 1, 20]);
    let (_, id) = identifier(&source, &bytes);
    let mut diagnostic_refused = false;
    let mut retained = false;
    for capacity in [0, 8, 16, 32, 64, 128, 256, 512, 1024, 4096] {
        let current = Memory::new(Arc::new(MemoryAccount::new(capacity, 100_000_000)));
        let execution = source.execution_in(&current);
        let parent = execution
            .read_scoped_source(&source, &[], 900, Encoding::Der, 0)
            .unwrap();
        match pss::inspect_in(id, &parent) {
            Err(error) => {
                assert!(error.is_resource());
                diagnostic_refused |= error.offset() == 415;
            }
            Ok(Some(reading)) => {
                assert_eq!(reading.faults().len(), 1);
                retained = true;
            }
            Ok(None) => panic!("written parameters cannot become absence"),
        }
        drop(parent);
        assert_eq!(current.used(), 0);
    }
    assert!(diagnostic_refused);
    assert!(retained);
}
