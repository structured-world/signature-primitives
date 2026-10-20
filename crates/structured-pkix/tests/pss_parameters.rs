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

#[test]
fn retained_readers_share_producing_schema_values_and_located_failures() {
    // Both public boundaries must use one grammar, including BER defaults,
    // malformed wrappers and unknown values that are not backend decisions.
    let hash = alg(SHA256, None);
    let mask = alg(MGF1, Some(&alg(SHA1, Some(&[5, 0]))));
    let mut complete = tlv(0xa0, &hash);
    complete.extend(tlv(0xa1, &mask));
    complete.extend(tlv(0xa2, &tlv(2, &[1; 20])));
    complete.extend(tlv(0xa3, &[2, 1, 2]));
    let cases = [
        alg(oid::RSASSA_PSS.as_bytes(), None),
        message(&[]),
        message(&complete),
        message(&[0xa2, 3, 2, 1, 20]),
        alg(oid::RSASSA_PSS.as_bytes(), Some(&[5, 0])),
        alg(&[42, 3], Some(&[48, 0])),
        message(&[0xa2, 3, 2, 1, 7, 0xa2, 3, 2, 1, 7]),
        message(&[0xa3, 3, 2, 1, 2, 0xa2, 3, 2, 1, 7]),
        message(&[0xa4, 0]),
        message(&[0xa2, 0]),
        message(&[0xa2, 3, 2, 1, 0xff]),
        message(&tlv(0xa1, &alg(MGF1, None))),
    ];
    for encoding in [Encoding::Ber, Encoding::Der] {
        for bytes in &cases {
            let source = Parser::new(encoding, Limits::default(), memory());
            let (reader, id) = identifier(&source, bytes);
            let current = memory();
            match (pss::read_in(id, &reader), pss::read(id, &current)) {
                (Ok(Some(producing)), Ok(Some(retained))) => {
                    assert_eq!(
                        producing.element().as_bytes(),
                        retained.element().as_bytes()
                    );
                    assert_eq!(
                        retained.element().as_bytes().as_ptr(),
                        id.parameters().unwrap().as_ptr()
                    );
                    assert_eq!(producing.element().span(), retained.element().span());
                    assert_eq!(
                        producing.hash().map(|hash| hash.value().as_bytes()),
                        retained.hash().map(|hash| hash.value().as_bytes())
                    );
                    assert_eq!(producing.salt().as_u64(), retained.salt().as_u64());
                    assert_eq!(producing.trailer().as_u64(), retained.trailer().as_u64());
                }
                (Ok(None), Ok(None)) => assert!(id.parameters().is_none()),
                (Err(producing), Err(retained)) => {
                    assert_eq!(
                        (producing.code(), producing.field(), producing.offset()),
                        (retained.code(), retained.field(), retained.offset())
                    );
                }
                results => panic!("different schema answers: {results:?}"),
            }
            match (pss::inspect_in(id, &reader), pss::inspect(id, &current)) {
                (Ok(Some(producing)), Ok(Some(retained))) => {
                    assert_eq!(
                        producing.parameters().element().as_bytes(),
                        retained.parameters().element().as_bytes()
                    );
                    let producing: Vec<_> = producing
                        .faults()
                        .iter()
                        .map(|fault| (fault.code(), fault.field(), fault.offset()))
                        .collect();
                    let retained: Vec<_> = retained
                        .faults()
                        .iter()
                        .map(|fault| (fault.code(), fault.field(), fault.offset()))
                        .collect();
                    assert_eq!(producing, retained);
                }
                (Ok(None), Ok(None)) => assert!(id.parameters().is_none()),
                (Err(producing), Err(retained)) => {
                    assert_eq!(
                        (producing.code(), producing.offset()),
                        (retained.code(), retained.offset())
                    );
                }
                results => panic!("different inspection answers: {results:?}"),
            }
            assert_eq!(current.used(), 0);
        }
    }
}

#[test]
fn retained_results_keep_original_hashes_wide_values_and_temporary_query_lifetime() {
    // Hash and MGF identities cannot merge, wide numbers cannot be projected
    // through a sentinel, and a borrowed result must outlive its short query.
    let hash = alg(SHA256, None);
    // Absent SHA1 parameters retain the hash identity without spelling the
    // literal ASN.1 MGF1-SHA1 DEFAULT (which would be a DER fault).
    let mask_hash = alg(SHA1, None);
    let mut fields = tlv(0xa0, &hash);
    fields.extend(tlv(0xa1, &alg(MGF1, Some(&mask_hash))));
    fields.extend(tlv(0xa2, &tlv(2, &[1; 20])));
    fields.extend(tlv(0xa3, &[2, 1, 2]));
    let bytes = message(&fields);
    let source = Parser::der(memory());
    let id = identifier(&source, &bytes).1;
    let old = source.memory().work_used();
    let values = {
        let current = memory();
        let operation = Parser::der(current.clone());
        let query = operation.read(&[], 900).unwrap();
        let values = pss::read(id, &query.execution()).unwrap().unwrap();
        assert_eq!(current.used(), 0);
        values
    };
    assert_eq!(
        values.hash().unwrap().value().algorithm().as_bytes(),
        SHA256
    );
    let pss::Mask::Mgf1 { hash: mgf_hash, .. } = values.mask() else {
        panic!("MGF1");
    };
    assert_eq!(mgf_hash.algorithm().as_bytes(), SHA1);
    assert_eq!(values.salt().as_u64(), None);
    let pss::Number::Written(salt) = values.salt() else {
        panic!("written salt");
    };
    assert_eq!(salt.value().as_bytes(), &[1; 20]);
    assert_eq!(values.trailer().as_u64(), Some(2));
    assert_eq!(source.memory().work_used(), old);
    assert_eq!(values.element().as_bytes().as_ptr(), bytes[13..].as_ptr());
}

#[test]
fn retained_inspection_retains_current_account_faults_after_operation_drop() {
    // DER spelling diagnostics survive independently of the original Reader
    // and temporary Work; only their current capacity owner retains the charge.
    let source = Parser::der(memory());
    let bytes = message(&[0xa2, 3, 2, 1, 20]);
    let id = identifier(&source, &bytes).1;
    let old_work = source.memory().work_used();
    let old_storage = source.memory().used();
    let current = memory();
    let reading = {
        let operation = Parser::der(current.clone());
        let query = operation.read(&[], 900).unwrap();
        pss::inspect(id, &query.execution()).unwrap().unwrap()
    };
    assert_eq!(reading.parameters().salt().as_u64(), Some(20));
    assert_eq!(
        (reading.faults()[0].code(), reading.faults()[0].offset()),
        (ErrorCode::DefaultWritten, 415)
    );
    assert_eq!(source.memory().used(), old_storage);
    assert_eq!(source.memory().work_used(), old_work);
    assert!(current.used() > 0);
    drop(reading);
    assert_eq!(current.used(), 0);
}

fn retained_cost(
    local: u64,
    aggregate: usize,
    source_limit: u64,
    inspection: bool,
) -> (structured_pkix::Result<()>, usize) {
    let bytes = message(&[0xa2, 3, 2, 1, if inspection { 20 } else { 32 }]);
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: source_limit,
            ..Limits::default()
        },
        memory(),
    );
    let id = identifier(&source, &bytes).1;
    let current = Memory::new(Arc::new(MemoryAccount::new(4096, aggregate)));
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_work: local,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = operation.read(&[], 900).unwrap();
    let result = if inspection {
        pss::inspect(id, &query.execution()).map(|_| ())
    } else {
        pss::read(id, &query.execution()).map(|_| ())
    };
    assert_eq!(current.used(), 0);
    (result, current.work_used())
}

#[test]
fn retained_work_admission_covers_source_current_aggregate_and_fault_copy() {
    // The exact full cost includes fault admission under both source/current
    // ceilings. A new funded account cannot reset the old parser's ceiling.
    for inspection in [false, true] {
        let (result, cost) = retained_cost(100_000, 100_000, 100_000, inspection);
        result.unwrap();
        retained_cost(cost as u64, cost, 100_000, inspection)
            .0
            .unwrap();
        for (local, aggregate) in [
            (0, 100_000),
            (cost as u64 - 1, 100_000),
            (100_000, 0),
            (100_000, cost - 1),
        ] {
            assert!(
                retained_cost(local, aggregate, 100_000, inspection)
                    .0
                    .unwrap_err()
                    .is_resource()
            );
        }
        let bytes = message(&[0xa2, 3, 2, 1, if inspection { 20 } else { 32 }]);
        let original = memory();
        let parser = Parser::der(original.clone());
        identifier(&parser, &bytes);
        let source_cost = original.work_used();
        retained_cost(
            100_000,
            100_000,
            source_cost as u64 + cost as u64,
            inspection,
        )
        .0
        .unwrap();
        assert!(
            retained_cost(
                100_000,
                100_000,
                source_cost as u64 + cost as u64 - 1,
                inspection
            )
            .0
            .unwrap_err()
            .is_resource()
        );
    }
}

#[test]
fn retained_absence_and_unknown_algorithm_still_require_source_work() {
    // No-parameter/unknown-ID gates are metadata work, not free fallbacks.
    // Neither can manufacture defaults or skip the original cumulative limit.
    for bytes in [alg(oid::RSASSA_PSS.as_bytes(), None), alg(&[42, 3], None)] {
        let source = Parser::der(memory());
        let id = identifier(&source, &bytes).1;
        let stopped = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        let error = pss::inspect(id, &stopped).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), 400);
        assert_eq!(stopped.work_used(), 0);
        assert_eq!(stopped.used(), 0);
    }
}

#[test]
fn retained_nested_and_implicit_identifiers_keep_real_depth_and_encoding() {
    // A retained IMPLICIT identifier must not add an invented SEQUENCE layer
    // or reset its enclosing depth. BER EOCs remain original parameter bytes.
    for tag in [0x30, 0xa1] {
        let mut id_bytes = message(&[0xa2, 3, 2, 1, 32]);
        id_bytes[0] = tag;
        let bytes = tlv(48, &id_bytes);
        let source = Parser::der(memory());
        let mut outer = source.read(&bytes, 400).unwrap();
        let root = outer.next_element().unwrap().unwrap();
        let mut inside = outer.enter(&root).unwrap();
        let element = inside.next_element().unwrap().unwrap();
        let id = if tag == 0x30 {
            algorithm::read(&inside, &element, "signature")
        } else {
            algorithm::read_implicit(&inside, &element, 1, "signature")
        }
        .unwrap();
        drop(inside);
        drop(outer);
        for (depth, success) in [(3, false), (4, true)] {
            let operation = Parser::new(
                Encoding::Der,
                Limits {
                    max_depth: depth,
                    ..Limits::default()
                },
                memory(),
            );
            let query = operation.read(&[], 900).unwrap();
            let result = pss::read(id, &query.execution());
            if success {
                assert_eq!(result.unwrap().unwrap().salt().as_u64(), Some(32));
            } else {
                assert!(result.unwrap_err().is_resource());
            }
        }
    }
    let parameters = [48, 0x80, 0xa2, 0x80, 2, 0x81, 1, 32, 0, 0, 0, 0];
    let bytes = alg(oid::RSASSA_PSS.as_bytes(), Some(&parameters));
    let source = Parser::ber(memory());
    let id = identifier(&source, &bytes).1;
    let reading = pss::inspect(id, &memory()).unwrap().unwrap();
    assert_eq!(reading.parameters().element().as_bytes(), parameters);
    assert_eq!(reading.faults(), []);
}

#[test]
fn retained_inspection_capacity_refusal_never_loses_a_diagnostic() {
    // A readable DEFAULT with insufficient diagnostic capacity must fail,
    // release scratch, and never return successful fields with no fault.
    let source = Parser::der(memory());
    let bytes = message(&[0xa2, 3, 2, 1, 20]);
    let id = identifier(&source, &bytes).1;
    let mut diagnostic_refused = false;
    let mut retained = false;
    for capacity in [0, 16, 64, 128, 512, 4096] {
        let current = Memory::new(Arc::new(MemoryAccount::new(capacity, 100_000)));
        match pss::inspect(id, &current) {
            Err(error) => {
                assert!(error.is_resource());
                diagnostic_refused |= error.offset() == 415;
            }
            Ok(Some(reading)) => {
                assert_eq!(reading.faults().len(), 1);
                retained = true;
            }
            Ok(None) => panic!("written parameter cannot become absence"),
        }
        assert_eq!(current.used(), 0);
    }
    assert!(diagnostic_refused && retained);
}

fn pss_certificate(key: u8, restrictions: Option<&[u8]>) -> Vec<u8> {
    // Trusted schema fixture only: the callback below observes parameter
    // provenance/role, never claims these byte-sized RSA keys are usable.
    let signature = message(&[0xa2, 3, 2, 1, 48]);
    let name = tlv(48, &tlv(49, &tlv(48, &[6, 3, 85, 4, 3, 12, 1, b'A'])));
    let date = tlv(23, b"261012120000Z");
    let spki = tlv(
        48,
        &[
            alg(oid::RSASSA_PSS.as_bytes(), restrictions),
            tlv(3, &[0, key]),
        ]
        .concat(),
    );
    let tbs = tlv(
        48,
        &[
            tlv(2, &[1]),
            signature.clone(),
            name.clone(),
            tlv(48, &[date.clone(), date].concat()),
            name,
            spki,
        ]
        .concat(),
    );
    tlv(48, &[tbs, signature, tlv(3, &[0, 1])].concat())
}

#[test]
fn verification_callback_reads_signature_and_key_parameters_without_a_reader() {
    // The actual public Verify boundary supplies no producing Reader. It
    // must still distinguish signature salt from key minimum, and absence
    // from malformed NULL, while using each identifier's original source.
    use core::cell::Cell;
    use structured_pkix::{
        Certificate,
        path::{
            self, Anchor, Interval, Policy, ValidationBounds, ValidationContext, Verified, Verify,
            WorkingKey,
        },
    };
    struct Provider {
        calls: Cell<usize>,
        restricted: bool,
    }
    impl<W: Work> Verify<W> for Provider {
        type Error = structured_pkix::Error;
        fn verify(
            &self,
            algorithm: &AlgorithmIdentifier<'_>,
            key: WorkingKey<'_>,
            _: &[u8],
            _: structured_pkix::signature::SignatureValue<'_>,
            work: &W,
        ) -> Result<Verified, Self::Error> {
            let signature = pss::read(*algorithm, work)?.unwrap();
            assert_eq!(signature.salt().as_u64(), Some(48));
            let restriction = pss::read(key.key().algorithm(), work)?;
            if self.restricted {
                let restriction = restriction.unwrap();
                assert_eq!(restriction.salt().as_u64(), Some(32));
                assert_eq!(
                    restriction.element().as_bytes().as_ptr(),
                    key.parameters().unwrap().as_ptr()
                );
            } else {
                assert!(restriction.is_none());
            }
            self.calls.set(self.calls.get() + 1);
            Ok(Verified::Yes)
        }
    }
    for restrictions in [None, Some(&[48, 5, 0xa2, 3, 2, 1, 32][..])] {
        let source = Parser::der(memory());
        let root_source = Parser::der(memory());
        let leaf_bytes = pss_certificate(7, None);
        let root_bytes = pss_certificate(8, restrictions);
        let leaf = Certificate::read(&source, &leaf_bytes, 400).unwrap();
        let root = Certificate::read(&root_source, &root_bytes, 800).unwrap();
        let operation = Parser::der(memory());
        let query = operation.read(&[], 9000).unwrap();
        let work = query.execution();
        let provider = Provider {
            calls: Cell::new(0),
            restricted: restrictions.is_some(),
        };
        let context = ValidationContext {
            execution: &work,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &provider,
            watch: &(),
            recognizer: &(),
        };
        assert!(matches!(
            path::validate(
                &[&leaf],
                Anchor::new(root.tbs().subject(), root.tbs().public_key()),
                &context
            )
            .unwrap(),
            path::Validation::Accepted(_)
        ));
        assert_eq!(provider.calls.get(), 1);
        let projected = WorkingKey::standing(root.tbs().public_key())
            .subject(&leaf, &work)
            .unwrap();
        assert_eq!(projected.parameters(), None);
        assert!(
            pss::read(projected.key().algorithm(), &work)
                .unwrap()
                .is_none()
        );
    }
    let source = Parser::der(memory());
    let encoded = pss_certificate(7, Some(&[5, 0]));
    let certificate = Certificate::read(&source, &encoded, 400).unwrap();
    let error = pss::read(certificate.tbs().public_key().algorithm(), &memory()).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
    assert!(!error.is_resource());
}
