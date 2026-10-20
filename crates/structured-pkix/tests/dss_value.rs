//! Shared DER signature structure, original ranges and producing execution.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Parser, Tag, universal};
use structured_pkix::signature::DssValue;
use structured_pkix::{Error, ErrorCode};

const PAIR: &[u8] = b"\x30\x06\x02\x01\x01\x02\x01\x02";

fn memory(bytes: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(bytes, work)))
}

#[test]
fn both_parent_encodings_preserve_exact_signed_bytes_and_component_spans() {
    // Sign padding is original data, not a reason to rewrite a signature.
    let bytes = b"\x30\x07\x02\x02\x00\x80\x02\x01\x01";
    for encoding in [Encoding::Ber, Encoding::Der] {
        let memory = memory(16, 4096);
        let parser = Parser::new(encoding, Limits::default(), memory.clone());
        let mut reader = parser.read(bytes, 400).unwrap();
        let value = DssValue::read(&mut reader, "signature").unwrap();
        assert_eq!(value.element().as_bytes(), bytes);
        assert_eq!(value.element().as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(value.r().as_bytes(), [0, 0x80]);
        assert_eq!(value.r().as_bytes().as_ptr(), bytes[4..].as_ptr());
        assert_eq!(value.s().as_u64(), Some(1));
        assert_eq!((value.r_span().start, value.r_span().end()), (402, 406));
        assert_eq!((value.s_span().start, value.s_span().end()), (406, 409));
        assert!(reader.is_empty());
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn a_pair_is_not_scalar_range_or_signature_acceptance() {
    // INTEGER syntax can be valid while an algorithm's scalar range is not.
    // Inspection preserves those numbers; the provider must still reject them.
    let bytes = b"\x30\x06\x02\x01\xff\x02\x01\x00";
    let parser = Parser::der(memory(16, 4096));
    let mut reader = parser.read(bytes, 400).unwrap();
    let value = DssValue::read(&mut reader, "signature").unwrap();
    assert_eq!(value.r().as_i64(), Some(-1));
    assert!(value.r().is_negative());
    assert_eq!(value.s().as_u64(), Some(0));
    assert_eq!(value.r().as_bytes(), [0xff]);
    assert_eq!(value.s().as_bytes(), [0]);
}

#[test]
fn only_the_element_entry_point_allows_surrounding_siblings() {
    // Embedded ASN.1 fields leave siblings to their schema; complete windows
    // must not silently ignore a second value after the signature pair.
    let bytes = b"\x30\x06\x02\x01\x01\x02\x01\x02\x05\x00";
    let parser = Parser::der(memory(16, 4096));
    let mut reader = parser.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = DssValue::read_element(&reader, &element, "signature").unwrap();
    assert_eq!(value.s().as_u64(), Some(2));
    let sibling = reader.expect(Tag::primitive(universal::NULL)).unwrap();
    reader.null(&sibling).unwrap();
    let mut complete = parser.read(bytes, 400).unwrap();
    let error = DssValue::read(&mut complete, "signature").unwrap_err();
    assert_eq!(
        (error.code(), error.offset()),
        (ErrorCode::TrailingData, 408)
    );
}

#[test]
fn der_restrictions_apply_even_under_a_ber_parent() {
    // BER envelope permission does not extend to ECDSA-Sig-Value's DER
    // headers or primitive, nonempty and minimal INTEGER contents.
    let cases: &[&[u8]] = &[
        b"\x30\x81\x06\x02\x01\x01\x02\x01\x02",
        b"\x30\x80\x02\x01\x01\x02\x01\x02\x00\x00",
        b"\x30\x07\x02\x81\x01\x01\x02\x01\x02",
        b"\x30\x07\x02\x02\x00\x01\x02\x01\x02",
        b"\x30\x07\x02\x02\xff\xff\x02\x01\x02",
        b"\x30\x05\x02\x00\x02\x01\x02",
        b"\x30\x06\x22\x01\x01\x02\x01\x02",
    ];
    for bytes in cases {
        let memory = memory(4096, 4096);
        let parser = Parser::ber(memory.clone());
        let mut reader = parser.read(bytes, 400).unwrap();
        let error = DssValue::read(&mut reader, "signature").unwrap_err();
        assert!(
            matches!(error.code(), ErrorCode::Encoding(_)),
            "{bytes:x?}: {error:?}"
        );
        assert_eq!(error.field(), "signature");
        assert!(!error.is_resource());
        drop(reader);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn missing_extra_and_wrong_fields_keep_their_original_locations() {
    // No fallback searches for a later INTEGER, and no third field vanishes.
    for (bytes, code, offset) in [
        (
            &b"\x30\x03\x02\x01\x01"[..],
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedEnd),
            405,
        ),
        (
            &b"\x30\x06\x02\x01\x01\x05\x01\x02"[..],
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            405,
        ),
        (
            &b"\x30\x09\x02\x01\x01\x02\x01\x02\x02\x01\x03"[..],
            ErrorCode::TrailingData,
            408,
        ),
        (
            &b"\x31\x06\x02\x01\x01\x02\x01\x02"[..],
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            400,
        ),
    ] {
        let parser = Parser::der(memory(4096, 4096));
        let mut reader = parser.read(bytes, 400).unwrap();
        let error = DssValue::read(&mut reader, "signature").unwrap_err();
        assert_eq!(
            (error.code(), error.field(), error.offset()),
            (code, "signature", offset)
        );
    }
}

fn run(encoding: Encoding, local: u64, aggregate: usize) -> (Result<(), Error>, usize) {
    let memory = memory(16, aggregate);
    let parser = Parser::new(
        encoding,
        Limits {
            max_work: local,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut reader = parser.read(PAIR, 400).unwrap();
    let result = DssValue::read(&mut reader, "signature").map(|_| ());
    assert_eq!(memory.used(), 0);
    (result, memory.work_used())
}

#[test]
fn exact_and_one_less_work_are_enforced_for_both_execution_paths() {
    // Derive the complete decode cost, then prove exact success and refusal
    // one unit earlier under either the local or aggregate ceiling.
    for encoding in [Encoding::Der, Encoding::Ber] {
        let (result, cost) = run(encoding, 4096, 4096);
        result.unwrap();
        assert!(cost > 0);
        run(encoding, cost as u64, cost).0.unwrap();
        for (local, aggregate) in [(cost as u64 - 1, 4096), (4096, cost - 1)] {
            let (result, spent) = run(encoding, local, aggregate);
            let error = result.unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.field(), "signature");
            assert!(spent <= aggregate);
        }
    }
}

#[test]
fn scoped_queries_keep_source_depth_and_do_not_retain_the_operation() {
    // A new request pays deferred reads while the original parser still
    // bounds them. The returned borrowed values need not retain that request.
    let source_memory = memory(0, 4096);
    let source = Parser::der(source_memory.clone());
    let source_spent = source_memory.work_used();
    let value;
    {
        let current_memory = memory(16, 4096);
        let operation = Parser::der(current_memory.clone());
        let query = operation.read(&[], 900).unwrap();
        let work = query.execution();
        let mut reader = work
            .read_scoped_source(&source, PAIR, 400, Encoding::Der, 0)
            .unwrap();
        value = DssValue::read(&mut reader, "signature").unwrap();
        assert!(current_memory.work_used() > 0);
        assert_eq!(source_memory.work_used(), source_spent);
    }
    assert_eq!(value.s().as_u64(), Some(2));

    let limited = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        memory(64, 4096),
    );
    let mut reader = limited.read(PAIR, 400).unwrap();
    assert_eq!(
        DssValue::read(&mut reader, "signature").unwrap_err().code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Depth
        ))
    );
    // The actual inherited depth is used, rather than restarting a nested
    // signature at depth zero when its parent permits only one level.
    let origin = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 1,
            ..Limits::default()
        },
        memory(64, 4096),
    );
    let operation = Parser::der(memory(64, 4096));
    let query = operation.read(&[], 900).unwrap();
    let work = query.execution();
    let mut nested = work
        .read_scoped_nested(&origin, PAIR, 400, Encoding::Der, 0)
        .unwrap();
    assert_eq!(
        DssValue::read(&mut nested, "signature").unwrap_err().code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Depth
        ))
    );
}

#[test]
fn current_query_refusal_precedes_any_signature_decoding() {
    // Available source/aggregate work cannot override a spent current query.
    let source = Parser::der(memory(0, 4096));
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1,
            ..Limits::default()
        },
        memory(0, 4096),
    );
    let query = operation.read(&[], 900).unwrap();
    let work = query.execution();
    let mut reader = work
        .read_scoped_source(&source, PAIR, 400, Encoding::Der, 0)
        .unwrap();
    let error = DssValue::read(&mut reader, "signature").unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 400);
}

#[test]
fn a_fresh_current_query_cannot_reset_the_source_work_ceiling() {
    // The source session is already the tighter boundary, despite a new
    // query with enough aggregate and local capacity to decode this value.
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1,
            ..Limits::default()
        },
        memory(64, 4096),
    );
    let operation = Parser::der(memory(64, 4096));
    let query = operation.read(&[], 900).unwrap();
    let work = query.execution();
    let mut reader = work
        .read_scoped_source(&source, PAIR, 400, Encoding::Der, 0)
        .unwrap();
    let error = DssValue::read(&mut reader, "signature").unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 400);
    assert!(work.work_remaining() > 0);
}

#[test]
fn arbitrary_width_integers_remain_borrowed_without_a_hidden_curve_limit() {
    // Structure reading must neither truncate at u64/curve width nor copy
    // a large scalar that only the selected backend can interpret.
    let mut contents = vec![2, 0x82, 2, 0];
    contents.extend_from_slice(&[1; 512]);
    contents.extend_from_slice(&[2, 1, 1]);
    let mut bytes = vec![0x30, 0x82, 2, 7];
    bytes.extend_from_slice(&contents);
    let memory = memory(16, 4096);
    let parser = Parser::der(memory.clone());
    let mut reader = parser.read(&bytes, 400).unwrap();
    let value = DssValue::read(&mut reader, "signature").unwrap();
    assert_eq!(value.r().as_bytes().len(), 512);
    assert_eq!(value.r().as_bytes().as_ptr(), bytes[8..].as_ptr());
    assert_eq!(value.r().as_u64(), None);
    assert_eq!(value.s().as_u64(), Some(1));
    assert!(memory.work_used() < 128);
    assert_eq!(memory.used(), 0);
}

#[test]
fn reading_an_element_requires_the_sequence_tag_under_der_too() {
    // The DER fast path must enforce schema tags just like the BER path.
    let parser = Parser::der(memory(0, 4096));
    let mut reader = parser.read(b"\x04\x00", 400).unwrap();
    let element = reader
        .expect(Tag::primitive(universal::OCTET_STRING))
        .unwrap();
    let error = DssValue::read_element(&reader, &element, "signature").unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
    assert_eq!(error.offset(), 400);
}

#[test]
fn zero_and_one_byte_short_storage_refuse_reader_metadata_without_retaining_capacity() {
    // Reader paths grow to four u32 slots. The decoded pair borrows its
    // content, but entering its SEQUENCE still must fund those 16 bytes.
    for limit in [0, 15, 16] {
        let memory = memory(limit, 4096);
        let parser = Parser::der(memory.clone());
        let mut reader = parser.read(PAIR, 400).unwrap();
        let result = DssValue::read(&mut reader, "signature");
        if limit == 16 {
            assert_eq!(result.unwrap().r().as_u64(), Some(1));
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error.code(),
                ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
                    structured_asn1::Limit::Memory
                ))
            );
            assert_eq!(error.offset(), 402);
        }
        assert_eq!(memory.used(), 0);
    }
}
