//! Public envelope boundaries and detached/empty content distinctions.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Parser, Tag, universal};
use structured_cms::{ContentInfo, Encapsulated, ErrorCode};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

#[test]
fn envelope_returns_original_content_and_inherited_reader() {
    // Schema interpretation consumes the original child, not serialized bytes.
    let data = [0x30, 7, 6, 1, 42, 0xa0, 2, 4, 0];
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&data, 400).unwrap();
    let (envelope, producing) = ContentInfo::read(&mut reader).unwrap();
    assert_eq!(envelope.content().as_bytes(), &data[7..]);
    assert_eq!(envelope.content().span().start, 407);
    assert_eq!(producing.depth(), 2);
    assert_eq!(envelope.span().start, 400);
}

#[test]
fn whole_envelope_refuses_a_second_document_element() {
    // A whole-message reader cannot silently select one of two envelopes.
    let data = [0x30, 7, 6, 1, 42, 0xa0, 2, 4, 0, 5, 0];
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&data, 400).unwrap();
    assert_eq!(
        ContentInfo::read(&mut reader).unwrap_err().code(),
        ErrorCode::TrailingData
    );
}

#[test]
fn detached_and_attached_empty_remain_distinct() {
    // Empty content can be signed; absence instead requires explicit caller bytes.
    let parser = Parser::ber(memory());
    let detached = [0x30, 3, 6, 1, 42];
    let mut reader = parser.read(&detached, 400).unwrap();
    let element = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let content = Encapsulated::read(&reader, &element).unwrap();
    assert!(content.is_detached());
    assert!(content.content().is_none());

    let attached = [0x30, 7, 6, 1, 42, 0xa0, 2, 4, 0];
    let mut reader = parser.read(&attached, 500).unwrap();
    let element = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let content = Encapsulated::read(&reader, &element).unwrap();
    assert!(!content.is_detached());
    assert!(content.content().unwrap().is_empty());
}

#[test]
fn encapsulated_wrapper_refuses_two_payload_values() {
    // EXPLICIT OCTET STRING is one value, even when both extra values are empty.
    let data = [0x30, 9, 6, 1, 42, 0xa0, 4, 4, 0, 4, 0];
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&data, 400).unwrap();
    let element = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let error = Encapsulated::read(&reader, &element).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TrailingData);
    assert_eq!(error.offset(), 409);
}
