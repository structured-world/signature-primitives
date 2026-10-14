//! Shared Extension structure feeds the same original CMS octet walker.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::Octets;
use structured_pkix::{error::CallbackError, extension};

#[test]
fn constructed_extension_keeps_fragments_default_and_trailing_metadata() {
    // TSTInfo inspection must retain readable default/trailing faults around
    // BER extnValue without replacing the strict certificate catalogue.
    let bytes = [
        0x30, 19, 6, 1, 42, 1, 1, 0, 0x24, 9, 4, 1, b'a', 0x24, 4, 4, 2, b'b', b'c', 5, 0,
    ];
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let fields = extension::open(&parent, &element, "extensions").unwrap();
    let header = fields.header();
    assert!(header.default_written());
    assert_eq!(header.critical_span().unwrap().start, 405);
    let value = fields
        .read_with(|seen, producing, element| {
            assert_eq!(seen.span(), header.span());
            assert_eq!(element.span().start, 408);
            assert_eq!(element.contents_span().start, 410);
            assert_eq!(producing.depth(), parent.depth() + 1);
            Octets::read(producing, element, "extensions.extnValue")
        })
        .unwrap();
    assert_eq!(value.trailing_span().unwrap().start, 419);
    assert_eq!(value.value().len(), 3);
    assert_eq!(value.value().pieces()[0].span().start, 412);
    assert_eq!(value.value().pieces()[1].span().start, 417);
    assert_eq!(value.value().pieces()[0].as_bytes(), b"a");
    assert_eq!(value.value().pieces()[1].as_bytes(), b"bc");
    assert_eq!(
        value.value().pieces()[1].as_bytes().as_ptr(),
        bytes[17..].as_ptr()
    );
    let octets = value.into_value();
    drop(parent);
    assert!(memory.used() > 0);
    drop(octets);
    assert_eq!(memory.used(), 0);
}

#[test]
fn octet_callback_depth_refusal_preserves_original_source_and_rolls_back() {
    // The structural kernel must not restart parser depth for a nested OCTET
    // STRING, and callback resource errors must keep their distinct provenance.
    let bytes = [0x30, 10, 6, 1, 42, 0x24, 5, 0x24, 3, 4, 1, b'a'];
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 2,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let error = extension::read_with(&parent, &element, "extensions", |_, producing, value| {
        Octets::read(producing, value, "extensions.extnValue")
    })
    .unwrap_err();
    let CallbackError::Callback(error) = error else {
        panic!("callback refusal");
    };
    assert!(error.is_resource());
    assert_eq!(error.field(), "extensions.extnValue");
    assert!(error.offset() >= 407);
    drop(error);
    assert_eq!(memory.used(), 0);
}
