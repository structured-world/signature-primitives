//! `MessageImprint` structure preserves malformed fields without a fake algorithm.

use std::sync::Arc;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_cms::{
    ErrorCode,
    timestamp::{HashAlgorithmReading, MessageImprint},
};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

#[test]
fn original_identifier_parameters_and_hash_are_borrowed() {
    // No backend resolution/width guess occurs during schema decoding. Complete
    // original parameters and content bytes remain available to the provider.
    let bytes = [0x30, 11, 0x30, 5, 6, 1, 42, 5, 0, 4, 2, b'a', b'b'];
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let imprint = MessageImprint::read(&parent, &element).unwrap();
    let HashAlgorithmReading::Identifier(algorithm) = imprint.algorithm() else {
        panic!("valid algorithm");
    };
    assert_eq!(algorithm.algorithm().as_bytes(), &[42]);
    assert_eq!(algorithm.parameters(), Some(&[5, 0][..]));
    assert_eq!(algorithm.offset(), 402);
    assert_eq!(imprint.hashed().as_one(), Some(&b"ab"[..]));
    assert_eq!(
        imprint.hashed().as_one().unwrap().as_ptr(),
        bytes[11..].as_ptr()
    );
    assert!(imprint.faults().is_empty());
    assert_eq!(memory.used(), 0);
}

#[test]
fn bare_oid_recovers_one_malformed_imprint_without_retagging() {
    // The known donor failure must keep the uniquely bounded hash reading,
    // with explicit algorithm malformation rather than a fabricated identifier.
    let bytes = [0x30, 10, 6, 1, 42, 0x24, 5, 4, 0, 4, 1, b'a'];
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let imprint = MessageImprint::read(&parent, &element).unwrap();
    let HashAlgorithmReading::Malformed {
        element,
        kind: Some(kind),
    } = imprint.algorithm()
    else {
        panic!("original bare OID remains malformed");
    };
    assert_eq!(kind.as_bytes(), &[42]);
    assert_eq!(element.as_bytes(), &[6, 1, 42]);
    assert_eq!(element.as_bytes().as_ptr(), bytes[2..].as_ptr());
    assert_eq!(imprint.hashed().len(), 1);
    assert_eq!(imprint.hashed().pieces().len(), 2);
    assert_eq!(imprint.hashed().pieces()[1].span().start, 411);
    assert_eq!(imprint.faults().len(), 1);
    assert_eq!(imprint.faults()[0].code(), ErrorCode::MalformedValue);
    assert_eq!(
        imprint.faults()[0].field(),
        "tstInfo.messageImprint.hashAlgorithm"
    );
    assert_eq!(imprint.faults()[0].offset(), 402);
    drop(imprint);
    assert_eq!(memory.used(), 0);
}

#[test]
fn bounded_algorithm_fault_and_trailing_bytes_do_not_discard_hash() {
    // Unknown algorithm syntax still has an independently located complete field.
    // Extra trailing bytes are retained as a separate structural fault.
    let bytes = [0x30, 10, 0x30, 2, 5, 0, 4, 2, b'a', b'b', 5, 0];
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let imprint = MessageImprint::read(&parent, &element).unwrap();
    assert!(matches!(
        imprint.algorithm(),
        HashAlgorithmReading::Malformed { kind: None, .. }
    ));
    assert_eq!(imprint.hashed().as_one(), Some(&b"ab"[..]));
    assert_eq!(imprint.faults().len(), 2);
    assert_eq!(imprint.faults()[1].code(), ErrorCode::TrailingData);
    assert_eq!(imprint.faults()[1].offset(), 410);
    drop(imprint);
    assert_eq!(memory.used(), 0);
}

#[test]
fn diagnostic_capacity_refusal_keeps_the_original_algorithm_field() {
    // Admit just the enclosing reader's path, then refuse diagnostic retention.
    // The failure stays an operation refusal at the original malformed field.
    let bytes = [0x30, 6, 6, 1, 42, 4, 1, b'a'];
    let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 65536)));
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let probing = parent.enter(&element).unwrap();
    let path_capacity = memory.used();
    assert!(path_capacity > 0);
    drop(probing);
    let mut occupied = memory.vector::<u8>();
    occupied.try_reserve_exact(4096 - path_capacity).unwrap();
    let refusal = MessageImprint::read(&parent, &element).unwrap_err();
    assert!(refusal.is_terminal() && refusal.is_resource());
    assert_eq!(refusal.field(), "tstInfo.messageImprint.hashAlgorithm");
    assert_eq!(refusal.offset(), 402);
    drop(refusal);
    assert_eq!(memory.used(), occupied.capacity());
    drop(occupied);
    assert_eq!(memory.used(), 0);
}
