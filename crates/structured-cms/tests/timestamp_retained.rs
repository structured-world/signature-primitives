//! Declared facts retain independent accounted bytes, without claiming proof.

use std::sync::Arc;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_cms::{ErrorCode, timestamp::TokenInfo};

fn memory(limit: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(limit, 1 << 24)))
}
fn bytes(serial: &[u8]) -> Vec<u8> {
    // Conforming private test algorithm plus explicitly written NULL; the
    // snapshot preserves that encoding without a provider default decision.
    let mut fields = vec![
        2,
        1,
        1,
        6,
        1,
        43,
        0x30,
        11,
        0x30,
        5,
        6,
        1,
        42,
        5,
        0,
        4,
        2,
        7,
        8,
        2,
        u8::try_from(serial.len()).unwrap(),
    ];
    fields.extend(serial);
    fields.extend([0x18, 15]);
    fields.extend(b"20260101000000Z");
    fields.extend([2, 1, 9]);
    let mut output = vec![0x30, u8::try_from(fields.len()).unwrap()];
    output.extend(fields);
    output
}

#[test]
fn declared_facts_survive_source_and_parser_and_release_final_capacity() {
    // This is declared-data retention, not an authenticated existence claim.
    // Independent bytes/capacity remain until the last facts owner is dropped.
    let memory = memory(1 << 20);
    let facts = {
        let parser = Parser::ber(memory.clone());
        let bytes = bytes(&[0, 0x80]);
        let mut reader = parser.read(&bytes, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let info = TokenInfo::read(&reader, &element).unwrap();
        assert!(!info.has_faults());
        info.retain_facts(&reader).unwrap()
    };
    assert_eq!(facts.imprint().algorithm().as_bytes(), &[42]);
    assert_eq!(facts.imprint().parameters(), Some(&[5, 0][..]));
    assert_eq!(facts.imprint().hashed(), &[7, 8]);
    assert_eq!(facts.policy().as_bytes(), &[43]);
    assert_eq!(facts.serial(), &[0, 0x80]);
    assert_eq!(facts.nonce(), Some(&[9][..]));
    assert!(facts.accuracy().is_none());
    assert!(!facts.ordering());
    assert_eq!(facts.gen_time().start().seconds(), 1_767_225_600);
    assert_eq!(facts.source_span().start, 400);
    assert!(memory.used() > 0);
    drop(facts);
    assert_eq!(memory.used(), 0);
}

#[test]
fn partial_retention_refusal_releases_new_capacity_and_preserves_source() {
    // The one-byte algorithm copy can fit; parameters cannot. Temporary
    // retained allocations must roll back while original parser/model stay valid.
    let storage = memory(1 << 20);
    let parser = Parser::ber(storage.clone());
    let bytes = bytes(&[7]);
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&reader, &element).unwrap();
    let old_storage = storage.used();
    let limited = memory(1);
    let reader = reader.with_execution(&limited);
    let error = info.retain_facts(&reader).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(limited.used(), 0);
    assert_eq!(storage.used(), old_storage);
    assert_eq!(info.imprint().hashed().as_one(), Some(&[7, 8][..]));
    assert_eq!(info.serial().element().contents(), &[7]);
    assert!(!info.has_faults());
}

#[test]
fn inspection_faults_cannot_be_erased_by_conforming_retention() {
    // Nonminimal serial is readable inspection with its original bytes/fault;
    // refusing the projection must not discard or silently normalize either.
    let memory = memory(1 << 20);
    let parser = Parser::ber(memory.clone());
    let bytes = bytes(&[0, 7]);
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let info = TokenInfo::read(&reader, &element).unwrap();
    let used = memory.used();
    let error = info.retain_facts(&reader).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert!(info.has_faults());
    assert_eq!(info.serial().element().contents(), &[0, 7]);
    assert_eq!(memory.used(), used);
}

#[test]
fn independent_copy_after_parser_drop_is_fallible_and_holds_its_own_capacity() {
    // A Timeline/report copy is a real allocation, unlike moving the original
    // owner. Refusal cannot poison that source; each successful copy frees only
    // its own charged capacity, after the parsing context is already gone.
    let source_memory = memory(1 << 20);
    let facts = {
        let parser = Parser::ber(source_memory.clone());
        let bytes = bytes(&[7]);
        let mut reader = parser.read(&bytes, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        TokenInfo::read(&reader, &element)
            .unwrap()
            .retain_facts(&reader)
            .unwrap()
    };
    let source_held = source_memory.used();
    let limited = memory(1);
    assert!(facts.try_copy_in(&limited).unwrap_err().is_resource());
    assert_eq!(limited.used(), 0);
    assert_eq!(source_memory.used(), source_held);
    assert_eq!(facts.serial(), &[7]);
    let destination = memory(1 << 20);
    let copied = facts.try_copy_in(&destination).unwrap();
    assert_eq!(copied.imprint().hashed(), facts.imprint().hashed());
    assert_eq!(copied.imprint().parameters(), facts.imprint().parameters());
    assert_eq!(copied.source_span(), facts.source_span());
    assert!(destination.used() > 0);
    drop(facts);
    assert_eq!(source_memory.used(), 0);
    assert_eq!(copied.serial(), &[7]);
    drop(copied);
    assert_eq!(destination.used(), 0);
}
