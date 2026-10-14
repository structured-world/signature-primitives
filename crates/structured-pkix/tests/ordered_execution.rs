//! Scoped preparation and cross-owner query use the one Name semantic core.

use core::cmp::Ordering;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)))
}

#[test]
fn retained_name_match_uses_current_reader_local_budget() {
    // A name read under a large storage budget cannot make a subsequent query
    // bypass that query's producing work ceiling. Both original names survive.
    let storage = memory();
    let parser = Parser::der(storage.clone());
    let left_bytes = name("STRASSE");
    let right_bytes = name("Straße");
    let mut reader = parser.read(&left_bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let left = structured_pkix::name::read(&reader, &element, "subject").unwrap();
    let mut reader = parser.read(&right_bytes, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let right = structured_pkix::name::read(&reader, &element, "tsa").unwrap();
    let query_memory = memory();
    let query_parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        query_memory.clone(),
    );
    let query = query_parser.read(&[], 0).unwrap();
    assert!(left.matches_in(&right, &query).unwrap_err().is_resource());
    assert_eq!(query_memory.used(), 0);
    let query_parser = Parser::der(query_memory.clone());
    let query = query_parser.read(&[], 0).unwrap();
    assert!(left.matches_in(&right, &query).unwrap());
    assert_eq!(query_memory.used(), 0);
    assert!(storage.used() > 0);
}

fn name(text: &str) -> Vec<u8> {
    // Trusted synthetic fixture: one UTF8 commonName; no repair/normalization
    // occurs in the test's encoding, so only shared Name processing can match.
    let length = u8::try_from(text.len()).unwrap();
    assert!(length < 100);
    let mut bytes = vec![
        0x30,
        11 + length,
        0x31,
        9 + length,
        0x30,
        7 + length,
        6,
        3,
        0x55,
        4,
        3,
        12,
        length,
    ];
    bytes.extend_from_slice(text.as_bytes());
    bytes
}

#[test]
fn scoped_and_retained_caches_agree_without_owner_coercion() {
    // Full folding/NFKC, differing values and owner direction must yield the
    // same order. Neither source Name nor cached canonical storage is copied
    // to make a current scoped query against retained storage work.
    for (left, right) in [
        ("  STRASSE ", "Straße"),
        ("alice", "bob"),
        ("e\u{301}", "é"),
    ] {
        let storage = memory();
        let current = memory();
        let parser = Parser::der(storage.clone());
        let left_bytes = name(left);
        let right_bytes = name(right);
        let mut left_reader = parser.read(&left_bytes, 400).unwrap();
        let element = left_reader.next_element().unwrap().unwrap();
        let left = structured_pkix::name::read(&left_reader, &element, "issuer").unwrap();
        let mut right_reader = parser.read(&right_bytes, 900).unwrap();
        let element = right_reader.next_element().unwrap().unwrap();
        let right = structured_pkix::name::read(&right_reader, &element, "asked").unwrap();
        let expected = left.order(&right, &storage).unwrap();
        assert_eq!(
            expected == Ordering::Equal,
            left.matches(&right, &storage).unwrap()
        );
        let retained = left.ordered(&storage).unwrap();
        let reader = right_reader.with_execution(&current);
        let held = storage.used();
        let old_work = storage.work_used();
        let scoped = right.ordered_in(&reader).unwrap();
        assert!(current.used() > 0);
        assert_eq!(storage.used(), held);
        assert_eq!(storage.work_used(), old_work);
        assert_eq!(
            retained.order(&scoped, &reader.execution()).unwrap(),
            expected
        );
        assert_eq!(
            scoped.order(&retained, &reader.execution()).unwrap(),
            expected.reverse()
        );
        drop(scoped);
        assert_eq!(current.used(), 0);
        assert_eq!(storage.used(), held);
    }
}

#[test]
fn cached_comparison_uses_new_local_scope_without_allocating_or_preparing_again() {
    // A retained cache cannot answer through its old aggregate allowance when
    // the new query's parser-local meter is exhausted; no normalization/copy
    // or scratch allocation may happen during this already prepared query.
    let original = memory();
    let original_parser = Parser::der(original.clone());
    let encoded = name("Straße");
    let mut reader = original_parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = structured_pkix::name::read(&reader, &element, "issuer").unwrap();
    let cache = value.ordered(&original).unwrap();
    let current = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let reader = parser.read(&[], 800).unwrap();
    let old_used = original.used();
    let old_work = original.work_used();
    let error = cache.order(&cache, &reader.execution()).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 400);
    assert_eq!(current.used(), 0);
    assert_eq!(current.work_used(), 0);
    assert_eq!(original.used(), old_used);
    assert_eq!(original.work_used(), old_work);
}

#[test]
fn scoped_preparation_refuses_storage_and_original_local_work_with_rollback() {
    // Unicode canonical text and descriptor growth are funded before storage.
    // Both a current storage ceiling and the original parser's exhausted local
    // work ceiling must refuse independently without leaking temporary capacity.
    let original = memory();
    let parser = Parser::der(original.clone());
    let encoded = name("Straße");
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = structured_pkix::name::read(&reader, &element, "issuer").unwrap();
    let unfunded = Memory::new(Arc::new(MemoryAccount::new(0, 1_000_000)));
    let current = reader.with_execution(&unfunded);
    let error = value.ordered_in(&current).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(unfunded.used(), 0);
    let funded = memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 10000,
            ..Limits::default()
        },
        funded.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = structured_pkix::name::read(&reader, &element, "issuer").unwrap();
    reader
        .charge(10000 - u64::try_from(funded.work_used()).unwrap())
        .unwrap();
    let held = funded.used();
    let error = value.ordered_in(&reader).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 411);
    assert_eq!(funded.used(), held);
    assert!(funded.work_used() <= 10000);
}

#[test]
fn scoped_ber_preparation_keeps_original_nested_depth_and_offset() {
    // At the exact original depth ceiling, UTF8String's OCTET STRING pieces
    // must normalize through the same reader session. Later exhaustion must
    // refuse at the original value, not a fresh parser's zero offset/budget.
    let encoded = [
        0x30, 24, 0x30, 22, 0x31, 20, 0x30, 18, 6, 3, 0x55, 4, 3, 0x2c, 11, 4, 4, b'S', b't', b'r',
        b'a', 4, 3, 0xc3, 0x9f, b'e',
    ];
    let storage = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 5,
            max_work: 10000,
            ..Limits::default()
        },
        storage.clone(),
    );
    let mut root = parser.read(&encoded, 400).unwrap();
    let wrapper = root.next_element().unwrap().unwrap();
    let mut inside = root.enter(&wrapper).unwrap();
    let element = inside.next_element().unwrap().unwrap();
    let segmented = structured_pkix::name::read(&inside, &element, "issuer").unwrap();
    let plain_bytes = name("STRASSE");
    let mut plain_reader = parser.read(&plain_bytes, 900).unwrap();
    let element = plain_reader.next_element().unwrap().unwrap();
    let plain = structured_pkix::name::read(&plain_reader, &element, "asked").unwrap();
    let current = memory();
    let reader = root.with_execution(&current);
    let segmented_cache = segmented.ordered_in(&reader).unwrap();
    let plain_cache = plain.ordered_in(&reader).unwrap();
    assert_eq!(
        segmented_cache
            .order(&plain_cache, &reader.execution())
            .unwrap(),
        Ordering::Equal
    );
    drop(segmented_cache);
    drop(plain_cache);
    assert_eq!(current.used(), 0);
    while reader.charge(1).is_ok() {}
    let error = segmented.ordered_in(&reader).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 413);
    assert_eq!(current.used(), 0);
    assert_eq!(storage.work_used() + current.work_used(), 10000);
}
