//! Mutable borrowed queries retain paid lookup and independent storage ownership.

use std::{borrow::Borrow, sync::Arc};
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{HashWork, Memory, MemoryAccount, MemoryError, OwnedText, SharedString},
};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

fn mutate_text_key<K: HashWork + Borrow<str>>(key: K, storage: &Memory) {
    let key_charge = storage.used();
    let mut map = storage.map();
    map.try_insert(key, 7_usize).unwrap();
    let charged = storage.used();
    storage
        .charge_work(storage.work_remaining() as u64)
        .unwrap();
    let before = storage.work_used();
    let query = memory(0, 4096);
    *map.get_mut_borrowed("Straße 🦀", &query).unwrap().unwrap() = 42;
    assert_eq!(map.remove_borrowed("Straße 🦀", &query).unwrap(), Some(42));
    assert!(map.is_empty());
    assert_eq!(storage.used(), charged - key_charge);
    assert_eq!(storage.work_used(), before);
    assert_eq!(query.used(), 0);
    drop(map);
    assert_eq!(storage.used(), 0);
}

#[test]
fn owned_and_shared_text_mutate_without_owned_query_or_producer_work() {
    // Actual retained XML key types must accept str directly under another
    // execution, even when their original construction budget is exhausted.
    let storage = memory(4096, 100_000);
    let key = OwnedText::try_from_str("Straße 🦀", &storage).unwrap();
    mutate_text_key(key, &storage);
    let storage = memory(4096, 100_000);
    let key = SharedString::try_from_str("Straße 🦀", &storage).unwrap();
    mutate_text_key(key, &storage);
}

#[test]
fn borrowed_mutation_exact_current_local_and_aggregate_boundaries() {
    // A completed lookup is insufficient for removal until its erase/move
    // admission also succeeds. Refusal must retain the original entry.
    for remove in [false, true] {
        for boundary in 0..3 {
            let storage = memory(4096, 100_000);
            let mut map = storage.map();
            map.try_insert(
                OwnedText::try_from_str("prefix", &storage).unwrap(),
                7_usize,
            )
            .unwrap();
            let charged = storage.used();
            let measured = memory(0, 4096);
            map.get_key_value_borrowed("prefix", &measured)
                .unwrap()
                .unwrap();
            let mut required = measured.work_used();
            if remove {
                required += 2 * size_of::<(OwnedText, usize)>() + 2;
            }
            let (local, aggregate, success) = match boundary {
                0 => (required - 1, 4096, false),
                1 => (4096, required - 1, false),
                _ => (required, required, true),
            };
            let current = memory(0, aggregate);
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: local as u64,
                    ..Limits::default()
                },
                current.clone(),
            );
            let reader = parser.read(&[], 900).unwrap();
            let result = if remove {
                map.remove_borrowed("prefix", &reader.execution())
            } else {
                map.get_mut_borrowed("prefix", &reader.execution())
                    .map(Option::<&mut usize>::copied)
            };
            if success {
                assert_eq!(result, Ok(Some(7)));
            } else {
                assert_eq!(result, Err(MemoryError::WorkExceeded));
            }
            let probe = memory(0, 4096);
            let entry = map.get_key_value_borrowed("prefix", &probe).unwrap();
            if success && remove {
                assert!(entry.is_none());
                assert!(storage.used() < charged);
            } else {
                assert_eq!(entry.map(|(_, value)| *value), Some(7));
                assert_eq!(storage.used(), charged);
            }
            assert_eq!(current.used(), 0);
            drop(map);
            assert_eq!(storage.used(), 0);
        }
    }
}

#[test]
fn borrowed_removal_keeps_value_owner_after_table_and_key_drop() {
    // Removing an owned value must release the key but retain the value's exact
    // pointer and capacity charge independently after the map is destroyed.
    let storage = memory(4096, 100_000);
    let key = SharedString::try_from_str("namespace", &storage).unwrap();
    let value = OwnedText::try_from_str("retained 🦀", &storage).unwrap();
    let pointer = value.as_bytes().as_ptr();
    let capacity = value.capacity();
    let mut map = storage.map();
    map.try_insert(key, value).unwrap();
    let query = memory(0, 4096);
    let retained = map.remove_borrowed("namespace", &query).unwrap().unwrap();
    assert_eq!(retained.as_bytes().as_ptr(), pointer);
    assert!(map.is_empty());
    drop(map);
    assert_eq!(storage.used(), capacity);
    assert_eq!(retained.as_str(), "retained 🦀");
    assert_eq!(query.used(), 0);
    drop(retained);
    assert_eq!(storage.used(), 0);
}

#[test]
fn missing_keys_are_absent_only_after_completed_paid_queries() {
    // Empty or missing lookups are distinct from unfunded queries; neither
    // mutation route may expose synthetic equality after a resource refusal.
    let storage = memory(4096, 100_000);
    let mut map = storage.map::<OwnedText, usize>();
    let denied = memory(0, 0);
    assert_eq!(
        map.get_mut_borrowed("missing", &denied),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(
        map.remove_borrowed("missing", &denied),
        Err(MemoryError::WorkExceeded)
    );
    let query = memory(0, 4096);
    assert_eq!(map.get_mut_borrowed("missing", &query), Ok(None));
    assert_eq!(map.remove_borrowed("missing", &query), Ok(None));
    map.try_insert(OwnedText::try_from_str("present", &storage).unwrap(), 7)
        .unwrap();
    let charged = storage.used();
    assert_eq!(map.get_mut_borrowed("missing", &query), Ok(None));
    assert_eq!(map.remove_borrowed("missing", &query), Ok(None));
    assert_eq!(map.len(), 1);
    assert_eq!(storage.used(), charged);
    assert_eq!(query.used(), 0);
}
