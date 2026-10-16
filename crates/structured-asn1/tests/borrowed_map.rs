//! Public canonical-key lookup without allocating an owned query.

use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    sync::Arc,
};
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{HashWork, Memory, MemoryAccount, MemoryError},
};

#[derive(Debug)]
struct Key(&'static str);
impl Borrow<str> for Key {
    fn borrow(&self) -> &str {
        self.0
    }
}
impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Key {}
impl HashWork for Key {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(self.0.len() as u64 + 1)
    }
}

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

#[test]
fn borrowed_text_returns_canonical_key_without_query_storage() {
    // An interner needs the stored key, not a newly copied query or a second
    // lookup. A separate current account pays traversal with zero storage.
    let storage = memory(4096, 100_000);
    let mut map = storage.map();
    for text in ["", "namespace", "Straße 🦀"] {
        map.try_insert(Key(text), ()).unwrap();
    }
    let capacity = storage.used();
    let work = storage.work_used();
    let current = memory(0, 4096);
    for text in ["", "namespace", "Straße 🦀"] {
        let (key, value) = map.get_key_value_borrowed(text, &current).unwrap().unwrap();
        assert_eq!(key.0, text);
        assert_eq!(*value, ());
        let stored = map
            .try_iter(&current)
            .unwrap()
            .find(|(entry, ())| entry.0 == text)
            .unwrap()
            .0;
        assert!(std::ptr::eq(key, stored));
    }
    assert!(
        map.get_key_value_borrowed("missing", &current)
            .unwrap()
            .is_none()
    );
    assert_eq!(storage.work_used(), work);
    assert_eq!(storage.used(), capacity);
    assert_eq!(current.used(), 0);
    drop(map);
    assert_eq!(storage.used(), 0);
}

#[test]
fn borrowed_text_refusal_is_not_successful_absence() {
    // A retained map cannot fund new work from its producer account or turn
    // resource refusal into None, with either aggregate or local limits.
    let storage = memory(4096, 100_000);
    let mut map = storage.map();
    map.try_insert(Key("namespace"), ()).unwrap();
    let denied = memory(0, 0);
    assert_eq!(
        map.get_key_value_borrowed("namespace", &denied)
            .unwrap_err(),
        MemoryError::WorkExceeded
    );
    let current = memory(0, 100_000);
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let reader = parser.read(&[], 900).unwrap();
    assert_eq!(
        map.get_key_value_borrowed("namespace", &reader.execution())
            .unwrap_err(),
        MemoryError::WorkExceeded
    );
    assert_eq!(current.used(), 0);
}

#[test]
fn borrowed_shared_string_lookup_reuses_owner_after_producer_work_is_spent() {
    // The real interner composition must find and clone its existing shared
    // key under a new query, with no temporary owned text or second lookup.
    use structured_asn1::memory::SharedString;
    let storage = memory(4096, 100_000);
    let mut map = storage.map();
    let source = String::from("retained namespace Straße 🦀");
    let key = SharedString::try_from_str(&source, &storage).unwrap();
    let text_capacity = key.allocated_bytes();
    map.try_insert(key, ()).unwrap();
    drop(source);
    storage
        .charge_work(storage.work_remaining() as u64)
        .unwrap();
    let work = storage.work_used();
    let capacity = storage.used();
    let query = memory(0, 4096);
    let (canonical, ()) = map
        .get_key_value_borrowed("retained namespace Straße 🦀", &query)
        .unwrap()
        .unwrap();
    let retained = canonical.clone();
    assert!(SharedString::ptr_eq(canonical, &retained));
    assert_eq!(storage.used(), capacity);
    assert_eq!(storage.work_used(), work);
    assert_eq!(query.used(), 0);
    drop(map);
    assert_eq!(storage.used(), text_capacity);
    assert_eq!(retained.as_str(), "retained namespace Straße 🦀");
    drop(retained);
    assert_eq!(storage.used(), 0);
}
