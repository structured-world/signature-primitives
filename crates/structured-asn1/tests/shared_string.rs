//! Public shared-string ownership and current-operation admission.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, SharedString};
use structured_asn1::{Encoding, Limits, Parser};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

#[test]
fn shared_string_survives_producer_and_clones_without_new_storage_or_scan() {
    // DOM-owned text must survive its source and parser while clones share
    // exactly one charged allocation; a later query funds its own map work.
    let storage = memory(4096, 4096);
    let retained;
    {
        let parser = Parser::der(storage.clone());
        let reader = parser.read(&[], 0).unwrap();
        retained = SharedString::try_from_str("Дія 🦀", &reader.execution()).unwrap();
    }
    let capacity = retained.allocated_bytes();
    assert_eq!(storage.used(), capacity);
    let work = storage.work_used();
    let clone = retained.clone();
    assert!(SharedString::ptr_eq(&retained, &clone));
    assert_eq!(storage.used(), capacity);
    assert_eq!(storage.work_used(), work);
    assert_eq!(&*clone, "Дія 🦀");
    drop(retained);
    assert_eq!(storage.used(), capacity);
    let query = memory(4096, 4096);
    let mut map = query.map();
    map.try_insert(clone.clone(), 7usize).unwrap();
    assert_eq!(
        map.get(&clone, &memory(0, 0)),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(map.get(&clone, &query).unwrap(), Some(&7));
    drop(clone);
    assert_eq!(storage.used(), capacity);
    drop(map);
    assert_eq!(storage.used(), 0);
}

#[test]
fn shared_string_creation_respects_local_and_aggregate_work_before_allocation() {
    // A successful old producer does not grant permission for new allocation
    // or copying under an exhausted parser or aggregate work ceiling.
    let storage = memory(4096, 4096);
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        storage.clone(),
    );
    let reader = parser.read(&[], 0).unwrap();
    assert_eq!(
        SharedString::try_from_str("text", &reader.execution()).unwrap_err(),
        MemoryError::WorkExceeded
    );
    assert_eq!(storage.used(), 0);
    let denied = memory(4096, 0);
    assert_eq!(
        SharedString::try_from_str("text", &denied).unwrap_err(),
        MemoryError::WorkExceeded
    );
    assert_eq!(denied.used(), 0);
}
