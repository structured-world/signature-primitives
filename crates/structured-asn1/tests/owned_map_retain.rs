//! Public current-query filtering over independently retained borrowed-key maps.

use std::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, RetainError};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

#[test]
fn borrowed_membership_filter_funds_both_tables_from_current_query() {
    // A selected-set subtraction consults another retained map inside the
    // predicate. Both traversals belong to the current query, without a key
    // catalogue/copy or permission to spend the original producer's budget.
    let storage = memory(4096, 100_000);
    let mut selected = storage.map();
    for key in [&b"root"[..], &b"child-a"[..], &b"child-b"[..]] {
        selected.try_insert(key, 0usize).unwrap();
    }
    let mut excluded = storage.map();
    excluded.try_insert(&b"child-b"[..], ()).unwrap();
    let original_work = storage.work_used();
    let capacity = storage.used();
    // This budget admits only the four-bucket selected-table scan. Nested
    // lookup refusal must retain its predicate cause and leave every row.
    let denied = memory(0, 4);
    assert_eq!(
        selected.try_retain(&denied, |key, _| {
            excluded.get(key, &denied).map(|found| found.is_none())
        }),
        Err(RetainError::Predicate(MemoryError::WorkExceeded))
    );
    assert_eq!(selected.len(), 3);
    let query = memory(0, 1000);
    selected
        .try_retain(&query, |key, value| {
            let keep = excluded.get(key, &query)?.is_none();
            if keep {
                *value += 1;
            }
            Ok::<_, MemoryError>(keep)
        })
        .unwrap();
    assert_eq!(selected.len(), 2);
    assert_eq!(selected.get(&&b"root"[..], &query).unwrap(), Some(&1));
    assert_eq!(selected.get(&&b"child-a"[..], &query).unwrap(), Some(&1));
    assert_eq!(selected.get(&&b"child-b"[..], &query).unwrap(), None);
    assert_eq!(storage.work_used(), original_work);
    assert_eq!(storage.used(), capacity);
    assert_eq!(query.used(), 0);
    drop(selected);
    drop(excluded);
    assert_eq!(storage.used(), 0);
}
