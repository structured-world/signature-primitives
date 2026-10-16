use alloc::sync::Arc;
use core::cell::Cell;
use core::hash::{Hash, Hasher};

use super::{HashWork, RetainError};
use crate::memory::{Memory, MemoryAccount, MemoryError, Work};
use crate::{Encoding, Limits, Parser};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

#[derive(Default)]
struct BorrowedCounters {
    hashes: Cell<usize>,
    borrows: Cell<usize>,
    equals: Cell<usize>,
}

impl BorrowedCounters {
    fn reset(&self) {
        self.hashes.set(0);
        self.borrows.set(0);
        self.equals.set(0);
    }
}

struct BorrowedQuery<'a> {
    value: usize,
    calls: &'a BorrowedCounters,
}

impl Hash for BorrowedQuery<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.calls.hashes.set(self.calls.hashes.get() + 1);
        // Deliberately collide: every stored candidate must be paid before Eq.
        0usize.hash(state);
    }
}
impl PartialEq for BorrowedQuery<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.calls.equals.set(self.calls.equals.get() + 1);
        self.value == other.value
    }
}
impl Eq for BorrowedQuery<'_> {}
impl HashWork for BorrowedQuery<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(1)
    }
}

struct BorrowedKey<'a>(BorrowedQuery<'a>);
impl<'a> core::borrow::Borrow<BorrowedQuery<'a>> for BorrowedKey<'a> {
    fn borrow(&self) -> &BorrowedQuery<'a> {
        self.0.calls.borrows.set(self.0.calls.borrows.get() + 1);
        &self.0
    }
}
impl Hash for BorrowedKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl PartialEq for BorrowedKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for BorrowedKey<'_> {}
impl HashWork for BorrowedKey<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(1)
    }
}

#[test]
fn borrowed_lookup_admits_hash_borrow_and_each_collision_before_side_effects() {
    // Refusal before hashing or during a collision chain must stop before
    // Borrow/Eq, never expose the synthetic match or retry the query hash.
    let calls = BorrowedCounters::default();
    let storage = memory(4096, 100_000);
    let mut map = storage.map();
    for value in 0..4 {
        map.try_insert(
            BorrowedKey(BorrowedQuery {
                value,
                calls: &calls,
            }),
            (),
        )
        .unwrap();
    }
    let query = BorrowedQuery {
        value: 99,
        calls: &calls,
    };
    let hash_cost = 1 + usize::try_from(map.control_work().unwrap()).unwrap();
    let capacity = storage.used();
    let original_work = storage.work_used();
    for (work, comparisons, success) in [
        (0, 0, false),
        (hash_cost, 0, false),
        (hash_cost + 7, 3, false),
        (hash_cost + 8, 4, true),
    ] {
        calls.reset();
        let current = memory(0, work);
        let result = map.get_key_value_borrowed(&query, &current);
        if success {
            assert!(result.unwrap().is_none());
        } else {
            assert!(matches!(result, Err(MemoryError::WorkExceeded)));
        }
        assert_eq!(calls.hashes.get(), usize::from(work > 0));
        assert_eq!(calls.borrows.get(), comparisons);
        assert_eq!(calls.equals.get(), comparisons);
        assert_eq!(map.len(), 4);
        assert_eq!(storage.used(), capacity);
        assert_eq!(storage.work_used(), original_work);
        assert_eq!(current.used(), 0);
    }
    // The original &K route shares this kernel without calling Borrow<Query>.
    calls.reset();
    let key = BorrowedKey(BorrowedQuery {
        value: 2,
        calls: &calls,
    });
    assert_eq!(map.get(&key, &memory(0, 4096)).unwrap(), Some(&()));
    assert_eq!(calls.hashes.get(), 1);
    assert_eq!(calls.borrows.get(), 0);
}

#[test]
fn borrowed_lookup_exact_parser_ceiling_is_not_bypassed_by_current_account() {
    // Probe/hash admission is not enough for unpaid candidate equality. A
    // local refusal and an aggregate refusal must preserve the same boundary.
    let calls = BorrowedCounters::default();
    let storage = memory(4096, 100_000);
    let mut map = storage.map();
    map.try_insert(
        BorrowedKey(BorrowedQuery {
            value: 7,
            calls: &calls,
        }),
        (),
    )
    .unwrap();
    let needed = 1 + map.control_work().unwrap() + 2;
    for (local, aggregate, success) in [
        (needed - 1, 1000, false),
        (1000, needed - 1, false),
        (needed, needed, true),
    ] {
        calls.reset();
        let current = memory(0, usize::try_from(aggregate).unwrap());
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            current.clone(),
        );
        let reader = parser.read(&[], 0).unwrap();
        let query = BorrowedQuery {
            value: 7,
            calls: &calls,
        };
        let result = map.get_key_value_borrowed(&query, &reader.execution());
        if success {
            assert_eq!(result.unwrap().unwrap().0.0.value, 7);
        } else {
            assert!(matches!(result, Err(MemoryError::WorkExceeded)));
        }
        assert_eq!(calls.hashes.get(), 1);
        assert_eq!(calls.borrows.get(), usize::from(success));
        assert_eq!(calls.equals.get(), usize::from(success));
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn retain_empty_and_sparse_maps_keep_storage_and_charge_current_scan() {
    // Sparse holes are work too; deletion never allocates a second key list
    // or refunds the backing table while it remains reusable.
    let storage = memory(16_384, 100_000);
    let mut empty = storage.map::<usize, usize>();
    let zero = memory(0, 0);
    empty
        .try_retain(&zero, |_, _| -> Result<bool, ()> { panic!("empty") })
        .unwrap();
    assert_eq!(zero.work_used(), 0);
    let mut map = storage.map();
    for key in 0..32usize {
        map.try_insert(key, key).unwrap();
    }
    for key in 0..31usize {
        map.remove(&key, &storage).unwrap();
    }
    let capacity = storage.used();
    let old_work = storage.work_used();
    let maximum = map.maximum_capacity;
    let mut visits = 0;
    assert_eq!(
        map.try_retain(&zero, |_, _| {
            visits += 1;
            Ok::<_, ()>(false)
        }),
        Err(RetainError::Resource(MemoryError::WorkExceeded))
    );
    assert_eq!(visits, 0);
    assert_eq!(map.len(), 1);
    assert_eq!(map.buckets().unwrap(), 64);
    let current = memory(0, 66);
    map.try_retain(&current, |key, value| {
        assert_eq!((*key, *value), (31, 31));
        Ok::<_, ()>(false)
    })
    .unwrap();
    assert_eq!(current.work_used(), 66);
    assert_eq!(current.used(), 0);
    assert!(map.is_empty());
    assert_eq!(map.key_work, 0);
    assert_eq!(map.maximum_capacity, maximum);
    assert_eq!(storage.work_used(), old_work);
    assert_eq!(storage.used(), capacity);
    drop(map);
    assert_eq!(storage.used(), 0);
}

#[test]
fn retain_local_and_aggregate_refusal_precede_predicate_and_erase() {
    // Enough storage is not permission to spend another operation's work.
    // Exact scan admission allows a predicate, but not an unpaid erase.
    let storage = memory(1024, 100_000);
    let mut map = storage.map();
    map.try_insert(1usize, 42usize).unwrap();
    for (local, aggregate, expected_visits, removed) in [
        (0, 100, 0, false),
        (100, 0, 0, false),
        (4, 100, 1, false),
        (100, 4, 1, false),
        (6, 6, 1, true),
    ] {
        let current = memory(0, aggregate);
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            current.clone(),
        );
        let reader = parser.read(&[], 700).unwrap();
        let mut visits = 0;
        let result = map.try_retain(&reader.execution(), |_, _| {
            visits += 1;
            Ok::<_, ()>(false)
        });
        assert_eq!(visits, expected_visits);
        if removed {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(
                result,
                Err(RetainError::Resource(MemoryError::WorkExceeded))
            );
        }
        assert_eq!(map.len(), usize::from(!removed));
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn retain_first_callback_error_preserves_remaining_entries_and_prior_edits() {
    // Order is intentionally unspecified. Two prior removals and the failing
    // callback's value edit survive; no later callback may run.
    let storage = memory(4096, 100_000);
    let mut map = storage.map();
    for key in 0..8usize {
        map.try_insert(key, 0usize).unwrap();
    }
    let current = memory(0, 1000);
    let before = storage.used();
    let cause = 37;
    let mut visits = 0;
    let result = map.try_retain(&current, |_, value| {
        visits += 1;
        *value += 1;
        if visits == 3 { Err(&cause) } else { Ok(false) }
    });
    assert_eq!(result, Err(RetainError::Predicate(&cause)));
    assert_eq!(visits, 3);
    assert_eq!(map.len(), 6);
    assert_eq!(map.key_work, 6);
    assert_eq!(
        map.try_iter(&current)
            .unwrap()
            .filter(|(_, v)| **v == 1)
            .count(),
        1
    );
    assert_eq!(storage.used(), before);
    for key in 8..64usize {
        map.try_insert(key, 0).unwrap();
    }
    assert_eq!(map.len(), 62);
    assert_eq!(map.key_work, 62);
    for key in 8..64usize {
        assert_eq!(map.get(&key, &storage).unwrap(), Some(&0));
    }
}

#[derive(Debug)]
struct Collision<'a> {
    id: usize,
    hashes: &'a Cell<usize>,
    equals: &'a Cell<usize>,
    metadata: &'a Cell<usize>,
}
impl Hash for Collision<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hashes.set(self.hashes.get() + 1);
        state.write_u8(0);
    }
}
impl PartialEq for Collision<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.equals.set(self.equals.get() + 1);
        self.id == other.id
    }
}
impl Eq for Collision<'_> {}
impl HashWork for Collision<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        self.metadata.set(self.metadata.get() + 1);
        Ok(1)
    }
}

#[test]
fn retain_removal_refusal_is_sticky_without_hash_equality_or_extra_storage() {
    // Even a collision cluster is filtered directly. Only the first erase is
    // funded; the second callback cannot authorize removal or later key access.
    let hashes = Cell::new(0);
    let equals = Cell::new(0);
    let metadata = Cell::new(0);
    let storage = memory(4096, 100_000);
    let mut map = storage.map();
    for id in 0..16 {
        map.try_insert(
            Collision {
                id,
                hashes: &hashes,
                equals: &equals,
                metadata: &metadata,
            },
            (),
        )
        .unwrap();
    }
    hashes.set(0);
    equals.set(0);
    metadata.set(0);
    let before = storage.used();
    let current = memory(0, usize::try_from(map.buckets().unwrap()).unwrap() + 2);
    let mut visits = 0;
    assert_eq!(
        map.try_retain(&current, |_, ()| {
            visits += 1;
            Ok::<_, ()>(false)
        }),
        Err(RetainError::Resource(MemoryError::WorkExceeded))
    );
    assert_eq!(visits, 2);
    assert_eq!(map.len(), 15);
    assert_eq!(map.key_work, 15);
    assert_eq!(hashes.get(), 0);
    assert_eq!(equals.get(), 0);
    assert_eq!(metadata.get(), 1);
    assert_eq!(storage.used(), before);
    assert_eq!(current.used(), 0);
    let next = memory(0, 1000);
    map.try_retain(&next, |_, ()| Ok::<_, ()>(false)).unwrap();
    assert!(map.is_empty());
    assert_eq!(map.key_work, 0);
}

#[test]
fn retain_predicate_cause_precedes_unneeded_erase_admission() {
    // The callback's own error wins even when no erase work remains. Retaining
    // this item is not permission to run the predicate on later entries.
    let storage = memory(1024, 100_000);
    let mut map = storage.map();
    map.try_insert(1usize, 7usize).unwrap();
    let current = memory(0, 4);
    assert_eq!(
        map.try_retain(&current, |_, _| Err(37)),
        Err(RetainError::Predicate(37))
    );
    assert_eq!(current.work_used(), 4);
    assert_eq!(map.len(), 1);
    assert_eq!(map.key_work, 1);
}

#[test]
fn retain_query_does_not_rebind_scoped_storage_or_revive_producer_work() {
    // A later current query can filter a producer-funded map after the producer
    // is spent. That does not give future insertions the new query's allowance.
    let storage = memory(4096, 100_000);
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 10_000,
            ..Limits::default()
        },
        storage.clone(),
    );
    let reader = parser.read(&[], 400).unwrap();
    let execution = reader.execution();
    let mut map = execution.map();
    map.try_insert(1usize, 1usize).unwrap();
    map.try_insert(2usize, 2usize).unwrap();
    execution
        .charge_work(10_000 - storage.work_used() as u64)
        .unwrap();
    assert_eq!(execution.charge_work(1), Err(MemoryError::WorkExceeded));
    let capacity = storage.used();
    let current = memory(0, 8);
    map.try_retain(&current, |_, _| Ok::<_, ()>(false)).unwrap();
    assert_eq!(current.work_used(), 8);
    assert_eq!(storage.work_used(), 10_000);
    assert_eq!(storage.used(), capacity);
    assert_eq!(map.try_insert(3, 3), Err(MemoryError::WorkExceeded));
    assert!(map.is_empty());
    drop(map);
    assert_eq!(storage.used(), 0);
}

#[test]
fn retain_zero_sized_pair_drops_once_and_keeps_table_capacity_until_drop() {
    // ZST payloads still have a real hash table allocation. Filtering must drop
    // the value once without refunding that allocation or reserving query memory.
    use core::sync::atomic::{AtomicUsize, Ordering};
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    #[derive(Hash, PartialEq, Eq)]
    struct Key;
    impl HashWork for Key {
        fn hash_work(&self) -> Result<u64, MemoryError> {
            Ok(1)
        }
    }
    struct Value;
    impl Drop for Value {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    assert_eq!(core::mem::size_of::<(Key, Value)>(), 0);
    let storage = memory(1024, 1000);
    let mut map = storage.map();
    map.try_insert(Key, Value).unwrap();
    let before = storage.used();
    assert!(before > 0);
    // The pinned engine chooses a larger minimum table for tiny/ZST entries
    // on wide-control-group targets. Fund that actual table, not a four-bucket
    // assumption appropriate only to the usize-pair fixtures above.
    let scan = usize::try_from(map.buckets().unwrap()).unwrap();
    let current = memory(0, scan + 2);
    map.try_retain(&current, |_, _| Ok::<_, ()>(false)).unwrap();
    assert_eq!(DROPS.load(Ordering::Relaxed), 1);
    assert_eq!(map.key_work, 0);
    assert_eq!(current.work_used(), scan + 2);
    assert_eq!(storage.used(), before);
    assert_eq!(current.used(), 0);
    drop(map);
    assert_eq!(DROPS.load(Ordering::Relaxed), 1);
    assert_eq!(storage.used(), 0);
}

#[cfg(feature = "std")]
#[test]
fn retain_drop_panic_keeps_key_metadata_consistent_with_erased_table() {
    // Hashbrown erases before running Drop. Our remaining-key metadata must
    // already agree if a caller's destructor unwinds out of the filter.
    struct Value<'a>(&'a Cell<bool>);
    impl Drop for Value<'_> {
        fn drop(&mut self) {
            assert!(!self.0.replace(false), "one deliberate drop panic");
        }
    }
    let panic = Cell::new(true);
    let storage = memory(4096, 100_000);
    let mut map = storage.map();
    map.try_insert(1usize, Value(&panic)).unwrap();
    let current = memory(0, 6);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        map.try_retain(&current, |_, _| Ok::<_, ()>(false))
    }));
    assert!(result.is_err());
    assert!(map.is_empty());
    assert_eq!(map.key_work, 0);
    map.try_insert(2, Value(&panic)).unwrap();
    assert_eq!(map.key_work, 1);
    drop(map);
    assert_eq!(storage.used(), 0);
}
