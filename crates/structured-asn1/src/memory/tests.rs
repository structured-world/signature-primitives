use alloc::sync::Arc;
use core::mem::size_of;

use super::{Memory, MemoryAccount, MemoryError};

fn memory(limit: usize) -> Memory {
    // The caller owns creation of the trusted account, before document processing.
    Memory::new(Arc::new(MemoryAccount::new(limit, usize::MAX)))
}

#[test]
fn sparse_map_traversal_cannot_use_an_old_operations_work() {
    // Hashbrown scans control buckets, including holes left by removals.
    // A new operation must refuse before constructing/scanning that iterator.
    let storage = memory(16_384);
    let mut values = storage.map();
    for key in 0..32usize {
        values.try_insert(key, key).unwrap();
    }
    for key in 0..31usize {
        values.remove(&key, &storage).unwrap();
    }
    assert_eq!(values.len(), 1);
    let execution = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(values.try_iter(&execution).is_err());
    assert_eq!(execution.work_used(), 0);
    let before = storage.work_used();
    let capacity = storage.used();
    let execution = Memory::new(Arc::new(MemoryAccount::new(0, 64)));
    {
        let mut entries = values.try_iter(&execution).unwrap();
        assert_eq!(entries.next(), Some((&31, &31)));
        assert!(entries.next().is_none());
        assert!(entries.next().is_none());
    }
    assert_eq!(execution.work_used(), 64);
    assert_eq!(execution.used(), 0);
    assert_eq!(storage.work_used(), before);
    assert_eq!(storage.used(), capacity);
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert_eq!(values.get(&31, &denied), Err(MemoryError::WorkExceeded));
    let lookup = Memory::new(Arc::new(MemoryAccount::new(0, 1024)));
    assert_eq!(values.get(&31, &lookup).unwrap(), Some(&31));
    assert_eq!(values.remove(&31, &lookup).unwrap(), Some(31));
    assert_eq!(storage.work_used(), before);
    assert_eq!(storage.used(), capacity);
    drop(values);
    assert_eq!(storage.used(), 0);
}

#[test]
fn map_removal_admits_metadata_and_movement_before_mutation() {
    // A budget sufficient for the lookup alone must not authorize erase
    // control updates and moving the returned tuple. Refusal retains the entry.
    let storage = memory(1024);
    let mut values = storage.map();
    values.try_insert(1usize, 42usize).unwrap();
    let execution = Memory::new(Arc::new(MemoryAccount::new(0, 4)));
    assert_eq!(
        values.remove(&1, &execution),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(values.len(), 1);
    assert_eq!(values.get(&1, &memory(0)).unwrap(), Some(&42));
}

#[test]
fn fallible_sort_preserves_order_and_multiplicity_without_allocating() {
    // Heap boundaries include empty, singleton, even/odd lengths and duplicate
    // keys. Sorting retains exactly the existing allocation and every value.
    let account = memory(1024);
    for input in [
        &[][..],
        &[7],
        &[2, 1],
        &[3, 1, 2],
        &[4, 1, 3, 2],
        &[3, 1, 3, 2, 1],
    ] {
        let mut values = account.vector();
        values.try_extend_from_slice(input).unwrap();
        let charge = account.used();
        values
            .try_sort_unstable_by(|left, right| Ok::<_, MemoryError>(left.cmp(right)))
            .unwrap();
        let mut expected = input.to_vec();
        expected.sort_unstable();
        assert_eq!(&*values, expected);
        assert_eq!(account.used(), charge);
    }
}

#[test]
fn sort_refusal_precedes_comparison_and_retains_all_values() {
    // Exhausting cumulative work must stop before calling user comparison
    // code, without dropping or manufacturing any element.
    let account = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let mut values = account.vector();
    values.try_extend_from_slice(&[2, 1]).unwrap();
    account
        .charge_work((1024 - account.work_used()) as u64)
        .unwrap();
    let mut comparisons = 0;
    assert_eq!(
        values.try_sort_unstable_by(|left, right| {
            comparisons += 1;
            Ok::<_, MemoryError>(left.cmp(right))
        }),
        Err(super::SortError::Resource(MemoryError::WorkExceeded))
    );
    assert_eq!(comparisons, 0);
    assert_eq!(&*values, &[2, 1]);
}

#[test]
fn fallible_sort_preserves_comparator_error_and_partial_permutation() {
    // CMS issuer-index comparisons carry a located resource error. Sorting
    // must preserve that error, stop comparisons immediately and lose no key.
    let account = memory(1024);
    let mut values = account.vector();
    values.try_extend_from_slice(&[5, 3, 1, 4, 2]).unwrap();
    let storage = account.used();
    let mut comparisons = 0;
    let source = ("issuer", 91u64);
    let result = values.try_sort_unstable_by(|left, right| {
        comparisons += 1;
        if comparisons == 3 {
            return Err(source);
        }
        Ok(left.cmp(right))
    });
    assert_eq!(result, Err(super::SortError::Comparison(source)));
    assert_eq!(comparisons, 3);
    assert_eq!(account.used(), storage);
    let mut retained = values.to_vec();
    retained.sort_unstable();
    assert_eq!(retained, [1, 2, 3, 4, 5]);
}

#[test]
fn retained_storage_outlives_the_original_handle() {
    // A proof's storage must remain charged after its creating operation ends.
    let account = memory(32);
    let observer = account.clone();
    let mut bytes = account.vector::<u8>();
    bytes.try_reserve_exact(16).unwrap();
    let capacity = bytes.capacity();
    drop(account);
    assert_eq!(observer.used(), capacity);
    drop(bytes);
    assert_eq!(observer.used(), 0);
}

#[test]
fn clearing_retains_the_capacity_charge() {
    // Removing values does not free reusable storage and must not replenish quota.
    let account = memory(32);
    let mut bytes = account.vector();
    bytes.try_push(7u8).unwrap();
    let capacity = bytes.capacity();
    bytes.clear();
    assert_eq!(account.used(), capacity);
    assert!(bytes.is_empty());
}

#[test]
fn growth_reserves_the_old_and_new_storage_peak() {
    // Growth can move storage: a budget fitting only the final allocation is insufficient.
    let account = memory(12);
    let mut bytes = account.vector();
    bytes.try_reserve_exact(8).unwrap();
    bytes.try_push(9u8).unwrap();
    assert_eq!(bytes.try_reserve_exact(8), Err(MemoryError::LimitExceeded));
    assert_eq!(&*bytes, &[9]);
    assert_eq!(bytes.capacity(), 8);
    assert_eq!(account.used(), 8);
}

#[test]
fn independent_containers_share_one_limit() {
    // Splitting storage across collections cannot bypass the operation's aggregate quota.
    let account = memory(8);
    let mut first = account.vector::<u32>();
    let mut second = account.vector::<u32>();
    first.try_reserve_exact(2).unwrap();
    assert_eq!(account.used(), 2 * size_of::<u32>());
    assert_eq!(second.try_push(1), Err(MemoryError::LimitExceeded));
    assert_eq!(second.capacity(), 0);
    drop(first);
    // Request exact storage: Vec's amortized initial capacity exceeds this
    // deliberately tiny quota even when it has room for one u32.
    second.try_reserve_exact(1).unwrap();
    second.try_push(1).unwrap();
}

#[test]
fn copies_are_fallible_and_do_not_change_the_original() {
    // An owned copy must acquire its own reservation before copying source values.
    let account = memory(8);
    let mut bytes = account.vector();
    bytes.try_reserve_exact(8).unwrap();
    bytes.try_push(42u8).unwrap();
    assert_eq!(bytes.try_copy().unwrap_err(), MemoryError::LimitExceeded);
    assert_eq!(&*bytes, &[42]);
    assert_eq!(account.used(), 8);
}

#[test]
fn rejected_copy_work_cannot_leave_new_capacity() {
    // Eight allocation units would fit, but the eight copy units would not.
    // Admit copying before attempting growth so refusal leaves no new buffer.
    let account = Memory::new(Arc::new(MemoryAccount::new(16, 10)));
    let mut bytes = account.vector();
    assert_eq!(
        bytes.try_extend_from_slice(&[1u8; 8]),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(bytes.capacity(), 0);
    assert_eq!(account.used(), 0);
    assert!(bytes.is_empty());
}

#[test]
fn zero_sized_values_do_not_request_storage() {
    // Zero-sized elements still form a collection but must not consume byte quota.
    let account = memory(0);
    let mut values = account.vector::<()>();
    values.try_push(()).unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(account.used(), 0);
}

#[test]
fn overflowing_capacity_is_rejected_without_spending() {
    // Attacker-selected capacities must not wrap the allocation layout or debit quota.
    let account = memory(usize::MAX);
    let mut values = account.vector::<u64>();
    assert_eq!(
        values.try_reserve_exact(usize::MAX),
        Err(MemoryError::CapacityOverflow)
    );
    assert_eq!(account.used(), 0);
}

#[test]
fn owned_storage_is_send_and_sync_when_elements_are() {
    // Retained proofs must be movable and shareable without a parser or thread-local account.
    fn send_sync<T: Send + Sync>() {}
    send_sync::<super::OwnedVec<u8>>();
    send_sync::<Memory>();
}

#[test]
fn releasing_storage_does_not_refund_work() {
    // A retained copy shares cumulative work even after its creator is dropped.
    let account = Memory::new(Arc::new(MemoryAccount::new(32, 10)));
    let mut bytes = account.vector::<u8>();
    bytes.try_reserve_exact(8).unwrap();
    bytes.try_push(42).unwrap();
    assert_eq!(account.work_used(), 9);
    assert_eq!(bytes.try_copy().unwrap_err(), MemoryError::WorkExceeded);
    // Admitting the copy's allocation consumed its one unit, even though copying
    // was subsequently refused. Its temporary storage has already been freed.
    assert_eq!(account.work_used(), 10);
    assert_eq!(account.used(), 8);
    drop(bytes);
    assert_eq!(account.used(), 0);
    assert_eq!(account.charge_work(1), Err(MemoryError::WorkExceeded));
}

#[test]
fn adapter_reservations_share_identity_and_lifetime() {
    // An external adapter can join the same aggregate account, without creating
    // a fresh allowance or losing charges when the original handle disappears.
    let account = memory(8);
    let observer = account.clone();
    assert!(account.same_account(&observer));
    assert!(!account.same_account(&memory(8)));
    let reservation = account.reserve(8).unwrap();
    drop(account);
    assert_eq!(observer.used(), 8);
    assert_eq!(observer.reserve(1).unwrap_err(), MemoryError::LimitExceeded);
    drop(reservation);
    assert_eq!(observer.used(), 0);
}

#[test]
fn unrepresentable_or_excess_work_is_refused_without_wrapping() {
    // The u64 API must never truncate costs on a word-sized target or wrap totals.
    let account = Memory::new(Arc::new(MemoryAccount::new(0, 1)));
    assert_eq!(
        account.charge_work(u64::MAX),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(account.work_used(), 0);
    account.charge_work(1).unwrap();
    assert_eq!(account.charge_work(1), Err(MemoryError::WorkExceeded));
    assert_eq!(account.work_used(), 1);
}

#[test]
fn hash_table_storage_joins_the_same_live_quota() {
    // Bucket/control-byte storage must go through the same pre-allocation
    // boundary as Vec storage; an empty allowance cannot admit the first entry.
    let denied = memory(0);
    let mut empty = denied.map::<usize, u8>();
    assert_eq!(empty.try_insert(1, 42), Err(MemoryError::LimitExceeded));
    assert!(empty.is_empty());
    assert_eq!(denied.used(), 0);
    let account = memory(1024);
    let mut values = account.map::<usize, u8>();
    values.try_insert(1, 42).unwrap();
    let capacity_charge = account.used();
    assert!(capacity_charge > core::mem::size_of::<(usize, u8)>());
    assert_eq!(values.get(&1, &account).unwrap(), Some(&42));
    assert_eq!(values.try_insert(1, 7).unwrap(), Some(42));
    assert_eq!(account.used(), capacity_charge);
    assert_eq!(values.remove(&1, &account).unwrap(), Some(7));
    assert_eq!(account.used(), capacity_charge);
    drop(values);
    assert_eq!(account.used(), 0);
}

#[test]
fn table_resize_admits_collision_probe_fanout_before_rehashing() {
    // Rehashing a full table of colliding keys can probe quadratically. The
    // allocation byte charge alone must not admit that attacker-controlled work.
    static HASHES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    #[derive(PartialEq, Eq)]
    struct Collision(usize);
    impl core::hash::Hash for Collision {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            HASHES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            state.write_u8(0);
        }
    }
    impl super::HashWork for Collision {
        fn hash_work(&self) -> Result<u64, MemoryError> {
            Ok(1)
        }
    }
    let account = Memory::new(Arc::new(MemoryAccount::new(64 * 1024, 10_000_000)));
    let mut values = account.map();
    for key in 0..448 {
        values.try_insert(Collision(key), 42u8).unwrap();
    }
    let storage = account.used();
    let remaining = 10_000_000 - account.work_used();
    account.charge_work((remaining - 30_000) as u64).unwrap();
    HASHES.store(0, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        values.try_insert(Collision(448), 7),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(HASHES.load(core::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(values.len(), 448);
    assert_eq!(account.used(), storage);
}

#[test]
fn collision_exhaustion_stops_before_equality_or_mutation() {
    // A failed comparison admission must stop probing immediately and must not
    // expose the synthetic matched entry or overwrite an unrelated value.
    #[derive(Debug)]
    struct Collision {
        id: usize,
        comparisons: Arc<core::sync::atomic::AtomicUsize>,
    }
    impl core::hash::Hash for Collision {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            state.write_u8(0);
        }
    }
    impl PartialEq for Collision {
        fn eq(&self, other: &Self) -> bool {
            self.comparisons
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            self.id == other.id
        }
    }
    impl Eq for Collision {}
    impl super::HashWork for Collision {
        fn hash_work(&self) -> Result<u64, MemoryError> {
            Ok(1000)
        }
    }
    let comparisons = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let account = Memory::new(Arc::new(MemoryAccount::new(1024, 10_000)));
    let mut values = account.map();
    values
        .try_insert(
            Collision {
                id: 1,
                comparisons: comparisons.clone(),
            },
            42u8,
        )
        .unwrap();
    // A three-entry table admits one control group and the query hash, but cannot
    // admit either key's equality work. The expensive comparison must never run.
    let remaining = 10_000 - account.work_used();
    account.charge_work((remaining - 1001) as u64).unwrap();
    assert_eq!(
        values.try_insert(
            Collision {
                id: 2,
                comparisons: comparisons.clone()
            },
            7
        ),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(comparisons.load(core::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(values.len(), 1);
    // Inspect retained bytes under a fresh work account; the rejection above
    // consumed the old work allowance but must not mutate the retained entry.
    assert_eq!(values.try_iter(&memory(0)).unwrap().next().unwrap().1, &42);
}

#[test]
fn owning_iteration_retains_the_allocation_charge() {
    // Moving a result into its iterator must not free its capacity while unread
    // elements or an exhausted iterator still retain the backing allocation.
    let account = memory(8);
    let mut bytes = account.vector();
    bytes.try_reserve_exact(8).unwrap();
    bytes.try_push(42u8).unwrap();
    let mut iter = bytes.into_iter();
    assert_eq!(iter.next(), Some(42));
    assert_eq!(iter.next(), None);
    assert_eq!(account.used(), 8);
    drop(iter);
    assert_eq!(account.used(), 0);
}

#[test]
fn successful_growth_releases_the_old_charge() {
    // Peak admission includes both blocks, but only replacement capacity stays charged.
    let account = memory(32);
    let mut bytes = account.vector::<u8>();
    bytes.try_reserve_exact(8).unwrap();
    bytes.try_push(42).unwrap();
    bytes.try_reserve_exact(8).unwrap();
    assert_eq!(&*bytes, &[42]);
    assert_eq!(account.used(), bytes.capacity());
    assert_eq!(bytes.capacity(), 9);
    drop(bytes);
    assert_eq!(account.used(), 0);
}

#[test]
fn forgetting_storage_does_not_refund_it() {
    // mem::forget leaks the allocation; a reservation must leak with it rather than
    // permit further allocations beyond the quota while the first block remains live.
    let account = memory(8);
    let mut bytes = account.vector::<u8>();
    bytes.try_reserve_exact(8).unwrap();
    core::mem::forget(bytes);
    assert_eq!(account.used(), 8);
    let mut next = account.vector::<u8>();
    assert_eq!(next.try_reserve_exact(1), Err(MemoryError::LimitExceeded));
}

#[cfg(feature = "std")]
#[test]
fn concurrent_admissions_cannot_exceed_the_shared_limit() {
    // All three attempts retain storage until inspection: exactly two eight-byte
    // allocations fit, regardless of scheduling or concurrent compare-exchanges.
    let account = memory(16);
    let ready = std::sync::Barrier::new(4);
    let release = std::sync::Barrier::new(4);
    std::thread::scope(|scope| {
        let mut workers = alloc::vec::Vec::new();
        for _ in 0..3 {
            workers.push(scope.spawn(|| {
                let mut bytes = account.vector::<u8>();
                let result = bytes.try_reserve_exact(8);
                ready.wait();
                release.wait();
                result
            }));
        }
        ready.wait();
        assert_eq!(account.used(), 16);
        release.wait();
        let mut accepted = 0;
        let mut denied = 0;
        for worker in workers {
            match worker.join().unwrap() {
                Ok(()) => accepted += 1,
                Err(MemoryError::LimitExceeded) => denied += 1,
                other => panic!("unexpected admission: {other:?}"),
            }
        }
        assert_eq!((accepted, denied), (2, 1));
    });
    assert_eq!(account.used(), 0);
}

#[cfg(feature = "std")]
#[test]
fn a_panicking_element_drop_still_releases_storage() {
    // Unwinding through a value's destructor must still deallocate the Vec backing
    // block and release its charge; the allocator must outlive that cleanup.
    struct Panics(u8);
    impl Drop for Panics {
        fn drop(&mut self) {
            panic!("drop {}", self.0);
        }
    }
    let account = memory(8);
    let mut values = account.vector();
    values.try_reserve_exact(1).unwrap();
    values.try_push(Panics(7)).unwrap();
    assert!(std::panic::catch_unwind(|| drop(values)).is_err());
    assert_eq!(account.used(), 0);
}
