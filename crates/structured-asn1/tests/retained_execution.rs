//! Ownership transfer from bounded schema scratch to independent results.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Limits, Parser};

#[test]
fn generic_callback_retains_memory_or_scoped_storage_without_new_work() {
    // Provider callbacks are generic over sealed Work. They must retain owned
    // outputs without copying or paying aggregate allocation work twice.
    fn retain<W: Work>(
        values: structured_asn1::memory::OwnedVec<u64, W>,
    ) -> structured_asn1::memory::OwnedVec<u64> {
        values.into_owned()
    }
    let account = Arc::new(MemoryAccount::new(1024, 1024));
    let memory = Memory::new(account.clone());
    let mut values = memory.vector();
    values.try_push(42_u64).unwrap();
    let pointer = values.as_ptr();
    let capacity = values.capacity();
    let handles = Arc::strong_count(&account);
    let work = memory.work_used();
    let retained = retain(values);
    assert_eq!(retained.as_ptr(), pointer);
    assert_eq!(retained.capacity(), capacity);
    assert_eq!(memory.work_used(), work);
    assert_eq!(Arc::strong_count(&account), handles);
    drop(retained);
    assert_eq!(memory.used(), 0);
    let parser = Parser::ber(memory.clone());
    let reader = parser.read(&[], 0).unwrap();
    let mut values = reader.execution().vector();
    values.try_push(7_u64).unwrap();
    let pointer = values.as_ptr();
    let work = memory.work_used();
    let retained = retain(values);
    assert_eq!(retained.as_ptr(), pointer);
    assert_eq!(memory.work_used(), work);
    drop(reader);
    drop(parser);
    assert_eq!(&*retained, &[7]);
    drop(retained);
    assert_eq!(memory.used(), 0);
}

#[test]
fn retention_moves_the_same_storage_past_parser_drop() {
    // Finishing a parse must not copy/reserve storage or keep the local reader
    // alive. The original account remains charged until the result is dropped.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let (result, address, capacity, work);
    {
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: 8,
                ..Limits::default()
            },
            memory.clone(),
        );
        let reader = parser.read(&[], 0).unwrap();
        let mut scratch = reader.execution().vector::<u8>();
        scratch.try_reserve_exact(4).unwrap();
        scratch.try_extend_from_slice(&[1, 2, 3, 4]).unwrap();
        address = scratch.as_ptr();
        capacity = scratch.capacity();
        work = memory.work_used();
        result = scratch.into_owned();
    }
    assert_eq!(result.as_ptr(), address);
    assert_eq!(result.capacity(), capacity);
    assert_eq!(&*result, &[1, 2, 3, 4]);
    assert_eq!(memory.used(), capacity);
    assert_eq!(memory.work_used(), work);
    drop(result);
    assert_eq!(memory.used(), 0);
}

#[test]
fn local_refusal_does_not_erase_the_source_on_retention() {
    // A refused operation leaves initialized values intact; later operations
    // on an independent result spend only their explicitly retained account.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let mut result;
    {
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: 4,
                ..Limits::default()
            },
            memory.clone(),
        );
        let reader = parser.read(&[], 0).unwrap();
        let mut scratch = reader.execution().vector::<u8>();
        scratch.try_reserve_exact(4).unwrap();
        assert_eq!(scratch.try_push(1), Err(MemoryError::WorkExceeded));
        result = scratch.into_owned();
    }
    result.try_push(1).unwrap();
    assert_eq!(&*result, &[1]);
    drop(result);
    assert_eq!(memory.used(), 0);
}

#[test]
fn retained_values_are_dropped_once_including_zero_sized_values() {
    // Transfer changes the allocator owner, never the initialized element set.
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Count;
    impl Drop for Count {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 64)));
    let result;
    {
        let parser = Parser::ber(memory.clone());
        let reader = parser.read(&[], 0).unwrap();
        let mut scratch = reader.execution().vector();
        scratch.try_push(Count).unwrap();
        scratch.try_push(Count).unwrap();
        result = scratch.into_owned();
    }
    assert_eq!(DROPS.load(Ordering::Relaxed), 0);
    drop(result);
    assert_eq!(DROPS.load(Ordering::Relaxed), 2);
    assert_eq!(memory.used(), 0);
}

#[test]
fn retention_preserves_alignment_spare_capacity_and_element_drops() {
    // Global deallocation must receive the original over-aligned layout and
    // only the initialized elements may be dropped, even with spare capacity.
    #[repr(align(64))]
    struct Aligned(Arc<AtomicUsize>, u8);
    impl Drop for Aligned {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
    let drops = Arc::new(AtomicUsize::new(0));
    let (result, address, charged);
    {
        let parser = Parser::ber(memory.clone());
        let reader = parser.read(&[], 0).unwrap();
        let mut scratch = reader.execution().vector();
        scratch.try_reserve_exact(5).unwrap();
        scratch.try_push(Aligned(drops.clone(), 7)).unwrap();
        scratch.try_push(Aligned(drops.clone(), 8)).unwrap();
        address = scratch.as_ptr();
        charged = memory.used();
        result = scratch.into_owned();
    }
    assert_eq!(result.as_ptr(), address);
    assert_eq!(result.capacity(), 5);
    assert_eq!(result[0].1, 7);
    assert_eq!(result[1].1, 8);
    assert_eq!(memory.used(), charged);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(result);
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    assert_eq!(memory.used(), 0);
}

#[test]
fn empty_retention_does_not_create_storage_or_work() {
    // An empty scratch has no block to transfer and cannot spend resources.
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let result;
    {
        let parser = Parser::ber(memory.clone());
        let reader = parser.read(&[], 0).unwrap();
        result = reader.execution().vector::<u64>().into_owned();
    }
    assert_eq!(result.capacity(), 0);
    assert_eq!(memory.used(), 0);
    assert_eq!(memory.work_used(), 0);
    drop(result);
    assert_eq!(memory.used(), 0);
}

#[test]
fn transferred_storage_is_the_last_owner_of_its_original_account() {
    // No external Memory handle may be needed to keep the allocation's ledger
    // alive. Dropping the final result then releases that same account.
    let account = Arc::new(MemoryAccount::new(1024, 1024));
    let weak = Arc::downgrade(&account);
    let result;
    {
        let parser = Parser::ber(Memory::new(account));
        let reader = parser.read(&[], 0).unwrap();
        let mut scratch = reader.execution().vector::<u8>();
        scratch.try_reserve_exact(4).unwrap();
        scratch.try_push(7).unwrap();
        result = scratch.into_owned();
    }
    {
        let retained = Memory::new(weak.upgrade().expect("result retains its account"));
        assert_eq!(retained.used(), 4);
    }
    assert_eq!(&*result, &[7]);
    drop(result);
    assert!(weak.upgrade().is_none());
}
