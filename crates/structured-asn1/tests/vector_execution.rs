//! Scoped ownership transfer keeps the allocation and restores original work.

use std::{cell::Cell, sync::Arc};
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, MemoryError, VecExecution, Work},
};

struct Dropped<'a>(&'a Cell<usize>);
impl Drop for Dropped<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn borrowed_vector_round_trip_has_no_copy_allocation_or_account_increment() {
    // Retained storage has its own keeper already. Rebinding borrowed Work
    // moves that keeper, and a refused spare-capacity push changes nothing.
    let account = Arc::new(MemoryAccount::new(4096, 65536));
    let memory = Memory::new(account.clone());
    let producer = Parser::ber(memory.clone());
    let query = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory.clone(),
    );
    let original = producer.read(&[], 0).unwrap();
    let current = query.read(&[], 0).unwrap();
    let drops = Cell::new(0);
    let mut values = original.execution().vector();
    values.try_reserve_exact(4).unwrap();
    values.try_push(Dropped(&drops)).unwrap();
    let pointer = values.as_ptr();
    let capacity = values.capacity();
    let charged = memory.used();
    let owners = Arc::strong_count(&account);
    let spent = original.execution().work_remaining();
    let VecExecution::Changed {
        mut values,
        previous,
    } = values.rebind(current.execution())
    else {
        panic!("same-account borrowed execution must transfer")
    };
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(values.capacity(), capacity);
    assert_eq!(memory.used(), charged);
    assert_eq!(Arc::strong_count(&account), owners);
    assert_eq!(
        values.try_push(Dropped(&drops)),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(values.len(), 1);
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(drops.get(), 1);
    let VecExecution::Changed { values, .. } = values.rebind(previous) else {
        panic!("original execution must restore")
    };
    assert_eq!(original.execution().work_remaining(), spent);
    assert_eq!(Arc::strong_count(&account), owners);
    let retained = values.into_owned();
    assert_eq!(retained.as_ptr(), pointer);
    drop(retained);
    assert_eq!(drops.get(), 2);
    assert_eq!(memory.used(), 0);
}

#[test]
fn account_mismatch_returns_both_inputs_without_moving_elements() {
    // A different account must not inherit another allocation's charge.
    let first = Memory::new(Arc::new(MemoryAccount::new(4096, 65536)));
    let second = Memory::new(Arc::new(MemoryAccount::new(4096, 65536)));
    let drops = Cell::new(0);
    let mut values = first.vector();
    values.try_push(Dropped(&drops)).unwrap();
    let pointer = values.as_ptr();
    let charged = first.used();
    let VecExecution::Foreign { values, requested } = values.rebind(second) else {
        panic!("different accounts must refuse")
    };
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(first.used(), charged);
    assert_eq!(requested.used(), 0);
    assert_eq!(drops.get(), 0);
    drop(values);
    assert_eq!(drops.get(), 1);
    assert_eq!(first.used(), 0);
}

#[test]
fn zero_sized_drop_values_keep_their_ownership_across_transfer() {
    // ZST capacity uses a sentinel rather than a heap allocation. The same
    // transfer must still preserve the exact number of owned destructors.
    use std::sync::atomic::{AtomicUsize, Ordering};
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Zst;
    impl Drop for Zst {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
    let parser = Parser::ber(memory.clone());
    let reader = parser.read(&[], 0).unwrap();
    let mut values = reader.execution().vector();
    values.try_push(Zst).unwrap();
    let pointer = values.as_ptr();
    let capacity = values.capacity();
    let VecExecution::Changed { values, previous } = values.rebind(reader.execution()) else {
        panic!("same account")
    };
    let VecExecution::Changed { values, .. } = values.rebind(previous) else {
        panic!("restored account")
    };
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(values.capacity(), capacity);
    assert_eq!(values.len(), 1);
    assert_eq!(memory.used(), 0);
    assert_eq!(DROPS.load(Ordering::Relaxed), 0);
    drop(values);
    assert_eq!(DROPS.load(Ordering::Relaxed), 1);
}
