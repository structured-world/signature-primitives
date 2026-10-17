use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::super::{Memory, MemoryAccount, MemoryError};
use super::{TableAllocator, scoped};
use crate::{Encoding, Limits, Parser};

type TableVec = allocator_api2_hashbrown::vec::Vec<u8, TableAllocator>;

fn table(values: &TableVec) -> &TableAllocator {
    values.allocator()
}

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

#[test]
fn table_and_vector_interfaces_share_live_capacity_and_growth_peak() {
    // The external hashbrown ABI and current vector ABI must retain the
    // same charge, reject the same coexistence peak and release on drop.
    let memory = memory(24, usize::MAX);
    let mut current = memory.vector::<u8>();
    current.try_extend_from_slice(&[7; 8]).unwrap();
    let mut table_interface = TableVec::new_in(TableAllocator::new(memory.clone()));
    scoped(&mut table_interface, table, &memory, |values| {
        values.try_reserve_exact(8)
    })
    .unwrap();
    table_interface.push(42);
    assert_eq!(memory.used(), 16);
    let attempts = table_interface.allocator().attempts.load(Ordering::Relaxed);
    assert!(
        scoped(&mut table_interface, table, &memory, |values| {
            values.try_reserve_exact(8)
        })
        .is_err()
    );
    assert_eq!(
        table_interface.allocator().failure(),
        MemoryError::LimitExceeded
    );
    assert_eq!(
        table_interface.allocator().attempts.load(Ordering::Relaxed),
        attempts
    );
    assert_eq!(&*table_interface, &[42]);
    assert_eq!(table_interface.capacity(), 8);
    assert_eq!(memory.used(), 16);
    drop(current);
    assert_eq!(memory.used(), 8);
    scoped(&mut table_interface, table, &memory, |values| {
        values.try_reserve_exact(8)
    })
    .unwrap();
    assert_eq!(&*table_interface, &[42]);
    assert_eq!(memory.used(), table_interface.capacity());
    drop(table_interface);
    assert_eq!(memory.used(), 0);
}

#[test]
fn table_allocation_without_an_installed_scope_is_refused_before_the_backend() {
    // Growth outside a scoped call has no execution to fund it. Refusal must
    // precede the backend, roll back capacity and spend no aggregate work.
    let memory = memory(64, 1000);
    let mut values = TableVec::new_in(TableAllocator::new(memory.clone()));
    assert!(values.try_reserve_exact(8).is_err());
    assert_eq!(values.allocator().failure(), MemoryError::WorkExceeded);
    assert_eq!(values.allocator().attempts.load(Ordering::Relaxed), 0);
    assert_eq!(values.capacity(), 0);
    assert_eq!(memory.used(), 0);
    assert_eq!(memory.work_used(), 0);
}

#[test]
fn table_scope_is_cleared_after_success_and_after_refusal() {
    // A stale scope would let a later allocation dereference an ended frame.
    let memory = memory(8, 1000);
    let mut values = TableVec::new_in(TableAllocator::new(memory.clone()));
    scoped(&mut values, table, &memory, |values| {
        assert!(values.allocator().scope_installed());
        values.try_reserve_exact(8)
    })
    .unwrap();
    assert!(!values.allocator().scope_installed());
    assert!(
        scoped(&mut values, table, &memory, |values| {
            values.try_reserve_exact(64)
        })
        .is_err()
    );
    assert!(!values.allocator().scope_installed());
}

#[test]
fn table_grow_admits_new_then_old_and_keeps_refused_work_spent() {
    // Mirrors the published vector allocator: capacity first, then the new
    // and old sizes, then the backend. A refusal of the old size keeps the
    // already admitted new size spent and leaves the original block intact.
    for (work, grown) in [(8 + 17 + 7, false), (8 + 17 + 8, true)] {
        let memory = memory(64, work);
        let mut values = TableVec::new_in(TableAllocator::new(memory.clone()));
        scoped(&mut values, table, &memory, |values| {
            values.try_reserve_exact(8)
        })
        .unwrap();
        values.push(42);
        let attempts = values.allocator().attempts.load(Ordering::Relaxed);
        let result = scoped(&mut values, table, &memory, |values| {
            values.try_reserve_exact(16)
        });
        assert_eq!(result.is_ok(), grown);
        assert_eq!(&*values, &[42]);
        if grown {
            assert_eq!(values.capacity(), 17);
            assert_eq!(memory.used(), 17);
            assert_eq!(memory.work_used(), 8 + 17 + 8);
        } else {
            assert_eq!(values.allocator().failure(), MemoryError::WorkExceeded);
            assert_eq!(
                values.allocator().attempts.load(Ordering::Relaxed),
                attempts
            );
            assert_eq!(values.capacity(), 8);
            assert_eq!(memory.used(), 8);
            assert_eq!(memory.work_used(), 8 + 17);
        }
    }
}

#[test]
fn table_scope_charges_the_local_parser_ceiling_and_the_aggregate() {
    // A borrowed execution's local ceiling must refuse growth even when the
    // aggregate account is ample, and the reverse, both before the backend.
    for (local, aggregate) in [(7, 1000), (1000, 7), (8, 8)] {
        let memory = memory(64, aggregate);
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            memory.clone(),
        );
        let reader = parser.read(&[], 0).unwrap();
        let execution = reader.execution();
        let mut values = TableVec::new_in(TableAllocator::new(memory.clone()));
        let result = scoped(&mut values, table, &execution, |values| {
            values.try_reserve_exact(8)
        });
        if local == 8 {
            assert!(result.is_ok());
            assert_eq!(memory.work_used(), 8);
            assert_eq!(memory.used(), 8);
        } else {
            assert!(result.is_err());
            assert_eq!(values.allocator().failure(), MemoryError::WorkExceeded);
            assert_eq!(values.allocator().attempts.load(Ordering::Relaxed), 0);
            assert_eq!(memory.used(), 0);
        }
    }
}

#[test]
fn quota_rejection_never_reaches_the_backend() {
    // Post-allocation checks would pass ordinary quota tests but still call
    // the allocator. Count the actual forwarding point to prevent that bug.
    let memory = memory(0, usize::MAX);
    let mut bytes = memory.vector::<u8>();
    assert_eq!(bytes.try_reserve_exact(1), Err(MemoryError::LimitExceeded));
    assert_eq!(bytes.values.allocator().attempts.load(Ordering::Relaxed), 0);
    assert_eq!(memory.used(), 0);
}

#[test]
fn backend_failure_rolls_back_a_pending_reservation() {
    // A genuine allocation failure must release the reservation and must
    // remain distinguishable from a configured quota rejection.
    let memory = memory(16, usize::MAX);
    let mut bytes = memory.vector::<u8>();
    bytes
        .values
        .allocator()
        .fail_backend
        .store(true, Ordering::Relaxed);
    assert_eq!(bytes.try_reserve_exact(8), Err(MemoryError::OutOfMemory));
    assert_eq!(bytes.capacity(), 0);
    assert_eq!(memory.used(), 0);
}

#[test]
fn failed_growth_keeps_old_bytes_and_old_charge() {
    // Failed realloc retains the old pointer and values; only the pending
    // replacement charge is rolled back.
    let memory = memory(32, usize::MAX);
    let mut bytes = memory.vector::<u8>();
    bytes.try_reserve_exact(8).unwrap();
    bytes.try_push(42).unwrap();
    bytes
        .values
        .allocator()
        .fail_backend
        .store(true, Ordering::Relaxed);
    assert_eq!(bytes.try_reserve_exact(8), Err(MemoryError::OutOfMemory));
    assert_eq!(&*bytes, &[42]);
    assert_eq!(bytes.capacity(), 8);
    assert_eq!(memory.used(), 8);
}
