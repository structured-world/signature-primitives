//! Public parser-bound scratch admission, independent of document decoding.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, SortError, Work};
use structured_asn1::{Encoding, Limits, Parser};

#[test]
fn scratch_growth_refuses_local_work_before_allocator_or_move() {
    // Spare aggregate allowance cannot authorize a replacement allocation
    // after the original parser's cumulative ceiling has been spent.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 8,
            ..Limits::default()
        },
        memory.clone(),
    );
    let reader = parser.read(&[], 900).unwrap();
    let execution = reader.execution();
    let mut bytes = execution.vector();
    bytes.try_reserve_exact(4).unwrap();
    bytes.try_push(7_u8).unwrap();
    let work = memory.work_used();
    assert_eq!(bytes.try_reserve_exact(8), Err(MemoryError::WorkExceeded));
    assert_eq!(&*bytes, &[7]);
    assert_eq!(bytes.capacity(), 4);
    assert_eq!(memory.used(), 4);
    assert_eq!(memory.work_used(), work);
    drop(bytes);
    assert_eq!(memory.used(), 0);
}

#[test]
fn scratch_sort_refuses_before_comparator_dispatch() {
    // A sorter must not pay only its comparison callback: its own dispatch
    // and value movements share the producing reader's remaining allowance.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 20,
            ..Limits::default()
        },
        memory.clone(),
    );
    let reader = parser.read(&[], 900).unwrap();
    let execution = reader.execution();
    let mut values = execution.vector();
    values.try_reserve_exact(4).unwrap();
    for value in [4_u32, 3, 2, 1] {
        values.try_push(value).unwrap();
    }
    let mut comparisons = 0;
    let result = values.try_sort_unstable_by(|left, right| {
        comparisons += 1;
        Ok::<_, MemoryError>(left.cmp(right))
    });
    assert_eq!(result, Err(SortError::Resource(MemoryError::WorkExceeded)));
    assert_eq!(comparisons, 0);
    assert_eq!(&*values, &[4, 3, 2, 1]);
    drop(values);
    assert_eq!(memory.used(), 0);
}

#[test]
fn scratch_execution_charges_aggregate_once_and_keeps_session_cumulative() {
    // Rebinding execution chooses the new aggregate domain, without resetting
    // the parser-local counter or charging both old and current accounts.
    let old = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let current = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 10,
            ..Limits::default()
        },
        old.clone(),
    );
    let reader = parser.read(&[], 900).unwrap().with_execution(&current);
    let execution = reader.execution();
    let mut bytes = execution.vector();
    bytes.try_reserve_exact(8).unwrap();
    bytes.try_push(7_u8).unwrap();
    assert_eq!(current.work_used(), 9);
    assert_eq!(old.work_used(), 0);
    reader.charge(1).unwrap();
    assert_eq!(bytes.try_push(8), Err(MemoryError::WorkExceeded));
    assert_eq!(&*bytes, &[7]);
    assert_eq!(current.work_used(), 10);
    drop(bytes);
    assert_eq!(current.used(), 0);
}

#[test]
fn reader_descent_cannot_allocate_a_path_after_local_work_exhaustion() {
    // Deferred BER scratch also enters ordinary readers. Paying its frame
    // afterwards cannot authorize the path allocation performed by enter.
    let bytes = [0x30, 0];
    let probe = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let probe_parser = Parser::ber(probe.clone());
    let mut probe_reader = probe_parser.read(&bytes, 400).unwrap();
    probe_reader.next_element().unwrap().unwrap();
    let header_work = probe.work_used() as u64;

    let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: header_work,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = reader.enter(&element).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 402);
    assert_eq!(memory.used(), 0);
    assert_eq!(memory.work_used() as u64, header_work);
}

#[test]
fn forgotten_parser_scratch_keeps_its_allocation_account_alive() {
    // Even a borrowed work ceiling cannot make leaked capacity disappear:
    // forgetting scratch must retain the independently owned storage account.
    let account = Arc::new(MemoryAccount::new(1024, 1024));
    let weak = Arc::downgrade(&account);
    {
        let parser = Parser::ber(Memory::new(account));
        let reader = parser.read(&[], 0).unwrap();
        let mut scratch = reader.execution().vector();
        scratch.try_reserve_exact(4).unwrap();
        scratch.try_push(7_u8).unwrap();
        assert_eq!(reader.memory().used(), 4);
        std::mem::forget(scratch);
    }
    let account = weak
        .upgrade()
        .expect("forgotten allocation retains its account");
    let memory = Memory::new(account);
    assert_eq!(memory.used(), 4);
}
