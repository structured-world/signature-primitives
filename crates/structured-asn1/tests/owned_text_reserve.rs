//! Exact text capacity preparation retains execution and UTF-8 invariants.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, MemoryError, OwnedText},
};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

#[test]
fn exact_reserve_pays_growth_once_without_scanning_unicode_prefix() {
    // Known total fragment length must need just one exact growth. Allocation
    // and old-buffer movement are paid, without another prefix validation.
    let account = memory(4096, 4096);
    let mut text = OwnedText::try_from_str("é🦀", &account).unwrap();
    let old = text.capacity();
    let before = account.work_used();
    text.try_reserve_exact(100).unwrap();
    let capacity = text.capacity();
    assert_eq!(capacity, "é🦀".len() + 100);
    assert_eq!(account.work_used() - before, old + capacity);
    assert_eq!(text.as_str(), "é🦀");
    let pointer = text.as_bytes().as_ptr();
    let before = account.work_used();
    for _ in 0..25 {
        text.try_push_str("🦀").unwrap();
    }
    assert_eq!(account.work_used() - before, 100);
    assert_eq!(text.as_bytes().as_ptr(), pointer);
    assert_eq!(account.used(), capacity);
    let retained = text.into_owned();
    assert_eq!(retained.as_bytes().as_ptr(), pointer);
    drop(retained);
    assert_eq!(account.used(), 0);
}

#[test]
fn exact_reserve_preserves_old_text_on_peak_capacity_refusal() {
    // Reserving three additional bytes needs a six-byte replacement plus the
    // original three-byte allocation during growth: nine is exact, eight short.
    for capacity in [8, 9] {
        let account = memory(capacity, 4096);
        let mut text = OwnedText::try_from_str("old", &account).unwrap();
        let pointer = text.as_bytes().as_ptr();
        let result = text.try_reserve_exact(3);
        if capacity == 8 {
            assert_eq!(result, Err(MemoryError::LimitExceeded));
            assert_eq!(text.as_bytes().as_ptr(), pointer);
            assert_eq!(text.capacity(), 3);
        } else {
            result.unwrap();
            assert_eq!(text.capacity(), 6);
        }
        assert_eq!(text.as_str(), "old");
        assert_eq!(account.used(), text.capacity());
        drop(text);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn exact_reserve_uses_original_local_and_aggregate_work() {
    // After three units of validation, growing 3 -> 6 needs nine more. A
    // one-less local or aggregate ceiling cannot change text/storage.
    for local in [11, 12] {
        let account = memory(128, 4096);
        let mut bytes = account.vector();
        bytes.try_extend_from_slice(b"old").unwrap();
        let pointer = bytes.as_ptr();
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            account.clone(),
        );
        let reader = parser.read(&[], 0).unwrap();
        let bytes = bytes.with_execution(&reader.execution()).unwrap();
        let mut text = OwnedText::from_utf8(bytes).unwrap();
        let result = text.try_reserve_exact(3);
        if local == 11 {
            assert_eq!(result, Err(MemoryError::WorkExceeded));
            assert_eq!(text.as_bytes().as_ptr(), pointer);
            assert_eq!(text.capacity(), 3);
        } else {
            result.unwrap();
            assert_eq!(text.capacity(), 6);
        }
        assert_eq!(text.as_str(), "old");
        drop(text);
        assert_eq!(account.used(), 0);
    }
    for remaining in [8, 9] {
        let account = memory(128, 4096);
        let mut text = OwnedText::try_from_str("old", &account).unwrap();
        let pointer = text.as_bytes().as_ptr();
        account
            .charge_work((account.work_remaining() - remaining) as u64)
            .unwrap();
        let before = account.work_used();
        let result = text.try_reserve_exact(3);
        if remaining == 8 {
            assert_eq!(result, Err(MemoryError::WorkExceeded));
            assert_eq!(text.as_bytes().as_ptr(), pointer);
            assert_eq!(text.capacity(), 3);
            assert_eq!(account.work_used() - before, 6);
        } else {
            result.unwrap();
            assert_eq!(text.capacity(), 6);
            assert_eq!(account.work_used() - before, 9);
        }
        assert_eq!(text.as_str(), "old");
        drop(text);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn existing_capacity_empty_and_overflow_do_not_scan_or_mutate_text() {
    // Capacity preparation is not a text copy/validation; no-growth works with
    // an exhausted execution, while overflow is a distinct processing failure.
    let account = memory(128, 4096);
    let mut bytes = account.vector();
    bytes.try_reserve_exact(128).unwrap();
    bytes.try_extend_from_slice("é".as_bytes()).unwrap();
    let mut text = OwnedText::from_utf8(bytes).unwrap();
    let pointer = text.as_bytes().as_ptr();
    account
        .charge_work(account.work_remaining() as u64)
        .unwrap();
    let before = account.work_used();
    text.try_reserve_exact(126).unwrap();
    text.try_reserve_exact(0).unwrap();
    assert_eq!(
        text.try_reserve_exact(usize::MAX),
        Err(MemoryError::CapacityOverflow)
    );
    assert_eq!(text.as_str(), "é");
    assert_eq!(text.as_bytes().as_ptr(), pointer);
    assert_eq!(text.capacity(), 128);
    assert_eq!(account.work_used(), before);
    drop(text);
    assert_eq!(account.used(), 0);
    let empty = memory(0, 0);
    let mut text = OwnedText::from_utf8(empty.vector()).unwrap();
    text.try_reserve_exact(0).unwrap();
    assert_eq!(text.capacity(), 0);
}
