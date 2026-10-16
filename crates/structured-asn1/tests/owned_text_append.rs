//! Valid-string appends preserve UTF-8 and the original scoped execution.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, MemoryError, OwnedText},
};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

#[test]
fn fragmented_text_pays_only_new_bytes_without_rescanning_prefix() {
    // Adjacent XML text fragments must not repeatedly validate the growing
    // prefix. Spare-capacity appends pay exactly the copied UTF-8 byte count.
    let account = memory(8192, 100_000);
    let mut bytes = account.vector();
    bytes.try_reserve_exact(8192).unwrap();
    bytes.try_extend_from_slice(b"prefix").unwrap();
    let mut text = OwnedText::from_utf8(bytes).unwrap();
    let pointer = text.as_bytes().as_ptr();
    let before = account.work_used();
    for _ in 0..1000 {
        text.try_push_str("é🦀").unwrap();
    }
    assert_eq!(account.work_used() - before, 6000);
    assert_eq!(text.as_str(), format!("prefix{}", "é🦀".repeat(1000)));
    assert_eq!(text.as_bytes().as_ptr(), pointer);
    assert_eq!(account.used(), 8192);
    drop(text);
    assert_eq!(account.used(), 0);
}

#[test]
fn append_enforces_exact_local_work_even_with_spare_capacity() {
    // Validation uses three units; append needs four more under the SAME
    // producing execution. A one-less local ceiling cannot mutate the text.
    for local in [6, 7] {
        let account = memory(128, 4096);
        let mut bytes = account.vector();
        bytes.try_reserve_exact(128).unwrap();
        bytes.try_extend_from_slice(b"old").unwrap();
        let pointer = bytes.as_ptr();
        let retained;
        {
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
            let result = text.try_push_str("🦀");
            if local == 6 {
                assert_eq!(result, Err(MemoryError::WorkExceeded));
                assert_eq!(text.as_str(), "old");
            } else {
                result.unwrap();
                assert_eq!(text.as_str(), "old🦀");
            }
            let before = account.work_used();
            retained = text.into_owned();
            assert_eq!(account.work_used(), before);
        }
        assert_eq!(retained.as_bytes().as_ptr(), pointer);
        assert_eq!(retained.capacity(), 128);
        assert_eq!(account.used(), 128);
        drop(retained);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn append_enforces_aggregate_work_and_empty_append_needs_none() {
    // Aggregate refusal must preserve valid Unicode and capacity just like
    // local refusal; an empty suffix does no work even after total exhaustion.
    for remaining in [3, 4] {
        let account = memory(128, 4096);
        let mut bytes = account.vector();
        bytes.try_reserve_exact(128).unwrap();
        bytes.try_extend_from_slice("é".as_bytes()).unwrap();
        let mut text = OwnedText::from_utf8(bytes).unwrap();
        let pointer = text.as_bytes().as_ptr();
        account
            .charge_work((account.work_remaining() - remaining) as u64)
            .unwrap();
        let result = text.try_push_str("🦀");
        if remaining == 3 {
            assert_eq!(result, Err(MemoryError::WorkExceeded));
            assert_eq!(text.as_str(), "é");
        } else {
            result.unwrap();
            assert_eq!(text.as_str(), "é🦀");
        }
        account
            .charge_work(account.work_remaining() as u64)
            .unwrap();
        let spent = account.work_used();
        text.try_push_str("").unwrap();
        assert_eq!(account.work_used(), spent);
        assert_eq!(text.as_bytes().as_ptr(), pointer);
        assert_eq!(account.used(), 128);
        drop(text);
        assert_eq!(account.used(), 0);
    }
    let account = memory(0, 0);
    let mut text = OwnedText::from_utf8(account.vector()).unwrap();
    text.try_push_str("").unwrap();
    assert_eq!(text.capacity(), 0);
}

#[test]
fn growth_refusal_preserves_original_text_and_live_capacity() {
    // Growth pays the peak where both allocations coexist. Derive the actual
    // vector growth size, then test one-less and exact capacity admission.
    let probe = memory(1024, 4096);
    let mut text = OwnedText::try_from_str("old", &probe).unwrap();
    let original_capacity = text.capacity();
    text.try_push_str("🦀").unwrap();
    let grown_capacity = text.capacity();
    assert!(grown_capacity > original_capacity);
    drop(text);
    assert_eq!(probe.used(), 0);
    let peak = original_capacity + grown_capacity;
    for capacity in [peak - 1, peak] {
        let account = memory(capacity, 4096);
        let mut text = OwnedText::try_from_str("old", &account).unwrap();
        let pointer = text.as_bytes().as_ptr();
        let result = text.try_push_str("🦀");
        if capacity == peak - 1 {
            assert_eq!(result, Err(MemoryError::LimitExceeded));
            assert_eq!(text.as_str(), "old");
            assert_eq!(text.as_bytes().as_ptr(), pointer);
            assert_eq!(text.capacity(), original_capacity);
            assert_eq!(account.used(), original_capacity);
        } else {
            result.unwrap();
            assert_eq!(text.as_str(), "old🦀");
            assert_eq!(account.used(), grown_capacity);
        }
        drop(text);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn growth_work_refusal_does_not_clear_text_or_refund_consumed_work() {
    // Copy admission can succeed before growth admission fails. The existing
    // owner stays intact; already consumed work is not refunded on failure.
    let account = memory(1024, 4096);
    let mut text = OwnedText::try_from_str("old", &account).unwrap();
    let pointer = text.as_bytes().as_ptr();
    let capacity = text.capacity();
    account
        .charge_work((account.work_remaining() - 4) as u64)
        .unwrap();
    let before = account.work_used();
    assert_eq!(text.try_push_str("🦀"), Err(MemoryError::WorkExceeded));
    assert_eq!(account.work_used() - before, 4);
    assert_eq!(text.as_str(), "old");
    assert_eq!(text.as_bytes().as_ptr(), pointer);
    assert_eq!(text.capacity(), capacity);
    assert_eq!(account.used(), capacity);
    drop(text);
    assert_eq!(account.used(), 0);
}
