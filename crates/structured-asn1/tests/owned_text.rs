//! Public immutable UTF-8 storage and scoped ownership boundary checks.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, MemoryError, OwnedText, TextErrorKind, Work},
};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

#[test]
fn owned_text_transfers_existing_buffer_without_copy_or_capacity_change() {
    // Immutable text must retain the exact allocation, including spare capacity,
    // after its producing parser and work wrapper have gone away.
    let account = memory(1024, 4096);
    let retained;
    let pointer;
    let capacity;
    {
        let parser = Parser::ber(account.clone());
        let reader = parser.read(&[], 0).unwrap();
        let mut bytes = reader.execution().vector();
        bytes.try_reserve_exact(128).unwrap();
        bytes.try_extend_from_slice("Дія 🦀".as_bytes()).unwrap();
        pointer = bytes.as_ptr();
        capacity = bytes.capacity();
        let before = account.work_used();
        let text = OwnedText::from_utf8(bytes).unwrap();
        assert_eq!(account.work_used() - before, "Дія 🦀".len());
        assert_eq!(text.as_bytes().as_ptr(), pointer);
        retained = text.into_owned();
        assert_eq!(account.work_used() - before, "Дія 🦀".len());
    }
    assert_eq!(retained.as_bytes(), "Дія 🦀".as_bytes());
    assert_eq!(retained.as_str(), "Дія 🦀");
    assert_eq!(retained.capacity(), capacity);
    assert_eq!(account.used(), capacity);
    let bytes = retained.into_bytes();
    assert_eq!(bytes.as_ptr(), pointer);
    assert_eq!(bytes.capacity(), capacity);
    drop(bytes);
    assert_eq!(account.used(), 0);
}

#[test]
fn owned_text_utf8_and_resource_errors_return_original_storage() {
    // Resource refusal takes precedence over inspecting invalid bytes. Both
    // error classes retain the complete source buffer and its capacity charge.
    for local in [0, 2] {
        let account = memory(1024, 4096);
        let mut bytes = account.vector();
        bytes.try_extend_from_slice(&[0xf0, 0x80]).unwrap();
        let pointer = bytes.as_ptr();
        let capacity = bytes.capacity();
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
        let error = OwnedText::from_utf8(bytes).unwrap_err();
        match error.kind() {
            TextErrorKind::Resource(cause) => {
                assert_eq!(local, 0);
                assert_eq!(cause, MemoryError::WorkExceeded);
            }
            TextErrorKind::Utf8(cause) => {
                assert_eq!(local, 2);
                assert_eq!(cause.valid_up_to(), 0);
                assert_eq!(cause.error_len(), Some(1));
            }
        }
        assert_eq!(account.used(), capacity);
        let bytes = error.into_bytes();
        assert_eq!(bytes.as_ptr(), pointer);
        assert_eq!(&*bytes, &[0xf0, 0x80]);
        assert_eq!(bytes.capacity(), capacity);
        drop(bytes);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn owned_text_can_move_to_another_thread_without_shared_string_counts() {
    // Independently retained immutable storage must preserve Send + Sync from
    // its existing vector/account; no refcount implementation is needed.
    fn send_sync<T: Send + Sync>() {}
    send_sync::<OwnedText>();
    let account = memory(1024, 4096);
    let text = OwnedText::try_from_str("thread 🦀", &account).unwrap();
    let pointer = text.as_bytes().as_ptr() as usize;
    let text = std::thread::spawn(move || {
        assert_eq!(text.as_bytes(), "thread 🦀".as_bytes());
        assert_eq!(text.as_bytes().as_ptr() as usize, pointer);
        text
    })
    .join()
    .unwrap();
    assert_eq!(account.used(), text.capacity());
    drop(text);
    assert_eq!(account.used(), 0);
}

#[test]
fn owned_text_validation_obeys_aggregate_work_and_zero_length_boundaries() {
    // A stored buffer cannot buy validation from a different generous account;
    // empty text, however, needs no scan and keeps any preallocated capacity.
    let account = memory(1024, 64);
    let mut bytes = account.vector();
    bytes.try_extend_from_slice(b"abc").unwrap();
    let pointer = bytes.as_ptr();
    account
        .charge_work(account.work_remaining() as u64)
        .unwrap();
    let error = OwnedText::from_utf8(bytes).unwrap_err();
    assert_eq!(
        error.kind(),
        TextErrorKind::Resource(MemoryError::WorkExceeded)
    );
    let mut bytes = error.into_bytes();
    assert_eq!(bytes.as_ptr(), pointer);
    bytes.clear();
    let text = OwnedText::from_utf8(bytes).unwrap();
    assert!(text.is_empty());
    assert_eq!(text.len(), 0);
    assert_eq!(text.as_bytes().as_ptr(), pointer);
    assert_eq!(account.used(), text.capacity());
    drop(text);
    assert_eq!(account.used(), 0);
    let empty = memory(0, 0);
    let text = OwnedText::from_utf8(empty.vector()).unwrap();
    assert_eq!(text.capacity(), 0);
    assert_eq!(empty.used(), 0);
}

#[test]
fn owned_text_distinguishes_truncated_and_invalid_unicode_without_normalizing() {
    // UTF-8 diagnostics preserve the standard byte position and incomplete-tail
    // distinction; retained valid text must not be normalized or truncated.
    for (input, start, width) in [
        (&b"ok\xff"[..], 2, Some(1)),
        (&b"ok\xf0\x9f"[..], 2, None),
        (&b"\xed\xa0\x80"[..], 0, Some(1)),
    ] {
        let account = memory(1024, 4096);
        let mut bytes = account.vector();
        bytes.try_extend_from_slice(input).unwrap();
        let error = OwnedText::from_utf8(bytes).unwrap_err();
        let TextErrorKind::Utf8(cause) = error.kind() else {
            panic!("expected UTF-8 failure")
        };
        assert_eq!(cause.valid_up_to(), start);
        assert_eq!(cause.error_len(), width);
        assert_eq!(&*error.into_bytes(), input);
        assert_eq!(account.used(), 0);
    }
    for input in ["", "\0", "é", "e\u{301}", "🦀", "\u{10ffff}"] {
        let account = memory(1024, 4096);
        let text = OwnedText::try_from_str(input, &account).unwrap();
        assert_eq!(text.as_bytes(), input.as_bytes());
        let bytes = text.into_bytes();
        let text = OwnedText::from_utf8(bytes).unwrap();
        assert_eq!(text.as_bytes(), input.as_bytes());
        assert_eq!(text.as_str(), input);
        drop(text);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn owned_text_views_need_no_new_work_and_cannot_mutate_validated_storage() {
    // The immutable owner validates once; a spent construction budget cannot
    // require another scan or prevent O(1) views of unchanged valid bytes.
    let account = memory(1024, 4096);
    let text = OwnedText::try_from_str("immutable 🦀", &account).unwrap();
    account
        .charge_work(account.work_remaining() as u64)
        .unwrap();
    let spent = account.work_used();
    for _ in 0..16 {
        assert_eq!(text.as_str(), "immutable 🦀");
        assert_eq!(std::borrow::Borrow::<str>::borrow(&text), text.as_str());
        assert_eq!(AsRef::<str>::as_ref(&text), text.as_str());
        assert_eq!(&*text, text.as_str());
    }
    assert_eq!(account.work_used(), spent);
    let mut bytes = text.into_bytes();
    bytes[0] = 0xff;
    let error = OwnedText::from_utf8(bytes).unwrap_err();
    assert_eq!(
        error.kind(),
        TextErrorKind::Resource(MemoryError::WorkExceeded)
    );
    drop(error);
    assert_eq!(account.used(), 0);
}

#[test]
fn owned_text_valid_string_copy_uses_exact_storage_and_original_scoped_work() {
    // The already-valid str path needs only its existing copy/allocation costs,
    // and must refuse before allocating when either original ceiling is short.
    for (capacity, work, expected) in [
        (2, 6, Some(MemoryError::LimitExceeded)),
        (3, 5, Some(MemoryError::WorkExceeded)),
        (3, 6, None),
    ] {
        let account = memory(capacity, work);
        let result = OwnedText::try_from_str("abc", &account);
        if let Some(cause) = expected {
            assert_eq!(result.unwrap_err(), cause);
            assert_eq!(account.used(), 0);
        } else {
            let text = result.unwrap();
            assert_eq!(text.as_str(), "abc");
            assert_eq!(text.capacity(), 3);
            assert_eq!(account.work_used(), 6);
            drop(text);
            assert_eq!(account.used(), 0);
        }
    }
    let account = memory(1024, 4096);
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 5,
            ..Limits::default()
        },
        account.clone(),
    );
    let reader = parser.read(&[], 0).unwrap();
    assert_eq!(
        OwnedText::try_from_str("abc", &reader.execution()).unwrap_err(),
        MemoryError::WorkExceeded,
    );
    assert_eq!(account.used(), 0);
}

#[test]
fn owned_text_hash_borrow_and_format_keep_standard_string_identity() {
    // Owned text keys must hash exactly like borrowed str, including Unicode;
    // lookup must charge the current query without a new owned query string.
    use std::hash::BuildHasher;
    use structured_asn1::memory::HashWork;
    let account = memory(4096, 100_000);
    let left = OwnedText::try_from_str("Straße 🦀", &account).unwrap();
    let right = OwnedText::try_from_str("Straße 🦀", &account).unwrap();
    assert_eq!(left, right);
    assert_eq!(format!("{left}"), "Straße 🦀");
    assert_eq!(format!("{left:?}"), "\"Straße 🦀\"");
    assert_eq!(left.hash_work().unwrap(), left.len() as u64 + 1);
    let builder = std::collections::hash_map::RandomState::new();
    assert_eq!(builder.hash_one(&left), builder.hash_one(left.as_str()));
    let mut map = account.map();
    map.try_insert(left, ()).unwrap();
    let query = memory(0, 4096);
    let (stored, ()) = map
        .get_key_value_borrowed("Straße 🦀", &query)
        .unwrap()
        .unwrap();
    assert_eq!(stored.as_str(), "Straße 🦀");
    assert_eq!(query.used(), 0);
    assert!(query.work_used() > 0);
    assert_eq!(
        map.get_key_value_borrowed("Straße 🦀", &memory(0, 0))
            .unwrap_err(),
        MemoryError::WorkExceeded,
    );
    drop(map);
    drop(right);
    assert_eq!(account.used(), 0);
}
