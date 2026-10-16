//! Whole-buffer drain preserves ordering, execution and reusable capacity.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, MemoryError},
};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

struct Payload {
    ordinal: usize,
    dropped: Arc<AtomicUsize>,
}

impl Drop for Payload {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn drain_moves_non_clone_values_in_order_and_reuses_capacity() {
    // XML attribute/error order must survive moves, without cloning payloads
    // or discarding the working buffer allocation between elements.
    let account = memory(4096, 4096);
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut values = account.vector();
    values.try_reserve_exact(8).unwrap();
    for ordinal in 0..3 {
        values
            .try_push(Payload {
                ordinal,
                dropped: dropped.clone(),
            })
            .unwrap();
    }
    let pointer = values.as_ptr();
    let capacity = values.capacity();
    let charged = account.used();
    let before = account.work_used();
    {
        let mut drain = values.try_drain_all().unwrap();
        assert_eq!(drain.len(), 3);
        assert_eq!(drain.size_hint(), (3, Some(3)));
        assert_eq!(drain.next().unwrap().ordinal, 0);
        assert_eq!(drain.next_back().unwrap().ordinal, 2);
        assert_eq!(drain.next().unwrap().ordinal, 1);
        assert!(drain.next().is_none());
        assert!(drain.next_back().is_none());
        assert!(drain.next().is_none());
    }
    assert_eq!(account.work_used() - before, 3 * size_of::<Payload>());
    assert_eq!(dropped.load(Ordering::Relaxed), 3);
    assert!(values.is_empty());
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(values.capacity(), capacity);
    assert_eq!(account.used(), charged);
    values
        .try_push(Payload {
            ordinal: 3,
            dropped: dropped.clone(),
        })
        .unwrap();
    assert_eq!(values.as_ptr(), pointer);
    drop(values);
    assert_eq!(dropped.load(Ordering::Relaxed), 4);
    assert_eq!(account.used(), 0);
}

#[test]
fn drain_local_admission_precedes_length_and_element_changes() {
    // A generous aggregate account cannot bypass the original local ceiling.
    // Movement of three u64 values requires 24 units before taking any value.
    for local in [23, 24] {
        let account = memory(128, 4096);
        let mut values = account.vector();
        values.try_extend_from_slice(&[10_u64, 20, 30]).unwrap();
        let pointer = values.as_ptr();
        let capacity = values.capacity();
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
            let mut values = values.with_execution(&reader.execution()).unwrap();
            {
                match values.try_drain_all() {
                    Err(cause) => {
                        assert_eq!(local, 23);
                        assert_eq!(cause, MemoryError::WorkExceeded);
                    }
                    Ok(drain) => {
                        assert_eq!(local, 24);
                        assert_eq!(drain.collect::<Vec<_>>(), [10, 20, 30]);
                    }
                }
            }
            assert_eq!(&*values, if local == 23 { &[10, 20, 30][..] } else { &[] });
            retained = values.into_owned();
        }
        assert_eq!(retained.as_ptr(), pointer);
        assert_eq!(retained.capacity(), capacity);
        assert_eq!(account.used(), capacity * size_of::<u64>());
        drop(retained);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn drain_aggregate_refusal_leaves_source_untouched() {
    // Admission is atomic with respect to the source, including exact and
    // one-less aggregate boundaries when all capacity was already retained.
    for remaining in [23, 24] {
        let account = memory(128, 4096);
        let mut values = account.vector();
        values.try_extend_from_slice(&[10_u64, 20, 30]).unwrap();
        let pointer = values.as_ptr();
        let capacity = values.capacity();
        account
            .charge_work((account.work_remaining() - remaining) as u64)
            .unwrap();
        {
            match values.try_drain_all() {
                Err(cause) => {
                    assert_eq!(remaining, 23);
                    assert_eq!(cause, MemoryError::WorkExceeded);
                }
                Ok(drain) => {
                    assert_eq!(remaining, 24);
                    assert_eq!(drain.collect::<Vec<_>>(), [10, 20, 30]);
                }
            }
        }
        assert_eq!(
            &*values,
            if remaining == 23 {
                &[10, 20, 30][..]
            } else {
                &[]
            }
        );
        assert_eq!(values.as_ptr(), pointer);
        assert_eq!(values.capacity(), capacity);
        drop(values);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn partial_drain_drops_only_unconsumed_payloads_and_keeps_storage() {
    // Early parser failure drops the remaining buffer elements, while a moved
    // value retains its independent lifetime and the buffer keeps its capacity.
    let account = memory(4096, 4096);
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut values = account.vector();
    for ordinal in 0..4 {
        values
            .try_push(Payload {
                ordinal,
                dropped: dropped.clone(),
            })
            .unwrap();
    }
    let capacity = values.capacity();
    let first;
    {
        let mut drain = values.try_drain_all().unwrap();
        first = drain.next().unwrap();
        assert_eq!(first.ordinal, 0);
    }
    assert_eq!(dropped.load(Ordering::Relaxed), 3);
    assert!(values.is_empty());
    assert_eq!(account.used(), capacity * size_of::<Payload>());
    drop(values);
    assert_eq!(account.used(), 0);
    assert_eq!(dropped.load(Ordering::Relaxed), 3);
    drop(first);
    assert_eq!(dropped.load(Ordering::Relaxed), 4);
}

#[test]
fn empty_and_zero_sized_drains_obey_work_without_allocating() {
    static DROPPED: AtomicUsize = AtomicUsize::new(0);
    struct ZeroSized;
    impl Drop for ZeroSized {
        fn drop(&mut self) {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ZST movement still traverses elements; an empty drain does no work even
    // under zero allowances, and neither case may allocate storage.
    let account = memory(0, 8);
    let mut values = account.vector();
    for _ in 0..3 {
        values.try_push(()).unwrap();
    }
    let before = account.work_used();
    assert_eq!(values.try_drain_all().unwrap().count(), 3);
    assert_eq!(account.work_used() - before, 3);
    assert_eq!(account.used(), 0);
    account
        .charge_work(account.work_remaining() as u64)
        .unwrap();
    assert_eq!(values.try_drain_all().unwrap().count(), 0);
    let empty = memory(0, 0);
    let mut values = empty.vector::<u64>();
    assert_eq!(values.try_drain_all().unwrap().count(), 0);

    // The upstream ZST destructor path must also drop unconsumed values once.
    let account = memory(0, 8);
    let mut values = account.vector();
    for _ in 0..3 {
        values.try_push(ZeroSized).unwrap();
    }
    {
        let mut drain = values.try_drain_all().unwrap();
        drop(drain.next().unwrap());
    }
    assert_eq!(DROPPED.load(Ordering::Relaxed), 3);
    assert!(values.is_empty());
    assert_eq!(account.used(), 0);
}

#[test]
fn moved_owned_payload_retains_its_independent_storage_charge() {
    // Moving retained results out must not tie their lifetime to the buffer or
    // refund their own charge when the empty working buffer is later dropped.
    use structured_asn1::memory::OwnedText;
    let account = memory(4096, 4096);
    let text = OwnedText::try_from_str("retained 🦀", &account).unwrap();
    let pointer = text.as_bytes().as_ptr();
    let capacity = text.capacity();
    let mut values = account.vector();
    values.try_push(text).unwrap();
    let retained = values.try_drain_all().unwrap().next().unwrap();
    assert_eq!(retained.as_bytes().as_ptr(), pointer);
    assert!(values.is_empty());
    drop(values);
    assert_eq!(account.used(), capacity);
    assert_eq!(retained.as_str(), "retained 🦀");
    drop(retained);
    assert_eq!(account.used(), 0);
}

#[test]
fn forgotten_drain_keeps_capacity_charge_and_allows_reuse() {
    // Like the underlying vector, forgetting its drain may leak elements, but
    // must not refund or invalidate the independently owned backing allocation.
    let account = memory(128, 4096);
    let mut values = account.vector();
    values.try_extend_from_slice(&[1_u32, 2, 3]).unwrap();
    let pointer = values.as_ptr();
    let capacity = values.capacity();
    std::mem::forget(values.try_drain_all().unwrap());
    assert!(values.is_empty());
    assert_eq!(account.used(), capacity * size_of::<u32>());
    values.try_push(4).unwrap();
    assert_eq!(&*values, &[4]);
    assert_eq!(values.as_ptr(), pointer);
    drop(values);
    assert_eq!(account.used(), 0);
}

#[test]
fn panicking_element_drop_does_not_lose_buffer_charge_or_other_values() {
    // An element destructor may unwind. The upstream slice/drop guard must
    // still destroy the other values and leave the reusable vector empty.
    struct Panics {
        ordinal: usize,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Panics {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            assert_ne!(self.ordinal, 1, "synthetic element destructor panic");
        }
    }
    let account = memory(4096, 4096);
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut values = account.vector();
    for ordinal in 0..3 {
        values
            .try_push(Panics {
                ordinal,
                dropped: dropped.clone(),
            })
            .unwrap();
    }
    let pointer = values.as_ptr();
    let capacity = values.capacity();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(values.try_drain_all().unwrap());
    }));
    assert!(result.is_err());
    assert_eq!(dropped.load(Ordering::Relaxed), 3);
    assert!(values.is_empty());
    assert_eq!(values.as_ptr(), pointer);
    assert_eq!(account.used(), capacity * size_of::<Panics>());
    drop(values);
    assert_eq!(account.used(), 0);
}
