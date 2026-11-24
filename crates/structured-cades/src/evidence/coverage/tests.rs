use super::{merge_spans, normalize};
use alloc::sync::Arc;
use structured_asn1::{
    Span,
    memory::{Memory, MemoryAccount, MemoryError},
};

#[test]
fn ordered_disjoint_coverage_needs_only_linear_work() {
    // Ordered spans need only the order check and the compaction walk.
    let work = Memory::new(Arc::new(MemoryAccount::new(4096, 1024)));
    let original = core::array::from_fn::<_, 16, _>(|index| Span {
        start: index as u64 * 16,
        length: 8,
    });
    let mut spans = work.vector();
    spans.try_extend_from_slice(&original).unwrap();
    let linear = 4 * original.len() - 1;
    work.charge_work((work.work_remaining() - linear) as u64)
        .unwrap();
    normalize(&mut spans, &work).unwrap();
    assert_eq!(&*spans, &original);
}

#[test]
fn coverage_union_is_independent_of_equal_start_order() {
    // A longer span arriving later at the same start extends the union.
    // The permuted form also exercises the sort fallback.
    let work = Memory::new(Arc::new(MemoryAccount::new(4096, 10_000)));
    let span = |start, length| Span { start, length };
    for input in [
        [span(1, 2), span(1, 6), span(7, 1), span(9, 2)],
        [span(9, 2), span(1, 2), span(7, 1), span(1, 6)],
    ] {
        let mut spans = work.vector();
        spans.try_extend_from_slice(&input).unwrap();
        normalize(&mut spans, &work).unwrap();
        assert_eq!(&*spans, &[span(1, 7), span(9, 2)]);
    }
}

#[test]
fn renewal_merge_preserves_normalized_coverage() {
    // Additions can bridge, overlap or precede the existing ranges.
    // Compare with normalizing the full input as the original path did.
    let work = Memory::new(Arc::new(MemoryAccount::new(4096, 100_000)));
    let span = |start, length| Span { start, length };
    let base = [span(5, 3), span(11, 2), span(20, 2), span(29, 5)];
    for extra in [
        &[span(0, 5)][..],
        &[span(8, 3), span(11, 17), span(28, 1)],
        &[span(5, 1), span(13, 0), span(40, 2)],
    ] {
        let mut reference = work.vector();
        reference.try_extend_from_slice(&base).unwrap();
        reference.try_extend_from_slice(extra).unwrap();
        normalize(&mut reference, &work).unwrap();
        assert_eq!(
            &*merge_spans(&base, extra.iter().copied(), &work).unwrap(),
            &*reference
        );
    }
}

#[test]
fn covered_renewals_do_not_need_a_scratch_catalogue() {
    // Already covered predecessors need just the output span. A refusal must
    // prevent visiting the next original, even when no output would change.
    let covering = [Span {
        start: 0,
        length: 64,
    }];
    let starts = 0..64_u32;
    let work = Memory::new(Arc::new(MemoryAccount::new(64, 300)));
    let spans = starts.clone().map(|start| Span {
        start: u64::from(start),
        length: 1,
    });
    let merged = merge_spans(&covering, spans, &work).unwrap();
    assert_eq!(&*merged, &covering);

    let visits = core::cell::Cell::new(0);
    let work = Memory::new(Arc::new(MemoryAccount::new(64, 2)));
    let spans = starts.map(|start| {
        visits.set(visits.get() + 1);
        Span {
            start: u64::from(start),
            length: 1,
        }
    });
    assert!(matches!(
        merge_spans(&covering, spans, &work),
        Err(MemoryError::WorkExceeded)
    ));
    assert_eq!(visits.get(), 0);
}
