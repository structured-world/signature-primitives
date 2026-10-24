use super::*;
use crate::range::{RangeReader, Slice};
use alloc::sync::Arc;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use structured_asn1::memory::MemoryAccount;
use structured_ltv::source::Snapshot;

fn complete<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("resident fixture unexpectedly suspended"),
    }
}

#[test]
fn shared_owner_preserves_old_nodes_across_two_complete_value_parses() {
    // A document/object-stream owner must append nodes without cloning or
    // renumbering previous references, and release all storage on drop.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)));
    let session = Session::new(crate::Limits::default(), memory.clone());
    let raw = b"[1 << /A (one) >>] << /B <74776F> >>";
    let source = Slice::new(
        raw,
        Snapshot {
            document: 1_u8,
            generation: 0_u8,
        },
    );
    let reader = RangeReader::new(&source, &session, &memory).unwrap();
    let mut cursor = Cursor { reader, at: 0 };
    let arena = Arena::new(&memory);
    let (arena, first) = complete(read_into(&mut cursor, &session, arena)).unwrap();
    let original = arena.nodes[first.0].location;
    let first_count = arena.nodes.len();
    let (arena, second) = complete(read_into(&mut cursor, &session, arena)).unwrap();
    assert_eq!(second.0, first_count);
    assert_eq!(arena.nodes[first.0].location, original);
    assert!(matches!(arena.nodes[first.0].kind, Kind::Array(_)));
    assert!(matches!(arena.nodes[second.0].kind, Kind::Dictionary(_, _)));
    assert_eq!(arena.fields.len(), 2);
    assert_eq!(cursor.at, raw.len() as u64);
    drop(arena);
    drop(cursor);
    assert_eq!(memory.used(), 0);
}

#[test]
fn decoded_values_keep_logical_offsets_and_actual_physical_enclosure() {
    // Decoding does not place logical objects at invented physical file
    // offsets. Both valid values and syntax failures carry the same
    // original encoded enclosure and historical decoding context.
    let domain = crate::source::Source::Decoded {
        stream: structured_asn1::Span {
            start: 9000,
            length: 42,
        },
        revision: 3,
        stage: 0,
    };
    for (raw, valid) in [
        (b"<< /A (a) /A <61> >>".as_slice(), true),
        (b"<< /A [1 >>", false),
    ] {
        let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 1_000_000)));
        let session = Session::new(crate::Limits::default(), memory.clone());
        let source = Slice::new(
            raw,
            Snapshot {
                document: 1_u8,
                generation: 0_u8,
            },
        );
        let reader = RangeReader::in_source(&source, &session, &memory, domain).unwrap();
        let mut cursor = Cursor { reader, at: 0 };
        match complete(read_into(&mut cursor, &session, Arena::new(&memory))) {
            Ok((arena, root)) => {
                assert!(valid);
                assert_eq!(arena.nodes[root.0].location.source(), domain);
                assert_eq!(arena.nodes[root.0].location.span().start, 0);
                assert_eq!(arena.nodes[root.0].location.enclosing().start, 9000);
                assert_eq!(arena.faults.len(), 1);
                assert_eq!(arena.faults[0].location.source(), domain);
            }
            Err(ReadFailure::Format(error)) => {
                assert!(!valid);
                assert_eq!(error.location.source(), domain);
                assert!(error.location.span().start < raw.len() as u64);
                assert_eq!(error.location.enclosing().start, 9000);
            }
            Err(error) => panic!("unexpected source failure: {error:?}"),
        }
        drop(cursor);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn member_boundary_is_enforced_before_acquiring_the_following_member() {
    // Parsing a bounded object-stream member cannot scan or allocate from
    // its following member. The enclosing snapshot stays the whole source.
    use crate::range::{RangeSource, ReadError, Stamp};
    use core::cell::Cell;
    struct Bounded(Cell<usize>);
    impl RangeSource for Bounded {
        type Document = u8;
        type Generation = u8;
        type Error = ();
        fn stamp(&self) -> Stamp<u8, u8> {
            Stamp {
                snapshot: Snapshot {
                    document: 1,
                    generation: 0,
                },
                length: 15,
            }
        }
        fn read_at<'q, W: Work + 'q>(
            &'q self,
            offset: u64,
            output: &'q mut [u8],
            _: &'q W,
        ) -> impl Future<Output = Result<usize, ReadError<()>>> + 'q {
            assert_eq!(offset, 5);
            assert_eq!(output.len(), 4);
            self.0.set(self.0.get() + 1);
            output.copy_from_slice(b"true");
            core::future::ready(Ok(4))
        }
    }
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 1_000_000)));
    let session = Session::new(crate::Limits::default(), memory.clone());
    let source = Bounded(Cell::new(0));
    let reader = RangeReader::in_region(
        &source,
        &session,
        &memory,
        crate::source::Source::File,
        structured_asn1::Span {
            start: 5,
            length: 4,
        },
    )
    .unwrap();
    let mut cursor = Cursor { reader, at: 5 };
    let (arena, root) = complete(read_into(&mut cursor, &session, Arena::new(&memory))).unwrap();
    assert!(matches!(arena.nodes[root.0].kind, Kind::Boolean(true)));
    assert_eq!(cursor.at, 9);
    assert_eq!(source.0.get(), 1);
    assert_eq!(cursor.reader.stamp().length, 15);
    drop(arena);
    drop(cursor);
    assert_eq!(memory.used(), 0);
}
