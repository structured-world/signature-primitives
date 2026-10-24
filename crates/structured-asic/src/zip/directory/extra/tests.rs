use super::*;
use alloc::sync::Arc;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use structured_asn1::{
    memory::{Memory, MemoryAccount},
    range::{RangeSource, Slice, Window},
    source::Snapshot,
};

fn finish<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("the original slice never suspends"),
    }
}

#[test]
fn local_zip64_requires_both_header_sentinels() {
    // APPNOTE §4.5.3 requires both local sizes and permits fields only for
    // corresponding sentinels. Matching ordinary sizes do not waive that rule.
    for (decoded, compressed) in [
        (1, u32::MAX),
        (u32::MAX, 1),
        (1, 1),
        (2, u32::MAX),
        (u32::MAX, 2),
        (2, 2),
    ] {
        let mut bytes = [0_u8; 20];
        bytes[..4].copy_from_slice(&[1, 0, 16, 0]);
        bytes[4..12].copy_from_slice(&2_u64.to_le_bytes());
        bytes[12..].copy_from_slice(&2_u64.to_le_bytes());
        let source = Slice::new(
            &bytes,
            Snapshot {
                document: 1,
                generation: 1,
            },
        );
        let session = crate::Session::new(
            crate::Limits::default(),
            Memory::new(Arc::new(MemoryAccount::new(4096, 100_000))),
        );
        let span = Span {
            start: 0,
            length: 20,
        };
        let mut cursor = Cursor {
            window: Window::new(&source, source.stamp(), span, session.execution()).unwrap(),
            at: 0,
            end: 20,
        };
        assert!(matches!(
            finish(local(&mut cursor, span, decoded, compressed)),
            Err(Error::Syntax {
                kind: Syntax::Local,
                ..
            })
        ));
    }
}

#[test]
fn local_zip64_retains_both_declared_sizes() {
    // Local ZIP64 includes both sizes in fixed order; unequal values prevent
    // a guessed compressed/decoded order from passing this positive case.
    {
        let (decoded, compressed) = (u32::MAX, u32::MAX);
        let mut bytes = [0_u8; 20];
        bytes[..4].copy_from_slice(&[1, 0, 16, 0]);
        bytes[4..12].copy_from_slice(&2_u64.to_le_bytes());
        bytes[12..].copy_from_slice(&3_u64.to_le_bytes());
        let source = Slice::new(
            &bytes,
            Snapshot {
                document: 1,
                generation: 1,
            },
        );
        let session = crate::Session::new(
            crate::Limits::default(),
            Memory::new(Arc::new(MemoryAccount::new(4096, 100_000))),
        );
        let span = Span {
            start: 0,
            length: 20,
        };
        let mut cursor = Cursor {
            window: Window::new(&source, source.stamp(), span, session.execution()).unwrap(),
            at: 0,
            end: 20,
        };
        let read = finish(local(&mut cursor, span, decoded, compressed)).unwrap();
        assert_eq!((read.decoded, read.compressed, read.zip64), (2, 3, true));
    }
}
