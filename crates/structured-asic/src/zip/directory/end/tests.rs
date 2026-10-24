use super::*;
use alloc::sync::Arc;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use structured_asn1::{
    memory::{Memory, MemoryAccount},
    range::Slice,
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
fn zip64_record_must_fit_before_its_locator_before_any_record_read() {
    // The locator cannot point into itself or its following classic EOCD.
    // Reject its enclosure before the fixed-record copy or source callbacks.
    let mut bytes = [0_u8; 64];
    bytes[..4].copy_from_slice(&0x0606_4b50_u32.to_le_bytes());
    bytes[4..12].copy_from_slice(&44_u64.to_le_bytes());
    let source = Slice::new(
        &bytes,
        Snapshot {
            document: 1,
            generation: 1,
        },
    );
    let work = Memory::new(Arc::new(MemoryAccount::new(4096, 100_000)));
    let session = crate::Session::new(crate::Limits::default(), work.clone());
    let mut cursor = Cursor {
        window: Window::new(
            &source,
            source.stamp(),
            Span {
                start: 0,
                length: 64,
            },
            session.execution(),
        )
        .unwrap(),
        at: 12,
        end: 64,
    };
    let mut locator = [0_u8; 20];
    locator[16..].copy_from_slice(&1_u32.to_le_bytes());
    let mut classic = [0_u8; 22];
    classic[8..12].copy_from_slice(&[255; 4]);
    let before = work.work_used();
    let error = finish(zip64(
        &mut cursor,
        &locator,
        &classic,
        20,
        Span {
            start: 64,
            length: 0,
        },
    ));
    assert!(matches!(
        error,
        Err(Error::Syntax {
            range: Span {
                start: 0,
                length: 56
            },
            kind: Syntax::Bounds,
        })
    ));
    assert_eq!(cursor.at, 12);
    assert_eq!(work.work_used(), before);
}
