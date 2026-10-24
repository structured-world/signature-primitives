use super::*;
use alloc::sync::Arc;
use core::{
    future::Future,
    pin::pin,
    task::{Context as TaskContext, Poll, Waker},
};
use structured_asn1::memory::{MemoryAccount, MemoryError};
use structured_ltv::source::Snapshot;

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("resident input cannot suspend"),
    }
}

#[test]
fn only_original_field_mdp_data_has_an_indirect_reference_exception() {
    // Table253 permits the explicit catalog reference only in FieldMDP Data.
    // An identical spelling in another transform/nesting cannot bypass Table252.
    for (bytes, expected) in [
        (b"<< /Type /Sig /Reference [<< /TransformMethod /FieldMDP /Data 12 0 R /TransformParams << /Action /All >> >>] >>".as_slice(), 0),
        (b"<< /Type /Sig /Reference [<< /TransformMethod /DocMDP /Data 12 0 R >>] >>", 1),
        (b"<< /Type /Sig /Reference [<< /TransformMethod /FieldMDP /Data 12 0 R /TransformParams 13 0 R >>] >>", 1),
        (b"<< /Type /Sig /Other << /TransformMethod /FieldMDP /Data 12 0 R >> >>", 1),
        (b"<< /Type /Sig /ByteRange [0 12 0 R 0 1] >>", 1),
    ] {
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 22)));
        let session = crate::Session::new(crate::Limits::default(), memory);
        let work = session.execution();
        let source = crate::range::Slice::new(bytes, Snapshot { document: 1u8, generation: 0u8 });
        let value = ready(crate::syntax::read(&source, &session, &work, 0)).unwrap();
        let mut count = 0;
        visit(&value.arena, value.root, &work, |_| { count += 1; Ok::<_, ()>(()) })
            .unwrap_or_else(|_| panic!("valid original syntax and funded callback"));
        assert_eq!(count, expected);
    }
}

#[test]
fn directness_walk_preserves_callback_and_pre_admission_refusal() {
    // Current-work refusal precedes callbacks, while callback errors retain
    // their exact cause instead of turning into another malformed finding.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 22)));
    let session = crate::Session::new(crate::Limits::default(), memory);
    let work = session.execution();
    let source = crate::range::Slice::new(
        b"<< /Type /Sig /Reference 12 0 R >>",
        Snapshot {
            document: 1u8,
            generation: 0u8,
        },
    );
    let value = ready(crate::syntax::read(&source, &session, &work, 0)).unwrap();
    let denied = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 0)));
    let mut called = false;
    let result = visit(&value.arena, value.root, &denied, |_| {
        called = true;
        Ok::<_, ()>(())
    });
    assert!(matches!(
        result,
        Err(VisitError::Processing(Error {
            kind: ErrorKind::Resource(MemoryError::WorkExceeded),
            ..
        }))
    ));
    assert!(!called);
    assert!(matches!(
        visit(&value.arena, value.root, &work, |_| Err(17u8)),
        Err(VisitError::Callback(17))
    ));
}
