//! Suspended, bounded original-range access without whole-file materialization.

use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Parser};
use structured_ltv::source::Snapshot;
use structured_pades::bytes::Form;
use structured_pades::error::{ErrorKind, ReadFailure, Syntax};
use structured_pades::range::{InputError, RangeReader, RangeSource, ReadError, Slice, Stamp};
use structured_pades::{Limits, Session};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

fn complete<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..10 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
    panic!("test future failed to complete after its explicit wake");
}

struct Sparse {
    generation: Cell<u32>,
    calls: Cell<usize>,
    maximum: Cell<usize>,
    changed: bool,
    refusal: bool,
    short: bool,
}

impl Sparse {
    fn new() -> Self {
        Self {
            generation: Cell::new(0),
            calls: Cell::new(0),
            maximum: Cell::new(0),
            changed: false,
            refusal: false,
            short: false,
        }
    }
}

impl RangeSource for Sparse {
    type Document = u32;
    type Generation = u32;
    type Error = &'static str;

    fn stamp(&self) -> Stamp<u32, u32> {
        Stamp {
            snapshot: Snapshot {
                document: 17,
                generation: self.generation.get(),
            },
            length: 9 * 1024 * 1024 * 1024,
        }
    }

    async fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        _work: &'q W,
    ) -> Result<usize, ReadError<Self::Error>> {
        self.calls.set(self.calls.get() + 1);
        self.maximum.set(self.maximum.get().max(output.len()));
        let mut suspended = false;
        core::future::poll_fn(|context| {
            if suspended {
                Poll::Ready(())
            } else {
                suspended = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        if self.refusal {
            return Err(ReadError::Resource(MemoryError::WorkExceeded));
        }
        if self.changed {
            self.generation.set(self.generation.get() + 1);
        }
        let length = if self.short { 1 } else { output.len() };
        for (index, byte) in output[..length].iter_mut().enumerate() {
            *byte = u8::try_from((offset + index as u64) % 251).unwrap();
        }
        Ok(length)
    }
}

#[test]
fn sparse_multigigabyte_source_uses_only_bounded_original_windows() {
    // A wasm32-compatible u64 offset must not become a whole-file allocation,
    // truncated usize offset or a requirement for synchronous browser I/O.
    let account = memory(8192, 100_000);
    let session = Session::new(Limits::default(), account.clone());
    let source = Sparse::new();
    let work = session.execution();
    let mut reader = RangeReader::new(&source, &session, &work).unwrap();
    assert_eq!(complete(reader.byte_at(1)).unwrap(), Some(1));
    assert_eq!(complete(reader.byte_at(2)).unwrap(), Some(2));
    let late = 8 * 1024 * 1024 * 1024 + 77;
    assert_eq!(
        complete(reader.byte_at(late)).unwrap(),
        Some(u8::try_from(late % 251).unwrap())
    );
    assert_eq!(source.calls.get(), 2);
    assert_eq!(source.maximum.get(), 4096);
    assert_eq!(
        complete(reader.byte_at(source.stamp().length)).unwrap(),
        None
    );
    assert_eq!(source.calls.get(), 2);
    assert_eq!(account.used(), 4096);
    drop(reader);
    assert_eq!(account.used(), 0);
}

#[test]
fn snapshot_change_during_await_never_returns_a_read_prefix() {
    // Source generation can change while acquisition is suspended. Returned
    // bytes then cannot establish PDF facts, even if their spelling is valid.
    let account = memory(8192, 100_000);
    let session = Session::new(Limits::default(), account.clone());
    let source = Sparse {
        changed: true,
        ..Sparse::new()
    };
    let work = session.execution();
    let mut reader = RangeReader::new(&source, &session, &work).unwrap();
    match complete(reader.byte_at(42)).unwrap_err() {
        InputError::Changed { location } => assert_eq!(
            location.span(),
            structured_asn1::Span {
                start: 0,
                length: 4096
            }
        ),
        other => panic!("wrong cause: {other:?}"),
    }
    drop(reader);
    assert_eq!(account.used(), 0);
}

#[test]
fn current_work_and_capacity_refuse_before_acquisition() {
    // An independently retained source cannot bypass either the current
    // query ceiling or actual scratch admission; no I/O starts on refusal.
    let account = memory(8192, 100_000);
    let session = Session::new(Limits::default(), account.clone());
    let operation = Parser::new(
        Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..Default::default()
        },
        account.clone(),
    );
    let current = operation.read(&[], 0).unwrap();
    let source = Sparse::new();
    assert!(matches!(
        RangeReader::new(&source, &session, &current.execution())
            .err()
            .unwrap(),
        InputError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        }
    ));
    assert_eq!(source.calls.get(), 0);
    assert_eq!(account.used(), 0);
    let tiny = memory(4095, 100_000);
    let session = Session::new(Limits::default(), tiny.clone());
    assert!(matches!(
        RangeReader::new(&source, &session, &session.execution())
            .err()
            .unwrap(),
        InputError::Resource {
            cause: MemoryError::LimitExceeded,
            ..
        }
    ));
    assert_eq!(tiny.used(), 0);
    assert_eq!(source.calls.get(), 0);
}

#[test]
fn callback_resource_and_short_reads_keep_their_original_classes() {
    // Short reads are legal, whereas typed acquisition refusal must neither
    // become EOF nor allow a successful partial value.
    let account = memory(8192, 100_000);
    let session = Session::new(Limits::default(), account.clone());
    let work = session.execution();
    let refused = Sparse {
        refusal: true,
        ..Sparse::new()
    };
    let mut reader = RangeReader::new(&refused, &session, &work).unwrap();
    assert!(matches!(
        complete(reader.byte_at(7)).unwrap_err(),
        InputError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        }
    ));
    drop(reader);
    let short = Sparse {
        short: true,
        ..Sparse::new()
    };
    let mut reader = RangeReader::new(&short, &session, &work).unwrap();
    for offset in 0..5 {
        assert_eq!(
            complete(reader.byte_at(offset)).unwrap(),
            Some(u8::try_from(offset).unwrap())
        );
    }
    assert_eq!(short.calls.get(), 5);
    drop(reader);
    assert_eq!(account.used(), 0);
}

#[test]
fn cancelling_a_suspended_read_releases_scratch_without_replaying_io() {
    // Cancellation must not leak a future-held buffer or retain an uncharged
    // source cache. No background reader survives the owning future.
    let account = memory(8192, 100_000);
    let session = Session::new(Limits::default(), account.clone());
    let source = Sparse::new();
    let work = session.execution();
    let mut reader = RangeReader::new(&source, &session, &work).unwrap();
    {
        let mut pending = pin!(reader.byte_at(9));
        let mut context = Context::from_waker(Waker::noop());
        assert!(pending.as_mut().poll(&mut context).is_pending());
    }
    assert_eq!(source.calls.get(), 1);
    drop(reader);
    assert_eq!(source.calls.get(), 1);
    assert_eq!(account.used(), 0);
}

#[test]
fn resident_slice_convenience_has_the_same_eof_and_generation_contract() {
    // The slice adapter is an optional source implementation, not a separate
    // grammar or an input shape required by the generic reader.
    let account = memory(8192, 100_000);
    let session = Session::new(Limits::default(), account.clone());
    let work = session.execution();
    let slice = Slice::new(
        b"%PDF-1.7",
        Snapshot {
            document: 4_u32,
            generation: 2_u32,
        },
    );
    let mut reader = RangeReader::new(&slice, &session, &work).unwrap();
    for (index, expected) in b"%PDF-1.7".iter().copied().enumerate() {
        assert_eq!(
            complete(reader.byte_at(index as u64)).unwrap(),
            Some(expected)
        );
    }
    assert_eq!(complete(reader.byte_at(8)).unwrap(), None);
    assert_eq!(reader.stamp().snapshot.document, 4);
    drop(reader);
    assert_eq!(account.used(), 0);
}

#[test]
fn reverse_eof_search_reuses_the_same_bounded_window() {
    // PDF startxref/EOF discovery walks backwards. Starting every acquisition
    // at the queried byte would turn one window into thousands of I/O calls.
    let account = memory(8192, 100_000);
    let session = Session::new(Limits::default(), account.clone());
    let source = Sparse::new();
    let work = session.execution();
    let mut reader = RangeReader::new(&source, &session, &work).unwrap();
    let end = source.stamp().length;
    for back in 1..=20 {
        let offset = end - back;
        assert_eq!(
            complete(reader.byte_at(offset)).unwrap(),
            Some(u8::try_from(offset % 251).unwrap())
        );
    }
    assert_eq!(source.calls.get(), 1);
    drop(reader);
    assert_eq!(account.used(), 0);
}

#[test]
fn short_read_of_an_aligned_prefix_never_scans_through_the_missing_gap() {
    // A source returning one byte at a time must not require 4096 awaits just
    // because the first query lies at the end of an aligned cache window.
    let account = memory(8192, 100_000);
    let session = Session::new(Limits::default(), account.clone());
    let source = Sparse {
        short: true,
        ..Sparse::new()
    };
    let work = session.execution();
    let mut reader = RangeReader::new(&source, &session, &work).unwrap();
    assert_eq!(
        complete(reader.byte_at(4095)).unwrap(),
        Some(u8::try_from(4095 % 251).unwrap())
    );
    assert_eq!(source.calls.get(), 2);
    assert_eq!(
        complete(reader.byte_at(4096)).unwrap(),
        Some(u8::try_from(4096 % 251).unwrap())
    );
    assert_eq!(source.calls.get(), 3);
    drop(reader);
    assert_eq!(account.used(), 0);
}

#[test]
fn range_boundaries_do_not_create_a_second_pdf_byte_grammar() {
    // Every multi-byte escape crosses the physical 4096-byte cache boundary.
    // These are normative golden results, not expected data computed by the
    // implementation under test or by the resident convenience adapter.
    for (form, encoded, expected) in [
        (Form::Name, b"#41".as_slice(), b"A".as_slice()),
        (Form::Literal, b"\\777", &[0xff]),
        (Form::Literal, b"\r\nX", b"\nX"),
        (Form::Literal, b"\\\r\nX", b"X"),
        (Form::Literal, b"\\7Z", &[7, b'Z']),
        (Form::Hexadecimal, b"A B C", &[0xab, 0xc0]),
    ] {
        let mut original = vec![b'x'; 4095];
        original.extend_from_slice(encoded);
        let source = Slice::new(
            &original,
            Snapshot {
                document: 23_u32,
                generation: 1_u32,
            },
        );
        let account = memory(16384, 100_000);
        let session = Session::new(Limits::default(), account.clone());
        let work = session.execution();
        let mut reader = RangeReader::new(&source, &session, &work).unwrap();
        let result = complete(reader.decode_bytes(
            structured_asn1::Span {
                start: 4095,
                length: encoded.len() as u64,
            },
            form,
        ))
        .unwrap()
        .into_owned();
        assert_eq!(&*result, expected);
        drop(reader);
        assert!(account.used() > 0);
        drop(result);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn malformed_byte_values_and_output_refusal_never_return_a_partial_buffer() {
    // Body syntax and actual output capacity retain their separate causes;
    // the temporary output is dropped before either failure leaves the call.
    let mut original = vec![b'x'; 4096];
    original[..3].copy_from_slice(b"#xz");
    let source = Slice::new(
        &original,
        Snapshot {
            document: 32_u32,
            generation: 0_u32,
        },
    );
    let account = memory(4103, 100_000);
    let session = Session::new(Limits::default(), account.clone());
    let work = session.execution();
    let mut reader = RangeReader::new(&source, &session, &work).unwrap();
    let error = complete(reader.decode_bytes(
        structured_asn1::Span {
            start: 0,
            length: 3,
        },
        Form::Name,
    ))
    .unwrap_err();
    assert!(matches!(error, ReadFailure::Format(error)
        if error.kind == ErrorKind::Syntax(Syntax::Name) && error.location.span().start == 2));
    assert_eq!(account.used(), 4096);
    let error = complete(reader.decode_bytes(
        structured_asn1::Span {
            start: 3,
            length: 100,
        },
        Form::Literal,
    ))
    .unwrap_err();
    assert!(matches!(error, ReadFailure::Format(error)
        if error.kind == ErrorKind::Resource(MemoryError::LimitExceeded)));
    assert_eq!(account.used(), 4096);
    drop(reader);
    assert_eq!(account.used(), 0);
}
