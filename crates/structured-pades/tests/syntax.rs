//! Actual public object parsing over bounded asynchronous original ranges.

use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use std::{cell::Cell, sync::Arc};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_ltv::source::Snapshot;
use structured_pades::error::{ErrorKind, Limit, ReadFailure, Unsupported};
use structured_pades::object::Type;
use structured_pades::range::{RangeSource, ReadError, Slice, Stamp};
use structured_pades::{Limits, Session};

fn complete<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..10 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
    panic!("test future did not complete after explicit wake");
}

fn memory(capacity: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, 100_000_000)))
}

#[test]
fn direct_values_keep_wire_order_original_ranges_and_reference_identity() {
    // PDF names decode #xx, array order is significant, references are not
    // followed, and unrelated following bytes are not part of the root value.
    let bytes = b"%comment\r<< /Byte#52ange [1 +2 -0 3. .4] /Ref 17 2 R /N null /S (a\\(b\\)) /H <0 1 F> >>tail";
    let account = memory(1_000_000);
    let session = Session::new(Limits::default(), account.clone());
    let source = Slice::new(
        bytes,
        Snapshot {
            document: 12_u32,
            generation: 3_u32,
        },
    );
    let value = complete(structured_pades::syntax::read(
        &source,
        &session,
        &session.execution(),
        0,
    ))
    .unwrap();
    assert_eq!(value.root().kind(), Type::Dictionary);
    assert_eq!(&bytes[usize::try_from(value.end()).unwrap()..], b"tail");
    assert_eq!(value.root().location().span().start, 9);
    let members: Vec<_> = value
        .root()
        .members(&account)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(members.len(), 10);
    assert!(members[0].name_equals(b"ByteRange", &account).unwrap());
    let numbers: Vec<_> = members[1]
        .members(&account)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(numbers.len(), 5);
    assert_eq!(numbers[0].unsigned(&account).unwrap(), 1);
    assert_eq!(numbers[1].unsigned(&account).unwrap(), 2);
    assert_eq!(numbers[2].unsigned(&account).unwrap(), 0);
    assert_eq!(numbers[3].kind(), Type::Real);
    assert_eq!(numbers[4].kind(), Type::Real);
    assert_eq!(members[3].reference(), Some((17, 2)));
    assert_eq!(members[5].kind(), Type::Null);
    let (_, body) = members[7].string_body().unwrap();
    let start = usize::try_from(body.span().start).unwrap();
    let end = usize::try_from(body.end()).unwrap();
    assert_eq!(&bytes[start..end], b"a\\(b\\)");
    drop(members);
    drop(numbers);
    drop(value);
    assert_eq!(account.used(), 0);
}

#[test]
fn wide_valid_integers_are_not_a_global_document_rejection_or_maximum_sentinel() {
    // A valid wide metadata integer remains readable. Only a caller asking
    // for a bounded u64 gets Unsupported, distinct from malformed spelling.
    let account = memory(100_000);
    let session = Session::new(Limits::default(), account.clone());
    let source = Slice::new(
        b"18446744073709551616",
        Snapshot {
            document: 1_u8,
            generation: 0_u8,
        },
    );
    let value = complete(structured_pades::syntax::read(
        &source, &session, &account, 0,
    ))
    .unwrap();
    assert_eq!(value.root().kind(), Type::Integer);
    assert_eq!(
        value.root().unsigned(&account).unwrap_err().kind,
        ErrorKind::Unsupported(Unsupported::NumericRange)
    );
    drop(value);
    assert_eq!(account.used(), 0);
}

#[test]
fn dictionary_semantics_use_decoded_keys_null_absence_and_first_equal_value() {
    // ISO 32000-1 §7.3.7: order is irrelevant and null means absence. Equal
    // duplicates retain the FIRST physical value, including literal spelling,
    // with a located fault rather than silently becoming conforming input.
    let raw = b"<< /A null /Z 1 /B (a) /#42 <61> /A 7 /Z +01 >>";
    let account = memory(1_000_000);
    let session = Session::new(Limits::default(), account.clone());
    let source = Slice::new(
        raw,
        Snapshot {
            document: 1_u8,
            generation: 0_u8,
        },
    );
    let value = complete(structured_pades::syntax::read(
        &source, &session, &account, 0,
    ))
    .unwrap();
    assert_eq!(value.faults().len(), 2);
    let root = value.root();
    assert_eq!(
        root.get(b"A", &account)
            .unwrap()
            .unwrap()
            .unsigned(&account)
            .unwrap(),
        7
    );
    assert_eq!(
        root.get(b"Z", &account)
            .unwrap()
            .unwrap()
            .unsigned(&account)
            .unwrap(),
        1
    );
    assert_eq!(
        root.get(b"B", &account)
            .unwrap()
            .unwrap()
            .location()
            .span()
            .start,
        19
    );
    assert!(root.get(b"absent", &account).unwrap().is_none());
    assert_eq!(root.members(&account).unwrap().count(), 12);
    drop(value);
    assert_eq!(account.used(), 0);
}

#[test]
fn duplicate_dictionary_values_compare_nested_semantics_without_float_sentinels() {
    // Reordered dictionaries, alternate string forms and exact decimal values
    // can say one typed value. Different wide integers/reals cannot merge via
    // u64 overflow, f64 rounding, or the position of a copied field.
    for raw in [
        b"<< /A << /X (a) /Y [1 true] >> /A << /Y [+01 true] /X <61> >> >>".as_slice(),
        b"<< /A 18446744073709551616 /A +018446744073709551616 >>",
        b"<< /A 0001.23000 /A +01.23 >>",
        b"<< /A -.0 /A 0.000 >>",
    ] {
        let account = memory(1_000_000);
        let session = Session::new(Limits::default(), account.clone());
        let source = Slice::new(
            raw,
            Snapshot {
                document: 1_u8,
                generation: 0_u8,
            },
        );
        let value = complete(structured_pades::syntax::read(
            &source, &session, &account, 0,
        ))
        .unwrap();
        assert_eq!(value.faults().len(), 1, "{raw:?}");
        drop(value);
        assert_eq!(account.used(), 0);
    }
    for raw in [
        b"<< /A 18446744073709551616 /A 18446744073709551617 >>".as_slice(),
        b"<< /A 9007199254740992.0 /A 9007199254740993.0 >>",
        b"<< /A -18446744073709551616 /A 18446744073709551616 >>",
        b"<< /A 1 /A 1.0 >>",
        b"<< /A [1 2] /A [2 1] >>",
        b"<< /A << /X 1 >> /A << /X 2 >> >>",
    ] {
        let account = memory(1_000_000);
        let session = Session::new(Limits::default(), account.clone());
        let source = Slice::new(
            raw,
            Snapshot {
                document: 1_u8,
                generation: 0_u8,
            },
        );
        assert!(
            matches!(complete(structured_pades::syntax::read(&source, &session, &account, 0)),
            Err(ReadFailure::Format(error)) if error.kind == ErrorKind::Ambiguous(structured_pades::error::Syntax::Dictionary)),
            "{raw:?}"
        );
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn malformed_container_and_scalar_boundaries_are_not_valid_prefixes() {
    // Containers require matching delimiters and complete dictionary pairs;
    // every scalar's grammar is checked, including zero name escapes.
    for raw in [
        b"[1 2".as_slice(),
        b"[1 >>",
        b"<< /A >>",
        b"<< 1 2 >>",
        b"/A#00",
        b"truefalse",
        b"(unfinished\\",
        b"<FZ>",
        b"--1",
        b".",
    ] {
        let account = memory(100_000);
        let session = Session::new(Limits::default(), account.clone());
        let source = Slice::new(
            raw,
            Snapshot {
                document: 1_u8,
                generation: 0_u8,
            },
        );
        assert!(
            matches!(complete(structured_pades::syntax::read(&source, &session, &account, 0)),
            Err(ReadFailure::Format(error)) if matches!(error.kind, ErrorKind::Syntax(_))),
            "{raw:?}"
        );
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn object_admission_precedes_decoded_name_allocation() {
    // With zero object allowance the denial must be Objects, not an output
    // allocation failure after parsing the attacker's name into a catalogue.
    let account = memory(4);
    let session = Session::new(
        Limits {
            max_objects: 0,
            ..Default::default()
        },
        account.clone(),
    );
    let source = Slice::new(
        b"/abc",
        Snapshot {
            document: 1_u8,
            generation: 0_u8,
        },
    );
    assert!(
        matches!(complete(structured_pades::syntax::read(&source, &session, &account, 0)),
        Err(ReadFailure::Format(error)) if error.kind == ErrorKind::Limit(Limit::Objects))
    );
    assert_eq!(account.used(), 0);
}

struct OneWindow {
    bytes: Vec<u8>,
    calls: Cell<usize>,
}

impl RangeSource for OneWindow {
    type Document = u8;
    type Generation = u8;
    type Error = ();

    fn stamp(&self) -> Stamp<u8, u8> {
        Stamp {
            snapshot: Snapshot {
                document: 7,
                generation: 0,
            },
            length: 8192,
        }
    }

    fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        _work: &'q W,
    ) -> impl Future<Output = Result<usize, ReadError<Self::Error>>> + 'q {
        self.calls.set(self.calls.get() + 1);
        let result = if offset >= 4096 {
            Err(ReadError::Resource(MemoryError::WorkExceeded))
        } else {
            let start = usize::try_from(offset).unwrap();
            let length = output.len().min(4096 - start);
            output[..length].copy_from_slice(&self.bytes[start..start + length]);
            Ok(length)
        };
        core::future::ready(result)
    }
}

#[test]
fn completed_delimited_value_does_not_acquire_the_unrelated_next_page() {
    // Snapshot revalidation after ')' must be metadata-only. Reading the
    // next page would fail a complete value because of unrelated source I/O.
    let mut bytes = vec![b'x'; 4096];
    bytes[0] = b'(';
    bytes[4095] = b')';
    let source = OneWindow {
        bytes,
        calls: Cell::new(0),
    };
    let account = memory(100_000);
    let session = Session::new(Limits::default(), account.clone());
    let value = complete(structured_pades::syntax::read(
        &source, &session, &account, 0,
    ));
    assert!(value.is_ok());
    assert_eq!(source.calls.get(), 1);
    assert_eq!(value.unwrap().end(), 4096);
    assert_eq!(account.used(), 0);
}
