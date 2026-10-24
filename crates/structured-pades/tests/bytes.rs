//! Original PDF byte semantics, source coordinates and transitive admission.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Parser, Span};
use structured_pades::bytes::{Bytes, Form};
use structured_pades::error::{ErrorKind, Syntax};
use structured_pades::source::{Location, Source};
use structured_pades::{Limits, Session};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

fn body(bytes: &[u8], form: Form) -> Bytes<'_> {
    Bytes::new(
        bytes,
        form,
        Location::new(Source::File, 100, bytes.len() as u64).unwrap(),
    )
    .unwrap()
}

#[test]
fn pdf_string_spellings_share_one_paid_byte_interpretation() {
    // Prevent separate comparison/decoding grammars: literal EOL/escapes and
    // odd hexadecimal nibbles must denote exactly the standard's byte values.
    let work = memory(4096, 10000);
    let literal = body(b"a\r\nb\\\r\nc\\n\\53\\053\\777\\z", Form::Literal);
    let decoded = literal.decode_in(&work).unwrap();
    assert_eq!(&*decoded, b"a\nbc\n++\xffz");
    let hex = body(b"61 0a 62 63 0a 2b 2b ff 7a", Form::Hexadecimal);
    assert!(literal.matches_in(hex, &work).unwrap());
    assert!(hex.equals_in(&decoded, &work).unwrap());
    assert_eq!(
        &*body(b"9 0 1 F A", Form::Hexadecimal)
            .decode_in(&work)
            .unwrap(),
        &[0x90, 0x1f, 0xa0]
    );
    assert_eq!(literal.as_bytes(), b"a\r\nb\\\r\nc\\n\\53\\053\\777\\z");
}

#[test]
fn names_decode_escapes_without_unicode_normalization() {
    // PDF names have byte identity. Escape spelling may differ, but neither
    // case folding nor Unicode normalization is a PDF name operation.
    let work = memory(4096, 10000);
    let escaped = body(b"Byte#52ange", Form::Name);
    assert!(escaped.equals_in(b"ByteRange", &work).unwrap());
    assert!(
        escaped
            .matches_in(body(b"ByteRange", Form::Name), &work)
            .unwrap()
    );
    assert!(!escaped.equals_in(b"byterange", &work).unwrap());
    for raw in [b"A#00".as_slice(), b"#xz", b"#1", b"A\0"] {
        let error = body(raw, Form::Name).decode_in(&work).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Syntax(Syntax::Name));
    }
}

#[test]
fn syntax_and_allocator_refusal_are_distinct() {
    // Malformed text is not allocator failure, and an incomplete output must
    // release actual capacity rather than becoming a successful byte prefix.
    let syntax_work = memory(4096, 1000);
    assert_eq!(
        body(b"aa xx", Form::Hexadecimal)
            .decode_in(&syntax_work)
            .unwrap_err()
            .kind,
        ErrorKind::Syntax(Syntax::String)
    );
    assert_eq!(
        body(b"x\\", Form::Literal)
            .decode_in(&syntax_work)
            .unwrap_err()
            .kind,
        ErrorKind::Syntax(Syntax::String)
    );
    assert_eq!(syntax_work.used(), 0);
    let refused = memory(1, 1000);
    assert_eq!(
        body(b"abcdef", Form::Literal)
            .decode_in(&refused)
            .unwrap_err()
            .kind,
        ErrorKind::Resource(MemoryError::LimitExceeded)
    );
    assert_eq!(refused.used(), 0);
    assert!(refused.work_used() > 0);
}

#[test]
fn empty_output_fanout_still_spends_current_work_before_reading() {
    // Escaped line endings produce no bytes; they must not bypass the work
    // ceiling or cause an allocation while scanning arbitrarily many lines.
    let work = memory(0, 15);
    let encoded = b"\\\n\\\n\\\n\\\n\\\n\\\n\\\n\\\n\\\n";
    let error = body(encoded, Form::Literal).decode_in(&work).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Resource(MemoryError::WorkExceeded));
    assert_eq!(error.location.span().start, 115);
    assert_eq!(work.work_used(), 15);
    assert_eq!(work.used(), 0);
}

#[test]
fn retained_decoding_releases_capacity_after_session_ends() {
    // into_owned must transfer the actual allocation/charge, not copy decoded
    // signature bytes or retain a borrowed source execution after setup drops.
    let account = memory(4096, 10000);
    let retained;
    {
        let session = Session::new(Limits::default(), account.clone());
        let decoded = body(b"01 23 45 67", Form::Hexadecimal)
            .decode_in(&session.execution())
            .unwrap();
        let pointer = decoded.as_ptr();
        retained = decoded.into_owned();
        assert_eq!(retained.as_ptr(), pointer);
    }
    assert!(account.used() >= 4);
    assert_eq!(&*retained, &[1, 0x23, 0x45, 0x67]);
    drop(retained);
    assert_eq!(account.used(), 0);
}

#[test]
fn source_and_current_query_ceilings_both_apply() {
    // A shared aggregate account must not waive the narrowed current operation
    // when reading an independently retained original PDF source.
    let account = memory(4096, 10000);
    let session = Session::new(Limits::default(), account.clone());
    let operation = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..Default::default()
        },
        account,
    );
    let read = operation.read(&[], 0).unwrap();
    let work = read.execution();
    let query = session.query(&work);
    assert_eq!(
        body(b"value", Form::Literal)
            .decode_in(&query)
            .unwrap_err()
            .kind,
        ErrorKind::Resource(MemoryError::WorkExceeded)
    );
    assert_eq!(query.memory().used(), 0);
}

#[test]
fn decoded_coordinates_never_claim_a_physical_byte_offset() {
    // A compressed object's logical position cannot be projected as a byte in
    // the file; retain the logical range AND the honest encoded enclosure.
    let stream = Span {
        start: 400,
        length: 25,
    };
    let logical = Location::new(
        Source::Decoded {
            stream,
            revision: 3,
            stage: 0,
        },
        900,
        4,
    )
    .unwrap();
    assert_eq!(
        logical.span(),
        Span {
            start: 900,
            length: 4
        }
    );
    assert_eq!(logical.enclosing(), stream);
    assert_eq!(logical.end(), 904);
    assert!(logical.contains(903));
    assert!(!logical.contains(904));
    assert!(Location::new(Source::File, u64::MAX, 1).is_none());
    assert!(
        Location::new(
            Source::Decoded {
                stream: Span {
                    start: u64::MAX,
                    length: 1
                },
                revision: 0,
                stage: 0,
            },
            0,
            0
        )
        .is_none()
    );
}
