//! Shared structural Extension facts before protocol-specific payload decoding.

use core::cell::Cell;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Parser, Span, Tag, universal};
use structured_pkix::error::CallbackError;
use structured_pkix::extension;
use structured_pkix::{ErrorCode, Extensions};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

#[test]
fn header_is_available_before_decoding_and_keeps_original_ranges() {
    // Inspection can retain written-false and trailing faults before a join;
    // the structural kernel must neither erase the value nor silently repair it.
    let encoded = [0x30, 11, 6, 1, 42, 1, 1, 0, 4, 1, 7, 5, 0];
    let account = memory();
    let parser = Parser::ber(account.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let held = account.used();
    let decoded = extension::read_with(&reader, &element, "extension", |header, inside, value| {
        assert_eq!(header.kind().as_bytes(), &[42]);
        assert!(!header.is_critical());
        assert!(header.default_written());
        assert_eq!(
            header.critical_span(),
            Some(Span {
                start: 405,
                length: 3
            })
        );
        assert_eq!(inside.offset(), 411);
        assert_eq!(inside.remaining(), &[5, 0]);
        assert_eq!(inside.depth(), reader.depth() + 1);
        assert!(core::ptr::eq(inside.parser(), &raw const parser));
        assert!(inside.memory().same_account(&account));
        assert_eq!(
            value.span(),
            Span {
                start: 408,
                length: 3
            }
        );
        assert_eq!(
            value.contents_span(),
            Span {
                start: 410,
                length: 1
            }
        );
        Ok::<_, u8>(value.contents())
    })
    .unwrap();
    assert_eq!(*decoded.value(), &[7]);
    assert_eq!(
        decoded.trailing_span(),
        Some(Span {
            start: 411,
            length: 2
        })
    );
    assert_eq!(decoded.value().as_ptr(), encoded[10..].as_ptr());
    assert_eq!(decoded.header().span(), element.span());
    assert_eq!(decoded.into_value(), &[7]);
    assert_eq!(
        account.used(),
        held,
        "only the temporary Reader path was held"
    );
}

#[test]
fn grammar_refusals_precede_callback_but_constructed_octets_reach_it() {
    // An unknown value tag is not an open-type callback input. BER constructed
    // OCTET STRING remains a readable value; the profile decides conformance.
    for encoded in [
        &[0x30, 5, 6, 1, 42, 2, 0][..],
        &[0x30, 3, 6, 1, 42][..],
        &[0x30, 8, 6, 1, 42, 1, 0, 4, 1, 7][..],
    ] {
        let parser = Parser::ber(memory());
        let mut reader = parser.read(encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let called = Cell::new(false);
        let result = extension::read_with(&reader, &element, "extension", |_, _, _| {
            called.set(true);
            Ok::<_, u8>(())
        });
        assert!(matches!(result, Err(CallbackError::Processing(_))));
        assert!(!called.get());
    }
    let encoded = [0x30, 8, 6, 1, 42, 0x24, 3, 4, 1, 7];
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let decoded = extension::read_with(&reader, &element, "extension", |header, inside, value| {
        assert_eq!(value.tag(), Tag::constructed(universal::OCTET_STRING));
        assert_eq!(header.critical_span(), None);
        assert!(inside.is_empty());
        let mut fragments = inside.enter(value).unwrap();
        let fragment = fragments.next_element().unwrap().unwrap();
        assert!(fragments.is_empty());
        Ok::<_, u8>(fragment.contents())
    })
    .unwrap();
    assert_eq!(decoded.into_value(), &[7]);
}

#[test]
fn resource_callback_refusal_keeps_cause_and_releases_temporary_path() {
    // A callback failure cannot become semantic malformed/absence or leak the
    // structural reader path. The callback uses the actual producing execution.
    let encoded = [0x30, 6, 6, 1, 42, 4, 1, 7];
    let account = memory();
    let parser = Parser::ber(account.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let held = account.used();
    let result = extension::read_with(&reader, &element, "extension", |_, inside, _| {
        inside.execution().charge_work(u64::MAX)
    });
    assert!(matches!(
        result,
        Err(CallbackError::Callback(MemoryError::WorkExceeded))
    ));
    assert_eq!(account.used(), held);
}

#[test]
fn written_default_can_be_retained_before_a_broken_value_header() {
    // A value-header failure after DEFAULT FALSE must not erase the prior
    // diagnostic. Two-stage reading permits its capacity admission first.
    let encoded = [0x30, 8, 6, 1, 42, 1, 1, 0, 4, 0x81];
    let account = memory();
    let parser = Parser::ber(account.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let held = account.used();
    let fields = extension::open(&reader, &element, "extension").unwrap();
    let mut diagnostics = fields.reader().execution().vector();
    assert!(fields.header().default_written());
    diagnostics
        .try_push(fields.header().critical_span().unwrap())
        .unwrap();
    let diagnostics = diagnostics.into_owned();
    let called = Cell::new(false);
    let result = fields.read_with(|_, _, _| {
        called.set(true);
        Ok::<_, u8>(())
    });
    assert!(matches!(result, Err(CallbackError::Processing(ref error)) if !error.is_resource()));
    assert!(!called.get());
    assert_eq!(
        &*diagnostics,
        &[Span {
            start: 405,
            length: 3
        }]
    );
    assert!(account.used() > held);
    drop(result);
    drop(diagnostics);
    assert_eq!(account.used(), held);
}

#[test]
fn implicit_catalogue_preserves_original_tag_and_strict_certificate_invariants() {
    // The IMPLICIT entrypoint must neither retag input nor change catalogue
    // policy. Both strict and inspection routes still share Extension grammar.
    let encoded = [0xa0, 8, 0x30, 6, 6, 1, 42, 4, 1, 7];
    let account = memory();
    let parser = Parser::der(account.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let held = account.used();
    let extensions = Extensions::read_implicit(&reader, &element, 0, "request.extensions").unwrap();
    assert_eq!(element.tag(), Tag::context(true, 0));
    let extension = extensions
        .get(structured_asn1::Oid::from_bytes(&[42]), &account)
        .unwrap()
        .unwrap();
    assert_eq!(extension.value(), &[7]);
    assert_eq!(extension.value().as_ptr(), encoded[9..].as_ptr());
    assert_eq!(
        extension.span(),
        Span {
            start: 402,
            length: 8
        }
    );
    drop(extensions);
    assert_eq!(account.used(), held);
    let error = Extensions::read_implicit(&reader, &element, 1, "request.extensions").unwrap_err();
    assert_eq!(error.offset(), 400);
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    for (encoded, expected) in [
        (&[0xa0, 0][..], ErrorCode::EmptySequence),
        (
            &[
                0xa0, 16, 0x30, 6, 6, 1, 42, 4, 1, 7, 0x30, 6, 6, 1, 42, 4, 1, 7,
            ][..],
            ErrorCode::DuplicateExtension,
        ),
        (
            &[0xa0, 10, 0x30, 8, 6, 1, 42, 4, 1, 7, 5, 0][..],
            ErrorCode::TrailingData,
        ),
        (
            &[0xa0, 9, 0x30, 7, 6, 1, 42, 0x24, 2, 4, 0][..],
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
        ),
        (
            &[0xa0, 11, 0x30, 9, 6, 1, 42, 1, 1, 0, 4, 1, 7][..],
            ErrorCode::MalformedValue,
        ),
    ] {
        let account = memory();
        let parser = Parser::der(account.clone());
        let mut reader = parser.read(encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let held = account.used();
        let error =
            Extensions::read_implicit(&reader, &element, 0, "request.extensions").unwrap_err();
        assert_eq!(error.code(), expected);
        assert_eq!(error.field(), "request.extensions");
        assert_eq!(account.used(), held);
    }
}

#[test]
fn full_iterator_uses_current_work_and_never_turns_refusal_into_absence() {
    // Queries can outlive parsing and run under another domain. Neither the
    // full traversal nor critical filtering may silently skip a refused item.
    let encoded = [
        0xa0, 19, 0x30, 6, 6, 1, 42, 4, 1, 7, 0x30, 9, 6, 1, 43, 1, 1, 0xff, 4, 1, 8,
    ];
    let original = memory();
    let parser = Parser::der(original.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let extensions = Extensions::read_implicit(&reader, &element, 0, "extensions").unwrap();
    let original_work = original.work_used();
    let account = Arc::new(MemoryAccount::new(0, 1));
    let query = Memory::new(account.clone());
    let owners = Arc::strong_count(&account);
    let mut iter = extensions.iter(&query);
    assert_eq!(Arc::strong_count(&account), owners);
    assert_eq!(query.work_used(), 0);
    assert!(!iter.next().unwrap().unwrap().is_critical());
    let error = iter.next().unwrap().unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 410);
    assert!(iter.next().is_none());
    assert!(iter.next().is_none());
    assert_eq!(query.work_used(), 1);
    assert_eq!(original.work_used(), original_work);
    assert_eq!(Arc::strong_count(&account), owners);

    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 1)));
    let mut criticals = extensions.criticals(&denied);
    assert!(criticals.next().unwrap().unwrap_err().is_resource());
    assert!(criticals.next().is_none());
    assert_eq!(denied.work_used(), 1, "the noncritical item was paid too");
}
