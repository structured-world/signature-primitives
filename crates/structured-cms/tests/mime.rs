//! The original-octet and XML-normalized routes share one MIME grammar.

#[path = "mime/essence.rs"]
mod essence;

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use structured_cms::mime::Syntax;
use structured_cms::mime::media_type_or_headers;

#[test]
fn complete_header_framing_and_content_type_are_funded_without_storage() {
    // Generic RFC822 field bodies stay opaque; Content-Type shares the media
    // grammar. Exact current-work refusal cannot be treated as invalid syntax
    // or choose an uncharged alternative, even with zero retained capacity.
    let body = " text/plain;\r\n\tcharset=\"us-ascii\"";
    let header = format!("X-Extension: original\0text\r\nContent-Type:{body}\r\n");
    let units = header.len() * 8 + body.len() * 4;
    let execution = work(units);
    assert!(media_type_or_headers(header.as_bytes(), &execution).unwrap());
    assert_eq!(execution.used(), 0);
    assert_eq!(execution.charge_work(1), Err(MemoryError::WorkExceeded));
    assert_eq!(
        media_type_or_headers(header.as_bytes(), &work(units - 1)),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(
        media_type_or_headers(b"text/plain", &work(0)),
        Err(MemoryError::WorkExceeded)
    );
}

fn work(units: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(0, units)))
}

#[test]
fn original_and_xml_normalized_folding_are_distinct() {
    // RFC822 3.1 folding is CRLF+WSP; XML1.0 2.11 has already normalized CRLF.
    let execution = work(10_000);
    let mut original = Syntax::<false>::new();
    assert!(!original.feed("text/plain;\n x=one", &execution).unwrap());
    assert!(!original.complete());
    let mut original = Syntax::<false>::new();
    assert!(original.feed("text/plain;\r", &execution).unwrap());
    assert!(original.feed("\n x=one", &execution).unwrap());
    assert!(original.complete());
    let mut xml = Syntax::<true>::new();
    assert!(xml.feed("text/plain;\n x=one", &execution).unwrap());
    assert!(xml.complete());
    assert_eq!(execution.used(), 0);
}

#[test]
fn failed_syntax_is_sticky_but_refusal_does_not_change_state() {
    // A later chunk cannot erase a syntax failure; a refused chunk consumed no
    // bytes and may be retried with an adequately admitted current operation.
    let execution = work(10_000);
    let mut syntax = Syntax::<false>::new();
    assert!(!syntax.feed("text//", &execution).unwrap());
    assert!(!syntax.feed("plain", &execution).unwrap());
    assert!(!syntax.complete());
    let mut syntax = Syntax::<false>::new();
    assert!(syntax.feed("text/", &execution).unwrap());
    assert_eq!(syntax.feed("bad", &work(0)), Err(MemoryError::WorkExceeded));
    assert!(syntax.feed("plain", &execution).unwrap());
    assert!(syntax.complete());
}

#[test]
fn fragment_boundaries_and_iterative_comments_allocate_nothing() {
    // Deep attacker-controlled nesting never creates recursive stack frames.
    let depth = 30_000;
    let input = format!(
        "{}{}text/plain; x=\"a\\\"b\"",
        "(".repeat(depth),
        ")".repeat(depth)
    );
    let execution = work(input.len() * 4);
    let mut syntax = Syntax::<false>::new();
    for byte in input.as_bytes() {
        assert!(syntax.feed([*byte], &execution).unwrap());
    }
    assert!(syntax.complete());
    assert_eq!(execution.used(), 0);
    assert_eq!(execution.charge_work(1), Err(MemoryError::WorkExceeded));
}
