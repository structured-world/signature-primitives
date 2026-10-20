//! The original-octet and XML-normalized routes share one MIME grammar.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use structured_cms::mime::Syntax;

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
