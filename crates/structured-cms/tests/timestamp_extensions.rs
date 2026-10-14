//! Token extension recovery uses one grammar and the original octet walker.

use std::sync::Arc;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_cms::{ErrorCode, timestamp::TokenExtensions};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}
fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![tag, u8::try_from(bytes.len()).unwrap()];
    output.extend_from_slice(bytes);
    output
}
fn extension(kind: u8, critical: Option<bool>, value: &[u8], trailing: &[u8]) -> Vec<u8> {
    let mut bytes = vec![6, 1, kind];
    if let Some(flag) = critical {
        bytes.extend_from_slice(&[1, 1, if flag { 0xff } else { 0 }]);
    }
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(trailing);
    tlv(0x30, &bytes)
}

#[test]
fn equal_assembled_values_retain_first_original_extension_and_one_duplicate_fault() {
    // Distinct BER segmentation must not fabricate a conflicting value or force
    // copies of primitive content just to decide duplicate identity.
    let first = extension(42, None, &[4, 2, b'a', b'b'], &[]);
    let second = extension(42, None, &[0x24, 6, 4, 1, b'a', 4, 1, b'b'], &[]);
    let mut members = first.clone();
    members.extend_from_slice(&second);
    let bytes = tlv(0xa1, &members);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = TokenExtensions::read(&parent, &element).unwrap();
    assert_eq!(extensions.entries().len(), 1);
    assert_eq!(extensions.entries()[0].value().as_one(), Some(&b"ab"[..]));
    assert_eq!(
        extensions.entries()[0].value().as_one().unwrap().as_ptr(),
        bytes[9..].as_ptr()
    );
    assert_eq!(extensions.faults().len(), 1);
    assert_eq!(extensions.faults()[0].code(), ErrorCode::DuplicateField);
    assert_eq!(
        extensions.faults()[0].offset(),
        402 + u64::try_from(first.len()).unwrap()
    );
    drop(extensions);
    assert_eq!(memory.used(), 0);
}

#[test]
fn conflicting_criticality_or_value_refuses_without_partial_catalogue() {
    // Choosing the first of conflicting extension assertions could drop a
    // security-relevant critical flag or value; conflicts must remain failure.
    let first = extension(42, None, &[4, 1, b'a'], &[]);
    for second in [
        extension(42, Some(true), &[4, 1, b'a'], &[]),
        extension(42, None, &[4, 1, b'b'], &[]),
    ] {
        let mut members = first.clone();
        members.extend(second);
        let bytes = tlv(0xa1, &members);
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let error = TokenExtensions::read(&parent, &element).unwrap_err();
        assert_eq!(error.code(), ErrorCode::DuplicateField);
        assert_eq!(error.offset(), 402 + u64::try_from(first.len()).unwrap());
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn default_fault_precedes_broken_value_and_later_members_remain_visible() {
    // The shared deferred header permits retention of written DEFAULT FALSE
    // before malformed extnValue. A bounded bad member cannot erase its sibling.
    let broken = extension(42, Some(false), &[4, 0x82, 1], &[]);
    let valid = extension(43, None, &[4, 1, b'c'], &[5, 0]);
    let mut members = broken.clone();
    members.extend(valid);
    let bytes = tlv(0xa1, &members);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = TokenExtensions::read(&parent, &element).unwrap();
    assert_eq!(extensions.entries().len(), 1);
    assert_eq!(extensions.entries()[0].kind().as_bytes(), &[43]);
    assert_eq!(extensions.entries()[0].value().as_one(), Some(&b"c"[..]));
    assert_eq!(extensions.faults().len(), 3);
    assert_eq!(extensions.faults()[0].code(), ErrorCode::DefaultWritten);
    assert_eq!(extensions.faults()[0].offset(), 407);
    assert!(!extensions.faults()[1].is_terminal());
    assert_eq!(extensions.faults()[2].code(), ErrorCode::TrailingData);
    drop(extensions);
    assert_eq!(memory.used(), 0);
}

#[test]
fn empty_extensions_are_a_readable_size_fault_not_successful_conformance() {
    // Optional absence and present-empty SIZE(1..MAX) are distinct. This view
    // preserves that fault rather than invoking permissive certificate parsing.
    let bytes = [0xa1, 0];
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = TokenExtensions::read(&parent, &element).unwrap();
    assert!(extensions.entries().is_empty());
    assert_eq!(extensions.faults().len(), 1);
    assert_eq!(extensions.faults()[0].code(), ErrorCode::MalformedValue);
    assert_eq!(extensions.faults()[0].offset(), 400);
    drop(extensions);
    assert_eq!(memory.used(), 0);
}

#[test]
fn critical_recognition_preserves_unknowns_and_original_callback_cause() {
    // Noncritical metadata participates in traversal but does not trigger the
    // critical handler. Unknown identifiers and callback failure are distinct.
    let mut members = extension(42, None, &[4, 1, 7], &[]);
    members.extend(extension(43, Some(true), &[4, 1, 8], &[]));
    members.extend(extension(44, Some(true), &[4, 1, 9], &[]));
    let bytes = tlv(0xa1, &members);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = TokenExtensions::read(&parent, &element).unwrap();
    let mut calls = Vec::new();
    let unknown = extensions
        .unrecognized_critical(&parent, |entry, _| {
            calls.push(entry.kind().as_bytes()[0]);
            Ok::<_, &'static str>(entry.kind().as_bytes() == [43])
        })
        .unwrap();
    assert_eq!(calls, [43, 44]);
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].as_bytes(), &[44]);
    let failure = extensions
        .unrecognized_critical(&parent, |_, _| Err::<bool, _>("handler-resource"))
        .unwrap_err();
    let structured_cms::timestamp::RecognitionError::Callback { span, source } = failure else {
        panic!("callback cause lost");
    };
    assert_eq!(source, "handler-resource");
    assert_eq!(span, extensions.entries()[1].span());
}

#[test]
fn critical_recognition_foreign_or_exhausted_query_never_calls_handler() {
    // Account identity does not substitute for source identity; query metadata
    // admission precedes recognition, and failure cannot become an empty list.
    let bytes = tlv(0xa1, &extension(42, Some(true), &[4, 1, 7], &[]));
    let account = memory();
    let parser = Parser::ber(account.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = TokenExtensions::read(&parent, &element).unwrap();
    let other = Parser::ber(account.clone());
    let foreign = other.read(&[], 900).unwrap();
    let mut calls = 0;
    let failure = extensions
        .unrecognized_critical(&foreign, |_, _| {
            calls += 1;
            Ok::<_, ()>(true)
        })
        .unwrap_err();
    assert!(matches!(
        failure,
        structured_cms::timestamp::RecognitionError::Processing(_)
    ));
    assert_eq!(calls, 0);
    let exhausted = Parser::new(
        structured_asn1::Encoding::Ber,
        structured_asn1::Limits {
            max_work: 1,
            ..structured_asn1::Limits::default()
        },
        account,
    );
    let query = exhausted.read(&[], 900).unwrap();
    let parent = parent.with_query(&query).unwrap();
    let failure = extensions
        .unrecognized_critical(&parent, |_, _| {
            calls += 1;
            Ok::<_, ()>(true)
        })
        .unwrap_err();
    let structured_cms::timestamp::RecognitionError::Processing(source) = failure else {
        panic!("refusal became recognition");
    };
    assert!(source.is_terminal());
    assert_eq!(source.offset(), extensions.entries()[0].span().start);
    assert_eq!(calls, 0);
}
