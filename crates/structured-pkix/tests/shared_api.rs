//! Qualification of the shared borrowed API through external call sites.

use structured_asn1::{Encoding, ErrorCode as AsnError, Limit, Limits, Parser};
use structured_pkix::{der, general_name, temporal};

fn memory() -> structured_asn1::memory::Memory {
    structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(1024 * 1024, 1024 * 1024),
    ))
}

#[test]
fn constructed_generalized_time_keeps_the_reading_and_der_refusal_separate() {
    // X.680 §46.3 and X.690 §§8.25, 8.23 allow OCTET STRING fragments
    // under the useful time tag. A readable BER value is still not DER.
    let bytes = b"\x38\x13\x04\x0820260101\x04\x07000000Z";
    let parser = Parser::ber(memory());
    let mut reader = parser.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let reading = temporal::read_generalized(&reader, &element, "genTime").unwrap();
    assert_eq!(
        reading.start(),
        temporal::Instant::new(1_767_225_600, 0).unwrap()
    );
    assert!(!reading.has_subnanosecond_remainder());
    let mut distinguished = reader.reread(&element, Encoding::Der).unwrap();
    let encoded = distinguished.next_element().unwrap().unwrap();
    let error = der::conforms(&distinguished, &encoded, "genTime").unwrap_err();
    assert_eq!(
        error.code(),
        structured_pkix::ErrorCode::Encoding(AsnError::UnexpectedTag)
    );
    assert_eq!(error.offset(), 400);
}

fn segmented_time(label: &[u8]) -> Vec<u8> {
    // Mix empty, primitive and nested indefinite OCTET STRING fragments.
    let mut bytes = vec![0x38, 0x80, 0x04, 0, 0x24, 0x80, 0x04, 8];
    bytes.extend_from_slice(&label[..8]);
    bytes.extend_from_slice(&[0x04, u8::try_from(label.len() - 8).unwrap()]);
    bytes.extend_from_slice(&label[8..]);
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes
}

#[test]
fn constructed_generalized_time_shares_decimal_calendar_and_leap_semantics() {
    // Segmentation changes encoding only: optional fields, offset conversion,
    // arbitrary decimal carry and leap labels use the primitive semantic core.
    for label in [
        &b"20260101000000Z"[..],
        &b"20161231235960.1234567891Z"[..],
        &b"2017010100.0000000000002777777777777777777777778Z"[..],
        &b"2026010101,5+0130"[..],
    ] {
        let mut primitive = vec![0x18, u8::try_from(label.len()).unwrap()];
        primitive.extend_from_slice(label);
        let constructed = segmented_time(label);
        let mut readings = Vec::new();
        for bytes in [&primitive, &constructed] {
            let execution = memory();
            let parser = Parser::ber(execution.clone());
            let mut reader = parser.read(bytes, 401).unwrap();
            let element = reader.next_element().unwrap().unwrap();
            let storage = execution.used();
            readings.push(temporal::read_generalized(&reader, &element, "genTime").unwrap());
            assert_eq!(execution.used(), storage);
        }
        assert_eq!(readings[0].start(), readings[1].start());
        assert_eq!(
            readings[0].has_subnanosecond_remainder(),
            readings[1].has_subnanosecond_remainder()
        );
    }
}

#[test]
fn constructed_generalized_time_refuses_invalid_children_and_labels() {
    // The useful type inherits OCTET STRING children, not recursive time
    // tags. Complete but invalid or unzoned labels cannot become readings.
    let wrong_child = b"\x38\x11\x18\x0f20260101000000Z".to_vec();
    let cases = [
        (wrong_child, structured_pkix::ErrorCode::MalformedValue, 403),
        (
            segmented_time(b"20260230000000Z"),
            structured_pkix::ErrorCode::TimeOutOfRange,
            401,
        ),
        (
            segmented_time(b"20260101000000"),
            structured_pkix::ErrorCode::MalformedTime,
            401,
        ),
        (
            segmented_time(b"20260101000000.Z"),
            structured_pkix::ErrorCode::MalformedTime,
            401,
        ),
    ];
    for (bytes, code, offset) in cases {
        let execution = memory();
        let parser = Parser::ber(execution.clone());
        let mut reader = parser.read(&bytes, 401).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let storage = execution.used();
        let error = temporal::read_generalized(&reader, &element, "genTime").unwrap_err();
        assert_eq!(error.code(), code);
        assert_eq!(error.offset(), offset);
        assert_eq!(error.field(), "genTime");
        assert_eq!(execution.used(), storage);
    }
}

#[test]
fn constructed_generalized_time_keeps_current_storage_work_and_original_depth_limits() {
    // Deferred decoding uses its new domain, releases partial scratch on
    // refusal and cannot reset the source reader's inherited depth ceiling.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let bytes = segmented_time(b"20260101000000Z");
    for (storage, work) in [(0, 1_000_000), (1_000_000, 0)] {
        let original = memory();
        let parser = Parser::ber(original.clone());
        let mut reader = parser.read(&bytes, 401).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let before = original.work_used();
        let execution = Memory::new(std::sync::Arc::new(MemoryAccount::new(storage, work)));
        let reader = reader.with_execution(&execution);
        let error = temporal::read_generalized(&reader, &element, "genTime").unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.field(), "genTime");
        assert_eq!(execution.used(), 0);
        assert_eq!(original.work_used(), before);
    }
    // Definite lengths defer descent until the temporal walker; indefinite
    // lengths would already exercise the ASN.1 scanner's same depth ceiling.
    let nested = b"\x38\x15\x24\x13\x04\x0820260101\x04\x07000000Z";
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 1,
            ..Limits::default()
        },
        memory(),
    );
    let mut reader = parser.read(nested, 401).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = temporal::read_generalized(&reader, &element, "genTime").unwrap_err();
    assert_eq!(
        error.code(),
        structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Depth))
    );
}

#[test]
fn constructed_generalized_time_cannot_reset_local_work_with_a_new_execution_domain() {
    // The original parser pays the outer header and retained reader path, but
    // cannot fund the walker's first frame allocation. Rebinding cannot refill
    // it or move the refusal to a synthetic joined-buffer offset.
    let bytes = b"\x38\x13\x04\x0820260101\x04\x07000000Z";
    let original = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 23,
            ..Limits::default()
        },
        original.clone(),
    );
    let mut reader = parser.read(bytes, 401).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let before = original.work_used();
    let execution = memory();
    let reader = reader.with_execution(&execution);
    let error = temporal::read_generalized(&reader, &element, "genTime").unwrap_err();
    assert_eq!(
        error.code(),
        structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Work))
    );
    // Frame allocation now refuses before visiting any child. Its original
    // container offset is the correct allocation location, not a joined label.
    assert_eq!(error.offset(), 401);
    assert_eq!(execution.used(), 0);
    assert_eq!(original.work_used(), before);
}

#[test]
fn public_mailbox_decode_needs_no_storage_and_uses_current_work() {
    // The producing parser's account cannot finance a later mailbox check.
    // Syntax-only success and refusal need no result/scratch allocation;
    // accepted quoted/literal identities keep their original byte view.
    use structured_asn1::memory::{Memory, MemoryAccount};
    for (mailbox, valid) in [
        ("\"\"@example.ua", true),
        ("\"a@b\"@localhost", true),
        ("user@[IPv6:::ffff:012.0.2.1]", true),
        ("user@[AS400:QSYS]", true),
        ("user(comment)@example.ua", false),
        ("user@[256.0.0.1]", false),
    ] {
        let mut bytes = vec![0x81, u8::try_from(mailbox.len()).unwrap()];
        bytes.extend_from_slice(mailbox.as_bytes());
        let parser = Parser::der(memory());
        let mut reader = parser.read(&bytes, 401).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let execution = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, mailbox.len())));
        let reader = reader.with_execution(&execution);
        match general_name::read(&reader, &element, "mailbox") {
            Ok(general_name::GeneralName::Email(value)) if valid => {
                assert_eq!(value, mailbox);
                assert_eq!(value.as_ptr(), element.contents().as_ptr());
            }
            Err(error) if !valid => {
                assert_eq!(error.code(), structured_pkix::ErrorCode::MalformedValue);
            }
            other => panic!("unexpected mailbox result: {other:?}"),
        }
        assert_eq!(execution.used(), 0);
        assert_eq!(execution.work_used(), mailbox.len());
        let error = general_name::read(&reader, &element, "mailbox").unwrap_err();
        assert_eq!(
            error.code(),
            structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Work))
        );
        assert_eq!(error.field(), "mailbox");
        assert_eq!(execution.work_used(), mailbox.len());
    }
}

#[test]
fn public_set_ordering_refuses_an_unfunded_retained_comparison() {
    // Parsing in an earlier account cannot finance deferred signedAttrs
    // ordering in a new request, even when both encodings are identical.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let bytes = b"\x04\x02ab";
    let parser = Parser::der(memory());
    let mut reader = parser.read(bytes, 101).unwrap();
    let member = reader.next_element().unwrap().unwrap();
    let execution = Memory::new(std::sync::Arc::new(MemoryAccount::new(1024, 0)));
    let reader = reader.with_execution(&execution);
    let result = der::set_ordered(&reader, bytes, &member, "signedAttrs");
    let error = result.unwrap_err();
    assert_eq!(
        error.code(),
        structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Work))
    );
    assert_eq!(error.offset(), 101);
    assert_eq!(error.field(), "signedAttrs");
    assert_eq!(execution.work_used(), 0);
}

#[test]
fn public_set_ordering_keeps_padding_semantics_and_reports_false_separately() {
    // The shorter octet string is virtually padded, not ordered by its
    // length. A fully funded inverted pair answers false, never a resource error.
    let bytes = b"\x04\x02ab";
    for (previous, expected) in [
        (&[][..], true),
        (&bytes[..], true),
        (&b"\x04\x02ab\x00"[..], true),
        (&b"\x04\x02ac"[..], false),
    ] {
        let parser = Parser::der(memory());
        let mut reader = parser.read(bytes, 101).unwrap();
        let member = reader.next_element().unwrap().unwrap();
        assert_eq!(
            der::set_ordered(&reader, previous, &member, "signedAttrs").unwrap(),
            expected
        );
    }
}

#[test]
fn public_set_ordering_preserves_the_parser_local_cumulative_ceiling() {
    // A generous aggregate domain must not reset a stricter original parser
    // ceiling between repeated comparisons of retained elements.
    let bytes = b"\x04\x02ab";
    let execution = memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 7,
            ..Limits::default()
        },
        execution.clone(),
    );
    let mut reader = parser.read(bytes, 101).unwrap();
    let member = reader.next_element().unwrap().unwrap();
    assert!(der::set_ordered(&reader, bytes, &member, "signedAttrs").unwrap());
    let before = execution.work_used();
    let error = der::set_ordered(&reader, bytes, &member, "signedAttrs").unwrap_err();
    assert_eq!(
        error.code(),
        structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Work))
    );
    assert_eq!(error.offset(), 101);
    assert_eq!(error.field(), "signedAttrs");
    assert_eq!(execution.work_used(), before);
}

#[test]
fn public_temporal_decode_uses_the_current_execution_account() {
    // A retained fractional timestamp may not scan or convert its digits
    // using the account that paid for an earlier parse.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let bytes = b"\x18\x1920161231235960.123456789Z";
    let parser = Parser::der(memory());
    let mut reader = parser.read(bytes, 201).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let execution = Memory::new(std::sync::Arc::new(MemoryAccount::new(1024, 0)));
    let reader = reader.with_execution(&execution);
    let error = temporal::read_generalized(&reader, &element, "genTime").unwrap_err();
    assert_eq!(
        error.code(),
        structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Work))
    );
    assert_eq!(error.offset(), 201);
    assert_eq!(error.field(), "genTime");
    assert_eq!(execution.work_used(), 0);
}

#[test]
fn public_temporal_decode_admits_exact_work_and_preserves_both_ceilings() {
    // The two fractional-digit passes are admitted once before decoding.
    // Independent cases exhaust the aggregate domain and original parser
    // ceiling; neither refused repeat consumes additional aggregate work.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let bytes = b"\x18\x1920161231235960.123456789Z";
    for (local, aggregate) in [(u64::MAX, 53), (53, 1024)] {
        let execution = Memory::new(std::sync::Arc::new(MemoryAccount::new(1024, aggregate)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            execution.clone(),
        );
        let mut reader = parser.read(bytes, 201).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let before = execution.work_used();
        let reading = temporal::read_generalized(&reader, &element, "genTime").unwrap();
        assert!(reading.start().is_leap_second());
        assert_eq!(reading.start().nanos(), 123_456_789);
        assert_eq!(
            execution.work_used() - before,
            2 * element.contents().len() + 1
        );
        let before = execution.work_used();
        let error = temporal::read_generalized(&reader, &element, "genTime").unwrap_err();
        assert_eq!(
            error.code(),
            structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Work))
        );
        assert_eq!(error.offset(), 201);
        assert_eq!(execution.work_used(), before);
    }
}

#[test]
fn der_fraction_validation_admits_the_semantic_decimal_passes() {
    // Paying for DER digit spelling cannot also finance the semantic
    // conversion's forward/reverse passes over an arbitrary-length fraction.
    let bytes = b"\x18\x1920161231235960.123456789Z";
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 27,
            ..Limits::default()
        },
        memory(),
    );
    let mut reader = parser.read(bytes, 201).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = der::conforms(&reader, &element, "genTime").unwrap_err();
    assert_eq!(
        error.code(),
        structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Work))
    );
}

#[test]
fn generalized_time_der_and_temporal_paths_agree_at_leap_boundary() {
    // The public DER validator must accept the same leap label as the
    // temporal reader, preserving precision beyond a nanosecond.
    let bytes = b"\x18\x1a20161231235960.1234567891Z";
    let parser = Parser::der(memory());
    let mut reader = parser.read(bytes, 51).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    der::conforms(&reader, &element, "timestamp").unwrap();
    let reading = temporal::read_generalized(&reader, &element, "timestamp").unwrap();
    assert!(reading.start().is_leap_second());
    assert_eq!(reading.start().nanos(), 123_456_789);
    assert!(reading.has_subnanosecond_remainder());
    assert_eq!(element.as_bytes().as_ptr(), bytes.as_ptr());
    assert_eq!(element.span().start, 51);
}

#[test]
fn public_general_name_borrows_bytes_and_shares_work_budget() {
    // Repeated name decoding must spend the caller's one budget rather than
    // creating a fresh parser for each read of the same attacker input.
    let bytes = b"\x82\x0aexample.ua";
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 12,
            ..Limits::default()
        },
        memory(),
    );
    let mut reader = parser.read(bytes, 71).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let general_name::GeneralName::Dns(name) =
        general_name::read(&reader, &element, "tsa").unwrap()
    else {
        panic!("expected DNS name");
    };
    assert_eq!(name, "example.ua");
    assert_eq!(name.as_ptr(), element.contents().as_ptr());
    let error = general_name::read(&reader, &element, "tsa").unwrap_err();
    assert_eq!(
        error.code(),
        structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Work))
    );
    assert_eq!(error.field(), "tsa");
}

#[test]
fn public_general_name_cannot_reset_nested_depth() {
    // directoryName contains an explicit Name SEQUENCE. The parent is
    // already nested, so a root-only allowance must refuse before descent.
    let bytes = b"\xa4\x02\x30\x00";
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 1,
            ..Limits::default()
        },
        memory(),
    );
    let mut reader = parser.read_nested(bytes, 91, Encoding::Der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = general_name::read(&reader, &element, "tsa").unwrap_err();
    assert_eq!(
        error.code(),
        structured_pkix::ErrorCode::Encoding(AsnError::LimitExceeded(Limit::Depth))
    );
    // The reader was already past the explicit wrapper's header when descent
    // was refused, so the failure locates its contents in the whole document.
    assert_eq!(error.offset(), element.contents_span().start);
}

#[test]
fn public_name_results_retain_storage_and_use_the_current_execution_domain() {
    // A consumer prepares a trust-store view in one account, then compares
    // it for a new request. Old work allowance must not finance that request;
    // display text may outlive the parser while keeping its own storage charge.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let source = memory();
    let execution = memory();
    let exhausted = Memory::new(std::sync::Arc::new(MemoryAccount::new(1024, 0)));
    let text = {
        let parser = Parser::der(source.clone());
        let bytes = b"\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x03\x0c\x07Subject";
        let mut reader = parser.read(bytes, 91).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let name = structured_pkix::name::read(&reader, &element, "issuer").unwrap();
        let prepared = name.ordered(&execution).unwrap();
        assert!(execution.used() > 0);
        let work = source.work_used();
        let error = prepared.order(&prepared, &exhausted).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), 91);
        assert_eq!(source.work_used(), work);
        name.common_name(&execution)
            .unwrap()
            .unwrap()
            .text(&execution)
            .unwrap()
            .unwrap()
    };
    assert_eq!(source.used(), 0);
    assert_eq!(execution.used(), text.capacity());
    assert_eq!(text.as_str(&execution).unwrap(), "Subject");
    assert!(text.as_str(&exhausted).is_err());
    drop(text);
    assert_eq!(execution.used(), 0);
}
