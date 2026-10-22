//! RFC3161 response framing, including the absence of token work on failures.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount},
};
use structured_cms::{
    ErrorCode,
    timestamp::{
        Response,
        response::{Failure, Status},
    },
};

fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if bytes.len() < 128 {
        out.push(u8::try_from(bytes.len()).unwrap());
    } else if bytes.len() < 256 {
        out.extend([0x81, u8::try_from(bytes.len()).unwrap()]);
    } else {
        out.push(0x82);
        out.extend(u16::try_from(bytes.len()).unwrap().to_be_bytes());
    }
    out.extend(bytes);
    out
}
fn response(status: &[u8], optional: &[u8], token: &[u8]) -> Vec<u8> {
    let mut fields = tlv(2, status);
    fields.extend(optional);
    let mut envelope = tlv(0x30, &fields);
    envelope.extend(token);
    tlv(0x30, &envelope)
}
fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_000_000, 100_000_000)))
}

#[test]
fn all_non_grant_statuses_preserve_original_text_and_failure_values() {
    // Status text is a nonempty sequence, not one concatenated string; absence
    // differs from present-empty failInfo. No token is manufactured on failure.
    let memory = memory();
    let parser = Parser::der(memory.clone());
    for (number, status) in [
        (2, Status::Rejection),
        (3, Status::Waiting),
        (4, Status::RevocationWarning),
        (5, Status::RevocationNotification),
    ] {
        let mut strings = tlv(12, b"");
        strings.extend(tlv(12, "временно недоступно".as_bytes()));
        let mut optional = tlv(0x30, &strings);
        optional.extend([3, 1, 0]);
        let bytes = response(&[number], &optional, &[]);
        let mut reader = parser.read(&bytes, 400).unwrap();
        let parsed = Response::read(&mut reader).unwrap();
        assert_eq!(parsed.status().status(), status);
        let text = parsed.status().text().unwrap();
        assert_eq!(
            text.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ["", "временно недоступно"]
        );
        assert_eq!(text[0].span().start, 409);
        assert_eq!(
            parsed.status().failure().unwrap().element().contents(),
            &[0]
        );
        assert!(parsed.token().is_none());
        assert!(parsed.token_reader_in(&reader).unwrap().is_none());
        drop(parsed);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn every_defined_failure_bit_and_combination_has_exact_named_bit_identity() {
    // ASN.1 numbers named bits from the MSB of the first content octet.
    // Do not treat this as a little-endian integer or truncate high bits.
    let reasons = [
        Failure::BadAlgorithm,
        Failure::BadRequest,
        Failure::BadDataFormat,
        Failure::TimeNotAvailable,
        Failure::UnacceptedPolicy,
        Failure::UnacceptedExtension,
        Failure::AdditionalInformationUnavailable,
        Failure::SystemFailure,
    ];
    for reason in reasons {
        let bit = reason as usize;
        let mut bits = vec![u8::try_from(7 - bit % 8).unwrap()];
        bits.resize(2 + bit / 8, 0);
        bits[1 + bit / 8] = 0x80 >> (bit % 8);
        let bytes = response(&[2], &tlv(3, &bits), &[]);
        let parser = Parser::der(memory());
        let mut reader = parser.read(&bytes, 400).unwrap();
        let parsed = Response::read(&mut reader).unwrap();
        let info = parsed.status().failure().unwrap();
        for candidate in reasons {
            assert_eq!(info.contains(candidate), candidate == reason);
        }
    }
    let bytes = response(&[2], &[3, 5, 6, 0x80, 0, 0, 0x40], &[]);
    let parser = Parser::der(memory());
    let mut reader = parser.read(&bytes, 400).unwrap();
    let parsed = Response::read(&mut reader).unwrap();
    assert!(
        parsed
            .status()
            .failure()
            .unwrap()
            .contains(Failure::BadAlgorithm)
    );
    assert!(
        parsed
            .status()
            .failure()
            .unwrap()
            .contains(Failure::SystemFailure)
    );
}

#[test]
fn unknown_status_and_failure_bits_are_errors_not_future_successes() {
    // RFC3161 explicitly requires errors for unknown values, including values
    // too wide for a scalar status/flag representation and negative INTEGERs.
    for status in [
        &[6][..],
        &[0xff][..],
        &[0, 0x80][..],
        &[1, 0, 0, 0, 0, 0, 0, 0, 0][..],
    ] {
        let bytes = response(status, &[], &[]);
        let parser = Parser::der(memory());
        let mut reader = parser.read(&bytes, 400).unwrap();
        let error = Response::read(&mut reader).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue);
        assert_eq!(error.offset(), 404);
    }
    for bits in [
        &[6, 0x40][..],
        &[5, 0, 0, 0, 0x20][..],
        &[7, 0, 0, 0, 0, 0x80][..],
    ] {
        let bytes = response(&[2], &tlv(3, bits), &[]);
        let parser = Parser::der(memory());
        let mut reader = parser.read(&bytes, 400).unwrap();
        let error = Response::read(&mut reader).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnknownField);
        assert_eq!(error.offset(), 407);
    }
}

#[test]
fn strict_der_and_full_schema_precede_any_token_decoding() {
    // DER framing and named-bit minimality are independent from general BIT
    // STRING padding. Text cardinality, order, tags and trailing fields matter.
    for optional in [
        &[3, 2, 0, 0x80][..],
        &[3, 2, 0, 0][..],
        &[3, 2, 8, 0][..],
        &[0x30, 0][..],
        &[0x30, 3, 12, 1, 0xff][..],
        &[0x30, 2, 22, 0][..],
        &[3, 1, 0, 0x30, 2, 12, 0][..],
        &[3, 1, 0, 3, 1, 0][..],
    ] {
        let bytes = response(&[2], optional, &[]);
        let parser = Parser::ber(memory());
        let mut reader = parser.read(&bytes, 400).unwrap();
        assert!(Response::read(&mut reader).is_err(), "{optional:?}");
    }
    for (status, token) in [
        (0, &[][..]),
        (1, &[][..]),
        (2, &[0x30, 0][..]),
        (3, &[0x30, 0][..]),
        (4, &[0x30, 0][..]),
        (5, &[0x30, 0][..]),
    ] {
        let bytes = response(&[status], &[], token);
        let parser = Parser::der(memory());
        let mut reader = parser.read(&bytes, 400).unwrap();
        assert_eq!(
            Response::read(&mut reader).unwrap_err().code(),
            ErrorCode::MalformedValue
        );
    }
    for bytes in [
        vec![0x30, 0x80, 0x30, 3, 2, 1, 2, 0, 0],
        vec![0x30, 0x81, 5, 0x30, 3, 2, 1, 2],
        vec![0x30, 5, 0x30, 3, 2, 1, 2, 5, 0],
    ] {
        let parser = Parser::ber(memory());
        let mut reader = parser.read(&bytes, 400).unwrap();
        assert!(Response::read(&mut reader).is_err());
    }
}

#[test]
fn status_catalogue_capacity_work_and_depth_refusals_release_every_owner() {
    // Repeated text entries allocate scoped storage. Find the exact producing
    // work boundary, then verify one-less and independent aggregate refusal.
    let mut text = Vec::new();
    for _ in 0..64 {
        text.extend(tlv(12, b"a"));
    }
    let bytes = response(&[2], &tlv(0x30, &text), &[]);
    let attempt = |local, global, capacity, depth| {
        let memory = Memory::new(Arc::new(MemoryAccount::new(capacity, global)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                max_depth: depth,
                ..Limits::default()
            },
            memory.clone(),
        );
        let mut parent = parser.read(&bytes, 400).unwrap();
        let result = Response::read(&mut parent);
        let success = result.is_ok();
        if let Err(error) = &result {
            assert!(
                error.is_resource() || matches!(error.code(), ErrorCode::Encoding(_)),
                "{error:?}"
            );
        }
        drop(result);
        assert_eq!(memory.used(), 0);
        success
    };
    let mut low = 0;
    let mut high = 100_000;
    while low < high {
        let mid = u64::midpoint(low, high);
        if attempt(mid, 1_000_000, 1_000_000, 32) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    assert!(attempt(low, 1_000_000, 1_000_000, 32));
    assert!(!attempt(low - 1, 1_000_000, 1_000_000, 32));
    assert!(!attempt(1_000_000, 0, 1_000_000, 32));
    assert!(!attempt(1_000_000, 1_000_000, 1, 32));
    assert!(!attempt(1_000_000, 1_000_000, 1_000_000, 0));
}
