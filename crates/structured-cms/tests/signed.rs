//! Complete `SignedData` envelopes, empty written fields and version precedence.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::{ErrorCode, SignedData, oid};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_048_576, 1_048_576)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    assert!(contents.len() < 128);
    let mut encoded = vec![tag, u8::try_from(contents.len()).unwrap()];
    encoded.extend_from_slice(contents);
    encoded
}

fn message(version: u8, kind: &[u8], optional: &[u8], signers: &[u8]) -> Vec<u8> {
    let mut inside = vec![2, 1, version, 0x31, 0];
    inside.extend_from_slice(&tlv(0x30, &tlv(6, kind)));
    inside.extend_from_slice(optional);
    inside.extend_from_slice(&tlv(0x31, signers));
    let value = tlv(0x30, &inside);
    let mut envelope = tlv(6, oid::SIGNED_DATA.as_bytes());
    envelope.extend_from_slice(&tlv(0xa0, &value));
    tlv(0x30, &envelope)
}

#[test]
fn degenerate_message_and_written_empty_fields_remain_distinct() {
    // An empty signer set is the certificate/CRL transport form, not a signature success.
    for (optional, present) in [(&[][..], false), (&[0xa0, 0, 0xa1, 0][..], true)] {
        let encoded = message(1, oid::DATA.as_bytes(), optional, &[]);
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let value = SignedData::read(&parser, &encoded, 400).unwrap();
        assert_eq!(value.version(), 1);
        assert_eq!(value.required_version(), 1);
        assert!(value.signers().is_empty());
        assert!(value.certificates().is_empty());
        assert!(value.certificate_choices().is_empty());
        assert!(value.revocations().is_empty());
        assert_eq!(value.certificate_field().is_some(), present);
        assert_eq!(value.revocation_field().is_some(), present);
        assert!(value.content().is_detached());
        assert!(value.faults().is_empty());
        drop(value);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn version_ladder_preserves_opaque_choices_with_exact_precedence() {
    // Versions are derived from the actual CHOICE tags, independent of declaration.
    for (optional, required) in [
        (vec![], 1),
        (tlv(0xa0, &[0xa1, 0]), 3),
        (tlv(0xa0, &[0xa1, 0, 0xa2, 0]), 4),
        (tlv(0xa0, &[0xa2, 0, 0xa3, 5, 6, 1, 42, 5, 0]), 5),
        (tlv(0xa1, &[0xa1, 5, 6, 1, 42, 5, 0]), 5),
    ] {
        let encoded = message(required, oid::DATA.as_bytes(), &optional, &[]);
        let parser = Parser::ber(memory());
        let value = SignedData::read(&parser, &encoded, 400).unwrap();
        assert_eq!(value.required_version(), u64::from(required));
        assert!(value.faults().is_empty());
    }
    let encoded = message(3, &[42], &[], &[]);
    let parser = Parser::ber(memory());
    assert_eq!(
        SignedData::read(&parser, &encoded, 400)
            .unwrap()
            .required_version(),
        3
    );
}

#[test]
fn signers_are_retained_independently_without_a_message_verdict() {
    // An SKI signer raises the message version to 3; original signature octets survive.
    let signer = [
        0x30, 19, 2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, 8,
    ];
    let encoded = message(3, oid::DATA.as_bytes(), &[], &signer);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let value = SignedData::read(&parser, &encoded, 400).unwrap();
    assert_eq!(value.signers().len(), 1);
    assert_eq!(value.signers()[0].signature().as_one(), Some(&[8][..]));
    assert_eq!(value.required_version(), 3);
    assert!(memory.used() > 0);
    drop(value);
    assert_eq!(memory.used(), 0);
}

#[test]
fn version_fault_storage_survives_reader_and_is_released_with_result() {
    // A readable mismatch is a retained fault, not a conforming or authenticated message.
    let encoded = message(1, &[42], &[], &[]);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let value = SignedData::read(&parser, &encoded, 400).unwrap();
    assert_eq!(value.faults().len(), 1);
    assert_eq!(value.faults()[0].code(), ErrorCode::VersionMismatch);
    assert_eq!(value.faults()[0].field(), "signedData.version");
    assert!(memory.used() > 0);
    drop(value);
    assert_eq!(memory.used(), 0);
}

#[test]
fn other_format_requires_exact_identifier_and_one_value() {
    // Keeping an opaque format is not permission to accept an arbitrary wrapper.
    for entry in [vec![0xa3, 0], vec![0xa3, 7, 6, 1, 42, 5, 0, 5, 0]] {
        let encoded = message(5, oid::DATA.as_bytes(), &tlv(0xa0, &entry), &[]);
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        assert!(SignedData::read(&parser, &encoded, 400).is_err());
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn original_local_budget_refuses_catalogue_growth_before_success() {
    // Advertised algorithms, signer storage and diagnostics all share the producer ceiling.
    let encoded = message(1, &[42], &[], &[]);
    let memory = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 40,
            ..Limits::default()
        },
        memory.clone(),
    );
    let error = SignedData::read(&parser, &encoded, 400).unwrap_err();
    assert!(error.is_resource());
    drop(error);
    assert_eq!(memory.used(), 0);
    assert!(memory.work_used() <= 40);
}

#[test]
fn revocation_query_retains_original_window_depth_and_current_execution() {
    // A query from another document funds the original CMS choice, without a
    // new parser, copied bytes or a fabricated depth-zero revocation document.
    let encoded = message(1, oid::DATA.as_bytes(), &tlv(0xa1, &[0x30, 0]), &[]);
    let origin_memory = memory();
    let parser = Parser::ber(origin_memory.clone());
    let value = SignedData::read(&parser, &encoded, 400).unwrap();
    let current = memory();
    let operation = Parser::ber(current.clone());
    let query = operation.read(&[], 900).unwrap();
    let before = origin_memory.work_used();
    let mut reader = value.revocation_reader_in(&query, 0).unwrap().unwrap();
    assert_eq!(reader.depth(), 4);
    assert!(core::ptr::eq(reader.parser(), &raw const parser));
    assert!(reader.memory().same_account(&current));
    let entry = reader.next_element().unwrap().unwrap();
    assert_eq!(entry.span(), value.revocations()[0].span());
    assert_eq!(
        entry.as_bytes().as_ptr(),
        value.revocations()[0].as_bytes().as_ptr()
    );
    assert!(reader.is_empty());
    assert_eq!(origin_memory.work_used(), before);
    assert!(current.work_used() > 0);
    assert!(value.revocation_reader_in(&query, 1).unwrap().is_none());
}

#[test]
fn revocation_query_enforces_current_depth_and_local_work_before_use() {
    // Original catalogue admission is not credit for a later operation, even
    // when its aggregate account still has enough capacity and work.
    let encoded = message(1, oid::DATA.as_bytes(), &tlv(0xa1, &[0x30, 0]), &[]);
    let parser = Parser::ber(memory());
    let value = SignedData::read(&parser, &encoded, 400).unwrap();
    for limits in [
        Limits {
            max_depth: 3,
            ..Limits::default()
        },
        Limits {
            max_work: 0,
            ..Limits::default()
        },
    ] {
        let current = memory();
        let operation = Parser::new(Encoding::Ber, limits, current.clone());
        let query = operation.read(&[], 900).unwrap();
        let error = value.revocation_reader_in(&query, 0).unwrap_err();
        assert!(error.is_terminal());
        assert!(error.is_resource());
        let at = if limits.max_work == 0 {
            value.revocation_field().unwrap().start
        } else {
            value.revocations()[0].span().start
        };
        assert_eq!(error.offset(), at);
        drop(error);
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn revocation_query_preserves_exhausted_origin_and_paid_absence() {
    // A fresh external query cannot reset the already spent CMS source limit;
    // an empty catalogue likewise cannot bypass current metadata admission.
    let encoded = message(1, oid::DATA.as_bytes(), &tlv(0xa1, &[0x30, 0]), &[]);
    let measure = memory();
    let measuring_parser = Parser::ber(measure.clone());
    drop(SignedData::read(&measuring_parser, &encoded, 400).unwrap());
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: u64::try_from(measure.work_used()).unwrap(),
            ..Limits::default()
        },
        memory(),
    );
    let value = SignedData::read(&parser, &encoded, 400).unwrap();
    let operation = Parser::ber(memory());
    let query = operation.read(&[], 900).unwrap();
    let error = value.revocation_reader_in(&query, 0).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), value.revocations()[0].span().start);

    let empty = message(1, oid::DATA.as_bytes(), &[], &[]);
    let empty_parser = Parser::ber(memory());
    let value = SignedData::read(&empty_parser, &empty, 400).unwrap();
    let denied = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(),
    );
    assert!(
        value
            .revocation_reader_in(&denied.read(&[], 0).unwrap(), 0)
            .unwrap_err()
            .is_resource()
    );
    assert!(value.revocation_reader_in(&query, 0).unwrap().is_none());
}

#[test]
fn carried_ocsp_requires_the_whole_successful_envelope_not_a_basic_response() {
    // RFC5940 §3 requires successful OCSPResponse + responseBytes. The shared
    // envelope reader preserves an unknown inner response type, without trust.
    let mut response_bytes = tlv(6, &[42]);
    response_bytes.extend_from_slice(&tlv(4, &[7, 8]));
    let mut response = vec![10, 1, 0];
    response.extend_from_slice(&tlv(0xa0, &tlv(0x30, &response_bytes)));
    for kind in [oid::OCSP_RESPONSE.as_bytes(), &[42][..]] {
        let mut fields = tlv(6, kind);
        fields.extend_from_slice(&tlv(0x30, &response));
        let encoded = message(
            5,
            oid::DATA.as_bytes(),
            &tlv(0xa1, &tlv(0xa1, &fields)),
            &[],
        );
        let parser = Parser::ber(memory());
        let signed = SignedData::read(&parser, &encoded, 400).unwrap();
        let query = parser.read(&[], 900).unwrap();
        let mut reader = signed.revocation_reader_in(&query, 0).unwrap().unwrap();
        let entry = reader.next_element().unwrap().unwrap();
        let other = structured_cms::signed::OtherRevocationInfo::read(&reader, &entry).unwrap();
        assert_eq!(other.kind().as_bytes(), kind);
        let original = other.value();
        let payload = other.ocsp().unwrap();
        if kind == oid::OCSP_RESPONSE.as_bytes() {
            let payload = payload.unwrap();
            assert_eq!(payload.payload(), &[7, 8]);
            assert!(payload.span().start > original.span().start);
            assert!(payload.payload().as_ptr() >= original.as_bytes().as_ptr());
        } else {
            assert!(payload.is_none());
        }
    }
}

#[test]
fn carried_ocsp_failure_and_malformed_known_payload_are_not_opaque_absence() {
    // An unsigned responder error cannot satisfy RFC5940's successful carried
    // response rule; malformed known syntax must also retain a located failure.
    for response in [vec![0x30, 3, 10, 1, 3], vec![5, 0], vec![0x30, 3, 10, 1, 0]] {
        let mut fields = tlv(6, oid::OCSP_RESPONSE.as_bytes());
        fields.extend_from_slice(&response);
        let encoded = message(
            5,
            oid::DATA.as_bytes(),
            &tlv(0xa1, &tlv(0xa1, &fields)),
            &[],
        );
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let signed = SignedData::read(&parser, &encoded, 400).unwrap();
        let query = parser.read(&[], 900).unwrap();
        let mut reader = signed.revocation_reader_in(&query, 0).unwrap().unwrap();
        let entry = reader.next_element().unwrap().unwrap();
        let other = structured_cms::signed::OtherRevocationInfo::read(&reader, &entry).unwrap();
        let at = other.value().span().start;
        let error = other.ocsp().unwrap_err();
        assert!(error.offset() >= at);
        assert!(!error.is_resource());
        drop((error, signed));
        assert_eq!(memory.used(), 0);
    }
}
