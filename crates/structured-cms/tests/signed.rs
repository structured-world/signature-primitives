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
