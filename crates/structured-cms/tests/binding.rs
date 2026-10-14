//! Content binding, selected algorithm protection and CMS-specific time syntax.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_cms::binding::{self, Binding, Scope};
use structured_cms::signer::SignerInfo;
use structured_cms::{ErrorCode, oid};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_048_576, 1_048_576)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    assert!(contents.len() < 128);
    let mut result = vec![tag, u8::try_from(contents.len()).unwrap()];
    result.extend_from_slice(contents);
    result
}

fn attribute(kind: Oid<'_>, value: &[u8]) -> Vec<u8> {
    let mut contents = tlv(6, kind.as_bytes());
    contents.extend_from_slice(&tlv(0x31, value));
    tlv(0x30, &contents)
}

fn signer(mut attributes: Vec<Vec<u8>>, unsigned: bool) -> Vec<u8> {
    attributes.sort();
    let attributes = attributes.concat();
    let mut contents = vec![2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42];
    if !unsigned && !attributes.is_empty() {
        contents.extend_from_slice(&tlv(0xa0, &attributes));
    }
    contents.extend_from_slice(&[0x30, 3, 6, 1, 43, 4, 1, 8]);
    if unsigned && !attributes.is_empty() {
        contents.extend_from_slice(&tlv(0xa1, &attributes));
    }
    tlv(0x30, &contents)
}

fn bound_attributes() -> Vec<Vec<u8>> {
    vec![
        attribute(oid::CONTENT_TYPE, &tlv(6, oid::DATA.as_bytes())),
        attribute(oid::MESSAGE_DIGEST, &[4, 2, 9, 10]),
    ]
}

#[test]
fn ordinary_binding_borrows_original_digest_and_protected_context_bytes() {
    // Protection is parsed, never considered matched by generic OID/byte rules.
    let mut attributes = bound_attributes();
    attributes.push(attribute(
        oid::ALGORITHM_PROTECTION,
        &[0x30, 10, 0x30, 3, 6, 1, 42, 0xa1, 3, 6, 1, 43],
    ));
    let encoded = signer(attributes, false);
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = SignerInfo::read(&reader, &element).unwrap();
    let Binding::Attributes {
        digest,
        digest_span,
        protection,
    } = binding::inspect(&value, &reader, Scope::Content(oid::DATA)).unwrap()
    else {
        panic!("attributes are present");
    };
    assert_eq!(digest, [9, 10]);
    assert_eq!(
        digest.as_ptr(),
        encoded[usize::try_from(digest_span.start - 400 + 2).unwrap()..].as_ptr()
    );
    let protection = protection.unwrap();
    assert_eq!(protection.digest().algorithm().as_bytes(), [42]);
    assert_eq!(protection.signature().algorithm().as_bytes(), [43]);
    assert_eq!(protection.signature().as_bytes(), [0xa1, 3, 6, 1, 43]);
}

#[test]
fn direct_content_is_only_valid_for_data_or_counter_signature() {
    // Missing attrs must not weaken non-id-data binding to bare raw verification.
    let encoded = signer(vec![], false);
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = SignerInfo::read(&reader, &element).unwrap();
    assert!(matches!(
        binding::inspect(&value, &reader, Scope::Content(oid::DATA)).unwrap(),
        Binding::Direct
    ));
    assert!(matches!(
        binding::inspect(&value, &reader, Scope::CounterSignature).unwrap(),
        Binding::Direct
    ));
    assert_eq!(
        binding::inspect(&value, &reader, Scope::Content(Oid::from_bytes(&[42])))
            .unwrap_err()
            .code(),
        ErrorCode::MissingField
    );
}

#[test]
fn counter_signature_requires_digest_and_forbids_content_type() {
    // Countersignatures bind parent signature bytes, which have no content type.
    let parser = Parser::ber(memory());
    let valid = signer(vec![attribute(oid::MESSAGE_DIGEST, &[4, 1, 9])], false);
    let mut reader = parser.read(&valid, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = SignerInfo::read(&reader, &element).unwrap();
    assert!(matches!(
        binding::inspect(&value, &reader, Scope::CounterSignature).unwrap(),
        Binding::Attributes { .. }
    ));
    let forbidden = signer(bound_attributes(), false);
    let mut reader = parser.read(&forbidden, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = SignerInfo::read(&reader, &element).unwrap();
    assert_eq!(
        binding::inspect(&value, &reader, Scope::CounterSignature)
            .unwrap_err()
            .code(),
        ErrorCode::AttributePlacement
    );
}

#[test]
fn signed_algorithm_protection_cannot_use_mac_or_two_choices() {
    // RFC6211 permits exactly one signature/MAC alternative; SignedData uses signature.
    for choices in [
        vec![0xa2, 3, 6, 1, 43],
        vec![0xa1, 3, 6, 1, 43, 0xa2, 3, 6, 1, 43],
    ] {
        let mut contents = vec![0x30, 3, 6, 1, 42];
        contents.extend_from_slice(&choices);
        let mut attributes = bound_attributes();
        attributes.push(attribute(oid::ALGORITHM_PROTECTION, &tlv(0x30, &contents)));
        let encoded = signer(attributes, false);
        let parser = Parser::ber(memory());
        let mut reader = parser.read(&encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let value = SignerInfo::read(&reader, &element).unwrap();
        let error = binding::inspect(&value, &reader, Scope::Content(oid::DATA)).unwrap_err();
        assert_eq!(
            error.field(),
            "signerInfo.signedAttrs.cmsAlgorithmProtection"
        );
        assert!(!error.is_resource());
    }
}

#[test]
fn recognized_cardinality_and_placement_are_not_applied_to_unknown_types() {
    // Specific RFC attributes have stronger rules than generic preserved ANYs.
    for (attributes, unsigned, expected) in [
        (
            {
                let mut a = bound_attributes();
                a.push(attribute(oid::MESSAGE_DIGEST, &[4, 2, 9, 10]));
                a
            },
            false,
            ErrorCode::AttributeCardinality,
        ),
        (
            vec![attribute(oid::CONTENT_TYPE, &tlv(6, oid::DATA.as_bytes()))],
            true,
            ErrorCode::AttributePlacement,
        ),
        (
            {
                let mut a = bound_attributes();
                a.push(attribute(oid::COUNTERSIGNATURE, &[5, 0]));
                a
            },
            false,
            ErrorCode::AttributePlacement,
        ),
    ] {
        let encoded = signer(attributes, unsigned);
        let parser = Parser::ber(memory());
        let mut reader = parser.read(&encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let value = SignerInfo::read(&reader, &element).unwrap();
        assert_eq!(
            binding::inspect(&value, &reader, Scope::Content(oid::DATA))
                .unwrap_err()
                .code(),
            expected
        );
    }
}

#[test]
fn signing_time_enforces_cms_year_choice_and_no_fraction() {
    // Generic DER GeneralizedTime allows a fraction; CMS signingTime forbids it.
    for (tag, label, valid) in [
        (0x17, &b"490101000000Z"[..], true),
        (0x18, &b"20500101000000Z"[..], true),
        (0x18, &b"19490101000000Z"[..], true),
        (0x18, &b"20260101000000Z"[..], false),
        (0x18, &b"20500101000000.1Z"[..], false),
    ] {
        let mut attributes = bound_attributes();
        attributes.push(attribute(oid::SIGNING_TIME, &tlv(tag, label)));
        let encoded = signer(attributes, false);
        let parser = Parser::ber(memory());
        let mut reader = parser.read(&encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let value = SignerInfo::read(&reader, &element).unwrap();
        let result = binding::inspect(&value, &reader, Scope::Content(oid::DATA));
        if valid {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err().code(), ErrorCode::AttributeSyntax);
        }
    }
}

#[test]
fn binding_preflight_keeps_producing_resource_failure_distinct() {
    // Exhausting the parser before lookup cannot become missing digest or mismatch.
    let encoded = signer(bound_attributes(), false);
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 4096,
            ..Limits::default()
        },
        memory(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = SignerInfo::read(&reader, &element).unwrap();
    while reader.charge(1).is_ok() {}
    let error = binding::inspect(&value, &reader, Scope::Content(oid::DATA)).unwrap_err();
    assert!(error.is_resource());
}
