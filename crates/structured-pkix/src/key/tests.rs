use super::PublicKeyInfo;
use crate::error::{ErrorCode, Result};
use crate::fixtures::{algorithm, bits, int, oid as oid_of, seq, tlv};
use crate::oid;
use structured_asn1::Parser;

fn parse<'a>(parser: &'a Parser, der: &'a [u8]) -> Result<PublicKeyInfo<'a>> {
    let mut reader = parser.read(der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    PublicKeyInfo::read_element(&reader, &element, "test")
}

#[test]
fn a_key_is_read_with_the_algorithm_it_belongs_to() {
    let der = seq(&[
        algorithm(oid::RSA_ENCRYPTION),
        bits(&[0x30, 0x0d, 0x02, 0x01, 0x11]),
    ]);
    let parser = Parser::der(crate::fixtures::memory());
    let key = parse(&parser, &der).unwrap();

    assert_eq!(key.algorithm().algorithm(), oid::RSA_ENCRYPTION);
    assert_eq!(key.key_octets(), Some(&[0x30, 0x0d, 0x02, 0x01, 0x11][..]));
    // The whole structure, which is what a fingerprint over the key
    // information is taken of.
    assert_eq!(key.as_bytes(), &der[..]);
}

#[test]
fn a_key_that_is_not_a_whole_number_of_octets_is_read_and_says_so() {
    // No algorithm a certificate carries writes a key with padding bits. One
    // that does is read, and the octets are refused rather than invented by
    // dropping the padding.
    let der = seq(&[algorithm(oid::RSA_ENCRYPTION), tlv(0x03, &[0x03, 0xf8])]);
    let parser = Parser::der(crate::fixtures::memory());
    let key = parse(&parser, &der).unwrap();

    assert_eq!(key.key().unused_bits(), 3);
    assert_eq!(key.key().len(), 5);
    assert_eq!(key.key_octets(), None);
}

#[test]
fn a_structure_that_is_not_a_key_is_refused() {
    // No key at all.
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &seq(&[algorithm(oid::RSA_ENCRYPTION)])).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedEnd)
    );

    // A key that is not a bit string.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[algorithm(oid::RSA_ENCRYPTION), int(5)]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // An algorithm identifier that is not one.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[oid_of(oid::RSA_ENCRYPTION), bits(&[0x01])]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // Something after the key.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[algorithm(oid::RSA_ENCRYPTION), bits(&[0x01]), int(1)]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TrailingData);
}

/// Public SPKI parsing keeps the caller's exact bytes and shared element budget.
#[test]
fn standalone_key_borrows_input_and_spends_parent_budget() {
    use structured_asn1::{Encoding, Limit, Limits};

    let der = seq(&[algorithm(oid::RSA_ENCRYPTION), bits(&[1, 2, 3])]);
    let parser = Parser::der(crate::fixtures::memory());
    let mut reader = parser.read(&der, 100).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&reader, &element, "key").unwrap();
    assert_eq!(key.as_bytes().as_ptr(), der.as_ptr());
    assert_eq!(
        key.key_octets().unwrap().as_ptr(),
        der[der.len() - 3..].as_ptr()
    );

    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_elements: 1,
            ..Limits::default()
        },
        crate::fixtures::memory(),
    );
    let mut reader = parser.read(&der, 100).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = PublicKeyInfo::read_element(&reader, &element, "key").unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(Limit::Elements))
    );
}
