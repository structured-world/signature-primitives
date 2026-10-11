use super::{ExtendedKeyUsage, KeyUsage};
use crate::error::ErrorCode;
use crate::fixtures::{
    bits, extension, extension_error, int, oid as oid_of, seq, tlv, with_extension,
};
use crate::oid;

#[test]
fn the_bits_of_a_key_usage_are_read_by_what_they_mean() {
    // Bits 1 and 5: signing in a way the signer cannot later deny, and signing
    // certificates. The two bits after them are padding.
    with_extension(
        extension(oid::KEY_USAGE, true, &tlv(0x03, &[0x02, 0x44])),
        |list| {
            let usage = list.key_usage(list.memory()).unwrap().unwrap();
            assert!(!usage.digital_signature());
            assert!(usage.content_commitment());
            assert!(usage.key_cert_sign());
            assert!(!usage.crl_sign());
            // A bit past the end of what was written is not set, which is what
            // a shorter usage means.
            assert!(!usage.decipher_only());
        },
    );
}

#[test]
fn a_usage_that_permits_nothing_is_refused() {
    // Every bit zero forbids every use while claiming to permit one.
    for value in [&[0x00][..], &[0x01, 0x00][..]] {
        let error = extension_error!(
            extension(oid::KEY_USAGE, true, &tlv(0x03, value)),
            key_usage
        );

        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
        assert_eq!(error.field(), "extensions.keyUsage");
    }
}

#[test]
fn an_extension_that_cannot_be_read_is_not_a_certificate_that_cannot_be_read() {
    // The certificate is still readable and still explains itself; only the
    // one extension refuses.
    with_extension(extension(oid::KEY_USAGE, true, &int(3)), |list| {
        assert_eq!(list.len(), 1);
        let error = list.key_usage(list.memory()).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
        );
    });
}

#[test]
fn an_absent_extension_is_absent_rather_than_broken() {
    with_extension(
        extension(
            oid::SUBJECT_KEY_IDENTIFIER,
            false,
            &crate::fixtures::octets(&[0x01]),
        ),
        |list| {
            assert!(list.key_usage(list.memory()).unwrap().is_none());
            assert!(list.extended_key_usage(list.memory()).unwrap().is_none());
        },
    );
}

#[test]
fn extended_purposes_are_read_as_identifiers() {
    let value = seq(&[oid_of(oid::TIME_STAMPING), oid_of(oid::OCSP_SIGNING)]);
    with_extension(extension(oid::EXT_KEY_USAGE, false, &value), |list| {
        let purposes = list.extended_key_usage(list.memory()).unwrap().unwrap();
        assert_eq!(purposes.purposes().len(), 2);
        assert!(purposes.has(oid::TIME_STAMPING, list.memory()).unwrap());
        assert!(!purposes.has(oid::SERVER_AUTH, list.memory()).unwrap());
        // The identifier standing for any purpose is not treated as matching
        // everything: whether it does is a policy question, and answering it
        // here would hide the difference between naming a purpose and naming
        // none.
        assert!(
            !purposes
                .has(oid::ANY_EXTENDED_KEY_USAGE, list.memory())
                .unwrap()
        );
    });
}

#[test]
fn a_list_of_no_purposes_is_refused() {
    let error = extension_error!(
        extension(oid::EXT_KEY_USAGE, false, &seq(&[])),
        extended_key_usage
    );

    assert_eq!(error.code(), ErrorCode::EmptySequence);
}

#[test]
fn a_second_structure_after_the_value_is_refused() {
    // Two answers to what the extension says.
    let mut value = bits(&[0x80]);
    value.extend_from_slice(&bits(&[0x40]));
    let error = extension_error!(extension(oid::KEY_USAGE, true, &value), key_usage);

    assert_eq!(error.code(), ErrorCode::TrailingData);
}

/// The typed reading is what a caller reaches for, and it is reached through
/// the extension list rather than by handing the extension around.
#[test]
fn reading_goes_through_the_list_the_certificate_carries() {
    // digitalSignature alone, in the minimal spelling DER requires: one bit
    // of data, seven of padding.
    with_extension(
        extension(oid::KEY_USAGE, true, &tlv(0x03, &[0x07, 0x80])),
        |list| {
            let found = list.get(oid::KEY_USAGE, list.memory()).unwrap().unwrap();
            let direct = KeyUsage::read(found, list.memory()).unwrap();
            let through = list.key_usage(list.memory()).unwrap().unwrap();

            assert_eq!(direct.bits().as_bytes(), through.bits().as_bytes());
            assert!(ExtendedKeyUsage::read(found, list.memory()).is_err());
        },
    );
}

#[test]
fn a_key_usage_with_trailing_zero_bits_is_refused_under_der() {
    // DER trims a named bit list to its last set bit. keyCertSign alone is
    // one byte with two padding bits; the same value padded out with a whole
    // zero byte is a second spelling of it.
    let padded = tlv(0x03, &[0x00, 0x04, 0x00]);
    let error = extension_error!(extension(oid::KEY_USAGE, true, &padded), key_usage);
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // A set bit past decipherOnly has no name in this schema.
    let overlong = tlv(0x03, &[0x06, 0x04, 0x40]);
    let error = extension_error!(extension(oid::KEY_USAGE, true, &overlong), key_usage);
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // The minimal spelling of keyCertSign, and the full nine named bits, both
    // read.
    for value in [tlv(0x03, &[0x02, 0x04]), tlv(0x03, &[0x07, 0xff, 0x80])] {
        with_extension(extension(oid::KEY_USAGE, true, &value), |list| {
            assert!(list.key_usage(list.memory()).unwrap().is_some());
        });
    }
}
