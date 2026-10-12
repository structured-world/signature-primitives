use crate::error::ErrorCode;
use crate::fixtures::{
    context, extension, extension_error, implicit, int, octets, oid as oid_of, seq, set, utf8,
    with_extension,
};
use crate::general_name::GeneralName;
use crate::oid;

#[test]
fn a_subject_key_identifier_is_kept_as_the_issuer_computed_it() {
    // How it was computed is the issuer's choice and is not written down, so
    // it is compared rather than recomputed.
    with_extension(
        extension(
            oid::SUBJECT_KEY_IDENTIFIER,
            false,
            &octets(&[0xde, 0xad, 0xbe, 0xef]),
        ),
        |list| {
            let identifier = list.subject_key_identifier(list.memory()).unwrap().unwrap();
            assert_eq!(identifier.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        },
    );
}

#[test]
fn an_authority_key_identifier_is_read_with_whatever_it_carries() {
    let name = seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME), utf8("Root")])])]);
    let value = seq(&[
        implicit(0, &[0x01, 0x02]),
        context(1, &[context(4, &[name])]),
        implicit(2, &[0x0a, 0x0b]),
    ]);
    with_extension(
        extension(oid::AUTHORITY_KEY_IDENTIFIER, false, &value),
        |list| {
            let identifier = list
                .authority_key_identifier(list.memory())
                .unwrap()
                .unwrap();
            assert_eq!(identifier.key_id(), Some(&[0x01, 0x02][..]));
            assert_eq!(identifier.serial().unwrap().as_bytes(), &[0x0a, 0x0b]);
            assert!(matches!(identifier.issuer()[0], GeneralName::Directory(_)));
        },
    );
}

#[test]
fn the_key_identifier_alone_is_the_usual_shape() {
    let value = seq(&[implicit(0, &[0x01, 0x02])]);
    with_extension(
        extension(oid::AUTHORITY_KEY_IDENTIFIER, false, &value),
        |list| {
            let identifier = list
                .authority_key_identifier(list.memory())
                .unwrap()
                .unwrap();
            assert_eq!(identifier.key_id(), Some(&[0x01, 0x02][..]));
            assert!(identifier.issuer().is_empty());
            assert!(identifier.serial().is_none());
        },
    );
}

#[test]
fn a_serial_number_without_the_names_beside_it_is_refused() {
    // A serial number is unique within one issuer and names nothing without
    // it, so the two are written together or not at all.
    let value = seq(&[implicit(2, &[0x0a])]);
    let error = extension_error!(
        extension(oid::AUTHORITY_KEY_IDENTIFIER, false, &value),
        authority_key_identifier
    );

    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.field(), "extensions.authorityKeyIdentifier");
}

#[test]
fn a_field_written_twice_is_refused() {
    let value = seq(&[implicit(0, &[0x01]), implicit(0, &[0x02])]);
    let error = extension_error!(
        extension(oid::AUTHORITY_KEY_IDENTIFIER, false, &value),
        authority_key_identifier
    );

    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn an_identifier_that_is_not_shaped_like_one_is_refused() {
    // Not wrapped in a sequence.
    let error = extension_error!(
        extension(oid::AUTHORITY_KEY_IDENTIFIER, false, &int(1)),
        authority_key_identifier
    );
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // A subject key identifier that is not an octet string.
    let error = extension_error!(
        extension(oid::SUBJECT_KEY_IDENTIFIER, false, &int(1)),
        subject_key_identifier
    );
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn a_field_of_another_tag_class_is_not_a_key_identifier_field() {
    // APPLICATION 0 shares the number and construction of keyIdentifier, and
    // only the class separates them.
    use crate::fixtures::tlv;
    let value = seq(&[tlv(0x40, &[0x01, 0x02])]);
    let error = extension_error!(
        extension(oid::AUTHORITY_KEY_IDENTIFIER, false, &value),
        authority_key_identifier
    );

    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn identifier_fields_written_backwards_are_refused() {
    // The three fields are written in the order of their numbers. The key
    // identifier arriving after the issuer pair is not this schema even with
    // nothing repeated.
    let name = seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME), utf8("Root")])])]);
    let value = seq(&[
        context(1, &[context(4, &[name])]),
        implicit(2, &[0x0a]),
        implicit(0, &[0x01, 0x02]),
    ]);
    let error = extension_error!(
        extension(oid::AUTHORITY_KEY_IDENTIFIER, false, &value),
        authority_key_identifier
    );

    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn an_authority_identifier_that_identifies_nothing_is_refused() {
    // Empty, the structure names no issuing key and no certificate while
    // wearing the extension that exists to name one: at least the key
    // identifier or the complete issuer-and-serial pair is required.
    let error = extension_error!(
        extension(oid::AUTHORITY_KEY_IDENTIFIER, false, &seq(&[])),
        authority_key_identifier
    );

    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.field(), "extensions.authorityKeyIdentifier");
}

#[test]
fn an_authority_issuer_without_a_directory_name_is_refused() {
    // The issuer half of the pair stands for the issuer field of the
    // identified certificate, which is a distinguished name: a list of
    // other forms beside the serial names no certificate issuer.
    let value = seq(&[
        context(1, &[implicit(2, b"ca.example.ua")]),
        implicit(2, &[0x0a]),
    ]);
    let error = extension_error!(
        extension(oid::AUTHORITY_KEY_IDENTIFIER, false, &value),
        authority_key_identifier
    );

    assert_eq!(error.code(), ErrorCode::MalformedValue);
}
