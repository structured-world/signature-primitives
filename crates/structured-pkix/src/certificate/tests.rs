use super::{Certificate, Version};
use crate::error::{ErrorCode, Result};
use crate::fixtures::{
    CertificateParts, algorithm, bits, boolean, context, extension, implicit, int, octets,
    oid as oid_of, printable, seq, set, tlv, utc_time, utf8,
};
use crate::oid;
use alloc::vec;
use structured_asn1::Parser;

fn parse<'a>(parser: &'a Parser, der: &'a [u8]) -> Result<Certificate<'a>> {
    Certificate::read(parser, der, 0)
}

#[test]
fn a_certificate_is_read_into_what_a_decision_needs() {
    let parts = CertificateParts::default();
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();
    let tbs = certificate.tbs();

    assert_eq!(tbs.version(), Version::V3);
    assert_eq!(tbs.serial().as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        tbs.issuer()
            .common_name(parser.memory())
            .unwrap()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .as_ref()
            .map(|text| text.as_str(&crate::fixtures::memory()).unwrap()),
        Some("Test Issuer")
    );
    assert_eq!(
        tbs.subject()
            .common_name(parser.memory())
            .unwrap()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .as_ref()
            .map(|text| text.as_str(&crate::fixtures::memory()).unwrap()),
        Some("Test Subject")
    );
    assert_eq!(
        tbs.public_key().algorithm().algorithm(),
        oid::RSA_ENCRYPTION
    );
    assert_eq!(
        tbs.public_key().key_octets(),
        Some(&[0xde, 0xad, 0xbe, 0xef][..])
    );
    assert_eq!(tbs.extensions().len(), 1);
    assert!(
        tbs.extensions()
            .get(oid::BASIC_CONSTRAINTS, tbs.extensions().memory())
            .unwrap()
            .is_some()
    );
    assert_eq!(certificate.signature().octets(), Some(&[0x5f, 0x1c][..]));
}

#[test]
fn the_signed_bytes_are_the_ones_that_arrived() {
    let parts = CertificateParts::default();
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();

    // Byte for byte the signed part of the document, not a re-encoding of what
    // was understood: a signature checked over a re-encoding says nothing
    // about the file somebody was sent.
    assert_eq!(certificate.signed_bytes(), &parts.tbs()[..]);
    assert_eq!(certificate.as_bytes(), &der[..]);

    // And the span says where those bytes are, for a caller holding the whole
    // document.
    let span = certificate.tbs().span();
    let start = usize::try_from(span.start).unwrap();
    let end = usize::try_from(span.end()).unwrap();
    assert_eq!(&der[start..end], certificate.signed_bytes());
}

#[test]
fn the_interval_is_read_and_answered_as_an_interval() {
    let parts = CertificateParts::default();
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let validity = parse(&parser, &der).unwrap().tbs().validity();

    assert!(validity.is_well_ordered());
    assert_eq!(validity.not_before().seconds(), 1_704_067_200);
    assert_eq!(validity.not_after().seconds(), 1_767_225_600);

    let inside = validity.not_before();
    let outside = validity.not_after();
    assert!(validity.contains(inside));
    // Both ends are included: a certificate is valid at the moment it becomes
    // valid.
    assert!(validity.contains(outside));
    assert!(validity.covers(inside, outside));
}

#[test]
fn an_interval_that_runs_backwards_is_reported_rather_than_refused() {
    // Never valid at any moment, and still a document somebody is holding and
    // is owed an explanation of.
    let parts = CertificateParts {
        validity: seq(&[utc_time("260101000000Z"), utc_time("240101000000Z")]),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let validity = parse(&parser, &der).unwrap().tbs().validity();

    assert!(!validity.is_well_ordered());
    assert!(!validity.contains(validity.not_before()));
}

#[test]
fn a_first_version_certificate_is_read_without_the_field_that_says_so() {
    let parts = CertificateParts {
        version: None,
        extensions: None,
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();

    assert_eq!(certificate.tbs().version(), Version::V1);
    assert!(certificate.tbs().extensions().is_empty());
    assert!(certificate.tbs().issuer_unique_id().is_none());
}

#[test]
fn the_unique_identifiers_the_second_version_added_are_read() {
    let parts = CertificateParts {
        version: Some(1),
        extensions: None,
        issuer_unique_id: Some(vec![0x00, 0xab]),
        subject_unique_id: Some(vec![0x00, 0xcd]),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();

    assert_eq!(certificate.tbs().version(), Version::V2);
    assert_eq!(
        certificate.tbs().issuer_unique_id().unwrap().octets(),
        Some(&[0xab][..])
    );
    assert_eq!(
        certificate.tbs().subject_unique_id().unwrap().octets(),
        Some(&[0xcd][..])
    );
}

#[test]
fn a_field_the_version_does_not_have_is_refused() {
    // Extensions in a certificate that says it is the first version, and a
    // unique identifier in the same. Two readers would describe these
    // differently, one reading the field and one stopping at the version.
    let with_extensions = CertificateParts {
        version: None,
        ..CertificateParts::default()
    };
    let with_identifier = CertificateParts {
        version: None,
        extensions: None,
        subject_unique_id: Some(vec![0x00, 0xcd]),
        ..CertificateParts::default()
    };

    for parts in [with_extensions, with_identifier] {
        let der = parts.build();
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnexpectedField);
    }
}

#[test]
fn an_algorithm_named_outside_the_signature_must_agree_with_the_one_inside_it() {
    // The outer identifier is not covered by the signature, so trusting it
    // would let anybody rewrite which algorithm a certificate is verified
    // with.
    let parts = CertificateParts {
        outer_algorithm: algorithm(oid::EC_PUBLIC_KEY),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::AlgorithmMismatch);
    assert_eq!(error.field(), "certificate.signatureAlgorithm");
}

#[test]
fn an_absent_parameter_and_a_null_one_are_the_same_algorithm() {
    // Issuers disagree about which to write where an algorithm takes no
    // parameters, and both say the same thing.
    let parts = CertificateParts {
        outer_algorithm: seq(&[oid_of(oid::RSA_ENCRYPTION)]),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();

    assert!(certificate.signature_algorithm().has_no_parameters());
    assert!(
        certificate
            .signature_algorithm()
            .matches(&certificate.tbs().signature(), parser.memory())
            .unwrap()
    );
}

#[test]
fn different_parameters_are_not_the_same_algorithm() {
    // Same identifier, different parameters: for the algorithms that take
    // them, the parameters are half of what is being verified.
    let parts = CertificateParts {
        outer_algorithm: seq(&[oid_of(oid::RSA_ENCRYPTION), int(7)]),
        inner_algorithm: seq(&[oid_of(oid::RSA_ENCRYPTION), int(8)]),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::AlgorithmMismatch);
}

#[test]
fn a_version_this_crate_does_not_know_is_refused() {
    // A fourth version describes fields nothing here knows, and reading it as
    // the newest known one would be guessing at what the issuer meant.
    let parts = CertificateParts {
        version: Some(3),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::UnsupportedVersion);
    assert_eq!(error.field(), "certificate.tbsCertificate.version");
}

#[test]
fn a_second_document_sharing_the_file_is_refused() {
    let parts = CertificateParts::default();
    let mut der = parts.build();
    der.extend_from_slice(&parts.build());

    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TrailingData);
}

#[test]
fn a_missing_field_names_the_field_that_should_have_followed() {
    // The signed part cut short after the issuer: the interval is where the
    // reader stops, and the error says so rather than pointing at the
    // certificate as a whole.
    let parts = CertificateParts::default();
    let tbs = seq(&[
        context(0, &[int(2)]),
        parts.serial.clone(),
        parts.inner_algorithm.clone(),
        parts.issuer.clone(),
    ]);
    let der = seq(&[tbs, parts.outer_algorithm.clone(), parts.signature.clone()]);

    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MissingField);
    assert_eq!(error.field(), "certificate.tbsCertificate");
}

#[test]
fn a_malformed_field_names_itself_and_not_the_certificate() {
    let parts = CertificateParts {
        validity: seq(&[utc_time("240101000000Z"), utc_time("241301000000Z")]),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::TimeOutOfRange);
    assert_eq!(
        error.field(),
        "certificate.tbsCertificate.validity.notAfter"
    );
}

#[test]
fn a_negative_serial_number_is_read_and_reported_as_what_it_is() {
    // The profile requires a positive serial, and certificates that break the
    // rule are in use. Refusing would leave a person holding a document that
    // nothing could explain.
    let parts = CertificateParts {
        serial: tlv(0x02, &[0xff, 0x7f]),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();

    assert!(certificate.tbs().serial().is_negative());
    assert_eq!(certificate.tbs().serial().as_bytes(), &[0xff, 0x7f]);
}

#[test]
fn extensions_are_read_with_their_criticality() {
    let parts = CertificateParts {
        extensions: Some(seq(&[
            extension(oid::BASIC_CONSTRAINTS, true, &seq(&[boolean(true)])),
            extension(oid::SUBJECT_KEY_IDENTIFIER, false, &octets(&[0x01, 0x02])),
        ])),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();
    let extensions = certificate.tbs().extensions();

    assert_eq!(extensions.len(), 2);
    assert!(
        extensions
            .get(oid::BASIC_CONSTRAINTS, extensions.memory())
            .unwrap()
            .unwrap()
            .is_critical()
    );
    // Absent means false, which is how most extensions are written.
    assert!(
        !extensions
            .get(oid::SUBJECT_KEY_IDENTIFIER, extensions.memory())
            .unwrap()
            .unwrap()
            .is_critical()
    );
    assert!(
        extensions
            .get(oid::KEY_USAGE, extensions.memory())
            .unwrap()
            .is_none()
    );
}

#[test]
fn two_copies_of_one_extension_are_refused() {
    // Which of them applies would have no answer, and a reader taking the
    // first would disagree with one taking the last about what the
    // certificate says.
    let parts = CertificateParts {
        extensions: Some(seq(&[
            extension(oid::KEY_USAGE, true, &bits(&[0x80])),
            extension(oid::KEY_USAGE, false, &bits(&[0x04])),
        ])),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::DuplicateExtension);
}

#[test]
fn an_unknown_critical_extension_is_reported_rather_than_refused() {
    let unknown = structured_asn1::Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x7f]);
    let parts = CertificateParts {
        extensions: Some(seq(&[
            extension(oid::BASIC_CONSTRAINTS, true, &seq(&[boolean(true)])),
            extension(unknown, true, &octets(&[0x00])),
        ])),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();
    let extensions = certificate.tbs().extensions();

    // Refusing to read it would leave nothing to say why the verdict stopped.
    let unhandled = extensions.unhandled_critical(&(), parser.memory()).unwrap();
    assert_eq!(unhandled.len(), 1);
    assert_eq!(unhandled[0].kind(), unknown);

    // A scheme that knows the extension says so, and it stops blocking.
    let known: &[structured_asn1::Oid<'_>] = &[unknown];
    assert_eq!(
        extensions
            .unhandled_critical(&known, parser.memory())
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn an_unknown_extension_that_is_not_critical_blocks_nothing() {
    let unknown = structured_asn1::Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x7f]);
    let parts = CertificateParts {
        extensions: Some(seq(&[extension(unknown, false, &octets(&[0x00]))])),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();

    assert_eq!(
        certificate
            .tbs()
            .extensions()
            .unhandled_critical(&(), parser.memory())
            .unwrap()
            .len(),
        0
    );
    // And it is still visible, because a report says what it found.
    assert!(
        certificate
            .tbs()
            .extensions()
            .get(unknown, certificate.tbs().extensions().memory())
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_name_with_several_parts_survives_the_round_it_is_read_in() {
    let issuer = seq(&[
        set(&[seq(&[oid_of(oid::COUNTRY), printable("RO")])]),
        set(&[seq(&[oid_of(oid::ORGANIZATION), utf8("certSIGN")])]),
    ]);
    let parts = CertificateParts {
        issuer: issuer.clone(),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();

    assert_eq!(certificate.tbs().issuer().as_bytes(), &issuer[..]);
    assert_eq!(certificate.tbs().issuer().parts().len(), 2);
}

#[test]
fn an_identifier_written_where_the_extensions_belong_is_refused() {
    // The three optional fields are written in one order, and a certificate
    // that repeats one or writes them out of order is a structure this schema
    // does not have.
    let parts = CertificateParts::default();
    let tbs = seq(&[
        context(0, &[int(2)]),
        parts.serial.clone(),
        parts.inner_algorithm.clone(),
        parts.issuer.clone(),
        parts.validity.clone(),
        parts.subject.clone(),
        parts.key.clone(),
        implicit(1, &[0x00, 0xab]),
        implicit(1, &[0x00, 0xcd]),
    ]);
    let der = seq(&[tbs, parts.outer_algorithm.clone(), parts.signature.clone()]);

    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn a_budget_that_runs_out_is_not_a_broken_certificate() {
    // Telling somebody their document is damaged when this device declined to
    // finish is a different statement, and a worse one.
    let parts = CertificateParts::default();
    let der = parts.build();
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_elements: 4,
            ..structured_asn1::Limits::default()
        },
        crate::fixtures::memory(),
    );

    let error = parse(&parser, &der).unwrap_err();
    assert!(error.is_limit(), "{error}");
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Elements
        ))
    );
}

#[test]
fn trailing_fields_written_out_of_order_are_refused() {
    // The schema fixes the order: issuer identifier, subject identifier,
    // extensions. A certificate writing them backwards is not this schema,
    // even when no field repeats.
    let parts = CertificateParts::default();
    let backwards_identifiers = seq(&[
        context(0, &[int(1)]),
        parts.serial.clone(),
        parts.inner_algorithm.clone(),
        parts.issuer.clone(),
        parts.validity.clone(),
        parts.subject.clone(),
        parts.key.clone(),
        implicit(2, &[0x00, 0xcd]),
        implicit(1, &[0x00, 0xab]),
    ]);
    let extensions_first = seq(&[
        context(0, &[int(2)]),
        parts.serial.clone(),
        parts.inner_algorithm.clone(),
        parts.issuer.clone(),
        parts.validity.clone(),
        parts.subject.clone(),
        parts.key.clone(),
        context(
            3,
            &[seq(&[extension(
                oid::BASIC_CONSTRAINTS,
                true,
                &seq(&[boolean(true)]),
            )])],
        ),
        implicit(2, &[0x00, 0xcd]),
    ]);

    for tbs in [backwards_identifiers, extensions_first] {
        let der = seq(&[tbs, parts.outer_algorithm.clone(), parts.signature.clone()]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnexpectedField);
    }
}

#[test]
fn a_reversed_interval_is_covered_by_nothing() {
    // Endpoints that do not form an interval cannot be covered by one. Both
    // moments below lie inside the validity, and handing them over reversed
    // must not read as coverage.
    let parts = CertificateParts::default();
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let validity = parse(&parser, &der).unwrap().tbs().validity();

    let earlier = validity.not_before();
    let later = validity.not_after();
    assert!(validity.covers(earlier, later));
    assert!(!validity.covers(later, earlier));
}

#[test]
fn a_spelled_out_default_version_is_refused() {
    // The version defaults to v1 and DER omits a component equal to its
    // default, so a certificate writing integer zero into the version wrapper
    // is a second spelling of the absent field.
    let parts = CertificateParts {
        version: Some(0),
        extensions: None,
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.field(), "certificate.tbsCertificate.version");
}

#[test]
fn a_certificate_is_der_even_inside_a_ber_container() {
    use crate::fixtures::{cat, oid as oid_of, tlv};
    // A CMS envelope may be BER, but the certificates it carries are DER.
    // A criticality flag spelled 0x01 is a BER-only spelling of true, and a
    // reader that stayed in BER inside the certificate would accept it.
    let lenient_flag = seq(&[seq(&[
        oid_of(oid::BASIC_CONSTRAINTS),
        tlv(0x01, &[0x01]),
        octets(&seq(&[boolean(true)])),
    ])]);
    let parts = CertificateParts {
        extensions: Some(lenient_flag),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::ber(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::MalformedBoolean)
    );

    // And the certificate's own header follows the same rule: an indefinite
    // outer sequence is BER, not a certificate.
    let parts = CertificateParts::default();
    let body = cat(&[
        parts.tbs(),
        parts.outer_algorithm.clone(),
        parts.signature.clone(),
    ]);
    let indefinite = cat(&[vec![0x30, 0x80], body, vec![0x00, 0x00]]);
    let parser = Parser::ber(crate::fixtures::memory());
    let error = parse(&parser, &indefinite).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::IndefiniteLengthNotAllowed)
    );
}

#[test]
fn an_empty_issuer_name_is_refused() {
    // An empty subject is allowed when the alternative name carries the
    // identity; an empty issuer names no authority at all, and two
    // identically empty names compare equal, so a certificate with one could
    // chain to a CA with an empty subject.
    let parts = CertificateParts {
        issuer: seq(&[]),
        ..CertificateParts::default()
    };
    let der = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::EmptySequence);
    assert_eq!(error.field(), "certificate.tbsCertificate.issuer");
}

#[test]
fn an_empty_subject_requires_a_critical_alternative_name() {
    // The subject may be empty only when the identity lives in the
    // alternative name, and then that extension must be present and marked
    // critical (RFC 5280 4.2.1.6). Absent, or present without the mark, the
    // certificate names nobody while reading as a supplied identity.
    let name_value = seq(&[implicit(2, b"example.ua")]);
    let no_san = CertificateParts {
        subject: seq(&[]),
        extensions: Some(seq(&[extension(oid::BASIC_CONSTRAINTS, true, &seq(&[]))])),
        ..CertificateParts::default()
    };
    let lax_san = CertificateParts {
        subject: seq(&[]),
        extensions: Some(seq(&[extension(oid::SUBJECT_ALT_NAME, false, &name_value)])),
        ..CertificateParts::default()
    };
    for parts in [no_san, lax_san] {
        let der = parts.build();
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MissingField);
        assert_eq!(error.field(), "certificate.tbsCertificate.subject");
    }

    // With the critical alternative name the empty subject reads.
    let with_san = CertificateParts {
        subject: seq(&[]),
        extensions: Some(seq(&[extension(oid::SUBJECT_ALT_NAME, true, &name_value)])),
        ..CertificateParts::default()
    };
    let der = with_san.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = parse(&parser, &der).unwrap();
    assert!(certificate.tbs().subject().is_empty());
}

#[test]
fn the_algorithm_parameter_comparison_is_charged_to_the_work_budget() {
    use crate::fixtures::{oid as oid_of, seq, tlv};
    // The inner and outer identifiers must agree, and agreeing is a byte
    // comparison over parameters that are opaque and have no local ceiling:
    // two large ones sharing a prefix cost that length, and a caller
    // bounding work must see it on the meter.
    let parameters = tlv(0x04, &vec![0xaa; 50_000]);
    let identifier = seq(&[oid_of(oid::RSA_ENCRYPTION), parameters]);
    let der = CertificateParts {
        inner_algorithm: identifier.clone(),
        outer_algorithm: identifier,
        ..CertificateParts::default()
    }
    .build();

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let error = Certificate::read(&parser, &der, 0).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    // Under the default budget the same certificate reads.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(Certificate::read(&parser, &der, 0).is_ok());
}
