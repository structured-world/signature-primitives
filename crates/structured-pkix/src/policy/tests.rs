use crate::error::ErrorCode;
use crate::fixtures::{extension, extension_error, ia5, int, oid as oid_of, seq, with_extension};
use crate::oid;
use alloc::vec;
use structured_asn1::Oid;

/// A policy an issuer defines for itself, which is what a trusted list points
/// at when it names the service that issued a certificate.
const ISSUER_POLICY: Oid<'static> = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x01, 0x02]);
const OTHER_POLICY: Oid<'static> = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x01, 0x03]);

#[test]
fn shared_notice_profiles_preserve_their_distinct_display_text_choices() {
    // RFC5280 §4.2.1.4 permits IA5String; EN319122-1 AnnexD's SPUserNotice
    // does not. Reusing the kernel must preserve BOTH normative choices.
    let parser = structured_asn1::Parser::der(crate::fixtures::memory());
    for (tag, content, ades) in [
        (22, b"A".as_slice(), false),
        (12, b"A".as_slice(), true),
        (26, b"A".as_slice(), true),
        (30, &[0, b'A'][..], true),
    ] {
        let bytes = vec![
            0x30,
            u8::try_from(content.len() + 2).unwrap(),
            tag,
            u8::try_from(content.len()).unwrap(),
        ];
        let bytes = [bytes, content.to_vec()].concat();
        let mut reader = parser.read(&bytes, 700).unwrap();
        let value = reader.next_element().unwrap().unwrap();
        assert!(super::user_notice_understood::<true>(&reader, &value).unwrap());
        assert_eq!(
            super::signature_notice_understood(&reader, &value).unwrap(),
            ades
        );
        assert_eq!(value.span().start, 700);
    }
}

#[test]
fn signature_notice_keeps_scalar_bounds_and_resource_refusals() {
    // DisplayText SIZE counts Unicode scalars, never UTF8 bytes. A paid
    // schema query must propagate exhausted work rather than saying unknown.
    let memory = crate::fixtures::memory();
    let parser = structured_asn1::Parser::der(memory.clone());
    for (count, expected) in [(0, false), (200, true), (201, false)] {
        let text = "é".repeat(count);
        let text = crate::fixtures::tlv(12, text.as_bytes());
        let bytes = seq(&[text]);
        let mut reader = parser.read(&bytes, 900).unwrap();
        let value = reader.next_element().unwrap().unwrap();
        assert_eq!(
            super::signature_notice_understood(&reader, &value).unwrap(),
            expected
        );
    }
    let bytes = [0x30, 3, 12, 1, b'A'];
    let mut reader = parser.read(&bytes, 1200).unwrap();
    let value = reader.next_element().unwrap().unwrap();
    memory.charge_work(memory.work_remaining() as u64).unwrap();
    let cause = super::signature_notice_understood(&reader, &value).unwrap_err();
    assert!(cause.is_resource());
    assert_eq!(value.as_bytes(), bytes);
}

#[test]
fn cps_pointer_does_not_inherit_certificate_name_host_requirements() {
    // RFC5280 §4.2.1.4 specifies a URI, without §4.2.1.6's certificate-name
    // host requirement. RFC3986 permits empty and percent-encoded reg-names.
    let parser = structured_asn1::Parser::der(crate::fixtures::memory());
    for uri in [
        "file:///tmp/cps",
        "https://local_host/cps",
        "https://%41.example/cps#part",
    ] {
        let value = ia5(uri);
        let qualifier = super::PolicyQualifier {
            kind: oid::CPS_QUALIFIER,
            value: &value,
            at: 101,
            outer: 0,
        };
        assert!(
            super::retained_qualifier_understood(&parser, qualifier, parser.memory()).unwrap(),
            "{uri}"
        );
    }
}

#[test]
fn lazy_policy_qualifier_keeps_its_document_depth() {
    // Isolate the lazy decoder with a tighter parser: a saved qualifier must
    // not become a root value and evade its original container depth.
    let value = seq(&[seq(&[
        oid_of(ISSUER_POLICY),
        seq(&[seq(&[
            oid_of(oid::CPS_QUALIFIER),
            ia5("https://example.ua/cps"),
        ])]),
    ])]);
    with_extension(extension(oid::CERTIFICATE_POLICIES, true, &value), |list| {
        let policies = list.certificate_policies(list.memory()).unwrap().unwrap();
        let qualifier = policies.policies()[0].qualifiers()[0];
        let limited = structured_asn1::Parser::new(
            structured_asn1::Encoding::Der,
            structured_asn1::Limits {
                max_depth: 0,
                ..structured_asn1::Limits::default()
            },
            crate::fixtures::memory(),
        );
        let error = super::retained_qualifier_understood(&limited, qualifier, limited.memory())
            .unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
                structured_asn1::Limit::Depth
            ))
        );
        assert_eq!(error.offset(), qualifier.at);
    });
}

#[test]
fn a_policy_is_read_with_whatever_was_written_beside_it() {
    let statement = ia5("https://example.ua/cps");
    let value = seq(&[seq(&[
        oid_of(ISSUER_POLICY),
        seq(&[seq(&[oid_of(oid::CPS_QUALIFIER), statement.clone()])]),
    ])]);
    with_extension(
        extension(oid::CERTIFICATE_POLICIES, false, &value),
        |list| {
            let policies = list.certificate_policies(list.memory()).unwrap().unwrap();
            assert!(policies.has(ISSUER_POLICY, list.memory()).unwrap());
            assert!(!policies.has(OTHER_POLICY, list.memory()).unwrap());

            let qualifiers = policies.policies()[0].qualifiers();
            assert_eq!(qualifiers.len(), 1);
            assert_eq!(qualifiers[0].kind(), oid::CPS_QUALIFIER);
            // The practice statement is a location, and it stays a string of
            // bytes here: nothing fetches it.
            assert_eq!(qualifiers[0].value(), &statement[..]);
        },
    );
}

#[test]
fn a_policy_without_qualifiers_is_the_usual_shape() {
    let value = seq(&[seq(&[oid_of(ISSUER_POLICY)])]);
    with_extension(
        extension(oid::CERTIFICATE_POLICIES, false, &value),
        |list| {
            let policies = list.certificate_policies(list.memory()).unwrap().unwrap();
            assert_eq!(policies.policies().len(), 1);
            assert!(policies.policies()[0].qualifiers().is_empty());
        },
    );
}

#[test]
fn the_identifier_standing_for_any_policy_is_not_treated_as_all_of_them() {
    // Whether it stands for a particular policy depends on where in a path
    // this certificate sits, which is not a question this layer can answer.
    let value = seq(&[seq(&[oid_of(oid::ANY_POLICY)])]);
    with_extension(
        extension(oid::CERTIFICATE_POLICIES, false, &value),
        |list| {
            let policies = list.certificate_policies(list.memory()).unwrap().unwrap();
            assert!(policies.has(oid::ANY_POLICY, list.memory()).unwrap());
            assert!(!policies.has(ISSUER_POLICY, list.memory()).unwrap());
        },
    );
}

#[test]
fn one_policy_written_twice_is_refused() {
    // Which qualifiers belong to it would have no answer.
    let value = seq(&[seq(&[oid_of(ISSUER_POLICY)]), seq(&[oid_of(ISSUER_POLICY)])]);
    let error = extension_error!(
        extension(oid::CERTIFICATE_POLICIES, false, &value),
        certificate_policies
    );

    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.field(), "extensions.certificatePolicies");
}

#[test]
fn a_qualifier_that_is_not_der_is_refused_before_it_is_preserved() {
    // The qualifier is kept as it was encoded and handed to whoever knows
    // the kind, on the promise that it is the encoding the document claims.
    // The outer header alone is not that promise: a value written a second
    // way one level down arrives at the same reader by the same route, and
    // the policy beside it would still read as asserted.
    use crate::fixtures::tlv;
    for qualifier in [
        // An integer written a byte longer than it needs, inside a
        // container this layer does not interpret.
        seq(&[tlv(0x02, &[0x00, 0x01])]),
        // The same one level down.
        seq(&[seq(&[tlv(0x02, &[0x00, 0x01])])]),
        // A string written the way the distinguished rules do not write one.
        seq(&[tlv(0x2c, b"\x0c\x01x")]),
        // A set whose members descend.
        tlv(0x31, &[int(2), int(1)].concat()),
    ] {
        let value = seq(&[seq(&[
            oid_of(ISSUER_POLICY),
            seq(&[seq(&[oid_of(oid::CPS_QUALIFIER), qualifier.clone()])]),
        ])]);
        extension_error!(
            extension(oid::CERTIFICATE_POLICIES, false, &value),
            certificate_policies
        );
    }

    // A qualifier that is DER is preserved exactly as before.
    let qualifier = seq(&[int(1)]);
    let value = seq(&[seq(&[
        oid_of(ISSUER_POLICY),
        seq(&[seq(&[oid_of(oid::CPS_QUALIFIER), qualifier.clone()])]),
    ])]);
    with_extension(
        extension(oid::CERTIFICATE_POLICIES, false, &value),
        |list| {
            let policies = list.certificate_policies(list.memory()).unwrap().unwrap();
            assert_eq!(
                policies.policies()[0].qualifiers()[0].value(),
                &qualifier[..]
            );
        },
    );
}

#[test]
fn a_list_of_no_policies_or_of_no_qualifiers_is_refused() {
    let error = extension_error!(
        extension(oid::CERTIFICATE_POLICIES, false, &seq(&[])),
        certificate_policies
    );
    assert_eq!(error.code(), ErrorCode::EmptySequence);

    let value = seq(&[seq(&[oid_of(ISSUER_POLICY), seq(&[])])]);
    let error = extension_error!(
        extension(oid::CERTIFICATE_POLICIES, false, &value),
        certificate_policies
    );
    assert_eq!(error.code(), ErrorCode::EmptySequence);
}

#[test]
fn a_mapping_is_read_as_the_pair_it_is() {
    let value = seq(&[seq(&[oid_of(ISSUER_POLICY), oid_of(OTHER_POLICY)])]);
    with_extension(extension(oid::POLICY_MAPPINGS, false, &value), |list| {
        let mappings = list.policy_mappings(list.memory()).unwrap().unwrap();
        assert_eq!(mappings.mappings().len(), 1);
        assert_eq!(mappings.mappings()[0].issuer_domain(), ISSUER_POLICY);
        assert_eq!(mappings.mappings()[0].subject_domain(), OTHER_POLICY);
    });
}

#[test]
fn mapping_the_identifier_that_stands_for_any_policy_is_refused() {
    // It would make every policy below this certificate equivalent to one of
    // them.
    for pair in [
        seq(&[oid_of(oid::ANY_POLICY), oid_of(OTHER_POLICY)]),
        seq(&[oid_of(ISSUER_POLICY), oid_of(oid::ANY_POLICY)]),
    ] {
        let error = extension_error!(
            extension(oid::POLICY_MAPPINGS, false, &seq(&[pair])),
            policy_mappings
        );

        assert_eq!(error.code(), ErrorCode::MalformedValue);
    }
}

#[test]
fn a_mapping_missing_half_of_the_pair_is_refused() {
    let value = seq(&[seq(&[oid_of(ISSUER_POLICY)])]);
    let error = extension_error!(
        extension(oid::POLICY_MAPPINGS, false, &value),
        policy_mappings
    );

    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedEnd)
    );
}

#[test]
fn a_policy_that_is_not_shaped_like_one_is_refused() {
    let error = extension_error!(
        extension(oid::CERTIFICATE_POLICIES, false, &int(1)),
        certificate_policies
    );

    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn one_issuer_policy_mapped_to_two_subject_policies_is_read() {
    // Path processing takes the set of subject policies equivalent to one
    // issuer policy (RFC 5280 6.1.4 (b)(1)), and a repeated issuer domain
    // with distinct subjects is the way that set is written.
    const THIRD_POLICY: Oid<'static> = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x01, 0x04]);
    let value = seq(&[
        seq(&[oid_of(ISSUER_POLICY), oid_of(OTHER_POLICY)]),
        seq(&[oid_of(ISSUER_POLICY), oid_of(THIRD_POLICY)]),
    ]);
    with_extension(extension(oid::POLICY_MAPPINGS, false, &value), |list| {
        let mappings = list.policy_mappings(list.memory()).unwrap().unwrap();
        assert_eq!(mappings.mappings().len(), 2);
        assert_eq!(mappings.mappings()[0].subject_domain(), OTHER_POLICY);
        assert_eq!(mappings.mappings()[1].subject_domain(), THIRD_POLICY);
    });
}

#[test]
fn an_identical_mapping_written_twice_reads_once() {
    // The list is a SEQUENCE OF with no uniqueness constraint, and a
    // repeated pair maps exactly what one occurrence maps: refusing it
    // would block a valid certificate. The repeat is folded away instead.
    let value = seq(&[
        seq(&[oid_of(ISSUER_POLICY), oid_of(OTHER_POLICY)]),
        seq(&[oid_of(ISSUER_POLICY), oid_of(OTHER_POLICY)]),
    ]);
    with_extension(extension(oid::POLICY_MAPPINGS, false, &value), |list| {
        let mappings = list.policy_mappings(list.memory()).unwrap().unwrap();
        assert_eq!(mappings.mappings().len(), 1);
        assert_eq!(mappings.mappings()[0].subject_domain(), OTHER_POLICY);
    });
}
