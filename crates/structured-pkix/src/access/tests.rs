use crate::error::ErrorCode;
use crate::fixtures::{
    bits, context, extension, extension_error, implicit, int, oid as oid_of, seq, set, utf8,
    with_extension,
};
use crate::general_name::GeneralName;
use crate::oid;
use alloc::vec::Vec;

#[test]
fn published_services_are_read_with_what_sits_at_each_one() {
    let value = seq(&[
        seq(&[oid_of(oid::OCSP), implicit(6, b"http://ocsp.example.ua")]),
        seq(&[
            oid_of(oid::CA_ISSUERS),
            implicit(6, b"http://ca.example.ua/root.cer"),
        ]),
    ]);
    with_extension(
        extension(oid::AUTHORITY_INFO_ACCESS, false, &value),
        |list| {
            let access = list.authority_info_access(list.memory()).unwrap().unwrap();
            assert_eq!(access.descriptions().len(), 2);

            // Nothing here fetches either of them.
            let status: Vec<_> = access
                .locations_for(oid::OCSP, list.memory())
                .collect::<crate::Result<_>>()
                .unwrap();
            assert_eq!(status.len(), 1);
            assert!(matches!(
                status[0],
                GeneralName::Uri("http://ocsp.example.ua")
            ));

            assert_eq!(
                access
                    .locations_for(oid::CA_REPOSITORY, list.memory())
                    .collect::<crate::Result<Vec<_>>>()
                    .unwrap()
                    .len(),
                0
            );
        },
    );
}

#[test]
fn location_search_refuses_before_comparison_and_stops_after_one_error() {
    // The document controls both the number and length of method OIDs.
    // A failed admission must not yield a match or charge another next().
    use structured_asn1::memory::{Memory, MemoryAccount};
    let value = seq(&[seq(&[
        oid_of(oid::OCSP),
        implicit(6, b"http://ocsp.example.ua"),
    ])]);
    with_extension(
        extension(oid::AUTHORITY_INFO_ACCESS, false, &value),
        |list| {
            let access = list.authority_info_access(list.memory()).unwrap().unwrap();
            let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 0)));
            let mut locations = access.locations_for(oid::OCSP, &execution);
            let error = locations.next().unwrap().unwrap_err();
            assert!(error.is_resource());
            assert_eq!(execution.work_used(), 0);
            assert!(locations.next().is_none());
            assert!(locations.next().is_none());
            assert_eq!(execution.work_used(), 0);
        },
    );
}

#[test]
fn location_search_charges_only_visited_methods_and_long_query_bytes() {
    // Iterator construction and borrowed results allocate nothing. Every
    // next() admits the next comparison, including a variable-width OID.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let value = seq(&[
        seq(&[oid_of(oid::OCSP), implicit(6, b"http://ocsp.example.ua")]),
        seq(&[
            oid_of(oid::CA_ISSUERS),
            implicit(6, b"http://ca.example.ua"),
        ]),
    ]);
    with_extension(
        extension(oid::AUTHORITY_INFO_ACCESS, false, &value),
        |list| {
            let access = list.authority_info_access(list.memory()).unwrap().unwrap();
            let each = 1 + oid::OCSP.as_bytes().len();
            let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, each)));
            let mut locations = access.locations_for(oid::OCSP, &execution);
            assert_eq!(execution.work_used(), 0);
            assert!(matches!(
                locations.next().unwrap().unwrap(),
                GeneralName::Uri("http://ocsp.example.ua")
            ));
            assert_eq!(execution.work_used(), each);
            let error = locations.next().unwrap().unwrap_err();
            assert_eq!(error.offset(), access.descriptions()[1].at);
            assert!(locations.next().is_none());
            assert_eq!(execution.work_used(), each);

            let mut bytes = [0x81; 80];
            bytes[79] = 1;
            let query = structured_asn1::Oid::from_bytes(&bytes);
            let full = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 162)));
            let mut locations = access.locations_for(query, &full);
            assert!(locations.next().is_none());
            assert_eq!(full.work_used(), 162);
            assert!(locations.next().is_none());
            assert_eq!(full.work_used(), 162);
            assert_eq!(full.used(), 0);
        },
    );
}

#[test]
fn the_subject_side_is_read_the_same_way_and_says_so() {
    let error = extension_error!(
        extension(oid::SUBJECT_INFO_ACCESS, false, &int(1)),
        subject_info_access
    );

    // The field names which of the two extensions failed, because they share
    // a shape and would otherwise be indistinguishable in a report.
    assert_eq!(error.field(), "extensions.subjectInfoAccess");

    let value = seq(&[seq(&[
        oid_of(oid::TIME_STAMPING_ACCESS),
        implicit(6, b"http://tsa.example.ua"),
    ])]);
    with_extension(extension(oid::SUBJECT_INFO_ACCESS, false, &value), |list| {
        let access = list.subject_info_access(list.memory()).unwrap().unwrap();
        assert_eq!(access.descriptions()[0].method(), oid::TIME_STAMPING_ACCESS);
    });
}

#[test]
fn a_distribution_point_is_read_with_the_names_it_carries() {
    let point = seq(&[context(
        0,
        &[context(
            0,
            &[implicit(6, b"http://crl.example.ua/root.crl")],
        )],
    )]);
    with_extension(
        extension(oid::CRL_DISTRIBUTION_POINTS, false, &seq(&[point])),
        |list| {
            let points = list
                .crl_distribution_points(list.memory())
                .unwrap()
                .unwrap();
            assert_eq!(points.points().len(), 1);
            assert!(matches!(
                points.points()[0].full_name()[0],
                GeneralName::Uri("http://crl.example.ua/root.crl")
            ));
            // Absent reasons mean the list covers all of them.
            assert!(points.points()[0].reasons().is_none());
            assert!(points.points()[0].issuer().is_empty());
        },
    );
}

#[test]
fn a_crl_issuer_that_is_not_a_directory_name_is_refused() {
    // A present issuer field holds the distinguished name the list's own
    // issuer field carries, and only that: any other name form cannot be
    // matched against a list, so the point identifies no usable issuer.
    let point = seq(&[
        context(0, &[context(0, &[implicit(6, b"http://crl.example.ua")])]),
        context(2, &[implicit(2, b"crl.example.ua")]),
    ]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, true, &seq(&[point])),
        crl_distribution_points
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn empty_reason_flags_are_refused() {
    // A reasons field present with no bit set covers no reason while
    // claiming to narrow the list: a reader would take the point for a
    // partial list and a full one at once. Absent is how "all reasons" is
    // said.
    let point = seq(&[
        context(0, &[context(0, &[implicit(6, b"http://crl.example.ua")])]),
        implicit(1, &[0x00]),
    ]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, true, &seq(&[point])),
        crl_distribution_points
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn a_relative_point_name_attribute_outside_its_syntax_is_refused() {
    use crate::fixtures::null;
    // The relative name is a part of a distinguished name, and the same rule
    // holds as for a whole one: a known attribute written outside its
    // declared syntax was never read, and a critical list of points carrying
    // it would count as parsed.
    let relative = context(1, &[seq(&[oid_of(oid::COMMON_NAME), null()])]);
    let point = seq(&[context(0, &[relative])]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, true, &seq(&[point])),
        crl_distribution_points
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn a_relative_distribution_name_cannot_validate_text_past_its_budget() {
    // RelativeName parsing preserves string bytes; the later schema scan
    // must admit the long value before validating/counting its characters.
    use crate::fixtures::CertificateParts;
    use structured_asn1::{Encoding, Limits, Parser};
    let relative = context(
        1,
        &[seq(&[oid_of(oid::SURNAME), utf8(&"x".repeat(16_384))])],
    );
    let point = seq(&[context(0, &[relative])]);
    let der = CertificateParts {
        extensions: Some(seq(&[extension(
            oid::CRL_DISTRIBUTION_POINTS,
            true,
            &seq(&[point]),
        )])),
        ..CertificateParts::default()
    }
    .build();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 8192,
            ..Limits::default()
        },
        crate::fixtures::memory(),
    );
    let certificate = crate::Certificate::read(&parser, &der, 0).unwrap();
    let error = certificate
        .tbs()
        .extensions()
        .crl_distribution_points(parser.memory())
        .unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
}

#[test]
fn a_point_named_under_whoever_issues_the_list_is_read_as_a_part_of_a_name() {
    let relative = context(1, &[seq(&[oid_of(oid::COMMON_NAME), utf8("CRL 3")])]);
    let root = seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME), utf8("Root")])])]);
    let point = seq(&[
        context(0, &[relative]),
        // keyCompromise: a reason that means something, which is what makes
        // this a partial list rather than a scope naming nothing.
        implicit(1, &[0x06, 0x40]),
        context(2, &[context(4, &[root])]),
    ]);
    with_extension(
        extension(oid::CRL_DISTRIBUTION_POINTS, false, &seq(&[point])),
        |list| {
            let points = list
                .crl_distribution_points(list.memory())
                .unwrap()
                .unwrap();
            let point = &points.points()[0];

            assert!(point.full_name().is_empty());
            let part = point.name_relative_to_issuer().unwrap();
            assert_eq!(part.attributes().len(), 1);
            assert_eq!(
                part.attributes()[0]
                    .text(&crate::fixtures::memory())
                    .unwrap()
                    .as_ref()
                    .map(|text| text.as_str(&crate::fixtures::memory()).unwrap()),
                Some("CRL 3")
            );

            // A point covering only some reasons is not a list a complete
            // answer can be built from on its own, so which reasons it covers
            // is kept.
            assert!(point.reasons().unwrap().bit(1));
            assert!(!point.issuer().is_empty());
        },
    );
}

#[test]
fn the_freshest_list_is_read_in_the_same_shape_and_names_itself() {
    let error = extension_error!(extension(oid::FRESHEST_CRL, false, &seq(&[])), freshest_crl);

    assert_eq!(error.code(), ErrorCode::EmptySequence);
    assert_eq!(error.field(), "extensions.freshestCRL");
}

#[test]
fn a_description_without_a_location_is_refused() {
    let value = seq(&[seq(&[oid_of(oid::OCSP)])]);
    let error = extension_error!(
        extension(oid::AUTHORITY_INFO_ACCESS, false, &value),
        authority_info_access
    );

    assert_eq!(error.code(), ErrorCode::MissingField);
}

#[test]
fn a_point_naming_itself_two_ways_is_refused() {
    // Both the location and the part of a name, which is two answers to where
    // the list is.
    let point = seq(&[context(
        0,
        &[
            context(0, &[implicit(6, b"http://crl.example.ua/root.crl")]),
            context(1, &[seq(&[oid_of(oid::COMMON_NAME), utf8("CRL 3")])]),
        ],
    )]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, false, &seq(&[point])),
        crl_distribution_points
    );

    assert_eq!(error.code(), ErrorCode::TrailingData);
}

#[test]
fn reasons_written_as_something_other_than_bits_are_refused() {
    let point = seq(&[
        context(0, &[context(0, &[implicit(6, b"http://crl.example.ua")])]),
        context(1, &[bits(&[0x80])]),
    ]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, false, &seq(&[point])),
        crl_distribution_points
    );

    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn a_field_of_another_tag_class_is_not_a_distribution_point_field() {
    use crate::fixtures::tlv;
    // APPLICATION 0, constructed, where the point's name would be.
    let point = seq(&[tlv(
        0x60,
        &context(0, &[implicit(6, b"http://crl.example.ua")]),
    )]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, false, &seq(&[point])),
        crl_distribution_points
    );

    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn a_point_that_names_no_source_at_all_is_refused() {
    // A point must say where the list is or who issues it. Empty, or carrying
    // only the reasons, it names no source a list could be fetched from and
    // is a malformed extension rather than a parsed one.
    for value in [seq(&[seq(&[])]), seq(&[seq(&[implicit(1, &[0x01, 0x80])])])] {
        let error = extension_error!(
            extension(oid::CRL_DISTRIBUTION_POINTS, false, &value),
            crl_distribution_points
        );

        assert_eq!(error.code(), ErrorCode::MalformedValue);
    }
}

#[test]
fn a_point_name_of_another_tag_class_is_refused() {
    use crate::fixtures::tlv;
    // APPLICATION 0, constructed, where the choice inside the point's name
    // field would be. Only the class says it is not the fullName choice.
    let point = seq(&[context(
        0,
        &[tlv(0x60, &implicit(6, b"http://crl.example.ua"))],
    )]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, false, &seq(&[point])),
        crl_distribution_points
    );

    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn point_fields_written_backwards_are_refused() {
    // The issuer arriving before the point's name is not the schema's order.
    let root = seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME), utf8("Root")])])]);
    let point = seq(&[
        context(2, &[context(4, &[root])]),
        context(0, &[context(0, &[implicit(6, b"http://crl.example.ua")])]),
    ]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, false, &seq(&[point])),
        crl_distribution_points
    );

    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn point_reasons_follow_der_named_bit_minimality() {
    use crate::fixtures::tlv;
    fn point_with_reasons(reasons: &[u8]) -> Vec<u8> {
        seq(&[
            context(0, &[context(0, &[implicit(6, b"http://crl.example.ua")])]),
            // The reasons ride implicitly tagged, so the raw bit string
            // contents follow the [1] tag directly.
            tlv(0x81, reasons),
        ])
    }

    // keyCompromise alone, padded out with a zero byte: DER trims a named bit
    // list to its last set bit, so this is a second spelling.
    let padded = point_with_reasons(&[0x00, 0x40, 0x00]);
    // A set bit past aACompromise(8) has no name in ReasonFlags.
    let overlong = point_with_reasons(&[0x06, 0x40, 0x40]);
    for value in [padded, overlong] {
        let error = extension_error!(
            extension(oid::CRL_DISTRIBUTION_POINTS, false, &seq(&[value])),
            crl_distribution_points
        );
        assert_eq!(error.code(), ErrorCode::MalformedValue);
    }

    // unused(0) is a named bit of the schema, so setting it beside a reason
    // that means something is readable: what it adds is nothing, and the
    // scope still names a reason. Alone it names none, which the test above
    // this one covers.
    let beside_a_reason = point_with_reasons(&[0x06, 0xc0]);
    with_extension(
        extension(
            oid::CRL_DISTRIBUTION_POINTS,
            false,
            &seq(&[beside_a_reason]),
        ),
        |list| {
            let points = list
                .crl_distribution_points(list.memory())
                .unwrap()
                .unwrap();
            assert!(points.points()[0].reasons().unwrap().bit(0));
            assert!(points.points()[0].reasons().unwrap().bit(1));
        },
    );
}

#[test]
fn the_reason_zero_walk_is_charged_to_the_work_budget() {
    use structured_asn1::Parser;
    // The all-zero walk touches every content byte before the DER length
    // rule can refuse the string, so it rides on the work meter.
    let mut zeros = alloc::vec![0x00u8];
    zeros.extend(alloc::vec![0x00u8; 100_000]);
    let point = seq(&[
        context(0, &[context(0, &[implicit(6, b"http://crl.example.ua")])]),
        implicit(1, &zeros),
    ]);
    let der = crate::fixtures::CertificateParts {
        extensions: Some(seq(&[extension(
            oid::CRL_DISTRIBUTION_POINTS,
            true,
            &seq(&[point]),
        )])),
        ..crate::fixtures::CertificateParts::default()
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
    let certificate = crate::Certificate::read(&parser, &der, 0).unwrap();
    let error = certificate
        .tbs()
        .extensions()
        .crl_distribution_points(certificate.tbs().extensions().memory())
        .unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
}

#[test]
fn a_relative_name_beside_several_issuer_names_is_refused() {
    // "The DistributionPointName MUST NOT use the nameRelativeToCRLIssuer
    // alternative when cRLIssuer contains more than one distinguished name"
    // (RFC 5280 4.2.1.13): the fragment appends to exactly one name, and
    // with two there is no answer to which list the point names.
    let relative = context(1, &[seq(&[oid_of(oid::COMMON_NAME), utf8("CRL 3")])]);
    let one = seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME), utf8("One")])])]);
    let two = seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME), utf8("Two")])])]);
    let point = seq(&[
        context(0, &[relative]),
        context(2, &[context(4, &[one]), context(4, &[two])]),
    ]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, true, &seq(&[point])),
        crl_distribution_points
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn a_reason_scope_of_only_the_unused_bit_is_refused() {
    // ReasonFlags names bit zero "unused" (RFC 5280 4.2.1.13), so a scope
    // holding that bit alone narrows the list to a set of reasons with no
    // members: the same nothing as a scope with no bit set, which is refused
    // beside it. Reading it as understood would let a critical extension
    // pass while naming a revocation scope nobody can act on.
    let point = seq(&[
        context(0, &[context(0, &[implicit(6, b"http://crl.example.ua")])]),
        implicit(1, &[0x07, 0x80]),
    ]);
    let error = extension_error!(
        extension(oid::CRL_DISTRIBUTION_POINTS, true, &seq(&[point])),
        crl_distribution_points
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // A named reason beside it still reads: the scope means something then.
    let point = seq(&[
        context(0, &[context(0, &[implicit(6, b"http://crl.example.ua")])]),
        implicit(1, &[0x06, 0xc0]),
    ]);
    with_extension(
        extension(oid::CRL_DISTRIBUTION_POINTS, true, &seq(&[point])),
        |list| {
            assert!(
                list.crl_distribution_points(list.memory())
                    .unwrap()
                    .is_some()
            );
        },
    );
}
