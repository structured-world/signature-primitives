use super::{GeneralName, read_all};
use crate::error::{ErrorCode, Result};
use crate::fixtures::{context, implicit, int, oid as oid_of, seq, set, tlv, utf8};
use crate::oid;
use alloc::vec::Vec;
use structured_asn1::Parser;

fn parse<'a>(
    parser: &'a Parser,
    der: &'a [u8],
) -> Result<structured_asn1::memory::OwnedVec<GeneralName<'a>>> {
    let mut reader = parser.read(der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    read_all(&reader, &element, "test")
}

#[test]
fn each_form_of_name_is_read_as_the_tag_says() {
    let directory = seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME), utf8("Signer")])])]);
    let der = seq(&[
        implicit(1, b"signer@example.ua"),
        implicit(2, b"example.ua"),
        context(4, &[directory]),
        implicit(6, b"https://example.ua/policy"),
        implicit(7, &[192, 0, 2, 1]),
        tlv(0x88, oid::OCSP.as_bytes()),
    ]);
    let parser = Parser::der(crate::fixtures::memory());
    let names = parse(&parser, &der).unwrap();

    assert_eq!(names.len(), 6);
    assert!(matches!(names[0], GeneralName::Email("signer@example.ua")));
    assert!(matches!(names[1], GeneralName::Dns("example.ua")));
    assert!(matches!(names[3], GeneralName::Uri(_)));
    assert!(matches!(names[4], GeneralName::IpAddress([192, 0, 2, 1])));

    let GeneralName::Directory(name) = &names[2] else {
        panic!("expected a distinguished name, got {:?}", names[2]);
    };
    assert_eq!(
        name.common_name(parser.memory())
            .unwrap()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .as_ref()
            .map(|text| text.as_str(&crate::fixtures::memory()).unwrap()),
        Some("Signer")
    );

    let GeneralName::RegisteredId(identifier) = names[5] else {
        panic!("expected an identifier, got {:?}", names[5]);
    };
    assert_eq!(identifier, oid::OCSP);
}

#[test]
fn a_location_is_read_as_text_and_left_alone() {
    // Nothing here resolves it. A parser that fetched a location a document
    // named would ask a server chosen by whoever wrote the document to
    // confirm what the document says.
    let der = seq(&[implicit(6, b"http://crl.example.ua/root.crl")]);
    let parser = Parser::der(crate::fixtures::memory());
    let names = parse(&parser, &der).unwrap();

    let GeneralName::Uri(location) = names[0] else {
        panic!("expected a location, got {:?}", names[0]);
    };
    assert_eq!(location, "http://crl.example.ua/root.crl");
}

#[test]
fn a_name_of_another_kind_keeps_its_identifier_and_value() {
    let value = utf8("something");
    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&value)),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let names = parse(&parser, &der).unwrap();

    let GeneralName::Other {
        type_id,
        value: kept,
    } = names[0]
    else {
        panic!("expected another kind of name, got {:?}", names[0]);
    };
    assert_eq!(type_id, oid::USER_ID);
    assert_eq!(kept, &value[..]);
}

#[test]
fn a_directory_name_attribute_outside_its_syntax_is_refused() {
    use crate::fixtures::null;

    // A directory name here is an identity the position requires: a known
    // attribute written outside its declared syntax, a NULL or bytes that do
    // not decode where a directory string belongs, is an identity this run
    // never read, and a critical list carrying it would count as parsed.
    let with_null = seq(&[oid_of(oid::COMMON_NAME), null()]);
    let with_bad_utf8 = seq(&[oid_of(oid::COMMON_NAME), tlv(0x0c, b"\xff\xfe")]);
    for attribute in [with_null, with_bad_utf8] {
        let der = seq(&[context(4, &[seq(&[set(&[attribute])])])]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue);
    }

    // A genuine name reads, an unknown kind's value staying data.
    let unknown = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x05, 0x02]);
    let genuine = seq(&[context(
        4,
        &[seq(&[
            set(&[seq(&[oid_of(oid::COMMON_NAME), utf8("Signer")])]),
            set(&[seq(&[oid_of(unknown), tlv(0x04, &[0x01])])]),
        ])],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &genuine).is_ok());
}

#[test]
fn an_email_that_is_not_a_mailbox_is_refused() {
    // An rfc822Name is a mailbox: a local part, one at sign, a domain. A
    // bare word or a doubled separator wears the field without being an
    // address.
    let bad = [
        &b"not-an-email"[..],
        b"two@@example.ua",
        b"@example.ua",
        b"signer@",
        b"signer@bad domain",
        b"lo cal@example.ua",
    ];
    for value in bad {
        let der = seq(&[implicit(1, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    let der = seq(&[implicit(1, b"signer+tag@example.ua")]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_location_that_is_not_an_absolute_uri_is_refused() {
    // The location field holds an absolute URI: a scheme, then what the
    // scheme defines. A bare word or a relative path names no location.
    let bad = [&b"not a uri"[..], b"/relative/path", b"1http://x", b"http:"];
    for value in bad {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    for value in [&b"http://crl.example.ua/root.crl"[..], b"urn:oid:1.2.3"] {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{value:02x?}");
    }
}

#[test]
fn a_local_part_that_is_not_a_dot_string_is_refused() {
    // The local part is a dot-string: atoms of the atom alphabet separated
    // by single dots (RFC 5321 4.1.2). An empty atom, an edge dot or a
    // character the alphabet does not have names no mailbox.
    let bad = [
        &b"a..b@example.ua"[..],
        b".a@example.ua",
        b"a.@example.ua",
        b"a,b@example.ua",
        b"a\"b@example.ua",
    ];
    for value in bad {
        let der = seq(&[implicit(1, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    let der = seq(&[implicit(1, b"a.b+tag@example.ua")]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_location_outside_the_uri_grammar_is_refused() {
    // The remainder after the scheme is bounded by the URI alphabet, and a
    // percent sign spells a byte only with two hexadecimal digits behind it
    // (RFC 3986 2.1): anything else wears the field without being a URI.
    let bad = [
        &b"https:%"[..],
        b"http://x%zz",
        b"http://x\x7f",
        b"http://x%2",
    ];
    for value in bad {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    let der = seq(&[implicit(6, b"http://x/a%2Fb?q=1")]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_domain_longer_than_the_name_limit_is_refused() {
    // The whole name is bounded too: 255 octets on the wire, which leaves
    // 253 characters of presentation form (RFC 1035 2.3.4).
    let label = "a".repeat(63);
    let short = "a".repeat(61);
    let fits = [label.as_str(), &label, &label, &short].join(".");
    assert_eq!(fits.len(), 253);
    let der = seq(&[implicit(2, fits.as_bytes())]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());

    let longer = "a".repeat(62);
    let over = [label.as_str(), &label, &label, &longer].join(".");
    let der = seq(&[implicit(2, over.as_bytes())]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn reversed_x400_personal_name_members_are_refused_under_der() {
    // The personal name is a SET, and DER writes its distinct context tags
    // in ascending order: the reversed spelling is a second spelling of one
    // value and is not DER.
    let reversed = seq(&[context(
        3,
        &[seq(&[context(
            5,
            &[implicit(1, b"Given"), implicit(0, b"Surname")],
        )])],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &reversed).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedField);

    let ordered = seq(&[context(
        3,
        &[seq(&[context(
            5,
            &[implicit(0, b"Surname"), implicit(1, b"Given")],
        )])],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &ordered).is_ok());
}

#[test]
fn a_domain_that_is_not_the_preferred_name_syntax_is_refused() {
    // The dNSName form is the preferred name syntax: dot-separated labels
    // of letters, digits and inner hyphens, each of one to sixty-three
    // characters. A space, a slash, an empty label or an edge hyphen wears
    // the field without being a domain, and a critical list carrying one
    // would count as a supplied identity.
    let bad = [
        &b"bad name"[..],
        b"example/com",
        b"example..com",
        b"-example.com",
        b"example-.com",
        b".example.com",
        b"example.com.",
    ];
    for value in bad {
        let der = seq(&[implicit(2, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    // Genuine domains read, including a digit-led label.
    for value in [&b"example.ua"[..], b"1a.example.ua", b"xn--80aswg.ua"] {
        let der = seq(&[implicit(2, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{value:02x?}");
    }
}

#[test]
fn a_name_outside_the_alphabet_its_field_has_is_refused() {
    // A byte above ASCII in a field whose alphabet is ASCII. Guessing at an
    // encoding would put a domain in the report that the certificate does not
    // carry.
    let der = seq(&[implicit(2, "приклад.укр".as_bytes())]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.field(), "test");
}

#[test]
fn a_string_written_as_a_structure_is_refused() {
    // The segmented form is a second spelling of one value, and the tag says
    // which spelling this is.
    let der = seq(&[context(2, &[tlv(0x16, b"example.ua")])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn a_kind_of_name_the_schema_does_not_have_is_refused() {
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[implicit(9, b"whatever")]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // An untagged value: without the tag nothing says which kind it is.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[int(1)]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn a_list_of_no_names_is_refused() {
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[]);
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::EmptySequence);
}

#[test]
fn an_address_of_the_wrong_width_is_refused() {
    // A name holds an address of four or sixteen bytes. Anything else is not
    // an address, and returning it as one would let a malformed critical name
    // extension pass as parsed.
    for bytes in [&[192u8, 0, 2][..], &[192, 0, 2, 1, 7][..], &[][..]] {
        let der = seq(&[implicit(7, bytes)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{bytes:02x?}");
    }

    for bytes in [[192u8, 0, 2, 1].as_slice(), [0u8; 16].as_slice()] {
        let der = seq(&[implicit(7, bytes)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{bytes:02x?}");
    }
}

#[test]
fn another_kind_of_name_holds_exactly_one_value() {
    // The explicit wrapper holds the one value the identifier describes.
    // Empty it names nothing, and with a second element there is no answer to
    // which value the name is.
    let empty = seq(&[context(0, &[oid_of(oid::USER_ID), context(0, &[])])]);
    let doubled = seq(&[context(
        0,
        &[oid_of(oid::USER_ID), context(0, &[int(1), int(2)])],
    )]);

    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &empty).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MissingField);

    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &doubled).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TrailingData);
}

#[test]
fn an_empty_textual_name_names_nothing_and_is_refused() {
    // An empty address, domain or location satisfies the shape while naming
    // nothing, and a critical alternative-name extension carrying only one of
    // these would count as having supplied an identity.
    for number in [1u8, 2, 6] {
        let der = seq(&[implicit(number, b"")]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "[{number}]");
    }
}

#[test]
fn an_x400_address_is_decoded_into_its_attributes() {
    use crate::fixtures::{null, printable};

    // A NULL among the standard attributes is not one of the members the
    // schema names.
    let bad_standard = seq(&[context(3, &[seq(&[null()])])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &bad_standard).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // A network address holding a letter: NumericString is digits and space.
    let bad_network = seq(&[context(3, &[seq(&[implicit(0, b"12A")])])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &bad_network).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // A domain-defined pair holding a NULL where two printable strings
    // belong.
    let bad_domain = seq(&[context(3, &[seq(&[]), seq(&[seq(&[null()])])])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &bad_domain).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // An extension attribute without its value.
    let bad_extension = seq(&[context(
        3,
        &[seq(&[]), set(&[seq(&[implicit(0, &[0x01])])])],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &bad_extension).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MissingField);

    // The genuine full form reads: a country and a terminal identifier, one
    // domain-defined pair, one extension attribute.
    let good = seq(&[context(
        3,
        &[
            seq(&[tlv(0x61, &printable("UA")), implicit(1, b"TERMID")]),
            seq(&[seq(&[printable("type"), printable("value")])]),
            set(&[seq(&[
                implicit(0, &[0x01]),
                context(1, &[crate::fixtures::printable("v")]),
            ])]),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let names = parse(&parser, &good).unwrap();
    assert!(matches!(names[0], GeneralName::X400(_)));
}

#[test]
fn an_x400_extension_value_is_decoded_by_its_declared_type() {
    use crate::fixtures::{null, printable};
    let address = |number: &[u8], value: Vec<u8>| {
        seq(&[context(
            3,
            &[
                seq(&[]),
                set(&[seq(&[implicit(0, number), context(1, &[value])])]),
            ],
        )])
    };

    // The value's syntax is defined by the number before it: a common name
    // wrapping a NULL is not the printable string that number declares.
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &address(&[0x01], null())).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // A number the schema does not define is a value this run cannot decode.
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &address(&[0x00, 0xc8], printable("x"))).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // The genuine forms read: a common name, a terminal type, an office
    // name.
    let good = [
        address(&[0x01], printable("Signer")),
        address(&[0x17], int(3)),
        address(&[0x0a], set(&[printable("Kyiv")])),
    ];
    for der in good {
        let parser = Parser::der(crate::fixtures::memory());
        let names = parse(&parser, &der).unwrap();
        assert!(matches!(names[0], GeneralName::X400(_)));
    }
}

#[test]
fn uri_names_keep_valid_fragments_and_original_borrowed_text() {
    // RFC5280 §4.2.1.6 forbids relative URIs, not fragments. RFC3986 §3
    // URI includes fragment; §4.3 absolute-URI is a different production.
    for value in [
        "https://operator@example.com:8443/path?q=1#id",
        "https://example.test/#",
        "urn:example:document#section%20two",
    ] {
        let der = seq(&[implicit(6, value.as_bytes())]);
        let parser = Parser::der(crate::fixtures::memory());
        let names = parse(&parser, &der).unwrap();
        let GeneralName::Uri(location) = names[0] else {
            panic!("URI")
        };
        assert_eq!(location, value);
        assert!(location.as_ptr() >= der.as_ptr());
        assert!(location.as_ptr() < der.as_ptr().wrapping_add(der.len()));
    }
}

#[test]
fn malformed_uri_fragments_are_refused() {
    // RFC3986 §3.5 permits a fragment, but excludes a second raw '#' and
    // requires complete percent encodings. Relative references stay refused.
    for value in [
        "https://example.test/#first#second",
        "https://example.test/#bad%",
        "https://example.test/#bad%GG",
        "https://example.test/#raw space",
        "#fragment",
    ] {
        let der = seq(&[implicit(6, value.as_bytes())]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue);
    }
}

#[test]
fn unordered_pds_parameter_members_are_refused_under_der() {
    use crate::fixtures::printable;
    // The parameter is a SET, and DER orders its two members by tag:
    // PrintableString before TeletexString. The reversed spelling is a
    // second spelling of one value and is not DER.
    let reversed = seq(&[context(
        3,
        &[
            seq(&[]),
            set(&[seq(&[
                implicit(0, &[0x0a]),
                context(1, &[set(&[tlv(0x14, b"T"), printable("P")])]),
            ])]),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &reversed).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedField);

    let ordered = seq(&[context(
        3,
        &[
            seq(&[]),
            set(&[seq(&[
                implicit(0, &[0x0a]),
                context(1, &[set(&[printable("P"), tlv(0x14, b"T")])]),
            ])]),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &ordered).is_ok());
}

#[test]
fn unordered_unformatted_address_members_are_refused_under_der() {
    use crate::fixtures::printable;
    // The unformatted address is a SET, and DER orders its members by tag:
    // the SEQUENCE of lines before the TeletexString. The reversed spelling
    // is a second spelling of one value and is not DER.
    let reversed = seq(&[context(
        3,
        &[
            seq(&[]),
            set(&[seq(&[
                implicit(0, &[0x10]),
                context(1, &[set(&[tlv(0x14, b"T"), seq(&[printable("Line")])])]),
            ])]),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &reversed).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedField);

    let ordered = seq(&[context(
        3,
        &[
            seq(&[]),
            set(&[seq(&[
                implicit(0, &[0x10]),
                context(1, &[set(&[seq(&[printable("Line")]), tlv(0x14, b"T")])]),
            ])]),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &ordered).is_ok());
}

#[test]
fn an_oversized_edi_party_name_is_refused() {
    // Both EDI fields are directory strings bounded at 32768 characters,
    // the ub-name limit their schema carries: an identity past the bound is
    // not the field's form.
    let oversized = "a".repeat(32769);
    let party = tlv(0x0c, oversized.as_bytes());
    let der = seq(&[context(5, &[context(1, &[party])])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    let at_limit = "a".repeat(32768);
    let party = tlv(0x0c, at_limit.as_bytes());
    let der = seq(&[context(5, &[context(1, &[party])])]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn an_x400_country_outside_its_code_forms_is_refused() {
    use crate::fixtures::printable;
    // The country choice is an ISO 3166 alpha-2 code or an X.121 DCC: two
    // uppercase letters, or three digits with no space in them. A digit in
    // the letter pair, or a space in the digits, names no country.
    let bad = [tlv(0x61, &printable("A1")), tlv(0x61, &tlv(0x12, b"1 3"))];
    for country in bad {
        let der = seq(&[context(3, &[seq(&[country])])]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue);
    }

    for country in [tlv(0x61, &printable("UA")), tlv(0x61, &tlv(0x12, b"123"))] {
        let der = seq(&[context(3, &[seq(&[country])])]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok());
    }
}

#[test]
fn unordered_x400_extension_attributes_are_refused_under_der() {
    // ExtensionAttributes is a SET OF, and DER writes its members in
    // ascending encoded order: the reversed spelling is a second spelling of
    // one value and is not DER.
    let smaller = seq(&[implicit(0, &[0x17]), context(1, &[int(1)])]);
    let larger = seq(&[implicit(0, &[0x17]), context(1, &[int(2)])]);
    let reversed = seq(&[context(
        3,
        &[seq(&[]), set(&[larger.clone(), smaller.clone()])],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &reversed).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedField);

    let ordered = seq(&[context(3, &[seq(&[]), set(&[smaller, larger])])]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &ordered).is_ok());
}

#[test]
fn a_constructed_x400_string_is_refused() {
    // DER writes these strings in the primitive form only; the constructed
    // spelling is a second spelling of one value. Checking the tag's class
    // and number without its form would let one through, here as an
    // administration domain whose empty contents also satisfy the size.
    let der = seq(&[context(3, &[seq(&[tlv(0x62, &tlv(0x33, &[]))])])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn an_edi_party_string_that_does_not_decode_is_refused() {
    // The tag alone is not the type: a party name tagged UTF8String whose
    // bytes are not UTF-8, or a BMPString of odd length, holds no characters
    // and a critical list carrying it would count as parsed.
    let bad_utf8 = seq(&[context(5, &[context(1, &[tlv(0x0c, b"\xff\xfe")])])]);
    let odd_bmp = seq(&[context(5, &[context(1, &[tlv(0x1e, &[0x00, 0x04, 0x10])])])]);
    for der in [bad_utf8, odd_bmp] {
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue);
    }

    // A Cyrillic party in BMP pairs decodes and reads.
    let cyrillic = seq(&[context(
        5,
        &[context(1, &[tlv(0x1e, &[0x04, 0x23, 0x04, 0x32])])],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let names = parse(&parser, &cyrillic).unwrap();
    assert!(matches!(names[0], GeneralName::EdiParty(_)));
}

#[test]
fn an_edi_party_must_name_its_party() {
    // The party name is the structure's one mandatory member. Empty, or
    // holding only the optional assigner, the value names no party and a
    // critical list carrying it would count as parsed.
    let empty = seq(&[context(5, &[])]);
    let assigner_only = seq(&[context(5, &[context(0, &[utf8("assigner")])])]);
    for der in [empty, assigner_only] {
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MissingField);
    }

    // The full form reads: optional assigner, then the party, each wrapping
    // one string.
    let full = seq(&[context(
        5,
        &[
            context(0, &[utf8("assigner")]),
            context(1, &[utf8("party")]),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let names = parse(&parser, &full).unwrap();
    assert!(matches!(names[0], GeneralName::EdiParty(_)));

    // The structure ends at the party name, so an assigner written after it,
    // like anything else there, is bytes beyond the structure's end.
    let backwards = seq(&[context(
        5,
        &[
            context(1, &[utf8("party")]),
            context(0, &[utf8("assigner")]),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &backwards).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TrailingData);
}

#[test]
fn an_x400_address_must_hold_its_standard_attributes() {
    // An OR-address opens with its mandatory built-in standard attributes.
    // Empty, the value names nothing and a critical list carrying it would
    // count as parsed.
    let empty = seq(&[context(3, &[])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &empty).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MissingField);

    // The plausible shape reads: the standard attributes, optionally followed
    // by the domain-defined attributes and the extension attributes, each
    // sized as the schema sizes them (one to four pairs, at least one
    // extension attribute).
    let domain = seq(&[seq(&[
        crate::fixtures::printable("ab"),
        crate::fixtures::printable("cd"),
    ])]);
    let extensions = crate::fixtures::set(&[seq(&[
        implicit(0, &[0x01]),
        context(1, &[crate::fixtures::printable("v")]),
    ])]);
    let shaped = seq(&[context(3, &[seq(&[]), domain.clone(), extensions.clone()])]);
    let parser = Parser::der(crate::fixtures::memory());
    let names = parse(&parser, &shaped).unwrap();
    assert!(matches!(names[0], GeneralName::X400(_)));

    // A fourth member, or a first that is not a sequence, is not the shape.
    let overfull = seq(&[context(3, &[seq(&[]), domain, extensions, seq(&[])])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &overfull).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TrailingData);
}

#[test]
fn an_empty_directory_name_names_nobody_and_is_refused() {
    // A directory name wrapping an empty sequence of parts satisfies the
    // shape while naming nobody: a critical list carrying only it would
    // count as a supplied identity, and as a subtree base it would be an
    // active constraint over nothing.
    let der = seq(&[context(4, &[seq(&[])])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn an_all_numeric_top_level_label_is_not_a_domain() {
    // The preferred name syntax keeps the highest-level label alphabetic
    // (RFC 1123 2.1), which is what separates a host name from a
    // dotted-decimal address. An address wearing the dNSName field would
    // ride under the wrong name-constraint form.
    for value in [&b"192.0.2.1"[..], b"example.123"] {
        let der = seq(&[implicit(2, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    // A digit-led or digit-bearing top label still reads while a letter is
    // in it somewhere.
    for value in [&b"example.x1"[..], b"example.1x"] {
        let der = seq(&[implicit(2, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{value:02x?}");
    }
}

#[test]
fn unordered_network_addresses_are_refused_under_der() {
    use crate::fixtures::octets;
    // The network addresses of a presentation address are a SET OF, and DER
    // writes its members in ascending encoded order: the reversed spelling
    // is a second spelling of one value and is not DER.
    let psap = |addresses: alloc::vec::Vec<u8>| {
        seq(&[context(
            3,
            &[
                seq(&[]),
                set(&[seq(&[
                    implicit(0, &[0x16]),
                    context(1, &[context(0, &[context(3, &[addresses])])]),
                ])]),
            ],
        )])
    };

    let reversed = psap(set(&[octets(&[0x02]), octets(&[0x01])]));
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &reversed).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedField);

    let ordered = psap(set(&[octets(&[0x01]), octets(&[0x02])]));
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &ordered).is_ok());
}

#[test]
fn an_oversized_mailbox_local_part_is_refused() {
    // The local part of a mailbox is bounded at sixty-four octets
    // (RFC 5321 4.5.3.1.1); past it the field carries something the mailbox
    // grammar does not name.
    let local = "a".repeat(65);
    let long = [local.as_str(), "example.ua"].join("@");
    let der = seq(&[implicit(1, long.as_bytes())]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // Exactly at the bound still reads.
    let local = "a".repeat(64);
    let fits = [local.as_str(), "example.ua"].join("@");
    let der = seq(&[implicit(1, fits.as_bytes())]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn brackets_outside_an_ip_literal_host_are_not_a_uri() {
    // The square brackets are general delimiters whose only defined place
    // is around an IP literal in the authority (RFC 3986 3.2.2). Anywhere
    // else they are not the URI grammar, and a critical list carrying one
    // would count as a supplied location.
    let bad = [
        &b"x:["[..],
        b"http://example.ua/a[b]",
        b"http://example.ua/?q=[1]",
        b"http://[example.ua/",
        b"ldap://[2001:db8::1/dc=ua",
    ];
    for value in bad {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    // A genuine IP literal host reads, with and without a port.
    let good = [
        &b"ldap://[2001:db8::1]/dc=ua"[..],
        b"http://[::1]:8080/x",
        b"http://[v1.x]/",
    ];
    for value in good {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{value:02x?}");
    }
}

#[test]
fn an_oversized_extension_attribute_set_is_refused() {
    // ub-extension-attributes bounds the set at 256 members (RFC 5280
    // appendix A); a 257th member puts the address outside the schema.
    let attribute = |option: u32| seq(&[implicit(0, &[0x17]), context(1, &[int(option)])]);

    let attributes: Vec<_> = (0..=256).map(attribute).collect();
    let der = seq(&[context(3, &[seq(&[]), set(&attributes)])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // Exactly at the bound still reads.
    let attributes: Vec<_> = (0..256).map(attribute).collect();
    let der = seq(&[context(3, &[seq(&[]), set(&attributes)])]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_bracketed_host_that_is_not_an_ip_literal_is_refused() {
    // Inside the brackets only the two IP-literal forms exist (RFC 3986
    // 3.2.2): an IPv6 address, or the versioned future form. A word of
    // letters is neither, and a URI wearing it would count as a location.
    let bad = [
        &b"http://[garbage]/"[..],
        b"http://[12345::1]/",
        b"http://[1:2:3:4:5:6:7:8:9]/",
        b"http://[1.2.3.4]/",
        b"http://[::1::2]/",
        b"http://[v.x]/",
        b"http://[v1x]/",
        b"http://[1:2]/",
    ];
    for value in bad {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    // Genuine IPv6 spellings and the future form still read.
    let good = [
        &b"http://[::1]/"[..],
        b"http://[2001:db8::1]:8080/",
        b"http://[1:2:3:4:5:6:7:8]/",
        b"http://[::ffff:192.0.2.1]/",
        b"http://[2001:db8::192.0.2.1]/",
        b"http://[v1.x:y]/",
    ];
    for value in good {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{value:02x?}");
    }
}

#[test]
fn a_numeric_built_in_domain_defined_pair_is_refused() {
    use crate::fixtures::printable;
    // The built-in domain-defined pair holds PrintableString in both
    // members; the numeric encoding belongs to other positions and a pair
    // wearing it is outside the schema.
    let numeric = |digits: &str| tlv(0x12, digits.as_bytes());
    let bad = [
        seq(&[seq(&[numeric("1"), printable("x")])]),
        seq(&[seq(&[printable("t"), numeric("2")])]),
    ];
    for value in bad {
        let der = seq(&[context(3, &[seq(&[]), value])]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
        );
    }

    // The printable pair still reads.
    let good = seq(&[seq(&[printable("t"), printable("v")])]);
    let der = seq(&[context(3, &[seq(&[]), good])]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_malformed_uri_authority_is_refused() {
    // The authority is [userinfo "@"] host [":" port] (RFC 3986 3.2): a
    // second raw at-sign belongs to no component, a port is digits only,
    // and a colon in a bare host is the port delimiter, not a host byte.
    let bad = [
        &b"http://a@b@c/"[..],
        b"http://example.test:abc/",
        b"http://example.test:80:81/",
        b"http://ex@mple@test",
    ];
    for value in bad {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    // One userinfo, a digit port, and an empty port all stay readable.
    let good = [
        &b"http://user@example.test/"[..],
        b"http://user:pw@example.test:8080/a",
        b"http://example.test:/",
        b"ldap://example.test:389/dc=ua",
    ];
    for value in good {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{value:02x?}");
    }
}

#[test]
fn a_uri_authority_without_a_host_is_refused() {
    // "URIs that include an authority (RFC 3986, Section 3.2) MUST include a
    // fully qualified domain name or IP address as the host" (RFC 5280
    // 4.2.1.6). An empty host, or one that is neither a name nor an address,
    // names no place, and a critical list carrying one would clear the gate
    // on a location nothing can be read from.
    let bad = [
        &b"http:///status"[..],
        b"http://user@/status",
        b"http://:8080/status",
        b"http://ex_ample.test/",
        b"http://-bad.test/",
        b"http://192.0.2.1.5/",
    ];
    for value in bad {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &der).unwrap_err();
        assert_eq!(error.code(), ErrorCode::MalformedValue, "{value:02x?}");
    }

    // A name, either address form, and a URI with no authority at all stay
    // readable: the rule speaks only of URIs that include one.
    let good = [
        &b"http://example.test/a"[..],
        b"http://localhost/a",
        // The root-terminated spelling is the absolute one, and a name that
        // ends at the root is as fully qualified as a name gets.
        b"http://example.test./a",
        b"http://example.test.:8080/a",
        b"http://192.0.2.1:8080/a",
        b"http://[2001:db8::1]/a",
        b"urn:oid:1.2.3",
        b"mailto:a@example.test",
    ];
    for value in good {
        let der = seq(&[implicit(6, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{value:02x?}");
    }
}

#[test]
fn a_numeric_x400_organizational_unit_is_refused() {
    use crate::fixtures::printable;
    // An organizational-unit name is a PrintableString alone, unlike the
    // explicit numeric-or-printable choices elsewhere in the address; the
    // numeric encoding wears the position without being the type.
    let numeric = seq(&[context(3, &[seq(&[context(6, &[tlv(0x12, b"12")])])])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &numeric).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // The printable unit still reads.
    let printable_unit = seq(&[context(3, &[seq(&[context(6, &[printable("unit")])])])]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &printable_unit).is_ok());
}

#[test]
fn an_overlong_mailbox_is_refused_as_a_whole() {
    // The whole path is bounded at 256 octets including its punctuation
    // (RFC 5321 4.5.3.1.3), leaving 254 for the mailbox itself: components
    // that fit their own bounds can still exceed it together.
    let local = "a".repeat(64);
    let label = "b".repeat(63);
    let domain = [label.as_str(), &label, &label, "ua"].join(".");
    let long = [local.as_str(), &domain].join("@");
    assert!(long.len() > 254);
    let der = seq(&[implicit(1, long.as_bytes())]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn a_numeric_unformatted_postal_line_is_refused() {
    use crate::fixtures::printable;
    // Every line of the printable address is a PrintableString; the numeric
    // encoding wears the position without being the type.
    let address = |line: Vec<u8>| {
        let attribute = seq(&[implicit(0, &[0x10]), context(1, &[set(&[seq(&[line])])])]);
        seq(&[context(3, &[seq(&[]), set(&[attribute])])])
    };

    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &address(tlv(0x12, b"1"))).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // The printable line still reads.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &address(printable("line"))).is_ok());
}

#[test]
fn numeric_x400_common_and_pds_names_are_refused() {
    use crate::fixtures::printable;
    // The common name and the PDS name are PrintableString alone; the
    // numeric encoding wears either position without being the type.
    let attribute = |number: u8, value: Vec<u8>| {
        let one = seq(&[implicit(0, &[number]), context(1, &[value])]);
        seq(&[context(3, &[seq(&[]), set(&[one])])])
    };

    for number in [1u8, 7] {
        let parser = Parser::der(crate::fixtures::memory());
        let error = parse(&parser, &attribute(number, tlv(0x12, b"1"))).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            "{number}"
        );

        let parser = Parser::der(crate::fixtures::memory());
        assert!(
            parse(&parser, &attribute(number, printable("name"))).is_ok(),
            "{number}"
        );
    }
}

#[test]
fn the_network_address_ordering_is_charged_to_the_work_budget() {
    use crate::fixtures::octets;
    // The ordering of two network addresses compares their encodings byte
    // by byte: two large members sharing a prefix cost that length, and a
    // caller bounding work must see it on the meter.
    let mut big = alloc::vec![0xaau8; 50_000];
    let first = octets(&big);
    *big.last_mut().unwrap() = 0xbb;
    let second = octets(&big);
    let psap = context(0, &[context(3, &[set(&[first, second])])]);
    let attribute = seq(&[implicit(0, &[0x16]), context(1, &[psap])]);
    let der = seq(&[context(3, &[seq(&[]), set(&[attribute])])]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    // Under the default budget the same address reads.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn edi_directory_string_decoding_is_charged_to_the_work_budget() {
    // Each field's decode scans its contents, and the per-field ceiling
    // does not bound the aggregate: the scan rides on the work meter.
    let big = alloc::vec![b'a'; 100_000];
    let der = seq(&[context(5, &[context(1, &[tlv(0x0c, &big)])])]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
}

#[test]
fn the_extension_attribute_ordering_is_charged_to_the_work_budget() {
    use crate::fixtures::octets;
    // The DER ordering of the extension-attribute set compares whole
    // attribute encodings byte by byte: two large members sharing a prefix
    // cost that length before either is decoded, and a caller bounding work
    // must see it on the meter. Each attribute holds a single network
    // address, so nothing inside it reaches any other charge.
    let mut big = alloc::vec![0xaau8; 50_000];
    let psap = context(0, &[context(3, &[set(&[octets(&big)])])]);
    let first = seq(&[implicit(0, &[0x16]), context(1, &[psap])]);
    *big.last_mut().unwrap() = 0xbb;
    let psap = context(0, &[context(3, &[set(&[octets(&big)])])]);
    let second = seq(&[implicit(0, &[0x16]), context(1, &[psap])]);
    let der = seq(&[context(3, &[seq(&[]), set(&[first, second])])]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    // Under the default budget the same address reads.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_constructed_primitive_value_inside_another_name_is_refused() {
    // DER writes every universal type in the primitive form, the containers
    // aside (X.690 10.2): a constructed UTF8String wrapping the same bytes
    // is a second spelling of one value, and preserving it would let a
    // recognizer clear a malformed identity as understood.
    let inner = utf8("x");
    let constructed = tlv(0x2c, &inner);
    let der = seq(&[context(
        0,
        &[oid_of(oid::USER_ID), context(0, &[constructed])],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // The containers stay readable: a SEQUENCE value is constructed by
    // definition and is preserved as before.
    let held = seq(&[int(1)]);
    let der = seq(&[context(0, &[oid_of(oid::USER_ID), context(0, &[held])])]);
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn the_directory_name_gate_is_charged_to_the_work_budget() {
    // Deciding whether every attribute is written inside its syntax walks
    // each value, and an unbounded kind has no local ceiling: a directory
    // name in this position must put that walk on the meter.
    let big = alloc::vec![b'a'; 100_000];
    let attribute = seq(&[oid_of(oid::DOMAIN_COMPONENT), tlv(0x16, &big)]);
    let der = seq(&[context(4, &[seq(&[set(&[attribute])])])]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
}

#[test]
fn a_quoted_local_part_is_a_mailbox_too() {
    // Local-part is a dot-string or a quoted string (RFC 5321 4.1.2), and
    // the field points at that grammar, so refusing the quoted form rejects
    // an identity the profile names and blocks a certificate carrying one.
    for value in [
        &b"\"Fred Bloggs\"@example.ua"[..],
        // A quoted pair: backslash then any graphic or space.
        b"\"a\\\"b\"@example.ua",
        // An at sign inside the quotes belongs to the local part.
        b"\"a@b\"@example.ua",
    ] {
        let der = seq(&[implicit(1, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{value:02x?}");
    }

    // What the quoted grammar does not name is still refused: an unescaped
    // quote inside, a control character, and a quote that never closes.
    for value in [
        &b"\"a\"b\"@example.ua"[..],
        b"\"a\tb\"@example.ua",
        b"\"unterminated@example.ua",
    ] {
        let der = seq(&[implicit(1, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert_eq!(
            parse(&parser, &der).unwrap_err().code(),
            ErrorCode::MalformedValue,
            "{value:02x?}"
        );
    }
}

#[test]
fn mailbox_validation_preserves_an_empty_quoted_local_part() {
    // RFC 5321 §4.1.2 Quoted-string uses *QcontentSMTP, so the empty quoted
    // form is valid syntax. The borrowed syntax predicate must preserve that
    // spelling without normalizing or materializing the address.
    // https://www.rfc-editor.org/rfc/rfc5321#section-4.1.2
    let bytes = b"\x81\x0d\"\"@example.ua";
    let parser = Parser::der(crate::fixtures::memory());
    let mut reader = parser.read(bytes, 91).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let GeneralName::Email(value) = super::read(&reader, &element, "mailbox").unwrap() else {
        panic!("expected a borrowed mailbox");
    };
    assert_eq!(value, "\"\"@example.ua");
    assert_eq!(value.as_ptr(), element.contents().as_ptr());
}

#[test]
fn an_address_literal_is_a_mailbox_domain() {
    // What follows the at sign is a domain or an address literal (RFC 2821
    // 4.1.2, the grammar RFC 5280 4.2.1.6 points at). Refusing the literal
    // leaves a critical alternative-name extension unhandled over a form the
    // profile names, which blocks the certificate carrying it.
    for value in [
        &b"postmaster@[192.0.2.1]"[..],
        // Snum is one to three digits below 256, padding included: the mail
        // grammar has no leading-zero rule of its own (RFC 2821 4.1.3).
        b"postmaster@[012.0.2.1]",
        b"postmaster@[IPv6:2001:db8::1]",
        b"postmaster@[IPv6:::ffff:192.0.2.1]",
        // The tag is a literal string of the grammar, and those are read
        // without regard to case (RFC 5234 2.3), so these are the same form
        // written differently.
        b"postmaster@[ipv6:2001:db8::1]",
        b"postmaster@[IPV6:2001:db8::1]",
        // A standardized tag names an address form registered elsewhere.
        b"postmaster@[AS400:QSYS]",
    ] {
        let der = seq(&[implicit(1, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{value:02x?}");
    }

    // The bracket alphabet alone is not a literal: an address out of range,
    // a tag with nothing after its colon, brackets around a bare word, and a
    // bracket that never closes.
    for value in [
        &b"postmaster@[192.0.2.256]"[..],
        b"postmaster@[AS400:]",
        b"postmaster@[example.ua]",
        b"postmaster@[192.0.2.1",
        // The tag holds its own alternative's meaning however it is spelled:
        // read as a general tag instead, these would carry any dcontent at
        // all where the grammar asks for an address.
        b"postmaster@[ipv6:not-an-address]",
        b"postmaster@[IPV6:not-an-address]",
        b"postmaster@[IPv6:not-an-address]",
    ] {
        let der = seq(&[implicit(1, value)]);
        let parser = Parser::der(crate::fixtures::memory());
        assert_eq!(
            parse(&parser, &der).unwrap_err().code(),
            ErrorCode::MalformedValue,
            "{value:02x?}"
        );
    }
}

#[test]
fn a_preserved_other_name_is_der_all_the_way_down() {
    use crate::fixtures::cat;
    // The value of an other-name is preserved for whoever interprets it, and
    // a recognizer claiming the type clears a critical extension on the
    // strength of it. Checking only the outer tag would let a container hold
    // children that are not DER at all: a non-minimal integer here, and an
    // end-of-contents marker, which belongs to the indefinite lengths DER
    // does not have.
    let non_minimal = seq(&[tlv(0x02, &[0x00, 0x7f])]);
    let end_of_contents = seq(&[cat(&[int(1), tlv(0x00, &[])])]);
    for payload in [non_minimal, end_of_contents] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }

    // A container whose children are DER is preserved as before.
    let sound = seq(&[int(1), utf8("x")]);
    let der = seq(&[context(0, &[oid_of(oid::USER_ID), context(0, &[sound])])]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_deeply_nested_preserved_value_is_answered_rather_than_crashed() {
    // The reader's depth limit exists so that deep input is an ordinary
    // refusal. A walk that spent a machine stack frame per element would
    // turn a limit the caller raised into a crash instead, and the caller
    // that raises it is the one asking to read an unusual document, not the
    // one asking to lose the process.
    use structured_asn1::Limits;

    // Sixty thousand containers, built from the inside out so that making
    // the fixture costs its size rather than its square.
    let mut backwards: Vec<u8> = int(1).iter().rev().copied().collect();
    for _ in 0..60_000 {
        let length = backwards.len();
        if let Ok(short) = u8::try_from(length)
            && short < 0x80
        {
            backwards.push(short);
        } else {
            let bytes = length.to_be_bytes();
            let first = bytes.iter().position(|byte| *byte != 0).unwrap();
            backwards.extend(bytes[first..].iter().rev());
            backwards.push(0x80 | u8::try_from(bytes.len() - first).unwrap());
        }
        backwards.push(0x30);
    }
    backwards.reverse();
    let payload = backwards;

    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&payload)),
        ],
    )]);
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_depth: 100_000,
            ..Limits::default()
        },
        crate::fixtures::memory(),
    );
    // Whatever the answer is, there is one.
    let _ = parse(&parser, &der);

    // And the ordinary limit still refuses the same document rather than
    // reading it.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_err());
}

#[test]
fn checking_a_preserved_string_is_charged_to_the_work_budget() {
    // A preserved value has no ceiling of its own and may approach the
    // element limit, and holding a restricted string to its alphabet walks
    // every character of it. That walk rides on the same meter the reads
    // use, or a caller who bounded the work does not get the bound.
    let big = alloc::vec![b'a'; 100_000];
    let payload = tlv(0x0c, &big);
    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&payload)),
        ],
    )]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    assert_eq!(
        parse(&parser, &der).unwrap_err().code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    // Under the default budget the same value is read and preserved.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn checking_a_preserved_time_is_charged_to_the_work_budget() {
    // A time written under the encoding's rule may carry a fraction, and
    // holding that fraction to digits walks every byte of it. A preserved
    // value has no ceiling of its own, so the walk rides on the same meter
    // the reads use.
    let mut written = b"19990101000000.".to_vec();
    written.extend(core::iter::repeat_n(b'1', 100_000));
    written.push(b'Z');
    let payload = tlv(0x18, &written);
    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&payload)),
        ],
    )]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    assert_eq!(
        parse(&parser, &der).unwrap_err().code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    // Under the default budget the same value is read and preserved.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

/// One primitive universal element whose tag number is written in the long
/// form, which is how every number past thirty is written (X.690 8.1.2.4).
fn wide(number: u8, contents: &[u8]) -> alloc::vec::Vec<u8> {
    let mut der = alloc::vec![0x1f, number];
    der.extend_from_slice(&tlv(0x00, contents)[1..]);
    der
}

#[test]
fn a_preserved_identifier_written_as_a_resource_name_is_held_to_its_arcs() {
    // The contents are the arcs in UTF-8 (X.690 8.21.2 and 8.22.2), the
    // object form opening at the root and the relative one not (X.680 34.3
    // and 35.3), and each arc is a Unicode label: digits, or the characters
    // X.660 7.5.2 lists, under the rules of 7.3 and 7.5.
    for payload in [
        wide(35, b"ISO/Registration"),
        wide(35, b"/ISO//Registration"),
        wide(35, b"/ISO/Registration Authority"),
        wide(36, b"/Registration"),
        wide(36, b""),
        // A control character is in none of the ranges the label is written
        // from, and the space above is in none of them either.
        wide(35, b"/a\x00"),
        // An integer label opens with a zero only where it is that one
        // digit (7.3), and a label carries no hyphen at either end nor two
        // where a normalized form would read them as a prefix (7.5.4).
        wide(35, b"/01"),
        wide(35, b"/-abc"),
        wide(35, b"/abc-"),
        wide(35, b"/ab--c"),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }

    for payload in [
        wide(35, b"/ISO/Registration_Authority/19785.CBEFF"),
        wide(36, b"Patron-formats/TLV-encoded"),
        // The digits of an integer label, and the one that is a zero.
        wide(35, b"/2/1024/0"),
        // A label is written from a wide range of characters, and the
        // no-break space is inside it: X.680 12.1.2 names that one
        // character as the space a label may hold.
        wide(35, "/a\u{a0}b".as_bytes()),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{payload:02x?}");
    }
}

#[test]
fn a_preserved_value_of_a_newer_type_is_held_to_its_notation() {
    // The contents of these are the value notation with the characters
    // X.690 8.26 names taken out, and what each writes is settled by its
    // property settings (X.680 38.4). A payload that is not the notation is
    // not a value of the type, and a critical name must not be cleared on
    // one.
    for payload in [
        // A date that is not eight digits, one whose month is not a month,
        // and one whose day is not in its month.
        wide(31, b"foo"),
        wide(31, b"2026133"),
        wide(31, b"20261301"),
        wide(31, b"20260231"),
        // A time of day past the hours of a day, and one too short.
        wide(32, b"250000"),
        wide(32, b"1200"),
        // A date and time whose halves are each malformed.
        wide(33, b"20261301120000"),
        wide(33, b"20260101250000"),
        // A duration with no components, one whose designators run the
        // wrong way, and one with a count and no designator.
        wide(34, b""),
        wide(34, b"1M1Y"),
        wide(34, b"1Y2"),
        // A fraction ends a duration: nothing may follow the designation
        // carrying one, in its own part or in the one after it
        // (X.680 38.3.6.13).
        wide(34, b"1.5Y2M"),
        wide(34, b"1.5YT1H"),
        wide(34, b"T1.5H30M"),
        // And a count is written without a leading zero unless it is the
        // single digit zero (38.3.6.11).
        wide(34, b"01Y"),
        wide(34, b"T00.5S"),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }

    // The notation each type writes is read and preserved.
    for payload in [
        wide(31, b"20240229"),
        wide(32, b"240000"),
        wide(33, b"20260101235960"),
        wide(34, b"1Y6M4DT12H30M5S"),
        wide(34, b"3W"),
        wide(34, b"T0.5S"),
        // A fraction on the last designation present, and the single digit
        // zero, which is the one integral part that may open with one.
        wide(34, b"1Y0.5M"),
        wide(34, b"0Y"),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{payload:02x?}");
    }
}

#[test]
fn a_preserved_unrestricted_time_is_held_to_the_notation_it_writes() {
    // It carries whatever the property settings choose: a point, a
    // duration, an interval of the two, and any of them repeated, written
    // in the extended formats that keep their separators (X.680 Table 7,
    // and X.690 8.26.1.2, which takes only the quotation marks off).
    for payload in [
        tlv(0x0e, b"2026-01-01T12:00:00Z"),
        tlv(0x0e, b"2026-01-01T12:00:00.500-05:00"),
        tlv(0x0e, b"2026-W01-3"),
        tlv(0x0e, b"2026-032"),
        tlv(0x0e, b"2026-01"),
        // The day of a leap year that a common year does not have, and the
        // week a long year has and a short one does not: 2024 has 366 days
        // and 2020 has 53 weeks.
        tlv(0x0e, b"2024-366"),
        tlv(0x0e, b"2020-W53"),
        // A year too wide for a counter, written to a day its cycle has.
        tlv(0x0e, b"+999999999999-02-28"),
        tlv(0x0e, b"24:00:00"),
        tlv(0x0e, b"P1Y6M"),
        tlv(0x0e, b"2026-01-01/2026-12-31"),
        tlv(0x0e, b"2026-01-01T00:00:00Z/P1Y"),
        tlv(0x0e, b"R5/P1Y"),
        tlv(0x0e, b"R/2026-01-01/P1D"),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{payload:02x?}");
    }

    // It is held to the notation, not to its alphabet: these are written
    // from the characters the formats use and are none of the forms.
    for payload in [
        tlv(0x0e, b"foo"),
        tlv(0x0e, b"---"),
        tlv(0x0e, b"2026-13-01"),
        tlv(0x0e, b"2026-01-32"),
        tlv(0x0e, b"2026-01-00"),
        // The year decides how far its own days and weeks run: 2023 is a
        // common year of 365 days, and 2021 is a short year of 52 weeks.
        tlv(0x0e, b"2023-366"),
        tlv(0x0e, b"2021-W53"),
        // A year too wide to hold in a counter still says what its months
        // are: the calendar repeats every four hundred years, so the last
        // four digits answer both questions however long the year is.
        tlv(0x0e, b"+999999999999-02-31"),
        tlv(0x0e, b"+999999999999-366"),
        tlv(0x0e, b"25:00:00"),
        tlv(0x0e, b"12:00.5:00"),
        tlv(0x0e, b"24:30:00"),
        // The twenty-fourth hour names one instant, the end of the day, so
        // nothing written past it is inside the day: neither a fraction of
        // that hour nor a fraction of a component after it.
        tlv(0x0e, b"24.5"),
        tlv(0x0e, b"24:00:00.5"),
        tlv(0x0e, b"P1Y/P2Y"),
        tlv(0x0e, b"R5"),
        tlv(0x0e, b"2026-01-01/2026-06-01/2026-12-01"),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }
}

/// The arcs of an identifier, as the contents of one: an alternative of the
/// identification choice wears its own tag over the type it is, so what
/// arrives is the type's contents without its universal tag.
const ARC: &[u8] = &[0x2a, 0x86, 0x24, 0x08, 0x01];

/// An embedded-pdv value carrying one identification alternative and a
/// value, which is the shape its definition names (X.680 36.5).
fn embedded(identification: &[u8]) -> alloc::vec::Vec<u8> {
    tlv(
        0x2b,
        &[tlv(0xa0, identification), tlv(0x82, b"data")].concat(),
    )
}

#[test]
fn a_preserved_value_of_an_associated_sequence_type_is_held_to_it() {
    // Three universal types are encoded as a sequence defined for them: the
    // external type (X.690 8.18.1), the embedded-pdv type (X.680 36.5) and
    // the unrestricted character string (44.5). Each has components that
    // must be there, so a container of the right tag with the wrong members
    // inside is not a value of the type, and preserving one would hand a
    // scheme a value of nothing.
    let identity = oid_of(structured_asn1::Oid::from_bytes(&[
        0x2a, 0x86, 0x24, 0x08, 0x01,
    ]));
    for payload in [
        // An external value with nothing in it, so without the encoding its
        // definition ends with.
        tlv(0x28, &[]),
        // The optional members and still no encoding.
        tlv(0x28, &identity),
        // The encoding before the members that come before it.
        tlv(0x28, &[tlv(0x81, b"x"), identity.clone()].concat()),
        // A choice the definition does not have.
        tlv(0x28, &tlv(0x83, b"x")),
        // Anything after it.
        tlv(0x28, &[tlv(0x81, b"x"), tlv(0x81, b"y")].concat()),
        // An embedded-pdv value with no members, with the identification
        // alone, with an alternative the choice does not have, and with the
        // members the other way round.
        tlv(0x2b, &[]),
        tlv(0x2b, &tlv(0xa0, &tlv(0x85, &[]))),
        tlv(
            0x2b,
            &[tlv(0xa0, &tlv(0x86, &[])), tlv(0x82, b"d")].concat(),
        ),
        tlv(
            0x2b,
            &[tlv(0x82, b"d"), tlv(0xa0, &tlv(0x85, &[]))].concat(),
        ),
        // And the unrestricted character string, which is written the same
        // way and is missing the same value.
        tlv(0x3d, &tlv(0xa0, &tlv(0x85, &[]))),
        // The alternatives of the identification choice are tagged over the
        // types they are, so their contents are those types: an identifier
        // whose last byte says a byte follows it, an integer written a byte
        // longer than it needs, a null with something in it, a pair that
        // holds one identifier where it names two, and an identifier
        // written constructed.
        embedded(&tlv(0x81, &[0x80])),
        embedded(&tlv(0x82, &[0x00, 0x01])),
        embedded(&tlv(0x85, b"x")),
        embedded(&tlv(0xa0, &tlv(0x80, ARC))),
        embedded(&tlv(0xa1, ARC)),
        // The external type carries its value in one of three ways, and two
        // of them say what the contents are: bits with no count of the
        // unused ones, and a single value that is two.
        tlv(0x28, &tlv(0x82, &[])),
        tlv(0x28, &tlv(0xa0, &[int(1), int(2)].concat())),
        // The value the sequence ends with is an octet string, and the
        // distinguished rules write a string in one piece (X.690 10.2), so
        // the segmented form is a second spelling of it here.
        tlv(
            0x2b,
            &[tlv(0xa0, &tlv(0x85, &[])), tlv(0xa2, &tlv(0x04, b"d"))].concat(),
        ),
        tlv(0x28, &[tlv(0xa1, &tlv(0x04, b"d"))].concat()),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }

    // Each written the way its definition writes it.
    for payload in [
        tlv(0x28, &[identity.clone(), tlv(0x81, b"data")].concat()),
        tlv(0x28, &tlv(0xa0, &int(1))),
        tlv(
            0x2b,
            &[tlv(0xa0, &tlv(0x85, &[])), tlv(0x82, b"data")].concat(),
        ),
        tlv(
            0x3d,
            &[tlv(0xa0, &tlv(0x81, ARC)), tlv(0x82, b"text")].concat(),
        ),
        // The pair of identifiers, the negotiation that is a number and an
        // identifier, and a context named by a number.
        embedded(&tlv(0xa0, &[tlv(0x80, ARC), tlv(0x81, ARC)].concat())),
        embedded(&tlv(0xa3, &[tlv(0x80, &[0x01]), tlv(0x81, ARC)].concat())),
        embedded(&tlv(0x82, &[0x2a])),
        // Bits, with the count of the unused ones the type opens with.
        tlv(0x28, &tlv(0x82, &[0x00, 0xff])),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{payload:02x?}");
    }
}

#[test]
fn a_spent_budget_inside_an_associated_sequence_stays_a_spent_budget() {
    // A value that is not the type is an answer about the document. A
    // budget that ran out is this run giving up, and it says nothing about
    // the document at all. Reading the second as the first would tell
    // somebody their certificate is malformed when the truth is that this
    // device stopped.
    let mut arcs = alloc::vec![0x81u8; 20_000];
    arcs.push(0x01);
    let payload = embedded(&tlv(0x81, &arcs));
    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&payload)),
        ],
    )]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    assert_eq!(
        parse(&parser, &der).unwrap_err().code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    // Under the default budget the identifier is read, and what it says
    // about the value is the ordinary answer.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_preserved_teletex_value_keeps_its_negotiated_repertoire() {
    // TeletexString is T.61, whose repertoire is a negotiation this crate
    // does not implement, so the bytes being there is what is checkable and
    // the value takes part in identity as bytes. Holding it to the ASCII
    // this crate reads it as for display would refuse a legacy value the
    // schema names, which blocks the certificate carrying it.
    let legacy = tlv(0x14, &[0xc2, 0x65]);
    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&legacy)),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());

    // The types whose alphabet is fixed are still held to it: an IA5String
    // is the 128-character set and nothing wider.
    let outside = tlv(0x16, &[0xc2, 0x65]);
    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&outside)),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_err());
}

#[test]
fn a_preserved_value_of_no_universal_type_is_refused() {
    // The universal numbers are assigned in Table 1 of X.680, and three
    // ranges belong to no type: zero, which the encoding rules keep, fifteen,
    // and everything from thirty-seven up. Bytes wearing one of those claim a
    // type the standard has not defined, and preserving them would hand a
    // scheme a value of nothing while clearing a critical name.
    for payload in [
        // Reserved for the encoding rules.
        tlv(0x00, &[]),
        // Reserved for future editions.
        tlv(0x0f, &[]),
        tlv(0x2f, &[]),
        // The first of the numbers reserved for addenda, in the long form.
        alloc::vec![0x1f, 0x25, 0x00],
        // And one far past them.
        alloc::vec![0x1f, 0x81, 0x00, 0x00],
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }

    // The highest assigned number is read as before.
    let payload = alloc::vec![0x1f, 0x24, 0x01, b'1'];
    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&payload)),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_preserved_real_is_held_to_its_contents() {
    // A real value's octets are settled to the last one (X.690 8.5), and the
    // distinguished rules narrow them further: base two with no scaling
    // factor and both parts in the fewest octets, or the decimal NR3 form
    // written one way (11.3). A payload that is not a value of the type must
    // not clear a critical name.
    for payload in [
        // Decimal with a number representation the encoding does not have.
        tlv(0x09, &[0x00]),
        // NR1, where the distinguished rules ask for NR3.
        tlv(0x09, b"\x011.E+0"),
        // NR3 with nothing after the form octet.
        tlv(0x09, &[0x03]),
        // A mantissa whose first or last digit is zero.
        tlv(0x09, b"\x030.E+0"),
        tlv(0x09, b"\x0310.E+0"),
        // A sign the rules do not write: on the mantissa when it is
        // positive, and on an exponent that is not zero.
        tlv(0x09, b"\x03+1.E+0"),
        tlv(0x09, b"\x031.E+1"),
        // A zero exponent written any way but the one.
        tlv(0x09, b"\x031.E0"),
        // A special value in more than its one octet, and one the encoding
        // reserves.
        tlv(0x09, &[0x40, 0x41]),
        tlv(0x09, &[0x44]),
        // Binary with no mantissa at all.
        tlv(0x09, &[0x80, 0x01]),
        // A mantissa that is even, which the normalization forbids.
        tlv(0x09, &[0x80, 0x01, 0x02]),
        // A base and a scaling factor the distinguished rules do not use.
        tlv(0x09, &[0xa0, 0x01, 0x01]),
        tlv(0x09, &[0x88, 0x01, 0x01]),
        // An exponent and a mantissa written in more octets than they need.
        tlv(0x09, &[0x81, 0x00, 0x00, 0x01]),
        tlv(0x09, &[0x80, 0x01, 0x00, 0x01]),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }

    // Written the way the rules write it, a real is preserved.
    for payload in [
        // Plus zero, which has no octets at all.
        tlv(0x09, &[]),
        // The special values and minus zero.
        tlv(0x09, &[0x40]),
        tlv(0x09, &[0x43]),
        // Binary: base two, no scaling, a one-octet exponent, an odd
        // mantissa.
        tlv(0x09, &[0x80, 0x01, 0x01]),
        tlv(0x09, &[0xc0, 0xff, 0x03]),
        // Decimal in the one form, positive and negative.
        tlv(0x09, b"\x031.E+0"),
        tlv(0x09, b"\x03-123.E-4"),
        tlv(0x09, b"\x03105.E12"),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{payload:02x?}");
    }
}

#[test]
fn a_preserved_enumerated_or_relative_identifier_is_held_to_its_contents() {
    // Two more types whose contents the encoding settles. An enumerated
    // value is encoded as the integer it is associated with (X.690 8.4), so
    // the integer's minimality applies to it. A relative object identifier's
    // sub-identifiers are written the way an identifier's are, in the fewest
    // octets and with no leading 0x80 (8.20.2). Neither reached a check, so
    // a payload that is not DER cleared a critical name.
    for payload in [
        // ENUMERATED written a byte longer than it needs.
        tlv(0x0a, &[0x00, 0x01]),
        tlv(0x0a, &[0xff, 0x81]),
        // ENUMERATED with no contents at all.
        tlv(0x0a, &[]),
        // RELATIVE-OID with a padded sub-identifier, and one that asks for a
        // continuation that never comes.
        tlv(0x0d, &[0x80, 0x01]),
        tlv(0x0d, &[0x81]),
        tlv(0x0d, &[]),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }

    // Written the one way each is written, both are preserved.
    for payload in [
        tlv(0x0a, &[0x01]),
        tlv(0x0a, &[0x00]),
        tlv(0x0d, &[0xc2, 0x7b, 0x03, 0x02]),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{payload:02x?}");
    }
}

#[test]
fn a_preserved_time_is_read_by_the_encoding_rather_than_the_validity_field() {
    // A certificate's validity dates are a narrower grammar than the
    // encoding's: the profile writes them without a fraction (RFC 5280
    // 4.1.2.5.2). A preserved value is not a validity date, and DER writes a
    // fractional-seconds element where there is one to write (X.690 11.7.3),
    // so holding a payload to the narrower grammar refuses what the encoding
    // permits and leaves a critical name unhandled.
    for payload in [
        tlv(0x18, b"20500101000000Z"),
        tlv(0x18, b"20500101000000.5Z"),
        tlv(0x18, b"20500101000000.123Z"),
        tlv(0x17, b"500101000000Z"),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{payload:02x?}");
    }

    // What DER does not write is still refused: a fraction ending in a zero
    // or standing for zero, a missing seconds element, a form that does not
    // end in Z, and a date that is not one.
    for payload in [
        tlv(0x18, b"20500101000000.50Z"),
        tlv(0x18, b"20500101000000.0Z"),
        tlv(0x18, b"205001010000Z"),
        tlv(0x18, b"20500101000000"),
        tlv(0x18, b"20501301000000Z"),
        tlv(0x17, b"501301000000Z"),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }
}

#[test]
fn a_preserved_string_that_is_not_its_type_is_refused() {
    // A restricted string's contents are settled by its type as much as an
    // integer's are by DER: bytes that are not characters of the alphabet
    // wear the tag without being a value of it (X.680 41). A recognizer
    // clears a critical name on the strength of what is preserved, so a
    // payload that is not the type it claims must not reach one.
    for payload in [
        // UTF8String whose bytes are not UTF-8.
        tlv(0x0c, &[0xff, 0xfe]),
        // PrintableString holding a character outside the closed alphabet.
        tlv(0x13, b"a*b"),
        // IA5String with a byte above the seven-bit repertoire.
        tlv(0x16, &[0x41, 0x80]),
        // NumericString holding something that is not a digit or a space.
        tlv(0x12, b"12x"),
        // BMPString whose length is not a whole number of characters.
        tlv(0x1e, &[0x00, 0x41, 0x00]),
        // UniversalString holding a value that is not a character.
        tlv(0x1c, &[0x00, 0x00, 0xd8, 0x00]),
        // The same one level down, under a container this crate does not
        // interpret.
        seq(&[int(1), tlv(0x0c, &[0xc0, 0x80])]),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }

    // A string that is its type is preserved as before, in either width.
    for payload in [
        utf8("Київ"),
        tlv(0x13, b"Kyiv"),
        tlv(0x1e, &[0x00, 0x41, 0x00, 0x42]),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok(), "{payload:02x?}");
    }
}

#[test]
fn a_container_written_primitive_under_a_preserved_value_is_refused() {
    // The construction rule runs both ways. A string written constructed is
    // a second spelling (X.690 10.2), and a container written primitive is
    // not the type at all: a sequence and a set are constructed by
    // definition (8.9.1, 8.11.1), as are the three types whose definition is
    // an associated sequence (8.17.1, 8.18.1, 8.24.1). Checking only one
    // direction let the other reach a recognizer that clears a critical
    // name on it.
    for payload in [
        // SEQUENCE and SET without the constructed bit.
        tlv(0x10, &[]),
        tlv(0x11, &[]),
        // External, embedded-pdv and the unrestricted character string.
        tlv(0x08, &[]),
        tlv(0x0b, &[]),
        tlv(0x1d, &[]),
        // And one level down, under a container that is written correctly.
        seq(&[int(1), tlv(0x10, &[])]),
    ] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_err(), "{payload:02x?}");
    }
}

#[test]
fn a_preserved_set_out_of_order_is_refused() {
    // The members of a set appear in ascending order of their encodings
    // (X.690 11.6 for a set-of, and 10.3 puts a set's components in tag
    // order, which the same comparison decides). A payload whose set is
    // written descending is not DER, and a recognizer must not clear a
    // critical name on it.
    let descending = tlv(0x31, &[int(2), int(1)].concat());
    let ascending = tlv(0x31, &[int(1), int(2)].concat());
    for (payload, ordered) in [(descending, false), (ascending, true)] {
        let der = seq(&[context(
            0,
            &[
                oid_of(oid::USER_ID),
                context(0, core::slice::from_ref(&payload)),
            ],
        )]);
        let parser = Parser::der(crate::fixtures::memory());
        assert_eq!(parse(&parser, &der).is_ok(), ordered, "{payload:02x?}");
    }

    // A set one level down is held to the same order.
    let payload = seq(&[int(1), tlv(0x31, &[int(2), int(1)].concat())]);
    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&payload)),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_err());

    // A sequence is ordered by its schema and not by its encodings, so the
    // same members in the same order are read as written.
    let payload = seq(&[int(2), int(1)]);
    let der = seq(&[context(
        0,
        &[
            oid_of(oid::USER_ID),
            context(0, core::slice::from_ref(&payload)),
        ],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_constructed_string_under_a_preserved_other_name_is_refused() {
    // The form a check at the root alone lets through: the value itself is a
    // container, which DER does write constructed, and the string one level
    // under it is written constructed too, which DER does not (X.690 10.2).
    // Every node has to be held to the same rule, or the second spelling of
    // a value clears a critical name through the first.
    let split = tlv(0x2c, &[utf8("a"), utf8("b")].concat());
    let der = seq(&[context(
        0,
        &[oid_of(oid::USER_ID), context(0, &[seq(&[int(1), split])])],
    )]);
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_err());
}
