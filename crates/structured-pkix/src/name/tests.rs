use super::{Encoding, Name, read};
use crate::error::{ErrorCode, Result};
use crate::fixtures::{cat, ia5, int, oid as oid_of, printable, seq, set, tlv, utf8};
use crate::oid;
use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use structured_asn1::{Oid, Parser};

fn parse<'a>(parser: &'a Parser, der: &'a [u8]) -> Result<Name<'a>> {
    let mut reader = parser.read(der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    read(&reader, &element, "test")
}

#[test]
fn ia5_name_attributes_use_their_exact_case_insensitive_rules() {
    // DN emailAddress is whole-value case-insensitive (RFC2985 §§5.2.1,
    // 6.1), unlike GeneralName.rfc822Name. Neither that rule nor RFC5280
    // §7.3's exact DC comparison compresses DirectoryString whitespace.
    for (kind, left, right, matches) in [
        (
            oid::EMAIL_ADDRESS,
            "USER@EXAMPLE.COM",
            "user@example.com",
            true,
        ),
        (
            oid::EMAIL_ADDRESS,
            " user@example.com",
            "user@example.com",
            false,
        ),
        (
            oid::EMAIL_ADDRESS,
            "user@ example.com",
            "user@  example.com",
            false,
        ),
        (oid::DOMAIN_COMPONENT, "EXAMPLE", "example", true),
        (oid::DOMAIN_COMPONENT, "example ", "example", false),
    ] {
        let left_der = seq(&[part(kind, ia5(left))]);
        let right_der = seq(&[part(kind, ia5(right))]);
        let parser = Parser::der(crate::fixtures::memory());
        let left = parse(&parser, &left_der).unwrap();
        let right = parse(&parser, &right_der).unwrap();
        let execution = crate::fixtures::memory();
        assert_eq!(left.matches(&right, &execution).unwrap(), matches);
        assert_eq!(left.order(&right, &execution).unwrap().is_eq(), matches);
        assert_eq!(
            left.ordered(&execution)
                .unwrap()
                .order(&right.ordered(&execution).unwrap(), &execution)
                .unwrap()
                .is_eq(),
            matches
        );
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn opaque_der_walk_admits_its_stack_before_allocating() {
    // The entered Reader's one path index fits, but the explicit traversal
    // stack does not. Empty constructed input must still refuse that storage.
    use alloc::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};
    let memory = Memory::new(Arc::new(MemoryAccount::new(16, 1024)));
    let parser = Parser::der(memory.clone());
    let mut reader = parser.read(&[0x30, 0], 73).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = super::walk_der(&reader, &element, "opaque", super::Strings::Checked)
        .expect_err("the traversal stack exceeds the remaining capacity");
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Memory
        ))
    );
    assert_eq!(error.offset(), 73);
    assert_eq!(memory.used(), 0);
}

/// One attribute, as a part of a name holding only it.
fn part(kind: Oid<'_>, value: Vec<u8>) -> Vec<u8> {
    set(&[seq(&[oid_of(kind), value])])
}

#[test]
fn displayed_text_retains_its_capacity_charge() {
    // A retained display string must keep its allocation charged after the
    // parser is released, then release exactly that storage on drop.
    let memory = crate::fixtures::memory();
    let parser = Parser::der(memory.clone());
    let der = seq(&[part(oid::COMMON_NAME, utf8("Retained subject"))]);
    let name = parse(&parser, &der).unwrap();
    let before = memory.used();
    let text = name
        .common_name(&crate::fixtures::memory())
        .unwrap()
        .unwrap()
        .text(&memory)
        .unwrap()
        .unwrap();
    assert!(memory.used() > before);
    drop(name);
    drop(parser);
    assert!(memory.used() > 0);
    drop(text);
    assert_eq!(memory.used(), 0);
}

#[test]
fn parsed_name_retains_its_descriptor_storage() {
    // RDN and attribute descriptor capacity belongs to the returned view,
    // rather than disappearing from accounting when its Reader is released.
    let memory = crate::fixtures::memory();
    let parser = Parser::der(memory.clone());
    let der = seq(&[part(oid::COMMON_NAME, utf8("Subject"))]);
    let mut reader = parser.read(&der, 81).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let name = read(&reader, &element, "subject").unwrap();
    drop(reader);
    assert!(memory.used() > 0);
    drop(name);
    drop(parser);
    assert_eq!(memory.used(), 0);
}

#[test]
fn attribute_search_refuses_once_in_the_current_domain() {
    // Exhaustion must remain observable rather than turn into a missing
    // attribute; a failed iterator must not continue scanning or charging.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[
        part(oid::ORGANIZATION, utf8("Example")),
        part(oid::COMMON_NAME, utf8("Subject")),
    ]);
    let mut reader = parser.read(&der, 101).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let name = read(&reader, &element, "subject").unwrap();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 0)));
    let before = parser.memory().work_used();
    let error = name.common_name(&execution).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 101);
    let mut attributes = name.attributes_of(oid::COMMON_NAME, &execution);
    assert!(attributes.next().unwrap().unwrap_err().is_resource());
    for _ in 0..3 {
        assert!(attributes.next().is_none());
    }
    assert_eq!(execution.work_used(), 0);
    assert_eq!(parser.memory().work_used(), before);

    // The reference belongs to Name; ending the budget borrow does not end it.
    let common = {
        let execution = crate::fixtures::memory();
        name.common_name(&execution).unwrap().unwrap()
    };
    assert_eq!(common.kind(), oid::COMMON_NAME);
}

#[test]
fn every_named_attribute_uses_its_equality_rule() {
    // Every named kind has a syntax and equality rule. Initials and
    // generationQualifier ignore case; pseudonym uses caseExactMatch.
    for kind in [oid::INITIALS, oid::GENERATION_QUALIFIER, oid::PSEUDONYM] {
        let one = seq(&[part(kind, printable("AB"))]);
        let other = seq(&[part(kind, utf8("ab"))]);
        let parser = Parser::der(crate::fixtures::memory());
        let one = parse(&parser, &one).unwrap();
        let other = parse(&parser, &other).unwrap();
        assert_eq!(
            one.matches(&other, &crate::fixtures::memory()).unwrap(),
            kind != oid::PSEUDONYM,
            "{kind:?}"
        );
    }

    // The distinguished-name qualifier is a PrintableString: it folds case
    // inside that type and refuses another.
    let one = seq(&[part(oid::DN_QUALIFIER, printable("X1"))]);
    let other = seq(&[part(oid::DN_QUALIFIER, printable("x1"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let one = parse(&parser, &one).unwrap();
    let other = parse(&parser, &other).unwrap();
    assert!(one.matches(&other, &crate::fixtures::memory()).unwrap());

    let mistyped = seq(&[part(oid::DN_QUALIFIER, utf8("x1"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let mistyped = parse(&parser, &mistyped).unwrap();
    assert!(!one.matches(&mistyped, &crate::fixtures::memory()).unwrap());
}

#[test]
fn an_unknown_attribute_kind_compares_by_its_encoded_value() {
    // A kind this crate does not name may define case-sensitive equality:
    // folding under a rule the type may not have would match names that
    // differ. Its values equal themselves and nothing else.
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x05, 0x01]);
    let upper = seq(&[part(unknown, printable("ID"))]);
    let lower = seq(&[part(unknown, printable("id"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let upper = parse(&parser, &upper).unwrap();
    let lower = parse(&parser, &lower).unwrap();
    assert!(!upper.matches(&lower, &crate::fixtures::memory()).unwrap());

    // Byte-equal values still match.
    let twin = seq(&[part(unknown, printable("ID"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let twin = parse(&parser, &twin).unwrap();
    assert!(upper.matches(&twin, &crate::fixtures::memory()).unwrap());
}

#[test]
fn an_encoding_the_attribute_type_does_not_permit_never_folds() {
    // A common name is a directory string, and IA5String is not one of its
    // choices: text folded out of an encoding the type does not have would
    // let a malformed issuer match a genuine subject it never equals.
    let malformed = seq(&[part(oid::COMMON_NAME, ia5("ROOT"))]);
    let genuine = seq(&[part(oid::COMMON_NAME, utf8("root"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let left = parse(&parser, &malformed).unwrap();
    let right = parse(&parser, &genuine).unwrap();
    assert!(!left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(!right.matches(&left, &crate::fixtures::memory()).unwrap());

    // Identical bytes still equal themselves, whatever the encoding.
    let twin = seq(&[part(oid::COMMON_NAME, ia5("ROOT"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let twin = parse(&parser, &twin).unwrap();
    assert!(left.matches(&twin, &crate::fixtures::memory()).unwrap());

    // And an attribute whose type does name IA5String still folds: a domain
    // component compares ignoring case.
    let upper = seq(&[part(oid::DOMAIN_COMPONENT, ia5("EXAMPLE"))]);
    let lower = seq(&[part(oid::DOMAIN_COMPONENT, ia5("example"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let upper = parse(&parser, &upper).unwrap();
    let lower = parse(&parser, &lower).unwrap();
    assert!(upper.matches(&lower, &crate::fixtures::memory()).unwrap());
}

/// `BMPString`, sixteen bits a character.
fn bmp(text: &str) -> Vec<u8> {
    let mut contents = Vec::new();
    for unit in text.encode_utf16() {
        contents.extend_from_slice(&unit.to_be_bytes());
    }
    tlv(0x1e, &contents)
}

#[test]
fn a_name_is_read_as_the_parts_it_was_written_in() {
    let der = seq(&[
        part(oid::COUNTRY, printable("UA")),
        part(oid::ORGANIZATION, utf8("Дія")),
        part(oid::COMMON_NAME, utf8("Тестовий підписувач")),
    ]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();

    assert_eq!(name.parts().len(), 3);
    assert_eq!(name.attributes().count(), 3);
    assert!(!name.is_empty());
    assert_eq!(
        name.common_name(&crate::fixtures::memory())
            .unwrap()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .as_ref()
            .map(|text| text.as_str(&crate::fixtures::memory()).unwrap()),
        Some("Тестовий підписувач")
    );
    assert_eq!(
        name.attribute(oid::COUNTRY, &crate::fixtures::memory())
            .unwrap()
            .unwrap()
            .value()
            .encoding(),
        Encoding::Printable
    );
    // Kept as it arrived, because this is what identity is compared on.
    assert_eq!(name.as_bytes(), &der[..]);
}

#[test]
fn an_organization_identifier_is_found_where_a_qualified_certificate_carries_it() {
    let der = seq(&[
        part(oid::ORGANIZATION, utf8("Autoritatea")),
        part(oid::ORGANIZATION_IDENTIFIER, printable("VATRO-12345678")),
    ]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();

    assert_eq!(
        name.organization_identifier(&crate::fixtures::memory())
            .unwrap()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .as_ref()
            .map(|text| text.as_str(&crate::fixtures::memory()).unwrap()),
        Some("VATRO-12345678")
    );
    // The common name describes the subject; it is not the identifier, and a
    // name that has one does not thereby have the other.
    assert!(
        name.common_name(&crate::fixtures::memory())
            .unwrap()
            .is_none()
    );
}

#[test]
fn several_attributes_of_one_kind_are_all_kept() {
    let der = seq(&[
        part(oid::ORGANIZATIONAL_UNIT, utf8("first")),
        part(oid::ORGANIZATIONAL_UNIT, utf8("second")),
    ]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();

    let units: Vec<_> = name
        .attributes_of(oid::ORGANIZATIONAL_UNIT, parser.memory())
        .map(|attribute| attribute.unwrap())
        .filter_map(|attribute| attribute.text(&crate::fixtures::memory()).unwrap())
        .map(|text| text.as_str(&crate::fixtures::memory()).unwrap().to_owned())
        .collect();
    assert_eq!(units, ["first", "second"]);
}

#[test]
fn the_same_name_written_differently_still_matches() {
    // The profile compares what a string says, not how it was written: the
    // type differs, the case differs, and the gap between the words is wider.
    let subject = seq(&[part(oid::ORGANIZATION, printable("ACME  Ltd"))]);
    let issuer = seq(&[part(oid::ORGANIZATION, utf8("acme ltd"))]);

    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let left = parse(&one, &subject).unwrap();
    let right = parse(&other, &issuer).unwrap();

    assert!(left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(right.matches(&left, &crate::fixtures::memory()).unwrap());
    // Same name, different bytes: a path would never be built if identity
    // meant only that the encodings agreed.
    assert_ne!(left.as_bytes(), right.as_bytes());
}

#[test]
fn a_name_written_in_sixteen_bit_characters_is_read_and_matched() {
    let wide = seq(&[part(oid::COMMON_NAME, bmp("Ministerul Finanțelor"))]);
    let narrow = seq(&[part(oid::COMMON_NAME, utf8("ministerul finanțelor"))]);

    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let left = parse(&one, &wide).unwrap();
    let right = parse(&other, &narrow).unwrap();

    assert_eq!(
        left.common_name(&crate::fixtures::memory())
            .unwrap()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .as_ref()
            .map(|text| text.as_str(&crate::fixtures::memory()).unwrap()),
        Some("Ministerul Finanțelor")
    );
    // Case folding is ASCII only, so the two differ in the letter with a
    // cedilla and only in that letter. They still match, because that letter
    // is the same in both.
    assert!(left.matches(&right, &crate::fixtures::memory()).unwrap());
}

#[test]
fn names_that_say_different_things_do_not_match() {
    let parsers = [
        Parser::der(crate::fixtures::memory()),
        Parser::der(crate::fixtures::memory()),
        Parser::der(crate::fixtures::memory()),
        Parser::der(crate::fixtures::memory()),
    ];
    let base = seq(&[
        part(oid::COUNTRY, printable("UA")),
        part(oid::ORGANIZATION, utf8("Acme")),
    ]);
    // A different value, the same value under a different attribute type, and
    // the same parts in the other order. None of them is this name.
    let others = [
        seq(&[
            part(oid::COUNTRY, printable("RO")),
            part(oid::ORGANIZATION, utf8("Acme")),
        ]),
        seq(&[
            part(oid::COUNTRY, printable("UA")),
            part(oid::ORGANIZATIONAL_UNIT, utf8("Acme")),
        ]),
        seq(&[
            part(oid::ORGANIZATION, utf8("Acme")),
            part(oid::COUNTRY, printable("UA")),
        ]),
        seq(&[part(oid::COUNTRY, printable("UA"))]),
    ];

    let name = parse(&parsers[0], &base).unwrap();
    for (index, other) in others.iter().enumerate() {
        let parser = Parser::der(crate::fixtures::memory());
        let candidate = parse(&parser, other).unwrap();
        assert!(
            !name
                .matches(&candidate, &crate::fixtures::memory())
                .unwrap(),
            "{index}"
        );
        assert!(
            !candidate
                .matches(&name, &crate::fixtures::memory())
                .unwrap(),
            "{index}"
        );
    }
}

#[test]
fn attributes_within_one_part_are_unordered_among_themselves() {
    // A part holding several attributes is a set, so writing them the other
    // way round writes the same name.
    let one = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), utf8("Signer")]),
        seq(&[oid_of(oid::SURNAME), utf8("Melnyk")]),
    ])]);
    let other = seq(&[set(&[
        seq(&[oid_of(oid::SURNAME), utf8("Melnyk")]),
        seq(&[oid_of(oid::COMMON_NAME), utf8("Signer")]),
    ])]);

    // The reversed spelling breaks DER's set order, so it is read as BER,
    // which is also the cross-encoding case the order-insensitive comparison
    // exists for.
    let left_parser = Parser::der(crate::fixtures::memory());
    let right_parser = Parser::ber(crate::fixtures::memory());
    let left = parse(&left_parser, &one).unwrap();
    let right = parse(&right_parser, &other).unwrap();

    assert_eq!(left.parts().len(), 1);
    assert_eq!(left.parts()[0].attributes().len(), 2);
    assert!(left.matches(&right, &crate::fixtures::memory()).unwrap());
}

#[test]
fn a_value_that_is_not_text_is_compared_as_it_was_encoded() {
    let one = seq(&[part(oid::DN_QUALIFIER, int(7))]);
    let same = seq(&[part(oid::DN_QUALIFIER, int(7))]);
    let different = seq(&[part(oid::DN_QUALIFIER, int(8))]);

    let parsers = [
        Parser::der(crate::fixtures::memory()),
        Parser::der(crate::fixtures::memory()),
        Parser::der(crate::fixtures::memory()),
    ];
    let left = parse(&parsers[0], &one).unwrap();
    let right = parse(&parsers[1], &same).unwrap();
    let other = parse(&parsers[2], &different).unwrap();

    assert_eq!(
        left.attributes().next().unwrap().value().encoding(),
        Encoding::Other
    );
    assert!(
        left.attributes()
            .next()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .is_none()
    );
    assert!(left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(!left.matches(&other, &crate::fixtures::memory()).unwrap());
}

#[test]
fn an_empty_name_is_read_rather_than_refused() {
    // A certificate may leave the subject empty and name it in an extension
    // instead, and refusing to read that would leave the product unable to
    // explain a certificate somebody is holding.
    let der = seq(&[]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();

    assert!(name.is_empty());
    assert_eq!(name.attributes().count(), 0);
}

#[test]
fn a_part_that_names_nothing_is_refused() {
    // Two names differing only by an empty part would compare as different
    // names while saying the same thing.
    let der = seq(&[set(&[])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &der).unwrap_err();

    assert_eq!(error.code(), ErrorCode::EmptySequence);
    assert_eq!(error.field(), "test");
}

#[test]
fn a_name_that_is_not_shaped_like_one_is_refused() {
    let parser = Parser::der(crate::fixtures::memory());
    // A part that is a sequence rather than a set.
    let der = seq(&[seq(&[seq(&[oid_of(oid::COMMON_NAME), utf8("x")])])]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // An attribute with a second value after the first: which one the name
    // holds would have no answer.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[set(&[cat(&[tlv(
        0x30,
        &cat(&[oid_of(oid::COMMON_NAME), utf8("one"), ia5("two")]),
    )])])]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::TrailingData);

    // An attribute with no value at all.
    let parser = Parser::der(crate::fixtures::memory());
    let der = seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME)])])]);
    let error = parse(&parser, &der).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MissingField);
}

#[test]
fn a_sixteen_bit_string_of_an_odd_length_is_not_read_as_text() {
    let der = seq(&[part(oid::COMMON_NAME, tlv(0x1e, &[0x00, 0x41, 0x00]))]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();

    // Half a character is not a character, and guessing at the missing byte
    // would put a name in the report that the certificate does not carry.
    assert!(
        name.common_name(&crate::fixtures::memory())
            .unwrap()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        name.common_name(&crate::fixtures::memory())
            .unwrap()
            .unwrap()
            .value()
            .encoding(),
        Encoding::Bmp
    );
}

#[test]
fn a_duplicated_attribute_cannot_match_two_different_ones() {
    // One part holding CN twice against one holding CN and a surname: each
    // left attribute finds the one right CN, so a matcher without one-to-one
    // correspondence calls these the same name in one direction and different
    // names in the other.
    let doubled = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), utf8("Signer")]),
        seq(&[oid_of(oid::COMMON_NAME), utf8("Signer")]),
    ])]);
    let mixed = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), utf8("Signer")]),
        seq(&[oid_of(oid::SURNAME), utf8("Melnyk")]),
    ])]);

    let left_parser = Parser::der(crate::fixtures::memory());
    let right_parser = Parser::der(crate::fixtures::memory());
    let left = parse(&left_parser, &doubled).unwrap();
    let right = parse(&right_parser, &mixed).unwrap();

    assert!(!left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(!right.matches(&left, &crate::fixtures::memory()).unwrap());

    // And a genuine duplicate on both sides still matches. Upper case sorts
    // before lower in the encoded order DER requires.
    let also_doubled = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), utf8("SIGNER")]),
        seq(&[oid_of(oid::COMMON_NAME), utf8("signer")]),
    ])]);
    let other_parser = Parser::der(crate::fixtures::memory());
    let other = parse(&other_parser, &also_doubled).unwrap();
    assert!(left.matches(&other, &crate::fixtures::memory()).unwrap());
}

#[test]
fn a_value_that_does_not_decode_never_matches_one_that_does() {
    // 0xC3 0x28 is not UTF-8. Read one byte a character for display it
    // renders as the two scalars C3 and 28, which a genuine UTF8String can
    // spell honestly. If the display fallback fed the comparison, the
    // malformed name would match the genuine one.
    let malformed = seq(&[part(oid::COMMON_NAME, tlv(0x0c, &[0xc3, 0x28]))]);
    let genuine = seq(&[part(oid::COMMON_NAME, utf8("\u{c3}("))]);

    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let left = parse(&one, &malformed).unwrap();
    let right = parse(&other, &genuine).unwrap();

    assert!(!left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(!right.matches(&left, &crate::fixtures::memory()).unwrap());

    // The display text still shows a person something.
    assert!(
        left.common_name(&crate::fixtures::memory())
            .unwrap()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_der_part_with_attributes_out_of_order_is_refused() {
    // DER requires the members of a set to appear in ascending order of their
    // encodings. The comparison of names deliberately ignores order, so an
    // unsorted part would otherwise match a correctly sorted one and a
    // malformed issuer could take part in a path.
    let backwards = seq(&[set(&[
        seq(&[oid_of(oid::SURNAME), utf8("Melnyk")]),
        seq(&[oid_of(oid::COMMON_NAME), utf8("Signer")]),
    ])]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &backwards).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // The same bytes are readable where BER is what was asked for, which is
    // how the unordered spelling still compares against a sorted name.
    let parser = Parser::ber(crate::fixtures::memory());
    let name = parse(&parser, &backwards).unwrap();
    assert_eq!(name.parts()[0].attributes().len(), 2);
}

#[test]
fn a_value_outside_its_declared_alphabet_never_matches_a_genuine_one() {
    // A PrintableString has no accented letters. One carrying the UTF-8 bytes
    // of one is malformed, and a genuine UTF8String can spell the same word
    // honestly; comparing the two as equal would let the malformed issuer
    // stand in for a real subject.
    let malformed = seq(&[part(oid::COMMON_NAME, tlv(0x13, "Sign\u{e9}".as_bytes()))]);
    let genuine = seq(&[part(oid::COMMON_NAME, utf8("Sign\u{e9}"))]);

    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let left = parse(&one, &malformed).unwrap();
    let right = parse(&other, &genuine).unwrap();

    assert!(!left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(!right.matches(&left, &crate::fixtures::memory()).unwrap());
    // Still shown to a person, and still equal to its own bytes.
    assert!(
        left.common_name(&crate::fixtures::memory())
            .unwrap()
            .unwrap()
            .text(&crate::fixtures::memory())
            .unwrap()
            .is_some()
    );
    let same_parser = Parser::der(crate::fixtures::memory());
    let same = parse(&same_parser, &malformed).unwrap();
    assert!(left.matches(&same, &crate::fixtures::memory()).unwrap());
}

#[test]
fn an_attribute_outside_its_size_bounds_never_folds() {
    // A country name is exactly two letters; " US " wears the type but is
    // not a value the schema names, and folding would collapse its padding
    // into a match with a genuine two-letter code.
    let malformed = seq(&[part(oid::COUNTRY, printable(" US "))]);
    let genuine = seq(&[part(oid::COUNTRY, printable("US"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let left = parse(&parser, &malformed).unwrap();
    let right = parse(&parser, &genuine).unwrap();
    assert!(!left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(!right.matches(&left, &crate::fixtures::memory()).unwrap());

    // Identical bytes still equal themselves, whatever the bounds say.
    let twin = seq(&[part(oid::COUNTRY, printable(" US "))]);
    let parser = Parser::der(crate::fixtures::memory());
    let twin = parse(&parser, &twin).unwrap();
    assert!(left.matches(&twin, &crate::fixtures::memory()).unwrap());

    // Well formed values still fold.
    let lower = seq(&[part(oid::COUNTRY, printable("us"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let lower = parse(&parser, &lower).unwrap();
    assert!(right.matches(&lower, &crate::fixtures::memory()).unwrap());
}

#[test]
fn an_oversized_personal_name_attribute_never_folds() {
    // The personal name attributes are bounded too: the name components at
    // 32768 characters and the pseudonym at 128 (RFC 5280 appendix A). A
    // value past its bound is not a value the schema names.
    // Padding spaces push the value past the bound while folding collapses
    // them away: without the bound the oversized spelling folds into a
    // match with the genuine one.
    let fits = "a".repeat(128);
    let padded = [fits.as_str(), &" ".repeat(200)].concat();
    let malformed = seq(&[part(oid::PSEUDONYM, printable(&padded))]);
    let genuine = seq(&[part(oid::PSEUDONYM, printable(&fits))]);
    let upper = "A".repeat(128);
    let folded = seq(&[part(oid::PSEUDONYM, printable(&upper))]);
    let parser = Parser::der(crate::fixtures::memory());
    let left = parse(&parser, &malformed).unwrap();
    let right = parse(&parser, &genuine).unwrap();
    let folded = parse(&parser, &folded).unwrap();

    // Pseudonym's caseExactMatch (RFC2985 §5.2.9) preserves case even at
    // the bound; exceeding the bound still prevents space preparation.
    assert!(!right.matches(&folded, &crate::fixtures::memory()).unwrap());
    assert!(!left.matches(&right, &crate::fixtures::memory()).unwrap());
}

#[test]
fn an_oversized_street_address_never_folds() {
    // The street address is bounded at 128 characters (X.520,
    // ub-street-address); padding past the bound folds away and would
    // otherwise fold into a match with a genuine value.
    let fits = "a".repeat(128);
    let padded = [fits.as_str(), &" ".repeat(200)].concat();
    let malformed = seq(&[part(oid::STREET_ADDRESS, printable(&padded))]);
    let genuine = seq(&[part(oid::STREET_ADDRESS, printable(&fits))]);
    let parser = Parser::der(crate::fixtures::memory());
    let left = parse(&parser, &malformed).unwrap();
    let right = parse(&parser, &genuine).unwrap();

    assert!(!left.matches(&right, &crate::fixtures::memory()).unwrap());
}

#[test]
fn a_country_that_is_not_two_letters_never_reads_as_one() {
    // The country is a two-letter ISO 3166 code: two digits fit the
    // printable repertoire and the size without naming any country, and a
    // directory identity carrying them must not read as decoded.
    let digits = seq(&[part(oid::COUNTRY, printable("12"))]);
    let letters = seq(&[part(oid::COUNTRY, printable("UA"))]);
    let parser = Parser::der(crate::fixtures::memory());
    let left = parse(&parser, &digits).unwrap();
    let right = parse(&parser, &letters).unwrap();

    assert!(!super::well_formed(left.attributes().next().unwrap()));
    assert!(super::well_formed(right.attributes().next().unwrap()));
}

#[test]
fn a_constructed_universal_attribute_value_is_refused_under_der() {
    // DER writes every universal type here in the primitive form, the two
    // containers aside (X.690 10.2): a constructed UTF8String is a second
    // spelling of one value, and even an unknown kind's opaque value must
    // be DER before it is preserved.
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x05, 0x03]);
    let constructed = seq(&[part(unknown, tlv(0x2c, &utf8("x")))]);
    let parser = Parser::der(crate::fixtures::memory());
    let error = parse(&parser, &constructed).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // The primitive spelling and a genuine container both still read.
    let primitive = seq(&[part(unknown, utf8("x"))]);
    let container = seq(&[part(unknown, seq(&[int(1)]))]);
    for der in [primitive, container] {
        let parser = Parser::der(crate::fixtures::memory());
        assert!(parse(&parser, &der).is_ok());
    }
}

#[test]
fn ber_does_not_make_primitive_only_types_constructible() {
    // X.690 §§8.2–8.5, 8.8, 8.19–8.22 and 8.26 require primitive
    // form for these types even under BER. Opaque preservation must reject
    // a container falsely claiming an INTEGER, OID, or newer time type.
    let unknown = Oid::from_bytes(&[0x2a, 3]);
    for tag in [1, 2, 5, 6, 9, 10, 13, 14, 31, 32, 33, 34, 35, 36] {
        let value = if tag < 31 {
            tlv(0x20 | tag, &[])
        } else {
            alloc::vec![0x3f, tag, 0]
        };
        let bytes = seq(&[part(unknown, value)]);
        let parser = Parser::ber(crate::fixtures::memory());
        assert!(parse(&parser, &bytes).is_err(), "universal tag {tag}");
    }
}

#[test]
fn ber_string_segments_use_the_base_string_tag() {
    // X.690 §8.23.3 encodes constructed restricted strings as implicitly
    // tagged OCTET STRINGs. UTF8String children with the outer tag repeated
    // are not valid segments, even though each child alone is a valid value.
    let unknown = Oid::from_bytes(&[0x2a, 3]);
    let parser = Parser::ber(crate::fixtures::memory());
    let valid = seq(&[part(unknown, tlv(0x2c, &tlv(4, b"A")))]);
    assert!(parse(&parser, &valid).is_ok());
    for child in [utf8("A"), int(1), tlv(0x84, b"A")] {
        let invalid = seq(&[part(unknown, tlv(0x2c, &child))]);
        assert!(parse(&parser, &invalid).is_err());
    }
}

#[test]
fn ber_partial_bit_segments_must_be_last_at_every_depth() {
    // X.690 §8.6.4 allows padding only in the last segment. A nested
    // partial segment followed by even an empty sibling is still nonfinal.
    let unknown = Oid::from_bytes(&[0x2a, 3]);
    let parser = Parser::ber(crate::fixtures::memory());
    let partial = tlv(3, &[7, 0x80]);
    let empty = tlv(3, &[0]);
    for value in [
        tlv(0x23, &[partial.clone(), empty.clone()].concat()),
        tlv(0x23, &[tlv(0x23, &partial), empty].concat()),
    ] {
        let invalid = seq(&[part(unknown, value)]);
        assert!(parse(&parser, &invalid).is_err());
    }
    let valid = seq(&[part(unknown, tlv(0x23, &tlv(0x23, &partial)))]);
    assert!(parse(&parser, &valid).is_ok());
}

#[test]
fn opaque_ber_times_keep_the_useful_types_broader_grammar() {
    // X.680 §§46.2–46.3 and 47.3 permit BER spellings that DER §§11.7–11.8
    // narrow. A preserved #BER value is not a PKIX validity timestamp.
    let unknown = Oid::from_bytes(&[0x2a, 3]);
    let parser = Parser::ber(crate::fixtures::memory());
    for text in [
        "1985110621",
        "1985110621Z",
        "1985110621.1415900",
        "198511062106,456Z",
        "19851106210627.000-0500",
        "1985110621+05",
    ] {
        let value = seq(&[part(unknown, tlv(0x18, text.as_bytes()))]);
        assert!(parse(&parser, &value).is_ok(), "{text}");
    }
    for text in ["8201021200Z", "8201020700-0500"] {
        let value = seq(&[part(unknown, tlv(0x17, text.as_bytes()))]);
        assert!(parse(&parser, &value).is_ok(), "{text}");
    }
    for (tag, text) in [
        (0x18, "19851106240000Z"),
        (0x18, "1985110621.Z"),
        (0x17, "82010212Z"),
        (0x17, "8201021200"),
        (0x17, "8201021200+05"),
        (0x17, "820102120060Z"),
    ] {
        let value = seq(&[part(unknown, tlv(tag, text.as_bytes()))]);
        assert!(parse(&parser, &value).is_err(), "{text}");
    }
}

#[test]
fn ber_associated_sequence_strings_validate_their_implicit_segments() {
    // EXTERNAL's octet-aligned/arbitrary alternatives and CHARACTER STRING's
    // string-value keep their implicit type semantics under context tags.
    // Accepting an INTEGER child would retain an invalid BER string.
    let unknown = Oid::from_bytes(&[0x2a, 3]);
    let parser = Parser::ber(crate::fixtures::memory());
    for value in [
        tlv(0x28, &tlv(0xa1, &int(1))),
        tlv(
            0x3d,
            &[tlv(0xa0, &tlv(0x85, &[])), tlv(0xa2, &int(1))].concat(),
        ),
    ] {
        let invalid = seq(&[part(unknown, value)]);
        assert!(parse(&parser, &invalid).is_err());
    }
    let valid = seq(&[part(unknown, tlv(0x28, &tlv(0xa2, &tlv(3, &[7, 0x80]))))]);
    assert!(parse(&parser, &valid).is_ok());
}

#[test]
fn preparation_admits_the_complete_fixed_schema_lookup_bound() {
    // Preparation asks for syntax twice, size bounds once and identity-specific
    // rules. Their full fixed table bound is 64 kind-byte passes, not 40.
    // With one unit missing, admission must refuse before scanning any value.
    use alloc::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};
    let parser = Parser::der(crate::fixtures::memory());
    let bytes = seq(&[part(oid::ORGANIZATION_IDENTIFIER, utf8("A"))]);
    let name = parse(&parser, &bytes).unwrap();
    let attribute = *name.attributes().next().unwrap();
    let bound = 64 * attribute.kind().as_bytes().len() + 4;
    let refused = Memory::new(Arc::new(MemoryAccount::new(0, bound - 1)));
    assert!(attribute.folds(&refused).unwrap_err().is_resource());
    assert_eq!(refused.work_used(), 0);
    let exact = Memory::new(Arc::new(MemoryAccount::new(0, bound)));
    assert!(attribute.folds(&exact).unwrap());
    assert_eq!(exact.work_used(), bound);
    assert_eq!(exact.used(), 0);
}

#[test]
fn the_set_ordering_comparison_is_charged_to_the_work_budget() {
    // The ordering walk compares up to the longer encoding: two large
    // members sharing a prefix cost that length, and a caller bounding
    // work must see it on the meter rather than paying an unmetered scan.
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x05, 0x04]);
    let mut big = alloc::vec![0xaau8; 50_000];
    let first = seq(&[oid_of(unknown), tlv(0x04, &big)]);
    *big.last_mut().unwrap() = 0xbb;
    let second = seq(&[oid_of(unknown), tlv(0x04, &big)]);
    let der = seq(&[set(&[first, second])]);

    let limits = structured_asn1::Limits {
        max_work: 4096,
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

    // Under the default budget the same name reads.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn comparing_a_retained_name_uses_the_current_operations_budget() {
    // Reading an opaque borrowed value does not perform a future comparison.
    // That comparison must refuse its own work before examining the payload,
    // even if an earlier parser account has enough allowance for it.
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x05, 0x05]);
    let big = alloc::vec![0xaau8; 100_000];
    let der = seq(&[part(unknown, tlv(0x04, &big))]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let name = parse(&parser, &der).unwrap();
    let execution = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(1024 * 1024, 8192),
    ));
    assert_eq!(
        name.matches(&name, &execution).unwrap_err().code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    assert_eq!(execution.work_used(), 0);
    // With sufficient current work allowance the same bytes still match.
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();
    let other = Parser::der(crate::fixtures::memory());
    let twin = parse(&other, &der).unwrap();
    assert!(name.matches(&twin, &crate::fixtures::memory()).unwrap());
}

#[test]
fn sorting_a_part_charges_the_kinds_it_compares() {
    // Ordering a part compares each attribute's kind before its value, and
    // a kind is as wide as the document writes it. A part of many wide
    // kinds sharing a long prefix, each with a value of one character,
    // spends the sort walking those kinds, so the charge counts them: a
    // document must not be able to buy a cheap read and an expensive
    // comparison.
    let kinds: Vec<Vec<u8>> = (1u8..=8)
        .map(|last| {
            let mut bytes = alloc::vec![0x81u8; 1_000];
            bytes[0] = 0x2a;
            *bytes.last_mut().unwrap() = last;
            bytes
        })
        .collect();
    let members: Vec<Vec<u8>> = kinds
        .iter()
        .map(|kind| seq(&[tlv(0x06, kind), utf8("x")]))
        .collect();
    let der = seq(&[set(&members)]);

    let limits = structured_asn1::Limits {
        max_work: 16_384,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    // Catalogue growth belongs to the producing allowance too. Fund reading
    // separately before testing the unchanged current-operation sort refusal.
    let error = parse(&parser, &der).unwrap_err();
    assert!(error.is_resource());
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();
    let execution = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(1024 * 1024, 16_384),
    ));
    let error = name.ordered(&execution).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    // Under the default budget the same name reads.
    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn a_part_of_several_attributes_matches_whatever_order_it_is_written_in() {
    // A part is a set, so the order inside it says nothing. These three hold
    // the same attributes: written in the other order, spelled in another
    // case, and written in another string type the schema permits. The
    // comparison walks both sides in a canonical order without building a
    // key, so this is the case that proves the ordering agrees with equality.
    // The members of a set are written in ascending encoded order under DER
    // (X.690 11.6), so the two sides put the same attributes in a different
    // relative order only because the longer spelling of the common name
    // sorts after the surname while the short one sorts before it.
    let one = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), utf8("a b")]),
        seq(&[oid_of(oid::SURNAME), utf8("Melnyk")]),
    ])]);
    let reordered = seq(&[set(&[
        seq(&[oid_of(oid::SURNAME), utf8("MELNYK")]),
        seq(&[
            oid_of(oid::COMMON_NAME),
            printable("a                    b"),
        ]),
    ])]);
    let different = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), utf8("a b")]),
        seq(&[oid_of(oid::SURNAME), utf8("Melnychuk")]),
    ])]);

    let first = Parser::der(crate::fixtures::memory());
    let second = Parser::der(crate::fixtures::memory());
    let third = Parser::der(crate::fixtures::memory());
    let left = parse(&first, &one).unwrap();
    let right = parse(&second, &reordered).unwrap();
    let other = parse(&third, &different).unwrap();

    assert!(left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(right.matches(&left, &crate::fixtures::memory()).unwrap());
    assert!(!left.matches(&other, &crate::fixtures::memory()).unwrap());
}

#[test]
fn a_part_of_several_attributes_keeps_undecodable_values_byte_only() {
    // One attribute of the part does not decode under its declared type, so
    // it equals only its own bytes while its neighbour still folds. Ordering
    // has to keep those two questions apart: a folded value and a byte-only
    // one are never the same attribute, whatever they spell.
    let malformed = tlv(0x0c, &[0xc3, 0x28]);
    let one = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), malformed.clone()]),
        seq(&[oid_of(oid::SURNAME), utf8("Melnyk")]),
    ])]);
    let same = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), malformed]),
        seq(&[oid_of(oid::SURNAME), utf8("melnyk")]),
    ])]);
    let genuine = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), utf8("\u{c3}(")]),
        seq(&[oid_of(oid::SURNAME), utf8("Melnyk")]),
    ])]);

    let first = Parser::der(crate::fixtures::memory());
    let second = Parser::der(crate::fixtures::memory());
    let third = Parser::der(crate::fixtures::memory());
    let left = parse(&first, &one).unwrap();
    let right = parse(&second, &same).unwrap();
    let other = parse(&third, &genuine).unwrap();

    assert!(left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(!left.matches(&other, &crate::fixtures::memory()).unwrap());
}

#[test]
fn two_attributes_of_one_kind_match_across_the_case_that_reorders_them() {
    // Both parts hold the same two common names, folded: a and b. Encoded,
    // upper case sorts before lower (X.690 11.6 orders set members by their
    // encodings), so one part is written B then a, and the other A then b.
    // Byte order and folded order disagree here, which is what forces the
    // comparison to order by what the values SAY rather than how they were
    // written.
    let one = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), utf8("B")]),
        seq(&[oid_of(oid::COMMON_NAME), utf8("a")]),
    ])]);
    let other = seq(&[set(&[
        seq(&[oid_of(oid::COMMON_NAME), utf8("A")]),
        seq(&[oid_of(oid::COMMON_NAME), utf8("b")]),
    ])]);

    let first = Parser::der(crate::fixtures::memory());
    let second = Parser::der(crate::fixtures::memory());
    let left = parse(&first, &one).unwrap();
    let right = parse(&second, &other).unwrap();

    assert!(left.matches(&right, &crate::fixtures::memory()).unwrap());
    assert!(right.matches(&left, &crate::fixtures::memory()).unwrap());
}

#[test]
fn an_unknown_attribute_written_as_a_character_string_is_preserved() {
    // The unrestricted character string type is encoded as the sequence its
    // definition names (X.690 8.24.1), so universal tag 29 arrives
    // constructed exactly as the external and embedded-pdv types do. An
    // attribute of a kind this crate does not name may be written in it, and
    // refusing the tag would abort a certificate over a value nobody here
    // interprets.
    // Written as its definition writes it: how the value is identified,
    // then the value (X.680 44.5).
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x05, 0x03]);
    let identification = tlv(0xa0, &tlv(0x85, &[]));
    let character_string = tlv(0x3d, &[identification, tlv(0x82, b"value")].concat());
    let der = seq(&[part(unknown, character_string)]);

    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();
    assert_eq!(name.attributes().count(), 1);
}

#[test]
fn a_letterform_folds_onto_the_letter_it_presents() {
    // The Map step is Table B.2 of RFC 3454, which folds case and carries
    // the compatibility mappings with it: `2102; 0063; Additional folding`
    // takes the double-struck capital C straight to a lowercase c. Folding
    // first and normalizing after arrives at a capital C instead, and an
    // organization writing its name in letterforms would not match the same
    // name written in letters.
    let presented = seq(&[part(oid::ORGANIZATION, utf8("\u{2102}ompany"))]);
    let plain = seq(&[part(oid::ORGANIZATION, utf8("company"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &presented)
            .unwrap()
            .matches(&parse(&other, &plain).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // The same for a letterform that is already lowercase, and for one
    // whose compatibility form is several letters.
    for (left, right) in [("\u{210E}", "h"), ("\u{2115}o", "no"), ("\u{33A1}", "m2")] {
        let one = Parser::der(crate::fixtures::memory());
        let other = Parser::der(crate::fixtures::memory());
        let left = seq(&[part(oid::ORGANIZATION, utf8(left))]);
        let right = seq(&[part(oid::ORGANIZATION, utf8(right))]);
        assert!(
            parse(&one, &left)
                .unwrap()
                .matches(&parse(&other, &right).unwrap(), &crate::fixtures::memory())
                .unwrap(),
            "{left:02x?}"
        );
    }

    // And letters that are not the same letter still differ.
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let left = seq(&[part(oid::ORGANIZATION, utf8("\u{2102}"))]);
    let right = seq(&[part(oid::ORGANIZATION, utf8("d"))]);
    assert!(
        !parse(&one, &left)
            .unwrap()
            .matches(&parse(&other, &right).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );
}

#[test]
fn a_segmented_value_inside_a_preserved_one_follows_the_encoding() {
    // The value an embedded-pdv ends with is an octet string, tagged over
    // its type. The distinguished rules write a string in one piece
    // (X.690 10.2), so the segmented form is a second spelling of it and is
    // refused there; the basic rules have both forms, and a document read
    // under them keeps what it was written with.
    let unknown = Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x05, 0x06]);
    let segmented = tlv(
        0x2b,
        &[tlv(0xa0, &tlv(0x85, &[])), tlv(0xa2, &tlv(0x04, b"d"))].concat(),
    );
    let der = seq(&[part(unknown, segmented)]);

    let parser = Parser::der(crate::fixtures::memory());
    assert!(parse(&parser, &der).is_err());

    let parser = Parser::new(
        structured_asn1::Encoding::Ber,
        structured_asn1::Limits::default(),
        crate::fixtures::memory(),
    );
    assert!(parse(&parser, &der).is_ok());
}

#[test]
fn the_preparation_maps_what_the_profile_says_it_maps() {
    // The comparison is the LDAP StringPrep profile (RFC 5280 7.1, which
    // requires RFC 4518). Its Map step sends tab, line feed, vertical tab,
    // form feed, carriage return and next line to SPACE, so a name broken
    // across a line equals the same name written with a space.
    let broken = seq(&[part(oid::ORGANIZATION, utf8("ACME\nCA"))]);
    let spaced = seq(&[part(oid::ORGANIZATION, utf8("ACME CA"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &broken)
            .unwrap()
            .matches(&parse(&other, &spaced).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // The same step sends soft hyphen, zero width space and the other
    // control and format code points to nothing, so a name carrying one
    // equals the name without it: they prepare to the same string.
    let hyphenated = seq(&[part(oid::ORGANIZATION, utf8("ACME\u{00ad}CA"))]);
    let joined = seq(&[part(oid::ORGANIZATION, utf8("ACMECA"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &hyphenated)
            .unwrap()
            .matches(&parse(&other, &joined).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // And a name that differs by a real character still differs.
    let different = seq(&[part(oid::ORGANIZATION, utf8("ACME CB"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        !parse(&one, &spaced)
            .unwrap()
            .matches(
                &parse(&other, &different).unwrap(),
                &crate::fixtures::memory()
            )
            .unwrap()
    );
}

#[test]
fn a_part_pays_for_the_comparison_its_shape_will_cost() {
    // Matching a part of several attributes orders both sides, and ordering
    // prepares values and sorts descriptors. The current execution account
    // must admit that work; reading cannot prepay later unbounded comparisons.
    let mut members = Vec::new();
    for first in 0..8u8 {
        let mut value = alloc::vec![b'a' + first];
        value.extend(core::iter::repeat_n(b'z', 20_000));
        members.push(seq(&[oid_of(oid::DOMAIN_COMPONENT), tlv(0x16, &value)]));
    }
    let der = seq(&[set(&members)]);

    let limits = structured_asn1::Limits {
        max_work: 250_000,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let name = parse(&parser, &der).unwrap();
    let execution = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(1024 * 1024, 250_000),
    ));
    let error = name.ordered(&execution).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );

    // One attribute of the same size compares without ordering, so it costs
    // only its own read.
    let mut value = alloc::vec![b'a'];
    value.extend(core::iter::repeat_n(b'z', 20_000));
    let single = seq(&[set(&[seq(&[
        oid_of(oid::DOMAIN_COMPONENT),
        tlv(0x16, &value),
    ])])]);
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    assert!(parse(&parser, &single).is_ok());
}

#[test]
fn case_folds_beyond_ascii_where_the_profile_requires_it() {
    // The preparation folds case by the table of RFC 3454 B.2 (RFC 4518 2.2,
    // required by RFC 5280 7.1), which covers Cyrillic and Latin letters with
    // diacritics, not only the ASCII range. Folding less leaves a genuine
    // path unbuilt: an issuer named in one case and the same authority's
    // subject named in another stop matching.
    let upper = seq(&[part(oid::ORGANIZATION, utf8("ЦЕНТРАЛЬНИЙ ОРГАН"))]);
    let lower = seq(&[part(oid::ORGANIZATION, utf8("центральний орган"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &upper)
            .unwrap()
            .matches(&parse(&other, &lower).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    let accented = seq(&[part(oid::ORGANIZATION, utf8("École"))]);
    let plain = seq(&[part(oid::ORGANIZATION, utf8("école"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &accented)
            .unwrap()
            .matches(&parse(&other, &plain).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // Different letters still differ.
    let different = seq(&[part(oid::ORGANIZATION, utf8("ecole"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        !parse(&one, &plain)
            .unwrap()
            .matches(
                &parse(&other, &different).unwrap(),
                &crate::fixtures::memory()
            )
            .unwrap()
    );
}

#[test]
fn a_value_the_preparation_prohibits_is_compared_as_bytes() {
    // The preparation refuses a value carrying a private-use code point, a
    // non-character or the replacement character (RFC 4518 2.4): nobody
    // agrees what those mean, so what the steps after them produce is not
    // defined. Folding one anyway would let two values the profile never
    // said were equal be treated as equal, and a certificate would attach to
    // the wrong authority. Byte identity is what is left, and the profile
    // names it as a sufficient rule (RFC 5280 7.1).
    // The deprecated and display-changing code points the same step lists
    // are not here: the mapping and the normalization remove them before it
    // runs, which the test above pins.
    for prohibited in ['\u{e000}', '\u{fdd0}', '\u{fffe}', '\u{fffd}'] {
        let upper = seq(&[part(
            oid::ORGANIZATION,
            utf8(&alloc::format!("A{prohibited}")),
        )]);
        let lower = seq(&[part(
            oid::ORGANIZATION,
            utf8(&alloc::format!("a{prohibited}")),
        )]);
        let one = Parser::der(crate::fixtures::memory());
        let other = Parser::der(crate::fixtures::memory());
        assert!(
            !parse(&one, &upper)
                .unwrap()
                .matches(&parse(&other, &lower).unwrap(), &crate::fixtures::memory())
                .unwrap(),
            "{prohibited:?}"
        );

        // The same bytes are still the same name, and the value is still
        // shown to a person.
        let one = Parser::der(crate::fixtures::memory());
        let other = Parser::der(crate::fixtures::memory());
        let left = parse(&one, &upper).unwrap();
        assert!(
            left.matches(&parse(&other, &upper).unwrap(), &crate::fixtures::memory())
                .unwrap(),
            "{prohibited:?}"
        );
        assert!(
            left.attributes()
                .next()
                .unwrap()
                .text(&crate::fixtures::memory())
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn a_legacy_teletex_value_is_kept_rather_than_called_malformed() {
    // TeletexString is T.61 and not UTF-8, and its repertoire is a
    // negotiation this crate does not implement. Requiring the bytes to
    // decode as UTF-8 called a legacy value malformed, and where a name is
    // required to be written inside its syntax that refused the whole
    // certificate over an encoding the schema names.
    let legacy = tlv(0x14, &[0xc2, 0x65]);
    let der = seq(&[part(oid::COMMON_NAME, legacy.clone())]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();
    assert!(super::well_formed(name.attributes().next().unwrap()));

    // It is not folded, though: what the bytes say is a negotiation, so the
    // value takes part in identity as its bytes.
    let twin = seq(&[part(oid::COMMON_NAME, legacy)]);
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        name.matches(&parse(&other, &twin).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    let different = seq(&[part(oid::COMMON_NAME, tlv(0x14, &[0xc2, 0x45]))]);
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        !name
            .matches(
                &parse(&other, &different).unwrap(),
                &crate::fixtures::memory()
            )
            .unwrap()
    );

    // A Teletex value that is ASCII still folds, which is the approximation
    // this crate reads it as.
    let upper = seq(&[part(oid::COMMON_NAME, tlv(0x14, b"ROOT"))]);
    let lower = seq(&[part(oid::COMMON_NAME, utf8("root"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &upper)
            .unwrap()
            .matches(&parse(&other, &lower).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // The size the schema gives the kind is still held, counted in bytes
    // where the characters cannot be counted.
    let long = seq(&[part(oid::COMMON_NAME, tlv(0x14, &[0xc2; 65]))]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &long).unwrap();
    assert!(!super::well_formed(name.attributes().next().unwrap()));
}

#[test]
fn a_character_the_mapping_removes_does_not_stop_the_preparation() {
    // The steps run in the order the profile gives them, and the gates that
    // decide whether a value can be prepared come after the mapping. The
    // characters that change display properties are mapped to nothing
    // (RFC 4518 2.2) before the step that prohibits them ever sees the
    // value, so treating one as a reason not to prepare refuses a value the
    // profile prepares and leaves a genuine path unbuilt.
    for removed in ['\u{200e}', '\u{200f}', '\u{202a}', '\u{206a}', '\u{00ad}'] {
        let upper = seq(&[part(oid::ORGANIZATION, utf8(&alloc::format!("A{removed}")))]);
        let lower = seq(&[part(oid::ORGANIZATION, utf8("a"))]);
        let one = Parser::der(crate::fixtures::memory());
        let other = Parser::der(crate::fixtures::memory());
        assert!(
            parse(&one, &upper)
                .unwrap()
                .matches(&parse(&other, &lower).unwrap(), &crate::fixtures::memory())
                .unwrap(),
            "{removed:?}"
        );
    }

    // The two deprecated tone marks are removed by the normalization rather
    // than the mapping, and that step comes before the same gates.
    for normalized in ['\u{0340}', '\u{0341}'] {
        let upper = seq(&[part(
            oid::ORGANIZATION,
            utf8(&alloc::format!("A{normalized}")),
        )]);
        let lower = seq(&[part(
            oid::ORGANIZATION,
            utf8(&alloc::format!("a{normalized}")),
        )]);
        let one = Parser::der(crate::fixtures::memory());
        let other = Parser::der(crate::fixtures::memory());
        assert!(
            parse(&one, &upper)
                .unwrap()
                .matches(&parse(&other, &lower).unwrap(), &crate::fixtures::memory())
                .unwrap(),
            "{normalized:?}"
        );
    }

    // A right-to-left mark does not make a name right-to-left either: the
    // mapping removes it, so what remains decides the direction.
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let marked = seq(&[part(oid::ORGANIZATION, utf8("Kyiv\u{200f}"))]);
    let plain = seq(&[part(oid::ORGANIZATION, utf8("kyiv"))]);
    assert!(
        parse(&one, &marked)
            .unwrap()
            .matches(&parse(&other, &plain).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );
}

#[test]
fn a_value_the_bidi_step_refuses_is_compared_as_bytes() {
    // The preparation is six steps and one of them checks direction
    // (RFC 4518 2.5, over RFC 3454 6): a value holding a right-to-left
    // letter may hold no left-to-right one, and must begin and end with a
    // right-to-left one. A value that fails it has no defined preparation,
    // so folding it anyway would make two values equal that the profile
    // never said were.
    let upper = seq(&[part(oid::ORGANIZATION, utf8("Aא"))]);
    let lower = seq(&[part(oid::ORGANIZATION, utf8("aא"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        !parse(&one, &upper)
            .unwrap()
            .matches(&parse(&other, &lower).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // The same bytes are still the same name.
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &upper)
            .unwrap()
            .matches(&parse(&other, &upper).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // A name written in one direction throughout passes the step and is
    // prepared as any other is: Hebrew has no case of its own, so what the
    // preparation does here is the space between the words.
    let spaced = seq(&[part(oid::ORGANIZATION, utf8("בית  הדפוס"))]);
    let single = seq(&[part(oid::ORGANIZATION, utf8("בית הדפוס"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &spaced)
            .unwrap()
            .matches(&parse(&other, &single).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // And the spaces at the edges are the ones a later step removes, so
    // they do not decide the direction of the edges either.
    let padded = seq(&[part(oid::ORGANIZATION, utf8(" בית הדפוס "))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &padded)
            .unwrap()
            .matches(&parse(&other, &single).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );
}

#[test]
fn a_character_the_profile_never_saw_is_compared_as_bytes() {
    // The preparation is defined over one repertoire, Unicode 3.2, and its
    // Prohibit step refuses everything outside it (RFC 4518 2 and 2.4). The
    // steps after it are tables read at their current version, so a
    // character assigned later carries a fold the profile never gave it:
    // the capital sharp s arrived in Unicode 5.1 and folds to two letters
    // that were in 3.2. Prepared, an issuer written with it would equal a
    // subject written without it, by a rule the profile does not contain.
    let newer = seq(&[part(oid::ORGANIZATION, utf8("STRAẞE"))]);
    let older = seq(&[part(oid::ORGANIZATION, utf8("strasse"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        !parse(&one, &newer)
            .unwrap()
            .matches(&parse(&other, &older).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // The same bytes are still the same name, which is what a value without
    // a preparation falls back to.
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &newer)
            .unwrap()
            .matches(&parse(&other, &newer).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // And a name written from the repertoire the profile knows still folds:
    // this is the case the step must not cost.
    let spaced = seq(&[part(oid::ORGANIZATION, utf8("ACME  CA"))]);
    let single = seq(&[part(oid::ORGANIZATION, utf8("acme ca"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &spaced)
            .unwrap()
            .matches(&parse(&other, &single).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );
}

#[test]
fn the_bidi_step_reads_the_value_the_normalizing_step_leaves() {
    // The steps run in the order RFC 4518 2 gives them, and normalizing
    // comes before the direction check. It has to: a compatibility form can
    // expand into letters of a direction the character it replaces did not
    // have. U+2121 is a symbol of neutral direction and its form KC is TEL,
    // three left-to-right letters, so a value holding it beside Hebrew ones
    // is right-to-left before the step and mixed after it. Read too early,
    // the value would be folded on a direction it does not have once
    // prepared, and two spellings that the profile leaves unequal would
    // match.
    let utf8_form = seq(&[part(oid::ORGANIZATION, utf8("א℡א"))]);
    let bmp_form = seq(&[part(oid::ORGANIZATION, bmp("א℡א"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        !parse(&one, &utf8_form)
            .unwrap()
            .matches(
                &parse(&other, &bmp_form).unwrap(),
                &crate::fixtures::memory()
            )
            .unwrap()
    );

    // The same bytes stay the same name, which is what a value without a
    // preparation falls back to.
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &utf8_form)
            .unwrap()
            .matches(
                &parse(&other, &utf8_form).unwrap(),
                &crate::fixtures::memory()
            )
            .unwrap()
    );

    // A value that is right-to-left throughout still folds across the
    // encodings, expansion or none.
    let utf8_form = seq(&[part(oid::ORGANIZATION, utf8("בית הדפוס"))]);
    let bmp_form = seq(&[part(oid::ORGANIZATION, bmp("בית הדפוס"))]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &utf8_form)
            .unwrap()
            .matches(
                &parse(&other, &bmp_form).unwrap(),
                &crate::fixtures::memory()
            )
            .unwrap()
    );
}

#[test]
fn a_value_wider_than_a_person_reads_is_shown_up_to_the_bound() {
    // Reading a value for a report is not the same question as comparing
    // it, and this one is public: an attribute type with no ceiling in the
    // schema could hand a report a string as wide as the element limit
    // permits. What is shown is as much of it as the widest name component
    // the profile names, and a mark saying the rest is there.
    let wide = "a".repeat(40_000);
    let der = seq(&[part(oid::ORGANIZATION_IDENTIFIER, utf8(&wide))]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();
    let owned = name
        .attributes()
        .next()
        .unwrap()
        .text(&crate::fixtures::memory())
        .unwrap()
        .unwrap();
    let shown = owned.as_str(&crate::fixtures::memory()).unwrap();
    assert_eq!(shown.chars().count(), 32_769);
    assert!(shown.ends_with('…'));
    assert!(shown.starts_with("aaaa"));

    // Inside the bound the value is shown whole, with no mark.
    let narrow = "a".repeat(32_768);
    let der = seq(&[part(oid::ORGANIZATION_IDENTIFIER, utf8(&narrow))]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();
    let owned = name
        .attributes()
        .next()
        .unwrap()
        .text(&crate::fixtures::memory())
        .unwrap()
        .unwrap();
    let shown = owned.as_str(&crate::fixtures::memory()).unwrap();
    assert_eq!(shown, narrow);

    // The same bound over a sixteen-bit value, which decodes two octets to
    // a character.
    let der = seq(&[part(oid::COMMON_NAME, bmp(&wide))]);
    let parser = Parser::der(crate::fixtures::memory());
    let name = parse(&parser, &der).unwrap();
    let owned = name
        .attributes()
        .next()
        .unwrap()
        .text(&crate::fixtures::memory())
        .unwrap()
        .unwrap();
    let shown = owned.as_str(&crate::fixtures::memory()).unwrap();
    assert_eq!(shown.chars().count(), 32_769);
    assert!(shown.ends_with('…'));
}

#[test]
fn funded_wide_values_keep_the_same_preparation_rule() {
    // RFC5280 §7.1 requires StringPrep, including beyond display's bound.
    // The iterative, accounted normalizer handles a long combining sequence;
    // width changes neither caseIgnoreMatch nor composition semantics.
    let wide = "\u{0301}".repeat(32_769);
    let upper = seq(&[part(
        oid::ORGANIZATION_IDENTIFIER,
        utf8(&alloc::format!("A{wide}")),
    )]);
    let lower = seq(&[part(
        oid::ORGANIZATION_IDENTIFIER,
        utf8(&alloc::format!("a{wide}")),
    )]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &upper)
            .unwrap()
            .matches(&parse(&other, &lower).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // A short sequence follows the identical rule.
    let narrow = "\u{0301}".repeat(64);
    let upper = seq(&[part(
        oid::ORGANIZATION_IDENTIFIER,
        utf8(&alloc::format!("A{narrow}")),
    )]);
    let lower = seq(&[part(
        oid::ORGANIZATION_IDENTIFIER,
        utf8(&alloc::format!("a{narrow}")),
    )]);
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    assert!(
        parse(&one, &upper)
            .unwrap()
            .matches(&parse(&other, &lower).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );
}

#[test]
fn a_name_spelled_in_either_composition_is_one_name() {
    // The preparation normalizes to form KC (RFC 4518 2.3) before comparing,
    // and the two spellings of an accented letter are the same letter: one
    // code point, or the plain letter followed by the combining accent. Which
    // one a certificate carries is decided by whatever typed it, so a name
    // that matches on one operating system and not on another would leave a
    // genuine path unbuilt for half the people who look at it.
    for (composed, decomposed) in [
        ("École", "E\u{0301}cole"),
        // Ukrainian yi, which decomposes the same way, onto the Cyrillic
        // letter it is built from rather than the Latin one that looks it.
        ("КИЇВ", "КИ\u{0406}\u{0308}В"),
    ] {
        let one = Parser::der(crate::fixtures::memory());
        let other = Parser::der(crate::fixtures::memory());
        let left = seq(&[part(oid::ORGANIZATION, utf8(composed))]);
        let right = seq(&[part(oid::ORGANIZATION, utf8(decomposed))]);
        assert!(
            parse(&one, &left)
                .unwrap()
                .matches(&parse(&other, &right).unwrap(), &crate::fixtures::memory())
                .unwrap(),
            "{composed}"
        );
    }

    // Compatibility equivalence is part of the same step: the form KC folds
    // a letterform back to the letter it is a presentation of.
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let left = seq(&[part(oid::ORGANIZATION, utf8("\u{FF21}\u{FF22}"))]);
    let right = seq(&[part(oid::ORGANIZATION, utf8("ab"))]);
    assert!(
        parse(&one, &left)
            .unwrap()
            .matches(&parse(&other, &right).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );

    // Normalizing is not erasing: an accent still tells two names apart.
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let left = seq(&[part(oid::ORGANIZATION, utf8("École"))]);
    let right = seq(&[part(oid::ORGANIZATION, utf8("Ecole"))]);
    assert!(
        !parse(&one, &left)
            .unwrap()
            .matches(&parse(&other, &right).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );
}

#[test]
fn a_fold_that_changes_a_letters_length_is_still_a_fold() {
    // The table folds a few letters to more than one character, and a German
    // organization name is the everyday case: STRASSE, Straße and STRAẞE are
    // one name, and treating the sharp s as its own letter leaves a genuine
    // path unbuilt over a spelling.
    for (left, right) in [
        ("Straße", "STRASSE"),
        // Final sigma is the same letter as sigma, and Greek writes it
        // wherever the word ends, so a name in capitals and the same name in
        // lowercase differ in that letter and in no other way.
        ("ΟΔΟΣ", "οδος"),
        // A ligature is the letters it is made of.
        ("ﬁnal", "FINAL"),
    ] {
        let one = Parser::der(crate::fixtures::memory());
        let other = Parser::der(crate::fixtures::memory());
        let left = seq(&[part(oid::ORGANIZATION, utf8(left))]);
        let right = seq(&[part(oid::ORGANIZATION, utf8(right))]);
        assert!(
            parse(&one, &left)
                .unwrap()
                .matches(&parse(&other, &right).unwrap(), &crate::fixtures::memory())
                .unwrap(),
            "{left:02x?}"
        );
    }

    // The capital sharp s is the letter the profile does not reach: it was
    // added to Unicode after 3.2, which is the repertoire the preparation is
    // defined over, so a name carrying it is compared as bytes and does not
    // fold onto the spelling with two letters. That costs a match between
    // two ways of writing one name, and it is the loss the profile chooses:
    // a fold this layer invented could equally join two names that are not
    // one.
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let capital = seq(&[part(oid::ORGANIZATION, utf8("STRAẞE"))]);
    let spelled = seq(&[part(oid::ORGANIZATION, utf8("strasse"))]);
    assert!(
        !parse(&one, &capital)
            .unwrap()
            .matches(
                &parse(&other, &spelled).unwrap(),
                &crate::fixtures::memory()
            )
            .unwrap()
    );

    // Folding more is not folding everything: a name is not the same as one
    // whose letters merely start the same way.
    let one = Parser::der(crate::fixtures::memory());
    let other = Parser::der(crate::fixtures::memory());
    let left = seq(&[part(oid::ORGANIZATION, utf8("Straße"))]);
    let right = seq(&[part(oid::ORGANIZATION, utf8("Stras"))]);
    assert!(
        !parse(&one, &left)
            .unwrap()
            .matches(&parse(&other, &right).unwrap(), &crate::fixtures::memory())
            .unwrap()
    );
}

/// A name prepared once orders exactly the way comparing them does.
///
/// The preparation exists so that a caller ordering a set of names does not
/// put a multi-valued part in order inside every comparison. It is only worth
/// having if it is the same order: two names differing by the order of a part's
/// attributes are one name, since a part is a set, and a preparation that kept
/// them as written would separate names the matching calls equal.
#[test]
fn a_prepared_name_orders_the_way_the_names_themselves_do() {
    // Two names holding one part of two attributes, saying the same thing. The
    // distinguished rules order a set by whole encodings, so the trailing
    // spaces, which the preparation drops, are enough to write the two
    // attributes in one order here and the other order there.
    let attributes = |common: &str, organization: &str| {
        seq(&[set(&[
            seq(&[oid_of(oid::COMMON_NAME), utf8(common)]),
            seq(&[oid_of(oid::ORGANIZATION), utf8(organization)]),
        ])])
    };
    let written = attributes("Ada", "Works");
    let other_way = seq(&[set(&[
        seq(&[oid_of(oid::ORGANIZATION), utf8("Works")]),
        seq(&[oid_of(oid::COMMON_NAME), utf8("Ada     ")]),
    ])]);

    let one = Parser::der(crate::fixtures::memory());
    let two = Parser::der(crate::fixtures::memory());
    let left = parse(&one, &written).unwrap();
    let right = parse(&two, &other_way).unwrap();

    assert!(
        left.matches(&right, &crate::fixtures::memory()).unwrap(),
        "a part is a set, so this is one name"
    );
    assert_eq!(
        left.order(&right, &crate::fixtures::memory()).unwrap(),
        core::cmp::Ordering::Equal
    );
    assert_eq!(
        left.ordered(&crate::fixtures::memory())
            .unwrap()
            .order(
                &right.ordered(&crate::fixtures::memory()).unwrap(),
                &crate::fixtures::memory()
            )
            .unwrap(),
        core::cmp::Ordering::Equal,
        "and the prepared form says the same thing"
    );

    // And a name that really is different orders the same way both ways round,
    // so the preparation is an ordering rather than a way of calling
    // everything equal.
    let three = Parser::der(crate::fixtures::memory());
    let different = attributes("Ada", "Elsewhere");
    let elsewhere = parse(&three, &different).unwrap();
    assert_eq!(
        left.ordered(&crate::fixtures::memory())
            .unwrap()
            .order(
                &elsewhere.ordered(&crate::fixtures::memory()).unwrap(),
                &crate::fixtures::memory()
            )
            .unwrap(),
        left.order(&elsewhere, &crate::fixtures::memory()).unwrap()
    );
    assert!(
        left.order(&elsewhere, &crate::fixtures::memory())
            .unwrap()
            .is_ne()
    );
}
