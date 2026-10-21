//! Original AC IETF value syntax, registration and scoped resource ownership.
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_cms::ErrorCode;
use structured_cms::attribute::Attribute;
use structured_cms::attribute_certificate::AttributeCertificate;
use structured_cms::attribute_certificate::ietf::{
    CHARGING_IDENTITY, Choice, GROUP, IetfAttrSyntax, Value,
};
use structured_pkix::general_name::GeneralName;

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}
fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if bytes.len() < 128 {
        result.push(u8::try_from(bytes.len()).unwrap());
    } else if bytes.len() < 256 {
        result.extend([0x81, u8::try_from(bytes.len()).unwrap()]);
    } else {
        result.extend([
            0x82,
            u8::try_from(bytes.len() >> 8).unwrap(),
            u8::try_from(bytes.len() & 255).unwrap(),
        ]);
    }
    result.extend(bytes);
    result
}
fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn syntax(authority: Option<&[u8]>, values: &[&[u8]]) -> Vec<u8> {
    seq(&[authority.unwrap_or(&[]), &seq(values)])
}
fn attr(kind: Oid<'_>, values: &[Vec<u8>]) -> Vec<u8> {
    let mut values = values.to_vec();
    values.sort();
    seq(&[&tlv(6, kind.as_bytes()), &tlv(0x31, &values.concat())])
}
fn read_attr<'a>(parser: &'a Parser, bytes: &'a [u8]) -> Attribute<'a> {
    let mut reader = parser.read(bytes, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    Attribute::read(&reader, &element, "attribute").unwrap()
}

#[test]
fn all_choices_remain_borrowed_in_original_order() {
    // Each supported syntax has one homogeneous catalogue with untouched bytes.
    for (first, second, expected) in [
        (tlv(4, b"one"), tlv(4, b"two"), Choice::Octets),
        (tlv(6, &[42]), tlv(6, &[43]), Choice::Oid),
        (tlv(12, "équipe".as_bytes()), tlv(12, b"team"), Choice::Utf8),
    ] {
        let bytes = syntax(None, &[&first, &second]);
        let mem = memory(1 << 20, 1 << 24);
        let parser = Parser::der(mem.clone());
        let mut reader = parser.read(&bytes, 700).unwrap();
        let value = IetfAttrSyntax::read(&mut reader).unwrap();
        drop(reader);
        assert_eq!(value.choice(), Some(expected));
        assert_eq!(value.values().len(), 2);
        assert!(value.authority().is_none());
        for member in value.values() {
            let start = usize::try_from(member.element.span().start - 700).unwrap();
            assert_eq!(member.element.as_bytes().as_ptr(), bytes[start..].as_ptr());
            assert_eq!(member.value.choice(), expected);
        }
        match value.values()[0].value {
            Value::Octets(bytes) => assert_eq!(bytes, b"one"),
            Value::Oid(oid) => assert_eq!(oid.as_bytes(), &[42]),
            Value::Utf8(text) => assert_eq!(text, "équipe"),
        }
        drop(value);
        assert_eq!(mem.used(), 0);
    }
}

#[test]
fn empty_values_and_empty_contents_do_not_invent_a_choice() {
    // No SIZE bound exists on the values sequence; empty contents are also legal.
    let bytes = syntax(None, &[]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let mut reader = parser.read(&bytes, 0).unwrap();
    let value = IetfAttrSyntax::read(&mut reader).unwrap();
    assert_eq!(value.choice(), None);
    assert!(value.values().is_empty());
    for member in [tlv(4, &[]), tlv(12, &[])] {
        let bytes = syntax(None, &[&member]);
        let mut reader = parser.read(&bytes, 0).unwrap();
        assert_eq!(IetfAttrSyntax::read(&mut reader).unwrap().values().len(), 1);
    }
}

#[test]
fn policy_authority_is_implicit_and_preserves_names_and_range() {
    // GeneralNames is implicitly tagged, distinct from the AC issuer itself.
    let authority = tlv(
        0xa0,
        &[
            tlv(0x82, b"authority.test"),
            tlv(0x86, b"urn:authority:one"),
        ]
        .concat(),
    );
    let bytes = syntax(Some(&authority), &[&tlv(12, b"group")]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let mut reader = parser.read(&bytes, 400).unwrap();
    let value = IetfAttrSyntax::read(&mut reader).unwrap();
    assert!(matches!(
        value.authority().unwrap(),
        [
            GeneralName::Dns("authority.test"),
            GeneralName::Uri("urn:authority:one")
        ]
    ));
    let element = value.authority_element().unwrap();
    assert_eq!(element.as_bytes(), authority);
    assert!(element.span().start > 400);
}

#[test]
fn every_mixed_choice_refuses_at_the_first_different_member() {
    // All ordered pairs must reject, not only an OID followed by text.
    let variants = [tlv(4, b"a"), tlv(6, &[42]), tlv(12, b"a")];
    for (i, left) in variants.iter().enumerate() {
        for (j, right) in variants.iter().enumerate() {
            if i == j {
                continue;
            }
            let bytes = syntax(None, &[left, right]);
            let parser = Parser::der(memory(1 << 20, 1 << 24));
            let mut reader = parser.read(&bytes, 700).unwrap();
            let error = IetfAttrSyntax::read(&mut reader).unwrap_err();
            assert_eq!(error.code(), ErrorCode::AttributeSyntax);
            assert_eq!(
                error.offset(),
                700 + u64::try_from(bytes.len() - right.len()).unwrap()
            );
        }
    }
}

#[test]
fn malformed_fields_and_compatibility_spellings_do_not_succeed() {
    // Missing/trailing/repeated authority, untagged VOMS and explicit wrappers
    // cannot become a valid registered AC attribute by guessing a grammar.
    let authority = tlv(0xa0, &tlv(0x82, b"authority.test"));
    let text = tlv(12, b"group");
    let valid = syntax(None, &[&text]);
    let cases = [
        seq(&[]),
        seq(&[&authority]),
        seq(&[&tlv(0xa0, &[]), &seq(&[])]),
        seq(&[&seq(&[&tlv(0x82, b"authority.test")]), &seq(&[&text])]),
        seq(&[
            &tlv(0xa0, &seq(&[&tlv(0x82, b"authority.test")])),
            &seq(&[&text]),
        ]),
        seq(&[&authority, &authority, &seq(&[])]),
        seq(&[&seq(&[&text]), &[5, 0]]),
        syntax(None, &[&[6, 0]]),
        syntax(None, &[&[6, 1, 128]]),
        syntax(None, &[&[12, 1, 255]]),
        syntax(None, &[&[2, 1, 1]]),
        syntax(None, &[&tlv(0x24, &tlv(4, b"a"))]),
        syntax(None, &[&tlv(0x2c, &tlv(4, b"a"))]),
        [valid, vec![5, 0]].concat(),
    ];
    for bytes in cases {
        let mem = memory(1 << 20, 1 << 24);
        let parser = Parser::ber(mem.clone());
        let mut reader = parser.read(&bytes, 300).unwrap();
        assert!(IetfAttrSyntax::read(&mut reader).is_err(), "{bytes:x?}");
        drop(reader);
        assert_eq!(mem.used(), 0);
    }
}

#[test]
fn registered_attributes_require_singleton_and_known_oid() {
    // Inner multiplicity is legal; multiple outer AttributeValues are not.
    let value = syntax(None, &[&tlv(12, b"one"), &tlv(12, b"two")]);
    for kind in [GROUP, CHARGING_IDENTITY] {
        let bytes = attr(kind, std::slice::from_ref(&value));
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let attribute = read_attr(&parser, &bytes);
        assert_eq!(
            IetfAttrSyntax::read_attribute(&attribute, parser.memory())
                .unwrap()
                .values()
                .len(),
            2
        );
        for values in [vec![], vec![value.clone(), value.clone()]] {
            let bytes = attr(kind, &values);
            let attribute = read_attr(&parser, &bytes);
            assert_eq!(
                IetfAttrSyntax::read_attribute(&attribute, parser.memory())
                    .unwrap_err()
                    .code(),
                ErrorCode::AttributeCardinality
            );
        }
    }
    let bytes = attr(Oid::from_bytes(&[42]), &[value]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let attribute = read_attr(&parser, &bytes);
    assert_eq!(
        IetfAttrSyntax::read_attribute(&attribute, parser.memory())
            .unwrap_err()
            .code(),
        ErrorCode::UnexpectedContentType
    );
}

#[test]
fn short_current_query_does_not_bound_retained_input_lifetime() {
    // The result survives both the Attribute catalogue and current query Parser.
    let bytes = attr(GROUP, &[syntax(None, &[&tlv(12, b"group")])]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let retained = {
        let attribute = read_attr(&parser, &bytes);
        let operation = Parser::der(memory(1 << 20, 1 << 24));
        let reader = operation.read(&[], 80).unwrap();
        IetfAttrSyntax::read_attribute(&attribute, &reader.execution()).unwrap()
    };
    assert!(matches!(retained.values()[0].value, Value::Utf8("group")));
    assert!(retained.element().span().start > 900);
}

#[test]
fn scoped_lookup_funds_absence_before_returning_none() {
    // Missing indices are absence only after current and original work admission.
    let bytes = attr(GROUP, &[syntax(None, &[])]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let attribute = read_attr(&parser, &bytes);
    assert!(
        attribute
            .value_reader_scoped(5, parser.memory(), "query")
            .unwrap()
            .is_none()
    );
    assert!(
        attribute
            .value_reader_scoped(5, &memory(0, 0), "query")
            .is_err()
    );
    let current = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let reader = current.read(&[], 80).unwrap();
    assert!(IetfAttrSyntax::read_attribute(&attribute, &reader.execution()).is_err());
    let source = parser.read(&[], 0).unwrap();
    source
        .charge(source.execution().work_remaining() as u64)
        .unwrap();
    assert!(
        attribute
            .value_reader_scoped(5, &memory(1 << 20, 1 << 24), "query")
            .is_err()
    );
}

#[test]
fn resource_refusal_releases_partial_names_and_member_catalogues() {
    // Decode rollback releases authority and earlier members, not consumed work.
    let authority = tlv(0xa0, &tlv(0x82, b"authority.test"));
    let member = tlv(12, b"group");
    let values = tlv(0x30, &member.repeat(32));
    let bytes = attr(GROUP, &[seq(&[&authority, &values])]);
    let parser = Parser::der(memory(1 << 20, 1 << 26));
    let attribute = read_attr(&parser, &bytes);
    let mut success = false;
    let mut refusal = false;
    for capacity in [0, 16, 64, 256, 512, 1024, 2048, 4096, 8192, 16384] {
        let query = memory(capacity, 1 << 24);
        let result = IetfAttrSyntax::read_attribute(&attribute, &query);
        if result.is_ok() {
            success = true;
        } else {
            refusal = true;
        }
        drop(result);
        assert_eq!(query.used(), 0);
    }
    assert!(success && refusal);
    for work in [0, 1, 17, 50, 100, 200] {
        let query = memory(1 << 20, work);
        assert!(IetfAttrSyntax::read_attribute(&attribute, &query).is_err());
        assert_eq!(query.used(), 0);
        assert!(query.work_used() <= work);
    }
}

#[test]
fn lazy_read_keeps_original_depth_and_rejects_non_der_headers() {
    // Attribute creation skips nested semantics under BER; lazy AC interpretation
    // still applies original depth and DER instead of a new default Parser.
    let nested = syntax(
        Some(&tlv(0xa0, &tlv(0x82, b"authority.test"))),
        &[&tlv(12, b"group")],
    );
    let bytes = attr(GROUP, &[nested]);
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 2,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let attribute = read_attr(&parser, &bytes);
    assert!(IetfAttrSyntax::read_attribute(&attribute, &memory(1 << 20, 1 << 24)).is_err());
    for value in [
        vec![0x30, 0x81, 2, 0x30, 0],
        vec![0x30, 0x80, 0x30, 0, 0, 0],
    ] {
        let bytes = attr(GROUP, &[value]);
        let parser = Parser::ber(memory(1 << 20, 1 << 24));
        let attribute = read_attr(&parser, &bytes);
        assert!(IetfAttrSyntax::read_attribute(&attribute, parser.memory()).is_err());
    }
}

#[test]
fn full_ac_attributes_use_shared_reader_without_changing_signature_input() {
    // Real AC wiring exercises the already-parsed Attribute, not a fabricated wrapper.
    let attribute = attr(GROUP, &[syntax(None, &[&tlv(12, b"printers")])]);
    let algorithm = seq(&[&[6, 1, 42]]);
    let signed = seq(&[
        &[2, 1, 1],
        &seq(&[]),
        &seq(&[&tlv(0x82, b"issuer.test")]),
        &algorithm,
        &[2, 1, 1],
        &seq(&[&tlv(24, b"20261021000000Z"), &tlv(24, b"20271021000000Z")]),
        &seq(&[&attribute]),
    ]);
    let bytes = seq(&[&signed, &algorithm, &[3, 2, 0, 9]]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let mut reader = parser.read(&bytes, 500).unwrap();
    let ac = AttributeCertificate::read(&mut reader).unwrap();
    let value =
        IetfAttrSyntax::read_attribute(&ac.information().attributes[0], &reader.execution())
            .unwrap();
    assert!(matches!(value.values()[0].value, Value::Utf8("printers")));
    assert_eq!(ac.signed_bytes(), signed);
    let start = usize::try_from(ac.signed_element().span().start - 500).unwrap();
    assert_eq!(ac.signed_bytes().as_ptr(), bytes[start..].as_ptr());
}

#[test]
fn scoped_attribute_cursor_preserves_original_ber_and_coordinates() {
    // The general Attribute helper preserves BER; only the AC IETF reader adds DER.
    let encoded = vec![0x24, 0x80, 4, 1, 7, 0, 0];
    let bytes = attr(GROUP, std::slice::from_ref(&encoded));
    let parser = Parser::ber(memory(1 << 20, 1 << 24));
    let attribute = read_attr(&parser, &bytes);
    let operation = Parser::der(memory(1 << 20, 1 << 24));
    let query = operation.read(&[], 100).unwrap();
    let execution = query.execution();
    let mut reader = attribute
        .value_reader_scoped(0, &execution, "original")
        .unwrap()
        .unwrap();
    assert_eq!(reader.encoding(), Encoding::Ber);
    let value = reader.next_element().unwrap().unwrap();
    assert_eq!(value.as_bytes(), encoded);
    assert_eq!(value.span(), attribute.values()[0].span());
    assert_eq!(
        value.as_bytes().as_ptr(),
        attribute.values()[0].as_bytes().as_ptr()
    );
    assert!(reader.is_empty());
}

#[test]
fn registration_preflight_precedes_payload_or_storage_work() {
    // Wrong OID/cardinality refuse using only paid metadata, with zero capacity.
    for (kind, values, expected) in [
        (
            Oid::from_bytes(&[42]),
            vec![vec![5, 0]],
            ErrorCode::UnexpectedContentType,
        ),
        (
            GROUP,
            vec![vec![5, 0], vec![5, 0]],
            ErrorCode::AttributeCardinality,
        ),
    ] {
        let bytes = attr(kind, &values);
        let parser = Parser::ber(memory(1 << 20, 1 << 24));
        let attribute = read_attr(&parser, &bytes);
        let work = memory(0, 17);
        assert_eq!(
            IetfAttrSyntax::read_attribute(&attribute, &work)
                .unwrap_err()
                .code(),
            expected
        );
        assert_eq!(work.work_used(), 17);
        assert_eq!(work.used(), 0);
    }
}
