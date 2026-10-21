//! Public role decoding: original bytes, complete registration and resource bounds.
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_cms::ErrorCode;
use structured_cms::attribute::Attribute;
use structured_cms::attribute_certificate::AttributeCertificate;
use structured_cms::attribute_certificate::role::{IDENTIFIER, RoleSyntax};
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
fn role(authority: Option<&[u8]>, uri: &[u8]) -> Vec<u8> {
    seq(&[authority.unwrap_or(&[]), &tlv(0xa1, &tlv(0x86, uri))])
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
fn original_uri_and_both_wrappers_remain_borrowed() {
    // A role uses an EXPLICIT CHOICE wrapper; every source view is untouched.
    for uri in [b"urn:administrator".as_slice(), b"https://roles.test/a#b"] {
        let bytes = role(None, uri);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let mut reader = parser.read(&bytes, 700).unwrap();
        let value = RoleSyntax::read(&mut reader).unwrap();
        assert_eq!(value.name().as_bytes(), uri);
        assert!(value.authority().is_none());
        assert!(value.authority_element().is_none());
        assert_eq!(value.element().as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(value.element().span().start, 700);
        assert_eq!(value.name_wrapper().as_bytes(), tlv(0xa1, &tlv(0x86, uri)));
        let name = value.name_element();
        assert_eq!(name.as_bytes(), tlv(0x86, uri));
        let start = usize::try_from(name.contents_span().start - 700).unwrap();
        assert_eq!(value.name().as_ptr(), bytes[start..].as_ptr());
    }
}

#[test]
fn implicit_authority_is_optional_and_keeps_all_names() {
    // Authority is GeneralNames, not an explicit SEQUENCE or a selected issuer.
    let authority = tlv(
        0xa0,
        &[tlv(0x82, b"authority.test"), tlv(0x86, b"urn:authority")].concat(),
    );
    let bytes = role(Some(&authority), b"urn:administrator");
    let mem = memory(1 << 20, 1 << 24);
    let parser = Parser::der(mem.clone());
    let mut reader = parser.read(&bytes, 400).unwrap();
    let value = RoleSyntax::read(&mut reader).unwrap();
    assert!(matches!(
        value.authority().unwrap(),
        [
            GeneralName::Dns("authority.test"),
            GeneralName::Uri("urn:authority")
        ]
    ));
    assert_eq!(value.authority_element().unwrap().as_bytes(), authority);
    drop(reader);
    assert!(mem.used() > 0);
    drop(value);
    assert_eq!(mem.used(), 0);
}

#[test]
fn malformed_missing_repeated_and_misplaced_fields_refuse() {
    // Complete schema checks must not accept an authority alone or ignore tails.
    let authority = tlv(0xa0, &tlv(0x82, b"authority.test"));
    let name = tlv(0xa1, &tlv(0x86, b"urn:role"));
    let cases = [
        seq(&[]),
        seq(&[&authority]),
        seq(&[&tlv(0xa0, &[]), &name]),
        seq(&[&tlv(0xa0, &seq(&[&tlv(0x82, b"authority.test")])), &name]),
        seq(&[&authority, &authority, &name]),
        seq(&[&name, &authority]),
        seq(&[&name, &name]),
        seq(&[&name, &[5, 0]]),
        seq(&[&tlv(0x81, b"urn:role")]),
        seq(&[&tlv(0x86, b"urn:role")]),
        seq(&[&tlv(0xa1, &[])]),
        seq(&[&tlv(0xa1, &[tlv(0x86, b"urn:role"), vec![5, 0]].concat())]),
        seq(&[&tlv(0xa1, &tlv(0xa6, &tlv(0x16, b"urn:role")))]),
        [role(None, b"urn:role"), vec![5, 0]].concat(),
    ];
    for bytes in cases {
        let mem = memory(1 << 20, 1 << 24);
        let parser = Parser::ber(mem.clone());
        let mut reader = parser.read(&bytes, 300).unwrap();
        assert!(RoleSyntax::read(&mut reader).is_err(), "{bytes:x?}");
        drop(reader);
        assert_eq!(mem.used(), 0);
    }
}

#[test]
fn every_other_name_choice_and_invalid_uri_refuses() {
    // GeneralName decoding alone is insufficient: RFC5755 requires URI here.
    for tag in [0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x87, 0x88] {
        let bytes = seq(&[&tlv(0xa1, &tlv(tag, &[]))]);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let mut reader = parser.read(&bytes, 80).unwrap();
        let error = RoleSyntax::read(&mut reader).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnexpectedTag);
        assert_eq!(error.offset(), 84);
    }
    for uri in [
        b"".as_slice(),
        b"relative/path",
        b"urn:bad space",
        b"urn:%xz",
        &[255],
    ] {
        let bytes = role(None, uri);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let mut reader = parser.read(&bytes, 80).unwrap();
        assert!(RoleSyntax::read(&mut reader).is_err(), "{uri:x?}");
    }
}

#[test]
fn registered_role_permits_multiple_values_in_original_order() {
    // id-at-role permits multiple AttributeValues; no singleton restriction.
    let bytes = attr(
        IDENTIFIER,
        &[role(None, b"urn:one"), role(None, b"urn:two")],
    );
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let attribute = read_attr(&parser, &bytes);
    let values = RoleSyntax::read_attribute(&attribute, parser.memory()).unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].name(), "urn:one");
    assert_eq!(values[1].name(), "urn:two");
    for (value, original) in values.iter().zip(attribute.values()) {
        assert_eq!(value.element().span(), original.span());
        assert_eq!(
            value.element().as_bytes().as_ptr(),
            original.as_bytes().as_ptr()
        );
    }
}

#[test]
fn registration_preflight_refuses_before_payload_or_allocation() {
    // Paid bounded metadata suffices to refuse a wrong type or empty catalogue.
    for (kind, values, expected) in [
        (
            Oid::from_bytes(&[42]),
            vec![vec![5, 0]],
            ErrorCode::UnexpectedContentType,
        ),
        (IDENTIFIER, vec![], ErrorCode::AttributeCardinality),
    ] {
        let bytes = attr(kind, &values);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let attribute = read_attr(&parser, &bytes);
        let work = memory(0, 4);
        let error = RoleSyntax::read_attribute(&attribute, &work).unwrap_err();
        assert_eq!(error.code(), expected);
        assert_eq!(error.offset(), 900);
        assert_eq!(work.work_used(), 4);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn invalid_later_value_drops_earlier_role_and_authority_storage() {
    // A valid first role cannot hide an invalid second role or leak its storage.
    let authority = tlv(0xa0, &tlv(0x82, b"authority.test"));
    let good = role(Some(&authority), b"urn:role");
    let bad = seq(&[&authority, &tlv(0xa1, &tlv(0x82, b"not-a-uri.test"))]);
    let bytes = attr(IDENTIFIER, &[good, bad]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let attribute = read_attr(&parser, &bytes);
    let query = memory(1 << 20, 1 << 24);
    assert!(RoleSyntax::read_attribute(&attribute, &query).is_err());
    assert_eq!(query.used(), 0);
    assert!(query.work_used() > 4);
}

#[test]
fn short_query_lifetime_does_not_bound_retained_roles() {
    // The catalogue survives its Attribute/current Parser; URI stays borrowed.
    let authority = tlv(0xa0, &tlv(0x82, b"authority.test"));
    let bytes = attr(IDENTIFIER, &[role(Some(&authority), b"urn:role")]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let query_memory = memory(1 << 20, 1 << 24);
    let retained = {
        let attribute = read_attr(&parser, &bytes);
        let operation = Parser::der(query_memory.clone());
        let reader = operation.read(&[], 0).unwrap();
        RoleSyntax::read_attribute(&attribute, &reader.execution()).unwrap()
    };
    assert_eq!(retained[0].name(), "urn:role");
    assert!(query_memory.used() > 0);
    drop(retained);
    assert_eq!(query_memory.used(), 0);
}

#[test]
fn storage_and_work_refusals_are_terminal_and_rollback() {
    // Wide authority and role catalogues are admitted before growth or scans.
    let authority = tlv(0xa0, &tlv(0x82, b"authority.test").repeat(8));
    let bytes = attr(IDENTIFIER, &vec![role(Some(&authority), b"urn:role"); 8]);
    let parser = Parser::der(memory(1 << 20, 1 << 28));
    let attribute = read_attr(&parser, &bytes);
    let mut success = false;
    let mut refusal = false;
    for capacity in [0, 64, 256, 1024, 4096, 16384, 65536] {
        let query = memory(capacity, 1 << 24);
        let result = RoleSyntax::read_attribute(&attribute, &query);
        match &result {
            Ok(_) => success = true,
            Err(error) => {
                assert!(error.is_resource());
                refusal = true;
            }
        }
        drop(result);
        assert_eq!(query.used(), 0);
    }
    assert!(success && refusal);
    for work in [0, 1, 4, 20, 100, 1000] {
        let query = memory(1 << 20, work);
        assert!(
            RoleSyntax::read_attribute(&attribute, &query)
                .unwrap_err()
                .is_resource()
        );
        assert_eq!(query.used(), 0);
        assert!(query.work_used() <= work);
    }
}

#[test]
fn original_and_current_local_ceilings_remain_enforced() {
    // A fresh generous account cannot erase source or current query ceilings.
    let bytes = attr(IDENTIFIER, &[role(None, b"urn:role")]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let attribute = read_attr(&parser, &bytes);
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let reader = operation.read(&[], 0).unwrap();
    assert!(
        RoleSyntax::read_attribute(&attribute, &reader.execution())
            .unwrap_err()
            .is_resource()
    );
    let original = parser.read(&[], 0).unwrap();
    original
        .charge(original.execution().work_remaining() as u64)
        .unwrap();
    assert!(
        RoleSyntax::read_attribute(&attribute, &memory(1 << 20, 1 << 24))
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn element_entry_keeps_depth_and_der_even_in_ber_carrier() {
    // No new Parser or retagging can legalize BER spellings or reset nesting.
    let encoded = role(None, b"urn:role");
    for bytes in [
        [
            vec![0x30, 0x81, u8::try_from(encoded.len() - 2).unwrap()],
            encoded[2..].to_vec(),
        ]
        .concat(),
        [vec![0x30, 0x80], encoded[2..].to_vec(), vec![0, 0]].concat(),
        seq(&[&tlv(0xa1, &[0x86, 0x81, 1, b'a'])]),
    ] {
        let bytes = attr(IDENTIFIER, &[bytes]);
        let parser = Parser::ber(memory(1 << 20, 1 << 24));
        let attribute = read_attr(&parser, &bytes);
        assert!(RoleSyntax::read_attribute(&attribute, parser.memory()).is_err());
    }
    let bytes = attr(IDENTIFIER, &[encoded]);
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 2,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let attribute = read_attr(&parser, &bytes);
    assert!(
        RoleSyntax::read_attribute(&attribute, &memory(1 << 20, 1 << 24))
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn full_ac_role_read_preserves_signed_information() {
    // Production AC -> original Attribute -> registered role, with no re-encode.
    let attribute = attr(IDENTIFIER, &[role(None, b"urn:administrator")]);
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
    let values =
        RoleSyntax::read_attribute(&ac.information().attributes[0], &reader.execution()).unwrap();
    assert_eq!(values[0].name(), "urn:administrator");
    assert_eq!(ac.signed_bytes(), signed);
    let start = usize::try_from(ac.signed_element().span().start - 500).unwrap();
    assert_eq!(ac.signed_bytes().as_ptr(), bytes[start..].as_ptr());
}
