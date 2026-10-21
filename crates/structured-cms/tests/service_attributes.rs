//! Public service/access identity reads and their source/resource boundaries.
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_cms::ErrorCode;
use structured_cms::attribute::Attribute;
use structured_cms::attribute_certificate::AttributeCertificate;
use structured_cms::attribute_certificate::service::{
    ACCESS_IDENTITY, AUTHENTICATION_INFO, SvceAuthInfo,
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
fn syntax(service: &[u8], ident: &[u8], auth: Option<&[u8]>) -> Vec<u8> {
    seq(&[
        service,
        ident,
        &auth.map_or_else(Vec::new, |bytes| tlv(4, bytes)),
    ])
}
fn ordinary(auth: Option<&[u8]>) -> Vec<u8> {
    syntax(
        &tlv(0x86, b"urn:service"),
        &tlv(0x81, b"user@example.test"),
        auth,
    )
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
fn directory(text: &[u8]) -> Vec<u8> {
    tlv(
        0xa4,
        &seq(&[&tlv(0x31, &seq(&[&[6, 3, 85, 4, 3], &tlv(12, text)]))]),
    )
}

#[test]
fn fields_borrow_original_octets_and_physical_ranges() {
    // Service, identity and credential accessors expose exactly original bytes.
    let bytes = ordinary(Some(b"opaque-credentials"));
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let mut reader = parser.read(&bytes, 700).unwrap();
    let value = SvceAuthInfo::read(&mut reader).unwrap();
    assert!(matches!(value.service(), GeneralName::Uri("urn:service")));
    assert!(matches!(
        value.ident(),
        GeneralName::Email("user@example.test")
    ));
    assert_eq!(value.auth_info(), Some(b"opaque-credentials".as_slice()));
    assert_eq!(value.element().as_bytes().as_ptr(), bytes.as_ptr());
    for element in [
        value.service_element(),
        value.ident_element(),
        value.auth_info_element().unwrap(),
    ] {
        let start = usize::try_from(element.span().start - 700).unwrap();
        assert_eq!(element.as_bytes().as_ptr(), bytes[start..].as_ptr());
    }
    let auth = value.auth_info_element().unwrap();
    assert_eq!(
        value.auth_info().unwrap().as_ptr(),
        auth.contents().as_ptr()
    );
    assert_eq!(value.element().span().start, 700);
}

#[test]
fn absent_and_present_empty_authentication_are_distinct() {
    // OCTET STRING has no SIZE restriction; presence is not inferred from length.
    for auth in [None, Some(b"".as_slice()), Some(b"value".as_slice())] {
        let bytes = ordinary(auth);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let mut reader = parser.read(&bytes, 0).unwrap();
        let value = SvceAuthInfo::read(&mut reader).unwrap();
        assert_eq!(value.auth_info(), auth);
        assert_eq!(value.auth_info_element().is_some(), auth.is_some());
    }
}

#[test]
fn all_general_name_choices_use_the_existing_kernel() {
    // Neither service nor ident is restricted to URI; every GeneralName choice works.
    let forms = [
        tlv(
            0xa0,
            &seq(&[&[6, 1, 42], &tlv(0xa0, &tlv(12, b"other"))])[2..],
        ),
        tlv(0x81, b"user@example.test"),
        tlv(0x82, b"host.test"),
        tlv(0xa3, &seq(&[])),
        directory(b"Holder"),
        tlv(0xa5, &tlv(0xa1, &tlv(12, b"party"))),
        tlv(0x86, b"urn:service"),
        tlv(0x87, &[127, 0, 0, 1]),
        tlv(0x88, &[42]),
    ];
    for (index, name) in forms.iter().enumerate() {
        let bytes = syntax(name, name, None);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let mut reader = parser.read(&bytes, 0).unwrap();
        let value = SvceAuthInfo::read(&mut reader).unwrap();
        for decoded in [value.service(), value.ident()] {
            let variant = match decoded {
                GeneralName::Other { .. } => 0,
                GeneralName::Email(_) => 1,
                GeneralName::Dns(_) => 2,
                GeneralName::X400(_) => 3,
                GeneralName::Directory(_) => 4,
                GeneralName::EdiParty(_) => 5,
                GeneralName::Uri(_) => 6,
                GeneralName::IpAddress(_) => 7,
                GeneralName::RegisteredId(_) => 8,
                _ => panic!("unexpected new name choice"),
            };
            assert_eq!(variant, index);
        }
        assert_eq!(value.service_element().as_bytes(), name);
        assert_eq!(value.ident_element().as_bytes(), name);
    }
}

#[test]
fn malformed_missing_and_trailing_components_refuse_completely() {
    // Required identities and the last optional field have an unambiguous layout.
    let service = tlv(0x86, b"urn:service");
    let ident = tlv(0x81, b"user@example.test");
    let cases = [
        seq(&[]),
        seq(&[&service]),
        seq(&[&service, &[5, 0]]),
        seq(&[&[5, 0], &ident]),
        seq(&[&tlv(0x82, b"bad..name"), &ident]),
        seq(&[&service, &tlv(0x81, b"invalid-mail")]),
        seq(&[&service, &ident, &[5, 0]]),
        seq(&[&service, &ident, &[4, 0], &[4, 0]]),
        seq(&[&service, &ident, &[4, 0], &[5, 0]]),
        seq(&[&service, &ident, &tlv(0x24, &tlv(4, b"auth"))]),
        seq(&[&tlv(0xa0, &service), &ident]),
        [ordinary(None), vec![5, 0]].concat(),
    ];
    for bytes in cases {
        let mem = memory(1 << 20, 1 << 24);
        let parser = Parser::ber(mem.clone());
        let mut reader = parser.read(&bytes, 300).unwrap();
        assert!(SvceAuthInfo::read(&mut reader).is_err(), "{bytes:x?}");
        drop(reader);
        assert_eq!(mem.used(), 0);
    }
}

#[test]
fn registered_types_preserve_multiple_values_and_access_prohibits_auth_info() {
    // Both OIDs allow many values, but accessIdentity forbids even empty authInfo.
    for kind in [AUTHENTICATION_INFO, ACCESS_IDENTITY] {
        let bytes = attr(kind, &[ordinary(None), ordinary(None)]);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let attribute = read_attr(&parser, &bytes);
        let values = SvceAuthInfo::read_attribute(&attribute, parser.memory()).unwrap();
        assert_eq!(values.len(), 2);
        for (value, original) in values.iter().zip(attribute.values()) {
            assert_eq!(value.element().span(), original.span());
            assert_eq!(
                value.element().as_bytes().as_ptr(),
                original.as_bytes().as_ptr()
            );
        }
    }
    for auth in [b"".as_slice(), b"credentials"] {
        for kind in [AUTHENTICATION_INFO, ACCESS_IDENTITY] {
            let bytes = attr(kind, &[ordinary(Some(auth))]);
            let parser = Parser::der(memory(1 << 20, 1 << 24));
            let attribute = read_attr(&parser, &bytes);
            let result = SvceAuthInfo::read_attribute(&attribute, parser.memory());
            if kind == AUTHENTICATION_INFO {
                assert_eq!(result.unwrap()[0].auth_info(), Some(auth));
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.code(), ErrorCode::AttributeSyntax);
                assert_eq!(error.field(), "attributeCertificate.svceAuthInfo.authInfo");
                assert!(error.offset() > attribute.values()[0].contents_span().start);
            }
        }
        let good = ordinary(None);
        let bytes = attr(ACCESS_IDENTITY, &[good.clone(), ordinary(Some(auth))]);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let attribute = read_attr(&parser, &bytes);
        assert_eq!(attribute.values()[0].as_bytes(), good);
        assert_eq!(
            SvceAuthInfo::read_attribute(&attribute, parser.memory())
                .unwrap_err()
                .code(),
            ErrorCode::AttributeSyntax
        );
    }
}

#[test]
fn registration_preflight_is_paid_and_precedes_value_decoding() {
    // Wrong types/empty catalogues refuse without payload work or storage.
    for (kind, values, code) in [
        (
            Oid::from_bytes(&[42]),
            vec![vec![5, 0]],
            ErrorCode::UnexpectedContentType,
        ),
        (AUTHENTICATION_INFO, vec![], ErrorCode::AttributeCardinality),
        (ACCESS_IDENTITY, vec![], ErrorCode::AttributeCardinality),
    ] {
        let bytes = attr(kind, &values);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let attribute = read_attr(&parser, &bytes);
        let current = memory(0, 17);
        let error = SvceAuthInfo::read_attribute(&attribute, &current).unwrap_err();
        assert_eq!(error.code(), code);
        assert_eq!(error.offset(), 900);
        assert_eq!(current.work_used(), 17);
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn late_invalid_value_and_name_failure_release_all_metadata() {
    // Earlier retained DirectoryNames cannot leak or become partial success.
    let good = syntax(&directory(b"Service"), &directory(b"Holder"), None);
    let bad = syntax(
        &directory(b"Service"),
        &tlv(0x82, b"bad..long.invalid.name.for.a.late.entry"),
        None,
    );
    let bytes = attr(AUTHENTICATION_INFO, &[good.clone(), bad]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let attribute = read_attr(&parser, &bytes);
    assert_eq!(attribute.values()[0].as_bytes(), good);
    let current = memory(1 << 20, 1 << 24);
    assert!(SvceAuthInfo::read_attribute(&attribute, &current).is_err());
    assert_eq!(current.used(), 0);
    assert!(current.work_used() > 17);
}

#[test]
fn retained_names_outlive_short_query_and_attribute_catalogue() {
    // Document borrows and metadata storage do not borrow the current query.
    let bytes = attr(
        AUTHENTICATION_INFO,
        &[syntax(
            &directory(b"Service"),
            &directory(b"Holder"),
            Some(b"auth"),
        )],
    );
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let query_memory = memory(1 << 20, 1 << 24);
    let retained = {
        let attribute = read_attr(&parser, &bytes);
        let current = Parser::der(query_memory.clone());
        let reader = current.read(&[], 80).unwrap();
        SvceAuthInfo::read_attribute(&attribute, &reader.execution()).unwrap()
    };
    assert!(matches!(retained[0].service(), GeneralName::Directory(_)));
    assert!(matches!(retained[0].ident(), GeneralName::Directory(_)));
    assert_eq!(retained[0].auth_info(), Some(b"auth".as_slice()));
    assert!(query_memory.used() > 0);
    drop(retained);
    assert_eq!(query_memory.used(), 0);
}

#[test]
fn capacity_and_aggregate_work_refusal_preserve_terminal_causes() {
    // Current storage/work covers every name/catalogue allocation and traversal.
    let value = syntax(&directory(b"Service"), &directory(b"Holder"), None);
    let bytes = attr(AUTHENTICATION_INFO, &vec![value; 8]);
    let parser = Parser::der(memory(1 << 20, 1 << 28));
    let attribute = read_attr(&parser, &bytes);
    let mut success = false;
    let mut refusal = false;
    for capacity in [0, 64, 256, 1024, 4096, 16384, 65536] {
        let current = memory(capacity, 1 << 24);
        let result = SvceAuthInfo::read_attribute(&attribute, &current);
        match &result {
            Ok(_) => success = true,
            Err(error) => {
                assert!(error.is_resource());
                refusal = true;
            }
        }
        drop(result);
        assert_eq!(current.used(), 0);
    }
    assert!(success && refusal);
    for work in [0, 1, 17, 50, 100, 1000] {
        let current = memory(1 << 20, work);
        assert!(
            SvceAuthInfo::read_attribute(&attribute, &current)
                .unwrap_err()
                .is_resource()
        );
        assert_eq!(current.used(), 0);
        assert!(current.work_used() <= work);
    }
}

#[test]
fn deferred_read_keeps_source_and_current_local_work() {
    // A fresh account cannot reset the source session or current parser ceiling.
    let bytes = attr(AUTHENTICATION_INFO, &[ordinary(None)]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let attribute = read_attr(&parser, &bytes);
    let current = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let reader = current.read(&[], 80).unwrap();
    assert!(
        SvceAuthInfo::read_attribute(&attribute, &reader.execution())
            .unwrap_err()
            .is_resource()
    );
    let original = parser.read(&[], 0).unwrap();
    original
        .charge(original.execution().work_remaining() as u64)
        .unwrap();
    assert!(
        SvceAuthInfo::read_attribute(&attribute, &memory(1 << 20, 1 << 24))
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn der_headers_and_original_depth_are_not_relaxed_by_ber_carrier() {
    // Lazy AC interpretation is DER and retains the producing depth, not defaults.
    let good = ordinary(None);
    for value in [
        [
            vec![0x30, 0x81, u8::try_from(good.len() - 2).unwrap()],
            good[2..].to_vec(),
        ]
        .concat(),
        [vec![0x30, 0x80], good[2..].to_vec(), vec![0, 0]].concat(),
        seq(&[
            &tlv(0x86, b"urn:service"),
            &tlv(0x81, b"a@test"),
            &[4, 0x81, 0],
        ]),
    ] {
        let bytes = attr(AUTHENTICATION_INFO, &[value]);
        let parser = Parser::ber(memory(1 << 20, 1 << 24));
        let attribute = read_attr(&parser, &bytes);
        assert!(SvceAuthInfo::read_attribute(&attribute, parser.memory()).is_err());
    }
    let bytes = attr(
        AUTHENTICATION_INFO,
        &[syntax(&directory(b"Service"), &directory(b"Holder"), None)],
    );
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
        SvceAuthInfo::read_attribute(&attribute, &memory(1 << 20, 1 << 24))
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn opaque_auth_bytes_are_borrowed_without_payload_sized_work_or_debug_output() {
    // Neither decoding nor Debug traverses/reveals service-specific credentials.
    let mut costs = Vec::new();
    for auth in [b"private-credential-marker".to_vec(), vec![0xff; 32768]] {
        let bytes = ordinary(Some(&auth));
        let mem = memory(1 << 20, 1 << 24);
        let parser = Parser::der(mem.clone());
        let mut reader = parser.read(&bytes, 0).unwrap();
        let value = SvceAuthInfo::read(&mut reader).unwrap();
        costs.push(mem.work_used());
        assert_eq!(
            value.auth_info().unwrap().as_ptr(),
            value.auth_info_element().unwrap().contents().as_ptr()
        );
        let debug = format!("{value:?}");
        assert!(!debug.contains("private-credential-marker"));
        assert!(!debug.contains("urn:service"));
        assert!(!debug.contains("user@example.test"));
        assert!(debug.len() < 300);
    }
    assert!(
        costs[1] - costs[0] < 32,
        "only extra length-header bytes cost work: {costs:?}"
    );
}

#[test]
fn actual_ac_authentication_and_access_values_preserve_signed_bytes() {
    // AC -> original Attribute -> registered reader, without fabricating wrappers.
    for kind in [AUTHENTICATION_INFO, ACCESS_IDENTITY] {
        let attribute = attr(kind, &[ordinary(None)]);
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
            SvceAuthInfo::read_attribute(&ac.information().attributes[0], &reader.execution())
                .unwrap();
        assert!(matches!(
            values[0].service(),
            GeneralName::Uri("urn:service")
        ));
        assert!(values[0].auth_info().is_none());
        assert_eq!(ac.signed_bytes(), signed);
        let start = usize::try_from(ac.signed_element().span().start - 500).unwrap();
        assert_eq!(ac.signed_bytes().as_ptr(), bytes[start..].as_ptr());
    }
}
