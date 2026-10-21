//! Public recipient targeting, original provenance and transitive admission.
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::attribute_certificate::AttributeCertificate;
use structured_cms::attribute_certificate::target::{
    CheckError, Decision, IDENTIFIER, Membership, TargetInformation, Value,
};
use structured_pkix::Extensions;
use structured_pkix::general_name::GeneralName;

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut value = vec![tag];
    if body.len() < 128 {
        value.push(u8::try_from(body.len()).unwrap());
    } else if body.len() < 256 {
        value.extend([0x81, u8::try_from(body.len()).unwrap()]);
    } else {
        value.extend([
            0x82,
            u8::try_from(body.len() >> 8).unwrap(),
            u8::try_from(body.len() & 255).unwrap(),
        ]);
    }
    value.extend(body);
    value
}
fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn target(group: bool, tag: u8, value: &[u8]) -> Vec<u8> {
    tlv(if group { 0xa1 } else { 0xa0 }, &tlv(tag, value))
}
fn targets(groups: &[&[u8]]) -> Vec<u8> {
    seq(groups)
}
fn extensions(payload: &[u8], critical: bool) -> Vec<u8> {
    seq(&[&seq(&[
        &tlv(6, IDENTIFIER.as_bytes()),
        if critical { &[1, 1, 255] } else { &[] },
        &tlv(4, payload),
    ])])
}
fn read<'a>(parser: &'a Parser, bytes: &'a [u8]) -> TargetInformation<'a> {
    let catalogue = catalogue(parser, bytes);
    TargetInformation::read(
        catalogue.get(IDENTIFIER, parser.memory()).unwrap().unwrap(),
        parser.memory(),
    )
    .unwrap()
}
fn catalogue<'a>(parser: &'a Parser, bytes: &'a [u8]) -> Extensions<'a> {
    let mut reader = parser.read(bytes, 700).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    Extensions::read_element(&reader, &element, "extensions").unwrap()
}
fn no_group(
    _: &GeneralName<'_>,
    _: &structured_asn1::memory::Execution<'_>,
) -> Result<Membership, ()> {
    panic!("no group callback expected")
}

#[test]
fn union_of_groups_and_original_identity() {
    // RFC5755 multiple Targets are a union, not selector-filter AND semantics.
    let bytes = extensions(
        &targets(&[
            &seq(&[&target(false, 0x82, b"other.test")]),
            &seq(&[&target(false, 0x82, b"EXAMPLE.TEST")]),
        ]),
        true,
    );
    let mem = memory(1 << 20, 1 << 24);
    let parser = Parser::der(mem.clone());
    let info = read(&parser, &bytes);
    assert_eq!(info.groups().len(), 2);
    assert_eq!(info.groups()[1].targets, 1..2);
    assert_eq!(info.targets()[1].group, 1);
    let element = info.targets()[1].element;
    assert_eq!(
        element.as_bytes().as_ptr(),
        bytes[usize::try_from(element.span().start - 700).unwrap()..].as_ptr()
    );
    let query = memory(0, 10000);
    assert_eq!(
        info.check(&[GeneralName::Dns("example.test")], &query, no_group)
            .unwrap(),
        Decision::Matches { target: 1 }
    );
    assert_eq!(query.used(), 0);
    assert!(query.work_used() > 0);
    drop(info);
    assert_eq!(mem.used(), 0);
}

#[test]
fn name_or_group_and_unknown_are_distinct() {
    // Group identity is caller knowledge, and does not require a direct name hit.
    let bytes = extensions(
        &targets(&[&seq(&[
            &target(false, 0x82, b"other.test"),
            &target(true, 0x86, b"urn:group:one"),
        ])]),
        true,
    );
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let info = read(&parser, &bytes);
    for (membership, expected) in [
        (Membership::Member, Decision::Matches { target: 1 }),
        (Membership::NotMember, Decision::Differs),
        (Membership::Unknown, Decision::Unproven),
    ] {
        let mut calls = 0;
        let result = info
            .check(
                &[GeneralName::Dns("example.test")],
                parser.memory(),
                |name, work| {
                    calls += 1;
                    work.charge_work(2).unwrap();
                    assert!(matches!(name, GeneralName::Uri("urn:group:one")));
                    Ok::<_, ()>(membership)
                },
            )
            .unwrap();
        assert_eq!(result, expected);
        assert_eq!(calls, 1);
    }
    let failure = info
        .check(&[], parser.memory(), |_, _| Err("original cause"))
        .unwrap_err();
    assert!(
        matches!(failure,CheckError::Callback{target,source:"original cause"} if target==info.targets()[1].element.span())
    );
}

fn target_cert() -> Vec<u8> {
    let issuer = seq(&[
        &seq(&[&tlv(0x82, b"issuer.test")]),
        &[2, 1, 7],
        &[3, 2, 0, 9],
    ]);
    let digest = seq(&[&[10, 1, 1], &seq(&[&[6, 1, 42]]), &[3, 2, 0, 8]]);
    tlv(0xa2, &[issuer, tlv(0x82, b"cert.test"), digest].concat())
}

#[test]
fn profile_preflight_precedes_every_positive_or_callback() {
    // A late targetCert must not be hidden by an earlier matching group/name.
    for critical in [true, false] {
        let bytes = extensions(
            &targets(&[&seq(&[
                &target(true, 0x82, b"group.test"),
                &target(false, 0x82, b"example.test"),
                &target_cert(),
            ])]),
            critical,
        );
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let info = read(&parser, &bytes);
        assert_eq!(info.certificates().len(), 1);
        let cert = &info.certificates()[0];
        assert_eq!(cert.certificate.serial.as_u64(), Some(7));
        assert!(cert.certificate.issuer_uid.is_some());
        assert!(matches!(cert.name, Some(GeneralName::Dns("cert.test"))));
        assert!(cert.digest.is_some());
        assert!(matches!(info.targets()[2].value, Value::Certificate(0)));
        let expected = if critical {
            Decision::ProhibitedTargetCertificate { target: 2 }
        } else {
            Decision::NonCritical
        };
        assert_eq!(
            info.check(
                &[GeneralName::Dns("example.test")],
                parser.memory(),
                no_group
            )
            .unwrap(),
            expected
        );
    }
}

#[test]
fn empty_present_never_means_absent_or_unrestricted() {
    // ASN.1 has no SIZE lower bound here; readable empty targets name nobody.
    for payload in [seq(&[]), seq(&[&seq(&[])])] {
        let bytes = extensions(&payload, true);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let info = read(&parser, &bytes);
        assert_eq!(
            info.check(&[], parser.memory(), no_group).unwrap(),
            Decision::Differs
        );
    }
}

#[test]
fn opaque_encoded_equality_cannot_prove_recipient_identity() {
    // otherName needs type-specific semantics; equal opaque bytes are no proof.
    let other = tlv(0xa0, &[tlv(6, &[42]), tlv(0xa0, &[5, 0])].concat());
    let bytes = extensions(&seq(&[&seq(&[&tlv(0xa0, &other)])]), true);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let info = read(&parser, &bytes);
    let Value::Name(name) = &info.targets()[0].value else {
        panic!()
    };
    assert_eq!(
        info.check(std::slice::from_ref(name), parser.memory(), no_group)
            .unwrap(),
        Decision::Unproven
    );
}

#[test]
fn mailbox_and_uri_use_the_existing_semantic_core() {
    // Host folding is permitted, mailbox local-part folding is not.
    let bytes = extensions(
        &seq(&[&seq(&[
            &target(false, 0x81, b"User@EXAMPLE.TEST"),
            &target(false, 0x86, b"https://EXAMPLE.TEST/a/../b"),
        ])]),
        true,
    );
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let info = read(&parser, &bytes);
    assert_eq!(
        info.check(
            &[GeneralName::Email("user@example.test")],
            parser.memory(),
            no_group
        )
        .unwrap(),
        Decision::Differs
    );
    assert_eq!(
        info.check(
            &[GeneralName::Email("User@example.test")],
            parser.memory(),
            no_group
        )
        .unwrap(),
        Decision::Matches { target: 0 }
    );
    assert_eq!(
        info.check(
            &[GeneralName::Uri("https://example.test/b")],
            parser.memory(),
            no_group
        )
        .unwrap(),
        Decision::Matches { target: 1 }
    );
}

#[test]
fn malformed_wrappers_and_late_fields_drop_partial_catalogues() {
    // A valid first target does not hide malformed later input or retain storage.
    let valid = target(false, 0x82, b"example.test");
    for bad in [
        tlv(0x80, b"example.test"),
        tlv(0xa0, &[]),
        tlv(0xa0, &[tlv(0x82, b"a.test"), tlv(0x82, b"b.test")].concat()),
        tlv(0xa3, &[]),
        tlv(0xa2, &[]),
        tlv(
            0xa2,
            &[
                seq(&[&seq(&[&tlv(0x82, b"issuer.test")]), &[2, 1, 1]]),
                vec![5, 0],
            ]
            .concat(),
        ),
    ] {
        let bytes = extensions(&seq(&[&seq(&[&valid, &bad])]), true);
        let mem = memory(1 << 20, 1 << 24);
        let parser = Parser::der(mem.clone());
        let catalogue = catalogue(&parser, &bytes);
        let retained = mem.used();
        assert!(
            TargetInformation::read(catalogue.get(IDENTIFIER, &mem).unwrap().unwrap(), &mem)
                .is_err()
        );
        assert_eq!(mem.used(), retained);
    }
}

#[test]
fn read_and_queries_keep_current_and_source_ceilings() {
    // A different query session cannot reset original work or bypass its own Work.
    let bytes = extensions(
        &seq(&[&seq(&[&target(false, 0x82, b"example.test")])]),
        true,
    );
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let catalogue = catalogue(&parser, &bytes);
    let extension = catalogue.get(IDENTIFIER, parser.memory()).unwrap().unwrap();
    let query = memory(0, 1 << 24);
    assert!(TargetInformation::read(extension, &query).is_err());
    assert_eq!(query.used(), 0);
    let info = {
        let operation = Parser::der(memory(1 << 20, 1 << 24));
        let reader = operation.read(&[], 500).unwrap();
        TargetInformation::read(extension, &reader.execution()).unwrap()
    };
    let query = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(0, 1 << 24),
    );
    let reader = query.read(&[], 100).unwrap();
    assert!(matches!(
        info.check(&[], &reader.execution(), no_group),
        Err(CheckError::Processing(_))
    ));
    let no_work = memory(0, 0);
    assert!(matches!(
        info.check(&[], &no_work, no_group),
        Err(CheckError::Processing(_))
    ));
    let source = parser.read(&[], 0).unwrap();
    let remaining = source.execution().work_remaining();
    source.charge(remaining as u64).unwrap();
    assert!(matches!(
        info.check(&[], &memory(0, 1 << 24), no_group),
        Err(CheckError::Processing(_))
    ));
}

#[test]
fn wrong_extension_and_inherited_depth_refuse_without_success() {
    // Wrong OIDs are rejected before payload decoding, and extension depth persists.
    let payload = seq(&[&seq(&[&target(false, 0x82, b"example.test")])]);
    let wrong = seq(&[&seq(&[&tlv(6, &[42]), &tlv(4, &payload)])]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let cat = catalogue(&parser, &wrong);
    let extension = cat
        .get(structured_asn1::Oid::from_bytes(&[42]), parser.memory())
        .unwrap()
        .unwrap();
    assert!(TargetInformation::read(extension, parser.memory()).is_err());
    let bytes = extensions(&payload, true);
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 3,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let cat = catalogue(&parser, &bytes);
    assert!(
        TargetInformation::read(
            cat.get(IDENTIFIER, parser.memory()).unwrap().unwrap(),
            parser.memory()
        )
        .is_err()
    );
}

fn ac(extension: &[u8]) -> Vec<u8> {
    let algorithm = seq(&[&[6, 1, 42]]);
    let attributes = seq(&[&seq(&[&[6, 1, 43], &[0x31, 2, 5, 0]])]);
    let signed = seq(&[
        &[2, 1, 1],
        &seq(&[]),
        &seq(&[&tlv(0x82, b"issuer.test")]),
        &algorithm,
        &[2, 1, 7],
        &seq(&[&tlv(24, b"20261021000000Z"), &tlv(24, b"20271021000000Z")]),
        &attributes,
        extension,
    ]);
    seq(&[&signed, &algorithm, &[3, 2, 0, 9]])
}
#[test]
fn certificate_lookup_wires_absence_and_targeting_without_reencoding() {
    // Full AC public lookup distinguishes unrestricted absence from restrictions.
    for extension in [
        &[][..],
        &extensions(
            &seq(&[&seq(&[&target(false, 0x82, b"example.test")])]),
            true,
        ),
    ] {
        let bytes = ac(extension);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let mut reader = parser.read(&bytes, 900).unwrap();
        let cert = AttributeCertificate::read(&mut reader).unwrap();
        let signed = cert.signed_bytes();
        let info = cert.target_information(&reader.execution()).unwrap();
        assert_eq!(info.is_none(), extension.is_empty());
        if let Some(info) = info {
            assert_eq!(
                info.check(
                    &[GeneralName::Dns("EXAMPLE.TEST")],
                    parser.memory(),
                    no_group
                )
                .unwrap(),
                Decision::Matches { target: 0 }
            );
        }
        assert_eq!(cert.signed_bytes().as_ptr(), signed.as_ptr());
    }
}

fn dn(text: &[u8]) -> Vec<u8> {
    seq(&[&tlv(0x31, &seq(&[&tlv(6, &[0x55, 4, 3]), &tlv(12, text)]))])
}

#[test]
fn directory_names_reuse_normalization_and_pay_query_scratch() {
    // Directory identity uses PKIX normalization, with scratch paid by this query.
    let encoded_name = tlv(0xa4, &dn(" Straße  Recipient ".as_bytes()));
    let bytes = extensions(&seq(&[&seq(&[&tlv(0xa0, &encoded_name)])]), true);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let info = read(&parser, &bytes);
    let other = tlv(0xa4, &dn(b"strasse recipient"));
    let other_parser = Parser::der(memory(1 << 20, 1 << 24));
    let mut reader = other_parser.read(&other, 1000).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let name = structured_pkix::general_name::read(&reader, &element, "recipient").unwrap();
    assert_eq!(
        info.check(std::slice::from_ref(&name), parser.memory(), no_group)
            .unwrap(),
        Decision::Matches { target: 0 }
    );
    let query = memory(0, 1 << 24);
    assert!(matches!(
        info.check(&[name], &query, no_group),
        Err(CheckError::Processing(_))
    ));
    assert_eq!(query.used(), 0);
}

#[test]
fn wide_inputs_and_each_group_callback_are_bounded() {
    // Flat iteration has no attacker-controlled recursion or free sibling fanout.
    let entry = target(true, 0x82, b"group.test");
    let group = tlv(0x30, &entry.repeat(256));
    let bytes = extensions(&seq(&[&group]), true);
    let parser = Parser::der(memory(1 << 22, 1 << 26));
    let info = read(&parser, &bytes);
    assert_eq!(info.targets().len(), 256);
    let query = memory(0, 40);
    let mut calls = 0;
    let result = info.check(&[], &query, |_, work| {
        calls += 1;
        work.charge_work(1)?;
        Ok::<_, structured_asn1::memory::MemoryError>(Membership::NotMember)
    });
    assert!(matches!(
        result,
        Err(CheckError::Callback {
            source: structured_asn1::memory::MemoryError::WorkExceeded,
            ..
        })
    ));
    assert_eq!(calls, 20);
    assert_eq!(query.work_used(), 40);
}

#[test]
fn every_partial_storage_refusal_releases_admitted_capacity() {
    // Refusing later catalogue growth drops earlier names/groups/TargetCerts too.
    let bytes = extensions(
        &seq(&[&seq(&[
            &target(false, 0x82, b"example.test"),
            &target_cert(),
        ])]),
        true,
    );
    let parser = Parser::der(memory(1 << 20, 1 << 26));
    let catalogue = catalogue(&parser, &bytes);
    let extension = catalogue.get(IDENTIFIER, parser.memory()).unwrap().unwrap();
    let mut succeeded = false;
    for capacity in [0, 16, 64, 256, 512, 1024, 2048, 4096, 8192, 16384] {
        let operation = memory(capacity, 1 << 20);
        let result = TargetInformation::read(extension, &operation);
        if result.is_ok() {
            succeeded = true;
        }
        drop(result);
        assert_eq!(operation.used(), 0);
    }
    assert!(succeeded);
}

#[test]
fn target_cert_optional_fields_and_payload_tail_follow_one_grammar() {
    // Omitted name/digest are legal; reordering, duplicates and payload tails are not.
    let issuer = seq(&[&seq(&[&tlv(0x82, b"issuer.test")]), &[2, 1, 1]]);
    let digest = seq(&[&[10, 1, 1], &seq(&[&[6, 1, 42]]), &[3, 2, 0, 8]]);
    for fields in [issuer.clone(), [issuer.clone(), digest.clone()].concat()] {
        let bytes = extensions(&seq(&[&seq(&[&tlv(0xa2, &fields)])]), true);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let info = read(&parser, &bytes);
        assert!(info.certificates()[0].name.is_none());
    }
    for fields in [
        [issuer.clone(), digest.clone(), tlv(0x82, b"late.test")].concat(),
        [
            issuer.clone(),
            tlv(0x82, b"one.test"),
            tlv(0x82, b"two.test"),
        ]
        .concat(),
    ] {
        let bytes = extensions(&seq(&[&seq(&[&tlv(0xa2, &fields)])]), true);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let cat = catalogue(&parser, &bytes);
        assert!(
            TargetInformation::read(
                cat.get(IDENTIFIER, parser.memory()).unwrap().unwrap(),
                parser.memory()
            )
            .is_err()
        );
    }
    let bytes = extensions(&[seq(&[]), vec![5, 0]].concat(), true);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let cat = catalogue(&parser, &bytes);
    assert!(
        TargetInformation::read(
            cat.get(IDENTIFIER, parser.memory()).unwrap().unwrap(),
            parser.memory()
        )
        .is_err()
    );
}
