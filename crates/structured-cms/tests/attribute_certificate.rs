//! Whole original AC signature inputs, schema alternatives and resource ownership.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::attribute_certificate::{AttributeCertificate, DigestedObject, IssuerForm};
use structured_cms::{ErrorCode, SignedData, oid};

fn memory(capacity: usize, work: u64) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(
        capacity,
        usize::try_from(work).unwrap(),
    )))
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(u8::try_from(body.len()).unwrap());
    } else if body.len() < 256 {
        out.extend([0x81, u8::try_from(body.len()).unwrap()]);
    } else {
        out.extend([
            0x82,
            u8::try_from(body.len() >> 8).unwrap(),
            u8::try_from(body.len() & 255).unwrap(),
        ]);
    }
    out.extend(body);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn algorithm() -> Vec<u8> {
    sequence(&[&[6, 1, 42]])
}
fn names() -> Vec<u8> {
    tlv(0x30, &tlv(0x82, b"example.test"))
}
fn issuer_serial(tag: u8) -> Vec<u8> {
    tlv(tag, &[names(), vec![2, 1, 7], vec![3, 2, 0, 9]].concat())
}
fn object_digest(tag: u8, kind: u8, other: bool) -> Vec<u8> {
    let mut body = vec![10, 1, kind];
    if other {
        body.extend([6, 1, 43]);
    }
    body.extend(algorithm());
    body.extend([3, 2, 0, 8]);
    tlv(tag, &body)
}
fn attributes() -> Vec<u8> {
    sequence(&[&sequence(&[&[6, 1, 44], &[0x31, 4, 5, 0, 5, 0]])])
}
fn info(holder: &[u8], issuer: &[u8], attrs: &[u8], tail: &[u8]) -> Vec<u8> {
    sequence(&[
        &[2, 1, 1],
        holder,
        issuer,
        &algorithm(),
        &[2, 1, 5],
        &sequence(&[&tlv(24, b"20261021000000Z"), &tlv(24, b"20271021000000Z")]),
        attrs,
        tail,
    ])
}
fn certificate(signed: &[u8], tag: u8) -> Vec<u8> {
    tlv(tag, &[signed, &algorithm(), &[3, 3, 0, 9, 10]].concat())
}
fn ordinary() -> Vec<u8> {
    certificate(
        &info(
            &sequence(&[&tlv(0xa1, &tlv(0x82, b"holder.test"))]),
            &tlv(0xa0, &names()),
            &attributes(),
            &[],
        ),
        0x30,
    )
}

#[test]
fn original_signed_inputs_and_all_values_survive_reading() {
    // A verifier gets the original acinfo TLV and signature bits, never rebuilt DER.
    let bytes = ordinary();
    let mem = memory(1 << 20, 1 << 24);
    let parser = Parser::ber(mem.clone());
    let mut reader = parser.read(&bytes, 700).unwrap();
    let ac = AttributeCertificate::read(&mut reader).unwrap();
    drop(reader);
    assert_eq!(ac.information().serial.as_u64(), Some(5));
    assert_eq!(ac.information().attributes.len(), 1);
    assert_eq!(ac.information().attributes[0].values().len(), 2);
    let start = usize::try_from(ac.signed_element().span().start - 700).unwrap();
    assert_eq!(ac.signed_bytes().as_ptr(), bytes[start..].as_ptr());
    assert_eq!(ac.signature_value().octets(), Some(&[9, 10][..]));
    assert_eq!(ac.signature_algorithm().algorithm().as_bytes(), [42]);
    assert_eq!(ac.information().issuer.form, IssuerForm::V2);
    assert!(ac.information().not_before < ac.information().not_after);
    drop(ac);
    assert_eq!(mem.used(), 0);
}

#[test]
fn independent_signature_engine_verifies_only_the_original_acinfo() {
    // A real Ed25519 engine detects substitutions of either signed bytes or bits.
    use ed25519_dalek::{Signature, Signer, SigningKey};
    let key = SigningKey::from_bytes(&[23; 32]);
    let signed = info(&[0x30, 0], &names(), &attributes(), &[]);
    let signature = key.sign(&signed);
    let bytes = sequence(&[
        &signed,
        &algorithm(),
        &tlv(3, &[&[0][..], &signature.to_bytes()].concat()),
    ]);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let mut reader = parser.read(&bytes, 100).unwrap();
    let ac = AttributeCertificate::read(&mut reader).unwrap();
    let value = Signature::from_slice(ac.signature_value().octets().unwrap()).unwrap();
    key.verifying_key()
        .verify_strict(ac.signed_bytes(), &value)
        .unwrap();
    let mut substituted = ac.signed_bytes().to_vec();
    let last = substituted.len() - 1;
    substituted[last] ^= 1;
    assert!(
        key.verifying_key()
            .verify_strict(&substituted, &value)
            .is_err()
    );
    let mut bits = value.to_bytes();
    bits[0] ^= 1;
    assert!(
        key.verifying_key()
            .verify_strict(ac.signed_bytes(), &Signature::from_bytes(&bits))
            .is_err()
    );
}

#[test]
fn every_holder_and_issuer_field_is_preserved_without_identity_selection() {
    // Multiple Holder fields are a SHOULD-level profile issue, not ambiguous ASN.1.
    let holder = sequence(&[
        &issuer_serial(0xa0),
        &tlv(0xa1, &tlv(0x82, b"holder.test")),
        &object_digest(0xa2, 1, false),
    ]);
    let issuer = tlv(
        0xa0,
        &[names(), issuer_serial(0xa0), object_digest(0xa1, 2, true)].concat(),
    );
    let extension = sequence(&[&[6, 1, 45], &[1, 1, 255], &[4, 2, 5, 0]]);
    let tail = [&[3, 2, 0, 7][..], &sequence(&[&extension])].concat();
    let bytes = certificate(&info(&holder, &issuer, &attributes(), &tail), 0x30);
    let mem = memory(1 << 20, 1 << 24);
    let parser = Parser::der(mem.clone());
    let mut reader = parser.read(&bytes, 400).unwrap();
    let ac = AttributeCertificate::read(&mut reader).unwrap();
    let fields = ac.information();
    assert_eq!(
        fields
            .holder
            .base_certificate
            .as_ref()
            .unwrap()
            .serial
            .as_u64(),
        Some(7)
    );
    assert_eq!(
        fields
            .holder
            .base_certificate
            .as_ref()
            .unwrap()
            .issuer_uid
            .unwrap()
            .octets(),
        Some(&[9][..])
    );
    assert_eq!(fields.holder.entity_names.as_ref().unwrap().len(), 1);
    assert_eq!(
        fields.holder.object_digest.as_ref().unwrap().object_type,
        DigestedObject::PublicKeyCertificate
    );
    let issuer = &fields.issuer;
    assert_eq!(issuer.form, IssuerForm::V2);
    assert_eq!(issuer.names.as_ref().unwrap().len(), 1);
    assert!(issuer.base_certificate.is_some());
    assert_eq!(
        issuer
            .object_digest
            .as_ref()
            .unwrap()
            .other_type
            .unwrap()
            .as_bytes(),
        [43]
    );
    assert_eq!(fields.issuer_uid.unwrap().octets(), Some(&[7][..]));
    assert!(fields.extensions.is_some());
    drop(ac);
    drop(reader);
    assert_eq!(mem.used(), 0);
}

#[test]
fn structural_reading_does_not_claim_profile_or_algorithm_acceptance() {
    // A v1 issuer inside a v2 AC and an empty Holder are inspectable profile facts.
    for kind in 0..=2 {
        let holder = sequence(&[&object_digest(0xa2, kind, kind == 2)]);
        let signed = info(&holder, &names(), &attributes(), &[]);
        let bytes = certificate(&signed, 0x30);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let mut reader = parser.read(&bytes, 50).unwrap();
        let ac = AttributeCertificate::read(&mut reader).unwrap();
        assert_eq!(ac.information().issuer.form, IssuerForm::V1);
        assert_eq!(
            ac.information()
                .holder
                .object_digest
                .as_ref()
                .unwrap()
                .digest
                .octets(),
            Some(&[8][..])
        );
    }
    let bytes = certificate(&info(&[0x30, 0], &tlv(0xa0, &[]), &attributes(), &[]), 0x30);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let mut reader = parser.read(&bytes, 50).unwrap();
    let ac = AttributeCertificate::read(&mut reader).unwrap();
    assert!(ac.information().holder.base_certificate.is_none());
    let issuer = &ac.information().issuer;
    assert_eq!(issuer.form, IssuerForm::V2);
    assert!(issuer.names.is_none());
}

#[test]
fn duplicate_reordered_and_mistagged_components_refuse() {
    // No duplicate/order recovery may silently select one certificate identity.
    for holder in [
        sequence(&[&issuer_serial(0xa0), &issuer_serial(0xa0)]),
        sequence(&[&object_digest(0xa2, 0, false), &issuer_serial(0xa0)]),
        sequence(&[&[0x80, 0]]),
        sequence(&[&tlv(0xa1, &[])]),
        sequence(&[&object_digest(0xa2, 3, false)]),
    ] {
        let bytes = certificate(&info(&holder, &names(), &attributes(), &[]), 0x30);
        let parser = Parser::der(memory(1 << 20, 1 << 24));
        let mut reader = parser.read(&bytes, 100).unwrap();
        let error = AttributeCertificate::read(&mut reader).unwrap_err();
        assert!(error.offset() >= 100);
        assert!(!error.is_resource());
    }
}

#[test]
fn attribute_bounds_duplicates_and_version_are_enforced() {
    // AC attributes have stronger bounds than a generic CMS Attribute value set.
    for (attrs, expected) in [
        (sequence(&[]), ErrorCode::EmptyAttributes),
        (
            sequence(&[&sequence(&[&[6, 1, 44], &[0x31, 0]])]),
            ErrorCode::AttributeCardinality,
        ),
        (
            sequence(&[
                &sequence(&[&[6, 1, 44], &[0x31, 2, 5, 0]]),
                &sequence(&[&[6, 1, 44], &[0x31, 2, 5, 0]]),
            ]),
            ErrorCode::DuplicateAttribute,
        ),
    ] {
        let bytes = certificate(&info(&[0x30, 0], &names(), &attrs, &[]), 0x30);
        let mem = memory(1 << 20, 1 << 24);
        let parser = Parser::der(mem.clone());
        let mut reader = parser.read(&bytes, 100).unwrap();
        let error = AttributeCertificate::read(&mut reader).unwrap_err();
        assert_eq!(error.code(), expected);
        drop(error);
        drop(reader);
        assert_eq!(mem.used(), 0);
    }
    let mut signed = info(&[0x30, 0], &names(), &attributes(), &[]);
    let at = signed.windows(3).position(|v| v == [2, 1, 1]).unwrap();
    signed[at + 2] = 0;
    let bytes = certificate(&signed, 0x30);
    let parser = Parser::der(memory(1 << 20, 1 << 24));
    let mut reader = parser.read(&bytes, 100).unwrap();
    assert_eq!(
        AttributeCertificate::read(&mut reader).unwrap_err().code(),
        ErrorCode::UnsupportedVersion
    );
}

#[test]
fn signed_info_requires_der_even_in_a_ber_carrier() {
    // Signing inputs cannot silently accept/re-encode an indefinite acinfo.
    let signed = info(&[0x30, 0], &names(), &attributes(), &[]);
    let header = if signed[1] < 128 {
        2
    } else {
        2 + usize::from(signed[1] & 127)
    };
    let ber = [&[0x30, 0x80][..], &signed[header..], &[0, 0]].concat();
    let bytes = certificate(&ber, 0x30);
    let parser = Parser::ber(memory(1 << 20, 1 << 24));
    let mut reader = parser.read(&bytes, 100).unwrap();
    assert!(AttributeCertificate::read(&mut reader).is_err());
}

#[test]
fn refusal_releases_storage_and_preserves_original_coordinates() {
    // Local work, aggregate work, depth and actual catalogue capacity are terminal.
    let bytes = ordinary();
    for (capacity, work, local, depth) in [
        (0, 1 << 24, 1 << 24, 100),
        (1 << 20, 80, 1 << 24, 100),
        (1 << 20, 1 << 24, 80, 100),
        (1 << 20, 1 << 24, 1 << 24, 2),
    ] {
        let mem = memory(capacity, work);
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                max_depth: depth,
                ..Limits::default()
            },
            mem.clone(),
        );
        let mut reader = parser.read(&bytes, 1000).unwrap();
        let error = AttributeCertificate::read(&mut reader).unwrap_err();
        assert!(error.is_resource(), "{error:?}");
        assert!(error.offset() >= 1000);
        drop(error);
        drop(reader);
        assert_eq!(mem.used(), 0);
    }
}

fn cms(encoded: &[u8]) -> Vec<u8> {
    let body = sequence(&[
        &[2, 1, 4],
        &[0x31, 0],
        &sequence(&[&tlv(6, oid::DATA.as_bytes())]),
        &tlv(0xa0, encoded),
        &[0x31, 0],
    ]);
    sequence(&[&tlv(6, oid::SIGNED_DATA.as_bytes()), &tlv(0xa0, &body)])
}

#[test]
fn lazy_cms_choice_preserves_source_and_charges_the_current_query() {
    // Original CMS [2] stays intact; lazy parsing uses the current query's account.
    let signed = info(&[0x30, 0], &names(), &attributes(), &[]);
    let bytes = cms(&certificate(&signed, 0xa2));
    let retained = memory(1 << 20, 1 << 24);
    let source = Parser::ber(retained.clone());
    let message = SignedData::read(&source, &bytes, 1000).unwrap();
    let current = memory(1 << 20, 1 << 24);
    let query_parser = Parser::der(current.clone());
    let query = query_parser.read(&[], 2000).unwrap();
    let mut original = message
        .certificate_choice_reader_in(&query, 0)
        .unwrap()
        .unwrap();
    let element = original.next_element().unwrap().unwrap();
    let ac = AttributeCertificate::read_implicit(&original, &element).unwrap();
    assert_eq!(ac.element().as_bytes()[0], 0xa2);
    assert_eq!(ac.signed_bytes(), signed);
    assert!(current.used() > 0);
    assert!(
        message
            .certificate_choice_reader_in(&query, 1)
            .unwrap()
            .is_none()
    );
    drop(ac);
    drop(original);
    drop(query);
    assert_eq!(current.used(), 0);
    let exhausted = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let query = exhausted.read(&[], 3000).unwrap();
    assert!(
        message
            .certificate_choice_reader_in(&query, 0)
            .unwrap_err()
            .is_resource()
    );
    drop(message);
    assert_eq!(retained.used(), 0);
}
