//! EN 319 122-1 §§5.2-5.5 attribute rules that narrow the generic CMS and ESS
//! schemas, reported per `SignerInfo` and role.

use std::sync::Arc;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_cms::cades::{Role, profile_faults};
use structured_cms::{ErrorCode, SignedData, oid};

fn memory(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_048_576, work)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    let length = contents.len();
    if length < 0x80 {
        encoded.push(u8::try_from(length).unwrap());
    } else if length < 0x100 {
        encoded.extend([0x81, u8::try_from(length).unwrap()]);
    } else {
        encoded.push(0x82);
        encoded.extend(u16::try_from(length).unwrap().to_be_bytes());
    }
    encoded.extend_from_slice(contents);
    encoded
}

/// Values in DER SET OF order, which signed attributes require.
fn attribute(kind: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = values.to_vec();
    sorted.sort();
    tlv(0x30, &[tlv(6, kind), tlv(0x31, &sorted.concat())].concat())
}

/// One signer with the given attributes; signed ones in DER SET OF order.
fn message(signed: &[Vec<u8>], unsigned: &[Vec<u8>]) -> Vec<u8> {
    let mut fields = vec![2, 1, 3, 0x80, 1, 7];
    fields.extend(tlv(0x30, &tlv(6, oid::SHA256.as_bytes())));
    if !signed.is_empty() {
        let mut sorted = signed.to_vec();
        sorted.sort();
        fields.extend(tlv(0xa0, &sorted.concat()));
    }
    fields.extend(tlv(0x30, &tlv(6, &[0x2b, 0x65, 0x70])));
    fields.extend(tlv(4, &[8]));
    if !unsigned.is_empty() {
        fields.extend(tlv(0xa1, &unsigned.concat()));
    }
    let mut inside = vec![2, 1, 3, 0x31, 0];
    inside.extend(tlv(0x30, &tlv(6, oid::DATA.as_bytes())));
    inside.extend(tlv(0x31, &tlv(0x30, &fields)));
    let envelope = [
        tlv(6, oid::SIGNED_DATA.as_bytes()),
        tlv(0xa0, &tlv(0x30, &inside)),
    ]
    .concat();
    tlv(0x30, &envelope)
}

const NONE: [(ErrorCode, &str); 0] = [];

fn codes(
    protected: &[Vec<u8>],
    unsigned: &[Vec<u8>],
    role: Role,
) -> Vec<(ErrorCode, &'static str)> {
    let encoded = message(protected, unsigned);
    let parser = Parser::ber(memory(1_000_000));
    let value = SignedData::read(&parser, &encoded, 0).unwrap();
    let query = parser.read(&[], 0).unwrap();
    let info = &value.signers()[0];
    profile_faults(info, role, &query)
        .unwrap()
        .iter()
        .map(|fault| (fault.code(), fault.field()))
        .collect()
}

fn token() -> Vec<u8> {
    // An opaque token value: the profile judges count, not token contents.
    tlv(0x30, &tlv(6, oid::SIGNED_DATA.as_bytes()))
}

#[test]
fn attributes_in_their_profile_sets_with_one_value_raise_nothing() {
    // §§5.2.3, 5.2.4.1, 5.2.5, 5.3, 5.5.3 as written by a conforming producer.
    let signed = [
        attribute(
            oid::COMMITMENT_TYPE_INDICATION.as_bytes(),
            &[tlv(0x30, &tlv(6, &[0x2a]))],
        ),
        attribute(
            oid::CONTENT_HINTS.as_bytes(),
            &[tlv(0x30, &tlv(6, &[0x2a]))],
        ),
        attribute(oid::SIGNER_LOCATION.as_bytes(), &[tlv(0x30, &[])]),
    ];
    let unsigned = [
        attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[token()]),
        attribute(oid::ARCHIVE_TIMESTAMP_V3.as_bytes(), &[token()]),
        attribute(oid::ARCHIVE_TIMESTAMP_V3.as_bytes(), &[token()]),
    ];
    assert_eq!(codes(&signed, &unsigned, Role::Signature), NONE);
}

#[test]
fn an_attribute_in_the_other_set_is_misplaced() {
    // §5.2.3 commitment-type-indication is signed; §5.3 signature-time-stamp
    // and §5.5.3 archive-time-stamp-v3 are unsigned.
    let signed = [attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[token()])];
    let unsigned = [
        attribute(
            oid::COMMITMENT_TYPE_INDICATION.as_bytes(),
            &[tlv(0x30, &tlv(6, &[0x2a]))],
        ),
        attribute(oid::MIME_TYPE.as_bytes(), &[tlv(12, b"text/plain")]),
    ];
    assert_eq!(
        codes(&signed, &unsigned, Role::Signature),
        [
            (ErrorCode::AttributePlacement, "commitmentTypeIndication"),
            (ErrorCode::AttributePlacement, "mimeType"),
            (ErrorCode::AttributePlacement, "signatureTimeStamp"),
        ]
    );
}

#[test]
fn a_single_valued_attribute_with_another_count_is_refused() {
    // "shall contain exactly one component of AttributeValue type".
    let signed = [attribute(
        oid::MIME_TYPE.as_bytes(),
        &[tlv(12, b"text/plain"), tlv(12, b"text/html")],
    )];
    let unsigned = [
        attribute(oid::ARCHIVE_TIMESTAMP_V3.as_bytes(), &[token(), token()]),
        attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[]),
    ];
    assert_eq!(
        codes(&signed, &unsigned, Role::Signature),
        [
            (ErrorCode::AttributeCardinality, "mimeType"),
            (ErrorCode::AttributeCardinality, "signatureTimeStamp"),
            (ErrorCode::AttributeCardinality, "archiveTimeStampV3"),
        ]
    );
}

#[test]
fn content_description_is_forbidden_only_within_a_countersignature() {
    // §§5.2.4.1-5.2.4.2: content-hints and mime-type describe the signed
    // content and shall not be used within a countersignature.
    let signed = [
        attribute(
            oid::CONTENT_HINTS.as_bytes(),
            &[tlv(0x30, &tlv(6, &[0x2a]))],
        ),
        attribute(oid::MIME_TYPE.as_bytes(), &[tlv(12, b"text/plain")]),
    ];
    assert_eq!(codes(&signed, &[], Role::Signature), NONE);
    assert_eq!(
        codes(&signed, &[], Role::Countersignature),
        [
            (ErrorCode::AttributePlacement, "contentHints"),
            (ErrorCode::AttributePlacement, "mimeType"),
        ]
    );
}

#[test]
fn an_implied_signature_policy_is_refused() {
    // §5.2.9.1: "The signaturePolicyImplied choice shall not be used."
    let implied = [attribute(
        oid::SIGNATURE_POLICY_IDENTIFIER.as_bytes(),
        &[vec![5, 0]],
    )];
    assert_eq!(
        codes(&implied, &[], Role::Signature),
        [(
            ErrorCode::AttributeSyntax,
            "signaturePolicyIdentifier.signaturePolicyImplied"
        )]
    );
    let explicit = [attribute(
        oid::SIGNATURE_POLICY_IDENTIFIER.as_bytes(),
        &[tlv(0x30, &tlv(6, &[0x2a]))],
    )];
    assert_eq!(codes(&explicit, &[], Role::Signature), NONE);
}

#[test]
fn ess_signing_certificate_policies_are_refused() {
    // §5.2.2.3: RFC 5035 permits policies; CAdES says "shall not be used".
    let identifier = tlv(0x30, &tlv(4, &[0; 32]));
    let policies = tlv(0x30, &tlv(0x30, &tlv(6, &[0x55, 0x1d, 0x20, 0])));
    let with = [attribute(
        oid::SIGNING_CERTIFICATE_V2.as_bytes(),
        &[tlv(0x30, &[tlv(0x30, &identifier), policies].concat())],
    )];
    assert_eq!(
        codes(&with, &[], Role::Signature),
        [(ErrorCode::AttributeSyntax, "signingCertificateV2.policies")]
    );
    let without = [attribute(
        oid::SIGNING_CERTIFICATE_V2.as_bytes(),
        &[tlv(0x30, &tlv(0x30, &identifier))],
    )];
    assert_eq!(codes(&without, &[], Role::Signature), NONE);
}

#[test]
fn a_spent_work_ceiling_refuses_instead_of_reporting_less() {
    // Lookups are paid; a ceiling too low for them is a resource refusal,
    // never a shorter list of faults.
    let protected = [attribute(
        oid::MIME_TYPE.as_bytes(),
        &[tlv(12, b"a"), tlv(12, b"b")],
    )];
    let encoded = message(&protected, &[]);
    let account = memory(1_000_000);
    let parser = Parser::ber(account.clone());
    let value = SignedData::read(&parser, &encoded, 0).unwrap();
    let query = parser.read(&[], 0).unwrap();
    let info = &value.signers()[0];
    let before = account.work_used();
    assert_eq!(
        profile_faults(info, Role::Signature, &query).unwrap().len(),
        1
    );
    let needed = account.work_used() - before;

    let spent = memory(1_000_000);
    let parser = Parser::ber(spent.clone());
    let value = SignedData::read(&parser, &encoded, 0).unwrap();
    let query = parser.read(&[], 0).unwrap();
    let info = &value.signers()[0];
    spent
        .charge_work((spent.work_remaining() - (needed - 1)) as u64)
        .unwrap();
    let error = profile_faults(info, Role::Signature, &query).unwrap_err();
    assert!(error.is_resource());
}

#[test]
fn ess_content_attributes_carry_exactly_one_value() {
    // RFC 2634 §1.3.4, imported by EN 319 122-1 §§5.2.4.1, 5.2.11-5.2.12:
    // "there MUST NOT be zero, or multiple, instances of AttributeValue".
    let signed = [
        attribute(
            oid::CONTENT_HINTS.as_bytes(),
            &[tlv(0x30, &tlv(6, &[0x2a])), tlv(0x30, &tlv(6, &[0x2b]))],
        ),
        attribute(oid::CONTENT_IDENTIFIER.as_bytes(), &[]),
        attribute(
            oid::CONTENT_REFERENCE.as_bytes(),
            &[tlv(0x30, &[]), tlv(0x30, &[0x05, 0])],
        ),
    ];
    assert_eq!(
        codes(&signed, &[], Role::Signature),
        [
            (ErrorCode::AttributeCardinality, "contentHints"),
            (ErrorCode::AttributeCardinality, "contentReference"),
            (ErrorCode::AttributeCardinality, "contentIdentifier"),
        ]
    );
}

#[test]
fn a_repeated_ess_content_attribute_is_refused() {
    // RFC 2634 §1.3.4: "A signerInfo MUST NOT include multiple instances of
    // any of the attribute types defined in ESS." The first instance stands;
    // each later one is reported where it is written.
    let reference = attribute(
        oid::CONTENT_REFERENCE.as_bytes(),
        &[tlv(0x30, &tlv(6, &[0x2a]))],
    );
    let identifier = attribute(oid::CONTENT_IDENTIFIER.as_bytes(), &[tlv(4, &[1])]);
    let other = attribute(oid::CONTENT_IDENTIFIER.as_bytes(), &[tlv(4, &[2])]);
    assert_eq!(
        codes(
            &[reference.clone(), reference, identifier, other],
            &[],
            Role::Signature
        ),
        [
            (ErrorCode::DuplicateAttribute, "contentReference"),
            (ErrorCode::DuplicateAttribute, "contentIdentifier"),
        ]
    );
    // Single-valued CAdES attributes without the ESS rule may repeat.
    let location = attribute(oid::SIGNER_LOCATION.as_bytes(), &[tlv(0x30, &[])]);
    assert_eq!(
        codes(&[location.clone(), location], &[], Role::Signature),
        NONE
    );
}

#[test]
fn a_claimed_saml_assertion_belongs_only_inside_signer_attributes() {
    // §5.2.6.2: claimed-SAML-assertion is carried in signer-attributes-v2
    // claimedAttributes; "It shall not be used anywhere else."
    let saml = attribute(oid::CLAIMED_SAML_ASSERTION.as_bytes(), &[tlv(12, b"<a/>")]);
    assert_eq!(
        codes(
            std::slice::from_ref(&saml),
            std::slice::from_ref(&saml),
            Role::Signature
        ),
        [
            (ErrorCode::AttributePlacement, "claimedSamlAssertion"),
            (ErrorCode::AttributePlacement, "claimedSamlAssertion"),
        ]
    );
}

#[test]
fn a_repeated_ats_hash_index_is_refused() {
    // §5.5.3: the archive time-stamp token carries "a single
    // ats-hash-index-v3 attribute"; the second instance is reported.
    let index = attribute(oid::ATS_HASH_INDEX_V3.as_bytes(), &[tlv(0x30, &[])]);
    assert_eq!(
        codes(&[], &[index.clone(), index], Role::ArchiveTimestamp),
        [(ErrorCode::DuplicateAttribute, "atsHashIndexV3")]
    );
}

#[test]
fn the_hash_index_belongs_only_to_an_archive_timestamp_signer() {
    // §5.5.2: ats-hash-index-v3 is an unsigned attribute of the CMS signature
    // of the time-stamp token in an archive-time-stamp-v3, of no other signer.
    let index = attribute(oid::ATS_HASH_INDEX_V3.as_bytes(), &[tlv(0x30, &[])]);
    let unsigned = std::slice::from_ref(&index);
    assert_eq!(codes(&[], unsigned, Role::ArchiveTimestamp), NONE);
    for role in [Role::Signature, Role::Countersignature] {
        assert_eq!(
            codes(&[], unsigned, role),
            [(ErrorCode::AttributePlacement, "atsHashIndexV3")]
        );
    }
}

#[test]
fn every_policy_value_inspected_is_paid_for() {
    // Each signature-policy-identifier value is inspected for the implied
    // choice. The same bytes split into twice as many values must cost at
    // least one unit more per extra value; byte-proportional work is equal.
    let used = |values: usize, arcs: usize| {
        let protected = [attribute(
            oid::SIGNATURE_POLICY_IDENTIFIER.as_bytes(),
            &(0..values)
                .map(|ordinal| {
                    let mut identifier = vec![0x2a, u8::try_from(ordinal).unwrap()];
                    identifier.resize(2 + arcs, 1);
                    tlv(0x30, &tlv(6, &identifier))
                })
                .collect::<Vec<_>>(),
        )];
        let encoded = message(&protected, &[]);
        let account = memory(1_000_000);
        let parser = Parser::ber(account.clone());
        let value = SignedData::read(&parser, &encoded, 0).unwrap();
        let query = parser.read(&[], 0).unwrap();
        let before = account.work_used();
        profile_faults(&value.signers()[0], Role::Signature, &query).unwrap();
        account.work_used() - before
    };
    // 30 values of 12 bytes and 60 values of 6 bytes: 360 bytes either way.
    let fewer = used(30, 6);
    let more = used(60, 0);
    assert!(
        more >= fewer + 30,
        "{more} work for 60 values, {fewer} for 30 of the same bytes"
    );
}

#[test]
fn a_foreign_reader_is_refused_before_inspection() {
    // The producing parser's ceilings fund the scans; another parser's
    // account cannot stand in for them.
    let encoded = message(
        &[attribute(oid::MIME_TYPE.as_bytes(), &[tlv(12, b"a")])],
        &[],
    );
    let parser = Parser::ber(memory(1_000_000));
    let value = SignedData::read(&parser, &encoded, 0).unwrap();
    let info = &value.signers()[0];
    let foreign = Parser::ber(memory(1_000_000));
    let other = foreign.read(&[], 0).unwrap();
    let error = profile_faults(info, Role::Signature, &other).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
}
