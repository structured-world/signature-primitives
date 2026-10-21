//! Original `CAdES` preparation: source identity, full census and level rules.

use std::sync::Arc;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_cades::{
    Level,
    prepare::{Preparation, Rule, Severity},
    source::Document,
};
use structured_cms::{SignedData, oid};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 16 << 20)))
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(u8::try_from(content.len()).unwrap());
    } else if content.len() < 256 {
        out.extend([0x81, u8::try_from(content.len()).unwrap()]);
    } else {
        out.extend([0x82]);
        out.extend(u16::try_from(content.len()).unwrap().to_be_bytes());
    }
    out.extend(content);
    out
}

fn attribute(kind: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &[tlv(6, kind), tlv(0x31, &values.concat())].concat())
}

fn signer(unsigned: &[Vec<u8>]) -> Vec<u8> {
    signer_with(&[], unsigned)
}

fn signer_with(signed: &[Vec<u8>], unsigned: &[Vec<u8>]) -> Vec<u8> {
    signer_value(signed, unsigned, 8)
}

fn signer_value(signed: &[Vec<u8>], unsigned: &[Vec<u8>], signature: u8) -> Vec<u8> {
    let mut fields = vec![2, 1, 3, 0x80, 1, 7];
    fields.extend(tlv(0x30, &tlv(6, oid::SHA256.as_bytes())));
    if !signed.is_empty() {
        let mut attributes = signed.to_vec();
        attributes.sort();
        fields.extend(tlv(0xa0, &attributes.concat()));
    }
    fields.extend(tlv(0x30, &tlv(6, &[0x2b, 0x65, 0x70])));
    fields.extend(tlv(4, &[signature]));
    if !unsigned.is_empty() {
        fields.extend(tlv(0xa1, &unsigned.concat()));
    }
    tlv(0x30, &fields)
}

fn token() -> Vec<u8> {
    token_with_attributes(&[], &[])
}

fn token_with_attributes(signed: &[Vec<u8>], unsigned: &[Vec<u8>]) -> Vec<u8> {
    // Structural RFC3161 envelope only. Arithmetic/ESS/EKU are deliberately
    // not supplied here and this fixture never asserts successful evidence.
    let mut info = vec![2, 1, 1];
    info.extend(tlv(6, &[43]));
    info.extend(tlv(
        0x30,
        &[tlv(0x30, &tlv(6, oid::SHA256.as_bytes())), tlv(4, &[0; 32])].concat(),
    ));
    info.extend([2, 1, 7]);
    info.extend(tlv(24, b"20260101000000Z"));
    token_carried_with(&tlv(4, &tlv(0x30, &info)), signed, unsigned)
}

fn token_information(info: &[u8]) -> Vec<u8> {
    token_carried(&tlv(4, info))
}

fn token_carried(octets: &[u8]) -> Vec<u8> {
    token_carried_with(octets, &[], &[])
}

fn token_carried_with(octets: &[u8], signed: &[Vec<u8>], unsigned: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![2, 1, 3, 0x31, 0];
    body.extend(tlv(
        0x30,
        &[tlv(6, oid::TST_INFO.as_bytes()), tlv(0xa0, octets)].concat(),
    ));
    body.extend(tlv(0x31, &signer_with(signed, unsigned)));
    tlv(
        0x30,
        &[
            tlv(6, oid::SIGNED_DATA.as_bytes()),
            tlv(0xa0, &tlv(0x30, &body)),
        ]
        .concat(),
    )
}

fn timestamp_signed_attributes() -> Vec<Vec<u8>> {
    vec![
        attribute(
            oid::CONTENT_TYPE.as_bytes(),
            &[tlv(6, oid::TST_INFO.as_bytes())],
        ),
        attribute(oid::MESSAGE_DIGEST.as_bytes(), &[tlv(4, &[0; 32])]),
    ]
}

fn message(unsigned: &[Vec<u8>]) -> Vec<u8> {
    message_with(&[], unsigned)
}

fn message_with(signed: &[Vec<u8>], unsigned: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![2, 1, 3, 0x31, 0];
    body.extend(tlv(0x30, &tlv(6, oid::DATA.as_bytes())));
    body.extend(tlv(0x31, &signer_with(signed, unsigned)));
    tlv(
        0x30,
        &[
            tlv(6, oid::SIGNED_DATA.as_bytes()),
            tlv(0xa0, &tlv(0x30, &body)),
        ]
        .concat(),
    )
}

#[test]
fn optional_timestamp_syntax_is_required_even_for_basic() {
    // Optional does not mean untyped: retain an empty token's original
    // obligation AND a located format finding, even without requesting B-T.
    for value in [tlv(0x30, &[]), token_information(&tlv(0x30, &[]))] {
        let time = attribute(oid::CONTENT_TIMESTAMP.as_bytes(), &[value]);
        let bytes = message_with(&[time], &[]);
        let account = memory();
        let parser = Parser::ber(account.clone());
        let data = SignedData::read(&parser, &bytes, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        let property = prepared.timestamps()[0].property();
        assert_eq!(prepared.timestamp_requirements().entries().len(), 1);
        assert!(
            prepared
                .findings()
                .iter()
                .any(
                    |finding| finding.location.node.span().start >= property.span().start
                        && finding.location.node.span().start < property.span().end()
                        && finding.severity == Severity::Required
                )
        );
        let storage = account.used();
        let pool = structured_cades::material::Pool::read(&prepared, &parent).unwrap();
        assert_eq!(
            account.used(),
            storage,
            "empty material pool borrows prepared token models"
        );
        assert_eq!(pool.token_faults().len(), 1);
        assert!(!pool.token_faults()[0].1.is_terminal());
    }
}

#[test]
fn reused_ess_profile_refuses_another_original_signer_or_parser() {
    // Reusing a parsed reading saves a parse, but must never allow another
    // signer's empty ESS reading to erase this signer's actual profile facts.
    let bytes = message(&[]);
    let account = memory();
    let parser = Parser::ber(account.clone());
    let other = Parser::ber(account.clone());
    let first = SignedData::read(&parser, &bytes, 500).unwrap();
    let second = SignedData::read(&parser, &bytes, 1500).unwrap();
    let copied_bytes = bytes.clone();
    let copied = SignedData::read(&parser, &copied_bytes, 500).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let foreign = other.read(&[], 0).unwrap();
    let reading =
        structured_cms::ess::SigningAttributes::read(&first.signers()[0], &parent).unwrap();
    let before = account.used();
    for (signer, reader) in [
        (&second.signers()[0], &parent),
        (&first.signers()[0], &foreign),
        (&copied.signers()[0], &parent),
    ] {
        let cause = structured_cms::cades::findings_from_reading(
            signer,
            structured_cms::cades::Role::ArchiveTimestamp,
            &reading,
            reader,
        )
        .unwrap_err();
        assert!(cause.is_terminal());
        assert_eq!(account.used(), before);
    }
}

#[test]
fn duplicate_singletons_keep_findings_and_the_complete_original_census() {
    // A format violation must not truncate preparation before counters and
    // timestamps are catalogued. Duplicate presence is still presence.
    let mime = attribute(oid::MIME_TYPE.as_bytes(), &[tlv(12, b"text/plain")]);
    let policy = attribute(oid::SIGNATURE_POLICY_IDENTIFIER.as_bytes(), &[tlv(5, &[])]);
    for repeated in [mime, policy] {
        let child = attribute(oid::COUNTERSIGNATURE.as_bytes(), &[signer(&[])]);
        let time = attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[token()]);
        let bytes = message_with(&[repeated.clone(), repeated], &[child, time]);
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        assert_eq!(prepared.counters().len(), 1);
        assert_eq!(prepared.timestamps().len(), 1);
        assert!(!prepared.all_format_requirements_met());
        assert!(prepared.findings().iter().any(|finding| matches!(
            finding.rule,
            Rule::Schema {
                code: structured_cms::ErrorCode::DuplicateAttribute,
                ..
            }
        )));
    }
}

#[test]
fn parallel_root_preservation_stays_original_and_cannot_disappear() {
    // EN319122-1 §5.5.3 applies the preservation rule when ANY parallel
    // root carries the historical proof, not merely the selected signer.
    let legacy = attribute(&[4, 0, 0x8d, 0x45, 2, 2], &[tlv(0x30, &[])]);
    let mut body = vec![2, 1, 3, 0x31, 0];
    body.extend(tlv(0x30, &tlv(6, oid::DATA.as_bytes())));
    body.extend(tlv(
        0x31,
        &[signer(&[]), signer_value(&[], &[legacy], 9)].concat(),
    ));
    let bytes = tlv(
        0x30,
        &[
            tlv(6, oid::SIGNED_DATA.as_bytes()),
            tlv(0xa0, &tlv(0x30, &body)),
        ]
        .concat(),
    );
    let account = memory();
    let parser = Parser::ber(account.clone());
    let data = SignedData::read(&parser, &bytes, 500).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let prepared =
        Preparation::read(&document, &data.signers()[0], Level::Archival, &parent).unwrap();
    assert_eq!(prepared.preservation().len(), 1);
    let required = prepared.preservation()[0];
    assert_eq!(
        required.kind,
        structured_cades::preservation::Kind::LongTermValidation
    );
    assert_eq!(required.signature.span(), data.signers()[1].span());
    let attribute = &data.signers()[1].unsigned_attributes().unwrap().items()[0];
    assert_eq!(required.property.span(), attribute.span());
    let context = required.value.unwrap();
    let reader = context.reader_in(&parent).unwrap();
    assert!(std::ptr::eq(reader.parser(), std::ptr::from_ref(&parser)));
    assert_eq!(
        context.element().as_bytes(),
        attribute.values()[0].as_bytes()
    );
    assert_eq!(context.element().span(), attribute.values()[0].span());
}

#[test]
fn mandatory_attribute_presence_does_not_replace_its_common_value_binding() {
    // CMS11.1 and EN6.3(f) require the written content-type to agree with
    // id-data. Merely observing its OID cannot discharge that obligation.
    let signed = [
        attribute(
            oid::CONTENT_TYPE.as_bytes(),
            &[tlv(6, oid::SIGNED_DATA.as_bytes())],
        ),
        attribute(oid::MESSAGE_DIGEST.as_bytes(), &[tlv(4, &[0; 32])]),
        attribute(oid::SIGNING_TIME.as_bytes(), &[tlv(23, b"260101000000Z")]),
    ];
    let bytes = message_with(&signed, &[]);
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 50).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let prepared = Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
    assert!(prepared.findings().iter().any(|finding| matches!(
        finding.rule,
        Rule::Schema {
            code: structured_cms::ErrorCode::ContentTypeMismatch,
            ..
        }
    )));
}

#[test]
fn an_archive_never_promotes_a_requested_basic_profile() {
    // Table1 '*' means SHOULD NOT, not automatic higher-level selection.
    let bytes = message(&[attribute(
        oid::ARCHIVE_TIMESTAMP_V3.as_bytes(),
        &[tlv(0x30, &[])],
    )]);
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 800).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let basic = Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
    assert_eq!(basic.requested(), Level::Basic);
    assert_eq!(basic.timestamps().len(), 1);
    assert!(!basic.all_format_requirements_met());
    assert!(
        basic.findings().iter().any(
            |finding| matches!(finding.rule, Rule::Missing(kind) if kind == oid::SIGNING_TIME)
        )
    );
    assert!(
        basic
            .findings()
            .iter()
            .any(|finding| finding.severity == Severity::Advisory)
    );
    let archival =
        Preparation::read(&document, &data.signers()[0], Level::Archival, &parent).unwrap();
    assert!(
        archival
            .findings()
            .iter()
            .any(|finding| matches!(finding.rule, Rule::SignatureTimestamp))
    );
}

#[test]
fn nested_timestamp_census_keeps_owning_parent_and_malformed_siblings() {
    // All-counter material needs nested TSA actors, even when another direct
    // value is unreadable. The common iterative walker defines the ordering.
    let timestamp = attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[tlv(0x30, &[])]);
    let grandchild = signer(std::slice::from_ref(&timestamp));
    let child = signer(&[
        timestamp,
        attribute(oid::COUNTERSIGNATURE.as_bytes(), &[grandchild]),
    ]);
    let bytes = message(&[attribute(
        oid::COUNTERSIGNATURE.as_bytes(),
        &[child, tlv(2, &[1])],
    )]);
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 900).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let prepared = Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
    assert_eq!(prepared.counters().len(), 3);
    assert_eq!(prepared.timestamps().len(), 2);
    assert_eq!(
        prepared.timestamps()[0].owner(),
        prepared.counters()[0].node()
    );
    assert_eq!(
        prepared.timestamps()[1].owner(),
        prepared.counters()[1].node()
    );
    assert_eq!(
        prepared.counters()[1].parent(),
        prepared.counters()[0].node()
    );
    assert!(prepared.counters()[2].malformed().is_some());
    assert_eq!(prepared.timestamp_requirements().entries().len(), 2);
}

#[test]
fn empty_timestamp_attribute_remains_an_unfulfilled_original_obligation() {
    // An unreadable occurrence cannot vanish from the complete LTV TSA census.
    let bytes = message(&[attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[])]);
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 700).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let prepared =
        Preparation::read(&document, &data.signers()[0], Level::Timestamped, &parent).unwrap();
    assert_eq!(prepared.timestamps().len(), 1);
    assert_eq!(prepared.timestamp_requirements().entries().len(), 1);
    assert!(!prepared.all_format_requirements_met());
}

#[test]
fn lower_level_timestamp_presences_are_advisories_not_failed_requirements() {
    // EN319122-1 Table1 '*' means SHOULD NOT. Keep every occurrence and
    // higher-level count, without converting that recommendation into SHALL.
    let bytes = message(&[
        attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[token()]),
        attribute(oid::ARCHIVE_TIMESTAMP_V3.as_bytes(), &[token()]),
    ]);
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 500).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    for level in [
        Level::Basic,
        Level::Timestamped,
        Level::LongTerm,
        Level::Archival,
    ] {
        let prepared = Preparation::read(&document, &data.signers()[0], level, &parent).unwrap();
        for (kind, discouraged) in [
            (oid::SIGNATURE_TIMESTAMP, level == Level::Basic),
            (oid::ARCHIVE_TIMESTAMP_V3, level < Level::Archival),
        ] {
            let findings: Vec<_> = prepared
                .findings()
                .iter()
                .filter(|finding| matches!(finding.rule, Rule::Forbidden(oid) if oid == kind))
                .collect();
            assert_eq!(
                findings.len(),
                usize::from(discouraged),
                "{level:?} {kind:?}"
            );
            for finding in findings {
                assert_eq!(finding.severity, Severity::Advisory);
                let attribute = data.signers()[0]
                    .unsigned_attributes()
                    .unwrap()
                    .unique_in(kind, &parent)
                    .unwrap()
                    .unwrap();
                assert_eq!(finding.location.node.span(), attribute.span());
            }
        }
        assert_eq!(prepared.timestamps().len(), 2);
        assert!(!prepared.findings().iter().any(|finding| matches!(
            finding.rule,
            Rule::SignatureTimestamp | Rule::ArchiveTimestamp
        )));
    }
}

#[test]
fn registered_legacy_values_cannot_substitute_an_arbitrary_asn1_type() {
    // AnnexA declares six reference/value sequences and two TimeStampTokens;
    // a lower-level advisory never waives the declared value's syntax.
    for suffix in [21, 22, 23, 24, 25, 26, 44, 45] {
        let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, suffix];
        let bytes = message(&[attribute(&kind, &[tlv(2, &[1])])]);
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        let invalid =
            prepared.findings().iter().any(|finding| {
                if finding.severity != Severity::Required {
                    return false;
                }
                match finding.rule {
                    Rule::Value { attribute, .. } => attribute.as_bytes() == kind,
                    Rule::Schema {
                        code:
                            structured_cms::ErrorCode::UnexpectedTag
                            | structured_cms::ErrorCode::Encoding(
                                structured_asn1::ErrorCode::UnexpectedTag,
                            ),
                        ..
                    } => true,
                    _ => false,
                }
            });
        assert!(invalid, "missing legacy schema refusal for {suffix}");
    }
}

#[test]
fn legacy_catalogue_enforces_value_and_baseline_instance_cardinality() {
    // AnnexA fixes one value per instance. Table1 permits repeated reference
    // timestamps, while its other six legacy rows permit at most one instance.
    for suffix in [21, 22, 23, 24, 25, 26, 44, 45] {
        let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, suffix];
        for count in [0, 1, 2] {
            let bytes = message(&[attribute(&kind, &vec![tlv(0x30, &[]); count])]);
            let parser = Parser::ber(memory());
            let data = SignedData::read(&parser, &bytes, 500).unwrap();
            let parent = parser.read(&[], 0).unwrap();
            let document = Document::new(&data, &parent).unwrap();
            let prepared =
                Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
            let invalid = prepared.findings().iter().any(|finding| {
                matches!(
                    finding.rule,
                    Rule::Schema {
                        code: structured_cms::ErrorCode::AttributeCardinality,
                        ..
                    }
                )
            });
            assert_eq!(invalid, count != 1, "suffix={suffix} count={count}");
        }
        let entry = attribute(&kind, &[tlv(0x30, &[])]);
        let bytes = message(&[entry.clone(), entry]);
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        let duplicate = prepared.findings().iter().any(|finding| {
            matches!(
                finding.rule,
                Rule::Schema {
                    code: structured_cms::ErrorCode::DuplicateAttribute,
                    ..
                }
            )
        });
        assert_eq!(duplicate, suffix != 25 && suffix != 26, "suffix={suffix}");
    }
}

#[test]
fn legacy_attributes_require_unsigned_placement_for_root_and_counter_signers() {
    // AnnexA's unsigned placement is mandatory independently of Table1's
    // lower-level advice or LT/LTA absence. Preserve the actual attribute span.
    for suffix in [21, 22, 23, 24, 25, 26, 44, 45] {
        let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, suffix];
        let attribute = attribute(&kind, &[tlv(0x30, &[])]);
        for counter in [false, true] {
            for protected in [false, true] {
                let (signed, unsigned) = if protected {
                    (vec![attribute.clone()], vec![])
                } else {
                    (vec![], vec![attribute.clone()])
                };
                let bytes = if counter {
                    message(&[self::attribute(
                        oid::COUNTERSIGNATURE.as_bytes(),
                        &[signer_with(&signed, &unsigned)],
                    )])
                } else {
                    message_with(&signed, &unsigned)
                };
                let at = 500
                    + bytes
                        .windows(attribute.len())
                        .position(|bytes| bytes == attribute)
                        .unwrap() as u64;
                let parser = Parser::ber(memory());
                let data = SignedData::read(&parser, &bytes, 500).unwrap();
                let parent = parser.read(&[], 0).unwrap();
                let document = Document::new(&data, &parent).unwrap();
                for level in [
                    Level::Basic,
                    Level::Timestamped,
                    Level::LongTerm,
                    Level::Archival,
                ] {
                    let prepared =
                        Preparation::read(&document, &data.signers()[0], level, &parent).unwrap();
                    let misplaced = prepared.findings().iter().any(|finding| {
                        finding.severity == Severity::Required
                            && finding.location.node.span().start == at
                            && matches!(
                                finding.rule,
                                Rule::Schema {
                                    code: structured_cms::ErrorCode::AttributePlacement,
                                    ..
                                }
                            )
                    });
                    assert_eq!(
                        misplaced, protected,
                        "suffix={suffix} counter={counter} protected={protected} level={level:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn legacy_reference_attributes_are_forbidden_only_at_long_term_levels() {
    // EN6.3 Table1 permits these with advisory '*' at B-B/B-T, forbids LT/LTA.
    let certificate_refs = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 21];
    let bytes = message(&[attribute(certificate_refs, &[tlv(0x30, &[])])]);
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 100).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    for level in [
        Level::Basic,
        Level::Timestamped,
        Level::LongTerm,
        Level::Archival,
    ] {
        let prepared = Preparation::read(&document, &data.signers()[0], level, &parent).unwrap();
        let forbidden = prepared.findings().iter().any(|finding| {
            finding.severity == Severity::Required && matches!(finding.rule, Rule::Forbidden(_))
        });
        assert_eq!(forbidden, level >= Level::LongTerm);
    }
}

#[test]
fn equal_encoded_foreign_source_and_exhausted_query_are_terminal() {
    // Equal bytes and equal account are not parser/model identity. Spent work
    // cannot be returned as an empty findings list or successful partial census.
    let bytes = message(&[]);
    let account = memory();
    let parser = Parser::ber(account.clone());
    let foreign = Parser::ber(account.clone());
    let data = SignedData::read(&parser, &bytes, 0).unwrap();
    let other = SignedData::read(&foreign, &bytes, 0).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    assert!(Document::new(&other, &parent).is_err());
    let document = Document::new(&data, &parent).unwrap();
    assert!(document.signer(&other.signers()[0]).is_err());
    account
        .charge_work(account.work_remaining() as u64)
        .unwrap();
    assert!(Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).is_err());
}

#[test]
fn every_v2_certificate_reference_refuses_sha1_even_with_v1() {
    // CAdES EN319122-1 §5.2.2.3 narrows generic ESS: V1 coexistence cannot
    // waive V2's non-SHA1 semantics, including later IDs and countersigners.
    for companion in [false, true] {
        for counter in [false, true] {
            for sha1 in [false, true] {
                let mut ids = tlv(0x30, &tlv(4, &[0; 32]));
                let hash = if sha1 { oid::SHA1 } else { oid::SHA256 };
                ids.extend(tlv(
                    0x30,
                    &[tlv(0x30, &tlv(6, hash.as_bytes())), tlv(4, &[0; 20])].concat(),
                ));
                let mut signed = vec![attribute(
                    oid::SIGNING_CERTIFICATE_V2.as_bytes(),
                    &[tlv(0x30, &tlv(0x30, &ids))],
                )];
                if companion {
                    signed.push(attribute(
                        oid::SIGNING_CERTIFICATE.as_bytes(),
                        &[tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &[0; 20]))))],
                    ));
                }
                let bytes = if counter {
                    message(&[attribute(
                        oid::COUNTERSIGNATURE.as_bytes(),
                        &[signer_with(&signed, &[])],
                    )])
                } else {
                    message_with(&signed, &[])
                };
                let parser = Parser::ber(memory());
                let data = SignedData::read(&parser, &bytes, 500).unwrap();
                let parent = parser.read(&[], 0).unwrap();
                let document = Document::new(&data, &parent).unwrap();
                let prepared =
                    Preparation::read(&document, &data.signers()[0], Level::Basic, &parent)
                        .unwrap();
                let failures: Vec<_> = prepared
                    .findings()
                    .iter()
                    .filter(|finding| matches!(finding.rule, Rule::SigningCertificateVersion))
                    .collect();
                assert_eq!(
                    failures.len(),
                    usize::from(sha1),
                    "companion={companion} counter={counter}"
                );
                for failure in failures {
                    assert_eq!(failure.severity, Severity::Required);
                }
            }
        }
    }
}

#[test]
fn claimed_saml_requires_one_octet_string_without_interpreting_the_claim() {
    // EN319122-1 §5.2.6.2 fixes the registered claim's envelope. Its XML and
    // authorization semantics remain with the caller, even for opaque bytes.
    for (values, valid) in [
        (vec![], false),
        (vec![tlv(4, b"one"), tlv(4, b"two")], false),
        (vec![tlv(2, &[1])], false),
        (vec![tlv(4, b"opaque claim")], true),
    ] {
        let claimed = attribute(oid::CLAIMED_SAML_ASSERTION.as_bytes(), &values);
        let attributes = tlv(0x30, &tlv(0xa0, &tlv(0x30, &claimed)));
        let bytes = message_with(
            &[attribute(
                oid::SIGNER_ATTRIBUTES_V2.as_bytes(),
                &[attributes],
            )],
            &[],
        );
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        let invalid = prepared.findings().iter().any(|finding| {
            finding.severity == Severity::Required
                && matches!(finding.rule, Rule::Value { attribute, .. } if attribute == oid::SIGNER_ATTRIBUTES_V2)
        });
        assert_eq!(invalid, !valid, "claimed values: {values:?}");
    }
}

#[test]
fn present_optional_attributes_must_satisfy_their_value_schemas() {
    // EN319122-1 §§5.2.3–5.2.5/5.2.11–12: an OID and singleton
    // catalogue alone cannot establish the syntax of its claimed value.
    for (kind, value) in [
        (oid::MIME_TYPE, tlv(12, b"text")),
        (oid::CONTENT_HINTS, tlv(0x30, &tlv(12, b"description"))),
        (oid::CONTENT_IDENTIFIER, tlv(2, &[1])),
        (oid::CONTENT_REFERENCE, tlv(0x30, &[])),
        (oid::COMMITMENT_TYPE_INDICATION, tlv(0x30, &[])),
        (oid::SIGNER_LOCATION, tlv(0x30, &[])),
        (oid::SIGNER_ATTRIBUTES_V2, tlv(0x30, &[])),
    ] {
        let bytes = message_with(&[attribute(kind.as_bytes(), &[value])], &[]);
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 300).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        assert!(
            prepared.findings().iter().any(
                |finding| matches!(finding.rule, Rule::Value { attribute, .. } if attribute == kind)
            ),
            "missing value finding for {kind:?}"
        );
    }
}

#[test]
fn empty_counter_and_ber_signature_timestamp_are_not_conforming() {
    // RFC5652 §11.4 needs at least one counter value; EN319122-1 §6.3(l)
    // requires the whole signature-time-stamp attribute to be DER encoded.
    let mut ber_timestamp = attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[tlv(0x30, &[])]);
    ber_timestamp.insert(1, 0x81);
    let bytes = message(&[
        attribute(oid::COUNTERSIGNATURE.as_bytes(), &[]),
        ber_timestamp,
    ]);
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 600).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let prepared =
        Preparation::read(&document, &data.signers()[0], Level::Timestamped, &parent).unwrap();
    assert!(prepared.findings().iter().any(|finding| matches!(finding.rule, Rule::Value { attribute, .. } if attribute == oid::SIGNATURE_TIMESTAMP)));
    assert!(prepared.findings().iter().any(|finding| matches!(finding.rule, Rule::Value { attribute, .. } if attribute == oid::COUNTERSIGNATURE)));
}

fn credential_attributes(number: u8) -> Vec<u8> {
    let entry = match number {
        0 => attribute(&[42], &[tlv(4, b"claim")]),
        1 => tlv(0xa0, &tlv(0x30, &[])),
        2 => tlv(0x30, &[tlv(6, &[42]), tlv(4, b"assertion")].concat()),
        _ => unreachable!(),
    };
    attribute(
        oid::SIGNER_ATTRIBUTES_V2.as_bytes(),
        &[tlv(0x30, &tlv(0xa0 + number, &tlv(0x30, &entry)))],
    )
}

#[test]
fn credential_references_need_protected_credentials_of_the_same_signer() {
    // Table1 requirement n applies even below LT: claimed values, unsigned
    // credentials and another signer's credentials do not satisfy this gate.
    for suffix in [44, 45] {
        let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, suffix];
        let reference = attribute(&kind, &[tlv(0x30, &[])]);
        for counter in [false, true] {
            for (mode, allowed) in [
                (0, false),
                (1, false),
                (2, true),
                (3, true),
                (4, false),
                (5, false),
            ] {
                let mut signed = vec![];
                let mut unsigned = vec![reference.clone()];
                match mode {
                    1 => signed.push(credential_attributes(0)),
                    2 => signed.push(credential_attributes(1)),
                    3 => signed.push(credential_attributes(2)),
                    4 => unsigned.push(credential_attributes(1)),
                    _ => {}
                }
                let bytes = if counter {
                    let roots = if mode == 5 {
                        vec![credential_attributes(1)]
                    } else {
                        vec![]
                    };
                    message_with(
                        &roots,
                        &[attribute(
                            oid::COUNTERSIGNATURE.as_bytes(),
                            &[signer_with(&signed, &unsigned)],
                        )],
                    )
                } else {
                    message_with(&signed, &unsigned)
                };
                let reference_at = 500
                    + bytes
                        .windows(reference.len())
                        .position(|bytes| bytes == reference)
                        .unwrap() as u64;
                let parser = Parser::ber(memory());
                let data = SignedData::read(&parser, &bytes, 500).unwrap();
                let parent = parser.read(&[], 0).unwrap();
                let document = Document::new(&data, &parent).unwrap();
                for level in [Level::Basic, Level::Timestamped] {
                    let prepared =
                        Preparation::read(&document, &data.signers()[0], level, &parent).unwrap();
                    let missing = prepared.findings().iter().any(|finding| {
                        finding.severity == Severity::Required
                            && finding.location.node.span().start == reference_at
                    });
                    assert_eq!(
                        missing, !allowed,
                        "suffix={suffix} counter={counter} mode={mode} level={level:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn policy_qualifier_values_are_optional_but_present_registered_values_are_typed() {
    // EN319122-1 §5.2.9.2/AnnexD declares qualifier OPTIONAL. Absence is
    // distinct from a present value of the wrong registered type; unknown
    // qualifiers and independently optional assertions remain opaque.
    for (kind, valid, registered) in [
        (vec![42], tlv(5, &[]), false),
        (
            vec![42, 134, 72, 134, 247, 13, 1, 9, 16, 5, 1],
            tlv(22, b"https://example.test/policy"),
            true,
        ),
        (
            vec![42, 134, 72, 134, 247, 13, 1, 9, 16, 5, 2],
            tlv(0x30, &[]),
            true,
        ),
        (vec![4, 0, 0x81, 0x95, 0x32, 2, 1], tlv(6, &[42]), true),
    ] {
        for mode in 0..3 {
            let mut pair = tlv(6, &kind);
            match mode {
                0 => {}
                1 => pair.extend(&valid),
                _ => pair.extend(tlv(2, &[1])),
            }
            let policy = attribute(
                oid::SIGNATURE_POLICY_IDENTIFIER.as_bytes(),
                &[tlv(
                    0x30,
                    &[
                        tlv(6, &[43]),
                        tlv(
                            0x30,
                            &[tlv(0x30, &tlv(6, oid::SHA256.as_bytes())), tlv(4, &[1; 32])]
                                .concat(),
                        ),
                        tlv(0x30, &tlv(0x30, &pair)),
                    ]
                    .concat(),
                )],
            );
            let assertion = attribute(
                oid::SIGNER_ATTRIBUTES_V2.as_bytes(),
                &[tlv(
                    0x30,
                    &tlv(0xa2, &tlv(0x30, &tlv(0x30, &tlv(6, &[42])))),
                )],
            );
            let bytes = message_with(&[policy, assertion], &[]);
            let parser = Parser::ber(memory());
            let data = SignedData::read(&parser, &bytes, 500).unwrap();
            let parent = parser.read(&[], 0).unwrap();
            let document = Document::new(&data, &parent).unwrap();
            let prepared =
                Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
            let invalid = |kind| {
                prepared.findings().iter().any(|finding| matches!(finding.rule, Rule::Value {attribute, ..} if attribute == kind))
            };
            assert_eq!(
                invalid(oid::SIGNATURE_POLICY_IDENTIFIER),
                mode == 2 && registered,
                "kind={kind:?} mode={mode}"
            );
            assert!(!invalid(oid::SIGNER_ATTRIBUTES_V2));
            if mode == 0 {
                let qualifier = prepared
                    .properties()
                    .open_values()
                    .iter()
                    .find(|entry| {
                        entry.role == structured_cades::properties::OpenRole::PolicyQualifier
                    })
                    .unwrap();
                assert!(qualifier.value.is_none());
            }
        }
    }
}

#[test]
fn local_policy_store_requires_uri_syntax_without_fetching_it() {
    // EN319122-1 §5.2.10 selects a URI, not arbitrary ASCII text. A proper
    // protected policy hash cannot waive the local-store value's own grammar.
    let policy = attribute(
        oid::SIGNATURE_POLICY_IDENTIFIER.as_bytes(),
        &[tlv(
            0x30,
            &[
                tlv(6, &[43]),
                tlv(
                    0x30,
                    &[tlv(0x30, &tlv(6, oid::SHA256.as_bytes())), tlv(4, &[1; 32])].concat(),
                ),
            ]
            .concat(),
        )],
    );
    for (uri, valid) in [
        (tlv(22, b"not a URI"), false),
        (tlv(22, b"file:///policy/%GG"), false),
        (tlv(22, b"file:///policy/document"), true),
        (
            tlv(
                0x36,
                &[tlv(4, b"file:///policy/"), tlv(4, b"document")].concat(),
            ),
            true,
        ),
    ] {
        let store = attribute(
            oid::SIGNATURE_POLICY_STORE.as_bytes(),
            &[tlv(0x30, &[tlv(6, &[42]), uri].concat())],
        );
        let bytes = message_with(std::slice::from_ref(&policy), &[store]);
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        let invalid = prepared.findings().iter().any(|finding| matches!(finding.rule, Rule::Value { attribute, .. } if attribute == oid::SIGNATURE_POLICY_STORE));
        assert_eq!(invalid, !valid);
        assert!(
            !prepared
                .findings()
                .iter()
                .any(|finding| matches!(finding.rule, Rule::PolicyStore))
        );
    }
}

#[test]
fn policy_store_requires_a_written_nonzero_protected_policy_digest() {
    // EN6.3(k) forbids an unbound store, including the normative zero-hash
    // UNKNOWN marker. It is not treated as a digest of the stored document.
    let store = attribute(
        oid::SIGNATURE_POLICY_STORE.as_bytes(),
        &[tlv(0x30, &[tlv(6, &[42]), tlv(4, b"policy")].concat())],
    );
    for hash in [None, Some(vec![]), Some(vec![0; 7])] {
        let signed: Vec<_> = hash
            .into_iter()
            .map(|hash| {
                attribute(
                    oid::SIGNATURE_POLICY_IDENTIFIER.as_bytes(),
                    &[tlv(
                        0x30,
                        &[
                            tlv(6, &[43]),
                            tlv(
                                0x30,
                                &[tlv(0x30, &tlv(6, oid::SHA256.as_bytes())), tlv(4, &hash)]
                                    .concat(),
                            ),
                        ]
                        .concat(),
                    )],
                )
            })
            .collect();
        let bytes = message_with(&signed, std::slice::from_ref(&store));
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 100).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        assert!(
            prepared
                .findings()
                .iter()
                .any(|finding| matches!(finding.rule, Rule::PolicyStore))
        );
    }
}

#[test]
fn nested_timestamp_inputs_and_cached_token_readers_keep_original_context() {
    // A child's timestamp covers the child's signature, while the child itself
    // covers its parent. Cached source models must not flip those two inputs
    // or create a default-budget parser when opening their carried TSTInfo.
    use structured_ltv::source::{Scope, Source};
    let stamp = attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[token()]);
    let grandchild = signer_value(&[], std::slice::from_ref(&stamp), 3);
    let child = signer_value(
        &[],
        &[
            stamp.clone(),
            attribute(oid::COUNTERSIGNATURE.as_bytes(), &[grandchild]),
        ],
        2,
    );
    let bytes = message(&[stamp, attribute(oid::COUNTERSIGNATURE.as_bytes(), &[child])]);
    let account = memory();
    let parser = Parser::ber(account.clone());
    let data = SignedData::read(&parser, &bytes, 900).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let prepared =
        Preparation::read(&document, &data.signers()[0], Level::Timestamped, &parent).unwrap();
    assert_eq!(prepared.timestamps().len(), 3);
    for (ordinal, signature) in [8, 2, 3].into_iter().enumerate() {
        let pieces = prepared.signature_input(ordinal, &parent).unwrap().unwrap();
        assert_eq!(
            pieces
                .iter()
                .flat_map(|piece| piece.as_bytes())
                .copied()
                .collect::<Vec<_>>(),
            [signature]
        );
    }
    assert!(
        prepared
            .counter_content_input(0, &parent)
            .unwrap()
            .is_none()
    );
    for (ordinal, input) in [(1, 8), (2, 2)] {
        let pieces = prepared
            .counter_content_input(ordinal, &parent)
            .unwrap()
            .unwrap();
        assert_eq!(
            pieces
                .iter()
                .flat_map(|piece| piece.as_bytes())
                .copied()
                .collect::<Vec<_>>(),
            [input]
        );
    }
    let baseline = account.used();
    let pool = structured_cades::material::Pool::read(&prepared, &parent).unwrap();
    assert!(pool.token_faults().is_empty());
    for ordinal in 0..3 {
        pool.with_token(ordinal, &parent, |context| {
            assert!(std::ptr::eq(
                context.reader().parser(),
                std::ptr::from_ref(&parser)
            ));
            context
                .token()
                .with_info(context.reader(), |info, reader, _| {
                    assert!(std::ptr::eq(reader.parser(), std::ptr::from_ref(&parser)));
                    assert_eq!(info.serial().value().as_u64(), Some(7));
                    Ok::<_, ()>(())
                })
                .unwrap();
            Ok::<_, ()>(())
        })
        .unwrap();
    }
    let work = parent.execution();
    let query = Scope::new(&document, document.snapshot(), &work);
    let index = pool.index(&query).unwrap();
    assert!(index.open().is_empty());
    drop(index);
    drop(pool);
    assert_eq!(account.used(), baseline);
    account
        .charge_work(account.work_remaining() as u64)
        .unwrap();
    assert!(prepared.signature_input(0, &parent).is_err());
}

#[test]
fn legacy_reference_timestamps_preserve_mapped_failures_and_original_obligations() {
    // A segmented malformed TSTInfo keeps its logical cause and physical map
    // after all document/parser/cache owners drop; valid old tokens remain
    // historical obligations rather than being promoted into modern proofs.
    use structured_cades::prepare::ReadError;
    use structured_cms::{
        content_source::{ContentError, Coordinates},
        timestamp::InfoError,
    };
    for suffix in [25, 26] {
        let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, suffix];
        let bad = token_carried(&tlv(0x24, &[tlv(4, &[2]), tlv(4, &[1, 1])].concat()));
        let bytes = message(&[attribute(&kind, &[bad])]);
        let expected = 500 + bytes.windows(3).position(|v| v == [4, 1, 2]).unwrap() as u64 + 2;
        let account = memory();
        let map = {
            let parser = Parser::ber(account.clone());
            let data = SignedData::read(&parser, &bytes, 500).unwrap();
            let parent = parser.read(&[], 0).unwrap();
            let document = Document::new(&data, &parent).unwrap();
            let prepared =
                Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
            assert!(prepared.timestamps().is_empty());
            let pool = structured_cades::material::Pool::read(&prepared, &parent).unwrap();
            let [
                (
                    _,
                    ReadError::Information(ContentError::Callback {
                        source: InfoError::Processing(cause),
                        context,
                    }),
                ),
            ] = pool.token_faults()
            else {
                panic!("mapped information cause lost")
            };
            assert_eq!(
                cause.code(),
                structured_cms::ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
            );
            assert_eq!(cause.field(), "tstInfo");
            assert_eq!(cause.offset(), 0);
            assert_eq!(context.coordinates(), Coordinates::Logical);
            context.try_copy_in(&parent.execution()).unwrap()
        };
        assert!(account.used() > 0);
        assert_eq!(map.project_offset(0, &account).unwrap(), expected);
        drop(map);
        assert_eq!(account.used(), 0);
        let good = message(&[attribute(&kind, &[token()])]);
        let parser = Parser::ber(account);
        let data = SignedData::read(&parser, &good, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        let pool = structured_cades::material::Pool::read(&prepared, &parent).unwrap();
        assert!(pool.token_faults().is_empty());
        assert!(prepared.timestamps().is_empty());
    }
}

#[test]
fn legacy_reference_traversal_obeys_producing_and_aggregate_work_and_rolls_back() {
    // The opaque CMS catalogue fits; inspecting every OtherCertID must then
    // refuse under either current local work or aggregate work, releasing all
    // temporary preparation storage without disguising refusal as a finding.
    let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 21];
    let entry = tlv(0x30, &tlv(4, &[1; 20]));
    let bytes = message(&[attribute(&kind, &[tlv(0x30, &entry.repeat(512))])]);
    for (local, aggregate) in [(20_000, 100_000_000), (100_000_000, 20_000)] {
        let account = Memory::new(Arc::new(MemoryAccount::new(1 << 20, aggregate)));
        let parser = Parser::new(
            structured_asn1::Encoding::Ber,
            structured_asn1::Limits {
                max_work: local,
                ..Default::default()
            },
            account.clone(),
        );
        let data = SignedData::read(&parser, &bytes, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let storage = account.used();
        let Err(cause) = Preparation::read(&document, &data.signers()[0], Level::Basic, &parent)
        else {
            panic!("legacy traversal escaped work admission")
        };
        assert!(cause.is_terminal());
        drop(cause);
        assert_eq!(account.used(), storage);
    }
}

#[test]
fn parallel_legacy_reference_tokens_do_not_change_selected_root_syntax() {
    // Keep another root's historical obligation without treating its broken
    // optional token as a syntax error in the independently selected signer.
    let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 26];
    let mut body = vec![2, 1, 3, 0x31, 0];
    body.extend(tlv(0x30, &tlv(6, oid::DATA.as_bytes())));
    body.extend(tlv(
        0x31,
        &[
            signer(&[]),
            signer_value(
                &[],
                &[attribute(&kind, &[token_information(&[2, 1, 1])])],
                9,
            ),
        ]
        .concat(),
    ));
    let bytes = tlv(
        0x30,
        &[
            tlv(6, oid::SIGNED_DATA.as_bytes()),
            tlv(0xa0, &tlv(0x30, &body)),
        ]
        .concat(),
    );
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 500).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let first = Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
    let pool = structured_cades::material::Pool::read(&first, &parent).unwrap();
    assert!(pool.token_faults().is_empty());
    assert_eq!(first.preservation().len(), 1);
    let second = Preparation::read(&document, &data.signers()[1], Level::Basic, &parent).unwrap();
    let pool = structured_cades::material::Pool::read(&second, &parent).unwrap();
    assert_eq!(pool.token_faults().len(), 1);
}

#[test]
fn md5_is_forbidden_in_every_legacy_reference_hash_position() {
    // EN319122-1 §6.2.1 forbids actual MD5 use, including advisory legacy
    // references. An opaque OID-bearing reference is not a successful escape.
    let md5 = [42, 134, 72, 134, 247, 13, 2, 5];
    let hash = tlv(0x30, &[tlv(0x30, &tlv(6, &md5)), tlv(4, &[1; 16])].concat());
    for suffix in [21, 22, 44, 45] {
        let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, suffix];
        let mut values = vec![tlv(0x30, &tlv(0x30, &hash))];
        if suffix == 22 || suffix == 45 {
            let crl = tlv(0x30, &tlv(0x30, &tlv(0x30, &hash)));
            let responder = tlv(
                0x30,
                &[tlv(0xa2, &tlv(4, &[1; 20])), tlv(24, b"20260101000000Z")].concat(),
            );
            let ocsp = tlv(
                0x30,
                &tlv(0x30, &tlv(0x30, &[responder, hash.clone()].concat())),
            );
            values = vec![
                tlv(0x30, &tlv(0x30, &tlv(0xa0, &crl))),
                tlv(0x30, &tlv(0x30, &tlv(0xa1, &ocsp))),
            ];
        }
        for value in values {
            let entry = attribute(&kind, &[value]);
            for counter in [false, true] {
                let bytes = if counter {
                    message(&[attribute(
                        oid::COUNTERSIGNATURE.as_bytes(),
                        &[signer(std::slice::from_ref(&entry))],
                    )])
                } else {
                    message(std::slice::from_ref(&entry))
                };
                let parser = Parser::ber(memory());
                let data = SignedData::read(&parser, &bytes, 500).unwrap();
                let parent = parser.read(&[], 0).unwrap();
                let document = Document::new(&data, &parent).unwrap();
                let prepared =
                    Preparation::read(&document, &data.signers()[0], Level::Basic, &parent)
                        .unwrap();
                assert!(
                    prepared.findings().iter().any(|finding| finding.severity
                        == Severity::Required
                        && matches!(
                            finding.rule,
                            Rule::Value {
                                field: "cades.legacy",
                                ..
                            }
                        )),
                    "suffix={suffix} counter={counter}"
                );
            }
        }
    }
}

#[test]
fn registered_signed_saml_uses_octets_without_validating_unknown_assertions() {
    // EN319122-1 §5.2.6.3 types the registered signed-SAML payload as
    // OCTET STRING. Unknown assertions remain opaque and absent OPTIONAL
    // payloads do not become fabricated signed assertion bytes.
    for (kind, registered) in [
        (vec![4, 0, 0x81, 0x95, 0x32, 3, 0], true),
        (vec![42], false),
    ] {
        for mode in 0..3 {
            let mut pair = tlv(6, &kind);
            match mode {
                0 => {}
                1 => pair.extend(tlv(4, b"signed assertion")),
                _ => pair.extend(tlv(2, &[1])),
            }
            let value = tlv(0x30, &tlv(0xa2, &tlv(0x30, &tlv(0x30, &pair))));
            let bytes = message_with(
                &[attribute(oid::SIGNER_ATTRIBUTES_V2.as_bytes(), &[value])],
                &[],
            );
            let parser = Parser::ber(memory());
            let data = SignedData::read(&parser, &bytes, 500).unwrap();
            let parent = parser.read(&[], 0).unwrap();
            let document = Document::new(&data, &parent).unwrap();
            let prepared =
                Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
            let invalid = prepared.findings().iter().any(|finding| matches!(finding.rule, Rule::Value {attribute, ..} if attribute == oid::SIGNER_ATTRIBUTES_V2));
            assert_eq!(
                invalid,
                registered && mode == 2,
                "kind={kind:?} mode={mode}"
            );
            if !invalid {
                let [entry] = prepared.properties().open_values() else {
                    panic!("original assertion lost")
                };
                assert_eq!(entry.value.is_some(), mode != 0);
                assert_eq!(entry.kind.unwrap().as_bytes(), kind);
            }
        }
    }
}

#[test]
fn legacy_other_cert_id_reports_its_original_issuer_hint_on_roots_and_counters() {
    // Table1(g) recommends omitting issuerSerial from complete certificate
    // references. Report the original field once as advisory, not bad syntax.
    let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 21];
    let name = tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(0x30, &[tlv(6, &[85, 4, 3]), tlv(12, b"Issuer")].concat()),
        ),
    );
    let issuer = tlv(0x30, &[tlv(0x30, &tlv(0xa4, &name)), tlv(2, &[7])].concat());
    for present in [false, true] {
        let mut reference = tlv(4, &[1; 20]);
        if present {
            reference.extend(&issuer);
        }
        let entry = attribute(&kind, &[tlv(0x30, &tlv(0x30, &reference))]);
        for counter in [false, true] {
            let bytes = if counter {
                message(&[attribute(
                    oid::COUNTERSIGNATURE.as_bytes(),
                    &[signer(std::slice::from_ref(&entry))],
                )])
            } else {
                message(std::slice::from_ref(&entry))
            };
            let parser = Parser::ber(memory());
            let data = SignedData::read(&parser, &bytes, 500).unwrap();
            let parent = parser.read(&[], 0).unwrap();
            let document = Document::new(&data, &parent).unwrap();
            let prepared =
                Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
            let hints: Vec<_> = prepared
                .findings()
                .iter()
                .filter(|finding| matches!(finding.rule, Rule::IssuerHint))
                .collect();
            assert_eq!(
                hints.len(),
                usize::from(present),
                "present={present} counter={counter}"
            );
            if present {
                assert_eq!(hints[0].severity, Severity::Advisory);
                assert_eq!(
                    hints[0].location.node.span().start,
                    500 + bytes
                        .windows(issuer.len())
                        .position(|value| value == issuer)
                        .unwrap() as u64
                );
            }
        }
    }
}

#[test]
fn legacy_reference_times_preserve_the_producing_ber_der_boundary() {
    // AnnexA references are BER-capable: X.690 §§8.23/8.25 permit useful
    // time segmentation into OCTET STRING fragments; §10.2 forbids it in DER.
    // Exercise the complete public CRL/OCSP path, not only a tag predicate.
    for number in [23, 24] {
        for constructed in [false, true] {
            for der in [false, true] {
                let text = if number == 23 {
                    b"260101000000Z".as_slice()
                } else {
                    b"20260101000000Z".as_slice()
                };
                let time = if constructed {
                    tlv(
                        number | 32,
                        &[tlv(4, &text[..6]), tlv(4, &text[6..])].concat(),
                    )
                } else {
                    tlv(number, text)
                };
                let value = if number == 23 {
                    let identifier = tlv(0x30, &[tlv(0x30, &[]), time].concat());
                    let item = tlv(0x30, &[tlv(4, &[0; 20]), identifier].concat());
                    tlv(0x30, &tlv(0x30, &tlv(0xa0, &tlv(0x30, &tlv(0x30, &item)))))
                } else {
                    let identifier = tlv(0x30, &[tlv(0xa2, &tlv(4, &[0; 20])), time].concat());
                    let item = tlv(0x30, &identifier);
                    tlv(0x30, &tlv(0x30, &tlv(0xa1, &tlv(0x30, &tlv(0x30, &item)))))
                };
                let kind =
                    structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 22]);
                let bytes = message(&[attribute(kind.as_bytes(), &[value])]);
                let parser = if der {
                    Parser::der(memory())
                } else {
                    Parser::ber(memory())
                };
                let read = SignedData::read(&parser, &bytes, 500);
                if constructed && der {
                    let cause = read.unwrap_err();
                    assert_eq!(
                        cause.code(),
                        structured_cms::ErrorCode::Pkix(structured_pkix::ErrorCode::Encoding(
                            structured_asn1::ErrorCode::UnexpectedTag
                        ))
                    );
                    continue;
                }
                let data = read.unwrap();
                let parent = parser.read(&[], 0).unwrap();
                let document = Document::new(&data, &parent).unwrap();
                let prepared =
                    Preparation::read(&document, &data.signers()[0], Level::Basic, &parent)
                        .unwrap();
                assert!(
                    !prepared
                        .properties()
                        .faults()
                        .iter()
                        .any(|fault| fault.attribute == kind),
                    "number={number} constructed={constructed} der={der}"
                );
            }
        }
    }
}

#[test]
fn conflicting_ess_keeps_findings_and_the_complete_timestamp_counter_census() {
    // Conflicting ESS instances/values are schema failures, not terminal
    // processing refusals. Neither a root nor a child may hide later actors.
    for kind in [oid::SIGNING_CERTIFICATE, oid::SIGNING_CERTIFICATE_V2] {
        for multiple_values in [false, true] {
            for in_counter in [false, true] {
                let first = tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &[1; 32]))));
                let second = tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &[2; 32]))));
                let conflicting = if multiple_values {
                    vec![attribute(kind.as_bytes(), &[first, second])]
                } else {
                    vec![
                        attribute(kind.as_bytes(), &[first]),
                        attribute(kind.as_bytes(), &[second]),
                    ]
                };
                let stamp = attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[token()]);
                let child = signer_with(
                    if in_counter { &conflicting } else { &[] },
                    std::slice::from_ref(&stamp),
                );
                let bytes = message_with(
                    if in_counter { &[] } else { &conflicting },
                    &[stamp, attribute(oid::COUNTERSIGNATURE.as_bytes(), &[child])],
                );
                let parser = Parser::ber(memory());
                let data = SignedData::read(&parser, &bytes, 500).unwrap();
                let parent = parser.read(&[], 0).unwrap();
                let document = Document::new(&data, &parent).unwrap();
                let prepared =
                    Preparation::read(&document, &data.signers()[0], Level::Basic, &parent)
                        .unwrap();
                let expected = if multiple_values {
                    structured_cms::ErrorCode::AttributeCardinality
                } else {
                    structured_cms::ErrorCode::DuplicateAttribute
                };
                assert!(
                    prepared
                        .findings()
                        .iter()
                        .any(|finding| finding.severity == Severity::Required
                            && matches!(finding.rule, Rule::Schema {code,..} if code==expected))
                );
                assert!(!prepared.all_format_requirements_met());
                assert_eq!(prepared.counters().len(), 1);
                assert_eq!(prepared.timestamps().len(), 2);
                assert_eq!(prepared.timestamp_requirements().entries().len(), 2);
                if !in_counter {
                    assert!(prepared.profile().signing().v1().is_none());
                    assert!(prepared.profile().signing().v2().is_none());
                    let strict =
                        structured_cms::ess::SigningAttributes::read(&data.signers()[0], &parent)
                            .unwrap_err();
                    assert_eq!(strict.code(), expected);
                }
            }
        }
    }
}

#[test]
fn optional_timestamp_md5_is_a_preparation_finding_at_basic() {
    // EN319122-1 §6.2.1 is unconditional: requesting only B-B cannot hide
    // a forbidden actual digest inside an optional root or nested timestamp.
    let md5 = [42, 134, 72, 134, 247, 13, 2, 5];
    for (signer_md5, imprint_md5) in [(true, false), (false, true), (true, true), (false, false)] {
        let signer_algorithm = if signer_md5 {
            md5.as_slice()
        } else {
            oid::SHA256.as_bytes()
        };
        let imprint_algorithm = if imprint_md5 {
            md5.as_slice()
        } else {
            oid::SHA256.as_bytes()
        };
        let hash = vec![0; if imprint_md5 { 16 } else { 32 }];
        let info = tlv(
            0x30,
            &[
                vec![2, 1, 1],
                tlv(6, &[43]),
                tlv(
                    0x30,
                    &[tlv(0x30, &tlv(6, imprint_algorithm)), tlv(4, &hash)].concat(),
                ),
                vec![2, 1, 7],
                tlv(24, b"20260101000000Z"),
            ]
            .concat(),
        );
        let token_signer = tlv(
            0x30,
            &[
                vec![2, 1, 3, 0x80, 1, 7],
                tlv(0x30, &tlv(6, signer_algorithm)),
                tlv(0x30, &tlv(6, &[0x2b, 0x65, 0x70])),
                tlv(4, &[8]),
            ]
            .concat(),
        );
        let body = tlv(
            0x30,
            &[
                vec![2, 1, 3, 0x31, 0],
                tlv(
                    0x30,
                    &[tlv(6, oid::TST_INFO.as_bytes()), tlv(0xa0, &tlv(4, &info))].concat(),
                ),
                tlv(0x31, &token_signer),
            ]
            .concat(),
        );
        let token = tlv(
            0x30,
            &[tlv(6, oid::SIGNED_DATA.as_bytes()), tlv(0xa0, &body)].concat(),
        );
        for kind in [
            oid::CONTENT_TIMESTAMP,
            oid::SIGNATURE_TIMESTAMP,
            oid::ARCHIVE_TIMESTAMP_V3,
        ] {
            for in_counter in [false, true] {
                let stamp = attribute(kind.as_bytes(), std::slice::from_ref(&token));
                let signed = if kind == oid::CONTENT_TIMESTAMP {
                    vec![stamp.clone()]
                } else {
                    vec![]
                };
                let unsigned = if kind == oid::CONTENT_TIMESTAMP {
                    vec![]
                } else {
                    vec![stamp]
                };
                let bytes = if in_counter {
                    message(&[attribute(
                        oid::COUNTERSIGNATURE.as_bytes(),
                        &[signer_with(&signed, &unsigned)],
                    )])
                } else {
                    message_with(&signed, &unsigned)
                };
                let parser = Parser::ber(memory());
                let data = SignedData::read(&parser, &bytes, 500).unwrap();
                let parent = parser.read(&[], 0).unwrap();
                let document = Document::new(&data, &parent).unwrap();
                let prepared =
                    Preparation::read(&document, &data.signers()[0], Level::Basic, &parent)
                        .unwrap();
                assert_eq!(
                    prepared
                        .findings()
                        .iter()
                        .filter(|f| matches!(f.rule, Rule::Md5))
                        .count(),
                    usize::from(signer_md5) + usize::from(imprint_md5),
                    "signer={signer_md5} imprint={imprint_md5} counter={in_counter} kind={kind:?}"
                );
                assert_eq!(prepared.timestamps().len(), 1);
            }
        }
    }
}

#[test]
fn signer_attributes_require_actual_entries_not_only_empty_wrappers() {
    // EN319122-1 §5.2.6.1 forbids an empty whole value, while an empty
    // claimed field may accompany a nonempty assertion. Certified fields
    // retain their independent nonempty requirement.
    let empty_claimed = tlv(0xa0, &tlv(0x30, &[]));
    let claimed = tlv(0xa0, &tlv(0x30, &attribute(&[42], &[tlv(12, b"role")])));
    let assertion = tlv(0xa2, &tlv(0x30, &tlv(0x30, &tlv(6, &[42]))));
    let empty_certified = tlv(0xa1, &tlv(0x30, &[]));
    for (fields, valid) in [
        (vec![], false),
        (empty_claimed.clone(), false),
        (claimed.clone(), true),
        ([empty_claimed.clone(), assertion].concat(), true),
        ([empty_claimed, empty_certified.clone()].concat(), false),
        ([claimed, empty_certified].concat(), false),
    ] {
        for in_counter in [false, true] {
            let signed = attribute(oid::SIGNER_ATTRIBUTES_V2.as_bytes(), &[tlv(0x30, &fields)]);
            let bytes = if in_counter {
                message(&[attribute(
                    oid::COUNTERSIGNATURE.as_bytes(),
                    &[signer_with(&[signed], &[])],
                )])
            } else {
                message_with(&[signed], &[])
            };
            let parser = Parser::ber(memory());
            let data = SignedData::read(&parser, &bytes, 500).unwrap();
            let parent = parser.read(&[], 0).unwrap();
            let document = Document::new(&data, &parent).unwrap();
            let prepared =
                Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
            let invalid=prepared.findings().iter().any(|f|f.severity==Severity::Required && matches!(f.rule,Rule::Value {attribute,..} if attribute==oid::SIGNER_ATTRIBUTES_V2));
            assert_eq!(invalid, !valid, "fields={fields:?} counter={in_counter}");
        }
    }
}

#[test]
fn counter_owned_archive_retains_a_placement_finding_and_its_original_census() {
    // EN319122-1 §5.5.3(3) selects a SignedData.signerInfos item for ATSv3;
    // nested counters are protected by that root's indexed unsigned values.
    // Do not admit a nested archive as conforming and then leave its required
    // actor impossible to produce through the root-only archive processor.
    let archive = attribute(oid::ARCHIVE_TIMESTAMP_V3.as_bytes(), &[token()]);
    let stamp = attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[token()]);
    for nested in [false, true] {
        let bytes = if nested {
            message(&[
                archive.clone(),
                attribute(
                    oid::COUNTERSIGNATURE.as_bytes(),
                    &[signer(&[stamp.clone(), archive.clone()])],
                ),
            ])
        } else {
            message(&[archive.clone(), stamp.clone()])
        };
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Timestamped, &parent).unwrap();
        let placements: Vec<_> = prepared
            .findings()
            .iter()
            .filter(|f| {
                f.severity == Severity::Required
                    && matches!(
                        f.rule,
                        Rule::Schema {
                            code: structured_cms::ErrorCode::AttributePlacement,
                            field: "archiveTimeStampV3"
                        }
                    )
            })
            .collect();
        assert_eq!(placements.len(), usize::from(nested));
        assert_eq!(prepared.timestamps().len(), if nested { 3 } else { 2 });
        assert_eq!(
            prepared.timestamp_requirements().entries().len(),
            prepared.timestamps().len()
        );
        if nested {
            let entry = &prepared.timestamps()[2];
            assert_eq!(entry.owner(), prepared.counters()[0].node());
            assert_eq!(
                placements[0].location.node.span().start,
                entry.property().span().start
            );
            assert!(!prepared.basic_format_requirements_met());
        }
    }
}

#[test]
fn optional_timestamp_ess_presence_and_schema_are_checked_without_certificate_selection() {
    // RFC5816 §2.2.1 requires a readable signed TSA certificate identifier.
    // A lower requested level cannot waive present timestamp syntax; ESS
    // policies permitted by RFC5035 must not inherit the CAdES root ban.
    let v1 = tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &[1; 20]))));
    let v2 = tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &[2; 32]))));
    let v2_other = tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &[3; 32]))));
    let v2_policy = tlv(
        0x30,
        &[
            tlv(0x30, &tlv(0x30, &tlv(4, &[2; 32]))),
            tlv(0x30, &tlv(0x30, &tlv(6, &[43]))),
        ]
        .concat(),
    );
    for mode in 0..9 {
        let mut signed = timestamp_signed_attributes();
        let mut unsigned = vec![];
        match mode {
            0 => {}
            1 => signed.push(attribute(
                oid::SIGNING_CERTIFICATE_V2.as_bytes(),
                &[tlv(0x30, &tlv(0x30, &[]))],
            )),
            2 => signed.push(attribute(
                oid::SIGNING_CERTIFICATE_V2.as_bytes(),
                &[v2.clone(), v2_other.clone()],
            )),
            3 => unsigned.push(attribute(
                oid::SIGNING_CERTIFICATE_V2.as_bytes(),
                std::slice::from_ref(&v2),
            )),
            4 => signed.extend([
                attribute(
                    oid::SIGNING_CERTIFICATE_V2.as_bytes(),
                    std::slice::from_ref(&v2),
                ),
                attribute(
                    oid::SIGNING_CERTIFICATE_V2.as_bytes(),
                    std::slice::from_ref(&v2_other),
                ),
            ]),
            5 => signed.push(attribute(
                oid::SIGNING_CERTIFICATE.as_bytes(),
                std::slice::from_ref(&v1),
            )),
            6 => signed.push(attribute(
                oid::SIGNING_CERTIFICATE_V2.as_bytes(),
                std::slice::from_ref(&v2),
            )),
            7 => signed.extend([
                attribute(
                    oid::SIGNING_CERTIFICATE.as_bytes(),
                    std::slice::from_ref(&v1),
                ),
                attribute(
                    oid::SIGNING_CERTIFICATE_V2.as_bytes(),
                    std::slice::from_ref(&v2),
                ),
            ]),
            _ => signed.push(attribute(
                oid::SIGNING_CERTIFICATE_V2.as_bytes(),
                std::slice::from_ref(&v2_policy),
            )),
        }
        let token = token_with_attributes(&signed, &unsigned);
        for kind in [oid::CONTENT_TIMESTAMP, oid::SIGNATURE_TIMESTAMP] {
            for in_counter in [false, true] {
                let stamp = attribute(kind.as_bytes(), std::slice::from_ref(&token));
                let (signed, unsigned) = if kind == oid::CONTENT_TIMESTAMP {
                    (vec![stamp], vec![])
                } else {
                    (vec![], vec![stamp])
                };
                let bytes = if in_counter {
                    message(&[attribute(
                        oid::COUNTERSIGNATURE.as_bytes(),
                        &[signer_with(&signed, &unsigned)],
                    )])
                } else {
                    message_with(&signed, &unsigned)
                };
                let parser = Parser::ber(memory());
                let data = SignedData::read(&parser, &bytes, 500).unwrap();
                let parent = parser.read(&[], 0).unwrap();
                let document = Document::new(&data, &parent).unwrap();
                let prepared =
                    Preparation::read(&document, &data.signers()[0], Level::Basic, &parent)
                        .unwrap();
                assert_eq!(prepared.timestamps().len(), 1);
                assert_eq!(prepared.timestamp_requirements().entries().len(), 1);
                let span = prepared.timestamps()[0].property().span();
                let faults:Vec<_>=prepared.findings().iter().filter(|f|f.severity==Severity::Required && f.location.node.span().start>=span.start && f.location.node.span().start<span.end() && matches!(f.rule,Rule::Schema {field,..} if field.contains("signingCertificate"))).collect();
                assert_eq!(
                    !faults.is_empty(),
                    mode < 5,
                    "mode={mode} counter={in_counter} kind={kind:?}"
                );
            }
        }
    }
}

fn timestamp_width_case(target: u8) {
    // Fixed widths come from the declared standard identity, never inferred
    // from supplied bytes. Syntax inspection needs no selected TSA or hash.
    for invalid in [false, true] {
        let width = |which| if invalid && target == which { 31 } else { 32 };
        let ess = tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &vec![0; width(0)]))));
        let signed = vec![
            attribute(oid::SIGNING_CERTIFICATE_V2.as_bytes(), &[ess]),
            attribute(
                oid::CONTENT_TYPE.as_bytes(),
                &[tlv(6, oid::TST_INFO.as_bytes())],
            ),
            attribute(
                oid::MESSAGE_DIGEST.as_bytes(),
                &[tlv(4, &vec![0; width(1)])],
            ),
        ];
        let info = tlv(
            0x30,
            &[
                vec![2, 1, 1],
                tlv(6, &[43]),
                tlv(
                    0x30,
                    &[
                        tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
                        tlv(4, &vec![0; width(2)]),
                    ]
                    .concat(),
                ),
                vec![2, 1, 7],
                tlv(24, b"20260101000000Z"),
            ]
            .concat(),
        );
        let token = token_carried_with(&tlv(4, &info), &signed, &[]);
        let bytes = message(&[attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[token])]);
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 500).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
        let span = prepared.timestamps()[0].property().span();
        let found = prepared.findings().iter().any(|f| {
            f.severity == Severity::Required
                && f.location.node.span().start >= span.start
                && f.location.node.span().start < span.end()
                && matches!(
                    f.rule,
                    Rule::Schema {
                        code: structured_cms::ErrorCode::DigestWidth,
                        ..
                    }
                )
        });
        assert_eq!(found, invalid, "target={target}");
    }
}

#[test]
fn timestamp_static_ess_width_is_checked_during_inspection() {
    timestamp_width_case(0);
}
#[test]
fn timestamp_static_message_digest_width_is_checked_during_inspection() {
    timestamp_width_case(1);
}
#[test]
fn timestamp_static_imprint_width_is_checked_during_inspection() {
    timestamp_width_case(2);
}

#[test]
fn timestamp_inspection_refusal_retains_the_joined_information_source_map() {
    // A failed query inside fragmented TSTInfo owns its logical-to-physical
    // map after the temporary join/Parser drop. It cannot escape as an outer
    // Processing error whose small logical offset looks document-relative.
    use structured_cades::prepare::ReadError;
    use structured_cms::content_source::Coordinates;
    let info = tlv(
        0x30,
        &[
            vec![2, 1, 1],
            tlv(6, &[43]),
            tlv(
                0x30,
                &[tlv(0x30, &tlv(6, oid::SHA256.as_bytes())), tlv(4, &[0; 32])].concat(),
            ),
            vec![2, 1, 7],
            tlv(24, b"20260101000000Z"),
        ]
        .concat(),
    );
    let carried = tlv(0x24, &[tlv(4, &info[..17]), tlv(4, &info[17..])].concat());
    let token = token_carried(&carried);
    let bytes = message(&[attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[token])]);
    let mut retained = None;
    for allowance in 1..20_000 {
        let account = memory();
        let parser = Parser::ber(account.clone());
        let data = SignedData::read(&parser, &bytes, 900).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let document = Document::new(&data, &parent).unwrap();
        account
            .charge_work((account.work_remaining() - allowance) as u64)
            .unwrap();
        match Preparation::read(&document, &data.signers()[0], Level::Basic, &parent) {
            Err(ReadError::Processing(structured_cades::Error::Encoding {
                field: "tstInfo.messageImprint.hashedMessage",
                ..
            })) => panic!("inner reader refusal lost its source map"),
            Err(
                error @ ReadError::Inspection {
                    coordinates: Coordinates::Logical,
                    ..
                },
            ) => {
                retained = Some((error, account.clone()));
                break;
            }
            Ok(_) => panic!("complete inspection reached without exercising inner refusal"),
            _ => {}
        }
    }
    drop(bytes);
    let (error, account) = retained.expect("one inner query refusal");
    let ReadError::Inspection {
        source,
        context,
        coordinates,
    } = error
    else {
        unreachable!()
    };
    assert_eq!(coordinates, Coordinates::Logical);
    assert!(source.is_terminal());
    assert_eq!(context.coordinates(), Coordinates::Logical);
    let physical = context.project_offset(source.offset(), &memory()).unwrap();
    assert!(context.carrier().start >= 900);
    assert!(physical >= context.carrier().start);
    assert!(physical <= context.carrier().end());
    assert!(
        account.used() > 0,
        "the independent map retains its actual storage charge"
    );
    drop(context);
    assert_eq!(
        account.used(),
        0,
        "refusal releases the map and every partial reading"
    );
}

fn archive_token_attributes(mode: u8) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut signed = timestamp_signed_attributes();
    signed.push(attribute(
        oid::SIGNING_CERTIFICATE_V2.as_bytes(),
        &[tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &[0; 32]))))],
    ));
    let kind = if mode == 5 {
        &[42, 134, 72, 134, 247, 13, 2, 5][..]
    } else if mode == 7 {
        &[96, 134, 72, 1, 101, 3, 4, 2, 2][..]
    } else {
        oid::SHA256.as_bytes()
    };
    let mut algorithm = tlv(6, kind);
    if mode == 6 {
        algorithm.extend(tlv(2, &[1]));
    }
    if mode == 10 {
        algorithm.extend(tlv(5, &[]));
    }
    let hashes = if mode == 8 {
        tlv(0x30, &tlv(4, &[0; 31]))
    } else {
        tlv(0x30, &[])
    };
    let value = if mode == 2 {
        tlv(0x30, &[])
    } else {
        tlv(
            0x30,
            &[
                tlv(0x30, &algorithm),
                hashes,
                tlv(0x30, &[]),
                tlv(0x30, &[]),
            ]
            .concat(),
        )
    };
    let mut index = attribute(
        oid::ATS_HASH_INDEX_V3.as_bytes(),
        std::slice::from_ref(&value),
    );
    if mode == 9 {
        index = vec![0x30, 0x80];
        index.extend([tlv(6, oid::ATS_HASH_INDEX_V3.as_bytes()), tlv(0x31, &value)].concat());
        index.extend([0, 0]);
    }
    if mode == 11 {
        index = attribute(oid::ATS_HASH_INDEX_V3.as_bytes(), &[]);
    }
    if mode == 3 || mode == 12 {
        signed.push(index.clone());
    }
    let unsigned = match mode {
        0 | 3 => vec![],
        4 => vec![index.clone(), index],
        _ => vec![index],
    };
    (signed, unsigned)
}

#[test]
fn optional_archive_index_is_inspected_before_basic_can_accept_its_format() {
    // EN319122-1 §§5.5.2/5.5.3 apply even to an optional ATSv3 at B-B.
    // This is original envelope/index syntax and declared identity, without
    // executing hashes, signatures, paths or a caller payload source.
    for mode in 0..13 {
        let (signed, unsigned) = archive_token_attributes(mode);
        let token = token_with_attributes(&signed, &unsigned);
        for nested in [false, true] {
            let archive = attribute(
                oid::ARCHIVE_TIMESTAMP_V3.as_bytes(),
                std::slice::from_ref(&token),
            );
            let bytes = if nested {
                message(&[attribute(
                    oid::COUNTERSIGNATURE.as_bytes(),
                    &[signer(&[archive])],
                )])
            } else {
                message(&[archive])
            };
            let parser = Parser::ber(memory());
            let data = SignedData::read(&parser, &bytes, 500).unwrap();
            let parent = parser.read(&[], 0).unwrap();
            let document = Document::new(&data, &parent).unwrap();
            let prepared =
                Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
            assert_eq!(prepared.timestamps().len(), 1);
            assert_eq!(prepared.timestamp_requirements().entries().len(), 1);
            let faults: Vec<_> = prepared
                .findings()
                .iter()
                .filter(|f| {
                    f.severity == Severity::Required
                        && match f.rule {
                            Rule::Md5 | Rule::ArchiveAlgorithm => true,
                            Rule::Schema { field, .. } => {
                                field.contains("atsHashIndexV3")
                                    || field.contains("hashIndAlgorithm")
                            }
                            _ => false,
                        }
                })
                .collect();
            assert_eq!(
                !faults.is_empty(),
                !matches!(mode, 1 | 10),
                "mode={mode} nested={nested}"
            );
            if mode == 5 {
                assert!(faults.iter().any(|f| matches!(f.rule, Rule::Md5)));
            }
            if mode == 7 {
                assert!(
                    faults
                        .iter()
                        .any(|f| matches!(f.rule, Rule::ArchiveAlgorithm))
                );
            }
        }
    }
}
