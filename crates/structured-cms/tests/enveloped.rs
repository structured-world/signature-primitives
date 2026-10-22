//! Public CMS envelope schema/provenance/resource tests, without a crypto engine.
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Oid, Parser, Reader};
use structured_cms::{
    ErrorCode,
    enveloped::{AgreementIdentifier, EnvelopedData, Originator, Recipient},
};

fn memory(bytes: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(bytes, work)))
}
fn generous() -> Memory {
    memory(1 << 22, 1 << 28)
}
fn tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if data.len() < 128 {
        out.push(u8::try_from(data.len()).unwrap());
    } else {
        let bytes = data.len().to_be_bytes();
        let at = bytes.iter().position(|&b| b != 0).unwrap();
        out.push(0x80 | u8::try_from(bytes.len() - at).unwrap());
        out.extend_from_slice(&bytes[at..]);
    }
    out.extend_from_slice(data);
    out
}
fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(48, &parts.concat())
}
fn oid() -> Vec<u8> {
    tlv(6, &[42, 3])
}
fn alg() -> Vec<u8> {
    seq(&[&oid(), &[5, 0]])
}
fn transport(ski: bool) -> Vec<u8> {
    let id = if ski {
        vec![128, 1, 7]
    } else {
        seq(&[&seq(&[]), &[2, 1, 9]])
    };
    seq(&[&[2, 1, if ski { 2 } else { 0 }], &id, &alg(), &[4, 1, 8]])
}
fn kek(date: &[u8], other: &[u8]) -> Vec<u8> {
    tlv(
        162,
        &[
            &[2, 1, 4][..],
            &seq(&[&[4, 1, 6], date, other]),
            &alg(),
            &[4, 1, 8],
        ]
        .concat(),
    )
}
fn password(kdf: bool) -> Vec<u8> {
    let derivation = if kdf { tlv(160, &oid()) } else { vec![] };
    tlv(
        163,
        &[&[2, 1, 0][..], &derivation, &alg(), &[4, 1, 8]].concat(),
    )
}
fn other() -> Vec<u8> {
    tlv(164, &[&oid()[..], &[5, 0]].concat())
}
fn agreement(originator: &[u8], key_id: &[u8], ukm: &[u8]) -> Vec<u8> {
    let keys = seq(&[
        &seq(&[key_id, &[4, 1, 8]]),
        &seq(&[&seq(&[&seq(&[]), &[2, 1, 10]]), &[4, 1, 9]]),
    ]);
    tlv(
        161,
        &[&[2, 1, 3][..], &tlv(160, originator), ukm, &alg(), &keys].concat(),
    )
}
fn envelope(
    version: u8,
    recipients: &[Vec<u8>],
    originator: &[u8],
    attrs: &[u8],
    cipher: &[u8],
) -> Vec<u8> {
    let mut recipients = recipients.to_vec();
    recipients.sort();
    let data = seq(&[
        &[2, 1, version],
        originator,
        &tlv(49, &recipients.concat()),
        &seq(&[&oid(), &alg(), cipher]),
        attrs,
    ]);
    seq(&[
        &tlv(6, structured_cms::enveloped::IDENTIFIER.as_bytes()),
        &tlv(160, &data),
    ])
}
fn read<'a>(
    parser: &'a Parser,
    bytes: &'a [u8],
) -> Result<EnvelopedData<'a>, structured_cms::Error> {
    EnvelopedData::read(&mut parser.read(bytes, 500).unwrap())
}

#[test]
fn all_five_recipient_forms_and_all_sender_identifiers() {
    // Every standardized recipient and mandatory originator/recipient CHOICE is
    // decoded; none is silently replaced by the first key/engine.
    let ids = [
        seq(&[&seq(&[]), &[2, 1, 1]]),
        vec![128, 1, 7],
        tlv(161, &[&alg()[..], &[3, 2, 0, 4]].concat()),
    ];
    for (i, id) in ids.iter().enumerate() {
        for key_id in [seq(&[&seq(&[]), &[2, 1, 3]]), tlv(160, &[4, 1, 6])] {
            let bytes = envelope(
                3,
                &[
                    transport(false),
                    transport(true),
                    agreement(id, &key_id, &tlv(161, &[4, 1, 4])),
                    kek(&[], &[]),
                    password(true),
                    password(false),
                    other(),
                ],
                &[],
                &[],
                &[128, 2, 1, 2],
            );
            let parser = Parser::der(generous());
            let value = read(&parser, &bytes).unwrap();
            assert_eq!(value.recipients.len(), 7);
            let agreement = value
                .recipients
                .iter()
                .find(|r| matches!(r, Recipient::Agreement { .. }))
                .unwrap();
            let Recipient::Agreement {
                originator,
                ukm,
                keys,
                ..
            } = agreement
            else {
                unreachable!()
            };
            assert_eq!(keys.len(), 2);
            assert_eq!(ukm.as_ref().unwrap().as_one(), Some(&[4][..]));
            assert_eq!(matches!(originator, Originator::Key { .. }), i == 2);
            assert_eq!(
                matches!(keys[0].identifier, AgreementIdentifier::KeyIdentifier(_)),
                key_id[0] == 160
            );
            assert!(
                value.recipients.iter().any(
                    |r| matches!(r,Recipient::Other{kind,..} if *kind==Oid::from_bytes(&[42,3]))
                )
            );
        }
    }
}
#[test]
fn version_ladder_and_original_originator_choices() {
    // EnvelopedData's 0/2/3/4 ladder is distinct from SignedData's 1/3/4/5.
    for (recipients, originator, attrs, version) in [
        (vec![transport(false)], vec![], vec![], 0),
        (vec![transport(true)], vec![], vec![], 2),
        (vec![kek(&[], &[])], vec![], vec![], 2),
        (vec![password(false)], vec![], vec![], 3),
        (vec![other()], vec![], vec![], 3),
        (vec![transport(false)], tlv(160, &[]), vec![], 2),
        (
            vec![transport(false)],
            tlv(160, &tlv(160, &tlv(162, &[]))),
            vec![],
            3,
        ),
        (
            vec![transport(false)],
            tlv(160, &tlv(160, &tlv(163, &[&oid()[..], &[5, 0]].concat()))),
            vec![],
            4,
        ),
        (
            vec![transport(false)],
            tlv(160, &tlv(161, &tlv(161, &[&oid()[..], &[5, 0]].concat()))),
            vec![],
            4,
        ),
        (
            vec![transport(false)],
            vec![],
            tlv(161, &seq(&[&oid(), &tlv(49, &[5, 0])])),
            2,
        ),
    ] {
        let good = envelope(version, &recipients, &originator, &attrs, &[128, 0]);
        let parser = Parser::der(generous());
        let value = read(&parser, &good).unwrap();
        assert_eq!(value.version, u64::from(version));
        assert_eq!(value.originator.is_some(), !originator.is_empty());
        let bad = envelope(7, &recipients, &originator, &attrs, &[128, 0]);
        assert_eq!(
            read(&parser, &bad).unwrap_err().code(),
            ErrorCode::VersionMismatch
        );
    }
}
#[test]
fn detached_empty_and_segmented_ciphertext_remain_distinct() {
    // BER segment fanout keeps exact original pieces; detached is not replaced
    // with an attached empty value, and DER still rejects constructed OCTETs.
    for cipher in [
        vec![],
        vec![128, 0],
        tlv(
            160,
            &[&[4, 1, 1][..], &tlv(36, &[4, 1, 2]), &[4, 0]].concat(),
        ),
    ] {
        let bytes = envelope(0, &[transport(false)], &[], &[], &cipher);
        let parser = Parser::new(Encoding::Ber, Limits::default(), generous());
        let value = read(&parser, &bytes).unwrap();
        match value.content.ciphertext {
            None => assert_eq!(cipher, []),
            Some(ref value) => {
                assert_eq!(value.len(), if cipher[0] == 128 { 0 } else { 2 });
                for piece in value.pieces() {
                    let at = usize::try_from(piece.span().start - 500).unwrap();
                    assert!(std::ptr::eq(
                        piece.as_bytes(),
                        core::ptr::from_ref(&bytes[at..at + piece.as_bytes().len()])
                    ));
                }
            }
        }
        if cipher.first() == Some(&160) {
            assert!(read(&Parser::der(generous()), &bytes).is_err());
        }
    }
}
#[test]
fn key_metadata_uses_generalized_time_ber_and_optional_other_value() {
    // OtherKeyAttribute has an OPTIONAL ANY, not Attribute's mandatory SET.
    // BER GeneralizedTime may be constructed; a DER-only time projection would
    // incorrectly refuse otherwise valid recipient key-selection metadata.
    for date in [
        tlv(24, b"20261022000000Z"),
        tlv(56, &tlv(4, b"20261022000000Z")),
    ] {
        let bytes = envelope(2, &[kek(&date, &seq(&[&oid()]))], &[], &[], &[128, 0]);
        let parser = Parser::new(Encoding::Ber, Limits::default(), generous());
        let value = read(&parser, &bytes).unwrap();
        let Recipient::Kek { identifier, .. } = &value.recipients[0] else {
            unreachable!()
        };
        assert!(identifier.date().is_some());
        assert!(identifier.other().unwrap().1.is_none());
    }
}
#[test]
fn malformed_envelopes_refuse_without_successful_prefix() {
    // Empty recipients/attributes, bad recipient versions and trailing schema
    // fields are errors before a provider can observe a parsed envelope.
    let parser = Parser::der(generous());
    assert!(read(&parser, &envelope(0, &[], &[], &[], &[128, 0])).is_err());
    assert!(
        read(
            &parser,
            &envelope(2, &[transport(false)], &[], &[161, 0], &[128, 0])
        )
        .is_err()
    );
    let mut bad = password(false);
    bad[4] = 1;
    assert!(read(&parser, &envelope(3, &[bad], &[], &[], &[128, 0])).is_err());
    let mut bytes = envelope(0, &[transport(false)], &[], &[], &[128, 0]);
    bytes.extend([5, 0]);
    assert_eq!(
        read(&parser, &bytes).unwrap_err().code(),
        ErrorCode::TrailingData
    );
}
#[test]
fn resource_refusal_rolls_back_and_retained_metadata_owns_capacity() {
    // Exact/zero source work and live storage remain enforced; dropping a
    // producing cursor never refunds retained recipient/catalogue allocation.
    let bytes = envelope(3, &[password(false), other()], &[], &[], &[128, 0]);
    let account = generous();
    let parser = Parser::der(account.clone());
    let value = read(&parser, &bytes).unwrap();
    let used = account.used();
    assert!(used > 0);
    assert_eq!(account.used(), used);
    drop(value);
    assert_eq!(account.used(), 0);
    let p = Parser::der(memory(0, 1 << 28));
    assert!(read(&p, &bytes).unwrap_err().is_resource());
    let p = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1,
            ..Limits::default()
        },
        generous(),
    );
    let mut r = p.read(&bytes, 500).unwrap();
    assert!(EnvelopedData::read(&mut r).unwrap_err().is_resource());
    let query_parser = Parser::der(generous());
    let query: Reader<'_> = query_parser.read(&[], 0).unwrap();
    let value = read(&parser, &bytes).unwrap();
    let mut cursor = value.reader_in(&query).unwrap();
    assert_eq!(
        cursor.next_element().unwrap().unwrap().span(),
        value.element().span()
    );
}

#[test]
fn retained_originator_queries_preserve_depth_location_and_current_work() {
    // Opening an untrusted retained choice is a new query, not prepaid parsing.
    // The exact original set-member level and encoded context tag survive.
    let origin = tlv(
        160,
        &[
            &tlv(160, &tlv(162, &[]))[..],
            &tlv(161, &tlv(161, &[&oid()[..], &[5, 0]].concat())),
        ]
        .concat(),
    );
    let bytes = envelope(4, &[transport(false)], &origin, &[], &[128, 0]);
    let parser = Parser::der(generous());
    let value = read(&parser, &bytes).unwrap();
    let original = value.originator.as_ref().unwrap();
    assert_eq!(original.choices().len(), 1);
    assert!(original.certificates().is_empty());
    assert_eq!(original.revocations().len(), 1);
    let qp = Parser::der(generous());
    let query = qp.read(&[], 0).unwrap();
    let mut certificate = original.certificate_reader_in(&query, 0).unwrap().unwrap();
    let mut crl = original.revocation_reader_in(&query, 0).unwrap().unwrap();
    let member_depth = value.reader_in(&query).unwrap().depth() + 3;
    assert_eq!(certificate.depth(), member_depth);
    assert_eq!(crl.depth(), member_depth);
    assert_eq!(
        certificate.next_element().unwrap().unwrap().tag(),
        structured_asn1::Tag::context(true, 2)
    );
    assert_eq!(
        crl.next_element().unwrap().unwrap().span(),
        original.revocations()[0].span()
    );
    assert!(original.certificate_reader_in(&query, 1).unwrap().is_none());
    let limited = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        generous(),
    );
    let query = limited.read(&[], 0).unwrap();
    assert!(
        original
            .certificate_reader_in(&query, usize::MAX)
            .unwrap_err()
            .is_resource()
    );
    assert!(
        original
            .revocation_reader_in(&query, usize::MAX)
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn ber_recipient_identifiers_keys_and_originator_bits_use_shared_segment_grammars() {
    // All known string fields follow BER, including BIT STRING's final-padding
    // rule. Neither a primitive-only SPKI reader nor an OCTET walker is used
    // as a replacement grammar for the sender's encoded public-key bits.
    let key_bits = tlv(35, &[3, 2, 0, 0x11, 3, 2, 3, 0xa0]);
    let sender = tlv(161, &[&alg()[..], &key_bits].concat());
    let ski = tlv(160, &[4, 1, 7, 4, 1, 8]);
    let transport = seq(&[&[2, 1, 2], &ski, &alg(), &tlv(36, &[4, 1, 9])]);
    let bytes = envelope(
        2,
        &[transport, agreement(&sender, &tlv(160, &[4, 1, 1]), &[])],
        &[],
        &[],
        &[128, 0],
    );
    let parser = Parser::ber(generous());
    let value = read(&parser, &bytes).unwrap();
    let key = value
        .recipients
        .iter()
        .find_map(|value| {
            if let Recipient::Agreement {
                originator: Originator::Key { bits, .. },
                ..
            } = value
            {
                Some(bits)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(key.element().tag(), structured_asn1::Tag::constructed(3));
    assert!(read(&Parser::der(generous()), &bytes).is_err());
    let bad_sender = tlv(
        161,
        &[&alg()[..], &tlv(35, &[3, 2, 3, 0xa0, 3, 1, 0])].concat(),
    );
    assert!(
        read(
            &parser,
            &envelope(
                2,
                &[agreement(&bad_sender, &seq(&[&seq(&[]), &[2, 1, 5]]), &[])],
                &[],
                &[],
                &[128, 0]
            )
        )
        .is_err()
    );
}

#[test]
fn open_recipient_fields_keep_their_actual_reader_context() {
    // Open formats and optional metadata must not force an extension provider
    // to reconstruct RecipientInfo or reopen at a falsely shallow depth.
    let date = tlv(56, &tlv(4, b"20261022000000Z"));
    let extra = seq(&[&oid(), &seq(&[&[5, 0]])]);
    let sender = tlv(161, &[&alg()[..], &[3, 2, 0, 0xa0]].concat());
    let bytes = envelope(
        3,
        &[
            kek(&date, &extra),
            other(),
            agreement(&sender, &seq(&[&seq(&[]), &[2, 1, 5]]), &[]),
        ],
        &[],
        &[],
        &[128, 0],
    );
    let parser = Parser::ber(generous());
    let value = read(&parser, &bytes).unwrap();
    let operation = Parser::der(generous());
    let query = operation.read(&[], 0).unwrap();
    let root = value.reader_in(&query).unwrap().depth();
    let mut count = 0;
    for recipient in &value.recipients {
        let fields = match recipient {
            Recipient::Kek { identifier, .. } => vec![
                (identifier.date().unwrap(), root + 4),
                (identifier.other().unwrap().1.unwrap(), root + 5),
            ],
            Recipient::Other { value, .. } => vec![(*value, root + 3)],
            Recipient::Agreement {
                originator: Originator::Key { bits, .. },
                ..
            } => vec![(*bits, root + 5)],
            _ => unreachable!(),
        };
        for (field, depth) in fields {
            let mut reader = field.reader_in(&query).unwrap();
            assert_eq!(reader.depth(), depth);
            assert_eq!(reader.encoding(), Encoding::Ber);
            let original = reader.next_element().unwrap().unwrap();
            assert_eq!(original.span(), field.element().span());
            assert!(core::ptr::eq(
                original.as_bytes(),
                field.element().as_bytes()
            ));
            let narrow = Parser::new(
                Encoding::Der,
                Limits {
                    max_depth: depth - 1,
                    ..Limits::default()
                },
                generous(),
            );
            assert!(field.reader_in(&narrow.read(&[], 0).unwrap()).is_err());
            let empty = Parser::der(memory(1 << 20, 0));
            assert!(
                field
                    .reader_in(&empty.read(&[], 0).unwrap())
                    .unwrap_err()
                    .is_resource()
            );
            count += 1;
        }
    }
    assert_eq!(count, 4);
}
