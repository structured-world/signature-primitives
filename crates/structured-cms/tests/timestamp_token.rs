//! Timestamp envelope uniqueness and scoped attached-content decoding.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Parser, Span};
use structured_cms::content_source::{ContentError, Coordinates};
use structured_cms::timestamp::{InfoError, Token};
use structured_cms::{ErrorCode, oid};

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if value.len() < 128 {
        output.push(u8::try_from(value.len()).unwrap());
    } else {
        output.extend([0x81, u8::try_from(value.len()).unwrap()]);
    }
    output.extend_from_slice(value);
    output
}
fn info() -> Vec<u8> {
    let mut fields = vec![
        2, 1, 1, 6, 1, 43, 0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, b'a', b'b', 2, 1, 7,
    ];
    fields.extend(tlv(0x18, b"20260101000000Z"));
    tlv(0x30, &fields)
}
fn signer(signature: u8, indefinite: bool) -> Vec<u8> {
    let fields = [
        2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, signature,
    ];
    if indefinite {
        let mut bytes = vec![0x30, 0x80];
        bytes.extend(fields);
        bytes.extend([0, 0]);
        bytes
    } else {
        tlv(0x30, &fields)
    }
}
fn message(kind: &[u8], payload: Option<&[u8]>, signers: &[u8], segmented: bool) -> Vec<u8> {
    let mut content = tlv(6, kind);
    if let Some(payload) = payload {
        let bytes = if segmented {
            let mut pieces = tlv(4, &payload[..7]);
            pieces.extend(tlv(4, &payload[7..]));
            tlv(0x24, &pieces)
        } else {
            tlv(4, payload)
        };
        content.extend(tlv(0xa0, &bytes));
    }
    let mut fields = vec![2, 1, 3, 0x31, 0];
    fields.extend(tlv(0x30, &content));
    fields.extend(tlv(0x31, signers));
    let mut envelope = tlv(6, oid::SIGNED_DATA.as_bytes());
    envelope.extend(tlv(0xa0, &tlv(0x30, &fields)));
    tlv(0x30, &envelope)
}
fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)))
}

#[test]
fn carried_info_tail_keeps_readable_facts_and_original_source_projection() {
    // A bounded readable first TSTInfo is inspection data, with an adverse fault;
    // trailing garbage must not suppress its callback or lose physical location.
    for segmented in [false, true] {
        let account = memory();
        let mut payload = info();
        payload.extend([0xff, 0xfe, 0xfd]);
        let bytes = message(
            oid::TST_INFO.as_bytes(),
            Some(&payload),
            &signer(8, false),
            segmented,
        );
        let expected = 400
            + u64::try_from(
                bytes
                    .windows(3)
                    .position(|bytes| bytes == [0xff, 0xfe, 0xfd])
                    .unwrap(),
            )
            .unwrap();
        let (offset, source) = {
            let parser = Parser::ber(account.clone());
            let token = Token::read(&parser, &bytes, 400).unwrap();
            let parent = parser.read(&[], 400).unwrap();
            token
                .with_info(&parent, |info, parent, map| {
                    assert_eq!(info.serial().value().as_u64(), Some(7));
                    assert_eq!(info.imprint().hashed().as_one(), Some(&b"ab"[..]));
                    assert_eq!(info.faults().len(), 1);
                    let fault = &info.faults()[0];
                    assert_eq!(fault.code(), ErrorCode::TrailingData);
                    assert_eq!(fault.field(), "tstInfo");
                    assert_eq!(fault.offset(), info.span().end());
                    Ok::<_, structured_cms::Error>((
                        fault.offset(),
                        map.try_copy_in(&parent.execution())?,
                    ))
                })
                .unwrap()
        };
        assert_eq!(source.project_offset(offset, &account).unwrap(), expected);
        assert_eq!(
            source.coordinates(),
            if segmented {
                Coordinates::Logical
            } else {
                Coordinates::Original
            }
        );
        drop(source);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn carried_tail_diagnostic_respects_local_and_aggregate_work_before_callback() {
    // Profile only the existing complete schema read, excluding tail retention.
    // The public path must refuse when no work remains for its additional fault.
    use structured_asn1::{Encoding, Limits, Tag, universal};
    use structured_cms::timestamp::TokenInfo;
    let mut payload = info();
    payload.extend([0xff, 0xfe, 0xfd]);
    let bytes = message(
        oid::TST_INFO.as_bytes(),
        Some(&payload),
        &signer(8, false),
        false,
    );
    let account = memory();
    let parser = Parser::ber(account.clone());
    let token = Token::read(&parser, &bytes, 400).unwrap();
    let query = parser.read(&[], 400).unwrap();
    let tail = token
        .message()
        .content()
        .content()
        .unwrap()
        .with_nested_reader(&query, Encoding::Ber, "tstInfo", |reader, _| {
            let element = reader
                .expect(Tag::constructed(universal::SEQUENCE))
                .unwrap();
            let info = TokenInfo::read(reader, &element)?;
            assert_eq!(info.faults().len(), 0);
            Ok::<_, structured_cms::Error>(reader.offset())
        })
        .unwrap();
    let prefix = account.work_used();
    for local in [false, true] {
        let account = Memory::new(Arc::new(MemoryAccount::new(
            1 << 20,
            if local { 1 << 24 } else { prefix },
        )));
        let limits = Limits {
            max_work: if local {
                u64::try_from(prefix).unwrap()
            } else {
                1 << 24
            },
            ..Limits::default()
        };
        let parser = Parser::new(Encoding::Ber, limits, account.clone());
        let token = Token::read(&parser, &bytes, 400).unwrap();
        let held = account.used();
        let parent = parser.read(&[], 400).unwrap();
        let called = core::cell::Cell::new(false);
        let error = token
            .with_info(&parent, |_, _, _| {
                called.set(true);
                Ok::<_, ()>(())
            })
            .unwrap_err();
        assert!(!called.get());
        let ContentError::Callback {
            source: InfoError::Processing(error),
            context,
        } = error
        else {
            panic!("lost original tail-retention refusal");
        };
        assert!(error.is_terminal());
        assert_eq!(error.field(), "tstInfo");
        assert_eq!(error.offset(), tail);
        drop(context);
        assert_eq!(account.used(), held);
        drop(token);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn equivalent_issuer_signers_preserve_original_token_reading_and_fault() {
    // The public token path shares semantic issuer identity with the comparer;
    // accepting a readable duplicate does not remove its ExtraSignature fault.
    let make = |text: &[u8], tag| {
        let mut attribute = vec![6, 3, 0x55, 4, 3];
        attribute.extend(tlv(tag, text));
        let mut sid = tlv(0x30, &tlv(0x31, &tlv(0x30, &attribute)));
        sid.extend([2, 1, 7]);
        let mut body = vec![2, 1, 1];
        body.extend(tlv(0x30, &sid));
        body.extend([0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, 8]);
        tlv(0x30, &body)
    };
    let first = make(b"Example CA", 0x0c);
    let mut signers = first.clone();
    signers.extend(make(b"  EXAMPLE   ca  ", 0x13));
    let bytes = message(oid::TST_INFO.as_bytes(), Some(&info()), &signers, false);
    let account = memory();
    let parser = Parser::ber(account.clone());
    let token = Token::read(&parser, &bytes, 400).unwrap();
    assert_eq!(token.signer().as_bytes(), first);
    assert_eq!(token.faults().len(), 1);
    assert_eq!(token.faults()[0].code(), ErrorCode::ExtraSignature);
    drop(token);
    assert_eq!(account.used(), 0);
}

#[test]
fn duplicate_sha2_signers_retain_first_encoding_and_extra_signature_fault() {
    // RFC5754 §2 default equivalence must also reach the public TSP envelope
    // recovery path; a readable duplicate still carries its adverse fault.
    for kind in [4, 1, 2, 3] {
        let make = |parameter: &[u8]| {
            let mut fields = vec![2, 1, 3, 0x80, 1, 7];
            let mut algorithm = vec![6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, kind];
            algorithm.extend_from_slice(parameter);
            fields.extend(tlv(0x30, &algorithm));
            fields.extend([0x30, 3, 6, 1, 43, 4, 1, 8]);
            tlv(0x30, &fields)
        };
        let first = make(&[]);
        for parameter in [&[5, 0][..], &[5, 0x81, 0][..]] {
            let mut signers = first.clone();
            signers.extend(make(parameter));
            let bytes = message(oid::TST_INFO.as_bytes(), Some(&info()), &signers, false);
            let parser = Parser::ber(memory());
            let token = Token::read(&parser, &bytes, 400).unwrap();
            assert_eq!(token.signer().as_bytes(), first);
            assert_eq!(token.signer().digest_algorithm().parameters(), None);
            assert_eq!(token.faults().len(), 1);
            assert_eq!(token.faults()[0].code(), ErrorCode::ExtraSignature);
        }
    }
}

#[test]
fn nested_timestamp_errors_keep_physical_provenance_after_both_joins_drop() {
    // A carried CMS token can itself contain segmented TSTInfo. Composing
    // maps must retain original physical positions rather than the outer join's
    // logical positions, without keeping either temporary byte buffer alive.
    use structured_asn1::Encoding;
    use structured_cms::{ContentInfo, Octets, SignedData};
    let memory = memory();
    let cms = message(
        oid::TST_INFO.as_bytes(),
        Some(&info()),
        &signer(8, false),
        true,
    );
    let mut pieces = tlv(4, &cms[..30]);
    pieces.extend(tlv(4, &cms[30..]));
    let document = tlv(0x24, &pieces);
    let result = {
        let parser = Parser::ber(memory.clone());
        let mut root = parser.read(&document, 400).unwrap();
        let element = root.next_element().unwrap().unwrap();
        let octets = Octets::read(&root, &element, "outer").unwrap();
        octets
            .with_nested_reader(&root, Encoding::Ber, "outer", |reader, map| {
                let (envelope, parent) = ContentInfo::read(reader).unwrap();
                let message = SignedData::read_element(&parent, envelope.content()).unwrap();
                let token = Token::from_message(message, &parent).unwrap();
                Ok::<_, ()>(token.with_info_mapped(&parent, map, |info, _, source| {
                    assert_eq!(source.coordinates(), Coordinates::Logical);
                    Err::<(), _>(info.span().start)
                }))
            })
            .unwrap()
    };
    let ContentError::Callback {
        source: InfoError::Callback(at),
        context,
    } = result.unwrap_err()
    else {
        panic!("callback cause must retain its source map");
    };
    let physical = context.project_offset(at, &memory).unwrap();
    assert!(physical > 430);
    assert_eq!(document[usize::try_from(physical - 400).unwrap()], 0x30);
    assert!(memory.used() > 0);
    drop(context);
    assert_eq!(memory.used(), 0);
}

#[test]
fn retained_facts_and_source_map_survive_segmented_info_scope() {
    // Logical fact ranges require their independent physical map. Keeping both
    // must not retain temporary joins/parser, lose fragment boundaries or let
    // source capacity go uncharged before the final owners are dropped.
    let memory = memory();
    let (facts, context) = {
        let parser = Parser::ber(memory.clone());
        let bytes = message(
            oid::TST_INFO.as_bytes(),
            Some(&info()),
            &signer(8, false),
            true,
        );
        let token = Token::read(&parser, &bytes, 400).unwrap();
        let query = parser.read(&[], 400).unwrap();
        token
            .with_info(&query, |info, parent, source| {
                let facts = info.retain_facts(parent)?;
                let context = source.try_copy_in(&parent.execution())?;
                Ok::<_, structured_cms::Error>((facts, context))
            })
            .unwrap()
    };
    assert_eq!(context.coordinates(), Coordinates::Logical);
    assert_eq!(facts.source_span().start, 0);
    assert_eq!(facts.serial(), &[7]);
    assert_eq!(facts.imprint().hashed(), b"ab");
    assert!(
        context
            .project_offset(facts.source_span().start, &memory)
            .unwrap()
            > 400
    );
    let ranges = context.project_span(facts.source_span(), &memory).unwrap();
    assert_eq!(ranges.len(), 2);
    assert!(ranges[0].end() < ranges[1].start);
    drop(ranges);
    assert!(memory.used() > 0);
    drop(facts);
    assert!(memory.used() > 0);
    drop(context);
    assert_eq!(memory.used(), 0);
}

#[test]
fn attached_timestamp_reads_whole_info_without_escaping_joined_models() {
    // Both BER payload forms use the original parser budget and yield the same
    // facts without asserting signature correctness or trust.
    for segmented in [false, true] {
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let bytes = message(
            oid::TST_INFO.as_bytes(),
            Some(&info()),
            &signer(8, false),
            segmented,
        );
        let token = Token::read(&parser, &bytes, 400).unwrap();
        let query = parser.read(&[], 400).unwrap();
        let seconds = token
            .with_info(&query, |info, _, map| {
                assert!(!info.has_faults());
                assert_eq!(
                    map.coordinates(),
                    if segmented {
                        Coordinates::Logical
                    } else {
                        Coordinates::Original
                    }
                );
                Ok::<_, ()>(info.gen_time().start().seconds())
            })
            .unwrap();
        assert_eq!(seconds, 1_767_225_600);
        assert!(token.faults().is_empty());
        assert_eq!(token.signer().signature().as_one(), Some(&[8][..]));
        drop(token);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn equal_ber_signers_keep_first_encoding_and_fault_but_conflicts_refuse() {
    // Outer BER length/indefinite spelling is not signer-value identity; an
    // actual signature difference remains ambiguous and cannot select one TSA.
    let parser = Parser::ber(memory());
    let mut signers = signer(8, false);
    signers.extend(signer(8, true));
    let bytes = message(oid::TST_INFO.as_bytes(), Some(&info()), &signers, false);
    let token = Token::read(&parser, &bytes, 400).unwrap();
    assert_eq!(token.faults().len(), 1);
    assert_eq!(token.faults()[0].code(), ErrorCode::ExtraSignature);
    assert_eq!(token.signer().as_bytes(), signer(8, false));
    let mut conflicting = signer(8, false);
    conflicting.extend(signer(9, true));
    let bytes = message(oid::TST_INFO.as_bytes(), Some(&info()), &conflicting, false);
    assert_eq!(
        Token::read(&parser, &bytes, 400).unwrap_err().code(),
        ErrorCode::SignerCount
    );
}

#[test]
fn detached_wrong_type_and_missing_signer_cannot_be_timestamp_envelopes() {
    // These RFC3161 envelope constraints are not left to a crypto callback.
    let parser = Parser::ber(memory());
    for (kind, payload, signers, expected) in [
        (
            oid::TST_INFO.as_bytes(),
            None,
            signer(8, false),
            ErrorCode::DetachedContent,
        ),
        (
            oid::DATA.as_bytes(),
            Some(info()),
            signer(8, false),
            ErrorCode::UnexpectedContentType,
        ),
        (
            oid::TST_INFO.as_bytes(),
            Some(info()),
            vec![],
            ErrorCode::SignerCount,
        ),
    ] {
        let bytes = message(kind, payload.as_deref(), &signers, false);
        assert_eq!(
            Token::read(&parser, &bytes, 400).unwrap_err().code(),
            expected
        );
    }
}

#[test]
fn malformed_info_error_keeps_logical_source_mapping_after_token_drop() {
    // Logical TSTInfo parse errors cannot leave the join as physical offsets.
    // The attached map retains the original error's exact physical projection.
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let payload = [0x30, 8, 2, 1, 1, 6, 1, 43, 2, 0];
    let bytes = message(
        oid::TST_INFO.as_bytes(),
        Some(&payload),
        &signer(8, false),
        true,
    );
    let token = Token::read(&parser, &bytes, 400).unwrap();
    let query = parser.read(&[], 400).unwrap();
    let original = token.message().content().content().unwrap().pieces()[0].span();
    let error = token
        .with_info(&query, |_, _, _| Ok::<_, ()>(()))
        .unwrap_err();
    drop(token);
    drop(query);
    drop(parser);
    let ContentError::Callback {
        source: InfoError::Processing(error),
        context,
    } = error
    else {
        panic!("located cause/map lost")
    };
    assert_eq!(context.coordinates(), Coordinates::Logical);
    let physical = context
        .project_span(
            Span {
                start: 0,
                length: 2,
            },
            &memory,
        )
        .unwrap();
    assert_eq!(
        &*physical,
        &[Span {
            start: original.start,
            length: 2
        }]
    );
    assert!(context.project_offset(error.offset(), &memory).unwrap() >= original.start);
    drop(error);
    drop(physical);
    drop(context);
    assert_eq!(memory.used(), 0);
}

#[test]
fn misplaced_and_unreadable_counter_values_still_mark_extra_signature() {
    // Timestamp detection is not the count of successfully decoded legal
    // unsigned children: signed placement and empty/unreadable values count.
    let parser = Parser::ber(memory());
    for tag in [0xa0, 0xa1] {
        for values in [&[][..], &[5, 0][..]] {
            let mut attr = tlv(6, oid::COUNTERSIGNATURE.as_bytes());
            attr.extend(tlv(0x31, values));
            let attrs = tlv(tag, &tlv(0x30, &attr));
            let original = signer(8, false);
            let mut fields = Vec::new();
            if tag == 0xa0 {
                fields.extend_from_slice(&original[2..13]);
                fields.extend(attrs);
                fields.extend_from_slice(&original[13..]);
            } else {
                fields.extend_from_slice(&original[2..]);
                fields.extend(attrs);
            }
            let bytes = message(
                oid::TST_INFO.as_bytes(),
                Some(&info()),
                &tlv(0x30, &fields),
                false,
            );
            let token = Token::read(&parser, &bytes, 400).unwrap();
            assert_eq!(token.faults().len(), 1);
            assert_eq!(token.faults()[0].code(), ErrorCode::ExtraSignature);
            assert_eq!(
                token.faults()[0].field(),
                if tag == 0xa0 {
                    "signerInfo.signedAttrs.countersignature"
                } else {
                    "signerInfo.unsignedAttrs.countersignature"
                }
            );
        }
    }
}
