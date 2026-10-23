//! Public ERS schema tests: original sources, flat ownership and refusal.

use std::sync::Arc;
use structured_asn1::{
    Parser, Tag,
    memory::{Memory, MemoryAccount},
    universal,
};
use structured_cms::{
    ErrorCode,
    evidence::{EvidenceRecord, TimeStamp},
};

#[path = "evidence/identities.rs"]
mod identities;
#[path = "evidence/tree.rs"]
mod tree;

fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(structured_asn1::length::DerLength::new(bytes.len() as u64).as_bytes());
    out.extend_from_slice(bytes);
    out
}
fn algorithm(tag: u8) -> Vec<u8> {
    tlv(tag, &tlv(6, &[96, 134, 72, 1, 101, 3, 4, 2, 1]))
}
fn token() -> Vec<u8> {
    tlv(0x30, &[tlv(6, &[42, 3]), tlv(0xa0, &tlv(5, &[]))].concat())
}
fn stamp(tree: Option<&[u8]>) -> Vec<u8> {
    let mut fields = algorithm(0xa0);
    if let Some(tree) = tree {
        fields.extend_from_slice(&tlv(0xa2, tree));
    }
    fields.extend_from_slice(&token());
    tlv(0x30, &fields)
}
fn record(version: u8, algorithms: &[u8], chains: &[u8]) -> Vec<u8> {
    tlv(
        0x30,
        &[tlv(2, &[version]), tlv(0x30, algorithms), tlv(0x30, chains)].concat(),
    )
}
fn memory(capacity: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, 10_000_000)))
}

#[test]
fn original_record_and_flat_chains_preserve_open_timestamp_and_depth() {
    // Unknown timestamp types remain present, not a missing/successful TSA.
    let encoded = record(
        1,
        &algorithm(0x30),
        &tlv(0x30, &[stamp(None), stamp(None)].concat()),
    );
    let parser = Parser::ber(memory(1_000_000));
    let mut parent = parser.read(&encoded, 700).unwrap();
    let element = parent
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    assert_eq!(parsed.original().element().as_bytes(), encoded);
    assert_eq!(parsed.chains()[0].timestamps(), 0..2);
    assert_eq!(parsed.timestamps().len(), 2);
    assert!(matches!(
        parsed.timestamps()[0].timestamp(),
        TimeStamp::Other(_)
    ));
    assert!(parsed.timestamps()[0].reduced_tree().is_none());
    let mut reopened = parsed.original().reader_in(&parent).unwrap();
    assert_eq!(reopened.depth(), parent.depth());
    assert_eq!(reopened.offset(), 700);
    assert_eq!(
        reopened.next_element().unwrap().unwrap().as_bytes(),
        encoded
    );
    let field = parsed.timestamps()[0].timestamp_source();
    let nested = field.reader_in(&parent).unwrap();
    assert_eq!(nested.depth(), 4);
    assert_eq!(nested.offset(), field.element().span().start);
}

#[test]
fn segmented_hash_values_keep_original_logical_content_and_release_capacity() {
    // BER fragmentation belongs to OCTET STRING, not a copied canonical hash.
    let hash = tlv(0x24, &[tlv(4, &[1, 2]), tlv(4, &[3])].concat());
    let tree = tlv(0x30, &hash);
    let encoded = record(1, &algorithm(0x30), &tlv(0x30, &stamp(Some(&tree))));
    let mem = memory(1_000_000);
    let parser = Parser::ber(mem.clone());
    let mut parent = parser.read(&encoded, 100).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let hashes = parsed.timestamps()[0].reduced_tree().unwrap()[0].hashes();
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0]
            .pieces()
            .iter()
            .flat_map(|p| p.as_bytes())
            .copied()
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(hashes[0].as_one().is_none());
    drop(parsed);
    // A new allocation can reuse the full quota only after retained catalogues drop.
    assert!(EvidenceRecord::read(&parent, &element).is_ok());
}

#[test]
fn empty_protocol_components_and_wrong_version_refuse_with_original_location() {
    // Empty mandatory record/chain catalogues cannot hide a missing timestamp.
    for (version, algorithms, chains, expected) in [
        (
            0,
            algorithm(0x30),
            tlv(0x30, &stamp(None)),
            ErrorCode::UnsupportedVersion,
        ),
        (1, vec![], tlv(0x30, &stamp(None)), ErrorCode::MissingField),
        (1, algorithm(0x30), vec![], ErrorCode::MissingField),
        (1, algorithm(0x30), tlv(0x30, &[]), ErrorCode::MissingField),
    ] {
        let encoded = record(version, &algorithms, &chains);
        let parser = Parser::ber(memory(1_000_000));
        let mut parent = parser.read(&encoded, 900).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let error = EvidenceRecord::read(&parent, &element).unwrap_err();
        assert_eq!(error.code(), expected);
        assert!(error.offset() >= 900);
    }
}

#[test]
fn empty_hash_lists_remain_inspectable_without_claiming_membership() {
    // RFC4998 §4.2 explicitly imposes no restriction on hash-list lengths.
    // Reading the original syntax is separate from proving first-list membership.
    for tree in [vec![], tlv(0x30, &[])] {
        let encoded = record(1, &algorithm(0x30), &tlv(0x30, &stamp(Some(&tree))));
        let parser = Parser::ber(memory(1_000_000));
        let mut parent = parser.read(&encoded, 900).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let parsed = EvidenceRecord::read(&parent, &element).unwrap();
        let levels = parsed.timestamps()[0].reduced_tree().unwrap();
        assert_eq!(levels.len(), usize::from(!tree.is_empty()));
        if let Some(first) = levels.first() {
            assert!(first.hashes().is_empty());
        }
    }
}

#[test]
fn catalogue_allocation_refusal_is_terminal_not_an_empty_record() {
    // Valid DER syntax with no storage allowance refuses before catalogue growth.
    let encoded = record(1, &algorithm(0x30), &tlv(0x30, &stamp(None)));
    let parser = Parser::ber(memory(0));
    let mut parent = parser.read(&encoded, 800).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let error = EvidenceRecord::read(&parent, &element).unwrap_err();
    assert!(error.is_terminal());
    assert!(error.offset() >= 800);
}

#[test]
fn crypto_infos_are_a_sequence_not_a_sorted_set() {
    // RFC4998 §3.1 defines CryptoInfos as SEQUENCE OF Attribute. DER must
    // preserve this order even though archive timestamp Attributes is a SET.
    let attribute = |last| {
        tlv(
            0x30,
            &[tlv(6, &[42, last]), tlv(0x31, &tlv(5, &[]))].concat(),
        )
    };
    let encoded = tlv(
        0x30,
        &[
            tlv(2, &[1]),
            tlv(0x30, &algorithm(0x30)),
            tlv(0xa0, &[attribute(5), attribute(3)].concat()),
            tlv(0x30, &tlv(0x30, &stamp(None))),
        ]
        .concat(),
    );
    let parser = Parser::der(memory(1_000_000));
    let mut parent = parser.read(&encoded, 600).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let infos = parsed.crypto_infos().unwrap();
    assert_eq!(infos.len(), 2);
    assert_eq!(infos[0].kind().as_bytes(), [42, 5]);
    assert_eq!(infos[1].kind().as_bytes(), [42, 3]);
}
