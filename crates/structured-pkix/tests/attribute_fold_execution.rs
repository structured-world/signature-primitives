//! Scoped attribute preparation must fund all deferred work in the query.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag, u8::try_from(contents.len()).unwrap()];
    bytes.extend_from_slice(contents);
    bytes
}

fn named(kind: &[u8], value: &[u8]) -> Vec<u8> {
    let mut attribute = tlv(6, kind);
    attribute.extend_from_slice(value);
    tlv(0x30, &tlv(0x31, &tlv(0x30, &attribute)))
}

#[test]
fn unicode_attribute_preparation_cannot_ignore_current_local_work() {
    // The retained Memory-only API has no query ceiling. The new entry must
    // refuse before a Unicode scan even while the account has abundant slack.
    let bytes = [
        0x30, 13, 0x31, 11, 0x30, 9, 6, 3, 0x55, 4, 3, 12, 2, 0xc3, 0x9f,
    ];
    let parser = Parser::der(memory(65536, 65536));
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let name = structured_pkix::name::read(&parent, &element, "subject").unwrap();
    let attribute = name.parts()[0].attributes()[0];
    let current = memory(65536, 65536);
    let query_parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = query_parser.read(&[], 900).unwrap();
    let error = attribute.folds_in(&query).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 411);
    assert_eq!(current.work_used(), 0);
    assert_eq!(current.used(), 0);
}

#[test]
fn scoped_attribute_folding_uses_the_retained_semantic_core() {
    // Scoped funding must not change supported/opaque/prohibited preparation.
    // Original Name storage remains on its own account; all query scratch dies.
    for (kind, text, expected) in [
        (&[0x55, 4, 3][..], "Example", true),
        (&[0x55, 4, 3][..], "Straße", true),
        (&[0x55, 4, 3][..], "\u{e000}", false),
        (&[42][..], "opaque", false),
    ] {
        let bytes = named(kind, &tlv(12, text.as_bytes()));
        let origin = memory(65536, 65536);
        let parser = Parser::der(origin.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let name = structured_pkix::name::read(&parent, &element, "subject").unwrap();
        let attribute = name.parts()[0].attributes()[0];
        let before = (origin.used(), origin.work_used());
        let retained_query = memory(65536, 65536);
        assert_eq!(attribute.folds(&retained_query).unwrap(), expected);
        let current = memory(65536, 65536);
        let query = parent.try_clone().unwrap().with_execution(&current);
        assert_eq!(attribute.folds_in(&query).unwrap(), expected);
        assert_eq!(current.work_used(), retained_query.work_used());
        assert_eq!(current.used(), 0);
        assert_eq!((origin.used(), origin.work_used()), before);
        assert_eq!(name.as_bytes(), bytes);
    }
}

#[test]
fn scoped_folding_enforces_exact_work_and_rolls_back_unicode_scratch() {
    // Primitive preparation has identical work under retained/scoped ownership.
    // Exact succeeds; local/global one-less and zero scratch capacity refuse.
    let bytes = named(&[0x55, 4, 3], &tlv(12, "Straße".as_bytes()));
    let origin = memory(65536, 65536);
    let parser = Parser::der(origin.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let name = structured_pkix::name::read(&parent, &element, "subject").unwrap();
    let attribute = name.parts()[0].attributes()[0];
    let measured = memory(65536, 65536);
    assert!(attribute.folds(&measured).unwrap());
    let cost = measured.work_used();
    assert!(cost > 1);
    let before = (origin.used(), origin.work_used());
    let mut lower = 0;
    let mut upper = 65536;
    while lower < upper {
        let capacity = lower + (upper - lower) / 2;
        let current = memory(capacity, 65536);
        let query = parent.try_clone().unwrap().with_execution(&current);
        match attribute.folds_in(&query) {
            Ok(folds) => {
                assert!(folds);
                upper = capacity;
            }
            Err(error) => {
                assert!(error.is_resource());
                lower = capacity + 1;
            }
        }
        assert_eq!(current.used(), 0);
    }
    let peak = lower;
    assert!(peak > 0);
    for (capacity, local, aggregate, succeeds) in [
        (peak, cost, cost, true),
        (peak, cost - 1, cost, false),
        (peak, cost, cost - 1, false),
        (peak - 1, cost, cost, false),
        (0, cost, cost, false),
    ] {
        let current = memory(capacity, aggregate);
        let query_parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: u64::try_from(local).unwrap(),
                ..Limits::default()
            },
            current.clone(),
        );
        let query = query_parser.read(&[], 900).unwrap();
        let answer = attribute.folds_in(&query);
        if succeeds {
            assert!(answer.unwrap());
        } else {
            let error = answer.unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.offset(), 411);
            assert_eq!(error.field(), "name.attribute");
        }
        assert_eq!(current.used(), 0);
        assert_eq!((origin.used(), origin.work_used()), before);
    }
}

#[test]
fn constructed_attribute_preparation_preserves_depth_and_element_limits() {
    // Deferred BER preparation uses the retained attribute's original depth.
    // A fresh query cannot flatten it under depth zero or reset element limits.
    let bytes = named(&[0x55, 4, 3], &tlv(0x2c, &[4, 1, b'a']));
    let origin = memory(65536, 65536);
    let parser = Parser::ber(origin.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let name = structured_pkix::name::read(&parent, &element, "subject").unwrap();
    let attribute = name.parts()[0].attributes()[0];
    assert!(attribute.folds_in(&parent).unwrap());
    let before = (origin.used(), origin.work_used());
    for limits in [
        Limits {
            max_depth: 2,
            ..Limits::default()
        },
        Limits {
            max_elements: 0,
            ..Limits::default()
        },
    ] {
        let current = memory(65536, 65536);
        let query_parser = Parser::new(Encoding::Ber, limits, current.clone());
        let query = query_parser.read(&[], 900).unwrap();
        let error = attribute.folds_in(&query).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), 411);
        assert_eq!(current.used(), 0);
        assert_eq!((origin.used(), origin.work_used()), before);
    }
}
