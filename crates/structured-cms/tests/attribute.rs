//! Original signed bytes and specific rather than blanket attribute constraints.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::ErrorCode;
use structured_cms::attribute::{Attributes, Placement};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

#[test]
fn signed_range_changes_only_the_implicit_identifier() {
    // Verification must consume original length/value octets, not a DER encoder.
    let encoded = [0xa0, 9, 0x30, 7, 6, 1, 42, 0x31, 2, 5, 0];
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let attributes = Attributes::read(&reader, &element, Placement::Signed).unwrap();
    let ranges = attributes.signed_bytes().unwrap();
    assert_eq!(ranges[0], [0x31]);
    assert_eq!(ranges[1], &encoded[1..]);
    assert_eq!(ranges[1].as_ptr(), encoded[1..].as_ptr());
    assert_eq!(
        attributes.items()[0].single("value").unwrap().as_bytes(),
        [5, 0]
    );
    drop(attributes);
    assert_eq!(memory.used(), 0);
}

#[test]
fn unknown_repeated_instances_and_empty_generic_values_are_preserved() {
    // RFC5652 specifies singleton restrictions for particular types, not all OIDs.
    let encoded = [
        0xa0, 14, 0x30, 5, 6, 1, 42, 0x31, 0, 0x30, 5, 6, 1, 42, 0x31, 0,
    ];
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let attributes = Attributes::read(&reader, &element, Placement::Signed).unwrap();
    assert_eq!(attributes.items().len(), 2);
    assert!(attributes.items()[0].values().is_empty());
    assert!(attributes.items()[1].values().is_empty());
    assert_eq!(
        attributes.items()[0]
            .single("knownSingleton")
            .unwrap_err()
            .code(),
        ErrorCode::AttributeCardinality
    );
}

#[test]
fn empty_inner_values_do_not_remove_the_nonempty_outer_bound() {
    // Generic Attribute and SignedAttributes have different ASN.1 bounds;
    // accepting an unknown empty inner set must not permit an empty outer set.
    let parser = Parser::ber(memory());
    let valid = [0xa0, 7, 0x30, 5, 6, 1, 42, 0x31, 0];
    let mut parent = parser.read(&valid, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let attributes = Attributes::read(&parent, &element, Placement::Signed).unwrap();
    assert_eq!(attributes.items().len(), 1);
    assert!(attributes.items()[0].values().is_empty());
    assert_eq!(attributes.signed_bytes().unwrap()[1], &valid[1..]);
    let empty = [0xa0, 0];
    let mut parent = parser.read(&empty, 500).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let error = Attributes::read(&parent, &element, Placement::Signed).unwrap_err();
    assert_eq!(error.code(), ErrorCode::EmptyAttributes);
    assert_eq!(error.offset(), 500);
}

#[test]
fn signed_ber_header_is_refused_while_unsigned_ber_is_readable() {
    // The schema role, not untrusted content, selects the mandatory DER boundary.
    let signed = [0xa0, 0x81, 9, 0x30, 7, 6, 1, 42, 0x31, 2, 5, 0];
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&signed, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    assert!(Attributes::read(&reader, &element, Placement::Signed).is_err());
    let unsigned = [0xa1, 0x80, 0x30, 7, 6, 1, 42, 0x31, 2, 5, 0, 0, 0];
    let mut reader = parser.read(&unsigned, 500).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let attributes = Attributes::read(&reader, &element, Placement::Unsigned).unwrap();
    assert_eq!(attributes.items().len(), 1);
    assert!(attributes.signed_bytes().is_none());
}

#[test]
fn implicit_set_ordering_is_checked_at_the_original_member() {
    // Context tagging cannot hide the SignedAttributes SET OF ordering rule.
    let encoded = [
        0xa0, 18, 0x30, 7, 6, 1, 43, 0x31, 2, 5, 0, 0x30, 7, 6, 1, 42, 0x31, 2, 5, 0,
    ];
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = Attributes::read(&reader, &element, Placement::Signed).unwrap_err();
    assert_eq!(error.code(), ErrorCode::AttributeOrder);
    assert_eq!(error.offset(), 411);
}

#[test]
fn original_local_refusal_is_not_a_malformed_attribute() {
    // Rereading under DER must not create a fresh work counter or catalogue.
    let encoded = [0xa0, 9, 0x30, 7, 6, 1, 42, 0x31, 2, 5, 0];
    let memory = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 2,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = Attributes::read(&reader, &element, Placement::Signed).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 400);
    assert_eq!(memory.used(), 0);
}

#[test]
fn deferred_value_reader_keeps_original_depth_counter_and_current_domain() {
    // A selected value is read from its original range, with no depth/work
    // reset and without charging a new request to retained catalogue storage.
    let encoded = [0xa0, 9, 0x30, 7, 6, 1, 42, 0x31, 2, 5, 0];
    let old = memory();
    let current = memory();
    let limit = 4096_u64;
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: limit,
            ..Limits::default()
        },
        old.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let attributes = Attributes::read(&reader, &element, Placement::Signed).unwrap();
    let attribute = &attributes.items()[0];
    let mut deferred = attribute
        .value_reader(0, &current, "counterSignature")
        .unwrap()
        .unwrap();
    assert_eq!(deferred.depth(), 3);
    assert_eq!(deferred.next_element().unwrap().unwrap().as_bytes(), [5, 0]);
    // Spend the actual parser-local remainder. Current-domain catalogue lookup
    // is independent work, so summing aggregate counters would not measure it.
    while reader.charge(1).is_ok() {}
    let mut refused = attribute
        .value_reader(0, &current, "counterSignature")
        .unwrap()
        .unwrap();
    let error = refused.next_element().unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 409);
    assert!(
        attribute
            .value_reader(1, &current, "counterSignature")
            .unwrap()
            .is_none()
    );
}

#[test]
fn lookup_preserves_all_unknown_instances_and_refusal_is_fused() {
    // An unfunded search cannot turn a repeated type into absent or unique.
    let encoded = [
        0xa0, 14, 0x30, 5, 6, 1, 42, 0x31, 0, 0x30, 5, 6, 1, 42, 0x31, 0,
    ];
    let old = memory();
    let parser = Parser::ber(old.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let attributes = Attributes::read(&reader, &element, Placement::Signed).unwrap();
    let current = memory();
    let kind = structured_asn1::Oid::from_bytes(&[42]);
    let found: Vec<_> = attributes
        .all(kind, &current)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(current.work_used(), 5);
    assert_eq!(
        attributes.unique_in(kind, &reader).unwrap_err().code(),
        ErrorCode::DuplicateAttribute
    );
    let unfunded = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let old_work = old.work_used();
    let mut refused = attributes.all(kind, &unfunded);
    let error = refused.next().unwrap().unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 402);
    assert!(refused.next().is_none());
    assert!(refused.next().is_none());
    assert_eq!(old.work_used(), old_work);
}

#[test]
fn absent_attribute_requires_the_producing_search_allowance() {
    // Even a no-match answer cannot skip the original local budget's final step.
    let encoded = [0xa0, 7, 0x30, 5, 6, 1, 42, 0x31, 0];
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 4096,
            ..Limits::default()
        },
        memory(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let attributes = Attributes::read(&reader, &element, Placement::Signed).unwrap();
    while reader.charge(1).is_ok() {}
    let missing = structured_asn1::Oid::from_bytes(&[43]);
    let error = attributes.unique_in(missing, &reader).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 402);
}

#[test]
fn opaque_signed_values_must_pass_der_semantics_not_just_headers() {
    // A BER TRUE spelled 01 has canonical headers but is not DER TRUE (FF).
    // Unknown ANY syntax still belongs to the signed set's DER contract.
    let encoded = [0xa0, 10, 0x30, 8, 6, 1, 42, 0x31, 3, 1, 1, 1];
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = Attributes::read(&reader, &element, Placement::Signed)
        .expect_err("a false DER conformance result cannot be ignored");
    assert_eq!(error.offset(), 409);
    assert_eq!(error.field(), "signerInfo.signedAttrs");
    assert!(!error.is_resource());
}

#[test]
fn producing_value_reader_rejects_foreign_session_before_lookup_or_allocation() {
    // An unrelated parent cannot fund just lookup while the returned value
    // quietly parses under another session's local meter. Retained query has
    // its separate explicit Memory route, not a producing-session fallback.
    let encoded = [0xa0, 9, 0x30, 7, 6, 1, 42, 0x31, 2, 5, 0];
    let memory = memory();
    let original = Parser::ber(memory.clone());
    let mut parent = original.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let attributes = Attributes::read(&parent, &element, Placement::Signed).unwrap();
    let foreign = Parser::ber(memory.clone());
    let query = foreign.read(&[], 900).unwrap();
    let held = memory.used();
    let work = memory.work_used();
    let Err(error) = attributes.items()[0].value_reader_in(0, &query, "value") else {
        panic!("foreign producing session accepted");
    };
    assert_eq!(
        error.code(),
        ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
    assert_eq!(error.offset(), 402);
    assert_eq!(memory.used(), held);
    assert_eq!(memory.work_used(), work);
    let reader = attributes.items()[0]
        .value_reader(0, &memory, "value")
        .unwrap();
    assert!(reader.is_some());
}
