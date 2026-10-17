//! Registered attribute deviations retain original facts without valid binding.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_cms::attribute::{Attributes, Placement};
use structured_cms::{ErrorCode, oid, signer::SignerInfo};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(64 << 20, 100_000_000)))
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if value.len() < 128 {
        bytes.push(u8::try_from(value.len()).unwrap());
    } else {
        let length = value.len().to_be_bytes();
        let first = length.iter().position(|byte| *byte != 0).unwrap();
        bytes.push(0x80 | u8::try_from(length.len() - first).unwrap());
        bytes.extend_from_slice(&length[first..]);
    }
    bytes.extend_from_slice(value);
    bytes
}

fn attribute(kind: Oid<'_>, value: &[u8]) -> Vec<u8> {
    let mut fields = tlv(6, kind.as_bytes());
    fields.extend(tlv(0x31, value));
    tlv(0x30, &fields)
}

fn signer(signed: Option<&[u8]>, unsigned: Option<&[u8]>) -> Vec<u8> {
    let mut fields = vec![2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42];
    if let Some(signed) = signed {
        fields.extend(tlv(0xa0, signed));
    }
    fields.extend([0x30, 3, 6, 1, 43, 4, 1, 8]);
    if let Some(unsigned) = unsigned {
        fields.extend(tlv(0xa1, unsigned));
    }
    tlv(0x30, &fields)
}

#[test]
fn every_extra_known_instance_retains_a_located_diagnostic() {
    // RFC5652 §11.3 forbids multiple signing-time instances. Readable copies
    // must not lose their diagnostics merely because nobody selects a cert.
    let one = attribute(oid::SIGNING_TIME, &tlv(0x17, b"010515140000Z"));
    for count in [2, 4096] {
        let attributes = one.repeat(count);
        let bytes = signer(Some(&attributes), None);
        let account = memory();
        let parser = Parser::ber(account.clone());
        let mut parent = parser.read(&bytes, 700).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let reading = SignerInfo::read(&parent, &element).unwrap();
        assert_eq!(reading.faults().len(), count - 1);
        let set = reading.signed_attributes().unwrap();
        assert_eq!(set.items().len(), count);
        for (index, fault) in reading.faults().iter().enumerate() {
            assert_eq!(fault.code(), ErrorCode::DuplicateAttribute);
            assert_eq!(
                fault.offset(),
                set.element().contents_span().start + ((index + 1) * one.len()) as u64
            );
            assert_eq!(fault.field(), "signerInfo.signedAttrs");
            assert!(!fault.is_resource());
        }
        assert_eq!(reading.as_bytes(), bytes);
        assert_eq!(
            set.signed_bytes().unwrap()[1].as_ptr(),
            set.element().as_bytes()[1..].as_ptr()
        );
        drop(parent);
        assert_eq!(reading.faults().len(), count - 1);
        drop(reading);
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn copied_singleton_selection_preserves_original_bytes_and_no_query_borrow() {
    // Inspection may identify one readable claim, but strict binding still
    // rejects the repeated instance. No canonicalized signed range is created.
    let one = attribute(oid::CONTENT_TYPE, &tlv(6, oid::DATA.as_bytes()));
    let bytes = signer(Some(&one.repeat(2)), None);
    let account = memory();
    let parser = Parser::ber(account.clone());
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&parent, &element).unwrap();
    let set = signer.signed_attributes().unwrap();
    let held = account.used();
    let current = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
    let selection = {
        let query = parent.try_clone().unwrap().with_execution(&current);
        set.singleton_inspection_in(oid::CONTENT_TYPE, &query)
            .unwrap()
    };
    assert_eq!(selection.repeats(), 1);
    assert!(core::ptr::eq(
        core::ptr::from_ref(selection.attribute().unwrap()),
        core::ptr::from_ref(&set.items()[0])
    ));
    assert_eq!(selection.attribute().unwrap().as_bytes(), one);
    assert_eq!(current.used(), 0);
    assert_eq!(account.used(), held);
    let absent = set
        .singleton_inspection_in(oid::MESSAGE_DIGEST, &parent)
        .unwrap();
    assert!(absent.attribute().is_none());
    assert_eq!(absent.repeats(), 0);
    let error = structured_cms::binding::inspect(
        &signer,
        &parent,
        structured_cms::binding::Scope::Content(oid::DATA),
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::DuplicateAttribute);
    assert_eq!(signer.faults()[0].code(), ErrorCode::DuplicateAttribute);
    assert_eq!(signer.as_bytes(), bytes);
    assert_eq!(
        set.signed_bytes().unwrap()[1],
        &set.element().as_bytes()[1..]
    );
}

#[test]
fn conflicting_singletons_refuse_and_foreign_readers_precede_work() {
    // Similar values cannot be chosen by caller presence or query failure.
    // A foreign zero-budget parser is a processing error, never absence/resource.
    let mut members = attribute(oid::MESSAGE_DIGEST, &[4, 1, 7]);
    members.extend(attribute(oid::MESSAGE_DIGEST, &[4, 1, 8]));
    let bytes = signer(Some(&members), None);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&parent, &element).unwrap();
    let set = signer.signed_attributes().unwrap();
    let error = set
        .singleton_inspection_in(oid::MESSAGE_DIGEST, &parent)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::DuplicateAttribute);
    assert_eq!(error.offset(), set.items()[1].span().start);
    let zero = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let foreign = Parser::ber(zero.clone());
    let query = foreign.read(&[], 900).unwrap();
    let error = set
        .singleton_inspection_in(oid::MESSAGE_DIGEST, &query)
        .unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
    assert_eq!(error.offset(), set.element().span().start);
    assert!(!error.is_resource());
    assert_eq!(zero.used(), 0);
    assert_eq!(zero.work_used(), 0);
}

#[test]
fn singleton_query_uses_exact_local_and_aggregate_work_without_allocating() {
    // Current query admission covers each catalogue step and full equal-copy
    // byte comparison, including the terminal step. Refusal preserves storage.
    let one = attribute(oid::CONTENT_TYPE, &tlv(6, oid::DATA.as_bytes()));
    let bytes = tlv(0xa0, &one.repeat(2));
    let account = memory();
    let parser = Parser::ber(account.clone());
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let set = Attributes::read(&parent, &element, Placement::Signed).unwrap();
    let parsed = account.work_used();
    let current = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
    let query = parent.try_clone().unwrap().with_execution(&current);
    assert_eq!(
        set.singleton_inspection_in(oid::CONTENT_TYPE, &query)
            .unwrap()
            .repeats(),
        1
    );
    let cost = current.work_used();
    assert!(cost > one.len());
    for (local, aggregate, succeeds) in [
        (cost, cost, true),
        (cost - 1, cost, false),
        (cost, cost - 1, false),
        (cost, 0, false),
    ] {
        let storage = memory();
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: (parsed + local) as u64,
                ..Limits::default()
            },
            storage.clone(),
        );
        let mut parent = parser.read(&bytes, 700).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let set = Attributes::read(&parent, &element, Placement::Signed).unwrap();
        assert_eq!(storage.work_used(), parsed);
        let held = storage.used();
        let current = Memory::new(Arc::new(MemoryAccount::new(0, aggregate)));
        let query = parent.try_clone().unwrap().with_execution(&current);
        let result = set.singleton_inspection_in(oid::CONTENT_TYPE, &query);
        if succeeds {
            assert_eq!(result.unwrap().repeats(), 1);
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.field(), "signerInfo.signedAttrs");
            assert!((700..700 + bytes.len() as u64).contains(&error.offset()));
        }
        assert_eq!(current.used(), 0);
        assert_eq!(storage.used(), held);
        assert_eq!(set.items()[0].as_bytes(), one);
    }
}

#[test]
fn generic_unknown_repeats_and_legal_unsigned_counters_keep_their_schema() {
    // RFC5652 does not impose global OID uniqueness. An unsigned counter may
    // legally repeat even when its child value needs separate interpretation.
    let unknown = attribute(Oid::from_bytes(&[42]), &[5, 0]);
    let counter = attribute(oid::COUNTERSIGNATURE, &[0x30, 0]);
    let bytes = signer(Some(&unknown.repeat(2)), Some(&counter.repeat(2)));
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&parent, &element).unwrap();
    assert!(signer.faults().is_empty());
    assert_eq!(signer.signed_attributes().unwrap().items().len(), 2);
    assert_eq!(signer.unsigned_attributes().unwrap().items().len(), 2);
}

#[test]
fn original_signer_element_retains_its_container_index_and_pointer() {
    // Exposing provenance must not fabricate a global ordinal or reread under
    // a new parser. Each direct sibling retains its original container position.
    let one = signer(None, None);
    let bytes = tlv(0x31, &one.repeat(2));
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let mut list = parent.enter(&element).unwrap();
    for index in 0..2 {
        let element = list.next_element().unwrap().unwrap();
        let signer = SignerInfo::read(&list, &element).unwrap();
        assert_eq!(signer.element().index(), index);
        assert_eq!(signer.element().span(), element.span());
        assert_eq!(
            signer.element().as_bytes().as_ptr(),
            element.as_bytes().as_ptr()
        );
    }
}

#[test]
fn every_registered_signed_only_type_is_diagnosed_in_unsigned_attributes() {
    // Placement is a schema fact, independent of decoding the type's values.
    // Each wrong instance is retained at its own original location.
    for kind in [
        oid::CONTENT_TYPE,
        oid::MESSAGE_DIGEST,
        oid::SIGNING_TIME,
        oid::ALGORITHM_PROTECTION,
    ] {
        let one = attribute(kind, &[5, 0]);
        let bytes = signer(None, Some(&one.repeat(2)));
        let parser = Parser::ber(memory());
        let mut parent = parser.read(&bytes, 700).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let signer = SignerInfo::read(&parent, &element).unwrap();
        let set = signer.unsigned_attributes().unwrap();
        assert_eq!(signer.faults().len(), 2);
        let strict = structured_cms::binding::inspect(
            &signer,
            &parent,
            structured_cms::binding::Scope::Content(oid::DATA),
        )
        .unwrap_err();
        assert_eq!(strict.code(), signer.faults()[0].code());
        assert_eq!(strict.field(), signer.faults()[0].field());
        assert_eq!(strict.offset(), signer.faults()[0].offset());
        for (fault, attribute) in signer.faults().iter().zip(set.items()) {
            assert_eq!(fault.code(), ErrorCode::AttributePlacement);
            assert_eq!(fault.offset(), attribute.span().start);
            assert_eq!(fault.field(), "signerInfo.unsignedAttrs");
        }
    }
}

#[test]
fn registered_diagnostic_retention_respects_capacity_and_both_work_ceilings() {
    // Cardinality diagnostics are not a free side channel around collection
    // allocation/copy accounting. Every refusal drops all partial catalogues.
    let one = attribute(oid::SIGNING_TIME, &tlv(0x17, b"010515140000Z"));
    let bytes = signer(Some(&one.repeat(3)), None);
    let read = |capacity, local, aggregate| {
        let memory = Memory::new(Arc::new(MemoryAccount::new(capacity, aggregate)));
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            memory.clone(),
        );
        let mut parent = parser.read(&bytes, 700).unwrap();
        let result = match parent.next_element() {
            Ok(Some(element)) => match SignerInfo::read(&parent, &element) {
                Ok(signer) => {
                    assert_eq!(signer.faults().len(), 2);
                    true
                }
                Err(error) => {
                    assert!(error.is_resource());
                    assert!((700..700 + bytes.len() as u64).contains(&error.offset()));
                    false
                }
            },
            Err(error) => {
                assert!(error.is_resource());
                false
            }
            Ok(None) => panic!("fixture has a signer"),
        };
        drop(parent);
        assert_eq!(memory.used(), 0);
        (result, memory.work_used())
    };
    let (success, cost) = read(65536, 1_000_000, 1_000_000);
    assert!(success);
    let mut lower = 0;
    let mut upper = 65536;
    while lower < upper {
        let capacity = lower + (upper - lower) / 2;
        if read(capacity, 1_000_000, 1_000_000).0 {
            upper = capacity;
        } else {
            lower = capacity + 1;
        }
    }
    assert!(lower > 0);
    assert!(read(lower, cost as u64, cost).0);
    assert!(!read(lower - 1, cost as u64, cost).0);
    assert!(!read(lower, cost as u64 - 1, cost).0);
    assert!(!read(lower, cost as u64, cost - 1).0);
    assert!(!read(0, cost as u64, cost).0);
}

#[test]
fn signed_counter_presence_is_a_fault_even_when_its_child_is_unreadable() {
    // RFC5652 §11.4 forbids signed countersignatures. Presence must not depend
    // on successfully decoding the malformed child SignerInfo (SEQUENCE {}).
    let counter = attribute(oid::COUNTERSIGNATURE, &[0x30, 0]);
    let bytes = signer(Some(&counter), None);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let reading = SignerInfo::read(&parent, &element).unwrap();
    assert_eq!(reading.faults().len(), 1);
    assert_eq!(reading.faults()[0].code(), ErrorCode::AttributePlacement);
    let strict = structured_cms::binding::inspect(
        &reading,
        &parent,
        structured_cms::binding::Scope::Content(oid::DATA),
    )
    .unwrap_err();
    assert_eq!(strict.code(), reading.faults()[0].code());
    assert_eq!(strict.field(), reading.faults()[0].field());
    assert_eq!(strict.offset(), reading.faults()[0].offset());
    assert_eq!(
        reading.faults()[0].offset(),
        reading.signed_attributes().unwrap().items()[0].span().start
    );
}
