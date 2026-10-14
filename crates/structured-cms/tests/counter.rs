//! Independent unsigned values, original offsets and inherited lazy limits.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::signer::SignerInfo;
use structured_cms::{ErrorCode, oid};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut value = vec![tag];
    if bytes.len() < 128 {
        value.push(u8::try_from(bytes.len()).unwrap());
    } else {
        let length = u16::try_from(bytes.len()).unwrap();
        value.push(0x82);
        value.extend_from_slice(&length.to_be_bytes());
    }
    value.extend_from_slice(bytes);
    value
}

#[test]
fn iterative_walk_preserves_preorder_and_parent_content_coverage() {
    // Nested children cover only their immediate parent's signature content.
    // Independent malformed siblings remain events, never successful signers.
    use structured_cms::counter::{Visit, walk};
    let leaf = signer(&[]);
    let nested = signer(&attribute(&leaf));
    let mut siblings = nested;
    siblings.extend_from_slice(&[2, 1, 3]);
    siblings.extend_from_slice(&leaf);
    let encoded = signer(&attribute(&siblings));
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let root = SignerInfo::read(&reader, &element).unwrap();
    let before = memory.used();
    let results = walk(&root, &reader, |event, producing| {
        match event {
            Visit::Signer {
                signer,
                signature,
                parent,
            } => {
                assert_eq!(signature.as_one(), Some(&[8][..]));
                assert!(signer.span().start > parent.start);
                assert!(producing.depth() > reader.depth());
                // This borrowed result lives in original input, not the frame.
                Ok::<_, ()>((signer.span().start, parent.start, Some(signer.as_bytes())))
            }
            Visit::Malformed { source, parent } => Ok((source.offset(), parent.start, None)),
        }
    })
    .unwrap();
    assert_eq!(results.len(), 4);
    assert!(results.windows(2).all(|pair| pair[0].0 < pair[1].0));
    assert_eq!(results[0].1, root.span().start);
    assert_eq!(results[1].1, results[0].0);
    assert_eq!(results[2].1, root.span().start);
    assert!(results[2].2.is_none());
    assert_eq!(results[3].2, Some(leaf.as_slice()));
    drop(root);
    drop(reader);
    assert_eq!(results[1].2, Some(leaf.as_slice()));
    assert!(memory.used() > 0);
    drop(results);
    drop(parser);
    assert_eq!(memory.used(), 0);
    assert!(before > 0);
}

#[test]
fn wide_leaf_walk_retains_no_pending_sibling_models() {
    // A width-controlled tree must not allocate a queue of decoded siblings.
    // ZST visitor output isolates traversal storage from retained results.
    use structured_cms::counter::{Visit, walk};
    let leaf = signer(&[]);
    let values = leaf.repeat(200);
    let encoded = signer(&attribute(&values));
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let root = SignerInfo::read(&reader, &element).unwrap();
    let held = memory.used();
    let mut visits = 0;
    let results = walk(&root, &reader, |event, _| {
        assert!(matches!(event, Visit::Signer { .. }));
        assert_eq!(memory.used(), held, "leaf width must not allocate frames");
        visits += 1;
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(visits, 200);
    assert_eq!(results.len(), 200);
    assert_eq!(memory.used(), held);
}

#[test]
fn walk_failure_drops_collected_results_and_active_frames() {
    // Callback/resource aborts expose no partial collection and release every
    // temporary frame/result; caller-owned source capacity remains charged.
    use std::cell::Cell;
    use structured_cms::counter::{Visit, WalkError, walk};
    struct Retained<'a>(&'a Cell<usize>);
    impl Drop for Retained<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let nested = signer(&attribute(&signer(&[])));
    let encoded = signer(&attribute(&nested));
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let root = SignerInfo::read(&reader, &element).unwrap();
    let held = memory.used();
    let dropped = Cell::new(0);
    let mut visits = 0;
    let error = walk(&root, &reader, |event, _| {
        assert!(matches!(event, Visit::Signer { .. }));
        visits += 1;
        if visits == 2 {
            return Err("backend failure");
        }
        Ok(Retained(&dropped))
    })
    .err()
    .unwrap();
    assert!(matches!(
        error,
        WalkError::Callback {
            source: "backend failure",
            ..
        }
    ));
    assert_eq!(dropped.get(), 1);
    assert_eq!(memory.used(), held);
    visits = 0;
    let error = walk(&root, &reader, |_, _| {
        visits += 1;
        memory.charge_work(memory.work_remaining() as u64).unwrap();
        Ok::<_, ()>(Retained(&dropped))
    })
    .err()
    .unwrap();
    assert!(matches!(error, WalkError::Processing(ref error) if error.is_resource()));
    assert_eq!(visits, 1);
    // Refusal can occur at result-copy admission, before retention; either way
    // the returned caller value and all active decoded frames must be dropped.
    assert_eq!(dropped.get(), 2);
    assert_eq!(memory.used(), held);
}

fn attribute(values: &[u8]) -> Vec<u8> {
    let mut contents = tlv(6, oid::COUNTERSIGNATURE.as_bytes());
    contents.extend(tlv(0x31, values));
    tlv(0x30, &contents)
}

fn signer(unsigned: &[u8]) -> Vec<u8> {
    let mut contents = vec![
        2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, 8,
    ];
    if !unsigned.is_empty() {
        contents.extend(tlv(0xa1, unsigned));
    }
    tlv(0x30, &contents)
}

#[test]
fn repeated_instances_and_values_are_lazy_and_keep_original_encoding() {
    // RFC5652 §11.4 permits both repetition dimensions. Taking one value
    // must not eagerly decode/retain all other SignerInfo catalogues.
    let child = signer(&[]);
    let mut values = child.clone();
    values.extend_from_slice(&child);
    let mut attributes = attribute(&values);
    attributes.extend(attribute(&child));
    let encoded = signer(&attributes);
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let parent = SignerInfo::read(&reader, &element).unwrap();
    let held = memory.used();
    let work = memory.work_used();
    let mut counters = parent.countersignatures_in(&reader);
    assert_eq!(memory.work_used(), work);
    assert_eq!(memory.used(), held);
    for _ in 0..3 {
        let child_value = counters.next().unwrap().unwrap();
        assert_eq!(child_value.as_bytes(), child);
        let start = usize::try_from(child_value.span().start - 400).unwrap();
        assert_eq!(child_value.as_bytes().as_ptr(), encoded[start..].as_ptr());
        assert_eq!(child_value.signature().as_one(), Some(&[8][..]));
        assert_eq!(
            memory.used(),
            held,
            "primitive child has no eager catalogue"
        );
    }
    assert!(counters.next().is_none());
    let work = memory.work_used();
    assert!(counters.next().is_none());
    assert_eq!(memory.work_used(), work);
}

#[test]
fn malformed_unsigned_values_do_not_erase_independent_later_signers() {
    // Empty known attribute and a malformed value are separate diagnostics;
    // neither may become absence or erase the later readable direct value.
    let child = signer(&[]);
    let mut values = vec![2, 1, 3];
    values.extend_from_slice(&child);
    let mut attributes = attribute(&[]);
    attributes.extend(attribute(&values));
    let encoded = signer(&attributes);
    let parser = Parser::ber(memory());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let parent = SignerInfo::read(&reader, &element).unwrap();
    let mut counters = parent.countersignatures_in(&reader);
    let empty = counters.next().unwrap().unwrap_err();
    assert_eq!(empty.code(), ErrorCode::AttributeCardinality);
    assert_eq!(empty.field(), "signerInfo.unsignedAttrs.countersignature");
    let malformed = counters.next().unwrap().unwrap_err();
    assert_eq!(malformed.code(), ErrorCode::UnexpectedTag);
    assert!(!malformed.is_resource());
    assert!(malformed.offset() > empty.offset());
    assert_eq!(counters.next().unwrap().unwrap().as_bytes(), child);
    assert!(counters.next().is_none());
}

#[test]
fn inherited_depth_and_current_work_refusal_stop_once() {
    // Lazy values must stay at their original depth. A fresh top-level Parser
    // would incorrectly accept this child; resource refusal cannot be skipped.
    let child = signer(&[]);
    let encoded = signer(&attribute(&child));
    let memory = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 4,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let parent = SignerInfo::read(&reader, &element).unwrap();
    let mut counters = parent.countersignatures_in(&reader);
    let error = counters.next().unwrap().unwrap_err();
    assert!(error.is_resource());
    assert!(error.offset() >= 400);
    assert!(counters.next().is_none());
    assert!(counters.next().is_none());
    memory.charge_work(memory.work_remaining() as u64).unwrap();
    let mut counters = parent.countersignatures_in(&reader);
    assert!(counters.next().unwrap().unwrap_err().is_resource());
    assert!(counters.next().is_none());
}

#[test]
fn deep_walk_refuses_original_depth_without_a_partial_result() {
    // Every nested countersignature consumes the original parser depth. The
    // iterative stack must not reset that depth at each child boundary.
    use structured_cms::counter::{Visit, WalkError, walk};
    let mut encoded = signer(&[]);
    for _ in 0..8 {
        encoded = signer(&attribute(&encoded));
    }
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 12,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let root = SignerInfo::read(&reader, &element).unwrap();
    let held = memory.used();
    let mut visited = 0;
    let error = walk(&root, &reader, |event, _| {
        assert!(matches!(event, Visit::Signer { .. }));
        visited += 1;
        Ok::<_, ()>(())
    })
    .err()
    .unwrap();
    assert!(matches!(error, WalkError::Processing(ref error) if error.is_resource()));
    assert!(visited > 0 && visited < 8);
    // The returned diagnostic independently retains its original path capacity.
    drop(error);
    assert_eq!(memory.used(), held);
}

#[test]
fn result_capacity_refusal_precedes_visitor_effects() {
    // Exhaust storage after parsing the source. The first returned scalar
    // cannot be admitted, so the callback must not run or mutate caller state.
    use structured_cms::counter::{WalkError, walk};
    let encoded = signer(&attribute(&signer(&[])));
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 1 << 24)));
    let parser = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let root = SignerInfo::read(&reader, &element).unwrap();
    let held = memory.used();
    let mut occupied = memory.vector::<u8>();
    occupied.try_reserve_exact(65536 - held).unwrap();
    let mut visited = 0;
    let error = walk(&root, &reader, |_, _| {
        visited += 1;
        Ok::<_, ()>(0u64)
    })
    .err()
    .unwrap();
    assert!(matches!(error, WalkError::Processing(ref error) if error.is_resource()));
    assert_eq!(visited, 0);
    drop(occupied);
    assert_eq!(memory.used(), held);
}

#[test]
fn foreign_producing_session_is_terminal_before_the_visitor() {
    // A reader with the same account but a different parser cannot turn caller
    // misuse into a malformed document event or successful partial traversal.
    use structured_cms::counter::{WalkError, walk};
    let encoded = signer(&attribute(&signer(&[])));
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let foreign = Parser::ber(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let root = SignerInfo::read(&reader, &element).unwrap();
    let other = foreign.read(&[], 0).unwrap();
    let held = memory.used();
    let mut visited = 0;
    let error = walk(&root, &other, |_, _| {
        visited += 1;
        Ok::<_, ()>(())
    })
    .expect_err("foreign session must refuse");
    assert!(matches!(error, WalkError::Processing(ref error)
        if error.code() == ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)));
    assert_eq!(visited, 0);
    assert_eq!(memory.used(), held);
}
