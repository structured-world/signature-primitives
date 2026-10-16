//! Projection/control tests, not an XML parser or native crypto oracle.
use super::*;
use structured_xades::hashes::{
    self, HashBinding, HashClass, HashCompleteness, HashError, HashFailure, HashOrigin,
    HashProblem, HashUse, HashUseState, HashXml,
};

pub(super) enum RefusalMutation {
    Keep,
    Change,
}

pub(super) enum Selection {
    Single,
    PerSignature,
}

impl HashXml for Tree {
    fn visit_hash_uses<VE, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        work: &W,
        mut visitor: impl FnMut(HashUse<usize>) -> Result<(), VE>,
    ) -> Result<HashCompleteness<usize>, VisitError<Cause, VE>> {
        self.check(snapshot, signature)
            .map_err(VisitError::Processing)?;
        self.hash_calls.set(self.hash_calls.get() + 1);
        for actual in &self.hash_uses {
            work.charge_work(1)
                .map_err(|cause| VisitError::Processing(Cause::Resource(cause)))?;
            if matches!(self.hash_selection, Selection::PerSignature)
                && actual.signature != signature
            {
                continue;
            }
            self.hash_visits.set(self.hash_visits.get() + 1);
            if let Err(cause) = visitor(*actual) {
                if matches!(self.hash_refusal, RefusalMutation::Change) {
                    self.generation.set(self.generation.get() + 1);
                }
                return Err(VisitError::Visitor(cause));
            }
        }
        Ok(self.hash_completeness)
    }
}

#[test]
fn whole_hash_guard_checks_counter_suites_without_child_baseline_properties() {
    // A clean root cannot certify an MD5-bearing child. The original complete
    // counter census determines who is queried; the first failing child's
    // actual method is retained and all earlier output capacity is released.
    xml_digest::with_checked_path(|path, _, _, memory| {
        for state in [
            HashUseState::Complete(HashClass::OtherKnown),
            HashUseState::Complete(HashClass::Md5),
            HashUseState::Unsupported,
            HashUseState::Unprocessed,
        ] {
            let mut xml = preparation_tree();
            let (child, _, _, _) =
                xml_digest::append_counter_credentials(&mut xml, memory, Coverage::ElementContent);
            xml.key_association = certificate::KeyAssociation::Same;
            xml.hash_selection = Selection::PerSignature;
            xml.hash_completeness = HashCompleteness::Complete;
            for (signature, state) in [
                (0, HashUseState::Complete(HashClass::OtherKnown)),
                (child, state),
            ] {
                xml.hash_uses.push(HashUse {
                    signature,
                    origin: HashOrigin::SignatureMessage {
                        instruction: signature,
                        method: None,
                    },
                    state,
                });
            }
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters =
                structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
                    Ok::<_, ()>(path)
                })
                .unwrap();
            let held = memory.used();
            let query = funded();
            let result = hashes::check_participants(
                &prepared,
                &counters,
                &Access::new(&xml, xml.snapshot(), &query),
            )
            .unwrap();
            if let HashUseState::Complete(HashClass::OtherKnown) = state {
                let hashes::ParticipantBinding::Bound(receipt) = result else {
                    panic!("complete participant guards")
                };
                assert_eq!(receipt.snapshot(), xml.snapshot());
                assert_eq!(receipt.signature(), 0);
                assert_eq!(receipt.counters().len(), counters.actors().len());
                assert_eq!(receipt.root().signature(), 0);
                assert_eq!(receipt.counters()[0].signature(), child);
            } else {
                let expected = match state {
                    HashUseState::Complete(_) => HashFailure::ProhibitedMd5,
                    HashUseState::Unsupported => HashFailure::Unsupported,
                    HashUseState::Unprocessed => HashFailure::Unprocessed,
                };
                assert!(
                    matches!(result, hashes::ParticipantBinding::Unproven(hashes::ParticipantProblem {signature, cause: HashProblem::Use { origin: HashOrigin::SignatureMessage { instruction, method: None }, cause }}) if signature == child && instruction == child && cause == expected)
                );
            }
            assert_eq!(xml.hash_calls.get(), 2);
            assert_eq!(query.used(), 0);
            assert_eq!(memory.used(), held);
        }
    });
}

fn fixture() -> Tree {
    let mut xml = Tree::normal();
    let info = xml.element_child(0, DS, "SignedInfo");
    let method = xml.nodes.len();
    xml.nodes.push(element(Some(info), DS, "SignatureMethod"));
    xml.hash_uses.push(HashUse {
        signature: 0,
        origin: HashOrigin::SignatureMessage {
            instruction: method,
            method: Some(method),
        },
        state: HashUseState::Complete(HashClass::OtherKnown),
    });
    xml.hash_completeness = HashCompleteness::Complete;
    xml
}

fn bound(xml: &Tree, memory: &Memory) -> binding::Bound<usize, u8, u8> {
    let access = Access::new(xml, xml.snapshot(), memory);
    let layout = container::locate(&access, 0).unwrap();
    binding::bind(&access, &layout).unwrap()
}

#[test]
fn actual_message_mgf_and_manifest_hashes_are_checked_without_new_crypto() {
    // Each native receipt matters, including MGF defaults and authenticated
    // Manifest instructions. Pure suites need no fabricated external digest.
    for class in [HashClass::OtherKnown, HashClass::Intrinsic] {
        let mut xml = fixture();
        xml.hash_uses[0].state = HashUseState::Complete(class);
        let instruction = xml.references[0].node;
        xml.hash_uses.push(HashUse {
            signature: 0,
            origin: HashOrigin::Reference {
                instruction,
                method: None,
                parent: Parent::Manifest(instruction),
            },
            state: HashUseState::Complete(HashClass::OtherKnown),
        });
        xml.hash_uses.push(HashUse {
            signature: 0,
            origin: HashOrigin::MaskGeneration {
                instruction: xml.hash_uses[0].origin.node(),
                method: None,
            },
            state: HashUseState::Complete(HashClass::OtherKnown),
        });
        let memory = funded();
        let selected = bound(&xml, &memory);
        let before = memory.used();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let HashBinding::Bound(receipt) = hashes::check(&selected, &access).unwrap() else {
            panic!("complete non-MD5 receipts")
        };
        assert_eq!(receipt.signature(), 0);
        assert_eq!(receipt.snapshot(), xml.snapshot());
        assert_eq!(xml.hash_visits.get(), 3);
        assert_eq!(xml.hash_calls.get(), 1);
        assert_eq!(xml.streamed.get(), 0);
        assert_eq!(memory.used(), before);
    }
}

#[test]
fn actual_md5_and_incomplete_uses_preserve_the_original_role_and_stop() {
    // No URI heuristic, unknown->known fallback or successful prefix. Keep
    // absence of a written method distinct from the actual enclosing node.
    for origin in [
        HashOrigin::SignatureMessage {
            instruction: 0,
            method: None,
        },
        HashOrigin::MaskGeneration {
            instruction: 0,
            method: None,
        },
        HashOrigin::Reference {
            instruction: 0,
            method: None,
            parent: Parent::Manifest(0),
        },
    ] {
        for (state, expected) in [
            (
                HashUseState::Complete(HashClass::Md5),
                HashFailure::ProhibitedMd5,
            ),
            (HashUseState::Unsupported, HashFailure::Unsupported),
            (HashUseState::Unprocessed, HashFailure::Unprocessed),
        ] {
            let mut xml = fixture();
            xml.hash_uses.insert(
                0,
                HashUse {
                    signature: 0,
                    origin,
                    state,
                },
            );
            let memory = funded();
            let selected = bound(&xml, &memory);
            let access = Access::new(&xml, xml.snapshot(), &memory);
            assert!(matches!(hashes::check(&selected,&access).unwrap(),
                HashBinding::Unproven(HashProblem::Use{origin:actual,cause})
                if actual==origin && cause==expected));
            assert_eq!(xml.hash_visits.get(), 1);
        }
    }
}

#[test]
fn discovery_and_invalid_projection_never_issue_a_positive_hash_receipt() {
    // Catalogue completeness is not inferred from the successfully visited
    // prefix. The owner's impossible projection is a processing error.
    for completeness in [
        HashCompleteness::Unsupported(0),
        HashCompleteness::Unprocessed(0),
    ] {
        let mut xml = fixture();
        xml.hash_completeness = completeness;
        let memory = funded();
        let selected = bound(&xml, &memory);
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let expected = match completeness {
            HashCompleteness::Unsupported(_) => HashFailure::Unsupported,
            _ => HashFailure::Unprocessed,
        };
        assert!(matches!(hashes::check(&selected,&access).unwrap(),
            HashBinding::Unproven(HashProblem::Catalogue{node:0,cause}) if cause==expected));
    }
    for shape in 0..3 {
        let mut xml = fixture();
        match shape {
            0 => xml.hash_uses.clear(),
            1 => xml.hash_uses.push(xml.hash_uses[0]),
            _ => {
                xml.hash_uses[0].origin = HashOrigin::MaskGeneration {
                    instruction: 0,
                    method: None,
                };
                xml.hash_uses[0].state = HashUseState::Complete(HashClass::Intrinsic);
            }
        }
        let memory = funded();
        let selected = bound(&xml, &memory);
        let access = Access::new(&xml, xml.snapshot(), &memory);
        assert!(matches!(
            hashes::check(&selected, &access),
            Err(HashError::Projection { .. })
        ));
    }
}

#[test]
fn hash_queries_use_current_work_and_keep_the_first_terminal_cause() {
    // Dispatch, owner traversal and callback admission are independent paid
    // steps. A later generation change cannot mask a visitor resource refusal.
    let mut xml = fixture();
    xml.hash_refusal = RefusalMutation::Change;
    let original = funded();
    let selected = bound(&xml, &original);
    let before = original.used();
    for ceiling in [0, 1, 2] {
        let current = memory(ceiling);
        let access = Access::new(&xml, xml.snapshot(), &current);
        let result = hashes::check(&selected, &access);
        match ceiling {
            0 => assert!(matches!(
                result,
                Err(HashError::Access(AccessError::Resource {
                    cause: MemoryError::WorkExceeded,
                    ..
                }))
            )),
            1 => assert!(matches!(
                result,
                Err(HashError::Access(AccessError::Xml(Cause::Resource(
                    MemoryError::WorkExceeded
                ))))
            )),
            _ => assert!(matches!(
                result,
                Err(HashError::Resource {
                    cause: MemoryError::WorkExceeded,
                    ..
                })
            )),
        }
        assert_eq!(current.used(), 0);
    }
    let calls = xml.hash_calls.get();
    let access = Access::new(&xml, xml.snapshot(), &original);
    assert!(matches!(
        hashes::check(&selected, &access),
        Err(HashError::Foreign { node: 0 })
    ));
    assert_eq!(xml.hash_calls.get(), calls);
    assert_eq!(original.used(), before);
}
