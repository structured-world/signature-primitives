//! Attribute-owner control fixtures; no XML parser/schema validity is inferred.

use super::*;
use structured_xades::attributes::{self, AttributeXml};
use structured_xades::scalar::{Datatype, Fact};

pub(super) struct TypeRoute {
    node: usize,
    fact: structured_xades::scalar::QNameFact<'static>,
}

impl structured_xades::scalar::QNameXml for Tree {
    fn with_qname<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        source: LexicalSource<'_>,
        work: &W,
        visitor: impl for<'view> FnOnce(structured_xades::scalar::QNameReading<'view>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Cause, VE>> {
        use structured_xades::scalar::{QNameFact, QNameReading};
        self.check(snapshot, node).map_err(VisitError::Processing)?;
        assert_eq!(
            source,
            LexicalSource::Attribute(Name {
                namespace: "http://www.w3.org/2001/XMLSchema-instance",
                local: "type",
            })
        );
        let mut fact = QNameFact::Unsupported;
        for route in &self.qname_routes {
            work.charge_work(1)
                .map_err(|cause| VisitError::Processing(Cause::Resource(cause)))?;
            if route.node == node {
                fact = route.fact;
                break;
            }
        }
        visitor(QNameReading {
            lexical: None,
            fact,
        })
        .map_err(VisitError::Visitor)
    }
}

pub(super) struct Route {
    node: usize,
    name: Name<'static>,
    change_on_refusal: bool,
}

impl AttributeXml for Tree {
    fn visit_attributes<VE, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        work: &W,
        mut visitor: impl for<'view> FnMut(Name<'view>) -> Result<(), VE>,
    ) -> Result<(), VisitError<Cause, VE>> {
        self.check(snapshot, node).map_err(VisitError::Processing)?;
        self.attribute_calls.set(self.attribute_calls.get() + 1);
        for route in &self.attribute_routes {
            work.charge_work(1)
                .map_err(|cause| VisitError::Processing(Cause::Resource(cause)))?;
            if route.node == node
                && let Err(cause) = visitor(route.name)
            {
                if route.change_on_refusal {
                    self.generation.set(self.generation.get() + 1);
                }
                return Err(VisitError::Visitor(cause));
            }
        }
        Ok(())
    }
}

fn add(xml: &mut Tree, node: usize, name: Name<'static>, datatype: Option<Datatype>) {
    xml.attribute_routes.push(Route {
        node,
        name,
        change_on_refusal: false,
    });
    if let Some(datatype) = datatype {
        xml.scalar_routes.push(scalar_checks::attribute_route(
            node,
            name,
            datatype,
            Fact::Valid,
        ));
    }
}

pub(super) fn fixture() -> Tree {
    let mut xml = preparation_tree();
    add(
        &mut xml,
        2,
        Name {
            namespace: "",
            local: "Target",
        },
        Some(Datatype::AnyUri),
    );
    let format = xml
        .nodes
        .iter()
        .position(|node| {
            matches!(
                node.value,
                Node::Element(Name {
                    namespace: XADES,
                    local: "DataObjectFormat"
                })
            )
        })
        .unwrap();
    add(
        &mut xml,
        format,
        Name {
            namespace: "",
            local: "ObjectReference",
        },
        Some(Datatype::AnyUri),
    );
    xml
}

#[test]
fn full_preparation_does_not_skip_malformed_optional_validation_reference_properties() {
    // EN319132-1 Annex A allows these optional properties at B-B/B-T, but their
    // written content must still satisfy its schema. Inventory alone must not
    // allow an empty required list or a reversed OCSP field sequence through.
    for kind in 0..3 {
        let mut xml = fixture();
        let property = xml.nodes.len();
        if kind == 2 {
            xml.nodes
                .push(element(Some(7), XADES_141, "CompleteCertificateRefsV2"));
        } else {
            xml.nodes
                .push(element(Some(7), XADES, "CompleteRevocationRefs"));
            let group = xml.nodes.len();
            xml.nodes.push(element(
                Some(property),
                XADES,
                if kind == 0 { "CRLRefs" } else { "OCSPRefs" },
            ));
            if kind == 1 {
                let entry = xml.nodes.len();
                xml.nodes.push(element(Some(group), XADES, "OCSPRef"));
                xml.nodes
                    .push(element(Some(entry), XADES, "DigestAlgAndValue"));
            }
        }
        let memory = funded();
        let result = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), &memory),
            0,
            unsigned::Requirements::Basic,
            None,
        );
        match kind {
            0 => assert!(
                matches!(result, Err(prepare::Error::Property(properties::Error::Missing {
                parent, local: "CRLRef",
            })) if parent == property + 1)
            ),
            1 => assert!(
                matches!(result, Err(prepare::Error::Property(properties::Error::Unexpected {
                node,
            })) if node == property + 3)
            ),
            _ => assert!(
                matches!(result, Err(prepare::Error::Property(properties::Error::Missing {
                parent, local: "CertRefs",
            })) if parent == property)
            ),
        }
        assert_eq!(memory.used(), 0);
        assert_eq!(xml.streamed.get(), 0);
        assert_eq!(xml.key_projection.get(), None);
    }
}

fn one(xml: &Tree, local: &str) -> usize {
    // This trusted control fixture has one node per selected wire name.
    xml.nodes.iter().position(|node| matches!(node.value,Node::Element(name) if name.namespace==XADES && name.local==local)).unwrap()
}

#[test]
fn original_root_attributes_can_be_checked_before_any_path_or_provider() {
    // Syntax preflight cannot require constructing CounterPaths/doing PKIX work.
    // This root-only capability still refuses a missing original Target.
    for missing in [false, true] {
        let mut xml = fixture();
        if missing {
            xml.attribute_routes.retain(|route| route.node != 2);
        }
        let source = funded();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), &source),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let query = funded();
        let result =
            attributes::check_prepared(&prepared, &Access::new(&xml, xml.snapshot(), &query));
        if missing {
            assert!(matches!(
                result,
                Err(attributes::Error::Missing {
                    node: 2,
                    local: "Target"
                })
            ));
        } else {
            result.unwrap();
        }
        assert_eq!(xml.key_projection.get(), None);
        assert_eq!(xml.streamed.get(), 0);
    }
}

#[test]
fn root_field_preflight_retains_exact_source_and_never_defaults_claimed_time() {
    // Final composition must not build a receipt from a valid URI pass plus an
    // unsupported/malformed/unzoned claim, or dispatch crypto while discovering
    // a missing original attribute. Each case uses the same public preflight.
    use properties::{ClaimedTimeFailure, DateTimeFact};
    for (fact, failure) in [
        (
            DateTimeFact::Valid {
                timezone_minutes: Some(60),
            },
            None,
        ),
        (DateTimeFact::Malformed, Some(ClaimedTimeFailure::Malformed)),
        (
            DateTimeFact::Unsupported,
            Some(ClaimedTimeFailure::Unsupported),
        ),
        (
            DateTimeFact::Valid {
                timezone_minutes: None,
            },
            Some(ClaimedTimeFailure::TimezoneUnstated),
        ),
    ] {
        let mut xml = fixture();
        xml.date_time = fact;
        let source = funded();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), &source),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let held = source.used();
        let query = funded();
        let result = prepare::check_fields(&prepared, &Access::new(&xml, xml.snapshot(), &query));
        if let Some(expected) = failure {
            assert!(matches!(result,
                Err(prepare::FieldError::UnprovenTime { node, cause })
                    if node == prepared.signed().signing_time() && cause == expected));
        } else {
            let checked = result.ok().unwrap();
            assert!(core::ptr::eq(checked.prepared(), &raw const prepared));
            assert_eq!(checked.claimed_time().snapshot(), xml.snapshot());
            assert_eq!(checked.claimed_time().signature(), 0);
            assert_eq!(checked.claimed_time().timezone_minutes(), 60);
        }
        assert_eq!(xml.date_time_calls.get(), 1);
        assert_eq!(xml.key_projection.get(), None);
        assert_eq!(xml.streamed.get(), 0);
        assert_eq!(query.used(), 0);
        assert_eq!(source.used(), held);
    }
}

#[test]
fn root_field_preflight_refuses_early_without_time_or_crypto_side_effects() {
    // Missing declared fields, a foreign source and an exhausted current query
    // are terminal at their own stage, before the later claimed-time owner.
    for mode in 0..3 {
        let mut xml = fixture();
        xml.date_time = properties::DateTimeFact::Valid {
            timezone_minutes: Some(0),
        };
        let source = funded();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), &source),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        if mode == 0 {
            xml.attribute_routes.retain(|route| route.node != 2);
        }
        let query = Memory::new(Arc::new(MemoryAccount::new(
            1 << 20,
            if mode == 2 { 0 } else { 1 << 20 },
        )));
        let snapshot = if mode == 1 {
            Snapshot {
                generation: 9,
                ..xml.snapshot()
            }
        } else {
            xml.snapshot()
        };
        let result = prepare::check_fields(&prepared, &Access::new(&xml, snapshot, &query));
        match mode {
            0 => assert!(matches!(
                result,
                Err(prepare::FieldError::Attributes(
                    attributes::Error::Missing {
                        node: 2,
                        local: "Target"
                    }
                ))
            )),
            1 => assert!(matches!(
                result,
                Err(prepare::FieldError::Attributes(attributes::Error::Foreign))
            )),
            _ => assert!(matches!(
                result,
                Err(prepare::FieldError::Attributes(attributes::Error::Access(
                    AccessError::Resource {
                        cause: MemoryError::WorkExceeded,
                        ..
                    }
                )))
            )),
        }
        assert_eq!(xml.date_time_calls.get(), 0);
        assert_eq!(xml.key_projection.get(), None);
        assert_eq!(xml.streamed.get(), 0);
        assert_eq!(query.used(), 0);
    }
}

#[test]
fn cert_uri_declaration_does_not_grant_an_undeclared_id() {
    // Annex C CertIDTypeV2 permits URI but not Id. Reusing ReferenceInfo's
    // Id+URI attribute set would incorrectly bless this signed extra field.
    let mut xml = fixture();
    let cert = xml
        .nodes
        .iter()
        .position(|node| {
            matches!(
                node.value,
                Node::Element(Name {
                    namespace: XADES,
                    local: "Cert"
                })
            )
        })
        .unwrap();
    add(
        &mut xml,
        cert,
        Name {
            namespace: "",
            local: "Id",
        },
        Some(Datatype::Id),
    );
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
    let counters =
        structured_xades::pki::bind_counters::<Tree, _, ()>(prepared.bound(), &access, |_, _| {
            panic!("no counter")
        })
        .unwrap();
    let before = memory.used();
    let result = attributes::check(&prepared, &counters, &access);
    assert!(
        matches!(result,Err(attributes::Error::Unexpected{node,attribute:0}) if node==cert),
        "{result:?}"
    );
    assert_eq!(memory.used(), before);
}

#[test]
fn declared_attributes_use_original_datatypes_and_do_not_descend_into_anytype_payloads() {
    // Own Id/URI/Encoding are checked individually; a foreign attribute and a
    // misleading XAdES-looking child inside ClaimedRole remain format payload.
    let mut xml = fixture();
    add(
        &mut xml,
        3,
        Name {
            namespace: "",
            local: "Id",
        },
        Some(Datatype::Id),
    );
    let cert = one(&xml, "Cert");
    add(
        &mut xml,
        cert,
        Name {
            namespace: "",
            local: "URI",
        },
        Some(Datatype::AnyUri),
    );
    let token = one(&xml, "EncapsulatedTimeStamp");
    add(
        &mut xml,
        token,
        Name {
            namespace: "",
            local: "Encoding",
        },
        Some(Datatype::AnyUri),
    );
    let role = xml.nodes.len();
    xml.nodes.push(element(Some(4), XADES, "SignerRoleV2"));
    let roles = xml.nodes.len();
    xml.nodes.push(element(Some(role), XADES, "ClaimedRoles"));
    let opaque = xml.nodes.len();
    xml.nodes.push(element(Some(roles), XADES, "ClaimedRole"));
    add(
        &mut xml,
        opaque,
        Name {
            namespace: "urn:extension",
            local: "Id",
        },
        None,
    );
    let misleading = xml.nodes.len();
    xml.nodes
        .push(element(Some(opaque), XADES, "QualifyingProperties"));
    add(
        &mut xml,
        misleading,
        Name {
            namespace: "",
            local: "Unknown",
        },
        None,
    );
    let storage = funded();
    let access = Access::new(&xml, xml.snapshot(), &storage);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
    let counters =
        structured_xades::pki::bind_counters::<Tree, _, ()>(prepared.bound(), &access, |_, _| {
            panic!("no counter")
        })
        .unwrap();
    let spent = storage.work_used();
    let held = storage.used();
    let query = funded();
    attributes::check(
        &prepared,
        &counters,
        &Access::new(&xml, xml.snapshot(), &query),
    )
    .unwrap();
    assert_eq!(xml.scalar_calls.get(), 5);
    assert_eq!(query.used(), 0);
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), spent);
}

#[test]
fn required_target_is_not_repaired_by_a_foreign_same_local_attribute_or_binding_metadata() {
    // A selected binding is not evidence that a required original attribute
    // exists in this view. Namespace-qualified lookalikes are not unqualified Target.
    for foreign in [false, true] {
        let mut xml = fixture();
        xml.attribute_routes.retain(|route| route.node != 2);
        if foreign {
            add(
                &mut xml,
                2,
                Name {
                    namespace: "urn:foreign",
                    local: "Target",
                },
                None,
            );
        }
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = structured_xades::pki::bind_counters::<Tree, _, ()>(
            prepared.bound(),
            &access,
            |_, _| panic!("no counter"),
        )
        .unwrap();
        let result = attributes::check(&prepared, &counters, &access);
        if foreign {
            assert!(matches!(
                result,
                Err(attributes::Error::Unexpected {
                    node: 2,
                    attribute: 0
                })
            ));
        } else {
            assert!(matches!(
                result,
                Err(attributes::Error::Missing {
                    node: 2,
                    local: "Target"
                })
            ));
        }
        assert_eq!(xml.scalar_calls.get(), 0);
    }
}

#[test]
fn invalid_type_qname_is_not_an_unimplemented_schema_claim() {
    // A native lexical/binding failure is already known. Preserve it separately
    // from a supported QName whose actual schema definition is unavailable.
    use structured_xades::scalar::QNameFact;
    for (fact, problem) in [
        (QNameFact::Absent, attributes::TypeProblem::Absent),
        (QNameFact::Malformed, attributes::TypeProblem::Malformed),
        (
            QNameFact::ComplexContent,
            attributes::TypeProblem::ComplexContent,
        ),
        (
            QNameFact::UnboundPrefix("missing"),
            attributes::TypeProblem::UnboundPrefix,
        ),
    ] {
        let mut xml = fixture();
        add(
            &mut xml,
            3,
            Name {
                namespace: "http://www.w3.org/2001/XMLSchema-instance",
                local: "type",
            },
            None,
        );
        xml.qname_routes.push(TypeRoute { node: 3, fact });
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let result = attributes::check_prepared(&prepared, &access);
        assert!(result.is_err());
        assert!(!matches!(
            result,
            Err(attributes::Error::InstanceUnassessed { .. })
        ));
        assert!(
            matches!(result, Err(attributes::Error::Type { node: 3, problem: actual }) if actual == problem)
        );
    }
}

#[test]
fn explicit_same_declared_type_uses_expanded_qname_not_prefix_spelling() {
    // XSD1.0 Structures 3.3.4(4) permits an explicit local type equal to the
    // declaration. Its QName must be expanded by the original XML owner;
    // unfamiliar/derived types remain unassessed rather than accepted by name.
    use structured_xades::scalar::{QNameFact, QNameValue};
    for (namespace, local, accepted) in [
        (Some(XADES), "SignedPropertiesType", true),
        (Some("urn:foreign"), "SignedPropertiesType", false),
        (Some(XADES), "SignedSignaturePropertiesType", false),
        (None, "SignedPropertiesType", false),
    ] {
        let mut xml = fixture();
        add(
            &mut xml,
            3,
            Name {
                namespace: "http://www.w3.org/2001/XMLSchema-instance",
                local: "type",
            },
            None,
        );
        xml.qname_routes.push(TypeRoute {
            node: 3,
            fact: QNameFact::Value(QNameValue {
                namespace,
                local_name: local,
            }),
        });
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let held = memory.used();
        let result = attributes::check_prepared(&prepared, &access);
        if accepted {
            result.unwrap();
        } else {
            assert!(matches!(
                result,
                Err(attributes::Error::InstanceUnassessed {
                    node: 3,
                    kind: attributes::InstanceAttribute::Type
                })
            ));
        }
        assert_eq!(memory.used(), held);
    }
}

#[test]
fn no_namespace_schema_hint_uses_original_any_uri_without_schema_acquisition() {
    // XSD1.0 Structures 3.2.7 declares this built-in attribute as anyURI;
    // a hint neither changes the pinned XAdES declaration nor requests a fetch.
    // Retain malformed/unsupported/missing owner facts, never infer validity
    // from the schema-location spelling or label the supported hint unassessed.
    let name = Name {
        namespace: "http://www.w3.org/2001/XMLSchema-instance",
        local: "noNamespaceSchemaLocation",
    };
    for fact in [
        Fact::Valid,
        Fact::Malformed,
        Fact::Unsupported,
        Fact::Absent,
    ] {
        let mut xml = fixture();
        add(&mut xml, 3, name, None);
        xml.scalar_routes.push(scalar_checks::attribute_route(
            3,
            name,
            Datatype::AnyUri,
            fact,
        ));
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let held = memory.used();
        let result = attributes::check_prepared(&prepared, &access);
        if fact == Fact::Valid {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(attributes::Error::Scalar(
                structured_xades::scalar::Error::Value { node: 3, datatype: Datatype::AnyUri, fact: actual }
            )) if actual == fact));
        }
        assert_eq!(memory.used(), held);
    }
}

#[test]
fn declared_xades_elements_forbid_even_false_xsi_nil() {
    // XSD1.0 Structures 3.3.4(3.1) forbids the ATTRIBUTE, not just nil=true,
    // when nillable defaults to false. Both pinned XAdES schemas omit nillable.
    // No lexical boolean callback or schema acquisition may precede this gate.
    for selected in 0..3 {
        let mut xml = fixture();
        let node = if selected < 2 {
            selected + 2
        } else {
            let role = xml.nodes.len();
            xml.nodes.push(element(Some(4), XADES, "SignerRoleV2"));
            let roles = xml.nodes.len();
            xml.nodes.push(element(Some(role), XADES, "ClaimedRoles"));
            let opaque = xml.nodes.len();
            xml.nodes.push(element(Some(roles), XADES, "ClaimedRole"));
            opaque
        };
        add(
            &mut xml,
            node,
            Name {
                namespace: "http://www.w3.org/2001/XMLSchema-instance",
                local: "nil",
            },
            None,
        );
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let held = memory.used();
        assert!(matches!(
            attributes::check_prepared(&prepared, &access),
            Err(attributes::Error::Unexpected { node: found, attribute })
                if found == node && attribute == usize::from(node == 2)
        ));
        assert_eq!(memory.used(), held);
    }
}

#[test]
fn schema_instance_is_unassessed_not_malformed_and_visitor_cause_is_not_overwritten() {
    // A valid-looking xsi:type still needs original QName/derivation facts.
    // Mutation while unwinding an earlier refusal must not replace its cause.
    for instance in [false, true] {
        let mut xml = fixture();
        add(
            &mut xml,
            3,
            Name {
                namespace: if instance {
                    "http://www.w3.org/2001/XMLSchema-instance"
                } else {
                    "urn:foreign"
                },
                local: if instance { "type" } else { "Id" },
            },
            None,
        );
        xml.attribute_routes.last_mut().unwrap().change_on_refusal = true;
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = structured_xades::pki::bind_counters::<Tree, _, ()>(
            prepared.bound(),
            &access,
            |_, _| panic!("no counter"),
        )
        .unwrap();
        let held = memory.used();
        let generation = xml.generation.get();
        let result = attributes::check(&prepared, &counters, &access);
        if instance {
            assert!(matches!(
                result,
                Err(attributes::Error::InstanceUnassessed {
                    node: 3,
                    kind: attributes::InstanceAttribute::Type
                })
            ));
        } else {
            assert!(matches!(
                result,
                Err(attributes::Error::Unexpected {
                    node: 3,
                    attribute: 0
                })
            ));
        }
        assert_eq!(xml.generation.get(), generation + 1);
        assert_eq!(memory.used(), held);
    }
}

#[test]
fn attribute_scope_and_late_current_refusals_release_all_scratch() {
    // Retained preparation does not fund a new traversal. The one-less work
    // case fails at the final enclosing query after every temporary frame drops.
    let xml = fixture();
    let storage = funded();
    let access = Access::new(&xml, xml.snapshot(), &storage);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
    let counters =
        structured_xades::pki::bind_counters::<Tree, _, ()>(prepared.bound(), &access, |_, _| {
            panic!("no counter")
        })
        .unwrap();
    let held = storage.used();
    let spent = storage.work_used();
    let probe = funded();
    attributes::check(
        &prepared,
        &counters,
        &Access::new(&xml, xml.snapshot(), &probe),
    )
    .unwrap();
    let full = probe.work_used();
    assert_eq!(probe.used(), 0);
    for (capacity, work) in [(65536, 0), (0, full), (65536, full - 1)] {
        let query = Memory::new(Arc::new(MemoryAccount::new(capacity, work)));
        let result = attributes::check(
            &prepared,
            &counters,
            &Access::new(&xml, xml.snapshot(), &query),
        );
        if capacity == 0 {
            assert!(matches!(
                result,
                Err(attributes::Error::Access(AccessError::Resource {
                    node: 2,
                    cause: MemoryError::LimitExceeded
                }))
            ));
        } else {
            assert!(matches!(
                result,
                Err(attributes::Error::Access(AccessError::Resource {
                    node: 0,
                    cause: MemoryError::WorkExceeded
                }))
            ));
        }
        assert_eq!(query.used(), 0);
        assert_eq!(storage.used(), held);
        assert_eq!(storage.work_used(), spent);
        if work == full - 1 {
            assert_eq!(query.work_used(), full - 1);
        }
    }
    let mut foreign = xml.snapshot();
    foreign.document += 1;
    let calls = xml.attribute_calls.get();
    assert!(matches!(
        attributes::check(&prepared, &counters, &Access::new(&xml, foreign, &probe)),
        Err(attributes::Error::Foreign)
    ));
    assert_eq!(xml.attribute_calls.get(), calls);
}

#[test]
fn counter_attributes_are_checked_without_demanding_a_child_baseline() {
    // The actual counter is allowed to lack root B properties, but an extra
    // undeclared attribute on its own SignedProperties cannot disappear.
    xml_digest::with_checked_path(|path, _, _, memory| {
        let mut xml = fixture();
        xml.key_association = certificate::KeyAssociation::Same;
        let (child, _, _) = append_nested_counter(&mut xml, 7, 12, true);
        let layout = container::locate(&Access::new(&xml, xml.snapshot(), memory), child).unwrap();
        add(
            &mut xml,
            layout.qualifying(),
            Name {
                namespace: "",
                local: "Target",
            },
            Some(Datatype::AnyUri),
        );
        add(
            &mut xml,
            layout.signed(),
            Name {
                namespace: "",
                local: "Encoding",
            },
            None,
        );
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        let held = memory.used();
        assert!(
            matches!(attributes::check(&prepared,&counters,&access),Err(attributes::Error::Unexpected{node,attribute:0}) if node==layout.signed())
        );
        assert_eq!(memory.used(), held);
    });
}
