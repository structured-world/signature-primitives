//! Scripted lexical-owner facts, not a second XML/XSD parser or native oracle.

use super::*;
use structured_xades::scalar::{self, Datatype, Fact, ScalarXml, UriValue, UriXml};

pub(super) struct UriRoute {
    node: usize,
    text: &'static str,
    fact: Fact,
    change: bool,
}

impl UriXml for Tree {
    fn with_uri<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        source: LexicalSource<'_>,
        execution: &W,
        visitor: impl for<'view> FnOnce(UriValue<'view>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Cause, VE>> {
        self.check(snapshot, node).map_err(VisitError::Processing)?;
        if source != LexicalSource::SimpleContent {
            return Err(VisitError::Processing(Cause::Source));
        }
        for route in &self.uri_routes {
            execution
                .charge_work(1)
                .map_err(|cause| VisitError::Processing(Cause::Resource(cause)))?;
            if route.node == node {
                // Simulates a native joined/collapsed temporary, NOT XML/XSD
                // normalization. The visitor cannot let this string escape.
                let mut joined = execution.vector();
                let value = match route.fact {
                    Fact::Valid => {
                        joined
                            .try_extend_from_slice(route.text.as_bytes())
                            .map_err(|cause| VisitError::Processing(Cause::Resource(cause)))?;
                        UriValue::Valid(core::str::from_utf8(&joined).unwrap())
                    }
                    Fact::Absent => UriValue::Absent,
                    Fact::ComplexContent => UriValue::ComplexContent,
                    Fact::Malformed => UriValue::Malformed,
                    Fact::Unsupported => UriValue::Unsupported,
                };
                let result = visitor(value).map_err(VisitError::Visitor);
                if route.change {
                    self.generation.set(self.generation.get() + 1);
                }
                return result;
            }
        }
        Err(VisitError::Processing(Cause::Incomplete))
    }
}

pub(super) struct Route {
    node: usize,
    source: LexicalSource<'static>,
    datatype: Datatype,
    fact: Fact,
    change: bool,
}

impl ScalarXml for Tree {
    fn scalar<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        source: LexicalSource<'_>,
        datatype: Datatype,
        execution: &W,
    ) -> Result<Fact, Cause> {
        self.check(snapshot, node)?;
        self.scalar_calls.set(self.scalar_calls.get() + 1);
        for route in &self.scalar_routes {
            execution.charge_work(1).map_err(Cause::Resource)?;
            if route.node == node && route.source == source && route.datatype == datatype {
                if route.change {
                    self.generation.set(self.generation.get() + 1);
                }
                return Ok(route.fact);
            }
        }
        Err(Cause::Incomplete)
    }
}

pub(super) fn route(node: usize, datatype: Datatype, fact: Fact) -> Route {
    Route {
        node,
        source: LexicalSource::SimpleContent,
        datatype,
        fact,
        change: false,
    }
}

pub(super) fn attribute_route(
    node: usize,
    name: Name<'static>,
    datatype: Datatype,
    fact: Fact,
) -> Route {
    let mut route = route(node, datatype, fact);
    route.source = LexicalSource::Attribute(name);
    route
}

fn policy_notice_fixture() -> (Tree, usize, usize, usize) {
    let (mut xml, _, policy) = policy_tree(false, false);
    let qualifiers = xml.nodes.len();
    xml.nodes
        .push(element(Some(policy), XADES, "SigPolicyQualifiers"));
    let qualifier = xml.nodes.len();
    xml.nodes
        .push(element(Some(qualifiers), XADES, "SigPolicyQualifier"));
    let uri = xml.nodes.len();
    xml.nodes.push(element(Some(qualifier), XADES, "SPURI"));
    let notice = xml.nodes.len();
    xml.nodes
        .push(element(Some(qualifier), XADES, "SPUserNotice"));
    let reference = xml.nodes.len();
    xml.nodes.push(element(Some(notice), XADES, "NoticeRef"));
    xml.nodes
        .push(element(Some(reference), XADES, "Organization"));
    let numbers = xml.nodes.len();
    xml.nodes
        .push(element(Some(reference), XADES, "NoticeNumbers"));
    let first = xml.nodes.len();
    xml.nodes.push(element(Some(numbers), XADES, "int"));
    let last = xml.nodes.len();
    xml.nodes.push(element(Some(numbers), XADES, "int"));
    // Opaque open content is not recursively interpreted as policy grammar.
    let foreign = xml.nodes.len();
    xml.nodes
        .push(element(Some(qualifier), "urn:foreign", "wrapper"));
    xml.nodes.push(element(Some(foreign), XADES, "int"));
    xml.scalar_routes
        .push(route(uri, Datatype::AnyUri, Fact::Valid));
    xml.scalar_routes
        .push(route(first, Datatype::Integer, Fact::Valid));
    xml.scalar_routes
        .push(route(last, Datatype::Integer, Fact::Valid));
    (xml, uri, first, last)
}

#[test]
fn policy_qualifiers_check_each_original_integer_without_machine_narrowing() {
    // A valid first number never masks a late malformed/unsupported number.
    // The owner sees xsd:integer, not xsd:int/positiveInteger or a u64 sentinel.
    for fact in [
        Fact::Valid,
        Fact::Malformed,
        Fact::Unsupported,
        Fact::ComplexContent,
    ] {
        let (mut xml, _, _, last) = policy_notice_fixture();
        xml.scalar_routes[2].fact = fact;
        let source = funded();
        let access = Access::new(&xml, xml.snapshot(), &source);
        let signed = signed_roles(&xml, &source).unwrap();
        let reading = policy::read(&access, &signed).unwrap().unwrap();
        let held = source.used();
        let before = source.work_used();
        let query = funded();
        let access = Access::new(&xml, xml.snapshot(), &query);
        let result = policy::check_qualifier_syntax(&access, &reading);
        if fact == Fact::Valid {
            result.unwrap();
        } else {
            assert!(
                matches!(result, Err(policy::SyntaxError::Scalar(scalar::Error::Value {
                node, datatype: Datatype::Integer, fact: actual
            })) if node == last && actual == fact)
            );
        }
        assert_eq!(xml.scalar_calls.get(), 3);
        assert_eq!(source.used(), held);
        assert_eq!(source.work_used(), before);
        assert_eq!(query.used(), 0);
        assert_eq!(xml.streamed.get(), 0);
    }
}

#[test]
fn qualifier_syntax_preserves_late_and_initial_refusal_without_partial_success() {
    // Syntax runs under the new query, independent of retained metadata storage.
    // Denial at the last admission still cannot return a successful subset.
    let (xml, _, _, _) = policy_notice_fixture();
    let source = funded();
    let access = Access::new(&xml, xml.snapshot(), &source);
    let signed = signed_roles(&xml, &source).unwrap();
    let reading = policy::read(&access, &signed).unwrap().unwrap();
    let query = funded();
    policy::check_qualifier_syntax(&Access::new(&xml, xml.snapshot(), &query), &reading).unwrap();
    let cost = query.work_used();
    for budget in [0, cost - 1] {
        let query = Memory::new(Arc::new(MemoryAccount::new(0, budget)));
        assert!(matches!(
            policy::check_qualifier_syntax(&Access::new(&xml, xml.snapshot(), &query), &reading),
            Err(policy::SyntaxError::Structure(properties::Error::Access(
                AccessError::Resource {
                    cause: MemoryError::WorkExceeded,
                    ..
                }
            )))
        ));
        assert_eq!(query.used(), 0);
    }
    xml.generation.set(2);
    assert!(matches!(
        policy::check_qualifier_syntax(&Access::new(&xml, reading.snapshot(), &query), &reading),
        Err(policy::SyntaxError::Structure(properties::Error::Access(
            AccessError::Changed { .. }
        )))
    ));
}

#[test]
fn lexical_facts_remain_distinct_and_do_not_create_a_schema_or_signature_receipt() {
    // Unsupported is not Malformed, and absent/complex is not a valid empty
    // scalar. Each requested datatype uses exactly the original source route.
    for datatype in [Datatype::AnyUri, Datatype::Id, Datatype::Integer] {
        for fact in [
            Fact::Valid,
            Fact::Absent,
            Fact::ComplexContent,
            Fact::Malformed,
            Fact::Unsupported,
        ] {
            let mut xml = Tree::normal();
            xml.scalar_routes.push(route(0, datatype, fact));
            let memory = funded();
            let access = Access::new(&xml, xml.snapshot(), &memory);
            let result = scalar::check(&access, 0, LexicalSource::SimpleContent, datatype);
            if fact == Fact::Valid {
                result.unwrap();
            } else {
                assert!(
                    matches!(result, Err(scalar::Error::Value {node:0,datatype:actual,fact:actual_fact}) if actual==datatype && actual_fact==fact)
                );
            }
            assert_eq!(xml.scalar_calls.get(), 1);
            assert_eq!(memory.used(), 0);
            assert_eq!(xml.streamed.get(), 0);
        }
    }
}

#[test]
fn lexical_query_preserves_foreign_generation_and_current_work_refusal() {
    // Zero dispatch work never reaches the owner; an owner-side refusal is
    // still the original cause. Successful callbacks cannot hide a mutation.
    let mut xml = Tree::normal();
    xml.scalar_routes
        .push(route(0, Datatype::AnyUri, Fact::Valid));
    for (work, calls) in [(0, 0), (1, 1)] {
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, work)));
        let access = Access::new(&xml, xml.snapshot(), &memory);
        xml.scalar_calls.set(0);
        let result = scalar::check(&access, 0, LexicalSource::SimpleContent, Datatype::AnyUri);
        if work == 0 {
            assert!(matches!(
                result,
                Err(scalar::Error::Access(AccessError::Resource {
                    node: 0,
                    cause: MemoryError::WorkExceeded
                }))
            ));
        } else {
            assert!(matches!(
                result,
                Err(scalar::Error::Access(AccessError::Xml(Cause::Resource(
                    MemoryError::WorkExceeded
                ))))
            ));
        }
        assert_eq!(xml.scalar_calls.get(), calls);
        assert_eq!(memory.used(), 0);
    }
    let memory = funded();
    let mut snapshot = xml.snapshot();
    snapshot.document += 1;
    let access = Access::new(&xml, snapshot, &memory);
    xml.scalar_calls.set(0);
    assert!(matches!(
        scalar::check(&access, 0, LexicalSource::SimpleContent, Datatype::AnyUri),
        Err(scalar::Error::Access(AccessError::Changed { node: 0 }))
    ));
    assert_eq!(xml.scalar_calls.get(), 0);
    xml.scalar_routes[0].change = true;
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        scalar::check(&access, 0, LexicalSource::SimpleContent, Datatype::AnyUri),
        Err(scalar::Error::Access(AccessError::Changed { node: 0 }))
    ));
    assert_eq!(xml.scalar_calls.get(), 1);
}

fn identifier_fixture() -> (Tree, usize, usize, usize) {
    let mut xml = Tree::normal();
    let parent = xml.nodes.len();
    xml.nodes.push(element(None, XADES, "ObjectIdentifier"));
    let identifier = xml.nodes.len();
    xml.nodes.push(element(Some(parent), XADES, "Identifier"));
    let documentation = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "DocumentationReferences"));
    let reference = xml.nodes.len();
    xml.nodes.push(element(
        Some(documentation),
        XADES,
        "DocumentationReference",
    ));
    xml.scalar_routes
        .push(route(identifier, Datatype::AnyUri, Fact::Valid));
    xml.scalar_routes
        .push(route(reference, Datatype::AnyUri, Fact::Valid));
    (xml, parent, identifier, reference)
}

#[test]
fn oid_qualifier_uses_complete_scoped_uri_and_the_shared_decimal_kernel() {
    // RFC3061 2/3: namespace case is insignificant, decimal arcs have no
    // padding/escapes/descriptors. OIDAsURI explicitly excludes URNs. Ordinary
    // URI identity does not invent a numeric OID or imply permanent assignment.
    for (qualifier, text, expected) in [
        (Some("OIDAsURN"), "urn:oid:1.2.840.113549", 1),
        (Some("OIDAsURN"), "URN:OID:2.18446744073709551616", 1),
        (Some("OIDAsURN"), "urn:oid:2.01", 2),
        (Some("OIDAsURN"), "urn:oid:1.40", 2),
        (Some("OIDAsURN"), "urn:oid:1.2%2e3", 2),
        (Some("OIDAsURN"), "urn:oid:1.2#tail", 2),
        (Some("OIDAsURN"), "urn:example:1.2", 3),
        (Some("OIDAsURI"), "UrN:example:1.2", 3),
        (Some("OIDAsURI"), "https://example.test/oid/1.2", 0),
        (None, "urn:example:object", 0),
    ] {
        let (mut xml, parent, node, _) = identifier_fixture();
        xml.identifier_qualifier = qualifier;
        xml.uri_routes.push(UriRoute {
            node,
            text,
            fact: Fact::Valid,
            change: false,
        });
        let source = funded();
        let reading =
            identifier::read(&Access::new(&xml, xml.snapshot(), &source), parent).unwrap();
        let query = funded();
        let result = identifier::check_value(&Access::new(&xml, xml.snapshot(), &query), &reading);
        match expected {
            0 => assert!(matches!(result, Ok(identifier::Meaning::Uri))),
            1 => {
                let identifier::Meaning::Oid(oid) = result.unwrap() else {
                    panic!("numeric OID lost")
                };
                let suffix = &text[8..];
                let rendered = oid.as_oid().text(&query).unwrap();
                assert_eq!(rendered.as_str(&query).unwrap(), suffix);
                drop(rendered);
                assert!(query.used() > 0);
                drop(oid);
            }
            2 => assert!(
                matches!(result, Err(identifier::MeaningError::Oid { node: actual, cause })
                if actual == node && cause.code() == structured_asn1::ErrorCode::MalformedOid)
            ),
            3 => assert!(
                matches!(result, Err(identifier::MeaningError::Qualifier { node: actual }) if actual == node)
            ),
            _ => unreachable!("trusted fixture outcome"),
        }
        assert_eq!(query.used(), 0);
        assert_eq!(xml.streamed.get(), 0);
    }
}

#[test]
fn oid_meaning_preserves_source_value_and_resource_failures_after_temporary_drop() {
    // A caller error remains first even if a broken source mutates afterward;
    // no normalized temporary may escape, nor partial decimal owner survive.
    for fact in [
        Fact::Absent,
        Fact::ComplexContent,
        Fact::Malformed,
        Fact::Unsupported,
    ] {
        let (mut xml, parent, node, _) = identifier_fixture();
        xml.identifier_qualifier = Some("OIDAsURN");
        xml.uri_routes.push(UriRoute {
            node,
            text: "urn:oid:1.2",
            fact,
            change: true,
        });
        let query = funded();
        let reading = identifier::read(&Access::new(&xml, xml.snapshot(), &query), parent).unwrap();
        assert!(
            matches!(identifier::check_value(&Access::new(&xml, xml.snapshot(), &query), &reading),
            Err(identifier::MeaningError::Value { node: actual, fact: actual_fact }) if actual == node && actual_fact == fact)
        );
        assert_eq!(query.used(), 0);
    }
    let (mut xml, parent, node, _) = identifier_fixture();
    xml.identifier_qualifier = Some("OIDAsURN");
    xml.uri_routes.push(UriRoute {
        node,
        text: "urn:oid:2.18446744073709551616",
        fact: Fact::Valid,
        change: false,
    });
    let source = funded();
    let reading = identifier::read(&Access::new(&xml, xml.snapshot(), &source), parent).unwrap();
    let query = funded();
    drop(identifier::check_value(&Access::new(&xml, xml.snapshot(), &query), &reading).unwrap());
    let cost = query.work_used();
    for (storage, work) in [(0, cost), (4096, 0), (4096, cost - 1)] {
        let query = Memory::new(Arc::new(MemoryAccount::new(storage, work)));
        let result = identifier::check_value(&Access::new(&xml, xml.snapshot(), &query), &reading);
        match (storage, work) {
            (0, _) => assert!(matches!(
                result,
                Err(identifier::MeaningError::Access(AccessError::Xml(
                    Cause::Resource(MemoryError::LimitExceeded)
                )))
            )),
            (_, 0) => assert!(matches!(
                result,
                Err(identifier::MeaningError::Access(AccessError::Resource {
                    cause: MemoryError::WorkExceeded,
                    ..
                }))
            )),
            _ => assert!(
                matches!(result, Err(identifier::MeaningError::Oid {cause, ..}) if cause.code() == structured_asn1::ErrorCode::LimitExceeded(structured_asn1::Limit::Work))
            ),
        }
        assert_eq!(query.used(), 0);
    }
    assert_eq!(source.used(), 0);
}

#[test]
fn prepared_uri_pass_checks_identifier_meaning_without_retaining_scratch() {
    // Public preparation wiring must execute meaning, not just structure or
    // anyURI validity. Both success and malformed OID release temporary storage.
    for bad in [false, true] {
        let (mut xml, _, _, _) = header_tree();
        let objects = xml.nodes.len();
        xml.nodes
            .push(element(Some(3), XADES, "SignedDataObjectProperties"));
        let format = xml.nodes.len();
        xml.nodes
            .push(element(Some(objects), XADES, "DataObjectFormat"));
        xml.scalar_routes.push(attribute_route(
            format,
            Name {
                namespace: "",
                local: "ObjectReference",
            },
            Datatype::AnyUri,
            Fact::Valid,
        ));
        let identifier = xml.nodes.len();
        xml.nodes
            .push(element(Some(format), XADES, "ObjectIdentifier"));
        let value = xml.nodes.len();
        xml.nodes
            .push(element(Some(identifier), XADES, "Identifier"));
        // The schema places ObjectIdentifier BEFORE MimeType. Construct source
        // order correctly instead of weakening the existing order assertion.
        xml.mime(format);
        xml.object_reference = Some("#direct");
        xml.nodes
            .push(element(Some(8), DS, "CanonicalizationMethod"));
        xml.nodes
            .push(element(Some(8), XADES, "EncapsulatedTimeStamp"));
        xml.uri_routes.push(UriRoute {
            node: value,
            text: if bad {
                "urn:oid:1.40"
            } else {
                "urn:oid:1.2.840"
            },
            fact: Fact::Valid,
            change: false,
        });
        xml.identifier_qualifier = Some("OIDAsURN");
        let source = funded();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), &source),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let held = source.used();
        let before = source.work_used();
        let query = funded();
        let result = prepare::check_uris(&prepared, &Access::new(&xml, xml.snapshot(), &query));
        if bad {
            assert!(
                matches!(result,Err(prepare::UriError::Identifier(identifier::CheckError::Meaning(identifier::MeaningError::Oid{node,cause})))
                if node==value && cause.code()==structured_asn1::ErrorCode::MalformedOid)
            );
        } else {
            result.unwrap();
        }
        assert_eq!(query.used(), 0);
        assert_eq!(source.used(), held);
        assert_eq!(source.work_used(), before);
        assert_eq!(xml.key_projection.get(), None);
        assert_eq!(xml.streamed.get(), 0);
    }
}

#[test]
fn late_documentation_refusal_drops_an_already_converted_numeric_oid() {
    // Retaining a valid numeric OID must not turn a later unsupported URI into
    // success, nor leak the OID or scoped normalized temporary on that refusal.
    let (mut xml, parent, node, documentation) = identifier_fixture();
    xml.identifier_qualifier = Some("OIDAsURN");
    xml.uri_routes.push(UriRoute {
        node,
        text: "urn:oid:2.18446744073709551616",
        fact: Fact::Valid,
        change: false,
    });
    xml.scalar_routes[1].fact = Fact::Unsupported;
    let source = funded();
    let reading = identifier::read(&Access::new(&xml, xml.snapshot(), &source), parent).unwrap();
    let query = funded();
    assert!(
        matches!(identifier::check(&Access::new(&xml,xml.snapshot(),&query),&reading),
        Err(identifier::CheckError::Scalar(scalar::Error::Value{node:actual,datatype:Datatype::AnyUri,fact:Fact::Unsupported})) if actual==documentation)
    );
    assert_eq!(query.used(), 0);
    assert_eq!(source.used(), 0);
    assert_eq!(xml.scalar_calls.get(), 1);
}

#[test]
fn identifier_checks_every_original_uri_including_late_documentation() {
    // The identifier and documentation share the original structural reader.
    // A valid first field never masks the later unsupported/malformed field.
    for fact in [Fact::Valid, Fact::Malformed, Fact::Unsupported] {
        let (mut xml, parent, original, reference) = identifier_fixture();
        xml.scalar_routes[1].fact = fact;
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let result = identifier::read_uri_syntax(&access, parent);
        if fact == Fact::Valid {
            let reading = result.unwrap();
            assert_eq!(reading.identifier, original);
            assert_eq!(reading.documentation, xml.nodes[reference].parent);
            assert_eq!(reading.qualifier, None);
        } else {
            assert!(
                matches!(result,Err(identifier::UriError::Scalar(scalar::Error::Value{node,datatype:Datatype::AnyUri,fact:actual})) if node==reference && actual==fact)
            );
        }
        assert_eq!(xml.scalar_calls.get(), 2);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn optional_documentation_is_not_fabricated_and_attributes_keep_their_exact_source() {
    // Schema absence suppresses a field obligation, not a failed requested
    // value. Attribute queries preserve expanded name and datatype identity.
    let (mut xml, parent, original, reference) = identifier_fixture();
    let documentation = xml.nodes[reference].parent.unwrap();
    xml.nodes[documentation].parent = None;
    xml.scalar_routes.truncate(1);
    let source = LexicalSource::Attribute(Name {
        namespace: "",
        local: "Id",
    });
    let mut attribute = route(parent, Datatype::Id, Fact::Valid);
    attribute.source = source;
    xml.scalar_routes.push(attribute);
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let reading = identifier::read_uri_syntax(&access, parent).unwrap();
    assert_eq!(reading.identifier, original);
    assert_eq!(reading.documentation, None);
    assert_eq!(xml.scalar_calls.get(), 1);
    scalar::check(&access, parent, source, Datatype::Id).unwrap();
    assert!(matches!(
        scalar::check(
            &access,
            parent,
            LexicalSource::Attribute(Name {
                namespace: "urn:foreign",
                local: "Id"
            }),
            Datatype::Id
        ),
        Err(scalar::Error::Access(AccessError::Xml(Cause::Incomplete)))
    ));
    assert_eq!(xml.scalar_calls.get(), 3);
    assert_eq!(memory.used(), 0);
}

#[test]
fn retained_format_encoding_uses_current_query_and_preserves_optional_absence() {
    // A retained format never grants new lexical work credit from its parse.
    // An absent optional element needs no scalar callback; present malformed
    // and unsupported fields keep their source and cause instead of disappearing.
    for fact in [
        None,
        Some(Fact::Valid),
        Some(Fact::Malformed),
        Some(Fact::Unsupported),
    ] {
        let (mut xml, parent, _) = data_format_tree();
        let encoding = fact.map(|fact| {
            let node = xml.nodes.len();
            xml.nodes.push(element(Some(parent), XADES, "Encoding"));
            xml.scalar_routes.push(route(node, Datatype::AnyUri, fact));
            node
        });
        let storage = funded();
        let signed = signed_roles(&xml, &storage).unwrap();
        let original =
            format::read(&Access::new(&xml, xml.snapshot(), &storage), &signed, 0).unwrap();
        let held = storage.used();
        let spent = storage.work_used();
        let query = Memory::new(Arc::new(MemoryAccount::new(0, 1000)));
        let access = Access::new(&xml, xml.snapshot(), &query);
        let result = format::check_encoding(&access, &original);
        if let Some(expected @ (Fact::Malformed | Fact::Unsupported)) = fact {
            assert!(
                matches!(result,Err(scalar::Error::Value{node,datatype:Datatype::AnyUri,fact:actual}) if Some(node)==encoding && actual==expected)
            );
        } else {
            result.unwrap();
        }
        assert_eq!(xml.scalar_calls.get(), usize::from(fact.is_some()));
        assert_eq!(storage.work_used(), spent);
        assert_eq!(storage.used(), held);
        assert_eq!(query.used(), 0);
        let calls = xml.scalar_calls.get();
        let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        let denied_access = Access::new(&xml, xml.snapshot(), &denied);
        assert!(
            matches!(format::check_encoding(&denied_access,&original),Err(scalar::Error::Access(AccessError::Resource{node,..})) if node==parent)
        );
        assert_eq!(xml.scalar_calls.get(), calls);
        xml.generation.set(xml.generation.get() + 1);
        let foreign = Access::new(&xml, xml.snapshot(), &query);
        assert!(
            matches!(format::check_encoding(&foreign,&original),Err(scalar::Error::Access(AccessError::Changed{node})) if node==parent)
        );
        assert_eq!(xml.scalar_calls.get(), calls);
    }
}
