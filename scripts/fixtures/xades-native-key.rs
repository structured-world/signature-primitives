//! Actual native XML/P-256 key-bridge tests, not whole-profile qualification.
//!
//! Other XML/reference capabilities deliberately return an error: this fixture
//! cannot accidentally act as a successful complete XML adapter. Certificates
//! below are synthetic parseable carriers, not trusted/validated issuer paths.

use core::{cell::Cell, convert::Infallible};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, Work},
};
use structured_pkix::{Certificate, path::WorkingKey};
use structured_xades::{
    binding::{Reference, SignatureXml, Status, Target},
    certificate::{CertificateXml, KeyAssociation},
    xml::{Name, Node, Snapshot, Xml},
};
use structured_xades::{
    identifier,
    reference::{LexicalSource, VisitError},
    scalar::{UriValue, UriXml},
    xml::Access,
};
use xml_sec::{
    XmlDocument,
    c14n::{C14nAlgorithm, C14nMode},
    document::{DocumentIdentity, NodeIdentity},
    xmldsig::*,
};

fn account() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28)))
}

#[derive(Debug)]
enum UriSourceError {
    NotProvided,
    Foreign,
    Native(xml_sec::xmldsig::extension::ScalarError),
}

// Capability-specific scalar fixture: it cannot fabricate successful DOM or
// signature/reference receipts. The actual native scalar kernel supplies ALL
// normalization, joining, schema validity, identity and work/capacity facts.
struct NativeUri<'view>(xml_sec::document::DocumentView<'view>);
impl Xml for NativeUri<'_> {
    type Id = NodeIdentity;
    type Document = DocumentIdentity;
    type Generation = u64;
    type Error = UriSourceError;
    fn snapshot(&self) -> Snapshot<DocumentIdentity, u64> {
        Snapshot {
            document: self.0.identity(),
            generation: self.0.generation(),
        }
    }
    fn inspect<R, Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: &Q,
        _: impl for<'view> FnOnce(Node<'view>) -> R,
    ) -> Result<R, Self::Error> {
        Err(UriSourceError::NotProvided)
    }
    fn attribute<R, Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: Name<'_>,
        _: &Q,
        _: impl for<'view> FnOnce(Option<&'view str>) -> R,
    ) -> Result<R, Self::Error> {
        Err(UriSourceError::NotProvided)
    }
    fn first_child<Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: &Q,
    ) -> Result<Option<NodeIdentity>, Self::Error> {
        Err(UriSourceError::NotProvided)
    }
    fn next_sibling<Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: NodeIdentity,
        _: &Q,
    ) -> Result<Option<NodeIdentity>, Self::Error> {
        Err(UriSourceError::NotProvided)
    }
}
impl UriXml for NativeUri<'_> {
    fn with_uri<R, VE, Q: Work>(
        &self,
        snapshot: Snapshot<DocumentIdentity, u64>,
        node: NodeIdentity,
        source: LexicalSource<'_>,
        work: &Q,
        visitor: impl for<'view> FnOnce(UriValue<'view>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Self::Error, VE>> {
        use xml_sec::xmldsig::extension::{
            self, InspectionError, ScalarFact, ScalarType, ScalarValue,
        };
        if snapshot != self.snapshot() {
            return Err(VisitError::Processing(UriSourceError::Foreign));
        }
        let source = match source {
            LexicalSource::SimpleContent => xml_sec::xmldsig::LexicalSource::SimpleContent,
            LexicalSource::Attribute(name) => xml_sec::xmldsig::LexicalSource::Attribute {
                namespace: if name.namespace.is_empty() {
                    None
                } else {
                    Some(name.namespace)
                },
                local_name: name.local,
            },
        };
        match extension::with_scalar(self.0, node, source, ScalarType::AnyUri, work, |original| {
            let value = match original.fact {
                ScalarFact::Absent => UriValue::Absent,
                ScalarFact::ComplexContent => UriValue::ComplexContent,
                ScalarFact::Malformed => UriValue::Malformed,
                ScalarFact::Unsupported => UriValue::Unsupported,
                ScalarFact::UnboundPrefix(_) => unreachable!("non-QName request"),
                ScalarFact::Value(ScalarValue::AnyUri(text)) => UriValue::Valid(text),
                ScalarFact::Value(_) => {
                    unreachable!("native AnyUri returned another requested datatype")
                }
            };
            visitor(value)
        }) {
            Ok(value) => Ok(value),
            Err(InspectionError::Processing(cause)) => {
                Err(VisitError::Processing(UriSourceError::Native(cause)))
            }
            Err(InspectionError::Visitor(cause)) => Err(VisitError::Visitor(cause)),
        }
    }
}

impl structured_xades::scalar::TextXml for NativeUri<'_> {
    fn with_text<R, VE, Q: Work>(
        &self,
        snapshot: Snapshot<DocumentIdentity, u64>,
        node: NodeIdentity,
        source: LexicalSource<'_>,
        work: &Q,
        visitor: impl for<'view> FnOnce(structured_xades::scalar::TextValue<'view>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Self::Error, VE>> {
        use structured_xades::scalar::TextValue;
        use xml_sec::xmldsig::extension::{self, InspectionError, ScalarFact, ScalarType};
        if snapshot != self.snapshot() {
            return Err(VisitError::Processing(UriSourceError::Foreign));
        }
        let source = match source {
            LexicalSource::SimpleContent => xml_sec::xmldsig::LexicalSource::SimpleContent,
            LexicalSource::Attribute(name) => xml_sec::xmldsig::LexicalSource::Attribute {
                namespace: if name.namespace.is_empty() {
                    None
                } else {
                    Some(name.namespace)
                },
                local_name: name.local,
            },
        };
        // Request ORIGINAL lexical data, deliberately no schema conversion.
        // Unsupported type semantics do not erase the separately returned text.
        match extension::with_scalar(
            self.0,
            node,
            source,
            ScalarType::Other {
                namespace: "urn:test:lexical-view",
                local_name: "original",
            },
            work,
            |original| {
                let value = match original.fact {
                    ScalarFact::Absent => TextValue::Absent,
                    ScalarFact::ComplexContent => TextValue::ComplexContent,
                    _ => TextValue::Present(
                        original
                            .lexical
                            .expect("present simple source has original lexical text"),
                    ),
                };
                visitor(value)
            },
        ) {
            Ok(value) => Ok(value),
            Err(InspectionError::Processing(cause)) => {
                Err(VisitError::Processing(UriSourceError::Native(cause)))
            }
            Err(InspectionError::Visitor(cause)) => Err(VisitError::Visitor(cause)),
        }
    }
}

impl structured_xades::scalar::ScalarXml for NativeUri<'_> {
    fn scalar<Q: Work>(
        &self,
        snapshot: Snapshot<DocumentIdentity, u64>,
        node: NodeIdentity,
        source: LexicalSource<'_>,
        datatype: structured_xades::scalar::Datatype,
        work: &Q,
    ) -> Result<structured_xades::scalar::Fact, Self::Error> {
        use structured_xades::scalar::{Datatype, Fact};
        use xml_sec::xmldsig::extension::{self, InspectionError, ScalarFact, ScalarType};
        if snapshot != self.snapshot() {
            return Err(UriSourceError::Foreign);
        }
        let source = match source {
            LexicalSource::SimpleContent => xml_sec::xmldsig::LexicalSource::SimpleContent,
            LexicalSource::Attribute(name) => xml_sec::xmldsig::LexicalSource::Attribute {
                namespace: (!name.namespace.is_empty()).then_some(name.namespace),
                local_name: name.local,
            },
        };
        let datatype = match datatype {
            Datatype::Id => ScalarType::Id,
            Datatype::AnyUri => ScalarType::AnyUri,
            Datatype::Integer => ScalarType::Integer,
        };
        match extension::with_scalar(self.0, node, source, datatype, work, |original| {
            Ok::<_, Infallible>(match original.fact {
                ScalarFact::Absent => Fact::Absent,
                ScalarFact::ComplexContent => Fact::ComplexContent,
                ScalarFact::Malformed => Fact::Malformed,
                ScalarFact::Unsupported => Fact::Unsupported,
                ScalarFact::UnboundPrefix(_) => unreachable!("non-QName request"),
                ScalarFact::Value(_) => Fact::Valid,
            })
        }) {
            Ok(value) => Ok(value),
            Err(InspectionError::Processing(cause)) => Err(UriSourceError::Native(cause)),
            Err(InspectionError::Visitor(never)) => match never {},
        }
    }
}

impl structured_xades::scalar::QNameXml for NativeUri<'_> {
    fn with_qname<R, VE, Q: Work>(
        &self,
        snapshot: Snapshot<DocumentIdentity, u64>,
        node: NodeIdentity,
        source: LexicalSource<'_>,
        work: &Q,
        visitor: impl for<'view> FnOnce(structured_xades::scalar::QNameReading<'view>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Self::Error, VE>> {
        use structured_xades::scalar::{QNameFact, QNameReading, QNameValue};
        use xml_sec::xmldsig::extension::{
            self, InspectionError, ScalarFact, ScalarType, ScalarValue,
        };
        if snapshot != self.snapshot() {
            return Err(VisitError::Processing(UriSourceError::Foreign));
        }
        let source = match source {
            LexicalSource::SimpleContent => xml_sec::xmldsig::LexicalSource::SimpleContent,
            LexicalSource::Attribute(name) => xml_sec::xmldsig::LexicalSource::Attribute {
                namespace: (!name.namespace.is_empty()).then_some(name.namespace),
                local_name: name.local,
            },
        };
        match extension::with_scalar(self.0, node, source, ScalarType::QName, work, |read| {
            let fact = match read.fact {
                ScalarFact::Absent => QNameFact::Absent,
                ScalarFact::ComplexContent => QNameFact::ComplexContent,
                ScalarFact::Malformed => QNameFact::Malformed,
                ScalarFact::Unsupported => QNameFact::Unsupported,
                ScalarFact::UnboundPrefix(prefix) => QNameFact::UnboundPrefix(prefix),
                ScalarFact::Value(ScalarValue::QName(value)) => QNameFact::Value(QNameValue {
                    namespace: value.namespace,
                    local_name: value.local_name,
                }),
                ScalarFact::Value(_) => unreachable!("native QName returned another datatype"),
            };
            visitor(QNameReading {
                lexical: read.lexical,
                fact,
            })
        }) {
            Ok(value) => Ok(value),
            Err(InspectionError::Processing(cause)) => {
                Err(VisitError::Processing(UriSourceError::Native(cause)))
            }
            Err(InspectionError::Visitor(cause)) => Err(VisitError::Visitor(cause)),
        }
    }
}

impl structured_xades::attributes::AttributeXml for NativeUri<'_> {
    fn visit_attributes<VE, Q: Work>(
        &self,
        snapshot: Snapshot<DocumentIdentity, u64>,
        node: NodeIdentity,
        work: &Q,
        mut visitor: impl for<'view> FnMut(Name<'view>) -> Result<(), VE>,
    ) -> Result<(), VisitError<Self::Error, VE>> {
        use xml_sec::xmldsig::extension::{self, InspectionError};
        if snapshot != self.snapshot() {
            return Err(VisitError::Processing(UriSourceError::Foreign));
        }
        match extension::visit_direct_attributes(self.0, node, work, |original| {
            visitor(Name {
                namespace: original.namespace.unwrap_or(""),
                local: original.local_name,
            })
        }) {
            Ok(()) => Ok(()),
            Err(InspectionError::Processing(cause)) => {
                Err(VisitError::Processing(UriSourceError::Native(cause)))
            }
            Err(InspectionError::Visitor(cause)) => Err(VisitError::Visitor(cause)),
        }
    }
}

impl structured_xades::properties::DateTimeXml for NativeUri<'_> {
    fn date_time<Q: Work>(
        &self,
        snapshot: Snapshot<DocumentIdentity, u64>,
        node: NodeIdentity,
        work: &Q,
    ) -> Result<structured_xades::properties::DateTimeFact, Self::Error> {
        use structured_xades::properties::DateTimeFact;
        use xml_sec::xmldsig::extension::{
            self, InspectionError, ScalarFact, ScalarType, ScalarValue,
        };
        if snapshot != self.snapshot() {
            return Err(UriSourceError::Foreign);
        }
        match extension::with_scalar(
            self.0,
            node,
            xml_sec::xmldsig::LexicalSource::SimpleContent,
            ScalarType::DateTime,
            work,
            |original| {
                Ok::<_, Infallible>(match original.fact {
                    ScalarFact::Value(ScalarValue::DateTime(value)) => DateTimeFact::Valid {
                        timezone_minutes: value.timezone_minutes,
                    },
                    ScalarFact::Unsupported => DateTimeFact::Unsupported,
                    ScalarFact::UnboundPrefix(_) => unreachable!("non-QName request"),
                    ScalarFact::Absent | ScalarFact::ComplexContent | ScalarFact::Malformed => {
                        DateTimeFact::Malformed
                    }
                    ScalarFact::Value(_) => {
                        unreachable!("native DateTime returned another requested datatype")
                    }
                })
            },
        ) {
            Ok(value) => Ok(value),
            Err(InspectionError::Processing(cause)) => Err(UriSourceError::Native(cause)),
            Err(InspectionError::Visitor(never)) => match never {},
        }
    }
}

impl structured_xades::properties::CalendarXml for NativeUri<'_> {
    fn with_calendar<R, VE, Q: Work>(
        &self,
        snapshot: Snapshot<DocumentIdentity, u64>,
        node: NodeIdentity,
        work: &Q,
        visitor: impl for<'view> FnOnce(
            structured_xades::properties::CalendarFact<'view>,
        ) -> Result<R, VE>,
    ) -> Result<R, VisitError<Self::Error, VE>> {
        use structured_xades::properties::{CalendarFact, CalendarValue};
        use xml_sec::xmldsig::extension::{
            self, InspectionError, ScalarFact, ScalarType, ScalarValue,
        };
        if snapshot != self.snapshot() {
            return Err(VisitError::Processing(UriSourceError::Foreign));
        }
        match extension::with_scalar(
            self.0,
            node,
            xml_sec::xmldsig::LexicalSource::SimpleContent,
            ScalarType::DateTime,
            work,
            |original| {
                let fact = match original.fact {
                    ScalarFact::Value(ScalarValue::DateTime(value)) => {
                        CalendarFact::Value(CalendarValue {
                            negative_year: value.negative_year,
                            year_digits: value.year_digits,
                            month: value.month,
                            day: value.day,
                            hour: value.hour,
                            minute: value.minute,
                            second: value.second,
                            fraction_digits: value.fraction_digits,
                            timezone_minutes: value.timezone_minutes,
                        })
                    }
                    ScalarFact::Unsupported => CalendarFact::Unsupported,
                    ScalarFact::UnboundPrefix(_) => unreachable!("non-QName request"),
                    ScalarFact::Absent | ScalarFact::ComplexContent | ScalarFact::Malformed => {
                        CalendarFact::Malformed
                    }
                    ScalarFact::Value(_) => {
                        unreachable!("native dateTime returned another requested datatype")
                    }
                };
                visitor(fact)
            },
        ) {
            Ok(value) => Ok(value),
            Err(InspectionError::Processing(cause)) => {
                Err(VisitError::Processing(UriSourceError::Native(cause)))
            }
            Err(InspectionError::Visitor(cause)) => Err(VisitError::Visitor(cause)),
        }
    }
}

#[test]
fn actual_native_joined_uri_is_interpreted_before_temporary_storage_drops() {
    // Real XML entity/CDATA joining + XSD whitespace processing, then shared
    // arbitrary-width OID conversion. No authentication/permanence is inferred.
    let document = XmlDocument::parse(
        "<Identifier> \tURN:OID:2.184467<!--join--><![CDATA[440737]]>09551616&#xA;</Identifier>",
    )
    .unwrap();
    let memory = account();
    let oid = document.with_view(|view| {
        let source = NativeUri(view);
        let reading = identifier::Reading {
            identifier: view.root_element(),
            qualifier: Some(identifier::Qualifier::Urn),
            description: None,
            documentation: None,
        };
        let identifier::Meaning::Oid(oid) =
            identifier::check_value(&Access::new(&source, source.snapshot(), &memory), &reading)
                .unwrap()
        else {
            panic!("actual XML OID lost")
        };
        oid
    });
    drop(document);
    let text = oid.as_oid().text(&memory).unwrap();
    assert_eq!(text.as_str(&memory).unwrap(), "2.18446744073709551616");
    drop(text);
    assert!(memory.used() > 0);
    drop(oid);
    assert_eq!(memory.used(), 0);
}

#[test]
fn actual_native_qname_preserves_original_namespace_scope_and_query_refusals() {
    // Actual XML namespace/Unicode/whitespace interpretation belongs to the
    // selected native owner. Common projection preserves the original lexical
    // value and never treats an unbound prefix as a supported schema type.
    use structured_xades::scalar::{QNameFact, QNameValue, QNameXml};
    for (xml, lexical, expected) in [
        (
            "<v xmlns='urn:default'>  Type  </v>",
            "  Type  ",
            QNameFact::Value(QNameValue {
                namespace: Some("urn:default"),
                local_name: "Type",
            }),
        ),
        (
            "<v xmlns:p='urn:type'>p:<!--split--><![CDATA[Type]]></v>",
            "p:Type",
            QNameFact::Value(QNameValue {
                namespace: Some("urn:type"),
                local_name: "Type",
            }),
        ),
        (
            "<v>Type</v>",
            "Type",
            QNameFact::Value(QNameValue {
                namespace: None,
                local_name: "Type",
            }),
        ),
        (
            "<v>xml:lang</v>",
            "xml:lang",
            QNameFact::Value(QNameValue {
                namespace: Some("http://www.w3.org/XML/1998/namespace"),
                local_name: "lang",
            }),
        ),
        ("<v>p:Type</v>", "p:Type", QNameFact::UnboundPrefix("p")),
        ("<v>p:x:y</v>", "p:x:y", QNameFact::Malformed),
    ] {
        let document = XmlDocument::parse(xml).unwrap();
        document.with_view(|view| {
            let source = NativeUri(view);
            let memory = account();
            source
                .with_qname(
                    source.snapshot(),
                    view.root_element(),
                    LexicalSource::SimpleContent,
                    &memory,
                    |read| {
                        assert_eq!(read.lexical, Some(lexical));
                        assert_eq!(read.fact, expected);
                        Ok::<_, Infallible>(())
                    },
                )
                .unwrap();
            assert_eq!(memory.used(), 0);
        });
    }
    let document = XmlDocument::parse("<v xmlns:p='urn:type'>p:<!--split-->Type</v>").unwrap();
    document.with_view(|view| {
        let source = NativeUri(view);
        let measure = account();
        source
            .with_qname(
                source.snapshot(),
                view.root_element(),
                LexicalSource::SimpleContent,
                &measure,
                |_| Ok::<_, Infallible>(()),
            )
            .unwrap();
        let needed = measure.work_used();
        for exact in [false, true] {
            let memory = account();
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: u64::try_from(needed - usize::from(!exact)).unwrap(),
                    ..Limits::default()
                },
                memory.clone(),
            );
            let reader = parser.read(&[], 900).unwrap();
            let calls = Cell::new(0);
            let result = source.with_qname(
                source.snapshot(),
                view.root_element(),
                LexicalSource::SimpleContent,
                &reader.execution(),
                |_| {
                    calls.set(calls.get() + 1);
                    Err::<(), _>("original visitor")
                },
            );
            if exact {
                assert!(matches!(
                    result,
                    Err(VisitError::Visitor("original visitor"))
                ));
                assert_eq!(calls.get(), 1);
            } else {
                assert!(matches!(
                    result,
                    Err(VisitError::Processing(UriSourceError::Native(
                        xml_sec::xmldsig::extension::ScalarError::Resource(
                            structured_asn1::memory::MemoryError::WorkExceeded
                        )
                    )))
                ));
                assert_eq!(calls.get(), 0);
            }
            assert_eq!(memory.used(), 0);
        }
        let zero = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 28)));
        assert!(matches!(
            source.with_qname(
                source.snapshot(),
                view.root_element(),
                LexicalSource::SimpleContent,
                &zero,
                |_| -> Result<(), Infallible> { panic!("refused temporary") }
            ),
            Err(VisitError::Processing(UriSourceError::Native(
                xml_sec::xmldsig::extension::ScalarError::Resource(
                    structured_asn1::memory::MemoryError::LimitExceeded
                )
            )))
        ));
        assert_eq!(zero.used(), 0);
    });
}

#[test]
fn actual_native_scalar_and_datetime_projection_preserve_complete_schema_facts() {
    // Real XML joining, Unicode ID and XSD1.0 calendar/zone processing go
    // through the owner's one scalar kernel, not a Rust numeric/RFC3339 parser.
    use structured_xades::{
        properties::{DateTimeFact, DateTimeXml},
        scalar::{Datatype, Fact, ScalarXml},
    };
    for (text, expected) in [
        (
            "2026-10-16T12:<!--join--><![CDATA[30:00.123456789012345678901234567890Z]]>",
            DateTimeFact::Valid {
                timezone_minutes: Some(0),
            },
        ),
        (
            "2026-10-16T12:30:00+02:30",
            DateTimeFact::Valid {
                timezone_minutes: Some(150),
            },
        ),
        (
            "2026-10-16T12:30:00",
            DateTimeFact::Valid {
                timezone_minutes: None,
            },
        ),
        (
            "18446744073709551616-01-01T00:00:00Z",
            DateTimeFact::Valid {
                timezone_minutes: Some(0),
            },
        ),
        ("0000-01-01T00:00:00Z", DateTimeFact::Malformed),
        ("2026-02-30T00:00:00Z", DateTimeFact::Malformed),
        ("2026-10-16T12:<child/>30:00Z", DateTimeFact::Malformed),
    ] {
        let document = XmlDocument::parse(&format!("<value>{text}</value>")).unwrap();
        let memory = account();
        document.with_view(|view| {
            let source = NativeUri(view);
            assert_eq!(
                source
                    .date_time(source.snapshot(), view.root_element(), &memory)
                    .unwrap(),
                expected
            );
        });
        assert_eq!(memory.used(), 0);
    }
    let document =
        XmlDocument::parse("<value Id='  ключ  '>99999999999999999999999999999999999</value>")
            .unwrap();
    document.with_view(|view| {
        let source = NativeUri(view);
        let memory = account();
        assert_eq!(
            source
                .scalar(
                    source.snapshot(),
                    view.root_element(),
                    LexicalSource::Attribute(Name {
                        namespace: "",
                        local: "Id"
                    }),
                    Datatype::Id,
                    &memory
                )
                .unwrap(),
            Fact::Valid
        );
        assert_eq!(
            source
                .scalar(
                    source.snapshot(),
                    view.root_element(),
                    LexicalSource::Attribute(Name {
                        namespace: "",
                        local: "Missing"
                    }),
                    Datatype::Id,
                    &memory
                )
                .unwrap(),
            Fact::Absent
        );
        // Native integer validity must not narrow this value to a machine word.
        assert_eq!(
            source
                .scalar(
                    source.snapshot(),
                    view.root_element(),
                    LexicalSource::SimpleContent,
                    Datatype::Integer,
                    &memory
                )
                .unwrap(),
            Fact::Valid
        );
    });
}

#[test]
fn actual_native_integer_preserves_unbounded_original_values_and_source_forms() {
    // XAdES Number/NoticeNumbers/int use the XSD1.0 integer base datatype;
    // signs, leading zeroes and arbitrarily wide digits are not u64 parsing.
    // The same original attribute/content bridge owns XML joining and grammar.
    use structured_xades::scalar::{Datatype, Fact, ScalarXml};
    let wide = format!("-{}", "9".repeat(10_000));
    for (text, expected) in [
        (wide.as_str(), Fact::Valid),
        ("  +00000  ", Fact::Valid),
        ("-0", Fact::Valid),
        ("1 2", Fact::Malformed),
        ("+", Fact::Malformed),
        ("١٢", Fact::Malformed),
        ("1.0", Fact::Malformed),
        ("", Fact::Malformed),
    ] {
        let document =
            XmlDocument::parse(&format!("<value Number='{text}'>{text}</value>")).unwrap();
        let memory = account();
        document.with_view(|view| {
            let source = NativeUri(view);
            for original in [
                LexicalSource::SimpleContent,
                LexicalSource::Attribute(Name {
                    namespace: "",
                    local: "Number",
                }),
            ] {
                assert_eq!(
                    source
                        .scalar(
                            source.snapshot(),
                            view.root_element(),
                            original,
                            Datatype::Integer,
                            &memory
                        )
                        .unwrap(),
                    expected
                );
            }
        });
        assert_eq!(memory.used(), 0);
    }
    let document = XmlDocument::parse("<value>-000<!--split--><![CDATA[123]]></value>").unwrap();
    let memory = account();
    document.with_view(|view| {
        let source = NativeUri(view);
        assert_eq!(
            source
                .scalar(
                    source.snapshot(),
                    view.root_element(),
                    LexicalSource::SimpleContent,
                    Datatype::Integer,
                    &memory
                )
                .unwrap(),
            Fact::Valid
        );
        use structured_xades::scalar::{TextValue, TextXml};
        source
            .with_text(
                source.snapshot(),
                view.root_element(),
                LexicalSource::SimpleContent,
                &memory,
                |value| {
                    assert!(matches!(value, TextValue::Present("-000123")));
                    Ok::<_, Infallible>(())
                },
            )
            .unwrap();
    });
    assert_eq!(memory.used(), 0);
}

#[test]
fn actual_native_attribute_axis_keeps_expanded_names_and_first_refusal() {
    // Namespace declarations are not attributes; the default namespace does
    // not qualify Id. The bridge forwards native admission and the FIRST
    // caller error without collecting/copying any attacker-controlled names.
    use structured_xades::attributes::AttributeXml;
    let document =
        XmlDocument::parse("<value xmlns='urn:default' xmlns:p='urn:explicit' Id='a' p:Id='b'/>")
            .unwrap();
    document.with_view(|view| {
        let source = NativeUri(view);
        let memory = account();
        let mut count = 0;
        source
            .visit_attributes(source.snapshot(), view.root_element(), &memory, |name| {
                assert_eq!(
                    name,
                    [
                        Name {
                            namespace: "",
                            local: "Id"
                        },
                        Name {
                            namespace: "urn:explicit",
                            local: "Id"
                        }
                    ][count]
                );
                count += 1;
                Ok::<_, Infallible>(())
            })
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(memory.used(), 0);
        count = 0;
        assert!(matches!(
            source.visit_attributes(source.snapshot(), view.root_element(), &memory, |_| {
                count += 1;
                Err("stop at first attribute")
            }),
            Err(VisitError::Visitor("stop at first attribute"))
        ));
        assert_eq!(count, 1);
        let zero = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        assert!(matches!(
            source.visit_attributes(
                source.snapshot(),
                view.root_element(),
                &zero,
                |_| -> Result<(), Infallible> { panic!("unfunded visitor") }
            ),
            Err(VisitError::Processing(UriSourceError::Native(
                xml_sec::xmldsig::extension::ScalarError::Resource(
                    structured_asn1::memory::MemoryError::WorkExceeded
                )
            )))
        ));
        assert_eq!(zero.used(), 0);
        let mut stale = source.snapshot();
        stale.generation += 1;
        assert!(matches!(
            source.visit_attributes(
                stale,
                view.root_element(),
                &zero,
                |_| -> Result<(), Infallible> { panic!("stale visitor") }
            ),
            Err(VisitError::Processing(UriSourceError::Foreign))
        ));
    });
}

#[test]
fn actual_native_integer_funds_current_work_join_and_repeated_queries() {
    // The typed adapter must preserve native resource failure at exact local
    // AND aggregate boundaries; earlier successful queries are not prepaid.
    use structured_xades::scalar::{Datatype, Fact, ScalarXml};
    let document = XmlDocument::parse("<value>-000<!--split--><![CDATA[123]]></value>").unwrap();
    document.with_view(|view| {
        let source = NativeUri(view);
        let measured = account();
        assert_eq!(
            source
                .scalar(
                    source.snapshot(),
                    view.root_element(),
                    LexicalSource::SimpleContent,
                    Datatype::Integer,
                    &measured
                )
                .unwrap(),
            Fact::Valid
        );
        let needed = measured.work_used();
        assert!(needed > 0);
        assert_eq!(measured.used(), 0);
        for aggregate in [false, true] {
            for exact in [false, true] {
                let limit = needed - usize::from(!exact);
                let memory = Memory::new(Arc::new(MemoryAccount::new(
                    1 << 20,
                    if aggregate { limit } else { 1 << 28 },
                )));
                let parser = Parser::new(
                    Encoding::Der,
                    Limits {
                        max_work: if aggregate {
                            1 << 28
                        } else {
                            u64::try_from(limit).unwrap()
                        },
                        ..Limits::default()
                    },
                    memory.clone(),
                );
                let reader = parser.read(&[], 700).unwrap();
                let work = reader.execution();
                let result = source.scalar(
                    source.snapshot(),
                    view.root_element(),
                    LexicalSource::SimpleContent,
                    Datatype::Integer,
                    &work,
                );
                if exact {
                    assert_eq!(result.unwrap(), Fact::Valid);
                    assert!(matches!(
                        source.scalar(
                            source.snapshot(),
                            view.root_element(),
                            LexicalSource::SimpleContent,
                            Datatype::Integer,
                            &work
                        ),
                        Err(UriSourceError::Native(
                            xml_sec::xmldsig::extension::ScalarError::Resource(
                                structured_asn1::memory::MemoryError::WorkExceeded
                            )
                        ))
                    ));
                } else {
                    assert!(matches!(
                        result,
                        Err(UriSourceError::Native(
                            xml_sec::xmldsig::extension::ScalarError::Resource(
                                structured_asn1::memory::MemoryError::WorkExceeded
                            )
                        ))
                    ));
                }
                assert_eq!(memory.used(), 0);
            }
        }
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 28)));
        assert!(matches!(
            source.scalar(
                source.snapshot(),
                view.root_element(),
                LexicalSource::SimpleContent,
                Datatype::Integer,
                &memory
            ),
            Err(UriSourceError::Native(
                xml_sec::xmldsig::extension::ScalarError::Resource(
                    structured_asn1::memory::MemoryError::LimitExceeded
                )
            ))
        ));
        assert_eq!(memory.used(), 0);
    });
    let document = XmlDocument::parse("<value>12 34</value>").unwrap();
    document.with_view(|view| {
        let source = NativeUri(view);
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 28)));
        assert_eq!(
            source
                .scalar(
                    source.snapshot(),
                    view.root_element(),
                    LexicalSource::SimpleContent,
                    Datatype::Integer,
                    &memory
                )
                .unwrap(),
            Fact::Malformed
        );
        assert_eq!(memory.used(), 0);
    });
}

#[test]
fn actual_native_datetime_current_query_refusal_is_not_a_schema_fact() {
    // Even already parsed XML must pay the CURRENT query's joined storage and
    // lexical scan. Refusal retains the native cause and releases scratch.
    use structured_xades::properties::DateTimeXml;
    let document =
        XmlDocument::parse("<time>2026-10-16T<!--join--><![CDATA[12:30:00Z]]></time>").unwrap();
    for memory in [
        Memory::new(Arc::new(MemoryAccount::new(0, 100_000))),
        Memory::new(Arc::new(MemoryAccount::new(100_000, 0))),
    ] {
        document.with_view(|view| {
            let source = NativeUri(view);
            assert!(matches!(
                source.date_time(source.snapshot(), view.root_element(), &memory),
                Err(UriSourceError::Native(
                    xml_sec::xmldsig::extension::ScalarError::Resource(_)
                ))
            ));
        });
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn actual_native_dn_text_preserves_escapes_and_joins_before_scoped_name_matching() {
    // Raw lexical text is NOT anyURI/ID whitespace collapse. The real owner
    // joins original text, then shared RFC4514/Name preserves its DN semantics.
    use structured_xades::scalar::{TextValue, TextXml};
    let document =
        XmlDocument::parse("<Issuer>CN=\\ <!--join--><![CDATA[A\\ ]]></Issuer>").unwrap();
    let memory = account();
    let parser = Parser::der(memory.clone());
    let bytes = [0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 12, 1, b'a'];
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let name = structured_pkix::name::read(&reader, &element, "issuer").unwrap();
    let query_account = account();
    let query_parser = Parser::der(query_account.clone());
    let query = query_parser.read(&[], 900).unwrap();
    document.with_view(|view| {
        let source = NativeUri(view);
        let matched = source
            .with_text(
                source.snapshot(),
                view.root_element(),
                LexicalSource::SimpleContent,
                &query.execution(),
                |value| {
                    let TextValue::Present(text) = value else {
                        panic!("present issuer")
                    };
                    assert_eq!(text, "CN=\\ A\\ ");
                    let selector = structured_pkix::name::Selector::parse_in(text, &query)?;
                    selector.matches_name_in(&name, &query)
                },
            )
            .unwrap();
        assert!(matched);
    });
    assert_eq!(query_account.used(), 0);
}

#[test]
fn actual_native_calendar_projection_retains_arbitrary_digits_and_original_hour() {
    // Source-only scalar qualification: no rounding, bounded-year parser,
    // end-of-day normalization or implicit timezone enters the common bridge.
    use structured_xades::properties::{CalendarFact, CalendarXml};
    let document = XmlDocument::parse("<time>18446744073709551616-01-01T<!--join--><![CDATA[00:00:00.000000000000000000000000000001+02:30]]></time>").unwrap();
    let memory = account();
    document.with_view(|view| {
        let source = NativeUri(view);
        source
            .with_calendar(source.snapshot(), view.root_element(), &memory, |fact| {
                let CalendarFact::Value(value) = fact else {
                    panic!("complete native dateTime")
                };
                assert_eq!(value.year_digits, "18446744073709551616");
                assert_eq!(
                    value.fraction_digits,
                    Some("000000000000000000000000000001")
                );
                assert_eq!(value.timezone_minutes, Some(150));
                Ok::<_, ()>(())
            })
            .unwrap();
    });
    assert_eq!(memory.used(), 0);
    let document = XmlDocument::parse("<time>2025-12-31T24:00:00</time>").unwrap();
    document.with_view(|view| {
        let source = NativeUri(view);
        source
            .with_calendar(source.snapshot(), view.root_element(), &memory, |fact| {
                let CalendarFact::Value(value) = fact else {
                    panic!("end-of-day dateTime")
                };
                assert_eq!(
                    (value.year_digits, value.month, value.day, value.hour),
                    ("2025", 12, 31, 24)
                );
                assert_eq!(value.timezone_minutes, None);
                Ok::<_, ()>(())
            })
            .unwrap();
    });
    assert_eq!(memory.used(), 0);
}

#[test]
fn actual_native_uri_resource_refusal_keeps_its_original_cause() {
    // Joining must admit capacity before copying. It cannot become malformed
    // URI/OID, nor return a successful incomplete string after resource refusal.
    let document =
        XmlDocument::parse("<Identifier>urn:oid:1<!--join--><![CDATA[.2.3]]></Identifier>")
            .unwrap();
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    document.with_view(|view| {
        let source = NativeUri(view);
        let reading = identifier::Reading {
            identifier: view.root_element(),
            qualifier: Some(identifier::Qualifier::Urn),
            description: None,
            documentation: None,
        };
        assert!(matches!(
            identifier::check_value(&Access::new(&source, source.snapshot(), &memory), &reading),
            Err(identifier::MeaningError::Access(
                structured_xades::xml::AccessError::Xml(UriSourceError::Native(
                    xml_sec::xmldsig::extension::ScalarError::Resource(
                        structured_asn1::memory::MemoryError::LimitExceeded
                    )
                ))
            ))
        ));
    });
    assert_eq!(memory.used(), 0);
}
fn unavailable<T>() -> Result<T, DsigError> {
    Err(DsigError::InvalidRequest {
        reason: "key-only qualification adapter: other capability not supplied",
    })
}

struct KeyOnly<'session, 'view, 'scope, 'inputs, W: Work> {
    session: &'session VerifiedSession<'view, 'scope, 'inputs, W>,
    unused: Cell<usize>,
}

impl<W: Work> Xml for KeyOnly<'_, '_, '_, '_, W> {
    type Id = NodeIdentity;
    type Document = DocumentIdentity;
    type Generation = u64;
    type Error = DsigError;
    fn snapshot(&self) -> Snapshot<DocumentIdentity, u64> {
        Snapshot {
            document: self.session.view().identity(),
            generation: self.session.view().generation(),
        }
    }
    fn inspect<R, Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: &Q,
        _: impl for<'a> FnOnce(Node<'a>) -> R,
    ) -> Result<R, DsigError> {
        self.unused.set(self.unused.get() + 1);
        unavailable()
    }
    fn attribute<R, Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: Name<'_>,
        _: &Q,
        _: impl for<'a> FnOnce(Option<&'a str>) -> R,
    ) -> Result<R, DsigError> {
        self.unused.set(self.unused.get() + 1);
        unavailable()
    }
    fn first_child<Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: &Q,
    ) -> Result<Option<NodeIdentity>, DsigError> {
        self.unused.set(self.unused.get() + 1);
        unavailable()
    }
    fn next_sibling<Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: NodeIdentity,
        _: &Q,
    ) -> Result<Option<NodeIdentity>, DsigError> {
        self.unused.set(self.unused.get() + 1);
        unavailable()
    }
}

impl<W: Work> SignatureXml for KeyOnly<'_, '_, '_, '_, W> {
    fn signature_status<Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: &Q,
    ) -> Result<Status, DsigError> {
        self.unused.set(self.unused.get() + 1);
        unavailable()
    }
    fn reference_count<Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: &Q,
    ) -> Result<usize, DsigError> {
        self.unused.set(self.unused.get() + 1);
        unavailable()
    }
    fn reference<R, Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: usize,
        _: &Q,
        _: impl for<'a> FnOnce(Reference<'a, NodeIdentity>) -> R,
    ) -> Result<R, DsigError> {
        self.unused.set(self.unused.get() + 1);
        unavailable()
    }
    fn qualifying_target<Q: Work>(
        &self,
        _: Snapshot<DocumentIdentity, u64>,
        _: NodeIdentity,
        _: &Q,
    ) -> Result<Target<NodeIdentity>, DsigError> {
        self.unused.set(self.unused.get() + 1);
        unavailable()
    }
}

impl<W: Work> CertificateXml for KeyOnly<'_, '_, '_, '_, W> {
    fn key_association<Q: Work>(
        &self,
        snapshot: Snapshot<DocumentIdentity, u64>,
        signature: NodeIdentity,
        _: &Certificate<'_>,
        key: WorkingKey<'_>,
        work: &Q,
    ) -> Result<KeyAssociation, DsigError> {
        if snapshot != self.snapshot() {
            return Err(DsigError::InvalidRequest {
                reason: "foreign original key query snapshot",
            });
        }
        match self
            .session
            .with_key_association_in(signature, key, work, |outcome| {
                Ok::<_, Infallible>(match outcome {
                    xml_sec::provider::KeyAssociation::Same => KeyAssociation::Same,
                    xml_sec::provider::KeyAssociation::Mismatch => KeyAssociation::Differs,
                    xml_sec::provider::KeyAssociation::Unproven => KeyAssociation::Unproven,
                })
            }) {
            Ok(outcome) => Ok(outcome),
            Err(CatalogueError::Processing(cause)) => Err(cause),
            Err(CatalogueError::Visitor(never)) => match never {},
        }
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    // Trusted, bounded synthetic fixture construction; not a runtime encoder.
    assert!(body.len() < 65536);
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else if body.len() < 256 {
        out.extend([0x81, body.len() as u8]);
    } else {
        out.extend([0x82, (body.len() >> 8) as u8, body.len() as u8]);
    }
    out.extend_from_slice(body);
    out
}
fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn certificate_der(spki: &[u8]) -> Vec<u8> {
    // RFC5280 4.1 parseable carrier only. XML signature mathematics are real;
    // this arbitrary certificate signature is not used to assert issuer trust.
    let algorithm = sequence(&[&tlv(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2])]);
    let name = sequence(&[&tlv(
        0x31,
        &sequence(&[&tlv(6, &[0x55, 4, 3]), &tlv(12, b"native-key")]),
    )]);
    let validity = sequence(&[&tlv(23, b"250101000000Z"), &tlv(23, b"300101000000Z")]);
    let tbs = sequence(&[
        &[0xa0, 3, 2, 1, 2],
        &[2, 1, 1],
        &algorithm,
        &name,
        &validity,
        &name,
        spki,
    ]);
    sequence(&[&tbs, &algorithm, &tlv(3, &[0, 0])])
}
fn with_certificate<R>(der: &[u8], visitor: impl FnOnce(&Certificate<'_>) -> R) -> R {
    let parser = Parser::der(account());
    let certificate = Certificate::read(&parser, der, 700).unwrap();
    visitor(&certificate)
}
fn fixture(seed: u8) -> (p256::SecretKey, Vec<u8>) {
    // Public test-only deterministic key; no production credentials/fixtures.
    let key = p256::SecretKey::from_slice(&[seed; 32]).unwrap();
    let spki = key.public_key().to_public_key_der().unwrap();
    let certificate = certificate_der(spki.as_bytes());
    (key, certificate)
}
fn signed(key: &p256::SecretKey) -> (XmlDocument, VerificationKey) {
    let private = key.to_pkcs8_der().unwrap();
    let signer = EcdsaP256SigningKey::from_pkcs8_der(private.as_bytes()).unwrap();
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::EcdsaSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped),
    );
    let document = XmlDocument::parse(
        SignContext::new(&signer)
            .sign_with_builder("<root>original</root>", &builder)
            .unwrap(),
    )
    .unwrap();
    let key = VerificationKey {
        algorithm: SignatureAlgorithm::EcdsaSha256,
        public_key_bytes: key
            .public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec(),
        certificate_der: None,
        name: None,
    };
    (document, key)
}

#[test]
fn common_key_trait_uses_current_execution_after_the_producer_is_exhausted() {
    // The expected descriptor/parser live ONLY inside the continuation, shorter
    // than the original session. No reference/DOM method or re-verification is
    // supplied by this adapter, and no new retained key allocation is needed.
    let (key, der) = fixture(7);
    let (document, key) = signed(&key);
    let memory = account();
    let producer = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1 << 20,
            ..Limits::default()
        },
        memory.clone(),
    );
    let reader = producer.read(&[], 0).unwrap();
    let producer_work = reader.execution();
    let query = Parser::der(memory.clone());
    let reader = query.read(&[], 900).unwrap();
    let work = reader.execution();
    with_verified_request(
        &document,
        &VerifyContext::new().key(&key),
        &VerificationRequest::default(),
        &producer_work,
        |session| {
            let signature = session.evidence().signatures()[0].identity();
            for shift in (0..=20).rev() {
                while producer_work.charge_work(1 << shift).is_ok() {}
            }
            let adapter = KeyOnly {
                session: &session,
                unused: Cell::new(0),
            };
            let held = memory.used();
            let before = memory.work_used();
            with_certificate(&der, |certificate| {
                let expected = WorkingKey::standing(certificate.tbs().public_key());
                assert_eq!(
                    adapter
                        .key_association(
                            adapter.snapshot(),
                            signature,
                            certificate,
                            expected,
                            &work
                        )
                        .unwrap(),
                    KeyAssociation::Same
                );
            });
            let cost = memory.work_used() - before;
            assert!(cost > 1);
            assert_eq!(memory.used(), held);
            assert!(producer_work.charge_work(1).is_err());
            with_certificate(&der, |certificate| {
                let expected = WorkingKey::standing(certificate.tbs().public_key());
                let exact = Memory::new(Arc::new(MemoryAccount::new(65536, cost)));
                assert_eq!(
                    adapter
                        .key_association(
                            adapter.snapshot(),
                            signature,
                            certificate,
                            expected,
                            &exact
                        )
                        .unwrap(),
                    KeyAssociation::Same
                );
                assert_eq!(exact.work_used(), cost);
                assert_eq!(exact.used(), 0);
                let denied = Memory::new(Arc::new(MemoryAccount::new(65536, cost - 1)));
                assert!(matches!(
                    adapter.key_association(
                        adapter.snapshot(),
                        signature,
                        certificate,
                        expected,
                        &denied
                    ),
                    Err(DsigError::SharedExecution(
                        structured_asn1::memory::MemoryError::WorkExceeded
                    ))
                ));
                assert_eq!(denied.used(), 0);
            });
            assert_eq!(adapter.unused.get(), 0);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(memory.used(), 0);
}

#[test]
fn different_key_is_differs_and_a_non_signature_source_is_an_error() {
    // Neither a different original key nor an invalid source becomes Same or
    // an unsupported/mismatch fallback. Only key association is being checked.
    let (key, _) = fixture(7);
    let (_, other) = fixture(8);
    let (document, key) = signed(&key);
    with_verified_request(
        &document,
        &VerifyContext::new().key(&key),
        &VerificationRequest::default(),
        &account(),
        |session| {
            let adapter = KeyOnly {
                session: &session,
                unused: Cell::new(0),
            };
            with_certificate(&other, |certificate| {
                let expected = WorkingKey::standing(certificate.tbs().public_key());
                let signature = session.evidence().signatures()[0].identity();
                assert_eq!(
                    adapter
                        .key_association(
                            adapter.snapshot(),
                            signature,
                            certificate,
                            expected,
                            &account()
                        )
                        .unwrap(),
                    KeyAssociation::Differs
                );
                assert!(
                    adapter
                        .key_association(
                            adapter.snapshot(),
                            session.view().root(),
                            certificate,
                            expected,
                            &account()
                        )
                        .is_err()
                );
            });
            assert_eq!(adapter.unused.get(), 0);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn an_opaque_successful_key_cannot_be_repaired_from_the_candidate_certificate() {
    // HMAC mathematically verifies this real XML but supplies no asymmetric
    // public-key evidence. The candidate certificate cannot create that receipt.
    let (_, certificate) = fixture(7);
    let signer = HmacSigningKey::new(vec![5; 32]).unwrap();
    let key = HmacVerificationKey::new(vec![5; 32]).unwrap();
    let builder = SignatureBuilder::new(
        C14nAlgorithm::new(C14nMode::Exclusive1_0, false),
        SignatureAlgorithm::HmacSha256,
    )
    .add_reference(
        ReferenceBuilder::new(DigestAlgorithm::Sha256)
            .uri("")
            .transform(Transform::Enveloped),
    );
    let document = XmlDocument::parse(
        SignContext::new(&signer)
            .sign_with_builder("<root/>", &builder)
            .unwrap(),
    )
    .unwrap();
    with_verified_request(
        &document,
        &VerifyContext::new().key(&key),
        &VerificationRequest::default(),
        &account(),
        |session| {
            let adapter = KeyOnly {
                session: &session,
                unused: Cell::new(0),
            };
            with_certificate(&certificate, |certificate| {
                let signature = session.evidence().signatures()[0].identity();
                assert_eq!(
                    adapter
                        .key_association(
                            adapter.snapshot(),
                            signature,
                            certificate,
                            WorkingKey::standing(certificate.tbs().public_key()),
                            &account()
                        )
                        .unwrap(),
                    KeyAssociation::Unproven
                );
            });
            assert_eq!(adapter.unused.get(), 0);
            Ok(())
        },
    )
    .unwrap();
}
