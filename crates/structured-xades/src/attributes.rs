//! Original `XAdES` attribute declarations and their base-datatype obligations.

mod declaration;
mod types;

use crate::container::{Layout, XADES};
use crate::pki::CounterPaths;
use crate::prepare::Prepared;
use crate::reference::{LexicalSource, VisitError};
use crate::scalar::{self, Datatype, QNameFact, QNameXml, ScalarXml};
use crate::timestamp::XADES_141;
use crate::xml::{Access, AccessError, Name, Node, Snapshot, Xml};
use structured_asn1::memory::{MemoryError, Work};

/// Original direct attributes, excluding namespace declarations. Their names
/// remain scoped to the visitor; no copied attribute catalogue is required.
pub trait AttributeXml: Xml + QNameXml {
    /// Visit each original direct attribute once, preserving first callback
    /// refusal. The owner checks document/generation and admits traversal/name
    /// work through THIS execution before access. XML normalization and namespace
    /// expansion belong to that owner; unqualified attributes have no namespace.
    fn visit_attributes<VE, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        execution: &W,
        visitor: impl for<'view> FnMut(Name<'view>) -> Result<(), VE>,
    ) -> Result<(), VisitError<Self::Error, VE>>;
}

/// Visits original attribute names with the common snapshot/admission fence.
/// Format-specific declarations belong to the requesting schema; traversal
/// and temporary namespace/name storage remain with the XML owner.
pub fn visit<X: AttributeXml, W: Work, E>(
    access: &Access<'_, X, W>,
    node: X::Id,
    visitor: impl for<'view> FnMut(Name<'view>) -> Result<(), E>,
) -> crate::xml::VisitResult<(), X, E> {
    access.query_fallible(node, |xml, snapshot, work| {
        xml.visit_attributes(snapshot, node, work, visitor)
    })
}

/// Schema-instance attributes need their own original interpretation; they are
/// not ordinary undeclared attributes or a request to fetch a schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceAttribute {
    /// An overriding schema type or unavailable `QName` projection is unassessed.
    Type,
    /// Original schema-location hints have not been assessed. No implicit fetch.
    SchemaLocation,
}

/// Known original xsi:type reading failure, not an unavailable type definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeProblem {
    /// Owner did not return the attribute observed by the same source traversal.
    Absent,
    /// Original source has element children rather than simple content.
    ComplexContent,
    /// Original text fails XSD1.0 `QName` syntax.
    Malformed,
    /// Original lexical prefix has no in-scope namespace binding.
    UnboundPrefix,
}

/// Original declaration, lexical, source and resource refusals stay distinct.
#[derive(Debug)]
pub enum Error<E, N> {
    /// The supplied retained source belongs to another original selection.
    Foreign,
    /// Original XML/generation/current-operation refusal.
    Access(AccessError<E, N>),
    /// A requested original ID/URI/integer value failed or is unsupported.
    Scalar(scalar::Error<E, N>),
    /// This original attribute has no declaration at the selected field.
    Unexpected {
        /// Original owning element.
        node: N,
        /// Zero-based direct-attribute ordinal in that immutable view, not a byte offset.
        attribute: usize,
    },
    /// A required original unqualified attribute is absent.
    Missing {
        /// Original owning element.
        node: N,
        /// Missing wire name, never an inferred/default value.
        local: &'static str,
    },
    /// This is incomplete schema-instance processing, NOT malformed syntax.
    InstanceUnassessed {
        /// Original owning element.
        node: N,
        /// Exact original attribute role requiring interpretation.
        kind: InstanceAttribute,
    },
    /// A known `QName` reading failure at the original xsi:type attribute.
    Type {
        /// Original owning element, permitting inspection of the original text.
        node: N,
        /// Exact reading-failure category; no callback-local prefix is retained.
        problem: TypeProblem,
    },
    /// The original `XAdES` node has no selected declaration in this capability.
    Unassessed {
        /// Original element, not an automatically accepted unknown field.
        node: N,
    },
}

/// Result in this XML owner's original source/error domain.
pub type AttributeResult<X> = Result<(), Error<<X as Xml>::Error, <X as Xml>::Id>>;

#[derive(Clone, Copy)]
enum Rule {
    None,
    Id,
    Target,
    Encoding,
    Uri,
    IdUri,
    RequiredUri,
    Include,
    Format,
    Identifier,
    Order,
    Open,
}

#[derive(Clone, Copy)]
enum Context {
    Ordinary,
    Renewed,
    CertifiedV2,
    CertV2,
}

struct Declaration {
    rule: Rule,
    descend: bool,
    context: Context,
    schema_type: Name<'static>,
}

#[derive(Clone, Copy)]
enum Field {
    Typed(Datatype),
    Required(Datatype),
    Declared,
}

fn field(rule: Rule, local: &str) -> Option<Field> {
    Some(match (rule, local) {
        (Rule::Id | Rule::Target | Rule::Encoding | Rule::IdUri | Rule::RequiredUri, "Id") => {
            Field::Typed(Datatype::Id)
        }
        (Rule::Target, "Target")
        | (Rule::Format, "ObjectReference")
        | (Rule::Include | Rule::RequiredUri, "URI") => Field::Required(Datatype::AnyUri),
        (Rule::Encoding, "Encoding") | (Rule::Uri | Rule::IdUri, "URI") => {
            Field::Typed(Datatype::AnyUri)
        }
        (Rule::Order, "Order") => Field::Required(Datatype::Integer),
        (Rule::Identifier, "Qualifier") | (Rule::Include, "referencedData") => Field::Declared,
        _ => return None,
    })
}

use self::declaration::declaration;

/// Check the selected root's original declared attributes BEFORE path/provider
/// execution. This needs only structural preparation, not a successful PKIX
/// path or countersignature result. Child containers are checked separately by
/// [`check`]; no root-only result certifies all participants or a baseline level.
pub fn check_prepared<X: AttributeXml + ScalarXml, W: Work>(
    prepared: &Prepared<X>,
    access: &Access<'_, X, W>,
) -> AttributeResult<X> {
    let layout = prepared.bound().containers();
    if layout.snapshot() != access.snapshot() {
        return Err(Error::Foreign);
    }
    check_layout(layout, access)?;
    access
        .query(layout.signature(), |_, _, _| Ok(()))
        .map_err(Error::Access)
}

/// Check declared attribute names and requested ID/URI/integer values in the
/// original selected `XAdES` source and ALL original counter containers. Open
/// foreign/AnyType payloads are delegated, never recursively reinterpreted by
/// their local names. `XMLDSig` elements retain their XML owner's contract.
///
/// This is NOT whole-schema validity or a B level: child grammar, schema-instance
/// interpretation, OID meaning, binary values, dates, math, trust and complete
/// profile assembly remain independent obligations. Unassessed xsi attributes
/// never become successful syntax or a fabricated malformed-document finding.
pub fn check<X: AttributeXml + ScalarXml, W: Work>(
    prepared: &Prepared<X>,
    counters: &CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> AttributeResult<X> {
    require_participants(prepared, counters, access)?;
    check_prepared(prepared, access)?;
    check_counter_nodes(prepared, counters, access)
}

fn require_participants<X: AttributeXml + ScalarXml, W: Work>(
    prepared: &Prepared<X>,
    counters: &CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> AttributeResult<X> {
    let layout = prepared.bound().containers();
    if layout.snapshot() != access.snapshot()
        || counters.snapshot() != access.snapshot()
        || !access
            .equal_id(layout.signature(), counters.signature())
            .map_err(|cause| resource(layout.signature(), cause))?
    {
        return Err(Error::Foreign);
    }
    Ok(())
}

// The final root assembly already holds its checked Fields receipt. Reuse
// counter traversal without repeating the root's scalar/attribute preflight.
pub(crate) fn check_counters<X: AttributeXml + ScalarXml, W: Work>(
    prepared: &Prepared<X>,
    counters: &CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> AttributeResult<X> {
    require_participants(prepared, counters, access)?;
    check_counter_nodes(prepared, counters, access)
}

fn check_counter_nodes<X: AttributeXml + ScalarXml, W: Work>(
    prepared: &Prepared<X>,
    counters: &CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
    access: &Access<'_, X, W>,
) -> AttributeResult<X> {
    let layout = prepared.bound().containers();
    for actor in counters.actors() {
        access
            .execution()
            .charge_work(1)
            .map_err(|cause| resource(layout.signature(), cause))?;
        if let Some(layout) = actor.containers() {
            check_layout(layout, access)?;
        }
    }
    access
        .query(layout.signature(), |_, _, _| Ok(()))
        .map_err(Error::Access)
}

struct Frame<N> {
    parent: N,
    next: Option<N>,
    context: Context,
}

fn check_layout<X: AttributeXml + ScalarXml, W: Work>(
    layout: &Layout<X>,
    access: &Access<'_, X, W>,
) -> AttributeResult<X> {
    let mut frames = access.execution().vector();
    let mut next = Some((layout.qualifying(), Context::Ordinary));
    loop {
        if let Some((node, parent)) = next.take() {
            let selected = access
                .inspect(node, |value| {
                    let Node::Element(name) = value else {
                        return Ok(None);
                    };
                    let length = name
                        .namespace
                        .len()
                        .checked_add(name.local.len())
                        .and_then(|cost| u64::try_from(cost).ok())
                        .ok_or(MemoryError::WorkExceeded)?;
                    access.execution().charge_work(length)?;
                    if name.namespace != XADES && name.namespace != XADES_141 {
                        return Ok(None);
                    }
                    Ok(Some(declaration(name, parent)))
                })
                .map_err(Error::Access)?
                .map_err(|cause| resource(node, cause))?;
            if let Some(selected) = selected {
                let selected = selected.ok_or(Error::Unassessed { node })?;
                check_node(node, selected.rule, selected.schema_type, access)?;
                if selected.descend {
                    let child = access.first_child(node).map_err(Error::Access)?;
                    frames
                        .try_push(Frame {
                            parent: node,
                            next: child,
                            context: selected.context,
                        })
                        .map_err(|cause| resource(node, cause))?;
                }
            }
        }
        access
            .execution()
            .charge_work(1)
            .map_err(|cause| resource(layout.qualifying(), cause))?;
        let Some(frame) = frames.last_mut() else {
            break;
        };
        if let Some(child) = frame.next {
            frame.next = access
                .next_sibling(frame.parent, child)
                .map_err(Error::Access)?;
            next = Some((child, frame.context));
        } else {
            frames.pop();
        }
    }
    Ok(())
}

fn resource<E, N>(node: N, cause: MemoryError) -> Error<E, N> {
    Error::Access(AccessError::Resource { node, cause })
}

fn check_node<X: AttributeXml + ScalarXml, W: Work>(
    node: X::Id,
    rule: Rule,
    schema_type: Name<'static>,
    access: &Access<'_, X, W>,
) -> AttributeResult<X> {
    let mut ordinal = 0usize;
    let mut required = false;
    let visited = access.query_fallible(node, |xml, snapshot, work| {
        xml.visit_attributes(snapshot, node, work, |name| {
            let cost = u64::try_from(name.local.len())
                .ok()
                .and_then(|length| length.checked_add(1))
                .ok_or_else(|| resource(node, MemoryError::WorkExceeded))?;
            work.charge_work(cost)
                .map_err(|cause| resource(node, cause))?;
            let current = ordinal;
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| resource(node, MemoryError::WorkExceeded))?;
            if access
                .equal(name.namespace, "http://www.w3.org/2001/XMLSchema-instance")
                .map_err(|cause| resource(node, cause))?
            {
                // XSD1.0 Structures §3.3.4(3.1): non-nillable declarations
                // forbid xsi:nil's PRESENCE, including nil="false". Every
                // element declared by the pinned Annex C schemas omits
                // nillable (default false), including AnyType enclosures.
                // Foreign/open CONTENT remains with its format owner.
                // https://www.w3.org/TR/2004/REC-xmlschema-1-20041028/#cvc-elt
                if name.local == "nil" {
                    return Err(Error::Unexpected {
                        node,
                        attribute: current,
                    });
                }
                if name.local == "noNamespaceSchemaLocation" {
                    // XSD1.0 Structures §3.2.7 declares exactly anyURI. The
                    // hint cannot replace our pinned declaration or initiate
                    // acquisition (§4.3.2); use the original XML scalar owner.
                    // https://www.w3.org/TR/2004/REC-xmlschema-1-20041028/#BuiltInAttrDecls
                    return scalar::check(
                        access,
                        node,
                        LexicalSource::Attribute(name),
                        Datatype::AnyUri,
                    )
                    .map_err(Error::Scalar);
                }
                let kind = match name.local {
                    "type" => Some(InstanceAttribute::Type),
                    "schemaLocation" => Some(InstanceAttribute::SchemaLocation),
                    _ => None,
                };
                if let Some(kind) = kind {
                    if matches!(kind, InstanceAttribute::Type)
                        && same_declared_type(node, name, schema_type, access)?
                    {
                        return Ok(());
                    }
                    return Err(Error::InstanceUnassessed { node, kind });
                }
            }
            if matches!(rule, Rule::Open) {
                return Ok(());
            }
            if !name.namespace.is_empty() {
                return Err(Error::Unexpected {
                    node,
                    attribute: current,
                });
            }
            let selected = field(rule, name.local).ok_or(Error::Unexpected {
                node,
                attribute: current,
            })?;
            if matches!(selected, Field::Required(_)) {
                required = true;
            }
            if let Field::Typed(datatype) | Field::Required(datatype) = selected {
                scalar::check(access, node, LexicalSource::Attribute(name), datatype)
                    .map_err(Error::Scalar)?;
            }
            Ok(())
        })
    });
    match visited {
        Ok(()) => (),
        Err(AccessError::Xml(VisitError::Processing(cause))) => {
            return Err(Error::Access(AccessError::Xml(cause)));
        }
        Err(AccessError::Xml(VisitError::Visitor(cause))) => return Err(cause),
        Err(AccessError::Changed { node }) => {
            return Err(Error::Access(AccessError::Changed { node }));
        }
        Err(AccessError::Resource { node, cause }) => return Err(resource(node, cause)),
    }
    if !required {
        let local = match rule {
            Rule::Target => Some("Target"),
            Rule::Include | Rule::RequiredUri => Some("URI"),
            Rule::Format => Some("ObjectReference"),
            Rule::Order => Some("Order"),
            _ => None,
        };
        if let Some(local) = local {
            return Err(Error::Missing { node, local });
        }
    }
    Ok(())
}

fn same_declared_type<X: AttributeXml, W: Work>(
    node: X::Id,
    attribute: Name<'_>,
    expected: Name<'static>,
    access: &Access<'_, X, W>,
) -> Result<bool, Error<X::Error, X::Id>> {
    enum Reading {
        Compared(bool),
        Problem(TypeProblem),
    }
    // XSD1.0 Structures §3.3.4(4–5): QName resolution is not derivation
    // or validation under an overriding type. Equality safely retains the
    // already selected declaration; other types remain explicitly unassessed.
    // https://www.w3.org/TR/2004/REC-xmlschema-1-20041028/#cvc-elt
    let reading = access.query_fallible(node, |xml, snapshot, work| {
        xml.with_qname(
            snapshot,
            node,
            LexicalSource::Attribute(attribute),
            work,
            |read| {
                let value = match read.fact {
                    QNameFact::Value(value) => value,
                    QNameFact::Unsupported => return Ok(Reading::Compared(false)),
                    QNameFact::Absent => return Ok(Reading::Problem(TypeProblem::Absent)),
                    QNameFact::ComplexContent => {
                        return Ok(Reading::Problem(TypeProblem::ComplexContent));
                    }
                    QNameFact::Malformed => return Ok(Reading::Problem(TypeProblem::Malformed)),
                    QNameFact::UnboundPrefix(_) => {
                        return Ok(Reading::Problem(TypeProblem::UnboundPrefix));
                    }
                };
                let Some(namespace) = value.namespace else {
                    return Ok(Reading::Compared(false));
                };
                if !access.equal(namespace, expected.namespace)? {
                    return Ok(Reading::Compared(false));
                }
                access
                    .equal(value.local_name, expected.local)
                    .map(Reading::Compared)
            },
        )
    });
    match reading {
        Ok(Reading::Compared(value)) => Ok(value),
        Ok(Reading::Problem(problem)) => Err(Error::Type { node, problem }),
        Err(AccessError::Xml(VisitError::Processing(cause))) => {
            Err(Error::Access(AccessError::Xml(cause)))
        }
        Err(AccessError::Xml(VisitError::Visitor(cause))) => Err(resource(node, cause)),
        Err(AccessError::Changed { node }) => Err(Error::Access(AccessError::Changed { node })),
        Err(AccessError::Resource { node, cause }) => Err(resource(node, cause)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certified_role_attribute_type_depends_on_its_original_parent_declaration() {
        // Annex C gives legacy CertifiedRole EncapsulatedPKIDataType, while
        // CertifiedRolesV2's identically named child is an attribute-free
        // choice wrapper. Local name alone must not grant Id/Encoding there.
        let parent = declaration::declaration(
            Name {
                namespace: XADES,
                local: "CertifiedRolesV2",
            },
            Context::Ordinary,
        )
        .unwrap();
        let wrapper = declaration::declaration(
            Name {
                namespace: XADES,
                local: "CertifiedRole",
            },
            parent.context,
        )
        .unwrap();
        assert!(matches!(wrapper.rule, Rule::None));
        assert!(wrapper.descend);
        let legacy = declaration::declaration(
            Name {
                namespace: XADES,
                local: "CertifiedRole",
            },
            Context::Ordinary,
        )
        .unwrap();
        assert!(matches!(legacy.rule, Rule::Encoding));
        assert!(!legacy.descend);
    }
}
