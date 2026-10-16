//! Baseline data-object format structure, reference coverage and object agreement.

use crate::binding::{Bound, Coverage, Status};
use crate::container::{DS, XADES};
use crate::properties::{DataObjectRole, Error, Reading};
use crate::reference::{Completeness, LexicalSource, Parent, ReferenceXml, Resolution, VisitError};
use crate::xml::{Access, AccessError, Name, Node, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

/// Format structure, reference eligibility and exact object-metadata refusals.
#[derive(Debug)]
pub enum FormatError<E, N> {
    /// Caller ordinal is absent or does not select a data-object format.
    Selection {
        /// Original selected signature.
        signature: N,
        /// Requested data-object property ordinal.
        index: usize,
    },
    /// Original schema, source-generation or resource cause.
    Property(Error<E, N>),
    /// Lookup reached an instruction whose target digest was not successfully
    /// checked, or which refers to `SignedProperties` rather than a data object.
    Reference {
        /// Original authenticated reference instruction.
        node: N,
        /// Actual completed or unchecked digest outcome.
        status: Status,
    },
    /// Supplied reading belongs to another selected signature or source.
    Foreign {
        /// Original property node from the supplied reading.
        node: N,
    },
    /// A present original `ds:Object` attribute differs from its format value.
    Metadata {
        /// Original property value element.
        node: N,
        /// Original referenced `ds:Object`.
        object: N,
        /// Exact unqualified attribute name.
        local: &'static str,
    },
}

/// Resolved original instruction, including present ds:Object metadata agreement.
/// MIME syntax, URI lexical validation and trust are separate checks.
#[derive(Debug, Clone, Copy)]
pub struct Resolved<N> {
    /// Original reference instruction.
    pub reference: N,
    /// Its exact authenticated original parent.
    pub parent: Parent<N>,
    /// Original same-document target, if present.
    pub target: Option<N>,
    /// Actual conservative transform coverage, independent of URI lookup.
    pub coverage: Coverage,
}

/// Required object-format association failed before scalar/digest execution.
#[derive(Debug)]
pub enum CoverageError<E, N> {
    /// Original format structure, resolution eligibility or source refusal.
    Format(FormatError<E, N>),
    /// Original guard/admission refusal.
    Access(AccessError<E, N>),
    /// Original XML catalogue traversal refusal, including its resource class.
    Processing(E),
    /// A format URI was not resolved to an authenticated instruction.
    Lookup {
        /// Original `DataObjectFormat`.
        node: N,
        /// Exact unsuccessful lookup outcome, distinct from processing refusal.
        resolution: Resolution<()>,
    },
    /// Required object reference has no format property.
    Missing {
        /// Original Reference node.
        reference: N,
    },
    /// Multiple formats identify the same reference instruction.
    Repeated {
        /// Original Reference node.
        reference: N,
    },
    /// Format does not qualify any required object (including counter exemptions).
    Unused {
        /// Original `DataObjectFormat`.
        node: N,
    },
    /// Supplied counter binding belongs to another source or child signature.
    ForeignCounter {
        /// Original selected signature.
        signature: N,
    },
    /// Original XML request did not provide a complete reference catalogue.
    Incomplete {
        /// Original unprocessed instruction or container.
        node: N,
    },
    /// Referenced data was not successfully checked by `XMLDSig`.
    Unchecked {
        /// Original Reference node.
        reference: N,
    },
}

/// Prepared original format with its unique required reference association.
#[derive(Debug)]
pub struct CoveredFormat<N, D, G> {
    original: Format<N, D, G>,
    reference: N,
    seen: bool,
}

impl<N: Copy, D: Copy, G: Copy> CoveredFormat<N, D, G> {
    /// Original property for subsequent scalar and object-metadata validation.
    #[must_use]
    pub fn original(&self) -> &Format<N, D, G> {
        &self.original
    }
    /// Exact required reference, including signed Manifest children.
    #[must_use]
    pub fn reference(&self) -> N {
        self.reference
    }
}

/// Accounted complete associations and object metadata agreement; scalar syntax
/// and MIME correctness are separate.
pub type Covered<X, W = structured_asn1::memory::Memory> =
    OwnedVec<CoveredFormat<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>, W>;
/// Original cause retained through reference-catalogue visitor refusal.
pub type CoverageResult<T, X> = Result<T, CoverageError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Checks EN319132-1 §6.3(k)'s complete per-object format coverage.
/// A selected authenticated counter binding supplies the counter-value exemption;
/// arbitrary caller booleans or nodes cannot claim that exception. All relevant
/// authenticated Manifest instructions must be traversed, not just references
/// for which a format happens to exist. Partial XML catalogues stay incomplete.
/// This establishes association and exact ds:Object metadata agreement, not
/// MIME syntax, Encoding URI validity or trust.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn check_references<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    signed: &Reading<X>,
    counter: Option<&crate::counter::Binding<X>>,
) -> CoverageResult<Covered<X>, X> {
    let layout = bound.containers();
    if access.snapshot() != layout.snapshot() {
        return Err(CoverageError::Access(AccessError::Changed {
            node: layout.signature(),
        }));
    }
    if signed.snapshot() != layout.snapshot() || signed.signature() != layout.signature() {
        return Err(CoverageError::Format(FormatError::Foreign {
            node: signed.parent(),
        }));
    }
    let counter_value = if let Some(counter) = counter {
        if counter.original().snapshot() != layout.snapshot()
            || counter.original().child() != layout.signature()
        {
            return Err(CoverageError::ForeignCounter {
                signature: layout.signature(),
            });
        }
        Some(counter.original().value())
    } else {
        None
    };
    let mut formats = prepare_formats(access, bound, signed)?;
    let mut indices = access
        .query(layout.signature(), |_, _, work| Ok(work.map()))
        .map_err(CoverageError::Access)?;
    for index in 0..formats.len() {
        admit(access, formats[index].original.node)?;
        let reference = formats[index].reference;
        if indices
            .try_insert(reference, index)
            .map_err(|cause| {
                CoverageError::Access(AccessError::Resource {
                    node: formats[index].original.node,
                    cause,
                })
            })?
            .is_some()
        {
            return Err(CoverageError::Repeated { reference });
        }
    }
    let visited = access
        .query(layout.signature(), |xml, snapshot, work| {
            Ok(xml.visit_authenticated_references(
                snapshot,
                layout.signature(),
                work,
                |descriptor| {
                    let r = descriptor.reference;
                    if r.target == Some(layout.signed())
                        || (counter_value.is_some() && r.target == counter_value)
                    {
                        return Ok(());
                    }
                    if r.status != Status::Valid {
                        return Err(CoverageError::Unchecked { reference: r.node });
                    }
                    // Existing accounted map admits hash/equality and the
                    // pinned engine's full possible hidden probe chain first.
                    // Actual lookup avoids F×R identity scans; conservative
                    // worst-probe admission is not claimed to be linear.
                    let Some(&index) = indices.get(&r.node, work).map_err(|cause| {
                        CoverageError::Access(AccessError::Resource {
                            node: r.node,
                            cause,
                        })
                    })?
                    else {
                        return Err(CoverageError::Missing { reference: r.node });
                    };
                    debug_assert!(index < formats.len());
                    formats[index].seen = true;
                    Ok(())
                },
            ))
        })
        .map_err(CoverageError::Access)?;
    let completeness = match visited {
        Ok(value) => value,
        Err(VisitError::Processing(cause)) => return Err(CoverageError::Processing(cause)),
        Err(VisitError::Visitor(cause)) => return Err(cause),
    };
    match completeness {
        Completeness::Complete => {}
        Completeness::Unchecked(node) | Completeness::Incomplete(node) => {
            return Err(CoverageError::Incomplete { node });
        }
    }
    for index in 0..formats.len() {
        admit(access, signed.parent())?;
        if !formats[index].seen {
            return Err(CoverageError::Unused {
                node: formats[index].original.node,
            });
        }
    }
    Ok(formats.into_owned())
}

fn admit<X: Xml, W: Work>(access: &Access<'_, X, W>, node: X::Id) -> CoverageResult<(), X> {
    access
        .query(node, |_, _, work| Ok(work.charge_work(1)))
        .map_err(CoverageError::Access)?
        .map_err(|cause| CoverageError::Access(AccessError::Resource { node, cause }))
}

fn prepare_formats<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    signed: &Reading<X>,
) -> CoverageResult<Covered<X, W>, X> {
    let mut formats = access
        .query(signed.parent(), |_, _, work| Ok(work.vector()))
        .map_err(CoverageError::Access)?;
    if let Some(objects) = signed.data_objects() {
        for index in 0..objects.entries().len() {
            admit(access, objects.parent())?;
            if objects.entries()[index].role != DataObjectRole::Format {
                continue;
            }
            let original = read(access, signed, index).map_err(CoverageError::Format)?;
            let resolved = match resolve(access, bound, &original).map_err(CoverageError::Format)? {
                Resolution::Resolved(value) => value,
                other => {
                    return Err(CoverageError::Lookup {
                        node: original.node,
                        resolution: other.map(|_| ()),
                    });
                }
            };
            let node = original.node;
            formats
                .try_push(CoveredFormat {
                    original,
                    reference: resolved.reference,
                    seen: false,
                })
                .map_err(|cause| CoverageError::Access(AccessError::Resource { node, cause }))?;
        }
    }
    Ok(formats)
}

/// Resolves `ObjectReference` with the same XML-owned `SignedInfo`/Manifest kernel
/// used for timestamp Include. Namespace/URI processing, acquisition permission
/// and original-context resolution are never reconstructed in this crate.
/// EN319132-1 §5.2.4 and §6.3 note8 permit a signed Manifest reference.
/// Present MimeType/Encoding values must exactly match corresponding attributes
/// when the resolved target is ds:Object; no case folding or URI normalization
/// is used, and no default is fabricated for an absent attribute.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn resolve<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    format: &Original<X>,
) -> FormatResult<Resolution<Resolved<X::Id>>, X> {
    let layout = bound.containers();
    if format.snapshot != layout.snapshot() || format.signature != layout.signature() {
        return Err(FormatError::Foreign { node: format.node });
    }
    if access.snapshot() != format.snapshot {
        return Err(FormatError::Property(Error::Access(AccessError::Changed {
            node: format.node,
        })));
    }
    let resolved = access
        .query(format.node, |xml, snapshot, work| {
            xml.resolve_reference(
                snapshot,
                format.signature,
                format.node,
                LexicalSource::Attribute(Name {
                    namespace: "",
                    local: "ObjectReference",
                }),
                work,
                |descriptor| {
                    let r = descriptor.reference;
                    if r.status != Status::Valid || r.target == Some(layout.signed()) {
                        return Err(FormatError::Reference {
                            node: r.node,
                            status: r.status,
                        });
                    }
                    if let Some(object) = r.target {
                        object_metadata(access, format, object)?;
                    }
                    Ok(Resolved {
                        reference: r.node,
                        parent: descriptor.parent,
                        target: r.target,
                        coverage: r.coverage,
                    })
                },
            )
        })
        .map_err(|cause| FormatError::Property(Error::Access(cause)))?;
    Ok(match resolved {
        Resolution::Resolved(value) => Resolution::Resolved(value?),
        Resolution::Missing => Resolution::Missing,
        Resolution::Unresolved => Resolution::Unresolved,
        Resolution::Unauthenticated => Resolution::Unauthenticated,
        Resolution::Unsupported => Resolution::Unsupported,
    })
}

fn object_metadata<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    format: &Original<X>,
    object: X::Id,
) -> FormatResult<(), X> {
    let access_error = |cause| FormatError::Property(Error::Access(cause));
    if !access
        .has_name(
            object,
            Name {
                namespace: DS,
                local: "Object",
            },
        )
        .map_err(access_error)?
    {
        return Ok(());
    }
    // EN319132-1 V1.3.1 §5.2.4 requires exactly the same attribute values,
    // not MIME equivalence or URI normalization. Only present format fields
    // participate; no absent Encoding is manufactured from ds:Object.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    for (node, local) in [
        (Some(format.mime), "MimeType"),
        (format.encoding, "Encoding"),
    ] {
        let Some(node) = node else { continue };
        access
            .attribute(
                object,
                Name {
                    namespace: "",
                    local,
                },
                |expected| {
                    let Some(expected) = expected else {
                        return Ok(());
                    };
                    if simple_content_matches(access, node, expected)? {
                        Ok(())
                    } else {
                        Err(FormatError::Metadata {
                            node,
                            object,
                            local,
                        })
                    }
                },
            )
            .map_err(access_error)??;
    }
    Ok(())
}

fn simple_content_matches<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    expected: &str,
) -> FormatResult<bool, X> {
    let access_error = |cause| FormatError::Property(Error::Access(cause));
    let mut child = access.first_child(parent).map_err(access_error)?;
    let mut offset = 0;
    let mut same = true;
    while let Some(node) = child {
        let compared = access
            .inspect(node, |value| match value {
                Node::Element(_) => Err(FormatError::Property(Error::Unexpected { node })),
                Node::Other => Ok(()),
                Node::Text(text) => {
                    if same {
                        if text.len() > expected.len() - offset {
                            same = false;
                        } else {
                            access
                                .query(node, |_, _, work| {
                                    Ok(u64::try_from(text.len())
                                        .map_err(|_| {
                                            structured_asn1::memory::MemoryError::WorkExceeded
                                        })
                                        .and_then(|length| work.charge_work(length)))
                                })
                                .map_err(access_error)?
                                .map_err(|cause| {
                                    access_error(AccessError::Resource { node, cause })
                                })?;
                            let end = offset + text.len();
                            same = text.as_bytes() == &expected.as_bytes()[offset..end];
                            offset = end;
                        }
                    }
                    Ok(())
                }
            })
            .map_err(access_error)?;
        compared?;
        child = access.next_sibling(parent, node).map_err(access_error)?;
    }
    Ok(same && offset == expected.len())
}

/// Original covered roles, before scalar/URI/object-metadata checks.
#[derive(Debug)]
pub struct Format<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    description: Option<N>,
    identifier: Option<N>,
    mime: N,
    encoding: Option<N>,
}

impl<N: Copy, D: Copy, G: Copy> Format<N, D, G> {
    /// Original XML identity and generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Signature whose whole `SignedProperties` coverage protects these nodes.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original `DataObjectFormat`; its unqualified `ObjectReference` attribute
    /// still needs the XML owner's authenticated-reference resolver.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original optional Description string element.
    #[must_use]
    pub fn description(&self) -> Option<N> {
        self.description
    }
    /// Original optional `ObjectIdentifier`, before its own content validation.
    #[must_use]
    pub fn identifier(&self) -> Option<N> {
        self.identifier
    }
    /// Original baseline-mandatory `MimeType`, before MIME/scalar agreement checks.
    #[must_use]
    pub fn mime(&self) -> N {
        self.mime
    }
    /// Original optional Encoding, before XML-owned anyURI validation.
    #[must_use]
    pub fn encoding(&self) -> Option<N> {
        self.encoding
    }
}

/// Source-aware result using the XML owner's original error/identity types.
pub type FormatResult<T, X> = Result<T, FormatError<<X as Xml>::Error, <X as Xml>::Id>>;
/// Original data-object format using the XML owner's stable identities.
pub type Original<X> = Format<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Check the original optional Encoding's XSD1.0 anyURI syntax. Absence stays
/// optional; a present empty value follows anyURI rules rather than being
/// fabricated as absent. EN319132-1 §5.2.4 and Annex C define this datatype.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// This does not resolve the URI, accept an encoding, check other attributes,
/// or repeat the separate ds:Object metadata comparison. Retained format data
/// stay on their original account; THIS query uses the supplied current Work.
pub fn check_encoding<X: crate::scalar::ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    original: &Original<X>,
) -> crate::scalar::ScalarResult<X> {
    use crate::scalar::{Datatype, Error as ScalarError};
    if original.snapshot != access.snapshot() {
        return Err(ScalarError::Access(AccessError::Changed {
            node: original.node,
        }));
    }
    access
        .query(original.node, |_, _, _| Ok(()))
        .map_err(ScalarError::Access)?;
    if let Some(node) = original.encoding {
        crate::scalar::check(access, node, LexicalSource::SimpleContent, Datatype::AnyUri)?;
    }
    Ok(())
}

/// Reads one original format from the complete authenticated property catalogue.
///
/// EN319132-1 V1.3.1 §6.3/Table2 requires `MimeType` in the baseline even though
/// the Annex C base schema makes it optional. `ObjectReference` must be present;
/// §5.2.4's target binding and ds:Object metadata agreement remain separate.
/// No scalar validation, successful reference resolution or MIME match is
/// inferred from this structural reading, and no URI dispatcher is introduced.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signed: &Reading<X>,
    index: usize,
) -> FormatResult<Original<X>, X> {
    let select = || FormatError::Selection {
        signature: signed.signature(),
        index,
    };
    let property = FormatError::Property;
    if access.snapshot() != signed.snapshot() {
        return Err(property(Error::Access(AccessError::Changed {
            node: signed.parent(),
        })));
    }
    access
        .query(signed.parent(), |_, _, work| Ok(work.charge_work(1)))
        .map_err(|cause| property(Error::Access(cause)))?
        .map_err(|cause| {
            property(Error::Resource {
                node: signed.parent(),
                cause,
            })
        })?;
    let objects = signed.data_objects().ok_or_else(select)?;
    let selected = objects.entries().get(index).ok_or_else(select)?;
    if selected.role != DataObjectRole::Format {
        return Err(select());
    }
    let node = selected.node;
    let has_reference = access
        .attribute(
            node,
            Name {
                namespace: "",
                local: "ObjectReference",
            },
            |value| value.is_some(),
        )
        .map_err(|cause| property(Error::Access(cause)))?;
    if !has_reference {
        return Err(property(Error::Missing {
            parent: node,
            local: "ObjectReference",
        }));
    }
    let mut fields = [None; 4];
    let mut previous = 0;
    for child in access.children(node) {
        let child = child.map_err(|cause| property(Error::Child(cause)))?;
        let mut selected = None;
        for (rank, local) in ["Description", "ObjectIdentifier", "MimeType", "Encoding"]
            .iter()
            .enumerate()
        {
            if access
                .has_name(
                    child,
                    Name {
                        namespace: XADES,
                        local,
                    },
                )
                .map_err(|cause| property(Error::Access(cause)))?
            {
                selected = Some(rank);
                break;
            }
        }
        let rank = selected.ok_or_else(|| property(Error::Unexpected { node: child }))?;
        if fields[rank].is_some() {
            return Err(property(Error::Duplicate { node: child }));
        }
        if rank < previous {
            return Err(property(Error::Order { node: child }));
        }
        fields[rank] = Some(child);
        previous = rank;
        match rank {
            1 => {
                crate::identifier::read(access, child).map_err(property)?;
            }
            2 => crate::mime::check(access, child).map_err(property)?,
            _ => crate::properties::simple_content(access, child).map_err(property)?,
        }
    }
    let mime = fields[2].ok_or_else(|| {
        property(Error::Missing {
            parent: node,
            local: "MimeType",
        })
    })?;
    Ok(Format {
        snapshot: signed.snapshot(),
        signature: signed.signature(),
        node,
        description: fields[0],
        identifier: fields[1],
        mime,
        encoding: fields[3],
    })
}
