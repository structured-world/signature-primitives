//! Original signed commitments and their authenticated Reference associations.

use crate::binding::{Bound, Status};
use crate::container::XADES;
use crate::identifier;
use crate::properties::{self, DataObjectRole, Error, PropertyResult};
use crate::reference::{
    Completeness, Descriptor, LexicalSource, Parent, ReferenceXml, Resolution, VisitError,
};
use crate::xml::{Access, AccessError, Name, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

/// Schema choice, preserving explicit references and `AllSignedDataObjects`.
#[derive(Debug)]
pub enum Objects<N> {
    /// Original empty marker, not a caller-supplied all-objects assertion.
    All(N),
    /// Nonempty original `ObjectReference` simple-content elements in order.
    References(OwnedVec<N>),
}

/// Structural signed commitment; URI syntax and policy meaning remain separate.
pub struct Reading<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    kind: identifier::Reading<N>,
    objects: Objects<N>,
    qualifiers: Option<N>,
}

impl<N: Copy, D: Copy, G: Copy> Reading<N, D, G> {
    /// Original commitment property.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original identifier. Its URI meaning is defined by registration/policy,
    /// not by a hard-coded common list of commitment types.
    #[must_use]
    pub fn kind(&self) -> &identifier::Reading<N> {
        &self.kind
    }
    /// Original schema choice.
    #[must_use]
    pub fn objects(&self) -> &Objects<N> {
        &self.objects
    }
    /// Original optional qualifiers container; each child was checked for the
    /// schema's `CommitmentTypeQualifier` role, whose `AnyType` payload stays open.
    #[must_use]
    pub fn qualifiers(&self) -> Option<N> {
        self.qualifiers
    }
}

/// Original commitment using this XML owner's identities.
pub type Original<X> = Reading<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Reads the complete §5.2.3 schema choice from covered original properties.
/// A commitment Identifier must not carry Qualifier, including an empty one.
/// Current Work funds even skipped metadata and every retained reference.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signed: &properties::Reading<X>,
    index: usize,
) -> PropertyResult<Original<X>, X> {
    let node = selected(access, signed, index)?;
    let mut kind = None;
    let mut all = None;
    let mut references = access
        .query(node, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    let mut qualifiers = None;
    for child in access.children(node) {
        let child = child.map_err(Error::Child)?;
        if named(access, child, "CommitmentTypeId")? {
            if kind.is_some() {
                return Err(Error::Duplicate { node: child });
            }
            if all.is_some() || !references.is_empty() || qualifiers.is_some() {
                return Err(Error::Order { node: child });
            }
            let original = identifier::read(access, child)?;
            if original.qualifier.is_some() {
                return Err(Error::Forbidden {
                    node: original.identifier,
                });
            }
            kind = Some(original);
        } else if named(access, child, "ObjectReference")? {
            if kind.is_none() || qualifiers.is_some() {
                return Err(Error::Order { node: child });
            }
            if all.is_some() {
                return Err(Error::Unexpected { node: child });
            }
            properties::simple_content(access, child)?;
            references
                .try_push(child)
                .map_err(|cause| Error::Resource { node: child, cause })?;
        } else if named(access, child, "AllSignedDataObjects")? {
            if kind.is_none() || qualifiers.is_some() {
                return Err(Error::Order { node: child });
            }
            if all.is_some() {
                return Err(Error::Duplicate { node: child });
            }
            if !references.is_empty() {
                return Err(Error::Unexpected { node: child });
            }
            if let Some(nested) = access.children(child).next() {
                return Err(Error::Unexpected {
                    node: nested.map_err(Error::Child)?,
                });
            }
            all = Some(child);
        } else if named(access, child, "CommitmentTypeQualifiers")? {
            if qualifiers.is_some() {
                return Err(Error::Duplicate { node: child });
            }
            if kind.is_none() || (all.is_none() && references.is_empty()) {
                return Err(Error::Order { node: child });
            }
            for qualifier in access.children(child) {
                let qualifier = qualifier.map_err(Error::Child)?;
                if !named(access, qualifier, "CommitmentTypeQualifier")? {
                    return Err(Error::Unexpected { node: qualifier });
                }
            }
            qualifiers = Some(child);
        } else {
            return Err(Error::Unexpected { node: child });
        }
    }
    let kind = kind.ok_or(Error::Missing {
        parent: node,
        local: "CommitmentTypeId",
    })?;
    let objects = if let Some(all) = all {
        Objects::All(all)
    } else {
        if references.is_empty() {
            return Err(Error::Missing {
                parent: node,
                local: "ObjectReference or AllSignedDataObjects",
            });
        }
        Objects::References(references.into_owned())
    };
    Ok(Reading {
        snapshot: signed.snapshot(),
        signature: signed.signature(),
        node,
        kind,
        objects,
        qualifiers,
    })
}

/// Original instruction eligible for this commitment, not application acceptance.
#[derive(Debug, Clone, Copy)]
pub struct Object<N> {
    /// Original authenticated Reference node.
    pub reference: N,
    /// Its original `SignedInfo` or authenticated Manifest parent.
    pub parent: Parent<N>,
}

/// Original commitment and completed reference associations. This preserves
/// source facts, not URI lexical validity or acceptance of the claimed meaning.
pub struct Association<N, D, G> {
    original: Reading<N, D, G>,
    objects: OwnedVec<Object<N>>,
}

impl<N, D, G> Association<N, D, G> {
    /// Original covered commitment structure.
    #[must_use]
    pub fn original(&self) -> &Reading<N, D, G> {
        &self.original
    }
    /// Actual original eligible instructions in declared/catalogue order.
    #[must_use]
    pub fn objects(&self) -> &[Object<N>] {
        &self.objects
    }
}

/// Associated commitment using only this owner's stable identity domain; it
/// does not retain the nominal XML adapter or a temporary document-view borrow.
pub type Prepared<X> = Association<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Reads and associates a commitment through the same two kernels used by
/// individual queries. Partial reference results are never returned on refusal.
pub fn prepare<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    signed: &properties::Reading<X>,
    index: usize,
) -> Result<Prepared<X>, AssociationError<X::Error, X::Id>> {
    let original = read(access, signed, index).map_err(AssociationError::Property)?;
    let objects = associate(access, bound, &original)?;
    Ok(Association { original, objects })
}

/// Association refusal preserving resource, processing and lookup distinctions.
#[derive(Debug)]
pub enum AssociationError<E, N> {
    /// Original common source/schema/admission cause.
    Property(Error<E, N>),
    /// XML resolver/catalogue processing cause.
    Processing(E),
    /// Explicit original URI did not resolve to an authenticated instruction.
    Lookup {
        /// Original `ObjectReference` element.
        node: N,
        /// Exact lookup outcome.
        resolution: Resolution<()>,
    },
    /// Referenced data was not checked, or it is `SignedProperties`.
    Ineligible {
        /// Original Reference node.
        node: N,
    },
    /// Original catalogue was not completely processed.
    Incomplete {
        /// Original unprocessed instruction/container.
        node: N,
    },
}

/// Resolves explicit references or expands the original all-objects marker via
/// the same authenticated catalogue. No hash, implicit acquisition, fabricated
/// URI, re-verification or application-policy acceptance occurs here.
pub fn associate<X: ReferenceXml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    original: &Original<X>,
) -> AssociationResult<OwnedVec<Object<X::Id>>, X> {
    let property = AssociationError::Property;
    bind_original(access, bound, original)?;
    let mut output = access
        .query(original.node, |_, _, work| Ok(work.vector()))
        .map_err(|cause| property(Error::Access(cause)))?;
    let is_properties = |r: crate::binding::Reference<'_, X::Id>| match r.target {
        Some(target) => access
            .equal_id(target, bound.containers().signed())
            .map_err(|cause| {
                property(Error::Resource {
                    node: r.node,
                    cause,
                })
            }),
        None => Ok(false),
    };
    let mut retain = |descriptor: Descriptor<'_, X::Id>| {
        let r = descriptor.reference;
        if r.status != Status::Valid {
            return Err(AssociationError::Ineligible { node: r.node });
        }
        output
            .try_push(Object {
                reference: r.node,
                parent: descriptor.parent,
            })
            .map_err(|cause| {
                property(Error::Resource {
                    node: r.node,
                    cause,
                })
            })
    };
    match &original.objects {
        Objects::References(nodes) => {
            for index in 0..nodes.len() {
                admit(access, original.node).map_err(property)?;
                let node = nodes[index];
                let resolved = access
                    .query(node, |xml, snapshot, work| {
                        xml.resolve_reference(
                            snapshot,
                            original.signature,
                            node,
                            LexicalSource::SimpleContent,
                            work,
                            |descriptor| {
                                let r = descriptor.reference;
                                if r.status != Status::Valid || is_properties(r)? {
                                    return Err(AssociationError::Ineligible { node: r.node });
                                }
                                retain(descriptor)
                            },
                        )
                    })
                    .map_err(|cause| property(Error::Access(cause)))?;
                match resolved {
                    Resolution::Resolved(value) => value?,
                    other => {
                        return Err(AssociationError::Lookup {
                            node,
                            resolution: other.map(|_| ()),
                        });
                    }
                }
            }
        }
        Objects::All(_) => {
            let visited = access
                .query(original.node, |xml, snapshot, work| {
                    Ok(xml.visit_authenticated_references(
                        snapshot,
                        original.signature,
                        work,
                        |descriptor| {
                            if is_properties(descriptor.reference)? {
                                return Ok(());
                            }
                            retain(descriptor)
                        },
                    ))
                })
                .map_err(|cause| property(Error::Access(cause)))?;
            let complete = match visited {
                Ok(value) => value,
                Err(VisitError::Processing(cause)) => {
                    return Err(AssociationError::Processing(cause));
                }
                Err(VisitError::Visitor(cause)) => return Err(cause),
            };
            match complete {
                Completeness::Complete => {}
                Completeness::Unchecked(node) | Completeness::Incomplete(node) => {
                    return Err(AssociationError::Incomplete { node });
                }
            }
        }
    }
    Ok(output.into_owned())
}

fn bind_original<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    original: &Original<X>,
) -> AssociationResult<(), X> {
    let property = AssociationError::Property;
    if access.snapshot() != original.snapshot || bound.containers().snapshot() != original.snapshot
    {
        return Err(property(Error::Access(AccessError::Changed {
            node: original.node,
        })));
    }
    if !access
        .equal_id(bound.containers().signature(), original.signature)
        .map_err(|cause| {
            property(Error::Resource {
                node: original.node,
                cause,
            })
        })?
    {
        return Err(property(Error::Access(AccessError::Changed {
            node: original.node,
        })));
    }
    Ok(())
}

/// Association result preserving this owner's processing and original node types.
pub type AssociationResult<T, X> = Result<T, AssociationError<<X as Xml>::Error, <X as Xml>::Id>>;

fn selected<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signed: &properties::Reading<X>,
    index: usize,
) -> PropertyResult<X::Id, X> {
    if access.snapshot() != signed.snapshot() {
        return Err(Error::Access(AccessError::Changed {
            node: signed.parent(),
        }));
    }
    admit(access, signed.parent())?;
    let selection = || Error::Selection {
        parent: signed.parent(),
        index,
    };
    let entry = signed
        .data_objects()
        .and_then(|objects| objects.entries().get(index))
        .ok_or_else(selection)?;
    if entry.role != DataObjectRole::Commitment {
        return Err(selection());
    }
    Ok(entry.node)
}

fn admit<X: Xml, W: Work>(access: &Access<'_, X, W>, node: X::Id) -> PropertyResult<(), X> {
    access
        .query(node, |_, _, work| Ok(work.charge_work(1)))
        .map_err(Error::Access)?
        .map_err(|cause| Error::Resource { node, cause })
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    local: &str,
) -> PropertyResult<bool, X> {
    access
        .has_name(
            node,
            Name {
                namespace: XADES,
                local,
            },
        )
        .map_err(Error::Access)
}
