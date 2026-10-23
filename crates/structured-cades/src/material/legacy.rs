//! Borrow original first-read validation values; never parse them for an index.

use super::{
    ArtifactRef, ArtifactSource, Error, ISSUER, Index, LegacyLocation, Node, Occurrence, Placement,
    Pool, Preparation,
};
use crate::properties::{Properties, values::Values};
use core::ops::ControlFlow;
use structured_asn1::{
    Reader, Span,
    memory::{OwnedVec, Work},
};
use structured_ltv::{material, source::Query};
use structured_pkix::{crl::CertificateList, ocsp::BasicResponse};

pub(super) struct Related<'d> {
    signature: Node,
    unsigned: Option<Span>,
    properties: Properties<'d>,
}
#[derive(Clone, Copy)]
struct Owner {
    signature: Node,
    token: Option<usize>,
    unsigned: Option<Span>,
    source: ModelSource,
}
#[derive(Clone, Copy)]
enum ModelSource {
    Root,
    Counter(usize),
    Parallel(usize),
    Token(usize),
    Related(usize),
}
pub(super) struct Slot {
    source: ModelSource,
    member: usize,
}
pub(super) struct Slots {
    pub(super) crls: OwnedVec<Slot>,
    pub(super) ocsp: OwnedVec<Slot>,
}
impl Owner {
    fn location(self, property: Node, member: usize) -> LegacyLocation {
        let span = property.span();
        let unsigned = self
            .unsigned
            .is_some_and(|outer| span.start >= outer.start && span.end() <= outer.end());
        LegacyLocation {
            signature: self.signature,
            property,
            member,
            token: self.token,
            unsigned,
        }
    }
}

pub(super) fn read_related<'d>(
    prepared: &Preparation<'_, 'd>,
    operation: &Reader<'d>,
) -> crate::Result<OwnedVec<Related<'d>>> {
    let work = operation.execution();
    let mut out = work.vector();
    for signer in prepared.document().message().signers() {
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, "cades.material", signer.span().start))?;
        if core::ptr::eq(signer, prepared.signer()) {
            continue;
        }
        if !Properties::has_legacy_values(signer, operation)? {
            continue;
        }
        out.try_push(Related {
            signature: Node::of(signer.span()),
            unsigned: signer.unsigned_attributes().map(|set| set.element().span()),
            properties: Properties::read(signer, operation)?,
        })
        .map_err(|cause| Error::resource(cause, "cades.material", signer.span().start))?;
    }
    Ok(out.into_owned())
}

// The admission callback runs BEFORE each optional source is examined, even
// when no values exist. Filtered-out counters/tokens therefore still cost work.
fn visit<'a, 'm, 'd, E>(
    pool: &'a Pool<'_, 'm, 'd>,
    admit: impl FnMut(Node) -> Result<(), E>,
    callback: impl FnMut(&'a Properties<'d>, Owner) -> Result<ControlFlow<()>, E>,
) -> Result<(), E> {
    visit_sources(pool.prepared, pool.tokens, &pool.related, admit, callback)
}

fn visit_sources<'a, 'm, 'd, E>(
    prepared: &'a Preparation<'m, 'd>,
    tokens: &'a crate::prepare::tokens::Cache<'m, 'd>,
    related: &'a [Related<'d>],
    mut admit: impl FnMut(Node) -> Result<(), E>,
    mut callback: impl FnMut(&'a Properties<'d>, Owner) -> Result<ControlFlow<()>, E>,
) -> Result<(), E> {
    let root = prepared.signer();
    let owner = Owner {
        signature: Node::of(root.span()),
        token: None,
        unsigned: root.unsigned_attributes().map(|set| set.element().span()),
        source: ModelSource::Root,
    };
    admit(owner.signature)?;
    if callback(prepared.properties(), owner)?.is_break() {
        return Ok(());
    }
    for (ordinal, counter) in prepared.counters().iter().enumerate() {
        admit(counter.node())?;
        if let Some(properties) = counter.properties() {
            let unsigned = counter.encoding.as_ref().and_then(|encoding| {
                crate::prepare::encoding::SignerView::Counter(encoding)
                    .unsigned()
                    .map(|(span, _, _)| span)
            });
            let owner = Owner {
                signature: counter.node(),
                token: None,
                unsigned,
                source: ModelSource::Counter(ordinal),
            };
            if callback(properties, owner)?.is_break() {
                return Ok(());
            }
        }
    }
    for ordinal in 0..prepared.timestamps().len() {
        admit(prepared.timestamps()[ordinal].property())?;
        let Some(token) = tokens.token(ordinal) else {
            continue;
        };
        let signer = token.token.signer();
        let owner = Owner {
            signature: Node::of(signer.span()),
            token: Some(token.ordinal),
            unsigned: signer.unsigned_attributes().map(|set| set.element().span()),
            source: ModelSource::Token(ordinal),
        };
        if let Some(properties) = token.properties
            && callback(properties, owner)?.is_break()
        {
            return Ok(());
        }
    }
    for (ordinal, counter) in prepared.parallel_counters().iter().enumerate() {
        admit(counter.node())?;
        if let Some(properties) = counter.properties() {
            let unsigned = counter.encoding.as_ref().and_then(|encoding| {
                crate::prepare::encoding::SignerView::Counter(encoding)
                    .unsigned()
                    .map(|(span, _, _)| span)
            });
            let owner = Owner {
                signature: counter.node(),
                token: None,
                unsigned,
                source: ModelSource::Parallel(ordinal),
            };
            if callback(properties, owner)?.is_break() {
                return Ok(());
            }
        }
    }
    for (ordinal, source) in related.iter().enumerate() {
        admit(source.signature)?;
        let owner = Owner {
            signature: source.signature,
            token: None,
            unsigned: source.unsigned,
            source: ModelSource::Related(ordinal),
        };
        if callback(&source.properties, owner)?.is_break() {
            return Ok(());
        }
    }
    Ok(())
}

pub(super) fn append_open<'d, W: Work>(
    prepared: &Preparation<'_, 'd>,
    tokens: &crate::prepare::tokens::Cache<'_, 'd>,
    related: &[Related<'d>],
    open: &mut OwnedVec<super::Open<'d>, W>,
    work: &W,
) -> crate::Result<()> {
    visit_sources(
        prepared,
        tokens,
        related,
        |node| {
            work.charge_work(1)
                .map_err(|cause| Error::resource(cause, "cades.material", node.span().start))
        },
        |properties, owner| {
            if let Some(values) = properties.legacy_values() {
                for (member, other) in values.other_revocation().iter().enumerate() {
                    let location = owner.location(other.property, member);
                    open.try_push(super::Open {
                        element: other.enclosure,
                        node: Node::of(other.enclosure.span()),
                        placement: Placement::OtherRevocationValues(location),
                        cause: None,
                    })
                    .map_err(|cause| {
                        Error::resource(cause, "cades.material", other.property.span().start)
                    })?;
                }
            }
            Ok(ControlFlow::Continue(()))
        },
    )
}

pub(super) fn slots(pool: &Pool<'_, '_, '_>, work: &impl Work) -> crate::Result<Option<Slots>> {
    let mut crls = None;
    let mut ocsp = None;
    let at = pool.prepared.signer().span().start;
    let resource = |cause| Error::resource(cause, "cades.material", at);
    visit(
        pool,
        |node| {
            work.charge_work(1)
                .map_err(|cause| Error::resource(cause, "cades.material", node.span().start))
        },
        |properties, owner| {
            if let Some(values) = properties.legacy_values() {
                if !values.crls().is_empty() {
                    let slots = crls.get_or_insert_with(|| work.vector());
                    for member in 0..values.crls().len() {
                        slots
                            .try_push(Slot {
                                source: owner.source,
                                member,
                            })
                            .map_err(resource)?;
                    }
                }
                if !values.ocsp_responses().is_empty() {
                    let slots = ocsp.get_or_insert_with(|| work.vector());
                    for member in 0..values.ocsp_responses().len() {
                        slots
                            .try_push(Slot {
                                source: owner.source,
                                member,
                            })
                            .map_err(resource)?;
                    }
                }
            }
            Ok(ControlFlow::Continue(()))
        },
    )?;
    // Total public lengths are checked once; subsequent O(1) counts cannot
    // overflow even on a narrower target.
    let crl_count = crls.as_ref().map_or(0, |rows| rows.len());
    let ocsp_count = ocsp.as_ref().map_or(0, |rows| rows.len());
    let overflow = || resource(structured_asn1::memory::MemoryError::CapacityOverflow);
    crl_count
        .checked_add(pool.crls.len())
        .ok_or_else(overflow)?;
    ocsp_count
        .checked_add(pool.ocsp.len())
        .ok_or_else(overflow)?;
    if crls.is_none() && ocsp.is_none() {
        return Ok(None);
    }
    Ok(Some(Slots {
        crls: crls.unwrap_or_else(|| work.vector()).into_owned(),
        ocsp: ocsp.unwrap_or_else(|| work.vector()).into_owned(),
    }))
}

fn values<'a, 'd>(pool: &'a Pool<'_, '_, 'd>, source: ModelSource) -> &'a Values<'d> {
    // Sealed slots belong to this immutable pool and are constructed only
    // after seeing an actual first-read values model. No caller index can
    // select a model from another phase/document.
    match source {
        ModelSource::Root => pool.prepared.properties(),
        ModelSource::Counter(index) => pool.prepared.counters()[index]
            .properties()
            .expect("recorded properties"),
        ModelSource::Parallel(index) => pool.prepared.parallel_counters()[index]
            .properties()
            .expect("recorded properties"),
        ModelSource::Token(index) => pool
            .tokens
            .token(index)
            .expect("recorded token")
            .properties
            .expect("recorded properties"),
        ModelSource::Related(index) => &pool.related[index].properties,
    }
    .legacy_values()
    .expect("recorded values")
}

pub(super) fn crl<'a, 'd>(
    pool: &'a Pool<'_, '_, 'd>,
    ordinal: usize,
    work: &impl Work,
) -> crate::Result<Option<&'a CertificateList<'d>>> {
    work.charge_work(3).map_err(|cause| {
        Error::resource(
            cause,
            "cades.material.crl",
            pool.prepared.signer().span().start,
        )
    })?;
    let Some(slots) = &pool.legacy_slots else {
        return Ok(None);
    };
    let Some(slot) = slots.crls.get(ordinal) else {
        return Ok(None);
    };
    Ok(Some(&values(pool, slot.source).crls()[slot.member].value))
}
pub(super) fn ocsp<'a, 'd>(
    pool: &'a Pool<'_, '_, 'd>,
    ordinal: usize,
    work: &impl Work,
) -> crate::Result<Option<&'a BasicResponse<'d>>> {
    work.charge_work(3).map_err(|cause| {
        Error::resource(
            cause,
            "cades.material.ocsp",
            pool.prepared.signer().span().start,
        )
    })?;
    let Some(slots) = &pool.legacy_slots else {
        return Ok(None);
    };
    let Some(slot) = slots.ocsp.get(ordinal) else {
        return Ok(None);
    };
    Ok(Some(
        &values(pool, slot.source).ocsp_responses()[slot.member].value,
    ))
}

pub(super) fn index<'s, 'm, 'd, Q>(
    pool: &'s Pool<'_, 'm, 'd>,
    index: &mut Index<'s, 'm, 'd, Q::Work>,
    query: &Q,
) -> Result<usize, material::IndexError<Node>>
where
    Q: Query<Id = Node, Document = super::DocumentId<'m, 'd>, Generation = ()>,
    'd: 's,
{
    let root = pool.prepared.signer();
    let signature = Node::of(root.span());
    let capacity = || material::IndexError::Resource {
        signature,
        cause: structured_asn1::memory::MemoryError::CapacityOverflow,
    };
    let mut ordinal = pool
        .prepared
        .document()
        .message()
        .certificate_choices()
        .len()
        .checked_add(pool.prepared.document().message().revocations().len())
        .ok_or_else(capacity)?;
    visit(
        pool,
        |node| query.admit(node, 1).map_err(material::IndexError::Scope),
        |properties, owner| {
            if let Some(values) = properties.legacy_values() {
                for entry in values.certificates() {
                    index.admit(query)?;
                    let location = owner.location(entry.property, entry.ordinal);
                    insert(
                        pool,
                        index,
                        query,
                        ordinal,
                        Member {
                            enclosure: entry.enclosure,
                            location,
                        },
                        Placement::CertificateValues(location),
                        ArtifactRef::Certificate(&entry.value),
                    )?;
                    ordinal = ordinal.checked_add(1).ok_or_else(capacity)?;
                }
                for entry in values.crls() {
                    index.admit(query)?;
                    let location = owner.location(entry.property, entry.ordinal);
                    insert(
                        pool,
                        index,
                        query,
                        ordinal,
                        Member {
                            enclosure: entry.enclosure,
                            location,
                        },
                        Placement::CrlValues(location),
                        ArtifactRef::Crl(&entry.value),
                    )?;
                    ordinal = ordinal.checked_add(1).ok_or_else(capacity)?;
                }
                for entry in values.ocsp_responses() {
                    index.admit(query)?;
                    let location = owner.location(entry.property, entry.ordinal);
                    insert(
                        pool,
                        index,
                        query,
                        ordinal,
                        Member {
                            enclosure: entry.enclosure,
                            location,
                        },
                        Placement::OcspValues(location),
                        ArtifactRef::Ocsp(&entry.value),
                    )?;
                    ordinal = ordinal.checked_add(1).ok_or_else(capacity)?;
                }
            }
            Ok(ControlFlow::Continue(()))
        },
    )?;
    Ok(ordinal)
}

#[derive(Clone, Copy)]
struct Member {
    enclosure: Node,
    location: LegacyLocation,
}

fn insert<'s, 'm, 'd, Q>(
    pool: &Pool<'_, 'm, 'd>,
    index: &mut Index<'s, 'm, 'd, Q::Work>,
    query: &Q,
    ordinal: usize,
    source: Member,
    placement: Placement,
    value: ArtifactRef<'s, 'd>,
) -> Result<(), material::IndexError<Node>>
where
    Q: Query<Id = Node, Document = super::DocumentId<'m, 'd>, Generation = ()>,
    'd: 's,
{
    // This format-owned slot is outside the root CHOICE range. The explicit
    // placement retains the actual attribute/member; it is not a made-up
    // certificate or revocation CHOICE inside a timestamp SignedData.
    let enclosure = match source.location.token {
        Some(token) => super::token_enclosure(pool.prepared, token)?,
        None => source.enclosure,
    };
    index.insert(
        ISSUER,
        value,
        Occurrence::new(
            ArtifactSource::Material(ordinal),
            pool.prepared.document().locate(enclosure.span()),
            placement,
        ),
        query,
    )
}

pub(super) fn malformed<E>(
    pool: &Pool<'_, '_, '_>,
    admit: impl FnMut(Node) -> Result<(), E>,
    mut callback: impl FnMut(Node, &crate::properties::Fault) -> Result<(), E>,
) -> Result<(), E> {
    visit(pool, admit, |properties, owner| {
        // Causes stay in their single original model, never cloned just to
        // create a material index. This census adds located negative facts.
        for fault in properties.faults() {
            callback(owner.signature, fault)?;
        }
        Ok(ControlFlow::Continue(()))
    })
}
