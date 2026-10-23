//! Original `PoE` extras: one model, exact location, separate frozen pool slots.
use super::{
    ArtifactRef, ArtifactSource, Crl, DocumentId, ISSUER, Index, Node, Occurrence, Ocsp, Open,
    Placement, PoeLocation, Pool, push_open,
};
use crate::{
    Error,
    prepare::{Preparation, proofs::Body},
};
use structured_asn1::{
    Element, Reader, Tag,
    memory::{OwnedVec, Work},
    universal,
};
use structured_cms::signed::{CertificateChoice, OtherRevocationInfo};
use structured_ltv::{material, source::Query};
use structured_pkix::crl::CertificateList;
const FIELD: &str = "cades.material.poe";

pub(super) enum Kind {
    Certificate(usize),
    Crl(usize),
    Ocsp(usize),
    Open,
}
pub(super) struct Slot {
    location: PoeLocation,
    node: Node,
    kind: Kind,
    certificate: bool,
}

pub(super) fn collect<'d, W: Work>(
    prepared: &Preparation<'_, 'd>,
    operation: &Reader<'d>,
    crls: &mut OwnedVec<Crl<'d>, W>,
    ocsp: &mut OwnedVec<Ocsp<'d>, W>,
    open: &mut OwnedVec<Open<'d>, W>,
) -> crate::Result<OwnedVec<Slot>> {
    let work = operation.execution();
    let mut slots = work.vector();
    for (proof, entry) in prepared.parsed.proofs.entries.iter().enumerate() {
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, entry.required.property.span().start))?;
        let Body::Poe(poe) = &entry.body else {
            continue;
        };
        if let Some(set) = poe.certificates() {
            let origin = set.fields_source().query_in(operation)?;
            let scoped = origin.execution();
            for (member, choice) in set.choices().iter().enumerate() {
                scoped
                    .charge_work(1)
                    .map_err(|cause| Error::resource(cause, FIELD, poe.element().span().start))?;
                let location = PoeLocation {
                    signature: entry.required.signature,
                    property: entry.required.property,
                    proof,
                    member,
                };
                let (node, kind) = match choice {
                    CertificateChoice::X509(index) => (
                        Node::of(set.certificates()[*index].span()),
                        Kind::Certificate(*index),
                    ),
                    CertificateChoice::Extended(element)
                    | CertificateChoice::AttributeV1(element)
                    | CertificateChoice::AttributeV2(element)
                    | CertificateChoice::Other(element) => {
                        push_open(open, *element, Placement::PoeCertificate(location), None)?;
                        (Node::of(element.span()), Kind::Open)
                    }
                };
                slots
                    .try_push(Slot {
                        location,
                        node,
                        kind,
                        certificate: true,
                    })
                    .map_err(|cause| Error::resource(cause, FIELD, node.span().start))?;
            }
        }
        if let Some(set) = poe.revocations() {
            let origin = set.fields_source().query_in(operation)?;
            let scoped = origin.execution();
            for (member, element) in set.values().iter().enumerate() {
                scoped
                    .charge_work(1)
                    .map_err(|cause| Error::resource(cause, FIELD, element.span().start))?;
                let location = PoeLocation {
                    signature: entry.required.signature,
                    property: entry.required.property,
                    proof,
                    member,
                };
                let kind = revocation(
                    &origin,
                    element,
                    Placement::PoeRevocation(location),
                    operation,
                    crls,
                    ocsp,
                    open,
                )?;
                slots
                    .try_push(Slot {
                        location,
                        node: Node::of(element.span()),
                        kind,
                        certificate: false,
                    })
                    .map_err(|cause| Error::resource(cause, FIELD, element.span().start))?;
            }
        }
    }
    Ok(slots.into_owned())
}

// Root, TSA and PoE containers use this SAME first-read revocation kernel.
pub(super) fn revocation<'d, W: Work>(
    parent: &Reader<'d>,
    element: &Element<'d>,
    placement: Placement,
    operation: &Reader<'d>,
    crls: &mut OwnedVec<Crl<'d>, W>,
    ocsp: &mut OwnedVec<Ocsp<'d>, W>,
    open: &mut OwnedVec<Open<'d>, W>,
) -> crate::Result<Kind> {
    let result = if element.tag() == Tag::constructed(universal::SEQUENCE) {
        CertificateList::read_element(parent, element)
            .map_err(Error::Pkix)
            .and_then(|value| {
                let index = crls.len();
                crls.try_push(Crl {
                    value,
                    node: Node::of(element.span()),
                    placement,
                })
                .map_err(|cause| Error::resource(cause, FIELD, element.span().start))?;
                Ok(Kind::Crl(index))
            })
    } else {
        OtherRevocationInfo::read(parent, element)
            .map_err(Error::Cms)
            .and_then(|other| other.ocsp().map_err(Error::Cms))
            .and_then(|response| {
                let Some(response) = response else {
                    return Ok(Kind::Open);
                };
                let Some(value) = response.basic_in(operation).map_err(Error::Pkix)? else {
                    return Ok(Kind::Open);
                };
                let index = ocsp.len();
                ocsp.try_push(Ocsp {
                    value,
                    node: Node::of(element.span()),
                    placement,
                })
                .map_err(|cause| Error::resource(cause, FIELD, element.span().start))?;
                Ok(Kind::Ocsp(index))
            })
    };
    match result {
        Ok(Kind::Open) => {
            push_open(open, *element, placement, None)?;
            Ok(Kind::Open)
        }
        Ok(kind) => Ok(kind),
        Err(cause) if cause.is_terminal() => Err(cause),
        Err(cause) => {
            push_open(open, *element, placement, Some(cause))?;
            Ok(Kind::Open)
        }
    }
}

pub(super) fn index<'s, 'm, 'd, Q>(
    pool: &'s Pool<'_, 'm, 'd>,
    index: &mut Index<'s, 'm, 'd, Q::Work>,
    query: &Q,
    mut ordinal: usize,
) -> Result<(), material::IndexError<Node>>
where
    Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
    'd: 's,
{
    for slot in &pool.proof_slots {
        index.admit(query)?;
        let value = match slot.kind {
            Kind::Certificate(member) => {
                let Body::Poe(poe) = &pool.prepared.parsed.proofs.entries[slot.location.proof].body
                else {
                    unreachable!("slots originate only from PoE");
                };
                ArtifactRef::Certificate(
                    &poe.certificates().expect("certificate slot").certificates()[member],
                )
            }
            Kind::Crl(member) => ArtifactRef::Crl(&pool.crls[member].value),
            Kind::Ocsp(member) => ArtifactRef::Ocsp(&pool.ocsp[member].value),
            Kind::Open => {
                ordinal = next(ordinal, slot.node)?;
                continue;
            }
        };
        // A PoE does NOT authenticate its unsigned date or own proof value.
        // The exact individual extra is the incorporation/coverage boundary,
        // never a fabricated whole-PoE or timestamp SignedData enclosure.
        let placement = if slot.certificate {
            Placement::PoeCertificate(slot.location)
        } else {
            Placement::PoeRevocation(slot.location)
        };
        index.insert(
            ISSUER,
            value,
            Occurrence::new(
                ArtifactSource::Material(ordinal),
                pool.prepared.document().locate(slot.node.span()),
                placement,
            ),
            query,
        )?;
        ordinal = next(ordinal, slot.node)?;
    }
    Ok(())
}
fn next(ordinal: usize, node: Node) -> Result<usize, material::IndexError<Node>> {
    ordinal
        .checked_add(1)
        .ok_or(material::IndexError::Resource {
            signature: node,
            cause: structured_asn1::memory::MemoryError::CapacityOverflow,
        })
}
