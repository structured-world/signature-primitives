//! Original selection phases; every output keeps the caller's scoped owner.

use super::{
    Edition, FIELD, Header, Part, SelectionError, archive_kind, category, covered_container,
};
use crate::{
    Error,
    prepare::{
        Preparation,
        encoding::{AttributeEncoding, SignerView},
    },
    preservation::Kind,
    source::Node,
};
use core::ops::Range;
use structured_asn1::{
    Oid, Reader,
    memory::{MemoryError, OwnedMap, OwnedVec, Work},
};
use structured_ltv::timestamp::Purpose;

fn resource(at: Node, cause: MemoryError) -> SelectionError {
    SelectionError::Processing(Error::resource(cause, FIELD, at.span().start))
}

pub(super) fn choose(
    prepared: &Preparation<'_, '_>,
    ordinal: usize,
    edition: Edition,
    previous: &[usize],
    later: &[super::Later<'_, '_, '_>],
    operation: &Reader<'_>,
) -> Result<OwnedVec<bool>, SelectionError> {
    let target = &prepared.timestamps()[ordinal];
    let work = operation.execution();
    let refusal = |cause| resource(target.property(), cause);
    let mut chosen = work.vector();
    chosen
        .try_reserve_exact(prepared.timestamps().len())
        .map_err(refusal)?;
    for _ in prepared.timestamps() {
        chosen.try_push(false).map_err(refusal)?;
    }
    for &index in previous {
        work.charge_work(1).map_err(refusal)?;
        let entry = prepared
            .timestamps()
            .get(index)
            .ok_or(SelectionError::WrongOccurrence)?;
        if index == ordinal {
            return Err(SelectionError::SelfIncluded);
        }
        if entry.owner() != target.owner()
            || entry.purpose() != Purpose::Archive
            || entry.value().is_none()
            || chosen[index]
        {
            return Err(SelectionError::WrongOccurrence);
        }
        if edition == Edition::Rfc3126 && entry.preservation_kind() != Some(Kind::ArchiveV1) {
            return Err(SelectionError::WrongEdition);
        }
        chosen[index] = true;
    }
    for (index, entry) in prepared.timestamps().iter().enumerate() {
        work.charge_work(1).map_err(refusal)?;
        if entry.owner() != target.owner()
            || index == ordinal
            || chosen[index]
            || entry.purpose() != Purpose::Archive
        {
            continue;
        }
        let mut proven = false;
        for proof in later {
            if proof.permits(prepared, entry, target, operation)? {
                proven = true;
                break;
            }
        }
        if !proven {
            return Err(SelectionError::UnprovenLater {
                property: entry.property(),
            });
        }
    }
    Ok(chosen.into_owned())
}

pub(super) struct Output<'out, 'input, W: Work, Q: Work> {
    parts: &'out mut OwnedVec<Part<'input>, W>,
    covered: &'out mut OwnedMap<Node, bool, W>,
    work: &'out Q,
    at: Node,
}
impl<'o, 's, W: Work, Q: Work> Output<'o, 's, W, Q> {
    pub(super) fn new(
        parts: &'o mut OwnedVec<Part<'s>, W>,
        covered: &'o mut OwnedMap<Node, bool, W>,
        work: &'o Q,
        at: Node,
    ) -> Self {
        Self {
            parts,
            covered,
            work,
            at,
        }
    }
    pub(super) fn prefix<'m, 'd: 's>(
        &mut self,
        prepared: &'s Preparation<'m, 'd>,
        view: SignerView<'s, 'd>,
        owner: Node,
        edition: Edition,
        operation: &Reader<'d>,
    ) -> Result<usize, SelectionError> {
        let refusal = |cause| resource(self.at, cause);
        if edition != Edition::Rfc3126 {
            self.parts
                .try_push(Part::Current(
                    prepared.document().message().encap_content_encoding(),
                ))
                .map_err(refusal)?;
        }
        let payload_at = self.parts.len();
        if edition == Edition::Rfc3126 {
            if let Some((_, bytes)) = view.signed() {
                self.parts.try_push(Part::Current(bytes)).map_err(refusal)?;
            }
            for piece in prepared.signature_of(owner, operation)? {
                self.parts
                    .try_push(Part::Current(piece.as_bytes()))
                    .map_err(refusal)?;
            }
        } else {
            for bytes in [
                prepared.document().message().certificate_encoding(),
                prepared.document().message().revocation_encoding(),
            ]
            .into_iter()
            .flatten()
            {
                self.parts.try_push(Part::Current(bytes)).map_err(refusal)?;
            }
            self.parts
                .try_push(Part::Current(view.fields()))
                .map_err(refusal)?;
        }
        Ok(payload_at)
    }
    pub(super) fn unsigned<'m, 'd: 's>(
        &mut self,
        prepared: &'s Preparation<'m, 'd>,
        view: SignerView<'s, 'd>,
        edition: Edition,
        chosen: &[bool],
    ) -> Result<(), SelectionError> {
        let at = self.at;
        let refusal = |cause| resource(at, cause);
        // RFC3126 fixes the category order. Later editions retain physical
        // attribute order; neither branch sorts or re-encodes original values.
        let passes = if edition == Edition::Rfc3126 { 8 } else { 1 };
        let mut certificate_values = false;
        let mut revocation_values = false;
        for pass in 0..passes {
            for index in 0..view.attributes() {
                self.work.charge_work(1).map_err(refusal)?;
                let attribute = view.attribute(index).expect("bounded original catalogue");
                let category = if edition == Edition::Rfc3126 {
                    self.work
                        .charge_work(1 + attribute.kind.as_bytes().len().min(11) as u64)
                        .map_err(refusal)?;
                    let last = [14, 21, 22, 23, 24, 25, 26, 27][pass];
                    if attribute.kind
                        != Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, last])
                    {
                        continue;
                    }
                    Some(pass)
                } else {
                    self.work
                        .charge_work(8 * (1 + attribute.kind.as_bytes().len().min(11) as u64))
                        .map_err(refusal)?;
                    category(attribute.kind)
                };
                certificate_values |= category == Some(3);
                revocation_values |= category == Some(4);
                if archive_kind(attribute.kind).is_none()
                    && attribute.kind != structured_cms::oid::ARCHIVE_TIMESTAMP_V3
                {
                    self.ordinary(prepared, attribute, edition)?;
                } else {
                    self.archive(prepared, attribute, edition, chosen)?;
                }
            }
        }
        if edition == Edition::Rfc3126 && (!certificate_values || !revocation_values) {
            return Err(SelectionError::PriorNotPreserved);
        }
        Ok(())
    }
    fn ordinary<'m, 'd: 's>(
        &mut self,
        prepared: &'s Preparation<'m, 'd>,
        attribute: AttributeEncoding<'d>,
        edition: Edition,
    ) -> Result<(), SelectionError> {
        let refusal = |cause| resource(self.at, cause);
        self.parts
            .try_push(Part::Current(if edition == Edition::Rfc3126 {
                attribute.contents
            } else {
                attribute.whole
            }))
            .map_err(refusal)?;
        self.covered
            .try_insert(Node::of(attribute.span), edition != Edition::Rfc3126)
            .map_err(refusal)?;
        if let Some(value) = attribute.single {
            self.covered
                .try_insert(Node::of(value), true)
                .map_err(refusal)?;
        }
        if let Some(ranges) = &prepared.timestamp_ranges
            && let Some(range) = ranges
                .get(&Node::of(attribute.span), self.work)
                .map_err(refusal)?
        {
            for ordinal in range.clone() {
                self.work.charge_work(1).map_err(refusal)?;
                if let Some(value) = prepared.timestamps()[ordinal].value() {
                    self.covered
                        .try_insert(Node::of(value.span()), true)
                        .map_err(refusal)?;
                }
            }
        }
        Ok(())
    }
    fn archive<'m, 'd: 's>(
        &mut self,
        prepared: &'s Preparation<'m, 'd>,
        attribute: AttributeEncoding<'d>,
        edition: Edition,
        chosen: &[bool],
    ) -> Result<(), SelectionError> {
        let at = self.at;
        let refusal = |cause| resource(at, cause);
        let ranges = prepared
            .timestamp_ranges
            .as_ref()
            .ok_or(SelectionError::WrongOccurrence)?;
        let range = ranges
            .get(&Node::of(attribute.span), self.work)
            .map_err(refusal)?
            .ok_or(SelectionError::WrongOccurrence)?;
        let mut count = 0usize;
        let mut length = 0u64;
        for value in range.clone() {
            self.work.charge_work(1).map_err(refusal)?;
            if chosen[value] {
                let element = prepared.timestamps()[value]
                    .value()
                    .ok_or(SelectionError::WrongOccurrence)?;
                length = length
                    .checked_add(element.as_bytes().len() as u64)
                    .ok_or(SelectionError::LengthOverflow)?;
                count += 1;
            }
        }
        if count == 0 {
            return Ok(());
        }
        if count == range.len() {
            self.parts
                .try_push(Part::Current(if edition == Edition::Rfc3126 {
                    attribute.contents
                } else {
                    attribute.whole
                }))
                .map_err(refusal)?;
            self.covered
                .try_insert(Node::of(attribute.span), edition != Edition::Rfc3126)
                .map_err(refusal)?;
        } else {
            self.partial(prepared, attribute, edition, chosen, range.clone(), length)?;
        }
        for value in range.clone() {
            self.work.charge_work(1).map_err(refusal)?;
            if chosen[value] {
                let element = prepared.timestamps()[value]
                    .value()
                    .expect("checked readable member");
                self.covered
                    .try_insert(Node::of(element.span()), true)
                    .map_err(refusal)?;
            }
        }
        Ok(())
    }
    fn partial<'m, 'd: 's>(
        &mut self,
        prepared: &'s Preparation<'m, 'd>,
        attribute: AttributeEncoding<'d>,
        edition: Edition,
        chosen: &[bool],
        range: Range<usize>,
        length: u64,
    ) -> Result<(), SelectionError> {
        let refusal = |cause| resource(self.at, cause);
        let set_header = Header::new(0x31, length);
        let body_length = (attribute.kind_encoding.len() as u64)
            .checked_add(u64::from(set_header.length))
            .and_then(|n| n.checked_add(length))
            .ok_or(SelectionError::LengthOverflow)?;
        if edition != Edition::Rfc3126 {
            self.parts
                .try_push(Part::Framing(Header::new(0x30, body_length)))
                .map_err(refusal)?;
        }
        self.parts
            .try_push(Part::Current(attribute.kind_encoding))
            .map_err(refusal)?;
        self.parts
            .try_push(Part::Framing(set_header))
            .map_err(refusal)?;
        for value in range {
            self.work.charge_work(1).map_err(refusal)?;
            if chosen[value] {
                self.parts
                    .try_push(Part::Current(
                        prepared.timestamps()[value]
                            .value()
                            .expect("checked readable member")
                            .as_bytes(),
                    ))
                    .map_err(refusal)?;
            }
        }
        Ok(())
    }
    pub(super) fn context<'m, 'd: 's>(
        &mut self,
        prepared: &'s Preparation<'m, 'd>,
        view: SignerView<'s, 'd>,
        owner: Node,
        edition: Edition,
    ) -> Result<(), SelectionError> {
        let refusal = |cause| resource(self.at, cause);
        if let Some((signed, _)) = view.signed() {
            for entry in prepared.timestamps() {
                self.work.charge_work(1).map_err(refusal)?;
                let span = entry.property().span();
                if entry.owner() == owner
                    && span.start >= signed.start
                    && span.end() <= signed.end()
                {
                    self.covered
                        .try_insert(entry.property(), true)
                        .map_err(refusal)?;
                    if let Some(value) = entry.value() {
                        self.covered
                            .try_insert(Node::of(value.span()), true)
                            .map_err(refusal)?;
                    }
                }
            }
        }
        if edition != Edition::Rfc3126 {
            for value in prepared.document().message().certificates() {
                self.covered
                    .try_insert(Node::of(value.span()), true)
                    .map_err(refusal)?;
            }
            for value in prepared.document().message().revocations() {
                self.covered
                    .try_insert(Node::of(value.span()), true)
                    .map_err(refusal)?;
            }
        }
        for counter in prepared.counters() {
            self.work.charge_work(1).map_err(refusal)?;
            if covered_container(view, counter.node(), self.covered, self.work).map_err(refusal)? {
                self.covered
                    .try_insert(counter.node(), true)
                    .map_err(refusal)?;
            }
        }
        Ok(())
    }
}
