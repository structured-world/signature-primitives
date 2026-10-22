//! Admission of an actual earlier source, separate from current projection.

use super::{
    ArchiveValue, Edition, FIELD, Framing, HistoricalInput, OriginalSnapshot, Part, SelectionError,
    archive_kind,
};
use crate::{
    Error,
    prepare::{Preparation, encoding::SignerView},
    source::Node,
};
use structured_asn1::{
    Oid, Reader,
    memory::{MemoryError, OwnedMap, OwnedVec, Work},
};
use structured_ltv::timestamp::Purpose;

impl OriginalSnapshot<'_, '_, '_> {
    fn resource(&self, cause: MemoryError) -> SelectionError {
        SelectionError::PriorProcessing(Error::resource(cause, FIELD, self.owner.span().start))
    }
    pub(super) fn boundaries(
        &self,
        prepared: &Preparation<'_, '_>,
        view: SignerView<'_, '_>,
        operation: &Reader<'_>,
    ) -> Result<(), SelectionError> {
        let work = self.reader.execution_query(operation);
        let equal = |left: &[u8], right: &[u8]| -> Result<bool, SelectionError> {
            work.charge_work(1).map_err(|cause| self.resource(cause))?;
            if left.len() != right.len() {
                return Ok(false);
            }
            work.charge_work(left.len() as u64)
                .map_err(|cause| self.resource(cause))?;
            Ok(left == right)
        };
        if core::mem::discriminant(&view) != core::mem::discriminant(&self.signer)
            || !equal(view.fields(), self.signer.fields())?
        {
            return Err(SelectionError::PriorNotPreserved);
        }
        let current = prepared.document().message();
        let prior = self.prepared.document().message();
        if !equal(
            current.encap_content_encoding(),
            prior.encap_content_encoding(),
        )? {
            return Err(SelectionError::PriorNotPreserved);
        }
        for (current, prior) in [
            (current.certificate_encoding(), prior.certificate_encoding()),
            (current.revocation_encoding(), prior.revocation_encoding()),
        ] {
            match (current, prior) {
                (None, None) => {}
                (Some(current), Some(prior)) if equal(current, prior)? => {}
                _ => return Err(SelectionError::PriorNotPreserved),
            }
        }
        Ok(())
    }
    pub(super) fn parent(
        &self,
        prepared: &Preparation<'_, '_>,
        owner: Node,
        operation: &Reader<'_>,
    ) -> Result<(), SelectionError> {
        let work = self.reader.execution_query(operation);
        let current = prepared.counter_parent(owner, operation)?;
        let prior = self
            .prepared
            .counter_parent_in(self.owner, self.reader, operation)
            .map_err(SelectionError::PriorProcessing)?;
        match (current, prior) {
            (None, None) => Ok(()),
            (Some(current), Some(prior)) => {
                let a = prepared.signature_of(current, operation)?;
                let b = self
                    .prepared
                    .signature_of_in(prior, self.reader, operation)
                    .map_err(SelectionError::PriorProcessing)?;
                let mut a_length = 0usize;
                let mut b_length = 0usize;
                for piece in a {
                    work.charge_work(1).map_err(|cause| self.resource(cause))?;
                    a_length = a_length
                        .checked_add(piece.as_bytes().len())
                        .ok_or(SelectionError::LengthOverflow)?;
                }
                for piece in b {
                    work.charge_work(1).map_err(|cause| self.resource(cause))?;
                    b_length = b_length
                        .checked_add(piece.as_bytes().len())
                        .ok_or(SelectionError::LengthOverflow)?;
                }
                if a_length != b_length {
                    return Err(SelectionError::PriorNotPreserved);
                }
                work.charge_work(a_length as u64)
                    .map_err(|cause| self.resource(cause))?;
                if !a
                    .iter()
                    .flat_map(|piece| piece.as_bytes())
                    .eq(b.iter().flat_map(|piece| piece.as_bytes()))
                {
                    return Err(SelectionError::PriorNotPreserved);
                }
                Ok(())
            }
            _ => Err(SelectionError::PriorNotPreserved),
        }
    }
    pub(super) fn attributes<'s>(
        &'s self,
        view: SignerView<'_, '_>,
        operation: &Reader<'_>,
    ) -> Result<OwnedMap<&'s [u8], usize>, SelectionError> {
        let work = self.reader.execution_query(operation);
        let refusal = |cause| self.resource(cause);
        let mut attributes = work.map();
        let mut archive_attributes = work.map();
        let mut remaining = 0usize;
        for index in 0..self.signer.attributes() {
            work.charge_work(1).map_err(refusal)?;
            let attribute = self
                .signer
                .attribute(index)
                .expect("bounded saved catalogue");
            if archive_kind(attribute.kind).is_some()
                || attribute.kind == structured_cms::oid::ARCHIVE_TIMESTAMP_V3
            {
                let count = archive_attributes
                    .get(&attribute.whole, &work)
                    .map_err(refusal)?
                    .copied()
                    .unwrap_or(0usize);
                archive_attributes
                    .try_insert(attribute.whole, count + 1)
                    .map_err(refusal)?;
                continue;
            }
            let count = attributes
                .get(&attribute.whole, &work)
                .map_err(refusal)?
                .copied()
                .unwrap_or(0usize);
            attributes
                .try_insert(attribute.whole, count + 1)
                .map_err(refusal)?;
            remaining += 1;
        }
        for index in 0..view.attributes() {
            work.charge_work(1).map_err(refusal)?;
            let attribute = view.attribute(index).expect("bounded original catalogue");
            if archive_kind(attribute.kind).is_some()
                || attribute.kind == structured_cms::oid::ARCHIVE_TIMESTAMP_V3
            {
                continue;
            }
            match attributes
                .get_mut(&attribute.whole, &work)
                .map_err(refusal)?
            {
                Some(count) if *count != 0 => {
                    *count -= 1;
                    remaining -= 1;
                }
                _ => return Err(SelectionError::PriorNotPreserved),
            }
        }
        if remaining != 0 {
            return Err(SelectionError::PriorNotPreserved);
        }
        Ok(archive_attributes.into_owned())
    }
    pub(super) fn previous(
        &self,
        prepared: &Preparation<'_, '_>,
        owner: Node,
        ordinal: usize,
        operation: &Reader<'_>,
    ) -> Result<OwnedVec<usize>, SelectionError> {
        let work = self.reader.execution_query(operation);
        let refusal = |cause| self.resource(cause);
        let mut archives = work.map();
        let mut remaining = 0usize;
        for timestamp in self.prepared.source_timestamps() {
            work.charge_work(1).map_err(refusal)?;
            if timestamp.owner() != self.owner || timestamp.purpose() != Purpose::Archive {
                continue;
            }
            let value = timestamp.value().ok_or(SelectionError::PriorNotPreserved)?;
            let key = ArchiveValue {
                generation: timestamp.preservation_kind().map_or(3, |kind| kind as u8),
                bytes: value.as_bytes(),
            };
            let count = archives
                .get(&key, &work)
                .map_err(refusal)?
                .copied()
                .unwrap_or(0usize);
            archives.try_insert(key, count + 1).map_err(refusal)?;
            remaining += 1;
        }
        let mut previous = work.vector();
        for (index, timestamp) in prepared.timestamps().iter().enumerate() {
            work.charge_work(1).map_err(refusal)?;
            if timestamp.owner() != owner || timestamp.purpose() != Purpose::Archive {
                continue;
            }
            let Some(value) = timestamp.value() else {
                continue;
            };
            let key = ArchiveValue {
                generation: timestamp.preservation_kind().map_or(3, |kind| kind as u8),
                bytes: value.as_bytes(),
            };
            if let Some(count) = archives.get_mut(&key, &work).map_err(refusal)? {
                if *count == 0 {
                    continue;
                }
                if index == ordinal {
                    return Err(SelectionError::SelfIncluded);
                }
                *count -= 1;
                remaining -= 1;
                previous.try_push(index).map_err(refusal)?;
            }
        }
        if remaining != 0 {
            return Err(SelectionError::PriorNotPreserved);
        }
        Ok(previous.into_owned())
    }
    fn demote<'b, W: Work>(
        &self,
        view: SignerView<'_, 'b>,
        attributes: &mut OwnedMap<&'b [u8], usize>,
        coverage: &mut OwnedMap<Node, bool, W>,
        operation: &Reader<'_>,
        at: Node,
    ) -> Result<(), SelectionError> {
        let prior = self.reader.execution_query(operation);
        let work = operation.execution();
        for index in 0..view.attributes() {
            prior.charge_work(1).map_err(|cause| self.resource(cause))?;
            let attribute = view.attribute(index).expect("bounded original catalogue");
            if archive_kind(attribute.kind).is_none()
                && attribute.kind != structured_cms::oid::ARCHIVE_TIMESTAMP_V3
            {
                continue;
            }
            let property = Node::of(attribute.span);
            if coverage.get(&property, &work).map_err(|cause| {
                SelectionError::Processing(Error::resource(cause, FIELD, at.span().start))
            })? != Some(&true)
            {
                continue;
            }
            let exact = match attributes
                .get_mut(&attribute.whole, &prior)
                .map_err(|cause| self.resource(cause))?
            {
                Some(count) if *count != 0 => {
                    *count -= 1;
                    true
                }
                _ => false,
            };
            // Original values do not authenticate a changed enclosing wrapper.
            if !exact {
                coverage.try_insert(property, false).map_err(|cause| {
                    SelectionError::Processing(Error::resource(cause, FIELD, at.span().start))
                })?;
            }
        }
        Ok(())
    }
}

impl<'s, 'd, S> HistoricalInput<'s, '_, 'd, S> {
    pub(super) fn restore<'om, 'od: 's>(
        mut self,
        snapshot: &'s OriginalSnapshot<'_, 'om, 'od>,
        view: SignerView<'s, 'd>,
        attributes: &mut OwnedMap<&'s [u8], usize>,
    ) -> Result<Self, SelectionError> {
        let work = self.operation.execution();
        let prior = snapshot.reader.execution_query(self.operation);
        let at = self.prepared.timestamps()[self.ordinal].property();
        let refusal =
            |cause| SelectionError::Processing(Error::resource(cause, FIELD, at.span().start));
        let mut coverage = self
            .covered
            .take()
            .expect("new recipe owns selection")
            .with_execution(&work)
            .map_err(|_| SelectionError::WrongOccurrence)?;
        snapshot.demote(view, attributes, &mut coverage, self.operation, at)?;
        self.covered = Some(coverage.into_owned());
        let mut parts = self
            .parts
            .with_execution(&work)
            .map_err(|_| SelectionError::WrongOccurrence)?;
        work.charge_work((parts.len() - self.unsigned_at) as u64)
            .map_err(refusal)?;
        while parts.len() > self.unsigned_at {
            let _ = parts.pop();
        }
        if self.edition == Edition::Rfc3126 {
            for pass in 0..8 {
                for index in 0..snapshot.signer.attributes() {
                    prior
                        .charge_work(12)
                        .map_err(|cause| snapshot.resource(cause))?;
                    let attribute = snapshot
                        .signer
                        .attribute(index)
                        .expect("bounded saved catalogue");
                    let last = [14, 21, 22, 23, 24, 25, 26, 27][pass];
                    if attribute.kind
                        == Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, last])
                    {
                        parts
                            .try_push(Part::Prior(attribute.contents))
                            .map_err(refusal)?;
                    }
                }
            }
        } else if let Some((_, whole, contents)) = snapshot.signer.unsigned() {
            self.original_unsigned = Some(whole);
            parts.try_push(Part::Prior(contents)).map_err(refusal)?;
        }
        self.parts = parts.into_owned();
        self.unsigned_header = None;
        self.prior = Some(snapshot.reader);
        self.framing = Framing::OriginalSnapshot;
        Ok(self)
    }
}
