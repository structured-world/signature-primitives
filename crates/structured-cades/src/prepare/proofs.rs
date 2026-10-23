//! Own each proof envelope ONCE; timestamp/cache/material views use indices.

use super::Timestamp;
use crate::{
    Error, Result,
    evidence::{LongTermValidation, PoeValue},
    preservation::{Kind, Required},
    properties::Properties,
    source::{Node, Value},
};
use structured_asn1::{
    Reader,
    memory::{OwnedMap, OwnedVec, Work},
};
use structured_cms::{
    evidence::{EvidenceRecord, TimeStamp},
    timestamp::Token,
};
use structured_ltv::timestamp::Purpose;

#[expect(
    clippy::large_enum_variant,
    reason = "The paid flat entry allocation owns both first-read alternatives; a separate heap allocation per PoE would add allocator failure and dispatch."
)]
pub(crate) enum Body<'d> {
    Record(EvidenceRecord<'d>),
    Poe(LongTermValidation<'d>),
}
pub(crate) struct Entry<'d> {
    pub(crate) required: Required<'d>,
    pub(crate) body: Body<'d>,
    pub(crate) timestamps: core::ops::Range<usize>,
    properties: OwnedVec<Option<Properties<'d>>>,
}
#[derive(Clone, Copy)]
pub(crate) struct Reference {
    pub(crate) proof: usize,
    pub(crate) stamp: usize,
}
pub(crate) struct Proofs<'d> {
    pub(crate) entries: OwnedVec<Entry<'d>>,
    pub(crate) index: OwnedMap<Node, Reference>,
    pub(crate) faults: OwnedVec<(Node, Error)>,
}
impl<'d> Entry<'d> {
    fn timestamp_count(&self) -> usize {
        match &self.body {
            Body::Record(record) => record.timestamps().len(),
            Body::Poe(poe) => match poe.proof() {
                Some(PoeValue::Timestamp(_)) => 1,
                Some(PoeValue::EvidenceRecord(record)) => record.timestamps().len(),
                None => 0,
            },
        }
    }
    fn timestamp_source(&self, stamp: usize, parent: &Reader<'d>) -> Result<Value<'d>> {
        if let Some(record) = self.record() {
            let value = record
                .timestamps()
                .get(stamp)
                .ok_or(Error::Foreign {
                    at: self.required.property.span().start,
                })?
                .timestamp_source();
            let reader = value.reader_in(parent)?;
            Ok(Value::of(&reader, value.element(), "cades.evidence"))
        } else {
            let Body::Poe(poe) = &self.body else {
                return Err(Error::Foreign {
                    at: self.required.property.span().start,
                });
            };
            // Preserve the original explicit wrapper's source/depth.
            poe.timestamp_source().ok_or(Error::Foreign {
                at: poe.element().span().start,
            })
        }
    }
    pub(crate) fn record(&self) -> Option<&EvidenceRecord<'d>> {
        match &self.body {
            Body::Record(record) => Some(record),
            Body::Poe(poe) => match poe.proof() {
                Some(PoeValue::EvidenceRecord(record)) => Some(record),
                _ => None,
            },
        }
    }
    pub(crate) fn token(&self, ordinal: usize) -> Option<&Token<'d>> {
        match &self.body {
            Body::Poe(poe) if matches!(poe.proof(), Some(PoeValue::Timestamp(_))) => {
                let Some(PoeValue::Timestamp(token)) = poe.proof() else {
                    return None;
                };
                (ordinal == 0).then_some(token)
            }
            _ => match self.record()?.timestamps().get(ordinal)?.timestamp() {
                TimeStamp::Rfc3161(token) => Some(token),
                TimeStamp::Other(_) => None,
            },
        }
    }
}
impl<'d> Proofs<'d> {
    pub(crate) fn collect<W: Work>(
        required: &[Required<'d>],
        parent: &Reader<'d>,
        timestamps: &mut OwnedVec<Timestamp<'d>, W>,
    ) -> Result<Self> {
        let work = parent.execution();
        let mut entries = work.vector();
        let mut index = work.map();
        let mut faults = work.vector();
        for required in required {
            work.charge_work(1).map_err(|cause| {
                Error::resource(cause, "cades.evidence", required.property.span().start)
            })?;
            if !required.kind.is_evidence() {
                continue;
            }
            let Some(value) = required.value else {
                continue;
            };
            let reader = value.reader_in(parent)?;
            let read = if required.kind == Kind::LongTermValidation {
                LongTermValidation::read(&reader, &value.element()).map(Body::Poe)
            } else {
                EvidenceRecord::read(&reader, &value.element())
                    .map(Body::Record)
                    .map_err(Error::Cms)
            };
            let body = match read {
                Ok(body) => body,
                Err(cause) if cause.is_terminal() => return Err(cause),
                Err(cause) => {
                    faults
                        .try_push((required.property, cause))
                        .map_err(|cause| {
                            Error::resource(cause, "cades.evidence", required.property.span().start)
                        })?;
                    continue;
                }
            };
            let mut entry = Entry {
                required: *required,
                body,
                timestamps: timestamps.len()..timestamps.len(),
                properties: work.vector().into_owned(),
            };
            let mut properties = work.vector();
            let count = entry.timestamp_count();
            properties.try_reserve_exact(count).map_err(|cause| {
                Error::resource(cause, "cades.evidence", required.property.span().start)
            })?;
            for stamp in 0..count {
                work.charge_work(1).map_err(|cause| {
                    Error::resource(cause, "cades.evidence", required.property.span().start)
                })?;
                let source = entry.timestamp_source(stamp, parent)?;
                let token_properties = if let Some(token) = entry.token(stamp) {
                    let reader = source.reader_in(parent)?;
                    if Properties::has_legacy_values(token.signer(), &reader)? {
                        Some(Properties::read(token.signer(), &reader)?)
                    } else {
                        None
                    }
                } else {
                    None
                };
                properties.try_push(token_properties).map_err(|cause| {
                    Error::resource(cause, "cades.evidence", source.element().span().start)
                })?;
                let node = Node::of(source.element().span());
                if index
                    .try_insert(
                        node,
                        Reference {
                            proof: entries.len(),
                            stamp,
                        },
                    )
                    .map_err(|cause| Error::resource(cause, "cades.evidence", node.span().start))?
                    .is_some()
                {
                    return Err(Error::Foreign {
                        at: node.span().start,
                    });
                }
                timestamps
                    .try_push(Timestamp {
                        owner: required.signature,
                        property: required.property,
                        value: Some(source),
                        purpose: Purpose::Archive,
                        preservation_kind: Some(required.kind),
                    })
                    .map_err(|cause| Error::resource(cause, "cades.evidence", node.span().start))?;
            }
            entry.properties = properties.into_owned();
            entry.timestamps.end = timestamps.len();
            entries.try_push(entry).map_err(|cause| {
                Error::resource(cause, "cades.evidence", required.property.span().start)
            })?;
        }
        Ok(Self {
            entries: entries.into_owned(),
            index: index.into_owned(),
            faults: faults.into_owned(),
        })
    }
    pub(crate) fn token(
        &self,
        reference: Reference,
    ) -> Option<(&Token<'d>, Option<&Properties<'d>>)> {
        let entry = self.entries.get(reference.proof)?;
        Some((
            entry.token(reference.stamp)?,
            entry.properties.get(reference.stamp)?.as_ref(),
        ))
    }
}
