//! Exact historical DSS value membership with paid collision resolution.

use super::{Item, KindOf};
use crate::{
    error::{Error, ErrorKind},
    model::admit,
    source::Location,
};
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, OwnedVec, Work};

#[derive(Hash, PartialEq, Eq)]
struct Value<'a> {
    kind: u8,
    bytes: &'a [u8],
}
impl HashWork for Value<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        (self.bytes.len() as u64)
            .checked_add(2)
            .ok_or(MemoryError::WorkExceeded)
    }
}

#[derive(Hash, PartialEq, Eq)]
struct Bucket(u64);
impl HashWork for Bucket {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(1)
    }
}

pub(super) struct Membership<W: Work> {
    heads: OwnedMap<Bucket, usize, W>,
    next: OwnedVec<Option<usize>, W>,
}

fn kind(value: KindOf) -> u8 {
    match value {
        KindOf::Certificate => 0,
        KindOf::Crl => 1,
        KindOf::Ocsp => 2,
        KindOf::Timestamp => 3,
    }
}

impl<W: Work> Membership<W> {
    pub(super) fn new(items: &[Item<'_>], location: Location, work: &W) -> crate::Result<Self> {
        let mut output = Self {
            heads: work.map(),
            next: work.vector(),
        };
        output
            .next
            .try_reserve_exact(items.len())
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        for (ordinal, item) in items.iter().enumerate() {
            admit(work, item.location, 1)?;
            let hash = output.hash(item, work)?;
            let previous = output
                .heads
                .try_insert(Bucket(hash), ordinal)
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: item.location,
                })?;
            output.next.try_push(previous).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: item.location,
            })?;
        }
        Ok(output)
    }

    fn hash(&self, item: &Item<'_>, work: &impl Work) -> crate::Result<u64> {
        self.heads
            .fingerprint(
                &Value {
                    kind: kind(item.kind),
                    bytes: &item.bytes,
                },
                work,
            )
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: item.location,
            })
    }

    pub(super) fn contains(
        &self,
        items: &[Item<'_>],
        item: &Item<'_>,
        work: &impl Work,
    ) -> crate::Result<bool> {
        let hash = self.hash(item, work)?;
        let mut next = self
            .heads
            .get(&Bucket(hash), work)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: item.location,
            })?
            .copied();
        while let Some(ordinal) = next {
            admit(work, item.location, 1)?;
            let candidate = &items[ordinal];
            if candidate.kind == item.kind && candidate.bytes.len() == item.bytes.len() {
                admit(work, item.location, item.bytes.len() as u64)?;
                if candidate.bytes == item.bytes {
                    return Ok(true);
                }
            }
            next = self.next[ordinal];
        }
        Ok(false)
    }
}
