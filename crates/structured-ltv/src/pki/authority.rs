//! One original signer/path/key/time association kernel for CRL and OCSP.

use super::{CheckedPath, exact};
use structured_asn1::memory::{MemoryError, Work};
use structured_pkix::{
    Certificate,
    path::WorkingKey,
    temporal::{LeapTable, Reading, Uncertainty},
};

#[derive(Clone, Copy)]
pub(super) enum Failure {
    Anchor,
    Signer,
    EffectiveKey,
    Interval,
}

pub(super) enum Error {
    Resource(MemoryError),
    Name(structured_pkix::Error),
    Time(Uncertainty),
}

impl<'document> CheckedPath<'document> {
    pub(super) fn path_authority<W: Work>(
        &self,
        path: &CheckedPath<'document>,
        signer: &Certificate<'document>,
        key: WorkingKey<'document>,
        at: Reading,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> Result<Option<Failure>, Error> {
        execution.charge_work(1).map_err(Error::Resource)?;
        if !exact(
            self.anchor.key().as_bytes(),
            path.anchor.key().as_bytes(),
            execution,
        )
        .map_err(Error::Resource)?
            || !self
                .anchor
                .name()
                .matches(path.anchor.name(), execution)
                .map_err(Error::Name)?
        {
            return Ok(Some(Failure::Anchor));
        }
        let target = path.members.last().expect("a checked path has a target");
        if !exact(
            target.certificate().as_bytes(),
            signer.as_bytes(),
            execution,
        )
        .map_err(Error::Resource)?
        {
            return Ok(Some(Failure::Signer));
        }
        // Two shifts, each bounded by three binary table searches, exactly as
        // for the existing CRL authority path. Preserve the full source Reading.
        let bits = usize::BITS - utc.transitions().len().leading_zeros();
        execution
            .charge_work(32 + 6 * (u64::from(bits) + 1))
            .map_err(Error::Resource)?;
        let from = utc.shift(at.start(), 0).map_err(Error::Time)?;
        let to = at.upper_bound(utc).map_err(Error::Time)?;
        if path.interval.from_instant() > from || path.interval.to_instant() < to {
            return Ok(Some(Failure::Interval));
        }
        if !exact(
            target.key().key().as_bytes(),
            key.key().as_bytes(),
            execution,
        )
        .map_err(Error::Resource)?
        {
            return Ok(Some(Failure::Signer));
        }
        let same = match (target.key().parameters(), key.parameters()) {
            (None, None) => true,
            (Some(left), Some(right)) => exact(left, right, execution).map_err(Error::Resource)?,
            _ => false,
        };
        Ok(if same {
            None
        } else {
            Some(Failure::EffectiveKey)
        })
    }
}
