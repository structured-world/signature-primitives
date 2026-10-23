//! Exact previous-chain input for RFC4998 §5.2 hash-tree renewal.

use super::{
    EvidenceRecord, FIELD, encoding,
    input::{Hasher, InputError},
    syntax,
};
use crate::encoding::{FeedError, Form, Projection, Rules};
use crate::{Error, ErrorCode, Result};
use structured_asn1::{
    Class, Reader,
    length::DerLength,
    memory::{OwnedVec, Work},
};
use structured_pkix::algorithm::digest::AsnDigest;

/// Immutable DER input covering EVERY chain preceding an actual new chain.
///
/// The surrounding sequence receives its required minimal DER length. Chain
/// values are projected through the shared encoding kernel; BER wrappers and
/// segmentation are not confused with DER bytes. No later chain or
/// unprotected CryptoInfos/EncryptionInfo is included (§5.2 steps3–4).
pub struct PriorSequence<'record, 'document> {
    record: &'record EvidenceRecord<'document>,
    before: usize,
    length: u64,
    projected: Prefix<'record, 'document>,
}
enum Prefix<'r, 'd> {
    Owned(OwnedVec<Projection<'d>>),
    Borrowed(&'r [Projection<'d>]),
}
impl<'d> Prefix<'_, 'd> {
    fn values(&self) -> &[Projection<'d>] {
        match self {
            Self::Owned(values) => values,
            Self::Borrowed(values) => values,
        }
    }
}
impl<'r, 'd> PriorSequence<'r, 'd> {
    /// Binds the prefix to the actual new chain and admits it before hashing.
    pub fn new(
        record: &'r EvidenceRecord<'d>,
        before_chain: usize,
        operation: &Reader<'d>,
    ) -> Result<Self> {
        operation.charge(1).map_err(encoding)?;
        if before_chain == 0 || before_chain >= record.chains.len() {
            return Err(syntax(
                ErrorCode::InvalidLocation,
                record.original.element.span(),
            ));
        }
        let projected = Self::project(record, before_chain, operation)?;
        let length = prefix_length(
            &projected,
            &operation.execution(),
            record.original.element.span().start,
        )?;
        Ok(Self {
            record,
            before: before_chain,
            length,
            projected: Prefix::Owned(projected),
        })
    }
    pub(super) fn all(
        record: &EvidenceRecord<'d>,
        operation: &Reader<'d>,
    ) -> Result<OwnedVec<Projection<'d>>> {
        Self::project(record, record.chains.len() - 1, operation)
    }
    pub(super) fn borrowed(
        record: &'r EvidenceRecord<'d>,
        before: usize,
        projected: &'r [Projection<'d>],
        operation: &Reader<'_>,
    ) -> Result<Self> {
        let values = &projected[..before];
        let length = prefix_length(
            values,
            &operation.execution(),
            record.original.element.span().start,
        )?;
        Ok(Self {
            record,
            before,
            length,
            projected: Prefix::Borrowed(values),
        })
    }
    fn project(
        record: &EvidenceRecord<'d>,
        count: usize,
        operation: &Reader<'d>,
    ) -> Result<OwnedVec<Projection<'d>>> {
        let origin = record.original.reader_in(operation)?;
        let work = origin.execution_query(operation);
        let mut rules = Rules::new(&work);
        // These IMPLICIT SET OF and OCTET STRING roles come from the SAME
        // parsed schemas. Context tag number alone never selects their form.
        for stamp in &record.timestamps[..record
            .chains
            .get(count)
            .map_or(record.timestamps.len(), |chain| chain.first)]
        {
            work.charge_work(1).map_err(|cause| {
                Error::resource(cause, FIELD, stamp.original.element.span().start)
            })?;
            if let Some(span) = stamp.attributes_span {
                rules.insert(span, Form::Set, &work)?;
            }
            if let super::TimeStamp::Rfc3161(token) = &stamp.token {
                let message = token.message();
                for span in [message.certificate_field(), message.revocation_field()]
                    .into_iter()
                    .flatten()
                {
                    rules.insert(span, Form::Set, &work)?;
                }
                for certificate in message.certificates() {
                    for identifier in [
                        certificate.signature_algorithm(),
                        certificate.tbs().signature(),
                        certificate.tbs().public_key().algorithm(),
                    ] {
                        rules.algorithm(identifier, &work)?;
                    }
                }
                for signer in message.signers() {
                    work.charge_work(1)
                        .map_err(|cause| Error::resource(cause, FIELD, signer.span().start))?;
                    for attrs in [signer.signed_attributes(), signer.unsigned_attributes()]
                        .into_iter()
                        .flatten()
                    {
                        rules.insert(attrs.element().span(), Form::Set, &work)?;
                    }
                    for identifier in [
                        signer.digest_algorithm().identifier(),
                        signer.signature_algorithm().identifier(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        rules.algorithm(identifier, &work)?;
                    }
                    let sid = signer.fields().identity[1];
                    if sid.tag().class() == Class::ContextSpecific {
                        rules.insert(sid.span(), Form::Octets, &work)?;
                    }
                }
            }
        }
        let mut values = work.vector();
        values
            .try_reserve_exact(count)
            .map_err(|cause| Error::resource(cause, FIELD, record.original.element.span().start))?;
        for chain in &record.chains[..count] {
            let parent = chain.original.reader_in(operation)?;
            values
                .try_push(Projection::new(&parent, chain.original.element, &rules)?)
                .map_err(|cause| {
                    Error::resource(cause, FIELD, chain.original.element.span().start)
                })?;
        }
        Ok(values.into_owned())
    }
    /// The selected new chain ordinal; no order is inferred from timestamps.
    #[must_use]
    pub fn before_chain(&self) -> usize {
        self.before
    }
    pub(super) fn contains(&self, stamp: &super::ArchiveTimeStamp<'_>) -> bool {
        core::ptr::eq(
            stamp,
            &raw const self.record.timestamps[self.record.chains[self.before].first],
        )
    }
    pub(super) fn hash<'p, P: AsnDigest<'p>, W: Work, SE>(
        &self,
        hasher: &Hasher<'p, '_, P, W>,
    ) -> core::result::Result<P::Output, InputError<SE, P::Error>> {
        let mut state = hasher.start()?;
        hasher.update(&mut state, &[0x30])?;
        hasher.update(&mut state, DerLength::new(self.length).as_bytes())?;
        for chain in self.projected.values() {
            chain
                .feed(&hasher.work, |bytes| hasher.update(&mut state, bytes))
                .map_err(|cause| match cause {
                    FeedError::Resource(cause) => hasher.resource(cause),
                    FeedError::Callback(cause) => cause,
                })?;
        }
        hasher.finish(state)
    }
}
fn prefix_length<W: Work>(values: &[Projection<'_>], work: &W, at: u64) -> Result<u64> {
    let mut length = 0u64;
    for value in values {
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, at))?;
        length = length
            .checked_add(value.len())
            .ok_or_else(|| Error::schema(ErrorCode::LengthOverflow, FIELD, at))?;
    }
    Ok(length)
}
