//! TS101733 §6.5.1: algorithm-dependent eight-hash and multiset-tree inputs.
//!
//! This is private: only the original-format recipe can construct components.
//! No arbitrary raw digest or caller-written successful receipt is accepted.

use crate::Error;
use core::cmp::Ordering;
use structured_asn1::memory::{OwnedVec, SortError, Work};
use structured_cms::{
    digest::{DigestBatch, DigestError, DigestMemo, PassResult, RequestSource},
    stream::{Receiver, Refused, StreamError},
};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

const FIELD: &str = "cades.longTermValidation.input";

/// Every actual derivation/refusal remains distinct from a completed mismatch.
#[derive(Debug)]
pub enum InputError<SE, PE> {
    /// Original source/schema/local/aggregate processing refusal.
    Processing(Error),
    /// Selected provider refused, or contradicted its promised output width.
    Digest(DigestError<PE>),
    /// Actual carried/detached content failed before complete EOF.
    Content(crate::timestamp::InputError<SE>),
    /// The required algorithm has no identity in this selected provider.
    Unsupported,
    /// Hs has no original signed-attribute encoding; no empty input is made.
    MissingSignedAttributes,
    /// Original unsigned date ordering uncertainty or resource refusal.
    Date(structured_pkix::temporal::CompareError),
    /// Qualified later archive/source/coverage admission refused.
    Augmentation(crate::timestamp::historical::SelectionError),
    /// Components belong to a different provider, identity or original request.
    Foreign,
    /// The common sticky receiver retains its original provider/driver cause.
    Receiver(Refused),
}

pub(super) fn batch<'p, P: AsnDigest<'p>, W: Work, SE>(
    provider: &'p P,
    algorithms: &[Algorithm],
    work: &W,
    at: u64,
) -> Result<DigestBatch<'p, P>, InputError<SE, P::Error>> {
    let mut identities = work.vector();
    identities
        .try_reserve_exact(algorithms.len())
        .map_err(|cause| InputError::Processing(Error::resource(cause, FIELD, at)))?;
    for algorithm in algorithms {
        work.charge_work(1)
            .map_err(|cause| InputError::Processing(Error::resource(cause, FIELD, at)))?;
        identities
            .try_push(
                provider
                    .identity(*algorithm)
                    .ok_or(InputError::Unsupported)?,
            )
            .map_err(|cause| InputError::Processing(Error::resource(cause, FIELD, at)))?;
    }
    DigestBatch::prepare(provider, identities.into_owned(), work, FIELD, at)
        .map_err(InputError::Digest)
}

/// Exactly eight independently typed completed components. Construction is
/// limited to the source-bound schema recipe in this module's parent.
pub(super) struct Eight<'p, P: AsnDigest<'p>> {
    parts: OwnedVec<DigestMemo<'p, P>>,
    covered: OwnedVec<structured_asn1::Span>,
    algorithms: OwnedVec<Algorithm>,
    at: u64,
}
impl<'p, P: AsnDigest<'p>> Eight<'p, P> {
    pub(super) fn build<W: Work, SE>(
        provider: &'p P,
        algorithms: &[Algorithm],
        work: &W,
        at: u64,
        covered: OwnedVec<structured_asn1::Span>,
        mut component: impl FnMut(
            usize,
            DigestBatch<'p, P>,
            &W,
        ) -> Result<DigestMemo<'p, P>, InputError<SE, P::Error>>,
    ) -> Result<Self, InputError<SE, P::Error>> {
        let resource = |cause| InputError::Processing(Error::resource(cause, FIELD, at));
        let mut parts = work.vector();
        parts.try_reserve_exact(8).map_err(resource)?;
        let mut saved = work.vector();
        saved.try_extend_from_slice(algorithms).map_err(resource)?;
        for index in 0..8 {
            work.charge_work(1).map_err(resource)?;
            let pending = batch(provider, algorithms, work, at)?;
            let completed = component(index, pending, work)?;
            parts.try_push(completed).map_err(resource)?;
        }
        Ok(Self {
            parts: parts.into_owned(),
            covered,
            algorithms: saved.into_owned(),
            at,
        })
    }

    pub(super) fn stream<W: Work, SE>(
        &self,
        ordinal: usize,
        provider: &'p P,
        identity: &P::Identity,
        out: &mut impl Receiver,
        work: &W,
    ) -> Result<(), InputError<SE, P::Error>> {
        work.charge_work(1)
            .map_err(|cause| InputError::Processing(Error::resource(cause, FIELD, self.at)))?;
        let algorithm = self.algorithms.get(ordinal).ok_or(InputError::Foreign)?;
        // Admit and validate ALL eight before the first byte reaches the
        // outer hash. A late mismatch cannot silently mix provider identities.
        debug_assert_eq!(self.parts.len(), 8);
        // All eight slots are assigned by the private constructor invariant
        // before any slot is observed; initial slices are not missing values.
        let mut outputs = [&[][..]; 8];
        for (slot, part) in outputs.iter_mut().zip(&*self.parts) {
            *slot = checked(
                part,
                ordinal,
                provider,
                identity,
                algorithm.width(),
                work,
                self.at,
            )?;
        }
        for bytes in outputs {
            out.write(bytes).map_err(InputError::Receiver)?;
        }
        Ok(())
    }
}

fn checked<'m, 'p, P: AsnDigest<'p>, W: Work, SE>(
    memo: &'m DigestMemo<'p, P>,
    ordinal: usize,
    provider: &'p P,
    identity: &P::Identity,
    width: usize,
    work: &W,
    at: u64,
) -> Result<&'m [u8], InputError<SE, P::Error>> {
    work.charge_work(1)
        .map_err(|cause| InputError::Processing(Error::resource(cause, FIELD, at)))?;
    let value = memo
        .for_request(ordinal, work)
        .map_err(InputError::Digest)?
        .ok_or(InputError::Foreign)?;
    if !value.finished().from_provider(provider) {
        return Err(InputError::Foreign);
    }
    if provider
        .compare(value.identity(), identity, work)
        .map_err(|cause| InputError::Digest(DigestError::Callback(cause)))?
        != Ordering::Equal
    {
        return Err(InputError::Foreign);
    }
    if value.as_bytes().len() != width {
        return Err(InputError::Digest(DigestError::OutputWidth {
            expected: width,
            actual: value.as_bytes().len(),
        }));
    }
    Ok(value.as_bytes())
}

/// Per-algorithm treehash preimage. Distinct encoded items are hashed first;
/// their COMPLETE outputs are sorted and streamed, preserving duplicates.
pub(super) struct Tree<'alg, 'p, P: AsnDigest<'p>, SE> {
    provider: &'p P,
    items: OwnedVec<DigestMemo<'p, P>>,
    algorithms: &'alg [Algorithm],
    at: u64,
    error: core::marker::PhantomData<fn() -> SE>,
}
impl<'alg, 'p, P: AsnDigest<'p>, SE> Tree<'alg, 'p, P, SE> {
    pub(super) fn new(
        provider: &'p P,
        items: OwnedVec<DigestMemo<'p, P>>,
        algorithms: &'alg [Algorithm],
        at: u64,
    ) -> Self {
        Self {
            provider,
            items,
            algorithms,
            at,
            error: core::marker::PhantomData,
        }
    }
}
impl<'p, P: AsnDigest<'p>, SE> RequestSource<'p, P> for Tree<'_, 'p, P, SE> {
    type Error = InputError<SE, P::Error>;
    fn stream_request<W: Work>(
        &mut self,
        ordinal: usize,
        provider: &'p P,
        identity: &P::Identity,
        out: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        let resource = |cause| InputError::Processing(Error::resource(cause, FIELD, self.at));
        work.charge_work(1).map_err(resource)?;
        if !core::ptr::eq(provider, self.provider) {
            return Err(InputError::Foreign);
        }
        let width = self
            .algorithms
            .get(ordinal)
            .ok_or(InputError::Foreign)?
            .width();
        let mut hashes = work.vector();
        hashes
            .try_reserve_exact(self.items.len())
            .map_err(resource)?;
        for item in &self.items {
            let value = checked(item, ordinal, provider, identity, width, work, self.at)?;
            hashes.try_push(value).map_err(resource)?;
        }
        hashes
            .try_sort_unstable_by(|left, right| {
                work.charge_work(1 + left.len().min(right.len()) as u64)?;
                Ok::<_, structured_asn1::memory::MemoryError>(left.cmp(right))
            })
            .map_err(|cause| match cause {
                SortError::Resource(cause) | SortError::Comparison(cause) => resource(cause),
            })?;
        for value in &hashes {
            work.charge_work(1).map_err(resource)?;
            out.write(value).map_err(InputError::Receiver)?;
        }
        // Empty treehash is H(empty), not an absent or invented zero digest.
        Ok(())
    }
}

pub(super) fn derived_result<T, SE, PE>(
    result: PassResult<T, InputError<SE, PE>, PE>,
) -> Result<T, InputError<SE, PE>> {
    result.map_err(|cause| match cause {
        StreamError::Source(cause) => cause,
        StreamError::Callback(cause) => InputError::Digest(cause),
        StreamError::Processing(cause) => InputError::Processing(Error::Cms(cause)),
    })
}

mod check;
mod recipe;
pub use check::{CheckError, CheckResult};

/// Construct components only when the actual common token check requests
/// covered input, after syntax, selected-key and signed-profile admission.
struct Lazy<'s, 'a, 'm, 'd, 'p, 'utc, P: AsnDigest<'p>, S> {
    view: &'s super::View<'a, 'm, 'd>,
    later: &'s [crate::timestamp::historical::Later<'s, 'm, 'd>],
    provider: &'p P,
    algorithms: &'s [Algorithm],
    operation: &'s structured_asn1::Reader<'d>,
    utc: &'s structured_pkix::temporal::LeapTable<'utc>,
    detached: Option<&'s mut S>,
    ready: Option<Eight<'p, P>>,
}
impl<'p, P: AsnDigest<'p>, S: structured_cms::stream::Source> Lazy<'_, '_, '_, '_, 'p, '_, P, S> {
    fn ready<W: Work>(
        &mut self,
        work: &W,
    ) -> Result<&Eight<'p, P>, InputError<S::Error, P::Error>> {
        if self.ready.is_none() {
            self.ready = Some(self.view.components_in(
                self.provider,
                self.algorithms,
                self.operation,
                self.detached.take(),
                self.utc,
                self.later,
                work,
            )?);
        }
        Ok(self
            .ready
            .as_ref()
            .expect("successful component construction"))
    }
}
impl<'p, P: AsnDigest<'p>, S: structured_cms::stream::Source> RequestSource<'p, P>
    for Lazy<'_, '_, '_, '_, 'p, '_, P, S>
{
    type Error = InputError<S::Error, P::Error>;
    fn stream_request<W: Work>(
        &mut self,
        ordinal: usize,
        provider: &'p P,
        identity: &P::Identity,
        out: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        self.ready(work)?
            .stream(ordinal, provider, identity, out, work)
    }
}
impl<'p, P: AsnDigest<'p>, S: structured_cms::stream::Source> structured_cms::stream::Source
    for Lazy<'_, '_, '_, '_, 'p, '_, P, S>
{
    type Error = InputError<S::Error, P::Error>;
    fn stream<W: Work>(&mut self, out: &mut impl Receiver, work: &W) -> Result<(), Self::Error> {
        work.charge_work(1).map_err(|cause| {
            InputError::Processing(Error::resource(
                cause,
                FIELD,
                self.view.required().property.span().start,
            ))
        })?;
        if self.algorithms.len() != 1 {
            return Err(InputError::Foreign);
        }
        let provider = self.provider;
        let identity = provider
            .identity(self.algorithms[0])
            .ok_or(InputError::Unsupported)?;
        self.ready(work)?.stream(0, provider, &identity, out, work)
    }
}

#[cfg(test)]
#[path = "poe/tests.rs"]
mod tests;
