//! One-pass digest fan-out with one final output per resolved semantic identity.

use crate::Error;
use crate::provider::{DigestProvider, Finalized, Prehash};
use crate::stream::{self, Sink, Source, StreamError};
use core::cmp::Ordering;
use structured_asn1::memory::{OwnedVec, SortError, Work};

/// A complete pass preserves source, common-processing and provider causes.
pub type PassError<SE, PE> = StreamError<SE, DigestError<PE>>;
/// A finalized output with the selected provider's full identity and storage type.
pub type DigestOutput<'a, P> =
    Finalized<'a, P, <P as DigestProvider<'a>>::Identity, <P as DigestProvider<'a>>::Output>;
/// Fallible digest processing, without reducing provider refusal to absence.
pub type DigestResult<T, E> = Result<T, DigestError<E>>;
/// A complete source pass, preserving acquisition and processing causes.
pub type PassResult<T, SE, PE> = Result<T, PassError<SE, PE>>;

/// Failure of common digest processing or the selected provider.
#[derive(Debug)]
pub enum DigestError<E> {
    /// Common storage, dispatch, sorting or lookup refusal before work.
    Processing(Error),
    /// Original callback error, including any opaque backend resource refusal.
    Callback(E),
    /// A callback returned a width inconsistent with its resolved identity.
    /// This is a provider contract failure, not malformed document data.
    OutputWidth {
        /// Fixed width promised by the selected resolved identity.
        expected: usize,
        /// Actual returned output width.
        actual: usize,
    },
}

struct Pending<I, S> {
    identity: I,
    state: S,
}

struct Request<I> {
    ordinal: usize,
    identity: I,
}

/// Prepared states from one selected provider; no state cloning or source replay.
pub struct DigestBatch<'a, P: DigestProvider<'a>> {
    provider: &'a P,
    pending: OwnedVec<Pending<P::Identity, P::State>>,
    mapping: OwnedVec<usize>,
    field: &'static str,
    at: u64,
}

impl<'a, P: DigestProvider<'a>> DigestBatch<'a, P> {
    /// Moves resolved identities into the current operation and initializes each once.
    ///
    /// Identities must come from this selected provider's resolver. They are
    /// sorted and deduplicated through its fallible semantic comparison, not
    /// OID/width equality. Admission precedes every callback, move and allocation.
    /// `field`/`at` identify the caller's enclosing original source structure.
    pub fn prepare<W: Work>(
        provider: &'a P,
        identities: OwnedVec<P::Identity>,
        execution: &W,
        field: &'static str,
        at: u64,
    ) -> Result<Self, DigestError<P::Error>> {
        crate::provider::require_instance(provider, field, at).map_err(DigestError::Processing)?;
        let refusal = |reason| DigestError::Processing(Error::resource(reason, field, at));
        execution.charge_work(1).map_err(refusal)?;
        let count = identities.len();
        let mut ordered = execution.vector();
        ordered
            .try_reserve_exact(identities.len())
            .map_err(refusal)?;
        execution
            .charge_work(core::mem::size_of_val(&*identities) as u64)
            .map_err(refusal)?;
        for (ordinal, identity) in identities.into_iter().enumerate() {
            ordered
                .try_push(Request { ordinal, identity })
                .map_err(refusal)?;
        }
        ordered
            .try_sort_unstable_by(|left, right| {
                provider.compare_digest(&left.identity, &right.identity, execution)
            })
            .map_err(|error| match error {
                SortError::Resource(reason) => refusal(reason),
                SortError::Comparison(error) => DigestError::Callback(error),
            })?;
        let mut pending: OwnedVec<Pending<P::Identity, P::State>, _> = execution.vector();
        let mut mapping = execution.vector();
        mapping.try_reserve_exact(count).map_err(refusal)?;
        // The sorted request records are a permutation of ordinals 0..count.
        // Every slot is assigned exactly once before this mapping is exposed.
        for _ in 0..count {
            mapping.try_push(0).map_err(refusal)?;
        }
        execution
            .charge_work(core::mem::size_of_val(&*ordered) as u64)
            .map_err(refusal)?;
        for Request { ordinal, identity } in ordered.into_owned() {
            execution.charge_work(1).map_err(refusal)?;
            if let Some(previous) = pending.last()
                && provider
                    .compare_digest(&previous.identity, &identity, execution)
                    .map_err(DigestError::Callback)?
                    == Ordering::Equal
            {
                mapping[ordinal] = pending.len() - 1;
                continue;
            }
            pending.try_reserve(1).map_err(refusal)?;
            let state = provider
                .start_digest(&identity, execution)
                .map_err(DigestError::Callback)?;
            pending
                .try_push(Pending { identity, state })
                .map_err(refusal)?;
            mapping[ordinal] = pending.len() - 1;
        }
        Ok(Self {
            provider,
            pending: pending.into_owned(),
            mapping: mapping.into_owned(),
            field,
            at,
        })
    }

    /// Number of unique resolved digest states, without rescanning identities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }
    /// Whether no digest was requested.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Feeds the source once; outputs are finalized only after complete successful EOF.
    ///
    /// A source or callback error drops every unfinished state and partial
    /// output. No partial digest is returned, and a source ignoring a refused
    /// write cannot make subsequent callbacks run or turn refusal into success.
    pub fn run<S: Source, W: Work>(
        mut self,
        source: &mut S,
        execution: &W,
    ) -> Result<DigestMemo<'a, P>, PassError<S::Error, P::Error>> {
        let field = self.field;
        let at = self.at;
        let mut outputs = execution.vector();
        outputs
            .try_reserve_exact(self.pending.len())
            .map_err(|reason| StreamError::Processing(Error::resource(reason, field, at)))?;
        stream::run(source, &mut BatchSink(&mut self), execution, field, at)?;
        self.finish(outputs, execution)
            .map_err(StreamError::Callback)
    }

    pub(crate) fn feed<W: Work>(
        &mut self,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), DigestError<P::Error>> {
        for pending in &mut self.pending {
            execution.charge_work(1).map_err(|reason| {
                DigestError::Processing(Error::resource(reason, self.field, self.at))
            })?;
            self.provider
                .update_digest(&mut pending.state, bytes, execution)
                .map_err(DigestError::Callback)?;
        }
        Ok(())
    }

    pub(crate) fn finish<W: Work>(
        self,
        mut outputs: OwnedVec<DigestOutput<'a, P>, W>,
        execution: &W,
    ) -> Result<DigestMemo<'a, P>, DigestError<P::Error>> {
        let refusal =
            |reason| DigestError::Processing(Error::resource(reason, self.field, self.at));
        execution
            .charge_work(core::mem::size_of_val(&*self.pending) as u64)
            .map_err(refusal)?;
        for pending in self.pending {
            execution.charge_work(1).map_err(refusal)?;
            let output = self
                .provider
                .finish_digest(pending.state, execution)
                .map_err(DigestError::Callback)?;
            if let Some(expected) = self.provider.digest_width(&pending.identity) {
                let actual = output.as_ref().len();
                if actual != expected {
                    return Err(DigestError::OutputWidth { expected, actual });
                }
            }
            outputs
                .try_push(Finalized::new(self.provider, pending.identity, output))
                .map_err(refusal)?;
        }
        Ok(DigestMemo {
            provider: self.provider,
            outputs: outputs.into_owned(),
            mapping: self.mapping,
            field: self.field,
            at: self.at,
        })
    }

    pub(crate) fn provider(&self) -> &'a P {
        self.provider
    }

    pub(crate) fn location(&self) -> (&'static str, u64) {
        (self.field, self.at)
    }
}

struct BatchSink<'s, 'a, P: DigestProvider<'a>>(&'s mut DigestBatch<'a, P>);

impl<'a, P: DigestProvider<'a>> Sink for BatchSink<'_, 'a, P> {
    type Error = DigestError<P::Error>;
    fn write<W: Work>(&mut self, bytes: &[u8], execution: &W) -> Result<(), Self::Error> {
        self.0.feed(bytes, execution)
    }
}

/// Immutable completed outputs, sorted by the selected provider's full identity.
pub struct DigestMemo<'a, P: DigestProvider<'a>> {
    provider: &'a P,
    outputs: OwnedVec<DigestOutput<'a, P>>,
    mapping: OwnedVec<usize>,
    field: &'static str,
    at: u64,
}

/// A separately completed input under an existing memo's resolved identity.
///
/// Signed attributes need their own digest output, while sharing the payload's
/// already resolved identity. This result borrows that identity and owns its
/// output; it cannot outlive the memo or become a fabricated digest identity.
pub struct RelatedDigest<'m, 'a, P: DigestProvider<'a>> {
    provider: &'a P,
    identity: &'m P::Identity,
    output: P::Output,
}

impl<'a, P: DigestProvider<'a>> RelatedDigest<'_, 'a, P> {
    /// Typed finalized input with short borrows, without identity/output clones.
    #[must_use]
    pub fn prehash(&self) -> Prehash<'_, '_, P, P::Identity> {
        Prehash::new(self.provider, self.identity, self.output.as_ref())
    }
}

struct RelatedSink<'s, 'a, P: DigestProvider<'a>> {
    provider: &'a P,
    state: &'s mut P::State,
}

impl<'a, P: DigestProvider<'a>> Sink for RelatedSink<'_, 'a, P> {
    type Error = DigestError<P::Error>;

    fn write<W: Work>(&mut self, bytes: &[u8], execution: &W) -> Result<(), Self::Error> {
        self.provider
            .update_digest(self.state, bytes, execution)
            .map_err(DigestError::Callback)
    }
}

impl<'a, P: DigestProvider<'a>> DigestMemo<'a, P> {
    /// Completes another input with the original request's resolved identity.
    ///
    /// For CMS signed attributes, feed their original retagged ranges here;
    /// their output is distinct from the payload output used by message-digest.
    /// No resolver, Identity clone, state reconstruction or payload replay is
    /// performed. An absent ordinal does not call the source or provider.
    /// `field`/`at` locate the caller's enclosing original input structure.
    pub fn digest_related<'m, S: Source, W: Work>(
        &'m self,
        ordinal: usize,
        source: &mut S,
        execution: &W,
        field: &'static str,
        at: u64,
    ) -> PassResult<Option<RelatedDigest<'m, 'a, P>>, S::Error, P::Error> {
        let Some(existing) = self
            .for_request(ordinal, execution)
            .map_err(StreamError::Callback)?
        else {
            return Ok(None);
        };
        let identity = existing.identity();
        let mut state = self
            .provider
            .start_digest(identity, execution)
            .map_err(|error| StreamError::Callback(DigestError::Callback(error)))?;
        stream::run(
            source,
            &mut RelatedSink {
                provider: self.provider,
                state: &mut state,
            },
            execution,
            field,
            at,
        )?;
        let output = self
            .provider
            .finish_digest(state, execution)
            .map_err(|error| StreamError::Callback(DigestError::Callback(error)))?;
        if let Some(expected) = self.provider.digest_width(identity) {
            let actual = output.as_ref().len();
            if actual != expected {
                return Err(StreamError::Callback(DigestError::OutputWidth {
                    expected,
                    actual,
                }));
            }
        }
        Ok(Some(RelatedDigest {
            provider: self.provider,
            identity,
            output,
        }))
    }

    /// Number of unique finalized outputs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.outputs.len()
    }
    /// Whether no completed output is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// Number of original requests, including identities that shared a state.
    #[must_use]
    pub fn request_count(&self) -> usize {
        self.mapping.len()
    }

    /// The already finalized output for an original request ordinal.
    ///
    /// This constant-work link avoids resolving an algorithm again or cloning
    /// its identity/state merely to find a shared output. Out-of-range ordinals
    /// mean absence only after current-operation admission.
    pub fn for_request<W: Work>(
        &self,
        ordinal: usize,
        execution: &W,
    ) -> DigestResult<Option<&DigestOutput<'a, P>>, P::Error> {
        execution.charge_work(1).map_err(|reason| {
            DigestError::Processing(Error::resource(reason, self.field, self.at))
        })?;
        let Some(index) = self.mapping.get(ordinal) else {
            return Ok(None);
        };
        // Preparation assigned every ordinal to a pending state; successful
        // finalization produced exactly one output for every such state.
        debug_assert!(*index < self.outputs.len());
        Ok(Some(&self.outputs[*index]))
    }

    /// Looks up a full resolved identity in the current execution account.
    ///
    /// Storage remains on its original account. No state/output clone, new hash
    /// or finalization is performed. A resource refusal cannot become absence.
    pub fn find<W: Work>(
        &self,
        identity: &P::Identity,
        execution: &W,
    ) -> DigestResult<Option<&DigestOutput<'a, P>>, P::Error> {
        let refusal =
            |reason| DigestError::Processing(Error::resource(reason, self.field, self.at));
        execution.charge_work(1).map_err(refusal)?;
        let mut from = 0;
        let mut to = self.outputs.len();
        while from < to {
            execution.charge_work(1).map_err(refusal)?;
            let middle = from + (to - from) / 2;
            let held = &self.outputs[middle];
            match self
                .provider
                .compare_digest(held.identity(), identity, execution)
                .map_err(DigestError::Callback)?
            {
                Ordering::Equal => return Ok(Some(held)),
                Ordering::Less => from = middle + 1,
                Ordering::Greater => to = middle,
            }
        }
        Ok(None)
    }
}
