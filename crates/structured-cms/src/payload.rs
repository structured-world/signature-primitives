//! One complete source pass for resolved digest and raw-signature states.

use crate::Error;
use crate::Octets;
use crate::digest::{DigestBatch, DigestError, DigestMemo, DigestOutput};
use crate::provider::{SignatureAnswer, SignatureProvider};
use crate::stream::{self, Sink, Source, StreamError};
use structured_asn1::memory::{OwnedVec, Work};
use structured_pkix::path::WorkingKey;

/// A raw challenge already resolved by this operation's selected provider.
///
/// The original signature catalogue must remain stable for the duration of
/// the pass. The effective key is a value, not a borrow of a temporary key
/// descriptor. A raw challenge is never satisfied by feeding digest bytes.
pub struct RawRequest<'a, P: SignatureProvider<'a>> {
    /// Fully resolved signature identity from the selected provider.
    pub identity: P::SignatureIdentity,
    /// Original effective key, including inherited parameters.
    pub key: WorkingKey<'a>,
    /// Original logical signature octets, without concatenation or re-encoding.
    pub signature: &'a Octets<'a>,
}

/// Why a prepared payload operation could not execute.
#[derive(Debug)]
pub enum PayloadError<E> {
    /// Common storage or fan-out admission failed before execution.
    Processing(Error),
    /// Original raw-verification callback failure.
    Callback(E),
    /// Digest processing or callback failure, with its distinct cause.
    Digest(DigestError<E>),
}

/// Source acquisition, processing and selected-provider causes for one pass.
pub type PassError<SE, PE> = StreamError<SE, PayloadError<PE>>;

/// A prepared fan-out bound to the digest batch's selected provider instance.
///
/// This is a processing mechanism, not CMS schema, signer selection or trust
/// validation. The caller must resolve and validate every request first.
pub struct PayloadBatch<'a, P: SignatureProvider<'a>> {
    digests: DigestBatch<'a, P>,
    raw: OwnedVec<P::RawState>,
}

/// Outputs available only after complete source EOF and successful callbacks.
pub struct Completed<'a, P: SignatureProvider<'a>> {
    digests: DigestMemo<'a, P>,
    raw: OwnedVec<SignatureAnswer>,
}

impl<'a, P: SignatureProvider<'a>> Completed<'a, P> {
    /// Complete typed digest outputs with their original request mapping.
    #[must_use]
    pub fn digests(&self) -> &DigestMemo<'a, P> {
        &self.digests
    }

    /// Raw answers in request order. These do not assert certificate trust.
    #[must_use]
    pub fn raw(&self) -> &[SignatureAnswer] {
        &self.raw
    }
}

impl<'a, P: SignatureProvider<'a>> PayloadBatch<'a, P> {
    /// Initializes raw challenges before source I/O, without retaining Work.
    ///
    /// No identity/state cloning, provider switching or prehash substitution
    /// occurs. Every request's metadata storage is admitted before its start
    /// callback. The callback accounts for its own complete transitive work.
    pub fn prepare<W: Work>(
        digests: DigestBatch<'a, P>,
        requests: OwnedVec<RawRequest<'a, P>>,
        execution: &W,
    ) -> Result<Self, PayloadError<P::Error>> {
        let (field, at) = digests.location();
        let refusal = |reason| PayloadError::Processing(Error::resource(reason, field, at));
        let mut raw = execution.vector();
        raw.try_reserve_exact(requests.len()).map_err(refusal)?;
        execution
            .charge_work(core::mem::size_of_val(&*requests) as u64)
            .map_err(refusal)?;
        for request in requests {
            execution.charge_work(1).map_err(refusal)?;
            let state = digests
                .provider()
                .start_raw(&request.identity, request.key, request.signature, execution)
                .map_err(PayloadError::Callback)?;
            raw.try_push(state).map_err(refusal)?;
        }
        Ok(Self {
            digests,
            raw: raw.into_owned(),
        })
    }

    /// Streams once to every digest and raw state, then consumes each once.
    ///
    /// Output catalogues are admitted before calling the source. Incomplete
    /// source acquisition or any sticky callback refusal returns no completed
    /// digests or raw answers, even if other states processed an input prefix.
    pub fn run<S: Source, W: Work>(
        mut self,
        source: &mut S,
        execution: &W,
    ) -> Result<Completed<'a, P>, PassError<S::Error, P::Error>> {
        let (field, at) = self.digests.location();
        let refusal = |reason| StreamError::Processing(Error::resource(reason, field, at));
        let mut outputs: OwnedVec<DigestOutput<'a, P>, W> = execution.vector();
        outputs
            .try_reserve_exact(self.digests.len())
            .map_err(refusal)?;
        let mut answers = execution.vector();
        answers.try_reserve_exact(self.raw.len()).map_err(refusal)?;
        stream::run(source, &mut PayloadSink(&mut self), execution, field, at)?;
        execution
            .charge_work(core::mem::size_of_val(&*self.raw) as u64)
            .map_err(refusal)?;
        let provider = self.digests.provider();
        let digests = self
            .digests
            .finish(outputs, execution)
            .map_err(|error| StreamError::Callback(PayloadError::Digest(error)))?;
        for state in self.raw {
            execution.charge_work(1).map_err(refusal)?;
            let answer = provider
                .finish_raw(state, execution)
                .map_err(|error| StreamError::Callback(PayloadError::Callback(error)))?;
            answers.try_push(answer).map_err(refusal)?;
        }
        Ok(Completed {
            digests,
            raw: answers.into_owned(),
        })
    }
}

struct PayloadSink<'s, 'a, P: SignatureProvider<'a>>(&'s mut PayloadBatch<'a, P>);

impl<'a, P: SignatureProvider<'a>> Sink for PayloadSink<'_, 'a, P> {
    type Error = PayloadError<P::Error>;

    fn write<W: Work>(&mut self, bytes: &[u8], execution: &W) -> Result<(), Self::Error> {
        self.0
            .digests
            .feed(bytes, execution)
            .map_err(PayloadError::Digest)?;
        let (field, at) = self.0.digests.location();
        for state in &mut self.0.raw {
            execution
                .charge_work(1)
                .map_err(|reason| PayloadError::Processing(Error::resource(reason, field, at)))?;
            self.0
                .digests
                .provider()
                .update_raw(state, bytes, execution)
                .map_err(PayloadError::Callback)?;
        }
        Ok(())
    }
}
