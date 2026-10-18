//! Selected-signer arithmetic and content facts from one complete payload pass.

use crate::binding::{self, BindError, DigestBinding};
use crate::digest::{DigestBatch, DigestError};
use crate::payload::{PayloadBatch, PayloadError, RawRequest};
use crate::prepare::{ResolvedBinding, ResolvedSigner};
use crate::provider::{SignatureAnswer, SignatureMode, SignatureProvider};
use crate::signer::SignerInfo;
use crate::stream::{self, RangesError, Sink, Source, StreamError};
use crate::{Error, ErrorCode};
use structured_asn1::memory::{OwnedVec, Work};
use structured_pkix::path::WorkingKey;

/// Failure to execute, distinct from per-signer arithmetic/content answers.
#[derive(Debug)]
pub enum CheckError<E> {
    /// Common processing admission failed at its original source location.
    Processing(Error),
    /// Original selected-provider failure, including its resource refusal.
    Callback(E),
    /// Completed provider bytes contradict their full resolved fixed width.
    OutputWidth {
        /// Width promised by the resolved provider identity.
        expected: usize,
        /// Actual completed output width.
        actual: usize,
    },
    /// The provider resolved the digest but cannot stream it.
    Unstreamable,
}

/// Original payload acquisition failure remains distinct from execution failure.
pub type PassError<SE, PE> = StreamError<SE, CheckError<PE>>;

/// Content agreement is separate from signature arithmetic and certificate trust.
#[derive(Debug)]
pub enum ContentAgreement {
    /// Original logical payload was the signature input, without signedAttrs.
    Direct,
    /// Payload digest agrees with the original message-digest declaration.
    Matches,
    /// Correctly sized payload digest differs; no attrs signature was attempted.
    Differs,
    /// Declared width cannot match the actual completed output.
    Malformed(Error),
}

/// Facts for one original signer, without SID, path or application acceptance.
pub struct Checked<'a> {
    signer: &'a SignerInfo<'a>,
    key: WorkingKey<'a>,
    content: ContentAgreement,
    signature: Option<SignatureAnswer>,
}

impl<'a> Checked<'a> {
    /// Original signer and retained conformance faults; nothing is repaired.
    #[must_use]
    pub fn signer(&self) -> &'a SignerInfo<'a> {
        self.signer
    }
    /// The exact effective key supplied to this signature challenge, including
    /// inherited parameters. This descriptor is not a certificate trust verdict.
    #[must_use]
    pub fn key(&self) -> WorkingKey<'a> {
        self.key
    }
    /// Actual content binding, independently of signature arithmetic.
    #[must_use]
    pub fn content(&self) -> &ContentAgreement {
        &self.content
    }
    /// None when an attribute imprint differs or is malformed.
    /// A Valid answer never asserts conformance, signer identity or trust.
    #[must_use]
    pub fn signature(&self) -> Option<SignatureAnswer> {
        self.signature
    }
}

enum Challenge<'a, P: SignatureProvider<'a>> {
    RawPayload(usize),
    RawAttributes {
        digest: usize,
        state: P::RawState,
    },
    Prehashed {
        digest: usize,
        identity: P::SignatureIdentity,
    },
}

struct Pending<'a, P: SignatureProvider<'a>> {
    signer: &'a SignerInfo<'a>,
    key: WorkingKey<'a>,
    binding: ResolvedBinding<'a>,
    challenge: Challenge<'a, P>,
}

/// Resolved requests bound to one exact provider instance and original ranges.
///
/// Call `prepare::resolve` for every selected signer before constructing this
/// batch. Unsupported/malformed preparation answers remain independent facts
/// in the caller; only Ready requests can enter this driver. Selection, SID
/// binding, ESS/path restrictions and multi-signer policy remain separate.
pub struct Batch<'a, P: SignatureProvider<'a>> {
    provider: &'a P,
    payload: PayloadBatch<'a, P>,
    pending: OwnedVec<Pending<'a, P>>,
    field: &'static str,
    at: u64,
}

impl<'a, P: SignatureProvider<'a>> Batch<'a, P> {
    /// Admits metadata and verifies provider identity before initializing states.
    ///
    /// Raw direct signatures need no unused digest state, but their declared
    /// digestAlgorithm was still resolved by `prepare::resolve` before this call.
    /// Raw states receive original signatures/effective keys before payload I/O;
    /// signedAttrs states never receive payload bytes in place of attrs bytes.
    pub fn prepare<W: Work>(
        provider: &'a P,
        requests: OwnedVec<ResolvedSigner<'a, P>>,
        execution: &W,
        field: &'static str,
        at: u64,
    ) -> Result<Self, CheckError<P::Error>> {
        let refusal = |reason| CheckError::Processing(Error::resource(reason, field, at));
        let mut digest_count = 0;
        let mut raw_count = 0;
        for request in &requests {
            execution.charge_work(1).map_err(refusal)?;
            if !core::ptr::eq(provider, request.provider()) {
                return Err(CheckError::Processing(Error::schema(
                    ErrorCode::ProviderMismatch,
                    field,
                    request.signer().span().start,
                )));
            }
            if matches!(request.signature(), SignatureMode::Raw(_))
                && matches!(request.binding(), ResolvedBinding::Direct)
            {
                raw_count += 1;
            } else {
                digest_count += 1;
            }
        }
        let mut pending = execution.vector();
        let mut identities = execution.vector();
        let mut raw = execution.vector();
        pending.try_reserve_exact(requests.len()).map_err(refusal)?;
        identities
            .try_reserve_exact(digest_count)
            .map_err(refusal)?;
        raw.try_reserve_exact(raw_count).map_err(refusal)?;
        execution
            .charge_work(core::mem::size_of_val(&*requests) as u64)
            .map_err(refusal)?;
        for request in requests {
            execution.charge_work(1).map_err(refusal)?;
            let parts = request.into_parts();
            let challenge = match parts.signature {
                SignatureMode::Raw(identity)
                    if matches!(parts.binding, ResolvedBinding::Direct) =>
                {
                    let index = raw.len();
                    raw.try_push(RawRequest {
                        identity,
                        key: parts.key,
                        signature: parts.signer.signature(),
                    })
                    .map_err(refusal)?;
                    Challenge::RawPayload(index)
                }
                SignatureMode::Raw(identity) => {
                    let digest = identities.len();
                    identities.try_push(parts.digest).map_err(refusal)?;
                    let state = provider
                        .start_raw(&identity, parts.key, parts.signer.signature(), execution)
                        .map_err(CheckError::Callback)?;
                    Challenge::RawAttributes { digest, state }
                }
                SignatureMode::Prehashed(identity) => {
                    let digest = identities.len();
                    identities.try_push(parts.digest).map_err(refusal)?;
                    Challenge::Prehashed { digest, identity }
                }
            };
            pending
                .try_push(Pending {
                    signer: parts.signer,
                    key: parts.key,
                    binding: parts.binding,
                    challenge,
                })
                .map_err(refusal)?;
        }
        let digests = DigestBatch::prepare(provider, identities.into_owned(), execution, field, at)
            .map_err(digest_error)?;
        let payload =
            PayloadBatch::prepare(digests, raw.into_owned(), execution).map_err(payload_error)?;
        Ok(Self {
            provider,
            payload,
            pending: pending.into_owned(),
            field,
            at,
        })
    }

    /// Executes one payload pass and returns facts only after complete successful EOF.
    ///
    /// Original retagged signedAttrs have their own signature input. Their
    /// message-digest is compared against the payload output first (RFC5652
    /// §§5.4–5.6), then raw attrs or its separately finalized typed prehash is
    /// checked. No identity/state Clone, payload replay or re-encoding occurs.
    /// <https://www.rfc-editor.org/rfc/rfc5652#section-5.4>
    pub fn run<S: Source, W: Work>(
        self,
        source: &mut S,
        execution: &W,
    ) -> Result<OwnedVec<Checked<'a>>, PassError<S::Error, P::Error>> {
        let refusal =
            |reason| StreamError::Processing(Error::resource(reason, self.field, self.at));
        let mut results = execution.vector();
        results
            .try_reserve_exact(self.pending.len())
            .map_err(refusal)?;
        // With no selected Ready challenges there is no reason to acquire bytes.
        if self.pending.is_empty() {
            return Ok(results.into_owned());
        }
        let completed = self
            .payload
            .run(source, execution)
            .map_err(|error| match error {
                StreamError::Source(error) => StreamError::Source(error),
                StreamError::Processing(error) => StreamError::Processing(error),
                StreamError::Callback(error) => StreamError::Callback(payload_error(error)),
            })?;
        execution
            .charge_work(core::mem::size_of_val(&*self.pending) as u64)
            .map_err(refusal)?;
        for request in self.pending {
            execution.charge_work(1).map_err(refusal)?;
            let (content, signature) = check(
                self.provider,
                request.signer,
                request.key,
                &request.binding,
                request.challenge,
                &completed,
                execution,
            )
            .map_err(StreamError::Callback)?;
            results
                .try_push(Checked {
                    signer: request.signer,
                    key: request.key,
                    content,
                    signature,
                })
                .map_err(refusal)?;
        }
        Ok(results.into_owned())
    }
}

fn check<'a, P: SignatureProvider<'a>, W: Work>(
    provider: &'a P,
    signer: &'a SignerInfo<'a>,
    key: WorkingKey<'a>,
    binding: &ResolvedBinding<'a>,
    challenge: Challenge<'a, P>,
    completed: &crate::payload::Completed<'a, P>,
    execution: &W,
) -> Result<(ContentAgreement, Option<SignatureAnswer>), CheckError<P::Error>> {
    let digest = match &challenge {
        Challenge::RawPayload(index) => {
            debug_assert!(*index < completed.raw().len());
            return Ok((ContentAgreement::Direct, Some(completed.raw()[*index])));
        }
        Challenge::RawAttributes { digest, .. } | Challenge::Prehashed { digest, .. } => *digest,
    };
    let payload = completed
        .digests()
        .for_request(digest, execution)
        .map_err(digest_error)?;
    let payload = payload.expect("prepared request ordinal has a completed output");
    if let ResolvedBinding::Attributes {
        digest: expected,
        digest_span,
    } = binding
    {
        match binding::matches_digest(
            provider,
            payload.finished(),
            expected,
            execution,
            "signerInfo.signedAttrs.messageDigest",
            *digest_span,
        )
        .map_err(bind_error)?
        {
            DigestBinding::Differs => return Ok((ContentAgreement::Differs, None)),
            DigestBinding::Malformed(error) => {
                return Ok((ContentAgreement::Malformed(error), None));
            }
            DigestBinding::Matches => {}
        }
        let attributes = signer
            .signed_attributes()
            .expect("prepared attrs binding retained its original attrs");
        let mut ranges = attributes
            .signed_bytes()
            .expect("prepared signed attrs have SET signature ranges");
        let signature = match challenge {
            Challenge::RawAttributes { mut state, .. } => {
                stream::run(
                    &mut ranges,
                    &mut RawSink {
                        provider,
                        state: &mut state,
                    },
                    execution,
                    "signerInfo.signedAttrs",
                    attributes.element().span().start,
                )
                .map_err(|error| range_error(error, attributes.element().span().start))?;
                provider
                    .finish_raw(state, execution)
                    .map_err(CheckError::Callback)?
            }
            Challenge::Prehashed { identity, .. } => {
                let related = completed
                    .digests()
                    .digest_related(
                        digest,
                        &mut ranges,
                        execution,
                        "signerInfo.signedAttrs",
                        attributes.element().span().start,
                    )
                    .map_err(|error| related_error(error, attributes.element().span().start))?
                    .expect("prepared request ordinal retains its identity");
                provider
                    .verify_prehashed(
                        &identity,
                        key,
                        signer.signature(),
                        related.prehash(),
                        execution,
                    )
                    .map_err(CheckError::Callback)?
            }
            Challenge::RawPayload(_) => {
                unreachable!("raw payload challenges returned before attrs processing")
            }
        };
        return Ok((ContentAgreement::Matches, Some(signature)));
    }
    let Challenge::Prehashed { identity, .. } = challenge else {
        unreachable!("only prehashed direct input reaches the digest branch");
    };
    let signature = provider
        .verify_prehashed(
            &identity,
            key,
            signer.signature(),
            payload.prehash(),
            execution,
        )
        .map_err(CheckError::Callback)?;
    Ok((ContentAgreement::Direct, Some(signature)))
}

struct RawSink<'s, 'a, P: SignatureProvider<'a>> {
    provider: &'a P,
    state: &'s mut P::RawState,
}
impl<'a, P: SignatureProvider<'a>> Sink for RawSink<'_, 'a, P> {
    type Error = P::Error;
    fn write<W: Work>(&mut self, bytes: &[u8], execution: &W) -> Result<(), Self::Error> {
        self.provider.update_raw(self.state, bytes, execution)
    }
}

fn digest_error<E>(error: DigestError<E>) -> CheckError<E> {
    match error {
        DigestError::Processing(error) => CheckError::Processing(error),
        DigestError::Callback(error) => CheckError::Callback(error),
        DigestError::OutputWidth { expected, actual } => {
            CheckError::OutputWidth { expected, actual }
        }
        DigestError::Unstreamable => CheckError::Unstreamable,
    }
}
fn payload_error<E>(error: PayloadError<E>) -> CheckError<E> {
    match error {
        PayloadError::Processing(error) => CheckError::Processing(error),
        PayloadError::Callback(error) => CheckError::Callback(error),
        PayloadError::Digest(error) => digest_error(error),
    }
}
fn bind_error<E>(error: BindError<E>) -> CheckError<E> {
    match error {
        BindError::Processing(error) => CheckError::Processing(error),
        BindError::Callback(error) => CheckError::Callback(error),
        BindError::OutputWidth { expected, actual } => CheckError::OutputWidth { expected, actual },
    }
}
fn range_error<E>(error: StreamError<RangesError, E>, at: u64) -> CheckError<E> {
    match error {
        StreamError::Source(RangesError::Resource(reason)) => {
            CheckError::Processing(Error::resource(reason, "signerInfo.signedAttrs", at))
        }
        StreamError::Source(RangesError::Receiver(_)) => {
            unreachable!("stream guard preserves the original sink refusal")
        }
        StreamError::Processing(error) => CheckError::Processing(error),
        StreamError::Callback(error) => CheckError::Callback(error),
    }
}
fn related_error<E>(error: StreamError<RangesError, DigestError<E>>, at: u64) -> CheckError<E> {
    match error {
        StreamError::Callback(error) => digest_error(error),
        error => range_error(error, at).map_callback(),
    }
}

impl<E> CheckError<DigestError<E>> {
    fn map_callback(self) -> CheckError<E> {
        match self {
            Self::Processing(error) => CheckError::Processing(error),
            Self::Callback(error) => digest_error(error),
            Self::OutputWidth { expected, actual } => CheckError::OutputWidth { expected, actual },
            Self::Unstreamable => CheckError::Unstreamable,
        }
    }
}
