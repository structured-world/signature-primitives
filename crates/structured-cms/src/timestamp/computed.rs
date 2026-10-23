//! Scoped computed imprints: alternatives and Merkle roots without double hashing.

use super::{ImprintAgreement, ImprintError, MessageImprint};
use crate::{Error, binding::DigestBinding, digest::DigestError, provider::Finished};
use core::cell::{Cell, RefCell};
use structured_asn1::{Reader, Span, digest::Resolution, memory::OwnedVec};
use structured_pkix::algorithm::digest::AsnDigest;

/// An input recipe executes under the token's one resolved digest identity.
///
/// A recipe can stream several normative alternatives together, or compute a
/// reduced hash tree. It cannot construct an affirmative proof from bytes or
/// a boolean: only this operation's completed states can be compared with the
/// original declared hash. Provider errors cannot borrow temporary joined
/// information. No identity/state/output cloning is required.
pub trait ComputedInput<P, PE> {
    /// Original source or recipe failure, independent of semantic disagreement.
    type Error;

    /// Complete the input, preserving refusal even when a callback ignores it.
    fn compute<'context, 'reader, 'document>(
        &mut self,
        context: &'context ImprintContext<'reader, 'document, P, Self::Error>,
    ) -> Result<ImprintProof<'context>, InputFailure<Self::Error>>
    where
        P: AsnDigest<'document, Error = PE>;
}

/// Original recipe failure or a marker whose cause the operation retains.
#[derive(Debug)]
pub enum InputFailure<E> {
    /// Original source/recipe cause; no successful prefix is returned.
    Source(E),
    /// The context keeps the first processing/provider/acquisition refusal.
    Refused(crate::stream::Refused),
}
impl<E> From<crate::stream::Refused> for InputFailure<E> {
    fn from(value: crate::stream::Refused) -> Self {
        Self::Refused(value)
    }
}

/// Closed comparison receipt, tied to this non-zero-sized operation owner.
///
/// This is not a standalone timestamp or trust proof. It cannot outlive the
/// computation or be substituted from another token/context.
pub struct ImprintProof<'context> {
    owner: &'context u8,
    agreement: ImprintAgreement,
}
impl ImprintProof<'_> {
    /// Actual completed comparison, for choosing among finished alternatives.
    #[must_use]
    pub fn agreement(&self) -> ImprintAgreement {
        self.agreement
    }
}

enum Expected<'a> {
    Borrowed(&'a [u8]),
    Joined(OwnedVec<u8>),
}
impl Expected<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Joined(bytes) => bytes,
        }
    }
}

/// One original imprint, one provider identity and the current producing work.
///
/// The context is constructed only after schema/session/width preflight. Its
/// non-zero-sized owner distinguishes even otherwise identical operations. All state
/// transitions retain the first refusal; no `RefCell` borrow crosses a callback.
pub struct ImprintContext<'reader, 'document, P: AsnDigest<'document>, E> {
    provider: &'document P,
    identity: P::Identity,
    reader: &'reader Reader<'document>,
    expected: Expected<'document>,
    field: &'static str,
    span: Span,
    owner: u8,
    active: Cell<usize>,
    abandoned: Cell<bool>,
    failure: RefCell<Option<ImprintError<E, P::Error>>>,
}

/// One unfinished state of this operation's exact resolved identity.
/// Dropping it unfinished prevents a successful computation, even if another
/// alternative matched. Opaque provider state owns its admitted storage.
pub struct ImprintState<'context, 'reader, 'document, P: AsnDigest<'document>, E> {
    context: &'context ImprintContext<'reader, 'document, P, E>,
    state: Option<P::State>,
}

/// The provider's own completed output, retaining its context and identity.
/// Intermediate tree hashes can be borrowed without copying, re-resolving or
/// reconstructing a state. There is no arbitrary-byte constructor.
pub struct ImprintDigest<'context, 'reader, 'document, P: AsnDigest<'document>, E> {
    context: &'context ImprintContext<'reader, 'document, P, E>,
    output: P::Output,
}
impl<'document, P: AsnDigest<'document>, E> ImprintDigest<'_, '_, 'document, P, E> {
    /// Complete output bytes, never a digest of a partial/refused state.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.output.as_ref()
    }
    /// Typed finalized output for existing common digest consumers.
    #[must_use]
    pub fn finished(&self) -> Finished<'_, P, P::Identity, P::Output> {
        Finished::new(self.context.provider, &self.context.identity, &self.output)
    }
}

impl<'reader, 'document, P: AsnDigest<'document>, E> ImprintContext<'reader, 'document, P, E> {
    /// Original producing information reader and current operation ceilings.
    #[must_use]
    pub fn reader(&self) -> &Reader<'document> {
        self.reader
    }
    /// Full selected-provider identity; output width is not an algorithm ID.
    #[must_use]
    pub fn identity(&self) -> &P::Identity {
        &self.identity
    }
    pub(crate) fn provider(&self) -> &'document P {
        self.provider
    }
    fn failed(&self) -> bool {
        self.failure.borrow().is_some()
    }
    fn refuse(&self, cause: ImprintError<E, P::Error>) -> crate::stream::Refused {
        let mut failure = self.failure.borrow_mut();
        if failure.is_none() {
            *failure = Some(cause);
        }
        crate::stream::Refused
    }
    fn admit(&self) -> Result<(), crate::stream::Refused> {
        if self.failed() {
            return Err(crate::stream::Refused);
        }
        self.reader.charge(1).map_err(|cause| {
            self.refuse(ImprintError::Processing(Error::encoding(cause, self.field)))
        })
    }
    fn admit_pass(&self) -> Result<(), crate::stream::Refused> {
        if self.failed() {
            return Err(crate::stream::Refused);
        }
        self.reader.charge(1).map_err(|cause| {
            self.refuse(ImprintError::Pass(crate::stream::StreamError::Processing(
                Error::encoding(cause, self.field),
            )))
        })
    }
    /// Starts another candidate/intermediate hash under this SAME identity.
    pub fn start(
        &self,
    ) -> Result<ImprintState<'_, 'reader, 'document, P, E>, crate::stream::Refused> {
        self.admit()?;
        let Some(active) = self.active.get().checked_add(1) else {
            return Err(self.refuse(ImprintError::IncompleteInput));
        };
        let state = self
            .provider
            .start(&self.identity, &self.reader.execution())
            .map_err(|cause| self.refuse(ImprintError::Digest(DigestError::Callback(cause))))?;
        let Resolution::Supported(state) = state else {
            return Err(self.refuse(ImprintError::Digest(DigestError::Unstreamable)));
        };
        self.active.set(active);
        Ok(ImprintState {
            context: self,
            state: Some(state),
        })
    }
    /// Feeds every selected state in ONE complete source pass. Empty state
    /// lists and foreign contexts refuse before source I/O. Source errors and
    /// ignored receiver failures remain sticky across the whole recipe.
    pub fn stream<'context, S: crate::stream::Source<Error = E>>(
        &'context self,
        source: &mut S,
        states: &mut [&mut ImprintState<'context, 'reader, 'document, P, E>],
    ) -> Result<(), crate::stream::Refused> {
        self.stream_with(source, states, &self.reader.execution())
    }

    /// Streams another original source using ITS producing ceiling and this
    /// operation's current root ceilings/account. This does not use the old
    /// source's former account or widen a narrowed current query. The format
    /// recipe supplies the actual source reader, never a replacement parser.
    pub fn stream_from<'context, S: crate::stream::Source<Error = E>>(
        &'context self,
        source: &mut S,
        origin: &Reader<'_>,
        states: &mut [&mut ImprintState<'context, 'reader, 'document, P, E>],
    ) -> Result<(), crate::stream::Refused> {
        self.stream_with(source, states, &origin.execution_query(self.reader))
    }

    fn stream_with<'context, S, W>(
        &'context self,
        source: &mut S,
        states: &mut [&mut ImprintState<'context, 'reader, 'document, P, E>],
        execution: &W,
    ) -> Result<(), crate::stream::Refused>
    where
        S: crate::stream::Source<Error = E>,
        W: structured_asn1::memory::Work,
    {
        self.admit()?;
        if states.is_empty() {
            return Err(self.refuse(ImprintError::IncompleteInput));
        }
        for state in &*states {
            self.admit()?;
            if !core::ptr::eq(&raw const state.context.owner, &raw const self.owner) {
                return Err(self.refuse(ImprintError::ForeignInput));
            }
        }
        let result = crate::stream::run(
            source,
            &mut Fanout { states },
            execution,
            self.field,
            self.span.start,
        );
        match result {
            Ok(()) => Ok(()),
            Err(crate::stream::StreamError::Source(cause)) => Err(self.refuse(ImprintError::Pass(
                crate::stream::StreamError::Source(cause),
            ))),
            Err(crate::stream::StreamError::Processing(cause)) => Err(self.refuse(
                ImprintError::Pass(crate::stream::StreamError::Processing(cause)),
            )),
            // State writes already retained the original callback cause.
            Err(crate::stream::StreamError::Callback(_)) => Err(crate::stream::Refused),
        }
    }
    /// Compares one completed output with the original declared hash. Other
    /// candidates can be completed and compared without another payload pass.
    pub fn compare<'context>(
        &'context self,
        digest: &ImprintDigest<'_, '_, 'document, P, E>,
    ) -> Result<ImprintProof<'context>, crate::stream::Refused> {
        self.admit()?;
        if !core::ptr::eq(&raw const digest.context.owner, &raw const self.owner) {
            return Err(self.refuse(ImprintError::ForeignInput));
        }
        self.compare_output(&digest.output)
    }

    // RFC4998 §4.2(5) permits an explicit tree identity distinct from the
    // timestamp imprint identity. Only the ERS kernel can supply that finished
    // provider output; callers still cannot construct a proof from raw bytes.
    pub(crate) fn compare_output<'context>(
        &'context self,
        output: &P::Output,
    ) -> Result<ImprintProof<'context>, crate::stream::Refused> {
        self.admit()?;
        let result = crate::binding::matches_digest(
            self.provider,
            Finished::new(self.provider, &self.identity, output),
            self.expected.bytes(),
            &self.reader.execution(),
            self.field,
            self.span,
        )
        .map_err(|cause| self.refuse(ImprintError::Comparison(cause)))?;
        Ok(ImprintProof {
            owner: &self.owner,
            agreement: match result {
                DigestBinding::Matches => ImprintAgreement::Matches,
                DigestBinding::Differs => ImprintAgreement::Differs,
                DigestBinding::Malformed(_) => ImprintAgreement::MalformedHash,
            },
        })
    }

    // A private format kernel may derive its root under an explicit different
    // RFC4998 tree identity. Keep its completed-output comparison inside the
    // operation's sticky refusal boundary; no public byte/proof constructor.
    pub(crate) fn compare_derived(
        &self,
        compare: impl FnOnce(&[u8], &structured_asn1::memory::Execution<'_>) -> Result<bool, E>,
    ) -> Result<ImprintProof<'_>, crate::stream::Refused> {
        self.admit()?;
        let matches =
            compare(self.expected.bytes(), &self.reader.execution()).map_err(|cause| {
                self.refuse(ImprintError::Pass(crate::stream::StreamError::Source(
                    cause,
                )))
            })?;
        Ok(ImprintProof {
            owner: &self.owner,
            agreement: if matches {
                ImprintAgreement::Matches
            } else {
                ImprintAgreement::Differs
            },
        })
    }
}

impl<'context, 'reader, 'document, P: AsnDigest<'document>, E>
    ImprintState<'context, 'reader, 'document, P, E>
{
    /// Admits and hashes one original/generated chunk. An ignored failure
    /// cannot be repaired by subsequent writes or finalization.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), crate::stream::Refused> {
        self.write_with(bytes, &self.context.reader.execution())
    }
    /// Hashes a range from another original reader, with that origin and the
    /// current operation admitted together. The caller's format kernel binds
    /// `bytes` to that original source before invoking this operation.
    pub fn write_from(
        &mut self,
        bytes: &[u8],
        origin: &Reader<'_>,
    ) -> Result<(), crate::stream::Refused> {
        self.write_with(bytes, &origin.execution_query(self.context.reader))
    }
    fn write_with<W: structured_asn1::memory::Work>(
        &mut self,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), crate::stream::Refused> {
        self.context.admit_pass()?;
        // Empty ranges still cost a producing-source/fanout visit. A digest
        // provider correctly charges zero byte work for them; it cannot fund
        // this structural traversal or enforce its origin ceiling for us.
        execution.charge_work(1).map_err(|cause| {
            self.context
                .refuse(ImprintError::Pass(crate::stream::StreamError::Processing(
                    Error::resource(cause, self.context.field, self.context.span.start),
                )))
        })?;
        self.context
            .provider
            .update(
                self.state
                    .as_mut()
                    .expect("unfinished state owns its backend"),
                bytes,
                execution,
            )
            .map_err(|cause| {
                self.context
                    .refuse(ImprintError::Pass(crate::stream::StreamError::Callback(
                        DigestError::Callback(cause),
                    )))
            })
    }
    /// Consumes the state exactly once. A wrong provider output width refuses
    /// before exposing it for an intermediate tree or final comparison.
    /// # Panics
    /// If the internal ownership invariant is violated. The consuming public
    /// API retains its backend state until this single completion.
    pub fn finish(
        mut self,
    ) -> Result<ImprintDigest<'context, 'reader, 'document, P, E>, crate::stream::Refused> {
        self.context.admit_pass()?;
        let output = self
            .context
            .provider
            .finish(
                self.state
                    .take()
                    .expect("unfinished state owns its backend"),
                &self.context.reader.execution(),
            )
            .map_err(|cause| {
                self.context
                    .refuse(ImprintError::Pass(crate::stream::StreamError::Callback(
                        DigestError::Callback(cause),
                    )))
            })?;
        if let Some(expected) = self.context.provider.width(&self.context.identity)
            && output.as_ref().len() != expected
        {
            return Err(self.context.refuse(ImprintError::Pass(
                crate::stream::StreamError::Callback(DigestError::OutputWidth {
                    expected,
                    actual: output.as_ref().len(),
                }),
            )));
        }
        Ok(ImprintDigest {
            context: self.context,
            output,
        })
    }
}
impl<'document, P: AsnDigest<'document>, E> Drop for ImprintState<'_, '_, 'document, P, E> {
    fn drop(&mut self) {
        let active = self.context.active.get();
        debug_assert!(active > 0);
        self.context.active.set(active - 1);
        if self.state.is_some() {
            self.context.abandoned.set(true);
        }
    }
}

struct Fanout<'states, 'state, 'context, 'reader, 'document, P: AsnDigest<'document>, E> {
    states: &'states mut [&'state mut ImprintState<'context, 'reader, 'document, P, E>],
}
impl<'document, P: AsnDigest<'document>, E> crate::stream::Sink
    for Fanout<'_, '_, '_, '_, 'document, P, E>
{
    type Error = crate::stream::Refused;
    fn write<W: structured_asn1::memory::Work>(
        &mut self,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), Self::Error> {
        for state in &mut *self.states {
            state.write_with(bytes, execution)?;
        }
        Ok(())
    }
}

/// Ordinary covered bytes use the same closed computation as derived inputs.
pub struct RawInput<'source, S>(&'source mut S);
impl<'source, S> RawInput<'source, S> {
    /// Borrows a source without allocation, copying or changing its errors.
    #[must_use]
    pub fn new(source: &'source mut S) -> Self {
        Self(source)
    }
}
impl<P, PE, S: crate::stream::Source> ComputedInput<P, PE> for RawInput<'_, S> {
    type Error = S::Error;
    fn compute<'context, 'reader, 'document>(
        &mut self,
        context: &'context ImprintContext<'reader, 'document, P, Self::Error>,
    ) -> Result<ImprintProof<'context>, InputFailure<Self::Error>>
    where
        P: AsnDigest<'document, Error = PE>,
    {
        let mut state = context.start()?;
        context.stream(self.0, &mut [&mut state])?;
        let output = state.finish()?;
        context.compare(&output).map_err(InputFailure::Refused)
    }
}

pub(super) fn compute<'a, P, I>(
    imprint: &MessageImprint<'a>,
    provider: &'a P,
    parent: &Reader<'a>,
    input: &mut I,
    identity: P::Identity,
) -> Result<ImprintAgreement, ImprintError<I::Error, P::Error>>
where
    P: AsnDigest<'a>,
    I: ComputedInput<P, P::Error>,
{
    let field = imprint.fields().hashed;
    let span = imprint.hashed().span();
    // Complete declared-hash materialization precedes state/provider effects.
    let expected = match imprint.hashed().as_one() {
        Some(bytes) => Expected::Borrowed(bytes),
        None => Expected::Joined(
            imprint
                .hashed()
                .copy_in(parent, field, span.start)
                .map_err(ImprintError::Processing)?,
        ),
    };
    let context = ImprintContext {
        provider,
        identity,
        reader: parent,
        expected,
        field,
        span,
        owner: 0,
        active: Cell::new(0),
        abandoned: Cell::new(false),
        failure: RefCell::new(None),
    };
    let result = input.compute(&context);
    if let Some(cause) = context.failure.borrow_mut().take() {
        return Err(cause);
    }
    let proof = match result {
        Ok(proof) => proof,
        Err(InputFailure::Source(cause)) => {
            return Err(ImprintError::Pass(crate::stream::StreamError::Source(
                cause,
            )));
        }
        Err(InputFailure::Refused(_)) => return Err(ImprintError::IncompleteInput),
    };
    if !core::ptr::eq(proof.owner, &raw const context.owner) {
        return Err(ImprintError::ForeignInput);
    }
    if context.active.get() != 0 || context.abandoned.get() {
        return Err(ImprintError::IncompleteInput);
    }
    Ok(proof.agreement)
}
