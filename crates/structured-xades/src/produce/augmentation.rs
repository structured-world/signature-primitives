//! Source-bound append operations over a caller-owned unpublished XML draft.

use super::{Error, Materials, Timestamp, TimestampKind, Writer};
use crate::{
    baseline::Assessment,
    prepare::Prepared,
    timestamp::{self, AppendKind, Input, TimestampXml},
    unsigned::Requirements,
    xml::Snapshot,
};
use structured_asn1::{
    Reader,
    memory::{Execution, Work},
};
use structured_cms::{
    provider::SignatureProvider,
    timestamp::{CheckContext, ProfileCheckError, TokenExtension},
};

/// Append-only transaction opened by the XML owner at the exact original tail.
/// Base identities remain fixed while new draft generations are unpublished.
/// Commit checks preserve original `SignedInfo`, `SignatureValue`, signed target
/// bytes, namespace context, earlier unsigned subtrees and all archive inputs.
/// Rollback/discard on any error belongs to the owner of that transaction.
pub trait Transaction: Writer {
    /// Opaque source node identity.
    type Id: Copy + Eq;
    /// Original document identity.
    type Document: Copy + Eq;
    /// Original generation identity.
    type Generation: Copy + Eq;
    /// Immutable base used to open this transaction, never the evolving draft.
    fn base(&self) -> Snapshot<Self::Document, Self::Generation>;
    /// Exact selected signature, not any signature in the same document.
    fn signature(&self) -> Self::Id;
    /// Original unsigned parent, absent when the owner must create it.
    fn unsigned_parent(&self) -> Option<Self::Id>;
    /// Copy the complete actual `CanonicalizationMethod` or `DigestMethod` with
    /// its parameters from the immutable base/staging source into the new property.
    /// This admits every scan/copy/allocation and verifies source identity.
    fn method<W: Work>(&mut self, method: Self::Id, work: &W) -> Result<(), Self::Error>;
}

/// Source-bound plan. Every operation checks this original source and selected
/// tail before callbacks, and again before returning a completed draft step.
/// A changed generation needs a new plan and a new TSA request.
pub struct Augmentation<'a, X: TimestampXml> {
    xml: &'a X,
    prepared: &'a Prepared<X>,
}

/// Original response, selected provider and explicit request/time context.
/// These borrows neither allocate nor select another crypto engine.
pub struct ResponseCheck<'a, 'context, P> {
    /// Exact live original response being checked and incorporated.
    pub response: &'a structured_cms::timestamp::Response<'a>,
    /// Actual selected provider.
    pub provider: &'a P,
    /// Current operation reader, independent of the response source.
    pub query: &'context Reader<'a>,
    /// Existing RFC3161 request, certificate and clock facts.
    pub context: &'context CheckContext<'a, 'context>,
}

/// Original whole-signature missing-material report for this XML identity domain.
pub type Presence<'view, 'source, X> = structured_ltv::material::Incorporation<
    'view,
    'source,
    <X as crate::xml::Xml>::Id,
    <X as crate::xml::Xml>::Document,
    <X as crate::xml::Xml>::Generation,
    crate::material::Placement<<X as crate::xml::Xml>::Id>,
>;
/// Source-domain timestamp response result retaining original causes.
pub type ResponseResult<T, X, PE, RE> =
    Result<T, ResponseError<<X as crate::xml::Xml>::Error, <X as crate::xml::Xml>::Id, PE, RE>>;
/// Checked response in the selected XML owner's identity domain.
pub type CheckedFor<'a, X> = Checked<
    'a,
    <X as crate::xml::Xml>::Document,
    <X as crate::xml::Xml>::Generation,
    <X as crate::xml::Xml>::Id,
>;
/// Future input result, without impossible response/provider error variants.
pub type InputResult<'a, X> = Result<
    Input<'a, X>,
    PreparationError<<X as crate::xml::Xml>::Error, <X as crate::xml::Xml>::Id>,
>;
impl<'a, X: TimestampXml> Augmentation<'a, X> {
    /// Borrow an actual prepared signature, without cloning any source/receipt.
    #[must_use]
    pub const fn new(xml: &'a X, prepared: &'a Prepared<X>) -> Self {
        Self { xml, prepared }
    }

    /// Prepare the exact future timestamp input after all required material
    /// and optional `RenewedDigestsV2` have been staged. No placeholder timestamp
    /// or token is inserted and no canonical bytes are buffered.
    pub fn input<A, W: Work>(
        &self,
        assessment: &Assessment<'_, A, X::Id, X::Document, X::Generation>,
        kind: TimestampKind,
        method: X::Id,
        work: &W,
    ) -> InputResult<'a, X> {
        self.gate(assessment, kind, work)
            .map_err(PreparationError::Admission)?;
        Input::prepare_append(
            self.xml,
            self.prepared.bound(),
            append_kind(kind),
            method,
            work,
        )
        .map_err(PreparationError::Input)
    }

    /// Check the exact original response through the existing RFC3161 and
    /// `XAdES` profile kernels, including the actual proposed input stream.
    /// Request context is mandatory. A granted response or matching nonce alone
    /// cannot construct a timestamp: privately issued mathematical evidence is
    /// required. Negative facts are returned intact when evidence is absent.
    #[expect(
        clippy::result_large_err,
        reason = "preserve original common profile/source/resource causes without allocating an error while handling exhaustion"
    )]
    pub fn check_response<'q, A, P, PE, RE>(
        &'q self,
        assessment: &Assessment<'_, A, X::Id, X::Document, X::Generation>,
        kind: TimestampKind,
        method: X::Id,
        check: &ResponseCheck<'q, '_, P>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> ResponseResult<CheckedFor<'q, X>, X, PE, RE>
    where
        'a: 'q,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let work = check.query.execution();
        self.gate(assessment, kind, &work)
            .map_err(ResponseError::Admission)?;
        let mut input = Input::prepare_append(
            self.xml,
            self.prepared.bound(),
            append_kind(kind),
            method,
            &work,
        )
        .map_err(ResponseError::Input)?;
        let facts = check
            .response
            .check_with_profile(
                check.provider,
                check.query,
                check.context,
                &mut input,
                recognizes,
                |input| timestamp::profile::check(&input),
            )
            .map_err(ResponseError::Check)?;
        Ok(Checked {
            snapshot: self.prepared.bound().containers().snapshot(),
            signature: self.prepared.bound().containers().signature(),
            method,
            kind,
            response: check.response,
            facts,
        })
    }

    /// Append the accepted actual token using its actual original method.
    /// The transaction must be opened against this exact source/tail. Any
    /// caller-side mutation while awaiting the TSA refuses before emission.
    pub fn write_timestamp<B, W: Work>(
        &self,
        timestamp: &Timestamp<'_, X::Document, X::Generation, X::Id>,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>>
    where
        B: Transaction<Id = X::Id, Document = X::Document, Generation = X::Generation>,
    {
        self.require(writer, work)?;
        let layout = self.prepared.bound().containers();
        work.charge_work(1).map_err(Error::Resource)?;
        if timestamp.snapshot != layout.snapshot()
            || !structured_ltv::source::equal_id(timestamp.signature, layout.signature(), work)
                .map_err(Error::Resource)?
        {
            return Err(Error::Foreign);
        }
        timestamp.write(writer, work, |writer, work| {
            writer.method(timestamp.method, work)
        })?;
        self.require(writer, work)
    }

    /// Append every missing actual artifact from the same source's complete
    /// incorporation report. Existing copies and earlier protected properties
    /// are preserved. Re-prepare and re-assess the draft before timestamping it.
    pub fn write_materials<'view, 'source, B, W: Work>(
        &self,
        required: &Presence<'view, 'source, X>,
        writer: &mut B,
        work: &W,
        envelope: impl FnMut(
            &'view structured_pkix::ocsp::BasicResponse<'source>,
            &Execution<'_>,
        )
            -> Result<&'view structured_pkix::ocsp::ResponseBytes<'source>, B::Error>,
    ) -> Result<(), Error<B::Error>>
    where
        B: Transaction<Id = X::Id, Document = X::Document, Generation = X::Generation>,
    {
        self.require(writer, work)?;
        let layout = self.prepared.bound().containers();
        work.charge_work(1).map_err(Error::Resource)?;
        if required.snapshot() != layout.snapshot()
            || !structured_ltv::source::equal_id(required.signature(), layout.signature(), work)
                .map_err(Error::Resource)?
        {
            return Err(Error::Foreign);
        }
        let materials = Materials::missing(required, work, envelope)?;
        materials.write(writer, work)?;
        self.require(writer, work)
    }

    fn gate<A, W: Work>(
        &self,
        assessment: &Assessment<'_, A, X::Id, X::Document, X::Generation>,
        kind: TimestampKind,
        work: &W,
    ) -> Result<(), Error<core::convert::Infallible>> {
        work.charge_work(1).map_err(Error::Resource)?;
        if self.xml.snapshot() != self.prepared.bound().containers().snapshot()
            || !core::ptr::eq(assessment.evidence().prepared(), self.prepared)
        {
            return Err(Error::Foreign);
        }
        if !assessment.all_requirements_met() {
            return Err(Error::Prerequisites);
        }
        if kind == TimestampKind::Archive
            && !matches!(
                assessment.requested(),
                Requirements::LongTerm | Requirements::Archival
            )
        {
            return Err(Error::Prerequisites);
        }
        Ok(())
    }

    fn require<B, W: Work>(&self, writer: &B, work: &W) -> Result<(), Error<B::Error>>
    where
        B: Transaction<Id = X::Id, Document = X::Document, Generation = X::Generation>,
    {
        let layout = self.prepared.bound().containers();
        work.charge_work(2).map_err(Error::Resource)?;
        if self.xml.snapshot() != layout.snapshot()
            || writer.base() != layout.snapshot()
            || !structured_ltv::source::equal_id(writer.signature(), layout.signature(), work)
                .map_err(Error::Resource)?
            || !super::same_parent(
                writer.unsigned_parent(),
                self.prepared.unsigned().parent(),
                work,
            )
            .map_err(Error::Resource)?
        {
            return Err(Error::Foreign);
        }
        Ok(())
    }
}

fn append_kind(kind: TimestampKind) -> AppendKind {
    match kind {
        TimestampKind::Signature => AppendKind::Signature,
        TimestampKind::Archive => AppendKind::Archive,
    }
}

/// Complete common response facts, with the exact proposed source and input.
/// Negative facts and positive evidence remain in one owner, without copying
/// retained proof storage or allocating a variant box.
pub struct Checked<'a, D, G, N> {
    snapshot: Snapshot<D, G>,
    signature: N,
    method: N,
    kind: TimestampKind,
    response: &'a structured_cms::timestamp::Response<'a>,
    facts: structured_cms::timestamp::response::CheckedResponse<'a>,
}
impl<D: Copy, G: Copy, N: Copy> Checked<'_, D, G, N> {
    /// Complete original check results, including negative/request/time facts.
    #[must_use]
    pub fn facts(&self) -> &structured_cms::timestamp::response::CheckedResponse<'_> {
        &self.facts
    }
    /// Borrow the actual same-response token only when the common checker
    /// issued evidence for this exact proposed input. No new query or crypto.
    #[must_use]
    pub fn timestamp(&self) -> Option<Timestamp<'_, D, G, N>> {
        let evidence = self.facts.timestamp()?.evidence()?;
        let token = self.response.token_element()?;
        let producer = self
            .response
            .token()?
            .signer()
            .digest_algorithm()
            .identifier()?
            .execution_origin();
        Some(Timestamp {
            snapshot: self.snapshot,
            signature: self.signature,
            method: self.method,
            kind: self.kind,
            token,
            producer,
            evidence,
        })
    }
}
/// Source/stage failures during future-input preparation.
#[derive(Debug)]
pub enum PreparationError<E, N> {
    /// Actual shared stage or original/current resource admission.
    Admission(Error<core::convert::Infallible>),
    /// Original XML input selection/refusal.
    Input(timestamp::InputError<E, N>),
}
/// Input/source errors and original RFC3161/profile causes remain distinct.
#[derive(Debug)]
pub enum ResponseError<E, N, PE, RE> {
    /// Original stage/source/work admission before provider or input replay.
    Admission(Error<core::convert::Infallible>),
    /// Actual original XML input selection or replay refusal.
    Input(timestamp::InputError<E, N>),
    /// Existing common timestamp check, including request mismatch/resource cause.
    Check(ProfileCheckError<timestamp::InputError<E, N>, PE, RE, timestamp::DigestError>),
}
