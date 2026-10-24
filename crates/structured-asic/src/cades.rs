//! `CAdES` execution over the actual original `ASiC` payload, without replay.

use crate::{
    content::Content,
    error::Error as ArchiveError,
    payload::Payload,
    zip::{Member, MemberId, ReadFailure},
};
use structured_asn1::{
    Reader,
    memory::{OwnedVec, Work},
    range::RangeSource,
};
use structured_cms::{
    SignedData,
    prepare::ResolvedSigner,
    provider::SignatureProvider,
    verify::{CheckError, Checked, ContentMode, DocumentBatch, DocumentChecks, PassError},
};
use structured_pkix::{Certificate, algorithm::digest::AsnDigest};

/// Original resolved requests, without inventing an independent dispatcher.
pub struct Challenge<'a, P: SignatureProvider<'a>> {
    /// Original carried `SignedData` model belonging to the selected Content.
    pub message: &'a SignedData<'a>,
    /// Actual producing/current source reader.
    pub parent: &'a Reader<'a>,
    /// The one selected signature/digest provider.
    pub provider: &'a P,
    /// Existing common resolver's requests, moved without state cloning.
    pub requests: OwnedVec<ResolvedSigner<'a, P>>,
}

/// Format framing and common/provider failures retain their independent cause.
#[derive(Debug)]
pub enum Error<SE, PE, D, G> {
    /// One original root `SignerInfo` has no prepared request. Complete-container
    /// execution cannot silently replace it with the selected successful roots.
    MissingSigner(structured_asn1::Span),
    /// Original archive, generation or current/source-budget refusal.
    Archive(ArchiveError<SE>),
    /// Original payload framing/decode/CRC failure before or during acquisition.
    Source(ReadFailure<SE, D, G>),
    /// Common batch initialization, preserving callback/resource classification.
    Prepare(CheckError<PE>),
    /// Failed complete payload pass. No partial check receipt is returned.
    Pass(PassError<ReadFailure<SE, D, G>, PE>),
}

/// Mathematical checks privately bound to the actual input member chosen by
/// this driver. A separately checked arbitrary source cannot create this type.
pub struct Checks<'a, 'v, 's, S: RangeSource> {
    content: &'a Content<'v, 's, S>,
    payload: MemberId<S::Document, S::Generation>,
    inner: DocumentChecks<'a>,
}

impl<'v, 's, S: RangeSource> Content<'v, 's, S> {
    /// Validates both member/session identities and payload framing BEFORE
    /// initializing provider states, then drives the existing CMS batch with
    /// the sealed original member stream. Negative signer answers are retained.
    pub async fn check_cades<'a, P: SignatureProvider<'a>>(
        &'a self,
        challenge: Challenge<'a, P>,
        payload: &impl Payload<'v, 's, S>,
    ) -> Result<Checks<'a, 'v, 's, S>, Error<S::Error, P::Error, S::Document, S::Generation>> {
        let execution = challenge.parent.execution();
        self.require(challenge.message, challenge.parent, &execution)
            .map_err(Error::Archive)?;
        // Validate the FULL original root census before starting any provider
        // state or payload pass. Multiple actual key challenges for one root
        // remain possible; they cannot fill a missing different root.
        let refusal = |cause| Error::Archive(crate::error::resource(self.enclosure(), cause));
        let mut selected = execution.map();
        for request in &challenge.requests {
            challenge
                .message
                .require_signer(request.signer(), "asic.signerInfos")
                .map_err(|cause| Error::Prepare(CheckError::Processing(cause)))?;
            selected
                .try_insert(request.signer().element().index(), ())
                .map_err(refusal)?;
        }
        for signer in challenge.message.signers() {
            if selected
                .get(&signer.element().index(), &execution)
                .map_err(refusal)?
                .is_none()
            {
                return Err(Error::MissingSigner(signer.span()));
            }
        }
        drop(selected);
        if !core::ptr::eq(self.member().archive(), payload.member().archive()) {
            return Err(Error::Archive(ArchiveError::Foreign {
                range: self.enclosure(),
            }));
        }
        let mut source = payload.source(&execution).map_err(Error::Source)?;
        let batch = DocumentBatch::prepare(
            challenge.provider,
            challenge.message,
            challenge.requests,
            ContentMode::Detached,
            challenge.parent,
        )
        .map_err(Error::Prepare)?;
        let checks = batch
            .run_detached_async(&mut source)
            .await
            .map_err(Error::Pass)?;
        self.member()
            .archive()
            .admit(&execution, self.enclosure())
            .map_err(Error::Archive)?;
        Ok(Checks {
            content: self,
            payload: payload.member().id(),
            inner: checks,
        })
    }
}

/// Existing `CAdES` binding refusal, without treating processing as mismatch.
#[derive(Debug)]
pub enum BindError<SE, PE> {
    /// Original archive generation/current-source admission.
    Archive(ArchiveError<SE>),
    /// Exact common SID/ESS/path/source binding refusal.
    Cades(structured_cades::basic::BindError<PE>),
}

/// The actual existing `CAdES` binding, privately linked to the `ASiC` input pass.
/// Exposing the inner immutable receipt does not permit replacing that receipt.
pub struct Signer<'r, 'm, 'd, 'p, 'v, 's, S: RangeSource> {
    member: Member<'v, 's, S>,
    payload: MemberId<S::Document, S::Generation>,
    inner: structured_cades::basic::SignerBinding<'r, 'm, 'd, 'p>,
}

impl<'a, 'v, 's, S: RangeSource> Checks<'a, 'v, 's, S> {
    /// Every actually executed prepared signer answer, without copying.
    #[must_use]
    pub fn checks(&self) -> &DocumentChecks<'a> {
        &self.inner
    }
    /// Exact original payload or manifest consumed by this batch.
    #[must_use]
    pub fn payload(&self) -> MemberId<S::Document, S::Generation> {
        self.payload
    }
    /// Runs the ONE existing `CAdES` SID/key/ESS/path binder on a check that this
    /// original member pass actually produced. No supplied successful boolean
    /// or separately checked arbitrary payload can create the linked signer.
    pub fn bind<'provider, 'r, 'm, 'd, 'p, P: AsnDigest<'provider>>(
        &self,
        prepared: &'r structured_cades::prepare::Preparation<'m, 'd>,
        checked: &Checked<'_>,
        certificate: &'p Certificate<'d>,
        path: Option<&'p structured_ltv::pki::CheckedPath<'d>>,
        provider: &'provider P,
        parent: &Reader<'provider>,
    ) -> Result<Signer<'r, 'm, 'd, 'p, 'v, 's, S>, BindError<S::Error, P::Error>>
    where
        'd: 'provider,
    {
        let execution = parent.execution();
        self.content
            .require(self.inner.message(), parent, &execution)
            .map_err(BindError::Archive)?;
        let inner = structured_cades::basic::bind(
            prepared,
            &self.inner,
            checked,
            certificate,
            path,
            provider,
            parent,
        )
        .map_err(BindError::Cades)?;
        let member = self
            .content
            .member()
            .archive()
            .original(self.content.member().id(), &execution)
            .map_err(BindError::Archive)?;
        Ok(Signer {
            member,
            payload: self.payload,
            inner,
        })
    }
}

/// One linked `CAdES` requested-level answer. Container census, manifest object
/// digests, other signatures and preservation continuity remain independent.
pub struct Assessment<'a, 'm, 'd, E, D, G> {
    signature: MemberId<D, G>,
    payload: MemberId<D, G>,
    inner: structured_cades::baseline::Assessment<'a, 'm, 'd, E>,
}

/// Wrong receipt and actual processing refusal remain separate from a negative level.
#[derive(Debug)]
pub enum LevelError<E> {
    /// Original archive generation, source or current query refused.
    Archive(ArchiveError<E>),
    /// Evidence was built from a different actual original `CAdES` binding.
    Foreign,
    /// Existing complete `CAdES` stage composition refused.
    Cades(structured_cades::baseline::LevelError),
}

/// Complete source-bound common level answer or its original processing refusal.
pub type LevelResult<'a, 'm, 'd, E, S> = Result<
    Assessment<'a, 'm, 'd, E, <S as RangeSource>::Document, <S as RangeSource>::Generation>,
    LevelError<<S as RangeSource>::Error>,
>;

impl<'r, 'm, 'd, 'p, S: RangeSource> Signer<'r, 'm, 'd, 'p, '_, '_, S> {
    /// Build ordinary shared Basic/Timed/LongTerm/Archives from this exact
    /// immutable signer. No duplicate `CAdES` stage or crypto implementation exists.
    #[must_use]
    pub fn inner(&self) -> &structured_cades::basic::SignerBinding<'r, 'm, 'd, 'p> {
        &self.inner
    }
    /// Composes the existing complete `CAdES` stages after requiring their ACTUAL
    /// root binding, not merely an equal original signer or a requested level.
    pub fn assess<'e, E>(
        &'e self,
        evidence: structured_cades::baseline::Evidence<'e, 'm, 'd, E>,
        operation: &Reader<'_>,
    ) -> LevelResult<'e, 'm, 'd, E, S> {
        self.member
            .archive()
            .admit(&operation.execution(), self.member.central_span())
            .map_err(LevelError::Archive)?;
        let binding = match &evidence {
            structured_cades::baseline::Evidence::Basic(basic) => basic.binding(),
            structured_cades::baseline::Evidence::Timestamped(timed) => timed.basic().binding(),
            structured_cades::baseline::Evidence::LongTerm(long)
            | structured_cades::baseline::Evidence::Archival {
                long_term: long, ..
            } => long.timed().basic().binding(),
        };
        if !core::ptr::eq(
            core::ptr::from_ref(binding).cast::<()>(),
            core::ptr::from_ref(&self.inner).cast::<()>(),
        ) {
            return Err(LevelError::Foreign);
        }
        let inner =
            structured_cades::baseline::assess(evidence, operation).map_err(LevelError::Cades)?;
        Ok(Assessment {
            signature: self.member.id(),
            payload: self.payload,
            inner,
        })
    }
}

impl<'a, 'm, 'd, E, D: Copy, G: Copy> Assessment<'a, 'm, 'd, E, D, G> {
    /// Original signature member whose actual check supplied this evidence.
    #[must_use]
    pub fn signature(&self) -> MemberId<D, G> {
        self.signature
    }
    /// Actual complete original input member, not a URI/name assertion.
    #[must_use]
    pub fn payload(&self) -> MemberId<D, G> {
        self.payload
    }
    /// All original common `CAdES` stage answers, independent of container facts.
    #[must_use]
    pub fn cades(&self) -> &structured_cades::baseline::Assessment<'a, 'm, 'd, E> {
        &self.inner
    }
}
