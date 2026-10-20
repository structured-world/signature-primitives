//! A CMS batch whose input is bound to one original `SignedData` container.

use super::{Batch, CheckError, Checked, PassError};
use crate::prepare::ResolvedSigner;
use crate::provider::SignatureProvider;
use crate::stream::Source;
use crate::{Error, ErrorCode, SignedData};
use structured_asn1::Reader;
use structured_asn1::memory::{Execution, OwnedVec, Work};

/// Explicit original content selection before provider initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentMode {
    /// Original eContent octets carried by this `SignedData`.
    Carried,
    /// An explicit caller source for a `SignedData` WITHOUT eContent.
    Detached,
}

/// Existing verification driver plus the exact original source association.
/// The selected root signers share one payload pass and one digest memo.
pub struct DocumentBatch<'operation, 'a, P: SignatureProvider<'a>> {
    message: &'a SignedData<'a>,
    batch: Batch<'a, P>,
    mode: ContentMode,
    execution: Execution<'operation>,
}

impl<'operation, 'a, P: SignatureProvider<'a>> DocumentBatch<'operation, 'a, P> {
    /// Checks container/signer provenance and explicit input mode BEFORE any
    /// provider initialization, then delegates to the one existing batch core.
    /// Detached source acquisition remains caller-owned; it is never a fallback
    /// for a carried document. No candidate selection or trust is performed.
    pub fn prepare(
        provider: &'a P,
        message: &'a SignedData<'a>,
        requests: OwnedVec<ResolvedSigner<'a, P>>,
        mode: ContentMode,
        parent: &'operation Reader<'a>,
    ) -> Result<Self, CheckError<P::Error>> {
        const FIELD: &str = "signedData.encapContentInfo";
        message
            .require_session(parent, FIELD)
            .map_err(CheckError::Processing)?;
        let execution = parent.execution();
        execution.charge_work(1).map_err(|cause| {
            CheckError::Processing(Error::resource(
                cause,
                FIELD,
                message.content().span().start,
            ))
        })?;
        if (mode == ContentMode::Detached) != message.content().is_detached() {
            return Err(CheckError::Processing(Error::schema(
                ErrorCode::InvalidLocation,
                FIELD,
                message.content().span().start,
            )));
        }
        for request in &requests {
            execution.charge_work(1).map_err(|cause| {
                CheckError::Processing(Error::resource(cause, FIELD, request.signer().span().start))
            })?;
            message
                .require_signer(request.signer(), "signedData.signerInfos")
                .map_err(CheckError::Processing)?;
        }
        let batch = Batch::prepare(provider, requests, &execution, FIELD, message.span().start)?;
        Ok(Self {
            message,
            batch,
            mode,
            execution,
        })
    }

    /// Consumes the ORIGINAL carried content through the same streaming batch.
    /// The caller cannot replace it with a different byte source. Empty carried
    /// content remains a real empty input, distinct from absence.
    pub fn run_carried(
        self,
    ) -> Result<DocumentChecks<'a>, PassError<crate::octets::SourceError, P::Error>> {
        let refusal = || {
            crate::stream::StreamError::Processing(Error::schema(
                ErrorCode::InvalidLocation,
                "signedData.encapContentInfo",
                self.message.content().span().start,
            ))
        };
        if self.mode != ContentMode::Carried {
            return Err(refusal());
        }
        let Some(mut content) = self.message.content().content() else {
            return Err(refusal());
        };
        let checks = self.batch.run(&mut content, &self.execution)?;
        Ok(DocumentChecks {
            message: self.message,
            checks,
        })
    }

    /// Consumes the explicit caller input of the original detached `SignedData`.
    /// This establishes that input's mathematical agreement with the signed
    /// message-digest, not an application claim about where bytes were acquired.
    pub fn run_detached<S: Source>(
        self,
        source: &mut S,
    ) -> Result<DocumentChecks<'a>, PassError<S::Error, P::Error>> {
        if self.mode != ContentMode::Detached || !self.message.content().is_detached() {
            return Err(crate::stream::StreamError::Processing(Error::schema(
                ErrorCode::InvalidLocation,
                "signedData.encapContentInfo",
                self.message.content().span().start,
            )));
        }
        let checks = self.batch.run(source, &self.execution)?;
        Ok(DocumentChecks {
            message: self.message,
            checks,
        })
    }
}

/// Original-container-bound mathematical facts for every selected root signer.
/// A successful partial source pass never creates this receipt. Per-signer
/// negative/unsupported results remain independent of application acceptance.
pub struct DocumentChecks<'a> {
    message: &'a SignedData<'a>,
    checks: OwnedVec<Checked<'a>>,
}

impl<'a> DocumentChecks<'a> {
    /// Same original document whose logical content this complete pass consumed.
    #[must_use]
    pub fn message(&self) -> &'a SignedData<'a> {
        self.message
    }
    /// Every prepared selected root result in request order, without copying.
    #[must_use]
    pub fn checks(&self) -> &[Checked<'a>] {
        &self.checks
    }

    /// Requires THIS actual batch result and original document in constant
    /// metadata work. Equal bytes, equivalent signer values or another check
    /// under the same account cannot supply its input-source association.
    pub fn require<W: Work>(
        &self,
        message: &SignedData<'_>,
        checked: &Checked<'_>,
        execution: &W,
    ) -> crate::Result<()> {
        let at = checked.signer().span().start;
        execution
            .charge_work(1)
            .map_err(|cause| Error::resource(cause, "signedData.signerInfos", at))?;
        let address = core::ptr::from_ref(checked).cast::<Checked<'a>>();
        if !core::ptr::eq(message, self.message) || !self.checks.as_ptr_range().contains(&address) {
            return Err(Error::schema(
                ErrorCode::InvalidLocation,
                "signedData.signerInfos",
                at,
            ));
        }
        Ok(())
    }
}
