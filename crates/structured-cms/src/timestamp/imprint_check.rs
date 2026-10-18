//! Complete one-pass imprint agreement under the explicitly selected provider.

use super::{HashAlgorithmReading, MessageImprint};
use crate::Error;
use crate::digest::{DigestBatch, DigestError, PassError};
use crate::provider::DigestAlgorithm;
use crate::stream::Source;
use structured_asn1::Reader;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::Work;
use structured_pkix::algorithm::digest::AsnDigest;

/// Imprint agreement alone does not establish token signature or authority trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImprintAgreement {
    /// The complete caller-supplied content agrees with the declared digest.
    Matches,
    /// A complete digest of that content disagrees with the declaration.
    Differs,
    /// Inspection retained a malformed imprint encoding or schema fault.
    MalformedImprint,
    /// The written algorithm violates the selected algorithm's parameter syntax.
    MalformedAlgorithm,
    /// A resolved fixed-output algorithm cannot produce the written hash width.
    MalformedHash,
    /// The selected provider cannot compute the explicit written algorithm.
    Unsupported,
}

/// Failed execution stays distinct from semantic mismatch and unsupported input.
#[derive(Debug)]
pub enum ImprintError<SE, PE> {
    /// Original common processing/resource failure.
    Processing(Error),
    /// Digest admission/finalization or provider output-contract failure.
    Digest(DigestError<PE>),
    /// Final output comparison or provider output-contract failure.
    Comparison(crate::binding::BindError<PE>),
    /// A source/common/provider failure prevents a complete content pass.
    Pass(PassError<SE, PE>),
    /// A prepared request was not present after successful common finalization.
    LostRequest,
}

pub(super) enum Resolved<I> {
    Ready(I),
    Unusable(ImprintAgreement),
}

impl<'a> MessageImprint<'a> {
    /// Computes the declared imprint over exactly one complete source pass.
    ///
    /// RFC3161 §2.4.1 identifies the hash by its complete written algorithm, not
    /// by output length. Resolution, malformed syntax and known impossible width
    /// precede state creation and source I/O. Finalized output is matched under
    /// the same selected provider, without replay, re-resolution or rehashing.
    /// Source/provider/resource failures cannot become `Differs`. Success is an
    /// imprint fact only; signature, ESS, path, request and time acceptance remain
    /// separate checks. <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1>
    pub fn check_content<P: AsnDigest<'a>, S: Source>(
        &self,
        provider: &'a P,
        parent: &Reader<'a>,
        source: &mut S,
    ) -> Result<ImprintAgreement, ImprintError<S::Error, P::Error>> {
        let resolved = self
            .resolve(provider, parent)
            .map_err(ImprintError::Processing)?;
        match resolved {
            Resolved::Ready(identity) => self.compute(provider, parent, source, identity),
            Resolved::Unusable(answer) => Ok(answer),
        }
    }

    pub(super) fn require_session(&self, parent: &Reader<'_>) -> crate::Result<()> {
        if !core::ptr::eq(self.hashed().parser(), parent.parser()) {
            return Err(Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                self.fields().enclosing,
                self.span().start,
            )));
        }
        Ok(())
    }

    pub(super) fn resolve<P: AsnDigest<'a>>(
        &self,
        provider: &'a P,
        parent: &Reader<'a>,
    ) -> crate::Result<Resolved<P::Identity>> {
        crate::provider::require_instance(provider, self.fields().enclosing, self.span().start)?;
        self.require_session(parent)?;
        if !self.faults().is_empty() {
            return Ok(Resolved::Unusable(ImprintAgreement::MalformedImprint));
        }
        let HashAlgorithmReading::Identifier(identifier) = self.algorithm() else {
            return Ok(Resolved::Unusable(ImprintAgreement::MalformedImprint));
        };
        let identity = match crate::provider::resolve_digest(
            provider,
            DigestAlgorithm::Written(*identifier),
            parent,
        )? {
            Resolution::Supported(identity) => identity,
            Resolution::Malformed => {
                return Ok(Resolved::Unusable(ImprintAgreement::MalformedAlgorithm));
            }
            Resolution::Unsupported => {
                return Ok(Resolved::Unusable(ImprintAgreement::Unsupported));
            }
        };
        if let Some(width) = provider.width(&identity)
            && self.hashed().len() != width
        {
            return Ok(Resolved::Unusable(ImprintAgreement::MalformedHash));
        }
        Ok(Resolved::Ready(identity))
    }

    pub(super) fn compute<P: AsnDigest<'a>, S: Source>(
        &self,
        provider: &'a P,
        parent: &Reader<'a>,
        source: &mut S,
        identity: P::Identity,
    ) -> Result<ImprintAgreement, ImprintError<S::Error, P::Error>> {
        let field = self.fields().hashed;
        let at = self.hashed().span().start;
        let joined;
        // Admit any expected-hash materialization before state or source effects.
        let expected = if let Some(bytes) = self.hashed().as_one() {
            bytes
        } else {
            joined = self
                .hashed()
                .copy_in(parent, field, at)
                .map_err(ImprintError::Processing)?;
            &*joined
        };
        let execution = parent.execution();
        let mut identities = execution.vector();
        identities
            .try_push(identity)
            .map_err(|reason| ImprintError::Processing(Error::resource(reason, field, at)))?;
        let batch = DigestBatch::prepare(provider, identities.into_owned(), &execution, field, at)
            .map_err(ImprintError::Digest)?;
        let memo = batch.run(source, &execution).map_err(ImprintError::Pass)?;
        let output = memo
            .for_request(0, &execution)
            .map_err(ImprintError::Digest)?
            .ok_or(ImprintError::LostRequest)?;
        let matches = crate::binding::matches_digest(
            provider,
            output.finished(),
            expected,
            &execution,
            field,
            self.hashed().span(),
        )
        .map_err(ImprintError::Comparison)?;
        Ok(match matches {
            crate::binding::DigestBinding::Matches => ImprintAgreement::Matches,
            crate::binding::DigestBinding::Differs => ImprintAgreement::Differs,
            crate::binding::DigestBinding::Malformed(_) => ImprintAgreement::MalformedHash,
        })
    }
}
