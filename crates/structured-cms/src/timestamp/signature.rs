//! Timestamp signature orchestration reuses the complete CMS execution kernel.

use super::Token;
use crate::{Error, ErrorCode, binding::Scope, prepare, provider::SignatureProvider, verify};
use structured_asn1::{Reader, memory::Work};
use structured_pkix::path::WorkingKey;

/// Arithmetic/content facts, without ESS, certificate trust or timestamp proof.
pub enum TokenSignature<'a> {
    /// Complete CMS pass, preserving the original signer and effective key.
    Checked(verify::Checked<'a>),
    /// No signature state or payload pass was started for this mechanism.
    Unsupported(prepare::Part),
    /// Schema/algorithm preflight refused before signature input execution.
    Malformed(Error),
}

/// Execution failures remain separate from arithmetic and conformance answers.
#[derive(Debug)]
pub enum SignatureError<E> {
    /// Original common processing/resource failure.
    Processing(Error),
    /// Schema/provider preparation failed with its original cause.
    Preparation(prepare::PrepareError<E>),
    /// State/challenge admission failed with its original cause.
    Admission(verify::CheckError<E>),
    /// The complete original attached-content pass failed.
    Pass(verify::PassError<crate::octets::SourceError, E>),
}

impl<'a> Token<'a> {
    /// Executes the one TSA signer over its original attached `TSTInfo` octets.
    ///
    /// This shares CMS preparation and raw/prehash execution, including exact
    /// retagged signedAttrs and its separate message-digest agreement. It never
    /// hashes a normalized/re-encoded `TSTInfo` in place of the signed payload.
    /// The key may borrow a shorter-lived caller descriptor and retain inherited
    /// parameters. SID/ESS binding, TSA purpose, request/time and trust remain
    /// independent checks; Valid alone never creates authenticated evidence.
    pub fn check_signature<'check, P: SignatureProvider<'check>>(
        &'check self,
        provider: &'check P,
        key: WorkingKey<'check>,
        parent: &Reader<'check>,
    ) -> Result<TokenSignature<'check>, SignatureError<P::Error>>
    where
        'a: 'check,
    {
        let request = match prepare::resolve(
            provider,
            self.signer(),
            key,
            parent,
            Scope::Content(self.message().content().kind()),
        )
        .map_err(SignatureError::Preparation)?
        {
            prepare::Preparation::Unsupported(part) => {
                return Ok(TokenSignature::Unsupported(part));
            }
            prepare::Preparation::Malformed(error) => return Ok(TokenSignature::Malformed(error)),
            prepare::Preparation::Ready(request) => request,
        };
        let field = "signedData.encapContentInfo.eContent";
        let at = self.message().content().span().start;
        let mut source = self.message().content().content().ok_or_else(|| {
            SignatureError::Processing(Error::schema(ErrorCode::MissingField, field, at))
        })?;
        let work = parent.execution();
        let mut requests = work.vector();
        requests
            .try_push(request)
            .map_err(|reason| SignatureError::Processing(Error::resource(reason, field, at)))?;
        let batch = verify::Batch::prepare(provider, requests.into_owned(), &work, field, at)
            .map_err(SignatureError::Admission)?;
        let mut results = batch
            .run(&mut source, &work)
            .map_err(SignatureError::Pass)?;
        let checked = results.pop().ok_or_else(|| {
            SignatureError::Processing(Error::schema(
                ErrorCode::MissingField,
                "signedData.signerInfos",
                self.message().span().start,
            ))
        })?;
        Ok(TokenSignature::Checked(checked))
    }
}
