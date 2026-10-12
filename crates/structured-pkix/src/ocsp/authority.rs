//! Explicit issuer scope, separate from request/time/revocation acceptance.

use super::{DelegateFacts, Digest, Lookup, ResponderRevocation, SignedResponse};
use crate::Certificate;
use crate::error::{CallbackResult, Error, Result};
use crate::path::WorkingKey;
use structured_asn1::memory::{Memory, MemoryError};

/// How the caller-bound signer is related to the selected target issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthoritySource {
    /// The actual target issuing key itself signed the response.
    Issuer,
    /// Common local path and explicit purpose established direct delegation.
    Delegate {
        /// The delegate's revocation exemption or unresolved checking fact.
        revocation: ResponderRevocation,
    },
    /// Caller explicitly selected a locally configured trusted responder for
    /// this issuer. This branch is never selected from response content.
    Configured,
}

/// Completed source/key-scope rejection, distinct from resource errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityFailure {
    /// Effective issuing key is not bound to the supplied issuer certificate.
    IssuerKeyBinding,
    /// Signed response's actual signer does not match the selected authority.
    Signer,
    /// Signature was checked with a different effective parameter state.
    EffectiveKey,
}

/// Signature and issuer-scope facts. Caller trust provenance, intended recipient,
/// pending delegate revocation, nonce, time and critical demands remain explicit.
#[derive(Debug, Clone, Copy)]
pub struct ScopedResponse<'r, 'a> {
    signed: SignedResponse<'r, 'a>,
    issuer: &'r Certificate<'a>,
    source: AuthoritySource,
}

impl<'r, 'a> ScopedResponse<'r, 'a> {
    /// Original authenticated response/signing source.
    #[must_use]
    pub fn signed(self) -> SignedResponse<'r, 'a> {
        self.signed
    }
    /// Selected target issuer, never inferred from included certificates.
    #[must_use]
    pub fn issuer(self) -> &'r Certificate<'a> {
        self.issuer
    }
    /// Explicit scope source, including unresolved delegated revocation.
    #[must_use]
    pub fn source(self) -> AuthoritySource {
        self.source
    }
    /// Select a target assertion using the same issuer as the signer binding.
    pub fn find<D: Digest>(
        self,
        target: &Certificate<'_>,
        digest: &D,
        execution: &Memory,
    ) -> CallbackResult<Lookup<'r, 'a>, D::Error> {
        self.signed.find(target, self.issuer, digest, execution)
    }
}

/// Completed issuer-scope binding outcome.
#[derive(Debug, Clone, Copy)]
pub enum AuthorityBinding<'r, 'a> {
    /// Scope established; this is not the final status-acceptance decision.
    Bound(ScopedResponse<'r, 'a>),
    /// Completed mismatch.
    Rejected(AuthorityFailure),
}

fn equal_bytes(left: &[u8], right: &[u8], execution: &Memory, at: u64) -> Result<bool> {
    let work = u64::try_from(left.len().max(right.len()))
        .ok()
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| Error::resource(MemoryError::WorkExceeded, "ocspResponse.authority", at))?;
    execution
        .charge_work(work)
        .map_err(|reason| Error::resource(reason, "ocspResponse.authority", at))?;
    Ok(left == right)
}

fn equal_key(
    left: WorkingKey<'_>,
    right: WorkingKey<'_>,
    execution: &Memory,
    at: u64,
) -> Result<bool> {
    if !equal_bytes(left.key().as_bytes(), right.key().as_bytes(), execution, at)? {
        return Ok(false);
    }
    match (left.parameters(), right.parameters()) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => equal_bytes(left, right, execution, at),
        _ => Ok(false),
    }
}

impl<'r, 'a> SignedResponse<'r, 'a> {
    /// Bind issuer-signed response to the actual authenticated target issuing
    /// key, including inherited parameters. Caller supplies issuer trust and
    /// current validity from its target path; a matching DN alone is inadequate.
    /// RFC6960 §4.2.2.2: <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2>
    pub fn bind_issuer(
        self,
        issuer: &'r Certificate<'a>,
        issuing_key: WorkingKey<'a>,
        execution: &Memory,
    ) -> Result<AuthorityBinding<'r, 'a>> {
        let at = self.response().span().start;
        if !equal_bytes(
            issuer.tbs().public_key().as_bytes(),
            issuing_key.key().as_bytes(),
            execution,
            at,
        )? {
            return Ok(AuthorityBinding::Rejected(
                AuthorityFailure::IssuerKeyBinding,
            ));
        }
        if !equal_bytes(
            self.signer().tbs().public_key().as_bytes(),
            issuer.tbs().public_key().as_bytes(),
            execution,
            at,
        )? || !self
            .signer()
            .tbs()
            .subject()
            .matches(issuer.tbs().subject(), execution)?
        {
            return Ok(AuthorityBinding::Rejected(AuthorityFailure::Signer));
        }
        if !equal_key(self.key(), issuing_key, execution, at)? {
            return Ok(AuthorityBinding::Rejected(AuthorityFailure::EffectiveKey));
        }
        Ok(AuthorityBinding::Bound(ScopedResponse {
            signed: self,
            issuer,
            source: AuthoritySource::Issuer,
        }))
    }

    /// Attach completed direct local delegation to this exact actual signer.
    /// An unresolved revocation fact remains unresolved in the returned source.
    pub fn bind_delegate(
        self,
        facts: DelegateFacts<'a>,
        execution: &Memory,
    ) -> Result<AuthorityBinding<'r, 'a>>
    where
        'a: 'r,
    {
        let at = self.response().span().start;
        if !equal_bytes(
            self.signer().as_bytes(),
            facts.responder().as_bytes(),
            execution,
            at,
        )? {
            return Ok(AuthorityBinding::Rejected(AuthorityFailure::Signer));
        }
        if !equal_key(self.key(), facts.key(), execution, at)? {
            return Ok(AuthorityBinding::Rejected(AuthorityFailure::EffectiveKey));
        }
        Ok(AuthorityBinding::Bound(ScopedResponse {
            signed: self,
            issuer: facts.issuer(),
            source: AuthoritySource::Delegate {
                revocation: facts.revocation(),
            },
        }))
    }

    /// Explicit caller assertion of locally configured responder trust for this
    /// target issuer, the separate RFC6960 §4.2.2.2 branch. Never call this merely
    /// because a certificate was included or carried an OCSP EKU. No traversal,
    /// allocation, trust discovery or policy selection occurs in this operation.
    #[must_use]
    pub fn trust_for_issuer(self, issuer: &'r Certificate<'a>) -> ScopedResponse<'r, 'a> {
        ScopedResponse {
            signed: self,
            issuer,
            source: AuthoritySource::Configured,
        }
    }
}
