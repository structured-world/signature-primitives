//! Explicit issuer scope, separate from request/time/revocation acceptance.

use super::{DelegateFacts, Digest, Lookup, ResponderRevocation, SignedResponse};
use crate::Certificate;
use crate::error::{CallbackResult, Error, Result};
use crate::path::WorkingKey;
use structured_asn1::memory::{MemoryError, Work};

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
    /// Present keyUsage allows neither applicable object-signing use.
    KeyUsage,
}

/// Signature and issuer-scope facts. Caller trust provenance, intended recipient,
/// pending delegate revocation, nonce, time and critical demands remain explicit.
#[derive(Debug, Clone, Copy)]
pub struct ScopedResponse<'r, 'a> {
    signed: SignedResponse<'r, 'a>,
    issuer: &'r Certificate<'a>,
    // Keep the actual input SPKI provenance as well as inherited parameters.
    // Rebuilding from an equal issuer certificate could change parser/source
    // identity and its lazy-reading ceilings, even if its DER bytes agree.
    issuing_key: Option<WorkingKey<'a>>,
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
    /// Actual effective issuer key used by issuer-signature or delegation
    /// authentication. Explicit configured-responder trust does not run that
    /// operation and honestly returns None, never a fabricated standing key.
    #[must_use]
    pub fn issuing_key(self) -> Option<WorkingKey<'a>> {
        self.issuing_key
    }
    /// Explicit scope source, including unresolved delegated revocation.
    #[must_use]
    pub fn source(self) -> AuthoritySource {
        self.source
    }
    /// Select a target assertion using the same issuer as the signer binding.
    pub fn find<D: Digest<E>, E: Work>(
        self,
        target: &Certificate<'_>,
        digest: &D,
        execution: &E,
    ) -> CallbackResult<Lookup<'r, 'a>, D::Error> {
        self.signed.find(target, self.issuer, digest, execution)
    }
}

/// Completed issuer-scope binding outcome.
#[derive(Debug, Clone, Copy)]
#[expect(
    clippy::large_enum_variant,
    reason = "return the original response and actual issuing key in-place without a new allocation during authentication"
)]
pub enum AuthorityBinding<'r, 'a> {
    /// Scope established; this is not the final status-acceptance decision.
    Bound(ScopedResponse<'r, 'a>),
    /// Completed mismatch.
    Rejected(AuthorityFailure),
}

fn equal_bytes<E: Work>(left: &[u8], right: &[u8], execution: &E, at: u64) -> Result<bool> {
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

fn equal_key<E: Work>(
    left: WorkingKey<'_>,
    right: WorkingKey<'_>,
    execution: &E,
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

pub(super) fn signing_usage<'a, E: Work + 'a>(
    certificate: &Certificate<'a>,
    execution: &E,
) -> Result<bool> {
    // RFC5280 §§4.2.1.3/4.2.1.12: OCSP is neither a certificate nor a CRL
    // signature; digitalSignature and/or contentCommitment are applicable.
    // <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12>
    Ok(certificate
        .tbs()
        .extensions()
        .key_usage(execution)?
        .is_none_or(|usage| usage.digital_signature() || usage.content_commitment()))
}

impl<'r, 'a> SignedResponse<'r, 'a> {
    /// Bind issuer-signed response to the actual authenticated target issuing
    /// key, including inherited parameters. Caller supplies issuer trust and
    /// current validity from its target path; a matching DN alone is inadequate.
    /// RFC6960 §4.2.2.2: <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2>
    pub fn bind_issuer<E: Work + 'a>(
        self,
        issuer: &'r Certificate<'a>,
        issuing_key: WorkingKey<'a>,
        execution: &E,
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
        if !signing_usage(issuer, execution)? {
            return Ok(AuthorityBinding::Rejected(AuthorityFailure::KeyUsage));
        }
        Ok(AuthorityBinding::Bound(ScopedResponse {
            signed: self,
            issuer,
            issuing_key: Some(issuing_key),
            source: AuthoritySource::Issuer,
        }))
    }

    /// Attach completed direct local delegation to this exact actual signer.
    /// An unresolved revocation fact remains unresolved in the returned source.
    pub fn bind_delegate<E: Work>(
        self,
        facts: DelegateFacts<'a>,
        execution: &E,
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
            issuing_key: Some(facts.issuing_key()),
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
            issuing_key: None,
            source: AuthoritySource::Configured,
        }
    }
}
