//! Actual signer binding and response signature authentication.

use super::{BasicResponse, ResponderMatch};
use crate::algorithm::digest::AsnDigest;
use crate::error::CallbackError;
use crate::path::{Verified, Verify, WorkingKey};
use crate::{Certificate, Error};
use core::fmt;
use structured_asn1::memory::{MemoryError, Work};

/// Failure to execute authentication, retaining the originating capability.
#[derive(Debug)]
pub enum SignatureError<V, D> {
    /// Located shared processing/resource failure.
    Processing(Error),
    /// Signature provider failure, including its resource or policy error.
    Verification(V),
    /// Digest provider failure, including its resource or policy error.
    Digest(D),
}

impl<V, D> From<Error> for SignatureError<V, D> {
    fn from(error: Error) -> Self {
        Self::Processing(error)
    }
}

impl<V: fmt::Display, D: fmt::Display> fmt::Display for SignatureError<V, D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Processing(error) => error.fmt(formatter),
            Self::Verification(error) => write!(formatter, "signature verifier: {error}"),
            Self::Digest(error) => write!(formatter, "digest provider: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<V: std::error::Error + 'static, D: std::error::Error + 'static> std::error::Error
    for SignatureError<V, D>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Processing(error) => Some(error),
            Self::Verification(error) => Some(error),
            Self::Digest(error) => Some(error),
        }
    }
}

/// Completed negative binding/signature result, not an execution failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFailure {
    /// Effective key does not belong to the supplied signer's original SPKI.
    KeyBinding,
    /// `ResponderID` does not identify the actual supplied signer.
    ResponderIdentity,
    /// Provider resolved protocol-imposed SHA-1 with a contradicting width.
    DigestWidth,
    /// The completed signature verification rejected the signature.
    Signature,
}

/// Original response authenticated by its actual signer. This proves neither
/// signer authorization for a target issuer nor freshness or request binding.
#[derive(Debug, Clone, Copy)]
pub struct SignedResponse<'r, 'a> {
    response: &'r BasicResponse<'a>,
    signer: &'r Certificate<'a>,
    key: WorkingKey<'a>,
}

impl<'r, 'a> SignedResponse<'r, 'a> {
    /// Original signed response, retaining every assertion and extension.
    #[must_use]
    pub fn response(self) -> &'r BasicResponse<'a> {
        self.response
    }
    /// Actual certificate whose subject/key matched `ResponderID`.
    #[must_use]
    pub fn signer(self) -> &'r Certificate<'a> {
        self.signer
    }
    /// Effective key bound to that certificate's original SPKI.
    #[must_use]
    pub fn key(self) -> WorkingKey<'a> {
        self.key
    }
}

/// Signature authentication outcome with unsupported capabilities separate.
#[derive(Debug)]
pub enum SignatureAuthentication<'r, 'a> {
    /// Signer identity and signature established; authorization remains separate.
    Signed(SignedResponse<'r, 'a>),
    /// Completed semantic rejection.
    Rejected(SignatureFailure),
    /// Protocol-imposed SHA-1 cannot be supplied by this provider/policy.
    UnsupportedDigest,
    /// Signature algorithm/effective key is unsupported by this verifier.
    UnsupportedSignature,
}

impl<'a> BasicResponse<'a> {
    /// Authenticate exact `ResponseData` with the actual signer's bound key.
    /// Included certificates are candidates only. RFC6960 §§4.2.2.2–4.2.2.3
    /// require authorization and status validity beyond this signature fact.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.2>
    pub fn authenticate_signature<'r, 'd, V: Verify<E>, D: AsnDigest<'d> + ?Sized, E: Work>(
        &'r self,
        signer: &'r Certificate<'a>,
        key: WorkingKey<'a>,
        verifier: &V,
        digest: &'d D,
        execution: &E,
    ) -> core::result::Result<SignatureAuthentication<'r, 'a>, SignatureError<V::Error, D::Error>>
    {
        const FIELD: &str = "ocspResponse.signature";
        let charge = |work| {
            execution
                .charge_work(work)
                .map_err(|reason| Error::resource(reason, FIELD, self.span.start))
        };
        let encoded = key.key().as_bytes();
        let actual = signer.tbs().public_key().as_bytes();
        let work = u64::try_from(encoded.len().max(actual.len()))
            .ok()
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| Error::resource(MemoryError::WorkExceeded, FIELD, self.span.start))?;
        charge(work)?;
        if encoded != actual {
            return Ok(SignatureAuthentication::Rejected(
                SignatureFailure::KeyBinding,
            ));
        }
        let identity = self
            .responder
            .matches_certificate(signer, digest, execution, FIELD, self.span.start)
            .map_err(|cause| match cause {
                CallbackError::Processing(cause) => SignatureError::Processing(cause),
                CallbackError::Callback(cause) => SignatureError::Digest(cause),
            })?;
        match identity {
            ResponderMatch::Matches => {}
            ResponderMatch::Differs => {
                return Ok(SignatureAuthentication::Rejected(
                    SignatureFailure::ResponderIdentity,
                ));
            }
            ResponderMatch::MalformedHashWidth => {
                return Ok(SignatureAuthentication::Rejected(
                    SignatureFailure::DigestWidth,
                ));
            }
            ResponderMatch::UnsupportedHash => {
                return Ok(SignatureAuthentication::UnsupportedDigest);
            }
        }
        charge(1)?;
        match verifier
            .verify(&self.algorithm, key, self.signed, self.signature, execution)
            .map_err(SignatureError::Verification)?
        {
            Verified::Yes => Ok(SignatureAuthentication::Signed(SignedResponse {
                response: self,
                signer,
                key,
            })),
            Verified::No => Ok(SignatureAuthentication::Rejected(
                SignatureFailure::Signature,
            )),
            Verified::Unsupported => Ok(SignatureAuthentication::UnsupportedSignature),
        }
    }
}

#[cfg(test)]
mod tests;
