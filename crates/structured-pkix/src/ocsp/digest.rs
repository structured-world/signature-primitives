//! OCSP identity hashes through the shared digest contract.

use super::CertId;
use super::ResponderId;
use crate::Certificate;
use crate::algorithm::digest::{self, Algorithm, AsnDigest};
use crate::error::{CallbackError, CallbackResult, Error, ErrorCode};
use structured_asn1::digest::{OnceError, Resolution, matches_once};
use structured_asn1::memory::{MemoryError, Work};

// A provider output of the wrong width is located at the selector it hashed for.
fn once<E>(error: OnceError<E>, field: &'static str, at: u64) -> CallbackError<E> {
    match error {
        OnceError::Provider(error) => CallbackError::Callback(error),
        OnceError::OutputWidth { .. } => {
            CallbackError::Processing(Error::new(ErrorCode::DigestOutput, field, at))
        }
    }
}

/// Identity comparison is not responder authentication or a certificate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertMatch {
    /// Serial, issuer name and both original-byte hashes match.
    Matches,
    /// A completed semantic or digest comparison found different identity.
    Differs,
    /// The advertised fixed hash width contradicts a carried hash value.
    MalformedHashWidth,
    /// The encoded hash identifier writes parameters its algorithm does not take.
    MalformedHashAlgorithm,
    /// The consumer does not support the encoded hash algorithm.
    UnsupportedHash,
}

/// Responder identity alone, without signature, authority or status acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderMatch {
    /// Subject Name or imposed SHA-1 public-key hash identifies this certificate.
    Matches,
    /// Completed name or complete digest comparison differs.
    Differs,
    /// Written hash or provider-advertised SHA-1 width contradicts twenty octets.
    MalformedHashWidth,
    /// Protocol-imposed SHA-1 is unsupported by the selected provider/policy.
    UnsupportedHash,
}

impl ResponderId<'_> {
    /// Compare an original responder selector with the actual signer certificate.
    /// RFC6960 §4.2.1 hashes subjectPublicKey contents with SHA-1, excluding
    /// BIT STRING tag, length and unused-bits count. Name comparison reuses the
    /// shared PKIX Name kernel. No signature recheck or standing-key fabrication.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1>
    ///
    /// `field` and `at` identify the real enclosing selector in the caller's
    /// source; callbacks preserve their own original processing/resource cause.
    pub fn matches_certificate<'d, D: AsnDigest<'d> + ?Sized, E: Work>(
        &self,
        certificate: &Certificate<'_>,
        digest: &'d D,
        execution: &E,
        field: &'static str,
        at: u64,
    ) -> CallbackResult<ResponderMatch, D::Error> {
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, field, at))?;
        let same = match self {
            Self::Name(name) => name.matches(certificate.tbs().subject(), execution)?,
            Self::KeyHash(expected) => {
                if expected.len() != Algorithm::Sha1.width() {
                    return Ok(ResponderMatch::MalformedHashWidth);
                }
                let Resolution::Supported(identity) = digest::supported(digest, Algorithm::Sha1)
                else {
                    return Ok(ResponderMatch::UnsupportedHash);
                };
                if digest
                    .width(&identity)
                    .is_some_and(|width| width != Algorithm::Sha1.width())
                {
                    return Ok(ResponderMatch::MalformedHashWidth);
                }
                let input = certificate.tbs().public_key().key().as_bytes();
                match matches_once(digest, &identity, input, expected, execution)
                    .map_err(|error| once(error, field, at))?
                {
                    Resolution::Supported(same) => same,
                    Resolution::Unsupported | Resolution::Malformed => {
                        return Ok(ResponderMatch::UnsupportedHash);
                    }
                }
            }
        };
        Ok(if same {
            ResponderMatch::Matches
        } else {
            ResponderMatch::Differs
        })
    }
}

impl CertId<'_> {
    /// Match the actual target and candidate issuer without re-encoding names.
    /// RFC6960 §4.1.1 hashes original target issuer DER and issuer public-key
    /// contents. The caller retains their authenticated issuer/path provenance;
    /// matching hashes does not verify the target certificate's signature.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1>
    pub fn matches<'d, D: AsnDigest<'d> + ?Sized, E: Work>(
        &self,
        target: &Certificate<'_>,
        issuer: &Certificate<'_>,
        digest: &'d D,
        execution: &E,
    ) -> CallbackResult<CertMatch, D::Error> {
        const FIELD: &str = "ocspResponse.certID";
        let at = self.span.start;
        let left = self.serial.as_bytes();
        let right = target.tbs().serial().as_bytes();
        let work = u64::try_from(left.len().max(right.len()))
            .ok()
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| Error::resource(MemoryError::WorkExceeded, FIELD, at))?;
        execution
            .charge_work(work)
            .map_err(|reason| Error::resource(reason, FIELD, at))?;
        if left != right {
            return Ok(CertMatch::Differs);
        }
        if !target
            .tbs()
            .issuer()
            .matches(issuer.tbs().subject(), execution)?
        {
            return Ok(CertMatch::Differs);
        }
        let identity = match digest::resolve(digest, &self.algorithm, execution)? {
            Resolution::Supported(identity) => identity,
            Resolution::Unsupported => return Ok(CertMatch::UnsupportedHash),
            Resolution::Malformed => return Ok(CertMatch::MalformedHashAlgorithm),
        };
        // A malformed known width is classified before either hashing callback.
        if let Some(width) = digest.width(&identity)
            && (self.issuer_name_hash.len() != width || self.issuer_key_hash.len() != width)
        {
            return Ok(CertMatch::MalformedHashWidth);
        }
        for (input, expected) in [
            (target.tbs().issuer().as_bytes(), self.issuer_name_hash),
            (
                issuer.tbs().public_key().key().as_bytes(),
                self.issuer_key_hash,
            ),
        ] {
            match matches_once(digest, &identity, input, expected, execution)
                .map_err(|error| once(error, FIELD, at))?
            {
                Resolution::Supported(true) => {}
                Resolution::Supported(false) => return Ok(CertMatch::Differs),
                Resolution::Unsupported | Resolution::Malformed => {
                    return Ok(CertMatch::UnsupportedHash);
                }
            }
        }
        Ok(CertMatch::Matches)
    }
}

#[cfg(test)]
mod tests;
