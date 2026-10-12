//! Actual signer binding and response signature authentication.

use super::{BasicResponse, Digest, DigestAlgorithm, ResponderId};
use crate::path::{Verified, Verify, WorkingKey};
use crate::{Certificate, Error};
use core::fmt;
use structured_asn1::memory::{Memory, MemoryError};

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
    pub fn authenticate_signature<'r, V: Verify, D: Digest>(
        &'r self,
        signer: &'r Certificate<'a>,
        key: WorkingKey<'a>,
        verifier: &V,
        digest: &D,
        execution: &Memory,
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
        let matches = match &self.responder {
            ResponderId::Name(name) => name.matches(signer.tbs().subject(), execution)?,
            ResponderId::KeyHash(expected) => {
                charge(1)?;
                let Some(resolved) = digest
                    .resolve(DigestAlgorithm::Sha1, execution)
                    .map_err(SignatureError::Digest)?
                else {
                    return Ok(SignatureAuthentication::UnsupportedDigest);
                };
                // RFC6960 §4.2.2.2 imposes SHA-1 and exactly 20 bytes here.
                // Never hash malformed width or substitute a signature hash.
                if resolved.width.get() != 20 || expected.len() != 20 {
                    return Ok(SignatureAuthentication::Rejected(
                        SignatureFailure::DigestWidth,
                    ));
                }
                digest
                    .matches(
                        resolved.handle,
                        key.key().key().as_bytes(),
                        expected,
                        execution,
                    )
                    .map_err(SignatureError::Digest)?
            }
        };
        if !matches {
            return Ok(SignatureAuthentication::Rejected(
                SignatureFailure::ResponderIdentity,
            ));
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
mod tests {
    use super::*;
    use crate::fixtures::{CertificateParts, bits, context, octets, seq, tlv};
    use core::{cell::Cell, num::NonZeroUsize};
    use structured_asn1::{BitString, Parser};

    struct Provider<'a> {
        key: &'a [u8],
        signed: &'a [u8],
        hashes: Cell<usize>,
        signatures: Cell<usize>,
        width: usize,
        digest_answer: Option<bool>,
        signature_answer: Verified,
        failure: bool,
    }
    impl Digest for Provider<'_> {
        type Handle = ();
        type Error = &'static str;
        fn resolve(
            &self,
            algorithm: DigestAlgorithm<'_>,
            _: &Memory,
        ) -> Result<Option<super::super::ResolvedDigest<()>>, Self::Error> {
            assert!(matches!(algorithm, DigestAlgorithm::Sha1));
            if self.failure {
                return Err("digest refusal");
            }
            Ok(self.digest_answer.map(|_| super::super::ResolvedDigest {
                handle: (),
                width: NonZeroUsize::new(self.width).unwrap(),
            }))
        }
        fn matches(
            &self,
            (): (),
            input: &[u8],
            expected: &[u8],
            _: &Memory,
        ) -> Result<bool, Self::Error> {
            self.hashes.set(self.hashes.get() + 1);
            assert_eq!(input.as_ptr(), self.key.as_ptr());
            assert_eq!(input, self.key);
            assert_eq!(expected, &[0x33; 20]);
            Ok(self.digest_answer.unwrap())
        }
    }
    impl Verify for Provider<'_> {
        type Error = &'static str;
        fn verify(
            &self,
            _: &crate::AlgorithmIdentifier<'_>,
            _: WorkingKey<'_>,
            signed: &[u8],
            _: BitString<'_>,
            _: &Memory,
        ) -> Result<Verified, Self::Error> {
            self.signatures.set(self.signatures.get() + 1);
            assert_eq!(signed.as_ptr(), self.signed.as_ptr());
            assert_eq!(signed, self.signed);
            Ok(self.signature_answer)
        }
    }

    #[test]
    fn actual_signer_precedes_hash_and_original_response_data_verification() {
        // This observes dispatch/provenance only, not cryptographic correctness.
        // Wrong SPKI, responder identity or SHA1 width must stop before verify.
        let certificate_bytes = CertificateParts::default().build();
        let execution = crate::fixtures::memory();
        let parser = Parser::der(execution.clone());
        let signer = Certificate::read(&parser, &certificate_bytes, 100).unwrap();
        let algorithm = signer.signature_algorithm().as_bytes();
        let timestamp = tlv(24, b"20261012120000Z");
        let id = seq(&[
            algorithm.to_vec(),
            octets(&[0x11; 20]),
            octets(&[0x22; 20]),
            tlv(2, &[1]),
        ]);
        let single = seq(&[id, tlv(0x80, &[]), timestamp.clone()]);
        let data = seq(&[
            context(2, &[octets(&[0x33; 20])]),
            timestamp,
            seq(&[single]),
        ]);
        let bytes = seq(&[data, algorithm.to_vec(), bits(&[0xab])]);
        let mut reader = parser.read(&bytes, 700).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let response = super::super::read_basic(&reader, &element).unwrap();
        let key = WorkingKey::standing(signer.tbs().public_key());
        let mut provider = Provider {
            key: signer.tbs().public_key().key().as_bytes(),
            signed: response.signed_bytes(),
            hashes: Cell::new(0),
            signatures: Cell::new(0),
            width: 20,
            digest_answer: Some(true),
            signature_answer: Verified::Yes,
            failure: false,
        };
        let retained = execution.used();
        let SignatureAuthentication::Signed(proof) = response
            .authenticate_signature(&signer, key, &provider, &provider, &execution)
            .unwrap()
        else {
            panic!("signature not authenticated");
        };
        assert!(core::ptr::eq(proof.response(), &raw const response));
        assert!(core::ptr::eq(proof.signer(), &raw const signer));
        assert_eq!(provider.signatures.get(), 1);
        assert_eq!(execution.used(), retained);
        provider.signatures.set(0);
        provider.width = 19;
        assert!(matches!(
            response
                .authenticate_signature(&signer, key, &provider, &provider, &execution)
                .unwrap(),
            SignatureAuthentication::Rejected(SignatureFailure::DigestWidth)
        ));
        assert_eq!(provider.signatures.get(), 0);
        provider.width = 20;
        provider.digest_answer = Some(false);
        assert!(matches!(
            response
                .authenticate_signature(&signer, key, &provider, &provider, &execution)
                .unwrap(),
            SignatureAuthentication::Rejected(SignatureFailure::ResponderIdentity)
        ));
        assert_eq!(provider.signatures.get(), 0);
        provider.digest_answer = None;
        assert!(matches!(
            response
                .authenticate_signature(&signer, key, &provider, &provider, &execution)
                .unwrap(),
            SignatureAuthentication::UnsupportedDigest
        ));
        provider.failure = true;
        assert!(matches!(
            response.authenticate_signature(&signer, key, &provider, &provider, &execution),
            Err(SignatureError::Digest("digest refusal"))
        ));
        let unfunded = Memory::new(alloc::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(0, 0),
        ));
        assert!(
            matches!(response.authenticate_signature(&signer, key, &provider, &provider, &unfunded), Err(SignatureError::Processing(error)) if error.is_resource() && error.offset() == 700)
        );
    }
}
