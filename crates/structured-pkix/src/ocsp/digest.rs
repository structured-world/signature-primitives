//! Provider-injected digest matching without materializing a second output.

use super::CertId;
use crate::AlgorithmIdentifier;
use crate::Certificate;
use crate::error::{CallbackError, CallbackResult, Error};
use core::num::NonZeroUsize;
use structured_asn1::memory::{Memory, MemoryError};

/// The digest's normative source, without reconstructing an identifier.
#[derive(Debug, Clone, Copy)]
pub enum DigestAlgorithm<'a> {
    /// Hash algorithm encoded in the original `CertID`, including parameters.
    Identifier(&'a AlgorithmIdentifier<'a>),
    /// SHA-1 imposed by the `ResponderID` byKey syntax, not a signature choice.
    Sha1,
}

/// Copyable resolved capability and fixed output width. No output is allocated
/// while resolving, and an unsupported capability is represented by None.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedDigest<H: Copy> {
    /// Provider-owned selected algorithm handle, not a second engine.
    pub handle: H,
    /// Fixed output width used to check expected data before hashing.
    pub width: NonZeroUsize,
}

/// The consumer's selected cryptographic provider and compiled algorithm policy.
/// Every input-derived callback scan/allocation/hash/comparison is admitted
/// through the supplied execution domain before work begins. A fixed output
/// reservation does not qualify opaque custom-provider internal allocations.
pub trait Digest {
    /// Copyable resolved algorithm capability.
    type Handle: Copy;
    /// Original provider or resource error, never collapsed into mismatch.
    type Error;
    /// Resolve original identifier/parameters or protocol-imposed SHA-1.
    fn resolve(
        &self,
        algorithm: DigestAlgorithm<'_>,
        execution: &Memory,
    ) -> core::result::Result<Option<ResolvedDigest<Self::Handle>>, Self::Error>;
    /// Hash original bytes and compare with an already width-checked expected
    /// value. No owned-output conversion or extra allocation is required by core.
    fn matches(
        &self,
        handle: Self::Handle,
        input: &[u8],
        expected: &[u8],
        execution: &Memory,
    ) -> core::result::Result<bool, Self::Error>;
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
    /// The consumer does not support the encoded hash algorithm/parameters.
    UnsupportedHash,
}

impl CertId<'_> {
    /// Match the actual target and candidate issuer without re-encoding names.
    /// RFC6960 §4.1.1 hashes original target issuer DER and issuer public-key
    /// contents. The caller retains their authenticated issuer/path provenance;
    /// matching hashes does not verify the target certificate's signature.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1>
    pub fn matches<D: Digest>(
        &self,
        target: &Certificate<'_>,
        issuer: &Certificate<'_>,
        digest: &D,
        execution: &Memory,
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
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, at))?;
        let Some(resolved) = digest
            .resolve(DigestAlgorithm::Identifier(&self.algorithm), execution)
            .map_err(CallbackError::Callback)?
        else {
            return Ok(CertMatch::UnsupportedHash);
        };
        // A malformed known width is classified before either hashing callback.
        if self.issuer_name_hash.len() != resolved.width.get()
            || self.issuer_key_hash.len() != resolved.width.get()
        {
            return Ok(CertMatch::MalformedHashWidth);
        }
        if !digest
            .matches(
                resolved.handle,
                target.tbs().issuer().as_bytes(),
                self.issuer_name_hash,
                execution,
            )
            .map_err(CallbackError::Callback)?
        {
            return Ok(CertMatch::Differs);
        }
        if !digest
            .matches(
                resolved.handle,
                issuer.tbs().public_key().key().as_bytes(),
                self.issuer_key_hash,
                execution,
            )
            .map_err(CallbackError::Callback)?
        {
            return Ok(CertMatch::Differs);
        }
        Ok(CertMatch::Matches)
    }
}

#[cfg(test)]
mod tests {
    use super::{CertMatch, Digest, DigestAlgorithm, ResolvedDigest};
    use core::cell::Cell;
    use core::num::NonZeroUsize;
    use structured_asn1::memory::Memory;

    struct Observed<'a> {
        original_algorithm: &'a [u8],
        name: &'a [u8],
        key: &'a [u8],
        hashes: Cell<usize>,
        supported: bool,
        failure: bool,
    }
    impl Digest for Observed<'_> {
        type Handle = u8;
        type Error = &'static str;
        fn resolve(
            &self,
            algorithm: DigestAlgorithm<'_>,
            _: &Memory,
        ) -> Result<Option<ResolvedDigest<u8>>, Self::Error> {
            let DigestAlgorithm::Identifier(algorithm) = algorithm else {
                panic!("CertID does not impose SHA1")
            };
            assert_eq!(algorithm.as_bytes(), self.original_algorithm);
            assert_eq!(
                algorithm.as_bytes().as_ptr(),
                self.original_algorithm.as_ptr()
            );
            if !self.supported {
                return Ok(None);
            }
            Ok(Some(ResolvedDigest {
                handle: 1,
                width: NonZeroUsize::new(20).unwrap(),
            }))
        }
        fn matches(
            &self,
            handle: u8,
            input: &[u8],
            expected: &[u8],
            _: &Memory,
        ) -> Result<bool, Self::Error> {
            assert_eq!(handle, 1);
            assert_eq!(expected.len(), 20);
            if self.failure {
                return Err("provider failure");
            }
            let calls = self.hashes.get();
            self.hashes.set(calls + 1);
            let original = if calls == 0 { self.name } else { self.key };
            assert_eq!(input, original);
            assert_eq!(input.as_ptr(), original.as_ptr());
            Ok(true)
        }
    }

    #[test]
    fn cert_id_prechecks_width_and_forwards_original_bytes_without_output_copy() {
        // A callback sees original target issuer DER, then raw public-key
        // contents, never rendered Name/SPKI. Bad expected width does not hash.
        let parts = crate::fixtures::CertificateParts::default();
        let issuer_bytes = crate::fixtures::CertificateParts {
            subject: parts.issuer.clone(),
            ..crate::fixtures::CertificateParts::default()
        }
        .build();
        let target_bytes = parts.build();
        let execution = crate::fixtures::memory();
        let parser = structured_asn1::Parser::der(execution.clone());
        let target = crate::Certificate::read(&parser, &target_bytes, 100).unwrap();
        let issuer = crate::Certificate::read(&parser, &issuer_bytes, 300).unwrap();
        let id = super::CertId {
            algorithm: target.signature_algorithm(),
            serial: target.tbs().serial(),
            issuer_name_hash: &[0x11; 20],
            issuer_key_hash: &[0x22; 20],
            span: structured_asn1::Span {
                start: 700,
                length: 50,
            },
        };
        let provider = Observed {
            original_algorithm: id.algorithm.as_bytes(),
            name: target.tbs().issuer().as_bytes(),
            key: issuer.tbs().public_key().key().as_bytes(),
            hashes: Cell::new(0),
            supported: true,
            failure: false,
        };
        let storage = execution.used();
        assert_eq!(
            id.matches(&target, &issuer, &provider, &execution).unwrap(),
            CertMatch::Matches
        );
        assert_eq!(provider.hashes.get(), 2);
        assert_eq!(execution.used(), storage);
        let malformed = super::CertId {
            issuer_name_hash: &[0x11; 19],
            ..id
        };
        provider.hashes.set(0);
        assert_eq!(
            malformed
                .matches(&target, &issuer, &provider, &execution)
                .unwrap(),
            CertMatch::MalformedHashWidth
        );
        assert_eq!(provider.hashes.get(), 0);
        let mut provider = provider;
        provider.supported = false;
        assert_eq!(
            id.matches(&target, &issuer, &provider, &execution).unwrap(),
            CertMatch::UnsupportedHash
        );
        provider.supported = true;
        provider.failure = true;
        assert!(matches!(
            id.matches(&target, &issuer, &provider, &execution)
                .unwrap_err(),
            crate::error::CallbackError::Callback("provider failure")
        ));
        let stopped = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(0, 0),
        ));
        assert!(
            matches!(id.matches(&target, &issuer, &provider, &stopped).unwrap_err(), crate::error::CallbackError::Processing(error) if error.is_resource() && error.offset() == 700)
        );
    }
}
