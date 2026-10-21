use super::CertMatch;
use crate::algorithm::digest::{Algorithm, AsnDigest};
use crate::error::CallbackError;
use core::cell::Cell;
use core::cmp::Ordering;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::Work;

/// Records every hashed input; answers with configurable support and fault.
struct Observed<'a> {
    name: &'a [u8],
    key: &'a [u8],
    hashes: Cell<usize>,
    supported: bool,
    failure: bool,
}

impl Digest<'_> for Observed<'_> {
    type Identity = Algorithm;
    type State = ();
    type Output = [u8; 20];
    type Error = &'static str;

    fn width(&self, identity: &Algorithm) -> Option<usize> {
        Some(identity.width())
    }
    fn compare<W: Work>(
        &self,
        l: &Algorithm,
        r: &Algorithm,
        _: &W,
    ) -> Result<Ordering, &'static str> {
        Ok(l.cmp(r))
    }
    fn start<W: Work>(&self, identity: &Algorithm, _: &W) -> Result<Resolution<()>, &'static str> {
        assert_eq!(*identity, Algorithm::Sha1);
        Ok(Resolution::Supported(()))
    }
    fn update<W: Work>(&self, (): &mut (), input: &[u8], _: &W) -> Result<(), &'static str> {
        if self.failure {
            return Err("provider failure");
        }
        let calls = self.hashes.get();
        self.hashes.set(calls + 1);
        let original = if calls == 0 { self.name } else { self.key };
        assert_eq!(input, original);
        assert_eq!(input.as_ptr(), original.as_ptr());
        Ok(())
    }
    fn finish<W: Work>(&self, (): (), _: &W) -> Result<[u8; 20], &'static str> {
        Ok([0x11; 20])
    }
    fn matches<W: Work>(
        &self,
        _: &Algorithm,
        _: &[u8; 20],
        expected: &[u8],
        _: &W,
    ) -> Result<bool, &'static str> {
        assert_eq!(expected.len(), 20);
        Ok(true)
    }
}

impl AsnDigest<'_> for Observed<'_> {
    fn identity(&self, algorithm: Algorithm) -> Option<Algorithm> {
        self.supported.then_some(algorithm)
    }
}

#[test]
fn retained_cert_id_query_cannot_escape_either_original_source_ceiling() {
    // A fresh query must not erase either target or AA local parser exhaustion.
    // Refuse before a digest callback, rather than reporting different identity.
    for exhaust_target in [true, false] {
        let parts = crate::fixtures::CertificateParts::default();
        let issuer_bytes = crate::fixtures::CertificateParts {
            subject: parts.issuer.clone(),
            ..crate::fixtures::CertificateParts::default()
        }
        .build();
        let target_bytes = parts.build();
        let target_memory = crate::fixtures::memory();
        let issuer_memory = crate::fixtures::memory();
        let current = crate::fixtures::memory();
        let target_parser = structured_asn1::Parser::der(target_memory.clone());
        let issuer_parser = structured_asn1::Parser::der(issuer_memory.clone());
        let parser = structured_asn1::Parser::der(current.clone());
        let target = crate::Certificate::read(&target_parser, &target_bytes, 100).unwrap();
        let issuer = crate::Certificate::read(&issuer_parser, &issuer_bytes, 300).unwrap();
        let sha1 = crate::fixtures::algorithm(crate::oid::SHA1);
        let mut reader = parser.read(&sha1, 900).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let algorithm = crate::algorithm::read(&reader, &element, "certID.hashAlgorithm").unwrap();
        let id = super::CertId {
            algorithm,
            serial: target.tbs().serial(),
            issuer_name_hash: &[0x11; 20],
            issuer_key_hash: &[0x22; 20],
            span: structured_asn1::Span {
                start: 700,
                length: 50,
            },
        };
        let provider = Observed {
            name: target.tbs().issuer().as_bytes(),
            key: issuer.tbs().public_key().key().as_bytes(),
            hashes: Cell::new(0),
            supported: true,
            failure: false,
        };
        let source_parser = if exhaust_target {
            &target_parser
        } else {
            &issuer_parser
        };
        let source = source_parser.read(&[], 0).unwrap();
        let source = source.execution();
        source.charge_work(source.work_remaining() as u64).unwrap();
        assert!(matches!(id.matches(&target, &issuer, &provider, &current),
            Err(CallbackError::Processing(error)) if error.is_resource()));
        assert_eq!(provider.hashes.get(), 0);
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
    let sha1 = crate::fixtures::algorithm(crate::oid::SHA1);
    let mut reader = parser.read(&sha1, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let algorithm = crate::algorithm::read(&reader, &element, "certID.hashAlgorithm").unwrap();
    let id = super::CertId {
        algorithm,
        serial: target.tbs().serial(),
        issuer_name_hash: &[0x11; 20],
        issuer_key_hash: &[0x22; 20],
        span: structured_asn1::Span {
            start: 700,
            length: 50,
        },
    };
    let provider = Observed {
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
        CallbackError::Callback("provider failure")
    ));
    let stopped = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 0),
    ));
    assert!(
        matches!(id.matches(&target, &issuer, &provider, &stopped).unwrap_err(), CallbackError::Processing(error) if error.is_resource() && error.offset() == 700)
    );
}

#[test]
fn cert_id_with_parameters_its_hash_does_not_take_is_malformed_not_unsupported() {
    // SHA-1 takes absent or NULL parameters (RFC 8017 Appendix B.1); an
    // INTEGER is a malformed identifier, decided before any hashing.
    let parts = crate::fixtures::CertificateParts::default();
    let target_bytes = parts.build();
    let execution = crate::fixtures::memory();
    let parser = structured_asn1::Parser::der(execution.clone());
    let target = crate::Certificate::read(&parser, &target_bytes, 100).unwrap();
    let sha1 = crate::fixtures::seq(&[
        crate::fixtures::oid(crate::oid::SHA1),
        crate::fixtures::int(1),
    ]);
    let mut reader = parser.read(&sha1, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let algorithm = crate::algorithm::read(&reader, &element, "certID.hashAlgorithm").unwrap();
    let id = super::CertId {
        algorithm,
        serial: target.tbs().serial(),
        issuer_name_hash: &[0x11; 20],
        issuer_key_hash: &[0x22; 20],
        span: structured_asn1::Span {
            start: 700,
            length: 50,
        },
    };
    let provider = Observed {
        name: &[],
        key: &[],
        hashes: Cell::new(0),
        supported: true,
        failure: false,
    };
    // The target is its own issuer here only for the name comparison.
    let issuer_bytes = crate::fixtures::CertificateParts {
        subject: parts.issuer.clone(),
        ..crate::fixtures::CertificateParts::default()
    }
    .build();
    let issuer = crate::Certificate::read(&parser, &issuer_bytes, 300).unwrap();
    assert_eq!(
        id.matches(&target, &issuer, &provider, &execution).unwrap(),
        CertMatch::MalformedHashAlgorithm
    );
    assert_eq!(provider.hashes.get(), 0);
}
