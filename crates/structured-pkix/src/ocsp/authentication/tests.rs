use super::*;
use crate::algorithm::digest::Algorithm;
use crate::fixtures::{CertificateParts, bits, context, extension, octets, seq, tlv};
use crate::signature::SignatureValue;
use core::cell::Cell;
use core::cmp::Ordering;
use structured_asn1::Parser;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::Memory;

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
impl Digest<'_> for Provider<'_> {
    type Identity = ();
    type State = ();
    type Output = [u8; 20];
    type Error = &'static str;
    fn width(&self, (): &()) -> Option<usize> {
        Some(self.width)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), _: &W) -> Result<Ordering, Self::Error> {
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), _: &W) -> Result<Resolution<()>, Self::Error> {
        if self.failure {
            return Err("digest refusal");
        }
        Ok(Resolution::Supported(()))
    }
    fn update<W: Work>(&self, (): &mut (), input: &[u8], _: &W) -> Result<(), Self::Error> {
        self.hashes.set(self.hashes.get() + 1);
        assert_eq!(input.as_ptr(), self.key.as_ptr());
        assert_eq!(input, self.key);
        Ok(())
    }
    fn finish<W: Work>(&self, (): (), _: &W) -> Result<[u8; 20], Self::Error> {
        Ok([0; 20])
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        _: &[u8; 20],
        expected: &[u8],
        _: &W,
    ) -> Result<bool, Self::Error> {
        assert_eq!(expected, &[0x33; 20]);
        Ok(self.digest_answer.unwrap())
    }
}
impl AsnDigest<'_> for Provider<'_> {
    fn identity(&self, algorithm: Algorithm) -> Option<()> {
        assert_eq!(algorithm, Algorithm::Sha1);
        self.digest_answer.map(|_| ())
    }
}
impl Verify for Provider<'_> {
    type Error = &'static str;
    fn verify(
        &self,
        _: &crate::AlgorithmIdentifier<'_>,
        _: WorkingKey<'_>,
        signed: &[u8],
        signature: SignatureValue<'_>,
        execution: &Memory,
    ) -> Result<Verified, Self::Error> {
        self.signatures.set(self.signatures.get() + 1);
        assert_eq!(signed.as_ptr(), self.signed.as_ptr());
        assert_eq!(signed, self.signed);
        let mut payload = signature
            .reader_in(execution)
            .expect("original signature source");
        let pair = crate::signature::DssValue::read(&mut payload, "ocsp.signature").unwrap();
        assert_eq!(pair.r().as_u64(), Some(1));
        assert_eq!(pair.s().as_u64(), Some(2));
        assert_eq!(
            pair.element().as_bytes().as_ptr(),
            signature.octets().unwrap().as_ptr()
        );
        assert_eq!(pair.element().span(), signature.payload_span());
        Ok(self.signature_answer)
    }
}

#[test]
fn responder_identity_query_reuses_original_key_bits_without_signature_or_output_copy() {
    // XAdES byKey identifiers need the same RFC6960 identity check outside
    // signature authentication. A malformed width cannot call the provider,
    // and current query refusal remains located processing failure.
    use crate::error::CallbackError;
    use crate::ocsp::{ResponderId, ResponderMatch};
    let bytes = CertificateParts::default().build();
    let memory = crate::fixtures::memory();
    let parser = Parser::der(memory.clone());
    let certificate = Certificate::read(&parser, &bytes, 100).unwrap();
    let mut provider = Provider {
        key: certificate.tbs().public_key().key().as_bytes(),
        signed: &[],
        hashes: Cell::new(0),
        signatures: Cell::new(0),
        width: 20,
        digest_answer: Some(true),
        signature_answer: Verified::Yes,
        failure: false,
    };
    let selector = ResponderId::KeyHash(&[0x33; 20]);
    let held = memory.used();
    assert_eq!(
        selector
            .matches_certificate(&certificate, &provider, &memory, "original.byKey", 900)
            .unwrap(),
        ResponderMatch::Matches
    );
    assert_eq!((provider.hashes.get(), provider.signatures.get()), (1, 0));
    assert_eq!(memory.used(), held);
    provider.failure = true;
    assert_eq!(
        ResponderId::KeyHash(&[0x33; 19])
            .matches_certificate(&certificate, &provider, &memory, "original.byKey", 900)
            .unwrap(),
        ResponderMatch::MalformedHashWidth
    );
    assert!(matches!(
        selector.matches_certificate(&certificate, &provider, &memory, "original.byKey", 900),
        Err(CallbackError::Callback("digest refusal"))
    ));
    let stopped = Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 0),
    ));
    assert!(
        matches!(selector.matches_certificate(&certificate,&provider,&stopped,"original.byKey",900),Err(CallbackError::Processing(error)) if error.is_resource() && error.offset()==900)
    );
    assert_eq!((provider.hashes.get(), provider.signatures.get()), (1, 0));
    assert_eq!(memory.used(), held);
}

#[test]
fn issuer_binding_enforces_object_signing_key_usage() {
    // RFC5280 4.2.1.3: certificate/CRL signing bits cannot authorize an
    // OCSP object signature; either object-signing bit is sufficient.
    for (usage, permitted) in [
        (None, true),
        (Some([7, 0x80]), true),
        (Some([6, 0x40]), true),
        (Some([1, 0x06]), false),
        (Some([5, 0x20]), false),
    ] {
        let certificate_bytes = CertificateParts {
            extensions: usage
                .map(|value| seq(&[extension(crate::oid::KEY_USAGE, true, &tlv(3, &value))])),
            ..CertificateParts::default()
        }
        .build();
        let execution = crate::fixtures::memory();
        let parser = Parser::der(execution.clone());
        let issuer = Certificate::read(&parser, &certificate_bytes, 100).unwrap();
        let algorithm = issuer.signature_algorithm().as_bytes();
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
        let bytes = seq(&[data, algorithm.to_vec(), bits(&[48, 6, 2, 1, 1, 2, 1, 2])]);
        let mut reader = parser.read(&bytes, 700).unwrap();
        let root = reader.next_element().unwrap().unwrap();
        let response = super::super::read_basic(&reader, &root).unwrap();
        let key = WorkingKey::standing(issuer.tbs().public_key());
        let provider = Provider {
            key: issuer.tbs().public_key().key().as_bytes(),
            signed: response.signed_bytes(),
            hashes: Cell::new(0),
            signatures: Cell::new(0),
            width: 20,
            digest_answer: Some(true),
            signature_answer: Verified::Yes,
            failure: false,
        };
        let SignatureAuthentication::Signed(signed) = response
            .authenticate_signature(&issuer, key, &provider, &provider, &execution)
            .unwrap()
        else {
            panic!("signature fixture rejected");
        };
        let result = signed.bind_issuer(&issuer, key, &execution).unwrap();
        assert_eq!(
            matches!(result, super::super::AuthorityBinding::Bound(_)),
            permitted
        );
        if !permitted {
            assert!(matches!(
                result,
                super::super::AuthorityBinding::Rejected(super::super::AuthorityFailure::KeyUsage)
            ));
        }
        assert_eq!(provider.signatures.get(), 1);
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
    let bytes = seq(&[data, algorithm.to_vec(), bits(&[48, 6, 2, 1, 1, 2, 1, 2])]);
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
    provider.digest_answer = Some(true);
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
