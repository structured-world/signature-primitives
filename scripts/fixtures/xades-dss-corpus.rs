//! Public DSS corpus decoded by shared code and independent XML/CMS/OCSP oracles.
//! XML signature/archive coverage and trust are not fabricated by this harness.

use std::{path::PathBuf, sync::Arc};
use structured_asn1::{
    Parser, Tag,
    memory::{Memory, MemoryAccount},
    universal,
};
use structured_cms::timestamp::Token;
use structured_pkix::{Certificate, ocsp};

#[path = "../../crates/structured-xades/tests/containers.rs"]
mod common_inputs;

fn corpus(level: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("XADES_DSS_CORPUS").unwrap()).join(level)
}

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28)))
}

#[test]
fn independent_timestamp_and_archive_inputs_match_the_signed_imprints() {
    // Actual C14N/reference octets from the independent fixture drive the SAME
    // common Input used by all other timestamp and archive routes.
    common_inputs::independent_corpus::check(&corpus("lta"));
}

#[test]
fn independent_signature_timestamp_input_matches_its_signed_imprint() {
    // The B-LT fixture is also a B-T signature (EN319132-1 V1.3.1 table 2
    // permits validation values at B-T); its one token covers SignatureValue.
    common_inputs::independent_corpus::check_signature(&corpus("lt"));
}

#[test]
fn independent_copied_signature_timestamp_does_not_cover_this_signature() {
    // DSS copied a genuine token from another signature: OpenSSL accepts its
    // CMS signature, but EN319132-1 §5.3 coverage of THIS SignatureValue fails.
    // The common Input must still select the exact independent C14N bytes.
    // Token 0 is the signed AllDataObjectsTimeStamp, token 1 the copy.
    common_inputs::independent_corpus::check_foreign_signature(
        &corpus("negative/copied-sigtst"),
        1,
    );
}

#[test]
fn independent_tampered_keyinfo_certificate_is_refused() {
    // DSS altered the KeyInfo certificate until OpenSSL no longer decodes it;
    // the shared reader must refuse it rather than yield a signer.
    let signer = std::fs::read(corpus("negative/tampered-keyinfo").join("signer.der")).unwrap();
    let parser = Parser::der(memory());
    assert!(Certificate::read(&parser, &signer, 0).is_err());
}

#[test]
fn independent_signature_and_archive_tokens_preserve_original_readings() {
    // The SHA256-pinned upstream XML has a signature timestamp and an archive
    // timestamp. OpenSSL independently verifies each CMS signature/eContent;
    // fixed expected imprints below come from its RFC3161 decoder.
    let directory = corpus("lta");
    let expected = [
        "b3d8aeb10b119f6513ca9c67b65e6ebe915034e3b0aec8a0c89dc42f17ec3bf7",
        "b49d025c7282021bfc5566a5325ef05abafce46fa810862a6fad5b0c0219c9bf",
    ];
    for (ordinal, imprint) in expected.iter().enumerate() {
        let original = std::fs::read(directory.join(format!("token-{ordinal}.der"))).unwrap();
        let extracted = std::fs::read(directory.join(format!("tstinfo-{ordinal}.der"))).unwrap();
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let token = Token::read(&parser, &original, 400).unwrap();
        assert!(token.faults().is_empty(), "{:?}", token.faults());
        let operation = parser.read(&[], 900).unwrap();
        assert_eq!(
            token.message().content().content().unwrap().as_one(),
            Some(extracted.as_slice())
        );
        token
            .with_info(&operation, |info, _, _| {
                assert!(!info.has_faults(), "{:?}", info.faults());
                assert_eq!(info.policy().as_bytes(), &[0x2a, 3, 4]);
                assert_eq!(info.imprint().hashed().len(), 32);
                let actual = info.imprint().hashed().as_one().unwrap();
                for (byte, hex) in actual.iter().zip(imprint.as_bytes().as_chunks::<2>().0) {
                    assert_eq!(
                        *byte,
                        u8::from_str_radix(std::str::from_utf8(hex).unwrap(), 16).unwrap()
                    );
                }
                assert!(info.accuracy().is_none());
                assert!(info.nonce().is_none());
                assert!(!info.ordering());
                assert!(!info.gen_time().has_subnanosecond_remainder());
                Ok::<_, ()>(())
            })
            .unwrap();
        drop(token);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn independent_signature_token_preserves_its_original_reading() {
    // OpenSSL verified this token's CMS signature and extracted its eContent;
    // the shared reader must yield the same TSTInfo without faults. The
    // imprint value itself is checked against libxml2 C14N in its own test.
    let directory = corpus("lt");
    let original = std::fs::read(directory.join("token-0.der")).unwrap();
    let extracted = std::fs::read(directory.join("tstinfo-0.der")).unwrap();
    let memory = memory();
    let parser = Parser::ber(memory.clone());
    let token = Token::read(&parser, &original, 400).unwrap();
    assert!(token.faults().is_empty(), "{:?}", token.faults());
    let operation = parser.read(&[], 900).unwrap();
    assert_eq!(
        token.message().content().content().unwrap().as_one(),
        Some(extracted.as_slice())
    );
    token
        .with_info(&operation, |info, _, _| {
            assert!(!info.has_faults(), "{:?}", info.faults());
            assert_eq!(info.policy().as_bytes(), &[0x2a, 3, 4]);
            assert_eq!(info.imprint().hashed().len(), 32);
            // OpenSSL `ts -reply -token_in -text`: accuracy and nonce unspecified,
            // ordering no.
            assert!(info.accuracy().is_none());
            assert!(info.nonce().is_none());
            assert!(!info.ordering());
            Ok::<_, ()>(())
        })
        .unwrap();
    drop(token);
    assert_eq!(memory.used(), 0);
}

#[test]
fn independent_signing_certificates_bind_each_signer() {
    // EN319132-1 §5.2.2: the one SigningCertificateV2 entry carries the
    // digest of the complete signer certificate DER and an IssuerSerialV2
    // hint; both must identify the KeyInfo signer xmlsec1 verified with.
    use sha2::Digest;
    for level in ["b", "lt", "lta"] {
        let directory = corpus(level);
        let signer = std::fs::read(directory.join("signer.der")).unwrap();
        let expected = std::fs::read(directory.join("cert-digest.bin")).unwrap();
        let method = std::fs::read_to_string(directory.join("cert-digest-method.txt")).unwrap();
        let actual = match method.as_str() {
            "http://www.w3.org/2001/04/xmlenc#sha256" => sha2::Sha256::digest(&signer).to_vec(),
            "http://www.w3.org/2001/04/xmlenc#sha512" => sha2::Sha512::digest(&signer).to_vec(),
            other => panic!("unexpected certificate digest method {other}"),
        };
        assert_eq!(actual, expected, "{level}");
        let hint = std::fs::read(directory.join("issuer-serial.der")).unwrap();
        let memory = memory();
        let parser = Parser::der(memory.clone());
        let certificate = Certificate::read(&parser, &signer, 0).unwrap();
        let mut reader = parser.read(&hint, 0).unwrap();
        let element = reader
            .expect(Tag::constructed(universal::SEQUENCE))
            .unwrap();
        let reading =
            structured_cms::ess::IssuerSerialReading::read(&reader, &element, "issuerSerialV2")
                .unwrap();
        assert!(reader.is_empty());
        assert!(
            reading.faults().is_empty(),
            "{level}: {:?}",
            reading.faults()
        );
        assert_eq!(
            reading.matches_certificate(&certificate, &reader).unwrap(),
            structured_cms::ess::IssuerAgreement::Matches,
            "{level}"
        );
    }
}

/// SHA-1 for the OCSP identities only: RFC6960 §4.2.1 imposes it for
/// `ResponderID` byKey, and this fixture's `CertID` names it explicitly.
struct Sha1;

impl ocsp::Digest for Sha1 {
    type Handle = ();
    type Error = &'static str;
    fn resolve(
        &self,
        algorithm: ocsp::DigestAlgorithm<'_>,
        _: &Memory,
    ) -> Result<Option<ocsp::ResolvedDigest<()>>, Self::Error> {
        // SHA-1 AlgorithmIdentifier with NULL parameters, as the fixture encodes it.
        const SHA1: &[u8] = &[0x30, 9, 6, 5, 0x2b, 14, 3, 2, 26, 5, 0];
        let supported = match algorithm {
            ocsp::DigestAlgorithm::Sha1 => true,
            ocsp::DigestAlgorithm::Identifier(identifier) => identifier.as_bytes() == SHA1,
        };
        Ok(supported.then(|| ocsp::ResolvedDigest {
            handle: (),
            width: core::num::NonZeroUsize::new(20).unwrap(),
        }))
    }
    fn matches(
        &self,
        (): (),
        input: &[u8],
        expected: &[u8],
        _: &Memory,
    ) -> Result<bool, Self::Error> {
        use sha1::Digest;
        Ok(sha1::Sha1::digest(input).as_slice() == expected)
    }
}

#[test]
fn independent_ocsp_response_identifies_the_signer_and_its_responder() {
    // OpenSSL verified the response signature with a key from the same
    // CertificateValues and printed a good status. The shared reader must find
    // exactly one responder by key hash and exactly one issuer for the signer's
    // CertID among those values; responder expiry and trust stay unchecked.
    let directory = corpus("lt");
    let memory = memory();
    let parser = Parser::der(memory.clone());
    let values: Vec<Vec<u8>> = (0..)
        .map(|ordinal| directory.join(format!("certificate-{ordinal}.der")))
        .take_while(|path| path.exists())
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    assert_eq!(values.len(), 4);
    let certificates: Vec<Certificate<'_>> = values
        .iter()
        .map(|value| Certificate::read(&parser, value, 0).unwrap())
        .collect();
    let signer_bytes = std::fs::read(directory.join("signer.der")).unwrap();
    let signer = Certificate::read(&parser, &signer_bytes, 0).unwrap();
    let response_bytes = std::fs::read(directory.join("ocsp-0.der")).unwrap();
    let ocsp::Response::Successful(envelope) =
        ocsp::Response::read(&parser, &response_bytes, 0).unwrap()
    else {
        panic!("OpenSSL decoded a successful response")
    };
    let basic = envelope.into_basic(&memory).unwrap().unwrap();
    assert!(matches!(basic.responder(), ocsp::ResponderId::KeyHash(_)));
    let responders = certificates
        .iter()
        .filter(|candidate| {
            basic
                .responder()
                .matches_certificate(candidate, &Sha1, &memory, "responderID", 0)
                .unwrap()
                == ocsp::ResponderMatch::Matches
        })
        .count();
    assert_eq!(responders, 1);
    let [single] = basic.responses() else {
        panic!("OpenSSL printed exactly one single response")
    };
    assert_eq!(single.status(), ocsp::Status::Good);
    let issuers = certificates
        .iter()
        .filter(|issuer| {
            single
                .id()
                .matches(&signer, issuer, &Sha1, &memory)
                .unwrap()
                == ocsp::CertMatch::Matches
        })
        .count();
    assert_eq!(issuers, 1);
}
