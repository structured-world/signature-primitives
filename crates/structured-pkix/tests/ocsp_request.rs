//! Public complete request parsing, native signatures and authenticated batch binding.
//! The fixed-curve oracle checks interoperability, not opaque backend allocation accounting.

use core::cmp::Ordering;
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use std::{cell::Cell, sync::Arc};
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::algorithm::{
    digest::{Algorithm as Hash, AsnDigest},
    signature::{self, Algorithm},
};
use structured_pkix::error::CallbackError;
use structured_pkix::ocsp::request::{
    RequestAuthentication, RequestSignatureFailure, RequestorBinding,
};
use structured_pkix::ocsp::{
    BasicResponse, CertMatch, ExtensionProcessing, Lookup, NonceBinding, OcspRequest, RequestNonce,
    SignatureAuthentication,
};
use structured_pkix::path::{Verified, Verify, WorkingKey};
use structured_pkix::signature::{DssValue, SignatureValue};
use structured_pkix::{AlgorithmIdentifier, Certificate, Error, ErrorCode, oid};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}
fn ample() -> Memory {
    memory(4_000_000, 100_000_000)
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(u8::try_from(body.len()).unwrap());
    } else if body.len() < 256 {
        out.extend([0x81, u8::try_from(body.len()).unwrap()]);
    } else {
        out.push(0x82);
        out.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    }
    out.extend(body);
    out
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(48, &parts.concat())
}
fn bits(bytes: &[u8]) -> Vec<u8> {
    tlv(3, &[&[0][..], bytes].concat())
}
fn sig_algorithm() -> Vec<u8> {
    seq(&[tlv(6, &[42, 134, 72, 206, 61, 4, 3, 2])])
}
fn name(label: &[u8]) -> Vec<u8> {
    tlv(48, &tlv(49, &seq(&[tlv(6, &[85, 4, 3]), tlv(12, label)])))
}
fn cert(key: &SigningKey, label: &[u8], san: bool) -> Vec<u8> {
    let key_algorithm = seq(&[
        tlv(6, &[42, 134, 72, 206, 61, 2, 1]),
        tlv(6, &[42, 134, 72, 206, 61, 3, 1, 7]),
    ]);
    let spki = seq(&[
        key_algorithm,
        bits(key.verifying_key().to_sec1_point(false).as_bytes()),
    ]);
    let date = tlv(23, b"261012120000Z");
    let mut fields = vec![
        tlv(0xa0, &[2, 1, 2]),
        tlv(2, &[1]),
        sig_algorithm(),
        name(label),
        seq(&[date.clone(), date]),
        name(label),
        spki,
    ];
    if san {
        fields.push(tlv(
            0xa3,
            &seq(&[extension(
                &[85, 29, 17],
                false,
                &seq(&[tlv(0x82, b"EXAMPLE.COM")]),
            )]),
        ));
    }
    let tbs = seq(&fields);
    let signature: Signature = key.sign(&tbs);
    seq(&[tbs, sig_algorithm(), bits(signature.to_der().as_bytes())])
}
fn hash_algorithm(null: bool) -> Vec<u8> {
    let mut parts = vec![tlv(6, oid::SHA1.as_bytes())];
    if null {
        parts.push(tlv(5, &[]));
    }
    seq(&parts)
}
fn id(serial: &[u8], algorithm: Vec<u8>, width: usize) -> Vec<u8> {
    seq(&[
        algorithm,
        tlv(4, &vec![0x11; width]),
        tlv(4, &vec![0x22; width]),
        tlv(2, serial),
    ])
}
fn entry(serial: u8) -> Vec<u8> {
    seq(&[id(&[serial], hash_algorithm(false), 20)])
}
fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut fields = vec![tlv(6, oid)];
    if critical {
        fields.push(tlv(1, &[255]));
    }
    fields.push(tlv(4, value));
    seq(&fields)
}
fn nonce(value: &[u8]) -> Vec<u8> {
    extension(oid::OCSP_NONCE.as_bytes(), false, &tlv(4, value))
}
fn tbs(entries: &[Vec<u8>], requestor: Option<Vec<u8>>, extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut fields = Vec::new();
    if let Some(name) = requestor {
        fields.push(tlv(0xa1, &name));
    }
    fields.push(seq(entries));
    if !extensions.is_empty() {
        fields.push(tlv(0xa2, &seq(extensions)));
    }
    seq(&fields)
}
fn signed(tbs: &[u8], key: &SigningKey, certificate: Option<&[u8]>) -> Vec<u8> {
    let signature: Signature = key.sign(tbs);
    let mut fields = vec![sig_algorithm(), bits(signature.to_der().as_bytes())];
    if let Some(certificate) = certificate {
        fields.push(tlv(0xa0, &tlv(48, certificate)));
    }
    seq(&[tbs.to_vec(), tlv(0xa0, &seq(&fields))])
}
fn response(key: &SigningKey, ids: &[Vec<u8>], nonce_value: Option<&[u8]>) -> Vec<u8> {
    let time = tlv(24, b"20261012120000Z");
    let singles: Vec<_> = ids
        .iter()
        .map(|id| seq(&[id.clone(), tlv(0x80, &[]), time.clone()]))
        .collect();
    let mut fields = vec![tlv(0xa1, &name(b"A")), time, seq(&singles)];
    if let Some(value) = nonce_value {
        fields.push(tlv(0xa1, &seq(&[nonce(value)])));
    }
    let tbs = seq(&fields);
    let signature: Signature = key.sign(&tbs);
    seq(&[tbs, sig_algorithm(), bits(signature.to_der().as_bytes())])
}

#[derive(Default)]
struct Provider {
    calls: Cell<usize>,
    comparisons: Cell<usize>,
    fail: bool,
    unsupported: bool,
    no_width: bool,
}
impl<W: Work> Verify<W> for Provider {
    type Error = Error;
    fn verify(
        &self,
        id: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        signed: &[u8],
        signature: SignatureValue<'_>,
        work: &W,
    ) -> Result<Verified, Error> {
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            return Err(Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                "oracle",
                91,
            ));
        }
        if self.unsupported {
            return Ok(Verified::Unsupported);
        }
        let source = signature.execution_in(work);
        let work = &source;
        signature::with_algorithm(*id, work, |algorithm| {
            if !matches!(algorithm, Some(Algorithm::Ecdsa(Hash::Sha256))) {
                return Ok(Verified::Unsupported);
            }
            let ec = structured_pkix::key::ec::read(key, work)?;
            let backend = VerifyingKey::from_sec1_bytes(ec.as_bytes()).unwrap();
            let pair = DssValue::read(&mut signature.reader_in(work)?, "request.ecdsa")?;
            let scalar = |value: structured_asn1::Integer<'_>| {
                let raw = value.as_bytes();
                let raw = if raw[0] == 0 { &raw[1..] } else { raw };
                assert!(!value.is_negative() && raw.len() <= 32);
                work.charge_work((32 + raw.len()) as u64).unwrap();
                let mut result = [0; 32];
                result[32 - raw.len()..].copy_from_slice(raw);
                result
            };
            let signature = Signature::from_scalars(scalar(pair.r()), scalar(pair.s())).unwrap();
            work.charge_work(signed.len() as u64).unwrap();
            Ok(if backend.verify(signed, &signature).is_ok() {
                Verified::Yes
            } else {
                Verified::No
            })
        })?
    }
}
impl Digest<'_> for Provider {
    type Identity = Hash;
    type State = ();
    type Output = [u8; 20];
    type Error = &'static str;
    fn width(&self, algorithm: &Hash) -> Option<usize> {
        if self.no_width {
            None
        } else {
            Some(algorithm.width())
        }
    }
    fn compare<W: Work>(
        &self,
        left: &Hash,
        right: &Hash,
        work: &W,
    ) -> Result<Ordering, &'static str> {
        self.comparisons.set(self.comparisons.get() + 1);
        if self.fail {
            return Err("comparison refusal");
        }
        work.charge_work(1).map_err(|_| "comparison work")?;
        Ok(if left == right {
            Ordering::Equal
        } else {
            Ordering::Less
        })
    }
    fn start<W: Work>(&self, _: &Hash, _: &W) -> Result<Resolution<()>, &'static str> {
        panic!("wire binding must not hash")
    }
    fn update<W: Work>(&self, (): &mut (), _: &[u8], _: &W) -> Result<(), &'static str> {
        panic!("wire binding must not hash")
    }
    fn finish<W: Work>(&self, (): (), _: &W) -> Result<[u8; 20], &'static str> {
        panic!("wire binding must not hash")
    }
    fn matches<W: Work>(
        &self,
        _: &Hash,
        _: &[u8; 20],
        _: &[u8],
        _: &W,
    ) -> Result<bool, &'static str> {
        panic!("wire binding must not hash")
    }
}
impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Hash) -> Option<Hash> {
        if self.unsupported {
            None
        } else {
            Some(algorithm)
        }
    }
}

#[test]
fn original_signed_request_verifies_native_p256_and_name_separately() {
    // Actual arithmetic must consume the original TBS, key and DER signature;
    // a valid signature over a different requester name is not a name match.
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let cert_bytes = cert(&key, b"A", true);
    let source = Parser::der(ample());
    let certificate = Certificate::read(&source, &cert_bytes, 900).unwrap();
    let provider = Provider::default();
    for (requestor, expected) in [
        (tlv(0xa4, &name(b"A")), RequestorBinding::Matches),
        (tlv(0x82, b"example.com"), RequestorBinding::Matches),
        (tlv(0xa4, &name(b"B")), RequestorBinding::Differs),
    ] {
        let tbs = tbs(&[entry(1), entry(2)], Some(requestor), &[nonce(&[7; 32])]);
        let bytes = signed(&tbs, &key, Some(&cert_bytes));
        let request = OcspRequest::read(&source, &bytes, 400).unwrap();
        assert_eq!(request.as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(request.signed_bytes(), tbs);
        assert_eq!(request.requests().len(), 2);
        assert_eq!(request.signature().unwrap().certificates().len(), 1);
        let before = source.memory().used();
        let outcome = request
            .authenticate_signature(
                &certificate,
                WorkingKey::standing(certificate.tbs().public_key()),
                &provider,
                &ample(),
            )
            .unwrap();
        let RequestAuthentication::Signed(proof) = outcome else {
            panic!("actual signature rejected");
        };
        assert!(std::ptr::eq(proof.request(), &raw const request));
        assert!(std::ptr::eq(proof.signer(), &raw const certificate));
        assert_eq!(proof.requestor(), expected);
        assert_eq!(source.memory().used(), before);
    }
    assert_eq!(provider.calls.get(), 3);
}

#[test]
fn complete_batch_preserves_nonce_original_entries_and_response_duplicates() {
    // Batch binding covers every request in wire order, including repeated
    // requests, and never chooses an arbitrary duplicate response assertion.
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let cert_bytes = cert(&key, b"A", false);
    let csource = Parser::der(ample());
    let certificate = Certificate::read(&csource, &cert_bytes, 100).unwrap();
    let qbytes = seq(&[tbs(
        &[entry(1), entry(2), entry(3), entry(1)],
        None,
        &[nonce(&[7; 32])],
    )]);
    let qsource = Parser::der(ample());
    let request = OcspRequest::read(&qsource, &qbytes, 400).unwrap();
    let rbytes = response(
        &key,
        &[
            id(&[1], hash_algorithm(true), 20),
            id(&[2], hash_algorithm(false), 20),
            id(&[2], hash_algorithm(true), 20),
        ],
        Some(&[7; 32]),
    );
    let rsource = Parser::der(ample());
    let mut reader = rsource.read(&rbytes, 700).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let response = BasicResponse::read_element(&reader, &element).unwrap();
    let provider = Provider::default();
    let SignatureAuthentication::Signed(authenticated) = response
        .authenticate_signature(
            &certificate,
            WorkingKey::standing(certificate.tbs().public_key()),
            &provider,
            &provider,
            &ample(),
        )
        .unwrap()
    else {
        panic!("response signature failed");
    };
    let current = ample();
    let before = current.used();
    let bound = request
        .bind_response(authenticated, &provider, &current)
        .unwrap();
    assert!(std::ptr::eq(bound.request(), &raw const request));
    assert!(std::ptr::eq(
        bound.response().response(),
        &raw const response
    ));
    assert_eq!(bound.nonce(), NonceBinding::Matches);
    assert!(matches!(
        bound.extensions(),
        ExtensionProcessing::Understood
    ));
    assert_eq!(bound.lookups().len(), 4);
    assert!(matches!(bound.lookups()[0].lookup(), Lookup::Found(_)));
    assert!(matches!(
        bound.lookups()[1].lookup(),
        Lookup::Ambiguous { .. }
    ));
    assert!(matches!(bound.lookups()[2].lookup(), Lookup::Missing));
    assert!(matches!(bound.lookups()[3].lookup(), Lookup::Found(_)));
    for (actual, original) in bound.lookups().iter().zip(request.requests()) {
        assert!(std::ptr::eq(actual.request(), original));
        assert!(matches!(
            actual.extensions(),
            ExtensionProcessing::Understood
        ));
    }
    assert!(current.used() > before);
    drop(bound);
    assert_eq!(current.used(), before);
    let failing = Provider {
        fail: true,
        ..Provider::default()
    };
    assert!(matches!(
        request.bind_response(authenticated, &failing, &current),
        Err(CallbackError::Callback("comparison refusal"))
    ));
    assert_eq!(current.used(), before);
    let stopped = memory(0, 1_000_000);
    let comparisons = provider.comparisons.get();
    assert!(
        matches!(request.bind_response(authenticated, &provider, &stopped), Err(CallbackError::Processing(error)) if error.is_resource())
    );
    assert_eq!(stopped.used(), 0);
    // A complete batch result needs storage before comparison callbacks run;
    // failure to retain it must not perform otherwise unnecessary callbacks.
    assert_eq!(provider.comparisons.get(), comparisons);
}

#[test]
fn wire_identity_distinguishes_algorithms_parameters_widths_serials_and_hashes() {
    // Known-width malformed hashes and unknown/invalid parameters cannot
    // become matches merely because their carried bytes are identical.
    let good = seq(&[tbs(&[entry(1)], None, &[])]);
    let source = Parser::der(ample());
    let request = OcspRequest::read(&source, &good, 400).unwrap();
    let original = request.requests()[0].id();
    let provider = Provider::default();
    let cases = [
        (id(&[1], hash_algorithm(true), 20), CertMatch::Matches),
        (id(&[2], hash_algorithm(false), 20), CertMatch::Differs),
        (
            id(&[1], hash_algorithm(false), 19),
            CertMatch::MalformedHashWidth,
        ),
        (
            id(&[1], seq(&[tlv(6, oid::SHA1.as_bytes()), tlv(4, &[])]), 20),
            CertMatch::MalformedHashAlgorithm,
        ),
        (
            id(&[1], seq(&[tlv(6, &[42, 3, 4])]), 20),
            CertMatch::UnsupportedHash,
        ),
        (
            id(&[1], seq(&[tlv(6, oid::SHA256.as_bytes())]), 32),
            CertMatch::Differs,
        ),
    ];
    for (id, expected) in cases {
        let bytes = seq(&[tbs(&[seq(&[id])], None, &[])]);
        let other = OcspRequest::read(&source, &bytes, 700).unwrap();
        assert_eq!(
            original
                .matches_id(&other.requests()[0].id(), &provider, &ample())
                .unwrap(),
            expected
        );
        assert_eq!(
            other.requests()[0]
                .id()
                .matches_id(&original, &provider, &ample())
                .unwrap(),
            expected
        );
    }
    let unsupported = Provider {
        unsupported: true,
        ..Provider::default()
    };
    assert_eq!(
        original
            .matches_id(&original, &unsupported, &ample())
            .unwrap(),
        CertMatch::UnsupportedHash
    );
    // Protocol-defined SHA-1 widths remain known even when a generic provider
    // does not advertise output width metadata. Equal malformed hashes differ
    // from two well-formed hashes that happen to compare equal.
    let bytes = seq(&[tbs(
        &[seq(&[id(&[1], hash_algorithm(false), 19)])],
        None,
        &[],
    )]);
    let malformed = OcspRequest::read(&source, &bytes, 700).unwrap();
    let no_width = Provider {
        no_width: true,
        ..Provider::default()
    };
    let identity = malformed.requests()[0].id();
    assert_eq!(
        identity.matches_id(&identity, &no_width, &ample()).unwrap(),
        CertMatch::MalformedHashWidth
    );
}

#[test]
fn malformed_requests_refuse_default_empty_missing_name_duplicate_and_trailing_fields() {
    // DER defaults and exact explicit wrappers are schema, not provider policy;
    // malformed requests never reach a signature callback or a partial batch.
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let mut extra = seq(&[tbs(&[entry(1)], None, &[])]);
    extra.push(0);
    let cases = [
        seq(&[seq(&[tlv(0xa0, &[2, 1, 0]), seq(&[entry(1)])])]),
        seq(&[seq(&[tlv(0xa0, &[2, 1, 1]), seq(&[entry(1)])])]),
        seq(&[tbs(&[], None, &[])]),
        signed(&tbs(&[entry(1)], None, &[]), &key, None),
        seq(&[seq(&[
            seq(&[entry(1)]),
            tlv(0xa2, &seq(&[nonce(&[1]), nonce(&[1])])),
        ])]),
        seq(&[tbs(&[entry(1)], None, &[]), tlv(5, &[])]),
        seq(&[seq(&[seq(&[entry(1)]), tlv(0x82, &seq(&[nonce(&[1])]))])]),
        extra,
    ];
    for bytes in cases {
        let work = ample();
        let source = Parser::ber(work.clone());
        let before = work.used();
        assert!(OcspRequest::read(&source, &bytes, 400).is_err());
        assert_eq!(work.used(), before);
    }
    let source = Parser::ber(ample());
    let valid = tbs(&[entry(1)], None, &[]);
    let bytes = [&[48, 128][..], &valid, &[0, 0]].concat();
    assert!(
        matches!(OcspRequest::read(&source,&bytes,400),Err(error) if matches!(error.code(),ErrorCode::Encoding(_)))
    );
}

#[test]
fn nonce_and_critical_extension_scopes_are_explicit_and_source_funded() {
    // Legacy received nonces stay readable; new generation constraints are
    // distinct. Unknown critical requirements never turn into Understood.
    for length in [0, 1, 16, 32, 128, 129] {
        let bytes = seq(&[tbs(&[entry(1)], None, &[nonce(&vec![7; length])])]);
        let source = Parser::der(ample());
        let request = OcspRequest::read(&source, &bytes, 400).unwrap();
        if length == 0 || length > 128 {
            assert!(request.nonce(&ample()).is_err());
        } else {
            assert_eq!(
                request.nonce(&ample()).unwrap().unwrap().as_bytes(),
                vec![7; length]
            );
        }
        assert_eq!(
            RequestNonce::new(&vec![7; length]).is_some(),
            (32..=128).contains(&length)
        );
    }
    let bytes = seq(&[tbs(
        &[entry(1)],
        None,
        &[extension(&[42, 3, 4], true, &[5, 0]), nonce(&[7; 32])],
    )]);
    let source = Parser::der(ample());
    let request = OcspRequest::read(&source, &bytes, 400).unwrap();
    assert!(
        matches!(request.check_extensions(&ample()).unwrap(),ExtensionProcessing::Unsupported { kind,.. } if kind.as_bytes()==[42,3,4])
    );
    assert_eq!(
        request.nonce(&ample()).unwrap().unwrap().as_bytes(),
        &[7; 32]
    );
    let exhausted = memory(0, 0);
    assert!(matches!(request.nonce(&exhausted),Err(error) if error.is_resource()));
}

#[test]
fn signature_negative_unsupported_callback_and_wrong_key_are_distinct() {
    // Wrong actual keys are rejected before a callback, and opaque provider
    // errors remain terminal rather than becoming signature mismatches.
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let wrong = SigningKey::from_slice(&[4; 32]).unwrap();
    let cert_bytes = cert(&key, b"A", false);
    let wrong_bytes = cert(&wrong, b"A", false);
    let source = Parser::der(ample());
    let certificate = Certificate::read(&source, &cert_bytes, 100).unwrap();
    let other = Certificate::read(&source, &wrong_bytes, 900).unwrap();
    let bytes = signed(
        &tbs(&[entry(1)], Some(tlv(0xa4, &name(b"A"))), &[]),
        &key,
        None,
    );
    let request = OcspRequest::read(&source, &bytes, 400).unwrap();
    let provider = Provider::default();
    assert!(matches!(
        request
            .authenticate_signature(
                &certificate,
                WorkingKey::standing(other.tbs().public_key()),
                &provider,
                &ample()
            )
            .unwrap(),
        RequestAuthentication::Rejected(RequestSignatureFailure::KeyBinding)
    ));
    assert_eq!(provider.calls.get(), 0);
    let unsupported = Provider {
        unsupported: true,
        ..Provider::default()
    };
    assert!(matches!(
        request
            .authenticate_signature(
                &certificate,
                WorkingKey::standing(certificate.tbs().public_key()),
                &unsupported,
                &ample()
            )
            .unwrap(),
        RequestAuthentication::UnsupportedSignature
    ));
    let failure = Provider {
        fail: true,
        ..Provider::default()
    };
    assert!(
        matches!(request.authenticate_signature(&certificate,WorkingKey::standing(certificate.tbs().public_key()),&failure,&ample()),Err(CallbackError::Callback(error)) if error.offset()==91)
    );
    let mut changed = bytes.clone();
    let position = usize::try_from(request.requests()[0].span().start - 400).unwrap();
    changed[position + usize::try_from(request.requests()[0].span().length).unwrap() - 1] ^= 1;
    let changed = OcspRequest::read(&source, &changed, 400).unwrap();
    assert!(matches!(
        changed
            .authenticate_signature(
                &certificate,
                WorkingKey::standing(certificate.tbs().public_key()),
                &provider,
                &ample()
            )
            .unwrap(),
        RequestAuthentication::Rejected(RequestSignatureFailure::Signature)
    ));
    let unsigned = seq(&[tbs(&[entry(1)], None, &[])]);
    let unsigned = OcspRequest::read(&source, &unsigned, 1000).unwrap();
    let calls = provider.calls.get();
    assert!(matches!(
        unsigned
            .authenticate_signature(
                &certificate,
                WorkingKey::standing(certificate.tbs().public_key()),
                &provider,
                &ample()
            )
            .unwrap(),
        RequestAuthentication::Unsigned
    ));
    assert_eq!(provider.calls.get(), calls);
}

#[test]
fn retained_request_query_cannot_reset_original_or_current_limits() {
    // Fresh query accounts must not erase the producing parse ceiling. The
    // exact same refusal also holds when the current root, instead, is empty.
    let bytes = seq(&[tbs(&[entry(1)], None, &[nonce(&[7; 32])])]);
    let account = ample();
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 100_000,
            ..Limits::default()
        },
        account.clone(),
    );
    let request = OcspRequest::read(&source, &bytes, 400).unwrap();
    let reader = source.read(&[], 400).unwrap();
    let remaining = reader.execution().work_remaining();
    reader.execution().charge_work(remaining as u64).unwrap();
    assert!(matches!(request.nonce(&ample()),Err(error) if error.is_resource()));
    let other = Parser::der(ample());
    let request = OcspRequest::read(&other, &bytes, 400).unwrap();
    assert!(matches!(request.nonce(&memory(0,0)),Err(error) if error.is_resource()));
}

#[test]
fn catalogue_capacity_work_depth_and_late_failure_release_partial_storage() {
    // Attacker-controlled request/certificate catalogues have accounted
    // capacity. Depth and local work are enforced before a partial result.
    let bytes = seq(&[tbs(&vec![entry(1); 64], None, &[])]);
    for (capacity, limits) in [
        (0, Limits::default()),
        (
            1_000_000,
            Limits {
                max_depth: 2,
                ..Limits::default()
            },
        ),
        (
            1_000_000,
            Limits {
                max_work: 2000,
                ..Limits::default()
            },
        ),
    ] {
        let work = memory(capacity, 100_000_000);
        let source = Parser::new(Encoding::Der, limits, work.clone());
        let before = work.used();
        assert!(matches!(OcspRequest::read(&source,&bytes,400),Err(error) if error.is_resource()));
        assert_eq!(work.used(), before);
    }
    let mut bad = vec![entry(1); 64];
    bad.push(tlv(5, &[]));
    let bytes = seq(&[tbs(&bad, None, &[])]);
    let account = ample();
    let source = Parser::der(account.clone());
    let before = account.used();
    assert!(OcspRequest::read(&source, &bytes, 400).is_err());
    assert_eq!(account.used(), before);
}

#[test]
fn nonce_comparison_cannot_escape_the_original_response_ceiling_after_decode() {
    // Exactly enough source work to decode the nonce is insufficient to scan
    // it again for equality, even if a fresh current account has ample work.
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let bytes = response(
        &key,
        &[id(&[1], hash_algorithm(false), 20)],
        Some(&[7; 128]),
    );
    let source = Parser::der(ample());
    let mut reader = source.read(&bytes, 700).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let parsed = BasicResponse::read_element(&reader, &element).unwrap();
    let before = reader.execution().work_remaining();
    parsed.nonce(&ample()).unwrap();
    let decode_cost = before - reader.execution().work_remaining();
    let source = Parser::der(ample());
    let mut reader = source.read(&bytes, 700).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let parsed = BasicResponse::read_element(&reader, &element).unwrap();
    let remaining = reader.execution().work_remaining();
    reader
        .execution()
        .charge_work((remaining - decode_cost) as u64)
        .unwrap();
    assert!(
        matches!(parsed.bind_nonce(Some(RequestNonce::from_sent(&[7; 128]).unwrap()), &ample()),
        Err(error) if error.is_resource())
    );
}

#[test]
fn batch_binding_keeps_every_nonce_and_critical_scope_outcome() {
    // A response can match every CertID yet be unrelated to the actual nonce;
    // request-wide and per-entry critical demands must also remain visible.
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let cert_bytes = cert(&key, b"A", false);
    let source = Parser::der(ample());
    let certificate = Certificate::read(&source, &cert_bytes, 100).unwrap();
    let provider = Provider::default();
    let cases = [
        (None, None, NonceBinding::NotRequested),
        (Some(&[7; 32][..]), None, NonceBinding::Missing),
        (None, Some(&[7; 32][..]), NonceBinding::Unsolicited),
        (
            Some(&[7; 32][..]),
            Some(&[8; 32][..]),
            NonceBinding::Differs,
        ),
    ];
    for (sent, received, expected) in cases {
        let single = seq(&[
            id(&[1], hash_algorithm(false), 20),
            tlv(0xa0, &seq(&[extension(&[42, 3, 5], true, &[5, 0])])),
        ]);
        let mut extensions = vec![extension(&[42, 3, 4], true, &[5, 0])];
        if let Some(sent) = sent {
            extensions.push(nonce(sent));
        }
        let bytes = seq(&[tbs(&[single], None, &extensions)]);
        let request = OcspRequest::read(&source, &bytes, 400).unwrap();
        let rbytes = response(&key, &[id(&[1], hash_algorithm(true), 20)], received);
        let mut reader = source.read(&rbytes, 700).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let response = BasicResponse::read_element(&reader, &element).unwrap();
        let SignatureAuthentication::Signed(signed) = response
            .authenticate_signature(
                &certificate,
                WorkingKey::standing(certificate.tbs().public_key()),
                &provider,
                &provider,
                &ample(),
            )
            .unwrap()
        else {
            panic!("native fixture signature");
        };
        let bound = {
            let query = ample();
            request.bind_response(signed, &provider, &query).unwrap()
        };
        assert_eq!(bound.nonce(), expected);
        assert!(
            matches!(bound.extensions(),ExtensionProcessing::Unsupported { kind,.. } if kind.as_bytes()==[42,3,4])
        );
        assert!(
            matches!(bound.lookups()[0].extensions(),ExtensionProcessing::Unsupported { kind,.. } if kind.as_bytes()==[42,3,5])
        );
        assert!(matches!(bound.lookups()[0].lookup(), Lookup::Found(_)));
    }
}

#[test]
fn signature_query_keeps_independent_signer_and_current_source_limits() {
    // A retained signer cannot borrow unlimited work from a fresh request
    // operation; an exhausted current operation cannot invoke the verifier.
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let cert_bytes = cert(&key, b"A", false);
    let cert_source = Parser::der(ample());
    let certificate = Certificate::read(&cert_source, &cert_bytes, 900).unwrap();
    let bytes = signed(
        &tbs(&[entry(1)], Some(tlv(0xa4, &name(b"A"))), &[]),
        &key,
        None,
    );
    let request_source = Parser::der(ample());
    let request = OcspRequest::read(&request_source, &bytes, 400).unwrap();
    let provider = Provider::default();
    let key = WorkingKey::standing(certificate.tbs().public_key());
    assert!(
        matches!(request.authenticate_signature(&certificate,key,&provider,&memory(0,0)),
        Err(CallbackError::Processing(error)) if error.is_resource() && error.offset()==400)
    );
    let reader = cert_source.read(&[], 900).unwrap();
    reader
        .execution()
        .charge_work(reader.execution().work_remaining() as u64)
        .unwrap();
    assert!(
        matches!(request.authenticate_signature(&certificate,key,&provider,&ample()),
        Err(CallbackError::Processing(error)) if error.is_resource())
    );
    assert_eq!(provider.calls.get(), 0);
}
