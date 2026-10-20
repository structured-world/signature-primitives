//! `RustCrypto` is an independent test provider, never a production backend.

use crate::algorithm::digest::{Algorithm, AsnDigest};
use crate::fixtures::{
    CertificateParts, bits, boolean, context, extension, generalized_time, int, null, octets,
    oid as encoded_oid, seq, tlv,
};
use crate::{AlgorithmIdentifier, Certificate, crl, ocsp, oid, path};
use core::cell::Cell;
use p256::ecdsa::signature::{Signer, Verifier};
use sha1::Digest as _;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{Memory, MemoryError, Work};
use structured_asn1::{BitString, Oid, Parser};

const ECDSA_SHA256: Oid<'static> = Oid::from_bytes(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2]);
const PRIME256V1: Oid<'static> = Oid::from_bytes(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7]);
const SHA1: Oid<'static> = Oid::from_bytes(&[0x2b, 0x0e, 3, 2, 0x1a]);
const CURVE_PARAMETERS: &[u8] = &[6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];

fn signing(seed: u8) -> p256::ecdsa::SigningKey {
    let mut scalar = [1; 32];
    scalar[31] = seed;
    p256::ecdsa::SigningKey::from_slice(&scalar).unwrap()
}
fn public(key: &p256::ecdsa::SigningKey) -> alloc::vec::Vec<u8> {
    seq(&[
        seq(&[encoded_oid(oid::EC_PUBLIC_KEY), encoded_oid(PRIME256V1)]),
        bits(key.verifying_key().to_sec1_point(false).as_ref()),
    ])
}
fn signed(signed: alloc::vec::Vec<u8>, key: &p256::ecdsa::SigningKey) -> alloc::vec::Vec<u8> {
    let signature: p256::ecdsa::Signature = key.sign(&signed);
    seq(&[
        signed,
        seq(&[encoded_oid(ECDSA_SHA256)]),
        bits(signature.to_der().as_bytes()),
    ])
}
fn certificate(
    mut parts: CertificateParts,
    key: &p256::ecdsa::SigningKey,
    issuer: &p256::ecdsa::SigningKey,
) -> alloc::vec::Vec<u8> {
    parts.inner_algorithm = seq(&[encoded_oid(ECDSA_SHA256)]);
    parts.outer_algorithm = parts.inner_algorithm.clone();
    parts.key = public(key);
    signed(parts.tbs(), issuer)
}

struct Provider {
    signatures: Cell<usize>,
    hashes: Cell<usize>,
}
impl Provider {
    fn new() -> Self {
        Self {
            signatures: Cell::new(0),
            hashes: Cell::new(0),
        }
    }
}
impl path::Verify for Provider {
    type Error = MemoryError;
    fn verify(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        key: path::WorkingKey<'_>,
        data: &[u8],
        signature: BitString<'_>,
        execution: &Memory,
    ) -> core::result::Result<path::Verified, Self::Error> {
        // Test admission is not a claim that all third-party provider internals
        // have been audited. Production adapters must qualify their own engine.
        execution.charge_work(
            u64::try_from(data.len())
                .map_err(|_| MemoryError::WorkExceeded)?
                .checked_add(4096)
                .ok_or(MemoryError::WorkExceeded)?,
        )?;
        if algorithm.algorithm() != ECDSA_SHA256
            || key.key().algorithm().algorithm() != oid::EC_PUBLIC_KEY
            || key.parameters() != Some(CURVE_PARAMETERS)
        {
            return Ok(path::Verified::Unsupported);
        }
        let (Some(point), Some(value)) = (key.key().key_octets(), signature.octets()) else {
            return Ok(path::Verified::No);
        };
        let (Ok(verifier), Ok(signature)) = (
            p256::ecdsa::VerifyingKey::from_sec1_bytes(point),
            p256::ecdsa::Signature::from_der(value),
        ) else {
            return Ok(path::Verified::No);
        };
        self.signatures.set(self.signatures.get() + 1);
        Ok(if verifier.verify(data, &signature).is_ok() {
            path::Verified::Yes
        } else {
            path::Verified::No
        })
    }
}
impl structured_asn1::digest::Digest<'_> for Provider {
    type Identity = ();
    type State = sha1::Sha1;
    type Output = alloc::vec::Vec<u8>;
    type Error = MemoryError;
    fn width(&self, (): &()) -> Option<usize> {
        Some(20)
    }
    fn compare<W: Work>(
        &self,
        (): &(),
        (): &(),
        _: &W,
    ) -> Result<core::cmp::Ordering, MemoryError> {
        Ok(core::cmp::Ordering::Equal)
    }
    fn start<W: Work>(
        &self,
        (): &(),
        execution: &W,
    ) -> Result<Resolution<sha1::Sha1>, MemoryError> {
        execution.charge_work(16)?;
        Ok(Resolution::Supported(sha1::Sha1::new()))
    }
    fn update<W: Work>(
        &self,
        state: &mut sha1::Sha1,
        input: &[u8],
        execution: &W,
    ) -> Result<(), MemoryError> {
        execution.charge_work(
            u64::try_from(input.len())
                .map_err(|_| MemoryError::WorkExceeded)?
                .checked_add(128)
                .ok_or(MemoryError::WorkExceeded)?,
        )?;
        self.hashes.set(self.hashes.get() + 1);
        state.update(input);
        Ok(())
    }
    fn finish<W: Work>(
        &self,
        state: sha1::Sha1,
        _: &W,
    ) -> Result<alloc::vec::Vec<u8>, MemoryError> {
        Ok(state.finalize().to_vec())
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &alloc::vec::Vec<u8>,
        expected: &[u8],
        execution: &W,
    ) -> Result<bool, MemoryError> {
        execution.charge_work(expected.len() as u64)?;
        Ok(output.as_slice() == expected)
    }
}
impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<()> {
        (algorithm == Algorithm::Sha1).then_some(())
    }
}

#[test]
fn real_crl_signature_keeps_tbs_and_rejects_corruption_and_wrong_issuer_key() {
    // A separate crypto implementation authenticates the exact retained TBS;
    // tampering and a same-named different signing key must be rejected.
    let key = signing(1);
    let parts = CertificateParts::default();
    let issuer = CertificateParts {
        subject: parts.issuer.clone(),
        extensions: Some(seq(&[
            extension(oid::BASIC_CONSTRAINTS, true, &seq(&[boolean(true)])),
            extension(oid::KEY_USAGE, true, &tlv(3, &[1, 0x86])),
        ])),
        ..CertificateParts::default()
    };
    let issuer_bytes = certificate(issuer, &key, &key);
    let tbs = seq(&[
        seq(&[encoded_oid(ECDSA_SHA256)]),
        parts.issuer,
        crate::fixtures::utc_time("250101000000Z"),
        crate::fixtures::utc_time("250102000000Z"),
    ]);
    let bytes = signed(tbs.clone(), &key);
    let execution = crate::fixtures::memory();
    let parser = Parser::der(execution.clone());
    let issuer = Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let parsed = crl::CertificateList::read(&parser, &bytes, 700).unwrap();
    assert_eq!(parsed.signed_bytes(), tbs);
    let provider = Provider::new();
    assert!(matches!(
        parsed
            .authenticate(
                &issuer,
                path::WorkingKey::standing(issuer.tbs().public_key()),
                &provider,
                &execution
            )
            .unwrap(),
        crl::Authentication::Authenticated(_)
    ));
    assert_eq!(provider.signatures.get(), 1);
    let mut corrupted = bytes.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let parsed = crl::CertificateList::read(&parser, &corrupted, 700).unwrap();
    assert!(matches!(
        parsed
            .authenticate(
                &issuer,
                path::WorkingKey::standing(issuer.tbs().public_key()),
                &provider,
                &execution
            )
            .unwrap(),
        crl::Authentication::Rejected(crl::AuthenticationFailure::Signature)
    ));
    let other_key = signing(2);
    let parts = CertificateParts::default();
    let other_bytes = certificate(
        CertificateParts {
            subject: parts.issuer,
            extensions: Some(seq(&[extension(oid::KEY_USAGE, true, &tlv(3, &[1, 0x86]))])),
            ..CertificateParts::default()
        },
        &other_key,
        &other_key,
    );
    let other = Certificate::read(&parser, &other_bytes, 1000).unwrap();
    let parsed = crl::CertificateList::read(&parser, &bytes, 700).unwrap();
    assert!(matches!(
        parsed
            .authenticate(
                &other,
                path::WorkingKey::standing(other.tbs().public_key()),
                &provider,
                &execution
            )
            .unwrap(),
        crl::Authentication::Rejected(crl::AuthenticationFailure::Signature)
    ));
}

fn response_data(
    issuer_key: &p256::ecdsa::SigningKey,
    responder_key: &p256::ecdsa::SigningKey,
    target: &CertificateParts,
) -> alloc::vec::Vec<u8> {
    response_data_with(issuer_key, responder_key, target, &tlv(0x80, &[]), &[], &[])
}

fn response_data_with(
    issuer_key: &p256::ecdsa::SigningKey,
    responder_key: &p256::ecdsa::SigningKey,
    target: &CertificateParts,
    status: &[u8],
    single_extensions: &[alloc::vec::Vec<u8>],
    response_extensions: &[alloc::vec::Vec<u8>],
) -> alloc::vec::Vec<u8> {
    let point = issuer_key.verifying_key().to_sec1_point(false);
    let id = seq(&[
        seq(&[encoded_oid(SHA1), null()]),
        octets(&sha1::Sha1::digest(&target.issuer)),
        octets(&sha1::Sha1::digest(point.as_ref())),
        target.serial.clone(),
    ]);
    let timestamp = generalized_time("20250101000000Z");
    let mut assertion = alloc::vec![
        id,
        status.to_vec(),
        timestamp.clone(),
        context(0, &[generalized_time("20250102000000Z")]),
    ];
    if !single_extensions.is_empty() {
        assertion.push(context(1, &[seq(single_extensions)]));
    }
    let mut data = alloc::vec![
        context(
            2,
            &[octets(&sha1::Sha1::digest(
                responder_key.verifying_key().to_sec1_point(false).as_ref(),
            ))],
        ),
        timestamp,
        seq(&[seq(&assertion)]),
    ];
    if !response_extensions.is_empty() {
        data.push(context(1, &[seq(response_extensions)]));
    }
    seq(&data)
}

fn envelope(basic: &[u8]) -> alloc::vec::Vec<u8> {
    seq(&[
        tlv(10, &[0]),
        context(0, &[seq(&[encoded_oid(oid::OCSP_BASIC), octets(basic)])]),
    ])
}
fn response<'a>(parser: &'a Parser, bytes: &'a [u8]) -> ocsp::BasicResponse<'a> {
    let ocsp::Response::Successful(payload) = ocsp::Response::read(parser, bytes, 700).unwrap()
    else {
        panic!("fixture requires successful response");
    };
    payload.into_basic(parser.memory()).unwrap().unwrap()
}

fn assert_current_good(
    source: &ocsp::ScopedResponse<'_, '_>,
    target: &Certificate<'_>,
    provider: &Provider,
    execution: &Memory,
) {
    let start = source.signed().response().responses()[0]
        .this_update()
        .instant();
    let utc = crate::temporal::LeapTable::new(start.seconds() - 10, start.seconds() + 100_000, &[])
        .unwrap();
    let request = ocsp::Request {
        target,
        nonce: None,
        intended_signer: Some(source.signed().signer()),
    };
    let time = ocsp::Evaluation {
        now: start.into(),
        utc: &utc,
        execution,
    };
    let ocsp::TargetEvidence::Evidence(evidence) =
        source.evaluate(&request, &time, provider).unwrap()
    else {
        panic!("real target evidence rejected");
    };
    assert_eq!(evidence.assertion().status(), ocsp::Status::Good);
    assert_eq!(evidence.window(), ocsp::UpdateWindow::Within);
    assert_eq!(evidence.recipient(), ocsp::RecipientBinding::Matches);
}

#[test]
fn real_ocsp_sha1_identity_and_signature_are_scoped_to_actual_issuer() {
    // Independent SHA1 and P256 providers exercise mandatory byKey identity,
    // exact ResponseData signing, request binding and time facts end to end.
    let key = signing(3);
    let target_parts = CertificateParts {
        serial: int(7),
        extensions: None,
        ..CertificateParts::default()
    };
    let issuer_bytes = certificate(
        CertificateParts {
            subject: target_parts.issuer.clone(),
            ..CertificateParts::default()
        },
        &key,
        &key,
    );
    let target_bytes = certificate(
        CertificateParts {
            serial: target_parts.serial.clone(),
            extensions: None,
            ..CertificateParts::default()
        },
        &signing(4),
        &key,
    );
    let data = response_data(&key, &key, &target_parts);
    let bytes = envelope(&signed(data.clone(), &key));
    let execution = crate::fixtures::memory();
    let parser = Parser::der(execution.clone());
    let issuer = Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let target = Certificate::read(&parser, &target_bytes, 300).unwrap();
    let parsed = response(&parser, &bytes);
    assert_eq!(parsed.signed_bytes(), data);
    let provider = Provider::new();
    let working = path::WorkingKey::standing(issuer.tbs().public_key());
    let ocsp::SignatureAuthentication::Signed(proof) = parsed
        .authenticate_signature(&issuer, working, &provider, &provider, &execution)
        .unwrap()
    else {
        panic!("real response signature failed");
    };
    let ocsp::AuthorityBinding::Bound(scoped) =
        proof.bind_issuer(&issuer, working, &execution).unwrap()
    else {
        panic!("actual issuer scope failed");
    };
    let instant = parsed.responses()[0].this_update().instant();
    let utc =
        crate::temporal::LeapTable::new(instant.seconds() - 10, instant.seconds() + 100_000, &[])
            .unwrap();
    let request = ocsp::Request {
        target: &target,
        nonce: None,
        intended_signer: Some(&issuer),
    };
    let time = ocsp::Evaluation {
        now: instant.into(),
        utc: &utc,
        execution: &execution,
    };
    let ocsp::TargetEvidence::Evidence(evidence) =
        scoped.evaluate(&request, &time, &provider).unwrap()
    else {
        panic!("real target evidence failed");
    };
    assert_eq!(evidence.assertion().status(), ocsp::Status::Good);
    assert_eq!(evidence.window(), ocsp::UpdateWindow::Within);
    assert_eq!(evidence.recipient(), ocsp::RecipientBinding::Matches);
    assert_eq!(provider.signatures.get(), 1);
    assert_eq!(provider.hashes.get(), 3);
    let mut corrupted = bytes.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let parsed = response(&parser, &corrupted);
    assert!(matches!(
        parsed
            .authenticate_signature(&issuer, working, &provider, &provider, &execution)
            .unwrap(),
        ocsp::SignatureAuthentication::Rejected(ocsp::SignatureFailure::Signature)
    ));
}

#[test]
fn real_delegate_authority_cannot_be_substituted_or_inferred_from_signature() {
    // Two independently signed delegates share purpose and issuer. Authority
    // facts for one cannot authorize the other's otherwise valid signature.
    let issuer_key = signing(5);
    let responder_key = signing(6);
    let other_key = signing(7);
    let target = CertificateParts::default();
    let issuer_bytes = certificate(
        CertificateParts {
            subject: target.issuer.clone(),
            ..CertificateParts::default()
        },
        &issuer_key,
        &issuer_key,
    );
    let delegate = |serial| CertificateParts {
        serial: int(serial),
        extensions: Some(seq(&[
            extension(
                oid::EXT_KEY_USAGE,
                false,
                &seq(&[encoded_oid(oid::OCSP_SIGNING)]),
            ),
            extension(oid::KEY_USAGE, true, &tlv(3, &[7, 0x80])),
        ])),
        ..CertificateParts::default()
    };
    let responder_bytes = certificate(delegate(8), &responder_key, &issuer_key);
    let other_bytes = certificate(delegate(9), &other_key, &issuer_key);
    let target_bytes = certificate(CertificateParts::default(), &signing(8), &issuer_key);
    let data = response_data(&issuer_key, &responder_key, &target);
    let bytes = envelope(&signed(data, &responder_key));
    let execution = crate::fixtures::memory();
    let parser = Parser::der(execution.clone());
    let issuer = Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let responder = Certificate::read(&parser, &responder_bytes, 300).unwrap();
    let other = Certificate::read(&parser, &other_bytes, 500).unwrap();
    let target = Certificate::read(&parser, &target_bytes, 600).unwrap();
    let parsed = response(&parser, &bytes);
    let provider = Provider::new();
    let context = path::ValidationContext {
        execution: &execution,
        interval: path::Interval::at(1_735_689_600),
        policy: path::Policy::default(),
        bounds: path::ValidationBounds::default(),
        verifier: &provider,
        watch: &(),
        recognizer: &(),
    };
    let issuing = path::WorkingKey::standing(issuer.tbs().public_key());
    let ocsp::Delegation::Accepted(facts) =
        ocsp::check_delegate(&responder, &issuer, issuing, &context).unwrap()
    else {
        panic!("real direct delegation rejected");
    };
    let ocsp::Delegation::Accepted(other_facts) =
        ocsp::check_delegate(&other, &issuer, issuing, &context).unwrap()
    else {
        panic!("second real delegation rejected");
    };
    let ocsp::SignatureAuthentication::Signed(signed) = parsed
        .authenticate_signature(&responder, facts.key(), &provider, &provider, &execution)
        .unwrap()
    else {
        panic!("real delegate response rejected");
    };
    assert!(matches!(
        signed.bind_issuer(&issuer, issuing, &execution).unwrap(),
        ocsp::AuthorityBinding::Rejected(ocsp::AuthorityFailure::Signer)
    ));
    assert!(matches!(
        signed.bind_delegate(other_facts, &execution).unwrap(),
        ocsp::AuthorityBinding::Rejected(ocsp::AuthorityFailure::Signer)
    ));
    let ocsp::AuthorityBinding::Bound(scoped) = signed.bind_delegate(facts, &execution).unwrap()
    else {
        panic!("actual delegate facts rejected");
    };
    assert_eq!(
        scoped.source(),
        ocsp::AuthoritySource::Delegate {
            revocation: ocsp::ResponderRevocation::Unresolved
        }
    );
    assert!(core::ptr::eq(scoped.issuer(), &raw const issuer));
    assert_current_good(&scoped, &target, &provider, &execution);
    assert_eq!(
        signed.trust_for_issuer(&issuer).source(),
        ocsp::AuthoritySource::Configured
    );
    assert_eq!(provider.signatures.get(), 3);
    let unfunded = Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 0),
    ));
    assert!(
        signed
            .bind_delegate(facts, &unfunded)
            .unwrap_err()
            .is_resource()
    );
    assert_eq!(provider.signatures.get(), 3);
}

#[test]
fn evaluated_evidence_carries_not_issued_status_and_the_archive_cutoff() {
    // The authenticated evaluation is where a consumer reads status: it must
    // report the RFC6960 §2.2 non-issued answer and the §4.4.4 cutoff it
    // already decoded, not the assertion's bare hold or nothing.
    let key = signing(3);
    let target_parts = CertificateParts {
        serial: int(7),
        extensions: None,
        ..CertificateParts::default()
    };
    let issuer_bytes = certificate(
        CertificateParts {
            subject: target_parts.issuer.clone(),
            ..CertificateParts::default()
        },
        &key,
        &key,
    );
    let target_bytes = certificate(
        CertificateParts {
            serial: target_parts.serial.clone(),
            extensions: None,
            ..CertificateParts::default()
        },
        &signing(4),
        &key,
    );
    let hold = context(
        1,
        &[
            generalized_time("19700101000000Z"),
            context(0, &[tlv(10, &[6])]),
        ],
    );
    let cutoff = extension(
        oid::OCSP_ARCHIVE_CUTOFF,
        false,
        &generalized_time("20190101000000Z"),
    );
    let extended = extension(oid::OCSP_EXTENDED_REVOKE, false, &null());
    for (response_extensions, not_issued) in [(alloc::vec![extended], true), (alloc::vec![], false)]
    {
        let data = response_data_with(
            &key,
            &key,
            &target_parts,
            &hold,
            core::slice::from_ref(&cutoff),
            &response_extensions,
        );
        let bytes = envelope(&signed(data, &key));
        let execution = crate::fixtures::memory();
        let parser = Parser::der(execution.clone());
        let issuer = Certificate::read(&parser, &issuer_bytes, 100).unwrap();
        let target = Certificate::read(&parser, &target_bytes, 300).unwrap();
        let parsed = response(&parser, &bytes);
        let provider = Provider::new();
        let working = path::WorkingKey::standing(issuer.tbs().public_key());
        let ocsp::SignatureAuthentication::Signed(proof) = parsed
            .authenticate_signature(&issuer, working, &provider, &provider, &execution)
            .unwrap()
        else {
            panic!("real response signature failed");
        };
        let ocsp::AuthorityBinding::Bound(scoped) =
            proof.bind_issuer(&issuer, working, &execution).unwrap()
        else {
            panic!("actual issuer scope failed");
        };
        let instant = parsed.responses()[0].this_update().instant();
        let utc = crate::temporal::LeapTable::new(-10, instant.seconds() + 100_000, &[]).unwrap();
        let request = ocsp::Request {
            target: &target,
            nonce: None,
            intended_signer: Some(&issuer),
        };
        let time = ocsp::Evaluation {
            now: instant.into(),
            utc: &utc,
            execution: &execution,
        };
        let ocsp::TargetEvidence::Evidence(evidence) =
            scoped.evaluate(&request, &time, &provider).unwrap()
        else {
            panic!("real target evidence failed");
        };
        if not_issued {
            assert_eq!(evidence.status(), ocsp::Status::NotIssued);
        } else {
            assert!(matches!(
                evidence.status(),
                ocsp::Status::Revoked {
                    time,
                    reason: Some(crl::Reason::CertificateHold),
                } if time.seconds() == 0
            ));
        }
        assert_eq!(
            evidence.archive_cutoff().map(crate::Time::seconds),
            Some(1_546_300_800)
        );
    }
}
