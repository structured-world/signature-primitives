//! Real signed OCSP evidence for original checked AC profiles.
use super::{ac_bytes, accepted, entity, ext, memory, name, read_ac, seq, tlv, validity};
use core::{cell::Cell, cmp::Ordering};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{Memory, MemoryError, Work};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_cms::attribute_certificate::validation::Profile;
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
use structured_pkix::ocsp::*;
use structured_pkix::path::{self, Verified, Verify, WorkingKey};
use structured_pkix::revocation::RevocationTarget;
use structured_pkix::signature::SignatureValue;
use structured_pkix::temporal::LeapTable;
use structured_pkix::{Certificate, oid};

fn ed() -> Vec<u8> {
    seq(&[&tlv(6, oid::ED25519.as_bytes())])
}
fn alg() -> Vec<u8> {
    seq(&[&tlv(6, oid::SHA256.as_bytes())])
}
fn pkc(key: &SigningKey, subject: &[u8], parent: &SigningKey, delegate: bool) -> Vec<u8> {
    let spki = seq(&[
        &ed(),
        &tlv(3, &[&[0][..], &key.verifying_key().to_bytes()].concat()),
    ]);
    let mut extensions = vec![ext(oid::KEY_USAGE, &[3, 2, 7, 128], true)];
    if delegate {
        extensions.push(ext(
            oid::EXT_KEY_USAGE,
            &seq(&[&tlv(6, oid::OCSP_SIGNING.as_bytes())]),
            true,
        ));
    }
    let extensions = tlv(
        163,
        &seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>()),
    );
    let data = seq(&[
        &[160, 3, 2, 1, 2],
        &[2, 1, 7],
        &ed(),
        &name(b"Authority"),
        &validity(),
        &name(subject),
        &spki,
        &extensions,
    ]);
    seq(&[
        &data,
        &ed(),
        &tlv(3, &[&[0][..], &parent.sign(&data).to_bytes()].concat()),
    ])
}

struct Crypto {
    hashes: Cell<usize>,
    signatures: Cell<usize>,
    failure: Cell<bool>,
}
impl Digest<'_> for Crypto {
    type Identity = Algorithm;
    type State = Sha256;
    type Output = [u8; 32];
    type Error = MemoryError;
    fn width(&self, a: &Algorithm) -> Option<usize> {
        Some(a.width())
    }
    fn compare<W: Work>(
        &self,
        a: &Algorithm,
        b: &Algorithm,
        w: &W,
    ) -> Result<Ordering, MemoryError> {
        w.charge_work(1)?;
        Ok(a.cmp(b))
    }
    fn start<W: Work>(&self, a: &Algorithm, w: &W) -> Result<Resolution<Sha256>, MemoryError> {
        w.charge_work(1)?;
        if self.failure.get() {
            return Err(MemoryError::WorkExceeded);
        }
        assert_eq!(*a, Algorithm::Sha256);
        Ok(Resolution::Supported(Sha256::new()))
    }
    fn update<W: Work>(&self, state: &mut Sha256, bytes: &[u8], w: &W) -> Result<(), MemoryError> {
        w.charge_work(bytes.len() as u64)?;
        state.update(bytes);
        self.hashes.set(self.hashes.get() + 1);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, w: &W) -> Result<[u8; 32], MemoryError> {
        w.charge_work(32)?;
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        _: &Algorithm,
        output: &[u8; 32],
        expected: &[u8],
        w: &W,
    ) -> Result<bool, MemoryError> {
        w.charge_work(32)?;
        Ok(output.as_slice() == expected)
    }
}
impl AsnDigest<'_> for Crypto {
    fn identity(&self, a: Algorithm) -> Option<Algorithm> {
        (a == Algorithm::Sha256).then_some(a)
    }
}
impl<W: Work> Verify<W> for Crypto {
    type Error = MemoryError;
    fn verify(
        &self,
        _: &structured_pkix::AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        data: &[u8],
        signature: SignatureValue<'_>,
        w: &W,
    ) -> Result<Verified, MemoryError> {
        w.charge_work(data.len() as u64 + 128)?;
        self.signatures.set(self.signatures.get() + 1);
        let raw: [u8; 32] = key.key().key().as_bytes().try_into().unwrap();
        let key = VerifyingKey::from_bytes(&raw).unwrap();
        let signature = Signature::from_slice(signature.bit_string().as_bytes()).unwrap();
        Ok(if key.verify_strict(data, &signature).is_ok() {
            Verified::Yes
        } else {
            Verified::No
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Change {
    None,
    Serial,
    Name,
    Key,
    Duplicate,
    Unknown,
    Revoked,
    Extended,
    Width,
    Algorithm,
    Parameters,
    ResponseCritical,
    SingleCritical,
    Nonce,
    Cutoff,
    BadSignature,
    Configured,
    Delegate,
    NoRev,
    NoNext,
    Normalized,
    Issuer,
    Wide,
    UnicodeNormalized,
}

fn documents(change: Change) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let aa_key = SigningKey::from_bytes(&[3; 32]);
    let remote_key = SigningKey::from_bytes(&[5; 32]);
    let remote = matches!(change, Change::Configured | Change::Delegate);
    let signer_key = if remote { &remote_key } else { &aa_key };
    let aa_name: &[u8] = if change == Change::Normalized {
        b"  AUTHORITY  "
    } else if change == Change::UnicodeNormalized {
        "ＡUTHORITY".as_bytes()
    } else if change == Change::Issuer {
        b"Other authority"
    } else {
        b"Authority"
    };
    let aa = pkc(&aa_key, aa_name, &aa_key, false);
    let signer = pkc(
        signer_key,
        if remote { b"Responder" } else { aa_name },
        &aa_key,
        remote,
    );
    let ac = if change == Change::Wide {
        super::ac_fields(
            &entity(130, b"holder.test"),
            &super::issuer(b"Authority"),
            &[1; 20],
            &validity(),
            &[],
        )
    } else {
        ac_bytes(
            &entity(130, b"holder.test"),
            &if change == Change::NoRev {
                vec![ext(
                    structured_cms::attribute_certificate::validation::NO_REV_AVAILABLE,
                    &[5, 0],
                    false,
                )]
            } else {
                vec![]
            },
        )
    };
    let serial = if change == Change::Wide {
        vec![1; 20]
    } else {
        vec![if change == Change::Serial { 6 } else { 5 }]
    };
    let mut name_hash = Sha256::digest(name(b"Authority")).to_vec();
    let mut key_hash = Sha256::digest(aa_key.verifying_key().to_bytes()).to_vec();
    if change == Change::Name {
        name_hash[0] ^= 1;
    }
    if change == Change::Key {
        key_hash[0] ^= 1;
    }
    if change == Change::Width {
        name_hash.pop();
    }
    let algorithm = match change {
        Change::Algorithm => seq(&[&[6, 1, 42]]),
        Change::Parameters => seq(&[&tlv(6, oid::SHA256.as_bytes()), &[2, 1, 1]]),
        _ => alg(),
    };
    let id = seq(&[
        &algorithm,
        &tlv(4, &name_hash),
        &tlv(4, &key_hash),
        &tlv(2, &serial),
    ]);
    let this = tlv(24, b"20261021000000Z");
    let single = assertion(change, &id, &this);
    let assertions = if change == Change::Duplicate {
        seq(&[&single, &single])
    } else {
        seq(&[&single])
    };
    let response_extensions = match change {
        Change::ResponseCritical => tlv(161, &seq(&[&ext(Oid::from_bytes(&[42]), &[5, 0], true)])),
        Change::Nonce => tlv(
            161,
            &seq(&[&ext(oid::OCSP_NONCE, &tlv(4, &[9; 32]), false)]),
        ),
        Change::Extended => tlv(
            161,
            &seq(&[&ext(oid::OCSP_EXTENDED_REVOKE, &[5, 0], false)]),
        ),
        _ => vec![],
    };
    let data = seq(&[
        &tlv(161, &name(if remote { b"Responder" } else { aa_name })),
        &this,
        &assertions,
        &response_extensions,
    ]);
    let mut signature = signer_key.sign(&data).to_bytes();
    if change == Change::BadSignature {
        signature[0] ^= 1;
    }
    let response = seq(&[&data, &ed(), &tlv(3, &[&[0][..], &signature].concat())]);
    (aa, signer, ac, response)
}

fn assertion(change: Change, id: &[u8], this: &[u8]) -> Vec<u8> {
    let status = match change {
        Change::Unknown => vec![130, 0],
        Change::Revoked => tlv(161, &tlv(24, b"20261020000000Z")),
        Change::Extended => tlv(
            161,
            &[tlv(24, b"19700101000000Z"), tlv(160, &[10, 1, 6])].concat(),
        ),
        _ => vec![128, 0],
    };
    let extensions = match change {
        Change::SingleCritical => tlv(161, &seq(&[&ext(Oid::from_bytes(&[42]), &[5, 0], true)])),
        Change::Cutoff => tlv(
            161,
            &seq(&[&ext(
                oid::OCSP_ARCHIVE_CUTOFF,
                &tlv(24, b"20261019000000Z"),
                false,
            )]),
        ),
        _ => vec![],
    };
    seq(&[
        id,
        &status,
        this,
        &if change == Change::NoNext {
            vec![]
        } else {
            tlv(160, &tlv(24, b"20261022000000Z"))
        },
        &extensions,
    ])
}

fn expect_outcome(change: Change, outcome: &TargetEvidence<'_, '_>) {
    match change {
        Change::Serial | Change::Name | Change::Key | Change::Issuer => {
            assert!(matches!(outcome, TargetEvidence::Lookup(Lookup::Missing)));
        }
        Change::Duplicate => assert!(matches!(
            outcome,
            TargetEvidence::Lookup(Lookup::Ambiguous { .. })
        )),
        Change::Algorithm => assert!(matches!(
            outcome,
            TargetEvidence::Lookup(Lookup::UnsupportedHash(_))
        )),
        Change::Width => assert!(matches!(
            outcome,
            TargetEvidence::Lookup(Lookup::MalformedHashWidth(_))
        )),
        Change::Parameters => assert!(matches!(
            outcome,
            TargetEvidence::Lookup(Lookup::MalformedHashAlgorithm(_))
        )),
        Change::ResponseCritical | Change::SingleCritical => assert!(matches!(
            outcome,
            TargetEvidence::UnsupportedCritical { .. }
        )),
        Change::NoRev => assert!(matches!(outcome, TargetEvidence::NoRevAvail)),
        Change::Delegate => assert!(matches!(outcome, TargetEvidence::AttributeDelegation)),
        _ => assert!(matches!(outcome, TargetEvidence::Evidence(_))),
    }
}

fn expect_facts(change: Change, evidence: &Evidence<'_, '_>) {
    assert_eq!(evidence.recipient(), RecipientBinding::Matches);
    match change {
        Change::Revoked => assert!(matches!(
            evidence.status(),
            Status::Revoked { reason: None, .. }
        )),
        _ => assert_eq!(
            evidence.status(),
            match change {
                Change::Unknown => Status::Unknown,
                Change::Extended => Status::NotIssued,
                _ => Status::Good,
            }
        ),
    }
    assert_eq!(
        evidence.window(),
        if change == Change::NoNext {
            UpdateWindow::NoNextUpdate
        } else {
            UpdateWindow::Within
        }
    );
    assert_eq!(
        evidence.nonce(),
        if change == Change::Nonce {
            NonceBinding::Unsolicited
        } else {
            NonceBinding::NotRequested
        }
    );
    assert_eq!(
        evidence.archive_cutoff().is_some(),
        change == Change::Cutoff
    );
    assert_eq!(
        evidence.revocation_time().is_some(),
        matches!(change, Change::Revoked | Change::Extended)
    );
}

fn scoped<'r>(
    authenticated: SignedResponse<'r, 'r>,
    aa: &'r Certificate<'r>,
    crypto: &Crypto,
    work: &Memory,
    change: Change,
) -> ScopedResponse<'r, 'r> {
    if change == Change::Configured {
        return authenticated.trust_for_issuer(aa);
    }
    let binding = if change == Change::Delegate {
        let context = path::ValidationContext {
            execution: work,
            interval: path::Interval::at(
                authenticated.response().produced_at().instant().seconds(),
            ),
            policy: path::Policy::default(),
            bounds: path::ValidationBounds::default(),
            verifier: crypto,
            watch: &(),
            recognizer: &(),
        };
        let Delegation::Accepted(facts) = check_delegate(
            authenticated.signer(),
            aa,
            WorkingKey::standing(aa.tbs().public_key()),
            &context,
        )
        .unwrap() else {
            panic!("delegate fixture")
        };
        authenticated.bind_delegate(facts, work).unwrap()
    } else {
        authenticated
            .bind_issuer(aa, WorkingKey::standing(aa.tbs().public_key()), work)
            .unwrap()
    };
    let AuthorityBinding::Bound(value) = binding else {
        panic!("authority binding")
    };
    value
}

fn inspect(
    change: Change,
    check: impl FnOnce(&Profile<'_, '_>, &Certificate<'_>, ScopedResponse<'_, '_>, &Crypto, &Memory),
) {
    let (aa, signer, ac, response) = documents(change);
    let w = memory(1 << 20, 1 << 28);
    let p = Parser::der(w.clone());
    let aa = Certificate::read(&p, &aa, 1000).unwrap();
    let signer = Certificate::read(&p, &signer, 2000).unwrap();
    let ac = read_ac(&p, &ac);
    let profile = accepted(ac.profile(&w).unwrap());
    assert_eq!(profile.issuer().as_bytes(), name(b"Authority"));
    assert!(core::ptr::eq(profile.encoded(), ac.element().as_bytes()));
    let mut r = p.read(&response, 3000).unwrap();
    let e = r.next_element().unwrap().unwrap();
    let response = BasicResponse::read_element(&r, &e).unwrap();
    let crypto = Crypto {
        hashes: Cell::new(0),
        signatures: Cell::new(0),
        failure: Cell::new(false),
    };
    let result = response
        .authenticate_signature(
            &signer,
            WorkingKey::standing(signer.tbs().public_key()),
            &crypto,
            &crypto,
            &w,
        )
        .unwrap();
    if change == Change::BadSignature {
        assert!(matches!(
            result,
            SignatureAuthentication::Rejected(SignatureFailure::Signature)
        ));
        return;
    }
    let SignatureAuthentication::Signed(authenticated) = result else {
        panic!("{result:?}")
    };
    // Full signed authority and target processing are exercised below while
    // all original parsed sources still live; no fixture authenticates an AA path.
    let scoped = scoped(authenticated, &aa, &crypto, &w, change);
    let now = response.responses()[0].this_update().instant();
    let utc = LeapTable::new(now.seconds() - 100_000, now.seconds() + 200_000, &[]).unwrap();
    let time = Evaluation {
        now: now.into(),
        utc: &utc,
        execution: &w,
    };
    let hashes = crypto.hashes.get();
    let signatures = crypto.signatures.get();
    let before = w.used();
    let bound = {
        let operation = Parser::der(w.clone());
        let query = operation.read(&[], 5000).unwrap();
        let work = query.execution();
        let time = Evaluation {
            execution: &work,
            now: time.now,
            utc: time.utc,
        };
        let request = Request {
            target: &profile,
            nonce: None,
            intended_signer: Some(&signer),
        };
        let reading = scoped
            .evaluate_with_target(&request, &time, &crypto)
            .unwrap();
        assert!(core::ptr::eq(reading.target(), &raw const profile));
        assert_eq!(reading.evaluated_at(), time.now);
        expect_outcome(change, reading.outcome());
        reading.evidence()
    };
    assert_eq!(crypto.signatures.get(), signatures);
    if let Some(bound) = bound {
        // Profile is not Copy or Clone. Binding is independently Copy and keeps
        // the actual type/reference after temporary request/reading drop.
        let again = bound;
        assert!(core::ptr::eq(bound.target(), &raw const profile));
        assert!(core::ptr::eq(again.target().certificate(), &raw const ac));
        let evidence = bound.evidence();
        assert!(core::ptr::eq(
            evidence.assertion(),
            &raw const response.responses()[0]
        ));
        expect_facts(change, &evidence);
        assert_eq!(crypto.hashes.get() - hashes, 2);
    }
    if matches!(
        change,
        Change::NoRev
            | Change::Delegate
            | Change::Serial
            | Change::Issuer
            | Change::Algorithm
            | Change::Parameters
            | Change::Width
            | Change::ResponseCritical
    ) {
        assert_eq!(crypto.hashes.get(), hashes);
    }
    assert_eq!(w.used(), before);
    check(&profile, &aa, scoped, &crypto, &w);
}

#[test]
fn all_ac_status_paths_use_the_original_aa_and_single_shared_ocsp_kernel() {
    // Actual Ed25519 responses and SHA256 CertIDs cover every composed branch,
    // including negative outcomes that must not mint a target binding.
    for change in [
        Change::None,
        Change::Serial,
        Change::Name,
        Change::Key,
        Change::Duplicate,
        Change::Unknown,
        Change::Revoked,
        Change::Extended,
        Change::Width,
        Change::Algorithm,
        Change::Parameters,
        Change::ResponseCritical,
        Change::SingleCritical,
        Change::Nonce,
        Change::Cutoff,
        Change::BadSignature,
        Change::Configured,
        Change::Delegate,
        Change::NoRev,
        Change::NoNext,
        Change::Normalized,
        Change::Issuer,
        Change::Wide,
        Change::UnicodeNormalized,
    ] {
        inspect(change, |_, _, _, _, _| {});
    }
}

#[test]
fn ac_nonce_recipient_time_and_callback_facts_remain_independent() {
    // A matching nonce cannot repair stale time, and a different exact signer
    // stops before identity hashing. Provider refusal remains its own cause.
    inspect(Change::Nonce, |profile, aa, source, crypto, w| {
        let start = source.signed().response().responses()[0]
            .this_update()
            .instant();
        let utc = LeapTable::new(start.seconds() - 10, start.seconds() + 200_000, &[]).unwrap();
        let now = structured_pkix::temporal::Instant::new(start.seconds() + 86_400, 0).unwrap();
        let time = Evaluation {
            now: now.into(),
            utc: &utc,
            execution: w,
        };
        for (nonce, expected) in [
            ([9; 32], NonceBinding::Matches),
            ([8; 32], NonceBinding::Differs),
        ] {
            let request = Request {
                target: profile,
                nonce: RequestNonce::new(&nonce),
                intended_signer: Some(aa),
            };
            let facts = source
                .evaluate_with_target(&request, &time, crypto)
                .unwrap()
                .evidence()
                .unwrap();
            assert_eq!(facts.evidence().nonce(), expected);
            assert_eq!(facts.evidence().window(), UpdateWindow::Stale);
        }
        let request = Request {
            target: profile,
            nonce: None,
            intended_signer: None,
        };
        crypto.failure.set(true);
        assert!(matches!(
            source.evaluate(&request, &time, crypto),
            Err(structured_pkix::error::CallbackError::Callback(
                MemoryError::WorkExceeded
            ))
        ));
    });
    inspect(Change::Configured, |profile, aa, source, crypto, w| {
        let start = source.signed().response().produced_at().instant();
        let utc = LeapTable::new(start.seconds() - 10, start.seconds() + 10, &[]).unwrap();
        let time = Evaluation {
            now: start.into(),
            utc: &utc,
            execution: w,
        };
        let request = Request {
            target: profile,
            nonce: None,
            intended_signer: Some(aa),
        };
        let hashes = crypto.hashes.get();
        let result = source
            .evaluate_with_target(&request, &time, crypto)
            .unwrap();
        assert!(matches!(result.outcome(), TargetEvidence::UnexpectedSigner));
        assert!(result.evidence().is_none());
        assert_eq!(crypto.hashes.get(), hashes);
    });
}

#[test]
fn ac_issuer_normalization_scratch_uses_query_capacity_and_rolls_back() {
    // A semantically equal Unicode AA name requires shared preparation scratch.
    // Its original account cannot silently fund an operation with zero capacity.
    inspect(
        Change::UnicodeNormalized,
        |profile, aa, source, crypto, original| {
            let work = memory(0, 1 << 24);
            let now = source.signed().response().produced_at().instant();
            let utc = LeapTable::new(now.seconds() - 10, now.seconds() + 100_000, &[]).unwrap();
            let time = Evaluation {
                now: now.into(),
                utc: &utc,
                execution: &work,
            };
            let request = Request {
                target: profile,
                nonce: None,
                intended_signer: None,
            };
            let held = original.used();
            let hashes = crypto.hashes.get();
            let result = source.evaluate_with_target(&request, &time, crypto);
            let Err(structured_pkix::error::CallbackError::Processing(error)) = result else {
                panic!("unfunded normalization: {result:?}")
            };
            assert!(error.is_resource());
            assert!(error.offset() >= aa.span().start);
            assert!(error.offset() < aa.span().start + aa.span().length);
            assert_eq!(crypto.hashes.get(), hashes);
            assert_eq!(work.used(), 0);
            assert_eq!(original.used(), held);
        },
    );
}

#[test]
fn ac_ocsp_retains_each_source_ceiling_and_current_operation_without_storage_leak() {
    // Parse AC, AA and response independently. Exhaust each original local
    // ceiling in turn, then the current query/aggregate, before any digest.
    for exhausted in 0..5 {
        let (aa_bytes, _, target_bytes, response_bytes) = documents(Change::None);
        let aa_p = Parser::der(memory(1 << 20, 1 << 28));
        let target_parser = Parser::der(memory(1 << 20, 1 << 28));
        let response_p = Parser::der(memory(1 << 20, 1 << 28));
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_work: if exhausted == 3 { 0 } else { 1 << 24 },
                ..Limits::default()
            },
            memory(1 << 20, if exhausted == 4 { 0 } else { 1 << 28 }),
        );
        let aa = Certificate::read(&aa_p, &aa_bytes, 1000).unwrap();
        let ac = read_ac(&target_parser, &target_bytes);
        let profile = accepted(ac.profile(target_parser.memory()).unwrap());
        let mut r = response_p.read(&response_bytes, 3000).unwrap();
        let e = r.next_element().unwrap().unwrap();
        let response = BasicResponse::read_element(&r, &e).unwrap();
        let crypto = Crypto {
            hashes: Cell::new(0),
            signatures: Cell::new(0),
            failure: Cell::new(false),
        };
        let key = WorkingKey::standing(aa.tbs().public_key());
        let SignatureAuthentication::Signed(signed) = response
            .authenticate_signature(&aa, key, &crypto, &crypto, response_p.memory())
            .unwrap()
        else {
            panic!("signature")
        };
        let AuthorityBinding::Bound(source) =
            signed.bind_issuer(&aa, key, response_p.memory()).unwrap()
        else {
            panic!("AA")
        };
        let original = match exhausted {
            0 => Some(&target_parser),
            1 => Some(&aa_p),
            2 => Some(&response_p),
            _ => None,
        };
        if let Some(p) = original {
            let r = p.read(&[], 0).unwrap();
            let w = r.execution();
            w.charge_work(w.work_remaining() as u64).unwrap();
        }
        let query = operation.read(&[], 5000).unwrap();
        let w = query.execution();
        let now = response.produced_at().instant();
        let utc = LeapTable::new(now.seconds() - 10, now.seconds() + 100_000, &[]).unwrap();
        let request = Request {
            target: &profile,
            nonce: None,
            intended_signer: None,
        };
        let time = Evaluation {
            now: now.into(),
            utc: &utc,
            execution: &w,
        };
        let used = w.memory().used();
        let result = source.evaluate_with_target(&request, &time, &crypto);
        let Err(structured_pkix::error::CallbackError::Processing(error)) = result else {
            panic!("unfunded input {exhausted}: {result:?}");
        };
        assert!(error.is_resource());
        assert_eq!(
            error.offset(),
            if exhausted == 0 {
                700
            } else if exhausted == 1 {
                1000
            } else {
                3000
            }
        );
        assert_eq!(crypto.hashes.get(), 0);
        assert_eq!(w.memory().used(), used);
    }
}
