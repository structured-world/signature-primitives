//! Real issuance signatures and complete preflight/resource behaviour.
use super::{attrs, entity, ext, issuer, memory, name, read_ac, read_pkc, seq, tlv, validity};
use core::cell::{Cell, RefCell};
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::signature::Verifier as _;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{MemoryError, Work};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_cms::attribute_certificate::validation::authentication::{
    AlgorithmAgreement, Authenticated, AuthenticationError, Failure, Outcome, Stage,
};
use structured_cms::attribute_certificate::validation::{Reason, Revocation};
use structured_pkix::algorithm::{digest, signature};
use structured_pkix::path::{Interval, Verified, Verify, WorkingKey};
use structured_pkix::signature::{DssValue, SignatureValue};
use structured_pkix::temporal::Instant;
use structured_pkix::{AlgorithmIdentifier, Certificate, oid};

fn generous() -> structured_asn1::memory::Memory {
    memory(1 << 20, 1 << 28)
}
fn alg(kind: Oid<'_>, parameters: &[u8]) -> Vec<u8> {
    seq(&[&tlv(6, kind.as_bytes()), parameters])
}
fn ed() -> Vec<u8> {
    alg(oid::ED25519, &[])
}
fn ec_sig() -> Vec<u8> {
    alg(Oid::from_bytes(&[42, 134, 72, 206, 61, 4, 3, 2]), &[])
}
fn spki(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
    seq(&[algorithm, &tlv(3, &[&[0][..], key].concat())])
}
fn authority(
    key: &[u8],
    subject: &[u8],
    times: &[u8],
    extensions: &[Vec<u8>],
    uid: &[u8],
) -> Vec<u8> {
    let extensions = if extensions.is_empty() {
        vec![]
    } else {
        tlv(
            163,
            &seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>()),
        )
    };
    let tbs = seq(&[
        &[160, 3, 2, 1, 2],
        &[2, 1, 7],
        &ed(),
        &name(b"Root"),
        times,
        &name(subject),
        key,
        uid,
        &extensions,
    ]);
    // AA PKC signature/path are intentionally supplied facts, not checked here.
    seq(&[&tbs, &ed(), &[3, 2, 0, 9]])
}
fn info(signature: &[u8], tail: &[u8], serial: u8, times: &[u8]) -> Vec<u8> {
    seq(&[
        &[2, 1, 1],
        &entity(130, b"holder.test"),
        &issuer(b"Authority"),
        signature,
        &[2, 1, serial],
        times,
        &attrs(),
        tail,
    ])
}
fn envelope(info: &[u8], algorithm: &[u8], signature: &[u8], padding: u8) -> Vec<u8> {
    seq(&[
        info,
        algorithm,
        &tlv(3, &[&[padding][..], signature].concat()),
    ])
}
fn signed(info: &[u8], outer: &[u8], key: &SigningKey) -> Vec<u8> {
    envelope(info, outer, &key.sign(info).to_bytes(), 0)
}
fn interval() -> Interval {
    Interval::at(1_790_000_000)
}
fn key_of<'a>(c: &Certificate<'a>) -> WorkingKey<'a> {
    WorkingKey::standing(c.tbs().public_key())
}
fn read_spki<'a>(p: &'a Parser, bytes: &'a [u8]) -> structured_pkix::PublicKeyInfo<'a> {
    let mut reader = p.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    structured_pkix::PublicKeyInfo::read_element(&reader, &element, "key").unwrap()
}
fn accepted<'r, 'a, 's>(outcome: Outcome<Authenticated<'r, 'a, 's>>) -> Authenticated<'r, 'a, 's> {
    match outcome {
        Outcome::Authenticated(value) => value,
        other => panic!("{other:?}"),
    }
}
fn reject(outcome: &Outcome<Authenticated<'_, '_, '_>>, expected: Failure) {
    assert!(
        matches!(outcome, Outcome::Rejected(r) if r.reason == expected),
        "{outcome:?}"
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    AlgorithmError,
    SignatureError,
    LateError,
    UnsupportedAlgorithm,
    MalformedAlgorithm,
    DifferentAlgorithm,
    UnsupportedSignature,
    InvalidSignature,
}
#[derive(Debug)]
enum Cause {
    Resource(MemoryError),
    Pkix(structured_pkix::Error),
    Marker(Fault),
}
impl From<MemoryError> for Cause {
    fn from(e: MemoryError) -> Self {
        Self::Resource(e)
    }
}
impl From<structured_pkix::Error> for Cause {
    fn from(e: structured_pkix::Error) -> Self {
        Self::Pkix(e)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ed,
    Ec,
    Rsa256,
    Dsa256,
}
fn identity(id: AlgorithmIdentifier<'_>, work: &impl Work) -> Result<Resolution<Kind>, Cause> {
    match signature::with_algorithm(id, work, |kind| match kind {
        Some(signature::Algorithm::Ed25519) => Some(Kind::Ed),
        Some(signature::Algorithm::Ecdsa(digest::Algorithm::Sha256)) => Some(Kind::Ec),
        Some(signature::Algorithm::RsaPkcs1v15(digest::Algorithm::Sha256)) => Some(Kind::Rsa256),
        Some(signature::Algorithm::Dsa(digest::Algorithm::Sha256)) => Some(Kind::Dsa256),
        _ => None,
    }) {
        Ok(Some(k)) => Ok(Resolution::Supported(k)),
        Ok(None) => Ok(Resolution::Unsupported),
        Err(e) if e.is_resource() => Err(Cause::Pkix(e)),
        Err(e)
            if matches!(
                e.code(),
                structured_pkix::ErrorCode::MalformedValue
                    | structured_pkix::ErrorCode::MissingField
                    | structured_pkix::ErrorCode::UnexpectedField
            ) =>
        {
            Ok(Resolution::Malformed)
        }
        Err(e) => Err(Cause::Pkix(e)),
    }
}
struct Oracle {
    fault: Fault,
    calls: RefCell<Vec<&'static str>>,
    allocate: bool,
    structural: bool,
    signed_pointer: Cell<*const u8>,
    parameters: Cell<*const u8>,
}
fn scalar(
    value: structured_asn1::Integer<'_>,
    work: &impl Work,
) -> Result<Option<[u8; 32]>, Cause> {
    work.charge_work(34)?;
    if value.is_negative() {
        return Ok(None);
    }
    let bytes = value.as_bytes();
    let bytes = if bytes.first() == Some(&0) {
        &bytes[1..]
    } else {
        bytes
    };
    if bytes.len() > 32 {
        return Ok(None);
    }
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(Some(out))
}
impl Oracle {
    fn new(fault: Fault) -> Self {
        Self {
            fault,
            calls: RefCell::new(vec![]),
            allocate: false,
            structural: false,
            signed_pointer: Cell::new(core::ptr::null()),
            parameters: Cell::new(core::ptr::null()),
        }
    }
    fn observe(&self, name: &'static str, work: &impl Work) -> Result<(), Cause> {
        work.charge_work(1)?;
        self.calls.borrow_mut().push(name);
        Ok(())
    }
}
impl AlgorithmAgreement for Oracle {
    type Error = Cause;
    fn algorithms<W: Work>(
        &self,
        a: AlgorithmIdentifier<'_>,
        b: AlgorithmIdentifier<'_>,
        w: &W,
    ) -> Result<Resolution<bool>, Cause> {
        self.observe("algorithms", w)?;
        match self.fault {
            Fault::AlgorithmError => return Err(Cause::Marker(self.fault)),
            Fault::UnsupportedAlgorithm => return Ok(Resolution::Unsupported),
            Fault::MalformedAlgorithm => return Ok(Resolution::Malformed),
            Fault::DifferentAlgorithm => return Ok(Resolution::Supported(false)),
            _ => {}
        }
        let left = identity(a, w)?;
        let right = identity(b, w)?;
        Ok(match (left, right) {
            (Resolution::Supported(a), Resolution::Supported(b)) => Resolution::Supported(a == b),
            (Resolution::Malformed, _) | (_, Resolution::Malformed) => Resolution::Malformed,
            _ => Resolution::Unsupported,
        })
    }
}
impl<W: Work> Verify<W> for Oracle {
    type Error = Cause;
    fn verify(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        input: &[u8],
        signature: SignatureValue<'_>,
        work: &W,
    ) -> Result<Verified, Cause> {
        self.observe("verify", work)?;
        if self.fault == Fault::SignatureError {
            return Err(Cause::Marker(self.fault));
        }
        if self.fault == Fault::UnsupportedSignature {
            return Ok(Verified::Unsupported);
        }
        if self.fault == Fault::InvalidSignature {
            return Ok(Verified::No);
        }
        let mut storage = work.vector();
        if self.allocate {
            storage.try_extend_from_slice(&[0; 32])?;
        }
        work.charge_work(input.len() as u64)?;
        let sig = signature.octets().unwrap();
        work.charge_work(sig.len() as u64)?;
        self.signed_pointer.set(input.as_ptr());
        self.parameters
            .set(key.parameters().map_or(core::ptr::null(), <[u8]>::as_ptr));
        if self.fault == Fault::LateError {
            return Err(Cause::Marker(self.fault));
        }
        if self.structural {
            let key_work = key.key().execution_in(work);
            key_work.charge_work(key.key().algorithm().algorithm().as_bytes().len() as u64)?;
            if key.key().algorithm().algorithm() == Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]) {
                let _ = structured_pkix::key::dsa::read(key, work)?;
            }
            return Ok(Verified::Yes);
        }
        // Fixed-size native oracles only, not a production backend-cost qualification.
        work.charge_work(1024)?;
        let key_work = key.key().execution_in(work);
        let valid = if algorithm.algorithm() == oid::ED25519 {
            let raw = structured_pkix::key::rfc8410::read(key.key(), work)?;
            key_work.charge_work(raw.as_bytes().len() as u64)?;
            let Ok(key) =
                ed25519_dalek::VerifyingKey::from_bytes(raw.as_bytes().try_into().unwrap())
            else {
                return Ok(Verified::No);
            };
            let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else {
                return Ok(Verified::No);
            };
            key.verify_strict(input, &sig).is_ok()
        } else {
            let decoded = structured_pkix::key::ec::read(key, work)?;
            key_work.charge_work(decoded.as_bytes().len() as u64)?;
            let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(decoded.as_bytes()) else {
                return Ok(Verified::No);
            };
            let mut reader = signature.reader_in(work)?;
            let scalars = DssValue::read(&mut reader, "signatureValue")?;
            let (Some(r), Some(s)) = (
                scalar(scalars.r(), &reader.execution())?,
                scalar(scalars.s(), &reader.execution())?,
            ) else {
                return Ok(Verified::No);
            };
            let Ok(signature) = p256::ecdsa::Signature::from_scalars(r, s) else {
                return Ok(Verified::No);
            };
            key.verify(input, &signature).is_ok()
        };
        Ok(if valid { Verified::Yes } else { Verified::No })
    }
}

#[test]
fn real_ed25519_signature_receipt_preserves_originals_and_pending_obligations() {
    // Actual arithmetic authenticates only the supplied exact DER acinfo and key.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let key = spki(&ed(), signing.verifying_key().as_bytes());
    let aa_bytes = authority(&key, b"Authority", &validity(), &[], &[]);
    let source = Parser::der(generous());
    let aa_source = Parser::der(generous());
    let aa = read_pkc(&aa_source, &aa_bytes);
    let body = info(&ed(), &[], 5, &validity());
    let bytes = signed(&body, &ed(), &signing);
    let ac = read_ac(&source, &bytes);
    let verifier = Oracle::new(Fault::None);
    let result = accepted(
        ac.authenticate(&aa, key_of(&aa), interval(), &verifier, &generous())
            .unwrap(),
    );
    assert!(core::ptr::eq(result.certificate(), &raw const ac));
    assert!(core::ptr::eq(result.authority(), &raw const aa));
    assert_eq!(
        result.key().key().as_bytes(),
        aa.tbs().public_key().as_bytes()
    );
    assert_eq!(result.interval().from_instant(), interval().from_instant());
    assert_eq!(result.profile().revocation(), Revocation::Required);
    assert_eq!(verifier.signed_pointer.get(), ac.signed_bytes().as_ptr());
    assert_eq!(*verifier.calls.borrow(), ["algorithms", "verify"]);
}

#[test]
fn real_signature_refuses_changed_signed_bytes_signature_and_wrong_signing_key() {
    // Every alteration remains readable but must fail real signature arithmetic.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let other = SigningKey::from_bytes(&[24; 32]);
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &aa_bytes);
    let body = info(&ed(), &[], 5, &validity());
    let mut wrong_sig = signing.sign(&body).to_bytes();
    wrong_sig[0] ^= 1;
    let cases = [
        envelope(
            &info(&ed(), &[], 6, &validity()),
            &ed(),
            &signing.sign(&body).to_bytes(),
            0,
        ),
        envelope(&body, &ed(), &wrong_sig, 0),
        signed(&body, &ed(), &other),
        envelope(&body, &ed(), &[0; 63], 0),
    ];
    for bytes in cases {
        let ac = read_ac(&p, &bytes);
        reject(
            &ac.authenticate(
                &aa,
                key_of(&aa),
                interval(),
                &Oracle::new(Fault::None),
                &generous(),
            )
            .unwrap(),
            Failure::Signature,
        );
    }
}

#[test]
fn real_ecdsa_uses_original_der_signature_reader_without_reencoding() {
    // Native ECDSA consumes the common scalar view in its original source/depth.
    let signing = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let public = signing.verifying_key().to_sec1_point(false);
    let key_alg = alg(
        oid::EC_PUBLIC_KEY,
        &tlv(6, &[42, 134, 72, 206, 61, 3, 1, 7]),
    );
    let aa_bytes = authority(
        &spki(&key_alg, public.as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let body = info(&ec_sig(), &[], 5, &validity());
    let signature: p256::ecdsa::Signature = signing.try_sign(&body).unwrap();
    let bytes = envelope(&body, &ec_sig(), signature.to_der().as_bytes(), 0);
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &aa_bytes);
    let ac = read_ac(&p, &bytes);
    accepted(
        ac.authenticate(
            &aa,
            key_of(&aa),
            interval(),
            &Oracle::new(Fault::None),
            &generous(),
        )
        .unwrap(),
    );
    let zero = memory(0, 1 << 20);
    assert!(
        matches!(ac.authenticate(&aa,key_of(&aa),interval(),&Oracle::new(Fault::None),&zero),
        Err(AuthenticationError::Callback {stage:Stage::Signature,source:Cause::Pkix(e),..}) if e.is_resource())
    );
    assert_eq!(zero.used(), 0);
}

#[test]
fn native_ecdsa_invalid_scalar_values_return_no_instead_of_panicking() {
    // Valid INTEGER syntax is not a proof of nonzero, positive, in-range scalars.
    let signing = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let public = signing.verifying_key().to_sec1_point(false);
    let key_alg = alg(
        oid::EC_PUBLIC_KEY,
        &tlv(6, &[42, 134, 72, 206, 61, 3, 1, 7]),
    );
    let aa_bytes = authority(
        &spki(&key_alg, public.as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &aa_bytes);
    let body = info(&ec_sig(), &[], 5, &validity());
    for value in [
        vec![0],
        vec![255],
        vec![1; 33],
        [vec![0], vec![255; 32]].concat(),
    ] {
        let sig = seq(&[&tlv(2, &value), &[2, 1, 1]]);
        let bytes = envelope(&body, &ec_sig(), &sig, 0);
        let ac = read_ac(&p, &bytes);
        reject(
            &ac.authenticate(
                &aa,
                key_of(&aa),
                interval(),
                &Oracle::new(Fault::None),
                &generous(),
            )
            .unwrap(),
            Failure::Signature,
        );
    }
}

#[test]
fn static_profile_and_aa_purpose_fail_before_any_provider_callback() {
    // Full profile and AA purpose reuse their existing kernels, including late extensions.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let key = spki(&ed(), signing.verifying_key().as_bytes());
    let p = Parser::der(generous());
    let normal = authority(&key, b"Authority", &validity(), &[], &[]);
    let aa = read_pkc(&p, &normal);
    let bad_profile = [
        (info(&ed(), &[], 0, &validity()), Reason::Serial),
        (
            info(
                &ed(),
                &seq(&[&ext(Oid::from_bytes(&[42, 3]), &[5, 0], true)]),
                5,
                &validity(),
            ),
            Reason::UnknownCritical,
        ),
    ];
    for (body, expected) in bad_profile {
        let bytes = signed(&body, &ed(), &signing);
        let ac = read_ac(&p, &bytes);
        let v = Oracle::new(Fault::None);
        let result = ac
            .authenticate(&aa, key_of(&aa), interval(), &v, &generous())
            .unwrap();
        assert!(
            matches!(result,Outcome::Rejected(r) if matches!(r.reason,Failure::Profile(c) if c.reason==expected))
        );
        assert!(v.calls.borrow().is_empty());
    }
    let body = info(&ed(), &[], 5, &validity());
    let bytes = signed(&body, &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    let cases = [
        (
            authority(&key, b"Other", &validity(), &[], &[]),
            Reason::AuthorityName,
        ),
        (
            authority(
                &key,
                b"Authority",
                &validity(),
                &[ext(oid::BASIC_CONSTRAINTS, &[48, 3, 1, 1, 255], true)],
                &[],
            ),
            Reason::AuthorityIsCa,
        ),
        (
            authority(
                &key,
                b"Authority",
                &validity(),
                &[ext(oid::KEY_USAGE, &[3, 2, 2, 4], true)],
                &[],
            ),
            Reason::AuthorityUsage,
        ),
        (
            authority(&key, b"Authority", &validity(), &[], &[130, 2, 0, 1]),
            Reason::AuthorityUniqueId,
        ),
    ];
    for (bytes, expected) in cases {
        let authority = read_pkc(&p, &bytes);
        let v = Oracle::new(Fault::None);
        let result = ac
            .authenticate(&authority, key_of(&authority), interval(), &v, &generous())
            .unwrap();
        assert!(
            matches!(result,Outcome::Rejected(r) if matches!(r.reason,Failure::Authority(c) if c.reason==expected))
        );
        assert!(v.calls.borrow().is_empty());
    }
}

#[test]
fn content_commitment_aa_usage_is_accepted_and_key_binding_is_mandatory() {
    // Bit1 is a valid AA signature use; a different supplied SPKI is not its key.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let other = SigningKey::from_bytes(&[24; 32]);
    let p = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[ext(oid::KEY_USAGE, &[3, 2, 6, 64], true)],
        &[],
    );
    let other_bytes = authority(
        &spki(&ed(), other.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let different = read_pkc(&p, &other_bytes);
    let bytes = signed(&info(&ed(), &[], 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    accepted(
        ac.authenticate(
            &aa,
            key_of(&aa),
            interval(),
            &Oracle::new(Fault::None),
            &generous(),
        )
        .unwrap(),
    );
    let v = Oracle::new(Fault::None);
    reject(
        &ac.authenticate(&aa, key_of(&different), interval(), &v, &generous())
            .unwrap(),
        Failure::KeyBinding,
    );
    assert!(v.calls.borrow().is_empty());
}

#[test]
fn validity_covers_whole_inclusive_window_and_keeps_fractional_leap_labels() {
    // Labels, including caller-authenticated leap facts, are never rounded to POSIX seconds.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = signed(&info(&ed(), &[], 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    let low = ac.information().not_before.instant();
    let high = ac.information().not_after.instant();
    for window in [
        Interval::at_instant(low),
        Interval::at_instant(high),
        Interval::between_instants(high, low),
        Interval::at_instant(Instant::new(low.seconds(), 1).unwrap()),
        Interval::at_instant(Instant::leap_after(high.seconds() - 1, 0).unwrap()),
    ] {
        let v = Oracle::new(Fault::None);
        let result = accepted(
            ac.authenticate(&aa, key_of(&aa), window, &v, &generous())
                .unwrap(),
        );
        assert_eq!(result.interval().from_instant(), window.from_instant());
    }
    for window in [
        Interval::at(low.seconds() - 1),
        Interval::at(high.seconds() + 1),
        Interval::between(low.seconds() - 1, high.seconds()),
        Interval::at_instant(Instant::new(high.seconds(), 1).unwrap()),
        Interval::at_instant(Instant::leap_after(high.seconds() + 86_399, 0).unwrap()),
    ] {
        let v = Oracle::new(Fault::None);
        reject(
            &ac.authenticate(&aa, key_of(&aa), window, &v, &generous())
                .unwrap(),
            Failure::AcValidity,
        );
        assert!(v.calls.borrow().is_empty());
    }
}

#[test]
fn authority_validity_is_independent_of_a_wider_ac_validity() {
    // A live AC cannot extend the actual signing certificate's evaluation window.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let narrow = seq(&[&tlv(24, b"20261021000000Z"), &tlv(24, b"20261022000000Z")]);
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &narrow,
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = signed(&info(&ed(), &[], 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    let v = Oracle::new(Fault::None);
    reject(
        &ac.authenticate(&aa, key_of(&aa), interval(), &v, &generous())
            .unwrap(),
        Failure::AuthorityValidity,
    );
    assert!(v.calls.borrow().is_empty());
    let range = Interval::between_instants(
        aa.tbs().validity().not_before().instant(),
        aa.tbs().validity().not_after().instant(),
    );
    accepted(
        ac.authenticate(&aa, key_of(&aa), range, &v, &generous())
            .unwrap(),
    );
}

#[test]
fn unsupported_malformed_mismatch_and_callback_refusals_never_collapse() {
    // Capability, syntax, semantic mismatch and opaque failures preserve their origin.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = signed(&info(&ed(), &[], 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    for (fault, stage) in [
        (Fault::UnsupportedAlgorithm, Stage::Algorithms),
        (Fault::UnsupportedSignature, Stage::Signature),
    ] {
        let v = Oracle::new(fault);
        assert!(
            matches!(ac.authenticate(&aa,key_of(&aa),interval(),&v,&generous()).unwrap(),Outcome::Unsupported(s) if s==stage)
        );
        assert_eq!(
            v.calls.borrow().contains(&"verify"),
            stage == Stage::Signature
        );
    }
    for (fault, expected) in [
        (Fault::MalformedAlgorithm, Failure::AlgorithmSyntax),
        (Fault::DifferentAlgorithm, Failure::AlgorithmMismatch),
        (Fault::InvalidSignature, Failure::Signature),
    ] {
        let v = Oracle::new(fault);
        reject(
            &ac.authenticate(&aa, key_of(&aa), interval(), &v, &generous())
                .unwrap(),
            expected,
        );
    }
    for (fault, stage) in [
        (Fault::AlgorithmError, Stage::Algorithms),
        (Fault::SignatureError, Stage::Signature),
        (Fault::LateError, Stage::Signature),
    ] {
        let mut v = Oracle::new(fault);
        v.allocate = true;
        let query = generous();
        assert!(
            matches!(ac.authenticate(&aa,key_of(&aa),interval(),&v,&query),
            Err(AuthenticationError::Callback {stage:s,source:Cause::Marker(f),context})
            if s==stage && f==fault && context==ac.signed_element().span())
        );
        assert_eq!(query.used(), 0);
    }
}

#[test]
fn native_algorithm_identity_rejects_mismatched_or_malformed_identifiers() {
    // Both original fields are resolved, not merely compared as arbitrary bytes.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    for (inner, outer, expected) in [
        (ed(), ec_sig(), Failure::AlgorithmMismatch),
        (alg(oid::ED25519, &[5, 0]), ed(), Failure::AlgorithmSyntax),
    ] {
        let bytes = signed(&info(&inner, &[], 5, &validity()), &outer, &signing);
        let ac = read_ac(&p, &bytes);
        let v = Oracle::new(Fault::None);
        reject(
            &ac.authenticate(&aa, key_of(&aa), interval(), &v, &generous())
                .unwrap(),
            expected,
        );
        assert_eq!(*v.calls.borrow(), ["algorithms"]);
    }
    let unknown = alg(Oid::from_bytes(&[42, 3]), &[]);
    let bytes = signed(&info(&unknown, &[], 5, &validity()), &unknown, &signing);
    let ac = read_ac(&p, &bytes);
    assert!(matches!(
        ac.authenticate(
            &aa,
            key_of(&aa),
            interval(),
            &Oracle::new(Fault::None),
            &generous()
        )
        .unwrap(),
        Outcome::Unsupported(Stage::Algorithms)
    ));
}

#[test]
fn rsa_sha256_null_absence_agreement_is_provider_semantics_not_byte_equality() {
    // This structural oracle tests identity/default agreement, not RSA arithmetic.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let kind = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 1, 11]);
    for (inner, outer) in [
        (alg(kind, &[]), alg(kind, &[5, 0])),
        (alg(kind, &[5, 0]), alg(kind, &[])),
    ] {
        let bytes = signed(&info(&inner, &[], 5, &validity()), &outer, &signing);
        let ac = read_ac(&p, &bytes);
        let mut v = Oracle::new(Fault::None);
        v.structural = true;
        accepted(
            ac.authenticate(&aa, key_of(&aa), interval(), &v, &generous())
                .unwrap(),
        );
    }
}

#[test]
fn padded_signature_is_rejected_before_algorithm_or_backend_work() {
    // A readable BIT STRING with unused bits is not a whole-octet signature.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let body = info(&ed(), &[], 5, &validity());
    let mut sig = signing.sign(&body).to_bytes();
    sig[63] &= 0xfe;
    let bytes = envelope(&body, &ed(), &sig, 1);
    let ac = read_ac(&p, &bytes);
    let v = Oracle::new(Fault::None);
    reject(
        &ac.authenticate(&aa, key_of(&aa), interval(), &v, &generous())
            .unwrap(),
        Failure::SignatureEncoding,
    );
    assert!(v.calls.borrow().is_empty());
}

#[test]
fn ber_and_implicit_carriers_preserve_exact_original_signature_input() {
    // Changing only the envelope never changes the original DER acinfo signed by the AA.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::ber(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let body = info(&ed(), &[], 5, &validity());
    let signature = tlv(3, &[&[0][..], &signing.sign(&body).to_bytes()].concat());
    let ber = [&[48, 128][..], &body, &ed(), &signature, &[0, 0]].concat();
    let ac = read_ac(&p, &ber);
    accepted(
        ac.authenticate(
            &aa,
            key_of(&aa),
            interval(),
            &Oracle::new(Fault::None),
            &generous(),
        )
        .unwrap(),
    );
    let bytes = tlv(162, &[body.clone(), ed(), signature].concat());
    let mut reader = p.read(&bytes, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let ac = structured_cms::attribute_certificate::AttributeCertificate::read_implicit(
        &reader, &element,
    )
    .unwrap();
    let v = Oracle::new(Fault::None);
    accepted(
        ac.authenticate(&aa, key_of(&aa), interval(), &v, &generous())
            .unwrap(),
    );
    assert_eq!(ac.signed_bytes(), body);
    assert_eq!(v.signed_pointer.get(), ac.signed_bytes().as_ptr());
}

#[test]
fn authenticated_profile_retains_target_proxy_and_status_obligations_without_reparse() {
    // Signature success does not satisfy effects; owned decoded lists retain their charge.
    use structured_cms::attribute_certificate::{proxy, target};
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let targets = seq(&[&seq(&[&tlv(160, &tlv(130, b"server.test"))])]);
    let tail = seq(&[
        &ext(target::IDENTIFIER, &targets, true),
        &ext(proxy::IDENTIFIER, &targets, true),
        &ext(super::validation::NO_REV_AVAILABLE, &[5, 0], false),
    ]);
    let bytes = signed(&info(&ed(), &tail, 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    let query = generous();
    let v = Oracle::new(Fault::None);
    let receipt = accepted(
        ac.authenticate(&aa, key_of(&aa), interval(), &v, &query)
            .unwrap(),
    );
    assert_eq!(receipt.profile().targeting().unwrap().targets().len(), 1);
    assert_eq!(receipt.profile().proxying().unwrap().targets().len(), 1);
    assert_eq!(receipt.profile().revocation(), Revocation::NoRevAvailable);
    assert!(query.used() > 0);
    let account = query.clone();
    drop(query);
    assert!(account.used() > 0);
    drop(receipt);
    assert_eq!(account.used(), 0);
}

#[test]
fn aki_is_a_retained_hint_and_does_not_force_an_extra_certificate_selection_policy() {
    // RFC5755§4.3.3 MAY use AKI; the actual key/signature establish the supplied issuer.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[ext(oid::SUBJECT_KEY_IDENTIFIER, &[4, 1, 1], false)],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let tail = seq(&[&ext(
        oid::AUTHORITY_KEY_IDENTIFIER,
        &[48, 3, 128, 1, 99],
        false,
    )]);
    let bytes = signed(&info(&ed(), &tail, 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    let receipt = accepted(
        ac.authenticate(
            &aa,
            key_of(&aa),
            interval(),
            &Oracle::new(Fault::None),
            &generous(),
        )
        .unwrap(),
    );
    assert_eq!(
        receipt.profile().authority_key().unwrap().key_id(),
        Some(&[99][..])
    );
}

#[test]
fn provider_capacity_and_late_failure_release_profile_and_temporary_storage() {
    use structured_cms::attribute_certificate::target;
    // Both profile materialization and callback-local buffers use actual current capacity.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = signed(&info(&ed(), &[], 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    let query = memory(31, 1 << 20);
    let mut v = Oracle::new(Fault::None);
    v.allocate = true;
    assert!(matches!(
        ac.authenticate(&aa, key_of(&aa), interval(), &v, &query),
        Err(AuthenticationError::Callback {
            stage: Stage::Signature,
            source: Cause::Resource(MemoryError::LimitExceeded),
            ..
        })
    ));
    assert_eq!(query.used(), 0);
    let targets = seq(&[&seq(&[&tlv(160, &tlv(130, b"server.test"))])]);
    let tail = seq(&[&ext(target::IDENTIFIER, &targets, true)]);
    let bytes = signed(&info(&ed(), &tail, 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    let zero = memory(0, 1 << 20);
    let v = Oracle::new(Fault::None);
    assert!(
        matches!(ac.authenticate(&aa,key_of(&aa),interval(),&v,&zero),Err(AuthenticationError::Processing(ref e)) if e.is_resource())
    );
    assert!(v.calls.borrow().is_empty());
    assert_eq!(zero.used(), 0);
    let query = generous();
    let mut v = Oracle::new(Fault::LateError);
    v.allocate = true;
    assert!(matches!(
        ac.authenticate(&aa, key_of(&aa), interval(), &v, &query),
        Err(AuthenticationError::Callback {
            source: Cause::Marker(Fault::LateError),
            ..
        })
    ));
    assert_eq!(query.used(), 0);
}

#[test]
fn current_query_zero_and_exact_work_are_enforced_across_foreign_sources() {
    // The source switches must not replace the caller's narrowed operation ceiling.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let p = Parser::der(generous());
    let ap = Parser::der(generous());
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let aa = read_pkc(&ap, &aa_bytes);
    let bytes = signed(&info(&ed(), &[], 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    let baseline = generous();
    let mut v = Oracle::new(Fault::None);
    v.structural = true;
    accepted(
        ac.authenticate(&aa, key_of(&aa), interval(), &v, &baseline)
            .unwrap(),
    );
    let cost = baseline.work_used();
    assert!(cost > 0);
    for budget in [0, 1, cost - 1, cost] {
        let query = memory(1 << 20, budget);
        let mut v = Oracle::new(Fault::None);
        v.structural = true;
        let result = ac.authenticate(&aa, key_of(&aa), interval(), &v, &query);
        if budget == cost {
            accepted(result.unwrap());
        } else {
            assert!(
                matches!(result,Err(AuthenticationError::Processing(ref e)) if e.is_resource())
                    || matches!(
                        result,
                        Err(AuthenticationError::Callback {
                            source: Cause::Resource(_),
                            ..
                        })
                    )
            );
        }
        assert_eq!(query.used(), 0);
    }
    let query_parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: (cost - 1) as u64,
            ..Limits::default()
        },
        generous(),
    );
    let reader = query_parser.read(&[], 9000).unwrap();
    let mut v = Oracle::new(Fault::None);
    v.structural = true;
    assert!(
        ac.authenticate(&aa, key_of(&aa), interval(), &v, &reader.execution())
            .is_err()
    );
}

#[test]
fn original_ac_and_aa_source_ceiling_cannot_be_reset_by_fresh_work() {
    // Exactly the original parse allowance leaves no free deferred validation work.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let aa_bytes = authority(
        &spki(&ed(), signing.verifying_key().as_bytes()),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let bytes = signed(&info(&ed(), &[], 5, &validity()), &ed(), &signing);
    let measured = generous();
    let observed = Parser::der(measured.clone());
    let _ = read_ac(&observed, &bytes);
    let p = Parser::new(
        Encoding::Der,
        Limits {
            max_work: measured.work_used() as u64,
            ..Limits::default()
        },
        generous(),
    );
    let ac = read_ac(&p, &bytes);
    let ap = Parser::der(generous());
    let aa = read_pkc(&ap, &aa_bytes);
    let v = Oracle::new(Fault::None);
    assert!(
        matches!(ac.authenticate(&aa,key_of(&aa),interval(),&v,&generous()),Err(AuthenticationError::Processing(e)) if e.is_resource() && e.offset()>=700)
    );
    assert!(v.calls.borrow().is_empty());
    let measured = generous();
    let observed = Parser::der(measured.clone());
    let _ = read_pkc(&observed, &aa_bytes);
    let ap = Parser::new(
        Encoding::Der,
        Limits {
            max_work: measured.work_used() as u64 + 1,
            ..Limits::default()
        },
        generous(),
    );
    let aa = read_pkc(&ap, &aa_bytes);
    let p = Parser::der(generous());
    let ac = read_ac(&p, &bytes);
    // The exhausted AA ceiling applies while comparing the AC issuer name;
    // the common Name kernel locates that action at its original left operand.
    let original_name = match &ac.information().issuer.names.as_ref().unwrap()[0] {
        structured_pkix::general_name::GeneralName::Directory(name) => name.as_bytes(),
        other => panic!("{other:?}"),
    };
    let name_at = 700
        + bytes
            .windows(original_name.len())
            .position(|w| w == original_name)
            .unwrap() as u64;
    let result = ac.authenticate(&aa, key_of(&aa), interval(), &v, &generous());
    assert!(
        matches!(&result,Err(AuthenticationError::Processing(e))
        if e.is_resource() && e.offset()==name_at && e.field()=="attributeCertificate.issuer"),
        "{result:?}"
    );
    assert!(v.calls.borrow().is_empty());
}

#[test]
fn independently_parsed_equal_spki_pays_its_own_source_before_byte_comparison() {
    // Equality of separately sourced bytes cannot bypass the supplied key's local ceiling.
    let signing = SigningKey::from_bytes(&[23; 32]);
    let encoded = spki(&ed(), signing.verifying_key().as_bytes());
    let measured = generous();
    let observed = Parser::der(measured.clone());
    let _ = read_spki(&observed, &encoded);
    let kp = Parser::new(
        Encoding::Der,
        Limits {
            max_work: measured.work_used() as u64 + 1,
            ..Limits::default()
        },
        generous(),
    );
    let key = WorkingKey::standing(read_spki(&kp, &encoded));
    let aa_bytes = authority(&encoded, b"Authority", &validity(), &[], &[]);
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = signed(&info(&ed(), &[], 5, &validity()), &ed(), &signing);
    let ac = read_ac(&p, &bytes);
    let v = Oracle::new(Fault::None);
    assert!(
        matches!(ac.authenticate(&aa,key,interval(),&v,&generous()),Err(AuthenticationError::Processing(e)) if e.is_resource() && e.offset()>=400 && e.offset()<700)
    );
    assert!(v.calls.borrow().is_empty());
}

#[test]
fn inherited_parameter_state_is_retained_and_its_original_ceiling_reaches_verification() {
    // Plumbing oracle only: the actual caller-supplied effective DSA state survives,
    // and the shared DSA reader still charges the third original parameter source.
    let dsa = Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]);
    let dsa_sig = alg(Oid::from_bytes(&[96, 134, 72, 1, 101, 3, 4, 3, 2]), &[]);
    let params = seq(&[&[2, 1, 23], &[2, 1, 11], &[2, 1, 2]]);
    let root_bytes = authority(
        &spki(&alg(dsa, &params), &[2, 1, 8]),
        b"Root",
        &validity(),
        &[],
        &[],
    );
    let aa_bytes = authority(
        &spki(&alg(dsa, &[]), &[2, 1, 4]),
        b"Authority",
        &validity(),
        &[],
        &[],
    );
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &aa_bytes);
    let root_source = Parser::der(generous());
    let root = Certificate::read(&root_source, &root_bytes, 5000).unwrap();
    let key = key_of(&root).subject(&aa, &generous()).unwrap();
    let signing = SigningKey::from_bytes(&[23; 32]);
    let bytes = signed(&info(&dsa_sig, &[], 5, &validity()), &dsa_sig, &signing);
    let ac = read_ac(&p, &bytes);
    let mut v = Oracle::new(Fault::None);
    v.structural = true;
    let receipt = accepted(
        ac.authenticate(&aa, key, interval(), &v, &generous())
            .unwrap(),
    );
    assert_eq!(
        receipt.key().parameters().unwrap().as_ptr(),
        root.tbs()
            .public_key()
            .algorithm()
            .parameters()
            .unwrap()
            .as_ptr()
    );
    assert_eq!(v.parameters.get(), key.parameters().unwrap().as_ptr());
    let observed = generous();
    let source = Parser::der(observed.clone());
    let _ = Certificate::read(&source, &root_bytes, 5000).unwrap();
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: observed.work_used() as u64 + 1,
            ..Limits::default()
        },
        generous(),
    );
    let root = Certificate::read(&source, &root_bytes, 5000).unwrap();
    let key = key_of(&root).subject(&aa, &generous()).unwrap();
    let query = generous();
    let mut v = Oracle::new(Fault::None);
    v.structural = true;
    v.allocate = true;
    assert!(matches!(ac.authenticate(&aa,key,interval(),&v,&query),
        Err(AuthenticationError::Callback {stage:Stage::Signature,source:Cause::Pkix(e),..}) if e.is_resource() && e.offset()>=5000));
    assert_eq!(query.used(), 0);
}
