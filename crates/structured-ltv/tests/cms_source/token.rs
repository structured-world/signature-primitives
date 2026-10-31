//! A real RFC3161 token over caller-selected archive input, checked by CMS.
//! The Ed25519 adapter is a test oracle, not a production engine.

use super::support::tlv;
use core::{cell::Cell, cmp::Ordering};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{Memory, MemoryError, OwnedVec, Work};
use structured_asn1::{Encoding, Parser, Reader};
use structured_cms::Octets;
use structured_cms::oid;
use structured_cms::provider::{Prehash, SignatureAnswer, SignatureMode, SignatureProvider};
use structured_cms::timestamp::{CheckContext, Evidence, Token};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
use structured_pkix::temporal::{Instant, LeapTable};
use structured_pkix::{AlgorithmIdentifier, Certificate, path::WorkingKey};

const SHA512: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 3];
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];

#[derive(Debug)]
pub enum Failure {
    Resource,
    Encoding,
    Account,
    Prehash,
}

impl From<MemoryError> for Failure {
    fn from(_: MemoryError) -> Self {
        Self::Resource
    }
}

struct Oracle {
    key: VerifyingKey,
    raw_finishes: Cell<usize>,
}

struct Raw<'a> {
    key: &'a VerifyingKey,
    signature: Signature,
    // The strict verifier needs contiguous input; its capacity is accounted.
    input: Option<OwnedVec<u8>>,
}

impl<'a> structured_asn1::digest::Digest<'a> for Oracle {
    type Identity = ();
    type State = Sha512;
    type Output = [u8; 64];
    type Error = Failure;

    fn width(&self, (): &()) -> Option<usize> {
        Some(64)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&'a self, (): &(), work: &W) -> Result<Resolution<Sha512>, Failure> {
        work.charge_work(128)?;
        Ok(Resolution::Supported(Sha512::new()))
    }
    fn update<W: Work>(&self, state: &mut Sha512, bytes: &[u8], work: &W) -> Result<(), Failure> {
        work.charge_work(bytes.len() as u64 + 128)?;
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha512, work: &W) -> Result<[u8; 64], Failure> {
        work.charge_work(256)?;
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &[u8; 64],
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        work.charge_work(64)?;
        Ok(output.as_slice() == expected)
    }
}

impl AsnDigest<'_> for Oracle {
    fn identity(&self, algorithm: Algorithm) -> Option<()> {
        (algorithm == Algorithm::Sha512).then_some(())
    }
}

impl<'a> SignatureProvider<'a> for Oracle {
    type SignatureIdentity = ();
    type RawState = Raw<'a>;

    fn resolve_signature(
        &'a self,
        identifier: AlgorithmIdentifier<'a>,
        (): &(),
        key: WorkingKey<'a>,
        _encoding: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<SignatureMode<()>>, Failure> {
        parent.execution().charge_work(64)?;
        if identifier.algorithm().as_bytes() != ED25519
            || key.key().algorithm().algorithm().as_bytes() != ED25519
        {
            return Ok(Resolution::Unsupported);
        }
        // RFC8410 §3 and RFC8419 §3.1: absent parameters, PureEdDSA only.
        if identifier.parameters().is_some()
            || key.parameters().is_some()
            || key.key().key_octets() != Some(self.key.as_bytes().as_slice())
        {
            return Ok(Resolution::Malformed);
        }
        Ok(Resolution::Supported(SignatureMode::Raw(())))
    }
    fn compare_signature<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start_raw<W: Work>(
        &'a self,
        (): &(),
        _key: WorkingKey<'a>,
        signature: &'a Octets<'a>,
        work: &W,
    ) -> Result<Raw<'a>, Failure> {
        work.charge_work(64)?;
        let bytes = signature.as_one().ok_or(Failure::Encoding)?;
        let signature = Signature::from_slice(bytes).map_err(|_| Failure::Encoding)?;
        Ok(Raw {
            key: &self.key,
            signature,
            input: Some(work.vector().into_owned()),
        })
    }
    fn update_raw<W: Work>(
        &self,
        state: &mut Raw<'a>,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), Failure> {
        let input = state.input.take().ok_or(Failure::Account)?;
        let mut scoped = match input.with_execution(work) {
            Ok(scoped) => scoped,
            Err(original) => {
                state.input = Some(original);
                return Err(Failure::Account);
            }
        };
        let result = scoped.try_extend_from_slice(bytes);
        state.input = Some(scoped.into_owned());
        result.map_err(|_| Failure::Resource)
    }
    fn finish_raw<W: Work>(&self, state: Raw<'a>, work: &W) -> Result<SignatureAnswer, Failure> {
        let input = state.input.ok_or(Failure::Account)?;
        // Conservative test-only allowance, not a runtime cost claim.
        work.charge_work(100_000 + input.len() as u64)?;
        self.raw_finishes.set(self.raw_finishes.get() + 1);
        Ok(match state.key.verify_strict(&input, &state.signature) {
            Ok(()) => SignatureAnswer::Valid,
            Err(_) => SignatureAnswer::Invalid,
        })
    }
    fn verify_prehashed<W: Work>(
        &'a self,
        (): &(),
        _key: WorkingKey<'a>,
        _signature: &Octets<'a>,
        _digest: Prehash<'_, '_, Self, ()>,
        _work: &W,
    ) -> Result<SignatureAnswer, Failure> {
        Err(Failure::Prehash)
    }
}

fn authority(signing: &SigningKey) -> Vec<u8> {
    // Synthetic TSA certificate from the RFC8032 test key, critical
    // timeStamping EKU as RFC3161 §2.3 requires.
    let algorithm = tlv(0x30, &tlv(6, ED25519));
    let mut attribute = tlv(6, &[0x55, 4, 3]);
    attribute.extend(tlv(12, b"Test Authority"));
    let name = tlv(0x30, &tlv(0x31, &tlv(0x30, &attribute)));
    let mut validity = tlv(0x17, b"250101000000Z");
    validity.extend(tlv(0x17, b"300101000000Z"));
    let mut bits = vec![0];
    bits.extend(signing.verifying_key().to_bytes());
    let mut spki = algorithm.clone();
    spki.extend(tlv(3, &bits));
    let mut key_identifier = tlv(6, structured_pkix::oid::SUBJECT_KEY_IDENTIFIER.as_bytes());
    key_identifier.extend(tlv(4, &tlv(4, &[7])));
    let mut eku = tlv(6, structured_pkix::oid::EXT_KEY_USAGE.as_bytes());
    eku.extend([1, 1, 0xff]);
    eku.extend(tlv(
        4,
        &tlv(
            0x30,
            &tlv(6, structured_pkix::oid::TIME_STAMPING.as_bytes()),
        ),
    ));
    let mut extensions = tlv(0x30, &key_identifier);
    extensions.extend(tlv(0x30, &eku));
    let mut tbs = vec![0xa0, 3, 2, 1, 2, 2, 1, 1];
    tbs.extend(&algorithm);
    tbs.extend(&name);
    tbs.extend(tlv(0x30, &validity));
    tbs.extend(&name);
    tbs.extend(tlv(0x30, &spki));
    tbs.extend(tlv(0xa3, &tlv(0x30, &extensions)));
    let tbs = tlv(0x30, &tbs);
    let mut signature_bits = vec![0];
    signature_bits.extend(signing.sign(&tbs).to_bytes());
    let mut certificate = tbs;
    certificate.extend(algorithm);
    certificate.extend(tlv(3, &signature_bits));
    tlv(0x30, &certificate)
}

fn token(
    signing: &SigningKey,
    certificate: &[u8],
    covered: &[u8],
    stated_accuracy: bool,
) -> Vec<u8> {
    let digest_algorithm = tlv(0x30, &tlv(6, SHA512));
    let mut imprint = digest_algorithm.clone();
    imprint.extend(tlv(4, &Sha512::digest(covered)));
    let mut info = vec![2, 1, 1, 6, 1, 43];
    info.extend(tlv(0x30, &imprint));
    info.extend([2, 1, 7]);
    info.extend(tlv(0x18, b"20260101000000Z"));
    if stated_accuracy {
        info.extend([0x30, 0]);
    }
    let info = tlv(0x30, &info);
    let mut content_type = tlv(6, oid::CONTENT_TYPE.as_bytes());
    content_type.extend(tlv(0x31, &tlv(6, oid::TST_INFO.as_bytes())));
    let mut digest = tlv(6, oid::MESSAGE_DIGEST.as_bytes());
    digest.extend(tlv(0x31, &tlv(4, &Sha512::digest(&info))));
    let mut ess_identifier = digest_algorithm.clone();
    ess_identifier.extend(tlv(4, &Sha512::digest(certificate)));
    let ess = tlv(0x30, &tlv(0x30, &tlv(0x30, &ess_identifier)));
    let mut signing_certificate = tlv(6, oid::SIGNING_CERTIFICATE_V2.as_bytes());
    signing_certificate.extend(tlv(0x31, &ess));
    let mut attributes = [
        tlv(0x30, &content_type),
        tlv(0x30, &digest),
        tlv(0x30, &signing_certificate),
    ];
    attributes.sort();
    let mut signed = tlv(0x31, &attributes.concat());
    let signature = signing.sign(&signed).to_bytes();
    signed[0] = 0xa0;
    let mut signer_fields = vec![2, 1, 3, 0x80, 1, 7];
    signer_fields.extend(&digest_algorithm);
    signer_fields.extend(signed);
    signer_fields.extend(tlv(0x30, &tlv(6, ED25519)));
    signer_fields.extend(tlv(4, &signature));
    let mut content = tlv(6, oid::TST_INFO.as_bytes());
    content.extend(tlv(0xa0, &tlv(4, &info)));
    let mut fields = vec![2, 1, 3];
    fields.extend(tlv(0x31, &digest_algorithm));
    fields.extend(tlv(0x30, &content));
    fields.extend(tlv(0x31, &tlv(0x30, &signer_fields)));
    let mut envelope = tlv(6, oid::SIGNED_DATA.as_bytes());
    envelope.extend(tlv(0xa0, &tlv(0x30, &fields)));
    tlv(0x30, &envelope)
}

/// Complete CMS token check over exactly `input`, retaining its evidence.
pub fn evidence(stamped: &[u8], input: &[u8], memory: &Memory) -> Option<Evidence> {
    evidence_with_policy(stamped, input, memory, None)
}

pub fn evidence_with_policy(
    stamped: &[u8],
    input: &[u8],
    memory: &Memory,
    policy: Option<structured_cms::timestamp::PolicyAccuracy<'_>>,
) -> Option<Evidence> {
    let signing = SigningKey::from_bytes(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);
    let certificate_bytes = authority(&signing);
    let bytes = token(&signing, &certificate_bytes, stamped, policy.is_none());
    let parser = Parser::ber(memory.clone());
    let certificates = Parser::der(memory.clone());
    let token = Token::read(&parser, &bytes, 400).unwrap();
    let parent = parser.read(&[], 400).unwrap();
    let certificate = Certificate::read(&certificates, &certificate_bytes, 900).unwrap();
    let certificate_parent = certificates.read(&[], 900).unwrap();
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let provider = Oracle {
        key: signing.verifying_key(),
        raw_finishes: Cell::new(0),
    };
    let context = CheckContext {
        certificate: &certificate,
        certificate_parent: &certificate_parent,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: None,
        utc: &utc,
        reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
        window: None,
        policy_accuracy: policy,
    };
    let checked = token
        .check(&provider, &parent, &context, &mut [input], |_, _| {
            Ok::<_, ()>(false)
        })
        .unwrap();
    assert_eq!(provider.raw_finishes.get(), 1);
    checked.into_evidence()
}
