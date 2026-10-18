//! RFC6979's public P-256 vector through the finalized-prehash CMS boundary.
//! Test-only fixed-curve adapter; no production backend or cost-model claim.

use core::{cell::Cell, cmp::Ordering, fmt};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Parser, Reader};
use structured_cms::provider::{Prehash, SignatureAnswer, SignatureMode, SignatureProvider};
use structured_cms::{Octets, binding, oid, prepare, signer::SignerInfo, verify};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
use structured_pkix::{AlgorithmIdentifier, PublicKeyInfo, path::WorkingKey};

const SHA256: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2];
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1];
const CURVE: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];

#[derive(Debug)]
enum Fault {
    Resource(MemoryError),
    Asn(structured_asn1::Error),
    Pkix(structured_pkix::Error),
    WrongMode,
}

impl fmt::Display for Fault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource(error) => error.fmt(formatter),
            Self::Asn(error) => error.fmt(formatter),
            Self::Pkix(error) => error.fmt(formatter),
            Self::WrongMode => formatter.write_str("raw input is not selected"),
        }
    }
}

impl From<MemoryError> for Fault {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

struct Oracle {
    public: [u8; 65],
    key: VerifyingKey,
    starts: Cell<usize>,
    finishes: Cell<usize>,
    verifications: Cell<usize>,
    received: Cell<[u8; 32]>,
}

impl<'a> structured_asn1::digest::Digest<'a> for Oracle {
    // Only SHA256 is supported; the shared resolver reads its parameters.
    type Identity = ();
    type State = Sha256;
    type Output = [u8; 32];
    type Error = Fault;

    fn width(&self, (): &()) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Fault> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&'a self, (): &(), work: &W) -> Result<Resolution<Sha256>, Fault> {
        work.charge_work(64)?;
        self.starts.set(self.starts.get() + 1);
        Ok(Resolution::Supported(Sha256::new()))
    }
    fn update<W: Work>(&self, state: &mut Sha256, bytes: &[u8], work: &W) -> Result<(), Fault> {
        work.charge_work(bytes.len() as u64 + 64)?;
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, work: &W) -> Result<[u8; 32], Fault> {
        work.charge_work(128)?;
        self.finishes.set(self.finishes.get() + 1);
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &[u8; 32],
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Fault> {
        work.charge_work(32)?;
        Ok(output.as_slice() == expected)
    }
}

impl AsnDigest<'_> for Oracle {
    fn identity(&self, algorithm: Algorithm) -> Option<()> {
        (algorithm == Algorithm::Sha256).then_some(())
    }
}

impl<'a> SignatureProvider<'a> for Oracle {
    type SignatureIdentity = ();
    type RawState = ();
    fn resolve_signature(
        &'a self,
        identifier: AlgorithmIdentifier<'a>,
        (): &(),
        key: WorkingKey<'a>,
        _encoding: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<SignatureMode<()>>, Fault> {
        parent.execution().charge_work(100)?;
        if identifier.algorithm().as_bytes() != ECDSA_SHA256
            || key.key().algorithm().algorithm().as_bytes() != EC
        {
            return Ok(Resolution::Unsupported);
        }
        // RFC5758 §3.2 requires absent ECDSA signature parameters; RFC5480
        // §2.1.1 requires the written named-curve parameters for this fixture.
        if identifier.parameters().is_some()
            || key.key().key_octets() != Some(self.public.as_slice())
        {
            return Ok(Resolution::Malformed);
        }
        let Some(mut reader) = key
            .key()
            .algorithm()
            .parameters_reader_in(parent, "key.parameters")
            .map_err(Fault::Pkix)?
        else {
            return Ok(Resolution::Malformed);
        };
        let curve = reader.read_oid().map_err(Fault::Asn)?;
        parent.execution().charge_work(CURVE.len() as u64)?;
        if curve.as_bytes() != CURVE {
            return Ok(Resolution::Unsupported);
        }
        Ok(Resolution::Supported(SignatureMode::Prehashed(())))
    }
    fn compare_signature<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Fault> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start_raw<W: Work>(
        &'a self,
        (): &(),
        _key: WorkingKey<'a>,
        _signature: &'a Octets<'a>,
        _work: &W,
    ) -> Result<(), Fault> {
        Err(Fault::WrongMode)
    }
    fn update_raw<W: Work>(&self, (): &mut (), _bytes: &[u8], _work: &W) -> Result<(), Fault> {
        Err(Fault::WrongMode)
    }
    fn finish_raw<W: Work>(&self, (): (), _work: &W) -> Result<SignatureAnswer, Fault> {
        Err(Fault::WrongMode)
    }
    fn verify_prehashed<W: Work>(
        &'a self,
        (): &(),
        _key: WorkingKey<'a>,
        signature: &Octets<'a>,
        digest: Prehash<'_, '_, Self, ()>,
        work: &W,
    ) -> Result<SignatureAnswer, Fault> {
        // Fixed-size DER parsing/curve arithmetic and the captured digest copy
        // are admitted before the test oracle. No hashing occurs in this method.
        work.charge_work(100_000 + signature.len() as u64 + 32)?;
        let Some(bytes) = signature.as_one() else {
            return Err(Fault::WrongMode);
        };
        self.received
            .set(digest.as_bytes().try_into().map_err(|_| Fault::WrongMode)?);
        self.verifications.set(self.verifications.get() + 1);
        let Ok(signature) = Signature::from_der(bytes) else {
            return Ok(SignatureAnswer::Invalid);
        };
        Ok(
            match self.key.verify_prehash(digest.as_bytes(), &signature) {
                Ok(()) => SignatureAnswer::Valid,
                Err(_) => SignatureAnswer::Invalid,
            },
        )
    }
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut bytes = [0; N];
    for (target, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |value: u8| match value {
            b'0'..=b'9' => value - b'0',
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("invalid public vector"),
        };
        *target = digit(pair[0]) * 16 + digit(pair[1]);
    }
    bytes
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    assert!(contents.len() < 128);
    let mut result = vec![tag, u8::try_from(contents.len()).unwrap()];
    result.extend_from_slice(contents);
    result
}

fn check(message: &[u8], null: bool) -> SignatureAnswer {
    // RFC6979 AppendixA.2.5 public key and SHA256("sample") signature.
    // https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
    let mut public = [0; 65];
    public[0] = 4;
    public[1..33].copy_from_slice(&hex::<32>(
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
    ));
    public[33..].copy_from_slice(&hex::<32>(
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
    ));
    let signature = Signature::from_scalars(
        hex::<32>("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
        hex::<32>("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
    )
    .unwrap()
    .to_der();
    let mut digest_algorithm = tlv(6, SHA256);
    if null {
        digest_algorithm.extend_from_slice(&[5, 0]);
    }
    let mut contents = vec![2, 1, 3, 0x80, 1, 7];
    contents.extend(tlv(0x30, &digest_algorithm));
    contents.extend(tlv(0x30, &tlv(6, ECDSA_SHA256)));
    contents.extend(tlv(4, signature.as_bytes()));
    let encoded = tlv(0x30, &contents);
    let mut key_algorithm = tlv(6, EC);
    key_algorithm.extend(tlv(6, CURVE));
    let mut key = tlv(0x30, &key_algorithm);
    let mut bits = vec![0];
    bits.extend_from_slice(&public);
    key.extend(tlv(3, &bits));
    let spki = tlv(0x30, &key);
    let memory = Memory::new(Arc::new(MemoryAccount::new(100_000, 1_000_000)));
    let parser = Parser::der(memory.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&reader, &element).unwrap();
    let mut key_reader = parser.read(&spki, 900).unwrap();
    let element = key_reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&key_reader, &element, "key").unwrap();
    let provider = Oracle {
        public,
        key: VerifyingKey::from_sec1_bytes(&public).unwrap(),
        starts: Cell::new(0),
        finishes: Cell::new(0),
        verifications: Cell::new(0),
        received: Cell::new([0; 32]),
    };
    let held = memory.used();
    let prepare::Preparation::Ready(ready) = prepare::resolve(
        &provider,
        &signer,
        WorkingKey::standing(key),
        &reader,
        binding::Scope::Content(oid::DATA),
    )
    .unwrap() else {
        panic!("vector mechanism must resolve");
    };
    let mut requests = reader.execution().vector();
    requests.try_push(ready).unwrap();
    let batch = verify::Batch::prepare(
        &provider,
        requests.into_owned(),
        &reader.execution(),
        "signerInfos",
        400,
    )
    .unwrap();
    let split = message.len() / 2;
    let mut source = [&message[..split], &message[split..]];
    let report = batch.run(&mut source, &reader.execution()).unwrap();
    assert_eq!(provider.starts.get(), 1);
    assert_eq!(provider.finishes.get(), 1);
    assert_eq!(provider.verifications.get(), 1);
    assert_eq!(
        provider.received.get(),
        <[u8; 32]>::from(Sha256::digest(message))
    );
    assert!(matches!(
        report[0].content(),
        verify::ContentAgreement::Direct
    ));
    assert!(report[0].signer().faults().is_empty());
    let answer = report[0].signature().unwrap();
    drop(report);
    assert_eq!(memory.used(), held);
    answer
}

#[test]
fn public_vector_receives_one_finalized_digest_without_rehash_or_state_rebuild() {
    // Absent/NULL SHA256 identity spellings verify the same full mechanism.
    // Different content must fail, even with the same width and signing key.
    assert_eq!(check(b"sample", false), SignatureAnswer::Valid);
    assert_eq!(check(b"sample", true), SignatureAnswer::Valid);
    assert_eq!(check(b"test", false), SignatureAnswer::Invalid);
}
