//! Exact digest range and execution tests for the DER policy envelope.

use core::{cell::Cell, cmp::Ordering};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    digest::{Digest, Resolution},
    memory::{Memory, MemoryAccount, MemoryError, Work},
};
use structured_cms::{
    ErrorCode,
    signature_policy::{Asn1Policy, PolicyDigestError},
};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

const ALGORITHM: &[u8] = &[48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1];

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag, u8::try_from(content.len()).unwrap()];
    bytes.extend(content);
    bytes
}

fn information() -> Vec<u8> {
    let at = tlv(24, b"20261126000000Z");
    let period = tlv(48, &at);
    let rules = tlv(48, &[period.as_slice(), &[48, 0, 48, 0]].concat());
    let issuer = tlv(48, &tlv(0x82, b"policy.test"));
    tlv(
        48,
        &[
            &[6, 2, 42, 3][..],
            &at,
            &issuer,
            &tlv(12, b"application"),
            &rules,
        ]
        .concat(),
    )
}

fn document(covered: &[u8], stored: Option<&[u8]>) -> Vec<u8> {
    let mut contents = covered.to_vec();
    if let Some(stored) = stored {
        contents.extend(tlv(4, stored));
    }
    tlv(48, &contents)
}

#[derive(Default)]
struct Provider {
    starts: Cell<usize>,
    updates: Cell<usize>,
}

impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<Self::Identity> {
        (algorithm == Algorithm::Sha256).then_some(())
    }
}

impl Digest<'_> for Provider {
    type Identity = ();
    type State = Sha256;
    type Output = [u8; 32];
    type Error = MemoryError;

    fn width(&self, (): &()) -> Option<usize> {
        Some(32)
    }

    fn compare<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Self::Error> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }

    fn start<W: Work>(&self, (): &(), work: &W) -> Result<Resolution<Self::State>, Self::Error> {
        work.charge_work(1)?;
        self.starts.set(self.starts.get() + 1);
        Ok(Resolution::Supported(Sha256::new()))
    }

    fn update<W: Work>(
        &self,
        state: &mut Self::State,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), Self::Error> {
        work.charge_work(bytes.len() as u64)?;
        self.updates.set(self.updates.get() + 1);
        state.update(bytes);
        Ok(())
    }

    fn finish<W: Work>(&self, state: Self::State, work: &W) -> Result<Self::Output, Self::Error> {
        work.charge_work(1)?;
        Ok(state.finalize().into())
    }

    fn matches<W: Work>(
        &self,
        (): &(),
        output: &Self::Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Self::Error> {
        work.charge_work(expected.len() as u64)?;
        Ok(output.as_slice() == expected)
    }
}

#[test]
fn hashes_the_original_pair_in_one_update_without_digest_storage() {
    // The complete original pair is borrowed. The outer header and optional
    // stored digest must never enter the hash, even when they are present.
    let covered = [ALGORITHM, &information()].concat();
    let expected = Sha256::digest(&covered);
    for stored in [None, Some(expected.as_slice())] {
        let bytes = document(&covered, stored);
        let producer = Parser::der(memory(1 << 20, 100_000));
        let mut parent = producer.read(&bytes, 900).unwrap();
        let policy = Asn1Policy::read(&mut parent).unwrap();
        assert_eq!(policy.identifier().as_bytes(), &[42, 3]);
        assert_eq!(policy.covered_bytes(), covered);
        assert_eq!(policy.covered_bytes().as_ptr(), bytes[2..].as_ptr());
        assert_eq!(policy.stored_digest().map(|(bytes, _)| bytes), stored);
        let current = memory(0, 100_000);
        let provider = Provider::default();
        assert_eq!(
            policy
                .digest(&provider, Algorithm::Sha256, &current)
                .unwrap()
                .as_bytes(),
            expected.as_slice(),
        );
        assert_eq!(provider.starts.get(), 1);
        assert_eq!(provider.updates.get(), 1);
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn algorithm_width_and_stored_digest_fail_at_their_own_boundary() {
    // Method and width contradictions never start the backend. A same-width
    // false embedded digest is a distinct result after one hash.
    let covered = [ALGORITHM, &information()].concat();
    let producer = Parser::der(memory(1 << 20, 100_000));
    let current = memory(0, 100_000);
    for (digest, starts) in [(&[9; 31][..], 0), (&[9; 32][..], 1)] {
        let bytes = document(&covered, Some(digest));
        let mut parent = producer.read(&bytes, 900).unwrap();
        let policy = Asn1Policy::read(&mut parent).unwrap();
        let provider = Provider::default();
        assert!(matches!(
            policy.digest(&provider, Algorithm::Sha384, &current),
            Err(PolicyDigestError::AlgorithmMismatch {
                selected: Algorithm::Sha384,
                written: Algorithm::Sha256
            })
        ));
        assert_eq!(provider.starts.get(), 0);
        let result = policy.digest(&provider, Algorithm::Sha256, &current);
        let (_, span) = policy.stored_digest().unwrap();
        match result {
            Err(PolicyDigestError::Processing(cause)) if starts == 0 => {
                assert_eq!(cause.code(), ErrorCode::DigestWidth);
                assert_eq!(cause.offset(), span.start);
            }
            Err(PolicyDigestError::StoredDigestMismatch(location)) if starts == 1 => {
                assert_eq!(location, span);
            }
            _ => panic!("unexpected policy result"),
        }
        assert_eq!(provider.starts.get(), starts);
        assert_eq!(provider.updates.get(), starts);
    }
}

#[test]
fn rejects_ber_and_extra_fields_even_under_a_ber_reader() {
    // The digest scope is fixed by DER and the exact envelope, never by
    // a re-encoder that could normalize untrusted bytes.
    let covered = [ALGORITHM, &information()].concat();
    let der = document(&covered, None);
    let indefinite = [&[48, 128][..], &covered, &[0, 0]].concat();
    let extra = tlv(48, &[covered.as_slice(), &[4, 1, 9, 5, 0]].concat());
    let producer = Parser::ber(memory(1 << 20, 100_000));
    assert!(Asn1Policy::read(&mut producer.read(&der, 900).unwrap()).is_ok());
    for bytes in [indefinite, extra, [&der[..], &[5, 0]].concat()] {
        assert!(Asn1Policy::read(&mut producer.read(&bytes, 900).unwrap()).is_err());
    }
}

#[test]
fn hashing_keeps_the_producing_and_current_work_limits() {
    // Exhaust independently the active account and the original parser's
    // local Work. A fresh aggregate must not unblock the latter.
    let bytes = document(&[ALGORITHM, &information()].concat(), None);
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 10_000,
            ..Limits::default()
        },
        memory(1 << 20, 100_000),
    );
    let parsed = Asn1Policy::read(&mut source.read(&bytes, 900).unwrap()).unwrap();
    let provider = Provider::default();
    assert!(matches!(
        parsed.digest(&provider, Algorithm::Sha256, &memory(0, 0)),
        Err(PolicyDigestError::Processing(cause)) if cause.is_resource()
    ));
    let scope = source.execution_in(source.memory());
    scope.charge_work(scope.work_remaining() as u64).unwrap();
    assert!(source.memory().work_remaining() > 0);
    assert!(matches!(
        parsed.digest(&provider, Algorithm::Sha256, &memory(0, 100_000)),
        Err(PolicyDigestError::Processing(cause)) if cause.is_resource()
    ));
    assert_eq!(provider.starts.get(), 0);
}
