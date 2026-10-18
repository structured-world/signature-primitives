//! Actual fixed-curve math for original actor-path composition, not trust.

use core::cell::Cell;
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use structured_asn1::{
    BitString, Parser,
    memory::{Memory, MemoryAccount, MemoryError, Work},
};
use structured_ltv::pki::{self, PathOutcome};
use structured_pkix::{
    AlgorithmIdentifier, Certificate, oid,
    path::{
        self, Anchor, Interval, ValidationBounds, ValidationContext, Verified, Verify, WorkingKey,
    },
};

const ECDSA: &[u8] = &[42, 134, 72, 206, 61, 4, 3, 2];
const CURVE: &[u8] = &[42, 134, 72, 206, 61, 3, 1, 7];

fn memory(capacity: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, 1 << 24)))
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if value.len() < 128 {
        result.push(u8::try_from(value.len()).unwrap());
    } else if let Ok(length) = u8::try_from(value.len()) {
        result.extend([0x81, length]);
    } else {
        result.extend([0x82]);
        result.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    }
    result.extend(value);
    result
}

fn name(common: &str) -> Vec<u8> {
    tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(
                0x30,
                &[
                    tlv(6, oid::COMMON_NAME.as_bytes()),
                    tlv(12, common.as_bytes()),
                ]
                .concat(),
            ),
        ),
    )
}

fn certificate(subject: &str, issuer: &str, key: &SigningKey, signer: &SigningKey) -> Vec<u8> {
    // Trusted DEV fixture writer. Its signatures are checked below with the
    // actual issuer public key, not an always-Yes callback or fake RSA payload.
    let algorithm = tlv(0x30, &tlv(6, ECDSA));
    let public = VerifyingKey::from(key).to_sec1_point(false);
    let mut bits = vec![0];
    bits.extend(public.as_bytes());
    let spki = tlv(
        0x30,
        &[
            tlv(
                0x30,
                &[tlv(6, oid::EC_PUBLIC_KEY.as_bytes()), tlv(6, CURVE)].concat(),
            ),
            tlv(3, &bits),
        ]
        .concat(),
    );
    let mut tbs = vec![0xa0, 3, 2, 1, 2, 2, 1, 7];
    tbs.extend(&algorithm);
    tbs.extend(name(issuer));
    tbs.extend(tlv(
        0x30,
        &[tlv(0x17, b"250101000000Z"), tlv(0x17, b"300101000000Z")].concat(),
    ));
    tbs.extend(name(subject));
    tbs.extend(spki);
    let tbs = tlv(0x30, &tbs);
    let signature: Signature = signer.sign_prehash(&Sha256::digest(&tbs)).unwrap();
    let mut bits = vec![0];
    bits.extend(signature.to_der().as_bytes());
    tlv(0x30, &[tbs, algorithm, tlv(3, &bits)].concat())
}

struct Oracle {
    calls: Cell<usize>,
}
impl<E: Work> Verify<E> for Oracle {
    type Error = MemoryError;
    fn verify(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        signed: &[u8],
        signature: BitString<'_>,
        work: &E,
    ) -> Result<Verified, Self::Error> {
        // DEV-only fixed-curve oracle: no claim that this qualifies an opaque
        // production backend's runtime cost. The callback sees current Work.
        work.charge_work(128 + signed.len() as u64 + signature.as_bytes().len() as u64)?;
        self.calls.set(self.calls.get() + 1);
        if algorithm.algorithm().as_bytes() != ECDSA {
            return Ok(Verified::Unsupported);
        }
        let Ok(key) = VerifyingKey::from_sec1_bytes(key.key().key().as_bytes()) else {
            return Ok(Verified::No);
        };
        let Ok(signature) = Signature::from_der(signature.as_bytes()) else {
            return Ok(Verified::No);
        };
        Ok(
            if key
                .verify_prehash(&Sha256::digest(signed), &signature)
                .is_ok()
            {
                Verified::Yes
            } else {
                Verified::No
            },
        )
    }
}

#[test]
fn actor_path_keeps_original_members_and_does_not_verify_projection_twice() {
    // Only the common validator produces the witness. Its path, effective
    // keys and owned member storage remain source-correct across Reader drop.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let leaf_key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let root_bytes = certificate("Root", "Root", &root_key, &root_key);
    let leaf_bytes = certificate("Leaf", "Root", &leaf_key, &root_key);
    let source = Parser::der(memory(1 << 20));
    let root = Certificate::read(&source, &root_bytes, 400).unwrap();
    let leaf = Certificate::read(&source, &leaf_bytes, 800).unwrap();
    let current = memory(1 << 20);
    let operation = Parser::der(current.clone());
    let query = operation.read(&[], 1200).unwrap();
    let work = query.execution();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    let context = ValidationContext {
        execution: &work,
        interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
        policy: path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &oracle,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(checked) =
        pki::check_path(&[&leaf], Anchor::from_certificate(&root), &context).unwrap()
    else {
        panic!("actual P256 leaf signature must pass")
    };
    assert_eq!(oracle.calls.get(), 1);
    assert_eq!(checked.members().len(), 1);
    assert!(core::ptr::eq(
        checked.members()[0].certificate(),
        &raw const leaf
    ));
    assert_eq!(
        checked.members()[0].key().key().as_bytes().as_ptr(),
        leaf.tbs().public_key().as_bytes().as_ptr()
    );
    assert!(core::ptr::eq(
        checked.anchor().certificate().unwrap(),
        &raw const root
    ));
    assert_eq!(checked.interval(), context.interval);
    assert_eq!(
        checked.facts().key.key().as_bytes(),
        leaf.tbs().public_key().as_bytes()
    );
    let held = current.used();
    assert!(held > 0);
    drop(checked);
    assert_eq!(current.used(), 0);
    let mut forged = leaf_bytes.clone();
    *forged.last_mut().unwrap() ^= 1;
    let changed = Certificate::read(&source, &forged, 1600).unwrap();
    assert!(
        matches!(pki::check_path(&[&changed],Anchor::from_certificate(&root),&context).unwrap(),PathOutcome::Rejected(reason) if reason.reason==path::RejectionReason::Signature)
    );
    assert_eq!(oracle.calls.get(), 2);
    assert_eq!(current.used(), 0);
}

#[test]
fn actor_path_refuses_resource_and_local_incomplete_without_partial_members() {
    // Resource, common rejection and local truncation are different outcomes;
    // no failure may leave an accepted partial actor census or leaked scratch.
    let key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let root_bytes = certificate("Root", "Root", &key, &key);
    let leaf_bytes = certificate("Leaf", "Root", &key, &key);
    let source = Parser::der(memory(1 << 20));
    let root = Certificate::read(&source, &root_bytes, 400).unwrap();
    let leaf = Certificate::read(&source, &leaf_bytes, 800).unwrap();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    for (capacity, localwork, incomplete) in [(0, 1_000_000, false), (1 << 20, 0, true)] {
        let current = memory(capacity);
        let operation = Parser::der(current.clone());
        let query = operation.read(&[], 1200).unwrap();
        let work = query.execution();
        let context = ValidationContext {
            execution: &work,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: path::Policy::default(),
            bounds: ValidationBounds {
                work: localwork,
                ..ValidationBounds::default()
            },
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let result = pki::check_path(&[&leaf], Anchor::from_certificate(&root), &context);
        if incomplete {
            assert!(matches!(
                result.unwrap(),
                PathOutcome::Incomplete(path::Truncation::Work)
            ));
        } else {
            assert!(
                matches!(result,Err(path::BuildError::Processing(error)) if error.is_resource())
            );
        }
        assert_eq!(oracle.calls.get(), 0);
        assert_eq!(current.used(), 0);
        assert!(
            matches!(pki::check_path(&[],Anchor::from_certificate(&root),&context).unwrap(),PathOutcome::Rejected(reason) if reason.reason==path::RejectionReason::EmptyPath)
        );
    }
}
