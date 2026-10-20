//! Shared fixed-curve certificate fixtures for integration tests.

use core::cell::Cell;
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_pkix::{
    AlgorithmIdentifier, oid,
    path::{Verified, Verify, WorkingKey},
};

const ECDSA: &[u8] = &[42, 134, 72, 206, 61, 4, 3, 2];
const CURVE: &[u8] = &[42, 134, 72, 206, 61, 3, 1, 7];

pub fn memory(capacity: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, 1 << 24)))
}

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
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

pub fn certificate(subject: &str, issuer: &str, key: &SigningKey, signer: &SigningKey) -> Vec<u8> {
    // Trusted DEV fixture writer. Its signatures are checked with the actual
    // issuer public key, not an always-Yes callback or fake RSA payload.
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

pub struct Oracle {
    pub calls: Cell<usize>,
}
impl<E: Work> Verify<E> for Oracle {
    type Error = MemoryError;
    fn verify(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        signed: &[u8],
        signature: structured_pkix::signature::SignatureValue<'_>,
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
