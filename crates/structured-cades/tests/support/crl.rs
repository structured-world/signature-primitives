//! Actual complete-list ECDSA fixture used by the timestamp/material scenario.

use crate::support::{ECDSA, name, tlv};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

pub fn crl(signer: &SigningKey) -> Vec<u8> {
    let algorithm = tlv(0x30, &tlv(6, ECDSA));
    let tbs = tlv(
        0x30,
        &[
            vec![2, 1, 1],
            algorithm.clone(),
            name("Root"),
            tlv(23, b"260101000000Z"),
            tlv(23, b"270101000000Z"),
        ]
        .concat(),
    );
    let signature: Signature = signer.sign_prehash(&Sha256::digest(&tbs)).unwrap();
    let mut bits = vec![0];
    bits.extend(signature.to_der().as_bytes());
    tlv(0x30, &[tbs, algorithm, tlv(3, &bits)].concat())
}
