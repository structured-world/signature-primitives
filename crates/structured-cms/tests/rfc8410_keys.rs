//! RFC8032 raw-key verification oracle; no production backend cost claim.

use ed25519_dalek::{Signature, VerifyingKey};
use std::sync::Arc;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_pkix::{
    PublicKeyInfo,
    key::rfc8410::{self, Algorithm},
};

fn hex<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0; N];
    let (pairs, tail) = value.as_bytes().as_chunks::<2>();
    assert_eq!(tail, []);
    assert_eq!(pairs.len(), N);
    for (byte, pair) in output.iter_mut().zip(pairs) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    output
}

#[test]
fn rfc8032_empty_message_signature_uses_the_borrowed_raw_key() {
    // RFC8032 §7.1 test1: a real selected backend consumes the shared raw
    // key without invoking a second SPKI/DER parser or changing its bytes.
    let public = hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = Signature::from_bytes(&hex::<64>(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ));
    let mut bytes = vec![0x30, 0x2a, 0x30, 5, 6, 3, 43, 101, 112, 3, 33, 0];
    bytes.extend(public);
    let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
    let parser = Parser::der(memory.clone());
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let info = PublicKeyInfo::read_element(&reader, &element, "key").unwrap();
    let key = rfc8410::read(info, &memory).unwrap();
    assert_eq!(key.algorithm(), Algorithm::Ed25519);
    let verifier = VerifyingKey::from_bytes(key.as_bytes().try_into().unwrap()).unwrap();
    verifier.verify_strict(b"", &signature).unwrap();
    assert!(verifier.verify_strict(b"changed", &signature).is_err());
    assert_eq!(key.as_bytes().as_ptr(), bytes[12..].as_ptr());
}

#[test]
fn readable_low_order_key_does_not_become_signature_acceptance() {
    // Width/parameters alone do not establish a usable Edwards point. A
    // zero encoding passes structure and is rejected by strict verification.
    let mut bytes = vec![0x30, 0x2a, 0x30, 5, 6, 3, 43, 101, 112, 3, 33, 0];
    bytes.extend([0; 32]);
    let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
    let parser = Parser::der(memory.clone());
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let info = PublicKeyInfo::read_element(&reader, &element, "key").unwrap();
    let key = rfc8410::read(info, &memory).unwrap();
    let verifier = VerifyingKey::from_bytes(key.as_bytes().try_into().unwrap()).unwrap();
    assert!(verifier.is_weak());
    assert!(
        verifier
            .verify_strict(b"", &Signature::from_bytes(&[0; 64]))
            .is_err()
    );
}
