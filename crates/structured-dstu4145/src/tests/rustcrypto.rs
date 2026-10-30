use crate::{ByteOrder, Error, domain::PublicKey, rustcrypto::Signature};
use signature::hazmat::PrehashVerifier;

fn generic_verify<'s, V: PrehashVerifier<Signature<'s>>>(
    verifier: &V,
    hash: &[u8],
    signature: &Signature<'s>,
) -> Result<(), signature::Error> {
    verifier.verify_prehash(hash, signature)
}

/// Existing independent worked examples call this through a generic trait
/// bound: unchanged hashes verify, mutations fail, and bytes remain borrowed.
pub(super) fn check(key: &PublicKey, hash: &[u8], bytes: &[u8], order: ByteOrder, valid: bool) {
    let signature = Signature::new(bytes, order).unwrap();
    assert_eq!(signature.as_ref().as_ptr(), bytes.as_ptr());
    assert_eq!(signature.byte_order(), order);
    assert_eq!(generic_verify(key, hash, &signature).is_ok(), valid);
    assert!(generic_verify(key, &[], &signature).is_err());
    assert!(generic_verify(key, &[0; 65], &signature).is_err());
    let undersized = Signature::new(&[1; 2], order).unwrap();
    assert!(generic_verify(key, hash, &undersized).is_err());
}

/// Structural framing is checked before scalar interpretation, without an
/// implicit endian choice or accepting an empty/odd/oversized signature.
#[test]
fn borrowed_signatures_refuse_invalid_framing() {
    let bytes = [0; 130];
    for length in [0, 1, 3, 127, 129, 130] {
        assert!(matches!(
            Signature::new(&bytes[..length], ByteOrder::LittleEndian),
            Err(Error::InvalidEncoding)
        ));
    }
    for length in [2, 42, 64, 128] {
        assert_eq!(
            Signature::new(&bytes[..length], ByteOrder::BigEndian)
                .unwrap()
                .as_ref(),
            &bytes[..length]
        );
    }
}
