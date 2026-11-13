//! Known-answer and tag verification tests for the standalone HMAC API.
#![cfg(feature = "hmac")]

use structured_cms::hmac::{Algorithm, Error, Mac, authenticate};

fn vector(algorithm: Algorithm, key: &[u8], message: &[u8], hex: &str) {
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert_eq!(remainder, []);
    let expected: Vec<_> = pairs
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(expected.len(), algorithm.output_len());
    assert_eq!(
        authenticate(algorithm, key, message).unwrap().as_bytes(),
        expected
    );
    let mut mac = Mac::begin(algorithm, key).unwrap();
    mac.update(&[]);
    for byte in message {
        mac.update(core::slice::from_ref(byte));
    }
    assert_eq!(mac.finalize().as_bytes(), expected);
}

// RFC 2202 section 3 and RFC 4231 section 4.2 cover every default digest.
#[test]
fn standard_vectors() {
    for (algorithm, hex) in [
        (Algorithm::Sha1, "b617318655057264e28bc0b6fb378c8ef146be00"),
        (
            Algorithm::Sha224,
            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
        ),
        (
            Algorithm::Sha256,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            Algorithm::Sha384,
            concat!(
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c",
                "faea9ea9076ede7f4af152e8b2fa9cb6"
            ),
        ),
        (
            Algorithm::Sha512,
            concat!(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            ),
        ),
    ] {
        vector(algorithm, &[0x0b; 20], b"Hi There", hex);
    }
}

// RFC 2202 section 2 and RFC 2286 section 2 cover the opt-in digests.
#[cfg(feature = "legacy-hmac")]
#[test]
fn legacy_vectors() {
    vector(
        Algorithm::Md5,
        &[0x0b; 16],
        b"Hi There",
        "9294727a3638bb1c13f48ef8158bfc9d",
    );
    vector(
        Algorithm::Ripemd160,
        &[0x0b; 20],
        b"Hi There",
        "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
    );
}

// A key larger than a block is hashed (RFC 4231 section 4.7).
#[test]
fn long_and_empty_keys() {
    vector(
        Algorithm::Sha256,
        &[0xaa; 131],
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    );
    vector(
        Algorithm::Sha256,
        b"",
        b"",
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
    );
}

// Require the exact prefix width and reject changes anywhere in the prefix.
#[test]
fn verifies_only_the_requested_prefix() {
    let start = || {
        let mut mac = Mac::begin(Algorithm::Sha256, b"key").unwrap();
        mac.update(b"data");
        mac
    };
    let tag = start().finalize();
    let bytes = tag.as_bytes();
    for length in 1..=bytes.len() {
        let expected = &bytes[..length];
        assert_eq!(start().verify_truncated(expected, length * 8), Ok(()));
        let mut wrong = expected.to_vec();
        for offset in 0..length {
            wrong[offset] ^= 1;
            assert_eq!(
                start().verify_truncated(&wrong, length * 8),
                Err(Error::Mismatch)
            );
            wrong[offset] ^= 1;
        }
    }
    for (tag, bits) in [
        (&[][..], 0),
        (&bytes[..1], 9),
        (bytes, 128),
        (&[0; 33], 264),
        (bytes, usize::MAX),
    ] {
        assert_eq!(
            start().verify_truncated(tag, bits),
            Err(Error::InvalidTagLength)
        );
    }
}

// Every leftmost bit count authenticates exactly those bits, including the
// partial final octet used by libxmlsec's compatibility ABI.
#[test]
fn verifies_partial_octets() {
    let start = || Mac::begin(Algorithm::Sha256, b"key").unwrap();
    let tag = start().finalize();
    let bytes = tag.as_bytes();
    for bits in 1_usize..=bytes.len() * 8 {
        let mut expected = bytes[..bits.div_ceil(8)].to_vec();
        assert_eq!(start().verify_truncated(&expected, bits), Ok(()));
        assert_eq!(tag.verify_truncated(&expected, bits), Ok(()));
        if !bits.is_multiple_of(8) {
            *expected.last_mut().unwrap() ^= 1;
            assert_eq!(start().verify_truncated(&expected, bits), Ok(()));
        }
        *expected.last_mut().unwrap() ^= 0x80;
        assert_eq!(
            start().verify_truncated(&expected, bits),
            Err(Error::Mismatch)
        );
    }
}
