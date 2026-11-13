//! Canonical Base64 profiles used by JOSE.

use structured_base64::{Base64Error, STANDARD, URL_SAFE_NO_PAD};

// RFC 4648 section 10 vectors plus the two alphabet-specific characters.
#[test]
fn vectors_and_exact_buffers() {
    for (plain, standard, url) in [
        (&b""[..], &b""[..], &b""[..]),
        (b"f", b"Zg==", b"Zg"),
        (b"fo", b"Zm8=", b"Zm8"),
        (b"foo", b"Zm9v", b"Zm9v"),
        (b"foob", b"Zm9vYg==", b"Zm9vYg"),
        (b"fooba", b"Zm9vYmE=", b"Zm9vYmE"),
        (b"foobar", b"Zm9vYmFy", b"Zm9vYmFy"),
        (&[251, 255], b"+/8=", b"-_8"),
    ] {
        for (profile, expected) in [(STANDARD, standard), (URL_SAFE_NO_PAD, url)] {
            let mut encoded = [0; 8];
            let mut decoded = [0; 6];
            assert_eq!(profile.encoded_len(plain.len()), Some(expected.len()));
            assert_eq!(
                profile.encode_slice(plain, &mut encoded[..expected.len()]),
                Ok(expected.len())
            );
            assert_eq!(&encoded[..expected.len()], expected);
            assert_eq!(
                profile.decode_slice(expected, &mut decoded[..plain.len()]),
                Ok(plain.len())
            );
            assert_eq!(&decoded[..plain.len()], plain);
        }
    }
}

// Each profile rejects other spellings of a canonical JOSE value.
#[test]
fn rejects_noncanonical_input() {
    let mut output = [0; 16];
    for input in [&b"Z g"[..], b"Zg==", b"A", b"+/8", b"Zh", b"Zm9", b"Zg\n"] {
        assert!(
            URL_SAFE_NO_PAD.decode_slice(input, &mut output).is_err(),
            "{input:?}"
        );
    }
    for input in [
        &b"Z g="[..],
        b"Zg",
        b"Zg=",
        b"Z===",
        b"====",
        b"Zg==AAAA",
        b"Zh==",
        b"Zm9=",
        b"-_8=",
    ] {
        assert!(
            STANDARD.decode_slice(input, &mut output).is_err(),
            "{input:?}"
        );
    }
}

// Encoding checks capacity before writing, including at the integer limit.
#[test]
fn capacity_is_checked() {
    for profile in [STANDARD, URL_SAFE_NO_PAD] {
        let mut output = [0; 3];
        assert_eq!(profile.encoded_len(usize::MAX), None);
        assert_eq!(
            profile.encode_slice(b"foo", &mut output),
            Err(Base64Error::OutputFull)
        );
        assert_eq!(output, [0; 3]);
        assert_eq!(
            profile.decode_slice(b"Zm9v", &mut output[..2]),
            Err(Base64Error::OutputFull)
        );
    }
}

// Allocating methods use the same canonical encoding and validation.
#[cfg(feature = "alloc")]
#[test]
fn owned_conveniences() {
    for (profile, expected) in [(STANDARD, "+/8="), (URL_SAFE_NO_PAD, "-_8")] {
        assert_eq!(profile.encode(&[251, 255]).unwrap(), expected);
        assert_eq!(profile.decode(expected.as_bytes()).unwrap(), [251, 255]);
        assert!(profile.decode(b"\n").is_err());
    }
}
