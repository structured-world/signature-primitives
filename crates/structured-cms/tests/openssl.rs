//! OpenSSL interoperability and private-key import refusal tests.
#![cfg(feature = "openssl")]

use std::sync::Arc;

use der::{Decode, Encode, asn1::ObjectIdentifier};
use pkcs8::PrivateKeyInfoRef;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
use structured_cms::openssl::{Envelope, Error, Key, KeyFamily};
use zeroize::Zeroizing;

fn work(limit: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(0, limit)))
}

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

const IV_AES: &str = "0102030405060708090a0b0c0d0e0f10";
const IV_DES: &str = "0102030405060708";
const AES128: &str = "a20c286ed74f780bd6c8fcf7fd15e873c3637b02ef928f0bb088a175a033e830";

#[test]
fn openssl_envelope_vectors() {
    // OpenSSL 4.0.3 enc -<cipher> -provider default -provider legacy
    // -md md5 -S 0102030405060708 -iv <iv> -pass pass:test.
    let vectors = [
        ("AES-128-CBC", IV_AES, AES128),
        (
            "AES-192-CBC",
            IV_AES,
            "df8c20e204909995e8ff03a883698d18316abfcc5eb69fcc9784952c00e78438",
        ),
        (
            "AES-256-CBC",
            IV_AES,
            "ba999ba37150c78010f2ad58e95e5a576f58114a6002a6ab38bca3325fde6809",
        ),
        (
            "DES-CBC",
            IV_DES,
            "0216fd6c09dd246ef545f779c4bf7368782ee346d998ce9602109c977dd226d2",
        ),
        (
            "DES-EDE-CBC",
            IV_DES,
            "f9318952866b982269e99ed5ae3e3c248b346b68476348cc14270e08adcd0089",
        ),
        (
            "DES-EDE3-CBC",
            IV_DES,
            "caee3a3699b531b51508aa75252d6bbe73e683b0b1c253471190c50974600abb",
        ),
    ];
    let work = work(4096);
    for (cipher, iv, ciphertext) in vectors {
        let headers = format!("Proc-Type: 4,ENCRYPTED\r\nDEK-Info: {cipher},{iv}\r\n");
        let envelope = Envelope::read(&headers, &work).unwrap().unwrap();
        let mut buffer = Zeroizing::new(hex(ciphertext));
        let length = envelope
            .decrypt_in_place(&mut buffer, Some(b"test"), &work)
            .unwrap();
        assert_eq!(&buffer[..length], b"traditional envelope test");
        assert!(buffer[length..].iter().all(|&byte| byte == 0));
    }
}

#[test]
fn protected_failures_do_not_fall_back() {
    // Recognized malformed headers must remain protected, independent of order.
    let budget = work(4096);
    for headers in [
        "DEK-Info: AES-128-CBC,00",
        "Proc-Type: 4,ENCRYPTED",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0102030405060708",
        "Proc-Type: 4,ENCRYPTED\nDEK-Info: DES-CBC,010203040506070g",
        "Unknown: 1\nProc-Type: 4,ENCRYPTED",
        "Proc-Type: 4,ENCRYPTED\nProc-Type: 4,ENCRYPTED",
    ] {
        assert_eq!(
            Envelope::read(headers, &budget).err(),
            Some(Error::Protected)
        );
    }
    assert!(Envelope::read("", &budget).unwrap().is_none());
    assert_eq!(
        Envelope::read("Unknown: 1", &budget).err(),
        Some(Error::NotTraditional)
    );
    let headers = format!("Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,{IV_AES}");
    let envelope = Envelope::read(&headers, &budget).unwrap().unwrap();
    let original = hex(AES128);
    let mut buffer = original.clone();
    assert_eq!(
        envelope.decrypt_in_place(&mut buffer, None, &budget),
        Err(Error::Protected)
    );
    assert_eq!(
        envelope.decrypt_in_place(&mut buffer, Some(b"test"), &work(0)),
        Err(Error::Resource(MemoryError::WorkExceeded))
    );
    assert_eq!(buffer, original);
    assert_eq!(
        envelope.decrypt_in_place(&mut buffer[..15], Some(b"test"), &budget),
        Err(Error::Protected)
    );
    assert_eq!(buffer, original);
    assert_eq!(
        envelope.decrypt_in_place(&mut buffer, Some(b"wrong"), &budget),
        Err(Error::Protected)
    );
    assert!(buffer.iter().all(|&byte| byte == 0));
}

const P256: &[u8] = include_bytes!("fixtures/openssl/prime256v1.sec1.der");
const P384: &[u8] = include_bytes!("fixtures/openssl/secp384r1.sec1.der");
const P521: &[u8] = include_bytes!("fixtures/openssl/secp521r1.sec1.der");
const DSA: &[u8] = include_bytes!("fixtures/openssl/dsa.der");

#[test]
fn ec_key_round_trip_and_inference() {
    // OpenSSL derives the same algorithm and point. Our output keeps the
    // original SEC1 bytes, including parameters that OpenSSL may omit.
    for (original, oracle) in [
        (
            P256,
            include_bytes!("fixtures/openssl/prime256v1.sec1.p8.der").as_slice(),
        ),
        (
            P384,
            include_bytes!("fixtures/openssl/secp384r1.sec1.p8.der").as_slice(),
        ),
        (
            P521,
            include_bytes!("fixtures/openssl/secp521r1.sec1.p8.der").as_slice(),
        ),
    ] {
        let expected = PrivateKeyInfoRef::from_der(oracle).unwrap();
        let mut without_parameters = sec1::EcPrivateKey::from_der(original).unwrap();
        without_parameters.parameters = None;
        let inferred = Zeroizing::new(without_parameters.to_der().unwrap());
        let budget = work(1_000_000);
        for input in [original, inferred.as_slice()] {
            let key = Key::read(input, None, 128, &budget).unwrap();
            let mut output = Zeroizing::new(vec![0xA5; key.encoded_len() + 1]);
            let actual =
                PrivateKeyInfoRef::from_der(key.write(&mut output, &budget).unwrap()).unwrap();
            assert_eq!(actual.algorithm, expected.algorithm);
            assert_eq!(actual.private_key.as_bytes(), input);
            assert_eq!(output[key.encoded_len()], 0xA5);
        }
    }
}

#[test]
fn ec_rejects_mismatched_point_and_version() {
    // d=1 is in range but cannot match the fixture's public point.
    let budget = work(1_000_000);
    let mut key = sec1::EcPrivateKey::from_der(P256).unwrap();
    let mut scalar = Zeroizing::new([0; 32]);
    scalar[31] = 1;
    key.private_key = scalar.as_ref();
    let mismatch = Zeroizing::new(key.to_der().unwrap());
    assert_eq!(
        Key::read(&mismatch, Some(KeyFamily::Ec), 128, &budget).err(),
        Some(Error::InvalidKey)
    );
    key.public_key = None;
    key.parameters = None;
    key.private_key = &scalar[1..];
    let short_scalar = Zeroizing::new(key.to_der().unwrap());
    assert_eq!(
        Key::read(&short_scalar, None, 128, &budget).err(),
        Some(Error::InvalidKey)
    );
    let mut wrong_version = Zeroizing::new(P256.to_vec());
    assert_eq!(&wrong_version[2..5], &[2, 1, 1]);
    wrong_version[4] = 2;
    assert_eq!(
        Key::read(&wrong_version, None, 128, &budget).err(),
        Some(Error::InvalidKey)
    );
}

#[test]
fn dsa_output_matches_openssl_and_refuses_inconsistent_key() {
    // A changed private exponent must not match the stored public value.
    let budget = work(10_000_000);
    let expected = include_bytes!("fixtures/openssl/dsa.p8.der");
    let key = Key::read(DSA, None, 128, &budget).unwrap();
    assert_eq!(key.encoded_len(), expected.len());
    let mut output = Zeroizing::new(vec![0xA5; expected.len()]);
    assert_eq!(
        key.write(&mut output[..expected.len() - 1], &budget),
        Err(Error::OutputTooShort {
            required: expected.len()
        })
    );
    assert_eq!(
        key.write(&mut output, &work(0)),
        Err(Error::Resource(MemoryError::WorkExceeded))
    );
    assert!(output.iter().all(|&byte| byte == 0xA5));
    assert_eq!(key.write(&mut output, &budget).unwrap(), expected);
    let p8 = PrivateKeyInfoRef::from_der(expected).unwrap();
    assert_eq!(
        p8.algorithm.oid,
        ObjectIdentifier::new_unwrap("1.2.840.10040.4.1")
    );
    assert_eq!(
        Key::read(expected, None, 128, &budget).err(),
        Some(Error::NotTraditional)
    );
    assert_eq!(
        Key::read(DSA, None, 127, &work(DSA.len())).err(),
        Some(Error::ComponentLimit)
    );
    assert_eq!(
        Key::read(DSA, None, 128, &work(DSA.len())).err(),
        Some(Error::Resource(MemoryError::WorkExceeded))
    );
    let mut inconsistent = Zeroizing::new(DSA.to_vec());
    let last = inconsistent.last_mut().unwrap();
    *last ^= 1;
    assert_eq!(
        Key::read(&inconsistent, None, 128, &budget).err(),
        Some(Error::InvalidKey)
    );
    let mut wrong_version = Zeroizing::new(DSA.to_vec());
    assert_eq!(&wrong_version[4..7], &[2, 1, 0]);
    wrong_version[6] = 1;
    assert_eq!(
        Key::read(&wrong_version, None, 128, &budget).err(),
        Some(Error::InvalidKey)
    );
}
