//! PKCS#8 X9.42 private values, including BER fragmentation and decrypted input.
use std::sync::Arc;
use structured_asn1::{
    Parser, Reader,
    memory::{Memory, MemoryAccount},
};
use structured_cms::personal::{Cause, Origin, PrivateKey, Source};
use structured_pkix::key::dh;

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = structured_asn1::length::DerLength::new(value.len() as u64);
    out.extend_from_slice(len.as_bytes());
    out.extend_from_slice(value);
    out
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(48, &parts.concat())
}
fn int(value: u8) -> Vec<u8> {
    tlv(2, &[value])
}
fn container(secret: &[u8], public: bool) -> Vec<u8> {
    let mut parts = vec![
        int(u8::from(public)),
        seq(&[
            tlv(6, dh::IDENTIFIER.as_bytes()),
            seq(&[int(23), int(2), int(11)]),
        ]),
        secret.to_vec(),
    ];
    if public {
        parts.push(tlv(0x81, &[0, 2, 1, 8]));
    }
    seq(&parts)
}
fn key<'a>(reader: &mut Reader<'a>) -> PrivateKey<'a> {
    let element = reader.next_element().unwrap().unwrap();
    PrivateKey::read(reader, &element).unwrap()
}

#[test]
fn private_values_are_borrowed_and_one_asymmetric_key_is_supported() {
    // v1/v2 containers share the same DH structure. No secret clone is needed.
    for public in [false, true] {
        let bytes = container(&tlv(4, &int(4)), public);
        let parser = Parser::der(memory(4096, 10000));
        let mut reader = parser.read(&bytes, 300).unwrap();
        let key = key(&mut reader);
        key.with_dh(&reader, &Source::Document, |value, _| {
            assert_eq!(value.x().as_bytes(), [4]);
            assert_eq!(value.parameters().p().as_bytes(), [23]);
            let index = usize::try_from(value.x().element().contents_span().start - 300).unwrap();
            assert_eq!(value.x().as_bytes().as_ptr(), bytes[index..].as_ptr());
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(parser.memory().used(), 0);
    }
}

#[test]
fn fragmented_secret_uses_scoped_wiping_storage_and_preserves_callback_failure() {
    // The carried INTEGER crosses BER fragments. A temporary join is funded
    // and released on success and on the original visitor error alike.
    let fragments = [tlv(4, &[2]), tlv(4, &[1, 4])].concat();
    let bytes = container(&tlv(0x24, &fragments), false);
    let parser = Parser::ber(memory(4096, 10000));
    let mut reader = parser.read(&bytes, 700).unwrap();
    let key = key(&mut reader);
    let retained = parser.memory().used();
    let result = key.with_dh(&reader, &Source::Document, |value, source| {
        assert_eq!(value.x().as_bytes(), [4]);
        assert!(parser.memory().used() > retained);
        let Source::Carried { map, .. } = source else {
            panic!("missing carried source")
        };
        assert!(
            map.offset_in_parent(
                value.x().element().contents_span().start,
                &reader.execution()
            )
            .unwrap()
                > 700
        );
        Err::<(), _>("visitor refused")
    });
    let error = result.unwrap_err();
    assert!(matches!(error.cause, Cause::Callback("visitor refused")));
    assert!(matches!(error.origins[0], Some(Origin::Carried(_))));
    drop(error);
    assert_eq!(parser.memory().used(), retained);
    key.with_dh(&reader, &Source::Document, |_, _| Ok::<_, ()>(()))
        .unwrap();
    assert_eq!(parser.memory().used(), retained);
}

#[test]
fn invalid_carried_der_and_foreign_reader_never_invoke_visitor() {
    // Private x is a complete DER INTEGER, not an arbitrary blob or BER integer.
    for secret in [
        &[5, 0][..],
        &[2, 0],
        &[2, 1, 0xff],
        &[2, 2, 0, 4],
        &[2, 0x81, 1, 4],
        &[2, 1, 4, 5, 0],
    ] {
        let bytes = container(&tlv(4, secret), false);
        let parser = Parser::ber(memory(4096, 10000));
        let mut reader = parser.read(&bytes, 400).unwrap();
        let key = key(&mut reader);
        assert!(
            key.with_dh(&reader, &Source::Document, |_, _| -> Result<(), ()> {
                panic!("invalid key reached visitor")
            })
            .is_err()
        );
    }
    let bytes = container(&tlv(4, &int(4)), false);
    let parser = Parser::der(memory(4096, 10000));
    let mut reader = parser.read(&bytes, 400).unwrap();
    let key = key(&mut reader);
    let other = Parser::der(memory(4096, 10000));
    let foreign = other.read(&[], 0).unwrap();
    let failure = key
        .with_dh(&foreign, &Source::Document, |_, _| -> Result<(), ()> {
            panic!("foreign reader reached visitor")
        })
        .unwrap_err();
    let Cause::Processing(error) = failure.cause else {
        panic!("wrong failure class")
    };
    assert_eq!(
        error.code(),
        structured_cms::ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
    let spent = memory(4096, 0);
    let query = reader.with_execution(&spent);
    let failure = key
        .with_dh(&query, &Source::Document, |_, _| -> Result<(), ()> {
            panic!("spent work reached visitor")
        })
        .unwrap_err();
    let Cause::Processing(error) = failure.cause else {
        panic!("wrong failure class")
    };
    assert!(error.is_resource());
}

#[test]
fn openssl_rfc5114_group3_pkcs8_has_unsigned_full_width_components() {
    // Independently generated public test key, not production secret material.
    let bytes = include_bytes!("fixtures/dh/private.der");
    let parser = Parser::der(memory(16384, 100_000));
    let mut reader = parser.read(bytes, 0).unwrap();
    let key = key(&mut reader);
    key.with_dh(&reader, &Source::Document, |value, _| {
        let params = value.parameters();
        assert_eq!(params.p().as_bytes().len(), 256);
        assert_eq!(params.q().as_bytes().len(), 32);
        assert_eq!(params.g().as_bytes().len(), 256);
        // Expected unsigned value from the independent OpenSSL ASN.1 dump.
        assert_eq!(
            value.x().as_bytes(),
            [
                0x0b, 0xed, 0xed, 0x9a, 0x17, 0x47, 0x15, 0x98, 0x09, 0x66, 0x5e, 0xa3, 0x32, 0x56,
                0xfa, 0x62, 0xb8, 0x72, 0x31, 0x34, 0xc7, 0x5b, 0xee, 0x65, 0x46, 0x08, 0x61, 0xab,
            ]
        );
        assert_eq!(key.secret.as_one().unwrap(), value.x().element().as_bytes());
        Ok::<_, ()>(())
    })
    .unwrap();
}

#[test]
fn private_scoped_decoding_enforces_exact_current_admission_and_releases_storage() {
    // A rejected join or nested decode cannot retain plaintext or call the backend.
    fn run(capacity: usize, work: usize) -> (bool, usize) {
        let fragments = [tlv(4, &[2]), tlv(4, &[1, 4])].concat();
        let bytes = container(&tlv(0x24, &fragments), false);
        let parser = Parser::ber(memory(4096, 10000));
        let mut reader = parser.read(&bytes, 700).unwrap();
        let key = key(&mut reader);
        let current = memory(capacity, work);
        let query = reader.with_execution(&current);
        let mut calls = 0;
        let result = key.with_dh(&query, &Source::Document, |_, _| {
            calls += 1;
            Ok::<_, ()>(())
        });
        let success = match result {
            Ok(()) => {
                assert_eq!(calls, 1);
                true
            }
            Err(error) => {
                assert_eq!(calls, 0);
                let Cause::Processing(source) = error.cause else {
                    panic!("not a processing failure")
                };
                assert!(source.is_resource());
                false
            }
        };
        assert_eq!(current.used(), 0);
        (success, current.work_used())
    }
    let (success, cost) = run(4096, 10000);
    assert!(success);
    assert!(run(4096, cost).0);
    assert!(!run(4096, cost - 1).0);
    assert!(!run(0, 10000).0);
}

#[cfg(feature = "password-protection")]
#[test]
fn encrypted_openssl_pkcs8_reuses_existing_decryption_and_dh_reader() {
    // Password handling/decryption precedes the same shared private-key reader.
    use structured_cms::personal::{
        ShroudedKey,
        password::{Decryption, Password},
    };
    let bytes = include_bytes!("fixtures/dh/encrypted.der");
    let parser = Parser::der(memory(65536, 1_000_000));
    let mut reader = parser.read(bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let encrypted = ShroudedKey::read(&reader, &element).unwrap();
    let plan = Decryption::key(&encrypted, &reader).unwrap();
    let password = Password::Octets(b"public-test-password");
    let base = plan.cost().unwrap();
    let extra = plan.password_cost(password).unwrap();
    let mut scratch = vec![0; base.scratch + extra.scratch];
    let mut output = vec![0; base.output];
    let count = plan
        .decrypt(password, &mut output, &mut scratch, &reader)
        .unwrap();
    assert_eq!(&output[..count], include_bytes!("fixtures/dh/private.der"));
    let mut plaintext = parser.read(&output[..count], 0).unwrap();
    let private = key(&mut plaintext);
    private
        .with_dh(
            &plaintext,
            &Source::Plaintext {
                ciphertext: encrypted.encrypted.span(),
                parent: &Source::Document,
            },
            |value, _| {
                assert_eq!(value.parameters().q().as_bytes().len(), 32);
                Ok::<_, ()>(())
            },
        )
        .unwrap();
    drop(private);
    drop(plaintext);
    output.fill(0);
    assert!(scratch.iter().all(|byte| *byte == 0));
}
