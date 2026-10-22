//! Complete public container processing, with an independent native PBMAC1 /
//! PBES2 adapter. Synthetic inputs contain no user's private key or password.
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser, Reader};
use structured_cms::{
    ErrorCode,
    personal::{
        self, Backend, Bag, BagValue, Cause, Decision, Failure, Integrity, Pfx, Plaintext,
        PrivateKey, Safe, ShroudedKey, Source,
        protection::{self, Prf, Salt},
    },
};

const DATA: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 7, 1];
const PASSWORD: &[u8] = b"test\xf0\x9f\x94\x90";
fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}
fn generous() -> Memory {
    memory(1 << 24, 1 << 29)
}
fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if bytes.len() < 128 {
        out.push(u8::try_from(bytes.len()).unwrap());
    } else {
        let size = bytes.len().to_be_bytes();
        let first = size.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 | u8::try_from(size.len() - first).unwrap());
        out.extend_from_slice(&size[first..]);
    }
    out.extend_from_slice(bytes);
    out
}
fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(48, &parts.concat())
}
fn oid(bytes: &[u8]) -> Vec<u8> {
    tlv(6, bytes)
}
fn alg(bytes: &[u8], parameter: &[u8]) -> Vec<u8> {
    seq(&[&oid(bytes), parameter])
}
fn number(n: u8) -> Vec<u8> {
    vec![2, 1, n]
}
fn data(bytes: &[u8]) -> Vec<u8> {
    seq(&[&oid(DATA), &tlv(160, &tlv(4, bytes))])
}
fn bag(last: u8, value: &[u8], attributes: &[u8]) -> Vec<u8> {
    seq(&[
        &oid(&[42, 134, 72, 134, 247, 13, 1, 12, 10, 1, last]),
        &tlv(160, value),
        attributes,
    ])
}
fn private(version: u8, public: &[u8]) -> Vec<u8> {
    seq(&[
        &number(version),
        &alg(&[43, 101, 112], &[]),
        &tlv(4, b"original secret"),
        public,
    ])
}
fn pfx(safe: &[u8], mac: &[u8]) -> Vec<u8> {
    seq(&[&number(3), &data(safe), mac])
}
fn pbkdf(key_length: bool) -> Vec<u8> {
    alg(
        protection::PBKDF2.as_bytes(),
        &seq(&[
            &tlv(4, b"salt"),
            &number(2),
            &if key_length { number(32) } else { vec![] },
            &alg(&[42, 134, 72, 134, 247, 13, 2, 9], &[5, 0]),
        ]),
    )
}
fn pbes() -> Vec<u8> {
    alg(
        protection::PBES2.as_bytes(),
        &seq(&[
            &pbkdf(true),
            &alg(&[96, 134, 72, 1, 101, 3, 4, 1, 42], &tlv(4, &[7; 16])),
        ]),
    )
}
fn encrypt(bytes: &[u8]) -> Vec<u8> {
    let mut key = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(PASSWORD, b"salt", 2, &mut key);
    let mut output = vec![0; bytes.len() + 16];
    cbc::Encryptor::<aes::Aes256Enc>::new_from_slices(&key, &[7; 16])
        .unwrap()
        .encrypt_padded_b2b::<Pkcs7>(bytes, &mut output)
        .unwrap()
        .to_vec()
}
fn mac_data(safe: &[u8], length: bool) -> Vec<u8> {
    let mut key = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(PASSWORD, b"salt", 2, &mut key);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(safe);
    let digest = mac.finalize().into_bytes();
    let pair = seq(&[
        &pbkdf(length),
        &alg(&[42, 134, 72, 134, 247, 13, 2, 9], &[5, 0]),
    ]);
    // RFC9879: external legacy values MUST be ignored, including zero count.
    seq(&[
        &seq(&[&alg(protection::PBMAC1.as_bytes(), &pair), &tlv(4, &digest)]),
        &tlv(4, b"ignored"),
        &number(0),
    ])
}
fn joined(
    octets: &structured_cms::Octets<'_>,
    reader: &Reader<'_>,
) -> Result<Vec<u8>, &'static str> {
    reader
        .charge(octets.len() as u64 + octets.pieces().len() as u64)
        .map_err(|_| "resource")?;
    Ok(octets
        .pieces()
        .iter()
        .flat_map(|p| p.as_bytes().iter().copied())
        .collect())
}
struct Native {
    events: Vec<&'static str>,
    accept: Decision,
    fail_bag: bool,
    failure_at: Option<u64>,
}
impl Native {
    fn new() -> Self {
        Self {
            events: vec![],
            accept: Decision::Accept,
            fail_bag: false,
            failure_at: None,
        }
    }
}
impl Backend for Native {
    type Error = &'static str;
    fn authenticate(
        &mut self,
        integrity: &Integrity<'_>,
        reader: &Reader<'_>,
    ) -> Result<Decision, Self::Error> {
        self.events.push("integrity");
        if self.accept != Decision::Accept {
            return Ok(self.accept);
        }
        if let Integrity::Password {
            safe,
            mac: Some(mac),
        } = integrity
        {
            let pair = mac.pbmac1.as_ref().ok_or("unsupported")?;
            let kdf = pair.pbkdf2.as_ref().ok_or("kdf")?;
            assert_eq!(kdf.key_length.unwrap().as_u64(), Some(32));
            assert_eq!(kdf.iterations.as_u64(), Some(2));
            let Salt::Specified(salt) = &kdf.salt else {
                return Err("salt");
            };
            reader.charge(1000).map_err(|_| "resource")?;
            let mut key = [0; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(PASSWORD, &joined(salt, reader)?, 2, &mut key);
            let mut verifier = Hmac::<Sha256>::new_from_slice(&key).unwrap();
            for piece in safe.pieces() {
                verifier.update(piece.as_bytes());
            }
            if verifier
                .verify_slice(&joined(&mac.digest, reader)?)
                .is_err()
            {
                return Ok(Decision::Reject);
            }
        }
        Ok(Decision::Accept)
    }
    fn decrypt_safe(
        &mut self,
        safe: &Safe<'_>,
        reader: &Reader<'_>,
        _: &Source<'_>,
    ) -> Result<Plaintext, Self::Error> {
        self.events.push("safe");
        match safe {
            Safe::Encrypted(value) => {
                Self::decrypt(value.content.ciphertext.as_ref().unwrap(), reader)
            }
            Safe::Enveloped(value) => {
                Self::decrypt(value.content.ciphertext.as_ref().unwrap(), reader)
            }
            _ => Err("privacy"),
        }
    }
    fn decrypt_key(
        &mut self,
        key: &ShroudedKey<'_>,
        reader: &Reader<'_>,
        _: &Source<'_>,
    ) -> Result<Plaintext, Self::Error> {
        self.events.push("decrypt-key");
        Self::decrypt(&key.encrypted, reader)
    }
    fn bag(&mut self, bag: &Bag<'_>, _: &Reader<'_>, _: &Source<'_>) -> Result<(), Self::Error> {
        if self.fail_bag {
            self.failure_at = Some(bag.original.element().span().start);
            return Err("visitor");
        }
        self.events.push(match &bag.value {
            BagValue::Key(_) => "key-bag",
            BagValue::Shrouded(_) => "shrouded",
            BagValue::Certificate(_) => "certificate",
            BagValue::Sdsi(_) => "sdsi",
            BagValue::Crl(_) => "crl",
            BagValue::Secret { .. } => "secret",
            BagValue::Other { .. } => "other",
            BagValue::Contents(_) => "nested",
        });
        Ok(())
    }
    fn key(
        &mut self,
        key: &PrivateKey<'_>,
        _: &Reader<'_>,
        source: &Source<'_>,
    ) -> Result<(), Self::Error> {
        assert_eq!(key.secret.as_one(), Some(&b"original secret"[..]));
        assert!(matches!(source, Source::Plaintext { .. }));
        self.events.push("clear-key");
        Ok(())
    }
}
impl Native {
    fn decrypt(
        encrypted: &structured_cms::Octets<'_>,
        reader: &Reader<'_>,
    ) -> Result<Plaintext, &'static str> {
        // Native adapters are trusted boundaries. Fund KDF, initialized input,
        // in-place cipher work and eventual plaintext wiping BEFORE work.
        reader
            .charge(1000 + 3 * encrypted.len() as u64)
            .map_err(|_| "resource")?;
        let mut plain = Plaintext::copy_octets(encrypted, reader).map_err(|_| "resource")?;
        let mut key = [0; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(PASSWORD, b"salt", 2, &mut key);
        let length = cbc::Decryptor::<aes::Aes256Dec>::new_from_slices(&key, &[7; 16])
            .unwrap()
            .decrypt_padded::<Pkcs7>(plain.as_mut_bytes())
            .map_err(|_| "cipher")?
            .len();
        // Processor must receive only unpadded plaintext. Reuse its existing
        // allocation through an explicit API, preserving wipe coverage.
        plain.truncate(length);
        Ok(plain)
    }
}
#[expect(
    clippy::result_large_err,
    reason = "exercise the public owned cause/source chain without replacing it with a test-only allocation"
)]
fn run(bytes: &[u8], backend: &mut Native) -> Result<Decision, Failure<&'static str>> {
    let parser = Parser::new(Encoding::Ber, Limits::default(), generous());
    let mut reader = parser.read(bytes, 100).unwrap();
    let pfx = Pfx::read(&mut reader).unwrap();
    personal::process(&pfx, &reader, backend)
}

#[test]
fn all_bags_nested_encrypted_safe_shrouded_key_and_pbmac1() {
    // The complete public processor must authenticate first, decrypt both
    // levels, preserve sibling/preorder order and visit every bag exactly once.
    let key = private(0, &[]);
    let shrouded = bag(2, &seq(&[&pbes(), &tlv(4, &encrypt(&key))]), &[]);
    let inner = seq(&[&bag(1, &key, &[]), &shrouded]);
    let typed = |kind: &[u8], value: &[u8]| seq(&[&oid(kind), &tlv(160, value)]);
    let bags = seq(&[
        &bag(6, &inner, &[]),
        &bag(
            3,
            &typed(
                &[42, 134, 72, 134, 247, 13, 1, 9, 22, 1],
                &tlv(4, b"certificate"),
            ),
            &[],
        ),
        &bag(
            3,
            &typed(
                &[42, 134, 72, 134, 247, 13, 1, 9, 22, 2],
                &tlv(22, b"base64"),
            ),
            &[],
        ),
        &bag(
            4,
            &typed(&[42, 134, 72, 134, 247, 13, 1, 9, 23, 1], &tlv(4, b"crl")),
            &[],
        ),
        &bag(5, &typed(&[42, 3], &tlv(4, b"secret")), &[]),
        &bag(9, &[5, 0], &[]),
    ]);
    let encrypted = seq(&[
        &number(0),
        &seq(&[&oid(DATA), &pbes(), &tlv(128, &encrypt(&bags))]),
    ]);
    let safe = seq(&[
        &data(&seq(&[])),
        &seq(&[
            &oid(&[42, 134, 72, 134, 247, 13, 1, 7, 6]),
            &tlv(160, &encrypted),
        ]),
    ]);
    let bytes = pfx(&safe, &mac_data(&safe, true));
    let mut backend = Native::new();
    assert_eq!(run(&bytes, &mut backend).unwrap(), Decision::Accept);
    assert_eq!(
        backend.events,
        [
            "integrity",
            "safe",
            "nested",
            "key-bag",
            "shrouded",
            "decrypt-key",
            "clear-key",
            "certificate",
            "sdsi",
            "crl",
            "secret",
            "other"
        ]
    );
}

#[test]
fn integrity_refusal_prevents_all_extraction_and_wrong_mac_rejects() {
    // Authentication refusal cannot be converted into a successful empty import
    // or trigger any password/privacy/extraction operation.
    let safe = seq(&[&data(&seq(&[&bag(1, &private(0, &[]), &[])]))]);
    let bytes = pfx(&safe, &mac_data(&safe, true));
    for answer in [Decision::Reject, Decision::Unsupported] {
        let mut backend = Native::new();
        backend.accept = answer;
        assert_eq!(run(&bytes, &mut backend).unwrap(), answer);
        assert_eq!(backend.events, ["integrity"]);
    }
    // Change the protected safe instead of relying on any MAC metadata offset.
    let changed = seq(&[&data(&seq(&[
        &bag(1, &private(0, &[]), &[]),
        &bag(9, &[5, 0], &[]),
    ]))]);
    let mut backend = Native::new();
    assert_eq!(
        run(&pfx(&changed, &mac_data(&safe, true)), &mut backend).unwrap(),
        Decision::Reject
    );
    assert_eq!(backend.events, ["integrity"]);
}

#[test]
fn pbmac1_requires_explicit_key_length_before_provider() {
    // RFC9879 §5 forbids missing PBKDF2 keyLength even when the PRF/MAC have
    // matching known widths. No backend callback can repair this syntax.
    let safe = seq(&[]);
    let bytes = pfx(&safe, &mac_data(&safe, false));
    let parser = Parser::new(Encoding::Ber, Limits::default(), generous());
    let Err(error) = Pfx::read(&mut parser.read(&bytes, 0).unwrap()) else {
        panic!("missing keyLength")
    };
    assert_eq!(error.code(), ErrorCode::MissingField);
}

#[test]
fn bag_attributes_and_private_public_version_are_independent() {
    // Preserve all original bag/key attributes without a guessed singleton or
    // one-key import policy. IMPLICIT key bits use the common fragment kernel.
    let parser = Parser::new(Encoding::Ber, Limits::default(), generous());
    let attrs = tlv(49, &seq(&[&oid(&[42, 3]), &[49, 0]]));
    let public = tlv(161, &tlv(3, &[0, 7]));
    let bytes = bag(1, &private(1, &public), &attrs);
    let mut reader = parser.read(&bytes, 200).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let bag = Bag::read(&reader, &element).unwrap();
    assert_eq!(bag.attributes.as_ref().unwrap().len(), 1);
    let BagValue::Key(key) = bag.value else {
        panic!("key")
    };
    assert!(key.public_key.is_some());
    assert_eq!(key.version, 1);
    for key in [private(0, &public), private(1, &[]), private(2, &[])] {
        let mut reader = parser.read(&key, 0).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        assert!(PrivateKey::read(&reader, &element).is_err());
    }
}

#[test]
fn fragmented_safe_retains_error_coordinate_chain_after_parser_drop() {
    // An opaque visitor refusal retains both fragment mappings without retaining
    // any joined plaintext buffer, parser, reader or temporary bag references.
    let bags = seq(&[&bag(1, &private(0, &[]), &[])]);
    let safe = seq(&[&data(&bags)]);
    let split = safe.len() / 2;
    let wrapped = seq(&[
        &oid(DATA),
        &tlv(
            160,
            &tlv(
                36,
                &[tlv(4, &safe[..split]), tlv(4, &safe[split..])].concat(),
            ),
        ),
    ]);
    let bytes = seq(&[&number(3), &wrapped]);
    let mut backend = Native::new();
    backend.fail_bag = true;
    let error = run(&bytes, &mut backend).unwrap_err();
    assert!(matches!(error.cause, Cause::Callback("visitor")));
    assert_eq!(error.origins.iter().flatten().count(), 2);
    assert_eq!(backend.events, ["integrity"]);
    let account = generous();
    let mut at = backend.failure_at.unwrap();
    for origin in error.origins.iter().flatten() {
        let personal::Origin::Carried(map) = origin else {
            panic!("unencrypted source")
        };
        let copied = map.try_copy_in(&account).unwrap();
        let ranges = copied
            .ranges_in_parent(
                structured_asn1::Span {
                    start: at,
                    length: 1,
                },
                &account,
            )
            .unwrap();
        let parent = copied.offset_in_parent(at, &account).unwrap();
        assert_eq!(ranges[0].start, parent);
        assert!(parent >= map.enclosure().start);
        at = parent;
    }
    let key = bag(1, &private(0, &[]), &[]);
    // The bag crosses the split, so its entire header need not occur as a
    // contiguous physical substring. Derive the point independently from the
    // known first fragment's payload placement and the original logical safe.
    let logical = safe
        .windows(key.len())
        .position(|part| part == key)
        .unwrap();
    assert!(logical < split);
    let first_fragment = bytes
        .windows(split)
        .position(|part| part == &safe[..split])
        .unwrap();
    let expected = first_fragment + logical;
    assert_eq!(at, u64::try_from(expected).unwrap() + 100);
    let personal::Origin::Carried(map) = error.origins[0].as_ref().unwrap() else {
        unreachable!()
    };
    assert!(map.offset_in_parent(u64::MAX, &account).is_err());
}

#[test]
fn malformed_bag_wrappers_and_trailing_data_refuse() {
    // Exact cardinality/framing matters even for unknown open types. An unknown
    // bag is preserved, but two EXPLICIT values or extra fields are ambiguous.
    let parser = Parser::new(Encoding::Ber, Limits::default(), generous());
    let kind = oid(&[42, 134, 72, 134, 247, 13, 1, 12, 10, 1, 99]);
    for bytes in [
        seq(&[&kind, &tlv(160, &[5, 0, 5, 0])]),
        seq(&[&kind, &tlv(160, &[5, 0]), &[5, 0]]),
        seq(&[&kind, &[160, 0]]),
    ] {
        let mut reader = parser.read(&bytes, 0).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        assert!(Bag::read(&reader, &element).is_err());
    }
}

#[test]
fn unknown_kdf_and_wide_positive_iterations_remain_original() {
    // Width is a backend work bound, not a reason to truncate to u32 or to
    // choose PBKDF2 for an unknown derivation algorithm.
    let params = seq(&[&tlv(4, b"salt"), &tlv(2, &[1, 0, 0, 0, 0, 0, 0, 0, 0])]);
    let bytes = alg(protection::PBKDF2.as_bytes(), &params);
    let parser = Parser::new(Encoding::Ber, Limits::default(), generous());
    let mut reader = parser.read(&bytes, 50).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let id = structured_pkix::algorithm::read(&reader, &element, "test").unwrap();
    let kdf = protection::Pbkdf2::read(id, &reader).unwrap();
    assert_eq!(kdf.iterations.as_u64(), None);
    assert!(matches!(kdf.prf, Prf::DefaultSha1));
    let other = Parser::der(generous());
    let foreign = other.read(&bytes, 50).unwrap();
    let before = other.memory().work_used();
    let Err(error) = protection::Pbkdf2::read(id, &foreign) else {
        panic!("foreign parser")
    };
    assert!(error.is_terminal());
    assert_eq!(other.memory().work_used(), before);
}

#[test]
fn resource_refusal_is_terminal_and_releases_temporary_storage() {
    // Iterative nested traversal and catalogues share the original local and
    // current aggregate ceilings; no successful subset escapes on refusal.
    let mut nested = seq(&[&bag(1, &private(0, &[]), &[])]);
    for _ in 0..30 {
        nested = seq(&[&bag(6, &nested, &[])]);
    }
    let bytes = pfx(&seq(&[&data(&nested)]), &[]);
    for capacity in [0, 128, 512] {
        let account = memory(capacity, 1 << 25);
        let parser = Parser::new(Encoding::Ber, Limits::default(), generous());
        let mut reader = parser.read(&bytes, 0).unwrap();
        let pfx = Pfx::read(&mut reader).unwrap();
        let mut backend = Native::new();
        let operation = Parser::der(account.clone());
        let current = operation.read(&[], 0).unwrap();
        let error = personal::process(&pfx, &current, &mut backend).unwrap_err();
        assert!(matches!(error.cause,Cause::Processing(ref e) if e.is_resource()));
        drop(pfx);
        drop(reader);
        drop(parser);
        assert_eq!(account.used(), 0);
    }
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 200,
            ..Limits::default()
        },
        generous(),
    );
    let mut reader = parser.read(&bytes, 0).unwrap();
    let pfx = Pfx::read(&mut reader).unwrap();
    let mut backend = Native::new();
    assert!(personal::process(&pfx, &reader, &mut backend).is_err());
}

#[test]
fn public_key_privacy_reuses_original_recipient_model() {
    // Public-key privacy is not silently treated as PBES2. The selected
    // callback receives the actual common recipient descriptor and ciphertext.
    let bags = seq(&[&bag(1, &private(0, &[]), &[])]);
    let recipient = seq(&[
        &number(2),
        &[128, 1, 7],
        &alg(&[42, 3], &[5, 0]),
        &tlv(4, b"wrapped-key"),
    ]);
    let encrypted = seq(&[
        &number(2),
        &tlv(49, &recipient),
        &seq(&[
            &oid(DATA),
            &alg(&[42, 3], &[5, 0]),
            &tlv(128, &encrypt(&bags)),
        ]),
    ]);
    let safe = seq(&[&seq(&[
        &oid(structured_cms::enveloped::IDENTIFIER.as_bytes()),
        &tlv(160, &encrypted),
    ])]);
    let mut backend = Native::new();
    assert_eq!(
        run(&pfx(&safe, &[]), &mut backend).unwrap(),
        Decision::Accept
    );
    assert_eq!(backend.events, ["integrity", "safe", "key-bag"]);
}

#[test]
fn public_key_integrity_checks_actual_carried_safe_before_extraction() {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use sha2::Digest;
    // A real independent PureEdDSA callback authenticates the exact original
    // carried safe; neither PFX headers nor re-encoded SignedData are its input.
    struct SignedNative {
        inner: Native,
        key: ed25519_dalek::VerifyingKey,
    }
    impl Backend for SignedNative {
        type Error = &'static str;
        fn authenticate(
            &mut self,
            integrity: &Integrity<'_>,
            query: &Reader<'_>,
        ) -> Result<Decision, Self::Error> {
            let Integrity::Signed(message) = integrity else {
                return Err("mode");
            };
            query.charge(10000).map_err(|_| "resource")?;
            let signer = &message.signers()[0];
            let bytes = joined(message.content().content().unwrap(), query)?;
            let signature = Signature::from_slice(signer.signature().as_one().unwrap()).unwrap();
            self.inner.events.push("signature");
            Ok(if self.key.verify_strict(&bytes, &signature).is_ok() {
                Decision::Accept
            } else {
                Decision::Reject
            })
        }
        fn decrypt_safe(
            &mut self,
            safe: &Safe<'_>,
            query: &Reader<'_>,
            source: &Source<'_>,
        ) -> Result<Plaintext, Self::Error> {
            self.inner.decrypt_safe(safe, query, source)
        }
        fn decrypt_key(
            &mut self,
            key: &ShroudedKey<'_>,
            query: &Reader<'_>,
            source: &Source<'_>,
        ) -> Result<Plaintext, Self::Error> {
            self.inner.decrypt_key(key, query, source)
        }
        fn bag(
            &mut self,
            bag: &Bag<'_>,
            query: &Reader<'_>,
            source: &Source<'_>,
        ) -> Result<(), Self::Error> {
            self.inner.bag(bag, query, source)
        }
        fn key(
            &mut self,
            key: &PrivateKey<'_>,
            query: &Reader<'_>,
            source: &Source<'_>,
        ) -> Result<(), Self::Error> {
            self.inner.key(key, query, source)
        }
    }
    let safe = seq(&[&data(&seq(&[&bag(1, &private(0, &[]), &[])]))]);
    let key = SigningKey::from_bytes(&[7; 32]);
    let signature = key.sign(&safe).to_bytes();
    let hash = alg(&[96, 134, 72, 1, 101, 3, 4, 2, 3], &[]);
    let signer = seq(&[
        &number(3),
        &[128, 1, 7],
        &hash,
        &alg(&[43, 101, 112], &[]),
        &tlv(4, &signature),
    ]);
    let envelope = seq(&[&number(3), &tlv(49, &hash), &data(&safe), &tlv(49, &signer)]);
    let wrapped = seq(&[
        &oid(&[42, 134, 72, 134, 247, 13, 1, 7, 2]),
        &tlv(160, &envelope),
    ]);
    let bytes = seq(&[&number(3), &wrapped]);
    let parser = Parser::ber(generous());
    let mut reader = parser.read(&bytes, 10).unwrap();
    let pfx = Pfx::read(&mut reader).unwrap();
    let mut backend = SignedNative {
        inner: Native::new(),
        key: key.verifying_key(),
    };
    assert_eq!(
        personal::process(&pfx, &reader, &mut backend).unwrap(),
        Decision::Accept
    );
    assert_eq!(backend.inner.events, ["signature", "key-bag"]);
    // Replacing the external selected verification key cannot be repaired by
    // an embedded key, signature parsing or successful container framing.
    backend.key = SigningKey::from_bytes(&[8; 32]).verifying_key();
    backend.inner.events.clear();
    assert_eq!(
        personal::process(&pfx, &reader, &mut backend).unwrap(),
        Decision::Reject
    );
    assert_eq!(backend.inner.events, ["signature"]);
    assert_eq!(sha2::Sha512::digest(&safe).len(), 64);
}

#[test]
fn legacy_pbe_all_identifiers_defaults_and_invalid_counts() {
    // All six PKCS#12 PBE identifiers share one structural kernel. Their
    // algorithm permission/cipher/KDF remains with the selected provider.
    for last in 1..=6 {
        let bytes = alg(
            &[42, 134, 72, 134, 247, 13, 1, 12, 1, last],
            &seq(&[&tlv(4, b"arbitrary salt"), &number(2)]),
        );
        let parser = Parser::ber(generous());
        let mut reader = parser.read(&bytes, 50).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let id = structured_pkix::algorithm::read(&reader, &element, "test").unwrap();
        assert!(matches!(
            protection::Protection::read(id, &reader).unwrap(),
            protection::Protection::Pkcs12(_)
        ));
    }
    for salt in [b"12345678".as_slice(), b"short".as_slice()] {
        for count in [number(0), number(2), vec![2, 1, 255]] {
            let bytes = alg(
                &[42, 134, 72, 134, 247, 13, 1, 5, 3],
                &seq(&[&tlv(4, salt), &count]),
            );
            let parser = Parser::ber(generous());
            let mut reader = parser.read(&bytes, 0).unwrap();
            let element = reader.next_element().unwrap().unwrap();
            let id = structured_pkix::algorithm::read(&reader, &element, "test").unwrap();
            assert_eq!(
                protection::Protection::read(id, &reader).is_ok(),
                salt.len() == 8 && count == number(2)
            );
        }
    }
}

#[test]
fn implicit_public_bits_cannot_hide_bad_padding_or_der_construction() {
    // [1] is a BIT STRING schema tag, not opaque context contents. Both its
    // primitive form and final/non-final constructed padding share the PKIX core.
    for public in [
        vec![129, 0],
        vec![129, 2, 8, 0],
        tlv(161, &[3, 2, 1, 0, 3, 2, 0, 7]),
    ] {
        let bytes = private(1, &public);
        let parser = Parser::ber(generous());
        let mut reader = parser.read(&bytes, 0).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        assert!(PrivateKey::read(&reader, &element).is_err());
    }
    let bytes = private(1, &tlv(161, &[3, 2, 0, 7]));
    let parser = Parser::der(generous());
    let mut reader = parser.read(&bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    assert!(PrivateKey::read(&reader, &element).is_err());
}

#[test]
fn wiping_plaintext_capacity_lifetime_and_prepaid_work() {
    // Capacity remains retained after Parser/Reader drop, including after
    // padding removal. Destructor cleanup does not allocate or need new work.
    let account = generous();
    let mut plain = {
        let parser = Parser::der(account.clone());
        let reader = parser.read(&[], 0).unwrap();
        Plaintext::copy_from(b"abc-padding", &reader).unwrap()
    };
    let live = account.used();
    assert!(live >= 11);
    plain.truncate(3);
    assert_eq!(plain.as_bytes(), b"abc");
    assert_eq!(account.used(), live);
    drop(plain);
    assert_eq!(account.used(), 0);
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        generous(),
    );
    let reader = parser.read(&[], 0).unwrap();
    assert!(Plaintext::copy_from(b"x", &reader).is_err());
}

#[test]
fn decryption_preserves_actual_ciphertext_enclosing_depth() {
    // The operation is at AuthenticatedSafe level, but ciphertext is several
    // ASN.1 levels deeper. Plaintext must inherit THAT depth, not the shallower
    // loop cursor, or encryption becomes a depth-limit reset.
    let bags = seq(&[&bag(1, &private(0, &[]), &[])]);
    let encrypted = seq(&[
        &number(0),
        &seq(&[
            &oid(DATA),
            &alg(&[42, 3], &[5, 0]),
            &tlv(128, &encrypt(&bags)),
        ]),
    ]);
    let safe = seq(&[&seq(&[
        &oid(&[42, 134, 72, 134, 247, 13, 1, 7, 6]),
        &tlv(160, &encrypted),
    ])]);
    let bytes = pfx(&safe, &[]);
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 11,
            ..Limits::default()
        },
        generous(),
    );
    let mut reader = parser.read(&bytes, 0).unwrap();
    let pfx = Pfx::read(&mut reader).unwrap();
    let mut backend = Native::new();
    let error = personal::process(&pfx, &reader, &mut backend).unwrap_err();
    assert!(matches!(error.cause,Cause::Processing(ref e) if e.is_resource()));
    assert_eq!(backend.events, ["integrity", "safe"]);
}

#[test]
fn password_encoding_is_layer_specific_and_accounted() {
    // Legacy BMP includes one terminating zero unit; UTF-8 PBMAC1/PBES2 does
    // not. A supplementary character must never be replaced or surrogate-split.
    let parser = Parser::ber(generous());
    let reader = parser.read(&[], 0).unwrap();
    assert_eq!(
        personal::legacy_password("", &reader).unwrap().as_bytes(),
        &[0, 0]
    );
    assert_eq!(
        personal::legacy_password("aé", &reader).unwrap().as_bytes(),
        &[0, 97, 0, 233, 0, 0]
    );
    let Err(error) = personal::legacy_password("🔐", &reader) else {
        panic!("not BMP")
    };
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn known_prf_parameters_and_mac_width_are_checked_before_provider() {
    // Open algorithms remain open, but known HMAC parameters and output width
    // have normative syntax; successful envelope framing cannot waive it.
    let parser = Parser::ber(generous());
    let kdf = alg(
        protection::PBKDF2.as_bytes(),
        &seq(&[
            &tlv(4, b"salt"),
            &number(2),
            &alg(&[42, 134, 72, 134, 247, 13, 2, 9], &[2, 1, 9]),
        ]),
    );
    let mut reader = parser.read(&kdf, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let id = structured_pkix::algorithm::read(&reader, &element, "test").unwrap();
    assert!(protection::Pbkdf2::read(id, &reader).is_err());
    let safe = seq(&[]);
    let mac = seq(&[
        &seq(&[
            &alg(&[96, 134, 72, 1, 101, 3, 4, 2, 1], &[5, 0]),
            &tlv(4, &[0; 31]),
        ]),
        &tlv(4, b"salt"),
    ]);
    let bytes = pfx(&safe, &mac);
    assert!(Pfx::read(&mut parser.read(&bytes, 0).unwrap()).is_err());
}

#[test]
fn open_bag_values_validate_whole_asn1_framing_before_visitor() {
    // Unknown ANY is not permission to hide a truncated child TLV inside a
    // definite-length SEQUENCE and reach extraction callbacks with it.
    let bytes = pfx(&seq(&[&data(&seq(&[&bag(99, &[48, 1, 255], &[])]))]), &[]);
    let mut backend = Native::new();
    let error = run(&bytes, &mut backend).unwrap_err();
    assert!(matches!(error.cause, Cause::Processing(_)));
    assert_eq!(backend.events, ["integrity"]);
}

#[test]
fn nested_safe_contents_do_not_reset_explicit_bag_depth() {
    // SafeContents is two ASN.1 levels below the parent loop (SafeBag and
    // EXPLICIT bagValue). Entering it through the loop cursor loses both.
    let leaf = seq(&[&bag(99, &[5, 0], &[])]);
    let nested = seq(&[&bag(6, &seq(&[&bag(6, &leaf, &[])]), &[])]);
    let bytes = pfx(&seq(&[&data(&nested)]), &[]);
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 14,
            ..Limits::default()
        },
        generous(),
    );
    let mut reader = parser.read(&bytes, 0).unwrap();
    let pfx = Pfx::read(&mut reader).unwrap();
    let mut backend = Native::new();
    let error = personal::process(&pfx, &reader, &mut backend).unwrap_err();
    assert!(matches!(error.cause,Cause::Processing(ref e) if e.is_resource()));
    assert_eq!(backend.events, ["integrity", "nested", "nested"]);
}

#[test]
fn pbmac1_ignored_iterations_still_obey_der_default_omission() {
    // RFC9879 ignores this field for KDF computation, but does not remove its
    // ASN.1 DEFAULT. X.690 §11.5 still forbids written DEFAULT 1 under DER.
    let safe = seq(&[]);
    let pair = seq(&[
        &pbkdf(true),
        &alg(&[42, 134, 72, 134, 247, 13, 2, 9], &[5, 0]),
    ]);
    let mac = seq(&[
        &seq(&[
            &alg(protection::PBMAC1.as_bytes(), &pair),
            &tlv(4, &[0; 32]),
        ]),
        &tlv(4, b"salt"),
        &number(1),
    ]);
    let bytes = pfx(&safe, &mac);
    let parser = Parser::der(generous());
    let Err(error) = Pfx::read(&mut parser.read(&bytes, 0).unwrap()) else {
        panic!("written DER default")
    };
    assert_eq!(error.code(), ErrorCode::DefaultWritten);
}

#[test]
fn legacy_mac_and_pbkdf2_defaults_preserve_written_provenance() {
    // Legacy MacData DEFAULT 1 differs from PBMAC1's ignored count. PBKDF2's
    // omitted SHA1 PRF differs from an actually written AlgorithmIdentifier;
    // DER omits its default, while BER preserves that spelling.
    let safe = seq(&[]);
    for encoding in [Encoding::Ber, Encoding::Der] {
        for written in [false, true] {
            let mac = seq(&[
                &seq(&[
                    &alg(&[96, 134, 72, 1, 101, 3, 4, 2, 1], &[5, 0]),
                    &tlv(4, &[0; 32]),
                ]),
                &tlv(4, b"salt"),
                &if written { number(1) } else { vec![] },
            ]);
            let bytes = pfx(&safe, &mac);
            let parser = Parser::new(encoding, Limits::default(), generous());
            let result = Pfx::read(&mut parser.read(&bytes, 0).unwrap());
            if encoding.is_der() && written {
                assert!(result.is_err());
                continue;
            }
            let model = result.unwrap();
            let Integrity::Password { mac: Some(mac), .. } = model.integrity() else {
                panic!("legacy MAC")
            };
            assert!(mac.pbmac1.is_none());
            assert_eq!(mac.iterations.is_some(), written);
        }
        for written in [false, true] {
            let params = seq(&[
                &alg(&[42, 3], &[5, 0]),
                &number(2),
                &if written {
                    alg(&[42, 134, 72, 134, 247, 13, 2, 7], &[5, 0])
                } else {
                    vec![]
                },
            ]);
            let bytes = alg(protection::PBKDF2.as_bytes(), &params);
            let parser = Parser::new(encoding, Limits::default(), generous());
            let mut reader = parser.read(&bytes, 30).unwrap();
            let element = reader.next_element().unwrap().unwrap();
            let id = structured_pkix::algorithm::read(&reader, &element, "test").unwrap();
            let result = protection::Pbkdf2::read(id, &reader);
            if encoding.is_der() && written {
                assert!(result.is_err());
                continue;
            }
            let kdf = result.unwrap();
            assert!(matches!(kdf.salt, Salt::Source(_)));
            assert_eq!(matches!(kdf.prf, Prf::Written(_)), written);
        }
    }
}
