//! Signature identity/parameter interpretation under original/current budgets.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::algorithm::signature::{self, Algorithm};
use structured_pkix::algorithm::{self, AlgorithmIdentifier, digest::Algorithm as Hash, pss};
use structured_pkix::{Certificate, ErrorCode};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if body.len() < 128 {
        bytes.push(u8::try_from(body.len()).unwrap());
    } else if body.len() < 256 {
        bytes.extend([0x81, u8::try_from(body.len()).unwrap()]);
    } else {
        bytes.push(0x82);
        bytes.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    }
    bytes.extend(body);
    bytes
}
fn encoded(oid: &[u8], parameters: Option<&[u8]>) -> Vec<u8> {
    let mut body = tlv(6, oid);
    if let Some(value) = parameters {
        body.extend(value);
    }
    tlv(48, &body)
}
fn identifier<'a>(parser: &'a Parser, bytes: &'a [u8]) -> AlgorithmIdentifier<'a> {
    let mut reader = parser.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    algorithm::read(&reader, &element, "signatureAlgorithm").unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fixed {
    Rsa(Hash),
    Dsa(Hash),
    Ec(Hash),
    Ed25519,
    Ed448,
}
#[derive(Clone, Copy)]
enum Rule {
    Null,
    Absent,
    Either,
}

fn cases() -> Vec<(Vec<u8>, Fixed, Rule)> {
    let mut cases = Vec::new();
    for (last, hash, rule) in [
        (5, Hash::Sha1, Rule::Null),
        (11, Hash::Sha256, Rule::Either),
        (12, Hash::Sha384, Rule::Either),
        (13, Hash::Sha512, Rule::Either),
        (14, Hash::Sha224, Rule::Either),
        (15, Hash::Sha512_224, Rule::Null),
        (16, Hash::Sha512_256, Rule::Null),
    ] {
        cases.push((
            vec![42, 134, 72, 134, 247, 13, 1, 1, last],
            Fixed::Rsa(hash),
            rule,
        ));
    }
    cases.push((
        vec![42, 134, 72, 206, 56, 4, 3],
        Fixed::Dsa(Hash::Sha1),
        Rule::Absent,
    ));
    cases.push((
        vec![42, 134, 72, 206, 61, 4, 1],
        Fixed::Ec(Hash::Sha1),
        Rule::Absent,
    ));
    for (last, hash) in [
        (1, Hash::Sha224),
        (2, Hash::Sha256),
        (3, Hash::Sha384),
        (4, Hash::Sha512),
    ] {
        cases.push((
            vec![42, 134, 72, 206, 61, 4, 3, last],
            Fixed::Ec(hash),
            Rule::Absent,
        ));
    }
    for (last, hash) in [(1, Hash::Sha224), (2, Hash::Sha256)] {
        cases.push((
            vec![96, 134, 72, 1, 101, 3, 4, 3, last],
            Fixed::Dsa(hash),
            Rule::Absent,
        ));
    }
    for (n, hash) in [
        (0, Hash::Sha3_224),
        (1, Hash::Sha3_256),
        (2, Hash::Sha3_384),
        (3, Hash::Sha3_512),
    ] {
        cases.push((
            vec![96, 134, 72, 1, 101, 3, 4, 3, 9 + n],
            Fixed::Ec(hash),
            Rule::Absent,
        ));
        cases.push((
            vec![96, 134, 72, 1, 101, 3, 4, 3, 13 + n],
            Fixed::Rsa(hash),
            Rule::Null,
        ));
    }
    cases.push((vec![43, 101, 112], Fixed::Ed25519, Rule::Absent));
    cases.push((vec![43, 101, 113], Fixed::Ed448, Rule::Absent));
    cases
}
fn fixed(algorithm: Algorithm<'_, '_>) -> Fixed {
    match algorithm {
        Algorithm::RsaPkcs1v15(hash) => Fixed::Rsa(hash),
        Algorithm::Dsa(hash) => Fixed::Dsa(hash),
        Algorithm::Ecdsa(hash) => Fixed::Ec(hash),
        Algorithm::Ed25519 => Fixed::Ed25519,
        Algorithm::Ed448 => Fixed::Ed448,
        other => panic!("not a fixed algorithm: {other:?}"),
    }
}

#[test]
fn every_recognized_fixed_oid_enforces_its_own_parameter_rule() {
    // The table covers every recognized fixed OID, including equal-width
    // SHA2/SHA3, pure Ed modes and distinct RSA reception requirements.
    for (oid, expected, rule) in cases() {
        for parameters in [None, Some(&[5, 0][..]), Some(&[2, 1, 0][..])] {
            let bytes = encoded(&oid, parameters);
            let source = Parser::der(memory(4096, 1_000_000));
            let id = identifier(&source, &bytes);
            let work = memory(0, 1000);
            let result = signature::with_algorithm(id, &work, |value| value.map(fixed));
            let valid = match rule {
                Rule::Absent => parameters.is_none(),
                Rule::Null => parameters == Some(&[5, 0][..]),
                Rule::Either => parameters.is_none() || parameters == Some(&[5, 0][..]),
            };
            if valid {
                assert_eq!(result.unwrap().unwrap(), expected);
            } else {
                let error = result.unwrap_err();
                let code = if parameters.is_none() {
                    ErrorCode::MissingField
                } else {
                    ErrorCode::MalformedValue
                };
                assert_eq!(error.code(), code);
                assert_eq!(error.field(), "signatureAlgorithm");
                assert_eq!(
                    error.offset(),
                    parameters.map_or(400, |_| 404 + oid.len() as u64)
                );
                assert!(!error.is_resource());
            }
            assert_eq!(work.work_used(), oid.len() + 1);
            assert_eq!(work.used(), 0);
            assert_eq!(id.as_bytes().as_ptr(), bytes.as_ptr());
        }
    }
}

#[test]
fn ber_null_identity_does_not_relax_absent_only_algorithms() {
    // A BER long-form NULL is a real primitive NULL for RSA, but is still
    // present for Ed/ECDSA/DSA and forbidden there. No DER byte comparison.
    for (oid, expected, rule) in cases() {
        let bytes = encoded(&oid, Some(&[5, 0x81, 0]));
        let source = Parser::ber(memory(4096, 1_000_000));
        let id = identifier(&source, &bytes);
        let result = signature::with_algorithm(id, &memory(0, 1000), |value| value.map(fixed));
        match rule {
            Rule::Absent => assert_eq!(result.unwrap_err().code(), ErrorCode::MalformedValue),
            _ => assert_eq!(result.unwrap().unwrap(), expected),
        }
        let der = Parser::der(memory(4096, 1_000_000));
        let mut reader = der.read(&bytes, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        assert!(algorithm::read(&reader, &element, "signatureAlgorithm").is_err());
    }
}

#[test]
fn unknown_oids_never_become_a_digest_key_agreement_or_nearby_signature() {
    // Digest/SPKI identifiers are different roles, and bounded support is not
    // a claim to recognize every OIW, DSA, PQ or obsolete signature profile.
    for oid in [
        &[43, 101, 110][..],
        &[43, 101, 111],
        &[43, 14, 3, 2, 29],
        &[96, 134, 72, 1, 101, 3, 4, 2, 1],
        &[96, 134, 72, 1, 101, 3, 4, 3, 3],
        &[96, 134, 72, 1, 101, 3, 4, 3, 8],
        &[96, 134, 72, 1, 101, 3, 4, 3, 17],
        &[42, 134, 72, 134, 247, 13, 1, 1, 1],
        &[42, 134, 72, 134, 247, 13, 1, 1, 4],
        &[42, 134, 72, 206, 61, 4, 3, 2, 1],
        &[42, 3],
    ] {
        for parameters in [None, Some(&[2, 1, 7][..])] {
            let source = Parser::der(memory(4096, 1_000_000));
            let bytes = encoded(oid, parameters);
            let id = identifier(&source, &bytes);
            assert!(
                signature::with_algorithm(id, &memory(0, 1000), |value| value.is_none()).unwrap()
            );
        }
    }
}

#[test]
fn pss_uses_the_same_kernel_cost_values_and_original_ranges() {
    // Recognition must not decode PSS twice, synthesize defaults or narrow
    // its salt. The direct and signature entry points have the same cost.
    let hash = encoded(&[96, 134, 72, 1, 101, 3, 4, 2, 1], None);
    let mgf_hash = encoded(&[43, 14, 3, 2, 26], None);
    let mgf = encoded(&[42, 134, 72, 134, 247, 13, 1, 1, 8], Some(&mgf_hash));
    let fields = [
        tlv(0xa0, &hash),
        tlv(0xa1, &mgf),
        tlv(0xa2, &tlv(2, &[1; 20])),
        tlv(0xa3, &[2, 1, 2]),
    ]
    .concat();
    let parameters = tlv(48, &fields);
    let bytes = encoded(&[42, 134, 72, 134, 247, 13, 1, 1, 10], Some(&parameters));
    let source = Parser::der(memory(10000, 1_000_000));
    let id = identifier(&source, &bytes);
    let direct_work = memory(10000, 100_000);
    let direct = {
        let operation = Parser::der(direct_work.clone());
        let query = operation.read(&[], 9000).unwrap();
        pss::read(id, &query.execution()).unwrap().unwrap()
    };
    let current = memory(10000, 100_000);
    let value = {
        let operation = Parser::der(current.clone());
        let query = operation.read(&[], 9000).unwrap();
        signature::with_algorithm(id, &query.execution(), |value| {
            let Some(Algorithm::RsaPss(value)) = value else {
                panic!("PSS");
            };
            *value
        })
        .unwrap()
    };
    assert_eq!(current.work_used(), direct_work.work_used());
    assert_eq!(
        value.element().as_bytes().as_ptr(),
        direct.element().as_bytes().as_ptr()
    );
    assert_eq!(value.element().as_bytes(), parameters);
    assert_eq!(
        value.hash().unwrap().value().algorithm().as_bytes(),
        &[96, 134, 72, 1, 101, 3, 4, 2, 1]
    );
    assert!(
        matches!(value.mask(), pss::Mask::Mgf1 { hash, .. } if hash.algorithm().as_bytes()==[43,14,3,2,26])
    );
    let pss::Number::Written(salt) = value.salt() else {
        panic!("written salt");
    };
    assert_eq!(salt.value().as_bytes(), &[1; 20]);
    assert_eq!(value.salt().as_u64(), None);
    assert_eq!(value.trailer().as_u64(), Some(2));
    assert_eq!(current.used(), 0);
}

#[test]
fn pss_signature_absence_null_and_der_defaults_do_not_become_key_restrictions() {
    // A signature needs its PSS SEQUENCE even though an SPKI may omit it.
    // Literal defaults are readable BER, strict DER spelling still refuses.
    for encoding in [Encoding::Ber, Encoding::Der] {
        for parameters in [
            None,
            Some(&[5, 0][..]),
            Some(&[48, 0][..]),
            Some(&[48, 5, 0xa2, 3, 2, 1, 20][..]),
        ] {
            let source = Parser::new(encoding, Limits::default(), memory(10000, 1_000_000));
            let bytes = encoded(&[42, 134, 72, 134, 247, 13, 1, 1, 10], parameters);
            let id = identifier(&source, &bytes);
            let result = signature::with_algorithm(id, &memory(10000, 100_000), |value| {
                matches!(value, Some(Algorithm::RsaPss(_)))
            });
            match parameters {
                None => assert_eq!(result.unwrap_err().code(), ErrorCode::MissingField),
                Some([5, 0]) => assert!(result.is_err()),
                Some([48, 0]) => assert!(result.unwrap()),
                _ if encoding.is_der() => {
                    assert_eq!(result.unwrap_err().code(), ErrorCode::DefaultWritten);
                }
                _ => assert!(result.unwrap()),
            }
        }
    }
}

#[test]
fn fixed_queries_preserve_exact_source_current_aggregate_and_single_session_billing() {
    // One OID scan is billed once; all applicable ceilings must admit before
    // it starts. A new account cannot reset the original cumulative budget.
    for (source_left, current_left, aggregate, success) in [
        (9, 9, 9, true),
        (8, 9, 9, false),
        (9, 8, 9, false),
        (9, 9, 8, false),
    ] {
        let source = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 1000,
                ..Limits::default()
            },
            memory(4096, 100_000),
        );
        let bytes = encoded(&[42, 134, 72, 206, 61, 4, 3, 2], None);
        let id = identifier(&source, &bytes);
        let old = source.execution_in(source.memory());
        old.charge_work((old.work_remaining() - source_left) as u64)
            .unwrap();
        let current = memory(0, aggregate);
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_work: current_left,
                ..Limits::default()
            },
            current.clone(),
        );
        let query = operation.read(&[], 9000).unwrap();
        let result = signature::with_algorithm(id, &query.execution(), |value| value.map(fixed));
        if success {
            assert_eq!(result.unwrap().unwrap(), Fixed::Ec(Hash::Sha256));
            assert_eq!(current.work_used(), 9);
            assert_eq!(old.work_remaining(), 0);
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource());
            assert_eq!((error.field(), error.offset()), ("signatureAlgorithm", 400));
            assert_eq!(current.work_used(), 0);
        }
        assert_eq!(current.used(), 0);
    }
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1000,
            ..Limits::default()
        },
        memory(4096, 100_000),
    );
    let bytes = encoded(&[42, 134, 72, 206, 61, 4, 3, 2], None);
    let id = identifier(&source, &bytes);
    let work = source.execution_in(source.memory());
    work.charge_work((work.work_remaining() - 9) as u64)
        .unwrap();
    let before = source.memory().work_used();
    assert!(signature::with_algorithm(id, &work, |value| value.is_some()).unwrap());
    assert_eq!(work.work_remaining(), 0);
    assert_eq!(source.memory().work_used(), before + 9);
}

#[test]
fn zero_work_is_terminal_even_for_unknown_or_invalid_parameters() {
    // Cheap negative outcomes are still decisions about untrusted metadata.
    for (oid, parameters) in [(&[42, 3][..], None), (&[43, 101, 112], Some(&[5, 0][..]))] {
        let source = Parser::der(memory(4096, 100_000));
        let bytes = encoded(oid, parameters);
        let id = identifier(&source, &bytes);
        let error = signature::with_algorithm(id, &memory(0, 0), |_| ()).unwrap_err();
        assert!(error.is_resource());
        assert_eq!((error.field(), error.offset()), ("signatureAlgorithm", 400));
    }
}

#[test]
fn pss_signature_keeps_current_depth_and_original_parameter_location() {
    // The classifier must pass current Work into the existing nested decoder,
    // rather than reopening parameters against a broader original ceiling.
    let source = Parser::der(memory(10000, 100_000));
    let bytes = encoded(&[42, 134, 72, 134, 247, 13, 1, 1, 10], Some(&[48, 0]));
    let id = identifier(&source, &bytes);
    for (depth, success) in [(0, false), (16, true)] {
        let current = memory(10000, 10000);
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_depth: depth,
                ..Limits::default()
            },
            current.clone(),
        );
        let query = operation.read(&[], 9000).unwrap();
        let result = signature::with_algorithm(id, &query.execution(), |value| {
            matches!(value, Some(Algorithm::RsaPss(_)))
        });
        if success {
            assert!(result.unwrap());
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.offset(), 413);
        }
        assert_eq!(current.used(), 0);
    }
}

mod ecdsa_callback {
    use super::*;
    // The public path callback has only original descriptors and current Work.
    // An independent RustCrypto oracle performs actual math after structural
    // recognition and key binding, without claiming its backend cost qualified.
    use p256::ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    };
    use structured_pkix::path::{
        self, Anchor, Interval, Policy, ValidationBounds, ValidationContext, Verified, Verify,
        WorkingKey,
    };
    use structured_pkix::signature::{DssValue, SignatureValue};
    struct Provider;
    impl<W: Work> Verify<W> for Provider {
        type Error = structured_pkix::Error;
        fn verify(
            &self,
            id: &AlgorithmIdentifier<'_>,
            key: WorkingKey<'_>,
            signed: &[u8],
            signature: SignatureValue<'_>,
            work: &W,
        ) -> Result<Verified, Self::Error> {
            signature::with_algorithm(*id, work, |algorithm| {
                let Some(Algorithm::Ecdsa(Hash::Sha256)) = algorithm else {
                    return Ok(Verified::Unsupported);
                };
                let key = structured_pkix::key::ec::read(key, work)?;
                work.charge_work(9).map_err(|reason| {
                    structured_pkix::Error::resource(
                        reason,
                        "subjectPublicKey.ec.curve",
                        key.parameters().span().start,
                    )
                })?;
                if !matches!(key.curve(), structured_pkix::key::ec::Curve::Named(oid)
                if oid.as_bytes() == [42,134,72,206,61,3,1,7])
                {
                    return Ok(Verified::Unsupported);
                }
                let backend = VerifyingKey::from_sec1_bytes(key.as_bytes()).unwrap();
                let pair = DssValue::read(&mut signature.reader_in(work)?, "ecdsa.signature")?;
                let scalar = |integer: structured_asn1::Integer<'_>| {
                    let raw = integer.as_bytes();
                    let raw = if raw[0] == 0 { &raw[1..] } else { raw };
                    assert!(!integer.is_negative() && raw.len() <= 32);
                    work.charge_work((32 + raw.len()) as u64).unwrap();
                    let mut scalar = [0; 32];
                    scalar[32 - raw.len()..].copy_from_slice(raw);
                    scalar
                };
                let signature =
                    Signature::from_scalars(scalar(pair.r()), scalar(pair.s())).unwrap();
                work.charge_work(signed.len() as u64).unwrap();
                Ok(if backend.verify(signed, &signature).is_ok() {
                    Verified::Yes
                } else {
                    Verified::No
                })
            })?
        }
    }
    #[test]
    fn actual_path_callback_selects_ecdsa_and_verifies_original_signed_bytes() {
        let issuer = SigningKey::from_slice(&[3; 32]).unwrap();
        let leaf = SigningKey::from_slice(&[4; 32]).unwrap();
        let algorithm = encoded(&[42, 134, 72, 206, 61, 4, 3, 2], None);
        let name = tlv(48, &tlv(49, &tlv(48, &[6, 3, 85, 4, 3, 12, 1, b'A'])));
        let date = tlv(23, b"261012120000Z");
        let certificate = |key: &SigningKey| {
            let spki_algorithm = encoded(
                &[42, 134, 72, 206, 61, 2, 1],
                Some(&tlv(6, &[42, 134, 72, 206, 61, 3, 1, 7])),
            );
            let point = key.verifying_key().to_sec1_point(false);
            let spki = tlv(
                48,
                &[
                    spki_algorithm,
                    tlv(3, &[&[0][..], point.as_bytes()].concat()),
                ]
                .concat(),
            );
            let tbs = tlv(
                48,
                &[
                    tlv(2, &[1]),
                    algorithm.clone(),
                    name.clone(),
                    tlv(48, &[date.clone(), date.clone()].concat()),
                    name.clone(),
                    spki,
                ]
                .concat(),
            );
            let signature: Signature = issuer.sign(&tbs);
            tlv(
                48,
                &[
                    tbs,
                    algorithm.clone(),
                    tlv(3, &[&[0][..], signature.to_der().as_bytes()].concat()),
                ]
                .concat(),
            )
        };
        let leaf_bytes = certificate(&leaf);
        let issuer_bytes = certificate(&issuer);
        let source = Parser::der(memory(100_000, 1_000_000));
        let issuer_source = Parser::der(memory(100_000, 1_000_000));
        let leaf = Certificate::read(&source, &leaf_bytes, 400).unwrap();
        let root = Certificate::read(&issuer_source, &issuer_bytes, 900).unwrap();
        let current = memory(100_000, 1_000_000);
        let operation = Parser::der(current.clone());
        let query = operation.read(&[], 9000).unwrap();
        let work = query.execution();
        let provider = Provider;
        let context = ValidationContext {
            execution: &work,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &provider,
            watch: &(),
            recognizer: &(),
        };
        assert!(matches!(
            path::validate(
                &[&leaf],
                Anchor::new(root.tbs().subject(), root.tbs().public_key()),
                &context
            )
            .unwrap(),
            path::Validation::Accepted(_)
        ));
        assert_eq!(
            provider
                .verify(
                    &leaf.signature_algorithm(),
                    WorkingKey::standing(root.tbs().public_key()),
                    b"changed",
                    leaf.signature_value(),
                    &work
                )
                .unwrap(),
            Verified::No
        );
    }
}

#[test]
fn visitor_stays_small_and_preserves_opaque_errors_without_running_on_refusal() {
    // PSS is a temporary borrowed view, not a 712-byte fixed-case result or
    // a new allocation. The visitor's non-Clone cause remains its own result.
    #[derive(Debug, PartialEq)]
    struct Cause(u8);
    assert!(core::mem::size_of::<Algorithm<'_, '_>>() <= 2 * core::mem::size_of::<usize>());
    let source = Parser::der(memory(10000, 100_000));
    let bytes = encoded(&[43, 101, 112], None);
    let id = identifier(&source, &bytes);
    let returned =
        signature::with_algorithm(id, &memory(0, 1000), |_| Err::<(), _>(Cause(7))).unwrap();
    assert_eq!(returned.unwrap_err(), Cause(7));
    let visited = std::cell::Cell::new(0);
    assert!(
        signature::with_algorithm(id, &memory(0, 0), |_| visited.set(visited.get() + 1))
            .unwrap_err()
            .is_resource()
    );
    let bytes = encoded(&[43, 101, 112], Some(&[5, 0]));
    let id = identifier(&source, &bytes);
    assert_eq!(
        signature::with_algorithm(id, &memory(0, 1000), |_| visited.set(visited.get() + 1))
            .unwrap_err()
            .code(),
        ErrorCode::MalformedValue
    );
    assert_eq!(visited.get(), 0);
}
