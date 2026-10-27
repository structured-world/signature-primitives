//! Independent profile reporting must not silently become strict acceptance.

use super::*;
use signature::Scheme;

fn expected_scheme(fixed: Fixed) -> Scheme {
    match fixed {
        Fixed::Rsa(hash) => Scheme::RsaPkcs1v15(hash),
        Fixed::Dsa(hash) => Scheme::Dsa(hash),
        Fixed::Ec(hash) => Scheme::Ecdsa(hash),
        Fixed::Ed25519 => Scheme::Ed25519,
        Fixed::Ed448 => Scheme::Ed448,
    }
}

#[test]
fn every_fixed_profile_retains_identity_fault_location_and_exact_cost() {
    // All fixed OIDs use the strict parameter table, even readable wrong values.
    // No catalogue allocation or second OID scan may hide in inspection.
    for (oid, expected, _) in cases() {
        for encoding in [Encoding::Der, Encoding::Ber] {
            for parameters in [None, Some(&[5, 0][..]), Some(&[2, 1, 0][..])] {
                let bytes = encoded(&oid, parameters);
                let source = Parser::new(encoding, Limits::default(), memory(4096, 1_000_000));
                let id = identifier(&source, &bytes);
                let strict_work = memory(0, 1000);
                let strict = signature::with_algorithm(id, &strict_work, |_| ());
                let current = memory(0, 1000);
                signature::with_inspection(id, &current, |reading| {
                    assert_eq!(reading.scheme(), Some(expected_scheme(expected)));
                    assert!(reading.parameters().is_none());
                    assert_eq!(reading.identifier().as_bytes().as_ptr(), bytes.as_ptr());
                    if let Err(error) = &strict {
                        assert_eq!(reading.faults(), std::slice::from_ref(error));
                    } else {
                        assert_eq!(reading.faults(), []);
                    }
                })
                .unwrap();
                assert_eq!(current.work_used(), oid.len() + 1);
                assert_eq!(current.work_used(), strict_work.work_used());
                assert_eq!(current.used(), 0);
            }
        }
    }
}

#[test]
fn pure_ml_dsa_and_ber_null_keep_faults_without_changing_strict() {
    // ML-DSA shares the absent-only rule; BER NULL spelling never erases presence.
    for last in [17, 18, 19] {
        let oid = [96, 134, 72, 1, 101, 3, 4, 3, last];
        let source = Parser::ber(memory(4096, 100_000));
        for parameters in [None, Some(&[5, 0x81, 0][..])] {
            let bytes = encoded(&oid, parameters);
            let id = identifier(&source, &bytes);
            signature::with_inspection(id, &memory(0, 1000), |reading| {
                assert!(matches!(reading.scheme(), Some(Scheme::MlDsa(_))));
                assert_eq!(reading.faults().len(), usize::from(parameters.is_some()));
                if parameters.is_some() {
                    assert_eq!(reading.faults()[0].code(), ErrorCode::MalformedValue);
                    assert_eq!(reading.faults()[0].offset(), 413);
                }
            })
            .unwrap();
        }
    }
    for (oid, _, rule) in cases() {
        let bytes = encoded(&oid, Some(&[5, 0x81, 0]));
        let source = Parser::ber(memory(4096, 100_000));
        let id = identifier(&source, &bytes);
        signature::with_inspection(id, &memory(0, 1000), |reading| {
            assert_eq!(reading.faults().is_empty(), !matches!(rule, Rule::Absent));
        })
        .unwrap();
    }
}

#[test]
fn missing_pss_is_recognized_but_never_fabricates_signature_parameters() {
    // Signature role requires parameters; the same key identifier stays unrestricted.
    let bytes = encoded(&[42, 134, 72, 134, 247, 13, 1, 1, 10], None);
    let source = Parser::der(memory(4096, 100_000));
    let id = identifier(&source, &bytes);
    signature::with_inspection(id, &memory(0, 1000), |reading| {
        assert_eq!(reading.scheme(), Some(Scheme::RsaPss));
        assert!(reading.parameters().is_none());
        assert_eq!(reading.faults().len(), 1);
        assert_eq!(reading.faults()[0].code(), ErrorCode::MissingField);
        assert_eq!(reading.faults()[0].offset(), 400);
    })
    .unwrap();
    assert!(pss::inspect(id, &memory(0, 1000)).unwrap().is_none());
    assert_eq!(
        signature::with_algorithm(id, &memory(0, 1000), |_| ())
            .unwrap_err()
            .code(),
        ErrorCode::MissingField
    );
}

#[test]
fn pss_inspection_shares_decoder_cost_original_values_and_diagnostic_lifetime() {
    // A written DER default stays visible without reparse, normalization or a new account.
    for encoding in [Encoding::Der, Encoding::Ber] {
        let parameters = [48, 10, 0xa2, 3, 2, 1, 20, 0xa3, 3, 2, 1, 1];
        let bytes = encoded(&[42, 134, 72, 134, 247, 13, 1, 1, 10], Some(&parameters));
        let source = Parser::new(encoding, Limits::default(), memory(10000, 100_000));
        let id = identifier(&source, &bytes);
        let direct_work = memory(10000, 100_000);
        let direct = pss::inspect(id, &direct_work).unwrap().unwrap();
        let current = memory(10000, 100_000);
        let saved = signature::with_inspection(id, &current, |reading| {
            assert_eq!(reading.scheme(), Some(Scheme::RsaPss));
            let actual = reading.parameters().unwrap();
            assert_eq!(
                actual.element().as_bytes().as_ptr(),
                parameters_pointer(&bytes)
            );
            assert_eq!(actual.element().span().start, 413);
            assert_eq!(actual.salt().as_u64(), Some(20));
            assert_eq!(actual.trailer().as_u64(), Some(1));
            assert_eq!(reading.faults(), direct.faults());
            assert_eq!(current.used(), direct_work.used());
            *actual
        })
        .unwrap();
        assert_eq!(saved.element().as_bytes(), parameters);
        assert_eq!(current.work_used(), direct_work.work_used());
        assert_eq!(current.used(), 0);
    }
}

fn parameters_pointer(bytes: &[u8]) -> *const u8 {
    bytes[13..].as_ptr()
}

#[test]
fn pss_grammar_refusal_and_diagnostic_storage_refusal_prevent_visit() {
    // Ambiguous or malformed PSS is not a usable scheme descriptor; diagnostic
    // allocation failure cannot silently remove a conformance fault.
    for parameters in [
        &[5, 0][..],
        &[48, 10, 0xa2, 3, 2, 1, 21, 0xa2, 3, 2, 1, 21],
        &[48, 5, 0xa2, 3, 2, 1, 0xff],
    ] {
        let bytes = encoded(&[42, 134, 72, 134, 247, 13, 1, 1, 10], Some(parameters));
        let source = Parser::der(memory(10000, 100_000));
        let id = identifier(&source, &bytes);
        let visited = std::cell::Cell::new(false);
        assert!(
            signature::with_inspection(id, &memory(10000, 10000), |_| visited.set(true)).is_err()
        );
        assert!(!visited.get());
    }
    let bytes = encoded(
        &[42, 134, 72, 134, 247, 13, 1, 1, 10],
        Some(&[48, 5, 0xa2, 3, 2, 1, 20]),
    );
    let source = Parser::der(memory(10000, 100_000));
    let id = identifier(&source, &bytes);
    let visited = std::cell::Cell::new(false);
    let current = memory(0, 10000);
    let error = signature::with_inspection(id, &current, |_| visited.set(true)).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 415);
    assert!(!visited.get());
    assert_eq!(current.used(), 0);
}

#[test]
fn unknown_and_invalid_profiles_cannot_bypass_current_or_origin_ceiling() {
    // Classification pays before visiting, even for unknown OIDs and faults.
    for oid in [&[42, 3][..], &[43, 101, 112]] {
        for origin_exhausted in [false, true] {
            let source = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: 1000,
                    ..Limits::default()
                },
                memory(4096, 100_000),
            );
            let bytes = encoded(oid, Some(&[5, 0]));
            let id = identifier(&source, &bytes);
            let original = source.execution_in(source.memory());
            let current = memory(0, if origin_exhausted { 1000 } else { 0 });
            if origin_exhausted {
                original
                    .charge_work(original.work_remaining() as u64)
                    .unwrap();
            }
            let visited = std::cell::Cell::new(false);
            let error =
                signature::with_inspection(id, &current, |_| visited.set(true)).unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.offset(), 400);
            assert!(!visited.get());
            assert_eq!(current.work_used(), 0);
        }
    }
}

#[test]
fn unknown_oid_callback_errors_and_original_views_survive_unchanged() {
    // Inspection neither assumes rules for unknown OIDs nor wraps a caller's error.
    #[derive(Debug, PartialEq)]
    struct Cause;
    let source = Parser::der(memory(4096, 100_000));
    let bytes = encoded(&[42, 3], Some(&[2, 1, 7]));
    let id = identifier(&source, &bytes);
    let result = signature::with_inspection(id, &memory(0, 1000), |reading| {
        assert_eq!(reading.scheme(), None);
        assert!(reading.parameters().is_none());
        assert_eq!(reading.faults(), []);
        Err::<(), _>(Cause)
    })
    .unwrap();
    assert_eq!(result, Err(Cause));
    let retained =
        signature::with_inspection(id, &memory(0, 1000), |reading| reading.identifier()).unwrap();
    assert_eq!(retained.as_bytes().as_ptr(), bytes.as_ptr());
}

#[test]
fn exact_current_admission_and_same_session_charge_are_preserved() {
    // Distinct local and aggregate ceilings apply, while a shared account is billed once.
    let bytes = encoded(&[43, 101, 112], Some(&[5, 0]));
    for (local, aggregate, success) in [(4, 4, true), (3, 4, false), (4, 3, false)] {
        let source = Parser::der(memory(4096, 100_000));
        let id = identifier(&source, &bytes);
        let current = memory(0, aggregate);
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            current.clone(),
        );
        let query = operation.read(&[], 9000).unwrap();
        let result = signature::with_inspection(id, &query.execution(), |reading| reading.scheme());
        if success {
            assert_eq!(result.unwrap(), Some(Scheme::Ed25519));
            assert_eq!(current.work_used(), 4);
        } else {
            assert!(result.unwrap_err().is_resource());
            assert_eq!(current.work_used(), 0);
        }
    }
    let source = Parser::der(memory(4096, 100_000));
    let id = identifier(&source, &bytes);
    let before = source.memory().work_used();
    signature::with_inspection(id, &source.execution_in(source.memory()), |_| ()).unwrap();
    assert_eq!(source.memory().work_used(), before + 4);
}

#[test]
fn pss_depth_refusal_is_located_and_terminal() {
    // Deferred PSS traversal cannot reset a narrowed current-operation depth ceiling.
    let bytes = encoded(&[42, 134, 72, 134, 247, 13, 1, 1, 10], Some(&[48, 0]));
    let source = Parser::der(memory(10000, 100_000));
    let id = identifier(&source, &bytes);
    let current = memory(10000, 10000);
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = operation.read(&[], 9000).unwrap();
    let visited = std::cell::Cell::new(false);
    let error =
        signature::with_inspection(id, &query.execution(), |_| visited.set(true)).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 413);
    assert!(!visited.get());
    assert_eq!(current.used(), 0);
}

#[test]
fn readable_profile_fault_and_actual_signature_math_are_independent() {
    // An independent test oracle verifies the original message while inspection
    // still reports forbidden ECDSA NULL. This does not qualify backend costs.
    use p256::ecdsa::{
        Signature, SigningKey,
        signature::{Signer, Verifier},
    };
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let message = b"original signed input";
    let signed: Signature = key.sign(message);
    let bytes = encoded(&[42, 134, 72, 206, 61, 4, 3, 2], Some(&[5, 0]));
    let source = Parser::der(memory(4096, 100_000));
    let id = identifier(&source, &bytes);
    let current = memory(0, 1000);
    signature::with_inspection(id, &current, |reading| {
        assert_eq!(reading.scheme(), Some(Scheme::Ecdsa(Hash::Sha256)));
        assert_eq!(reading.faults()[0].code(), ErrorCode::MalformedValue);
        assert_eq!(reading.identifier().parameters(), Some(&[5, 0][..]));
        assert!(key.verifying_key().verify(message, &signed).is_ok());
        assert!(
            key.verifying_key()
                .verify(b"changed input", &signed)
                .is_err()
        );
    })
    .unwrap();
    let visited = std::cell::Cell::new(false);
    assert_eq!(
        signature::with_algorithm(id, &current, |_| visited.set(true))
            .unwrap_err()
            .code(),
        ErrorCode::MalformedValue
    );
    assert!(!visited.get());
}
