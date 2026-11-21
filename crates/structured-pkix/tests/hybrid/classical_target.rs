//! Real signatures over independently assembled preTBS inputs.
use super::*;
use ml_dsa::signature::Keypair;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

fn name(value: &[u8]) -> Vec<u8> {
    tlv(
        48,
        &tlv(
            49,
            &tlv(48, &[tlv(6, &[0x55, 4, 3]), tlv(12, value)].concat()),
        ),
    )
}
fn native(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn pq(seed: u8) -> ml_dsa::SigningKey<ml_dsa::MlDsa65> {
    ml_dsa::SigningKey::from_seed(&[seed; 32].into())
}
fn pq_algorithm() -> Vec<u8> {
    tlv(48, &tlv(6, &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, 0x12]))
}
fn bits(bytes: &[u8]) -> Vec<u8> {
    tlv(3, &[&[0][..], bytes].concat())
}
fn key_extension(seed: u8) -> Vec<u8> {
    let spki = tlv(
        48,
        &[pq_algorithm(), bits(&pq(seed).verifying_key().encode())].concat(),
    );
    extension(72, &spki)
}
fn extension(last: u8, value: &[u8]) -> Vec<u8> {
    tlv(48, &[tlv(6, &[0x55, 0x1d, last]), tlv(4, value)].concat())
}
fn issue(
    subject: u8,
    issuer: u8,
    alt_key: Option<Vec<u8>>,
    authority: bool,
    alt_signer: u8,
) -> Vec<u8> {
    let mut tbs = children(&children(ROOT)[0]);
    tbs[1] = tlv(2, &[subject]);
    tbs[3] = name(&[b'A' + issuer]);
    tbs[5] = name(&[b'A' + subject]);
    let algorithm = tlv(
        48,
        &[
            tlv(6, &[42, 134, 72, 206, 61, 2, 1]),
            tlv(6, &[42, 134, 72, 206, 61, 3, 1, 7]),
        ]
        .concat(),
    );
    let point = native(subject).verifying_key().to_sec1_point(false);
    tbs[6] = tlv(48, &[algorithm, bits(point.as_bytes())].concat());
    let mut extensions = Vec::new();
    if authority {
        extensions.push(extension(19, &tlv(48, &tlv(1, &[0xff]))));
    }
    if let Some(key) = alt_key {
        extensions.push(key);
    }
    extensions.push(extension(73, &pq_algorithm()));
    *tbs.last_mut().unwrap() = tlv(0xa3, &tlv(48, &extensions.concat()));
    // Independent X.509 transform: omit native signature AlgorithmIdentifier
    // and the entire altSignatureValue extension, preserving all other fields.
    let preimage = tlv(
        48,
        &tbs.iter()
            .enumerate()
            .filter(|(index, _)| *index != 2)
            .flat_map(|(_, value)| value.iter().copied())
            .collect::<Vec<_>>(),
    );
    let signature = pq(alt_signer)
        .expanded_key()
        .sign_deterministic(&preimage, &[])
        .unwrap();
    extensions.push(extension(74, &bits(&signature.encode())));
    *tbs.last_mut().unwrap() = tlv(0xa3, &tlv(48, &extensions.concat()));
    let signed = tlv(48, &tbs.concat());
    let native_signature: Signature = native(issuer).sign(&signed);
    tlv(
        48,
        &[
            signed,
            tbs[2].clone(),
            bits(native_signature.to_der().as_bytes()),
        ]
        .concat(),
    )
}

#[test]
fn classical_target_issuer_signatures_succeed_under_both_requirements() {
    // The target holds only ECDSA, but both issuer signatures are real and
    // valid. The intermediate must supply the key used to verify that target.
    let root_bytes = issue(1, 1, Some(key_extension(1)), true, 1);
    let intermediate_bytes = issue(2, 1, Some(key_extension(2)), true, 1);
    let leaf_bytes = issue(3, 2, None, false, 2);
    let work = ample();
    let parser = Parser::der(work.clone());
    let root = Certificate::read(&parser, &root_bytes, 100).unwrap();
    let intermediate = Certificate::read(&parser, &intermediate_bytes, 10000).unwrap();
    let leaf = Certificate::read(&parser, &leaf_bytes, 20000).unwrap();
    let alternative = hybrid::inspect_certificate(&root, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    for requirement in [Requirement::Alternative, Requirement::Both] {
        let pq = Pq::new();
        let context = ValidationContext {
            execution: &work,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &Native,
            watch: &(),
            recognizer: &(),
        };
        let result = path::hybrid::validate(
            &[&leaf, &intermediate],
            path::hybrid::HybridAnchor {
                native: Anchor::from_certificate(&root),
                alternative,
            },
            &context,
            requirement,
            &pq,
        )
        .unwrap();
        assert!(
            matches!(result.outcome, path::Validation::Accepted(_)),
            "{:?}",
            result.outcome
        );
        assert_eq!(pq.calls.get(), 2);
        for (position, certificate) in [&leaf, &intermediate].iter().enumerate() {
            let slot = &result.signatures()[position];
            assert_eq!(slot.position, position);
            assert_eq!(slot.source, certificate.span());
            let pair = slot.signatures.unwrap();
            assert_eq!(pair.native, Verified::Yes);
            assert_eq!(pair.alternative, Alternative::Verified(Verified::Yes));
        }
    }
}

fn assessment(
    leaf: &[u8],
    intermediate: &[u8],
    requirement: Requirement,
) -> (bool, Vec<Option<hybrid::Signatures>>, usize) {
    let root_bytes = issue(1, 1, Some(key_extension(1)), true, 1);
    let work = ample();
    let parser = Parser::der(work.clone());
    let root = Certificate::read(&parser, &root_bytes, 100).unwrap();
    let intermediate = Certificate::read(&parser, intermediate, 10000).unwrap();
    let leaf = Certificate::read(&parser, leaf, 20000).unwrap();
    let alternative = hybrid::inspect_certificate(&root, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    let context = ValidationContext {
        execution: &work,
        interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &Native,
        watch: &(),
        recognizer: &(),
    };
    let pq = Pq::new();
    let result = path::hybrid::validate(
        &[&leaf, &intermediate],
        path::hybrid::HybridAnchor {
            native: Anchor::from_certificate(&root),
            alternative,
        },
        &context,
        requirement,
        &pq,
    )
    .unwrap();
    (
        matches!(result.outcome, path::Validation::Accepted(_)),
        result
            .signatures()
            .iter()
            .map(|slot| slot.signatures)
            .collect(),
        pq.calls.get(),
    )
}

#[test]
fn classical_target_does_not_accept_a_foreign_alternative_issuer_or_missing_issuer_key() {
    // A missing subject key is harmless only at the terminal position. It
    // must neither substitute for the issuer key nor change a computed No.
    let intermediate = issue(2, 1, Some(key_extension(2)), true, 1);
    let wrong_leaf = issue(3, 2, None, false, 3);
    for requirement in [Requirement::Alternative, Requirement::Both] {
        let (accepted, slots, calls) = assessment(&wrong_leaf, &intermediate, requirement);
        assert!(!accepted);
        let pair = slots[0].unwrap();
        assert_eq!(pair.native, Verified::Yes);
        assert_eq!(pair.alternative, Alternative::Verified(Verified::No));
        assert_eq!(calls, 2);
    }
    let intermediate = issue(2, 1, None, true, 1);
    let leaf = issue(3, 2, None, false, 2);
    let (accepted, slots, calls) = assessment(&leaf, &intermediate, Requirement::Alternative);
    assert!(!accepted);
    assert!(slots[0].is_none());
    assert!(matches!(
        slots[1].unwrap().alternative,
        Alternative::Nonconforming(_)
    ));
    assert_eq!(calls, 0);
}

fn remove_alternative(bytes: &[u8], last: u8) -> Vec<u8> {
    let mut outer = children(bytes);
    let mut tbs = children(&outer[0]);
    let mut extensions = children(&children(tbs.last().unwrap())[0]);
    extensions.retain(|value| children(value)[0] != tlv(6, &[0x55, 0x1d, last]));
    *tbs.last_mut().unwrap() = tlv(0xa3, &tlv(48, &extensions.concat()));
    outer[0] = tlv(48, &tbs.concat());
    let signature: Signature = native(2).sign(&outer[0]);
    outer[2] = bits(signature.to_der().as_bytes());
    tlv(48, &outer.concat())
}

#[test]
fn classical_target_still_requires_both_alternative_signature_extensions() {
    // Keep the native signature valid after stripping either extension so
    // native success cannot mask missing required alternative evidence.
    let intermediate = issue(2, 1, Some(key_extension(2)), true, 1);
    let leaf = issue(3, 2, None, false, 2);
    for last in [73, 74] {
        let stripped = remove_alternative(&leaf, last);
        for requirement in [Requirement::Alternative, Requirement::Both] {
            let (accepted, slots, calls) = assessment(&stripped, &intermediate, requirement);
            assert!(!accepted);
            let pair = slots[0].unwrap();
            assert_eq!(pair.native, Verified::Yes);
            assert!(matches!(pair.alternative, Alternative::Nonconforming(_)));
            assert_eq!(calls, 1);
        }
    }
}

#[test]
fn present_malformed_or_critical_unknown_target_key_is_not_omission() {
    // Malformed noncritical data must not take the absent-key branch. The
    // ordinary critical-extension gate still applies before signature work.
    let intermediate = issue(2, 1, Some(key_extension(2)), true, 1);
    let malformed = extension(72, &tlv(5, &[]));
    let unknown_spki = tlv(48, &[tlv(48, &tlv(6, &[42, 3, 4])), bits(&[1])].concat());
    let critical = tlv(
        48,
        &[
            tlv(6, &[0x55, 0x1d, 72]),
            tlv(1, &[0xff]),
            tlv(4, &unknown_spki),
        ]
        .concat(),
    );
    for (key, critical) in [(malformed, false), (critical, true)] {
        let leaf = issue(3, 2, Some(key), false, 2);
        let (accepted, slots, calls) = assessment(&leaf, &intermediate, Requirement::Both);
        assert!(!accepted);
        if critical {
            assert!(slots[0].is_none());
        } else {
            assert!(matches!(
                slots[0].unwrap().alternative,
                Alternative::Nonconforming(_)
            ));
        }
        assert_eq!(calls, 1);
    }
}

#[test]
fn signature_only_preparation_does_not_claim_complete_certificate_profile() {
    // The new mathematics entry point permits the target; the established
    // complete-profile entry point still enforces X.509 section 7.2.2.
    let issuer_bytes = issue(2, 1, Some(key_extension(2)), true, 1);
    let leaf_bytes = issue(3, 2, None, false, 2);
    let work = ample();
    let parser = Parser::der(work.clone());
    let issuer = Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let leaf = Certificate::read(&parser, &leaf_bytes, 10000).unwrap();
    assert_eq!(
        hybrid::prepare_certificate(&leaf, &work)
            .unwrap_err()
            .code(),
        structured_pkix::ErrorCode::MissingField
    );
    let key = hybrid::inspect_certificate(&issuer, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    let prepared = hybrid::prepare_certificate_signature(&leaf, &work).unwrap();
    assert_eq!(
        prepared.verify(key, &Pq::new(), &work).unwrap(),
        Verified::Yes
    );
    assert!(
        hybrid::prepare_certificate_signature(&leaf, &memory(0, 0))
            .unwrap_err()
            .is_resource()
    );
}
