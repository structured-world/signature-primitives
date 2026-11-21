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
