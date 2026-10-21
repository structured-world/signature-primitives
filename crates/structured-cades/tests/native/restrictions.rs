//! ESS path membership excludes the separately supplied trust anchor.

use super::*;
use p256::ecdsa::{Signature, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};

#[test]
fn certificate_anchor_is_not_an_ess_path_restriction_member() {
    // RFC5280 §6.1 keeps the anchor outside the prospective path. Two ESS
    // identifiers activate the restriction, but an unrelated additional ID
    // does not require the anchor to be named (RFC5035 §§3/5).
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let root_bytes = certificate("Root", "Root", &root_key, &root_key, false);
    let leaf_bytes = certificate("Signer", "Root", &key, &root_key, false);
    let ids = [
        tlv(0x30, &tlv(4, &Sha256::digest(&leaf_bytes))),
        tlv(0x30, &tlv(4, &[9; 32])),
    ]
    .concat();
    let mut attributes = vec![
        attribute(oid::CONTENT_TYPE.as_bytes(), &tlv(6, oid::DATA.as_bytes())),
        attribute(
            oid::MESSAGE_DIGEST.as_bytes(),
            &tlv(4, &Sha256::digest(b"sample")),
        ),
        attribute(oid::SIGNING_TIME.as_bytes(), &tlv(23, b"260101000000Z")),
        attribute(
            oid::SIGNING_CERTIFICATE_V2.as_bytes(),
            &tlv(0x30, &tlv(0x30, &ids)),
        ),
    ];
    attributes.sort();
    let attrs = attributes.concat();
    let signature: Signature = key
        .sign_prehash(&Sha256::digest(tlv(0x31, &attrs)))
        .unwrap();
    let encoded_signer = tlv(
        0x30,
        &[
            vec![2, 1, 1],
            tlv(0x30, &[support::name("Root"), vec![2, 1, 7]].concat()),
            tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
            tlv(0xa0, &attrs),
            tlv(0x30, &tlv(6, support::ECDSA)),
            tlv(4, signature.to_der().as_bytes()),
        ]
        .concat(),
    );
    let bytes = message(
        oid::DATA.as_bytes(),
        Some(b"sample"),
        &[root_bytes.clone(), leaf_bytes.clone()],
        &[],
        &[encoded_signer],
    );
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 400).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let work = parent.execution();
    let root = data
        .certificates()
        .iter()
        .find(|value| value.as_bytes() == root_bytes)
        .unwrap();
    let leaf = data
        .certificates()
        .iter()
        .find(|value| value.as_bytes() == leaf_bytes)
        .unwrap();
    let oracle = Oracle::new();
    let context = ValidationContext {
        execution: &work,
        interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
        policy: path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &oracle,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(path) =
        pki::check_path(&[leaf], Anchor::from_certificate(root), &context).unwrap()
    else {
        panic!("real P256 path");
    };
    assert_eq!(path.members().len(), 1);
    assert!(path.anchor().certificate().is_some());
    let prepare::Preparation::Ready(plan) = prepare::resolve(
        &oracle,
        &data.signers()[0],
        path.members()[0].key(),
        &parent,
        Scope::Content(oid::DATA),
    )
    .unwrap() else {
        panic!("real CMS plan");
    };
    let mut requests = work.vector();
    requests.try_push(plan).unwrap();
    let checks = DocumentBatch::prepare(
        &oracle,
        &data,
        requests.into_owned(),
        ContentMode::Carried,
        &parent,
    )
    .unwrap()
    .run_carried()
    .unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let prepared = Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
    let binding = basic::bind(
        &prepared,
        &checks,
        &checks.checks()[0],
        leaf,
        Some(&path),
        &oracle,
        &parent,
    )
    .unwrap();
    assert_eq!(binding.restrictions(), basic::PathRestriction::Matches);
    assert!(binding.is_bound());
}
