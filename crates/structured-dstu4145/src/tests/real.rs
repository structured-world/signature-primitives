use super::accounting::{memory, parser};
use crate::{
    accounted::{Hashes, Key, prepare_dke},
    hash::Hash,
};
use base64ct::{Base64, Encoding};
use structured_asn1::digest::{Digest, Resolution};
use structured_pkix::{Certificate, algorithm::signature, key};

/// Unmodified independently issued public CA signatures qualify the complete
/// ASN->key/DKE->streaming hash->native digest mapping->signature path. These
/// are mathematical self-signature checks, not statements of anchor trust.
#[test]
fn independently_issued_gost_and_kupyna_certificates_verify() {
    for pem in [
        include_str!("../../tests/data/nbu-gost.pem"),
        include_str!("../../tests/data/nbu-kupyna.pem"),
    ] {
        let text: std::string::String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let bytes = Base64::decode_vec(&text).unwrap();
        let memory = memory();
        let parser = parser(memory.clone());
        let certificate = Certificate::read(&parser, &bytes, 1200).unwrap();
        let public = certificate.tbs().public_key();
        let reading = key::dstu4145::read(public, &memory).unwrap();
        let dke = prepare_dke(reading.parameters().unwrap(), &memory).unwrap();
        let prepared = Key::prepare(public, &dke, &memory).unwrap();
        let profile =
            signature::with_algorithm(certificate.signature_algorithm(), &memory, |value| {
                match value {
                    Some(signature::Algorithm::Dstu4145(profile)) => profile,
                    _ => panic!("DSTU signature"),
                }
            })
            .unwrap();
        let identity = prepared.digest_identity(profile, &memory).unwrap();
        if profile.digest() == structured_pkix::algorithm::digest::Algorithm::Kupyna256 {
            assert!(matches!(identity.hash(), Hash::Kupyna(32)));
            assert_eq!(
                reading.profile().digest(),
                structured_pkix::algorithm::digest::Algorithm::Gost34311
            );
        }
        let Resolution::Supported(mut state) = Hashes.start(&identity, &memory).unwrap() else {
            panic!("hash")
        };
        for chunk in certificate.tbs().as_bytes().chunks(17) {
            Hashes.update(&mut state, chunk, &memory).unwrap();
        }
        let output = Hashes.finish(state, &memory).unwrap();
        assert!(
            prepared
                .verify_signature_value(
                    profile,
                    identity,
                    output.as_ref(),
                    certificate.signature_value(),
                    &memory
                )
                .unwrap()
        );
        let mut changed = output.as_ref().to_vec();
        changed[0] ^= 1;
        assert!(
            !prepared
                .verify_signature_value(
                    profile,
                    identity,
                    &changed,
                    certificate.signature_value(),
                    &memory
                )
                .unwrap()
        );
    }
}
