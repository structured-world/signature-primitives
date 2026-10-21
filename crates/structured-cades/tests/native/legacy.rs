//! Original Annex A schemas reuse the actual PKIX models, without authentication.

#[path = "../support/crl.rs"]
mod crl_fixture;
use crate::support::{attribute, certificate, memory, message, name, signer, tlv};
use p256::ecdsa::SigningKey;
use structured_asn1::Parser;
use structured_cades::{Level, prepare::Preparation, source::Document};
use structured_cms::{SignedData, oid};

fn basic_ocsp() -> Vec<u8> {
    // Structural DEV response, as in the shared OCSP decoder's fixtures.
    // It has no authenticated status authority and asserts no signature math.
    let algorithm = tlv(0x30, &tlv(6, &[42, 3, 4]));
    let produced = tlv(24, b"20260101000000Z");
    let id = tlv(
        0x30,
        &[
            algorithm.clone(),
            tlv(4, &[1; 20]),
            tlv(4, &[2; 20]),
            tlv(2, &[7]),
        ]
        .concat(),
    );
    let single = tlv(0x30, &[id, tlv(0x80, &[]), produced.clone()].concat());
    let data = tlv(
        0x30,
        &[tlv(0xa2, &tlv(4, &[3; 20])), produced, tlv(0x30, &single)].concat(),
    );
    tlv(0x30, &[data, algorithm, tlv(3, &[0, 1])].concat())
}

fn schema_fault(suffix: u8, value: &[u8], key: &SigningKey, certificate: &[u8]) -> bool {
    let kind = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, suffix];
    let unsigned = [attribute(&kind, value)];
    let signature = signer(
        Some(oid::DATA.as_bytes()),
        b"sample",
        certificate,
        key,
        &[],
        &unsigned,
    );
    let bytes = message(
        oid::DATA.as_bytes(),
        Some(b"sample"),
        &[certificate.to_vec()],
        &[],
        &[signature],
    );
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 500).unwrap();
    let parent = parser.read(&[], 0).unwrap();
    let document = Document::new(&data, &parent).unwrap();
    let prepared = Preparation::read(&document, &data.signers()[0], Level::Basic, &parent).unwrap();
    prepared
        .properties()
        .faults()
        .iter()
        .any(|fault| fault.attribute.as_bytes() == kind)
}

#[test]
fn legacy_reference_and_material_shapes_use_the_existing_readers() {
    // Positive complete nested schemas and malformed inner fields must take
    // the same producing-reader path. An outer SEQUENCE alone proves nothing.
    let key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let cert = certificate("Root", "Root", &key, &key, false);
    let crl = crl_fixture::crl(&key);
    let hash = tlv(4, &[1; 20]);
    let other = tlv(
        0x30,
        &[tlv(0x30, &tlv(6, oid::SHA256.as_bytes())), tlv(4, &[2; 32])].concat(),
    );
    let issuer = tlv(
        0x30,
        &[tlv(0x30, &tlv(0xa4, &name("Root"))), tlv(2, &[7])].concat(),
    );
    let references = tlv(
        0x30,
        &[
            tlv(0x30, &[hash.clone(), issuer].concat()),
            tlv(0x30, &other),
        ]
        .concat(),
    );
    let crl_id = tlv(
        0x30,
        &[name("Root"), tlv(23, b"260101000000Z"), tlv(2, &[1])].concat(),
    );
    let crls = tlv(
        0x30,
        &tlv(0x30, &tlv(0x30, &[hash.clone(), crl_id].concat())),
    );
    let ocsp_id = tlv(
        0x30,
        &[tlv(0xa2, &tlv(4, &[3; 20])), tlv(24, b"20260101000000Z")].concat(),
    );
    let ocsps = tlv(0x30, &tlv(0x30, &tlv(0x30, &[ocsp_id, other].concat())));
    let open = tlv(0x30, &[tlv(6, &[42]), tlv(0x30, &tlv(2, &[1]))].concat());
    let revocations = tlv(
        0x30,
        &tlv(
            0x30,
            &[tlv(0xa0, &crls), tlv(0xa1, &ocsps), tlv(0xa2, &open)].concat(),
        ),
    );
    let values = tlv(
        0x30,
        &[
            tlv(0xa0, &tlv(0x30, &crl)),
            tlv(0xa1, &tlv(0x30, &basic_ocsp())),
            tlv(0xa2, &open),
        ]
        .concat(),
    );
    for (suffix, value) in [
        (21, &references),
        (44, &references),
        (22, &revocations),
        (45, &revocations),
        (23, &tlv(0x30, &cert)),
        (24, &values),
    ] {
        assert!(
            !schema_fault(suffix, value, &key, &cert),
            "valid suffix={suffix}"
        );
    }
    for (suffix, value) in [
        (21, tlv(0x30, &tlv(0x30, &tlv(2, &[1])))),
        (
            44,
            tlv(
                0x30,
                &tlv(
                    0x30,
                    &[hash, tlv(0x30, &[tlv(0x30, &[]), tlv(2, &[7])].concat())].concat(),
                ),
            ),
        ),
        (22, tlv(0x30, &tlv(0x30, &tlv(0xa0, &tlv(2, &[1]))))),
        (
            45,
            tlv(
                0x30,
                &tlv(0x30, &[tlv(0xa2, &open), tlv(0xa2, &open)].concat()),
            ),
        ),
        (23, tlv(0x30, &tlv(0x30, &[]))),
        (24, tlv(0x30, &tlv(0xa1, &tlv(0x30, &tlv(0x30, &[]))))),
    ] {
        assert!(
            schema_fault(suffix, &value, &key, &cert),
            "malformed suffix={suffix}"
        );
    }
}
