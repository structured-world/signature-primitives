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

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one retained-pool lifecycle checks all actual root/TSA certificate, CRL, bare-OCSP and open-value placements plus refusal/drop"
)]
fn historical_material_retains_actual_root_and_tsa_containers() {
    // Annex A.1.4 carries BARE basic responses. The format issuer indexes
    // those actual values and their first-read models, without inventing a
    // successful OCSPResponse envelope or re-parsing them during lookup.
    use structured_cades::material::{Placement, Pool};
    use structured_ltv::source::{Scope, Source};
    let key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let cert = certificate("Root", "Root", &key, &key, false);
    let crl = crl_fixture::crl(&key);
    let basic = basic_ocsp();
    let open_values = tlv(0x30, &tlv(2, &[1]));
    let other = tlv(0x30, &[tlv(6, &[42]), open_values.clone()].concat());
    let certificate_values = attribute(
        &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 23],
        &tlv(0x30, &cert),
    );
    let revocation_values = attribute(
        &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 24],
        &tlv(
            0x30,
            &[
                tlv(0xa0, &tlv(0x30, &crl)),
                tlv(0xa1, &tlv(0x30, &basic)),
                tlv(0xa2, &other),
            ]
            .concat(),
        ),
    );
    let values = [certificate_values, revocation_values];
    let info = tlv(
        0x30,
        &[
            vec![2, 1, 1],
            tlv(6, &[42, 3]),
            tlv(
                0x30,
                &[tlv(0x30, &tlv(6, oid::SHA256.as_bytes())), tlv(4, &[0; 32])].concat(),
            ),
            vec![2, 1, 9],
            tlv(24, b"20260101000100Z"),
        ]
        .concat(),
    );
    let tsa_signer = signer(
        Some(oid::TST_INFO.as_bytes()),
        &info,
        &cert,
        &key,
        &[],
        &values,
    );
    let token = message(
        oid::TST_INFO.as_bytes(),
        Some(&info),
        std::slice::from_ref(&cert),
        &[],
        &[tsa_signer],
    );
    let mut unsigned = values.to_vec();
    unsigned.push(attribute(
        &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 48],
        &token,
    ));
    let root_signer = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &cert,
        &key,
        &[],
        &unsigned,
    );
    let bytes = message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[cert],
        &[],
        &[root_signer],
    );
    let account = memory();
    {
        let parser = Parser::ber(account.clone());
        let data = SignedData::read(&parser, &bytes, 900).unwrap();
        let reader = parser.read(&[], 900).unwrap();
        let document = Document::new(&data, &reader).unwrap();
        let prepared =
            Preparation::read(&document, &data.signers()[0], Level::Basic, &reader).unwrap();
        assert!(prepared.properties().faults().is_empty());
        let original_values = prepared.properties().legacy_values().unwrap();
        assert_eq!(original_values.certificates().len(), 1);
        assert_eq!(original_values.crls().len(), 1);
        assert_eq!(original_values.ocsp_responses().len(), 1);
        assert_eq!(original_values.other_revocation().len(), 1);
        assert_eq!(original_values.other_revocation()[0].kind.as_bytes(), [42]);
        assert_eq!(
            original_values.other_revocation()[0]
                .values
                .element()
                .as_bytes(),
            open_values
        );
        let pool = Pool::read(&prepared, &reader).unwrap();
        assert_eq!(pool.open().len(), 2);
        assert!(
            pool.open()
                .iter()
                .all(|entry| matches!(entry.placement, Placement::OtherRevocationValues(_)))
        );
        assert_eq!(pool.crls(), 2);
        assert_eq!(pool.ocsp_responses(), 2);
        let work = reader.execution();
        let query = Scope::new(&document, document.snapshot(), &work);
        let index = pool.index(&query).unwrap();
        let mut certificates = [0, 0];
        for occurrence in index
            .certificate(&original_values.certificates()[0].value, &query)
            .unwrap()
        {
            if let Placement::CertificateValues(location) = occurrence.unwrap().placement() {
                assert!(location.unsigned);
                certificates[usize::from(location.token.is_some())] += 1;
            }
        }
        assert_eq!(certificates, [1, 1]);
        for is_ocsp in [false, true] {
            let mut locations = [0, 0];
            let occurrences = if is_ocsp {
                index
                    .ocsp(pool.ocsp(0, &work).unwrap().unwrap(), &query)
                    .unwrap()
            } else {
                index
                    .crl(pool.crl(0, &work).unwrap().unwrap(), &query)
                    .unwrap()
            };
            for occurrence in occurrences {
                match occurrence.unwrap().placement() {
                    Placement::CrlValues(location) | Placement::OcspValues(location) => {
                        assert!(location.unsigned);
                        locations[usize::from(location.token.is_some())] += 1;
                    }
                    _ => panic!("invented legacy wire container"),
                }
            }
            assert_eq!(locations, [1, 1]);
        }
        // Retained-index lookups remain subject to NEW work; no free cache
        // traversal, successful absence or hidden source reparse on refusal.
        let before = account.used();
        account
            .charge_work(account.work_remaining() as u64)
            .unwrap();
        assert!(pool.ocsp(0, &work).is_err());
        assert!(pool.crl(0, &work).is_err());
        assert_eq!(account.used(), before);
    }
    assert_eq!(account.used(), 0);
}
