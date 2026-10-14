//! Original-session admission for retained CRL/OCSP catalogues.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::crl::CertificateList;
use structured_pkix::ocsp::Response;

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)))
}
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if value.len() < 128 {
        bytes.push(u8::try_from(value.len()).unwrap());
    } else {
        bytes.push(0x82);
        bytes.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    }
    bytes.extend_from_slice(value);
    bytes
}
fn algorithm() -> Vec<u8> {
    tlv(0x30, &[6, 3, 42, 3, 4])
}

#[test]
fn crl_entry_catalogue_growth_respects_original_local_ceiling() {
    // Revoked entries must not grow a global-only Vec after their byte grammar
    // passed. A failing final read releases every partially decoded entry.
    let date = tlv(23, b"261012120000Z");
    let issuer = tlv(
        0x30,
        &tlv(0x31, &tlv(0x30, &[6, 3, 0x55, 4, 3, 12, 1, b'A'])),
    );
    let mut entries = Vec::new();
    for serial in 1..=64 {
        entries.extend(tlv(0x30, &[tlv(2, &[serial]), date.clone()].concat()));
    }
    let tbs = tlv(
        0x30,
        &[algorithm(), issuer, date, tlv(0x30, &entries)].concat(),
    );
    let bytes = tlv(0x30, &[tbs, algorithm(), vec![3, 2, 0, 0xab]].concat());
    let measured = memory();
    let parser = Parser::der(measured.clone());
    let value = CertificateList::read(&parser, &bytes, 400).unwrap();
    assert_eq!(value.tbs().revoked_certificates().len(), 64);
    let work = measured.work_used();
    let memory = memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: u64::try_from(work - 1).unwrap(),
            ..Limits::default()
        },
        memory.clone(),
    );
    let error = CertificateList::read(&parser, &bytes, 400).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(memory.used(), 0);
    assert!(memory.work_remaining() > 1000);
}

#[test]
fn ocsp_response_catalogue_growth_respects_original_local_ceiling() {
    // An OCSP response vector is part of the same signed BasicResponse source,
    // not a separately unlimited operation after each SingleResponse is read.
    let date = tlv(24, b"20261012120000Z");
    let id = tlv(
        0x30,
        &[
            algorithm(),
            tlv(4, &[0x11; 20]),
            tlv(4, &[0x22; 20]),
            tlv(2, &[1]),
        ]
        .concat(),
    );
    let assertion = tlv(0x30, &[id, vec![0x80, 0], date.clone()].concat());
    let mut assertions = Vec::new();
    for _ in 0..64 {
        assertions.extend_from_slice(&assertion);
    }
    let response_data = tlv(
        0x30,
        &[
            tlv(0xa2, &tlv(4, &[0x33; 20])),
            date,
            tlv(0x30, &assertions),
        ]
        .concat(),
    );
    let basic = tlv(
        0x30,
        &[response_data, algorithm(), vec![3, 2, 0, 0xab]].concat(),
    );
    let response_bytes = tlv(
        0x30,
        &[tlv(6, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1]), tlv(4, &basic)].concat(),
    );
    let bytes = tlv(0x30, &[vec![10, 1, 0], tlv(0xa0, &response_bytes)].concat());
    let measured = memory();
    let parser = Parser::der(measured.clone());
    let Response::Successful(payload) = Response::read(&parser, &bytes, 400).unwrap() else {
        panic!("successful envelope required")
    };
    let value = payload.into_basic(&measured).unwrap().unwrap();
    assert_eq!(value.responses().len(), 64);
    let work = measured.work_used();
    let memory = memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: u64::try_from(work - 1).unwrap(),
            ..Limits::default()
        },
        memory.clone(),
    );
    let Response::Successful(payload) = Response::read(&parser, &bytes, 400).unwrap() else {
        panic!("successful envelope required")
    };
    let error = payload.into_basic(&memory).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(memory.used(), 0);
    assert!(memory.work_remaining() > 1000);
}

#[test]
fn ocsp_carried_certificate_catalogue_growth_respects_local_ceiling() {
    // Carried certificates have their own funded decoders, but the outer
    // retention vector must also charge before growth, under the same session.
    let date = tlv(24, b"20261012120000Z");
    let name = tlv(
        0x30,
        &tlv(0x31, &tlv(0x30, &[6, 3, 0x55, 4, 3, 12, 1, b'A'])),
    );
    let signed_certificate = tlv(
        0x30,
        &[
            tlv(2, &[1]),
            algorithm(),
            name.clone(),
            tlv(0x30, &[date.clone(), date.clone()].concat()),
            name,
            tlv(0x30, &[algorithm(), tlv(3, &[0, 0xab])].concat()),
        ]
        .concat(),
    );
    let certificate = tlv(
        0x30,
        &[signed_certificate, algorithm(), tlv(3, &[0, 0xab])].concat(),
    );
    let mut certificates = Vec::new();
    for _ in 0..64 {
        certificates.extend_from_slice(&certificate);
    }
    let id = tlv(
        0x30,
        &[
            algorithm(),
            tlv(4, &[0x11; 20]),
            tlv(4, &[0x22; 20]),
            tlv(2, &[1]),
        ]
        .concat(),
    );
    let assertion = tlv(0x30, &[id, vec![0x80, 0], date.clone()].concat());
    let response_data = tlv(
        0x30,
        &[tlv(0xa2, &tlv(4, &[0x33; 20])), date, tlv(0x30, &assertion)].concat(),
    );
    let basic = tlv(
        0x30,
        &[
            response_data,
            algorithm(),
            vec![3, 2, 0, 0xab],
            tlv(0xa0, &tlv(0x30, &certificates)),
        ]
        .concat(),
    );
    let response_bytes = tlv(
        0x30,
        &[tlv(6, &[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1]), tlv(4, &basic)].concat(),
    );
    let bytes = tlv(0x30, &[vec![10, 1, 0], tlv(0xa0, &response_bytes)].concat());
    let measured = memory();
    let parser = Parser::der(measured.clone());
    let Response::Successful(payload) = Response::read(&parser, &bytes, 400).unwrap() else {
        panic!("successful envelope required")
    };
    let value = payload.into_basic(&measured).unwrap().unwrap();
    assert_eq!(value.certificates().len(), 64);
    let work = measured.work_used();
    let memory = memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: u64::try_from(work - 1).unwrap(),
            ..Limits::default()
        },
        memory.clone(),
    );
    let Response::Successful(payload) = Response::read(&parser, &bytes, 400).unwrap() else {
        panic!("successful envelope required")
    };
    let error = payload.into_basic(&memory).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(memory.used(), 0);
    assert!(memory.work_remaining() > 1000);
}
