//! Producing certificate schema queries share the local parser ceiling.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::Certificate;

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)))
}
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if contents.len() < 128 {
        bytes.push(u8::try_from(contents.len()).unwrap());
    } else {
        bytes.extend_from_slice(&[0x81, u8::try_from(contents.len()).unwrap()]);
    }
    bytes.extend_from_slice(contents);
    bytes
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

#[test]
fn empty_subject_san_lookup_cannot_bypass_producing_work() {
    // Empty-subject validity needs the critical SAN lookup (RFC5280 4.1.2.6).
    // Its full catalogue scan is certificate parsing work, not a new retained
    // query. Measure all actual admission and refuse one unit before success.
    let algorithm = seq(&[tlv(6, &[42])]);
    let issuer = seq(&[tlv(
        0x31,
        &seq(&[tlv(6, &[0x55, 4, 3]), tlv(12, b"issuer")]),
    )]);
    let san = seq(&[
        tlv(6, structured_pkix::oid::SUBJECT_ALT_NAME.as_bytes()),
        tlv(1, &[0xff]),
        tlv(4, &seq(&[tlv(0x82, b"example.com")])),
    ]);
    let unrelated = seq(&[tlv(6, &[43]), tlv(4, &[])]);
    let tbs = seq(&[
        tlv(0xa0, &[2, 1, 2]),
        tlv(2, &[7]),
        algorithm.clone(),
        issuer,
        seq(&[tlv(23, b"240101000000Z"), tlv(23, b"300101000000Z")]),
        seq(&[]),
        seq(&[algorithm.clone(), tlv(3, &[0, 1])]),
        tlv(0xa3, &seq(&[unrelated, san])),
    ]);
    let encoded = seq(&[tbs, algorithm, tlv(3, &[0, 1])]);
    // Map lookups pay one comparison per hash-tag match, and each map draws a
    // random hasher seed, so a parse can cost an extra comparison now and then.
    // The smallest of several parses is the work without one; every parse pays
    // at least that, so one unit less must refuse whatever the seed.
    let total = (0..32)
        .map(|_| {
            let baseline = memory();
            let parser = Parser::der(baseline.clone());
            let certificate = Certificate::read(&parser, &encoded, 400).unwrap();
            assert!(certificate.tbs().subject().is_empty());
            let work = u64::try_from(baseline.work_used()).unwrap();
            drop(certificate);
            assert_eq!(baseline.used(), 0);
            work
        })
        .min()
        .unwrap();
    let current = memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: total - 1,
            ..Limits::default()
        },
        current.clone(),
    );
    let error = Certificate::read(&parser, &encoded, 400)
        .expect_err("lookup must consume producing allowance");
    assert!(error.is_resource());
    assert_eq!(current.used(), 0);
}
