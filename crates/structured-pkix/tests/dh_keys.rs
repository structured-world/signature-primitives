//! X9.42 framing, borrowed provenance and resource boundaries, without DH math.
use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, Work},
};
use structured_pkix::{PublicKeyInfo, key::dh};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = structured_asn1::length::DerLength::new(value.len() as u64);
    out.extend_from_slice(len.as_bytes());
    out.extend_from_slice(value);
    out
}
fn seq(values: &[Vec<u8>]) -> Vec<u8> {
    tlv(48, &values.concat())
}
fn int(value: u8) -> Vec<u8> {
    tlv(2, &[value])
}
fn parameters(extra: &[Vec<u8>]) -> Vec<u8> {
    let mut values = vec![int(23), int(2), int(11)];
    values.extend_from_slice(extra);
    seq(&values)
}
fn spki(params: &[u8], y: &[u8]) -> Vec<u8> {
    let mut algorithm = tlv(6, dh::IDENTIFIER.as_bytes());
    algorithm.extend_from_slice(params);
    let mut bits = vec![0];
    bits.extend_from_slice(y);
    seq(&[tlv(48, &algorithm), tlv(3, &bits)])
}
fn info<'a>(parser: &'a Parser, bytes: &'a [u8]) -> PublicKeyInfo<'a> {
    let mut reader = parser.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    PublicKeyInfo::read_element(&reader, &element, "key").unwrap()
}

#[test]
fn dh_order_optional_fields_and_borrowed_source_spans() {
    // p,g,q must not silently use the DSA order p,q,g. Both optional fields
    // vary independently, and a non-octet-aligned seed is preserved as bits.
    for j in [false, true] {
        for evidence in [false, true] {
            let mut extras = Vec::new();
            if j {
                extras.push(int(2));
            }
            if evidence {
                extras.push(seq(&[tlv(3, &[3, 0xa8]), int(0)]));
            }
            let bytes = spki(&parameters(&extras), &tlv(2, &[0, 0x83]));
            let parser = Parser::der(memory(4096, 10000));
            let key = dh::read(info(&parser, &bytes), parser.memory()).unwrap();
            let params = key.parameters();
            assert_eq!(params.p().as_bytes(), [23]);
            assert_eq!(params.g().as_bytes(), [2]);
            assert_eq!(params.q().as_bytes(), [11]);
            assert_eq!(params.j().is_some(), j);
            assert_eq!(params.validation().is_some(), evidence);
            if let Some(validation) = params.validation() {
                assert_eq!(validation.seed().as_bytes(), [0xa8]);
                assert_eq!(validation.pgen_counter().as_bytes(), [0]);
            }
            assert_eq!(key.y().as_bytes(), [0x83]);
            let start = usize::try_from(key.y().element().contents_span().start - 400).unwrap();
            assert_eq!(
                key.y().integer().as_bytes().as_ptr(),
                bytes[start..].as_ptr()
            );
            assert_eq!(parser.memory().used(), 0);
        }
    }
}

#[test]
fn malformed_parameters_and_key_values_never_become_backend_input() {
    // Missing q, malformed optional evidence and duplicate/trailing values fail.
    let bad = [
        vec![],
        vec![5, 0],
        int(3),
        seq(&[int(23), int(2)]),
        parameters(&[int(2), int(3)]),
        parameters(&[seq(&[tlv(3, &[0, 1])])]),
        parameters(&[seq(&[int(1), int(2)])]),
        parameters(&[seq(&[tlv(3, &[0, 1]), int(2), int(3)])]),
        parameters(&[int(0xff)]),
    ];
    for params in bad {
        let bytes = spki(&params, &int(7));
        let parser = Parser::ber(memory(4096, 10000));
        assert!(
            !dh::read(info(&parser, &bytes), parser.memory())
                .unwrap_err()
                .is_resource()
        );
        assert_eq!(parser.memory().used(), 0);
    }
    for y in [
        vec![5, 0],
        vec![2, 0],
        vec![2, 1, 0xff],
        vec![2, 2, 0, 7],
        vec![2, 0x81, 1, 7],
        vec![2, 1, 7, 5, 0],
    ] {
        let bytes = spki(&parameters(&[]), &y);
        let parser = Parser::ber(memory(4096, 10000));
        assert!(
            !dh::read(info(&parser, &bytes), parser.memory())
                .unwrap_err()
                .is_resource()
        );
    }
}

#[test]
fn classifier_rejects_pkcs3_and_spent_source_or_current_work_is_terminal() {
    // dhKeyAgreement has different parameters; it must never dispatch as X9.42.
    let bytes = spki(&parameters(&[]), &int(7));
    let parser = Parser::der(memory(4096, 10000));
    let key = info(&parser, &bytes);
    assert!(dh::is_algorithm(key.algorithm(), parser.memory()).unwrap());
    let foreign = seq(&[
        seq(&[
            tlv(6, &[42, 134, 72, 134, 247, 13, 1, 3, 1]),
            seq(&[int(23), int(2)]),
        ]),
        tlv(3, &[0, 2, 1, 7]),
    ]);
    let other = info(&parser, &foreign);
    assert!(!dh::is_algorithm(other.algorithm(), parser.memory()).unwrap());
    assert!(dh::read(other, parser.memory()).is_err());
    let full = memory(4096, 10000);
    dh::read(key, &full).unwrap();
    let cost = full.work_used();
    dh::read(key, &memory(4096, cost)).unwrap();
    assert!(
        dh::read(key, &memory(4096, cost - 1))
            .unwrap_err()
            .is_resource()
    );
    assert!(dh::read(key, &memory(0, 10000)).unwrap_err().is_resource());
    // A fresh account cannot replenish the producing parser's local ceiling.
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 10000,
            ..Limits::default()
        },
        memory(4096, 100_000),
    );
    let key = info(&parser, &bytes);
    let execution = key.execution_in(parser.memory());
    while execution.charge_work(1).is_ok() {}
    assert!(
        dh::read(key, &memory(4096, 100_000))
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn current_depth_and_padded_public_bits_cannot_bypass_refusal() {
    // A later operation may tighten depth; non-whole key bits are not truncated.
    let bytes = spki(&parameters(&[]), &int(8));
    let parser = Parser::der(memory(4096, 10000));
    let key = info(&parser, &bytes);
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        memory(4096, 10000),
    );
    let query = operation.read(&[], 0).unwrap();
    assert!(dh::read(key, &query.execution()).unwrap_err().is_resource());
    let mut padded = bytes.clone();
    let index = padded.len() - 4;
    padded[index] = 1;
    assert!(dh::read(info(&parser, &padded), parser.memory()).is_err());
}

#[test]
fn openssl_rfc5114_group3_round_trips_original_spki() {
    // The independently generated X9.42 public key preserves every encoded byte.
    let bytes = include_bytes!("fixtures/dh/public.der");
    let parser = Parser::der(memory(16384, 100_000));
    let info = info(&parser, bytes);
    let key = dh::read(info, parser.memory()).unwrap();
    assert_eq!(key.parameters().p().as_bytes().len(), 256);
    assert_eq!(key.parameters().q().as_bytes().len(), 32);
    assert_eq!(key.parameters().g().as_bytes().len(), 256);
    assert_eq!(
        &key.parameters().p().as_bytes()[..4],
        &[0x87, 0xa8, 0xe6, 0x1d]
    );
    assert_eq!(
        &key.parameters().g().as_bytes()[..4],
        &[0x3f, 0xb3, 0x2c, 0x9b]
    );
    assert_eq!(
        key.parameters().q().as_bytes(),
        &[
            0x8c, 0xf8, 0x36, 0x42, 0xa7, 0x09, 0xa0, 0x97, 0xb4, 0x47, 0x99, 0x76, 0x40, 0x12,
            0x9d, 0xa2, 0x99, 0xb1, 0xa4, 0x7d, 0x1e, 0xb3, 0x75, 0x0b, 0xa3, 0x08, 0xb0, 0xfe,
            0x64, 0xf5, 0xfb, 0xd3,
        ]
    );
    assert!(key.y().as_bytes().len() <= 256);
    let mut roundtrip = Vec::new();
    structured_pkix::key::effective::EffectiveSpki::read(
        structured_pkix::path::EffectiveKey::standing(info),
        parser.memory(),
    )
    .unwrap()
    .visit(parser.memory(), |_, part, _| {
        roundtrip.extend_from_slice(part);
        Ok::<_, core::convert::Infallible>(())
    })
    .unwrap();
    assert_eq!(roundtrip, bytes);
}
