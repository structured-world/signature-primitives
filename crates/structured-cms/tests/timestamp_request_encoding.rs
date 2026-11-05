//! New request construction round-trips through the original request parser.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Parser, Tag,
    memory::{Memory, MemoryAccount},
    universal,
};
use structured_cms::timestamp::{NewRequest, Request, RequestEncodingError, RequestExtension};
use structured_pkix::algorithm;

const SHA256: &[u8] = &[48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1];

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)))
}

#[test]
fn all_optional_request_fields_round_trip_without_nonce_narrowing() {
    // High-bit and wide nonces retain their unsigned value and minimal sign
    // padding. False DEFAULT and absent fields remain genuinely omitted.
    let memory = memory();
    let parser = Parser::der(memory.clone());
    let mut source = parser.read(SHA256, 70).unwrap();
    let element = source
        .expect(Tag::constructed(universal::SEQUENCE))
        .unwrap();
    let algorithm = algorithm::read(&source, &element, "hash").unwrap();
    let digest = [42; 32];
    for nonce in [
        None,
        Some(&[][..]),
        Some(&[0, 0, 127][..]),
        Some(&[128][..]),
        Some(&[255; 25][..]),
    ] {
        for cert_req in [false, true] {
            for include in [false, true] {
                let extensions = [RequestExtension {
                    identifier: algorithm.algorithm(),
                    critical: true,
                    value: &[5, 0],
                }];
                let request = NewRequest {
                    algorithm,
                    hashed_message: &digest,
                    policy: include.then_some(algorithm.algorithm()),
                    nonce,
                    cert_req,
                    extensions: if include { &extensions } else { &[] },
                };
                let encoded = request.encode_der(&source).unwrap();
                let mut reader = parser.read(&encoded, 900).unwrap();
                let element = reader.next_element().unwrap().unwrap();
                let request = Request::read(&reader, &element).unwrap();
                assert_eq!(
                    match request.imprint().algorithm() {
                        structured_cms::timestamp::HashAlgorithmReading::Identifier(value) =>
                            value.algorithm(),
                        structured_cms::timestamp::HashAlgorithmReading::Malformed { .. } =>
                            panic!("request algorithm identifier"),
                    },
                    algorithm.algorithm()
                );
                assert_eq!(request.cert_req(), cert_req);
                assert_eq!(request.policy(), include.then_some(algorithm.algorithm()));
                assert_eq!(request.extensions().is_some(), include);
                match nonce {
                    None => assert!(request.nonce().is_none()),
                    Some(bytes) => {
                        let actual = request.nonce().unwrap();
                        assert!(!actual.is_negative());
                        if bytes.len() == 25 {
                            assert_eq!(actual.as_bytes(), [&[0][..], bytes].concat());
                        } else {
                            assert_eq!(
                                actual.as_u64().unwrap(),
                                bytes.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b))
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn duplicate_extensions_foreign_reader_and_source_exhaustion_are_terminal() {
    // Refuse before publishing output, preserving original reader identity
    // even when a different reader has the same aggregate memory account.
    let memory = memory();
    let parser = Parser::der(memory.clone());
    let mut reader = parser.read(SHA256, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let algorithm = algorithm::read(&reader, &element, "hash").unwrap();
    let duplicate = RequestExtension {
        identifier: algorithm.algorithm(),
        critical: false,
        value: &[],
    };
    let mut request = NewRequest {
        algorithm,
        hashed_message: &[0; 32],
        policy: None,
        nonce: None,
        cert_req: false,
        extensions: &[duplicate, duplicate],
    };
    assert!(matches!(
        request.encode_der(&reader),
        Err(RequestEncodingError::Processing(_))
    ));
    assert_eq!(memory.used(), 0);
    request.extensions = &[];
    let other = Parser::der(memory.clone());
    let other_reader = other.read(&[], 0).unwrap();
    assert!(matches!(
        request.encode_der(&other_reader),
        Err(RequestEncodingError::Processing(_))
    ));
    memory.charge_work(memory.work_remaining() as u64).unwrap();
    assert!(matches!(
        request.encode_der(&reader),
        Err(RequestEncodingError::Resource(_))
    ));
    assert_eq!(memory.used(), 0);
}

#[test]
fn ber_outer_headers_are_framed_as_der_but_opaque_non_der_parameters_refuse() {
    // Algorithm outer framing may be canonicalized, but a constructed BER
    // parameter cannot be laundered into a DER request by copying its bytes.
    let parser = Parser::new(Encoding::Ber, structured_asn1::Limits::default(), memory());
    let bytes = [&[48, 128][..], &SHA256[2..], &[0, 0]].concat();
    let mut reader = parser.read(&bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let identifier = algorithm::read(&reader, &element, "hash").unwrap();
    let request = NewRequest {
        algorithm: identifier,
        hashed_message: &[0; 32],
        policy: None,
        nonce: None,
        cert_req: false,
        extensions: &[],
    };
    let encoded = request.encode_der(&reader).unwrap();
    assert!(encoded.windows(SHA256.len()).any(|window| window == SHA256));
    let bytes = [&[48, 128][..], &SHA256[2..], &[4, 129, 1, 42, 0, 0]].concat();
    let mut reader = parser.read(&bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let identifier = algorithm::read(&reader, &element, "hash").unwrap();
    let request = NewRequest {
        algorithm: identifier,
        ..request
    };
    assert!(request.encode_der(&reader).is_err());
}
