//! Public DSTU profile, framing and producing-budget qualification.

use std::sync::Arc;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::algorithm::dstu4145::{self, Basis, ByteOrder, Curve, Reduction};
use structured_pkix::algorithm::{self, AlgorithmIdentifier, digest, signature};
use structured_pkix::key;
use structured_pkix::signature::SignatureValue;
use structured_pkix::{Certificate, ErrorCode, PublicKeyInfo};

fn memory(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(100_000, work)))
}
fn source() -> Parser {
    Parser::der(memory(2_000_000))
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(u8::try_from(body.len()).unwrap());
    } else {
        out.extend([0x82]);
        out.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    }
    out.extend(body);
    out
}
fn oid(hash: usize, basis: u8, order: ByteOrder) -> Vec<u8> {
    let mut out = vec![0x2a, 0x86, 0x24, 2, 1, 1, 1, 1, 3];
    if hash == 0 {
        out.push(1);
    } else {
        out.extend([6, u8::try_from(hash).unwrap()]);
    }
    out.push(basis);
    if order == ByteOrder::BigEndian {
        out.extend([1, 1]);
    }
    out
}
fn algorithm_bytes(oid: &[u8], params: Option<&[u8]>) -> Vec<u8> {
    let mut body = tlv(6, oid);
    body.extend(params.unwrap_or(&[]));
    tlv(48, &body)
}
fn id<'a>(source: &'a Parser, bytes: &'a [u8]) -> AlgorithmIdentifier<'a> {
    let mut reader = source.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    algorithm::read(&reader, &element, "algorithm").unwrap()
}
fn named(hash: usize, basis: u8, index: u8) -> Vec<u8> {
    let mut bytes = oid(hash, basis, ByteOrder::LittleEndian);
    bytes.extend([2, index]);
    tlv(48, &tlv(6, &bytes))
}
fn explicit_fields(reduction: Option<&[u8]>) -> Vec<Vec<u8>> {
    let mut field = tlv(2, &[0, 0xa3]); // m=163, positive DER INTEGER.
    field.extend(reduction.unwrap_or(&[]));
    let mut point = vec![0x42; 21];
    point[20] = 1;
    vec![
        tlv(48, &field),
        tlv(2, &[1]),
        tlv(4, &point),
        tlv(2, &[0x7f]),
        tlv(4, &point),
    ]
}
fn explicit(reduction: Option<&[u8]>) -> Vec<u8> {
    tlv(48, &tlv(48, &explicit_fields(reduction).concat()))
}
fn key_bytes(oid: &[u8], params: Option<&[u8]>, point: &[u8]) -> Vec<u8> {
    tlv(
        48,
        &[
            algorithm_bytes(oid, params),
            tlv(3, &[vec![0], tlv(4, point)].concat()),
        ]
        .concat(),
    )
}
fn spki<'a>(parser: &'a Parser, bytes: &'a [u8]) -> PublicKeyInfo<'a> {
    let mut reader = parser.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    PublicKeyInfo::read_element(&reader, &element, "spki").unwrap()
}
fn carried<'a>(parser: &'a Parser, bytes: &'a [u8]) -> SignatureValue<'a> {
    SignatureValue::read(&mut parser.read(bytes, 800).unwrap(), "signature").unwrap()
}
fn leave(parser: &Parser, units: usize) {
    let old = parser.execution_in(parser.memory());
    old.charge_work((old.work_remaining() - units) as u64)
        .unwrap();
}

#[test]
fn exact_profiles_are_shared_by_strict_and_inspection() {
    // Basis, digest and byte order are independent axes; ONB is not BE.
    for (hash, expected) in [
        digest::Algorithm::Gost34311,
        digest::Algorithm::Kupyna256,
        digest::Algorithm::Kupyna384,
        digest::Algorithm::Kupyna512,
    ]
    .into_iter()
    .enumerate()
    {
        for (basis, expected_basis) in [(1, Basis::Polynomial), (2, Basis::OptimalNormal)] {
            for order in [ByteOrder::LittleEndian, ByteOrder::BigEndian] {
                let source = source();
                let bytes = algorithm_bytes(&oid(hash, basis, order), None);
                let id = id(&source, &bytes);
                let profile = dstu4145::identify(id, source.memory()).unwrap().unwrap();
                assert_eq!(
                    (profile.digest(), profile.basis(), profile.byte_order()),
                    (expected, expected_basis, order)
                );
                signature::with_algorithm(id, source.memory(), |value| {
                    assert!(matches!(value,Some(signature::Algorithm::Dstu4145(p)) if p == profile))
                })
                .unwrap();
                signature::with_inspection(id, source.memory(), |reading| {
                    assert_eq!(reading.scheme(), Some(signature::Scheme::Dstu4145(profile)));
                    assert!(reading.faults().is_empty());
                })
                .unwrap();
            }
        }
    }
}

#[test]
fn unknown_branches_and_parameters_do_not_acquire_acceptance() {
    // Prefix lookalikes and curve OIDs are not signature algorithm aliases.
    let source = source();
    for suffix in [vec![1], vec![2, 0], vec![1, 1, 0], vec![9]] {
        let mut written = oid(0, 1, ByteOrder::LittleEndian);
        written.extend(suffix);
        let bytes = algorithm_bytes(&written, None);
        let id = id(&source, &bytes);
        assert!(dstu4145::identify(id, source.memory()).unwrap().is_none());
        signature::with_algorithm(id, source.memory(), |value| assert!(value.is_none())).unwrap();
    }
    let bytes = algorithm_bytes(&oid(2, 1, ByteOrder::LittleEndian), Some(&[5, 0]));
    let id = id(&source, &bytes);
    assert_eq!(
        signature::with_algorithm(id, source.memory(), |_| ())
            .unwrap_err()
            .code(),
        ErrorCode::MalformedValue
    );
    signature::with_inspection(id, source.memory(), |reading| {
        assert!(reading.scheme().is_some());
        assert_eq!(reading.faults().len(), 1);
        assert_eq!(
            reading.faults()[0].offset(),
            id.parameters_span().unwrap().start
        );
    })
    .unwrap();
}

#[test]
fn digest_identities_require_absence_and_keep_fixed_widths() {
    // UA CMS §§1.10–11: neither digest parameters nor a nonzero default IV
    // are inferred. Providers must bind the operation's required GOST DKE.
    let source = source();
    for hash in [
        digest::Algorithm::Gost34311,
        digest::Algorithm::Kupyna256,
        digest::Algorithm::Kupyna384,
        digest::Algorithm::Kupyna512,
    ] {
        for params in [None, Some(&[5, 0][..])] {
            let bytes = algorithm_bytes(hash.identifier().as_bytes(), params);
            let id = id(&source, &bytes);
            let expected = if params.is_none() {
                Resolution::Supported(hash)
            } else {
                Resolution::Malformed
            };
            assert_eq!(digest::algorithm(&id, source.memory()).unwrap(), expected);
        }
    }
    assert_eq!(digest::Algorithm::Gost34311.width(), 32);
    assert_eq!(digest::Algorithm::Kupyna384.width(), 48);
    assert_eq!(digest::Algorithm::Kupyna512.width(), 64);
}

#[test]
fn named_curves_and_unsupported_names_retain_original_identity() {
    // Every assigned curve arc is distinct; an unknown arc has no guessed m.
    let source = source();
    for hash in 0..4 {
        for (basis, degrees) in [
            (1, &[163, 167, 173, 179, 191, 233, 257, 307, 367, 431][..]),
            (2, &[173, 179, 191, 233, 431][..]),
        ] {
            for (index, degree) in degrees.iter().enumerate() {
                let params = named(hash, basis, u8::try_from(index).unwrap());
                let bytes =
                    algorithm_bytes(&oid(hash, basis, ByteOrder::LittleEndian), Some(&params));
                let value = dstu4145::read_parameters(id(&source, &bytes), source.memory())
                    .unwrap()
                    .unwrap();
                assert_eq!(value.curve().degree(), Some(*degree));
                assert!(value.dke().is_none());
                assert_eq!(value.element().as_bytes(), params);
            }
        }
    }
    let params = named(0, 1, 10);
    let bytes = algorithm_bytes(&oid(0, 1, ByteOrder::LittleEndian), Some(&params));
    let value = dstu4145::read_parameters(id(&source, &bytes), source.memory())
        .unwrap()
        .unwrap();
    let Curve::Named(name) = value.curve() else {
        panic!("named")
    };
    assert!(name.known().is_none());
    assert_eq!(name.identifier().as_bytes().last(), Some(&10));
}

#[test]
fn explicit_polynomial_and_normal_fields_preserve_components() {
    // Structural inspection never performs irreducibility/point/order math.
    let source = source();
    for (basis, reduction, expected) in [
        (1, Some(tlv(2, &[7])), Reduction::Trinomial(7)),
        (
            1,
            Some(tlv(
                48,
                &[tlv(2, &[1]), tlv(2, &[2]), tlv(2, &[8])].concat(),
            )),
            Reduction::Pentanomial { k: 1, j: 2, l: 8 },
        ),
        (2, None, Reduction::OptimalNormal),
    ] {
        let params = explicit(reduction.as_deref());
        let bytes = algorithm_bytes(&oid(0, basis, ByteOrder::LittleEndian), Some(&params));
        let value = dstu4145::read_parameters(id(&source, &bytes), source.memory())
            .unwrap()
            .unwrap();
        let Curve::Explicit(curve) = value.curve() else {
            panic!("explicit")
        };
        assert_eq!(curve.degree_value(), 163);
        assert_eq!(curve.degree().value().as_u32(), Some(163));
        assert_eq!(curve.reduction(), expected);
        assert_eq!(curve.order().value().as_u64(), Some(127));
        assert_eq!(curve.a().value().as_u64(), Some(1));
        assert_eq!(curve.b().as_bytes().len(), 21);
        assert_eq!(curve.base_point().big_endian().next(), Some(1));
        assert!(curve.field().span().start > value.element().span().start);
    }
}

#[test]
fn packed_dke_is_exactly_64_octets_and_not_inherited() {
    // Optional DKE absence is preserved; present data is not replaced by default.
    let source = source();
    for length in [0, 63, 64, 65] {
        let mut curve_oid = oid(0, 1, ByteOrder::LittleEndian);
        curve_oid.extend([2, 6]);
        let params = tlv(
            48,
            &[tlv(6, &curve_oid), tlv(4, &vec![0xa9; length])].concat(),
        );
        let bytes = algorithm_bytes(&oid(0, 1, ByteOrder::LittleEndian), Some(&params));
        let result = dstu4145::read_parameters(id(&source, &bytes), source.memory());
        if length == 64 {
            assert_eq!(
                result.unwrap().unwrap().dke().unwrap().contents(),
                [0xa9; 64]
            );
        } else {
            assert_eq!(result.unwrap_err().code(), ErrorCode::MalformedValue);
        }
    }
}

#[test]
fn malformed_parameters_keep_their_located_cause() {
    // Reject ambiguous grammar, bad signs, DEFAULT spelling and extra fields.
    let source = source();
    let reduction = tlv(2, &[7]);
    let valid = explicit_fields(Some(&reduction));
    let mut cases = Vec::new();
    for index in [0, 1, 2, 3, 4] {
        let mut fields = valid.clone();
        fields[index] = vec![5, 0];
        cases.push((tlv(48, &tlv(48, &fields.concat())), None));
    }
    for (version, expected) in [
        (0, ErrorCode::DefaultWritten),
        (1, ErrorCode::UnsupportedVersion),
    ] {
        let fields = [vec![tlv(0xa0, &tlv(2, &[version]))], valid.clone()].concat();
        cases.push((tlv(48, &tlv(48, &fields.concat())), Some(expected)));
    }
    let mut fields = valid.clone();
    fields[3] = tlv(2, &[0xff]);
    cases.push((
        tlv(48, &tlv(48, &fields.concat())),
        Some(ErrorCode::MalformedValue),
    ));
    let mut fields = valid.clone();
    fields[3] = tlv(2, &[0]);
    cases.push((
        tlv(48, &tlv(48, &fields.concat())),
        Some(ErrorCode::MalformedValue),
    ));
    let mut fields = valid.clone();
    fields.push(vec![5, 0]);
    cases.push((
        tlv(48, &tlv(48, &fields.concat())),
        Some(ErrorCode::TrailingData),
    ));
    cases.push((tlv(48, &[]), Some(ErrorCode::MissingField)));
    for (params, expected) in cases {
        let bytes = algorithm_bytes(&oid(0, 1, ByteOrder::LittleEndian), Some(&params));
        let error = dstu4145::read_parameters(id(&source, &bytes), source.memory()).unwrap_err();
        assert!(!error.is_resource());
        assert!(error.offset() >= 400);
        if let Some(expected) = expected {
            assert_eq!(error.code(), expected);
        }
    }
}

#[test]
fn key_octets_keep_source_endianness_and_width() {
    // Key and parameter field octets reverse as views, with no copied payload.
    let source = source();
    for order in [ByteOrder::LittleEndian, ByteOrder::BigEndian] {
        let params = named(0, 1, 6); // m=257.
        let mut point = vec![0x42; 33];
        let top = if order == ByteOrder::LittleEndian {
            32
        } else {
            0
        };
        point[top] = 1;
        let bytes = key_bytes(&oid(0, 1, order), Some(&params), &point);
        let value = key::dstu4145::read(spki(&source, &bytes), source.memory()).unwrap();
        assert_eq!(value.degree(), Some(257));
        assert_eq!(value.point().byte_order(), order);
        assert_eq!(value.point().big_endian().next(), Some(1));
        assert_eq!(value.point().as_bytes(), point);
        let offset = usize::try_from(value.point().offset() - 400).unwrap();
        assert_eq!(value.point().as_bytes().as_ptr(), bytes[offset..].as_ptr());
        let wrong = key_bytes(&oid(0, 1, order), Some(&params), &point[..32]);
        assert_eq!(
            key::dstu4145::read(spki(&source, &wrong), source.memory())
                .unwrap_err()
                .code(),
            ErrorCode::MalformedValue
        );
        point[top] = 2; // one unused field bit set.
        let wrong = key_bytes(&oid(0, 1, order), Some(&params), &point);
        assert_eq!(
            key::dstu4145::read(spki(&source, &wrong), source.memory())
                .unwrap_err()
                .code(),
            ErrorCode::MalformedValue
        );
    }
}

#[test]
fn missing_key_parameters_stay_missing_and_null_is_not_inheritance() {
    // An unavailable curve is not reconstructed from the compressed width.
    let source = source();
    let oid = oid(0, 1, ByteOrder::LittleEndian);
    let bytes = key_bytes(&oid, None, &[1, 2, 3]);
    let key = key::dstu4145::read(spki(&source, &bytes), source.memory()).unwrap();
    assert!(key.parameters().is_none());
    assert!(key.degree().is_none());
    let bytes = key_bytes(&oid, Some(&[5, 0]), &[1, 2, 3]);
    assert!(key::dstu4145::read(spki(&source, &bytes), source.memory()).is_err());
}

#[test]
fn signature_order_is_of_the_whole_bit_string_and_width_uses_n() {
    // DSTU §5.10 S||R reverses as a whole, not as two independent halves.
    // m=257 with L(n)=256 has 32-octet scalars, not 33-octet field elements.
    let source = source();
    for order in [ByteOrder::LittleEndian, ByteOrder::BigEndian] {
        let mut r = [0; 32];
        r[0] = 0x12;
        r[31] = 0x34;
        let mut s = [0; 32];
        s[0] = 0x56;
        s[31] = 0x78;
        let payload = match order {
            ByteOrder::LittleEndian => [
                r.into_iter().rev().collect::<Vec<_>>(),
                s.into_iter().rev().collect(),
            ]
            .concat(),
            ByteOrder::BigEndian => [s.to_vec(), r.to_vec()].concat(),
        };
        let bytes = tlv(3, &[vec![0], tlv(4, &payload)].concat());
        let value = carried(&source, &bytes)
            .dstu4145_in(source.memory(), order, 256)
            .unwrap();
        assert_eq!(value.r().big_endian().collect::<Vec<_>>(), r);
        assert_eq!(value.s().big_endian().collect::<Vec<_>>(), s);
        assert_eq!(value.element().contents(), payload);
        assert!(
            carried(&source, &bytes)
                .dstu4145_in(source.memory(), order, 257)
                .is_err()
        );
    }
}

#[test]
fn signatures_require_der_wrapper_unpadded_carriage_and_no_tail() {
    // BER outside a signature does not permit BER-only inner framing.
    for parser in [source(), Parser::ber(memory(2_000_000))] {
        for inner in [
            tlv(4, &[0; 42]),
            [vec![4, 0x81, 42], vec![0; 42]].concat(),
            [tlv(4, &[0; 42]), vec![5, 0]].concat(),
            tlv(0x24, &tlv(4, &[0; 42])),
            tlv(4, &[0; 40]),
        ] {
            let bytes = tlv(3, &[vec![0], inner.clone()].concat());
            let result =
                carried(&parser, &bytes).dstu4145_in(parser.memory(), ByteOrder::LittleEndian, 163);
            if inner == tlv(4, &[0; 42]) {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        }
        let bytes = tlv(3, &[vec![1], tlv(4, &[0; 42])].concat());
        assert!(
            carried(&parser, &bytes)
                .dstu4145_in(parser.memory(), ByteOrder::LittleEndian, 163)
                .is_err()
        );
    }
}

#[test]
fn original_and_current_resource_refusals_precede_decoding() {
    // Wider current accounts cannot reset the original cumulative ceiling.
    let source = source();
    let bytes = key_bytes(
        &oid(0, 1, ByteOrder::LittleEndian),
        Some(&named(0, 1, 6)),
        &[0; 33],
    );
    let info = spki(&source, &bytes);
    let zero = memory(0);
    assert!(key::dstu4145::read(info, &zero).unwrap_err().is_resource());
    leave(&source, 0);
    assert!(
        key::dstu4145::read(info, &memory(100_000))
            .unwrap_err()
            .is_resource()
    );

    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 1,
            ..Limits::default()
        },
        memory(100_000),
    );
    let bytes = tlv(3, &[vec![0], tlv(4, &[0; 42])].concat());
    let signature = carried(&source, &bytes);
    let zero = memory(0);
    assert!(
        signature
            .dstu4145_in(&zero, ByteOrder::LittleEndian, 163)
            .unwrap_err()
            .is_resource()
    );
    leave(&source, 0);
    assert!(
        signature
            .dstu4145_in(&memory(100_000), ByteOrder::LittleEndian, 163)
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn public_certificates_exercise_real_little_and_big_endian_keys() {
    // Unmodified independently published CZO certificates, not math/trust oracles.
    for (bytes, order, hash, order_bits) in [
        (
            &include_bytes!("data/dstu4145/kupyna-le.der")[..],
            ByteOrder::LittleEndian,
            digest::Algorithm::Kupyna256,
            430,
        ),
        (
            &include_bytes!("data/dstu4145/gost-le.der")[..],
            ByteOrder::LittleEndian,
            digest::Algorithm::Gost34311,
            430,
        ),
        (
            &include_bytes!("data/dstu4145/gost-be.der")[..],
            ByteOrder::BigEndian,
            digest::Algorithm::Gost34311,
            256,
        ),
    ] {
        let source = source();
        let cert = Certificate::read(&source, bytes, 1200).unwrap();
        let key = key::dstu4145::read(cert.tbs().public_key(), source.memory()).unwrap();
        assert_eq!(key.profile().byte_order(), order);
        assert_eq!(key.degree(), Some(257));
        assert_eq!(key.profile().digest(), digest::Algorithm::Gost34311);
        signature::with_algorithm(cert.signature_algorithm(), source.memory(), |algorithm| {
            let Some(signature::Algorithm::Dstu4145(profile)) = algorithm else {
                panic!("DSTU")
            };
            assert_eq!(profile.digest(), hash);
            let value = cert
                .signature_value()
                .dstu4145_in(source.memory(), profile.byte_order(), order_bits)
                .unwrap();
            assert_eq!(
                value.r().as_bytes().len(),
                usize::try_from(order_bits.div_ceil(8)).unwrap()
            );
        })
        .unwrap();
    }
}
