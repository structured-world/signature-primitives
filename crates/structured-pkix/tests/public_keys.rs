//! Public qualification of the structural RSA and EC key readers.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, ErrorCode as Asn1, Limits, Parser};
use structured_pkix::key::{dsa, ec, rsa};
use structured_pkix::path::WorkingKey;
use structured_pkix::{Certificate, ErrorCode, PublicKeyInfo, oid};

const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

fn memory(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 16, work)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    match contents.len() {
        length @ 0..=127 => output.push(u8::try_from(length).unwrap()),
        length @ 128..=255 => output.extend([0x81, u8::try_from(length).unwrap()]),
        length => {
            output.push(0x82);
            output.extend(u16::try_from(length).unwrap().to_be_bytes());
        }
    }
    output.extend_from_slice(contents);
    output
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn bits(unused: u8, octets: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[unused][..], octets].concat())
}

fn spki(algorithm: &[u8], parameters: Option<&[u8]>, key: Vec<u8>) -> Vec<u8> {
    let mut identifier = vec![tlv(0x06, algorithm)];
    identifier.extend(parameters.map(<[u8]>::to_vec));
    seq(&[seq(&identifier), key])
}

fn rsa_key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    seq(&[tlv(0x02, modulus), tlv(0x02, exponent)])
}

fn rsa_spki(key: &[u8]) -> Vec<u8> {
    spki(
        oid::RSA_ENCRYPTION.as_bytes(),
        Some(&[0x05, 0x00]),
        bits(0, key),
    )
}

fn ec_spki(parameters: Option<&[u8]>, point: &[u8]) -> Vec<u8> {
    spki(oid::EC_PUBLIC_KEY.as_bytes(), parameters, bits(0, point))
}

fn named() -> Vec<u8> {
    tlv(0x06, PRIME256V1)
}

fn info<'a>(parser: &'a Parser, der: &'a [u8]) -> PublicKeyInfo<'a> {
    let mut reader = parser.read(der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    PublicKeyInfo::read_element(&reader, &element, "subjectPublicKeyInfo").unwrap()
}

fn position(haystack: &[u8], needle: &[u8]) -> u64 {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap() as u64
}

fn certificate(subject: &str, key: &[u8]) -> Vec<u8> {
    // Trusted fixture writer: the readers below never verify its signature.
    let name = |text: &str| {
        seq(&[tlv(
            0x31,
            &seq(&[
                tlv(0x06, oid::COMMON_NAME.as_bytes()),
                tlv(0x0c, text.as_bytes()),
            ]),
        )])
    };
    let algorithm = seq(&[tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
    let tbs = seq(&[
        tlv(0xa0, &tlv(0x02, &[2])),
        tlv(0x02, &[1]),
        algorithm.clone(),
        name("Root"),
        seq(&[tlv(0x17, b"240101000000Z"), tlv(0x17, b"300101000000Z")]),
        name(subject),
        key.to_vec(),
    ]);
    seq(&[tbs, algorithm, bits(0, &[1])])
}

#[test]
fn rsa_components_borrow_the_original_magnitudes_and_report_exact_bits() {
    // The sign octet is not part of the magnitude, offsets name the first
    // magnitude octet in the whole document, and the modulus bit length is
    // measured rather than rounded to octets (0x01 then 255 octets: 2041).
    let mut modulus = vec![0x01];
    modulus.extend([0xab; 255]);
    let der = rsa_spki(&rsa_key(&modulus, &[0x01, 0x00, 0x01]));
    let parser = Parser::der(memory(100_000));
    let read = rsa::read(info(&parser, &der), parser.memory()).unwrap();
    assert_eq!(read.modulus().as_bytes(), modulus.as_slice());
    assert_eq!(read.modulus().bits(), 2041);
    assert_eq!(read.modulus().offset(), position(&der, &modulus));
    assert_eq!(read.exponent().as_bytes(), [1, 0, 1]);
    assert_eq!(read.exponent().bits(), 17);
    assert_eq!(
        read.modulus().as_bytes().as_ptr(),
        der[usize::try_from(position(&der, &modulus)).unwrap()..].as_ptr()
    );

    // A top bit needs the sign octet, which is stripped but counted in the offset.
    let der = rsa_spki(&rsa_key(&[0x00, 0x80, 0x01], &[0x03]));
    let read = rsa::read(info(&parser, &der), parser.memory()).unwrap();
    assert_eq!(read.modulus().as_bytes(), [0x80, 0x01]);
    assert_eq!(read.modulus().bits(), 16);
    assert_eq!(
        read.modulus().offset(),
        position(&der, &[0x00, 0x80, 0x01]) + 1
    );
}

#[test]
fn rsa_pss_keys_carry_the_same_structure() {
    // RFC 4055 §1.2: id-RSASSA-PSS keys use RSAPublicKey too, with or without
    // their restriction parameters.
    let der = spki(
        oid::RSASSA_PSS.as_bytes(),
        None,
        bits(0, &rsa_key(&[0x7f], &[0x03])),
    );
    let parser = Parser::der(memory(10_000));
    let read = rsa::read(info(&parser, &der), parser.memory()).unwrap();
    assert_eq!(read.modulus().as_bytes(), [0x7f]);
}

#[test]
fn rsa_structural_refusals_are_typed_and_located() {
    // Each malformed shape is refused with its own code at its own place,
    // never accepted as a key and never confused with a resource refusal.
    let parser = Parser::der(memory(100_000));
    let refusal = |der: &[u8]| {
        let parser = Parser::der(memory(100_000));
        let error = rsa::read(info(&parser, der), parser.memory()).unwrap_err();
        assert!(!error.is_resource());
        (error.code(), error.offset())
    };

    let other = ec_spki(Some(&named()), &[0x04, 1, 2]);
    assert_eq!(refusal(&other), (ErrorCode::UnexpectedField, 2));

    let key = rsa_key(&[0x7f], &[0x03]);
    // DER padding bits are zero (X.690 §11.2.1), so the last octet is even.
    let even = rsa_key(&[0x7f], &[0x02]);
    let padded = spki(
        oid::RSA_ENCRYPTION.as_bytes(),
        Some(&[0x05, 0x00]),
        bits(1, &even),
    );
    let at = position(&padded, &even);
    assert_eq!(refusal(&padded), (ErrorCode::MalformedValue, at));

    let not_sequence = rsa_spki(&tlv(0x02, &[0x7f]));
    assert_eq!(
        refusal(&not_sequence),
        (
            ErrorCode::Encoding(Asn1::UnexpectedTag),
            position(&not_sequence, &[0x02, 0x01, 0x7f])
        )
    );

    let after = [key.clone(), vec![0x05, 0x00]].concat();
    let trailing = rsa_spki(&after);
    assert_eq!(refusal(&trailing).0, ErrorCode::TrailingData);

    let third = rsa_spki(&seq(&[
        tlv(0x02, &[0x7f]),
        tlv(0x02, &[0x03]),
        tlv(0x02, &[0x01]),
    ]));
    assert_eq!(refusal(&third).0, ErrorCode::TrailingData);

    let missing = rsa_spki(&seq(&[tlv(0x02, &[0x7f])]));
    assert_eq!(
        refusal(&missing).0,
        ErrorCode::Encoding(Asn1::UnexpectedEnd)
    );

    let negative = rsa_spki(&rsa_key(&[0x80], &[0x03]));
    assert_eq!(
        refusal(&negative),
        (
            ErrorCode::MalformedValue,
            position(&negative, &[0x02, 0x01, 0x80])
        )
    );

    let zero = rsa_spki(&rsa_key(&[0x7f], &[0x00]));
    assert_eq!(
        refusal(&zero),
        (
            ErrorCode::MalformedValue,
            position(&zero, &[0x02, 0x01, 0x00])
        )
    );

    let not_minimal = rsa_spki(&rsa_key(&[0x00, 0x7f], &[0x03]));
    assert_eq!(
        refusal(&not_minimal).0,
        ErrorCode::Encoding(Asn1::IntegerNotMinimal)
    );
    drop(parser);
}

#[test]
fn readers_refuse_unfunded_work_before_reading() {
    // An exhausted current execution refuses at the algorithm comparison,
    // before the key bits are decoded, and reports a resource refusal.
    let rsa_der = rsa_spki(&rsa_key(&[0x7f], &[0x03]));
    let ec_der = ec_spki(Some(&named()), &[0x04, 1, 2]);
    let source = Parser::der(memory(100_000));
    let spent = memory(0);
    let error = rsa::read(info(&source, &rsa_der), &spent).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 2);
    let error = ec::read(WorkingKey::standing(info(&source, &ec_der)), &spent).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 2);
    assert_eq!(spent.work_used(), 0);
}

#[test]
fn readers_charge_the_current_execution_and_the_local_ceiling() {
    // The query reader's own ceiling applies to retained key bits: a funded
    // aggregate account does not bypass a spent local operation.
    let rsa_der = rsa_spki(&rsa_key(&[0x7f], &[0x03]));
    let account = memory(100_000);
    let source = Parser::der(account.clone());
    let key = info(&source, &rsa_der);
    let before = account.work_used();
    rsa::read(key, &account).unwrap();
    assert!(account.work_used() > before);

    let query = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..structured_asn1::Limits::default()
        },
        account.clone(),
    );
    let reader = query.read(&[], 0).unwrap();
    let error = rsa::read(key, &reader.execution()).unwrap_err();
    assert!(error.is_resource());
}

#[test]
fn ec_named_curve_and_point_forms_borrow_the_original_octets() {
    // Uncompressed points split into equal coordinates; compressed points keep
    // the parity octet's meaning; both report their document offset.
    let parser = Parser::der(memory(100_000));
    let uncompressed = [0x04, 1, 2, 3, 4];
    let der = ec_spki(Some(&named()), &uncompressed);
    let read = ec::read(WorkingKey::standing(info(&parser, &der)), parser.memory()).unwrap();
    let ec::Curve::Named(curve) = read.curve() else {
        panic!("named curve expected");
    };
    assert_eq!(curve.as_bytes(), PRIME256V1);
    assert!(!read.is_inherited());
    assert_eq!(read.parameters().span().start, position(&der, &named()));
    let ec::Point::Uncompressed { x, y } = read.point() else {
        panic!("uncompressed point expected");
    };
    assert_eq!((x, y), (&[1, 2][..], &[3, 4][..]));
    assert_eq!(read.point().coordinate_len(), 2);
    assert_eq!(read.as_bytes(), uncompressed);
    assert_eq!(read.offset(), position(&der, &uncompressed));

    let der = ec_spki(Some(&named()), &[0x02, 9, 9, 9]);
    let read = ec::read(WorkingKey::standing(info(&parser, &der)), parser.memory()).unwrap();
    assert!(matches!(
        read.point(),
        ec::Point::Compressed {
            x: [9, 9, 9],
            odd: false
        }
    ));
}

#[test]
fn ec_reports_implicit_and_specified_curves_instead_of_refusing_them() {
    // RFC 5480 §2.1.1 forbids these choices in PKIX; the reader reports which
    // was written so the caller can refuse it as policy, not as malformed DER.
    let parser = Parser::der(memory(100_000));
    let implicit = ec_spki(Some(&[0x05, 0x00]), &[0x04, 1, 2]);
    let read = ec::read(
        WorkingKey::standing(info(&parser, &implicit)),
        parser.memory(),
    )
    .unwrap();
    assert!(matches!(read.curve(), ec::Curve::Implicit));
    assert!(!read.is_inherited());

    let domain = seq(&[tlv(0x02, &[1])]);
    let specified = ec_spki(Some(&domain), &[0x04, 1, 2]);
    let read = ec::read(
        WorkingKey::standing(info(&parser, &specified)),
        parser.memory(),
    )
    .unwrap();
    let ec::Curve::Specified(element) = read.curve() else {
        panic!("specified curve expected");
    };
    assert_eq!(element.as_bytes(), domain.as_slice());
}

#[test]
fn ec_structural_refusals_are_typed_and_located() {
    // Absent parameters, unknown parameter forms, padded bits, the point at
    // infinity, the forbidden hybrid form and uneven coordinates are refused.
    let refusal = |der: &[u8]| {
        let parser = Parser::der(memory(100_000));
        let error =
            ec::read(WorkingKey::standing(info(&parser, der)), parser.memory()).unwrap_err();
        assert!(!error.is_resource());
        (error.code(), error.offset())
    };
    let other = rsa_spki(&rsa_key(&[0x7f], &[0x03]));
    assert_eq!(refusal(&other), (ErrorCode::UnexpectedField, 2));

    let absent = ec_spki(None, &[0x04, 1, 2]);
    assert_eq!(refusal(&absent), (ErrorCode::MissingField, 2));

    let wrong = ec_spki(Some(&tlv(0x02, &[1])), &[0x04, 1, 2]);
    assert_eq!(
        refusal(&wrong),
        (
            ErrorCode::Encoding(Asn1::UnexpectedTag),
            position(&wrong, &[0x02, 0x01, 0x01])
        )
    );

    for point in [
        &[][..],
        &[0x00],
        &[0x04],
        &[0x04, 1, 2, 3],
        &[0x02],
        &[0x06, 1, 2],
        &[0x07, 1, 2],
        &[0x05, 1, 2],
    ] {
        let der = ec_spki(Some(&named()), point);
        let at = position(&der, &[0x03, u8::try_from(point.len() + 1).unwrap(), 0x00]) + 3;
        assert_eq!(refusal(&der), (ErrorCode::MalformedValue, at), "{point:?}");
    }

    let padded = spki(
        oid::EC_PUBLIC_KEY.as_bytes(),
        Some(&named()),
        bits(4, &[0x04, 0x10, 0x20]),
    );
    assert_eq!(
        refusal(&padded),
        (
            ErrorCode::MalformedValue,
            position(&padded, &[0x04, 0x10, 0x20])
        )
    );
}

#[test]
fn ec_inherits_the_authority_curve_from_its_own_certificate() {
    // RFC 5280 §6.1.4(e): a key that writes no parameters stands in its
    // authority's. The curve is decoded where the authority wrote it, in the
    // authority's own parser session and document coordinates.
    let root_der = certificate("Root", &ec_spki(Some(&named()), &[0x04, 1, 2]));
    let leaf_der = certificate("Leaf", &ec_spki(None, &[0x03, 7]));
    let root_parser = Parser::der(memory(100_000));
    let leaf_parser = Parser::der(memory(100_000));
    let root = Certificate::read(&root_parser, &root_der, 0).unwrap();
    let leaf = Certificate::read(&leaf_parser, &leaf_der, 0).unwrap();
    let current = memory(100_000);
    let key = WorkingKey::standing(root.tbs().public_key())
        .subject(&leaf, &current)
        .unwrap();
    let read = ec::read(key, &current).unwrap();
    let ec::Curve::Named(curve) = read.curve() else {
        panic!("inherited named curve expected");
    };
    assert_eq!(curve.as_bytes(), PRIME256V1);
    assert!(read.is_inherited());
    assert_eq!(
        read.parameters().span().start,
        position(&root_der, &named())
    );
    assert_eq!(read.offset(), position(&leaf_der, &[0x03, 7]));
    assert!(matches!(
        read.point(),
        ec::Point::Compressed { x: [7], odd: true }
    ));

    // Without the transition the leaf alone has no curve in force.
    let error = ec::read(WorkingKey::standing(leaf.tbs().public_key()), &current).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MissingField);
}

fn bounded_source() -> Parser {
    Parser::new(
        Encoding::Der,
        Limits {
            max_work: 10_000,
            ..Limits::default()
        },
        memory(1_000_000),
    )
}

fn exhaust_source(source: &Parser) {
    let original = source.execution_in(source.memory());
    original
        .charge_work(original.work_remaining() as u64)
        .unwrap();
}

#[test]
fn unknown_key_identity_requires_original_source_work_before_refusal() {
    // An independently funded current query cannot reset the parsed key's
    // exhausted local budget, even on an unknown-algorithm fast path.
    let source = bounded_source();
    let bytes = spki(&[42, 3], None, bits(0, &[1]));
    let key = info(&source, &bytes);
    exhaust_source(&source);
    let current = memory(100_000);
    for error in [
        rsa::read(key, &current).map(|_| ()).unwrap_err(),
        dsa::read(WorkingKey::standing(key), &current)
            .map(|_| ())
            .unwrap_err(),
        ec::read(WorkingKey::standing(key), &current)
            .map(|_| ())
            .unwrap_err(),
    ] {
        assert!(error.is_resource(), "source exhaustion became {error:?}");
        assert_eq!(error.offset(), key.algorithm().offset());
    }
}

#[test]
fn inherited_ec_cannot_read_a_key_after_its_own_source_work_is_exhausted() {
    // Curve parameters and current funding belong to separate live sources.
    // They must not erase the exhausted leaf's own OID/point source budget.
    let root_der = certificate("Root", &ec_spki(Some(&named()), &[4, 1, 2]));
    let leaf_der = certificate("Leaf", &ec_spki(None, &[3, 7]));
    let root_source = bounded_source();
    let leaf_source = bounded_source();
    let root = Certificate::read(&root_source, &root_der, 400).unwrap();
    let leaf = Certificate::read(&leaf_source, &leaf_der, 9000).unwrap();
    let current = memory(100_000);
    let key = WorkingKey::standing(root.tbs().public_key())
        .subject(&leaf, &current)
        .unwrap();
    exhaust_source(&leaf_source);
    let error = ec::read(key, &current).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), leaf.tbs().public_key().algorithm().offset());
}

#[test]
fn inherited_ec_point_decision_requires_its_last_source_unit() {
    // The leaf pays exactly eight units for its seven-byte OID and one for
    // point framing. Foreign curve work cannot stand in for the ninth unit.
    for point in [&[3, 7][..], &[0][..]] {
        for allowance in [8, 9] {
            let root_der = certificate("Root", &ec_spki(Some(&named()), &[4, 1, 2]));
            let leaf_der = certificate("Leaf", &ec_spki(None, point));
            let root_source = bounded_source();
            let leaf_source = bounded_source();
            let root = Certificate::read(&root_source, &root_der, 400).unwrap();
            let leaf = Certificate::read(&leaf_source, &leaf_der, 9000).unwrap();
            let current = memory(100_000);
            let key = WorkingKey::standing(root.tbs().public_key())
                .subject(&leaf, &current)
                .unwrap();
            let original = leaf_source.execution_in(leaf_source.memory());
            original
                .charge_work((original.work_remaining() - allowance) as u64)
                .unwrap();
            let result = ec::read(key, &current);
            assert_eq!(original.work_remaining(), 0);
            if allowance == 8 {
                let error = result.unwrap_err();
                assert!(error.is_resource());
                assert_eq!(error.offset(), leaf.tbs().public_key().key_offset());
            } else if point == [0] {
                let error = result.unwrap_err();
                assert_eq!(error.code(), ErrorCode::MalformedValue);
                assert_eq!(error.offset(), leaf.tbs().public_key().key_offset());
            } else {
                let read = result.unwrap();
                assert!(read.is_inherited());
                assert_eq!(
                    read.as_bytes().as_ptr(),
                    leaf.tbs().public_key().key_octets().unwrap().as_ptr()
                );
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum KeyReader {
    Rsa,
    Dsa,
    Ec,
}

impl KeyReader {
    fn read<W: Work>(self, key: PublicKeyInfo<'_>, work: &W) -> structured_pkix::Result<()> {
        match self {
            Self::Rsa => rsa::read(key, work).map(|_| ()),
            Self::Dsa => dsa::read(WorkingKey::standing(key), work).map(|_| ()),
            Self::Ec => ec::read(WorkingKey::standing(key), work).map(|_| ()),
        }
    }
    fn mismatch_cost(self) -> usize {
        match self {
            Self::Rsa => 2,
            Self::Dsa | Self::Ec => 1,
        }
    }
}

#[test]
fn identity_negatives_obey_exact_source_current_and_aggregate_bounds() {
    // Unknown two-byte OIDs take one length decision per candidate, no OID
    // scan or allocation. All applicable ceilings must fund those decisions.
    for reader in [KeyReader::Rsa, KeyReader::Dsa, KeyReader::Ec] {
        let cost = reader.mismatch_cost();
        for (source_left, operation_left, aggregate, complete) in [
            (cost, cost, cost, true),
            (cost - 1, cost, cost, false),
            (cost, cost - 1, cost, false),
            (cost, cost, cost - 1, false),
        ] {
            let source = bounded_source();
            let bytes = spki(&[42, 3], None, bits(0, &[1]));
            let key = info(&source, &bytes);
            let original = source.execution_in(source.memory());
            original
                .charge_work((original.work_remaining() - source_left) as u64)
                .unwrap();
            let current = Memory::new(Arc::new(MemoryAccount::new(0, aggregate)));
            let operation = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: u64::try_from(operation_left).unwrap(),
                    ..Limits::default()
                },
                current.clone(),
            );
            let query = operation.read(&[], 9000).unwrap();
            let error = reader.read(key, &query.execution()).unwrap_err();
            assert_eq!(error.offset(), key.algorithm().offset());
            if complete {
                assert_eq!(error.code(), ErrorCode::UnexpectedField);
                assert_eq!(current.work_used(), cost);
                assert_eq!(original.work_remaining(), 0);
            } else {
                assert!(error.is_resource(), "{reader:?}: {error:?}");
            }
            assert_eq!(current.used(), 0);
        }
    }
}

#[test]
fn same_source_metadata_is_charged_once_on_the_last_available_units() {
    // A producing operation must not double-charge its own source ceiling
    // when the deferred reader binds the existing source/current query.
    for reader in [KeyReader::Rsa, KeyReader::Dsa, KeyReader::Ec] {
        let source = bounded_source();
        let bytes = spki(&[42, 3], None, bits(0, &[1]));
        let key = info(&source, &bytes);
        let query = source.read(&[], 9000).unwrap();
        let execution = query.execution();
        let cost = reader.mismatch_cost();
        execution
            .charge_work((execution.work_remaining() - cost) as u64)
            .unwrap();
        let before = source.memory().work_used();
        let error = reader.read(key, &execution).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnexpectedField);
        assert_eq!(execution.work_remaining(), 0);
        assert_eq!(source.memory().work_used(), before + cost);
    }
}

#[test]
fn known_key_metadata_also_refuses_at_its_source_before_structure_decoding() {
    // A valid OID must be paid before its parameters or key bits are opened;
    // nested-reader refusal at a later byte is not pre-admission of that OID.
    for (reader, bytes) in [
        (KeyReader::Rsa, rsa_spki(&rsa_key(&[127], &[3]))),
        (
            KeyReader::Dsa,
            spki(&[42, 134, 72, 206, 56, 4, 1], None, bits(0, &[2, 1, 7])),
        ),
        (KeyReader::Ec, ec_spki(Some(&named()), &[3, 7])),
    ] {
        let source = bounded_source();
        let key = info(&source, &bytes);
        exhaust_source(&source);
        let error = reader.read(key, &memory(100_000)).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), key.algorithm().offset());
    }
}

#[test]
fn inherited_curve_retains_its_own_source_refusal_and_location() {
    // Correctly admitting the leaf must not remove the separate inherited
    // curve source's cumulative ceiling or substitute the leaf's coordinates.
    let root_der = certificate("Root", &ec_spki(Some(&named()), &[4, 1, 2]));
    let leaf_der = certificate("Leaf", &ec_spki(None, &[3, 7]));
    let root_source = bounded_source();
    let leaf_source = bounded_source();
    let root = Certificate::read(&root_source, &root_der, 400).unwrap();
    let leaf = Certificate::read(&leaf_source, &leaf_der, 9000).unwrap();
    let current = memory(100_000);
    let key = WorkingKey::standing(root.tbs().public_key())
        .subject(&leaf, &current)
        .unwrap();
    exhaust_source(&root_source);
    let error = ec::read(key, &current).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), 400 + position(&root_der, &named()));
}

#[test]
fn padded_ec_point_framing_is_admitted_before_returning_malformed() {
    // Even a padded BIT STRING must fund point framing before a completed
    // malformed-key answer. Foreign curve funding cannot hide leaf exhaustion.
    for allowance in [8, 9] {
        let root_der = certificate("Root", &ec_spki(Some(&named()), &[4, 1, 2]));
        let leaf_spki = spki(oid::EC_PUBLIC_KEY.as_bytes(), None, bits(1, &[4, 16, 32]));
        let leaf_der = certificate("Leaf", &leaf_spki);
        let root_source = bounded_source();
        let leaf_source = bounded_source();
        let root = Certificate::read(&root_source, &root_der, 400).unwrap();
        let leaf = Certificate::read(&leaf_source, &leaf_der, 9000).unwrap();
        let current = memory(100_000);
        let key = WorkingKey::standing(root.tbs().public_key())
            .subject(&leaf, &current)
            .unwrap();
        let original = leaf_source.execution_in(leaf_source.memory());
        original
            .charge_work((original.work_remaining() - allowance) as u64)
            .unwrap();
        let error = ec::read(key, &current).unwrap_err();
        assert_eq!(error.offset(), leaf.tbs().public_key().key_offset());
        if allowance == 8 {
            assert!(error.is_resource(), "{error:?}");
        } else {
            assert_eq!(error.code(), ErrorCode::MalformedValue);
        }
        assert_eq!(original.work_remaining(), 0);
    }
}
