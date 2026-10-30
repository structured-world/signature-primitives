use super::{compressed, encoded, polynomial};
use crate::{
    ByteOrder,
    accounted::{DkeBinding, Failure, Hashes, Identity, Key},
    curve::Point,
    domains,
    gost::{DEFAULT_DKE, Dke},
};
use std::{sync::Arc, vec::Vec};
use structured_asn1::{
    Encoding, Limits, Parser,
    digest::{Digest, Resolution},
    memory::{Memory, MemoryAccount, MemoryError, Work},
};
use structured_pkix::{PublicKeyInfo, algorithm::dstu4145};

pub(super) const SIGNATURE_OID: &[u8] = &[0x2a, 0x86, 0x24, 2, 1, 1, 1, 1, 3, 1, 1];
pub(super) fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000_000)))
}
pub(super) fn parser(memory: Memory) -> Parser {
    Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1_000_000_000,
            ..Limits::default()
        },
        memory,
    )
}
pub(super) fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = std::vec![tag];
    if body.len() < 128 {
        bytes.push(u8::try_from(body.len()).unwrap());
    } else if body.len() < 256 {
        bytes.extend([0x81, u8::try_from(body.len()).unwrap()]);
    } else {
        bytes.push(0x82);
        bytes.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    }
    bytes.extend(body);
    bytes
}
pub(super) fn fixture(dke: &[u8; 64]) -> Vec<u8> {
    let mut curve = SIGNATURE_OID.to_vec();
    curve.extend([2, 0]);
    let mut params = tlv(6, &curve);
    params.extend(tlv(4, dke));
    let mut algorithm = tlv(6, SIGNATURE_OID);
    algorithm.extend(tlv(48, &params));
    let mut body = tlv(48, &algorithm);
    let spec = &domains::PB[0];
    let field = polynomial(spec);
    let public = encoded(
        compressed(
            &field,
            Point {
                x: spec.x,
                y: spec.y,
            },
        ),
        21,
        ByteOrder::LittleEndian,
    );
    let mut bits = std::vec![0];
    bits.extend(tlv(4, &public));
    body.extend(tlv(3, &bits));
    tlv(48, &body)
}
pub(super) fn read<'a>(parser: &'a Parser, bytes: &'a [u8], at: u64) -> PublicKeyInfo<'a> {
    let mut reader = parser.read(bytes, at).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    PublicKeyInfo::read_element(&reader, &element, "key").unwrap()
}
fn leave(parser: &Parser, remaining: usize) {
    let scope = parser.execution_in(parser.memory());
    scope
        .charge_work(u64::try_from(scope.work_remaining() - remaining).unwrap())
        .unwrap();
}

/// Rebinding a DKE source must not discard the current foreign-source limit.
/// Each independent parser can refuse before table preparation is admitted.
#[test]
fn preparing_dke_preserves_every_current_ceiling() {
    for exhausted in 0..3 {
        let source = parser(memory());
        let previous = parser(memory());
        let root = parser(memory());
        let raw = fixture(&DEFAULT_DKE);
        let info = read(&source, &raw, 1200);
        let parsed = structured_pkix::key::dstu4145::read(info, source.memory()).unwrap();
        let parameters = parsed.parameters().unwrap();
        leave([&source, &previous, &root][exhausted], 0);
        let account = memory();
        let operation = root.execution_in(&account);
        let current = operation.execution_for(&previous);
        assert!(matches!(
            crate::accounted::prepare_dke(parameters, &current),
            Err(Failure::Resource {
                reason: MemoryError::WorkExceeded,
                at: _
            })
        ));
        assert_eq!(account.work_used(), 0);
    }
}

/// Equal table bytes do not authorize binding after a current source is spent.
#[test]
fn binding_dke_preserves_existing_current_source() {
    let source = parser(memory());
    let previous = parser(memory());
    let root = parser(memory());
    let raw = fixture(&DEFAULT_DKE);
    let info = read(&source, &raw, 1200);
    let parsed = structured_pkix::key::dstu4145::read(info, source.memory()).unwrap();
    let dke = Dke::new(&DEFAULT_DKE).unwrap();
    leave(&previous, 0);
    let account = memory();
    let operation = root.execution_in(&account);
    let current = operation.execution_for(&previous);
    assert!(matches!(
        DkeBinding::new(parsed.parameters().unwrap(), &dke, &current),
        Err(Failure::Resource {
            reason: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert_eq!(account.work_used(), 0);
}

/// A single metadata unit must not authorize the complete curve operation
/// after preparation rebinds from a foreign current source to the key source.
#[test]
fn preparing_key_preserves_existing_current_source() {
    let source = parser(memory());
    let previous = parser(memory());
    let root = parser(memory());
    let raw = fixture(&DEFAULT_DKE);
    let info = read(&source, &raw, 1200);
    let dke = Dke::new(&DEFAULT_DKE).unwrap();
    leave(&previous, 1);
    let account = memory();
    let operation = root.execution_in(&account);
    let current = operation.execution_for(&previous);
    assert!(matches!(
        Key::prepare(info, &dke, &current),
        Err(Failure::Resource {
            reason: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert!(account.work_used() < 1000);
}

/// Bound DKE values carry the actual parameter source through deferred hashing.
/// A broad fresh operation cannot bypass a spent producing parser.
#[test]
fn hashing_preserves_original_parameter_ceiling() {
    let source = parser(memory());
    let bytes = fixture(&DEFAULT_DKE);
    let info = read(&source, &bytes, 1200);
    let parsed = structured_pkix::key::dstu4145::read(info, source.memory()).unwrap();
    let dke = Dke::new(&DEFAULT_DKE).unwrap();
    let binding = DkeBinding::new(parsed.parameters().unwrap(), &dke, source.memory()).unwrap();
    let identity = Identity::gost(binding);
    let Resolution::Supported(mut state) = Hashes.start(&identity, source.memory()).unwrap() else {
        panic!("hash")
    };
    leave(&source, 0);
    let current = memory();
    assert!(matches!(
        Hashes.start(&identity, &current),
        Err(Failure::Resource {
            reason: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert!(matches!(
        Hashes.update(&mut state, b"message", &current),
        Err(Failure::Resource {
            reason: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert!(matches!(
        Hashes.finish(state, &current),
        Err(Failure::Resource {
            reason: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert_eq!(current.work_used(), 0);
}

/// Identity comparison admits both source ceilings with one current account
/// bill. Equal DKEs at different addresses deduplicate semantically.
#[test]
fn dke_comparison_has_joint_admission_without_double_billing() {
    let a = parser(memory());
    let b = parser(memory());
    let raw = fixture(&DEFAULT_DKE);
    let left = read(&a, &raw, 1200);
    let right = read(&b, &raw, 2400);
    let da = Dke::new(&DEFAULT_DKE).unwrap();
    let db = Dke::new(&DEFAULT_DKE).unwrap();
    let pa = dstu4145::read_parameters(left.algorithm(), a.memory())
        .unwrap()
        .unwrap();
    let pb = dstu4145::read_parameters(right.algorithm(), b.memory())
        .unwrap()
        .unwrap();
    let ia = Identity::gost(DkeBinding::new(pa, &da, a.memory()).unwrap());
    let ib = Identity::gost(DkeBinding::new(pb, &db, b.memory()).unwrap());
    let current = memory();
    assert_eq!(
        Hashes.compare(&ia, &ib, &current).unwrap(),
        core::cmp::Ordering::Equal
    );
    assert_eq!(current.work_used(), 65);
    leave(&b, 64);
    assert!(matches!(
        Hashes.compare(&ia, &ib, &current),
        Err(Failure::Resource { .. })
    ));
    assert_eq!(current.work_used(), 65);
}

/// Prepared numerical keys do not discard their original source limit.
/// Bad DKE association also refuses before any digest state can be started.
#[test]
fn prepared_keys_keep_source_and_effective_dke() {
    let source = parser(memory());
    let raw = fixture(&DEFAULT_DKE);
    let info = read(&source, &raw, 1200);
    let dke = Dke::new(&DEFAULT_DKE).unwrap();
    let key = Key::prepare(info, &dke, source.memory()).unwrap();
    let profile = dstu4145::identify(info.algorithm(), source.memory())
        .unwrap()
        .unwrap();
    let identity = key.digest_identity(profile, source.memory()).unwrap();
    let mut wrong = DEFAULT_DKE;
    wrong.swap(0, 1);
    let wrong = Dke::new(&wrong).unwrap();
    assert!(matches!(
        Key::prepare(info, &wrong, source.memory()),
        Err(Failure::Backend {
            reason: crate::Error::InvalidDke,
            ..
        })
    ));
    leave(&source, 0);
    let current = memory();
    assert!(matches!(
        key.verify_prehash(profile, identity, &[0; 32], &[0; 42], &current),
        Err(Failure::Resource { .. })
    ));
    assert_eq!(current.work_used(), 0);
}

/// Enough source work for OCTET framing does not authorize the expensive math.
/// A foreign signature and key preserve both ceilings and the current query.
#[test]
fn signature_origin_admits_complete_arithmetic_before_execution() {
    let source = parser(memory());
    let raw = fixture(&DEFAULT_DKE);
    let info = read(&source, &raw, 1200);
    let dke = Dke::new(&DEFAULT_DKE).unwrap();
    let key = Key::prepare(info, &dke, source.memory()).unwrap();
    let profile = dstu4145::identify(info.algorithm(), source.memory())
        .unwrap()
        .unwrap();
    let identity = key.digest_identity(profile, source.memory()).unwrap();
    let signature_source = parser(memory());
    let mut value = std::vec![0];
    value.extend(tlv(4, &[0; 42]));
    let raw = tlv(3, &value);
    let signature = structured_pkix::signature::SignatureValue::read(
        &mut signature_source.read(&raw, 9000).unwrap(),
        "signature",
    )
    .unwrap();
    leave(&signature_source, 1000);
    let current = memory();
    assert!(matches!(
        key.verify_signature_value(profile, identity, &[0; 32], signature, &current),
        Err(Failure::Resource {
            reason: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert!(current.work_used() < 1000);
}

/// Semantic reuse keeps the first actual hash producer. An exhausted first
/// origin cannot be replaced by a broader duplicate merely because its DKE
/// compares equal, and no second hash state/source pass is introduced.
#[test]
fn deduplicated_hash_preserves_first_actual_parameter_source() {
    let a = parser(memory());
    let b = parser(memory());
    let raw = fixture(&DEFAULT_DKE);
    let left = read(&a, &raw, 1200);
    let right = read(&b, &raw, 2400);
    let da = Dke::new(&DEFAULT_DKE).unwrap();
    let db = Dke::new(&DEFAULT_DKE).unwrap();
    let ka = structured_pkix::key::dstu4145::read(left, a.memory()).unwrap();
    let kb = structured_pkix::key::dstu4145::read(right, b.memory()).unwrap();
    let pa = ka.parameters().unwrap();
    let pb = kb.parameters().unwrap();
    let ia = Identity::gost(DkeBinding::new(pa, &da, a.memory()).unwrap());
    let ib = Identity::gost(DkeBinding::new(pb, &db, b.memory()).unwrap());
    let current = memory();
    let mut ids = current.vector();
    ids.try_push(ia).unwrap();
    ids.try_push(ib).unwrap();
    let provider = structured_cms::provider::ProviderSession::new(Hashes);
    let batch = structured_cms::digest::DigestBatch::prepare(
        &provider,
        ids.into_owned(),
        &current,
        "content",
        400,
    )
    .unwrap();
    assert_eq!(batch.len(), 1);
    leave(&a, 0);
    let result = batch.run(&mut [&b"content"[..]], &current);
    assert!(matches!(
        result,
        Err(structured_cms::stream::StreamError::Callback(
            structured_cms::digest::DigestError::Callback(Failure::Resource {
                reason: MemoryError::WorkExceeded,
                ..
            })
        ))
    ));
}
