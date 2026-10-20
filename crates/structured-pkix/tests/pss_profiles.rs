//! PSS interpretation and key constraints preserve independent source budgets.

use std::sync::Arc;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::algorithm::pss::profile::{self, Profile};
use structured_pkix::algorithm::{
    self, AlgorithmIdentifier, digest::Algorithm as Hash, pss, signature,
};
use structured_pkix::{ErrorCode, oid};

const SHA1: &[u8] = &[43, 14, 3, 2, 26];
const SHA256: &[u8] = &[96, 134, 72, 1, 101, 3, 4, 2, 1];
const MGF1: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 1, 8];

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}
fn parser() -> Parser {
    Parser::ber(memory(100_000, 10_000_000))
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if body.len() < 128 {
        bytes.push(u8::try_from(body.len()).unwrap());
    } else {
        bytes.push(0x82);
        bytes.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    }
    bytes.extend(body);
    bytes
}
fn alg(oid: &[u8], parameter: Option<&[u8]>) -> Vec<u8> {
    let mut body = tlv(6, oid);
    if let Some(parameter) = parameter {
        body.extend(parameter);
    }
    tlv(48, &body)
}
fn pss_bytes(
    hash: Option<&[u8]>,
    mask: Option<&[u8]>,
    salt: Option<&[u8]>,
    trailer: Option<&[u8]>,
) -> Vec<u8> {
    let mut fields = Vec::new();
    for (tag, value) in [(0xa0, hash), (0xa1, mask), (0xa2, salt), (0xa3, trailer)] {
        if let Some(value) = value {
            fields.extend(tlv(tag, value));
        }
    }
    alg(oid::RSASSA_PSS.as_bytes(), Some(&tlv(48, &fields)))
}
fn id<'a>(source: &'a Parser, bytes: &'a [u8], at: u64) -> AlgorithmIdentifier<'a> {
    let mut reader = source.read(bytes, at).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    algorithm::read(&reader, &element, "signatureAlgorithm").unwrap()
}
fn parameters<'a>(source: &'a Parser, bytes: &'a [u8], at: u64) -> pss::Parameters<'a> {
    let identifier = id(source, bytes, at);
    pss::read(identifier, source.memory()).unwrap().unwrap()
}
fn projected<'a>(parameters: &pss::Parameters<'a>, work: &impl Work) -> Profile<'a> {
    let Resolution::Supported(profile) = parameters.profile(work).unwrap() else {
        panic!("recognized profile")
    };
    profile
}

#[test]
fn projection_defaults_and_original_fields_survive_the_signature_visitor() {
    // A callback can retain source-backed fields after the temporary PSS
    // descriptor and current operation disappear, without a second PSS read.
    let source = parser();
    let bytes = pss_bytes(None, None, None, None);
    let identifier = id(&source, &bytes, 400);
    let result = {
        // Structural PSS decoding may use its existing accounted reader
        // scratch. Projection itself adds no allocation or second parse.
        let work = memory(4096, 100_000);
        signature::with_algorithm(identifier, &work, |algorithm| {
            let Some(signature::Algorithm::RsaPss(parameters)) = algorithm else {
                panic!("PSS")
            };
            projected(parameters, &work)
        })
        .unwrap()
    };
    assert_eq!(result.hash(), Hash::Sha1);
    assert_eq!(result.mask_hash(), Hash::Sha1);
    assert!(matches!(result.salt(), pss::Number::Default(20)));
    assert!(matches!(result.trailer(), pss::Number::Default(1)));
    assert_eq!(result.element().span().start, 413);
    assert_eq!(result.element().as_bytes().as_ptr(), bytes[13..].as_ptr());
}

#[test]
fn all_shared_digests_and_independent_mgf_hashes_keep_their_exact_identities() {
    // Projection uses the common digest core, not output width or the message
    // hash in place of the MGF hash. Every currently recognized digest is covered.
    for hash in [
        Hash::Sha1,
        Hash::Sha224,
        Hash::Sha256,
        Hash::Sha384,
        Hash::Sha512,
        Hash::Sha512_224,
        Hash::Sha512_256,
        Hash::Sha3_224,
        Hash::Sha3_256,
        Hash::Sha3_384,
        Hash::Sha3_512,
    ] {
        let source = parser();
        let hash_id = alg(hash.identifier().as_bytes(), None);
        let mask_id = alg(MGF1, Some(&alg(SHA256, Some(&[5, 0x81, 0]))));
        let bytes = pss_bytes(
            Some(&hash_id),
            Some(&mask_id),
            Some(&tlv(2, &[0, 128])),
            None,
        );
        let original = parameters(&source, &bytes, 700);
        let work = memory(0, 100_000);
        let profile = projected(&original, &work);
        assert_eq!(profile.hash(), hash);
        assert_eq!(profile.mask_hash(), Hash::Sha256);
        let pss::Number::Written(salt) = profile.salt() else {
            panic!("salt")
        };
        assert_eq!(salt.value().as_bytes(), &[0, 128]);
        assert_eq!(profile.salt().as_u64(), Some(128));
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn unsupported_and_malformed_profiles_are_not_restriction_mismatches() {
    // Unknown algorithms/non-BC trailers remain unsupported; a recognized
    // digest with invalid parameters or a negative trailer is malformed.
    let source = parser();
    let bad_hash = alg(SHA256, Some(&[2, 1, 1]));
    let unknown_hash = alg(&[42, 3], None);
    let bad_sha3 = alg(&[96, 134, 72, 1, 101, 3, 4, 2, 8], Some(&[5, 0]));
    let unknown_mask = alg(&[42, 3], None);
    let bad_mgf = alg(MGF1, Some(&bad_hash));
    for (hash, mask, trailer, malformed) in [
        (Some(&bad_hash[..]), None, None, true),
        (Some(&bad_sha3[..]), None, None, true),
        (Some(&unknown_hash[..]), None, None, false),
        (None, Some(&bad_mgf[..]), None, true),
        (None, Some(&unknown_mask[..]), None, false),
        (None, None, Some(&[2, 1, 2][..]), false),
        (None, None, Some(&[2, 1, 255][..]), true),
        (
            None,
            None,
            Some(&[2, 10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]),
            false,
        ),
    ] {
        let bytes = pss_bytes(hash, mask, None, trailer);
        let fields = parameters(&source, &bytes, 900);
        let result = fields.profile(&memory(0, 100_000));
        if malformed {
            let error = result.unwrap_err();
            assert_eq!(error.code(), ErrorCode::MalformedValue);
            assert!(error.offset() > 900);
            assert!(!error.is_resource());
        } else {
            assert!(matches!(result.unwrap(), Resolution::Unsupported));
        }
    }
}

#[test]
fn explicit_ber_defaults_match_omission_but_der_faults_remain_visible() {
    // A profile is algorithm meaning, not evidence that inspection's DER
    // diagnostics disappeared. Both forms yield the same PSS constraints.
    let bytes = pss_bytes(
        Some(&alg(SHA1, Some(&[5, 0]))),
        None,
        Some(&[2, 1, 20]),
        Some(&[2, 1, 1]),
    );
    let empty = pss_bytes(None, None, None, None);
    let source = parser();
    let work = memory(4096, 100_000);
    let written = projected(&parameters(&source, &bytes, 400), &work);
    let omitted = projected(&parameters(&source, &empty, 800), &work);
    assert!(written.allows(&omitted, &work).unwrap());
    assert!(omitted.allows(&written, &work).unwrap());
    assert!(matches!(written.trailer(), pss::Number::Written(_)));
    let der = Parser::der(memory(100_000, 1_000_000));
    let identifier = id(&der, &bytes, 400);
    assert_eq!(
        pss::read(identifier, &work).unwrap_err().code(),
        ErrorCode::DefaultWritten
    );
    let reading = pss::inspect(identifier, &work).unwrap().unwrap();
    assert_eq!(reading.faults().len(), 3);
    let inspected = projected(&reading.parameters(), &work);
    assert!(inspected.allows(&omitted, &work).unwrap());
    assert_eq!(reading.faults().len(), 3);
}

#[test]
fn salt_is_a_floor_and_wide_distinct_numbers_never_collapse_to_a_sentinel() {
    // RFC4055 §3.3 is numeric >=, not encoded equality or usize/u64 equality.
    let source = parser();
    for (minimum, used, allowed) in [
        (vec![0], vec![0], true),
        (vec![20], vec![19], false),
        (vec![20], vec![20], true),
        (vec![20], vec![21], true),
        (vec![0, 128], vec![127], false),
        (vec![1; 20], vec![1; 19], false),
        (vec![1; 20], vec![1; 20], true),
        (vec![1; 20], vec![2; 20], true),
        (vec![2; 20], vec![1; 20], false),
        (vec![1; 1000], vec![1; 999], false),
    ] {
        let key = pss_bytes(None, None, Some(&tlv(2, &minimum)), None);
        let sig = pss_bytes(None, None, Some(&tlv(2, &used)), None);
        let work = memory(0, 1_000_000);
        let key = projected(&parameters(&source, &key, 400), &work);
        let sig = projected(&parameters(&source, &sig, 9000), &work);
        assert_eq!(key.allows(&sig, &work).unwrap(), allowed);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn key_identifier_roles_keep_absence_separate_from_default_restrictions() {
    // Unrestricted keys do not silently acquire SHA1 defaults; written empty
    // parameters do. Neither another key algorithm nor invalid NULL is false.
    let key_source = parser();
    let sig_source = parser();
    let bytes = pss_bytes(Some(&alg(SHA256, None)), None, Some(&[2, 1, 32]), None);
    let work = memory(100_000, 1_000_000);
    let signature = projected(&parameters(&sig_source, &bytes, 9000), &work);
    for (key_bytes, expected) in [
        (
            alg(oid::RSA_ENCRYPTION.as_bytes(), Some(&[5, 0])),
            Some(true),
        ),
        (
            alg(oid::RSA_ENCRYPTION.as_bytes(), Some(&[5, 0x81, 0])),
            Some(true),
        ),
        (alg(oid::RSASSA_PSS.as_bytes(), None), Some(true)),
        (pss_bytes(None, None, None, None), Some(false)),
        (
            pss_bytes(Some(&alg(SHA256, None)), None, Some(&[2, 1, 31]), None),
            Some(true),
        ),
        (
            pss_bytes(Some(&alg(SHA256, None)), None, Some(&[2, 1, 33]), None),
            Some(false),
        ),
        (alg(&[42, 3], None), None),
        (
            pss_bytes(None, Some(&alg(&[42, 3], None)), None, None),
            None,
        ),
    ] {
        let key = id(&key_source, &key_bytes, 400);
        match (
            profile::key_allows(key, &signature, &work).unwrap(),
            expected,
        ) {
            (Resolution::Supported(actual), Some(expected)) => assert_eq!(actual, expected),
            (Resolution::Unsupported, None) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    for key_bytes in [
        alg(oid::RSA_ENCRYPTION.as_bytes(), None),
        alg(oid::RSA_ENCRYPTION.as_bytes(), Some(&[2, 1, 0])),
        alg(oid::RSASSA_PSS.as_bytes(), Some(&[5, 0])),
    ] {
        assert!(profile::key_allows(id(&key_source, &key_bytes, 400), &signature, &work).is_err());
    }
}

#[test]
fn hash_and_mgf_restrictions_are_independent_and_not_just_equal_width() {
    // Same-width digests are distinct; different message and MGF hashes are
    // usable profiles and must be compared in their own positions.
    let source = parser();
    let hash = alg(SHA256, None);
    let sha3 = alg(&[96, 134, 72, 1, 101, 3, 4, 2, 8], None);
    let mgf = alg(MGF1, Some(&alg(SHA1, None)));
    let key = pss_bytes(Some(&hash), Some(&mgf), None, None);
    let work = memory(0, 1_000_000);
    let key = projected(&parameters(&source, &key, 400), &work);
    for (hash, mask, expected) in [
        (&hash, mgf.clone(), true),
        (&sha3, mgf, false),
        (&hash, alg(MGF1, Some(&hash)), false),
    ] {
        let bytes = pss_bytes(Some(hash), Some(&mask), None, None);
        let signature = projected(&parameters(&source, &bytes, 9000), &work);
        assert_eq!(key.allows(&signature, &work).unwrap(), expected);
    }
}

#[test]
fn deferred_projection_preserves_source_current_and_aggregate_ceilings() {
    // The all-default projection costs exactly one unit, even without a
    // written hash. Fresh work must not reset the original cumulative budget.
    for (left, current, aggregate, success) in [
        (1, 1, 1, true),
        (0, 1, 1, false),
        (1, 0, 1, false),
        (1, 1, 0, false),
    ] {
        let source = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: 10_000,
                ..Limits::default()
            },
            memory(4096, 100_000),
        );
        let bytes = pss_bytes(None, None, None, None);
        let values = parameters(&source, &bytes, 400);
        let original = source.execution_in(source.memory());
        original
            .charge_work((original.work_remaining() - left) as u64)
            .unwrap();
        let work = memory(0, aggregate);
        let operation = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: current,
                ..Limits::default()
            },
            work.clone(),
        );
        let query = operation.read(&[], 9000).unwrap();
        let result = values.profile(&query.execution());
        if success {
            assert!(matches!(result.unwrap(), Resolution::Supported(_)));
            assert_eq!(original.work_remaining(), 0);
            assert_eq!(work.work_used(), 1);
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.offset(), 413);
        }
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn comparison_is_paid_by_each_source_and_current_query_before_numeric_reads() {
    // Exactly five metadata/normalization/scan units per default profile;
    // ten on a shared session, and current work cannot stop halfway as false.
    let source = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 10_000,
            ..Limits::default()
        },
        memory(4096, 100_000),
    );
    let bytes = pss_bytes(None, None, None, None);
    let work = memory(0, 1_000_000);
    let profile = projected(&parameters(&source, &bytes, 400), &work);
    let original = source.execution_in(source.memory());
    let before = original.work_remaining();
    let current = memory(0, 10);
    assert!(profile.allows(&profile, &current).unwrap());
    assert_eq!(current.work_used(), 10);
    assert_eq!(original.work_remaining(), before - 10);
    for remaining in [0, 1, 2, 5, 9] {
        let error = profile.allows(&profile, &memory(0, remaining)).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), 413);
    }
    let shared = source.execution_in(source.memory());
    let before = source.memory().work_used();
    assert!(profile.allows(&profile, &shared).unwrap());
    assert_eq!(source.memory().work_used(), before + 10);
}

#[test]
fn either_original_comparison_source_can_refuse_before_a_mismatch_answer() {
    // A funded current operation cannot reset either independent source.
    // The cheap hash-mismatch branch must also admit both original metadata.
    for exhausted_key in [true, false] {
        let key_source = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: 10_000,
                ..Limits::default()
            },
            memory(4096, 100_000),
        );
        let sig_source = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: 10_000,
                ..Limits::default()
            },
            memory(4096, 100_000),
        );
        let key_bytes = pss_bytes(None, None, None, None);
        let sig_bytes = pss_bytes(Some(&alg(SHA256, None)), None, None, None);
        let work = memory(0, 100_000);
        let key = projected(&parameters(&key_source, &key_bytes, 400), &work);
        let sig = projected(&parameters(&sig_source, &sig_bytes, 9000), &work);
        let exhausted = if exhausted_key {
            &key_source
        } else {
            &sig_source
        };
        let remaining = exhausted.execution_in(exhausted.memory()).work_remaining();
        exhausted
            .execution_in(exhausted.memory())
            .charge_work(remaining as u64)
            .unwrap();
        let error = key.allows(&sig, &work).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), if exhausted_key { 413 } else { 9013 });
    }
}

#[test]
fn key_query_and_written_trailer_never_turn_refusal_into_semantic_answers() {
    // Unknown/unrestricted key fast paths and unsupported trailers must pay
    // before answering. A retained profile keeps its signature source ceiling.
    let source = parser();
    let signature_bytes = pss_bytes(None, None, None, None);
    let fields = parameters(&source, &signature_bytes, 9000);
    let signature = projected(&fields, &memory(0, 100_000));
    for bytes in [
        alg(oid::RSA_ENCRYPTION.as_bytes(), Some(&[5, 0])),
        alg(oid::RSASSA_PSS.as_bytes(), None),
        alg(&[42, 3], None),
    ] {
        let identifier = id(&source, &bytes, 400);
        let error = profile::key_allows(identifier, &signature, &memory(0, 0)).unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.offset(), 400);
    }
    let bytes = pss_bytes(None, None, None, Some(&[2, 1, 2]));
    let fields = parameters(&source, &bytes, 400);
    for available in [0, 1, 10] {
        assert!(
            fields
                .profile(&memory(0, available))
                .unwrap_err()
                .is_resource()
        );
    }
    assert!(matches!(
        fields.profile(&memory(0, 11)).unwrap(),
        Resolution::Unsupported
    ));
}

#[test]
fn selected_working_key_restrictions_precede_the_adapter_verification_step() {
    // The signature callback consumes the existing borrowed PSS descriptor
    // and the selected key's original SPKI. Refused restrictions never reach
    // the adapter's later mathematical operation; this test does not perform
    // or claim to qualify RSA arithmetic or backend allocation behavior.
    use structured_pkix::{PublicKeyInfo, path::WorkingKey};
    let key_source = parser();
    let signature_source = parser();
    let key_algorithm = pss_bytes(Some(&alg(SHA256, None)), None, Some(&[2, 1, 32]), None);
    let rsa_bits = tlv(48, &[tlv(2, &[0, 195]), tlv(2, &[1, 0, 1])].concat());
    let spki_bytes = tlv(
        48,
        &[key_algorithm, tlv(3, &[&[0][..], &rsa_bits].concat())].concat(),
    );
    let mut reader = key_source.read(&spki_bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let key = PublicKeyInfo::read_element(&reader, &element, "subjectPublicKeyInfo").unwrap();
    let selected = WorkingKey::standing(key);
    for (salt, expected) in [(31, false), (32, true), (33, true)] {
        let bytes = pss_bytes(Some(&alg(SHA256, None)), None, Some(&[2, 1, salt]), None);
        let identifier = id(&signature_source, &bytes, 9000);
        let work = memory(4096, 100_000);
        let reached_math = std::cell::Cell::new(false);
        let allowed = signature::with_algorithm(identifier, &work, |algorithm| {
            let Some(signature::Algorithm::RsaPss(parameters)) = algorithm else {
                panic!("PSS")
            };
            let Resolution::Supported(profile) = parameters.profile(&work).unwrap() else {
                panic!("profile")
            };
            let answer = profile::key_allows(selected.key().algorithm(), &profile, &work).unwrap();
            if !matches!(answer, Resolution::Supported(true)) {
                return false;
            }
            let rsa = structured_pkix::key::rsa::read(selected.key(), &work).unwrap();
            assert_eq!(rsa.modulus().as_bytes(), &[195]);
            reached_math.set(true);
            true
        })
        .unwrap();
        assert_eq!(allowed, expected);
        assert_eq!(reached_math.get(), expected);
    }
}
