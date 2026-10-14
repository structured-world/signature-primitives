//! Original-value entry points preserve producing resource bounds.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount},
};
use structured_pkix::usage::ExtendedKeyUsage;

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if contents.len() < 128 {
        bytes.push(u8::try_from(contents.len()).unwrap());
    } else {
        bytes.push(0x82);
        bytes.extend(u16::try_from(contents.len()).unwrap().to_be_bytes());
    }
    bytes.extend(contents);
    bytes
}

#[test]
fn original_eku_catalogue_obeys_local_work_before_growth() {
    // The wire traversal fits this ceiling; catalogue allocation/copy work
    // must use the same producing ceiling rather than aggregate Memory alone.
    let mut purposes = Vec::new();
    for suffix in 1..=64 {
        purposes.extend(tlv(6, &[42, suffix]));
    }
    let bytes = tlv(0x30, &purposes);
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)));
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 4000,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut parent = parser.read(&bytes, 400).unwrap();
    let value = parent.next_element().unwrap().unwrap();
    let error = ExtendedKeyUsage::read_value(&parent, &value).unwrap_err();
    assert!(error.is_resource());
    assert!(error.offset() >= 400);
    assert_eq!(memory.used(), 0);
    assert!(memory.work_used() <= 4000);
}

fn algorithm(kind: &[u8], parameters: &[u8]) -> Vec<u8> {
    let mut fields = tlv(6, kind);
    fields.extend(parameters);
    tlv(0x30, &fields)
}

#[test]
fn sha2_defaults_are_specific_and_original_null_encodings_survive() {
    // RFC5754 covers these four OIDs, not every identifier ending in NULL.
    for suffix in [4, 1, 2, 3] {
        let kind = [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, suffix];
        for parameters in [&[5, 0][..], &[5, 0x81, 0][..]] {
            let left = algorithm(&kind, &[]);
            let right = algorithm(&kind, parameters);
            let mut bytes = left.clone();
            bytes.extend(&right);
            let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(10000, 10000))));
            let mut parent = parser.read(&bytes, 400).unwrap();
            let first = parent.next_element().unwrap().unwrap();
            let second = parent.next_element().unwrap().unwrap();
            let left = structured_pkix::algorithm::read(&parent, &first, "left").unwrap();
            let right = structured_pkix::algorithm::read(&parent, &second, "right").unwrap();
            assert!(left.digest_matches_in(&right, &parent).unwrap());
            assert!(!left.same_written_in(&right, &parent).unwrap());
            assert_eq!(right.parameters(), Some(parameters));
            assert!(right.has_null_parameter());
        }
    }
}

#[test]
fn unknown_parameters_keep_written_identity() {
    // A primitive NULL value can have different BER headers; an unknown
    // algorithm does not acquire an absent-parameter default from that fact.
    for (left_params, right_params, expected) in [
        (&[][..], &[5, 0][..], false),
        (&[5, 0][..], &[5, 0x81, 0][..], true),
        (&[4, 1, 7][..], &[4, 1, 7][..], true),
        (&[4, 1, 7][..], &[4, 0x81, 1, 7][..], false),
        (&[0x30, 0][..], &[0x30, 0][..], true),
        (&[0x30, 0][..], &[0x30, 0x81, 0][..], false),
    ] {
        let mut bytes = algorithm(&[42, 3], left_params);
        bytes.extend(algorithm(&[42, 3], right_params));
        let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(10000, 10000))));
        let mut parent = parser.read(&bytes, 400).unwrap();
        let first = parent.next_element().unwrap().unwrap();
        let second = parent.next_element().unwrap().unwrap();
        let left = structured_pkix::algorithm::read(&parent, &first, "left").unwrap();
        let right = structured_pkix::algorithm::read(&parent, &second, "right").unwrap();
        assert_eq!(left.same_written_in(&right, &parent).unwrap(), expected);
        assert_eq!(left.digest_matches_in(&right, &parent).unwrap(), expected);
        assert_eq!(
            right.parameters(),
            (!right_params.is_empty()).then_some(right_params)
        );
    }
}

#[test]
fn invalid_sha2_parameters_are_not_a_digest_mismatch() {
    // Validate both known operands before identity comparison: malformed
    // parameters remain malformed even when the other OID is different.
    let kind = [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
    let mut bytes = algorithm(&[42, 3], &[]);
    bytes.extend(algorithm(&kind, &[4, 0]));
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(10000, 10000))));
    let mut parent = parser.read(&bytes, 400).unwrap();
    let first = parent.next_element().unwrap().unwrap();
    let second = parent.next_element().unwrap().unwrap();
    let left = structured_pkix::algorithm::read(&parent, &first, "left").unwrap();
    let right = structured_pkix::algorithm::read(&parent, &second, "right").unwrap();
    let error = left.digest_matches_in(&right, &parent).unwrap_err();
    assert_eq!(error.code(), structured_pkix::ErrorCode::MalformedValue);
    assert_eq!(error.offset(), second.span().start);
    assert!(!left.same_written_in(&right, &parent).unwrap());
}

#[test]
fn foreign_algorithm_query_refuses_before_work() {
    // Sharing an allocation account does not make two parser sessions equal.
    let bytes = algorithm(&[42, 3], &[]);
    let memory = Memory::new(Arc::new(MemoryAccount::new(10000, 10000)));
    let parser = Parser::ber(memory.clone());
    let foreign = Parser::ber(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let value = structured_pkix::algorithm::read(&parent, &element, "algorithm").unwrap();
    let other = foreign.read(&[], 0).unwrap();
    let before = memory.work_used();
    let error = value.digest_matches_in(&value, &other).unwrap_err();
    assert_eq!(error.code(), structured_pkix::ErrorCode::ForeignReader);
    assert_eq!(error.offset(), 400);
    assert_eq!(memory.work_used(), before);
}

#[test]
fn constructed_sha2_parameters_are_malformed_not_opaque_defaults() {
    // A readable constructed parameter remains original data for inspection,
    // but cannot satisfy RFC5754's absent-or-primitive-NULL digest contract.
    let kind = [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
    let bytes = algorithm(&kind, &[0x30, 0]);
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(10000, 10000))));
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let value = structured_pkix::algorithm::read(&parent, &element, "algorithm").unwrap();
    assert_eq!(value.parameters(), Some(&[0x30, 0][..]));
    assert!(!value.has_null_parameter());
    assert!(value.same_written_in(&value, &parent).unwrap());
    let error = value.digest_matches_in(&value, &parent).unwrap_err();
    assert_eq!(error.code(), structured_pkix::ErrorCode::MalformedValue);
    assert_eq!(error.offset(), 400);
}

#[test]
fn original_eku_retains_only_unique_purposes_and_storage_charge() {
    // Deduplication preserves first occurrence order. Returned storage is
    // independent of the reader cursor, and its charge ends with the result.
    let bytes = tlv(0x30, &[6, 2, 42, 3, 6, 2, 42, 4, 6, 2, 42, 3]);
    let memory = Memory::new(Arc::new(MemoryAccount::new(10000, 100_000)));
    let parser = Parser::der(memory.clone());
    let result = {
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        ExtendedKeyUsage::read_value(&parent, &element).unwrap()
    };
    assert_eq!(result.purposes().len(), 2);
    assert_eq!(result.purposes()[0].as_bytes(), &[42, 3]);
    assert_eq!(result.purposes()[1].as_bytes(), &[42, 4]);
    assert!(memory.used() > 0);
    drop(result);
    assert_eq!(memory.used(), 0);
}

#[test]
fn original_eku_memory_refusal_rolls_back_catalogues() {
    // Wide input fits wire traversal but must not bypass storage admission.
    let mut purposes = Vec::new();
    for suffix in 0_u16..256 {
        let high = u8::try_from(suffix / 128).unwrap();
        let low = u8::try_from(suffix % 128).unwrap();
        purposes.extend(tlv(6, &[42, 1 + high, low]));
    }
    let bytes = tlv(0x30, &purposes);
    let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 1_000_000)));
    let parser = Parser::der(memory.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let error = ExtendedKeyUsage::read_value(&parent, &element).unwrap_err();
    assert!(error.is_resource());
    assert!(error.offset() >= 400);
    assert_eq!(memory.used(), 0);
}

#[test]
fn original_eku_preserves_schema_and_depth_boundaries() {
    // The new entry point is the same strict EKU grammar, not a permissive
    // catalogue constructor, and entering it consumes inherited depth.
    for bytes in [tlv(0x30, &[]), tlv(0x31, &[6, 2, 42, 3])] {
        let memory = Memory::new(Arc::new(MemoryAccount::new(10000, 10000)));
        let parser = Parser::der(memory.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let value = parent.next_element().unwrap().unwrap();
        assert!(ExtendedKeyUsage::read_value(&parent, &value).is_err());
        assert_eq!(memory.used(), 0);
    }
    let bytes = tlv(0x30, &[6, 2, 42, 3]);
    let memory = Memory::new(Arc::new(MemoryAccount::new(10000, 10000)));
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut parent = parser.read(&bytes, 400).unwrap();
    let value = parent.next_element().unwrap().unwrap();
    assert!(ExtendedKeyUsage::read_value(&parent, &value).is_err());
    assert_eq!(memory.used(), 0);
}

#[test]
fn malformed_primitive_null_never_becomes_cached_valid_null() {
    // Only a successfully decoded NULL receives value equivalence; the tag
    // alone must not bless nonempty contents in otherwise readable BER.
    let bytes = algorithm(&[42, 3], &[5, 1, 0]);
    let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(10000, 10000))));
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    assert!(structured_pkix::algorithm::read(&parent, &element, "algorithm").is_err());
}

#[test]
fn digest_query_admits_exact_local_and_aggregate_work() {
    // These two known OIDs require 30 units: two classifications (10 each),
    // metadata (1), and OID comparison (9). Refusal stays located at the real
    // operand and cannot be silently converted into inequality.
    for (aggregate, remaining, succeeds) in [
        (false, 0, false),
        (false, 29, false),
        (false, 30, true),
        (true, 0, false),
        (true, 29, false),
        (true, 30, true),
    ] {
        let kind = [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
        let mut bytes = algorithm(&kind, &[]);
        bytes.extend(algorithm(&kind, &[5, 0]));
        let memory = Memory::new(Arc::new(MemoryAccount::new(10000, 100_000)));
        let parser = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: 100_000,
                ..Limits::default()
            },
            memory.clone(),
        );
        let mut parent = parser.read(&bytes, 400).unwrap();
        let first = parent.next_element().unwrap().unwrap();
        let second = parent.next_element().unwrap().unwrap();
        let left = structured_pkix::algorithm::read(&parent, &first, "left").unwrap();
        let right = structured_pkix::algorithm::read(&parent, &second, "right").unwrap();
        let drain = 100_000 - u64::try_from(memory.work_used()).unwrap() - remaining;
        if aggregate {
            memory.charge_work(drain).unwrap();
        } else {
            parent.charge(drain).unwrap();
        }
        let before = memory.work_used();
        let result = left.digest_matches_in(&right, &parent);
        if succeeds {
            assert!(result.unwrap());
            assert_eq!(memory.work_used() - before, 30);
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource());
            assert!(error.offset() == first.span().start || error.offset() == second.span().start);
            assert!(memory.work_used() - before <= usize::try_from(remaining).unwrap());
        }
        assert_eq!(memory.used(), 0);
    }
}
