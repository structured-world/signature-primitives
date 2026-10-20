//! RFC 8410 key structure and independent current/origin admission.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::{
    ErrorCode, PublicKeyInfo,
    key::rfc8410::{self, Algorithm},
};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag, u8::try_from(contents.len()).unwrap()];
    bytes.extend_from_slice(contents);
    bytes
}

fn spki(oid: &[u8], parameters: Option<&[u8]>, unused: u8, key: &[u8]) -> Vec<u8> {
    let mut algorithm = tlv(6, oid);
    if let Some(parameters) = parameters {
        algorithm.extend_from_slice(parameters);
    }
    let mut fields = tlv(0x30, &algorithm);
    fields.extend(tlv(3, &[&[unused][..], key].concat()));
    tlv(0x30, &fields)
}

fn info<'a>(parser: &'a Parser, bytes: &'a [u8]) -> PublicKeyInfo<'a> {
    let mut reader = parser.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    PublicKeyInfo::read_element(&reader, &element, "key").unwrap()
}

const ALGORITHMS: [(u8, Algorithm, usize); 4] = [
    (110, Algorithm::X25519, 32),
    (111, Algorithm::X448, 56),
    (112, Algorithm::Ed25519, 32),
    (113, Algorithm::Ed448, 57),
];

#[test]
fn all_algorithms_keep_exact_raw_bytes_and_identity_without_storage() {
    // Raw bytes that look like an ASN.1 header are still the key itself;
    // Ed25519 and X25519 stay distinct despite their identical widths.
    for (last, algorithm, length) in ALGORITHMS {
        let mut raw = vec![0xff; length];
        raw[..3].copy_from_slice(&[4, 30, 0]);
        let bytes = spki(&[43, 101, last], None, 0, &raw);
        let parser = Parser::der(memory(4096, 4096));
        let info = info(&parser, &bytes);
        let current = memory(0, 4096);
        let key = rfc8410::read(info, &current).unwrap();
        assert_eq!(key.algorithm(), algorithm);
        assert_eq!(algorithm.public_key_len(), length);
        assert_eq!(key.as_bytes(), raw);
        assert_eq!(key.offset(), info.key_offset());
        let start = usize::try_from(key.offset() - 400).unwrap();
        assert_eq!(key.as_bytes().as_ptr(), bytes[start..].as_ptr());
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn short_long_empty_and_nested_encodings_are_not_raw_key_widths() {
    // A nested OCTET STRING, or a truncated/extended point, must not be
    // repaired by stripping its header or padding the key for a backend.
    for (last, _, length) in ALGORITHMS {
        for raw in [
            vec![],
            vec![0; length - 1],
            vec![0; length + 1],
            tlv(4, &vec![0; length]),
        ] {
            let bytes = spki(&[43, 101, last], None, 0, &raw);
            let parser = Parser::der(memory(4096, 4096));
            let info = info(&parser, &bytes);
            let error = rfc8410::read(info, &memory(0, 4096)).unwrap_err();
            assert_eq!(
                (error.code(), error.offset()),
                (ErrorCode::MalformedValue, info.key_offset())
            );
            assert!(!error.is_resource());
        }
    }
}

#[test]
fn every_present_parameter_is_refused_with_its_actual_location() {
    // RFC8410 §3 forbids NULL too. Matching parameters or an authority's
    // parameters cannot turn these into a valid key spelling.
    for (last, _, length) in ALGORITHMS {
        for parameter in [vec![5, 0], vec![2, 1, 1], vec![0x30, 0]] {
            let bytes = spki(&[43, 101, last], Some(&parameter), 0, &vec![0; length]);
            let parser = Parser::der(memory(4096, 4096));
            let error = rfc8410::read(info(&parser, &bytes), &memory(0, 4096)).unwrap_err();
            assert_eq!(error.code(), ErrorCode::MalformedValue);
            assert_eq!(error.field(), "subjectPublicKeyInfo.algorithm.parameters");
            assert_eq!(error.offset(), 409);
        }
    }
}

#[test]
fn ber_null_spelling_does_not_change_absent_only_rule() {
    // BER NULL with a long length header is still present, not absence.
    let bytes = spki(&[43, 101, 112], Some(&[5, 0x81, 0]), 0, &[0; 32]);
    let parser = Parser::ber(memory(4096, 4096));
    assert_eq!(
        rfc8410::read(info(&parser, &bytes), &memory(0, 4096))
            .unwrap_err()
            .code(),
        ErrorCode::MalformedValue
    );
}

#[test]
fn padded_bit_strings_do_not_get_rounded_to_whole_key_octets() {
    // All low padding bits are zero, so the generic BIT STRING is readable;
    // these algorithms nevertheless require a whole number of octets.
    for (last, _, length) in ALGORITHMS {
        let bytes = spki(&[43, 101, last], None, 1, &vec![0; length]);
        let parser = Parser::der(memory(4096, 4096));
        let info = info(&parser, &bytes);
        let error = rfc8410::read(info, &memory(0, 4096)).unwrap_err();
        assert_eq!(
            (error.code(), error.offset()),
            (ErrorCode::MalformedValue, info.key_offset())
        );
    }
}

#[test]
fn neighboring_unknown_oids_never_select_a_key_by_width() {
    // Exact algorithm identity wins over payload length, including OIDs
    // sharing a prefix or differing in only the final byte.
    for oid in [
        &[43, 101, 109][..],
        &[43, 101, 114],
        &[43, 100, 112],
        &[43, 101, 112, 1],
        &[43],
    ] {
        let bytes = spki(oid, None, 0, &[0; 32]);
        let parser = Parser::der(memory(4096, 4096));
        let info = info(&parser, &bytes);
        let current = memory(0, 4096);
        let error = rfc8410::read(info, &current).unwrap_err();
        assert_eq!(
            (error.code(), error.offset()),
            (ErrorCode::UnexpectedField, info.algorithm().offset())
        );
        assert_eq!(current.work_used(), if oid.len() == 3 { 4 } else { 1 });
    }
}

#[test]
fn exact_and_one_less_work_apply_to_all_algorithms() {
    // Recognition costs a bounded metadata step and the exact OID bytes;
    // the raw key is borrowed, not secretly traversed or decoded again.
    for (last, _, length) in ALGORITHMS {
        let bytes = spki(&[43, 101, last], None, 0, &vec![0; length]);
        let parser = Parser::der(memory(4096, 4096));
        let info = info(&parser, &bytes);
        rfc8410::read(info, &memory(0, 4)).unwrap();
        for allowance in [0, 3] {
            let current = memory(0, allowance);
            let error = rfc8410::read(info, &current).unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.offset(), info.algorithm().offset());
            assert!(current.work_used() <= allowance);
            assert_eq!(current.used(), 0);
        }
    }
}

#[test]
fn original_source_work_cannot_be_replenished_by_a_fresh_account() {
    // Deferred metadata/OID processing is still part of the source session.
    let bytes = spki(&[43, 101, 112], None, 0, &[0; 32]);
    let initial = {
        let parser = Parser::der(memory(4096, 4096));
        info(&parser, &bytes);
        parser.memory().work_used()
    };
    for extra in [3, 4] {
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: (initial + extra) as u64,
                ..Limits::default()
            },
            memory(4096, 4096),
        );
        let info = info(&parser, &bytes);
        let current = memory(0, 4096);
        let result = rfc8410::read(info, &current);
        if extra == 4 {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().is_resource());
        }
    }
}

#[test]
fn current_work_remains_effective_without_inventing_a_nested_depth() {
    // No ASN.1 value is entered during this metadata query. A depth-zero
    // operation is sufficient, but its cumulative work must still be paid.
    let bytes = spki(&[43, 101, 112], None, 0, &[0; 32]);
    let parser = Parser::der(memory(4096, 4096));
    let info = info(&parser, &bytes);
    for allowance in [0, 3] {
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_depth: 0,
                max_work: allowance,
                ..Limits::default()
            },
            memory(0, 4096),
        );
        let reader = operation.read(&[], 900).unwrap();
        assert!(
            rfc8410::read(info, &reader.execution())
                .unwrap_err()
                .is_resource()
        );
    }
    let key;
    {
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_depth: 0,
                max_work: 4,
                ..Limits::default()
            },
            memory(0, 4096),
        );
        let reader = operation.read(&[], 900).unwrap();
        key = rfc8410::read(info, &reader.execution()).unwrap();
    }
    assert_eq!(key.as_bytes(), [0; 32]);
}
