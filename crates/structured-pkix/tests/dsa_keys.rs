//! Borrowed DSA schema and current-execution qualification, not group validation.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::{Certificate, ErrorCode, PublicKeyInfo, key::dsa, path::WorkingKey};

const DSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if bytes.len() < 128 {
        out.push(u8::try_from(bytes.len()).unwrap());
    } else if bytes.len() < 256 {
        out.push(0x81);
        out.push(u8::try_from(bytes.len()).unwrap());
    } else {
        out.push(0x82);
        out.extend(u16::try_from(bytes.len()).unwrap().to_be_bytes());
    }
    out.extend_from_slice(bytes);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn integer(bytes: &[u8]) -> Vec<u8> {
    tlv(2, bytes)
}
fn parms() -> Vec<u8> {
    seq(&[integer(&[0, 0x83]), integer(&[5]), integer(&[2])])
}
fn spki(parameters: Option<&[u8]>, value: &[u8]) -> Vec<u8> {
    let mut algorithm = tlv(6, DSA);
    if let Some(parameters) = parameters {
        algorithm.extend_from_slice(parameters);
    }
    seq(&[tlv(0x30, &algorithm), tlv(3, &[&[0][..], value].concat())])
}
fn info<'a>(parser: &'a Parser, bytes: &'a [u8]) -> PublicKeyInfo<'a> {
    let mut reader = parser.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    PublicKeyInfo::read_element(&reader, &element, "key").unwrap()
}

#[test]
fn components_keep_unsigned_bytes_sign_octets_and_physical_spans() {
    // A sign octet is preserved in the INTEGER view but excluded from the
    // magnitude given to a backend. No encoded key or component is copied.
    let bytes = spki(Some(&parms()), &integer(&[0, 0x80]));
    let parser = Parser::der(memory(4096, 10000));
    let key = dsa::read(WorkingKey::standing(info(&parser, &bytes)), parser.memory()).unwrap();
    let params = key.parameters().unwrap();
    assert!(!params.is_inherited());
    assert_eq!(params.p().as_bytes(), [0x83]);
    assert_eq!(params.p().integer().as_bytes(), [0, 0x83]);
    assert_eq!(params.q().as_bytes(), [5]);
    assert_eq!(params.g().as_bytes(), [2]);
    assert_eq!(key.y().as_bytes(), [0x80]);
    for component in [params.p(), params.q(), params.g(), key.y()] {
        let start = usize::try_from(component.element().contents_span().start - 400).unwrap();
        assert_eq!(
            component.integer().as_bytes().as_ptr(),
            bytes[start..].as_ptr()
        );
    }
    assert_eq!(parser.memory().used(), 0);
}

#[test]
fn absent_parameters_and_zero_are_inspection_not_usable_key_facts() {
    // Neither fabricate a default group nor silently accept a zero DSA key.
    let bytes = spki(None, &integer(&[0]));
    let parser = Parser::der(memory(4096, 10000));
    let key = dsa::read(WorkingKey::standing(info(&parser, &bytes)), parser.memory()).unwrap();
    assert!(key.parameters().is_none());
    assert_eq!(key.y().as_bytes(), [0]);
    let bytes = spki(
        Some(&seq(&[integer(&[0]), integer(&[0]), integer(&[0])])),
        &integer(&[0]),
    );
    let key = dsa::read(WorkingKey::standing(info(&parser, &bytes)), parser.memory()).unwrap();
    let params = key.parameters().unwrap();
    assert_eq!(
        [
            params.p().as_bytes(),
            params.q().as_bytes(),
            params.g().as_bytes()
        ],
        [&[0][..]; 3]
    );
}

#[test]
fn written_null_wrong_arity_and_negative_components_refuse() {
    // Written NULL is not omitted parameters; no backend sees a repaired key.
    for parameters in [
        vec![5, 0],
        integer(&[1]),
        seq(&[]),
        seq(&[integer(&[1]), integer(&[2])]),
        seq(&[integer(&[1]), integer(&[2]), integer(&[3]), integer(&[4])]),
        seq(&[integer(&[0xff]), integer(&[2]), integer(&[3])]),
        seq(&[integer(&[1]), integer(&[0xff]), integer(&[3])]),
        seq(&[integer(&[1]), integer(&[2]), integer(&[0xff])]),
    ] {
        let bytes = spki(Some(&parameters), &integer(&[7]));
        let parser = Parser::der(memory(4096, 10000));
        let error =
            dsa::read(WorkingKey::standing(info(&parser, &bytes)), parser.memory()).unwrap_err();
        assert_eq!(error.field(), "subjectPublicKeyInfo.algorithm.parameters");
        assert!(!error.is_resource());
        assert!(error.offset() >= 400);
        assert_eq!(parser.memory().used(), 0);
    }
    let bytes = spki(None, &integer(&[0x80]));
    let parser = Parser::der(memory(4096, 10000));
    assert_eq!(
        dsa::read(WorkingKey::standing(info(&parser, &bytes)), parser.memory())
            .unwrap_err()
            .code(),
        ErrorCode::MalformedValue
    );
}

#[test]
fn key_integer_is_der_even_in_ber_spki_and_has_no_trailing_value() {
    // Key bits are opaque to SPKI reading, but DSA's carried INTEGER is DER.
    for value in [
        vec![2, 0x81, 1, 7],
        vec![2, 2, 0, 7],
        vec![2, 0],
        vec![0x22, 1, 7],
        vec![5, 0],
        vec![2, 1, 7, 5, 0],
    ] {
        let bytes = spki(None, &value);
        let parser = Parser::ber(memory(4096, 10000));
        let error =
            dsa::read(WorkingKey::standing(info(&parser, &bytes)), parser.memory()).unwrap_err();
        assert!(!error.is_resource());
        assert_eq!(error.field(), "subjectPublicKey.dsa");
        assert_eq!(parser.memory().used(), 0);
    }
}

#[test]
fn large_components_stay_borrowed_without_backend_width_limits() {
    // A decoder must not impose a curve/backend cutoff or truncate to u64.
    let mut wide = vec![1];
    wide.extend([0xaa; 512]);
    let parameters = seq(&[integer(&wide), integer(&[3]), integer(&[2])]);
    let bytes = spki(Some(&parameters), &integer(&wide));
    let parser = Parser::der(memory(4096, 10000));
    let key = dsa::read(WorkingKey::standing(info(&parser, &bytes)), parser.memory()).unwrap();
    assert_eq!(key.parameters().unwrap().p().as_bytes(), wide);
    assert_eq!(key.y().as_bytes(), wide);
    assert!(key.y().integer().as_u64().is_none());
}

fn run(current_work: usize, capacity: usize) -> (Result<(), structured_pkix::Error>, usize) {
    let bytes = spki(Some(&parms()), &integer(&[7]));
    let parser = Parser::der(memory(4096, 10000));
    let info = info(&parser, &bytes);
    let current = memory(capacity, current_work);
    let result = dsa::read(WorkingKey::standing(info), &current).map(|_| ());
    assert_eq!(current.used(), 0);
    (result, current.work_used())
}

#[test]
fn exact_current_work_and_metadata_capacity_refuse_before_excess() {
    // Deferred decoding is funded by this request, not the retained source.
    let (result, cost) = run(10000, 4096);
    result.unwrap();
    run(cost, 4096).0.unwrap();
    assert!(run(cost - 1, 4096).0.unwrap_err().is_resource());
    // The shallow parameter reader needs the existing four-u32 path buffer.
    // It is released before the key INTEGER is opened, so peak storage is16.
    run(10000, 16).0.unwrap();
    for capacity in [0, 15] {
        let error = run(10000, capacity).0.unwrap_err();
        assert!(error.is_resource());
        assert_eq!(error.field(), "subjectPublicKeyInfo.algorithm.parameters");
        assert!(error.offset() >= 400);
    }
}

#[test]
fn spent_current_query_is_terminal_and_short_borrow_does_not_escape() {
    // Scoped Work cannot be substituted with a wider old account.
    let bytes = spki(Some(&parms()), &integer(&[7]));
    let parser = Parser::der(memory(4096, 10000));
    let info = info(&parser, &bytes);
    let current = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(4096, 10000),
    );
    let query = current.read(&[], 900).unwrap();
    let error = dsa::read(WorkingKey::standing(info), &query.execution()).unwrap_err();
    assert!(error.is_resource());
    let key;
    {
        let current = memory(4096, 10000);
        key = dsa::read(WorkingKey::standing(info), &current).unwrap();
        assert_eq!(current.used(), 0);
    }
    assert_eq!(key.y().as_bytes(), [7]);
}

fn certificate(subject: &[u8], key: &[u8]) -> Vec<u8> {
    // Trusted synthetic carrier: no signature/path acceptance is claimed.
    let name = |value: &[u8]| seq(&[tlv(0x31, &seq(&[tlv(6, &[0x55, 4, 3]), tlv(0x0c, value)]))]);
    let algorithm = seq(&[tlv(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2])]);
    let tbs = seq(&[
        tlv(0xa0, &integer(&[2])),
        integer(&[1]),
        algorithm.clone(),
        name(b"Root"),
        seq(&[tlv(0x17, b"240101000000Z"), tlv(0x17, b"300101000000Z")]),
        name(subject),
        key.to_vec(),
    ]);
    seq(&[tbs, algorithm, tlv(3, &[0, 1])])
}

#[test]
fn effective_parameters_retain_issuer_source_and_explicit_null_is_not_repaired() {
    // Generic path inheritance supplies absent parameters only; the DSA
    // profile still refuses a NULL written by the child.
    let root_bytes = certificate(b"Root", &spki(Some(&parms()), &integer(&[7])));
    let leaf_bytes = certificate(b"Leaf", &spki(None, &integer(&[8])));
    let null_bytes = certificate(b"Null", &spki(Some(&[5, 0]), &integer(&[8])));
    let root_parser = Parser::der(memory(8192, 100_000));
    let leaf_parser = Parser::der(memory(8192, 100_000));
    let root = Certificate::read(&root_parser, &root_bytes, 100).unwrap();
    let leaf = Certificate::read(&leaf_parser, &leaf_bytes, 900).unwrap();
    let null = Certificate::read(&leaf_parser, &null_bytes, 1900).unwrap();
    let current = memory(8192, 100_000);
    let parent = WorkingKey::standing(root.tbs().public_key());
    let key = dsa::read(parent.subject(&leaf, &current).unwrap(), &current).unwrap();
    let parameters = key.parameters().unwrap();
    assert!(parameters.is_inherited());
    assert!(parameters.element().span().start < 900);
    assert!(key.y().element().span().start >= 900);
    assert_eq!(parameters.p().as_bytes(), [0x83]);
    let error = dsa::read(parent.subject(&null, &current).unwrap(), &current).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert!(error.offset() >= 1900);
}

#[test]
fn explicit_parameters_override_inheritance_and_algorithm_change_clears_it() {
    // A subject's own group wins. Crossing another algorithm cannot smuggle
    // an earlier DSA authority's parameters into a later parameterless key.
    let root_bytes = certificate(b"Root", &spki(Some(&parms()), &integer(&[7])));
    let own = seq(&[integer(&[23]), integer(&[11]), integer(&[4])]);
    let leaf_bytes = certificate(b"Own", &spki(Some(&own), &integer(&[8])));
    let mut foreign = spki(None, &integer(&[8]));
    let oid_start = foreign
        .windows(DSA.len())
        .position(|part| part == DSA)
        .unwrap();
    foreign[oid_start + DSA.len() - 1] = 2;
    let foreign_bytes = certificate(b"Other", &foreign);
    let last_bytes = certificate(b"Last", &spki(None, &integer(&[9])));
    let parser = Parser::der(memory(65536, 100_000));
    let root = Certificate::read(&parser, &root_bytes, 0).unwrap();
    let leaf = Certificate::read(&parser, &leaf_bytes, 900).unwrap();
    let other = Certificate::read(&parser, &foreign_bytes, 1900).unwrap();
    let last = Certificate::read(&parser, &last_bytes, 2900).unwrap();
    let current = memory(4096, 100_000);
    let root = WorkingKey::standing(root.tbs().public_key());
    let key = dsa::read(root.subject(&leaf, &current).unwrap(), &current).unwrap();
    let parameters = key.parameters().unwrap();
    assert!(!parameters.is_inherited());
    assert_eq!(parameters.p().as_bytes(), [23]);
    assert!(parameters.element().span().start >= 900);
    let other = root.subject(&other, &current).unwrap();
    assert_eq!(
        dsa::read(other, &current).unwrap_err().code(),
        ErrorCode::UnexpectedField
    );
    let last = other.subject(&last, &current).unwrap();
    assert!(dsa::read(last, &current).unwrap().parameters().is_none());
}

#[test]
fn source_local_work_and_current_depth_are_not_reset_by_deferred_reading() {
    // A new account cannot replenish the producing parser's spent local
    // work. Conversely, a generous source cannot widen the current query.
    let bytes = spki(Some(&parms()), &integer(&[7]));
    let (initial, total) = {
        let parser = Parser::der(memory(4096, 10000));
        let info = info(&parser, &bytes);
        let initial = parser.memory().work_used();
        dsa::read(WorkingKey::standing(info), parser.memory()).unwrap();
        (initial, parser.memory().work_used())
    };
    let run_source = |allowance: usize| {
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: allowance as u64,
                ..Limits::default()
            },
            memory(4096, 10000),
        );
        let info = info(&parser, &bytes);
        let current = memory(4096, 10000);
        dsa::read(WorkingKey::standing(info), &current).map(|_| ())
    };
    // Selector work belongs to current Work, whereas nested source work
    // also spends the producing parser. Measure that boundary separately
    // instead of mistaking the full aggregate cost for the source ceiling.
    assert!(run_source(initial).unwrap_err().is_resource());
    run_source(total).unwrap();
    let (mut low, mut high) = (initial, total);
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        match run_source(middle) {
            Ok(()) => high = middle,
            Err(error) => {
                assert!(error.is_resource());
                low = middle;
            }
        }
    }
    run_source(high).unwrap();
    assert!(run_source(high - 1).unwrap_err().is_resource());
    let parser = Parser::der(memory(4096, 10000));
    let info = info(&parser, &bytes);
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        memory(4096, 10000),
    );
    let query = operation.read(&[], 900).unwrap();
    assert!(
        dsa::read(WorkingKey::standing(info), &query.execution())
            .unwrap_err()
            .is_resource()
    );
}

#[test]
fn padded_key_bits_refuse_before_integer_inspection() {
    // A correctly encoded padded BIT STRING is still not an octet-aligned
    // DSA key; it cannot be handed to an INTEGER reader by dropping bits.
    let mut bytes = spki(None, &integer(&[8]));
    let end = bytes.len();
    bytes[end - 4] = 1;
    let parser = Parser::der(memory(4096, 10000));
    let info = info(&parser, &bytes);
    let error = dsa::read(WorkingKey::standing(info), parser.memory()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.offset(), info.key_offset());
}
