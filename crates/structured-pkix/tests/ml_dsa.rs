//! Pure ML-DSA public structure, source provenance and callback admission.

use std::cell::Cell;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::algorithm::{self, AlgorithmIdentifier, ml_dsa::ParameterSet, signature};
use structured_pkix::key::ml_dsa;
use structured_pkix::signature::SignatureValue;
use structured_pkix::{Certificate, ErrorCode, PublicKeyInfo};

const SETS: [(u8, ParameterSet, usize, usize); 3] = [
    (17, ParameterSet::MlDsa44, 1312, 2420),
    (18, ParameterSet::MlDsa65, 1952, 3309),
    (19, ParameterSet::MlDsa87, 2592, 4627),
];

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(u8::try_from(body.len()).unwrap());
    } else {
        out.push(0x82);
        out.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    }
    out.extend(body);
    out
}
fn identifier_bytes(last: u8, parameters: Option<&[u8]>) -> Vec<u8> {
    let mut body = tlv(6, &[96, 134, 72, 1, 101, 3, 4, 3, last]);
    body.extend(parameters.unwrap_or(&[]));
    tlv(48, &body)
}
fn bits(raw: &[u8], padding: u8) -> Vec<u8> {
    tlv(3, &[&[padding], raw].concat())
}
fn spki_bytes(last: u8, parameters: Option<&[u8]>, raw: &[u8], padding: u8) -> Vec<u8> {
    tlv(
        48,
        &[identifier_bytes(last, parameters), bits(raw, padding)].concat(),
    )
}
fn spki<'a>(source: &'a Parser, bytes: &'a [u8]) -> PublicKeyInfo<'a> {
    let mut reader = source.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    PublicKeyInfo::read_element(&reader, &element, "spki").unwrap()
}
fn id<'a>(source: &'a Parser, bytes: &'a [u8]) -> AlgorithmIdentifier<'a> {
    let mut reader = source.read(bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    algorithm::read(&reader, &element, "algorithm").unwrap()
}
fn value<'a>(source: &'a Parser, bytes: &'a [u8]) -> SignatureValue<'a> {
    SignatureValue::read(&mut source.read(bytes, 900).unwrap(), "signature").unwrap()
}
fn limited(work: u64) -> Parser {
    Parser::new(
        Encoding::Der,
        Limits {
            max_work: work,
            ..Limits::default()
        },
        memory(4096, 1_000_000),
    )
}
fn leave(source: &Parser, units: usize) {
    let old = source.execution_in(source.memory());
    old.charge_work((old.work_remaining() - units) as u64)
        .unwrap();
}

#[test]
fn all_sets_share_identity_widths_and_borrow_original_octets() {
    // Table2's three identities must stay distinct without copying large keys
    // or retaining a short operation/refcount merely to return a raw view.
    for (last, set, key_len, sig_len) in SETS {
        assert_eq!(
            (set.public_key_len(), set.signature_len()),
            (key_len, sig_len)
        );
        let source = limited(100_000);
        let key_bytes = spki_bytes(last, None, &vec![0x42; key_len], 0);
        let key = spki(&source, &key_bytes);
        let signature_bytes = bits(&vec![0x24; sig_len], 0);
        let signature = value(&source, &signature_bytes);
        let (decoded, raw) = {
            let account = Arc::new(MemoryAccount::new(0, 1000));
            let current = Memory::new(account.clone());
            let owners = Arc::strong_count(&account);
            let decoded = ml_dsa::read(key, &current).unwrap();
            let raw = signature.ml_dsa_in(set, &current).unwrap();
            assert_eq!(Arc::strong_count(&account), owners);
            assert_eq!(current.used(), 0);
            assert_eq!(current.work_used(), 11); // one 9-byte OID + metadata; signature metadata
            (decoded, raw)
        };
        assert_eq!(decoded.parameter_set(), set);
        assert_eq!(
            decoded.as_bytes().as_ptr(),
            key.key_octets().unwrap().as_ptr()
        );
        assert_eq!(decoded.offset(), 422);
        assert_eq!(raw.as_ptr(), signature.octets().unwrap().as_ptr());
        assert_eq!(signature.payload_span().start, 905);
        assert_eq!(
            algorithm::ml_dsa::resolve(key.algorithm(), &memory(0, 10)).unwrap(),
            Some(set)
        );
        signature::with_algorithm(key.algorithm(), &memory(0, 10), |recognized| {
            assert!(
                matches!(recognized, Some(signature::Algorithm::MlDsa(actual)) if actual == set)
            );
        })
        .unwrap();
    }
}

#[test]
fn forbidden_parameters_have_one_shared_located_rule_in_ber_and_der() {
    // NULL is present even with BER length spelling; key and signature roles
    // use one absent-parameters kernel and never call a visitor on refusal.
    for encoding in [Encoding::Ber, Encoding::Der] {
        for (last, _, key_len, _) in SETS {
            for parameter in [&[5, 0][..], &[2, 1, 0], &[48, 0]] {
                let source = Parser::new(encoding, Limits::default(), memory(4096, 100_000));
                let bytes = spki_bytes(last, Some(parameter), &vec![0; key_len], 0);
                let key = spki(&source, &bytes);
                let current = memory(0, 1000);
                let error = ml_dsa::read(key, &current).unwrap_err();
                assert_eq!(
                    (error.code(), error.field(), error.offset()),
                    (ErrorCode::MalformedValue, "spki", 417)
                );
                let visited = Cell::new(false);
                let error =
                    signature::with_algorithm(key.algorithm(), &current, |_| visited.set(true))
                        .unwrap_err();
                assert_eq!(
                    (error.code(), error.offset()),
                    (ErrorCode::MalformedValue, 417)
                );
                assert!(!visited.get());
            }
        }
    }
    let source = Parser::ber(memory(4096, 100_000));
    let bytes = identifier_bytes(17, Some(&[5, 0x81, 0]));
    let identifier = id(&source, &bytes);
    assert_eq!(
        algorithm::ml_dsa::resolve(identifier, &memory(0, 10))
            .unwrap_err()
            .code(),
        ErrorCode::MalformedValue
    );
}

#[test]
fn unknown_prehash_and_adjacent_oids_do_not_select_a_pure_parameter_set() {
    // Exact identity matters: HashML-DSA, SLH-DSA and a longer OID sharing
    // the same prefix cannot silently select a pure ML-DSA verification flow.
    for last in [20, 32, 33, 34, 35] {
        let source = limited(100_000);
        let bytes = spki_bytes(last, Some(&[5, 0]), &[0; 32], 0);
        let key = spki(&source, &bytes);
        assert_eq!(
            algorithm::ml_dsa::resolve(key.algorithm(), &memory(0, 10)).unwrap(),
            None
        );
        assert!(
            signature::with_algorithm(key.algorithm(), &memory(0, 10), |value| value.is_none())
                .unwrap()
        );
        assert_eq!(
            ml_dsa::read(key, &memory(0, 10)).unwrap_err().code(),
            ErrorCode::UnexpectedField
        );
    }
    let bytes = tlv(48, &tlv(6, &[96, 134, 72, 1, 101, 3, 4, 3, 17, 1]));
    let source = limited(100_000);
    assert_eq!(
        algorithm::ml_dsa::resolve(id(&source, &bytes), &memory(0, 11)).unwrap(),
        None
    );
}

#[test]
fn key_framing_is_raw_exact_whole_octets_and_not_an_inner_asn1_decode() {
    // No truncation, padding or nested OCTET STRING is permitted; a raw key
    // whose leading bytes resemble ASN.1 still remains uninterpreted bytes.
    for (last, _, size, _) in SETS {
        for length in [0, size - 1, size + 1] {
            let source = limited(100_000);
            let bytes = spki_bytes(last, None, &vec![0; length], 0);
            let key = spki(&source, &bytes);
            let error = ml_dsa::read(key, &memory(0, 10)).unwrap_err();
            assert_eq!(
                (error.code(), error.offset()),
                (ErrorCode::MalformedValue, key.key_offset())
            );
        }
        let source = limited(100_000);
        let bytes = spki_bytes(last, None, &vec![0; size], 1);
        assert_eq!(
            ml_dsa::read(spki(&source, &bytes), &memory(0, 10))
                .unwrap_err()
                .code(),
            ErrorCode::MalformedValue
        );
        let wrapped = tlv(4, &vec![0; size]);
        let bytes = spki_bytes(last, None, &wrapped, 0);
        assert_eq!(
            ml_dsa::read(spki(&source, &bytes), &memory(0, 10))
                .unwrap_err()
                .code(),
            ErrorCode::MalformedValue
        );
        let mut raw = vec![0; size];
        raw[..4].copy_from_slice(&[4, 0x82, 0xff, 0xff]);
        let bytes = spki_bytes(last, None, &raw, 0);
        assert_eq!(
            ml_dsa::read(spki(&source, &bytes), &memory(0, 10))
                .unwrap()
                .as_bytes(),
            raw
        );
    }
}

#[test]
fn raw_signature_framing_never_truncates_unwraps_or_accepts_unused_bits() {
    // Framing is separate from mathematical acceptance and does not scan the
    // packed value. Malformed data must not become an unknown or empty result.
    for (_, set, _, size) in SETS {
        for length in [0, size - 1, size + 1] {
            let source = limited(100_000);
            let bytes = bits(&vec![0; length], 0);
            let signature = value(&source, &bytes);
            let error = signature.ml_dsa_in(set, &memory(0, 1)).unwrap_err();
            assert_eq!(
                (error.code(), error.field(), error.offset()),
                (
                    ErrorCode::MalformedValue,
                    "signature",
                    signature.payload_span().start
                )
            );
        }
        let source = limited(100_000);
        let bytes = bits(&vec![0; size], 1);
        let error = value(&source, &bytes)
            .ml_dsa_in(set, &memory(0, 1))
            .unwrap_err();
        assert_eq!(
            (error.code(), error.offset()),
            (ErrorCode::MalformedValue, 900)
        );
    }
}

#[test]
fn key_identity_admits_source_current_and_aggregate_before_every_outcome() {
    // New current funding must not reset source work, including unknown and
    // malformed branches. No account is cloned or storage acquired on refusal.
    for (last, parameter, source_left, current_left, aggregate, success) in [
        (17, None, 10, 10, 10, true),
        (17, None, 9, 10, 10, false),
        (17, None, 10, 9, 10, false),
        (17, None, 10, 10, 9, false),
        (32, None, 0, 10, 10, false),
        (17, Some(&[5, 0][..]), 0, 10, 10, false),
    ] {
        let source = limited(100_000);
        let bytes = spki_bytes(last, parameter, &vec![0; 1312], 0);
        let key = spki(&source, &bytes);
        leave(&source, source_left);
        let current = memory(0, aggregate);
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_work: current_left,
                ..Limits::default()
            },
            current.clone(),
        );
        let query = operation.read(&[], 9999).unwrap();
        let result = ml_dsa::read(key, &query.execution());
        if success {
            result.unwrap();
            assert_eq!(current.work_used(), 10);
            assert_eq!(source.execution_in(source.memory()).work_remaining(), 0);
        } else {
            let error = result.unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.offset(), key.algorithm().offset());
            assert_eq!(current.work_used(), 0);
        }
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn signature_metadata_admits_all_ceilings_even_before_cheap_malformed_refusal() {
    // One metadata unit must be admitted before inspecting even padding/length.
    // Equal parser/account identity must not charge that unit twice.
    for (source_left, current_left, aggregate, success) in [
        (1, 1, 1, true),
        (0, 1, 1, false),
        (1, 0, 1, false),
        (1, 1, 0, false),
    ] {
        for (length, padding) in [(2420, 0), (2420, 1), (0, 0)] {
            let source = limited(100_000);
            let bytes = bits(&vec![0; length], padding);
            let signature = value(&source, &bytes);
            leave(&source, source_left);
            let current = memory(0, aggregate);
            let operation = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: current_left,
                    ..Limits::default()
                },
                current.clone(),
            );
            let query = operation.read(&[], 8000).unwrap();
            let result = signature.ml_dsa_in(ParameterSet::MlDsa44, &query.execution());
            if success {
                if length == 2420 && padding == 0 {
                    result.unwrap();
                } else {
                    assert_eq!(result.unwrap_err().code(), ErrorCode::MalformedValue);
                }
                assert_eq!(current.work_used(), 1);
            } else {
                let error = result.unwrap_err();
                assert!(error.is_resource());
                assert_eq!((error.field(), error.offset()), ("signature", 900));
                assert_eq!(current.work_used(), 0);
            }
        }
    }
    let source = limited(100_000);
    let bytes = bits(&vec![0; 2420], 0);
    let signature = value(&source, &bytes);
    leave(&source, 1);
    let current = source.execution_in(source.memory());
    let before = source.memory().work_used();
    signature
        .ml_dsa_in(ParameterSet::MlDsa44, &current)
        .unwrap();
    assert_eq!(current.work_remaining(), 0);
    assert_eq!(source.memory().work_used(), before + 1);
}

#[test]
fn separate_key_and_signature_sources_preserve_one_current_root() {
    // Crossing from an independent key document to a signature replaces the
    // foreign-source ceiling, never a narrowed current root operation ceiling.
    let key_source = limited(100_000);
    let signature_source = limited(100_000);
    let bytes = spki_bytes(17, None, &vec![0; 1312], 0);
    let key = spki(&key_source, &bytes);
    let encoded = bits(&vec![0; 2420], 0);
    let signature = value(&signature_source, &encoded);
    leave(&key_source, 10);
    leave(&signature_source, 1);
    let current = memory(0, 1000);
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 10,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = operation.read(&[], 8000).unwrap();
    let execution = query.execution();
    let decoded = ml_dsa::read(key, &execution).unwrap();
    assert!(
        signature
            .ml_dsa_in(decoded.parameter_set(), &execution)
            .unwrap_err()
            .is_resource()
    );
    assert_eq!(current.work_used(), 10);
    assert_eq!(
        signature_source
            .execution_in(signature_source.memory())
            .work_remaining(),
        1
    );
}

fn certificate(last: u8, key_len: usize, sig_len: usize, marker: u8) -> Vec<u8> {
    let algorithm = identifier_bytes(last, None);
    let name = tlv(48, &tlv(49, &tlv(48, &[6, 3, 85, 4, 3, 12, 1, b'A'])));
    let time = tlv(23, b"261012120000Z");
    let fields = [
        vec![2, 1, 1],
        algorithm.clone(),
        name.clone(),
        tlv(48, &[time.clone(), time].concat()),
        name,
        spki_bytes(last, None, &vec![marker; key_len], 0),
    ]
    .concat();
    tlv(
        48,
        &[tlv(48, &fields), algorithm, bits(&vec![0; sig_len], 0)].concat(),
    )
}

struct Inspect<'a> {
    signed: &'a [u8],
    visits: Cell<usize>,
}
impl<W: Work> structured_pkix::path::Verify<W> for Inspect<'_> {
    type Error = structured_pkix::Error;
    fn verify(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        key: structured_pkix::path::WorkingKey<'_>,
        signed: &[u8],
        signature: SignatureValue<'_>,
        execution: &W,
    ) -> Result<structured_pkix::path::Verified, Self::Error> {
        // A structural oracle for actual path-driver wiring, not a claim that
        // all-zero synthetic signature coefficients verify mathematically.
        assert_eq!(signed.as_ptr(), self.signed.as_ptr());
        let key = ml_dsa::read(key.key(), execution)?;
        signature::with_algorithm(*algorithm, execution, |algorithm| {
            assert!(
                matches!(algorithm, Some(signature::Algorithm::MlDsa(set)) if set == key.parameter_set())
            );
        })?;
        signature.ml_dsa_in(key.parameter_set(), execution)?;
        self.visits.set(self.visits.get() + 1);
        Ok(structured_pkix::path::Verified::Yes)
    }
}

#[test]
fn supplied_path_dispatches_original_ml_dsa_structure_to_the_selected_callback() {
    // The complete certificate/path public route must preserve algorithm, key,
    // original signed bytes and signature source through its selected verifier.
    use structured_pkix::path::{
        self, Anchor, Interval, Policy, ValidationBounds, ValidationContext,
    };
    for (last, _, key_len, sig_len) in SETS {
        let leaf_bytes = certificate(last, key_len, sig_len, 1);
        let root_bytes = certificate(last, key_len, sig_len, 2);
        let source = Parser::der(memory(100_000, 1_000_000));
        let leaf = Certificate::read(&source, &leaf_bytes, 400).unwrap();
        let root = Certificate::read(&source, &root_bytes, 10000).unwrap();
        let work = memory(100_000, 1_000_000);
        let verifier = Inspect {
            signed: leaf.signed_bytes(),
            visits: Cell::new(0),
        };
        let context = ValidationContext {
            execution: &work,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &verifier,
            watch: &(),
            recognizer: &(),
        };
        let result = path::validate(
            &[&leaf],
            Anchor::new(root.tbs().subject(), root.tbs().public_key()),
            &context,
        )
        .unwrap();
        assert!(
            matches!(result, path::Validation::Accepted(_)),
            "{result:?}"
        );
        assert_eq!(verifier.visits.get(), 1);
    }
}
