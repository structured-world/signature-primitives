//! Public signature provenance through deferred decoding and verification.

use std::cell::Cell;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::signature::{DssValue, SignatureValue};
use structured_pkix::{Certificate, ErrorCode};

const PAIR: &[u8] = b"\x30\x06\x02\x01\x01\x02\x01\x02";

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

fn bits(payload: &[u8]) -> Vec<u8> {
    tlv(3, &[&[0][..], payload].concat())
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if body.len() < 128 {
        bytes.push(u8::try_from(body.len()).unwrap());
    } else {
        bytes.extend_from_slice(&[0x81, u8::try_from(body.len()).unwrap()]);
    }
    bytes.extend_from_slice(body);
    bytes
}

fn algorithm() -> Vec<u8> {
    tlv(48, &[6, 3, 42, 3, 4])
}
fn name() -> Vec<u8> {
    tlv(48, &tlv(49, &tlv(48, &[6, 3, 85, 4, 3, 12, 1, b'A'])))
}
fn date() -> Vec<u8> {
    tlv(23, b"261012120000Z")
}

fn signed_object(tbs: &[u8], payload: &[u8]) -> Vec<u8> {
    tlv(48, &[tbs, &algorithm(), &bits(payload)].concat())
}

fn certificate(payload: &[u8]) -> Vec<u8> {
    certificate_with_key(payload, 7)
}

fn certificate_with_key(payload: &[u8], key: u8) -> Vec<u8> {
    let tbs = tlv(
        48,
        &[
            vec![2, 1, 1],
            algorithm(),
            name(),
            tlv(48, &[date(), date()].concat()),
            name(),
            tlv(48, &[algorithm(), bits(&[key])].concat()),
        ]
        .concat(),
    );
    signed_object(&tbs, payload)
}

fn response(payload: &[u8]) -> Vec<u8> {
    let time = tlv(24, b"20261012120000Z");
    let id = tlv(
        48,
        &[
            algorithm(),
            tlv(4, &[1; 20]),
            tlv(4, &[2; 20]),
            tlv(2, &[1]),
        ]
        .concat(),
    );
    let assertion = tlv(48, &[id, tlv(0x80, &[]), time.clone()].concat());
    let data = tlv(
        48,
        &[tlv(0xa1, &name()), time, tlv(48, &assertion)].concat(),
    );
    let basic = signed_object(&data, payload);
    let carriage = tlv(
        48,
        &[tlv(6, &[43, 6, 1, 5, 5, 7, 48, 1, 1]), tlv(4, &basic)].concat(),
    );
    tlv(48, &[vec![10, 1, 0], tlv(0xa0, &carriage)].concat())
}

fn pair<'a, W: Work>(
    signature: SignatureValue<'a>,
    work: &W,
) -> structured_pkix::Result<DssValue<'a>> {
    DssValue::read(&mut signature.reader_in(work)?, "signature.pair")
}

#[test]
fn all_three_carriers_keep_original_windows_without_payload_ownership() {
    // Cert/CRL/OCSP must capture provenance at their first BIT STRING read.
    // Decoder results survive the short query, borrowing only original bytes.
    let source_work = memory(100_000, 1_000_000);
    let source = Parser::ber(source_work.clone());
    let cert_bytes = certificate(PAIR);
    let cert = Certificate::read(&source, &cert_bytes, 400).unwrap();
    let crl_bytes = signed_object(&tlv(48, &[algorithm(), name(), date()].concat()), PAIR);
    let crl = structured_pkix::crl::CertificateList::read(&source, &crl_bytes, 800).unwrap();
    let response_bytes = response(PAIR);
    let structured_pkix::ocsp::Response::Successful(envelope) =
        structured_pkix::ocsp::Response::read(&source, &response_bytes, 1200).unwrap()
    else {
        panic!("success");
    };
    let basic = envelope.into_basic(&source_work).unwrap().unwrap();
    for (signature, raw, bytes, base) in [
        (cert.signature_value(), cert.signature(), &cert_bytes, 400),
        (crl.signature_value(), crl.signature(), &crl_bytes, 800),
        (
            basic.signature_value(),
            basic.signature(),
            &response_bytes,
            1200,
        ),
    ] {
        assert_eq!(signature.bit_string(), raw);
        let offset = bytes
            .windows(PAIR.len())
            .position(|window| window == PAIR)
            .unwrap();
        assert_eq!(
            signature.octets().unwrap().as_ptr(),
            bytes[offset..].as_ptr()
        );
        assert_eq!(signature.payload_span().start, base + offset as u64);
        assert_eq!(signature.span().end(), signature.payload_span().end());
        let held = source_work.used();
        let value = {
            let current = memory(16, 4096);
            let operation = Parser::der(current.clone());
            let query = operation.read(&[], 9000).unwrap();
            let value = pair(signature, &query.execution()).unwrap();
            assert_eq!(current.used(), 0);
            assert_eq!(source_work.used(), held);
            value
        };
        assert_eq!(
            value.element().as_bytes().as_ptr(),
            bytes[offset..].as_ptr()
        );
        assert_eq!(value.r_span().start, base + offset as u64 + 2);
        assert_eq!(value.s().as_u64(), Some(2));
    }
}

#[test]
fn raw_access_needs_no_cursor_and_padded_bits_never_open_one() {
    // Raw EdDSA/RSA/PQ do not pay for an unnecessary ASN.1 decode. Padded
    // inspection data cannot silently become a complete-octet signature.
    let encoded = bits(PAIR);
    let source = Parser::der(memory(0, 4096));
    let signature =
        SignatureValue::read(&mut source.read(&encoded, 400).unwrap(), "original").unwrap();
    let stopped = memory(0, 0);
    assert_eq!(signature.octets(), Some(PAIR));
    assert_eq!(stopped.work_used(), 0);
    // Constructing a Memory-funded empty cursor scans no input. The first
    // actual DER read must refuse before inspecting the signature bytes.
    assert!(pair(signature, &stopped).unwrap_err().is_resource());
    let padded = [3, 2, 1, 2];
    let signature =
        SignatureValue::read(&mut source.read(&padded, 700).unwrap(), "padded").unwrap();
    assert_eq!(signature.bit_string().unused_bits(), 1);
    assert_eq!(signature.octets(), None);
    let error = signature.reader_in(&stopped).unwrap_err();
    assert_eq!(
        (error.code(), error.field(), error.offset()),
        (ErrorCode::MalformedValue, "padded", 700)
    );
    assert_eq!(stopped.work_used(), 0);
}

fn deferred(
    local: u64,
    aggregate: usize,
    source_limit: u64,
) -> (structured_pkix::Result<()>, usize) {
    let encoded = bits(PAIR);
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: source_limit,
            ..Limits::default()
        },
        memory(16, 4096),
    );
    let signature =
        SignatureValue::read(&mut source.read(&encoded, 400).unwrap(), "original").unwrap();
    let current = memory(16, aggregate);
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_work: local,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = operation.read(&[], 900).unwrap();
    let result = pair(signature, &query.execution()).map(|_| ());
    assert_eq!(current.used(), 0);
    (result, current.work_used())
}

#[test]
fn original_current_and_aggregate_work_are_cumulative_and_exact() {
    // A freshly funded operation cannot reset origin work; a generous origin
    // cannot bypass the current root or aggregate account. Refusal is terminal.
    let (result, cost) = deferred(4096, 4096, 4096);
    result.unwrap();
    deferred(cost as u64, cost, 4096).0.unwrap();
    for (local, aggregate) in [
        (0, 4096),
        (cost as u64 - 1, 4096),
        (4096, 0),
        (4096, cost - 1),
    ] {
        assert!(
            deferred(local, aggregate, 4096)
                .0
                .unwrap_err()
                .is_resource()
        );
    }
    let encoded = bits(PAIR);
    let meter = memory(16, 4096);
    let source = Parser::der(meter.clone());
    SignatureValue::read(&mut source.read(&encoded, 400).unwrap(), "original").unwrap();
    let parse_cost = meter.work_used();
    assert!(
        deferred(4096, 4096, parse_cost as u64)
            .0
            .unwrap_err()
            .is_resource()
    );
    deferred(4096, 4096, (parse_cost + cost) as u64).0.unwrap();
}

#[test]
fn original_and_current_depth_and_scratch_are_enforced() {
    // The BIT STRING is a real carrier level; its DER SEQUENCE adds another.
    // Neither decoding under a new operation nor a fresh account resets depth.
    let encoded = bits(PAIR);
    for (source_depth, query_depth, success) in [(1, 20, false), (20, 1, false), (2, 2, true)] {
        let source = Parser::new(
            Encoding::Der,
            Limits {
                max_depth: source_depth,
                ..Limits::default()
            },
            memory(16, 4096),
        );
        let signature =
            SignatureValue::read(&mut source.read(&encoded, 400).unwrap(), "original").unwrap();
        let current = memory(16, 4096);
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_depth: query_depth,
                ..Limits::default()
            },
            current.clone(),
        );
        let query = operation.read(&[], 900).unwrap();
        let result = pair(signature, &query.execution());
        if success {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().is_resource());
        }
        assert_eq!(current.used(), 0);
    }
    let source = Parser::der(memory(0, 4096));
    let signature =
        SignatureValue::read(&mut source.read(&encoded, 400).unwrap(), "original").unwrap();
    for storage in [0, 15, 16] {
        let current = memory(storage, 4096);
        let result = pair(signature, &current);
        if storage == 16 {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().is_resource());
        }
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn deferred_der_faults_retain_the_original_payload_location() {
    // BER on the carrier never relaxes DSS DER or discards trailing bytes.
    for payload in [
        &b"\x30\x81\x06\x02\x01\x01\x02\x01\x02"[..],
        &b"\x30\x06\x02\x01\x01\x02\x01\x02\x05\x00"[..],
    ] {
        let encoded = bits(payload);
        let source = Parser::ber(memory(16, 4096));
        let signature =
            SignatureValue::read(&mut source.read(&encoded, 400).unwrap(), "original").unwrap();
        let error = pair(signature, &memory(16, 4096)).unwrap_err();
        assert!(!error.is_resource());
        assert!(error.offset() >= 403);
        assert_eq!(error.field(), "signature.pair");
    }
}

struct Inspect(Cell<usize>);
impl<W: Work> structured_pkix::path::Verify<W> for Inspect {
    type Error = structured_pkix::Error;
    fn verify(
        &self,
        _: &structured_pkix::AlgorithmIdentifier<'_>,
        _: structured_pkix::path::WorkingKey<'_>,
        _: &[u8],
        signature: SignatureValue<'_>,
        work: &W,
    ) -> Result<structured_pkix::path::Verified, Self::Error> {
        self.0.set(self.0.get() + 1);
        assert_eq!(pair(signature, work)?.r().as_u64(), Some(1));
        Ok(structured_pkix::path::Verified::Yes)
    }
}

struct Exhaust;
impl<W: Work> structured_pkix::path::Verify<W> for Exhaust {
    type Error = structured_pkix::Error;
    fn verify(
        &self,
        _: &structured_pkix::AlgorithmIdentifier<'_>,
        _: structured_pkix::path::WorkingKey<'_>,
        _: &[u8],
        signature: SignatureValue<'_>,
        work: &W,
    ) -> Result<structured_pkix::path::Verified, Self::Error> {
        work.charge_work(work.work_remaining() as u64).unwrap();
        pair(signature, work)?;
        panic!("an exhausted decode cannot succeed")
    }
}

#[test]
fn supplied_and_constructed_path_callbacks_receive_the_same_source_descriptor() {
    // Both path drivers must preserve the descriptor, rather than one silently
    // projecting it back to BitString. This oracle tests wiring, not arithmetic.
    use structured_pkix::path::{
        self, Anchor, Interval, Policy, ValidationBounds, ValidationContext,
    };
    let bytes = certificate(PAIR);
    let current = memory(100_000, 1_000_000);
    let source = Parser::der(current.clone());
    let cert = Certificate::read(&source, &bytes, 400).unwrap();
    let root_bytes = certificate_with_key(PAIR, 8);
    let root = Certificate::read(&source, &root_bytes, 800).unwrap();
    let verifier = Inspect(Cell::new(0));
    let context = ValidationContext {
        execution: &current,
        interval: Interval::at(cert.tbs().validity().not_before().seconds()),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let anchor = Anchor::new(root.tbs().subject(), root.tbs().public_key());
    let result = path::validate(&[&cert], anchor, &context).unwrap();
    assert!(
        matches!(result, path::Validation::Accepted(_)),
        "{result:?}"
    );
    assert_eq!(verifier.0.get(), 1);
    let anchors = [anchor];
    let context = path::Context {
        execution: &current,
        anchors: &anchors,
        interval: context.interval,
        policy: Policy::default(),
        bounds: path::Bounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let built = path::build(&cert, &[], &context).unwrap();
    assert_eq!(built.paths().len(), 1);
    assert_eq!(verifier.0.get(), 2);
}

#[test]
fn crl_authentication_dispatches_original_signature_context() {
    // CRL authentication must preserve the same descriptor after issuer/key
    // gates; a schema-only direct getter test cannot prove callback wiring.
    let current = memory(100_000, 1_000_000);
    let source = Parser::der(current.clone());
    let issuer_bytes = certificate(PAIR);
    let issuer = Certificate::read(&source, &issuer_bytes, 400).unwrap();
    let bytes = signed_object(&tlv(48, &[algorithm(), name(), date()].concat()), PAIR);
    let crl = structured_pkix::crl::CertificateList::read(&source, &bytes, 800).unwrap();
    let verifier = Inspect(Cell::new(0));
    let answer = crl
        .authenticate(
            &issuer,
            structured_pkix::path::WorkingKey::standing(issuer.tbs().public_key()),
            &verifier,
            &current,
        )
        .unwrap();
    assert!(matches!(
        answer,
        structured_pkix::crl::Authentication::Authenticated(_)
    ));
    assert_eq!(verifier.0.get(), 1);
}

#[test]
fn real_ecdsa_uses_original_carried_scalars_without_a_second_der_parser() {
    // Test-only fixed-curve engine: common DssValue owns DER decoding, the
    // backend receives scalar arrays and checks actual signature arithmetic.
    // This is interoperability evidence, not opaque backend cost qualification.
    use p256::ecdsa::{
        Signature, SigningKey,
        signature::{Signer, Verifier},
    };
    let key = SigningKey::from_slice(&[3; 32]).unwrap();
    let message = b"original signed bytes";
    let signed: Signature = key.sign(message);
    let encoded = certificate(signed.to_der().as_bytes());
    let source = Parser::der(memory(100_000, 1_000_000));
    let certificate = Certificate::read(&source, &encoded, 400).unwrap();
    let current = memory(16, 4096);
    let decoded = pair(certificate.signature_value(), &current).unwrap();
    let scalar = |integer: structured_asn1::Integer<'_>| {
        assert!(!integer.is_negative());
        let original = integer.as_bytes();
        let bytes = match original {
            [0, rest @ ..] => rest,
            all => all,
        };
        assert!(bytes.len() <= 32);
        current.charge_work((32 + bytes.len()) as u64).unwrap();
        let mut output = [0; 32];
        output[32 - bytes.len()..].copy_from_slice(bytes);
        output
    };
    let signature = Signature::from_scalars(scalar(decoded.r()), scalar(decoded.s())).unwrap();
    key.verifying_key().verify(message, &signature).unwrap();
    assert!(
        key.verifying_key()
            .verify(b"changed signed bytes", &signature)
            .is_err()
    );
    assert_eq!(
        decoded.element().as_bytes().as_ptr(),
        certificate.signature().octets().unwrap().as_ptr()
    );
    assert_eq!(current.used(), 0);
}

#[test]
fn callback_decode_failures_stay_errors_for_path_and_crl_authentication() {
    // An opaque malformed signature is discovered by the selected decoder.
    // Neither driver may collapse that callback failure into No/Unsupported.
    use structured_pkix::path::{
        self, Anchor, Interval, Policy, ValidationBounds, ValidationContext,
    };
    let encoded = certificate(b"\x30\x03\x02\x01\x01");
    let root_bytes = certificate_with_key(PAIR, 8);
    let current = memory(100_000, 1_000_000);
    let source = Parser::der(current.clone());
    let certificate = Certificate::read(&source, &encoded, 400).unwrap();
    let root = Certificate::read(&source, &root_bytes, 800).unwrap();
    let verifier = Inspect(Cell::new(0));
    let context = ValidationContext {
        execution: &current,
        interval: Interval::at(certificate.tbs().validity().not_before().seconds()),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let error = path::validate(
        &[&certificate],
        Anchor::new(root.tbs().subject(), root.tbs().public_key()),
        &context,
    )
    .unwrap_err();
    assert!(
        matches!(error, path::BuildError::Verification(error) if !error.is_resource() && error.offset() == certificate.signature_value().payload_span().end())
    );
    let bytes = signed_object(
        &tlv(48, &[algorithm(), name(), date()].concat()),
        b"\x30\x03\x02\x01\x01",
    );
    let crl = structured_pkix::crl::CertificateList::read(&source, &bytes, 1200).unwrap();
    let error = crl
        .authenticate(
            &root,
            path::WorkingKey::standing(root.tbs().public_key()),
            &verifier,
            &current,
        )
        .unwrap_err();
    assert!(
        matches!(error, structured_pkix::error::CallbackError::Callback(error) if !error.is_resource() && error.offset() == crl.signature_value().payload_span().end())
    );
    let current = memory(100_000, 1_000_000);
    let context = ValidationContext {
        execution: &current,
        verifier: &Exhaust,
        interval: context.interval,
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        watch: &(),
        recognizer: &(),
    };
    let error = path::validate(
        &[&certificate],
        Anchor::new(root.tbs().subject(), root.tbs().public_key()),
        &context,
    )
    .unwrap_err();
    assert!(
        matches!(error, path::BuildError::Verification(error) if error.is_resource() && error.offset() == certificate.signature_value().payload_span().start)
    );
    let current = memory(100_000, 1_000_000);
    let error = crl
        .authenticate(
            &root,
            path::WorkingKey::standing(root.tbs().public_key()),
            &Exhaust,
            &current,
        )
        .unwrap_err();
    assert!(
        matches!(error, structured_pkix::error::CallbackError::Callback(error) if error.is_resource() && error.offset() == crl.signature_value().payload_span().start)
    );
}
