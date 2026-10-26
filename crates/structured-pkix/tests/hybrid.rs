//! Independent BC vectors, exact transformed inputs and source/current refusals.
use ml_dsa::signature::digest::Update;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use std::cell::Cell;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Parser, Span};
use structured_pkix::hybrid::{self, Alternative, AlternativeVerifier, Preimage, Requirement};
use structured_pkix::path::{
    self, Anchor, Interval, Policy, ValidationBounds, ValidationContext, Verified, Verify,
    WorkingKey,
};
use structured_pkix::signature::SignatureValue;
use structured_pkix::{AlgorithmIdentifier, Certificate, PublicKeyInfo};

const CERT: &[u8] = include_bytes!("data/hybrid/certificate.der");
const ROOT: &[u8] = include_bytes!("data/hybrid/root.der");
const CRL: &[u8] = include_bytes!("data/hybrid/crl.der");
const REQUEST: &[u8] = include_bytes!("data/hybrid/request.der");
const CERT_INPUT: &[u8] = include_bytes!("data/hybrid/certificate-preimage.der");
const CRL_INPUT: &[u8] = include_bytes!("data/hybrid/crl-preimage.der");
const REQUEST_INPUT: &[u8] = include_bytes!("data/hybrid/request-preimage.der");

fn memory(bytes: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(bytes, work)))
}
fn ample() -> Memory {
    memory(16_000_000, 100_000_000)
}
struct Native;
impl<W: Work> Verify<W> for Native {
    type Error = structured_pkix::Error;
    fn verify(
        &self,
        _: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        signed: &[u8],
        signature: SignatureValue<'_>,
        work: &W,
    ) -> Result<Verified, Self::Error> {
        key.key().execution_in(work).charge_work(1).unwrap();
        signature
            .execution_in(work)
            .charge_work(signed.len() as u64)
            .unwrap();
        let key = VerifyingKey::from_sec1_bytes(key.key().key_octets().unwrap()).unwrap();
        let signature = DerSignature::from_bytes(signature.octets().unwrap()).unwrap();
        Ok(if key.verify(signed, &signature).is_ok() {
            Verified::Yes
        } else {
            Verified::No
        })
    }
}
struct Pq {
    calls: Cell<usize>,
}
impl Pq {
    fn new() -> Self {
        Self {
            calls: Cell::new(0),
        }
    }
}
impl<W: Work> AlternativeVerifier<W> for Pq {
    type Error = &'static str;
    fn verify(
        &self,
        _: AlgorithmIdentifier<'_>,
        key: PublicKeyInfo<'_>,
        input: &Preimage<'_>,
        signature: SignatureValue<'_>,
        work: &W,
    ) -> Result<Verified, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        key.execution_in(work)
            .charge_work(key.key_octets().unwrap().len() as u64)
            .map_err(|_| "key budget")?;
        let raw: &ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa65> = key
            .key_octets()
            .unwrap()
            .try_into()
            .map_err(|_| "key width")?;
        let key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(raw);
        let signature = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature.octets().unwrap())
            .map_err(|_| "packed signature")?;
        // FIPS204's pure-mode domain separator and empty context are handled
        // by compute_mu. Stream the original message without joining it.
        let mu = key
            .compute_mu(
                |state| {
                    input
                        .visit(work, |bytes, _, execution| {
                            execution
                                .charge_work(bytes.len() as u64)
                                .map_err(|_| ml_dsa::Error::new())?;
                            state.update(bytes);
                            Ok::<(), ml_dsa::Error>(())
                        })
                        .map_err(|_| ml_dsa::Error::new())
                },
                &[],
            )
            .map_err(|_| "input budget")?;
        Ok(if key.verify_mu(&mu, &signature) {
            Verified::Yes
        } else {
            Verified::No
        })
    }
}
fn collect(input: &Preimage<'_>, work: &Memory) -> Vec<u8> {
    let mut bytes = Vec::new();
    input
        .visit(work, |chunk, _, _| {
            bytes.extend_from_slice(chunk);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(bytes.len() as u64, input.encoded_len());
    bytes
}

#[test]
fn bouncy_castle_preimages_and_both_mathematical_signatures() {
    // BC independently captures and signs the transformed inputs for all three schemas.
    let work = ample();
    let parser = Parser::der(work.clone());
    let root = Certificate::read(&parser, ROOT, 100).unwrap();
    let cert = Certificate::read(&parser, CERT, 500).unwrap();
    let crl = structured_pkix::crl::CertificateList::read(&parser, CRL, 900).unwrap();
    let request = hybrid::request::Request::read(&parser, REQUEST, 1200).unwrap();
    let alt = hybrid::inspect_certificate(&root, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    assert_eq!(
        collect(
            hybrid::prepare_certificate(&cert, &work)
                .unwrap()
                .preimage(),
            &work
        ),
        CERT_INPUT
    );
    assert_eq!(
        collect(hybrid::prepare_crl(&crl, &work).unwrap().preimage(), &work),
        CRL_INPUT
    );
    assert_eq!(
        collect(request.prepare(&work).unwrap().preimage(), &work),
        REQUEST_INPUT
    );
    let pq = Pq::new();
    let key = WorkingKey::standing(root.tbs().public_key());
    let cert = hybrid::check_certificate(&cert, key, alt, &Native, &pq, &work).unwrap();
    let crl = hybrid::check_crl(&crl, key, alt, &Native, &pq, &work).unwrap();
    let request = request.check(&Native, &pq, &work).unwrap();
    for pair in [cert, crl, request] {
        assert!(Requirement::Both.accepts(pair));
    }
    assert_eq!(pq.calls.get(), 3);
}

struct Answer(Verified);
impl<W: Work> Verify<W> for Answer {
    type Error = ();
    fn verify(
        &self,
        _: &AlgorithmIdentifier<'_>,
        _: WorkingKey<'_>,
        _: &[u8],
        _: SignatureValue<'_>,
        _: &W,
    ) -> Result<Verified, ()> {
        Ok(self.0)
    }
}

#[test]
fn alternative_path_survives_native_no_but_both_policy_does_not() {
    // The same shared constraints run in both modes; native No cannot veto required PQ alone.
    let work = ample();
    let parser = Parser::der(work.clone());
    let root = Certificate::read(&parser, ROOT, 100).unwrap();
    let leaf = Certificate::read(&parser, CERT, 500).unwrap();
    let alt = hybrid::inspect_certificate(&root, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    let anchor = path::hybrid::HybridAnchor {
        native: Anchor::from_certificate(&root),
        alternative: alt,
    };
    for requirement in [Requirement::Alternative, Requirement::Both] {
        let native = Answer(Verified::No);
        let pq = Pq::new();
        let context = ValidationContext {
            execution: &work,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &native,
            watch: &(),
            recognizer: &(),
        };
        let result = path::hybrid::validate(&[&leaf], anchor, &context, requirement, &pq).unwrap();
        assert_eq!(result.signatures()[0].position, 0);
        assert_eq!(result.signatures()[0].source, leaf.span());
        let pair = result.signatures()[0].signatures.unwrap();
        assert_eq!(pair.native, Verified::No);
        assert_eq!(pair.alternative, Alternative::Verified(Verified::Yes));
        assert_eq!(
            matches!(result.outcome, path::Validation::Accepted(_)),
            requirement == Requirement::Alternative
        );
    }
}

#[test]
fn preimage_ranges_borrow_original_input_and_callback_failure_stops() {
    // Only DER headers are new; each reported source span maps back to identical received bytes.
    let work = ample();
    let parser = Parser::der(work.clone());
    let cert = Certificate::read(&parser, CERT, 400).unwrap();
    let prepared = hybrid::prepare_certificate(&cert, &work).unwrap();
    prepared
        .preimage()
        .visit(&work, |bytes, span, _| {
            if let Some(Span { start, length }) = span {
                let start = usize::try_from(start - 400).unwrap();
                assert_eq!(
                    bytes,
                    &CERT[start..start + usize::try_from(length).unwrap()]
                );
                assert!(core::ptr::eq(
                    bytes.as_ptr(),
                    cert.as_bytes()[start..].as_ptr()
                ));
            }
            Ok::<(), ()>(())
        })
        .unwrap();
    let mut calls = 0;
    let error = prepared
        .preimage()
        .visit(&work, |_, _, _| {
            calls += 1;
            Err::<(), _>("stop")
        })
        .unwrap_err();
    assert!(matches!(
        error,
        structured_pkix::error::CallbackError::Callback("stop")
    ));
    assert_eq!(calls, 1);
    let refusal = prepared
        .preimage()
        .visit(&memory(0, 0), |_, _, _| -> Result<(), ()> {
            panic!("unfunded callback")
        });
    assert!(
        matches!(refusal,Err(structured_pkix::error::CallbackError::Processing(ref e)) if e.is_resource())
    );
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    result.extend(structured_asn1::length::DerLength::new(contents.len() as u64).as_bytes());
    result.extend(contents);
    result
}
fn children(bytes: &[u8]) -> Vec<Vec<u8>> {
    let parser = Parser::der(ample());
    let mut reader = parser.read(bytes, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let mut inside = reader.enter(&element).unwrap();
    let mut output = Vec::new();
    while let Some(value) = inside.next_element().unwrap() {
        output.push(value.as_bytes().to_vec());
    }
    output
}
fn alter_extension(kind: u8, change: impl FnOnce(&mut Vec<Vec<u8>>)) -> Vec<u8> {
    let mut outer = children(CERT);
    let mut tbs = children(&outer[0]);
    let wrapper = children(tbs.last().unwrap());
    let mut extensions = children(&wrapper[0]);
    let index = extensions
        .iter()
        .position(|value| children(value)[0] == tlv(6, &[0x55, 0x1d, kind]))
        .unwrap();
    let mut extension = children(&extensions[index]);
    change(&mut extension);
    if extension.is_empty() {
        extensions.remove(index);
    } else {
        extensions[index] = tlv(48, &extension.concat());
    }
    *tbs.last_mut().unwrap() = tlv(0xa3, &tlv(48, &extensions.concat()));
    outer[0] = tlv(48, &tbs.concat());
    tlv(48, &outer.concat())
}

#[test]
fn missing_malformed_and_substituted_alternatives_never_become_native_success() {
    // Missing, padding and wrong widths are conformance; changed signed algorithm fails PQ math.
    let variants = [
        alter_extension(74, Vec::clear),
        alter_extension(74, |e| {
            *e.last_mut().unwrap() = tlv(4, &tlv(3, &[0]));
        }),
        alter_extension(73, |e| {
            *e.last_mut().unwrap() = tlv(4, &tlv(48, &tlv(6, &[0x2a, 3, 4])));
        }),
    ];
    for (i, bytes) in variants.iter().enumerate() {
        let work = ample();
        let parser = Parser::der(work.clone());
        let root = Certificate::read(&parser, ROOT, 100).unwrap();
        let cert = Certificate::read(&parser, bytes, 400).unwrap();
        let alt = hybrid::inspect_certificate(&root, &work)
            .unwrap()
            .key
            .reading()
            .unwrap()
            .unwrap();
        let pq = Pq::new();
        let result = hybrid::check_certificate(
            &cert,
            WorkingKey::standing(root.tbs().public_key()),
            alt,
            &Answer(Verified::Yes),
            &pq,
            &work,
        )
        .unwrap();
        assert_eq!(result.native, Verified::Yes);
        assert!(!Requirement::Both.accepts(result));
        if i < 2 {
            assert!(matches!(result.alternative, Alternative::Nonconforming(_)));
            assert_eq!(pq.calls.get(), 0);
        } else {
            assert_eq!(result.alternative, Alternative::Verified(Verified::No));
        }
    }
}

#[test]
fn alternative_issuer_key_is_not_the_subject_key() {
    // A valid, correctly framed but unrelated subject key must not authenticate its issuer's signature.
    let work = ample();
    let parser = Parser::der(work.clone());
    let root = Certificate::read(&parser, ROOT, 0).unwrap();
    let cert = Certificate::read(&parser, CERT, 500).unwrap();
    let subject_key = hybrid::inspect_certificate(&cert, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    let pq = Pq::new();
    let pair = hybrid::check_certificate(
        &cert,
        WorkingKey::standing(root.tbs().public_key()),
        subject_key,
        &Native,
        &pq,
        &work,
    )
    .unwrap();
    assert_eq!(pair.native, Verified::Yes);
    assert_eq!(pair.alternative, Alternative::Verified(Verified::No));
}

#[test]
fn origin_exhaustion_and_retained_preimage_are_not_reset_by_new_work() {
    // Current work pays the new query, while the producing parser's cumulative
    // local ceiling remains binding independently of the old aggregate account.
    let source = ample();
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 1_000_000,
            ..structured_asn1::Limits::default()
        },
        source.clone(),
    );
    let cert = Certificate::read(&parser, CERT, 900).unwrap();
    let current = ample();
    let prepared = hybrid::prepare_certificate(&cert, &current).unwrap();
    let original = source.execution_for(&parser);
    original
        .charge_work(original.work_remaining() as u64)
        .unwrap();
    let mut calls = 0;
    let error = prepared
        .preimage()
        .visit(&ample(), |_, _, _| {
            calls += 1;
            Ok::<(), ()>(())
        })
        .unwrap_err();
    assert_eq!(calls, 0);
    assert!(
        matches!(error,structured_pkix::error::CallbackError::Processing(ref e) if e.is_resource())
    );
}

#[test]
fn oversized_and_truncated_ml_dsa_values_are_refused_before_provider() {
    // Fixed-width framing is shared with native ML-DSA, before any backend state or math.
    for width in [3308, 3310] {
        let bytes = alter_extension(74, |extension| {
            let mut raw = vec![0; 1 + width];
            raw[0] = 0;
            *extension.last_mut().unwrap() = tlv(4, &tlv(3, &raw));
        });
        let work = ample();
        let parser = Parser::der(work.clone());
        let root = Certificate::read(&parser, ROOT, 0).unwrap();
        let cert = Certificate::read(&parser, &bytes, 500).unwrap();
        let key = hybrid::inspect_certificate(&root, &work)
            .unwrap()
            .key
            .reading()
            .unwrap()
            .unwrap();
        let pq = Pq::new();
        let pair = hybrid::check_certificate(
            &cert,
            WorkingKey::standing(root.tbs().public_key()),
            key,
            &Answer(Verified::Yes),
            &pq,
            &work,
        )
        .unwrap();
        assert!(matches!(pair.alternative, Alternative::Nonconforming(_)));
        assert_eq!(pq.calls.get(), 0);
    }
}

#[test]
fn malformed_component_inspection_keeps_native_and_original_bytes() {
    // Readable extension faults are located inspection data, never valid provider inputs.
    let bytes = alter_extension(73, |e| {
        *e.last_mut().unwrap() = tlv(4, &[5, 0]);
    });
    let work = ample();
    let parser = Parser::der(work.clone());
    let cert = Certificate::read(&parser, &bytes, 400).unwrap();
    let inspected = hybrid::inspect_certificate(&cert, &work).unwrap();
    assert_eq!(inspected.algorithm.as_bytes(), Some([5, 0].as_slice()));
    let fault = inspected.algorithm.reading().unwrap_err().error();
    assert!(fault.offset() >= 400);
    assert!(inspected.key.reading().unwrap().is_some());
    assert!(inspected.signature.reading().unwrap().is_some());
}

#[test]
fn missing_native_field_is_not_an_alternative_only_encoding() {
    // Alternative-only mathematics is a policy choice, not permission to omit required ASN.1 fields.
    let work = ample();
    let parser = Parser::der(work);
    let mut cert = children(CERT);
    cert.pop();
    assert!(Certificate::read(&parser, &tlv(48, &cert.concat()), 0).is_err());
    let mut request = children(REQUEST);
    request.pop();
    assert!(hybrid::request::Request::read(&parser, &tlv(48, &request.concat()), 0).is_err());
}

#[test]
fn csr_attribute_order_duplicates_and_cardinality_are_enforced() {
    // Removing the alternative attribute does not authorize input SET reordering or duplicate identities.
    let outer = children(REQUEST);
    let cri = children(&outer[0]);
    let attrs = children(&cri[3]);
    for variant in 0..3 {
        let mut modified = attrs.clone();
        if variant == 0 {
            modified.swap(0, 1);
        } else if variant == 1 {
            modified.push(modified[0].clone());
            modified.sort();
        } else {
            let mut attribute = children(&modified[0]);
            let values = children(&attribute[1]);
            attribute[1] = tlv(0x31, &[values[0].clone(), values[0].clone()].concat());
            modified[0] = tlv(48, &attribute.concat());
            modified.sort();
        }
        let mut new_cri = cri.clone();
        new_cri[3] = tlv(0xa0, &modified.concat());
        let mut new_outer = outer.clone();
        new_outer[0] = tlv(48, &new_cri.concat());
        let bytes = tlv(48, &new_outer.concat());
        let parser = Parser::der(ample());
        let result = hybrid::request::Request::read(&parser, &bytes, 800);
        if variant < 2 {
            assert!(result.is_err());
        } else {
            let result = result.unwrap();
            assert!(result.prepare(&ample()).is_err());
            assert_eq!(result.attributes().len(), 3);
        }
    }
}

#[test]
fn hybrid_path_shares_duplicate_and_local_bounds_preflight() {
    // No duplicate path, exhausted local work or depth bound can reach either verifier.
    let work = ample();
    let parser = Parser::der(work.clone());
    let root = Certificate::read(&parser, ROOT, 0).unwrap();
    let leaf = Certificate::read(&parser, CERT, 800).unwrap();
    let alternative = hybrid::inspect_certificate(&root, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    for bounds in [
        ValidationBounds {
            work: 0,
            ..ValidationBounds::default()
        },
        ValidationBounds {
            depth: 0,
            ..ValidationBounds::default()
        },
        ValidationBounds::default(),
    ] {
        let native = Answer(Verified::Yes);
        let pq = Pq::new();
        let context = ValidationContext {
            execution: &work,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: Policy::default(),
            bounds,
            verifier: &native,
            watch: &(),
            recognizer: &(),
        };
        let anchor = path::hybrid::HybridAnchor {
            native: Anchor::from_certificate(&root),
            alternative,
        };
        let result =
            path::hybrid::validate(&[&leaf, &leaf], anchor, &context, Requirement::Both, &pq)
                .unwrap();
        assert!(!matches!(result.outcome, path::Validation::Accepted(_)));
        assert_eq!(pq.calls.get(), 0);
    }
}

#[test]
fn unknown_critical_extension_still_blocks_the_shared_path_processor() {
    // Understanding hybrid extensions does not waive any unrelated critical demand.
    let mut outer = children(CERT);
    let mut tbs = children(&outer[0]);
    let wrapped = children(tbs.last().unwrap());
    let mut extensions = children(&wrapped[0]);
    extensions.push(tlv(
        48,
        &[tlv(6, &[0x2a, 3, 4, 5]), tlv(1, &[0xff]), tlv(4, &[5, 0])].concat(),
    ));
    *tbs.last_mut().unwrap() = tlv(0xa3, &tlv(48, &extensions.concat()));
    outer[0] = tlv(48, &tbs.concat());
    let bytes = tlv(48, &outer.concat());
    let work = ample();
    let parser = Parser::der(work.clone());
    let root = Certificate::read(&parser, ROOT, 0).unwrap();
    let cert = Certificate::read(&parser, &bytes, 500).unwrap();
    let alternative = hybrid::inspect_certificate(&root, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    let native = Answer(Verified::Yes);
    let pq = Pq::new();
    let context = ValidationContext {
        execution: &work,
        interval: Interval::at(cert.tbs().validity().not_before().seconds()),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &native,
        watch: &(),
        recognizer: &(),
    };
    let result = path::hybrid::validate(
        &[&cert],
        path::hybrid::HybridAnchor {
            native: Anchor::from_certificate(&root),
            alternative,
        },
        &context,
        Requirement::Alternative,
        &pq,
    )
    .unwrap();
    assert!(matches!(
        result.outcome,
        path::Validation::Rejected(path::Rejection {
            reason: path::RejectionReason::CriticalExtension(_),
            ..
        })
    ));
    assert_eq!(pq.calls.get(), 0);
    assert!(result.signatures()[0].signatures.is_none());
}

struct Unsupported;
impl<W: Work> AlternativeVerifier<W> for Unsupported {
    type Error = ();
    fn verify(
        &self,
        _: AlgorithmIdentifier<'_>,
        _: PublicKeyInfo<'_>,
        _: &Preimage<'_>,
        _: SignatureValue<'_>,
        _: &W,
    ) -> Result<Verified, ()> {
        Ok(Verified::Unsupported)
    }
}

struct PositiveAlternative;
impl<W: Work> AlternativeVerifier<W> for PositiveAlternative {
    type Error = ();
    fn verify(
        &self,
        _: AlgorithmIdentifier<'_>,
        _: PublicKeyInfo<'_>,
        _: &Preimage<'_>,
        _: SignatureValue<'_>,
        _: &W,
    ) -> Result<Verified, ()> {
        Ok(Verified::Yes)
    }
}
#[test]
fn critical_unknown_subject_key_cannot_be_understood_by_oid_alone() {
    // Controlled math isolates critical-extension enforcement: a known
    // extension OID cannot vouch for an unknown alternative key algorithm.
    let bytes = alter_extension(72, |extension| {
        let mut spki = {
            let parser = Parser::der(ample());
            let mut reader = parser.read(extension.last().unwrap(), 0).unwrap();
            let octets = reader.next_element().unwrap().unwrap();
            children(octets.contents())
        };
        spki[0] = tlv(48, &tlv(6, &[0x2a, 3, 4, 5]));
        *extension.last_mut().unwrap() = tlv(4, &tlv(48, &spki.concat()));
    });
    let work = ample();
    let parser = Parser::der(work.clone());
    let root = Certificate::read(&parser, ROOT, 0).unwrap();
    let cert = Certificate::read(&parser, &bytes, 500).unwrap();
    let alternative = hybrid::inspect_certificate(&root, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    let native = Answer(Verified::Yes);
    let context = ValidationContext {
        execution: &work,
        interval: Interval::at(cert.tbs().validity().not_before().seconds()),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &native,
        watch: &(),
        recognizer: &(),
    };
    let result = path::hybrid::validate(
        &[&cert],
        path::hybrid::HybridAnchor {
            native: Anchor::from_certificate(&root),
            alternative,
        },
        &context,
        Requirement::Both,
        &PositiveAlternative,
    )
    .unwrap();
    assert!(
        matches!(result.outcome,path::Validation::Rejected(path::Rejection {reason:path::RejectionReason::CriticalExtension(kind),..}) if kind==hybrid::SUBJECT_ALT_PUBLIC_KEY_INFO)
    );
}
#[test]
fn unsupported_backend_is_not_invalid_mathematics_or_native_fallback() {
    // Supported wire framing does not imply a selected backend can execute it.
    let work = ample();
    let parser = Parser::der(work.clone());
    let root = Certificate::read(&parser, ROOT, 0).unwrap();
    let cert = Certificate::read(&parser, CERT, 500).unwrap();
    let key = hybrid::inspect_certificate(&root, &work)
        .unwrap()
        .key
        .reading()
        .unwrap()
        .unwrap();
    let pair = hybrid::check_certificate(
        &cert,
        WorkingKey::standing(root.tbs().public_key()),
        key,
        &Answer(Verified::Yes),
        &Unsupported,
        &work,
    )
    .unwrap();
    assert_eq!(pair.native, Verified::Yes);
    assert_eq!(
        pair.alternative,
        Alternative::Verified(Verified::Unsupported)
    );
    assert!(!Requirement::Alternative.accepts(pair));
    assert!(!Requirement::Both.accepts(pair));
}

#[test]
fn duplicate_alternative_extensions_refuse_before_selection() {
    // Even equal repeated values cannot be selected by first/last-wins behavior.
    let mut outer = children(CERT);
    let mut tbs = children(&outer[0]);
    let wrapped = children(tbs.last().unwrap());
    let mut extensions = children(&wrapped[0]);
    extensions.push(extensions[0].clone());
    *tbs.last_mut().unwrap() = tlv(0xa3, &tlv(48, &extensions.concat()));
    outer[0] = tlv(48, &tbs.concat());
    let bytes = tlv(48, &outer.concat());
    let parser = Parser::der(ample());
    assert_eq!(
        Certificate::read(&parser, &bytes, 500).unwrap_err().code(),
        structured_pkix::ErrorCode::DuplicateExtension
    );
}
