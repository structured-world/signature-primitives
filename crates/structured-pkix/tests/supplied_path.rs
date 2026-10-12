//! External-call-site qualification of supplied-path outcomes and budgets.

use std::cell::Cell;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{BitString, Oid, Parser};
use structured_pkix::path::{
    self, Anchor, BuildError, ConstraintSource, Interval, Policy, RejectionReason, Truncation,
    Validation, ValidationBounds, ValidationContext, Verified, Verify, WorkingKey,
};
use structured_pkix::{AlgorithmIdentifier, Certificate, ErrorCode, oid};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if contents.len() < 128 {
        output.push(u8::try_from(contents.len()).unwrap());
    } else {
        output.extend_from_slice(&[0x81, u8::try_from(contents.len()).unwrap()]);
    }
    output.extend_from_slice(contents);
    output
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn name(text: &str) -> Vec<u8> {
    if text.is_empty() {
        return seq(&[]);
    }
    seq(&[tlv(
        0x31,
        &seq(&[
            tlv(0x06, oid::COMMON_NAME.as_bytes()),
            tlv(0x0c, text.as_bytes()),
        ]),
    )])
}

fn certificate(subject: &str, critical: bool) -> Vec<u8> {
    let extensions = if critical {
        vec![seq(&[
            tlv(0x06, &[0x2a, 3, 4, 5]),
            tlv(0x01, &[0xff]),
            tlv(0x04, &[]),
        ])]
    } else {
        Vec::new()
    };
    certificate_with_extensions(subject, &extensions)
}

fn certificate_with_extensions(subject: &str, extensions: &[Vec<u8>]) -> Vec<u8> {
    // Trusted fixture writer, not a production encoder. The verifier below
    // asserts original byte identity rather than pretending this is RSA crypto.
    let algorithm = seq(&[tlv(0x06, oid::RSA_ENCRYPTION.as_bytes()), tlv(0x05, &[])]);
    let mut fields = vec![
        tlv(0xa0, &tlv(0x02, &[2])),
        tlv(0x02, &[1]),
        algorithm.clone(),
        name("Root"),
        seq(&[tlv(0x17, b"240101000000Z"), tlv(0x17, b"300101000000Z")]),
        name(subject),
        seq(&[algorithm.clone(), tlv(0x03, &[0, 1])]),
    ];
    if !extensions.is_empty() {
        fields.push(tlv(0xa3, &seq(extensions)));
    }
    seq(&[seq(&fields), algorithm, tlv(0x03, &[0, 1])])
}

struct Provider<'a> {
    signed: &'a [u8],
    calls: Cell<usize>,
    error: bool,
}
impl Verify for Provider<'_> {
    type Error = &'static str;
    fn verify(
        &self,
        _algorithm: &AlgorithmIdentifier<'_>,
        _key: WorkingKey<'_>,
        signed: &[u8],
        _signature: BitString<'_>,
        _execution: &Memory,
    ) -> Result<Verified, Self::Error> {
        assert_eq!(signed.as_ptr(), self.signed.as_ptr());
        assert_eq!(signed, self.signed);
        self.calls.set(self.calls.get() + 1);
        if self.error {
            return Err("provider original cause");
        }
        Ok(Verified::Yes)
    }
}

#[test]
fn public_supplied_path_keeps_signed_bytes_and_callback_error_identity() {
    // No encode/reparse bridge may alter the callback's original signed view.
    let root_der = certificate("Root", false);
    let leaf_der = certificate("Leaf", false);
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let root = Certificate::read(&parser, &root_der, 0).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
    let anchor = Anchor::new(root.tbs().subject(), root.tbs().public_key());
    for error in [false, true] {
        let execution = memory(1_000_000, 1_000_000);
        let provider = Provider {
            signed: leaf.signed_bytes(),
            calls: Cell::new(0),
            error,
        };
        let context = ValidationContext {
            execution: &execution,
            interval: Interval::at_instant(leaf.tbs().validity().not_before().instant()),
            policy: Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &provider,
            watch: &(),
            recognizer: &(),
        };
        match path::validate(&[&leaf], anchor, &context) {
            Ok(Validation::Accepted(facts)) if !error => assert_eq!(
                facts.key.key().as_bytes().as_ptr(),
                leaf.tbs().public_key().as_bytes().as_ptr()
            ),
            Err(BuildError::Verification(cause)) if error => {
                assert_eq!(cause, "provider original cause");
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(provider.calls.get(), 1);
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn public_current_domain_refusal_is_located_and_precedes_the_provider() {
    // An earlier parser's storage/work account cannot finance this check.
    let root_der = certificate("Root", false);
    let leaf_der = certificate("Leaf", false);
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let root = Certificate::read(&parser, &root_der, 0).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
    for (storage, work, limit) in [
        (0, 1_000_000, structured_asn1::Limit::Memory),
        (1_000_000, 0, structured_asn1::Limit::Work),
    ] {
        let execution = memory(storage, work);
        let provider = Provider {
            signed: leaf.signed_bytes(),
            calls: Cell::new(0),
            error: false,
        };
        let context = ValidationContext {
            execution: &execution,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &provider,
            watch: &(),
            recognizer: &(),
        };
        let error = path::validate(
            &[&leaf],
            Anchor::new(root.tbs().subject(), root.tbs().public_key()),
            &context,
        )
        .unwrap_err();
        let BuildError::Processing(error) = error else {
            panic!("a shared refusal remains a processing error")
        };
        assert_eq!(
            error.code(),
            ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(limit))
        );
        let subject_at =
            leaf.tbs().subject().as_bytes().as_ptr() as usize - leaf_der.as_ptr() as usize;
        assert_eq!(error.offset(), 700 + subject_at as u64);
        assert_eq!(provider.calls.get(), 0);
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn public_duplicates_and_explicit_anchor_inclusion_are_semantic_failures() {
    // Identity is original encoded content, including separately parsed copies.
    let root_der = certificate("Root", false);
    let leaf_der = certificate("Leaf", false);
    let copy_der = leaf_der.clone();
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let root = Certificate::read(&parser, &root_der, 0).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
    let copy = Certificate::read(&parser, &copy_der, 900).unwrap();
    let execution = memory(1_000_000, 1_000_000);
    let provider = Provider {
        signed: leaf.signed_bytes(),
        calls: Cell::new(0),
        error: false,
    };
    let context = ValidationContext {
        execution: &execution,
        interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &provider,
        watch: &(),
        recognizer: &(),
    };
    for (chain, reason) in [
        (
            [&leaf, &copy],
            RejectionReason::DuplicateCertificate { earlier: 0 },
        ),
        ([&leaf, &root], RejectionReason::AnchorIncluded),
    ] {
        let Validation::Rejected(rejected) =
            path::validate(&chain, Anchor::from_certificate(&root), &context).unwrap()
        else {
            panic!("invalid path membership must not reach verification")
        };
        assert_eq!(rejected.at, Some(ConstraintSource::Certificate(1)));
        assert_eq!(rejected.reason, reason);
    }
    assert_eq!(provider.calls.get(), 0);
    assert_eq!(execution.used(), 0);
}

#[test]
fn public_pure_anchor_does_not_make_its_own_certificate_a_path() {
    // RFC5280 §6 excludes the anchor certificate even when trust inputs were
    // supplied as its name/key, rather than as a Certificate wrapper.
    let root_der = certificate("Root", false);
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let root = Certificate::read(&parser, &root_der, 0).unwrap();
    let execution = memory(1_000_000, 1_000_000);
    let provider = Provider {
        signed: root.signed_bytes(),
        calls: Cell::new(0),
        error: false,
    };
    let context = ValidationContext {
        execution: &execution,
        interval: Interval::at(root.tbs().validity().not_before().seconds()),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &provider,
        watch: &(),
        recognizer: &(),
    };
    let Validation::Rejected(rejected) = path::validate(
        &[&root],
        Anchor::new(root.tbs().subject(), root.tbs().public_key()),
        &context,
    )
    .unwrap() else {
        panic!("a verified self-published anchor is not a certificate path")
    };
    assert_eq!(rejected.at, Some(ConstraintSource::Certificate(0)));
    assert_eq!(rejected.reason, RejectionReason::AnchorIncluded);
    assert_eq!(provider.calls.get(), 1);
    assert_eq!(execution.used(), 0);
}

struct RegistryFailure;
impl structured_pkix::Recognizer for RegistryFailure {
    type Error = &'static str;
    fn recognizes(&self, _kind: Oid<'_>, _execution: &Memory) -> Result<bool, Self::Error> {
        Err("registry original cause")
    }
}

struct Deadline(bool);
impl path::Watch for Deadline {
    fn out_of_time(&self) -> bool {
        self.0
    }
}

#[test]
fn public_duplicate_extension_error_stays_at_the_decoding_boundary() {
    // A decoded Certificate cannot contain ambiguous duplicate extensions.
    // Reject it before path checking with the original code, field and offset.
    let extension = seq(&[tlv(0x06, &[0x2a, 3, 4, 5]), tlv(0x04, &[])]);
    let der = certificate_with_extensions("Leaf", &[extension.clone(), extension]);
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let error = Certificate::read(&parser, &der, 700).unwrap_err();
    assert_eq!(error.code(), ErrorCode::DuplicateExtension);
    assert_eq!(error.field(), "certificate.tbsCertificate.extensions");
    assert!(error.offset() >= 700);
    assert!(error.offset() < 700 + der.len() as u64);
    assert!(!error.is_resource());
}

#[test]
fn critical_uri_san_with_fragment_identifies_an_empty_subject() {
    // Public-path consumer regression: RFC5280 §4.2.1.6 permits a critical
    // URI SAN as the sole identity, including RFC3986 §3's fragment component.
    let value = "https://operator@example.com:8443/path?q=1#id";
    let san = seq(&[
        tlv(0x06, oid::SUBJECT_ALT_NAME.as_bytes()),
        tlv(0x01, &[0xff]),
        tlv(0x04, &seq(&[tlv(0x86, value.as_bytes())])),
    ]);
    let root_der = certificate("Root", false);
    let leaf_der = certificate_with_extensions("", &[san]);
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let root = Certificate::read(&parser, &root_der, 0).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
    assert!(leaf.tbs().subject().is_empty());
    let execution = memory(1_000_000, 1_000_000);
    let provider = Provider {
        signed: leaf.signed_bytes(),
        calls: Cell::new(0),
        error: false,
    };
    let context = ValidationContext {
        execution: &execution,
        interval: Interval::at_instant(leaf.tbs().validity().not_before().instant()),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &provider,
        watch: &(),
        recognizer: &(),
    };
    let outcome = path::validate(
        &[&leaf],
        Anchor::new(root.tbs().subject(), root.tbs().public_key()),
        &context,
    )
    .unwrap();
    assert!(matches!(outcome, Validation::Accepted(_)), "{outcome:?}");
    assert_eq!(provider.calls.get(), 1);
    drop(outcome);
    assert_eq!(execution.used(), 0);
}

#[test]
fn critical_policy_qualifiers_require_interpretation() {
    // RFC5280 §4.2.1.4: a decoded critical policy still requires every
    // qualifier to be interpretable. Noncritical opaque qualifiers remain
    // retained data and must not invent a trust restriction.
    for (qualifier, value, interpreted) in [
        (Oid::from_bytes(&[0x2a, 3, 5]), tlv(0x05, &[]), false),
        (oid::CPS_QUALIFIER, tlv(0x05, &[]), false),
        (oid::USER_NOTICE_QUALIFIER, tlv(0x05, &[]), false),
        (
            oid::CPS_QUALIFIER,
            tlv(0x16, b"https://example.test/policy#section"),
            true,
        ),
    ] {
        for critical in [false, true] {
            let information = seq(&[
                tlv(0x06, &[0x2a, 3, 4]),
                seq(&[seq(&[tlv(0x06, qualifier.as_bytes()), value.clone()])]),
            ]);
            let mut parts = vec![tlv(0x06, oid::CERTIFICATE_POLICIES.as_bytes())];
            if critical {
                parts.push(tlv(0x01, &[0xff]));
            }
            parts.push(tlv(0x04, &seq(&[information])));
            let root_der = certificate("Root", false);
            let leaf_der = certificate_with_extensions("Leaf", &[seq(&parts)]);
            let parser = Parser::der(memory(1_000_000, 1_000_000));
            let root = Certificate::read(&parser, &root_der, 0).unwrap();
            let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
            let execution = memory(1_000_000, 1_000_000);
            let provider = Provider {
                signed: leaf.signed_bytes(),
                calls: Cell::new(0),
                error: false,
            };
            let context = ValidationContext {
                execution: &execution,
                interval: Interval::at_instant(leaf.tbs().validity().not_before().instant()),
                policy: Policy::default(),
                bounds: ValidationBounds::default(),
                verifier: &provider,
                watch: &(),
                recognizer: &(),
            };
            let outcome = path::validate(
                &[&leaf],
                Anchor::new(root.tbs().subject(), root.tbs().public_key()),
                &context,
            )
            .unwrap();
            if critical && !interpreted {
                let Validation::Rejected(rejected) = &outcome else {
                    panic!("uninterpreted critical qualifier: {outcome:?}")
                };
                assert_eq!(rejected.at, Some(ConstraintSource::Certificate(0)));
                assert_eq!(
                    rejected.reason,
                    RejectionReason::CriticalExtension(oid::CERTIFICATE_POLICIES)
                );
                assert_eq!(provider.calls.get(), 0);
            } else {
                assert!(matches!(outcome, Validation::Accepted(_)), "{outcome:?}");
                assert_eq!(provider.calls.get(), 1);
            }
            drop(outcome);
            assert_eq!(execution.used(), 0);
        }
    }
}

#[test]
fn malformed_critical_policy_extensions_keep_decoder_details() {
    // Criticality cannot replace a relevant decoder's code/field/offset
    // with the unknown-critical-extension verdict. Leaf-only mappings and
    // inhibitAnyPolicy still need decoding when their critical bit is set.
    for (kind, critical) in [
        (structured_pkix::oid::CERTIFICATE_POLICIES, false),
        (structured_pkix::oid::CERTIFICATE_POLICIES, true),
        (structured_pkix::oid::POLICY_CONSTRAINTS, false),
        (structured_pkix::oid::POLICY_CONSTRAINTS, true),
        (structured_pkix::oid::POLICY_MAPPINGS, true),
        (structured_pkix::oid::INHIBIT_ANY_POLICY, true),
    ] {
        let root_der = certificate("Root", false);
        let mut components = vec![tlv(0x06, kind.as_bytes())];
        if critical {
            components.push(tlv(0x01, &[0xff]));
        }
        components.push(tlv(0x04, &[0x05, 0x00]));
        let leaf_der = certificate_with_extensions("Leaf", &[seq(&components)]);
        let parser = Parser::der(memory(1_000_000, 1_000_000));
        let root = Certificate::read(&parser, &root_der, 0).unwrap();
        let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
        let execution = memory(1_000_000, 1_000_000);
        let extensions = leaf.tbs().extensions();
        let expected = if kind == structured_pkix::oid::CERTIFICATE_POLICIES {
            extensions.certificate_policies(&execution).map(|_| ())
        } else if kind == structured_pkix::oid::POLICY_CONSTRAINTS {
            extensions.policy_constraints(&execution).map(|_| ())
        } else if kind == structured_pkix::oid::POLICY_MAPPINGS {
            extensions.policy_mappings(&execution).map(|_| ())
        } else {
            extensions.inhibit_any_policy(&execution).map(|_| ())
        }
        .unwrap_err();
        let provider = Provider {
            signed: leaf.signed_bytes(),
            calls: Cell::new(0),
            error: false,
        };
        let context = ValidationContext {
            execution: &execution,
            interval: Interval::at_instant(leaf.tbs().validity().not_before().instant()),
            policy: Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &provider,
            watch: &(),
            recognizer: &(),
        };
        let Validation::Rejected(rejected) = path::validate(
            &[&leaf],
            Anchor::new(root.tbs().subject(), root.tbs().public_key()),
            &context,
        )
        .unwrap() else {
            panic!("malformed policy extension is a completed rejection")
        };
        assert_eq!(rejected.at, Some(ConstraintSource::Certificate(0)));
        assert_eq!(
            rejected.reason,
            RejectionReason::MalformedExtension {
                extension: kind,
                code: expected.code(),
                field: expected.field(),
                offset: expected.offset(),
            }
        );
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn public_policy_failure_and_local_policy_limit_are_distinct() {
    // Requiring absent policy evidence is a completed rejection; refusing
    // even the initial policy root is incomplete, with no accepted key facts.
    let root_der = certificate("Root", false);
    let leaf_der = certificate("Leaf", false);
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let root = Certificate::read(&parser, &root_der, 0).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
    let execution = memory(1_000_000, 1_000_000);
    let provider = Provider {
        signed: leaf.signed_bytes(),
        calls: Cell::new(0),
        error: false,
    };
    let context = ValidationContext {
        execution: &execution,
        interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
        policy: Policy {
            explicit: true,
            ..Policy::default()
        },
        bounds: ValidationBounds::default(),
        verifier: &provider,
        watch: &(),
        recognizer: &(),
    };
    let anchor = Anchor::new(root.tbs().subject(), root.tbs().public_key());
    let Validation::Rejected(rejected) = path::validate(&[&leaf], anchor, &context).unwrap() else {
        panic!("absent required policies")
    };
    assert_eq!(rejected.at, Some(ConstraintSource::Certificate(0)));
    assert_eq!(rejected.reason, RejectionReason::Policies);
    assert_eq!(provider.calls.get(), 1);
    let context = ValidationContext {
        bounds: ValidationBounds {
            policies: 0,
            ..context.bounds
        },
        ..context
    };
    assert!(matches!(
        path::validate(&[&leaf], anchor, &context).unwrap(),
        Validation::Incomplete(Truncation::Policies)
    ));
    assert_eq!(provider.calls.get(), 1);
    assert_eq!(execution.used(), 0);
}

#[test]
fn public_local_limits_and_empty_input_never_produce_accepted_facts() {
    // Local ceilings report incomplete execution, while the empty path is a
    // completed input rejection. Neither is a provider verdict.
    let root_der = certificate("Root", false);
    let leaf_der = certificate("Leaf", false);
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let root = Certificate::read(&parser, &root_der, 0).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
    for (depth, work, expired, expected) in [
        (0, 1_000_000, false, Truncation::Depth),
        (12, 0, false, Truncation::Work),
        (12, 1_000_000, true, Truncation::Time),
    ] {
        let execution = memory(1_000_000, 1_000_000);
        let provider = Provider {
            signed: leaf.signed_bytes(),
            calls: Cell::new(0),
            error: false,
        };
        let deadline = Deadline(expired);
        let context = ValidationContext {
            execution: &execution,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: Policy::default(),
            bounds: ValidationBounds {
                depth,
                work,
                policies: 1024,
            },
            verifier: &provider,
            watch: &deadline,
            recognizer: &(),
        };
        let anchor = Anchor::new(root.tbs().subject(), root.tbs().public_key());
        assert!(
            matches!(path::validate(&[&leaf], anchor, &context).unwrap(), Validation::Incomplete(reason) if reason == expected)
        );
        let Validation::Rejected(rejected) = path::validate(&[], anchor, &context).unwrap() else {
            panic!("empty input is a completed rejection")
        };
        assert_eq!(rejected.at, None);
        assert_eq!(rejected.reason, RejectionReason::EmptyPath);
        assert_eq!(provider.calls.get(), 0);
        assert_eq!(execution.used(), 0);
        assert_eq!(execution.work_used(), 0);
    }
}

#[test]
fn public_validity_rejection_precedes_signature_verification() {
    // A target outside the requested interval is already a completed failure.
    let root_der = certificate("Root", false);
    let leaf_der = certificate("Leaf", false);
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let root = Certificate::read(&parser, &root_der, 0).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
    let execution = memory(1_000_000, 1_000_000);
    let provider = Provider {
        signed: leaf.signed_bytes(),
        calls: Cell::new(0),
        error: false,
    };
    let context = ValidationContext {
        execution: &execution,
        interval: Interval::at(leaf.tbs().validity().not_after().seconds() + 1),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &provider,
        watch: &(),
        recognizer: &(),
    };
    let Validation::Rejected(rejected) = path::validate(
        &[&leaf],
        Anchor::new(root.tbs().subject(), root.tbs().public_key()),
        &context,
    )
    .unwrap() else {
        panic!("expired certificate")
    };
    assert_eq!(rejected.at, Some(ConstraintSource::Certificate(0)));
    assert_eq!(rejected.reason, RejectionReason::Validity);
    assert_eq!(provider.calls.get(), 0);
    assert_eq!(execution.used(), 0);
}

#[test]
fn public_unknown_critical_and_recognizer_failure_remain_distinct() {
    // A false answer is semantic; failure to query the registry is not.
    let root_der = certificate("Root", false);
    let leaf_der = certificate("Leaf", true);
    let parser = Parser::der(memory(1_000_000, 1_000_000));
    let root = Certificate::read(&parser, &root_der, 0).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 700).unwrap();
    let execution = memory(1_000_000, 1_000_000);
    let provider = Provider {
        signed: leaf.signed_bytes(),
        calls: Cell::new(0),
        error: false,
    };
    let context = ValidationContext {
        execution: &execution,
        interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
        policy: Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &provider,
        watch: &(),
        recognizer: &(),
    };
    let anchor = Anchor::new(root.tbs().subject(), root.tbs().public_key());
    let Validation::Rejected(rejected) = path::validate(&[&leaf], anchor, &context).unwrap() else {
        panic!("unknown critical extension")
    };
    assert_eq!(
        rejected.reason,
        RejectionReason::CriticalExtension(Oid::from_bytes(&[0x2a, 3, 4, 5]))
    );
    let context = ValidationContext {
        recognizer: &RegistryFailure,
        execution: &execution,
        interval: context.interval,
        policy: context.policy,
        bounds: context.bounds,
        verifier: &provider,
        watch: &(),
    };
    assert!(matches!(
        path::validate(&[&leaf], anchor, &context),
        Err(BuildError::Recognition("registry original cause"))
    ));
    assert_eq!(provider.calls.get(), 0);
    assert_eq!(execution.used(), 0);
}
