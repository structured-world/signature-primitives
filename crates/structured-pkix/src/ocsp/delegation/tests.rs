use super::*;
use crate::fixtures::{
    CertificateParts, algorithm, bits, extension, int, null, oid as encoded_oid, seq, tlv,
};
use crate::signature::SignatureValue;
use core::cell::Cell;
use structured_asn1::memory::Memory;
use structured_asn1::{Oid, Parser};

struct VerifiedBy<'a> {
    key: &'a [u8],
    calls: Cell<usize>,
}

#[test]
fn delegation_retains_the_actual_inherited_issuing_parameters() {
    // This observes common effective-key provenance, not DSA arithmetic. A
    // consumer must not reconstruct the issuer's standing (parameterless) key
    // when attaching this successful local delegation to its original path.
    struct Observe<'a>(&'a [u8]);
    impl Verify for Observe<'_> {
        type Error = core::convert::Infallible;
        fn verify(
            &self,
            _: &crate::AlgorithmIdentifier<'_>,
            key: WorkingKey<'_>,
            _: &[u8],
            _: SignatureValue<'_>,
            _: &Memory,
        ) -> core::result::Result<path::Verified, Self::Error> {
            assert_eq!(key.parameters(), Some(self.0));
            Ok(path::Verified::Yes)
        }
    }
    let kind = Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]);
    let parameters = seq(&[int(17), int(3), int(5)]);
    let parent_bytes = CertificateParts {
        key: seq(&[seq(&[encoded_oid(kind), parameters]), bits(&[1])]),
        ..CertificateParts::default()
    }
    .build();
    let mut issuer_parts = CertificateParts {
        key: seq(&[seq(&[encoded_oid(kind)]), bits(&[2])]),
        ..CertificateParts::default()
    };
    issuer_parts.subject = issuer_parts.issuer.clone();
    let issuer_bytes = issuer_parts.build();
    let responder_bytes = CertificateParts {
        extensions: Some(seq(&[purpose(oid::OCSP_SIGNING)])),
        ..CertificateParts::default()
    }
    .build();
    let memory = crate::fixtures::memory();
    let parser = Parser::der(memory.clone());
    let parent = Certificate::read(&parser, &parent_bytes, 100).unwrap();
    let issuer = Certificate::read(&parser, &issuer_bytes, 700).unwrap();
    let responder = Certificate::read(&parser, &responder_bytes, 1300).unwrap();
    let key = WorkingKey::standing(parent.tbs().public_key())
        .subject(&issuer, &memory)
        .unwrap();
    let expected = parent.tbs().public_key().algorithm().parameters().unwrap();
    let observer = Observe(expected);
    let context = ValidationContext {
        execution: &memory,
        interval: path::Interval::at(1_735_689_600),
        policy: path::Policy::default(),
        bounds: path::ValidationBounds::default(),
        verifier: &observer,
        watch: &(),
        recognizer: &(),
    };
    let Delegation::Accepted(facts) = check_delegate(&responder, &issuer, key, &context).unwrap()
    else {
        panic!("observed actual issuing key")
    };
    assert_eq!(facts.issuing_key().parameters(), Some(expected));
    assert!(core::ptr::eq(
        facts.issuing_key().parameters().unwrap(),
        expected
    ));
    assert_eq!(
        facts.issuing_key().key().as_bytes(),
        issuer.tbs().public_key().as_bytes()
    );
    assert!(
        WorkingKey::standing(facts.issuer().tbs().public_key())
            .parameters()
            .is_none()
    );
}
impl Verify for VerifiedBy<'_> {
    type Error = &'static str;
    fn verify(
        &self,
        _: &crate::AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        _: &[u8],
        _: SignatureValue<'_>,
        _: &Memory,
    ) -> core::result::Result<path::Verified, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        Ok(if key.key().as_bytes() == self.key {
            path::Verified::Yes
        } else {
            path::Verified::No
        })
    }
}

fn purpose(kind: Oid<'_>) -> alloc::vec::Vec<u8> {
    extension(oid::EXT_KEY_USAGE, true, &seq(&[encoded_oid(kind)]))
}

fn inspect_extensions(
    extensions: Option<alloc::vec::Vec<u8>>,
    inspect: impl FnOnce(BuildResult<Delegation<'_>, &'static str, core::convert::Infallible>, usize),
) {
    let mut parts = CertificateParts::default();
    parts.subject = parts.issuer.clone();
    let issuer_bytes = parts.build();
    let bytes = CertificateParts {
        extensions,
        ..CertificateParts::default()
    }
    .build();
    let execution = crate::fixtures::memory();
    let parser = Parser::der(execution.clone());
    let issuer = Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let responder = Certificate::read(&parser, &bytes, 700).unwrap();
    let provider = VerifiedBy {
        key: issuer.tbs().public_key().as_bytes(),
        calls: Cell::new(0),
    };
    let context = ValidationContext {
        execution: &execution,
        interval: path::Interval::at(1_735_689_600),
        policy: path::Policy::default(),
        bounds: path::ValidationBounds::default(),
        verifier: &provider,
        watch: &(),
        recognizer: &(),
    };
    inspect(
        check_delegate(
            &responder,
            &issuer,
            WorkingKey::standing(issuer.tbs().public_key()),
            &context,
        ),
        provider.calls.get(),
    );
}

#[test]
fn content_commitment_authorizes_delegated_ocsp_signing() {
    // RFC5280 4.2.1.12 explicitly permits nonRepudiation/contentCommitment
    // alone with OCSPSigning; rejecting it must not suppress path checking.
    inspect_extensions(
        Some(seq(&[
            purpose(oid::OCSP_SIGNING),
            extension(oid::KEY_USAGE, true, &tlv(3, &[6, 0x40])),
        ])),
        |result, calls| {
            assert!(matches!(result.unwrap(), Delegation::Accepted(_)));
            assert_eq!(calls, 1);
        },
    );
}

#[test]
fn purpose_key_usage_and_unknown_critical_demands_remain_distinct() {
    // Explicit OCSPSigning is required; any-purpose and other EKUs cannot
    // substitute. Critical metadata and purpose failures are distinct facts.
    let any = Oid::from_bytes(&[0x55, 0x1d, 0x25, 0]);
    for extra in [
        None,
        Some(seq(&[purpose(any)])),
        Some(seq(&[purpose(oid::TIME_STAMPING)])),
    ] {
        inspect_extensions(extra, |result, calls| {
            assert!(matches!(
                result.unwrap(),
                Delegation::Rejected(DelegationFailure::SigningPurpose)
            ));
            assert_eq!(calls, 0);
        });
    }
    inspect_extensions(
        Some(seq(&[
            purpose(oid::OCSP_SIGNING),
            extension(oid::KEY_USAGE, true, &tlv(3, &[5, 0x20])),
        ])),
        |result, calls| {
            assert!(matches!(
                result.unwrap(),
                Delegation::Rejected(DelegationFailure::KeyUsage)
            ));
            assert_eq!(calls, 0);
        },
    );
    let unknown = Oid::from_bytes(&[0x2a, 3, 4]);
    inspect_extensions(
        Some(seq(&[
            purpose(oid::OCSP_SIGNING),
            extension(unknown, true, &null()),
        ])),
        |result, calls| {
            assert!(
                matches!(result.unwrap(), Delegation::PathRejected(path::Rejection { reason: path::RejectionReason::CriticalExtension(kind), .. }) if kind == unknown)
            );
            assert_eq!(calls, 0);
        },
    );
}

#[test]
fn missing_exemption_is_unresolved_and_no_check_requires_exact_null() {
    // NoCheck has an exact NULL schema, even when noncritical. Absence must
    // not become an implicit exemption or a completed revocation check.
    inspect_extensions(Some(seq(&[purpose(oid::OCSP_SIGNING)])), |result, calls| {
        let Delegation::Accepted(facts) = result.unwrap() else {
            panic!("delegate without exemption rejected");
        };
        assert_eq!(facts.revocation(), ResponderRevocation::Unresolved);
        assert_eq!(calls, 1);
    });
    for value in [int(0), tlv(5, &[0]), [null(), null()].concat()] {
        inspect_extensions(
            Some(seq(&[
                purpose(oid::OCSP_SIGNING),
                extension(oid::OCSP_NO_CHECK, false, &value),
            ])),
            |result, calls| {
                assert!(matches!(result, Err(path::BuildError::Processing(_))));
                assert_eq!(calls, 0);
            },
        );
    }
}

#[test]
fn direct_delegation_checks_purpose_current_validity_and_null_exemption() {
    // Dispatch fixture: direct issuance uses the exact caller-bound issuer
    // key. noCheck never bypasses validity or authorizes a different issuer.
    let mut issuer_parts = CertificateParts::default();
    issuer_parts.subject = issuer_parts.issuer.clone();
    let issuer_bytes = issuer_parts.build();
    let other_bytes = CertificateParts {
        key: seq(&[algorithm(oid::RSA_ENCRYPTION), bits(&[1, 2, 3])]),
        subject: issuer_parts.subject.clone(),
        ..CertificateParts::default()
    }
    .build();
    let execution = crate::fixtures::memory();
    let parser = Parser::der(execution.clone());
    let issuer = Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let other = Certificate::read(&parser, &other_bytes, 300).unwrap();
    let provider = VerifiedBy {
        key: issuer.tbs().public_key().as_bytes(),
        calls: Cell::new(0),
    };
    let mut context = ValidationContext {
        execution: &execution,
        interval: path::Interval::at(1_735_689_600),
        policy: path::Policy::default(),
        bounds: path::ValidationBounds::default(),
        verifier: &provider,
        watch: &(),
        recognizer: &(),
    };
    let key = WorkingKey::standing(issuer.tbs().public_key());
    let purpose = |kind| extension(oid::EXT_KEY_USAGE, true, &seq(&[encoded_oid(kind)]));
    let bytes = CertificateParts {
        extensions: Some(seq(&[
            purpose(oid::OCSP_SIGNING),
            extension(oid::OCSP_NO_CHECK, true, &null()),
        ])),
        ..CertificateParts::default()
    }
    .build();
    let responder = Certificate::read(&parser, &bytes, 700).unwrap();
    let Delegation::Accepted(facts) = check_delegate(&responder, &issuer, key, &context).unwrap()
    else {
        panic!("direct delegate rejected");
    };
    assert_eq!(facts.revocation(), ResponderRevocation::NoCheck);
    assert_eq!(provider.calls.get(), 1);
    assert!(core::ptr::eq(facts.issuer(), &raw const issuer));
    context.interval = path::Interval::at(1_798_761_600);
    assert!(matches!(
        check_delegate(&responder, &issuer, key, &context).unwrap(),
        Delegation::PathRejected(path::Rejection {
            reason: path::RejectionReason::Validity,
            ..
        })
    ));
    assert_eq!(provider.calls.get(), 1);
    context.interval = path::Interval::at(1_735_689_600);
    assert!(matches!(
        check_delegate(
            &responder,
            &issuer,
            WorkingKey::standing(other.tbs().public_key()),
            &context
        )
        .unwrap(),
        Delegation::Rejected(DelegationFailure::IssuerKeyBinding)
    ));
    assert!(matches!(
        check_delegate(
            &responder,
            &other,
            WorkingKey::standing(other.tbs().public_key()),
            &context
        )
        .unwrap(),
        Delegation::PathRejected(path::Rejection {
            reason: path::RejectionReason::Signature,
            ..
        })
    ));
}
