//! The validation process over constructed facts, case by case after the
//! steps of ETSI EN 319 102-1 V1.4.1 clauses 5.3.4 and 5.5.4.

use super::*;
use crate::pki::status::Revoked;
use crate::validation::crypto::{Family, Hash, Mechanism, Scheme};
use crate::validation::policy::{Element, Requirements as Policy};
use alloc::sync::Arc;
use alloc::vec;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};

// These cases explicitly select the catalogue; the evaluator has no default.
const ETSI_TS_119_312_V2_1_1: Policy<'static> = Policy {
    crypto: crate::validation::ETSI_TS_119_312_V2_1_1,
    elements: Elements::NONE,
    timestamp_delay: None,
};

/// The start of the UTC day, from the civil date (Howard Hinnant's
/// algorithm).
fn day(year: i64, month: i64, date: i64) -> Instant {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + date - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Instant::new((era * 146_097 + doe - 719_468) * 86_400, 0).unwrap()
}

/// A recorded revocation. Its date is never compared here: the revocation
/// evidence has already placed it against the interval.
fn revoked(when: When) -> Status {
    // Same UTC label as the public RFC 4134 certificate, without importing
    // an unrelated complete certificate into this arithmetic-only test.
    let der = b"\x17\x0d990919010847Z";
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1_000_000)));
    let parser = Parser::der(memory);
    let mut reader = parser.read(der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let at = structured_pkix::Time::read(&reader, &element, "revoked").unwrap();
    Status::Revoked {
        basis: 0,
        revoked: Revoked { at, reason: None },
        when,
    }
}

const NOT_REVOKED: Status = Status::NotRevoked {
    basis: 0,
    later: None,
};

/// An RSA PKCS#1 v1.5 key of `bits` with the exponent 65537.
const fn rsa(bits: u32) -> Scheme {
    Scheme {
        family: Family::RsaPkcs1,
        bits,
        exponent_bits: Some(17),
        subgroup_bits: None,
    }
}

const SHA256_RSA4096: Material = Material {
    hash: Some(Hash::Sha256),
    scheme: Some(rsa(4096)),
};

const SHA256_RSA2048: Material = Material {
    hash: Some(Hash::Sha256),
    scheme: Some(rsa(2048)),
};

const RECOGNIZED: Anchor = Anchor {
    current: Conclusion::Recognized,
    over_interval: Conclusion::UpperBoundOnly,
};

const CERTIFICATE: [Material; 1] = [SHA256_RSA4096];

const GOOD: Path<'static> = Path {
    chain: Chain::Valid,
    anchor: RECOGNIZED,
    authorities: &[],
    materials: &CERTIFICATE,
    revocation_issuers: &[],
};

const INTACT: [Reference; 1] = [Reference::Intact];

const OWN: [Material; 1] = [SHA256_RSA4096];

const PATHS: [Path<'static>; 1] = [GOOD];

/// An ordinary signature: a certificate valid from 2025 through 2027, a
/// signature timestamp on 2026-06-01 and nothing proving when it was made
/// before that, judged on 2026-10-19.
fn facts() -> Facts<'static> {
    Facts {
        format: Format::Conformant,
        context: Context::Ready,
        signer: Some(Signer {
            not_before: day(2025, 1, 1),
            not_after: day(2027, 12, 31),
            revocation: NOT_REVOKED,
        }),
        references: &INTACT,
        value: Value::Verified,
        materials: &OWN,
        elements: Elements::NONE,
        time: Time {
            after: None,
            before: Some(day(2026, 6, 1)),
        },
        paths: &PATHS,
        truncated: false,
        order: Order::Coherent,
        signature_timestamp: true,
        claimed_signing_time: None,
        utc: None,
        changes: Changes::NotApplicable,
        now: day(2026, 10, 19),
    }
}

fn validate(facts: &Facts<'_>, policy: &Policy<'_>) -> Outcome {
    // Every transferred case exercises the public resource-admitted entry.
    let work = Memory::new(Arc::new(MemoryAccount::new(0, 1_000_000)));
    crate::validation::validate(facts, policy, &work).unwrap()
}

fn run(facts: &Facts<'_>) -> Outcome {
    validate(facts, &ETSI_TS_119_312_V2_1_1)
}

fn sub(facts: &Facts<'_>) -> Option<&'static str> {
    run(facts).sub.map(SubIndication::as_str)
}

/// Pure `EdDSA` has an intrinsic hash. Allowlisting one variant admits neither
/// the other variant nor unknown methods.
#[test]
fn fixed_eddsa_variants_are_separately_selectable() {
    let rules = [crate::validation::SchemeRule {
        family: Family::Ed25519,
        min_bits: 0,
        min_subgroup_bits: 0,
        until: None,
    }];
    let selected = Policy {
        crypto: Constraints {
            schemes: &rules,
            ..ETSI_TS_119_312_V2_1_1.crypto
        },
        ..ETSI_TS_119_312_V2_1_1
    };
    for family in [Family::Ed25519, Family::Ed448, Family::Other] {
        let material = [Material {
            hash: None,
            scheme: Some(Scheme {
                family,
                bits: 0,
                exponent_bits: None,
                subgroup_bits: None,
            }),
        }];
        let path = [Path {
            materials: &[],
            ..GOOD
        }];
        let input = Facts {
            materials: &material,
            paths: &path,
            ..facts()
        };
        assert_eq!(
            validate(&input, &selected).indication == Indication::TotalPassed,
            family == Family::Ed25519
        );
        assert_eq!(
            run(&input).indication == Indication::TotalPassed,
            family != Family::Other
        );
    }
}

/// The decision keeps no storage and succeeds with an exact traversal budget.
/// One less unit must refuse instead of producing an indication.
#[test]
fn evaluation_requires_work_but_no_allocation_capacity() {
    let input = facts();
    let probe = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    let expected = crate::validation::validate(&input, &ETSI_TS_119_312_V2_1_1, &probe).unwrap();
    let cost = probe.work_used();
    assert!(cost > 0);
    assert_eq!(probe.used(), 0);
    for allowance in [0, cost - 1, cost] {
        let work = Memory::new(Arc::new(MemoryAccount::new(0, allowance)));
        let result = crate::validation::validate(&input, &ETSI_TS_119_312_V2_1_1, &work);
        if allowance < cost {
            assert_eq!(
                result,
                Err(structured_asn1::memory::MemoryError::WorkExceeded)
            );
        } else {
            assert_eq!(result, Ok(expected));
        }
        assert_eq!(work.used(), 0);
    }
}

/// A wider current account cannot erase either original or current parser ceilings.
#[test]
fn borrowed_execution_preserves_both_parser_ceilings() {
    use structured_asn1::memory::{MemoryError, Work};
    use structured_asn1::{Encoding, Limits};
    for (original_limit, current_limit) in [(10, 100_000), (100_000, 10)] {
        let source = Parser::new(
            Encoding::Der,
            Limits {
                max_work: original_limit,
                ..Limits::default()
            },
            Memory::new(Arc::new(MemoryAccount::new(0, 100_000))),
        );
        let current = Parser::new(
            Encoding::Der,
            Limits {
                max_work: current_limit,
                ..Limits::default()
            },
            Memory::new(Arc::new(MemoryAccount::new(0, 100_000))),
        );
        let reader = current.read(&[], 0).unwrap();
        let execution = reader.execution();
        let joint = execution.execution_for(&source);
        assert_eq!(
            crate::validation::validate(&facts(), &ETSI_TS_119_312_V2_1_1, &joint),
            Err(MemoryError::WorkExceeded),
        );
    }
}

/// All nested catalogue entries and path members contribute to admission,
/// even when a short-circuit decision would find a passing path earlier.
#[test]
fn admission_covers_nested_constraints_and_path_fanout() {
    let hashes = [Hash::Sha256; 64];
    let suites = [crate::validation::SuiteRule {
        family: Family::RsaPkcs1,
        hashes: &hashes,
    }; 8];
    let requirements = Policy {
        crypto: Constraints {
            suites: &suites,
            ..ETSI_TS_119_312_V2_1_1.crypto
        },
        ..ETSI_TS_119_312_V2_1_1
    };
    let references = [Reference::Intact; 32];
    let authorities = [NOT_REVOKED; 16];
    let materials = [SHA256_RSA4096; 16];
    let paths = [Path {
        authorities: &authorities,
        materials: &materials,
        ..GOOD
    }; 8];
    let input = Facts {
        references: &references,
        paths: &paths,
        ..facts()
    };
    let work = Memory::new(Arc::new(MemoryAccount::new(0, 1_000_000)));
    let result = crate::validation::validate(&input, &requirements, &work).unwrap();
    assert_eq!(result.indication, Indication::TotalPassed);
    let cost = work.work_used();
    assert!(cost > 8 * 16 * 64);
    let short = Memory::new(Arc::new(MemoryAccount::new(0, cost - 1)));
    assert_eq!(
        crate::validation::validate(&input, &requirements, &short),
        Err(structured_asn1::memory::MemoryError::WorkExceeded),
    );
    assert_eq!(work.used(), 0);
}

/// RFC 6960 2.2 rejects a never-issued certificate even when the signature
/// math and its timestamp hold. It must not turn into `TRY_LATER` or success.
#[test]
fn a_never_issued_signer_has_an_explicit_nonretryable_result() {
    let mut input = facts();
    input.signer.as_mut().unwrap().revocation = Status::NotIssued { basis: 0 };
    let outcome = run(&input);
    let expected = SubIndication::Custom(Custom::CertificateNotIssued);
    assert_eq!(outcome.indication, Indication::Indeterminate);
    assert_eq!(outcome.sub, Some(expected));
    assert_eq!(outcome.basis, Some(Basis::SignerRevocation));
    assert_eq!(expected.retry(), None);
}

/// EN 319 102-1 5.2.4.4: an inaccessible or unreadable policy must never
/// become a successful validation under an arbitrary set of constraints.
#[test]
fn initialization_failures_prevent_success() {
    for (context, expected) in [
        (
            Context::PolicyUnavailable,
            SubIndication::SignaturePolicyNotAvailable,
        ),
        (
            Context::PolicyProcessingError,
            SubIndication::PolicyProcessingError,
        ),
    ] {
        let outcome = run(&Facts { context, ..facts() });
        assert_eq!(outcome.indication, Indication::Indeterminate);
        assert_eq!(outcome.sub, Some(expected));
        assert_eq!(outcome.basis, Some(Basis::PolicyContext));
    }
}

/// EN 319 102-1 5.5.4 step 5a: a signature timestamp under a delay policy
/// requires a claimed signing time, even when every cryptographic fact holds.
#[test]
fn a_delay_policy_requires_the_claimed_signing_time() {
    let policy = Policy {
        timestamp_delay: Some(core::time::Duration::from_secs(60)),
        ..ETSI_TS_119_312_V2_1_1
    };
    let outcome = validate(&facts(), &policy);
    assert_eq!(outcome.indication, Indication::Indeterminate);
    assert_eq!(outcome.sub, Some(SubIndication::SigConstraintsFailure));
    assert_eq!(outcome.basis, Some(Basis::TimestampDelay));
}

/// EN 319 102-1 5.2.6.4 step 8 uses current validation time, not the
/// signature timestamp, for the certificate authenticating revocation data.
#[test]
fn an_expired_revocation_issuer_prevents_path_success() {
    let issuers = [RevocationIssuer {
        not_before: day(2025, 1, 1),
        not_after: day(2026, 8, 1),
    }];
    let paths = [Path {
        revocation_issuers: &issuers,
        ..GOOD
    }];
    let outcome = run(&Facts {
        paths: &paths,
        ..facts()
    });
    assert_eq!(outcome.indication, Indication::Indeterminate);
    assert_eq!(outcome.sub, Some(SubIndication::RevocationOutOfBoundsNoPoe));
    assert_eq!(
        outcome.basis,
        Some(Basis::RevocationIssuer { path: 0, index: 0 })
    );
    assert_eq!(outcome.path, Some(0));
}

/// Initialization is step 3: format and certificate identification precede
/// it, while a bad signature value cannot hide an unprocessed policy.
#[test]
fn initialization_failures_follow_the_building_block_order() {
    let mut input = facts();
    input.context = Context::PolicyProcessingError;
    input.value = Value::Mismatch;
    assert_eq!(run(&input).sub, Some(SubIndication::PolicyProcessingError));
    assert_eq!(run(&input).axes.crypto, None);
    assert_eq!(run(&input).path, None);
    input.signer = None;
    assert_eq!(
        run(&input).sub,
        Some(SubIndication::NoSigningCertificateFound)
    );
    input.format = Format::Malformed;
    assert_eq!(run(&input).sub, Some(SubIndication::FormatFailure));
}

/// Step 5b requires strictly after, down to the nanosecond, and the claimed
/// time must not replace either proven bound or best-signature-time.
#[test]
fn timestamp_delay_is_strict_and_does_not_promote_the_claim() {
    let policy = Policy {
        timestamp_delay: Some(core::time::Duration::from_secs(60)),
        ..ETSI_TS_119_312_V2_1_1
    };
    let best = facts().time.before.unwrap();
    let table = LeapTable::new(best.seconds() - 200, best.seconds() + 200, &[]).unwrap();
    let mut input = facts();
    input.utc = Some(&table);
    for (offset, expected) in [
        (-1, None),
        (0, Some(SubIndication::SigConstraintsFailure)),
        (1, Some(SubIndication::SigConstraintsFailure)),
    ] {
        input.claimed_signing_time = Some(table.shift(best, -60_000_000_000 - offset).unwrap());
        let outcome = validate(&input, &policy);
        assert_eq!(outcome.sub, expected);
        assert_eq!(outcome.best_signature_time, best);
        assert_eq!(outcome.axes.validity, Some(Coverage::Undecided));
    }
    input.claimed_signing_time = None;
    input.signature_timestamp = false;
    assert_eq!(
        validate(&input, &policy).indication,
        Indication::TotalPassed
    );
    input.signature_timestamp = true;
    input.order = Order::Violated;
    assert_eq!(
        validate(&input, &policy).sub,
        Some(SubIndication::TimestampOrderFailure)
    );
}

/// The same positive leap second belongs to elapsed delay. A two-second
/// deadline from 23:59:59 is midnight exactly, so equality must fail.
#[test]
fn timestamp_delay_uses_the_common_leap_arithmetic() {
    use structured_pkix::temporal::Transition;
    let midnight = day(2026, 6, 1);
    let transitions = [Transition::new(midnight.seconds(), 1)];
    let table = LeapTable::new(
        midnight.seconds() - 100,
        midnight.seconds() + 100,
        &transitions,
    )
    .unwrap();
    let policy = Policy {
        timestamp_delay: Some(core::time::Duration::from_secs(2)),
        ..ETSI_TS_119_312_V2_1_1
    };
    let input = Facts {
        claimed_signing_time: Instant::new(midnight.seconds() - 1, 0),
        utc: Some(&table),
        ..facts()
    };
    assert_eq!(
        validate(&input, &policy).sub,
        Some(SubIndication::SigConstraintsFailure)
    );
    let longer = Policy {
        timestamp_delay: Some(core::time::Duration::from_nanos(2_000_000_001)),
        ..policy
    };
    assert_eq!(
        validate(&input, &longer).indication,
        Indication::TotalPassed
    );
}

/// Missing corrections, uncovered endpoints and huge shifts cannot silently
/// fall back to POSIX seconds or fabricate a passed delay constraint.
#[test]
fn timestamp_delay_preserves_time_uncertainty() {
    let policy = Policy {
        timestamp_delay: Some(core::time::Duration::from_secs(60)),
        ..ETSI_TS_119_312_V2_1_1
    };
    let best = facts().time.before.unwrap();
    let mut input = Facts {
        claimed_signing_time: Some(best),
        ..facts()
    };
    let expected = Some(SubIndication::Custom(Custom::TimeUncertain));
    assert_eq!(validate(&input, &policy).sub, expected);
    let short = LeapTable::new(best.seconds() - 10, best.seconds() + 10, &[]).unwrap();
    input.utc = Some(&short);
    assert_eq!(validate(&input, &policy).sub, expected);
    let huge = Policy {
        timestamp_delay: Some(core::time::Duration::MAX),
        ..policy
    };
    assert_eq!(validate(&input, &huge).sub, expected);
    let later = LeapTable::new(best.seconds() + 1, best.seconds() + 200, &[]).unwrap();
    input.utc = Some(&later);
    input.claimed_signing_time = Instant::new(best.seconds() + 1, 0);
    assert_eq!(validate(&input, &policy).sub, expected);
}

/// Issuer validity includes both endpoints; every used issuer must pass,
/// and another fully valid path remains usable after one issuer fails.
#[test]
fn revocation_issuer_validity_is_inclusive_and_path_specific() {
    let now = facts().now;
    let good = RevocationIssuer {
        not_before: now,
        not_after: now,
    };
    let bad = RevocationIssuer {
        not_before: day(2027, 1, 1),
        not_after: day(2028, 1, 1),
    };
    let issuers = [good, bad];
    let bad_path = Path {
        revocation_issuers: &issuers,
        ..GOOD
    };
    let paths = [bad_path];
    let outcome = run(&Facts {
        paths: &paths,
        ..facts()
    });
    assert_eq!(outcome.sub, Some(SubIndication::RevocationOutOfBoundsNoPoe));
    assert_eq!(
        outcome.basis,
        Some(Basis::RevocationIssuer { path: 0, index: 1 })
    );
    let paths = [Path {
        revocation_issuers: &issuers[..1],
        ..GOOD
    }];
    assert_eq!(
        run(&Facts {
            paths: &paths,
            ..facts()
        })
        .indication,
        Indication::TotalPassed
    );
    let paths = [bad_path, GOOD];
    assert_eq!(
        run(&Facts {
            paths: &paths,
            ..facts()
        })
        .path,
        Some(1)
    );
    assert_eq!(
        run(&Facts {
            paths: &paths,
            ..facts()
        })
        .indication,
        Indication::TotalPassed
    );
}

/// The ordinary signature passes at its timestamp, as 5.5.4 decides it,
/// while the axes say what the interval leaves open: with no lower bound
/// the certificate's validity across the interval is undecided and the
/// anchor is recognized only from the upper bound (EN 319 102-1 clause 5.5.4).
#[test]
fn an_ordinary_timestamped_signature_passes_and_its_axes_keep_the_interval() {
    let outcome = run(&facts());
    assert_eq!(outcome.indication, Indication::TotalPassed);
    assert_eq!(outcome.sub, None);
    assert_eq!(outcome.basis, None);
    assert_eq!(outcome.process, Process::WithTime);
    assert_eq!(outcome.best_signature_time, day(2026, 6, 1));
    assert_eq!(outcome.path, Some(0));
    assert_eq!(
        outcome.axes,
        Axes {
            integrity: Integrity::Intact,
            validity: Some(Coverage::Undecided),
            revocation: Some(NOT_REVOKED),
            trust: Some(Conclusion::UpperBoundOnly),
            crypto: None,
            changes: Changes::NotApplicable,
        }
    );
}

/// What changed after the signed revision is reported and decides nothing:
/// an unpermitted later change leaves the signature's own indication as it
/// was.
#[test]
fn later_changes_are_an_axis_and_not_the_indication() {
    for changes in [
        Changes::None,
        Changes::Permitted,
        Changes::Unpermitted,
        Changes::Undetermined,
    ] {
        let outcome = run(&Facts { changes, ..facts() });
        assert_eq!(outcome.indication, Indication::TotalPassed);
        assert_eq!(outcome.axes.changes, changes);
    }
}

/// With a proven lower bound inside the validity the interval is covered
/// whole; with no timestamp the basic process runs at the current time.
#[test]
fn the_axes_and_the_process_follow_what_is_proven_about_time() {
    let mut bounded = facts();
    bounded.time.after = Some(day(2026, 5, 1));
    assert_eq!(run(&bounded).axes.validity, Some(Coverage::Whole));

    let mut basic = facts();
    basic.time.before = None;
    let outcome = run(&basic);
    assert_eq!(outcome.indication, Indication::TotalPassed);
    assert_eq!(outcome.process, Process::Basic);
    assert_eq!(outcome.best_signature_time, day(2026, 10, 19));
}

/// 5.3.4 step 1: an unprocessable format is `FORMAT_FAILURE`, whatever else
/// the facts say.
#[test]
fn a_malformed_signature_fails_on_its_format_first() {
    let mut facts = facts();
    facts.format = Format::Malformed;
    facts.value = Value::Mismatch;
    facts.signer = None;
    let outcome = run(&facts);
    assert_eq!(outcome.indication, Indication::TotalFailed);
    assert_eq!(outcome.sub, Some(SubIndication::FormatFailure));
    assert_eq!(outcome.basis, Some(Basis::Format));
}

/// 5.3.4 step 2: without a signing certificate nothing else is decided.
#[test]
fn without_a_signing_certificate_the_result_is_indeterminate() {
    let mut facts = facts();
    facts.signer = None;
    facts.value = Value::Mismatch;
    assert_eq!(sub(&facts), Some("NO_SIGNING_CERTIFICATE_FOUND"));
}

/// 5.2.7.4: signed data is obtained before any hash is compared, and the
/// hashes before the signature value; each finding names what it rests on.
#[test]
fn cryptographic_verification_follows_its_steps_in_order() {
    let mut facts = facts();
    let refs = [Reference::Intact, Reference::Mismatch, Reference::Missing];
    facts.references = &refs;
    facts.value = Value::Mismatch;
    let outcome = run(&facts);
    assert_eq!(outcome.sub, Some(SubIndication::SignedDataNotFound));
    assert_eq!(outcome.basis, Some(Basis::Reference(2)));
    assert_eq!(outcome.axes.integrity, Integrity::Broken);

    let refs = [Reference::Intact, Reference::Mismatch];
    facts.references = &refs;
    let outcome = run(&facts);
    assert_eq!(outcome.indication, Indication::TotalFailed);
    assert_eq!(outcome.sub, Some(SubIndication::HashFailure));
    assert_eq!(outcome.basis, Some(Basis::Reference(1)));

    facts.references = &INTACT;
    let outcome = run(&facts);
    assert_eq!(outcome.sub, Some(SubIndication::SigCryptoFailure));
    assert_eq!(outcome.basis, Some(Basis::SignatureValue));
}

/// 5.3.4 step 5: a signature that does not verify fails even where no chain
/// could be built, and a value this build cannot compute is indeterminate,
/// never a failure.
#[test]
fn a_failed_verification_outranks_the_certificate_validation() {
    let mut facts = facts();
    facts.paths = &[];
    facts.value = Value::Mismatch;
    assert_eq!(run(&facts).indication, Indication::TotalFailed);

    facts.value = Value::Unsupported;
    let outcome = run(&facts);
    assert_eq!(outcome.indication, Indication::Indeterminate);
    assert_eq!(
        outcome.sub,
        Some(SubIndication::Custom(Custom::UnsupportedAlgorithm))
    );
    assert_eq!(outcome.axes.integrity, Integrity::Unsupported);
}

/// 5.5.4 step 4b: proof the signature existed before notBefore fails it.
#[test]
fn a_signature_proven_before_the_certificate_is_not_yet_valid() {
    let mut facts = facts();
    facts.time.before = Some(day(2024, 12, 31));
    let outcome = run(&facts);
    assert_eq!(outcome.indication, Indication::TotalFailed);
    assert_eq!(outcome.sub, Some(SubIndication::NotYetValid));
    assert_eq!(outcome.basis, Some(Basis::SignerValidity));
    assert_eq!(outcome.axes.validity, Some(Coverage::Outside));
}

/// Expiry is not retroactive: a signature timestamped inside the validity
/// still passes after the certificate expired. Without such proof the
/// signature is out of bounds, known not revoked or not, and with proof it
/// was made after notAfter it fails as EXPIRED (5.3.4 step 4, 5.5.4 step
/// 4d).
#[test]
fn expiry_is_judged_at_best_signature_time() {
    let mut facts = facts();
    facts.now = day(2030, 1, 1);
    assert_eq!(run(&facts).indication, Indication::TotalPassed);

    facts.time.before = None;
    assert_eq!(sub(&facts), Some("OUT_OF_BOUNDS_NOT_REVOKED"));

    if let Some(signer) = facts.signer.as_mut() {
        signer.revocation = Status::NoEvidence;
    }
    assert_eq!(sub(&facts), Some("OUT_OF_BOUNDS_NO_POE"));

    let mut facts = self::facts();
    facts.time.after = Some(day(2027, 12, 31));
    facts.time.before = Some(day(2028, 1, 2));
    let outcome = run(&facts);
    assert_eq!(outcome.indication, Indication::TotalFailed);
    assert_eq!(outcome.sub, Some(SubIndication::Expired));
}

/// A revocation the evidence places after best-signature-time does not
/// reach back; one it cannot place is `REVOKED_NO_POE`; one proven before the
/// signature was made fails it (5.3.4 step 4, 5.5.4 step 4a).
#[test]
fn a_revocation_is_judged_against_best_signature_time() {
    let mut facts = facts();
    let signer = facts.signer.as_mut().unwrap();
    signer.revocation = Status::NotRevoked {
        basis: 0,
        later: match revoked(When::NotProvablyAfter) {
            Status::Revoked { revoked, .. } => Some(revoked),
            _ => unreachable!(),
        },
    };
    assert_eq!(run(&facts).indication, Indication::TotalPassed);

    facts.signer.as_mut().unwrap().revocation = revoked(When::NotProvablyAfter);
    let outcome = run(&facts);
    assert_eq!(outcome.indication, Indication::Indeterminate);
    assert_eq!(outcome.sub, Some(SubIndication::RevokedNoPoe));
    assert_eq!(outcome.basis, Some(Basis::SignerRevocation));

    facts.signer.as_mut().unwrap().revocation = revoked(When::Before);
    let outcome = run(&facts);
    assert_eq!(outcome.indication, Indication::TotalFailed);
    assert_eq!(outcome.sub, Some(SubIndication::Revoked));
}

/// Stale, held or absent status information may become decidable later;
/// what Table 6 does not name is a stated custom diagnostic. None of them
/// passes.
#[test]
fn undecided_revocation_is_indeterminate_and_says_why() {
    let cases = [
        (Status::NotFresh { basis: 0 }, "TRY_LATER", None),
        (Status::OnHold { basis: 0 }, "TRY_LATER", None),
        (Status::NoEvidence, "TRY_LATER", None),
        (
            Status::Unknown { basis: 0 },
            "CUSTOM",
            Some(Custom::RevocationUnknown),
        ),
        (
            Status::Conflict {
                first: 0,
                second: 1,
            },
            "CUSTOM",
            Some(Custom::RevocationConflict),
        ),
        (
            Status::HeldOrRevoked { basis: 0 },
            "CUSTOM",
            Some(Custom::RevocationHeldOrRevoked),
        ),
    ];
    for (status, token, custom) in cases {
        let mut facts = facts();
        facts.signer.as_mut().unwrap().revocation = status;
        let outcome = run(&facts);
        assert_eq!(outcome.indication, Indication::Indeterminate, "{status:?}");
        assert_eq!(outcome.sub.map(SubIndication::as_str), Some(token));
        if let Some(custom) = custom {
            assert_eq!(outcome.sub, Some(SubIndication::Custom(custom)));
        }
    }
}

/// 5.2.6.4: each way a chain can fall short has its sub-indication and
/// names the path, and an authority revoked is `REVOKED_CA_NO_POE`.
#[test]
fn each_chain_shortfall_has_its_sub_indication() {
    let mut facts = facts();
    facts.paths = &[];
    assert_eq!(sub(&facts), Some("NO_CERTIFICATE_CHAIN_FOUND"));
    assert_eq!(run(&facts).basis, Some(Basis::Paths));

    let revoked_ca = [revoked(When::NotProvablyAfter)];
    let shortfalls = [
        (
            Path {
                chain: Chain::GeneralFailure,
                ..GOOD
            },
            "CERTIFICATE_CHAIN_GENERAL_FAILURE",
            Basis::Path(0),
        ),
        (
            Path {
                anchor: Anchor {
                    current: Conclusion::NoRule,
                    over_interval: Conclusion::NoRule,
                },
                ..GOOD
            },
            "NO_CERTIFICATE_CHAIN_FOUND",
            Basis::Path(0),
        ),
        (
            Path {
                anchor: Anchor {
                    current: Conclusion::NotRecognized,
                    over_interval: Conclusion::UpperBoundOnly,
                },
                ..GOOD
            },
            "NO_CERTIFICATE_CHAIN_FOUND_NO_POE",
            Basis::Path(0),
        ),
        (
            Path {
                authorities: &revoked_ca,
                ..GOOD
            },
            "REVOKED_CA_NO_POE",
            Basis::Authority { path: 0, index: 0 },
        ),
        (
            Path {
                chain: Chain::ConstraintsFailure,
                ..GOOD
            },
            "CHAIN_CONSTRAINTS_FAILURE",
            Basis::Path(0),
        ),
    ];
    for (path, token, basis) in shortfalls {
        let paths = [path];
        let outcome = run(&Facts {
            paths: &paths,
            ..facts
        });
        assert_eq!(outcome.indication, Indication::Indeterminate, "{token}");
        assert_eq!(outcome.sub.map(SubIndication::as_str), Some(token));
        assert_eq!(outcome.basis, Some(basis));
        assert_eq!(outcome.path, Some(0));
    }
}

/// 5.2.6.4 step 2: the first chain that validates is used however many
/// failed before it, and where none does the last one's status is reported.
#[test]
fn the_first_passing_chain_is_used_and_otherwise_the_last_status_reported() {
    let broken = Path {
        chain: Chain::GeneralFailure,
        ..GOOD
    };
    let constrained = Path {
        chain: Chain::ConstraintsFailure,
        ..GOOD
    };
    let mut facts = facts();
    let paths = [broken, constrained, GOOD];
    facts.paths = &paths;
    let outcome = run(&facts);
    assert_eq!(outcome.indication, Indication::TotalPassed);
    assert_eq!(outcome.path, Some(2));

    let paths = [broken, constrained];
    facts.paths = &paths;
    let outcome = run(&facts);
    assert_eq!(outcome.sub, Some(SubIndication::ChainConstraintsFailure));
    assert_eq!(outcome.path, Some(1));
}

/// RSA 2048 holds through 2026. A signature timestamped in 2026 still
/// passes in 2027; one with no proof is `CRYPTO_CONSTRAINTS_FAILURE_NO_POE`
/// with the end the policy knew; one proven made after the end fails the
/// constraint outright (5.3.4 step 6, 5.5.4 steps 4c and 8).
#[test]
fn the_signatures_algorithms_are_judged_at_best_signature_time() {
    let own = [SHA256_RSA2048];
    let mut facts = facts();
    facts.materials = &own;
    facts.now = day(2027, 6, 1);
    assert_eq!(run(&facts).indication, Indication::TotalPassed);

    facts.time.before = None;
    let outcome = run(&facts);
    assert_eq!(
        outcome.sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
    assert_eq!(outcome.basis, Some(Basis::Material(0)));
    let unmet = outcome.unmet.unwrap();
    assert_eq!(unmet.mechanism, Mechanism::Scheme(rsa(2048)));
    assert_eq!(unmet.until, Some(day(2027, 1, 1)));
    assert_eq!(outcome.axes.crypto, Some((Basis::Material(0), unmet)));

    facts.time.after = Some(day(2027, 2, 1));
    facts.time.before = Some(day(2027, 3, 1));
    assert_eq!(sub(&facts), Some("CRYPTO_CONSTRAINTS_FAILURE"));
}

/// A signature made under SHA-1 and timestamped while SHA-1 was still
/// considered secure passes today; without the timestamp it does not.
#[test]
fn a_sha1_signature_needs_proof_it_existed_before_2012_08() {
    let sha1 = [Material {
        hash: Some(Hash::Sha1),
        scheme: Some(rsa(2048)),
    }];
    let mut facts = facts();
    facts.materials = &sha1;
    facts.signer = Some(Signer {
        not_before: day(2010, 1, 1),
        not_after: day(2012, 1, 1),
        revocation: NOT_REVOKED,
    });
    facts.time.before = Some(day(2011, 3, 1));
    assert_eq!(run(&facts).indication, Indication::TotalPassed);

    facts.time.before = None;
    assert_eq!(run(&facts).indication, Indication::Indeterminate);
}

/// Certificates and revocation data are judged at the current time, even
/// where the signature itself is timestamped while their algorithm still
/// held: a proof of their own existence is the long-term process of 5.6,
/// not this one (5.5.4 step 10 and NOTE 7), so none is taken.
#[test]
fn path_material_is_judged_at_the_current_time() {
    let weak = [SHA256_RSA2048];
    let path = [Path {
        materials: &weak,
        ..GOOD
    }];
    let mut facts = facts();
    facts.paths = &path;
    facts.now = day(2027, 6, 1);
    let outcome = run(&facts);
    assert_eq!(
        outcome.sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
    assert_eq!(
        outcome.basis,
        Some(Basis::PathMaterial { path: 0, index: 0 })
    );
    // The signature's timestamp in 2026 does not carry over to them.
    assert_eq!(facts.time.before, Some(day(2026, 6, 1)));
}

/// EN 319 102-1 V1.4.1 5.2.6.4 step 4b/c ends the selected chain before
/// its later X.509 and cryptographic constraints can hide signer revocation.
#[test]
fn signer_revocation_precedes_later_path_constraints() {
    let weak = [SHA256_RSA2048];
    for chain in [Chain::Valid, Chain::ConstraintsFailure] {
        let paths = [Path {
            chain,
            materials: &weak,
            ..GOOD
        }];
        for (status, expected) in [
            (revoked(When::Before), SubIndication::Revoked),
            (revoked(When::NotProvablyAfter), SubIndication::RevokedNoPoe),
            (Status::OnHold { basis: 0 }, SubIndication::TryLater),
        ] {
            let mut facts = facts();
            facts.paths = &paths;
            facts.now = day(2027, 6, 1);
            facts.time.after = Some(day(2026, 1, 1));
            facts.signer.as_mut().unwrap().revocation = status;
            let outcome = run(&facts);
            assert_eq!(outcome.sub, Some(expected), "{chain:?}, {status:?}");
            assert_eq!(outcome.basis, Some(Basis::SignerRevocation));
            assert_eq!(outcome.path, Some(0));
        }
    }
}

/// A hold is step 4c, before the signing-certificate validity of step 7.
/// Even proven expiry must not replace its `TRY_LATER` response.
#[test]
fn signer_hold_precedes_signer_expiry() {
    let mut facts = facts();
    facts.now = day(2028, 10, 1);
    facts.signer.as_mut().unwrap().revocation = Status::OnHold { basis: 0 };
    facts.time.after = Some(day(2028, 1, 1));
    facts.time.before = Some(day(2028, 6, 1));
    let outcome = run(&facts);
    assert_eq!(outcome.sub, Some(SubIndication::TryLater));
    assert_eq!(outcome.basis, Some(Basis::SignerRevocation));
}

/// A path whose validation fails still reports its anchor's recognition
/// over the interval: the trust axis follows the path the outcome names.
#[test]
fn the_trust_axis_follows_a_failing_reported_path() {
    let paths = [Path {
        chain: Chain::ConstraintsFailure,
        ..GOOD
    }];
    let outcome = run(&Facts {
        paths: &paths,
        ..facts()
    });
    assert_eq!(outcome.path, Some(0));
    assert_eq!(outcome.axes.trust, Some(Conclusion::UpperBoundOnly));
}

/// 5.5.4 step 4c precedes step 4e: material still below the constraints at
/// best-signature-time is reported before the timestamps' order.
#[test]
fn the_signatures_algorithms_are_judged_before_the_timestamp_order() {
    let own = [SHA256_RSA2048];
    let outcome = run(&Facts {
        materials: &own,
        order: Order::Violated,
        time: Time {
            after: None,
            before: None,
        },
        now: day(2027, 6, 1),
        ..facts()
    });
    assert_eq!(
        outcome.sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
}

/// A key size the policy never considered secure: with a content timestamp
/// the signature is proven made while it was not reliable, which is
/// `CRYPTO_CONSTRAINTS_FAILURE` (5.3.4 step 6); without one it is the
/// `_NO_POE` form SAV returns (5.2.8.4.1). A chain's material is always the
/// `_NO_POE` form, which 5.2.6.4 step 6 and 5.5.4 step 10 name.
#[test]
fn never_secure_material_fails_outright_only_when_proven_made_after() {
    let rsa512 = Material {
        hash: Some(Hash::Sha256),
        scheme: Some(rsa(512)),
    };
    let own = [rsa512];
    for (after, expected) in [
        (None, SubIndication::CryptoConstraintsFailureNoPoe),
        (
            Some(day(2026, 5, 1)),
            SubIndication::CryptoConstraintsFailure,
        ),
    ] {
        let outcome = run(&Facts {
            materials: &own,
            time: Time {
                after,
                before: Some(day(2026, 6, 1)),
            },
            ..facts()
        });
        assert_eq!(outcome.sub, Some(expected), "{after:?}");
    }
    let weak = [rsa512];
    let paths = [Path {
        materials: &weak,
        ..GOOD
    }];
    assert_eq!(
        run(&Facts {
            paths: &paths,
            time: Time {
                after: Some(day(2026, 5, 1)),
                before: Some(day(2026, 6, 1)),
            },
            ..facts()
        })
        .sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
}

/// 5.2.6.4 steps 2 and 3 decide whether a chain reaches a trusted anchor
/// before step 4 validates it, so an untrusted anchor is reported over a
/// general path failure.
#[test]
fn the_anchor_is_judged_before_path_validation() {
    let paths = [Path {
        chain: Chain::GeneralFailure,
        anchor: Anchor {
            current: Conclusion::NoRule,
            over_interval: Conclusion::NoRule,
        },
        ..GOOD
    }];
    assert_eq!(
        run(&Facts {
            paths: &paths,
            ..facts()
        })
        .sub,
        Some(SubIndication::NoCertificateChainFound)
    );
}

/// The anchor is judged at the current time, as the basic validation of
/// 5.5.4 step 2 judges it: one trusted when the signature was timestamped
/// and no longer trusted now is `NO_CERTIFICATE_CHAIN_FOUND_NO_POE`, which
/// nothing later in 5.5.4 recovers.
#[test]
fn an_anchor_no_longer_trusted_now_is_not_recovered_by_a_timestamp() {
    let paths = [Path {
        anchor: Anchor {
            current: Conclusion::NotRecognized,
            over_interval: Conclusion::Recognized,
        },
        ..GOOD
    }];
    let outcome = run(&Facts {
        paths: &paths,
        time: Time {
            after: Some(day(2026, 5, 1)),
            before: Some(day(2026, 6, 1)),
        },
        ..facts()
    });
    assert_eq!(
        outcome.sub,
        Some(SubIndication::NoCertificateChainFoundNoPoe)
    );
    assert_eq!(outcome.axes.trust, Some(Conclusion::Recognized));
}

/// A signature element the policy requires and the signature lacks is
/// `SIG_CONSTRAINTS_FAILURE`, naming the element (5.2.8.4); the same
/// signature carrying it passes.
#[test]
fn a_missing_required_element_is_a_signature_constraints_failure() {
    let policy = Policy {
        elements: Elements::NONE.with(Element::SigningCertificate),
        ..ETSI_TS_119_312_V2_1_1
    };
    let outcome = validate(&facts(), &policy);
    assert_eq!(outcome.indication, Indication::Indeterminate);
    assert_eq!(outcome.sub, Some(SubIndication::SigConstraintsFailure));
    assert_eq!(
        outcome.basis,
        Some(Basis::Element(Element::SigningCertificate))
    );
    let carried = Facts {
        elements: Elements::NONE.with(Element::SigningCertificate),
        ..facts()
    };
    assert_eq!(
        validate(&carried, &policy).indication,
        Indication::TotalPassed
    );
}

/// A signature whose RSA exponent is 3 is outside clause 6.2.2.1 of TS 119
/// 312 and does not pass, whatever its modulus.
#[test]
fn a_small_rsa_exponent_does_not_pass() {
    let own = [Material {
        hash: Some(Hash::Sha256),
        scheme: Some(Scheme {
            exponent_bits: Some(2),
            ..rsa(4096)
        }),
    }];
    let outcome = run(&Facts {
        materials: &own,
        ..facts()
    });
    assert_eq!(
        outcome.sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
    assert_eq!(
        outcome.unmet.map(|unmet| unmet.mechanism),
        Some(Mechanism::Exponent(Scheme {
            exponent_bits: Some(2),
            ..rsa(4096)
        }))
    );
}

/// TS 119 312 V2.1.1 8.4 Table 7: a large DSA p must not hide a weak q
/// in the public validation result, even with an otherwise intact signature.
#[test]
fn a_weak_dsa_subgroup_prevents_total_passed() {
    let own = [Material {
        hash: Some(Hash::Sha256),
        scheme: Some(Scheme {
            family: Family::Dsa,
            bits: 3072,
            exponent_bits: None,
            subgroup_bits: Some(160),
        }),
    }];
    let outcome = run(&Facts {
        materials: &own,
        ..facts()
    });
    assert_eq!(outcome.indication, Indication::Indeterminate);
    assert_eq!(
        outcome.sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
    assert_eq!(outcome.basis, Some(Basis::Material(0)));
    assert_eq!(outcome.unmet.unwrap().until, Some(day(2015, 12, 1)));
}

/// TS 119 312 V2.1.1 7.3 Table 4: a cryptographically verified SHA3/RSA
/// PKCS#1 v1.5 signature still does not meet the default policy's suite list.
#[test]
fn an_unlisted_signature_suite_prevents_total_passed() {
    let own = [Material {
        hash: Some(Hash::Sha3_256),
        scheme: Some(rsa(3072)),
    }];
    let outcome = run(&Facts {
        materials: &own,
        ..facts()
    });
    assert_eq!(outcome.indication, Indication::Indeterminate);
    assert_eq!(
        outcome.sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
    assert_eq!(outcome.basis, Some(Basis::Material(0)));
    assert_eq!(
        outcome.unmet.unwrap().mechanism,
        Mechanism::Suite {
            hash: Hash::Sha3_256,
            scheme: rsa(3072)
        }
    );
}

/// Certificate material uses the same suite gate, at validation time, and
/// reports that path's material rather than blaming the document signature.
#[test]
fn an_unlisted_path_suite_keeps_its_evidence_location() {
    let materials = [Material {
        hash: Some(Hash::Sha3_256),
        scheme: Some(rsa(3072)),
    }];
    let paths = [Path {
        materials: &materials,
        ..GOOD
    }];
    let outcome = run(&Facts {
        paths: &paths,
        ..facts()
    });
    assert_eq!(
        outcome.sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
    assert_eq!(
        outcome.basis,
        Some(Basis::PathMaterial { path: 0, index: 0 })
    );
    assert_eq!(
        outcome.unmet.unwrap().mechanism,
        Mechanism::Suite {
            hash: Hash::Sha3_256,
            scheme: rsa(3072)
        }
    );
}

/// Caller-selected suites apply whole, without an implicit catalogue override.
#[test]
fn caller_selected_suites_replace_the_catalogue() {
    let constraints = Constraints {
        suites: &[crate::validation::crypto::SuiteRule {
            family: Family::RsaPkcs1,
            hashes: &[Hash::Sha256, Hash::Sha3_256],
        }],
        ..ETSI_TS_119_312_V2_1_1.crypto
    };
    let policy = Policy {
        crypto: constraints,
        ..ETSI_TS_119_312_V2_1_1
    };
    let materials = [Material {
        hash: Some(Hash::Sha3_256),
        scheme: Some(rsa(3072)),
    }];
    let facts = Facts {
        materials: &materials,
        ..facts()
    };
    assert_eq!(
        validate(&facts, &policy).indication,
        Indication::TotalPassed
    );
    assert_eq!(
        run(&facts).sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
}

/// 5.5.4 step 4e.
#[test]
fn disordered_timestamps_are_a_timestamp_order_failure() {
    let mut facts = facts();
    facts.order = Order::Violated;
    let outcome = run(&facts);
    assert_eq!(outcome.sub, Some(SubIndication::TimestampOrderFailure));
    assert_eq!(outcome.basis, Some(Basis::Timestamps));
}

/// An explicitly empty set accepts no mechanism, without catalogue fallback.
#[test]
fn caller_selected_empty_constraints_have_no_fallback() {
    const NONE: Constraints<'static> = Constraints {
        hashes: &[],
        schemes: &[],
        suites: &[],
        rsa_exponent_bits: None,
    };
    let policy = Policy {
        crypto: NONE,
        ..ETSI_TS_119_312_V2_1_1
    };
    let facts = facts();
    assert_eq!(run(&facts).indication, Indication::TotalPassed);
    assert_eq!(
        validate(&facts, &policy).sub,
        Some(SubIndication::CryptoConstraintsFailureNoPoe)
    );
}

/// Every combination of a grid of facts: evaluation is deterministic, and
/// adding validation data, here a further path built for the same
/// certificate, never changes a TOTAL-PASSED or TOTAL-FAILED result
/// (5.1.3, rule b for both), while it may settle an indeterminate one. The
/// facts are one signer's alone, so nothing about another signature can
/// enter them, let alone improve them.
#[test]
fn more_validation_data_never_overturns_a_determinate_result() {
    let revocations = [
        NOT_REVOKED,
        revoked(When::Before),
        revoked(When::NotProvablyAfter),
        Status::NotFresh { basis: 0 },
        Status::NoEvidence,
    ];
    let times = [
        Time {
            after: None,
            before: None,
        },
        Time {
            after: None,
            before: Some(day(2026, 6, 1)),
        },
        Time {
            after: Some(day(2026, 5, 1)),
            before: Some(day(2026, 6, 1)),
        },
        Time {
            after: None,
            before: Some(day(2024, 6, 1)),
        },
        Time {
            after: Some(day(2028, 1, 1)),
            before: Some(day(2028, 2, 1)),
        },
    ];
    let candidates = [
        GOOD,
        Path {
            chain: Chain::GeneralFailure,
            ..GOOD
        },
        Path {
            anchor: Anchor {
                current: Conclusion::NotRecognized,
                over_interval: Conclusion::NotRecognized,
            },
            ..GOOD
        },
        Path {
            chain: Chain::ConstraintsFailure,
            ..GOOD
        },
    ];
    let values = [Value::Verified, Value::Mismatch, Value::Unsupported];
    let nows = [day(2026, 10, 19), day(2030, 1, 1)];
    let mut checked = 0usize;
    for revocation in revocations {
        for time in times {
            for value in values {
                for now in nows {
                    for first in 0..candidates.len() {
                        let base = [candidates[first]];
                        let mut facts = facts();
                        facts.signer.as_mut().unwrap().revocation = revocation;
                        facts.time = time;
                        facts.value = value;
                        facts.now = now;
                        facts.paths = &base;
                        let before = run(&facts);
                        assert_eq!(before, run(&facts));
                        for added in candidates {
                            for paths in [
                                vec![candidates[first], added],
                                vec![added, candidates[first]],
                            ] {
                                let more = Facts {
                                    paths: &paths,
                                    ..facts
                                };
                                let after = run(&more);
                                if before.indication != Indication::Indeterminate {
                                    assert_eq!(after.indication, before.indication, "{more:?}");
                                }
                                checked += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(checked, 5 * 5 * 3 * 2 * 4 * 4 * 2);
}
