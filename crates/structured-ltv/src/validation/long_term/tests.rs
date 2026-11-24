use super::*;
use crate::pki::status::Status;
use crate::validation::{
    Anchor, Changes, Context, ETSI_TS_119_312_V2_1_1, Element, Elements, Format, Order, Path,
    Recognition, Reference, Signer, Time, Value,
};
use alloc::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};

const fn at(seconds: i64) -> Instant {
    match Instant::new(seconds, 0) {
        Some(value) => value,
        None => panic!("whole seconds form an instant"),
    }
}

const VALID: Validity = Validity {
    not_before: at(10),
    not_after: at(50),
};
const CURRENT: Instant = at(100);
const VALUE: Object = Object(0);
const CERT: Object = Object(1);
const ISSUER: Object = Object(2);
const REVOCATION: Object = Object(3);
const NEW_TOKEN: Object = Object(4);
const OLD_TOKEN: Object = Object(5);
const DIGEST: Object = Object(6);
const PRESENT: &[Object] = &[VALUE, CERT, ISSUER, REVOCATION, NEW_TOKEN, OLD_TOKEN];
const HISTORICAL: &[Proof] = &[
    Proof {
        object: CERT,
        at: at(20),
    },
    Proof {
        object: ISSUER,
        at: at(20),
    },
    Proof {
        object: REVOCATION,
        at: at(30),
    },
    Proof {
        object: VALUE,
        at: at(25),
    },
];
const REV: RevocationData<'static> = RevocationData {
    object: REVOCATION,
    issuer: ISSUER,
    issuer_validity: VALID,
    issued: at(30),
    fresh_before: Some(at(80)),
    status: Revocation::Clear,
    crypto: &[],
    delegated: None,
};
const MEMBER: Member<'static> = Member {
    object: CERT,
    crypto: &[],
    revocations: RevocationCheck::Required(&[REV]),
};
const CANDIDATE: Candidate<'static> = Candidate {
    chain: crate::validation::Chain::Valid,
    recognized: true,
    anchor_sunset: None,
    validity: VALID,
    members: &[MEMBER],
};
const CANDIDATES: &[Candidate<'static>] = &[CANDIDATE];
const INITIAL_SIGNATURE: Signature<'static> = Signature {
    value: VALUE,
    validity: VALID,
    candidates: CANDIDATES,
    model: ValidityModel::Shell,
    revoked_ca_at: None,
    revocations: &[REV],
    affected_crypto: &[],
    retry: RetryCause::Other,
};
const REQUIREMENTS: Requirements<'static> = Requirements {
    crypto: ETSI_TS_119_312_V2_1_1,
    elements: Elements::NONE,
    timestamp_delay: None,
};
const CURRENT_PATH: Path<'static> = Path {
    chain: crate::validation::Chain::Valid,
    anchor: Anchor {
        current: Recognition::Recognized,
        over_interval: Recognition::Recognized,
    },
    authorities: &[],
    materials: &[],
    revocation_issuers: &[],
    revocation_retry: None,
};

fn facts() -> Facts<'static> {
    Facts {
        format: Format::Conformant,
        context: Context::Ready,
        signer: Some(Signer {
            not_before: VALID.not_before,
            not_after: VALID.not_after,
            expiry_evidence: crate::pki::status::ExpiryEvidence::CaAssuranceAtSigning,
            revocation: Status::NotRevoked {
                basis: 0,
                later: None,
            },
        }),
        references: &[Reference::Intact],
        value: Value::Verified,
        materials: &[],
        signed_attribute_materials: &[],
        elements: Elements::NONE,
        time: Time {
            after: None,
            before: None,
        },
        content_timestamp: None,
        paths: &[CURRENT_PATH],
        truncated: false,
        order: Order::Coherent,
        signature_timestamp: false,
        signature_timestamps: &[],
        claimed_signing_time: None,
        utc: None,
        changes: Changes::NotApplicable,
        now: CURRENT,
    }
}

fn inputs<'a>(current: &'a Facts<'a>) -> Inputs<'a> {
    Inputs {
        object_count: 7,
        present: PRESENT,
        initial: HISTORICAL,
        current,
        signature: INITIAL_SIGNATURE,
        records: &[],
        timestamps: &[],
        has_long_term_attributes: true,
        require_long_term_attributes: false,
    }
}

fn memory(bytes: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(bytes, work)))
}

fn run(input: &Inputs<'_>, requirements: &Requirements<'_>) -> Report<Memory> {
    validate(input, requirements, &memory(1 << 20, 1_000_000)).unwrap()
}

#[test]
fn old_revocation_reconstructs_a_valid_historical_result() {
    let current = facts();
    let input = inputs(&current);
    let report = run(&input, &REQUIREMENTS);
    assert_eq!(
        report.current.sub,
        Some(SubIndication::OutOfBoundsNotRevoked)
    );
    assert_eq!(report.decision, Decision::Passed);
    assert_eq!(report.best_signature_time, at(25));
    let past = report.past.unwrap();
    assert_eq!(
        past.certificate,
        Some(PastCertificate::Passed {
            path: 0,
            horizon: Horizon::Through(at(30))
        })
    );
    assert_eq!(past.revocation_poe, Some(true));
    assert_eq!(past.signature_poe, Some(true));
}

/// EN 319 102-1 §5.6.3.4 step 9 and NOTE 6 assess the signature
/// at its earliest proof and keep the certificate's horizon independent.
#[test]
fn archival_acceptance_keeps_the_signature_proof_time_separate_from_control_time() {
    let material = [Material {
        hash: Some(Hash::Sha1),
        scheme: None,
    }];
    let current = Facts {
        materials: &material,
        ..facts()
    };
    let hashes = [crate::validation::HashRule {
        hash: Hash::Sha1,
        until: Some(at(28)),
    }];
    let requirements = Requirements {
        crypto: crate::validation::Constraints {
            hashes: &hashes,
            ..REQUIREMENTS.crypto
        },
        ..REQUIREMENTS
    };
    let report = run(&inputs(&current), &requirements);
    assert_eq!(report.best_signature_time, at(25));
    assert_eq!(
        report.past.unwrap().certificate,
        Some(PastCertificate::Passed {
            path: 0,
            horizon: Horizon::Through(at(30))
        })
    );
    assert_eq!(report.decision, Decision::Passed);
}

/// Historical recovery cannot hide the independent timestamp ordering check.
#[test]
fn historical_recovery_rechecks_timestamp_order_before_delay() {
    let mut current = facts();
    current.order = Order::Violated;
    current.signature_timestamp = true;
    let requirements = Requirements {
        timestamp_delay: Some(core::time::Duration::from_secs(10)),
        ..REQUIREMENTS
    };
    let report = run(&inputs(&current), &requirements);
    assert_eq!(
        report.current.sub,
        Some(SubIndication::OutOfBoundsNotRevoked)
    );
    assert_eq!(report.past.unwrap().decision, Decision::Passed);
    assert_eq!(report.stage, Stage::TimestampOrder);
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::TimestampOrderFailure)
    );
}

/// The outer archival process preserves anchor failure excluded by 5.6.3.4
/// step 3. The standalone past-signature block has its own recovery list.
#[test]
fn only_standalone_past_signature_recovers_a_sunset_current_anchor() {
    let paths = [Path {
        anchor: Anchor {
            current: Recognition::OutsideValidity,
            over_interval: Recognition::Recognized,
        },
        ..CURRENT_PATH
    }];
    let current = Facts {
        paths: &paths,
        ..facts()
    };
    let mut input = inputs(&current);
    let historical = [Candidate {
        anchor_sunset: Some(at(50)),
        ..CANDIDATE
    }];
    input.signature.candidates = &historical;
    let report = run(&input, &REQUIREMENTS);
    assert_eq!(
        report.current.sub,
        Some(SubIndication::NoCertificateChainFoundNoPoe)
    );
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::NoCertificateChainFoundNoPoe)
    );
    assert!(report.past.is_none());
    assert_eq!(
        past_result(
            input.signature,
            SubIndication::NoCertificateChainFoundNoPoe,
            HISTORICAL
        )
        .decision,
        Decision::Passed,
    );
}

/// Step 8 uses the archival proof time and preserves a required-element finding.
#[test]
fn archival_proof_can_recover_only_a_delay_constraint_failure() {
    let table = structured_pkix::temporal::LeapTable::new(0, 200, &[]).unwrap();
    let mut current = facts();
    current.signer.as_mut().unwrap().not_after = at(110);
    current.time.before = Some(at(90));
    current.signature_timestamp = true;
    current.claimed_signing_time = Some(at(20));
    current.utc = Some(&table);
    let requirements = Requirements {
        timestamp_delay: Some(core::time::Duration::from_secs(10)),
        ..REQUIREMENTS
    };
    let report = run(&inputs(&current), &requirements);
    assert_eq!(
        report.current.basis,
        Some(crate::validation::Basis::TimestampDelay)
    );
    assert_eq!(report.best_signature_time, at(25));
    assert_eq!(report.decision, Decision::Passed);

    let mut late = inputs(&current);
    late.initial = &HISTORICAL[..3];
    let report = run(&late, &requirements);
    assert_eq!(report.stage, Stage::TimestampDelay);
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::SigConstraintsFailure)
    );

    let missing = Requirements {
        elements: Elements::NONE.with(Element::ContentType),
        ..requirements
    };
    let report = run(&inputs(&current), &missing);
    assert_eq!(
        report.current.basis,
        Some(crate::validation::Basis::Element(Element::ContentType))
    );
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::SigConstraintsFailure)
    );
}

#[test]
fn missing_certificate_proof_keeps_original_finding_and_exposes_no_poe() {
    let current = facts();
    let mut input = inputs(&current);
    let candidates = [Candidate {
        anchor_sunset: Some(at(50)),
        ..CANDIDATE
    }];
    input.signature.candidates = &candidates;
    input.initial = &HISTORICAL[1..];
    let report = run(&input, &REQUIREMENTS);
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::OutOfBoundsNotRevoked)
    );
    let past = report.past.unwrap();
    assert_eq!(
        past.certificate,
        Some(PastCertificate::Finding {
            sub: SubIndication::NoPoe,
            path: Some(0),
            missing_proof: Some(CERT),
        })
    );
    assert_eq!(SubIndication::NoPoe.retry(), Some(Retry::ProofOfExistence));
}

#[test]
fn a_poe_before_issuance_is_not_yet_valid() {
    let current = facts();
    let mut input = inputs(&current);
    let complete = [
        HISTORICAL[0],
        HISTORICAL[1],
        HISTORICAL[2],
        Proof {
            object: VALUE,
            at: at(9),
        },
    ];
    input.initial = &complete;
    assert_eq!(
        run(&input, &REQUIREMENTS).decision,
        Decision::Finding(SubIndication::NotYetValid)
    );
}

#[test]
fn path_findings_preserve_identity_and_normative_precedence() {
    use crate::validation::Chain;
    let current = facts();
    for (chain, expected) in [
        (
            Chain::GeneralFailure,
            SubIndication::CertificateChainGeneralFailure,
        ),
        (
            Chain::ConstraintsFailure,
            SubIndication::ChainConstraintsFailure,
        ),
    ] {
        let candidates = [Candidate { chain, ..CANDIDATE }];
        let mut input = inputs(&current);
        input.signature.candidates = &candidates;
        assert_eq!(
            run(&input, &REQUIREMENTS).past.unwrap().certificate,
            Some(PastCertificate::Finding {
                sub: expected,
                path: Some(0),
                missing_proof: None,
            })
        );
    }
    let mut input = inputs(&current);
    input.signature.candidates = &[];
    assert_eq!(
        run(&input, &REQUIREMENTS).past.unwrap().certificate,
        Some(PastCertificate::Finding {
            sub: SubIndication::NoCertificateChainFound,
            path: None,
            missing_proof: None,
        })
    );
}

#[test]
fn current_failures_and_absent_long_term_attributes_stop_recovery() {
    let mut current = facts();
    current.value = Value::Mismatch;
    let report = run(&inputs(&current), &REQUIREMENTS);
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::SigCryptoFailure)
    );
    assert_eq!(report.stage, Stage::WithTime);
    assert!(report.past.is_none());
    let current = facts();
    let mut input = inputs(&current);
    input.has_long_term_attributes = false;
    assert!(run(&input, &REQUIREMENTS).past.is_none());
}

const TIMESTAMP: Timestamp<'static> = Timestamp {
    object: NEW_TOKEN,
    generated: at(40),
    not_before: None,
    imprint: Hash::Sha256,
    current: Decision::Passed,
    past: None,
    acceptance: &[],
    covered: &[],
    required: false,
};

#[test]
fn newer_valid_token_protects_the_older_token_before_its_hash_sunset() {
    let current = facts();
    let rules = [
        crate::validation::HashRule {
            hash: Hash::Sha1,
            until: Some(at(60)),
        },
        crate::validation::HashRule {
            hash: Hash::Sha256,
            until: None,
        },
    ];
    let requirements = Requirements {
        crypto: crate::validation::Constraints {
            hashes: &rules,
            ..REQUIREMENTS.crypto
        },
        ..REQUIREMENTS
    };
    let tokens = [
        Timestamp {
            covered: &[Covered::Direct(OLD_TOKEN)],
            ..TIMESTAMP
        },
        Timestamp {
            object: OLD_TOKEN,
            generated: at(24),
            imprint: Hash::Sha1,
            covered: &[Covered::Direct(VALUE)],
            required: true,
            ..TIMESTAMP
        },
    ];
    let mut input = inputs(&current);
    input.timestamps = &tokens;
    let report = run(&input, &requirements);
    assert_eq!(report.best_signature_time, at(24));
    assert_eq!(report.timestamps().len(), 2);
    assert_eq!(report.timestamps()[1].decision, Decision::Passed);
    input.timestamps = &tokens[1..];
    let report = run(&input, &requirements);
    assert_eq!(report.stage, Stage::Timestamp(0));
    assert_eq!(report.decision, Decision::Finding(SubIndication::NoPoe));
}

/// Evidence can prove existence within the timestamp's accuracy interval.
#[test]
fn timestamp_proof_can_precede_generation_upper_bound() {
    let current = facts();
    let proof_time = Instant::new(23, 500_000_000).unwrap();
    let initial = [
        HISTORICAL[0],
        HISTORICAL[1],
        HISTORICAL[2],
        HISTORICAL[3],
        Proof {
            object: NEW_TOKEN,
            at: proof_time,
        },
    ];
    for required in [false, true] {
        let timestamps = [Timestamp {
            generated: at(24),
            covered: &[Covered::Direct(VALUE)],
            required,
            ..TIMESTAMP
        }];
        let mut input = inputs(&current);
        input.initial = &initial;
        input.timestamps = &timestamps;
        let report = run(&input, &REQUIREMENTS);
        assert_eq!(report.timestamps()[0].decision, Decision::Passed);
        assert_eq!(report.decision, Decision::Passed);
        assert_eq!(report.best_signature_time, at(24));
    }
}

#[test]
fn indirect_reference_needs_later_target_proof_before_digest_sunset() {
    let current = facts();
    let rules = [crate::validation::HashRule {
        hash: Hash::Sha256,
        until: Some(at(50)),
    }];
    let requirements = Requirements {
        crypto: crate::validation::Constraints {
            hashes: &rules,
            ..REQUIREMENTS.crypto
        },
        ..REQUIREMENTS
    };
    let token_proof = Proof {
        object: NEW_TOKEN,
        at: at(40),
    };
    let token = [Timestamp {
        generated: at(20),
        covered: &[Covered::Reference {
            digest: DIGEST,
            target: VALUE,
            hash: Hash::Sha256,
        }],
        ..TIMESTAMP
    }];
    let mut input = inputs(&current);
    input.timestamps = &token;
    let initial = [
        HISTORICAL[0],
        HISTORICAL[1],
        HISTORICAL[2],
        HISTORICAL[3],
        token_proof,
    ];
    input.initial = &initial;
    assert_eq!(run(&input, &requirements).best_signature_time, at(20));
    let mut late = initial;
    late[3].at = at(50);
    input.initial = &late;
    assert_eq!(run(&input, &requirements).best_signature_time, at(50));
}

#[test]
fn failed_record_cannot_contribute_proofs() {
    let current = facts();
    let mut input = inputs(&current);
    input.initial = &HISTORICAL[..3];
    let covered = [VALUE];
    let records = [EvidenceRecord {
        decision: Decision::Passed,
        initial: at(25),
        covered: &covered,
    }];
    input.records = &records;
    assert_eq!(run(&input, &REQUIREMENTS).decision, Decision::Passed);
    let rejected = [EvidenceRecord {
        decision: Decision::Finding(SubIndication::HashFailure),
        ..records[0]
    }];
    input.records = &rejected;
    assert_eq!(run(&input, &REQUIREMENTS).best_signature_time, CURRENT);
}

#[test]
fn final_acceptance_and_required_timestamp_failures_stay_separate() {
    let current = facts();
    let mut input = inputs(&current);
    let token = [Timestamp {
        current: Decision::Finding(SubIndication::HashFailure),
        required: true,
        ..TIMESTAMP
    }];
    input.timestamps = &token;
    let report = run(&input, &REQUIREMENTS);
    assert_eq!(report.stage, Stage::Timestamp(0));
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::HashFailure)
    );
    let optional = [Timestamp {
        required: false,
        ..token[0]
    }];
    input.timestamps = &optional;
    let requirements = Requirements {
        elements: Elements::NONE.with(Element::ContentType),
        ..REQUIREMENTS
    };
    // At the current time this case fails on certificate validity before
    // reaching signature acceptance; historical processing exposes the latter.
    let report = run(&input, &requirements);
    assert_eq!(report.stage, Stage::SignatureAcceptance);
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::SigConstraintsFailure)
    );
    assert_eq!(
        report.timestamps()[0].decision,
        Decision::Finding(SubIndication::HashFailure)
    );
}

#[test]
fn invalid_catalogues_and_resource_refusal_are_terminal_errors() {
    let current = facts();
    let mut input = inputs(&current);
    let work = memory(0, 1_000_000);
    assert!(matches!(
        validate(&input, &REQUIREMENTS, &work),
        Err(Error::Resource(_))
    ));
    assert_eq!(work.used(), 0);
    assert!(matches!(
        validate(&input, &REQUIREMENTS, &memory(1 << 20, 0)),
        Err(Error::Resource(_))
    ));
    let invalid = [Object(7)];
    input.present = &invalid;
    assert!(matches!(
        validate(&input, &REQUIREMENTS, &memory(1 << 20, 1_000_000)),
        Err(Error::ForeignObject(Object(7)))
    ));
}

fn past_result(signature: Signature<'_>, sub: SubIndication, proofs: &[Proof]) -> PastSignature {
    validate_past_signature(
        &PastInputs {
            object_count: 7,
            proofs,
            now: CURRENT,
            current: Decision::Finding(sub),
            signature,
        },
        &REQUIREMENTS,
        &memory(1 << 20, 1_000_000),
    )
    .unwrap()
}

/// Authority compromise is a key compromise in the chain model too.
#[test]
fn authority_compromise_limits_historical_chain_model() {
    let sub = SubIndication::RevokedCaNoPoe;
    for reason in [
        Reason::AuthorityCompromise,
        Reason::AttributeAuthorityCompromise,
    ] {
        let revocations = [RevocationData {
            status: Revocation::Revoked {
                at: at(24),
                reason: Some(reason),
            },
            ..REV
        }];
        let members = [Member {
            revocations: RevocationCheck::Required(&revocations),
            ..MEMBER
        }];
        let candidates = [Candidate {
            members: &members,
            ..CANDIDATE
        }];
        let signature = Signature {
            model: ValidityModel::Chain,
            candidates: &candidates,
            revocations: &revocations,
            revoked_ca_at: Some(at(31)),
            ..INITIAL_SIGNATURE
        };
        let report = past_result(signature, sub, HISTORICAL);
        assert_eq!(report.signature_poe, Some(false), "{reason:?}");
        assert_eq!(report.decision, Decision::Finding(sub));
    }
}

/// A recoverable delay cannot make evidence from before issuance valid.
#[test]
fn delay_recovery_rechecks_signer_not_before() {
    let utc = structured_pkix::temporal::LeapTable::new(0, 200, &[]).unwrap();
    let mut current = facts();
    let signer = current.signer.as_mut().unwrap();
    signer.not_before = at(50);
    signer.not_after = at(110);
    current.time.before = Some(at(90));
    current.signature_timestamp = true;
    current.claimed_signing_time = Some(at(20));
    current.utc = Some(&utc);
    let requirements = Requirements {
        timestamp_delay: Some(core::time::Duration::from_secs(10)),
        ..REQUIREMENTS
    };
    let mut input = inputs(&current);
    input.signature.validity = Validity {
        not_before: at(50),
        not_after: at(110),
    };
    let report = run(&input, &requirements);
    assert_eq!(
        report.current.basis,
        Some(crate::validation::Basis::TimestampDelay)
    );
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::NotYetValid)
    );
}

/// A newer record with no reliable historical proof cannot mask an older one.
#[test]
fn unusable_newer_revocation_does_not_mask_older_evidence() {
    let hashes = [
        crate::validation::HashRule {
            hash: Hash::Sha1,
            until: Some(at(40)),
        },
        crate::validation::HashRule {
            hash: Hash::Sha256,
            until: None,
        },
    ];
    let requirements = Requirements {
        crypto: crate::validation::Constraints {
            hashes: &hashes,
            ..REQUIREMENTS.crypto
        },
        ..REQUIREMENTS
    };
    let weak = [CryptoObject {
        object: DIGEST,
        material: Material {
            hash: Some(Hash::Sha1),
            scheme: None,
        },
    }];
    let newer = RevocationData {
        object: DIGEST,
        issued: at(45),
        crypto: &weak,
        ..REV
    };
    let records = [REV, newer];
    let members = [Member {
        revocations: RevocationCheck::Required(&records),
        ..MEMBER
    }];
    let candidates = [Candidate {
        members: &members,
        ..CANDIDATE
    }];
    let current = facts();
    let mut input = inputs(&current);
    input.signature.candidates = &candidates;
    let proofs = [
        HISTORICAL[0],
        HISTORICAL[1],
        HISTORICAL[2],
        HISTORICAL[3],
        Proof {
            object: DIGEST,
            at: at(46),
        },
    ];
    input.initial = &proofs;
    assert_eq!(run(&input, &requirements).decision, Decision::Passed);
}

/// For two eligible clear records, the latest record's crypto limit applies
/// even if an older record would admit the signature proof.
#[test]
fn latest_eligible_clear_revocation_sets_the_crypto_horizon() {
    let old = RevocationData {
        fresh_before: Some(at(110)),
        ..REV
    };
    let material = [CryptoObject {
        object: DIGEST,
        material: Material {
            hash: Some(Hash::Sha1),
            scheme: None,
        },
    }];
    let newer = RevocationData {
        object: DIGEST,
        issued: at(45),
        crypto: &material,
        ..old
    };
    let hashes = [crate::validation::HashRule {
        hash: Hash::Sha1,
        until: Some(at(48)),
    }];
    let requirements = Requirements {
        crypto: crate::validation::Constraints {
            hashes: &hashes,
            ..REQUIREMENTS.crypto
        },
        ..REQUIREMENTS
    };
    let proofs = [
        HISTORICAL[0],
        HISTORICAL[1],
        HISTORICAL[2],
        Proof {
            object: VALUE,
            at: at(49),
        },
        Proof {
            object: DIGEST,
            at: at(46),
        },
    ];
    let current = facts();
    for records in [&[old][..], &[old, newer][..], &[newer, old][..]] {
        let members = [Member {
            revocations: RevocationCheck::Required(records),
            ..MEMBER
        }];
        let candidates = [Candidate {
            members: &members,
            ..CANDIDATE
        }];
        let mut input = inputs(&current);
        input.initial = &proofs;
        input.signature.candidates = &candidates;
        let report = run(&input, &requirements);
        let past = report.past.unwrap();
        let (horizon, expected) = if records.len() == 1 {
            (Horizon::Through(at(50)), Decision::Passed)
        } else {
            (
                Horizon::Before(at(48)),
                Decision::Finding(SubIndication::OutOfBoundsNotRevoked),
            )
        };
        assert_eq!(
            past.certificate,
            Some(PastCertificate::Passed { path: 0, horizon })
        );
        assert_eq!(report.decision, expected);
    }
}

/// Historical evidence can supply the required issuer proof independently of
/// the current chain's status catalogue.
#[test]
fn issuer_proof_comes_from_the_selected_historical_target_record() {
    let current = facts();
    let mut input = inputs(&current);
    input.signature.revocations = &[];
    let report = run(&input, &REQUIREMENTS);
    assert_eq!(report.past.unwrap().revocation_poe, Some(true));
    assert_eq!(report.decision, Decision::Passed);
}

/// A path lacking issuer proof must not mask one satisfying both proof checks.
#[test]
fn historical_path_selection_prefers_a_covered_path_with_issuer_proof() {
    let records = [RevocationData {
        issuer: DIGEST,
        ..REV
    }];
    let members = [Member {
        revocations: RevocationCheck::Required(&records),
        ..MEMBER
    }];
    let no_issuer_proof = Candidate {
        members: &members,
        ..CANDIDATE
    };
    let sub = SubIndication::OutOfBoundsNotRevoked;
    for (candidates, expected_path) in [
        ([no_issuer_proof, CANDIDATE], 1),
        ([CANDIDATE, no_issuer_proof], 0),
    ] {
        let signature = Signature {
            candidates: &candidates,
            ..INITIAL_SIGNATURE
        };
        let report = past_result(signature, sub, HISTORICAL);
        assert_eq!(report.decision, Decision::Passed);
        assert_eq!(report.revocation_poe, Some(true));
        assert_eq!(
            report.certificate,
            Some(PastCertificate::Passed {
                path: expected_path,
                horizon: Horizon::Through(at(30)),
            })
        );
    }
    let candidates = [no_issuer_proof];
    let signature = Signature {
        candidates: &candidates,
        ..INITIAL_SIGNATURE
    };
    let report = past_result(signature, sub, HISTORICAL);
    assert_eq!(
        report.decision,
        Decision::Finding(SubIndication::RevocationOutOfBoundsNoPoe)
    );
    assert_eq!(report.signature_poe, Some(true));
    assert_eq!(report.revocation_poe, Some(false));
}

/// A valid path whose horizon precedes the signature proof must not mask a
/// later candidate that actually covers it.
#[test]
fn historical_path_selection_continues_until_signature_proof_is_covered() {
    let restricted = Candidate {
        anchor_sunset: Some(at(35)),
        ..CANDIDATE
    };
    let later = [RevocationData {
        object: DIGEST,
        issued: at(45),
        ..REV
    }];
    let members = [Member {
        revocations: RevocationCheck::Required(&later),
        ..MEMBER
    }];
    let extended = Candidate {
        members: &members,
        ..CANDIDATE
    };
    let proofs = [
        HISTORICAL[0],
        HISTORICAL[1],
        HISTORICAL[2],
        Proof {
            object: DIGEST,
            at: at(46),
        },
        Proof {
            object: VALUE,
            at: at(40),
        },
    ];
    let sub = SubIndication::OutOfBoundsNotRevoked;
    for (candidates, expected_path) in [([restricted, extended], 1), ([extended, restricted], 0)] {
        let signature = Signature {
            candidates: &candidates,
            ..INITIAL_SIGNATURE
        };
        let report = past_result(signature, sub, &proofs);
        assert_eq!(report.decision, Decision::Passed);
        assert_eq!(
            report.certificate,
            Some(PastCertificate::Passed {
                path: expected_path,
                horizon: Horizon::Through(at(45))
            })
        );
    }
    let candidates = [restricted];
    let signature = Signature {
        candidates: &candidates,
        ..INITIAL_SIGNATURE
    };
    let report = past_result(signature, sub, &proofs);
    assert_eq!(report.decision, Decision::Finding(sub));
    assert_eq!(report.signature_poe, Some(false));
    assert!(matches!(
        report.certificate,
        Some(PastCertificate::Passed { path: 0, .. })
    ));
}

/// Steps 4 and 5 of EN 319 102-1 §5.6.2.4.4 have independent proof rules.
#[test]
fn algorithm_and_freshness_recovery_use_their_own_proof_rules() {
    let affected = [CryptoObject {
        object: CERT,
        material: Material {
            hash: Some(Hash::Sha256),
            scheme: None,
        },
    }];
    let record = RevocationData {
        fresh_before: Some(at(80)),
        ..REV
    };
    let signature = Signature {
        affected_crypto: &affected,
        retry: RetryCause::Freshness {
            record: &record,
            retry_at: None,
        },
        ..INITIAL_SIGNATURE
    };
    let proofs = [
        HISTORICAL[0],
        HISTORICAL[1],
        HISTORICAL[2],
        Proof {
            object: VALUE,
            at: at(55),
        },
    ];
    for sub in [
        SubIndication::CryptoConstraintsFailureNoPoe,
        SubIndication::TryLater,
    ] {
        let report = past_result(signature, sub, &proofs);
        assert_eq!(report.signature_poe, Some(false));
        assert_eq!(report.decision, Decision::Passed, "{sub:?}");
    }
    let report = past_result(
        signature,
        SubIndication::CryptoConstraintsFailureNoPoe,
        &proofs[..3],
    );
    assert_eq!(report.decision, Decision::Passed);
    assert_eq!(
        past_result(signature, SubIndication::TryLater, &proofs[..3]).decision,
        Decision::Finding(SubIndication::TryLater),
    );
}

/// Reinstatement replaces an older hold regardless of catalogue order. An
/// equally dated or older clear status cannot clear the hold.
#[test]
fn newer_clear_status_supersedes_hold_but_not_permanent_revocation() {
    for (reason, clear_time, expected) in [
        (Reason::CertificateHold, 40, Decision::Passed),
        (
            Reason::CertificateHold,
            30,
            Decision::Finding(SubIndication::OutOfBoundsNotRevoked),
        ),
        (
            Reason::CertificateHold,
            29,
            Decision::Finding(SubIndication::OutOfBoundsNotRevoked),
        ),
        (
            Reason::KeyCompromise,
            40,
            Decision::Finding(SubIndication::OutOfBoundsNotRevoked),
        ),
    ] {
        let old = RevocationData {
            status: Revocation::Revoked {
                at: at(20),
                reason: Some(reason),
            },
            ..REV
        };
        let newer = RevocationData {
            object: DIGEST,
            issued: at(clear_time),
            ..REV
        };
        for revocations in [[old, newer], [newer, old]] {
            let members = [Member {
                revocations: RevocationCheck::Required(&revocations),
                ..MEMBER
            }];
            let candidates = [Candidate {
                members: &members,
                ..CANDIDATE
            }];
            let signature = Signature {
                candidates: &candidates,
                revocations: &revocations,
                ..INITIAL_SIGNATURE
            };
            let proofs = [
                HISTORICAL[0],
                HISTORICAL[1],
                HISTORICAL[2],
                Proof {
                    object: VALUE,
                    at: at(40),
                },
                Proof {
                    object: DIGEST,
                    at: at(42),
                },
            ];
            assert_eq!(
                past_result(signature, SubIndication::OutOfBoundsNotRevoked, &proofs).decision,
                expected,
                "{reason:?}/{clear_time}"
            );
        }
    }
}

#[test]
fn past_signature_only_recovers_the_cited_current_findings() {
    use SubIndication as S;
    for sub in [
        S::NoCertificateChainFoundNoPoe,
        S::RevokedNoPoe,
        S::RevocationOutOfBoundsNoPoe,
        S::OutOfBoundsNotRevoked,
        S::OutOfBoundsNoPoe,
    ] {
        let answer = past_result(INITIAL_SIGNATURE, sub, HISTORICAL);
        assert_eq!(answer.decision, Decision::Passed, "{sub:?}");
        assert_eq!(answer.signature_poe, Some(true));
    }
    for sub in [
        S::HashFailure,
        S::SigConstraintsFailure,
        S::NoSigningCertificateFound,
    ] {
        let answer = past_result(INITIAL_SIGNATURE, sub, HISTORICAL);
        assert_eq!(answer.decision, Decision::Finding(sub));
        assert_eq!(answer.certificate, None);
    }
}

#[test]
fn ca_revocation_requires_a_separate_proof_of_target_revocation_data() {
    let signature = Signature {
        revoked_ca_at: Some(at(30)),
        ..INITIAL_SIGNATURE
    };
    let sub = SubIndication::RevokedCaNoPoe;
    assert_eq!(
        past_result(signature, sub, HISTORICAL).decision,
        Decision::Passed
    );
    let earlier = Signature {
        revoked_ca_at: Some(at(29)),
        ..signature
    };
    assert_eq!(
        past_result(earlier, sub, HISTORICAL).decision,
        Decision::Finding(sub)
    );
}

#[test]
fn stale_status_is_rechecked_at_proven_signing_time_with_strict_freshness() {
    let sub = SubIndication::TryLater;
    let mut record = RevocationData {
        fresh_before: Some(at(25)),
        ..REV
    };
    let signature = Signature {
        retry: RetryCause::Freshness {
            record: &record,
            retry_at: Some(at(80)),
        },
        ..INITIAL_SIGNATURE
    };
    let report = past_result(signature, sub, HISTORICAL);
    assert_eq!(report.decision, Decision::Finding(sub));
    assert_eq!(report.retry_at, Some(at(80)));
    record.fresh_before = Some(at(26));
    let signature = Signature {
        retry: RetryCause::Freshness {
            record: &record,
            retry_at: Some(at(80)),
        },
        ..INITIAL_SIGNATURE
    };
    let report = past_result(signature, sub, HISTORICAL);
    assert_eq!(report.decision, Decision::Passed);
    assert_eq!(report.retry_at, None);
    let signature = Signature {
        retry: RetryCause::Suspension { retry_at: None },
        ..INITIAL_SIGNATURE
    };
    assert_eq!(
        past_result(signature, sub, HISTORICAL).decision,
        Decision::Passed
    );
}

#[test]
fn shell_slides_on_non_compromise_revocation_and_chain_does_not() {
    let revocations = [RevocationData {
        status: Revocation::Revoked {
            at: at(25),
            reason: Some(Reason::Superseded),
        },
        ..REV
    }];
    let members = [Member {
        revocations: RevocationCheck::Required(&revocations),
        ..MEMBER
    }];
    let paths = [Candidate {
        members: &members,
        ..CANDIDATE
    }];
    let signature = Signature {
        candidates: &paths,
        revocations: &revocations,
        ..INITIAL_SIGNATURE
    };
    let sub = SubIndication::RevokedNoPoe;
    let shell = past_result(signature, sub, HISTORICAL);
    assert_eq!(shell.signature_poe, Some(false));
    assert_eq!(shell.decision, Decision::Finding(sub));
    let chain = Signature {
        model: ValidityModel::Chain,
        ..signature
    };
    assert_eq!(
        past_result(chain, sub, HISTORICAL).decision,
        Decision::Passed
    );
}

#[test]
fn every_affected_crypto_object_needs_its_own_proof_before_sunset() {
    let hashes = [crate::validation::HashRule {
        hash: Hash::Sha1,
        until: Some(at(40)),
    }];
    let requirements = Requirements {
        crypto: crate::validation::Constraints {
            hashes: &hashes,
            ..REQUIREMENTS.crypto
        },
        ..REQUIREMENTS
    };
    let affected = [
        CryptoObject {
            object: VALUE,
            material: Material {
                hash: Some(Hash::Sha1),
                scheme: None,
            },
        },
        CryptoObject {
            object: DIGEST,
            material: Material {
                hash: Some(Hash::Sha1),
                scheme: None,
            },
        },
    ];
    let sub = SubIndication::CryptoConstraintsFailureNoPoe;
    let current = Decision::Finding(sub);
    let signature = Signature {
        affected_crypto: &affected,
        ..INITIAL_SIGNATURE
    };
    let mut proofs = [
        HISTORICAL[0],
        HISTORICAL[1],
        HISTORICAL[2],
        HISTORICAL[3],
        Proof {
            object: DIGEST,
            at: at(40),
        },
    ];
    for (at, expected) in [(at(40), current), (at(39), Decision::Passed)] {
        proofs[4].at = at;
        let result = validate_past_signature(
            &PastInputs {
                object_count: 7,
                proofs: &proofs,
                now: CURRENT,
                current,
                signature,
            },
            &requirements,
            &memory(1 << 20, 1_000_000),
        )
        .unwrap();
        assert_eq!(result.decision, expected);
    }
}

#[test]
fn historical_crypto_cutoff_cannot_be_recovered_using_an_unrelated_proof() {
    let hashes = [crate::validation::HashRule {
        hash: Hash::Sha1,
        until: Some(at(30)),
    }];
    let requirements = Requirements {
        crypto: crate::validation::Constraints {
            hashes: &hashes,
            ..REQUIREMENTS.crypto
        },
        ..REQUIREMENTS
    };
    let material = [CryptoObject {
        object: REVOCATION,
        material: Material {
            hash: Some(Hash::Sha1),
            scheme: None,
        },
    }];
    let revocations = [RevocationData {
        crypto: &material,
        ..REV
    }];
    let members = [Member {
        revocations: RevocationCheck::Required(&revocations),
        ..MEMBER
    }];
    let paths = [Candidate {
        members: &members,
        ..CANDIDATE
    }];
    let current = facts();
    let mut input = inputs(&current);
    input.signature.candidates = &paths;
    let report = run(&input, &requirements);
    assert_eq!(
        report.past.unwrap().certificate,
        Some(PastCertificate::Finding {
            sub: SubIndication::NoPoe,
            path: Some(0),
            missing_proof: Some(REVOCATION),
        })
    );
}

#[test]
fn issuer_proof_must_fall_inside_its_own_validity() {
    let mut proofs = [HISTORICAL[0], HISTORICAL[1], HISTORICAL[2], HISTORICAL[3]];
    proofs[1].at = VALID.not_before;
    let result = past_result(
        INITIAL_SIGNATURE,
        SubIndication::OutOfBoundsNotRevoked,
        &proofs,
    );
    assert_eq!(result.revocation_poe, Some(false));
    assert_eq!(
        result.decision,
        Decision::Finding(SubIndication::RevocationOutOfBoundsNoPoe)
    );
}

#[test]
fn timestamp_order_uses_producer_order_and_future_uses_lower_bound() {
    let current = facts();
    let mut input = inputs(&current);
    let timestamps = [
        TIMESTAMP,
        Timestamp {
            generated: at(41),
            ..TIMESTAMP
        },
    ];
    input.timestamps = &timestamps;
    let report = run(&input, &REQUIREMENTS);
    assert_eq!(report.timestamps().len(), 2);
    let future = [Timestamp {
        generated: at(101),
        not_before: Some(at(99)),
        ..TIMESTAMP
    }];
    input.timestamps = &future;
    assert_eq!(run(&input, &REQUIREMENTS).timestamps().len(), 1);
    let future = [Timestamp {
        not_before: Some(at(101)),
        ..future[0]
    }];
    input.timestamps = &future;
    assert!(
        matches!(validate(&input, &REQUIREMENTS, &memory(1 << 20, 1_000_000)), Err(Error::FutureTime(at)) if at == future[0].generated)
    );
}

/// An explicit waiver leaves the certificate's own proof obligation intact.
#[test]
fn historical_revocation_waiver_is_distinct_from_missing_evidence() {
    let sub = SubIndication::OutOfBoundsNotRevoked;
    let members = [Member {
        revocations: RevocationCheck::Waived,
        ..MEMBER
    }];
    let candidates = [Candidate {
        members: &members,
        ..CANDIDATE
    }];
    let signature = Signature {
        candidates: &candidates,
        ..INITIAL_SIGNATURE
    };
    let report = past_result(signature, sub, HISTORICAL);
    assert_eq!(report.decision, Decision::Passed);
    assert_eq!(report.revocation_poe, None);
    assert_eq!(
        past_result(signature, sub, &HISTORICAL[1..]).decision,
        Decision::Finding(sub)
    );
    let members = [Member {
        revocations: RevocationCheck::Required(&[]),
        ..MEMBER
    }];
    let candidates = [Candidate {
        members: &members,
        ..CANDIDATE
    }];
    let signature = Signature {
        candidates: &candidates,
        ..signature
    };
    assert_eq!(
        past_result(signature, sub, HISTORICAL).decision,
        Decision::Finding(sub)
    );
}
