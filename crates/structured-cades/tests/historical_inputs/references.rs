use super::*;
use structured_cades::preservation::Kind;
use structured_cades::timestamp::references::{
    Component, ReferenceInput, SelectionError as RefError,
};
use structured_ltv::source::Source as _;
use structured_ltv::timestamp::Purpose;

const SIGNATURE_REFS: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 25];
const REFS_ONLY: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 26];
const CERT_REFS: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 21];
const REV_REFS: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 22];

#[test]
fn signed_reference_timestamps_are_not_basic_format_conformance() {
    // EN319122-1 A.1.5 defines both as UNSIGNED. Retain a signed occurrence
    // for diagnostics, but never treat its placement as a valid B-B fact.
    let fixture = Fixture::new();
    let token = fixture.token(b"references");
    for kind in [SIGNATURE_REFS, REFS_ONLY] {
        let root = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &fixture.certificate,
            &fixture.signer,
            &[attribute(kind, &token)],
            &[],
        );
        let bytes = message(
            oid::DATA.as_bytes(),
            Some(b"payload"),
            &[fixture.root.clone(), fixture.certificate.clone()],
            &[],
            &[root],
        );
        let parser = Parser::ber(memory());
        let message = SignedData::read(&parser, &bytes, 900).unwrap();
        let operation = parser.read(&[], 900).unwrap();
        let document = Document::new(&message, &operation).unwrap();
        let prepared =
            Preparation::read(&document, &message.signers()[0], Level::Basic, &operation).unwrap();
        assert_eq!(prepared.timestamps().len(), 1);
        assert!(!prepared.basic_format_requirements_met());
        assert!(matches!(
            ReferenceInput::new(&prepared, 0, &operation),
            Err(RefError::WrongOccurrence)
        ));
    }
}

#[test]
fn both_reference_timestamp_families_enter_the_complete_census() {
    // Recognized reference timestamps cannot disappear from the actor census
    // merely because their purpose differs from an archive timestamp.
    let fixture = Fixture::new();
    let token = fixture.token(b"references");
    let bytes = fixture.message(
        &[
            attribute(SIGNATURE_REFS, &token),
            attribute(REFS_ONLY, &token),
        ],
        false,
        false,
    );
    let parser = Parser::ber(memory());
    let message = SignedData::read(&parser, &bytes, 900).unwrap();
    let operation = parser.read(&[], 900).unwrap();
    let document = Document::new(&message, &operation).unwrap();
    let prepared =
        Preparation::read(&document, &message.signers()[0], Level::Basic, &operation).unwrap();
    assert_eq!(prepared.preservation().len(), 2);
    assert_eq!(prepared.timestamps().len(), 2);
    assert_eq!(prepared.timestamps()[0].purpose(), Purpose::ValidationData);
    assert_eq!(
        prepared.timestamps()[0].preservation_kind(),
        Some(Kind::SignatureReferences)
    );
    assert_eq!(prepared.timestamps()[1].purpose(), Purpose::ValidationData);
    assert_eq!(
        prepared.timestamps()[1].preservation_kind(),
        Some(Kind::References)
    );
}

fn encoded_attribute(kind: &[u8], value: &[u8], ber: bool) -> (Vec<u8>, Vec<u8>) {
    let contents = if ber {
        [
            vec![6, 0x81, u8::try_from(kind.len()).unwrap()],
            kind.to_vec(),
            vec![0x31, 0x80],
            value.to_vec(),
            vec![0, 0],
        ]
        .concat()
    } else {
        [tlv(6, kind), tlv(0x31, value)].concat()
    };
    let whole = if ber {
        [vec![0x30, 0x80], contents.clone(), vec![0, 0]].concat()
    } else {
        tlv(0x30, &contents)
    };
    (whole, contents)
}

#[derive(Clone, Copy)]
enum Role {
    Root,
    Counter,
    ParallelRoot,
    ParallelCounter,
}

fn reference_message(fixture: &Fixture, attributes: &[Vec<u8>], role: Role) -> (Vec<u8>, Vec<u8>) {
    let root = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &fixture.certificate,
        &fixture.signer,
        &[],
        &[],
    );
    let parent = support::signature_octets(&root);
    let counter = matches!(role, Role::Counter | Role::ParallelCounter);
    let owner = signer(
        if counter {
            None
        } else {
            Some(oid::DATA.as_bytes())
        },
        if counter { &parent } else { b"payload" },
        &fixture.certificate,
        &fixture.signer,
        &[],
        attributes,
    );
    let carrier = if counter {
        signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &fixture.certificate,
            &fixture.signer,
            &[],
            &[attribute(oid::COUNTERSIGNATURE.as_bytes(), &owner)],
        )
    } else {
        owner.clone()
    };
    let signers = if matches!(role, Role::ParallelRoot | Role::ParallelCounter) {
        vec![root, carrier]
    } else {
        vec![carrier]
    };
    (
        message(
            oid::DATA.as_bytes(),
            Some(b"payload"),
            &[fixture.root.clone(), fixture.certificate.clone()],
            &[],
            &signers,
        ),
        owner,
    )
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one native path exercises both original byte recipes, four owners, BER forms and cryptographic disagreement"
)]
#[expect(
    clippy::result_large_err,
    reason = "inspect original unboxed common timestamp failures without losing their causes"
)]
fn real_reference_timestamps_bind_original_ber_inputs_for_every_owner() {
    // Independently assemble the normative preimage, then check actual ECDSA,
    // ESS, TSA certificate/path, imprint and time. Every owner and both BER
    // spellings use the same common check, without inferring archive purpose.
    for role in [
        Role::Root,
        Role::Counter,
        Role::ParallelRoot,
        Role::ParallelCounter,
    ] {
        for ber in [false, true] {
            for (kind, matches) in [
                (SIGNATURE_REFS, true),
                (REFS_ONLY, true),
                (SIGNATURE_REFS, false),
                (REFS_ONLY, false),
            ] {
                let fixture = Fixture::new();
                let (_, bare_owner) = reference_message(&fixture, &[], role);
                let signature = support::signature_octets(&bare_owner);
                let signature_token = fixture.token(&signature);
                let (sig_attr, sig_body) =
                    encoded_attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &signature_token, ber);
                let second_signature_token = fixture.token_with_unsigned(
                    &signature,
                    &[attribute(
                        &[42, 9],
                        &tlv(4, b"second original timestamp carrier"),
                    )],
                );
                let (second_sig_attr, second_sig_body) = encoded_attribute(
                    oid::SIGNATURE_TIMESTAMP.as_bytes(),
                    &second_signature_token,
                    ber,
                );
                // These are ordinary reference bytes. Timestamp verification
                // does not claim to authenticate the referenced artifacts.
                let (cert_attr, cert_body) =
                    encoded_attribute(CERT_REFS, &tlv(0x30, &tlv(0x30, &tlv(4, &[7; 20]))), ber);
                let (rev_attr, rev_body) = encoded_attribute(REV_REFS, &tlv(0x30, &[]), ber);
                let mut covered = Vec::new();
                if kind == SIGNATURE_REFS {
                    covered.extend(&signature);
                    covered.extend(&sig_body);
                    covered.extend(&second_sig_body);
                }
                covered.extend(&cert_body);
                covered.extend(&rev_body);
                if !matches {
                    covered.push(0); // A different actual preimage, still signed by the real TSA.
                }
                let token = fixture.token(&covered);
                // Physical order differs from the normative category order.
                // Unknown/value attributes must not enter this input.
                let unsigned = [
                    rev_attr,
                    attribute(&[42, 3], &tlv(4, b"not covered")),
                    sig_attr,
                    cert_attr,
                    second_sig_attr,
                    attribute(kind, &token),
                ];
                let (bytes, _) = reference_message(&fixture, &unsigned, role);
                let parser = Parser::ber(memory());
                let message = SignedData::read(&parser, &bytes, 900).unwrap();
                let operation = parser.read(&[], 900).unwrap();
                let document = Document::new(&message, &operation).unwrap();
                let selected = if matches!(role, Role::ParallelRoot | Role::ParallelCounter) {
                    message
                        .signers()
                        .iter()
                        .find(|signer| signer.unsigned_attributes().is_none())
                        .unwrap()
                } else {
                    &message.signers()[0]
                };
                let prepared =
                    Preparation::read(&document, selected, Level::Basic, &operation).unwrap();
                let ordinal = prepared
                    .timestamps()
                    .iter()
                    .position(|entry| entry.value().is_some_and(|value| value.as_bytes() == token))
                    .unwrap();
                let entry = &prepared.timestamps()[ordinal];
                let signature_ordinal = prepared
                    .timestamps()
                    .iter()
                    .position(|entry| {
                        entry
                            .value()
                            .is_some_and(|value| value.as_bytes() == signature_token)
                    })
                    .unwrap();
                assert_eq!(entry.purpose(), Purpose::ValidationData);
                let tsa = structured_pkix::Certificate::read(&parser, &fixture.tsa, 50000).unwrap();
                let root = message
                    .certificates()
                    .iter()
                    .find(|certificate| certificate.as_bytes() == fixture.root)
                    .unwrap();
                let work = operation.execution();
                let interval = structured_pkix::path::Interval::between(
                    tsa.tbs().validity().not_before().seconds(),
                    tsa.tbs().validity().not_after().seconds(),
                );
                let oracle = Oracle::new();
                let utc =
                    structured_pkix::temporal::LeapTable::new(interval.from(), interval.to(), &[])
                        .unwrap();
                let validation = structured_pkix::path::ValidationContext {
                    execution: &work,
                    interval,
                    policy: structured_pkix::path::Policy::default(),
                    bounds: structured_pkix::path::ValidationBounds::default(),
                    verifier: &oracle,
                    watch: &(),
                    recognizer: &(),
                };
                let structured_ltv::pki::PathOutcome::Accepted(path) =
                    structured_ltv::pki::check_path(
                        &[&tsa],
                        structured_pkix::path::Anchor::from_certificate(root),
                        &validation,
                    )
                    .unwrap()
                else {
                    panic!("real TSA path")
                };
                let time = timestamp::CheckTime {
                    utc: &utc,
                    reference: Some(interval.to_instant()),
                    policy_accuracy: None,
                };
                let mut input = ReferenceInput::new(&prepared, ordinal, &operation).unwrap();
                let checked = timestamp::with_token(&prepared, ordinal, &operation, |context| {
                    context.check_references(
                        &oracle,
                        &path,
                        &operation,
                        &time,
                        &mut input,
                        |_, _| Ok::<_, Infallible>(true),
                    )
                })
                .unwrap();
                assert_eq!(
                    checked.timestamp().imprint,
                    if matches {
                        ImprintAgreement::Matches
                    } else {
                        ImprintAgreement::Differs
                    }
                );
                if !matches {
                    assert!(
                        checked.timestamp().actor().is_none(),
                        "real TSA over different bytes is not this proof"
                    );
                    continue;
                }
                let actor = checked
                    .timestamp()
                    .actor()
                    .expect("real complete timestamp proof");
                assert_eq!(actor.verified().signature(), entry.owner());
                let source = prepared.document();
                let query = structured_ltv::source::Scope::new(source, source.snapshot(), &work);
                let earlier = &prepared.timestamps()[signature_ordinal];
                assert!(
                    !checked
                        .coverage()
                        .covers(actor.verified(), earlier.property(), &query)
                        .unwrap(),
                    "outer Attribute wrapper is omitted"
                );
                let earlier_token = prepared
                    .timestamp_requirements()
                    .entries()
                    .iter()
                    .find(|required| required.property == earlier.property())
                    .unwrap()
                    .token;
                assert_eq!(
                    checked
                        .coverage()
                        .covers(actor.verified(), earlier_token, &query)
                        .unwrap(),
                    kind == SIGNATURE_REFS
                );
                assert!(
                    !checked
                        .coverage()
                        .covers(actor.verified(), entry.property(), &query)
                        .unwrap(),
                    "no self coverage"
                );
                // One input/occurrence cannot be replayed as another token.
                let starts = oracle.starts.get();
                let wrong =
                    timestamp::with_token(&prepared, signature_ordinal, &operation, |context| {
                        context.check_references(
                            &oracle,
                            &path,
                            &operation,
                            &time,
                            &mut input,
                            |_, _| Ok::<_, Infallible>(true),
                        )
                    });
                assert!(matches!(
                    wrong,
                    Err(timestamp::VisitError::Callback(
                        timestamp::CheckError::Selection(_)
                    ))
                ));
                assert_eq!(oracle.starts.get(), starts);
            }
        }
    }
}

#[test]
fn reference_recipe_storage_work_and_original_session_are_current() {
    // Cached metadata is not permission to allocate a new selection or scan
    // its descriptors under an exhausted current execution. Partial storage
    // must be released on every refusal, retaining the original source.
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};
    let fixture = Fixture::new();
    let token = fixture.token(b"reference bytes");
    let attributes = [
        attribute(CERT_REFS, &tlv(0x30, &[])),
        attribute(REV_REFS, &tlv(0x30, &[])),
        attribute(REFS_ONLY, &token),
    ];
    let bytes = fixture.message(&attributes, false, false);
    let parser = Parser::ber(memory());
    let message = SignedData::read(&parser, &bytes, 900).unwrap();
    let original_signed_data = message.as_bytes().to_vec();
    let reader = parser.read(&[], 900).unwrap();
    let document = Document::new(&message, &reader).unwrap();
    let prepared =
        Preparation::read(&document, &message.signers()[0], Level::Basic, &reader).unwrap();
    for work_limit in 0..128 {
        let account = Memory::new(Arc::new(MemoryAccount::new(1 << 20, work_limit)));
        let operation = parser.read(&[], 900).unwrap().with_execution(&account);
        match ReferenceInput::new(&prepared, 0, &operation) {
            Ok(input) => drop(input),
            Err(RefError::Processing(cause)) => {
                assert!(cause.is_terminal());
                assert!(cause.offset() >= 900);
            }
            Err(cause) => panic!("resource refusal lost: {cause:?}"),
        }
        assert_eq!(
            account.used(),
            0,
            "success/drop and partial refusal release selection storage"
        );
    }
    let account = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 20)));
    let operation = parser.read(&[], 900).unwrap().with_execution(&account);
    assert!(matches!(
        ReferenceInput::new(&prepared, 0, &operation),
        Err(RefError::Processing(_))
    ));
    assert_eq!(account.used(), 0);
    assert_eq!(message.as_bytes(), original_signed_data);
}

#[test]
fn missing_and_conflicting_reference_inputs_refuse_before_hashing() {
    // The selected EN recipe requires original inputs; neither missing
    // components nor a duplicate unique references Attribute means empty bytes.
    let fixture = Fixture::new();
    let token = fixture.token(b"not a substitute input");
    for (kind, attributes, missing) in [
        (SIGNATURE_REFS, vec![], Some(Component::SignatureTimestamp)),
        (REFS_ONLY, vec![], Some(Component::CertificateReferences)),
        (
            REFS_ONLY,
            vec![attribute(CERT_REFS, &tlv(0x30, &[]))],
            Some(Component::RevocationReferences),
        ),
        (
            REFS_ONLY,
            vec![
                attribute(CERT_REFS, &tlv(0x30, &[])),
                attribute(CERT_REFS, &tlv(0x30, &[])),
            ],
            None,
        ),
    ] {
        let mut attributes = attributes;
        attributes.push(attribute(kind, &token));
        let bytes = fixture.message(&attributes, false, false);
        let parser = Parser::ber(memory());
        let message = SignedData::read(&parser, &bytes, 900).unwrap();
        let operation = parser.read(&[], 900).unwrap();
        let document = Document::new(&message, &operation).unwrap();
        let prepared =
            Preparation::read(&document, &message.signers()[0], Level::Basic, &operation).unwrap();
        let result = ReferenceInput::new(&prepared, 0, &operation);
        match missing {
            Some(expected) => {
                assert!(matches!(result, Err(RefError::Missing(actual)) if actual == expected));
            }
            None => assert!(matches!(result, Err(RefError::Duplicate { .. }))),
        }
        // Structural refusal takes precedence over allocating descriptors:
        // a zero-capacity query still identifies the missing component.
        if let Some(expected) = missing {
            use structured_asn1::memory::{Memory, MemoryAccount};
            let zero = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1 << 20)));
            let current = parser.read(&[], 900).unwrap().with_execution(&zero);
            assert!(
                matches!(ReferenceInput::new(&prepared, 0, &current), Err(RefError::Missing(actual)) if actual == expected)
            );
            assert_eq!(zero.used(), 0);
        }
        let foreign = Parser::ber(memory());
        let reader = foreign.read(&[], 900).unwrap();
        assert!(matches!(
            ReferenceInput::new(&prepared, 0, &reader),
            Err(RefError::Processing(_))
        ));
    }
}
