//! Public CRL schema, wire provenance and execution-boundary checks.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::ErrorCode;
use structured_pkix::crl::{CertificateList, Version};

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if contents.len() < 128 {
        result.push(u8::try_from(contents.len()).unwrap());
    } else {
        result.extend_from_slice(&[0x81, u8::try_from(contents.len()).unwrap()]);
    }
    result.extend_from_slice(contents);
    result
}

fn algorithm() -> Vec<u8> {
    tlv(48, &[6, 3, 0x2a, 3, 4])
}
fn issuer() -> Vec<u8> {
    tlv(48, &tlv(49, &tlv(48, &[6, 3, 0x55, 4, 3, 12, 1, b'A'])))
}
fn date() -> Vec<u8> {
    tlv(23, b"261012120000Z")
}
fn extension(critical: bool) -> Vec<u8> {
    let mut value = vec![6, 3, 0x55, 0x1d, 0x14];
    if critical {
        value.extend_from_slice(&[1, 1, 0xff]);
    }
    value.extend_from_slice(&[4, 3, 2, 1, 1]);
    tlv(48, &value)
}
fn tbs(version: Option<u8>, tail: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    if let Some(version) = version {
        result.extend_from_slice(&[2, 1, version]);
    }
    result.extend(algorithm());
    result.extend(issuer());
    result.extend(date());
    result.extend_from_slice(tail);
    tlv(48, &result)
}
fn crl(tbs: &[u8]) -> Vec<u8> {
    tlv(48, &[tbs, &algorithm(), &[3, 2, 0, 0xab]].concat())
}
fn entry(serial: u8, extensions: &[u8]) -> Vec<u8> {
    tlv(48, &[&[2, 1, serial][..], &date(), extensions].concat())
}

fn certificate(v3: bool, usage: Option<u8>, key: u8) -> Vec<u8> {
    let mut signed = Vec::new();
    if v3 {
        signed.extend(tlv(0xa0, &[2, 1, 2]));
    }
    signed.extend([2, 1, 1]);
    signed.extend(algorithm());
    signed.extend(issuer());
    signed.extend(tlv(48, &[date(), date()].concat()));
    signed.extend(issuer());
    signed.extend(tlv(48, &[algorithm(), tlv(3, &[0, key])].concat()));
    if let Some(bits) = usage {
        let extension = tlv(
            48,
            &[
                &[6, 3, 0x55, 0x1d, 0x0f][..],
                &tlv(
                    4,
                    &tlv(3, &[u8::try_from(bits.trailing_zeros()).unwrap(), bits]),
                ),
            ]
            .concat(),
        );
        signed.extend(tlv(0xa3, &tlv(48, &extension)));
    }
    crl(&tlv(48, &signed))
}

struct SignatureYes;
impl structured_pkix::path::Verify for SignatureYes {
    type Error = std::convert::Infallible;
    fn verify(
        &self,
        _: &structured_pkix::AlgorithmIdentifier<'_>,
        _: structured_pkix::path::WorkingKey<'_>,
        _: &[u8],
        _: structured_asn1::BitString<'_>,
        _: &Memory,
    ) -> Result<structured_pkix::path::Verified, Self::Error> {
        Ok(structured_pkix::path::Verified::Yes)
    }
}

fn authenticated<'r, 'a>(
    crl: &'r CertificateList<'a>,
    issuer: &'r structured_pkix::Certificate<'a>,
    execution: &Memory,
) -> structured_pkix::crl::Authenticated<'r, 'a> {
    let result = crl
        .authenticate(
            issuer,
            structured_pkix::path::WorkingKey::standing(issuer.tbs().public_key()),
            &SignatureYes,
            execution,
        )
        .unwrap();
    let structured_pkix::crl::Authentication::Authenticated(proof) = result else {
        panic!("fixture authority refused")
    };
    proof
}

#[test]
fn complete_crl_number_requires_noncriticality_and_valid_nonnegative_syntax() {
    // RFC5280 §5.2.3 forbids critical cRLNumber. Known noncritical metadata
    // must not bypass validation merely because no delta was selected.
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = certificate(false, None, 7);
    let issuer_cert = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    for number in [
        extension(true),
        tlv(
            48,
            &[tlv(6, &[0x55, 0x1d, 0x14]), tlv(4, &[2, 1, 0xff])].concat(),
        ),
        tlv(48, &[tlv(6, &[0x55, 0x1d, 0x14]), tlv(4, &[5, 0])].concat()),
    ] {
        let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &number))));
        let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
        assert!(
            authenticated(&parsed, &issuer_cert, &execution)
                .entry(&issuer_cert, &execution)
                .is_err()
        );
    }
    let bytes = crl(&tbs(None, &[]));
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    assert!(matches!(
        authenticated(&parsed, &issuer_cert, &execution)
            .entry(&issuer_cert, &execution)
            .unwrap(),
        structured_pkix::crl::EntryLookup::Absent
    ));
}

#[test]
fn identical_relative_distribution_fields_keep_default_issuer_dn_equality() {
    // 5.2.5 requires the original relative fields to have identical encoding;
    // 6.3.3(b)(1) still compares the issuer bases as names, not as DER aliases.
    use structured_pkix::crl::{Reasons, ScopeOutcome};
    let relative = tlv(
        0xa1,
        &tlv(48, &[tlv(6, &[0x55, 4, 3]), tlv(12, b"Point")].concat()),
    );
    let point_name = tlv(0xa0, &relative);
    let dp = tlv(
        48,
        &[
            tlv(6, &[0x55, 0x1d, 0x1f]),
            tlv(4, &tlv(48, &tlv(48, &point_name))),
        ]
        .concat(),
    );
    let target_body = tlv(
        48,
        &[
            tlv(0xa0, &[2, 1, 2]),
            tlv(2, &[1]),
            algorithm(),
            issuer(),
            tlv(48, &[date(), date()].concat()),
            issuer(),
            tlv(48, &[algorithm(), tlv(3, &[0, 7])].concat()),
            tlv(0xa3, &tlv(48, &dp)),
        ]
        .concat(),
    );
    let target_bytes = crl(&target_body);
    let idp = tlv(
        48,
        &[
            tlv(6, &[0x55, 0x1d, 0x1c]),
            tlv(1, &[0xff]),
            tlv(4, &tlv(48, &point_name)),
        ]
        .concat(),
    );
    let alternate = tlv(
        48,
        &tlv(
            49,
            &tlv(48, &[tlv(6, &[0x55, 4, 3]), tlv(19, b"A")].concat()),
        ),
    );
    let crl_body = tlv(
        48,
        &[
            tlv(2, &[1]),
            algorithm(),
            alternate,
            date(),
            tlv(0xa0, &tlv(48, &idp)),
        ]
        .concat(),
    );
    let bytes = crl(&crl_body);
    let issuer_bytes = certificate(false, None, 7);
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let signer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let target = structured_pkix::Certificate::read(&parser, &target_bytes, 300).unwrap();
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    assert_eq!(
        authenticated(&parsed, &signer, &execution)
            .scope(&target, &execution)
            .unwrap(),
        ScopeOutcome::Applicable(Reasons::ALL)
    );
}

#[test]
fn distribution_names_require_exact_selected_encoding_without_synthetic_broadening() {
    // RFC5280 5.2.5 requires identical selected name encodings, while 6.3.3
    // permits intersecting GeneralNames lists. Semantic aliases cannot acquire
    // coverage by falling back to a synthetic issuer-name distribution point.
    use structured_pkix::crl::{Reasons, ScopeFailure, ScopeOutcome};
    let full = |names: Vec<Vec<u8>>| tlv(0xa0, &names.concat());
    let rdn = |tag| {
        tlv(
            0xa1,
            &tlv(48, &[tlv(6, &[0x55, 4, 3]), tlv(tag, b"A")].concat()),
        )
    };
    let alternate_dn = tlv(
        48,
        &tlv(
            49,
            &tlv(48, &[tlv(6, &[0x55, 4, 3]), tlv(19, b"A")].concat()),
        ),
    );
    for (dp_name, idp_name, exact) in [
        (
            full(vec![tlv(0x86, b"HTTP://crl.example:80/a")]),
            full(vec![tlv(0x86, b"http://crl.example/a")]),
            false,
        ),
        (
            full(vec![tlv(0x82, b"CRL.example")]),
            full(vec![tlv(0x82, b"crl.example")]),
            false,
        ),
        (
            full(vec![tlv(0xa4, &alternate_dn)]),
            full(vec![tlv(0xa4, &issuer())]),
            false,
        ),
        (rdn(19), rdn(12), false),
        (rdn(12), rdn(12), true),
        (
            full(vec![
                tlv(0x86, b"http://other.example/a"),
                tlv(0x86, b"http://crl.example/a"),
            ]),
            full(vec![tlv(0x86, b"http://crl.example/a")]),
            true,
        ),
    ] {
        let dp_extension = tlv(
            48,
            &[
                tlv(6, &[0x55, 0x1d, 0x1f]),
                tlv(4, &tlv(48, &tlv(48, &tlv(0xa0, &dp_name)))),
            ]
            .concat(),
        );
        let target_body = tlv(
            48,
            &[
                tlv(0xa0, &[2, 1, 2]),
                tlv(2, &[1]),
                algorithm(),
                issuer(),
                tlv(48, &[date(), date()].concat()),
                issuer(),
                tlv(48, &[algorithm(), tlv(3, &[0, 7])].concat()),
                tlv(0xa3, &tlv(48, &dp_extension)),
            ]
            .concat(),
        );
        let target_bytes = crl(&target_body);
        let idp_extension = tlv(
            48,
            &[
                tlv(6, &[0x55, 0x1d, 0x1c]),
                tlv(1, &[0xff]),
                tlv(4, &tlv(48, &tlv(0xa0, &idp_name))),
            ]
            .concat(),
        );
        let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &idp_extension))));
        let issuer_bytes = certificate(false, None, 7);
        let execution = memory(128 * 1024, 1_000_000);
        let parser = Parser::der(execution.clone());
        let signer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
        let target = structured_pkix::Certificate::read(&parser, &target_bytes, 300).unwrap();
        let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
        assert_eq!(
            authenticated(&parsed, &signer, &execution)
                .scope(&target, &execution)
                .unwrap(),
            if exact {
                ScopeOutcome::Applicable(Reasons::ALL)
            } else {
                ScopeOutcome::NotApplicable(ScopeFailure::DistributionName)
            }
        );
    }
}

#[test]
fn explicit_crl_issuer_requires_original_name_encoding() {
    // RFC5280 4.2.1.13 mandates identical cRLIssuer DER, even where ordinary
    // Name matching equates PrintableString and UTF8String. An indirect source
    // cannot gain coverage through a different target issuer's fallback.
    use structured_pkix::crl::{ScopeFailure, ScopeOutcome};
    let alternate = tlv(
        48,
        &tlv(
            49,
            &tlv(48, &[tlv(6, &[0x55, 4, 3]), tlv(19, b"A")].concat()),
        ),
    );
    let other_issuer = tlv(
        48,
        &tlv(
            49,
            &tlv(48, &[tlv(6, &[0x55, 4, 3]), tlv(12, b"B")].concat()),
        ),
    );
    let idp_extension = tlv(
        48,
        &[
            tlv(6, &[0x55, 0x1d, 0x1c]),
            tlv(1, &[0xff]),
            tlv(4, &tlv(48, &tlv(0x84, &[0xff]))),
        ]
        .concat(),
    );
    let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &idp_extension))));
    let issuer_bytes = certificate(false, None, 7);
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let signer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    let proof = authenticated(&parsed, &signer, &execution);
    for (named_issuer, exact) in [(issuer(), true), (alternate, false)] {
        let point = tlv(48, &tlv(0xa2, &tlv(0xa4, &named_issuer)));
        let dp_extension = tlv(
            48,
            &[tlv(6, &[0x55, 0x1d, 0x1f]), tlv(4, &tlv(48, &point))].concat(),
        );
        let target_body = tlv(
            48,
            &[
                tlv(0xa0, &[2, 1, 2]),
                tlv(2, &[1]),
                algorithm(),
                other_issuer.clone(),
                tlv(48, &[date(), date()].concat()),
                issuer(),
                tlv(48, &[algorithm(), tlv(3, &[0, 7])].concat()),
                tlv(0xa3, &tlv(48, &dp_extension)),
            ]
            .concat(),
        );
        let target_bytes = crl(&target_body);
        let target = structured_pkix::Certificate::read(&parser, &target_bytes, 300).unwrap();
        assert_eq!(
            proof.scope(&target, &execution).unwrap(),
            if exact {
                ScopeOutcome::Applicable(structured_pkix::crl::Reasons::ALL)
            } else {
                ScopeOutcome::NotApplicable(ScopeFailure::Issuer)
            }
        );
    }
}

#[test]
fn direct_entry_issuer_uses_dn_equality_instead_of_certificate_issuer_encoding_rule() {
    // RFC5280 §7.1 compares UTF8String and PrintableString with the common DN
    // rules. §5.3.3's original encoding rule belongs to certificateIssuer,
    // not the default issuer name in an ordinary direct CRL.
    let alternate = tlv(
        48,
        &tlv(
            49,
            &tlv(48, &[tlv(6, &[0x55, 4, 3]), tlv(19, b"A")].concat()),
        ),
    );
    let signed = tlv(
        48,
        &[algorithm(), alternate, date(), tlv(48, &entry(1, &[]))].concat(),
    );
    let bytes = crl(&signed);
    let issuer_bytes = certificate(false, None, 7);
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_cert = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    let proof = authenticated(&parsed, &issuer_cert, &execution);
    assert!(matches!(
        proof.scope(&issuer_cert, &execution).unwrap(),
        structured_pkix::crl::ScopeOutcome::Applicable(_)
    ));
    assert!(matches!(
        proof.entry(&issuer_cert, &execution).unwrap(),
        structured_pkix::crl::EntryLookup::Found(_)
    ));
}

#[test]
fn entry_date_relation_is_utc_qualified_and_resource_error_locates_original_date() {
    // Raw date order alone cannot establish UTC occurrence. The shared helper
    // must preserve unknown facts and place resource errors at the date field.
    use structured_pkix::temporal::{Instant, LeapTable};
    use structured_pkix::time::Relation;
    let bytes = crl(&tbs(None, &tlv(48, &entry(1, &[]))));
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    let entry = &parsed.tbs().revoked_certificates()[0];
    let label = entry.revocation_date().instant();
    let utc = LeapTable::new(label.seconds() - 10, label.seconds() + 10, &[]).unwrap();
    assert_eq!(
        entry.time_relation(label.into(), &utc, &execution).unwrap(),
        Relation::At
    );
    assert_eq!(
        entry
            .time_relation(
                Instant::new(label.seconds() + 1, 0).unwrap().into(),
                &utc,
                &execution
            )
            .unwrap(),
        Relation::Before
    );
    assert_eq!(
        entry
            .time_relation(
                Instant::new(label.seconds() - 1, 0).unwrap().into(),
                &utc,
                &execution
            )
            .unwrap(),
        Relation::After
    );
    let unknown = LeapTable::new(label.seconds() + 1, label.seconds() + 10, &[]).unwrap();
    assert!(matches!(
        entry
            .time_relation(label.into(), &unknown, &execution)
            .unwrap(),
        Relation::Uncertain(_)
    ));
    let error = entry
        .time_relation(label.into(), &utc, &memory(0, 0))
        .unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), entry.span().start + 5);
}

fn reason_scoped_crl(flags: &[u8]) -> Vec<u8> {
    let idp = tlv(48, &tlv(0x83, flags));
    let extension = tlv(
        48,
        &[tlv(6, &[0x55, 0x1d, 0x1c]), tlv(1, &[0xff]), tlv(4, &idp)].concat(),
    );
    crl(&tbs(
        Some(1),
        &[tlv(23, b"261013120000Z"), tlv(0xa0, &tlv(48, &extension))].concat(),
    ))
}

#[test]
fn qualified_coverage_retains_sources_and_never_accepts_unusable_time() {
    // Only applicable, current, conflict-free absence may add reasons. The
    // union owns accounted source handles and keeps exact source provenance.
    use structured_pkix::crl::{
        CompleteEvidence, Coverage, CoverageAdmission, Evaluation, SourceOrigin,
    };
    use structured_pkix::temporal::{Instant, LeapTable};
    let first_bytes = reason_scoped_crl(&[3, 0x78]);
    let second_bytes = reason_scoped_crl(&[7, 0x07, 0x80]);
    let issuer_bytes = certificate(false, None, 7);
    let other_bytes = certificate(false, None, 8);
    let execution = memory(128 * 1024, 10_000_000);
    let parser = Parser::der(execution.clone());
    let target = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let other_target = structured_pkix::Certificate::read(&parser, &other_bytes, 2000).unwrap();
    let first = CertificateList::read(&parser, &first_bytes, 600).unwrap();
    let second = CertificateList::read(&parser, &second_bytes, 1000).unwrap();
    let first_proof = authenticated(&first, &target, &execution);
    let second_proof = authenticated(&second, &target, &execution);
    let now = first.tbs().this_update().instant();
    let next = first.tbs().next_update().unwrap().instant();
    let utc = LeapTable::new(now.seconds() - 10, next.seconds() + 10, &[]).unwrap();
    let mut time = Evaluation {
        now: now.into(),
        utc: &utc,
        execution: &execution,
        origin: SourceOrigin::Cached,
    };
    let CompleteEvidence::Facts(facts) = first_proof.evaluate(&target, &time).unwrap() else {
        panic!("first scope missing");
    };
    let first_absence = facts.absence().unwrap();
    let CompleteEvidence::Facts(facts) = second_proof.evaluate(&target, &time).unwrap() else {
        panic!("second scope missing");
    };
    let second_absence = facts.absence().unwrap();
    let retained = execution.used();
    assert!(
        Coverage::new(first_absence, &memory(0, 10_000_000))
            .unwrap_err()
            .is_resource()
    );
    let mut coverage = Coverage::new(first_absence, &execution).unwrap();
    assert!(!coverage.reasons().is_complete());
    assert_eq!(
        coverage
            .add(second_absence, &memory(0, 10_000_000))
            .unwrap(),
        CoverageAdmission::DifferentExecution
    );
    assert_eq!(
        coverage.add(second_absence, &execution).unwrap(),
        CoverageAdmission::Added
    );
    assert!(coverage.reasons().is_complete());
    assert_eq!(coverage.sources().len(), 2);
    let CompleteEvidence::Facts(other_facts) = first_proof.evaluate(&other_target, &time).unwrap()
    else {
        panic!("second target scope missing");
    };
    assert_eq!(
        coverage
            .add(other_facts.absence().unwrap(), &execution)
            .unwrap(),
        CoverageAdmission::DifferentTarget
    );
    assert_eq!(coverage.sources().len(), 2);
    assert_eq!(
        coverage.add(first_absence, &execution).unwrap(),
        CoverageAdmission::Redundant
    );
    assert_eq!(coverage.sources().len(), 2);
    assert!(
        coverage
            .add(first_absence, &memory(0, 0))
            .is_ok_and(|value| value == CoverageAdmission::DifferentExecution)
    );
    time.now = next.into();
    let CompleteEvidence::Facts(facts) = first_proof.evaluate(&target, &time).unwrap() else {
        panic!("cached deadline scope missing");
    };
    assert!(facts.absence().is_some());
    assert_eq!(
        coverage.add(facts.absence().unwrap(), &execution).unwrap(),
        CoverageAdmission::DifferentTime
    );
    time.origin = SourceOrigin::Replacement;
    let CompleteEvidence::Facts(facts) = first_proof.evaluate(&target, &time).unwrap() else {
        panic!("replacement deadline scope missing");
    };
    assert!(facts.absence().is_none());
    time.now = Instant::new(next.seconds() + 1, 0).unwrap().into();
    let CompleteEvidence::Facts(facts) = first_proof.evaluate(&target, &time).unwrap() else {
        panic!("expired source scope missing");
    };
    assert!(facts.absence().is_none());
    drop(coverage);
    assert_eq!(execution.used(), retained);
}

#[test]
fn explicit_distribution_point_disjoint_reasons_cannot_gain_synthetic_coverage() {
    // RFC 5280 §6.3.3's fallback concerns CRLs not specified in a DP.
    // This named source is specified but has no intersection of reasons;
    // replacing its DP with the synthetic all-reasons DP would broaden it.
    use structured_pkix::crl::{ScopeFailure, ScopeOutcome};
    let directory = tlv(0xa4, &issuer());
    let point_name = tlv(0xa0, &tlv(0xa0, &directory));
    let point = tlv(48, &[point_name.clone(), tlv(0x81, &[6, 0x40])].concat());
    let dp_extension = tlv(
        48,
        &[tlv(6, &[0x55, 0x1d, 0x1f]), tlv(4, &tlv(48, &point))].concat(),
    );
    let mut target_tbs = tlv(0xa0, &[2, 1, 2]);
    target_tbs.extend([2, 1, 1]);
    target_tbs.extend(algorithm());
    target_tbs.extend(issuer());
    target_tbs.extend(tlv(48, &[date(), date()].concat()));
    target_tbs.extend(issuer());
    target_tbs.extend(tlv(48, &[algorithm(), tlv(3, &[0, 7])].concat()));
    target_tbs.extend(tlv(0xa3, &tlv(48, &dp_extension)));
    let target_bytes = crl(&tlv(48, &target_tbs));
    let idp = tlv(48, &[point_name, tlv(0x83, &[5, 0x20])].concat());
    let idp_extension = tlv(
        48,
        &[tlv(6, &[0x55, 0x1d, 0x1c]), tlv(1, &[0xff]), tlv(4, &idp)].concat(),
    );
    let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &idp_extension))));
    let issuer_bytes = certificate(false, None, 7);
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_cert = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let target = structured_pkix::Certificate::read(&parser, &target_bytes, 300).unwrap();
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    assert_eq!(
        authenticated(&parsed, &issuer_cert, &execution)
            .scope(&target, &execution)
            .unwrap(),
        ScopeOutcome::NotApplicable(ScopeFailure::NoReasons)
    );
}

#[test]
fn freshness_preserves_deadlines_missing_fields_and_utc_uncertainty() {
    // Authentication alone says nothing about freshness. The exact deadline
    // stays distinct, missing nextUpdate stays missing, and unavailable UTC facts
    // cannot be silently accepted as either current or expired evidence.
    use structured_pkix::crl::Freshness;
    use structured_pkix::temporal::{Instant, LeapTable, Uncertainty};
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = certificate(false, None, 7);
    let issuer_cert = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let bytes = crl(&tbs(None, &tlv(23, b"261013120000Z")));
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    let proof = authenticated(&parsed, &issuer_cert, &execution);
    let this = parsed.tbs().this_update().instant();
    let next = parsed.tbs().next_update().unwrap().instant();
    let utc = LeapTable::new(this.seconds() - 10, next.seconds() + 10, &[]).unwrap();
    for (label, expected) in [
        (
            Instant::new(this.seconds() - 1, 0).unwrap(),
            Freshness::NotYetCurrent,
        ),
        (this, Freshness::Current),
        (
            Instant::new(next.seconds() - 1, 999_999_999).unwrap(),
            Freshness::Current,
        ),
        (next, Freshness::AtNextUpdate),
    ] {
        assert_eq!(
            proof.freshness(label.into(), &utc, &execution).unwrap(),
            expected
        );
    }
    // Beyond-nanosecond precision still differentiates exact deadline from
    // after it even when the floor is the same whole-second label.
    let label = tlv(24, b"20261013120000.0000000001Z");
    let mut reader = parser.read(&label, 1500).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let fractional = structured_pkix::temporal::read_generalized(&reader, &element, "now").unwrap();
    assert_eq!(fractional.start(), next);
    assert!(fractional.has_subnanosecond_remainder());
    assert_eq!(
        proof.freshness(fractional, &utc, &execution).unwrap(),
        Freshness::Stale
    );
    let unknown = LeapTable::new(this.seconds(), next.seconds(), &[]).unwrap();
    assert_eq!(
        proof.freshness(this.into(), &unknown, &execution).unwrap(),
        Freshness::Uncertain(Uncertainty::OutsideCoverage)
    );
    let invented_leap = Instant::leap_after(this.seconds() + 43_199, 0).unwrap();
    assert_eq!(
        proof
            .freshness(invented_leap.into(), &utc, &execution)
            .unwrap(),
        Freshness::Uncertain(Uncertainty::NotInUtc)
    );
    assert!(
        proof
            .freshness(this.into(), &utc, &memory(0, 0))
            .unwrap_err()
            .is_resource()
    );
    let missing_bytes = crl(&tbs(None, &[]));
    let missing = CertificateList::read(&parser, &missing_bytes, 900).unwrap();
    assert_eq!(
        authenticated(&missing, &issuer_cert, &execution)
            .freshness(this.into(), &utc, &execution)
            .unwrap(),
        Freshness::MissingNextUpdate
    );
    let inverted_bytes = crl(&tbs(None, &date()));
    let inverted = CertificateList::read(&parser, &inverted_bytes, 1000).unwrap();
    assert_eq!(
        authenticated(&inverted, &issuer_cert, &execution)
            .freshness(this.into(), &utc, &execution)
            .unwrap(),
        Freshness::InvalidUpdateOrder
    );
}

#[test]
fn ldap_crl_locations_require_a_dn_and_one_binary_crl_attribute() {
    // RFC5280 4.2.1.13 selects an entry and exactly one RFC4523 CRL
    // attribute; generic LDAP defaults must not select all attributes.
    for (location, valid) in [
        ("ldap:", false),
        ("ldap:///", false),
        ("ldap:///?certificateRevocationList;binary", false),
        ("ldap://ldap.example/?authorityRevocationList;binary", false),
        ("ldap:///cn=CA", false),
        ("ldap:///cn=CA?certificateRevocationList", false),
        (
            "ldap:///cn=CA?certificateRevocationList;binary,authorityRevocationList;binary",
            false,
        ),
        ("ldap:///cn=CA?*", false),
        ("ldap:///broken?certificateRevocationList;binary", false),
        ("ldap:///cn=CA%5C?certificateRevocationList;binary", false),
        (
            "ldap:///cn=CA?certificateRevocationList;binary?children",
            false,
        ),
        (
            "ldap:///cn=CA?certificateRevocationList;binary?base?(broken)",
            false,
        ),
        (
            "ldap://user@host/cn=CA?certificateRevocationList;binary",
            false,
        ),
        (
            "ldap:///cn=CA?certificateRevocationList;binary#fragment",
            false,
        ),
        ("ldap:///cn=CA?certificateRevocationList;binary", true),
        (
            "LDAP://ldap.example/cn=CA%2Cdc=example?AuthorityRevocationList;BINARY",
            true,
        ),
        (
            "ldap:///telephoneNumber=123?2.5.4.39;binary?base?(&(objectClass=*)(cn=CA))",
            true,
        ),
        (
            "ldap:///cn=CA?deltaRevocationList;binary?sub?(cn=CA)?!1.2.3=value",
            true,
        ),
    ] {
        let name = tlv(0xa0, &tlv(0xa0, &tlv(0x86, location.as_bytes())));
        let ext = tlv(
            48,
            &[
                tlv(6, &[0x55, 0x1d, 0x1c]),
                tlv(1, &[0xff]),
                tlv(4, &tlv(48, &name)),
            ]
            .concat(),
        );
        let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &ext))));
        let execution = memory(128 * 1024, 1_000_000);
        let parser = Parser::der(execution.clone());
        let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
        let extension = parsed
            .tbs()
            .extensions()
            .get(structured_pkix::oid::ISSUING_DISTRIBUTION_POINT, &execution)
            .unwrap()
            .unwrap();
        let result = structured_pkix::crl::IssuingDistributionPoint::read(extension, &execution);
        assert_eq!(result.is_ok(), valid, "{location}");
        if !valid {
            assert_eq!(result.unwrap_err().code(), ErrorCode::MalformedValue);
        }
    }
}

#[test]
fn distribution_point_locations_preserve_required_scheme_authorities() {
    // The LDAP empty-host exception must not admit malformed HTTP/HTTPS/FTP
    // locations. Both certificate DP and CRL IDP readers use this same grammar.
    for (location, valid) in [
        ("http:", false),
        ("http:crl", false),
        ("http:///crl", false),
        ("HTTPS://:443/crl", false),
        ("https://user@/crl", false),
        ("ftp:", false),
        ("ftp:/crl", false),
        ("ftp:///crl", false),
        ("http://crl.example/a", true),
        ("https://[2001:db8::1]:443/a?q=1#id", true),
        ("ftp://user@crl.example/a;type=i", true),
        (
            "ldap:///cn=CA,dc=example,dc=com?certificateRevocationList;binary",
            true,
        ),
        ("urn:example:crl", true),
    ] {
        let name = tlv(0xa0, &tlv(0xa0, &tlv(0x86, location.as_bytes())));
        let idp_extension = tlv(
            48,
            &[
                tlv(6, &[0x55, 0x1d, 0x1c]),
                tlv(1, &[0xff]),
                tlv(4, &tlv(48, &name)),
            ]
            .concat(),
        );
        let dp_extension = tlv(
            48,
            &[
                tlv(6, &[0x55, 0x1d, 0x1f]),
                tlv(4, &tlv(48, &tlv(48, &name))),
            ]
            .concat(),
        );
        let bytes = crl(&tbs(
            Some(1),
            &tlv(0xa0, &tlv(48, &[idp_extension, dp_extension].concat())),
        ));
        let execution = memory(128 * 1024, 1_000_000);
        let parser = Parser::der(execution.clone());
        let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
        let extension = parsed
            .tbs()
            .extensions()
            .get(structured_pkix::oid::ISSUING_DISTRIBUTION_POINT, &execution)
            .unwrap()
            .unwrap();
        let result = structured_pkix::crl::IssuingDistributionPoint::read(extension, &execution);
        assert_eq!(result.is_ok(), valid, "IDP: {location}");
        if !valid {
            assert_eq!(result.unwrap_err().code(), ErrorCode::MalformedValue);
        }

        let extension = parsed
            .tbs()
            .extensions()
            .get(structured_pkix::oid::CRL_DISTRIBUTION_POINTS, &execution)
            .unwrap()
            .unwrap();
        let result = structured_pkix::access::DistributionPoints::read(extension, &execution);
        assert_eq!(result.is_ok(), valid, "DP: {location}");
        if !valid {
            assert_eq!(result.unwrap_err().code(), ErrorCode::MalformedValue);
        }
    }
}

#[test]
fn distribution_point_ldap_uri_preserves_an_unspecified_server() {
    // RFC5280 §4.2.1.13 permits ldap:/// pointers that rely on caller server
    // knowledge. SAN host requirements cannot be applied to a DP location.
    let location = b"ldap:///cn=CA,dc=example,dc=com?certificateRevocationList;binary";
    let name = tlv(0xa0, &tlv(0xa0, &tlv(0x86, location)));
    let idp = tlv(48, &name);
    let extension = tlv(
        48,
        &[tlv(6, &[0x55, 0x1d, 0x1c]), tlv(1, &[0xff]), tlv(4, &idp)].concat(),
    );
    let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &extension))));
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    let extension = parsed
        .tbs()
        .extensions()
        .get(structured_pkix::oid::ISSUING_DISTRIBUTION_POINT, &execution)
        .unwrap()
        .unwrap();
    let scope =
        structured_pkix::crl::IssuingDistributionPoint::read(extension, &execution).unwrap();
    let [structured_pkix::general_name::GeneralName::Uri(actual)] = scope.full_name() else {
        panic!("missing URI")
    };
    assert_eq!(actual.as_bytes(), location);
}

#[test]
fn delta_binding_requires_matching_full_authority_identifier_payloads() {
    // RFC5280 §6.3.3(c)(3) compares AKI extensions, not just their key IDs.
    // Missing fields remain explicit; changed optional issuer/serial metadata
    // cannot pass because the keyIdentifier happens to agree.
    use structured_pkix::crl::{DeltaBinding, DeltaFailure, MissingDeltaField};
    fn metadata(delta: bool, aki: Option<&[u8]>) -> Vec<u8> {
        let mut extensions = extension(false);
        if delta {
            let number = tlv(
                48,
                &[tlv(6, &[0x55, 0x1d, 0x14]), tlv(4, &[2, 1, 2])].concat(),
            );
            extensions = number;
            extensions.extend(tlv(
                48,
                &[
                    tlv(6, &[0x55, 0x1d, 0x1b]),
                    tlv(1, &[0xff]),
                    tlv(4, &[2, 1, 1]),
                ]
                .concat(),
            ));
        }
        if let Some(aki) = aki {
            extensions.extend(tlv(
                48,
                &[tlv(6, &[0x55, 0x1d, 0x23]), tlv(4, aki)].concat(),
            ));
        }
        tlv(0xa0, &tlv(48, &extensions))
    }
    let key_id = tlv(48, &[0x80, 1, 7]);
    let another = tlv(48, &[0x80, 1, 8]);
    let tuple = tlv(
        48,
        &[
            tlv(0x80, &[7]),
            tlv(0xa1, &tlv(0xa4, &issuer())),
            tlv(0x82, &[1]),
        ]
        .concat(),
    );
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = certificate(false, None, 7);
    let issuer_cert = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    for (base_aki, delta_aki, expected) in [
        (None, None, 0),
        (Some(&key_id[..]), None, 1),
        (Some(&key_id[..]), Some(&key_id[..]), 2),
        (Some(&key_id[..]), Some(&another[..]), 3),
        (Some(&key_id[..]), Some(&tuple[..]), 3),
    ] {
        let base_bytes = crl(&tbs(Some(1), &metadata(false, base_aki)));
        let delta_bytes = crl(&tbs(Some(1), &metadata(true, delta_aki)));
        let base = CertificateList::read(&parser, &base_bytes, 300).unwrap();
        let delta = CertificateList::read(&parser, &delta_bytes, 600).unwrap();
        let base_proof = authenticated(&base, &issuer_cert, &execution);
        let delta_proof = authenticated(&delta, &issuer_cert, &execution);
        match (
            base_proof.bind_delta(&delta_proof, &execution).unwrap(),
            expected,
        ) {
            (DeltaBinding::Missing(MissingDeltaField::BaseAuthorityIdentifier), 0)
            | (DeltaBinding::Missing(MissingDeltaField::DeltaAuthorityIdentifier), 1)
            | (DeltaBinding::Bound(_), 2)
            | (DeltaBinding::Rejected(DeltaFailure::AuthorityIdentifier), 3) => (),
            other => panic!("unexpected authority pairing: {other:?}"),
        }
    }
}

#[test]
fn remove_from_crl_on_a_complete_source_refuses_even_an_unmatched_entry() {
    // RFC5280 §5.3.1 permits removeFromCRL only on deltas. It cannot be
    // ignored merely because that malformed entry names another certificate.
    let reason = tlv(
        48,
        &[tlv(6, &[0x55, 0x1d, 0x15]), tlv(4, &[10, 1, 8])].concat(),
    );
    let bytes = crl(&tbs(Some(1), &tlv(48, &entry(2, &tlv(48, &reason)))));
    let issuer_bytes = certificate(false, None, 7);
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_cert = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    let error = authenticated(&parsed, &issuer_cert, &execution)
        .entry(&issuer_cert, &execution)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn delta_entries_override_base_without_requiring_a_prior_hold() {
    // RFC5280 §6.3.3(i)–(k): delta first, base only when absent, and removal
    // prevents falling back to the base. §5.2.4 does not require this base
    // to contain a hold entry before a delta removal is accepted.
    use structured_pkix::crl::{CombinedEntry, DeltaBinding, EntryOrigin, Reason};
    fn revoked(serial: u8, reason: u8) -> Vec<u8> {
        let extension = tlv(
            48,
            &[tlv(6, &[0x55, 0x1d, 0x15]), tlv(4, &tlv(10, &[reason]))].concat(),
        );
        tlv(48, &entry(serial, &tlv(48, &extension)))
    }
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = certificate(false, None, 7);
    let issuer_cert = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    for (base_entry, delta_entry, expected) in [
        (revoked(1, 6), revoked(1, 8), 0),
        (revoked(2, 1), revoked(1, 8), 0),
        (revoked(1, 1), Vec::new(), 1),
        (revoked(1, 1), revoked(1, 3), 2),
        (revoked(2, 1), Vec::new(), 3),
    ] {
        let base_bytes = crl(&tbs(
            Some(1),
            &[base_entry, crl_metadata(Some(&[5]), None, false)].concat(),
        ));
        let delta_bytes = crl(&tbs(
            Some(1),
            &[delta_entry, crl_metadata(Some(&[6]), Some(&[5]), false)].concat(),
        ));
        let base = CertificateList::read(&parser, &base_bytes, 300).unwrap();
        let delta = CertificateList::read(&parser, &delta_bytes, 600).unwrap();
        let base_proof = authenticated(&base, &issuer_cert, &execution);
        let delta_proof = authenticated(&delta, &issuer_cert, &execution);
        let DeltaBinding::Bound(pair) = base_proof.bind_delta(&delta_proof, &execution).unwrap()
        else {
            panic!("valid source pair refused")
        };
        match (pair.entry(&issuer_cert, &execution).unwrap(), expected) {
            (CombinedEntry::Removed { entry }, 0) => {
                assert!(std::ptr::eq(
                    entry,
                    &raw const delta.tbs().revoked_certificates()[0]
                ));
            }
            (
                CombinedEntry::Revoked {
                    origin: EntryOrigin::Complete,
                    reason: Reason::KeyCompromise,
                    entry,
                },
                1,
            ) => assert!(std::ptr::eq(
                entry,
                &raw const base.tbs().revoked_certificates()[0]
            )),
            (
                CombinedEntry::Revoked {
                    origin: EntryOrigin::Delta,
                    reason: Reason::AffiliationChanged,
                    entry,
                },
                2,
            ) => assert!(std::ptr::eq(
                entry,
                &raw const delta.tbs().revoked_certificates()[0]
            )),
            (CombinedEntry::Absent, 3) => (),
            _ => panic!("wrong effective delta entry"),
        }
        assert!(
            pair.entry(&issuer_cert, &memory(0, 0))
                .unwrap_err()
                .is_resource()
        );
    }
}

#[test]
fn composed_delta_uses_delta_expiry_and_preserves_entry_failures() {
    // RFC5280 §5.2.4: a current delta updates an expired base. Neither an
    // unpaired delta nor an unsupported/conflicting entry can mint absence.
    use structured_pkix::crl::{
        CompleteEvidence, DeltaBinding, DeltaEvidence, Evaluation, Freshness, SourceOrigin,
    };
    use structured_pkix::temporal::{Instant, LeapTable};
    let execution = memory(128 * 1024, 10_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = certificate(false, None, 7);
    let target = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let unknown = tlv(
        48,
        &[tlv(6, &[0x2a, 3, 4]), tlv(1, &[0xff]), tlv(4, &[5, 0])].concat(),
    );
    let reason = tlv(
        48,
        &[tlv(6, &[0x55, 0x1d, 0x15]), tlv(4, &[10, 1, 8])].concat(),
    );
    for (entries, absence) in [
        (Vec::new(), true),
        (tlv(48, &entry(1, &tlv(48, &reason))), true),
        (tlv(48, &entry(2, &tlv(48, &unknown))), false),
        (tlv(48, &[entry(1, &[]), entry(1, &[])].concat()), false),
    ] {
        let base_bytes = crl(&tbs(
            Some(1),
            &[
                tlv(23, b"261012120001Z"),
                crl_metadata(Some(&[5]), None, false),
            ]
            .concat(),
        ));
        let delta_bytes = crl(&tbs(
            Some(1),
            &[
                tlv(23, b"261013120000Z"),
                entries,
                crl_metadata(Some(&[6]), Some(&[5]), false),
            ]
            .concat(),
        ));
        let base = CertificateList::read(&parser, &base_bytes, 300).unwrap();
        let delta = CertificateList::read(&parser, &delta_bytes, 600).unwrap();
        let base_proof = authenticated(&base, &target, &execution);
        let delta_proof = authenticated(&delta, &target, &execution);
        let DeltaBinding::Bound(pair) = base_proof.bind_delta(&delta_proof, &execution).unwrap()
        else {
            panic!("pair binding failed");
        };
        let start = base.tbs().this_update().instant();
        let end = delta.tbs().next_update().unwrap().instant();
        let utc = LeapTable::new(start.seconds() - 10, end.seconds() + 10, &[]).unwrap();
        let mut time = Evaluation {
            now: Instant::new(start.seconds() + 2, 0).unwrap().into(),
            utc: &utc,
            execution: &execution,
            origin: SourceOrigin::Cached,
        };
        assert!(matches!(
            delta_proof.evaluate(&target, &time).unwrap(),
            CompleteEvidence::DeltaNeedsBase
        ));
        let DeltaEvidence::Facts(facts) = pair.evaluate(&target, &time).unwrap() else {
            panic!("pair scope failed");
        };
        assert_eq!(facts.base_freshness(), Freshness::Stale);
        assert_eq!(facts.delta_freshness(), Freshness::Current);
        assert_eq!(facts.absence().is_some(), absence);
        time.now = end.into();
        time.origin = SourceOrigin::Replacement;
        let DeltaEvidence::Facts(facts) = pair.evaluate(&target, &time).unwrap() else {
            panic!("expired pair scope failed");
        };
        assert_eq!(facts.delta_freshness(), Freshness::AtNextUpdate);
        assert!(facts.absence().is_none());
        let unfunded = memory(0, 0);
        time.execution = &unfunded;
        assert!(pair.evaluate(&target, &time).unwrap_err().is_resource());
    }
}

#[test]
fn entry_lookup_is_issuer_bound_and_scans_critical_demands_after_a_match() {
    // A later unrelated critical demand still prevents a status conclusion;
    // repeated matching identity is conflicting, not first/last-wins.
    use structured_pkix::crl::EntryLookup;
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = certificate(false, None, 7);
    let issuer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    for (entries, expected) in [
        (vec![entry(1, &[])], 1),
        (vec![entry(2, &[])], 0),
        (vec![entry(1, &[]), entry(1, &[])], 2),
    ] {
        let bytes = crl(&tbs(Some(1), &tlv(48, &entries.concat())));
        let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
        match (
            authenticated(&parsed, &issuer, &execution)
                .entry(&issuer, &execution)
                .unwrap(),
            expected,
        ) {
            (EntryLookup::Found(entry), 1) => assert_eq!(entry.serial().as_u64(), Some(1)),
            (EntryLookup::Absent, 0) => (),
            (EntryLookup::Conflict { first, second }, 2) => {
                assert!(first.span().start < second.span().start);
            }
            _ => panic!("wrong entry identity result"),
        }
    }
    let unknown = tlv(48, &[6, 3, 0x2a, 3, 4, 1, 1, 0xff, 4, 2, 5, 0]);
    let bytes = crl(&tbs(
        Some(1),
        &tlv(48, &[entry(1, &[]), entry(99, &tlv(48, &unknown))].concat()),
    ));
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    assert!(
        matches!(authenticated(&parsed, &issuer, &execution).entry(&issuer, &execution).unwrap(), EntryLookup::Unsupported { kind, span } if kind.as_bytes() == [0x2a,3,4] && span.start > parsed.tbs().revoked_certificates()[0].span().start)
    );
    let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &unknown))));
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    assert!(matches!(
        authenticated(&parsed, &issuer, &execution)
            .entry(&issuer, &execution)
            .unwrap(),
        EntryLookup::Unsupported { .. }
    ));
    assert!(
        authenticated(&parsed, &issuer, &execution)
            .entry(&issuer, &memory(0, 0))
            .unwrap_err()
            .is_limit()
    );
}

#[test]
fn indirect_issuer_replacement_applies_to_its_entry_and_following_entries() {
    // Equal serials under a different inherited issuer are different identities.
    // Omission inherits from the preceding entry, not from the CRL issuer.
    use structured_pkix::crl::EntryLookup;
    let execution = memory(128 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = certificate(false, None, 7);
    let issuer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let other_name = tlv(48, &tlv(49, &tlv(48, &[6, 3, 0x55, 4, 3, 12, 1, b'B'])));
    let issuer_extension = |name: &[u8]| {
        tlv(
            48,
            &[
                &[6, 3, 0x55, 0x1d, 0x1d, 1, 1, 0xff][..],
                &tlv(4, &tlv(48, &tlv(0xa4, name))),
            ]
            .concat(),
        )
    };
    let indirect = tlv(
        0xa0,
        &tlv(
            48,
            &tlv(
                48,
                &[
                    6, 3, 0x55, 0x1d, 0x1c, 1, 1, 0xff, 4, 5, 48, 3, 0x84, 1, 0xff,
                ],
            ),
        ),
    );
    let wrong_issuer = tlv(
        48,
        &[
            entry(9, &tlv(48, &issuer_extension(&other_name))),
            entry(1, &[]),
        ]
        .concat(),
    );
    let bytes = crl(&tbs(Some(1), &[wrong_issuer, indirect.clone()].concat()));
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    assert!(matches!(
        authenticated(&parsed, &issuer, &execution)
            .entry(&issuer, &execution)
            .unwrap(),
        EntryLookup::Absent
    ));
    let restored = tlv(
        48,
        &[
            entry(9, &tlv(48, &issuer_extension(&other_name))),
            entry(
                8,
                &tlv(48, &issuer_extension(issuer.tbs().issuer().as_bytes())),
            ),
            entry(1, &[]),
        ]
        .concat(),
    );
    let bytes = crl(&tbs(Some(1), &[restored, indirect].concat()));
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    assert!(
        matches!(authenticated(&parsed, &issuer, &execution).entry(&issuer, &execution).unwrap(), EntryLookup::Found(entry) if entry.serial().as_u64() == Some(1))
    );
    let direct = crl(&tbs(
        Some(1),
        &tlv(
            48,
            &entry(
                1,
                &tlv(48, &issuer_extension(issuer.tbs().issuer().as_bytes())),
            ),
        ),
    ));
    let parsed = CertificateList::read(&parser, &direct, 600).unwrap();
    assert_eq!(
        authenticated(&parsed, &issuer, &execution)
            .entry(&issuer, &execution)
            .unwrap_err()
            .code(),
        ErrorCode::MalformedValue
    );
}

#[test]
fn authentication_binds_key_and_usage_before_signature_dispatch() {
    // A trusted certificate A plus an unrelated trusted key B must not become
    // one signing authority. V3 requires cRLSign; V1 is exempt from presence.
    use std::cell::Cell;
    use structured_pkix::crl::{Authentication, AuthenticationFailure};
    use structured_pkix::path::{Verified, Verify, WorkingKey};
    struct Verifier<'s> {
        calls: Cell<usize>,
        signed: &'s [u8],
    }
    impl Verify for Verifier<'_> {
        type Error = u8;
        fn verify(
            &self,
            _: &structured_pkix::AlgorithmIdentifier<'_>,
            _: WorkingKey<'_>,
            signed: &[u8],
            _: structured_asn1::BitString<'_>,
            _: &Memory,
        ) -> Result<Verified, u8> {
            assert_eq!(signed.as_ptr(), self.signed.as_ptr());
            assert_eq!(signed, self.signed);
            self.calls.set(self.calls.get() + 1);
            Ok(Verified::Yes)
        }
    }
    let execution = memory(64 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let bytes = crl(&tbs(None, &[]));
    let parsed = CertificateList::read(&parser, &bytes, 500).unwrap();
    let verifier = Verifier {
        calls: Cell::new(0),
        signed: parsed.signed_bytes(),
    };
    for (v3, usage, accepted) in [
        (false, None, true),
        (true, Some(2), true),
        (true, None, false),
        (true, Some(0x80), false),
    ] {
        let bytes = certificate(v3, usage, 7);
        let issuer = structured_pkix::Certificate::read(&parser, &bytes, 700).unwrap();
        let outcome = parsed
            .authenticate(
                &issuer,
                WorkingKey::standing(issuer.tbs().public_key()),
                &verifier,
                &execution,
            )
            .unwrap();
        if accepted {
            let Authentication::Authenticated(proof) = outcome else {
                panic!("authentication refused")
            };
            assert!(std::ptr::eq(proof.crl(), &raw const parsed));
            assert!(std::ptr::eq(proof.issuer(), &raw const issuer));
        } else {
            assert!(matches!(
                outcome,
                Authentication::Rejected(AuthenticationFailure::KeyUsage)
            ));
        }
    }
    assert_eq!(verifier.calls.get(), 2);
    let a_bytes = certificate(false, None, 7);
    let b_bytes = certificate(false, None, 8);
    let a = structured_pkix::Certificate::read(&parser, &a_bytes, 700).unwrap();
    let b = structured_pkix::Certificate::read(&parser, &b_bytes, 900).unwrap();
    assert!(matches!(
        parsed
            .authenticate(
                &a,
                WorkingKey::standing(b.tbs().public_key()),
                &verifier,
                &execution
            )
            .unwrap(),
        Authentication::Rejected(AuthenticationFailure::KeyBinding)
    ));
    assert_eq!(verifier.calls.get(), 2);
}

#[test]
fn callback_refusal_unsupported_and_resource_errors_keep_their_origin() {
    // No/Unsupported are completed answers; provider errors and resource
    // exhaustion must survive as errors instead of becoming signature mismatch.
    use structured_pkix::crl::{Authentication, AuthenticationFailure};
    use structured_pkix::error::CallbackError;
    use structured_pkix::path::{Verified, Verify, WorkingKey};
    struct Verifier(Result<Verified, u8>);
    impl Verify for Verifier {
        type Error = u8;
        fn verify(
            &self,
            _: &structured_pkix::AlgorithmIdentifier<'_>,
            _: WorkingKey<'_>,
            _: &[u8],
            _: structured_asn1::BitString<'_>,
            _: &Memory,
        ) -> Result<Verified, u8> {
            self.0
        }
    }
    let execution = memory(64 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let bytes = crl(&tbs(None, &[]));
    let parsed = CertificateList::read(&parser, &bytes, 300).unwrap();
    let issuer_bytes = certificate(false, None, 7);
    let issuer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 700).unwrap();
    let key = WorkingKey::standing(issuer.tbs().public_key());
    assert!(matches!(
        parsed
            .authenticate(&issuer, key, &Verifier(Ok(Verified::No)), &execution)
            .unwrap(),
        Authentication::Rejected(AuthenticationFailure::Signature)
    ));
    assert!(matches!(
        parsed
            .authenticate(
                &issuer,
                key,
                &Verifier(Ok(Verified::Unsupported)),
                &execution
            )
            .unwrap(),
        Authentication::Unsupported
    ));
    assert!(matches!(
        parsed.authenticate(&issuer, key, &Verifier(Err(17)), &execution),
        Err(CallbackError::Callback(17))
    ));
    let current = memory(0, 0);
    let error = parsed
        .authenticate(&issuer, key, &Verifier(Err(17)), &current)
        .unwrap_err();
    let CallbackError::Processing(error) = error else {
        panic!("resource error lost")
    };
    assert!(error.is_limit());
    assert_eq!(error.offset(), 300);
}

#[test]
fn original_signed_ranges_versions_and_missing_next_update_survive() {
    // V1 without nextUpdate is readable evidence, not an invented freshness
    // bound. Reading V2 entries preserves wire order and exact signed bytes.
    let execution = memory(64 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    for (version, tail, expected) in [
        (None, Vec::new(), Version::V1),
        (
            Some(1),
            tlv(48, &[entry(7, &[]), entry(2, &[])].concat()),
            Version::V2,
        ),
    ] {
        let signed = tbs(version, &tail);
        let bytes = crl(&signed);
        let parsed = CertificateList::read(&parser, &bytes, 701).unwrap();
        assert_eq!(parsed.tbs().version(), expected);
        assert_eq!(parsed.tbs().next_update(), None);
        assert_eq!(parsed.signed_bytes(), signed);
        assert_eq!(parsed.as_bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(parsed.span().start, 701);
        let signed_offset = usize::try_from(parsed.tbs().span().start - 701).unwrap();
        assert_eq!(
            parsed.signed_bytes().as_ptr(),
            bytes[signed_offset..].as_ptr()
        );
        if expected == Version::V2 {
            assert_eq!(
                parsed.tbs().revoked_certificates()[0].serial().as_u64(),
                Some(7)
            );
            assert_eq!(
                parsed.tbs().revoked_certificates()[1].serial().as_u64(),
                Some(2)
            );
        }
    }
    assert_eq!(execution.used(), 0);
}

#[test]
fn extension_bearing_crls_require_v2_and_reject_duplicate_or_empty_collections() {
    // Version is a schema boundary, not an issuer policy. Duplicate extension
    // identities and present empty entry/extension sequences are ambiguous.
    let parser = Parser::der(memory(64 * 1024, 1_000_000));
    let ext = tlv(48, &extension(false));
    for tail in [tlv(0xa0, &ext), tlv(48, &entry(3, &ext))] {
        let bytes = crl(&tbs(None, &tail));
        assert_eq!(
            CertificateList::read(&parser, &bytes, 0)
                .unwrap_err()
                .code(),
            ErrorCode::UnexpectedField
        );
    }
    for tail in [tlv(48, &[]), tlv(0xa0, &tlv(48, &[]))] {
        let bytes = crl(&tbs(Some(1), &tail));
        assert_eq!(
            CertificateList::read(&parser, &bytes, 0)
                .unwrap_err()
                .code(),
            ErrorCode::EmptySequence
        );
    }
    let duplicate = tlv(
        0xa0,
        &tlv(48, &[extension(false), extension(true)].concat()),
    );
    let bytes = crl(&tbs(Some(1), &duplicate));
    assert_eq!(
        CertificateList::read(&parser, &bytes, 0)
            .unwrap_err()
            .code(),
        ErrorCode::DuplicateExtension
    );
    let bytes = crl(&tbs(Some(1), &tlv(0xa0, &ext)));
    assert_eq!(
        CertificateList::read(&parser, &bytes, 0)
            .unwrap()
            .tbs()
            .extensions()
            .len(),
        1
    );
}

#[test]
fn der_enforcement_algorithm_agreement_and_trailing_fields_are_not_bypassed() {
    // A BER envelope cannot relax the signed object or choose an unsigned
    // algorithm. Schema errors remain distinct from resource refusals.
    let parser = Parser::new(
        Encoding::Ber,
        Limits::default(),
        memory(64 * 1024, 1_000_000),
    );
    let signed = tbs(None, &[]);
    let bytes = crl(&signed);
    let indefinite = [&[48, 0x80][..], &bytes[2..], &[0, 0]].concat();
    assert!(CertificateList::read(&parser, &indefinite, 0).is_err());
    let mismatch = tlv(
        48,
        &[
            signed.as_slice(),
            &tlv(48, &[6, 3, 0x2a, 3, 5]),
            &[3, 2, 0, 1],
        ]
        .concat(),
    );
    assert_eq!(
        CertificateList::read(&parser, &mismatch, 0)
            .unwrap_err()
            .code(),
        ErrorCode::AlgorithmMismatch
    );
    for bytes in [
        crl(&tbs(Some(0), &[])),
        crl(&tbs(Some(2), &[])),
        crl(&tbs(None, &tlv(2, &[1]))),
        [&bytes[..], &[0]].concat(),
    ] {
        assert!(CertificateList::read(&parser, &bytes, 0).is_err());
    }
}

#[test]
fn lazy_extensions_charge_current_execution_and_retained_metadata_releases_on_drop() {
    // Stored extension metadata stays on its original account. Lazy decoding
    // rebinds work and scratch without transferring or refunding that storage.
    let original = memory(64 * 1024, 1_000_000);
    let parser = Parser::der(original.clone());
    let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &extension(false)))));
    let parsed = CertificateList::read(&parser, &bytes, 900).unwrap();
    assert!(original.used() > 0);
    let used_work = original.work_used();
    let current = memory(64 * 1024, 1_000_000);
    let extension = parsed.tbs().extensions().iter().next().unwrap();
    let mut reader = extension.reader(&current).unwrap();
    assert_eq!(reader.read_integer().unwrap().as_u64(), Some(1));
    assert!(current.work_used() > 0);
    assert_eq!(original.work_used(), used_work);
    drop(reader);
    drop(parsed);
    assert_eq!(original.used(), 0);
    let exhausted = Parser::der(memory(0, 1_000_000));
    let error = CertificateList::read(&exhausted, &bytes, 900).unwrap_err();
    assert!(error.is_resource());
    assert!(error.offset() >= 900);
}

#[test]
fn producing_reader_preserves_local_limits_and_rebinds_all_new_storage() {
    // A retained envelope must not reset parser-local work/depth when a new
    // operation reads its CRL. New metadata belongs to current execution.
    let bytes = crl(&tbs(None, &date()));
    let old = memory(64 * 1024, 1_000_000);
    let parser = Parser::der(old.clone());
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let old_work = old.work_used();
    let current = memory(64 * 1024, 1_000_000);
    let rebound = reader.with_execution(&current);
    let parsed = CertificateList::read_element(&rebound, &element).unwrap();
    assert!(parsed.tbs().next_update().is_some());
    assert_eq!(old.work_used(), old_work);
    assert!(current.used() > 0);
    drop(parsed);
    drop(rebound);
    assert_eq!(current.used(), 0);
    let shallow = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 1,
            ..Limits::default()
        },
        memory(64 * 1024, 1_000_000),
    );
    let error = CertificateList::read(&shallow, &bytes, 400).unwrap_err();
    assert!(error.is_limit());
    assert!(error.offset() >= 400);
    let limited = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 80,
            ..Limits::default()
        },
        memory(64 * 1024, 1_000_000),
    );
    assert!(
        CertificateList::read(&limited, &bytes, 400)
            .unwrap_err()
            .is_limit()
    );
}

#[test]
fn empty_issuer_malformed_calendar_and_entry_trailing_data_are_refused() {
    // Structural schema and calendar checks apply before any issuer or
    // signature callback; readable reversed time intervals remain evidence.
    let parser = Parser::der(memory(64 * 1024, 1_000_000));
    let empty_issuer = tlv(48, &[algorithm(), tlv(48, &[]), date()].concat());
    let bytes = crl(&empty_issuer);
    assert_eq!(
        CertificateList::read(&parser, &bytes, 300)
            .unwrap_err()
            .code(),
        ErrorCode::EmptySequence
    );
    let bad_date = tlv(
        48,
        &[algorithm(), issuer(), tlv(23, b"260230120000Z")].concat(),
    );
    let bytes = crl(&bad_date);
    assert_eq!(
        CertificateList::read(&parser, &bytes, 300)
            .unwrap_err()
            .code(),
        ErrorCode::TimeOutOfRange
    );
    let bad_entry = tlv(48, &[&[2, 1, 1][..], &date(), &[5, 0]].concat());
    let bytes = crl(&tbs(Some(1), &tlv(48, &bad_entry)));
    assert!(CertificateList::read(&parser, &bytes, 300).is_err());
}

#[test]
fn issuing_distribution_point_shares_names_and_preserves_partial_indirect_scope() {
    // Full/relative DP names use the certificate DP grammar. A partial reason
    // mask or indirect flag must not be flattened into complete direct coverage.
    use structured_pkix::crl::{CertificateKind, IssuingDistributionPoint};
    let execution = memory(64 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    for (fields, expected_kind, expected_indirect) in [
        (vec![0x81, 1, 0xff], CertificateKind::EndEntity, false),
        (vec![0x82, 1, 0xff], CertificateKind::Authority, false),
        (vec![0x84, 1, 0xff], CertificateKind::All, true),
        (vec![0x85, 1, 0xff], CertificateKind::Attribute, false),
        (vec![0x83, 2, 1, 2], CertificateKind::All, false),
        (
            tlv(0xa0, &tlv(0xa0, &tlv(0x86, b"https://crl.example/list"))),
            CertificateKind::All,
            false,
        ),
        (
            tlv(0xa0, &tlv(0xa1, &tlv(48, &[6, 3, 0x55, 4, 3, 12, 1, b'A']))),
            CertificateKind::All,
            false,
        ),
    ] {
        let ext = tlv(
            48,
            &[
                &[6, 3, 0x55, 0x1d, 0x1c, 1, 1, 0xff][..],
                &tlv(4, &tlv(48, &fields)),
            ]
            .concat(),
        );
        let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &ext))));
        let parsed = CertificateList::read(&parser, &bytes, 100).unwrap();
        let extension = parsed.tbs().extensions().iter().next().unwrap();
        let scope = IssuingDistributionPoint::read(extension, &execution).unwrap();
        assert_eq!(scope.certificate_kind(), expected_kind);
        assert_eq!(scope.is_indirect(), expected_indirect);
        if fields[0] == 0x83 {
            assert!(scope.reasons().unwrap().bit(6));
        }
        if fields[0] == 0xa0 {
            assert!(!scope.full_name().is_empty() || scope.name_relative_to_issuer().is_some());
        }
    }
    for fields in [
        vec![],
        vec![0x81, 1, 0],
        vec![0x81, 1, 0xff, 0x82, 1, 0xff],
        vec![0x84, 1, 0xff, 0x84, 1, 0xff],
        vec![0x83, 1, 0],
        vec![0x83, 2, 0, 0],
    ] {
        let ext = tlv(
            48,
            &[&[6, 3, 0x55, 0x1d, 0x1c][..], &tlv(4, &tlv(48, &fields))].concat(),
        );
        let bytes = crl(&tbs(Some(1), &tlv(0xa0, &tlv(48, &ext))));
        let parsed = CertificateList::read(&parser, &bytes, 100).unwrap();
        assert!(
            IssuingDistributionPoint::read(
                parsed.tbs().extensions().iter().next().unwrap(),
                &execution
            )
            .is_err()
        );
    }
}

#[test]
fn entry_extensions_distinguish_reason_removal_invalidity_and_issuer_inheritance() {
    // Reason enumeration 8 is removal, not a reason-mask bit; invalidityDate
    // and certificateIssuer retain separate meaning and absence semantics.
    use structured_pkix::crl::Reason;
    let execution = memory(64 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    for (number, expected) in [
        (0, Reason::Unspecified),
        (6, Reason::CertificateHold),
        (8, Reason::RemoveFromCrl),
        (9, Reason::PrivilegeWithdrawn),
        (10, Reason::AttributeAuthorityCompromise),
    ] {
        let ext = tlv(
            48,
            &[&[6, 3, 0x55, 0x1d, 0x15][..], &tlv(4, &tlv(10, &[number]))].concat(),
        );
        let bytes = crl(&tbs(Some(1), &tlv(48, &entry(3, &tlv(48, &ext)))));
        let parsed = CertificateList::read(&parser, &bytes, 100).unwrap();
        let entry = &parsed.tbs().revoked_certificates()[0];
        assert_eq!(entry.reason(&execution).unwrap(), Some(expected));
        assert!(entry.invalidity_date(&execution).unwrap().is_none());
        assert!(entry.certificate_issuer(&execution).unwrap().is_none());
    }
    for value in [
        tlv(10, &[7]),
        tlv(10, &[11]),
        tlv(10, &[0xff]),
        tlv(2, &[6]),
        tlv(10, &[0, 6]),
    ] {
        let ext = tlv(
            48,
            &[&[6, 3, 0x55, 0x1d, 0x15][..], &tlv(4, &value)].concat(),
        );
        let bytes = crl(&tbs(Some(1), &tlv(48, &entry(3, &tlv(48, &ext)))));
        let parsed = CertificateList::read(&parser, &bytes, 100).unwrap();
        assert!(
            parsed.tbs().revoked_certificates()[0]
                .reason(&execution)
                .is_err()
        );
    }
    let invalidity = tlv(
        48,
        &[
            &[6, 3, 0x55, 0x1d, 0x18][..],
            &tlv(4, &tlv(24, b"20261010120000Z")),
        ]
        .concat(),
    );
    let issuer_ext = tlv(
        48,
        &[
            &[6, 3, 0x55, 0x1d, 0x1d, 1, 1, 0xff][..],
            &tlv(4, &tlv(48, &tlv(0xa4, &issuer()))),
        ]
        .concat(),
    );
    let bytes = crl(&tbs(
        Some(1),
        &tlv(48, &entry(3, &tlv(48, &[invalidity, issuer_ext].concat()))),
    ));
    let parsed = CertificateList::read(&parser, &bytes, 100).unwrap();
    let entry = &parsed.tbs().revoked_certificates()[0];
    assert!(entry.invalidity_date(&execution).unwrap().unwrap() < entry.revocation_date());
    assert_eq!(
        entry.certificate_issuer(&execution).unwrap().unwrap().len(),
        1
    );
    assert!(entry.reason(&memory(0, 0)).unwrap_err().is_limit());
}

fn crl_metadata(number: Option<&[u8]>, minimum: Option<&[u8]>, scope: bool) -> Vec<u8> {
    // Delta pairing also needs the profile-required authority key identifier.
    let mut entries = tlv(
        48,
        &[tlv(6, &[0x55, 0x1d, 0x23]), tlv(4, &[48, 3, 0x80, 1, 7])].concat(),
    );
    for (id, critical, value) in [(0x14, false, number), (0x1b, true, minimum)] {
        if let Some(value) = value {
            let mut ext = vec![6, 3, 0x55, 0x1d, id];
            if critical {
                ext.extend([1, 1, 0xff]);
            }
            ext.extend(tlv(4, &tlv(2, value)));
            entries.extend(tlv(48, &ext));
        }
    }
    if scope {
        entries.extend(tlv(
            48,
            &[
                6, 3, 0x55, 0x1d, 0x1c, 1, 1, 0xff, 4, 5, 48, 3, 0x84, 1, 0xff,
            ],
        ));
    }
    tlv(0xa0, &tlv(48, &entries))
}

#[test]
fn authenticated_delta_binding_keeps_sources_and_checks_arbitrary_width_numbers() {
    // Binding cannot mix keys/scopes or reverse base/delta numbering. CRL
    // numbers are not narrowed to u64, and the combined evidence keeps both
    // original signed objects rather than constructing a new signed CRL.
    use structured_pkix::crl::{Authentication, DeltaBinding, DeltaFailure, MissingDeltaField};
    use structured_pkix::path::{Verified, Verify, WorkingKey};
    struct Accept;
    impl Verify for Accept {
        type Error = std::convert::Infallible;
        fn verify(
            &self,
            _: &structured_pkix::AlgorithmIdentifier<'_>,
            _: WorkingKey<'_>,
            _: &[u8],
            _: structured_asn1::BitString<'_>,
            _: &Memory,
        ) -> Result<Verified, Self::Error> {
            Ok(Verified::Yes)
        }
    }
    let execution = memory(64 * 1024, 1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = certificate(false, None, 7);
    let issuer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let key = WorkingKey::standing(issuer.tbs().public_key());
    for (base_number, delta_number, minimum, scope, expected) in [
        (Some(&[5][..]), Some(&[6][..]), Some(&[5][..]), false, None),
        (
            Some(&[5][..]),
            Some(&[5][..]),
            Some(&[4][..]),
            false,
            Some(DeltaFailure::NumberOrder),
        ),
        (
            Some(&[5][..]),
            Some(&[6][..]),
            Some(&[6][..]),
            false,
            Some(DeltaFailure::BaseTooOld),
        ),
        (
            Some(&[5][..]),
            Some(&[6][..]),
            Some(&[4][..]),
            true,
            Some(DeltaFailure::Scope),
        ),
        (
            Some(&[1, 0, 0, 0, 0, 0, 0, 0, 0][..]),
            Some(&[1, 0, 0, 0, 0, 0, 0, 0, 1][..]),
            Some(&[1, 0, 0, 0, 0, 0, 0, 0, 0][..]),
            false,
            None,
        ),
    ] {
        let base_bytes = crl(&tbs(Some(1), &crl_metadata(base_number, None, false)));
        let delta_bytes = crl(&tbs(Some(1), &crl_metadata(delta_number, minimum, scope)));
        let base = CertificateList::read(&parser, &base_bytes, 300).unwrap();
        let delta = CertificateList::read(&parser, &delta_bytes, 600).unwrap();
        let Authentication::Authenticated(base_proof) = base
            .authenticate(&issuer, key, &Accept, &execution)
            .unwrap()
        else {
            panic!()
        };
        let Authentication::Authenticated(delta_proof) = delta
            .authenticate(&issuer, key, &Accept, &execution)
            .unwrap()
        else {
            panic!()
        };
        match (
            base_proof.bind_delta(&delta_proof, &execution).unwrap(),
            expected,
        ) {
            (DeltaBinding::Bound(pair), None) => {
                assert_eq!(pair.base().crl().as_bytes().as_ptr(), base_bytes.as_ptr());
                assert_eq!(pair.delta().crl().as_bytes().as_ptr(), delta_bytes.as_ptr());
            }
            (DeltaBinding::Rejected(actual), Some(expected)) => assert_eq!(actual, expected),
            _ => panic!("wrong delta binding result"),
        }
        assert!(
            base_proof
                .bind_delta(&delta_proof, &memory(0, 0))
                .unwrap_err()
                .is_limit()
        );
    }
    let bytes = crl(&tbs(None, &[]));
    let bare = CertificateList::read(&parser, &bytes, 300).unwrap();
    let Authentication::Authenticated(proof) = bare
        .authenticate(&issuer, key, &Accept, &execution)
        .unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        proof.bind_delta(&proof, &execution).unwrap(),
        DeltaBinding::Missing(MissingDeltaField::Indicator)
    ));
}
