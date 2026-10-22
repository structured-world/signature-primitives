//! Typed AC evidence through the same public CRL processor as PKC targets.
use super::{ac_bytes, accepted, alg, entity, ext, memory, name, pkc, read_ac, read_pkc, seq, tlv};
use structured_asn1::memory::{Memory, Work};
use structured_asn1::{Oid, Parser};
use structured_cms::attribute_certificate::validation::usage::{
    Evidence as _, Status as UseStatus,
};
use structured_pkix::crl::*;
use structured_pkix::path::{Verified, Verify, WorkingKey};
use structured_pkix::temporal::LeapTable;
use structured_pkix::{Certificate, oid};

fn generous() -> Memory {
    memory(1 << 20, 1 << 28)
}
struct FixtureSignature;
impl<W: Work> Verify<W> for FixtureSignature {
    type Error = structured_asn1::memory::MemoryError;
    fn verify(
        &self,
        _: &structured_pkix::AlgorithmIdentifier<'_>,
        _: WorkingKey<'_>,
        data: &[u8],
        sig: structured_pkix::signature::SignatureValue<'_>,
        w: &W,
    ) -> Result<Verified, Self::Error> {
        // Structural wiring oracle only; actual signature arithmetic has separate coverage.
        w.charge_work((data.len() + sig.bit_string().as_bytes().len()) as u64)?;
        Ok(Verified::Yes)
    }
}
fn auth<'r, 'a>(
    list: &'r CertificateList<'a>,
    aa: &'r Certificate<'a>,
    w: &Memory,
) -> Authenticated<'r, 'a> {
    match list
        .authenticate(
            aa,
            WorkingKey::standing(aa.tbs().public_key()),
            &FixtureSignature,
            w,
        )
        .unwrap()
    {
        Authentication::Authenticated(a) => a,
        other => panic!("{other:?}"),
    }
}
fn authority() -> Vec<u8> {
    pkc(
        b"Root",
        b"Authority",
        &[7],
        &[],
        &[ext(oid::KEY_USAGE, &[3, 2, 1, 2], true)],
    )
}
fn list(issuer: &[u8], entries: &[Vec<u8>], extensions: &[Vec<u8>], next: bool) -> Vec<u8> {
    let body = list_body(issuer, entries, extensions, next, &alg());
    seq(&[&body, &alg(), &[3, 2, 0, 9]])
}
fn list_body(
    issuer: &[u8],
    entries: &[Vec<u8>],
    extensions: &[Vec<u8>],
    next: bool,
    algorithm: &[u8],
) -> Vec<u8> {
    seq(&[
        &[2, 1, 1],
        algorithm,
        &name(issuer),
        &tlv(23, b"261021000000Z"),
        &if next {
            tlv(23, b"261022000000Z")
        } else {
            vec![]
        },
        &if entries.is_empty() {
            vec![]
        } else {
            seq(&entries.iter().map(Vec::as_slice).collect::<Vec<_>>())
        },
        &if extensions.is_empty() {
            vec![]
        } else {
            tlv(
                160,
                &seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>()),
            )
        },
    ])
}
fn entry(serial: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
    seq(&[
        &tlv(2, serial),
        &tlv(23, b"261020000000Z"),
        &if extensions.is_empty() {
            vec![]
        } else {
            seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>())
        },
    ])
}
fn idp(body: &[u8]) -> Vec<u8> {
    ext(oid::ISSUING_DISTRIBUTION_POINT, &tlv(48, body), true)
}
fn metadata(number: u8, delta: Option<u8>, scope: Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = vec![
        ext(oid::CRL_NUMBER, &[2, 1, number], false),
        ext(oid::AUTHORITY_KEY_IDENTIFIER, &[48, 3, 128, 1, 7], false),
        scope,
    ];
    if let Some(base) = delta {
        out.push(ext(oid::DELTA_CRL_INDICATOR, &[2, 1, base], true));
    }
    out
}

#[test]
fn ac_category_scope_and_never_revoke_scheme_are_distinct() {
    // RFC5280§5.2.5: attribute-only is not PKC scope; absent category covers both.
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let ac = read_ac(&p, &bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    for (scope, allowed) in [
        (vec![133, 1, 255], true),
        (vec![129, 1, 255], false),
        (vec![130, 1, 255], false),
        (vec![132, 1, 255], true),
    ] {
        let bytes = list(b"Authority", &[], &[idp(&scope)], true);
        let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
        let a = auth(&crl, &aa, &generous());
        assert_eq!(
            matches!(
                a.scope(&profile, &generous()).unwrap(),
                ScopeOutcome::Applicable(_)
            ),
            allowed
        );
        if scope[0] == 133 {
            assert!(matches!(
                a.scope(&aa, &generous()).unwrap(),
                ScopeOutcome::NotApplicable(ScopeFailure::CertificateKind)
            ));
        }
    }
    let no_rev = ac_bytes(
        &entity(130, b"holder.test"),
        &[ext(super::validation::NO_REV_AVAILABLE, &[5, 0], false)],
    );
    let ac = read_ac(&p, &no_rev);
    let profile = accepted(ac.profile(&generous()).unwrap());
    let bytes = list(b"Authority", &[], &[], true);
    let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
    let a = auth(&crl, &aa, &generous());
    assert!(matches!(
        a.scope(&profile, &generous()).unwrap(),
        ScopeOutcome::NotApplicable(ScopeFailure::NoRevAvail)
    ));
}

#[test]
fn ac_complete_facts_preserve_exact_target_scope_time_and_source() {
    // A component absence binds the real checked AC, never a fabricated PKC.
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let ac = read_ac(&p, &bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    let bytes = list(b"Authority", &[], &[idp(&[133, 1, 255])], true);
    let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
    let a = auth(&crl, &aa, &generous());
    let now = crl.tbs().this_update().instant();
    let next = crl.tbs().next_update().unwrap().instant();
    let utc = LeapTable::new(now.seconds() - 10, next.seconds() + 10, &[]).unwrap();
    let w = generous();
    let time = Evaluation {
        now: now.into(),
        utc: &utc,
        execution: &w,
        origin: SourceOrigin::Cached,
    };
    let CompleteEvidence::Facts(facts) = a.evaluate(&profile, &time).unwrap() else {
        panic!("applicable")
    };
    assert!(core::ptr::eq(facts.target(), &raw const profile));
    assert!(core::ptr::eq(facts.source().crl(), &raw const crl));
    let absent = facts.absence().unwrap();
    assert!(core::ptr::eq(absent.target().certificate(), &raw const ac));
    assert_eq!(absent.evaluated_at(), now.into());
    let mut coverage = Coverage::new(absent, &w).unwrap();
    assert!(coverage.reasons().is_complete());
    assert_eq!(
        coverage.add(absent, &w).unwrap(),
        CoverageAdmission::Redundant
    );
    assert_eq!(coverage.sources().len(), 1);
    assert!(core::ptr::eq(coverage.target(), &raw const profile));
    // Shared use consumes already-qualified coverage without rechecking CRLs;
    // neither another AC nor a later evaluation label may borrow this status.
    assert_eq!(
        coverage.check(&profile, time.now, &w).unwrap(),
        UseStatus::Good
    );
    let later = structured_pkix::temporal::Instant::new(now.seconds() + 1, 0)
        .unwrap()
        .into();
    assert_eq!(
        coverage.check(&profile, later, &w).unwrap(),
        UseStatus::Time
    );
    let other_bytes = ac_bytes(&entity(130, b"other.test"), &[]);
    let other_ac = read_ac(&p, &other_bytes);
    let other = accepted(other_ac.profile(&w).unwrap());
    assert_eq!(
        coverage.check(&other, time.now, &w).unwrap(),
        UseStatus::Target
    );
    drop(other);
    let zero = memory(0, 0);
    assert!(
        coverage
            .check(&profile, time.now, &zero)
            .unwrap_err()
            .is_resource()
    );
    assert!(w.used() > 0);
    drop(coverage);
    assert_eq!(w.used(), 0);
}

#[test]
fn ac_entry_lookup_checks_whole_list_and_retains_conflicts() {
    // Unknown critical demands on unrelated entries and duplicate identities remain adverse.
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let ac = read_ac(&p, &bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    for (entries, expected) in [
        (vec![entry(&[5], &[])], 0),
        (vec![entry(&[5], &[]), entry(&[5], &[])], 1),
        (
            vec![
                entry(&[5], &[]),
                entry(&[6], &[ext(Oid::from_bytes(&[42, 9]), &[5, 0], true)]),
            ],
            2,
        ),
        (vec![entry(&[6], &[])], 3),
    ] {
        let bytes = list(b"Authority", &entries, &[idp(&[133, 1, 255])], true);
        let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
        let a = auth(&crl, &aa, &generous());
        let found = a.entry(&profile, &generous()).unwrap();
        assert!(match expected {
            0 => matches!(found, EntryLookup::Found(_)),
            1 => matches!(found, EntryLookup::Conflict { .. }),
            2 => matches!(found, EntryLookup::Unsupported { .. }),
            _ => matches!(found, EntryLookup::Absent),
        });
    }
}

#[test]
fn ac_bound_delta_removal_uses_original_pair_without_reconstruction() {
    // A valid updating delta may remove an entry; standalone delta cannot mint absence.
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let ac = read_ac(&p, &bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    let base_bytes = list(
        b"Authority",
        &[entry(&[5], &[])],
        &metadata(7, None, idp(&[133, 1, 255])),
        true,
    );
    let delta_bytes = list(
        b"Authority",
        &[entry(&[5], &[ext(oid::CRL_REASON, &[10, 1, 8], false)])],
        &metadata(8, Some(7), idp(&[133, 1, 255])),
        true,
    );
    let base = CertificateList::read(&p, &base_bytes, 4000).unwrap();
    let delta = CertificateList::read(&p, &delta_bytes, 8000).unwrap();
    let base = auth(&base, &aa, &generous());
    let delta = auth(&delta, &aa, &generous());
    let w = generous();
    let DeltaBinding::Bound(pair) = base.bind_delta(&delta, &w).unwrap() else {
        panic!("bound")
    };
    assert!(matches!(
        pair.entry(&profile, &w).unwrap(),
        CombinedEntry::Removed { .. }
    ));
    let now = base.crl().tbs().this_update().instant();
    let utc = LeapTable::new(now.seconds() - 10, now.seconds() + 90000, &[]).unwrap();
    let time = Evaluation {
        now: now.into(),
        utc: &utc,
        execution: &w,
        origin: SourceOrigin::Cached,
    };
    assert!(matches!(
        delta.evaluate(&profile, &time).unwrap(),
        CompleteEvidence::DeltaNeedsBase
    ));
    let DeltaEvidence::Facts(facts) = pair.evaluate(&profile, &time).unwrap() else {
        panic!("scope")
    };
    assert!(core::ptr::eq(facts.target(), &raw const profile));
    assert!(facts.absence().is_some());
    assert!(matches!(
        facts.absence().unwrap().source(),
        EvidenceSource::Delta { .. }
    ));
}

#[test]
fn native_ed25519_crl_signature_authenticates_before_ac_evidence() {
    use ed25519_dalek::Signer;
    // Reuse the independent native signature adapter; altered signed entries refuse.
    let signing = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
    let ed = seq(&[&tlv(6, oid::ED25519.as_bytes())]);
    let key = seq(&[
        &ed,
        &tlv(3, &[&[0][..], signing.verifying_key().as_bytes()].concat()),
    ]);
    let aa_tbs = seq(&[
        &[160, 3, 2, 1, 2],
        &[2, 1, 7],
        &ed,
        &name(b"Root"),
        &super::validity(),
        &name(b"Authority"),
        &key,
        &tlv(163, &seq(&[&ext(oid::KEY_USAGE, &[3, 2, 1, 2], true)])),
    ]);
    let aa_bytes = seq(&[&aa_tbs, &ed, &[3, 2, 0, 9]]);
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &aa_bytes);
    let target_bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let ac = read_ac(&p, &target_bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    let body = list_body(b"Authority", &[], &[idp(&[133, 1, 255])], true, &ed);
    let signature = signing.sign(&body).to_bytes();
    let bytes = seq(&[&body, &ed, &tlv(3, &[&[0][..], &signature].concat())]);
    let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
    let verifier = super::authentication::native_signature_verifier();
    let Authentication::Authenticated(proof) = crl
        .authenticate(
            &aa,
            WorkingKey::standing(aa.tbs().public_key()),
            &verifier,
            &generous(),
        )
        .unwrap()
    else {
        panic!("native signature")
    };
    assert!(matches!(
        proof.entry(&profile, &generous()).unwrap(),
        EntryLookup::Absent
    ));
    let changed = list_body(
        b"Authority",
        &[entry(&[5], &[])],
        &[idp(&[133, 1, 255])],
        true,
        &ed,
    );
    let bytes = seq(&[&changed, &ed, &tlv(3, &[&[0][..], &signature].concat())]);
    let crl = CertificateList::read(&p, &bytes, 8000).unwrap();
    assert!(matches!(
        crl.authenticate(
            &aa,
            WorkingKey::standing(aa.tbs().public_key()),
            &verifier,
            &generous()
        )
        .unwrap(),
        Authentication::Rejected(AuthenticationFailure::Signature)
    ));
}

#[test]
fn ac_indirect_issuer_inheritance_and_serial_width_remain_exact() {
    // Issuer identity is a stream state, not serial-only matching or per-entry reset.
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let ac = read_ac(&p, &bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    let issuer = ext(
        oid::CERTIFICATE_ISSUER,
        &seq(&[&super::directory(b"Other")]),
        true,
    );
    let entries = vec![entry(&[4], &[issuer]), entry(&[5], &[])];
    let bytes = list(
        b"Authority",
        &entries,
        &[idp(&[132, 1, 255, 133, 1, 255])],
        true,
    );
    let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
    let proof = auth(&crl, &aa, &generous());
    assert!(matches!(
        proof.entry(&profile, &generous()).unwrap(),
        EntryLookup::Absent
    ));
    let issuer = ext(
        oid::CERTIFICATE_ISSUER,
        &seq(&[&super::directory(b"Authority")]),
        true,
    );
    let entries = vec![entry(&[4], &[issuer]), entry(&[5], &[])];
    let bytes = list(
        b"Authority",
        &entries,
        &[idp(&[132, 1, 255, 133, 1, 255])],
        true,
    );
    let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
    assert!(matches!(
        auth(&crl, &aa, &generous())
            .entry(&profile, &generous())
            .unwrap(),
        EntryLookup::Found(_)
    ));
    let wide = super::ac_fields(
        &entity(130, b"holder.test"),
        &super::issuer(b"Authority"),
        &[1; 20],
        &super::validity(),
        &[],
    );
    let ac = read_ac(&p, &wide);
    let profile = accepted(ac.profile(&generous()).unwrap());
    let bytes = list(
        b"Authority",
        &[entry(&[1; 19], &[]), entry(&[1; 20], &[])],
        &[idp(&[133, 1, 255])],
        true,
    );
    let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
    let EntryLookup::Found(found) = auth(&crl, &aa, &generous())
        .entry(&profile, &generous())
        .unwrap()
    else {
        panic!("wide identity")
    };
    assert_eq!(found.serial().as_bytes(), &[1; 20]);
}

#[test]
fn ac_freshness_never_converts_stale_missing_or_unknown_time_to_absence() {
    // Same original target, several source windows and acquisition endpoint facts.
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let ac = read_ac(&p, &bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    for next in [true, false] {
        let bytes = list(b"Authority", &[], &[idp(&[133, 1, 255])], next);
        let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
        let proof = auth(&crl, &aa, &generous());
        let this = crl.tbs().this_update().instant();
        let endpoint = structured_pkix::temporal::Instant::new(this.seconds() + 86400, 0).unwrap();
        let utc = LeapTable::new(this.seconds() - 10, endpoint.seconds() + 10, &[]).unwrap();
        let unknown = LeapTable::new(this.seconds() + 1, endpoint.seconds() + 10, &[]).unwrap();
        for (now, table, origin, expected) in [
            (this, &utc, SourceOrigin::Cached, next),
            (endpoint, &utc, SourceOrigin::Cached, next),
            (endpoint, &utc, SourceOrigin::Replacement, false),
            (this, &unknown, SourceOrigin::Cached, false),
        ] {
            let w = generous();
            let time = Evaluation {
                now: now.into(),
                utc: table,
                execution: &w,
                origin,
            };
            let CompleteEvidence::Facts(facts) = proof.evaluate(&profile, &time).unwrap() else {
                panic!("facts")
            };
            assert_eq!(facts.absence().is_some(), expected);
            assert!(core::ptr::eq(facts.target(), &raw const profile));
        }
    }
}

#[test]
fn ac_reason_coverage_unions_only_same_target_time_and_execution() {
    // Two complementary reason partitions require two retained authenticated contributors.
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let ac = read_ac(&p, &bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    let first_bytes = list(
        b"Authority",
        &[],
        &[idp(&[131, 2, 0, 127, 133, 1, 255])],
        true,
    );
    let second_bytes = list(
        b"Authority",
        &[],
        &[idp(&[131, 3, 7, 0, 128, 133, 1, 255])],
        true,
    );
    let first = CertificateList::read(&p, &first_bytes, 4000).unwrap();
    let second = CertificateList::read(&p, &second_bytes, 8000).unwrap();
    let first = auth(&first, &aa, &generous());
    let second = auth(&second, &aa, &generous());
    let now = first.crl().tbs().this_update().instant();
    let utc = LeapTable::new(now.seconds() - 10, now.seconds() + 90000, &[]).unwrap();
    let w = generous();
    let time = Evaluation {
        now: now.into(),
        utc: &utc,
        execution: &w,
        origin: SourceOrigin::Cached,
    };
    let CompleteEvidence::Facts(a) = first.evaluate(&profile, &time).unwrap() else {
        panic!("first")
    };
    let CompleteEvidence::Facts(b) = second.evaluate(&profile, &time).unwrap() else {
        panic!("second")
    };
    let a = a.absence().unwrap();
    let b = b.absence().unwrap();
    let other_bytes = super::ac_fields(
        &entity(130, b"holder.test"),
        &super::issuer(b"Authority"),
        &[6],
        &super::validity(),
        &[],
    );
    let other_ac = read_ac(&p, &other_bytes);
    let other_profile = accepted(other_ac.profile(&generous()).unwrap());
    let mut coverage = Coverage::new(a, &w).unwrap();
    assert!(!coverage.reasons().is_complete());
    assert_eq!(
        coverage.check(&profile, time.now, &w).unwrap(),
        UseStatus::Reasons
    );
    assert_eq!(
        coverage.add(b, &generous()).unwrap(),
        CoverageAdmission::DifferentExecution
    );
    assert_eq!(coverage.add(b, &w).unwrap(), CoverageAdmission::Added);
    assert!(coverage.reasons().is_complete());
    assert_eq!(
        coverage.check(&profile, time.now, &w).unwrap(),
        UseStatus::Good
    );
    assert_eq!(coverage.sources().len(), 2);
    let original = coverage.reasons();
    let CompleteEvidence::Facts(other) = first.evaluate(&other_profile, &time).unwrap() else {
        panic!("other")
    };
    assert_eq!(
        coverage.add(other.absence().unwrap(), &w).unwrap(),
        CoverageAdmission::DifferentTarget
    );
    assert_eq!(coverage.reasons(), original);
    let later = Evaluation {
        now: structured_pkix::temporal::Instant::new(now.seconds() + 1, 0)
            .unwrap()
            .into(),
        utc: &utc,
        execution: &w,
        origin: SourceOrigin::Cached,
    };
    let CompleteEvidence::Facts(later) = first.evaluate(&profile, &later).unwrap() else {
        panic!("later")
    };
    assert_eq!(
        coverage.add(later.absence().unwrap(), &w).unwrap(),
        CoverageAdmission::DifferentTime
    );
    drop(coverage);
    assert_eq!(w.used(), 0);
}

#[test]
fn ac_distribution_name_mismatch_is_not_discarded_by_issuer_fallback() {
    // RFC5280§5.2.5 explicit DP identity remains exact; issuer fallback cannot bypass it.
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let point = tlv(160, &tlv(160, &tlv(134, b"http://example.test/crl")));
    let bytes = ac_bytes(
        &entity(130, b"holder.test"),
        &[ext(
            oid::CRL_DISTRIBUTION_POINTS,
            &seq(&[&seq(&[&point])]),
            false,
        )],
    );
    let ac = read_ac(&p, &bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    for (uri, matched) in [
        (b"http://example.test/crl".as_slice(), true),
        (b"http://EXAMPLE.test/crl".as_slice(), false),
    ] {
        let scope = [tlv(160, &tlv(160, &tlv(134, uri))), vec![133, 1, 255]].concat();
        let bytes = list(b"Authority", &[], &[idp(&scope)], true);
        let crl = CertificateList::read(&p, &bytes, 4000).unwrap();
        let proof = auth(&crl, &aa, &generous());
        assert_eq!(
            matches!(
                proof.scope(&profile, &generous()).unwrap(),
                ScopeOutcome::Applicable(_)
            ),
            matched
        );
    }
}

#[test]
fn ac_current_and_original_source_refusal_are_terminal_and_rollback_storage() {
    // A fresh account cannot reset the producing AC limit; zero query work/storage refuses.
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let source = generous();
    let measured = Parser::der(source.clone());
    let ac = read_ac(&measured, &bytes);
    let _ = accepted(ac.profile(&source).unwrap());
    let cost = source.work_used();
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: cost as u64,
            ..structured_asn1::Limits::default()
        },
        generous(),
    );
    let ac = read_ac(&parser, &bytes);
    let profile = accepted(ac.profile(parser.memory()).unwrap());
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let list_bytes = list(b"Authority", &[], &[idp(&[133, 1, 255])], true);
    let crl = CertificateList::read(&p, &list_bytes, 4000).unwrap();
    let proof = auth(&crl, &aa, &generous());
    let query = generous();
    assert!(proof.scope(&profile, &query).unwrap_err().is_resource());
    assert_eq!(query.used(), 0);
    let p = Parser::der(generous());
    let ac = read_ac(&p, &bytes);
    let profile = accepted(ac.profile(&generous()).unwrap());
    let query = memory(1 << 20, 0);
    assert!(proof.entry(&profile, &query).unwrap_err().is_resource());
    assert_eq!(query.used(), 0);
    let now = crl.tbs().this_update().instant();
    let utc = LeapTable::new(now.seconds() - 10, now.seconds() + 90000, &[]).unwrap();
    let w = generous();
    let time = Evaluation {
        now: now.into(),
        utc: &utc,
        execution: &w,
        origin: SourceOrigin::Cached,
    };
    let CompleteEvidence::Facts(facts) = proof.evaluate(&profile, &time).unwrap() else {
        panic!("facts")
    };
    let absence = facts.absence().unwrap();
    let zero = memory(0, 1 << 20);
    assert!(Coverage::new(absence, &zero).unwrap_err().is_resource());
    assert_eq!(zero.used(), 0);
    let coverage = {
        let query_parser = Parser::der(w.clone());
        let query = query_parser.read(&[], 9000).unwrap();
        Coverage::new(absence, &query.execution()).unwrap()
    };
    assert!(w.used() > 0);
    assert!(core::ptr::eq(coverage.target(), &raw const profile));
    drop(coverage);
    assert_eq!(w.used(), 0);
}

#[test]
fn ac_issuer_comparison_keeps_original_target_ceiling_after_metadata() {
    // The one target metadata step is not credit for the following Name
    // comparison. Scope and entry must both refuse before scanning its bytes.
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let source = generous();
    let measured = Parser::der(source.clone());
    let ac = read_ac(&measured, &bytes);
    let _ = accepted(ac.profile(&source).unwrap());
    let cost = source.work_used();
    let p = Parser::der(generous());
    let aa_bytes = authority();
    let aa = read_pkc(&p, &aa_bytes);
    let list_bytes = list(b"Authority", &[entry(&[7], &[])], &[], true);
    let crl = CertificateList::read(&p, &list_bytes, 4000).unwrap();
    let proof = auth(&crl, &aa, &generous());
    for entry_query in [false, true] {
        let parser = Parser::new(
            structured_asn1::Encoding::Der,
            structured_asn1::Limits {
                max_work: cost as u64 + 1,
                ..structured_asn1::Limits::default()
            },
            generous(),
        );
        let ac = read_ac(&parser, &bytes);
        let profile = accepted(ac.profile(parser.memory()).unwrap());
        let query = generous();
        let outcome = if entry_query {
            proof.entry(&profile, &query).map(|_| ())
        } else {
            proof.scope(&profile, &query).map(|_| ())
        };
        assert!(outcome.unwrap_err().is_resource());
        assert_eq!(query.used(), 0);
    }
}
