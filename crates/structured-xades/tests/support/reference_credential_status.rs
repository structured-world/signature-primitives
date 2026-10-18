//! Actual credential status sets, ordinary alternatives and delta contributors.

use super::*;

#[derive(Clone, Copy)]
enum Case {
    Attribute,
    Ordinary,
    Redundant,
    Missing,
    Absent,
    Delta(u8),
}

fn add_refs(xml: &mut Tree, role: &str, bytes: &[&[u8]]) {
    let property = add(
        xml,
        7,
        XADES,
        if role == "attribute" {
            "AttributeRevocationRefs"
        } else {
            "CompleteRevocationRefs"
        },
    );
    let list = add(xml, property, XADES, "CRLRefs");
    for bytes in bytes {
        let entry = add(xml, list, XADES, "CRLRef");
        let digest = add(xml, entry, XADES, "DigestAlgAndValue");
        let method = add(xml, digest, DS, "DigestMethod");
        xml.digest_algorithms.push((method, SHA256));
        let value = add(xml, digest, DS, "DigestValue");
        xml.binary_routes
            .push((value, Sha256::digest(bytes).to_vec()));
    }
}

fn references(xml: &mut Tree, case: Case, complete: &[u8], pair: &(Vec<u8>, Vec<u8>)) {
    let (base, delta) = super::super::super::super::timestamp_oracle::crl_pair();
    let mut ordinary = vec![base.as_slice(), delta.as_slice()];
    if matches!(case, Case::Ordinary | Case::Redundant) {
        ordinary.push(complete);
    }
    add_refs(xml, "ordinary", &ordinary);
    if matches!(case, Case::Absent) {
        return;
    }
    let mut attribute = Vec::new();
    match case {
        Case::Attribute | Case::Redundant => attribute.push(complete),
        Case::Delta(mask) => {
            if mask & 1 != 0 {
                attribute.push(pair.0.as_slice());
            }
            if mask & 2 != 0 {
                attribute.push(pair.1.as_slice());
            }
        }
        _ => (),
    }
    // A syntactically nonempty but unrelated reference cannot satisfy the set.
    if attribute.is_empty() {
        attribute.push(base.as_slice());
    }
    add_refs(xml, "attribute", &attribute);
}

fn with_delta_status(
    path: &pki::CheckedPath<'_>,
    pair: &(Vec<u8>, Vec<u8>),
    memory: &Memory,
    check: impl FnOnce(&pki::PathStatuses<'_, '_, '_>),
) {
    use structured_pkix::{
        crl,
        temporal::{Instant, LeapTable},
    };
    let parser = Parser::der(memory.clone());
    let base = crl::CertificateList::read(&parser, &pair.0, 5000).unwrap();
    let delta = crl::CertificateList::read(&parser, &pair.1, 6000).unwrap();
    let issuer = path.anchor().certificate().unwrap();
    let key = WorkingKey::standing(issuer.tbs().public_key());
    let verifier = super::super::super::super::timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let crl::Authentication::Authenticated(base) =
        base.authenticate(issuer, key, &verifier, memory).unwrap()
    else {
        panic!("actual complete signature")
    };
    let crl::Authentication::Authenticated(delta) =
        delta.authenticate(issuer, key, &verifier, memory).unwrap()
    else {
        panic!("actual delta signature")
    };
    let crl::DeltaBinding::Bound(pair) = base.bind_delta(&delta, memory).unwrap() else {
        panic!("same real issuer/scope")
    };
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let evaluation = crl::Evaluation {
        now: Instant::new(1_767_225_600, 0).unwrap().into(),
        utc: &utc,
        execution: memory,
        origin: crl::SourceOrigin::Cached,
    };
    let crl::DeltaEvidence::Facts(facts) = pair
        .evaluate(path.members()[0].certificate(), &evaluation)
        .unwrap()
    else {
        panic!("applicable original pair")
    };
    let coverage = crl::Coverage::new(facts.absence().unwrap(), memory).unwrap();
    let authorities = [pki::CrlAuthorities::Delta {
        base: pki::CrlAuthority::Anchor,
        delta: pki::CrlAuthority::Anchor,
    }];
    let pki::CrlCoverageBinding::Bound(bound) = path
        .bind_crl_coverage(0, &coverage, &authorities, &utc, memory)
        .unwrap()
    else {
        panic!("actual target binding")
    };
    let entries = [pki::MemberStatus::Crl(&bound)];
    let statuses = path
        .status_census(evaluation.now, &entries, memory)
        .unwrap();
    check(&statuses);
    assert_eq!(verifier.calls.get(), 2);
}

fn with_artifacts(
    xml: &Tree,
    participants: &pki::ParticipantRequirements<'_, '_, usize, u8, u8>,
    statuses: [&pki::PathStatuses<'_, '_, '_>; 2],
    ca: &pki::CheckedPath<'_>,
    storage: &Memory,
    check: impl FnOnce(&structured_ltv::material::ArtifactUses<'_, '_, '_, '_, '_, usize, u8, u8>),
) {
    let [ordinary, credential] = statuses;
    let access = Access::new(xml, xml.snapshot(), storage);
    let roots: Vec<_> = participants
        .entries()
        .iter()
        .filter_map(|entry| match entry.authority() {
            pki::ParticipantAuthority::Path(path) => Some(if core::ptr::eq(path, ca) {
                credential
            } else {
                ordinary
            }),
            _ => None,
        })
        .collect();
    let nodes = [
        pki::AuthorityNode {
            statuses: ordinary,
            responders: &[],
        },
        pki::AuthorityNode {
            statuses: credential,
            responders: &[],
        },
    ];
    let closed = participants
        .close_statuses(&roots, &nodes, &access)
        .unwrap();
    let uses = pki::authority_uses(&closed, &access).unwrap();
    let artifacts = structured_ltv::material::artifact_uses(&uses, &access).unwrap();
    check(&artifacts);
}

#[test]
fn credential_status_references_use_actual_sources_and_ordinary_alternatives() {
    // Complete/delta status facts come from real signatures and target binding.
    // Ordinary alternatives satisfy presence without erasing separate exclusive
    // CA prohibitions; SHOULD NOT redundancy remains an advisory fact.
    for case in [
        Case::Attribute,
        Case::Ordinary,
        Case::Redundant,
        Case::Missing,
        Case::Absent,
        Case::Delta(0),
        Case::Delta(1),
        Case::Delta(2),
        Case::Delta(3),
    ] {
        with_checked_path(|signer, leaf, root, storage| {
            with_ca_path(root, storage, |ca| {
                let complete =
                    super::super::super::super::timestamp_oracle::complete_crl_number(2, 3);
                let pair = super::super::super::super::timestamp_oracle::crl_pair_number(2, 4);
                let (mut xml, _, _, _, archive) =
                    super::super::super::participant_tree(leaf, storage);
                xml.nodes[archive].parent = None;
                references(&mut xml, case, &complete, &pair);
                let access = Access::new(&xml, xml.snapshot(), storage);
                let prepared =
                    prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
                with_participants(&xml, &prepared, signer, ca, storage, |participants| {
                    super::super::super::with_original_delta_statuses(
                        signer,
                        storage,
                        |ordinary| {
                            let check = |credential: &pki::PathStatuses<'_, '_, '_>| {
                                with_artifacts(
                                    &xml,
                                    participants,
                                    [ordinary, credential],
                                    ca,
                                    storage,
                                    |artifacts| {
                                        check_report(&xml, &prepared, artifacts, storage, case);
                                    },
                                );
                            };
                            if matches!(case, Case::Delta(_)) {
                                with_delta_status(ca, &pair, storage, check);
                            } else {
                                with_complete_status(ca, &complete, storage, check);
                            }
                        },
                    );
                });
            });
        });
    }
}

fn check_report(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    artifacts: &structured_ltv::material::ArtifactUses<'_, '_, '_, '_, '_, usize, u8, u8>,
    storage: &Memory,
    case: Case,
) {
    let parser = Parser::der(storage.clone());
    let operation = parser.read(&[], 900).unwrap();
    material::with_values(xml, prepared, &operation, |_, view| {
        assert_status_role_refusals(xml, prepared, artifacts, &view, storage);
        let held = storage.used();
        let paid = storage.work_used();
        let query = funded();
        let provider = Oracle::new(Mode::Ready);
        let report = validation::check_revocation_reference_roles(
            xml, prepared, artifacts, &view, None, &provider, &query,
        )
        .unwrap();
        assert!(report.all_root_sources_referenced());
        let expected = !matches!(case, Case::Missing | Case::Delta(0..=2));
        assert_eq!(report.all_credential_sources_referenced(), expected);
        if matches!(case, Case::Absent) {
            assert!(report.credential_sources().is_empty());
        } else {
            assert_eq!(
                report.credential_sources().len(),
                if matches!(case, Case::Delta(_)) { 2 } else { 1 }
            );
            for source in report.credential_sources() {
                assert!(matches!(
                    artifacts.inputs().requirements().entries()[source.participant()].participant(),
                    pki::Participant::Credential { .. }
                ));
                assert_eq!(source.source().member(), 0);
                assert_eq!(
                    source.redundant_attribute_reference(),
                    matches!(case, Case::Redundant)
                );
                if matches!(case, Case::Ordinary) {
                    assert_eq!(source.presence(), (true, false));
                }
            }
        }
        for (ordinal, row) in report.rows().iter().enumerate() {
            assert_eq!(row.search(), validation::ReferenceSearch::Compared);
            if row.role() == unsigned::Role::AttributeRevocationReferences {
                assert!(report.comparisons(ordinal).unwrap().is_empty());
                assert!(report.root_comparisons(ordinal).unwrap().is_empty());
            }
        }
        if matches!(case, Case::Ordinary | Case::Redundant) {
            assert!(report.rows().iter().enumerate().any(|(row, _)| {
                report.comparisons(row).unwrap().iter().any(|comparison| {
                    comparison.agreement()
                        == validation::StatusRoleAgreement::Compared(Agreement::Matches)
                        && comparison.kind() == material::ExclusiveFindingKind::ForbiddenCa
                })
            }));
        }
        let hashes = match case {
            Case::Delta(_) => 4,
            _ => 3,
        };
        assert_eq!(
            (provider.started.get(), provider.finished.get()),
            (hashes, hashes)
        );
        drop(report);
        assert_eq!(query.used(), 0);
        assert_eq!(storage.used(), held);
        assert_eq!(storage.work_used(), paid);
        Ok::<_, ()>(())
    })
    .unwrap();
}
