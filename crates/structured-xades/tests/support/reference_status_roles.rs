//! Actual CA target/status graph, with metadata-only credential-format receipts.

#[path = "reference_credential_status.rs"]
mod credential_status;

use super::*;
use structured_asn1::{Parser, memory::Memory};
use structured_ltv::pki;
use structured_pkix::path::{Anchor, Interval, ValidationBounds, ValidationContext, WorkingKey};
use structured_xades::{certificate, credential, timestamp, validation};

fn with_ca_path(root_bytes: &[u8], memory: &Memory, check: impl FnOnce(&pki::CheckedPath<'_>)) {
    // A real signed CA certificate is the credential authority, not the
    // ordinary root signature's EE. The source/key remains independent.
    let ca_bytes = super::super::super::timestamp_oracle::crl_authority_certificate(2);
    let parser = Parser::der(memory.clone());
    let root = structured_pkix::Certificate::read(&parser, root_bytes, 4400).unwrap();
    let ca = structured_pkix::Certificate::read(&parser, &ca_bytes, 5400).unwrap();
    let verifier = super::super::super::timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let context = ValidationContext {
        execution: memory,
        interval: Interval::at(1_767_225_600),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let pki::PathOutcome::Accepted(path) =
        pki::check_path(&[&ca], Anchor::from_certificate(&root), &context).unwrap()
    else {
        panic!("actual credential CA path")
    };
    assert!(
        path.members()[0]
            .certificate()
            .tbs()
            .extensions()
            .basic_constraints(memory)
            .unwrap()
            .unwrap()
            .is_authority()
    );
    check(&path);
    assert_eq!(verifier.calls.get(), 1);
}

fn with_complete_status(
    path: &pki::CheckedPath<'_>,
    bytes: &[u8],
    memory: &Memory,
    check: impl FnOnce(&pki::PathStatuses<'_, '_, '_>),
) {
    // Shared signature/applicability/coverage kernels build the actual source
    // receipt. No caller-written Good flag is used by the role classifier.
    use structured_pkix::{
        crl,
        temporal::{Instant, LeapTable},
    };
    let parser = Parser::der(memory.clone());
    let crl = crl::CertificateList::read(&parser, bytes, 6400).unwrap();
    let issuer = path.anchor().certificate().unwrap();
    let verifier = super::super::super::timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let crl::Authentication::Authenticated(authenticated) = crl
        .authenticate(
            issuer,
            WorkingKey::standing(issuer.tbs().public_key()),
            &verifier,
            memory,
        )
        .unwrap()
    else {
        panic!("actual complete CRL")
    };
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let evaluation = crl::Evaluation {
        now: Instant::new(1_767_225_600, 0).unwrap().into(),
        utc: &utc,
        execution: memory,
        origin: crl::SourceOrigin::Cached,
    };
    let crl::CompleteEvidence::Facts(facts) = authenticated
        .evaluate(path.members()[0].certificate(), &evaluation)
        .unwrap()
    else {
        panic!("applicable original status")
    };
    let coverage = crl::Coverage::new(facts.absence().unwrap(), memory).unwrap();
    let authorities = [pki::CrlAuthorities::Complete(pki::CrlAuthority::Anchor)];
    let pki::CrlCoverageBinding::Bound(bound) = path
        .bind_crl_coverage(0, &coverage, &authorities, &utc, memory)
        .unwrap()
    else {
        panic!("same actual issuer/target authority")
    };
    let entries = [pki::MemberStatus::Crl(&bound)];
    let statuses = path
        .status_census(evaluation.now, &entries, memory)
        .unwrap();
    check(&statuses);
    assert_eq!(verifier.calls.get(), 1);
}

fn add_crl_refs(xml: &mut Tree, bytes: &[u8]) -> usize {
    let refs = add(xml, 7, XADES, "CompleteRevocationRefs");
    let list = add(xml, refs, XADES, "CRLRefs");
    let references = list;
    for _ in 0..2 {
        let reference = add(xml, list, XADES, "CRLRef");
        let digest = add(xml, reference, XADES, "DigestAlgAndValue");
        let method = add(xml, digest, DS, "DigestMethod");
        xml.digest_algorithms.push((method, SHA256));
        let value = add(xml, digest, DS, "DigestValue");
        xml.binary_routes
            .push((value, Sha256::digest(bytes).to_vec()));
    }
    let values = add(xml, 7, XADES, "RevocationValues");
    let list = add(xml, values, XADES, "CRLValues");
    let value = add(xml, list, XADES, "EncapsulatedCRLValue");
    xml.binary_routes.push((value, bytes.to_vec()));
    references
}

fn add_root_crl_refs(xml: &mut Tree, list: usize, mask: u8) {
    let (base, delta) = super::super::super::timestamp_oracle::crl_pair();
    for (bit, bytes) in [(1, base), (2, delta)] {
        if mask & bit == 0 {
            continue;
        }
        let reference = add(xml, list, XADES, "CRLRef");
        let digest = add(xml, reference, XADES, "DigestAlgAndValue");
        let method = add(xml, digest, DS, "DigestMethod");
        xml.digest_algorithms.push((method, SHA256));
        let value = add(xml, digest, DS, "DigestValue");
        xml.binary_routes
            .push((value, Sha256::digest(&bytes).to_vec()));
    }
}

fn with_ocsp_status(
    path: &pki::CheckedPath<'_>,
    bytes: &[u8],
    memory: &Memory,
    check: impl FnOnce(&pki::PathStatuses<'_, '_, '_>),
) {
    use structured_pkix::{
        ocsp,
        temporal::{Instant, LeapTable},
    };
    let parser = Parser::der(memory.clone());
    let ocsp::Response::Successful(response) = ocsp::Response::read(&parser, bytes, 6400).unwrap()
    else {
        panic!("whole successful OCSP envelope")
    };
    let query = parser.read(&[], 900).unwrap();
    let basic = response.basic_in(&query).unwrap().unwrap();
    let issuer = path.anchor().certificate().unwrap();
    let key = WorkingKey::standing(issuer.tbs().public_key());
    let verifier = super::super::super::timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let ocsp::SignatureAuthentication::Signed(signed) = basic
        .authenticate_signature(issuer, key, &verifier, &verifier, memory)
        .unwrap()
    else {
        panic!("real OCSP signature")
    };
    let ocsp::AuthorityBinding::Bound(scoped) = signed.bind_issuer(issuer, key, memory).unwrap()
    else {
        panic!("actual target issuing key")
    };
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let evaluation = ocsp::Evaluation {
        now: Instant::new(1_767_225_600, 0).unwrap().into(),
        utc: &utc,
        execution: memory,
    };
    let request = ocsp::Request {
        target: path.members()[0].certificate(),
        nonce: None,
        intended_signer: None,
    };
    let reading = scoped
        .evaluate_with_target(&request, &evaluation, &verifier)
        .unwrap();
    let evidence = reading.evidence().unwrap();
    let pki::OcspBinding::Bound(bound) = path.bind_ocsp(0, &evidence, memory).unwrap() else {
        panic!("actual CA member status")
    };
    let entries = [pki::MemberStatus::Ocsp(&bound)];
    let statuses = path
        .status_census(evaluation.now, &entries, memory)
        .unwrap();
    check(&statuses);
    assert_eq!(verifier.calls.get(), 1);
}

fn add_ocsp_refs(xml: &mut Tree, bytes: &[u8], include_envelope: bool) -> usize {
    use structured_xades::properties::{CalendarFact, CalendarValue};
    let refs = add(xml, 7, XADES, "CompleteRevocationRefs");
    let list = add(xml, refs, XADES, "OCSPRefs");
    for _ in 0..2 {
        let reference = add(xml, list, XADES, "OCSPRef");
        let id = add(xml, reference, XADES, "OCSPIdentifier");
        let responder = add(xml, id, XADES, "ResponderID");
        let key = add(xml, responder, XADES, "ByKey");
        let mut value = vec![0xa2, 22, 4, 20];
        value.extend([0x33; 20]);
        xml.binary_routes.push((key, value));
        let time = add(xml, id, XADES, "ProducedAt");
        xml.calendar_routes.push((
            time,
            CalendarFact::Value(CalendarValue {
                negative_year: false,
                year_digits: "2026",
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                fraction_digits: None,
                timezone_minutes: Some(0),
            }),
        ));
        let digest = add(xml, reference, XADES, "DigestAlgAndValue");
        let method = add(xml, digest, DS, "DigestMethod");
        xml.digest_algorithms.push((method, SHA256));
        let value = add(xml, digest, DS, "DigestValue");
        xml.binary_routes
            .push((value, Sha256::digest(bytes).to_vec()));
    }
    if include_envelope {
        let values = add(xml, 7, XADES, "RevocationValues");
        let list = add(xml, values, XADES, "OCSPValues");
        let value = add(xml, list, XADES, "EncapsulatedOCSPValue");
        xml.binary_routes.push((value, bytes.to_vec()));
    }
    refs
}

fn with_participants<'d>(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    signer_path: &pki::CheckedPath<'d>,
    ca_path: &pki::CheckedPath<'d>,
    memory: &Memory,
    check: impl FnOnce(&pki::ParticipantRequirements<'_, 'd, usize, u8, u8>),
) {
    let access = Access::new(xml, xml.snapshot(), memory);
    let signer = certificate::check_path(
        xml,
        prepared.bound(),
        prepared.certificates(),
        signer_path,
        &Oracle::new(Mode::Ready),
        memory,
    )
    .unwrap();
    let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
        Ok::<_, ()>(signer_path)
    })
    .unwrap();
    let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
    let required = timestamp::requirements_with_counters(
        &access,
        prepared,
        &stamps,
        timestamp::TimestampSelection::All,
    )
    .unwrap();
    let structured_ltv::timestamp::TimestampPathBinding::Bound(prior) =
        required.bind_paths(&[], &access).unwrap()
    else {
        panic!("complete zero-token scope")
    };
    let anchor = ca_path.anchor();
    let effective = structured_pkix::path::EffectiveAnchor::bind(
        anchor,
        WorkingKey::standing(anchor.key()),
        memory,
    )
    .unwrap()
    .unwrap();
    let paths = [ca_path];
    let provider = super::super::CredentialAuthorities {
        paths: &paths,
        anchor: &effective,
    };
    let credentials =
        credential::check_participants(prepared, &counters, &provider, &access).unwrap();
    let participants =
        pki::participants(&signer, &counters, &credentials, &prior, &access).unwrap();
    check(&participants);
}

#[test]
fn ordinary_crl_refs_use_complete_actual_ca_target_roles_and_one_digest() {
    // The status issuer is the shared root; the target CA is exclusively a
    // credential authority. Inspecting only the issuer or root signer EE would
    // miss the prohibition. Two original refs share one complete-list digest.
    for (mask, incomplete_second) in [(0_u8, false), (1, false), (2, false), (3, false), (3, true)]
    {
        with_checked_path(|signer_path, leaf, root, storage| {
            with_ca_path(root, storage, |ca_path| {
                let bytes = super::super::super::timestamp_oracle::complete_crl_number(2, 3);
                let (mut xml, _, _, _, archive) = super::super::participant_tree(leaf, storage);
                xml.nodes[archive].parent = None;
                let list = add_crl_refs(&mut xml, &bytes);
                add_root_crl_refs(&mut xml, list, mask);
                if incomplete_second {
                    add_crl_refs(&mut xml, &bytes);
                }
                let access = Access::new(&xml, xml.snapshot(), storage);
                let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None);
                if incomplete_second {
                    // Ordinary reference properties are singletons. A second
                    // property cannot pool its missing inputs with the first.
                    assert!(matches!(
                        prepared,
                        Err(prepare::Error::Property(
                            structured_xades::properties::Error::Duplicate { .. }
                        ))
                    ));
                    return;
                }
                let prepared = prepared.unwrap();
                with_participants(
                    &xml,
                    &prepared,
                    signer_path,
                    ca_path,
                    storage,
                    |participants| {
                        super::super::with_original_delta_statuses(
                            signer_path,
                            storage,
                            |ordinary| {
                                with_complete_status(ca_path, &bytes, storage, |credential| {
                                    let roots: Vec<_> = participants
                                        .entries()
                                        .iter()
                                        .filter_map(|entry| match entry.authority() {
                                            pki::ParticipantAuthority::Path(path) => {
                                                Some(if core::ptr::eq(path, ca_path) {
                                                    credential
                                                } else {
                                                    assert!(core::ptr::eq(path, signer_path));
                                                    ordinary
                                                })
                                            }
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
                                    let artifacts =
                                        structured_ltv::material::artifact_uses(&uses, &access)
                                            .unwrap();
                                    let parser = Parser::der(storage.clone());
                                    let operation = parser.read(&[], 900).unwrap();
                                    material::with_values(
                                        &xml,
                                        &prepared,
                                        &operation,
                                        |_, view| {
                                            assert_crl_roles(
                                                &xml, &prepared, &artifacts, &view, ca_path,
                                                storage, mask,
                                            );
                                            Ok::<_, ()>(())
                                        },
                                    )
                                    .unwrap();
                                });
                            },
                        );
                    },
                );
            });
        });
    }
}

fn assert_crl_roles(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    artifacts: &structured_ltv::material::ArtifactUses<'_, '_, '_, '_, '_, usize, u8, u8>,
    view: &material::View<'_, usize, u8, u8>,
    ca_path: &pki::CheckedPath<'_>,
    storage: &Memory,
    mask: u8,
) {
    assert_status_role_refusals(xml, prepared, artifacts, view, storage);
    let held = storage.used();
    let paid = storage.work_used();
    let query = funded();
    let provider = Oracle::new(Mode::Ready);
    let report = validation::check_revocation_reference_roles(
        xml, prepared, artifacts, view, None, &provider, &query,
    )
    .unwrap();
    assert_eq!(report.rows().len(), 2 + mask.count_ones() as usize);
    assert_eq!(report.all_root_sources_referenced(), mask == 3);
    assert_eq!(report.root_sources().len(), 2);
    for source in report.root_sources() {
        assert_eq!(source.member(), 0);
        assert_eq!(source.contributor(), 0);
        assert!(matches!(
            source.artifact(),
            structured_ltv::material::ArtifactRef::Crl(_)
        ));
    }
    assert!(core::ptr::eq(report.prepared(), prepared));
    for row in 0..2 {
        assert_eq!(report.rows()[row].property(), 0);
        assert_eq!(report.rows()[row].entry(), row);
        assert_eq!(
            report.rows()[row].search(),
            validation::ReferenceSearch::Compared
        );
        let compared = report.comparisons(row).unwrap();
        assert_eq!(compared.len(), 1);
        assert_eq!(
            compared[0].kind(),
            material::ExclusiveFindingKind::ForbiddenCa
        );
        assert_eq!(
            compared[0].agreement(),
            validation::StatusRoleAgreement::Compared(Agreement::Matches)
        );
        assert_eq!(
            compared[0].target().as_bytes(),
            ca_path.members()[0].certificate().as_bytes()
        );
        assert!(matches!(
            compared[0].artifact(),
            structured_ltv::material::ArtifactRef::Crl(_)
        ));
        assert!(compared[0].envelope().is_none());
        let root = report.root_comparisons(row).unwrap();
        assert_eq!(root.len(), 2);
        for (ordinal, compared) in root.iter().enumerate() {
            assert_eq!(compared.source(), ordinal);
            assert_eq!(
                compared.agreement(),
                validation::StatusRoleAgreement::Compared(Agreement::Differs)
            );
        }
    }
    assert_eq!((provider.started.get(), provider.finished.get()), (3, 3));
    drop(report);
    assert_eq!(query.used(), 0);
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), paid);
}

fn assert_status_role_refusals(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    artifacts: &structured_ltv::material::ArtifactUses<'_, '_, '_, '_, '_, usize, u8, u8>,
    view: &material::View<'_, usize, u8, u8>,
    storage: &Memory,
) {
    // Retained status/CA facts do not pay for this query. A late stream error
    // must release the partial report and preserve the original provider cause.
    use structured_asn1::memory::MemoryAccount;
    use structured_xades::validation::CertificateRoleError;
    let held = storage.used();
    let paid = storage.work_used();
    let value = prepared.validation_references()[0].entries()[0]
        .digest()
        .unwrap()
        .1;
    for (capacity, work) in [(0, 1 << 24), (1 << 24, 0)] {
        let query = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, work)));
        let provider = Oracle::new(Mode::Ready);
        let result = validation::check_revocation_reference_roles(
            xml, prepared, artifacts, view, None, &provider, &query,
        );
        if work == 0 {
            assert!(matches!(
                result,
                Err(binary::Error::Access {
                    cause: AccessError::Resource {
                        cause: MemoryError::WorkExceeded,
                        ..
                    },
                    ..
                })
            ));
        } else {
            assert!(matches!(result, Err(binary::Error::Access {
                location,
                cause: AccessError::Xml(super::super::super::Cause::Resource(MemoryError::LimitExceeded)),
            }) if location.node == value));
        }
        assert_eq!(provider.started.get(), 0);
        assert_eq!(query.used(), 0);
    }
    let query = funded();
    let provider = Oracle::new(Mode::RefuseUpdate);
    assert!(matches!(validation::check_revocation_reference_roles(
        xml, prepared, artifacts, view, None, &provider, &query,
    ), Err(binary::Error::Callback { location,
        cause: CertificateRoleError::Digest(digest::Error::Provider(Failure::Refused)),
    }) if location.node == value));
    assert_eq!((provider.started.get(), provider.finished.get()), (1, 0));
    assert_eq!(query.used(), 0);
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), paid);
}

#[test]
fn ordinary_ocsp_refs_require_the_original_whole_envelope() {
    // A status assertion for the actual credential CA is forbidden in ordinary
    // refs. Its authenticated basic bytes cannot stand in for a missing whole
    // OCSPResponse. Both repeated refs share one hash when the envelope exists.
    for (include_envelope, root_status, attribute) in [
        (true, false, false),
        (false, false, false),
        (true, true, false),
        (false, true, false),
        (true, false, true),
        (false, false, true),
    ] {
        with_checked_path(|signer_path, leaf, root, storage| {
            with_ca_path(root, storage, |ca_path| {
                let serial = if root_status { 1 } else { 9 };
                let bytes =
                    super::super::super::timestamp_oracle::ocsp_response_for_serial(2, serial);
                let (mut xml, _, _, _, archive) = super::super::participant_tree(leaf, storage);
                xml.nodes[archive].parent = None;
                let property = add_ocsp_refs(&mut xml, &bytes, include_envelope);
                if attribute {
                    xml.nodes[property].value =
                        structured_xades::xml::Node::Element(structured_xades::xml::Name {
                            namespace: XADES,
                            local: "AttributeRevocationRefs",
                        });
                }
                let access = Access::new(&xml, xml.snapshot(), storage);
                let prepared =
                    prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
                with_participants(
                    &xml,
                    &prepared,
                    signer_path,
                    ca_path,
                    storage,
                    |participants| {
                        with_status_case(
                            [signer_path, ca_path],
                            &bytes,
                            storage,
                            root_status,
                            |statuses| {
                                check_ocsp_graph(
                                    &xml,
                                    &prepared,
                                    participants,
                                    statuses,
                                    ca_path,
                                    storage,
                                    (include_envelope, root_status, attribute),
                                );
                            },
                        );
                    },
                );
            });
        });
    }
}

fn with_status_case(
    paths: [&pki::CheckedPath<'_>; 2],
    bytes: &[u8],
    storage: &Memory,
    root_status: bool,
    check: impl FnOnce([&pki::PathStatuses<'_, '_, '_>; 2]),
) {
    let [signer, ca] = paths;
    if root_status {
        let crl = super::super::super::timestamp_oracle::complete_crl_number(2, 3);
        with_ocsp_status(signer, bytes, storage, |ordinary| {
            with_complete_status(ca, &crl, storage, |credential| {
                check([ordinary, credential]);
            });
        });
    } else {
        super::super::with_original_delta_statuses(signer, storage, |ordinary| {
            with_ocsp_status(ca, bytes, storage, |credential| {
                check([ordinary, credential]);
            });
        });
    }
}

fn check_ocsp_graph(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    participants: &pki::ParticipantRequirements<'_, '_, usize, u8, u8>,
    statuses: [&pki::PathStatuses<'_, '_, '_>; 2],
    ca_path: &pki::CheckedPath<'_>,
    storage: &Memory,
    case: (bool, bool, bool),
) {
    let (include_envelope, root_status, attribute) = case;
    let [ordinary, credential] = statuses;
    let access = Access::new(xml, xml.snapshot(), storage);
    let roots: Vec<_> = participants
        .entries()
        .iter()
        .filter_map(|entry| match entry.authority() {
            pki::ParticipantAuthority::Path(path) => Some(if core::ptr::eq(path, ca_path) {
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
    let parser = Parser::der(storage.clone());
    let operation = parser.read(&[], 900).unwrap();
    material::with_values(xml, prepared, &operation, |_, view| {
        if include_envelope {
            assert_status_role_refusals(xml, prepared, &artifacts, &view, storage);
        }
        let query = funded();
        let provider = Oracle::new(Mode::Ready);
        let held = storage.used();
        let paid = storage.work_used();
        let report = validation::check_revocation_reference_roles(
            xml, prepared, &artifacts, &view, None, &provider, &query,
        )
        .unwrap();
        assert_eq!(report.rows().len(), 2);
        assert_eq!(
            report.all_root_sources_referenced(),
            attribute || (root_status && include_envelope)
        );
        assert_eq!(
            report.all_credential_sources_referenced(),
            !attribute || include_envelope
        );
        if attribute {
            assert_eq!(report.credential_sources().len(), 1);
            let source = &report.credential_sources()[0];
            assert_eq!(source.source().member(), 0);
            assert_eq!(source.presence(), (false, include_envelope));
            assert!(matches!(
                source.source().artifact(),
                structured_ltv::material::ArtifactRef::Ocsp(_)
            ));
            assert!(matches!(
                participants.entries()[source.participant()].participant(),
                pki::Participant::Credential { .. }
            ));
        }
        for row in 0..2 {
            assert_ocsp_row(&report, row, ca_path, case);
        }
        let hashes = usize::from(include_envelope);
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

fn assert_ocsp_row(
    report: &validation::RevocationRoles<'_, '_, '_, usize, u8, u8>,
    row: usize,
    ca_path: &pki::CheckedPath<'_>,
    (include_envelope, root_status, attribute): (bool, bool, bool),
) {
    let expected = if include_envelope {
        validation::StatusRoleAgreement::Compared(Agreement::Matches)
    } else {
        validation::StatusRoleAgreement::EnvelopeUnprovided
    };
    let comparisons = report.comparisons(row).unwrap();
    if attribute {
        assert!(comparisons.is_empty());
        assert!(report.root_comparisons(row).unwrap().is_empty());
        let compared = report.credential_comparisons(row).unwrap();
        assert_eq!(compared.len(), 1);
        assert_eq!(compared[0].source(), 0);
        assert_eq!(compared[0].agreement(), expected);
        return;
    }
    if root_status {
        assert!(comparisons.is_empty());
        let compared = report.root_comparisons(row).unwrap();
        assert_eq!(compared.len(), 1);
        assert_eq!(compared[0].source(), 0);
        assert_eq!(compared[0].agreement(), expected);
    } else {
        assert_eq!(comparisons.len(), 1);
        let comparison = &comparisons[0];
        assert_eq!(
            comparison.target().as_bytes(),
            ca_path.members()[0].certificate().as_bytes()
        );
        assert_eq!(
            comparison.kind(),
            material::ExclusiveFindingKind::ForbiddenCa
        );
        assert!(matches!(
            comparison.artifact(),
            structured_ltv::material::ArtifactRef::Ocsp(_)
        ));
        assert_eq!(comparison.agreement(), expected);
        if include_envelope {
            assert!(matches!(
                comparison.envelope(),
                Some((structured_ltv::material::ArtifactSource::Material(_), _))
            ));
        } else {
            assert!(comparison.envelope().is_none());
        }
    }
}

#[derive(Clone, Copy)]
enum CredentialRefs {
    Attribute,
    Ordinary,
    Protected,
    Redundant,
    Missing,
    Absent,
}

fn add_credential_certificate_refs(xml: &mut Tree, ca: &[u8], root: &[u8], case: CredentialRefs) {
    if matches!(case, CredentialRefs::Absent) {
        return;
    }
    let property = add(xml, 7, XADES_141, "AttributeCertificateRefsV2");
    let list = add(xml, property, XADES_141, "CertRefs");
    if !matches!(case, CredentialRefs::Missing) {
        add_certificate_reference(xml, list, ca);
    }
    if matches!(
        case,
        CredentialRefs::Attribute | CredentialRefs::Missing | CredentialRefs::Redundant
    ) {
        add_certificate_reference(xml, list, root);
    }
    if matches!(case, CredentialRefs::Ordinary | CredentialRefs::Redundant) {
        let property = add(xml, 7, XADES_141, "CompleteCertificateRefsV2");
        let list = add(xml, property, XADES_141, "CertRefs");
        add_certificate_reference(xml, list, root);
    }
    if matches!(case, CredentialRefs::Protected) {
        let list = xml.nodes.iter().position(|node| matches!(node.value,
            structured_xades::xml::Node::Element(name) if name.namespace == XADES && name.local == "SigningCertificateV2"
        )).unwrap();
        add_certificate_reference(xml, list, root);
    }
}

#[test]
fn credential_required_certificates_honor_original_protected_and_ordinary_alternatives() {
    // Actual credential CA and direct-anchor receipts determine the required
    // set. Presence in protected/ordinary properties is a valid alternative;
    // redundant attribute copies are an advisory SHOULD NOT, not a failure.
    for case in [
        CredentialRefs::Attribute,
        CredentialRefs::Ordinary,
        CredentialRefs::Protected,
        CredentialRefs::Redundant,
        CredentialRefs::Missing,
        CredentialRefs::Absent,
    ] {
        with_checked_path(|signer_path, leaf, root, storage| {
            with_ca_path(root, storage, |ca_path| {
                let (mut xml, _, _, _, archive) = super::super::participant_tree(leaf, storage);
                xml.nodes[archive].parent = None;
                add_credential_certificate_refs(
                    &mut xml,
                    ca_path.members()[0].certificate().as_bytes(),
                    root,
                    case,
                );
                let access = Access::new(&xml, xml.snapshot(), storage);
                let prepared =
                    prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
                with_participants(&xml, &prepared, signer_path, ca_path, storage, |required| {
                    assert_credential_reference_set(&xml, &prepared, required, storage, case);
                });
            });
        });
    }
}

fn assert_credential_reference_set(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    required: &pki::ParticipantRequirements<'_, '_, usize, u8, u8>,
    storage: &Memory,
    case: CredentialRefs,
) {
    let held = storage.used();
    let paid = storage.work_used();
    let query = funded();
    let provider = Oracle::new(Mode::Ready);
    let report = validation::check_credential_certificate_references(
        xml, prepared, required, &provider, &query,
    )
    .unwrap();
    let absent = matches!(case, CredentialRefs::Absent);
    assert_eq!(report.property_present(), !absent);
    assert_eq!(
        report.all_required_referenced(),
        !matches!(case, CredentialRefs::Missing)
    );
    assert!(core::ptr::eq(report.prepared(), prepared));
    if absent {
        assert!(report.rows().is_empty());
        assert!(report.candidates().is_empty());
    } else {
        assert!(report.candidates().len() >= 2);
        for candidate in report.candidates() {
            assert!(matches!(
                required.entries()[candidate.participant()].participant(),
                pki::Participant::Credential { .. }
            ));
            let (protected, ordinary, attribute) = candidate.presence();
            assert_eq!(
                candidate.redundant_attribute_reference(),
                matches!(case, CredentialRefs::Redundant) && ordinary
            );
            assert_eq!(
                protected,
                matches!(case, CredentialRefs::Protected)
                    && candidate.role() == structured_ltv::material::PathCertificate::Anchor
            );
            assert_eq!(
                ordinary,
                matches!(case, CredentialRefs::Ordinary | CredentialRefs::Redundant)
                    && candidate.role() == structured_ltv::material::PathCertificate::Anchor
            );
            if matches!(case, CredentialRefs::Missing) {
                assert_eq!(
                    attribute,
                    candidate.role() == structured_ltv::material::PathCertificate::Anchor
                );
            } else {
                assert!(protected || ordinary || attribute);
            }
        }
        for row in 0..report.rows().len() {
            assert_eq!(
                report.rows()[row].search(),
                validation::ReferenceSearch::Compared
            );
            assert_eq!(
                report.comparisons(row).unwrap().len(),
                report.candidates().len()
            );
        }
    }
    let hashes = if absent { 0 } else { 2 };
    assert_eq!(
        (provider.started.get(), provider.finished.get()),
        (hashes, hashes)
    );
    drop(report);
    assert_eq!(query.used(), 0);
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), paid);
    assert_credential_reference_refusals(xml, prepared, required, storage, absent);
}

fn assert_credential_reference_refusals(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    required: &pki::ParticipantRequirements<'_, '_, usize, u8, u8>,
    storage: &Memory,
    absent: bool,
) {
    // Retained credential paths grant no credit to the current query. Optional
    // absence needs no catalogue, whereas failure after stream start releases
    // every temporary and retains the original protected DigestValue location.
    use structured_asn1::memory::MemoryAccount;
    use validation::ReferenceDigestError;
    let held = storage.used();
    let paid = storage.work_used();
    for (capacity, work) in [(0, 1 << 24), (1 << 24, 0)] {
        let query = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, work)));
        let provider = Oracle::new(Mode::Ready);
        let answer = validation::check_credential_certificate_references(
            xml, prepared, required, &provider, &query,
        );
        if work == 0 {
            assert!(matches!(
                answer,
                Err(binary::Error::Access {
                    cause: AccessError::Resource {
                        cause: MemoryError::WorkExceeded,
                        ..
                    },
                    ..
                })
            ));
        } else if absent {
            let report = answer.unwrap();
            assert!(report.all_required_referenced());
            assert!(report.candidates().is_empty());
        } else {
            // Output-row admission precedes XML decoding and provider effects.
            assert!(matches!(answer, Err(binary::Error::Callback { location,
                cause: ReferenceDigestError::Digest(digest::Error::Resource(MemoryError::LimitExceeded)),
            }) if location.node == prepared.bound().containers().signature()));
        }
        assert_eq!(provider.started.get(), 0);
        assert_eq!(query.used(), 0);
    }
    if !absent {
        let query = funded();
        let provider = Oracle::new(Mode::RefuseUpdate);
        let value = prepared.certificates().entries()[0].digest();
        assert!(
            matches!(validation::check_credential_certificate_references(xml, prepared, required, &provider, &query),
            Err(binary::Error::Callback { location, cause: ReferenceDigestError::Digest(digest::Error::Provider(Failure::Refused)) }) if location.node == value)
        );
        assert_eq!((provider.started.get(), provider.finished.get()), (1, 0));
        assert_eq!(query.used(), 0);
        let provider = Oracle::new(Mode::Unsupported);
        let report = validation::check_credential_certificate_references(
            xml, prepared, required, &provider, &query,
        )
        .unwrap();
        assert!(!report.all_required_referenced());
        for candidate in report.candidates() {
            assert_eq!(candidate.presence(), (false, false, false));
        }
        assert_eq!((provider.started.get(), provider.finished.get()), (2, 0));
        drop(report);
        assert_eq!(query.used(), 0);
    }
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), paid);
}
