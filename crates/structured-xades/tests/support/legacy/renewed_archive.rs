//! Real RFC 3161, path and status receipts over the fixture XML adapter.

use super::*;
use sha2::{Digest, Sha256};
use structured_cms::stream::{Refused, Source};
use structured_ltv::{
    material::ArtifactRef,
    pki::{self, AuthorityNode, CheckedPath, PathStatuses, TimestampBinding},
    timestamp::TimestampPathBinding,
};
use structured_pkix::{
    Certificate, crl,
    path::{Anchor, EffectiveKey, Interval, ValidationBounds, ValidationContext},
    temporal::{Instant, LeapTable},
};
use structured_xades::{
    certificate::KeyAssociation,
    credential,
    material::{self, Archived, Placement},
    produce,
    timestamp::{self, TimestampSelection, TokenProfile},
};

#[test]
fn renewed_archive_reuses_shared_tsa_material() {
    // A matching CA certificate and CRL in ordinary values are reusable under
    // TS 101 903 §8.1. They must not generate new TSVD or duplicate bytes.
    renewal(2);
}

#[test]
fn renewed_archive_places_missing_tsa_material_between_archives() {
    // A second CA's evidence is available from checked inputs only. Insert it
    // immediately after the first archive and verify the two distinct inputs.
    renewal(3);
}

fn renewal(tsa_root_seed: u8) {
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 30)));
    let digest = xml_digest::Oracle::new(xml_digest::Mode::Ready);
    let parser = structured_asn1::Parser::der(work.clone());
    let operation = parser.read(&[], 0).unwrap();
    let (signer_bytes, signer_root) = timestamp_oracle::certificate_pair();
    let signer_crl = timestamp_oracle::complete_crl_for(2);
    let tsa_crl = timestamp_oracle::complete_crl_for(tsa_root_seed);
    let (mut xml, certs) = signature(&signer_bytes, &signer_root, &signer_crl);
    let (first, token, provider, tsa_bytes, tsa_root) = archive(&mut xml, &work, tsa_root_seed);

    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let signer = Certificate::read(&parser, &signer_bytes, 1000).unwrap();
    let signer_anchor = Certificate::read(&parser, &signer_root, 2000).unwrap();
    let tsa = Certificate::read(&parser, &tsa_bytes, 3000).unwrap();
    let tsa_anchor = Certificate::read(&parser, &tsa_root, 4000).unwrap();
    let signer_crl = crl::CertificateList::read(&parser, &signer_crl, 5000).unwrap();
    let tsa_crl = crl::CertificateList::read(&parser, &tsa_crl, 6000).unwrap();
    let signer_path = path(&signer, &signer_anchor, &work);
    let tsa_path = path(&tsa, &tsa_anchor, &work);
    let context = CheckContext {
        certificate: &tsa,
        certificate_parent: &operation,
        key: EffectiveKey::standing(tsa.tbs().public_key()),
        requested: None,
        utc: &utc,
        reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
        window: None,
        policy_accuracy: None,
    };
    let checks = Parties {
        signer: &signer_path,
        tsa: &tsa_path,
        signer_crl: &signer_crl,
        tsa_crl: &tsa_crl,
        digest: &digest,
        utc: &utc,
        work: &work,
    };
    let mut writer = lifecycle::Draft::new(&xml, Some(7));
    let require_missing = tsa_root_seed != 2;
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = prepare(&access);
    let inventory = legacy::inventory(&access, &prepared, old::HashDataUri::Standard).unwrap();
    let checked = check(&provider, &context, &xml, &prepared, first, &operation);
    checks.with_census(&xml, &prepared, &inventory, TimestampSelection::All, &checked, |closed| {
        with_index(&xml, &prepared, &inventory, &operation, |index, access| {
            let report = material::historical_timestamp_material(closed, index, access).unwrap();
            assert_eq!(report.authorities().len(), 1);
            assert!(core::ptr::eq(report.authorities()[0].authority.statuses.path(), checks.tsa));
            assert_eq!(report.authorities()[0].authority.statuses.entries().len(), 1);
            let missing = missing_values(&report, (first, token));
            assert_eq!(missing.len(), if require_missing { 2 } else { 0 });
            let ca = report.artifacts().iter().find(|row| {
                matches!(row.artifact, ArtifactRef::Certificate(cert) if cert.as_bytes() == tsa_root)
            }).unwrap();
            assert_eq!(ca.is_missing(), require_missing);
            if !require_missing {
                assert!(matches!(ca.elsewhere.unwrap().placement(), Placement::Signature(node) if node == certs));
            }
            produce::write_historical_timestamp_values(&missing, &mut writer, &work).unwrap();
        });
    });
    let ts_data = apply_values(&mut xml, writer.events, require_missing);
    let (second, _, second_provider, _, _) = archive(&mut xml, &work, tsa_root_seed);
    xml.generation.set(2);
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = prepare(&access);
    let inventory = legacy::inventory(&access, &prepared, old::HashDataUri::Standard).unwrap();
    let earlier = check(&provider, &context, &xml, &prepared, first, &operation);
    let later = check(
        &second_provider,
        &context,
        &xml,
        &prepared,
        second,
        &operation,
    );
    let coverage = inventory.archive_coverage(&access, 1).unwrap();
    checks.with_census(&xml, &prepared, &inventory, TimestampSelection::BeforeArchive(1), &earlier, |closed| {
        with_index(&xml, &prepared, &inventory, &operation, |index, access| {
            let report = material::historical_timestamp_material_before_archive(
                closed, index, &coverage, later.verified(), access,
            ).unwrap();
            assert_eq!(report.authorities().len(), 1);
            assert_eq!(report.artifacts().len(), 3);
            for row in report.artifacts() {
                let Some(Archived::Present(copy)) = row.archive else { panic!("second archive covers every TSA input"); };
                assert_eq!((row.property, row.token), (first, token));
                if row.own_token.is_none() && let Some(ts_data) = ts_data {
                    assert!(matches!(copy.placement(), Placement::AssociatedTimestamp { container, property }
                        if container == ts_data && property == first));
                    assert_eq!(row.adjacent.unwrap().location().node, copy.location().node);
                }
            }
            assert!(matches!(
                material::historical_timestamp_material_before_archive(closed, index, &coverage, earlier.verified(), access),
                Err(material::HistoricalTimestampError::Archive { property }) if property == first
            ));
        });
    });
}

fn signature(signer_bytes: &[u8], signer_root: &[u8], signer_crl: &[u8]) -> (Tree, usize) {
    let mut xml = profile_tree(Profile::PreEn);
    xml.key_association = KeyAssociation::Same;
    let digest_value = xml.nodes.iter().position(|node| {
        matches!(node.value, Node::Element(name) if name == Name { namespace: DS, local: "DigestValue" })
    }).unwrap();
    xml.binary_routes
        .push((digest_value, Sha256::digest(signer_bytes).to_vec()));
    xml.digest_algorithm = Some("http://www.w3.org/2001/04/xmlenc#sha256");
    let certs = append(&mut xml, 7, XADES, "CertificateValues");
    let member = append(&mut xml, certs, XADES, "EncapsulatedX509Certificate");
    xml.binary_routes.push((member, signer_root.to_vec()));
    let revocations = append(&mut xml, 7, XADES, "RevocationValues");
    let lists = append(&mut xml, revocations, XADES, "CRLValues");
    let member = append(&mut xml, lists, XADES, "EncapsulatedCRLValue");
    xml.binary_routes.push((member, signer_crl.to_vec()));
    (xml, certs)
}

fn missing_values<'a, 'd>(
    report: &'a material::HistoricalTimestampMaterial<'_, '_, 'd, usize, u8, u8>,
    source: (usize, usize),
) -> Vec<produce::Material<'a, 'd>> {
    report
        .artifacts()
        .iter()
        .filter_map(|row| {
            assert_eq!((row.property, row.token), source);
            assert!(row.archive.is_none());
            if !row.is_missing() {
                return None;
            }
            Some(match row.artifact {
                ArtifactRef::Certificate(cert) => produce::Material::certificate(cert),
                ArtifactRef::Crl(crl) => produce::Material::crl(crl),
                ArtifactRef::Ocsp(_) => panic!("fixture uses a CRL"),
            })
        })
        .collect()
}

struct Parties<'a, 'd> {
    signer: &'a CheckedPath<'d>,
    tsa: &'a CheckedPath<'d>,
    signer_crl: &'a crl::CertificateList<'d>,
    tsa_crl: &'a crl::CertificateList<'d>,
    digest: &'a xml_digest::Oracle,
    utc: &'a LeapTable<'d>,
    work: &'a Memory,
}

type Census<'req, 'view, 'cert, 'doc> =
    pki::ParticipantClosure<'req, 'view, 'cert, 'doc, usize, u8, u8, structured_xades::Xades>;

impl<'d> Parties<'_, 'd> {
    fn with_census(
        &self,
        xml: &Tree,
        prepared: &legacy::Prepared<Tree>,
        inventory: &legacy::Inventory<'_, Tree>,
        selection: TimestampSelection,
        actor: &timestamp::TimestampActor<'_, 'd, Tree>,
        visit: impl for<'req, 'view, 'cert> FnOnce(&Census<'req, 'view, 'cert, 'd>),
    ) {
        let access = Access::new(xml, xml.snapshot(), self.work);
        let TimestampBinding::Bound(tsa) =
            self.tsa.bind_timestamp(actor, self.utc, self.work).unwrap()
        else {
            panic!("original TSA path binds to the verified token")
        };
        let required = inventory.requirements(&access, selection).unwrap();
        let supplied = [&tsa];
        let TimestampPathBinding::Bound(paths) = required.bind_paths(&supplied, &access).unwrap()
        else {
            panic!("complete original timestamp set")
        };
        let signer =
            legacy::check_path(xml, prepared, self.signer, self.digest, self.work).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.binding(), &access, |_, _| {
            Ok::<_, ()>(self.signer)
        })
        .unwrap();
        let credentials =
            legacy::check_credentials(prepared, &counters, &NoCredentials, &access).unwrap();
        let participants = structured_xades::pki::historical_participants(
            &signer,
            &counters,
            &credentials,
            &paths,
            &access,
        )
        .unwrap();
        with_status(
            self.signer,
            self.signer_crl,
            self.signer.anchor().certificate().unwrap(),
            self.utc,
            self.work,
            |signer_status| {
                with_status(
                    self.tsa,
                    self.tsa_crl,
                    self.tsa.anchor().certificate().unwrap(),
                    self.utc,
                    self.work,
                    |tsa_status| {
                        let roots = [signer_status, tsa_status];
                        let nodes = roots.map(|statuses| AuthorityNode {
                            statuses,
                            responders: &[],
                        });
                        let closed = participants
                            .close_statuses(&roots, &nodes, &access)
                            .unwrap();
                        visit(&closed);
                    },
                );
            },
        );
    }
}

fn prepare(access: &Access<'_, Tree, Memory>) -> legacy::Prepared<Tree> {
    legacy::prepare(access, &legacy::locate(access, 0, Profile::PreEn).unwrap()).unwrap()
}

fn archive(
    xml: &mut Tree,
    work: &Memory,
    seed: u8,
) -> (usize, usize, timestamp_oracle::Oracle, Vec<u8>, Vec<u8>) {
    struct Bytes(Vec<u8>);
    impl Receiver for Bytes {
        fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }
    let property = append(xml, 7, XADES_141, "ArchiveTimeStamp");
    append(xml, property, DS, "CanonicalizationMethod");
    let token = append(xml, property, XADES, "EncapsulatedTimeStamp");
    let access = Access::new(xml, xml.snapshot(), work);
    let prepared = prepare(&access);
    let stamp = old::read_pre_en(&access, &prepared, property).unwrap();
    let mut input = timestamp::Input::prepare(xml, prepared.binding(), &stamp, work).unwrap();
    let mut bytes = Bytes(Vec::new());
    input.stream(&mut bytes, work).unwrap();
    let (provider, encoded, tsa, root) = timestamp_oracle::fixture_with_root_seed(&bytes.0, seed);
    xml.binary_routes.push((token, encoded));
    (property, token, provider, tsa, root)
}

fn check<'certificate, 'document>(
    provider: &timestamp_oracle::Oracle,
    context: &CheckContext<'document, 'certificate>,
    xml: &Tree,
    prepared: &legacy::Prepared<Tree>,
    property: usize,
    operation: &structured_asn1::Reader<'_>,
) -> timestamp::TimestampActor<'certificate, 'document, Tree> {
    let work = operation.execution();
    let access = Access::new(xml, xml.snapshot(), &work);
    let stamp = old::read_pre_en(&access, prepared, property).unwrap();
    timestamp::Check {
        xml,
        provider,
        context,
    }
    .retain_actor(prepared.binding(), &stamp, 0, operation, |_, _| {
        Ok::<_, ()>(false)
    })
    .unwrap()
    .unwrap()
}

fn with_index(
    xml: &Tree,
    prepared: &legacy::Prepared<Tree>,
    inventory: &legacy::Inventory<'_, Tree>,
    operation: &structured_asn1::Reader<'_>,
    visit: impl for<'source, 'query> FnOnce(
        &material::Index<'source, usize, u8, u8, structured_asn1::memory::Execution<'query>>,
        &Access<'_, Tree, structured_asn1::memory::Execution<'query>>,
    ),
) {
    material::with_historical_values(xml, prepared, operation, |query, values| {
        inventory
            .with_tokens(xml, query, TokenProfile::Cms, |query, tokens| {
                let work = query.execution();
                let access = Access::new(xml, xml.snapshot(), &work);
                let carried = tokens.material_in(query).unwrap();
                let index = material::index_with_tokens(&values, &carried, &access).unwrap();
                visit(&index, &access);
                Ok::<_, ()>(())
            })
            .unwrap();
        Ok::<_, ()>(())
    })
    .unwrap();
}

fn path<'d>(
    leaf: &'d Certificate<'d>,
    root: &'d Certificate<'d>,
    work: &Memory,
) -> CheckedPath<'d> {
    let verifier = timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let context = ValidationContext {
        execution: work,
        interval: Interval::at(1_767_225_600),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let pki::PathOutcome::Accepted(path) =
        pki::check_path(&[leaf], Anchor::from_certificate(root), &context).unwrap()
    else {
        panic!("valid test chain")
    };
    path
}

fn with_status<'d>(
    path: &CheckedPath<'d>,
    list: &crl::CertificateList<'d>,
    root: &Certificate<'d>,
    utc: &LeapTable<'_>,
    work: &Memory,
    visit: impl FnOnce(&PathStatuses<'_, '_, 'd>),
) {
    let verifier = timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let key = EffectiveKey::standing(root.tbs().public_key());
    let crl::Authentication::Authenticated(list) =
        list.authenticate(root, key, &verifier, work).unwrap()
    else {
        panic!("valid original CRL")
    };
    let evaluation = crl::Evaluation {
        now: Instant::new(1_767_225_600, 0).unwrap().into(),
        utc,
        execution: work,
        origin: crl::SourceOrigin::Cached,
    };
    let crl::CompleteEvidence::Facts(facts) = list
        .evaluate(path.target().certificate(), &evaluation)
        .unwrap()
    else {
        panic!("applicable original CRL")
    };
    let coverage = crl::Coverage::new(facts.absence().unwrap(), work).unwrap();
    let authorities = [pki::CrlAuthorities::Complete(pki::CrlAuthority::Anchor)];
    let pki::CrlCoverageBinding::Bound(bound) = path
        .bind_crl_coverage(0, &coverage, &authorities, utc, work)
        .unwrap()
    else {
        panic!("actual CRL authority")
    };
    let entries = [pki::MemberStatus::Crl(&bound)];
    let statuses = path.status_census(evaluation.now, &entries, work).unwrap();
    visit(&statuses);
}

fn apply_values(
    xml: &mut Tree,
    events: Vec<lifecycle::Written>,
    require_values: bool,
) -> Option<usize> {
    if !require_values {
        assert_eq!(events, []);
        return None;
    }
    let mut parents = vec![7];
    let validation = xml.nodes.len();
    for event in events {
        match event {
            lifecycle::Written::Begin(ns, local) => {
                let node = append(xml, *parents.last().unwrap(), ns, local);
                parents.push(node);
            }
            lifecycle::Written::End => assert!(parents.pop().is_some()),
            lifecycle::Written::Binary(bytes) => {
                xml.binary_routes.push((*parents.last().unwrap(), bytes));
            }
            other => panic!("unexpected writer event: {other:?}"),
        }
    }
    assert_eq!(parents, [7]);
    Some(validation)
}

struct NoCredentials;
impl<'p, 'd> credential::Provider<'p, 'd, Tree> for NoCredentials {
    type Evidence = ();
    type Error = MemoryError;
    fn authenticate<W: Work>(
        &self,
        _: &Access<'_, Tree, W>,
        _: credential::Credential<usize, u8, u8>,
    ) -> Result<credential::Authentication<'p, 'd, ()>, MemoryError> {
        panic!("fixture has no protected credentials")
    }
}
