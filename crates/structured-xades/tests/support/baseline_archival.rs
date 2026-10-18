//! B-LTA level over one original preparation's complete stage chain.

use super::{
    LongTermReport, NoCredentials, Tree, fixture, funded, timestamp_oracle, values, xml_digest,
};
use structured_asn1::memory::{Memory, Work};
use structured_ltv::pki;
use structured_xades::{
    baseline, certificate, credential, material, prepare, timestamp, unsigned,
    xml::{Access, Xml},
};

fn archival_fixture(leaf: &[u8], root: &[u8]) -> (Tree, timestamp_oracle::Oracle, Vec<u8>) {
    // The signature token covers the original SignatureValue projection. The
    // archive token covers its own original input, which already holds the
    // complete validation pool and that earlier token.
    use structured_cms::stream;
    let memory = funded();
    let (mut xml, _, _) = fixture(leaf, root, values::Pool::Complete);
    let (archive, tokens) =
        super::super::append_timestamp(&mut xml, 7, timestamp::Role::Archive, 1);
    let covered = {
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared =
            prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
        let stamp = &prepared.timestamps()[1];
        assert_eq!(stamp.node(), archive);
        let mut input = timestamp::Input::prepare(&xml, prepared.bound(), stamp, &memory).unwrap();
        let mut sink = super::super::Collect::new(&memory);
        stream::run(&mut input, &mut sink, &memory, "archive", 0).unwrap();
        sink.bytes().to_vec()
    };
    let (provider, token, tsa, _) = timestamp_oracle::fixture_with_root(&covered);
    xml.binary_routes.push((tokens[0], token));
    (xml, provider, tsa)
}

type TsaPath<'a> = pki::TimestampPath<'a, 'a, 'a, usize, u8, u8>;

struct Tokens<'a> {
    xml: &'a Tree,
    prepared: &'a prepare::Prepared<Tree>,
    provider: &'a timestamp_oracle::Oracle,
    tsa: &'a [u8],
}

impl Tokens<'_> {
    fn with_paths(
        &self,
        path: &pki::CheckedPath<'_>,
        memory: &Memory,
        check: impl for<'t> FnOnce(
            &TsaPath<'t>,
            &TsaPath<'t>,
            &structured_ltv::timestamp::Verified<usize, u8, u8>,
        ),
    ) {
        // Both original tokens are checked once with their real TSA key and
        // bound to the actual checked path; later stages reuse these receipts.
        use structured_pkix::{
            path::WorkingKey,
            temporal::{Instant, LeapTable},
        };
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let tsa = structured_pkix::Certificate::read(&parser, self.tsa, 400).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = structured_cms::timestamp::CheckContext {
            certificate: &tsa,
            certificate_parent: &operation,
            key: WorkingKey::standing(tsa.tbs().public_key()),
            requested: None,
            utc: &utc,
            reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
            window: None,
        };
        let token = timestamp::Check {
            xml: self.xml,
            provider: self.provider,
            context: &context,
        };
        let retain = |stamp| {
            token
                .retain_actor(self.prepared.bound(), stamp, 0, &operation, |_, _| {
                    Ok::<_, ()>(false)
                })
                .unwrap()
                .unwrap()
        };
        let signature_actor = retain(&self.prepared.timestamps()[0]);
        let archive_actor = retain(&self.prepared.timestamps()[1]);
        let bind = |actor| {
            let pki::TimestampBinding::Bound(value) =
                path.bind_timestamp(actor, &utc, memory).unwrap()
            else {
                panic!("actual TSA/path/full generation")
            };
            value
        };
        check(
            &bind(&signature_actor),
            &bind(&archive_actor),
            archive_actor.verified(),
        );
        assert_eq!(self.provider.verified.get(), 2);
    }
}

#[test]
fn archival_level_joins_whole_and_archive_material_of_one_preparation() {
    // B-LTA needs every earlier level of the same preparation. Each archive's
    // material must also come from the whole signature's authenticated
    // credential census: an equivalent second census is a foreign report.
    xml_digest::with_checked_path(|path, leaf, root, _| {
        // Two real tokens, both participant censuses and the material checks
        // share one operation: keep the storage ceiling, fund combined work.
        let memory = &Memory::new(std::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(65_536, 2_000_000),
        ));
        let (xml, provider, tsa) = archival_fixture(leaf, root);
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared =
            prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
        let fields = prepare::check_fields(&prepared, &access).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        let structured_xades::hashes::ParticipantBinding::Bound(hashes) =
            structured_xades::hashes::check_participants(&prepared, &counters, &access).unwrap()
        else {
            panic!("complete actual hash projection")
        };
        let selected = xml_digest::checked_certificate(&xml, &prepared, path, memory);
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let basic = baseline::basic(
            baseline::BasicInput {
                fields: &fields,
                hashes: &hashes,
                certificate: &selected,
                counters: &counters,
            },
            &xml,
            &operation,
        )
        .unwrap();
        let tokens = Tokens {
            xml: &xml,
            prepared: &prepared,
            provider: &provider,
            tsa: &tsa,
        };
        tokens.with_paths(path, memory, |signature_path, archive_path, evidence| {
            let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
            let select = |selection| {
                timestamp::requirements_with_counters(&access, &prepared, &stamps, selection)
                    .unwrap()
            };
            let whole = select(timestamp::TimestampSelection::All);
            let all_paths = [signature_path, archive_path];
            let structured_ltv::timestamp::TimestampPathBinding::Bound(paths) =
                whole.bind_paths(&all_paths, &access).unwrap()
            else {
                panic!("complete original token census")
            };
            let earlier = select(timestamp::TimestampSelection::BeforeArchive(1));
            let prior_paths = [signature_path];
            let structured_ltv::timestamp::TimestampPathBinding::Bound(prior) =
                earlier.bind_paths(&prior_paths, &access).unwrap()
            else {
                panic!("complete original earlier-token census")
            };
            let timed = baseline::timestamped(&basic, &paths, &access).unwrap();
            let coverage = timestamp::Input::prepare(
                &xml,
                prepared.bound(),
                &prepared.timestamps()[1],
                memory,
            )
            .unwrap()
            .element_coverage(memory)
            .unwrap();
            Chain {
                xml: &xml,
                prepared: &prepared,
                counters: &counters,
                selected: &selected,
                operation: &operation,
                paths: &paths,
                prior: &prior,
                timed: &timed,
                coverage: &coverage,
                evidence,
            }
            .check(path, memory, &access);
        });
    });
}

struct Chain<'a> {
    xml: &'a Tree,
    prepared: &'a prepare::Prepared<Tree>,
    counters: &'a structured_xades::pki::CounterPaths<'a, 'a, usize, u8, u8>,
    selected: &'a certificate::CheckedPathCertificate<'a, 'a, usize, u8, u8>,
    operation: &'a structured_asn1::Reader<'a>,
    paths: &'a structured_ltv::timestamp::TimestampPaths<'a, 'a, 'a, usize, u8, u8>,
    prior: &'a structured_ltv::timestamp::TimestampPaths<'a, 'a, 'a, usize, u8, u8>,
    timed: &'a baseline::Timed<'a, 'a, 'a, 'a, 'a, 'a, usize, u8, u8>,
    coverage: &'a structured_ltv::material::Coverage<usize, u8, u8, Memory>,
    evidence: &'a structured_ltv::timestamp::Verified<usize, u8, u8>,
}

type Credentials<'a> = credential::ParticipantCredentials<'a, 'a, (), usize, u8, u8>;

impl Chain<'_> {
    fn check<W: Work>(
        &self,
        path: &pki::CheckedPath<'_>,
        memory: &Memory,
        access: &Access<'_, Tree, W>,
    ) {
        // The whole B-LT stage and the archive census reuse one authenticated
        // credential census; a second equivalent census stays foreign.
        let credentials =
            credential::check_participants(self.prepared, self.counters, &NoCredentials, access)
                .unwrap();
        let other =
            credential::check_participants(self.prepared, self.counters, &NoCredentials, access)
                .unwrap();
        let participants = pki::participants(
            self.selected,
            self.counters,
            &credentials,
            self.paths,
            access,
        )
        .unwrap();
        xml_digest::with_original_delta_statuses(path, memory, |statuses| {
            let nodes = [pki::AuthorityNode {
                statuses,
                responders: &[],
            }];
            // One status root per actual actor: signer plus both TSA paths.
            let roots = [statuses; 3];
            let closure = participants.close_statuses(&roots, &nodes, access).unwrap();
            material::with_counter_values(
                self.xml,
                self.prepared,
                self.counters,
                self.operation,
                |query, view| {
                    let work = query.execution();
                    let access = Access::new(self.xml, self.xml.snapshot(), &work);
                    let index = material::index(&view, &access).unwrap();
                    let x509 = material::check_participants(
                        self.prepared,
                        &closure,
                        self.counters,
                        &index,
                        &access,
                    )
                    .unwrap();
                    let format = material::credentials::check(
                        &credentials,
                        self.counters,
                        self.paths.required(),
                        &index,
                        &material::credentials::Scope::whole(),
                        &NoCredentials,
                        &access,
                    )
                    .unwrap();
                    let long_term =
                        baseline::long_term(self.timed, &x509, &format, &access).unwrap();
                    assert!(long_term.all_material_requirements_met());
                    let archive = Archive {
                        chain: self,
                        long_term: &long_term,
                        statuses,
                        nodes: &nodes,
                    };
                    archive.assess(&credentials, true, &index, &access);
                    archive.assess(&other, false, &index, &access);
                    // A whole B-LT report alone does not answer a B-LTA request.
                    assert!(matches!(
                        baseline::assess(baseline::Evidence::LongTerm(&long_term)),
                        Err(baseline::LevelError::Mismatch {
                            requested: unsigned::Requirements::Archival,
                            supplied: unsigned::Requirements::LongTerm,
                        })
                    ));
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        });
    }
}

struct Archive<'a> {
    chain: &'a Chain<'a>,
    long_term: &'a LongTermReport<'a>,
    statuses: &'a pki::PathStatuses<'a, 'a, 'a>,
    nodes: &'a [pki::AuthorityNode<'a, 'a, 'a>],
}

impl Archive<'_> {
    fn assess<W: Work, Q: Work>(
        &self,
        census: &Credentials<'_>,
        same: bool,
        index: &material::Index<'_, usize, u8, u8, W>,
        access: &Access<'_, Tree, Q>,
    ) {
        // Material before the archive is checked against its own original
        // coverage; only the census identity differs between both calls.
        let chain = self.chain;
        let earlier =
            pki::participants(chain.selected, chain.counters, census, chain.prior, access).unwrap();
        // Signer plus the earlier signature-timestamp TSA.
        let roots = [self.statuses; 2];
        let closed = earlier.close_statuses(&roots, self.nodes, access).unwrap();
        let x509 = structured_ltv::material::archived_participants(
            &closed,
            index,
            chain.coverage,
            chain.evidence,
            access,
        )
        .unwrap();
        let format = material::credentials::check(
            census,
            chain.counters,
            chain.prior.required(),
            index,
            &material::credentials::Scope::before_archive(chain.coverage, chain.evidence),
            &NoCredentials,
            access,
        )
        .unwrap();
        let pair = baseline::archive_material(&x509, &format, access).unwrap();
        let reports = [&pair];
        let census = baseline::archives(chain.prepared, &reports, access).unwrap();
        assert!(census.all_archive_material_covered());
        let assessed = baseline::assess(baseline::Evidence::Archival {
            long_term: self.long_term,
            archives: &census,
        });
        if same {
            let level = assessed.unwrap();
            assert_eq!(level.requested(), unsigned::Requirements::Archival);
            assert!(level.all_requirements_met());
        } else {
            assert!(matches!(assessed, Err(baseline::LevelError::Foreign)));
        }
    }
}
