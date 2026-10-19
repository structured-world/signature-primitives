//! Composition evidence with real TSP/path math and synthetic XML framing.

use super::{Tree, attribute_checks, funded, timestamp_oracle, xml_digest};
use structured_asn1::memory::{MemoryError, Work};
use structured_ltv::{baseline as composed, pki};
use structured_xades::{
    baseline, certificate, hashes, prepare, timestamp, unsigned,
    xml::{Access, Xml},
};

#[path = "baseline_archival.rs"]
mod archival;
#[path = "baseline_values.rs"]
mod values;

/// The format-neutral time report over this format's basic stage.
type TimedReport<'a, 'c, 'd, 'r, 'p, 'v, 'bd> = composed::Timed<
    'a,
    'c,
    'd,
    baseline::Basic<'r, 'p, 'v, 'bd, usize, u8, u8>,
    certificate::CheckedPathCertificate<'v, 'bd, usize, u8, u8>,
    usize,
    u8,
    u8,
    structured_xades::Xades,
>;

fn fixture(
    leaf: &[u8],
    root: &[u8],
    pool: values::Pool,
) -> (Tree, timestamp_oracle::Oracle, Vec<u8>) {
    // Only the XML framing is synthetic. The signed timestamp covers exactly
    // the original selected SignatureValue projection emitted by that owner.
    use structured_cms::stream;
    let memory = funded();
    let mut xml = attribute_checks::fixture();
    xml.date_time = structured_xades::properties::DateTimeFact::Valid {
        timezone_minutes: Some(0),
    };
    xml.key_association = certificate::KeyAssociation::Same;
    xml_digest::basic_binary_routes(&mut xml, leaf, root, 0);
    xml.hash_completeness = hashes::HashCompleteness::Complete;
    xml.hash_uses.push(hashes::HashUse {
        signature: 0,
        origin: hashes::HashOrigin::SignatureMessage {
            instruction: 0,
            method: None,
        },
        state: hashes::HashUseState::Complete(hashes::HashClass::OtherKnown),
    });
    values::incorporate(&mut xml, leaf, root, pool);
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), &memory),
        0,
        unsigned::Requirements::Timestamped,
        None,
    )
    .unwrap();
    let stamp = &prepared.timestamps()[0];
    let mut input = timestamp::Input::prepare(&xml, prepared.bound(), stamp, &memory).unwrap();
    let mut sink = super::Collect::new(&memory);
    stream::run(&mut input, &mut sink, &memory, "fixture", 0).unwrap();
    let (provider, token, tsa, _) = timestamp_oracle::fixture_with_root(sink.bytes());
    xml.binary = token;
    (xml, provider, tsa)
}

#[test]
fn timed_assembly_keeps_full_original_token_census_and_current_query_refusal() {
    for pool in [
        values::Pool::Absent,
        values::Pool::Complete,
        values::Pool::CompleteOnly,
        values::Pool::DeltaOnly,
    ] {
        for requested in [
            unsigned::Requirements::Timestamped,
            unsigned::Requirements::LongTerm,
        ] {
            run_timed_assembly(pool, requested);
        }
    }
}

fn run_timed_assembly(pool: values::Pool, requested: unsigned::Requirements) {
    // Static B-T composition cannot omit an original TSA, replay token math,
    // substitute a cached successful timestamp for query funding or treat a
    // certificate-path interval as an application trust/chronology verdict.
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    xml_digest::with_checked_path(|path, leaf, root, memory| {
        let (xml, provider, tsa) = fixture(leaf, root, pool);
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, requested, None).unwrap();
        let fields = prepare::check_fields(&prepared, &access).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        let hashes::ParticipantBinding::Bound(hashes) =
            hashes::check_participants(&prepared, &counters, &access).unwrap()
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
        let tsa = structured_pkix::Certificate::read(&parser, &tsa, 400).unwrap();
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
        let actor = timestamp::Check {
            xml: &xml,
            provider: &provider,
            context: &context,
        }
        .retain_actor(
            prepared.bound(),
            &prepared.timestamps()[0],
            0,
            &operation,
            |_, _| Ok::<_, ()>(false),
        )
        .unwrap()
        .unwrap();
        let pki::TimestampBinding::Bound(tsa_path) =
            path.bind_timestamp(&actor, &utc, memory).unwrap()
        else {
            panic!("actual TSA/path/full generation")
        };
        let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
        let required = timestamp::requirements_with_counters(
            &access,
            &prepared,
            &stamps,
            timestamp::TimestampSelection::All,
        )
        .unwrap();
        assert!(matches!(
            required.bind_paths(&[], &access).unwrap(),
            structured_ltv::timestamp::TimestampPathBinding::Unproven(
                structured_ltv::timestamp::TimestampPathFailure::Count
            )
        ));
        let supplied = [&tsa_path];
        let structured_ltv::timestamp::TimestampPathBinding::Bound(paths) =
            required.bind_paths(&supplied, &access).unwrap()
        else {
            panic!("complete original token census")
        };
        let held = memory.used();
        let timed = composed::timestamped(&basic, &paths, &access).unwrap();
        assert_static_time(&timed, &basic, &paths);
        assert_timed_level(&timed, requested);
        assert_eq!(provider.verified.get(), 1);
        check_material(
            &timed,
            &paths,
            path,
            &xml,
            &operation,
            &access,
            pool == values::Pool::Complete,
        );
        assert_current_query(&timed, &xml);
        drop(timed);
        assert_eq!(memory.used(), held);
    });
}

fn assert_static_time(
    timed: &TimedReport<'_, '_, '_, '_, '_, '_, '_>,
    basic: &baseline::Basic<'_, '_, '_, '_, usize, u8, u8>,
    paths: &structured_ltv::timestamp::TimestampPaths<
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
) {
    // Both the successful interval and exact input receipts survive assembly;
    // a report about an equivalent-looking second input would be insufficient.
    assert!(timed.all_static_time_requirements_met());
    assert!(core::ptr::eq(timed.basic(), basic));
    assert!(core::ptr::eq(timed.paths(), paths));
    assert_eq!(timed.signatures().len(), 1);
    assert!(matches!(
        timed.signatures()[0],
        composed::SignatureTimeFact::Bound(_)
    ));
}

fn assert_timed_level(
    timed: &TimedReport<'_, '_, '_, '_, '_, '_, '_>,
    requested: unsigned::Requirements,
) {
    // A B-T report answers only a B-T request: a B-LT preparation also
    // requires validation material, which these time facts do not carry.
    let assessed = baseline::assess(baseline::Evidence::timestamped(timed));
    if requested == unsigned::Requirements::Timestamped {
        let level = assessed.unwrap();
        assert_eq!(level.requested(), requested);
        assert!(level.all_requirements_met());
    } else {
        assert!(matches!(
            assessed,
            Err(baseline::LevelError::Mismatch {
                requested: unsigned::Requirements::LongTerm,
                supplied: unsigned::Requirements::Timestamped,
            })
        ));
    }
}

type LongTermReport<'a> = composed::LongTerm<
    'a,
    TimedReport<'a, 'a, 'a, 'a, 'a, 'a, 'a>,
    structured_xades::material::Checks<'a, 'a, 'a, 'a, 'a, usize, u8, u8>,
    structured_xades::material::credentials::Report<'a, 'a, 'a, (), usize, u8, u8>,
>;

fn assert_long_term_level(report: &LongTermReport<'_>, complete: bool) {
    // B-LT is met only when the incorporated material is complete; an absent
    // or partial pool keeps the level negative instead of falling back to B-T.
    let assessed = baseline::assess(baseline::Evidence::LongTerm(report));
    let requested = report
        .timed()
        .basic()
        .inputs()
        .fields
        .prepared()
        .requirements();
    if requested == unsigned::Requirements::LongTerm {
        let level = assessed.unwrap();
        assert_eq!(level.requested(), requested);
        assert_eq!(level.all_requirements_met(), complete);
    } else {
        assert!(matches!(
            assessed,
            Err(baseline::LevelError::Mismatch {
                requested: unsigned::Requirements::Timestamped,
                supplied: unsigned::Requirements::LongTerm,
            })
        ));
    }
}

fn assert_current_query(timed: &TimedReport<'_, '_, '_, '_, '_, '_, '_>, xml: &Tree) {
    // Cached interval facts do not pay for a later operation's source/selection
    // checks, and a refused query must not retain partial report capacity.
    let denied = structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(65_536, 0),
    ));
    let query = Access::new(xml, xml.snapshot(), &denied);
    assert!(matches!(
        composed::timestamped(timed.basic(), timed.paths(), &query),
        Err(composed::TimeError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert_eq!(denied.used(), 0);
}

struct NoCredentials;

impl<'p, 'd> structured_xades::credential::Provider<'p, 'd, Tree> for NoCredentials {
    type Evidence = ();
    type Error = MemoryError;
    fn authenticate<W: Work>(
        &self,
        _: &Access<'_, Tree, W>,
        _: structured_xades::credential::Credential<usize, u8, u8>,
    ) -> Result<structured_xades::credential::Authentication<'p, 'd, ()>, MemoryError> {
        panic!("this original signature declares no credential")
    }
}

impl structured_xades::material::credentials::Provider<Tree, ()> for NoCredentials {
    type Error = MemoryError;
    fn visit<VE, W: Work>(
        &self,
        _: &structured_xades::credential::Checked<'_, '_, (), usize, u8, u8>,
        _: &[structured_xades::material::Opaque<usize, u8, u8>],
        _: &Access<'_, Tree, W>,
        _: impl for<'v, 'd> FnMut(
            structured_xades::material::credentials::Need<'v, 'd, usize, u8, u8>,
        ) -> Result<(), VE>,
    ) -> Result<
        structured_xades::material::credentials::Completeness,
        structured_xades::reference::VisitError<MemoryError, VE>,
    > {
        panic!("absence of original credentials needs no format handler")
    }
}

fn check_material(
    timed: &TimedReport<'_, '_, '_, '_, '_, '_, '_>,
    paths: &structured_ltv::timestamp::TimestampPaths<
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    path: &pki::CheckedPath<'_>,
    xml: &Tree,
    operation: &structured_asn1::Reader<'_>,
    access: &Access<'_, Tree, structured_asn1::memory::Memory>,
    complete: bool,
) {
    // Exact empty credential catalogues are still distinct receipts. A second
    // successful collection cannot be substituted into the first actor closure.
    // Missing incorporated CRL/issuer bytes stay negative after composition.
    use structured_xades::{credential, material};
    let basic = timed.basic().inputs();
    let prepared = basic.fields.prepared();
    let credentials =
        credential::check_participants(prepared, basic.counters, &NoCredentials, access).unwrap();
    let other =
        credential::check_participants(prepared, basic.counters, &NoCredentials, access).unwrap();
    let participants = structured_xades::pki::participants(
        basic.certificate,
        basic.counters,
        &credentials,
        paths,
        access,
    )
    .unwrap();
    xml_digest::with_original_delta_statuses(path, access.execution(), |statuses| {
        let roots = [statuses; 2];
        let nodes = [pki::AuthorityNode {
            statuses,
            responders: &[],
        }];
        let closure = participants.close_statuses(&roots, &nodes, access).unwrap();
        material::with_counter_values(xml, prepared, basic.counters, operation, |query, view| {
            let work = query.execution();
            let access = Access::new(xml, xml.snapshot(), &work);
            let index = material::index(&view, &access).unwrap();
            let x509 =
                material::check_participants(prepared, &closure, basic.counters, &index, &access)
                    .unwrap();
            let format = material::credentials::check(
                &credentials,
                basic.counters,
                paths.required(),
                &index,
                &material::credentials::Scope::whole(),
                &NoCredentials,
                &access,
            )
            .unwrap();
            let report = composed::long_term(timed, &x509, &format, &access).unwrap();
            assert!(core::ptr::eq(report.timed(), timed));
            assert!(core::ptr::eq(report.x509(), &raw const x509));
            assert!(report.credentials().all_requirements_met());
            assert_eq!(report.all_material_requirements_met(), complete);
            assert_long_term_level(&report, complete);
            let foreign = material::credentials::check(
                &other,
                basic.counters,
                paths.required(),
                &index,
                &material::credentials::Scope::whole(),
                &NoCredentials,
                &access,
            )
            .unwrap();
            assert!(matches!(
                composed::long_term(timed, &x509, &foreign, &access),
                Err(pki::ParticipantError::Foreign { signature: 0 })
            ));
            Ok::<_, ()>(())
        })
        .unwrap();
    });
}
