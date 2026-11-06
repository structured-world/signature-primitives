//! Construction and checking share actual ReferenceOutput/canonical inputs.

use super::super::lifecycle::{Draft, Written};
use super::*;

impl renewed::MethodProvider<'_, Tree> for Oracle<'_> {
    fn resolve_new<W: Work>(
        &self,
        algorithm: &str,
        work: &W,
    ) -> Result<Resolution<Identity>, Failure> {
        work.charge_work(algorithm.len() as u64)
            .map_err(Failure::Resource)?;
        self.new_resolved.set(self.new_resolved.get() + 1);
        if self.refuse_new {
            return Err(Failure::Refused);
        }
        Ok(match algorithm {
            SHA256 | SHA256_ALIAS => Resolution::Supported(Identity::Sha256),
            SHA384 => Resolution::Supported(Identity::Sha384),
            MD5_ALIAS => Resolution::Supported(Identity::Md5),
            "" | " sha256 " => Resolution::Malformed,
            _ => Resolution::Unsupported,
        })
    }
}

#[test]
fn renewal_can_introduce_a_digest_absent_from_the_original_document() {
    // A real renewal can select a new algorithm absent from every source node.
    // Construction must not require publishing a dummy DigestMethod first.
    let mut fixture = fixture();
    fixture.xml.digest_algorithm = Some(SHA384);
    fixture.xml.digest_algorithms = vec![(fixture.old, SHA384)];
    let work = funded();
    let access = Access::new(&fixture.xml, fixture.xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let oracle = Oracle::default();
    let renewal = renewed::create(
        &fixture.xml,
        &bound,
        fixture.method,
        SHA256,
        &oracle,
        &work,
        |_, _| Ok(true),
    )
    .unwrap();
    assert_eq!(oracle.started.get(), 2);
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::Timestamped).unwrap();
    let mut writer = Draft::new(&fixture.xml, inventory.parent());
    renewal.write(&mut writer, &work).unwrap();
    assert!(
        writer
            .events
            .contains(&Written::Attribute("Algorithm", SHA256.to_owned()))
    );
}

#[test]
fn renewed_property_contains_actual_object_and_original_instruction_hashes() {
    // The new method hashes each selected instruction and its detached object
    // separately. A URI spelling cannot replace full semantic identity checks.
    let fixture = fixture();
    let work = funded();
    let access = Access::new(&fixture.xml, fixture.xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let oracle = Oracle::default();
    let renewal = renewed::create(
        &fixture.xml,
        &bound,
        fixture.method,
        SHA256,
        &oracle,
        &work,
        |candidate, _| Ok(candidate.reference == fixture.instruction),
    )
    .unwrap();
    assert_eq!(
        renewal.references().collect::<Vec<_>>(),
        [fixture.instruction]
    );
    assert_eq!(oracle.started.get(), 2);
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::Timestamped).unwrap();
    let mut writer = Draft::new(&fixture.xml, inventory.parent());
    renewal.write(&mut writer, &work).unwrap();
    let values: Vec<_> = writer
        .events
        .iter()
        .filter_map(|e| match e {
            Written::Binary(value) => Some(value.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(
        values,
        [
            fixture
                .xml
                .binary_routes
                .iter()
                .find(|(n, _)| *n == fixture.object)
                .unwrap()
                .1
                .as_slice(),
            fixture
                .xml
                .binary_routes
                .iter()
                .find(|(n, _)| *n == fixture.reference)
                .unwrap()
                .1
                .as_slice()
        ]
    );
    assert_eq!(
        writer.events[0],
        Written::Begin(XADES_141, "RenewedDigestsV2")
    );
    assert_eq!(writer.events[1], Written::Method(fixture.method));
    assert_eq!(writer.events[2], Written::Begin(DS, "DigestMethod"));
    assert_eq!(
        writer.events[3],
        Written::Attribute("Algorithm", SHA256.to_owned())
    );
    assert_eq!(writer.events[4], Written::End);
    assert_eq!(oracle.new_resolved.get(), 1);
    writer.events.clear();
    writer.base.document += 1;
    assert!(matches!(
        renewal.write(&mut writer, &work),
        Err(structured_xades::produce::Error::Foreign)
    ));
    assert_eq!(writer.events, []);
}

#[test]
fn renewal_preflights_all_selected_methods_and_never_returns_a_success_subset() {
    // Invalid selected origin, unchanged method and missing whole catalogue
    // all stop before hashing. A late provider failure drops partial state.
    for fault in 0..4 {
        let mut fixture = fixture();
        match fault {
            0 => fixture.xml.digest_algorithms = vec![(fixture.old, SHA256_ALIAS)],
            1 => {
                fixture.xml.reference_locations =
                    vec![(fixture.instruction, ObjectLocation::Unknown)];
            }
            2 => fixture.xml.reference_completeness = Completeness::Unchecked(0),
            _ => {}
        }
        let work = funded();
        let access = Access::new(&fixture.xml, fixture.xml.snapshot(), &work);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let oracle = Oracle {
            refuse_start: (fault == 3).then_some(2),
            ..Oracle::default()
        };
        let held = work.used();
        let result = renewed::create(
            &fixture.xml,
            &bound,
            fixture.method,
            SHA256,
            &oracle,
            &work,
            |_, _| Ok(true),
        );
        match fault {
            0 => assert!(matches!(
                result,
                Err(renewed::CreationError::Unchanged { .. })
            )),
            1 => assert!(matches!(
                result,
                Err(renewed::CreationError::Ineligible { .. })
            )),
            2 => assert!(matches!(
                result,
                Err(renewed::CreationError::Processing(
                    renewed::CheckError::Incomplete(_)
                ))
            )),
            _ => assert!(matches!(
                result,
                Err(renewed::CreationError::Processing(
                    renewed::CheckError::Digest { .. }
                ))
            )),
        }
        assert_eq!(work.used(), held);
        assert_eq!(oracle.started.get(), if fault == 3 { 2 } else { 0 });
    }
}

#[test]
fn no_selected_expiring_digest_emits_no_empty_renewal() {
    // A complete census with no selected renewal is real absence, not an empty
    // schema-invalid RenewedDigestsV2 or skipped completeness inspection.
    let fixture = fixture();
    let work = funded();
    let access = Access::new(&fixture.xml, fixture.xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let oracle = Oracle::default();
    let renewal = renewed::create(
        &fixture.xml,
        &bound,
        fixture.method,
        SHA256,
        &oracle,
        &work,
        |_, _| Ok(false),
    )
    .unwrap();
    assert!(renewal.is_empty());
    assert_eq!(oracle.started.get(), 0);
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::Timestamped).unwrap();
    let mut writer = Draft::new(&fixture.xml, inventory.parent());
    renewal.write(&mut writer, &work).unwrap();
    assert_eq!(writer.events, []);
}

#[test]
fn new_method_refusals_precede_digest_and_source_callbacks() {
    // Both literal and aliased forbidden algorithms fail before mathematics.
    // Parameter-required/unknown and malformed values retain distinct answers.
    use structured_xades::certificate::Agreement;
    for (uri, expected, calls) in [
        (
            "http://www.w3.org/2001/04/xmldsig-more#md5",
            Agreement::ProhibitedAlgorithm,
            0,
        ),
        (MD5_ALIAS, Agreement::ProhibitedAlgorithm, 1),
        ("urn:fixture:needs-parameters", Agreement::Unsupported, 1),
        (" sha256 ", Agreement::MalformedMethod, 1),
        ("", Agreement::MalformedMethod, 1),
    ] {
        let fixture = fixture();
        let work = funded();
        let access = Access::new(&fixture.xml, fixture.xml.snapshot(), &work);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let oracle = Oracle::default();
        let held = work.used();
        let result = renewed::create(
            &fixture.xml,
            &bound,
            fixture.method,
            uri,
            &oracle,
            &work,
            |_, _| panic!("new method must be admitted before selection"),
        );
        assert!(
            matches!(result, Err(renewed::CreationError::NewAlgorithm(answer)) if answer == expected)
        );
        assert_eq!(oracle.new_resolved.get(), calls);
        assert_eq!(oracle.resolved.get(), 0);
        assert_eq!(oracle.started.get(), 0);
        assert_eq!(work.used(), held);
    }
}

#[test]
fn new_method_preserves_exact_alias_and_is_not_resolved_again_when_written() {
    // Semantic aliases can name the same hash, but the emitted spelling must
    // remain exactly the selected value, not an OID/URI inferred from identity.
    let fixture = fixture();
    let work = funded();
    let access = Access::new(&fixture.xml, fixture.xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let oracle = Oracle::default();
    let renewal = renewed::create(
        &fixture.xml,
        &bound,
        fixture.method,
        SHA256_ALIAS,
        &oracle,
        &work,
        |_, _| Ok(true),
    )
    .unwrap();
    assert_eq!(oracle.new_resolved.get(), 1);
    assert_eq!(oracle.started.get(), 2);
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::Timestamped).unwrap();
    let mut writer = Draft::new(&fixture.xml, inventory.parent());
    renewal.write(&mut writer, &work).unwrap();
    assert!(
        writer
            .events
            .contains(&Written::Attribute("Algorithm", SHA256_ALIAS.to_owned()))
    );
    assert!(!writer.events.contains(&Written::Method(fixture.digest)));
    assert_eq!(oracle.new_resolved.get(), 1);
    assert_eq!(oracle.started.get(), 2);
}

#[test]
fn new_method_preserves_terminal_provider_and_exhausted_current_work() {
    // No fallback identity is invented on policy/backend refusal or resource
    // exhaustion, and neither path starts streaming or acquires source bytes.
    for exhausted in [false, true] {
        let fixture = fixture();
        let work = funded();
        let access = Access::new(&fixture.xml, fixture.xml.snapshot(), &work);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let oracle = Oracle {
            refuse_new: true,
            ..Oracle::default()
        };
        if exhausted {
            work.charge_work(work.work_remaining() as u64).unwrap();
        }
        let result = renewed::create(
            &fixture.xml,
            &bound,
            fixture.method,
            SHA256,
            &oracle,
            &work,
            |_, _| panic!("refused method must not select input"),
        );
        if exhausted {
            assert!(matches!(
                result,
                Err(renewed::CreationError::Input(
                    structured_xades::timestamp::InputError::Child(
                        structured_xades::xml::ChildError::Access(AccessError::Resource {
                            cause: MemoryError::WorkExceeded,
                            ..
                        })
                    )
                ))
            ));
            assert_eq!(oracle.new_resolved.get(), 0);
        } else {
            assert!(matches!(
                result,
                Err(renewed::CreationError::NewProvider(Failure::Refused))
            ));
            assert_eq!(oracle.new_resolved.get(), 1);
        }
        assert_eq!(oracle.started.get(), 0);
    }
}
