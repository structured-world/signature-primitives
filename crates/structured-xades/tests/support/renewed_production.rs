//! Construction and checking share actual ReferenceOutput/canonical inputs.

use super::super::lifecycle::{Draft, Written};
use super::*;

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
        fixture.digest,
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
    assert_eq!(writer.events[2], Written::Method(fixture.digest));
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
            fixture.digest,
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
        fixture.digest,
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
