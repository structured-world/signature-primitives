//! Source-paired CRL field/digest composition, not dummy-signature trust.

use super::*;
use digest::Error::Provider;
use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount},
};
use structured_pkix::crl::CertificateList;
use structured_xades::{
    properties::{CalendarFact, CalendarValue},
    validation::{self, CrlValueError, ReferenceTime},
};
use validation::ReferenceDigestError::Digest;

fn calendar() -> CalendarValue<'static> {
    CalendarValue {
        negative_year: false,
        year_digits: "2026",
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
        fraction_digits: None,
        timezone_minutes: Some(0),
    }
}

fn original(bytes: &[u8], with_identifier: bool) -> Tree {
    let (mut xml, _) = fixture(material::Kind::Crl, bytes.to_vec(), true);
    if with_identifier {
        let entry = xml
            .nodes
            .iter()
            .position(|node| {
                matches!(
                    node.value,
                    super::super::super::Node::Element(Name {
                        namespace: XADES,
                        local: "CRLRef"
                    })
                )
            })
            .unwrap();
        let id = add(&mut xml, entry, XADES, "CRLIdentifier");
        let issuer = add(&mut xml, id, XADES, "Issuer");
        let time = add(&mut xml, id, XADES, "IssueTime");
        xml.text_routes.push((issuer, "CN=A"));
        xml.calendar_routes
            .push((time, CalendarFact::Value(calendar())));
    }
    xml
}

fn assert_calendar_and_issuer(
    xml: &mut Tree,
    refs: &validation::ReferenceProperty<usize, u8, u8>,
    actual: &CertificateList<'_>,
    operation: &structured_asn1::Reader<'_>,
    query: &Memory,
) {
    for (fact, expected, hashes) in [
        (
            CalendarFact::Value(CalendarValue {
                second: 1,
                ..calendar()
            }),
            ReferenceTime::Differs,
            1,
        ),
        (
            CalendarFact::Value(CalendarValue {
                timezone_minutes: None,
                ..calendar()
            }),
            ReferenceTime::TimezoneUnstated,
            1,
        ),
        (CalendarFact::Malformed, ReferenceTime::Malformed, 0),
        (CalendarFact::Unsupported, ReferenceTime::Unsupported, 0),
    ] {
        xml.calendar_routes[0].1 = fact;
        let provider = Oracle::new(Mode::Ready);
        let result =
            validation::check_crl_value_reference(xml, refs, 0, actual, &provider, operation)
                .unwrap()
                .unwrap();
        assert!(!result.agrees());
        assert_eq!(result.identity().unwrap().value.issued_at(), expected);
        assert_eq!(result.digest().is_some(), hashes != 0);
        assert_eq!(provider.started.get(), hashes);
        assert_eq!(query.used(), 0);
    }
    xml.calendar_routes[0].1 = CalendarFact::Value(calendar());
    xml.text_routes[0].1 = "CN=other";
    let result = validation::check_crl_value_reference(
        xml,
        refs,
        0,
        actual,
        &Oracle::new(Mode::Ready),
        operation,
    )
    .unwrap()
    .unwrap();
    assert!(!result.agrees());
    assert!(!result.identity().unwrap().value.issuer_matches());
    assert_eq!(
        result.digest(),
        Some(validation::ReferenceDigest::Compared(Agreement::Matches))
    );
    xml.text_routes[0].1 = "CN=A";
}

#[test]
fn crl_value_combines_fields_and_digest_of_the_same_original_list() {
    // Different original CRLs cannot supply independent successful halves.
    // Optional identifier absence is valid when the digest identifies the list;
    // unknown/malformed calendar facts do not invoke the selected provider.
    let bytes = super::super::super::readable_crl_fixture(b"260101000000Z");
    let other = super::super::super::readable_crl_fixture(b"260101000001Z");
    let storage = funded();
    let origin = Parser::der(storage.clone());
    let actual = CertificateList::read(&origin, &bytes, 400).unwrap();
    let second = CertificateList::read(&origin, &other, 700).unwrap();
    for with_identifier in [false, true] {
        let mut xml = original(&bytes, with_identifier);
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), &storage),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let refs = &prepared.validation_references()[0];
        let held = storage.used();
        let spent = storage.work_used();
        let query = funded();
        let parser = Parser::der(query.clone());
        let operation = parser.read(&[], 900).unwrap();
        let provider = Oracle::new(Mode::Ready);
        let result =
            validation::check_crl_value_reference(&xml, refs, 0, &actual, &provider, &operation)
                .unwrap()
                .unwrap();
        assert!(result.agrees());
        assert_eq!(result.identity().is_some(), with_identifier);
        assert!(core::ptr::eq(result.actual(), &raw const actual));
        assert!(core::ptr::eq(result.references(), refs));
        assert_eq!(result.entry(), 0);
        assert_eq!(
            result.digest(),
            Some(validation::ReferenceDigest::Compared(Agreement::Matches))
        );
        assert_eq!(provider.started.get(), 1);
        assert_eq!(provider.one_shot.get(), 0);
        assert_eq!(query.used(), 0);
        assert_eq!(storage.used(), held);
        assert_eq!(storage.work_used(), spent);
        if !with_identifier {
            continue;
        }
        assert_calendar_and_issuer(&mut xml, refs, &actual, &operation, &query);
        // Rewrite only the original fixture's declared digest to the other
        // list. Pairing to actual B now fails time, pairing to A fails digest.
        let digest_node = refs.entries()[0].digest().unwrap().1;
        xml.binary_routes
            .iter_mut()
            .find(|(node, _)| *node == digest_node)
            .unwrap()
            .1 = Sha256::digest(&other).to_vec();
        for (value, identity, digest) in [
            (&actual, ReferenceTime::Matches, Agreement::Differs),
            (&second, ReferenceTime::Differs, Agreement::Matches),
        ] {
            let result = validation::check_crl_value_reference(
                &xml,
                refs,
                0,
                value,
                &Oracle::new(Mode::Ready),
                &operation,
            )
            .unwrap()
            .unwrap();
            assert!(!result.agrees());
            assert_eq!(result.identity().unwrap().value.issued_at(), identity);
            assert_eq!(
                result.digest(),
                Some(validation::ReferenceDigest::Compared(digest))
            );
        }
        assert_eq!(storage.used(), held);
        assert_eq!(storage.work_used(), spent);
        assert_eq!(query.used(), 0);
    }
}

#[test]
fn crl_value_retains_current_budget_source_and_provider_refusals() {
    // Successful metadata is not credit for another query. A final guard
    // refusal cannot return a successful prefix or charge the retained source.
    let bytes = super::super::super::readable_crl_fixture(b"260101000000Z");
    let xml = original(&bytes, true);
    let storage = funded();
    let origin = Parser::der(storage.clone());
    let actual = CertificateList::read(&origin, &bytes, 400).unwrap();
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), &storage),
        0,
        unsigned::Requirements::Basic,
        None,
    )
    .unwrap();
    let refs = &prepared.validation_references()[0];
    let held = storage.used();
    let spent = storage.work_used();
    let measured = funded();
    let parser = Parser::der(measured.clone());
    let operation = parser.read(&[], 900).unwrap();
    assert!(
        validation::check_crl_value_reference(
            &xml,
            refs,
            0,
            &actual,
            &Oracle::new(Mode::Ready),
            &operation
        )
        .unwrap()
        .unwrap()
        .agrees()
    );
    let needed = measured.work_used();
    for aggregate in [false, true] {
        for exact in [false, true] {
            let limit = needed - usize::from(!exact);
            let memory = Memory::new(Arc::new(MemoryAccount::new(
                1 << 20,
                if aggregate { limit } else { 1 << 28 },
            )));
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: if aggregate { 1 << 28 } else { limit as u64 },
                    ..Limits::default()
                },
                memory.clone(),
            );
            let operation = parser.read(&[], 900).unwrap();
            let result = validation::check_crl_value_reference(
                &xml,
                refs,
                0,
                &actual,
                &Oracle::new(Mode::Ready),
                &operation,
            );
            if exact {
                assert!(result.unwrap().unwrap().agrees());
            } else {
                assert!(matches!(
                    result,
                    Err(CrlValueError::Access(AccessError::Resource {
                        cause: MemoryError::WorkExceeded,
                        ..
                    }))
                ));
            }
            assert_eq!(memory.used(), 0);
        }
    }
    let provider = Oracle::new(Mode::RefuseUpdate);
    assert!(matches!(
        validation::check_crl_value_reference(&xml, refs, 0, &actual, &provider, &operation),
        Err(CrlValueError::Digest(binary::Error::Callback {
            cause: Digest(Provider(Failure::Refused)),
            ..
        }))
    ));
    let provider = Oracle::new(Mode::Ready);
    assert!(matches!(
        validation::check_crl_value_reference(
            &xml,
            refs,
            usize::MAX,
            &actual,
            &provider,
            &operation
        ),
        Err(CrlValueError::Index { index: usize::MAX })
    ));
    assert_eq!(provider.started.get(), 0);
    xml.generation.set(xml.generation.get() + 1);
    assert!(matches!(
        validation::check_crl_value_reference(&xml, refs, 0, &actual, &provider, &operation),
        Err(CrlValueError::Access(AccessError::Changed { .. }))
    ));
    assert_eq!(provider.started.get(), 0);
    assert_eq!(measured.used(), 0);
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), spent);
}
