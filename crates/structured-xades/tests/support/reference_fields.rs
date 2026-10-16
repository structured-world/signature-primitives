//! Scripted XML scalar facts over complete Annex A reference structures.

use super::*;
use structured_xades::{
    scalar::{self, Datatype, Fact},
    validation::{ReferenceFieldError, ReferenceKind, check_reference_fields},
};

impl structured_xades::scalar::TextXml for Tree {
    fn with_text<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        source: LexicalSource<'_>,
        work: &W,
        visitor: impl for<'view> FnOnce(structured_xades::scalar::TextValue<'view>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Cause, VE>> {
        self.check(snapshot, node).map_err(VisitError::Processing)?;
        assert_eq!(source, LexicalSource::SimpleContent);
        for (original, text) in &self.text_routes {
            work.charge_work(1)
                .map_err(|cause| VisitError::Processing(Cause::Resource(cause)))?;
            if *original == node {
                work.charge_work(text.len() as u64)
                    .map_err(|cause| VisitError::Processing(Cause::Resource(cause)))?;
                return visitor(structured_xades::scalar::TextValue::Present(text))
                    .map_err(VisitError::Visitor);
            }
        }
        Err(VisitError::Processing(Cause::Source))
    }
}

impl properties::CalendarXml for Tree {
    fn with_calendar<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        work: &W,
        visitor: impl for<'view> FnOnce(properties::CalendarFact<'view>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Cause, VE>> {
        self.check(snapshot, node).map_err(VisitError::Processing)?;
        for (original, value) in &self.calendar_routes {
            work.charge_work(1)
                .map_err(|cause| VisitError::Processing(Cause::Resource(cause)))?;
            if *original == node {
                return visitor(*value).map_err(VisitError::Visitor);
            }
        }
        Err(VisitError::Processing(Cause::Source))
    }
}

struct Fixture {
    xml: Tree,
    crl_time: usize,
    number: usize,
    cert_digest: usize,
    cert: usize,
}

fn add(xml: &mut Tree, parent: usize, namespace: &'static str, local: &'static str) -> usize {
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(parent), namespace, local));
    node
}

fn digest(xml: &mut Tree, parent: usize, local: &'static str) -> usize {
    let digest = add(xml, parent, XADES, local);
    let method = add(xml, digest, DS, "DigestMethod");
    xml.digest_algorithms
        .push((method, "http://www.w3.org/2001/04/xmlenc#sha256"));
    add(xml, digest, DS, "DigestValue")
}

fn fixture(number_fact: Fact) -> Fixture {
    // Only field routing is scripted. Structure/cardinality use the actual
    // public preparation path, including the imported V2 Cert grammar.
    let mut xml = attribute_checks::fixture();
    xml.date_time = properties::DateTimeFact::Valid {
        timezone_minutes: Some(0),
    };
    let certificates = add(&mut xml, 7, XADES_141, "CompleteCertificateRefsV2");
    let list = add(&mut xml, certificates, XADES_141, "CertRefs");
    let cert = add(&mut xml, list, XADES, "Cert");
    let cert_digest = digest(&mut xml, cert, "CertDigest");
    add(&mut xml, cert, XADES, "IssuerSerialV2");
    let references = add(&mut xml, 7, XADES, "CompleteRevocationRefs");
    let crls = add(&mut xml, references, XADES, "CRLRefs");
    let crl = add(&mut xml, crls, XADES, "CRLRef");
    digest(&mut xml, crl, "DigestAlgAndValue");
    let identifier = add(&mut xml, crl, XADES, "CRLIdentifier");
    add(&mut xml, identifier, XADES, "Issuer");
    let crl_time = add(&mut xml, identifier, XADES, "IssueTime");
    let number = add(&mut xml, identifier, XADES, "Number");
    xml.scalar_routes
        .push(scalar_checks::route(number, Datatype::Integer, number_fact));
    let ocsps = add(&mut xml, references, XADES, "OCSPRefs");
    let ocsp = add(&mut xml, ocsps, XADES, "OCSPRef");
    let identifier = add(&mut xml, ocsp, XADES, "OCSPIdentifier");
    let responder = add(&mut xml, identifier, XADES, "ResponderID");
    add(&mut xml, responder, XADES, "ByKey");
    add(&mut xml, identifier, XADES, "ProducedAt");
    digest(&mut xml, ocsp, "DigestAlgAndValue");
    let others = add(&mut xml, references, XADES, "OtherRefs");
    let opaque = add(&mut xml, others, XADES, "OtherRef");
    add(&mut xml, opaque, "urn:fixture:opaque", "application-format");
    Fixture {
        xml,
        crl_time,
        number,
        cert_digest,
        cert,
    }
}

fn prepare(xml: &Tree, memory: &Memory) -> prepare::Prepared<Tree> {
    prepare::prepare(
        &Access::new(xml, xml.snapshot(), memory),
        0,
        unsigned::Requirements::Timestamped,
        None,
    )
    .unwrap()
}

#[test]
fn empty_complete_revocation_references_are_not_permitted_by_annex_a_semantics() {
    // The XSD makes each group optional, but EN319132-1 A.1.2 expressly
    // prohibits incorporating an empty CompleteRevocationRefs property.
    let mut xml = attribute_checks::fixture();
    let node = add(&mut xml, 7, XADES, "CompleteRevocationRefs");
    let memory = funded();
    assert!(
        matches!(prepare::prepare(&Access::new(&xml, xml.snapshot(), &memory), 0,
        unsigned::Requirements::Timestamped, None),
        Err(prepare::Error::Property(properties::Error::Missing {parent, local: "CRLRefs, OCSPRefs or OtherRefs"})) if parent == node)
    );
    assert_eq!(memory.used(), 0);
}

#[test]
fn ocsp_by_key_uses_the_shared_der_field_kernel_and_original_location() {
    // Annex A encodes the byKey FIELD, including its explicit wrapper; naked
    // hashes and BER/nonminimal spellings must not become valid DER hints.
    let mut f = fixture(Fact::Valid);
    let memory = funded();
    let prepared = prepare(&f.xml, &memory);
    let references = &prepared.validation_references()[1];
    let validation::ReferenceIdentifier::Ocsp {
        responder: validation::ResponderIdentifier::Key(node),
        ..
    } = references.entries()[1].identifier()
    else {
        panic!("original ByKey")
    };
    let mut encoded = vec![0xa2, 22, 4, 20];
    encoded.extend([0x33; 20]);
    f.xml.binary_routes.push((node, encoded.clone()));
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let held = memory.used();
    let reading = validation::with_responder_key(&f.xml, references, 1, &operation, |hash| {
        assert_eq!(hash, [0x33; 20]);
        Ok::<_, ()>(hash.len())
    })
    .unwrap()
    .unwrap();
    assert_eq!(
        reading.location,
        Location {
            snapshot: f.xml.snapshot(),
            node
        }
    );
    assert_eq!(reading.value, 20);
    assert_eq!(memory.used(), held);
    let mut trailing = encoded.clone();
    trailing.extend([5, 0]);
    let mut nonminimal = vec![0xa2, 0x81, 22];
    nonminimal.extend(&encoded[2..]);
    for bytes in [
        vec![0x33; 20],
        vec![0xa2, 3, 4, 1, 0x33],
        trailing,
        nonminimal,
    ] {
        f.xml.binary_routes.last_mut().unwrap().1 = bytes;
        let called = Cell::new(false);
        let result = validation::with_responder_key(&f.xml, references, 1, &operation, |_| {
            called.set(true);
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(binary::Error::Callback {
                cause: validation::ResponderKeyError::Encoding(_)
                    | validation::ResponderKeyError::Responder(_)
                    | validation::ResponderKeyError::Trailing { .. },
                ..
            })
        ));
        assert!(!called.get());
        assert_eq!(memory.used(), held);
    }
}

#[test]
fn ocsp_by_key_current_refusal_is_terminal_and_releases_decoding_capacity() {
    // Source-model retention does not fund a new query. Neither current local
    // work nor allocation refusal is an absent or mismatching responder key.
    let mut f = fixture(Fact::Valid);
    let original = funded();
    let prepared = prepare(&f.xml, &original);
    let references = &prepared.validation_references()[1];
    let validation::ReferenceIdentifier::Ocsp {
        responder: validation::ResponderIdentifier::Key(node),
        ..
    } = references.entries()[1].identifier()
    else {
        panic!("original ByKey")
    };
    let mut encoded = vec![0xa2, 22, 4, 20];
    encoded.extend([0x33; 20]);
    f.xml.binary_routes.push((node, encoded));
    let held = original.used();
    for (capacity, work) in [(0, 1_000_000), (1_000_000, 0)] {
        let query = Memory::new(Arc::new(MemoryAccount::new(capacity, work)));
        let parser = structured_asn1::Parser::der(query.clone());
        let operation = parser.read(&[], 900).unwrap();
        let called = Cell::new(false);
        let result = validation::with_responder_key(&f.xml, references, 1, &operation, |_| {
            called.set(true);
            Ok::<_, ()>(())
        });
        assert!(matches!(result, Err(binary::Error::Access { .. })));
        assert!(!called.get());
        assert_eq!(query.used(), 0);
        assert_eq!(original.used(), held);
    }
}

#[test]
fn original_issuer_and_responder_names_use_shared_rfc4514_and_current_query_limits() {
    // DN assertions compare through shared RFC4514/Name, not text equality,
    // private case-folding or serialization of the actual certificate name.
    let mut f = fixture(Fact::Valid);
    let original = funded();
    let initial = prepare(&f.xml, &original);
    let statuses = &initial.validation_references()[1];
    let validation::ReferenceIdentifier::Crl { issuer, .. } = statuses.entries()[0].identifier()
    else {
        panic!("issuer")
    };
    let validation::ReferenceIdentifier::Ocsp {
        responder: validation::ResponderIdentifier::Key(key),
        ..
    } = statuses.entries()[1].identifier()
    else {
        panic!("responder")
    };
    f.xml.nodes[key].value = Node::Element(Name {
        namespace: XADES,
        local: "ByName",
    });
    f.xml
        .text_routes
        .extend([(issuer, "CN=A"), (key, "cn=\\ A\\ ")]);
    let prepared = prepare(&f.xml, &original);
    let statuses = &prepared.validation_references()[1];
    let name_bytes = [0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 12, 1, b'a'];
    let parser = structured_asn1::Parser::der(original.clone());
    let mut reader = parser.read(&name_bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let actual = structured_pkix::name::read(&reader, &element, "issuer").unwrap();
    let held = original.used();
    let paid = original.work_used();
    let query_account = funded();
    let query_parser = structured_asn1::Parser::der(query_account.clone());
    let query = query_parser.read(&[], 900).unwrap();
    for index in 0..2 {
        assert_eq!(
            validation::matches_reference_name(&f.xml, statuses, index, &actual, &query).unwrap(),
            Some(true)
        );
    }
    assert_eq!(query_account.used(), 0);
    assert_eq!(original.used(), held);
    assert_eq!(original.work_used(), paid);
    f.xml.text_routes[0].1 = "CN=Different";
    assert_eq!(
        validation::matches_reference_name(&f.xml, statuses, 0, &actual, &query).unwrap(),
        Some(false)
    );
    f.xml.text_routes[0].1 = "CN=broken\\";
    assert!(
        matches!(validation::matches_reference_name(&f.xml,statuses,0,&actual,&query),Err(validation::ReferenceNameError::Name {node,cause}) if node == issuer && !cause.is_resource())
    );
    for (capacity, work) in [(0, 100_000), (100_000, 0)] {
        f.xml.text_routes[0].1 = "CN=A";
        let account = Memory::new(Arc::new(MemoryAccount::new(capacity, work)));
        let parser = structured_asn1::Parser::der(account.clone());
        let query = parser.read(&[], 900).unwrap();
        let result = validation::matches_reference_name(&f.xml, statuses, 0, &actual, &query);
        if capacity == 0 {
            assert!(
                matches!(result,Err(validation::ReferenceNameError::Name {node,cause}) if node == issuer && cause.is_resource())
            );
        } else {
            assert!(matches!(
                result,
                Err(validation::ReferenceNameError::Access(
                    AccessError::Resource { .. }
                ))
            ));
        }
        assert_eq!(account.used(), 0);
        assert_eq!(original.used(), held);
    }
}

#[test]
fn unsigned_certificate_hint_reuses_the_same_original_issuer_serial_reading() {
    // Unsigned CertIDListV2 imports the SAME issuer/serial type, but cannot
    // become protected SigningCertificateV2 or a successful certificate binding.
    let mut f = fixture(Fact::Valid);
    let memory = funded();
    let prepared = prepare(&f.xml, &memory);
    let references = &prepared.validation_references()[0];
    let validation::ReferenceIdentifier::Certificate {
        issuer_serial: node,
    } = references.entries()[0].identifier()
    else {
        panic!("original issuer/serial")
    };
    f.xml.binary_routes.push((
        node,
        vec![
            0x30, 21, 0x30, 16, 0xa4, 14, 0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1,
            b'a', 2, 1, 1,
        ],
    ));
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let held = memory.used();
    let read =
        validation::with_reference_issuer_serial(&f.xml, references, 0, &operation, |reading| {
            assert!(reading.faults().is_empty());
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        read.location,
        Location {
            snapshot: f.xml.snapshot(),
            node
        }
    );
    assert_eq!(memory.used(), held);
    let error = validation::with_reference_issuer_serial(&f.xml, references, 0, &operation, |_| {
        Err::<(), _>("caller refusal")
    })
    .unwrap_err();
    assert!(
        matches!(error,binary::Error::Callback {location,cause: certificate::IssuerError::Callback("caller refusal")} if location.node == node)
    );
    assert_eq!(memory.used(), held);
    // Preserve readable shared faults rather than silently discarding the hint.
    f.xml.binary_routes.last_mut().unwrap().1 = vec![0x30, 5, 0x30, 0, 2, 1, 7];
    let read =
        validation::with_reference_issuer_serial(&f.xml, references, 0, &operation, |reading| {
            assert!(!reading.faults().is_empty());
            Ok::<_, ()>(reading.faults().len())
        })
        .unwrap()
        .unwrap();
    assert_eq!(read.location.node, node);
    assert!(read.value > 0);
    assert_eq!(memory.used(), held);
}

#[test]
fn crl_identifier_composes_mandatory_fields_and_keeps_number_as_a_hint() {
    // Metadata comparison over a parsed list, NOT authentication of this
    // dummy-signature fixture. A written optional number cannot substitute
    // for issuer/time or silently impose a machine-width constraint.
    use properties::{CalendarFact, CalendarValue};
    use validation::{CrlReferenceError, ReferenceIdentifier, ReferenceTime, check_crl_reference};
    let mut f = fixture(Fact::Valid);
    let storage = funded();
    let prepared = prepare(&f.xml, &storage);
    let refs = &prepared.validation_references()[1];
    let ReferenceIdentifier::Crl {
        node,
        issuer,
        time,
        number,
    } = refs.entries()[0].identifier()
    else {
        panic!("original CRL identifier")
    };
    assert_eq!(number, Some(f.number));
    let bytes = readable_crl_fixture(b"260101000000Z");
    let origin = structured_asn1::Parser::der(storage.clone());
    let crl = structured_pkix::crl::CertificateList::read(&origin, &bytes, 400).unwrap();
    f.xml.text_routes.push((issuer, "CN=A"));
    let calendar = CalendarValue {
        negative_year: false,
        year_digits: "2026",
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
        fraction_digits: None,
        timezone_minutes: Some(0),
    };
    f.xml
        .calendar_routes
        .push((time, CalendarFact::Value(calendar)));
    let query = funded();
    let parser = structured_asn1::Parser::der(query.clone());
    let operation = parser.read(&[], 900).unwrap();
    let held = storage.used();
    let spent = storage.work_used();
    for (text, time_value, name_matches, time_matches) in [
        (
            "CN=A",
            CalendarFact::Value(calendar),
            true,
            ReferenceTime::Matches,
        ),
        (
            "CN=b",
            CalendarFact::Value(calendar),
            false,
            ReferenceTime::Matches,
        ),
        (
            "CN=A",
            CalendarFact::Value(CalendarValue {
                timezone_minutes: None,
                ..calendar
            }),
            true,
            ReferenceTime::TimezoneUnstated,
        ),
        (
            "CN=A",
            CalendarFact::Unsupported,
            true,
            ReferenceTime::Unsupported,
        ),
    ] {
        f.xml.text_routes[0].1 = text;
        f.xml.calendar_routes[0].1 = time_value;
        let result = check_crl_reference(&f.xml, refs, 0, &crl, &operation)
            .unwrap()
            .unwrap();
        assert_eq!(result.location.node, node);
        assert_eq!(result.value.issuer_matches(), name_matches);
        assert_eq!(result.value.issued_at(), time_matches);
        assert_eq!(result.value.number_hint(), number);
        assert_eq!(storage.used(), held);
        assert_eq!(storage.work_used(), spent);
        assert_eq!(query.used(), 0);
    }
    f.xml.calendar_routes.clear();
    assert!(matches!(
        check_crl_reference(&f.xml, refs, 0, &crl, &operation),
        Err(CrlReferenceError::Time(_))
    ));
    assert!(
        check_crl_reference(&f.xml, refs, 1, &crl, &operation)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        check_crl_reference(&f.xml, refs, 99, &crl, &operation),
        Err(CrlReferenceError::Index { index: 99 })
    ));
    assert_eq!(query.used(), 0);
}

#[test]
fn reference_times_preserve_timezone_end_of_day_and_all_fractional_digits() {
    // Only parsed XML components are scripted; actual PKIX time decoding,
    // Gregorian projection and the shared comparison run through public APIs.
    use properties::{CalendarFact as C, CalendarValue as V};
    use validation::ReferenceTime as T;
    let mut f = fixture(Fact::Valid);
    let memory = funded();
    let prepared = prepare(&f.xml, &memory);
    let references = &prepared.validation_references()[1];
    let parser = structured_asn1::Parser::der(memory.clone());
    let bytes = readable_crl_fixture(b"260101000000Z");
    let crl = structured_pkix::crl::CertificateList::read(&parser, &bytes, 400).unwrap();
    let actual = crl.tbs().this_update();
    let query_account = funded();
    let query_parser = structured_asn1::Parser::der(query_account.clone());
    let query = query_parser.read(&[], 900).unwrap();
    let base = V {
        negative_year: false,
        year_digits: "2026",
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
        fraction_digits: None,
        timezone_minutes: Some(0),
    };
    for (value, expected) in [
        (C::Value(base), T::Matches),
        (
            C::Value(V {
                year_digits: "2025",
                month: 12,
                day: 31,
                hour: 24,
                ..base
            }),
            T::Matches,
        ),
        (
            C::Value(V {
                hour: 2,
                minute: 30,
                timezone_minutes: Some(150),
                ..base
            }),
            T::Matches,
        ),
        (
            C::Value(V {
                fraction_digits: Some("000000000000000000000000000000000"),
                ..base
            }),
            T::Matches,
        ),
        (
            C::Value(V {
                fraction_digits: Some("000000000000000000000000000000001"),
                ..base
            }),
            T::Differs,
        ),
        (
            C::Value(V {
                year_digits: "18446744073709551616",
                ..base
            }),
            T::Differs,
        ),
        (
            C::Value(V {
                negative_year: true,
                year_digits: "0001",
                ..base
            }),
            T::Differs,
        ),
        (
            C::Value(V {
                timezone_minutes: None,
                ..base
            }),
            T::TimezoneUnstated,
        ),
        (C::Malformed, T::Malformed),
        (C::Unsupported, T::Unsupported),
    ] {
        f.xml.calendar_routes.clear();
        f.xml.calendar_routes.push((f.crl_time, value));
        assert_eq!(
            validation::matches_reference_time(&f.xml, references, 0, actual, &query).unwrap(),
            Some(expected)
        );
        assert_eq!(query_account.used(), 0);
    }
}

#[test]
fn reference_time_cannot_use_old_account_credit_past_current_local_work() {
    // Reusing a parsed CRL and retained XML model must not bypass a new
    // operation's zero local ceiling or return an incomplete comparison.
    let f = fixture(Fact::Valid);
    let memory = funded();
    let prepared = prepare(&f.xml, &memory);
    let references = &prepared.validation_references()[1];
    let parser = structured_asn1::Parser::der(memory.clone());
    let bytes = readable_crl_fixture(b"260101000000Z");
    let crl = structured_pkix::crl::CertificateList::read(&parser, &bytes, 400).unwrap();
    let actual = crl.tbs().this_update();
    let query_account = funded();
    let held = memory.used();
    let denied = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..Default::default()
        },
        query_account.clone(),
    );
    let query = denied.read(&[], 900).unwrap();
    assert!(matches!(
        validation::matches_reference_time(&f.xml, references, 0, actual, &query),
        Err(validation::ReferenceTimeError::Access(
            AccessError::Resource { .. }
        ))
    ));
    assert_eq!(memory.used(), held);
    assert_eq!(query_account.used(), 0);
}

#[test]
fn reference_time_keeps_xsd10_bce_and_extended_year_rollover() {
    // XSD1.0 -0001 is astronomical year zero. A timezone at the other end of
    // the supported PKIX range can produce XML year10000, not a narrowed9999.
    use properties::{CalendarFact as C, CalendarValue as V};
    let mut f = fixture(Fact::Valid);
    let memory = funded();
    let prepared = prepare(&f.xml, &memory);
    let references = &prepared.validation_references()[1];
    let parser = structured_asn1::Parser::der(memory.clone());
    let query_account = funded();
    let query_parser = structured_asn1::Parser::der(query_account.clone());
    let query = query_parser.read(&[], 900).unwrap();
    for (actual, value) in [
        (
            b"00000101000000Z".as_slice(),
            V {
                negative_year: true,
                year_digits: "0001",
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                fraction_digits: None,
                timezone_minutes: Some(0),
            },
        ),
        (
            b"99991231235959Z".as_slice(),
            V {
                negative_year: false,
                year_digits: "10000",
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 59,
                fraction_digits: None,
                timezone_minutes: Some(1),
            },
        ),
        (
            b"20161231235960Z".as_slice(),
            V {
                negative_year: false,
                year_digits: "2017",
                month: 1,
                day: 1,
                hour: 2,
                minute: 29,
                second: 60,
                fraction_digits: None,
                timezone_minutes: Some(150),
            },
        ),
        (
            b"00000228233000Z".as_slice(),
            V {
                negative_year: true,
                year_digits: "0001",
                month: 3,
                day: 1,
                hour: 0,
                minute: 30,
                second: 0,
                fraction_digits: None,
                timezone_minutes: Some(60),
            },
        ),
    ] {
        let bytes = readable_crl_fixture_as(actual, structured_pkix::time::Form::Generalized);
        let crl = structured_pkix::crl::CertificateList::read(&parser, &bytes, 400).unwrap();
        f.xml.calendar_routes.clear();
        f.xml.calendar_routes.push((f.crl_time, C::Value(value)));
        assert_eq!(
            validation::matches_reference_time(
                &f.xml,
                references,
                0,
                crl.tbs().this_update(),
                &query
            )
            .unwrap(),
            Some(validation::ReferenceTime::Matches)
        );
        assert_eq!(query_account.used(), 0);
    }
}

#[test]
fn reference_time_uses_xsd10_value_normalization_before_comparison() {
    // XSD1.0 dateTime §3.2.7.3 and Appendix E normalize second60 even at
    // timezone zero. Comparing raw calendar components loses that equality.
    use properties::{CalendarFact as C, CalendarValue as V};
    let mut f = fixture(Fact::Valid);
    let memory = funded();
    let prepared = prepare(&f.xml, &memory);
    let references = &prepared.validation_references()[1];
    let parser = structured_asn1::Parser::der(memory.clone());
    let query = parser.read(&[], 900).unwrap();
    let bytes =
        readable_crl_fixture_as(b"20161231235960Z", structured_pkix::time::Form::Generalized);
    let crl = structured_pkix::crl::CertificateList::read(&parser, &bytes, 400).unwrap();
    f.xml.calendar_routes.push((
        f.crl_time,
        C::Value(V {
            negative_year: false,
            year_digits: "2017",
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            fraction_digits: None,
            timezone_minutes: Some(0),
        }),
    ));
    assert_eq!(
        validation::matches_reference_time(&f.xml, references, 0, crl.tbs().this_update(), &query,)
            .unwrap(),
        Some(validation::ReferenceTime::Matches)
    );
}

#[test]
fn original_validation_reference_models_preserve_order_and_execute_all_field_kernels() {
    // Written optional properties must reach original scalar/base64 kernels,
    // while an open OtherRef stays opaque and never becomes authenticated data.
    let f = fixture(Fact::Valid);
    let original = funded();
    let prepared = prepare(&f.xml, &original);
    assert_eq!(prepared.validation_references().len(), 2);
    let certs = &prepared.validation_references()[0];
    assert_eq!(certs.role(), unsigned::Role::CertificateReferences);
    assert_eq!(certs.entries().len(), 1);
    assert_eq!(certs.entries()[0].node(), f.cert);
    assert_eq!(certs.entries()[0].kind(), ReferenceKind::Certificate);
    assert_eq!(certs.entries()[0].digest().unwrap().1, f.cert_digest);
    let issuer_serial = f.xml.element_child(f.cert, XADES, "IssuerSerialV2");
    assert!(
        matches!(certs.entries()[0].identifier(), validation::ReferenceIdentifier::Certificate {issuer_serial: node} if node == issuer_serial)
    );
    let statuses = &prepared.validation_references()[1];
    assert_eq!(statuses.entries().len(), 3);
    for (entry, kind) in statuses.entries().iter().zip([
        ReferenceKind::Crl,
        ReferenceKind::Ocsp,
        ReferenceKind::Other,
    ]) {
        assert_eq!(entry.kind(), kind);
    }
    let identifier = f.xml.nodes[f.crl_time].parent.unwrap();
    let issuer = f.xml.element_child(identifier, XADES, "Issuer");
    assert!(
        matches!(statuses.entries()[0].identifier(), validation::ReferenceIdentifier::Crl {node, issuer: original_issuer, time, number: Some(number)} if node == identifier && original_issuer == issuer && time == f.crl_time && number == f.number)
    );
    let identifier = f
        .xml
        .element_child(statuses.entries()[1].node(), XADES, "OCSPIdentifier");
    let responder = f.xml.element_child(identifier, XADES, "ResponderID");
    let by_key = f.xml.element_child(responder, XADES, "ByKey");
    let produced = f.xml.element_child(identifier, XADES, "ProducedAt");
    assert!(
        matches!(statuses.entries()[1].identifier(), validation::ReferenceIdentifier::Ocsp {node, responder: validation::ResponderIdentifier::Key(key), time} if node == identifier && key == by_key && time == produced)
    );
    let held = original.used();
    let paid = original.work_used();
    let query = funded();
    let fields =
        prepare::check_fields(&prepared, &Access::new(&f.xml, f.xml.snapshot(), &query)).unwrap();
    assert!(core::ptr::eq(fields.prepared(), &raw const prepared));
    assert_eq!(f.xml.date_time_calls.get(), 3);
    assert_eq!(query.used(), 0);
    assert_eq!(original.used(), held);
    assert_eq!(original.work_used(), paid);
    assert_eq!(f.xml.key_projection.get(), None);
    assert_eq!(f.xml.streamed.get(), 0);
}

#[test]
fn validation_reference_number_refusal_keeps_its_original_node_and_datatype() {
    // A late malformed/unsupported wide integer cannot be treated as absent,
    // narrowed to a machine sentinel or hidden by an earlier valid digest.
    for fact in [Fact::Malformed, Fact::Unsupported, Fact::ComplexContent] {
        let f = fixture(fact);
        let original = funded();
        let prepared = prepare(&f.xml, &original);
        let query = funded();
        assert!(
            matches!(prepare::check_fields(&prepared, &Access::new(&f.xml, f.xml.snapshot(), &query)),
            Err(prepare::FieldError::ValidationReference(ReferenceFieldError::Scalar(
                scalar::Error::Value {node, datatype: Datatype::Integer, fact: actual}
            ))) if node == f.number && actual == fact)
        );
        assert_eq!(query.used(), 0);
        assert_eq!(f.xml.key_projection.get(), None);
        assert_eq!(f.xml.streamed.get(), 0);
    }
}

#[test]
fn hint_datetime_accepts_unstated_zone_without_defaulting_the_signing_time() {
    // XSD permits an unstated zone in these identifiers; the distinct root
    // SigningTime obligation still requires its actual explicit zone.
    let mut f = fixture(Fact::Valid);
    f.xml.date_time = properties::DateTimeFact::Valid {
        timezone_minutes: None,
    };
    let original = funded();
    let prepared = prepare(&f.xml, &original);
    let query = funded();
    let access = Access::new(&f.xml, f.xml.snapshot(), &query);
    for reference in prepared.validation_references() {
        check_reference_fields(reference, &access).unwrap();
    }
    assert!(matches!(
        prepare::check_fields(&prepared, &access),
        Err(prepare::FieldError::UnprovenTime {
            cause: properties::ClaimedTimeFailure::TimezoneUnstated,
            ..
        })
    ));
    assert_eq!(query.used(), 0);
}

#[test]
fn validation_reference_time_and_binary_errors_keep_their_original_enclosures() {
    // Neither XML decoding refusal nor an invalid date is a missing reference
    // or digest mismatch, and the first actual field remains located.
    let mut f = fixture(Fact::Valid);
    f.xml.date_time = properties::DateTimeFact::Malformed;
    let original = funded();
    let prepared = prepare(&f.xml, &original);
    let query = funded();
    assert!(
        matches!(check_reference_fields(&prepared.validation_references()[1],
        &Access::new(&f.xml, f.xml.snapshot(), &query)),
        Err(ReferenceFieldError::Time {node, fact: properties::DateTimeFact::Malformed})
            if node == f.crl_time)
    );
    f.xml.decoding = Decoding::Refuse;
    assert!(
        matches!(check_reference_fields(&prepared.validation_references()[0],
        &Access::new(&f.xml, f.xml.snapshot(), &query)),
        Err(ReferenceFieldError::Binary {location, cause: AccessError::Xml(Cause::Source)})
            if location.node == f.cert_digest)
    );
    assert_eq!(query.used(), 0);
}

#[test]
fn validation_reference_field_queries_require_the_new_work_budget_before_callbacks() {
    // Retained catalogue storage does not fund a new query. A zero current
    // ceiling refuses before scalar or binary processing, leaving source holds.
    let f = fixture(Fact::Valid);
    let original = funded();
    let prepared = prepare(&f.xml, &original);
    let held = original.used();
    let denied = memory(0);
    assert!(matches!(
        check_reference_fields(
            &prepared.validation_references()[0],
            &Access::new(&f.xml, f.xml.snapshot(), &denied)
        ),
        Err(ReferenceFieldError::Access(AccessError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        }))
    ));
    assert_eq!(f.xml.scalar_calls.get(), 0);
    assert_eq!(f.xml.date_time_calls.get(), 0);
    assert_eq!(f.xml.decoded_pointer.get(), 0);
    assert_eq!(denied.used(), 0);
    assert_eq!(original.used(), held);
}
