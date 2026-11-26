//! Original extended property production and consumption with shared source plans.

use super::{
    lifecycle::{Draft, Written},
    *,
};
use sha2::{Digest as _, Sha256};
use structured_asn1::Parser;
use structured_cms::timestamp::{Request, Requested, Response};
use structured_xades::{
    extended,
    produce::{self, ExtendedAugmentation},
    timestamp::{ExtendedKind, ReferenceSyntax},
};

fn add(xml: &mut Tree, parent: usize, ns: &'static str, local: &'static str) -> usize {
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(parent), ns, local));
    node
}

fn reference_prefix(xml: &mut Tree, syntax: ReferenceSyntax) -> [usize; 2] {
    let revocation = add(xml, 7, XADES, "CompleteRevocationRefs");
    let other = add(xml, revocation, XADES, "OtherRefs");
    add(xml, other, XADES, "OtherRef");
    let (ns, local) = match syntax {
        ReferenceSyntax::Original => (XADES, "CompleteCertificateRefs"),
        ReferenceSyntax::V2 => (XADES_141, "CompleteCertificateRefsV2"),
    };
    let certificates = add(xml, 7, ns, local);
    let certs = add(xml, certificates, ns, "CertRefs");
    let cert = add(xml, certs, XADES, "Cert");
    let digest = add(xml, cert, XADES, "CertDigest");
    add(xml, digest, DS, "DigestMethod");
    add(xml, digest, DS, "DigestValue");
    if syntax == ReferenceSyntax::Original {
        let issuer = add(xml, cert, XADES, "IssuerSerial");
        add(xml, issuer, DS, "X509IssuerName");
        add(xml, issuer, DS, "X509SerialNumber");
    }
    [revocation, certificates]
}

#[test]
fn c_hash_and_xl_value_bind_the_required_original_certificate() {
    // A matching C digest does not prove that the original XL value is present.
    // Both comparisons preserve the separately funded certificate source.
    let origin = funded();
    let input = candidate_certificate();
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 20_000,
            ..structured_asn1::Limits::default()
        },
        origin.clone(),
    );
    let certificate = structured_pkix::Certificate::read(&parser, &input, 100).unwrap();
    let required = [validation::ReferenceTarget::Certificate(&certificate)];
    let (mut xml, _, _) = Tree::stamped(Role::Signature);
    let syntax = ReferenceSyntax::Original;
    reference_prefix(&mut xml, syntax);
    let values = add(&mut xml, 7, XADES, "CertificateValues");
    add(&mut xml, values, XADES, "EncapsulatedX509Certificate");
    let work = funded();
    let hash = input.iter().fold(0, |hash, byte| hash ^ byte);
    for wire in [hash, hash ^ 1] {
        xml.binary = vec![wire];
        let access = Access::new(&xml, xml.snapshot(), &work);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let prepared = extended::prepare(&access, &bound, syntax).unwrap();
        let reference = &prepared.references()[1].entries()[0];
        let (method, _) = reference.digest().unwrap();
        let provider = WholeCertificate {
            mode: DigestMode::Available,
            method,
            calls: Cell::new(0),
            pointer: Cell::new(0),
        };
        let expected = if wire == hash {
            validation::RequiredReferences::Complete
        } else {
            validation::RequiredReferences::Unmatched(reference.node())
        };
        assert_eq!(
            validation::check_required_references(
                &xml,
                &prepared.references()[1],
                &required,
                &provider,
                &work,
            )
            .unwrap(),
            expected,
        );
        assert_eq!(
            extended::check_incorporation(&xml, &prepared.values()[0], &required, &work).unwrap(),
            Some(0),
        );
    }
    xml.binary = input.clone();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let catalogue = material::read(&access, values).unwrap();
    assert_eq!(
        extended::check_incorporation(&xml, &catalogue, &required, &work).unwrap(),
        None,
    );
    let producing = parser.execution_in(&origin);
    producing
        .charge_work(producing.work_remaining() as u64)
        .unwrap();
    assert!(matches!(
        extended::check_incorporation(&xml, &catalogue, &required, &work),
        Err(binary::Error::Callback {
            cause: MemoryError::WorkExceeded,
            ..
        }),
    ));
}

fn source_bytes(
    source: &mut impl stream::Source<Error = InputError<Cause, usize>>,
    work: &Memory,
) -> Vec<u8> {
    let mut output = Collect::new(work);
    stream::run(source, &mut output, work, "fixture", 0).unwrap();
    output.bytes().to_vec()
}

fn canonical_ids(input: &[u8]) -> Vec<usize> {
    input
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|entry| entry[0] == b'E')
        .map(|entry| usize::from(entry[1]))
        .collect()
}

#[test]
fn x1_and_x2_preserve_wire_order_in_both_vocabularies() {
    // Verify exactly the previously staged input after the token is inserted.
    // The order deliberately differs from the enumeration of allowed roles.
    for syntax in [ReferenceSyntax::Original, ReferenceSyntax::V2] {
        for x1 in [true, false] {
            let (mut xml, _, _) = Tree::stamped(Role::Signature);
            let refs = reference_prefix(&mut xml, syntax);
            let unrelated = add(&mut xml, 7, XADES, "CertificateValues");
            let method = add(&mut xml, 0, DS, "CanonicalizationMethod");
            let kind = if x1 {
                ExtendedKind::SignatureAndReferences(syntax)
            } else {
                ExtendedKind::ReferencesOnly(syntax)
            };
            let work = funded();
            let access = Access::new(&xml, xml.snapshot(), &work);
            let layout = container::locate(&access, 0).unwrap();
            let bound = binding::bind(&access, &layout).unwrap();
            let mut future =
                Input::prepare_extended_append(&xml, &bound, kind, method, &work).unwrap();
            let exact = source_bytes(&mut future, &work);
            let mut expected = if x1 { vec![12, 8] } else { vec![] };
            expected.extend(refs);
            assert_eq!(canonical_ids(&exact), expected);
            assert!(!expected.contains(&unrelated));
            drop(future);

            let name = kind.name();
            let stamp = add(&mut xml, 7, name.namespace, name.local);
            xml.nodes[method].parent = Some(stamp);
            add(&mut xml, stamp, XADES, "EncapsulatedTimeStamp");
            add(&mut xml, 7, XADES, "CompleteRevocationRefs");
            xml.generation.set(2);
            let access = Access::new(&xml, xml.snapshot(), &work);
            let layout = container::locate(&access, 0).unwrap();
            let bound = binding::bind(&access, &layout).unwrap();
            let stamp = timestamp::read_extended(&access, &bound, stamp, kind).unwrap();
            let mut actual = Input::prepare(&xml, &bound, &stamp, &work).unwrap();
            assert_eq!(source_bytes(&mut actual, &work), exact);
        }
    }
}

#[test]
fn c_x_xl_and_archive_inventory_retains_every_occurrence_in_its_scope() {
    // Reuse common field grammars and retain both A occurrences for checking.
    for syntax in [ReferenceSyntax::Original, ReferenceSyntax::V2] {
        let (mut xml, _, _) = Tree::stamped(Role::Signature);
        let refs = reference_prefix(&mut xml, syntax);
        let (x, _) = append_timestamp(&mut xml, 7, Role::SignatureAndReferences, 1);
        let name = ExtendedKind::SignatureAndReferences(syntax).name();
        xml.nodes[x] = element(Some(7), name.namespace, name.local);
        let certs = add(&mut xml, 7, XADES, "CertificateValues");
        let revocation = add(&mut xml, 7, XADES, "RevocationValues");
        let (a, _) = append_timestamp(&mut xml, 7, Role::Archive, 1);
        let (renewal, _) = append_timestamp(&mut xml, 7, Role::Archive, 1);
        let work = funded();
        let access = Access::new(&xml, xml.snapshot(), &work);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let prepared = extended::prepare(&access, &bound, syntax).unwrap();
        assert_eq!(
            prepared
                .references()
                .iter()
                .map(validation::ReferenceProperty::node)
                .collect::<Vec<_>>(),
            refs
        );
        assert_eq!(
            prepared.references()[1].entries()[0]
                .xml_issuer_serial()
                .is_some(),
            syntax == ReferenceSyntax::Original,
        );
        assert_eq!(
            prepared
                .values()
                .iter()
                .map(material::Catalogue::parent)
                .collect::<Vec<_>>(),
            [certs, revocation]
        );
        assert_eq!(
            prepared
                .timestamps()
                .iter()
                .map(timestamp::Stamp::node)
                .collect::<Vec<_>>(),
            [8, x, a, renewal]
        );
        assert_eq!(prepared.first_unverified(&[], &work).unwrap(), Some(8));
    }
}

#[test]
fn extended_stage_preparation_progresses_from_c_to_a_without_relaxing_baseline() {
    // References stay available for X and do not disqualify the XL material
    // census or A archives when the caller explicitly selects this profile.
    for syntax in [ReferenceSyntax::Original, ReferenceSyntax::V2] {
        let mut xml = preparation_tree();
        let signature_stamp = 8;
        let refs = reference_prefix(&mut xml, syntax);
        check_extended_stage(
            &xml,
            syntax,
            unsigned::Requirements::Timestamped,
            &refs,
            &[signature_stamp],
            &[],
        );

        let kind = ExtendedKind::SignatureAndReferences(syntax);
        let (x, _) = append_timestamp(&mut xml, 7, Role::SignatureAndReferences, 1);
        let name = kind.name();
        xml.nodes[x] = element(Some(7), name.namespace, name.local);
        check_extended_stage(
            &xml,
            syntax,
            unsigned::Requirements::Timestamped,
            &refs,
            &[signature_stamp, x],
            &[],
        );

        let certs = add(&mut xml, 7, XADES, "CertificateValues");
        let revocation = add(&mut xml, 7, XADES, "RevocationValues");
        let value = add(&mut xml, certs, XADES, "EncapsulatedX509Certificate");
        let artifact = candidate_certificate();
        xml.binary = artifact.clone();
        let values = [certs, revocation];
        check_extended_stage(
            &xml,
            syntax,
            unsigned::Requirements::LongTerm,
            &refs,
            &[signature_stamp, x],
            &values,
        );

        let (archive, _) = append_timestamp(&mut xml, 7, Role::Archive, 1);
        if syntax == ReferenceSyntax::Original {
            xml.nodes[archive] = element(Some(7), XADES, "ArchiveTimeStamp");
        }
        check_extended_stage(
            &xml,
            syntax,
            unsigned::Requirements::Archival,
            &refs,
            &[signature_stamp, x, archive],
            &values,
        );

        let work = funded();
        let access = Access::new(&xml, xml.snapshot(), &work);
        let prepared =
            prepare::prepare_extended(&access, 0, syntax, unsigned::Requirements::LongTerm, None)
                .unwrap();
        let parser = Parser::der(work.clone());
        let operation = parser.read(&[], 0).unwrap();
        material::with_values(&xml, &prepared, &operation, |_, indexed| {
            let value = indexed
                .values()
                .iter()
                .find(|entry| entry.location.node == value)
                .unwrap();
            let material::Value::Certificate(certificate) = &value.value else {
                panic!("original certificate")
            };
            assert_eq!(certificate.as_bytes(), artifact);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert!(
            matches!(prepare::prepare(&access, 0, unsigned::Requirements::Archival, None),
            Err(prepare::Error::Property(properties::Error::Forbidden { node })) if refs.contains(&node))
        );
    }
}

fn check_extended_stage(
    xml: &Tree,
    syntax: ReferenceSyntax,
    stage: unsigned::Requirements,
    refs: &[usize],
    timestamps: &[usize],
    values: &[usize],
) {
    let work = funded();
    let access = Access::new(xml, xml.snapshot(), &work);
    let prepared = prepare::prepare_extended(&access, 0, syntax, stage, None).unwrap();
    assert_eq!(prepared.extended_syntax(), Some(syntax));
    assert_eq!(
        prepared
            .validation_references()
            .iter()
            .map(validation::ReferenceProperty::node)
            .collect::<Vec<_>>(),
        refs
    );
    assert_eq!(
        prepared
            .material()
            .iter()
            .map(material::Catalogue::parent)
            .collect::<Vec<_>>(),
        values
    );
    assert_eq!(
        prepared
            .timestamps()
            .iter()
            .map(timestamp::Stamp::node)
            .collect::<Vec<_>>(),
        timestamps
    );
    if stage == unsigned::Requirements::Archival {
        let at = timestamps.len() - 1;
        let required = timestamp::requirements(
            &access,
            &prepared,
            timestamp::TimestampSelection::BeforeArchive(at),
        )
        .unwrap();
        assert_eq!(
            required
                .entries()
                .iter()
                .map(|token| token.property)
                .collect::<Vec<_>>(),
            timestamps[..at]
        );
    }
}

#[test]
fn archive_names_select_distinct_original_object_and_property_coverage() {
    // The older archive omits referenced Objects and unlisted extension
    // properties. The 1.4.1 archive includes both and seals any earlier A.
    let (mut xml, _, _) = Tree::stamped(Role::Signature);
    let certs = add(&mut xml, 7, XADES, "CertificateValues");
    let revocation = add(&mut xml, 7, XADES, "RevocationValues");
    let extension = add(&mut xml, 7, "urn:extension", "Other");
    let covered = add(&mut xml, 0, DS, "Object");
    xml.references[0].target = Some(covered);
    let unreferenced = add(&mut xml, 0, DS, "Object");
    let (first, _) = append_timestamp(&mut xml, 7, Role::Archive, 1);
    xml.nodes[first] = element(Some(7), XADES, "ArchiveTimeStamp");
    let (renewal, _) = append_timestamp(&mut xml, 7, Role::Archive, 1);
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    for (node, kind, expected) in [
        (
            first,
            ExtendedKind::Archive132,
            vec![9, 12, 13, 8, certs, revocation, unreferenced],
        ),
        (
            renewal,
            ExtendedKind::Archive141,
            vec![
                9,
                12,
                13,
                8,
                certs,
                revocation,
                extension,
                first,
                covered,
                unreferenced,
            ],
        ),
    ] {
        let stamp = timestamp::read_extended(&access, &bound, node, kind).unwrap();
        let mut input = Input::prepare(&xml, &bound, &stamp, &work).unwrap();
        assert_eq!(canonical_ids(&source_bytes(&mut input, &work)), expected);
    }
}

#[test]
fn p256_tsa_response_is_bound_to_the_exact_x_request_and_transaction() {
    // Reject a different request nonce and a foreign generation before
    // inserting the token. The accepted token contains real P256 evidence.
    let (mut xml, _, _) = Tree::stamped(Role::Signature);
    let refs = reference_prefix(&mut xml, ReferenceSyntax::V2);
    let method = add(&mut xml, 0, DS, "CanonicalizationMethod");
    let protected = [12, 8, refs[0], refs[1]]
        .into_iter()
        .flat_map(|node| {
            [
                b'E',
                u8::try_from(node).unwrap(),
                b'M',
                u8::try_from(method).unwrap(),
            ]
        })
        .collect::<Vec<_>>();
    let (provider, token, tsa_bytes, request_bytes) =
        timestamp_oracle::fixture_unstated_accuracy(&protected);
    let work = funded();
    let parser = Parser::der(work.clone());
    let mut query = parser.read(&request_bytes, 1000).unwrap();
    let element = query.next_element().unwrap().unwrap();
    let original = Request::read(&query, &element).unwrap();
    let structured_cms::timestamp::HashAlgorithmReading::Identifier(algorithm) =
        *original.imprint().algorithm()
    else {
        panic!("generated SHA-256");
    };
    let response_bytes = timestamp_oracle::tlv(48, &[&[48, 3, 2, 1, 0][..], &token].concat());
    let mut response_reader = parser.read(&response_bytes, 2000).unwrap();
    let response = Response::read(&mut response_reader).unwrap();
    let tsa = structured_pkix::Certificate::read(&parser, &tsa_bytes, 3000).unwrap();
    let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let context = CheckContext {
        certificate: &tsa,
        certificate_parent: &query,
        key: structured_pkix::path::EffectiveKey::standing(tsa.tbs().public_key()),
        requested: Some(Requested {
            request: &original,
            parent: &query,
        }),
        utc: &utc,
        reference: Some(structured_pkix::temporal::Instant::new(1_800_000_000, 0).unwrap()),
        window: None,
        policy_accuracy: None,
    };
    let check = produce::ResponseCheck {
        response: &response,
        provider: &provider,
        query: &response_reader,
        context: &context,
    };
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let kind = ExtendedKind::SignatureAndReferences(ReferenceSyntax::V2);
    let mut plan = ExtendedAugmentation::prepare(&xml, &bound, kind, method, &work).unwrap();
    let request = |nonce| produce::ContentRequest {
        algorithm,
        nonce: Some(nonce),
        policy: None,
        cert_req: true,
        extensions: &[],
    };
    assert_ne!(
        plan.request(&provider, &query, &request(&[8])).unwrap(),
        request_bytes
    );
    assert!(matches!(
        plan.check_response(&check, |_, _| Ok::<_, ()>(false)),
        Err(produce::ResponseError::Admission(produce::Error::Foreign))
    ));
    assert_eq!(
        plan.request(&provider, &query, &request(&[7])).unwrap(),
        request_bytes
    );
    let checked = plan
        .check_response(&check, |_, _| Ok::<_, ()>(false))
        .unwrap();
    let mut draft = Draft::new(&xml, Some(7));
    plan.write_timestamp(&checked, &mut draft, &work).unwrap();
    assert_eq!(
        draft.events[0],
        Written::Begin(XADES_141, "SigAndRefsTimeStampV2")
    );
    assert!(draft.events.contains(&Written::Binary(token)));
    xml.generation.set(2);
    assert!(matches!(
        plan.write_timestamp(&checked, &mut draft, &work),
        Err(produce::Error::Foreign)
    ));
}

impl produce::ReferenceWriter for Draft {
    fn distinguished_name<W: Work>(
        &mut self,
        _: &structured_pkix::Name<'_>,
        work: &W,
    ) -> Result<(), Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        self.events.push(Written::Text("CN=fixture".into()));
        Ok(())
    }
    fn integer<W: Work>(
        &mut self,
        value: structured_asn1::Integer<'_>,
        work: &W,
    ) -> Result<(), Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        self.events
            .push(Written::Text(value.as_u64().unwrap().to_string()));
        Ok(())
    }
    fn datetime<W: Work>(&mut self, _: structured_pkix::Time, work: &W) -> Result<(), Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        self.events
            .push(Written::Text("2025-01-01T00:00:00Z".into()));
        Ok(())
    }
}

#[test]
fn c_hashes_whole_artifacts_and_xl_embeds_the_same_original_encodings() {
    // Whole-response OCSP bytes, exact CRL number, and V1 issuer/serial are
    // selected from parsed artifacts. V2 emits no invented issuer hint.
    let (provider, _, cert_bytes) = timestamp_oracle::fixture(b"irrelevant");
    let crl_bytes = timestamp_oracle::complete_crl_number(2, 37);
    let ocsp_bytes = timestamp_oracle::ocsp_response(2);
    let work = funded();
    let parser = Parser::der(work.clone());
    let cert = structured_pkix::Certificate::read(&parser, &cert_bytes, 1000).unwrap();
    let crl = structured_pkix::crl::CertificateList::read(&parser, &crl_bytes, 2000).unwrap();
    let structured_pkix::ocsp::Response::Successful(ocsp) =
        structured_pkix::ocsp::Response::read(&parser, &ocsp_bytes, 3000).unwrap()
    else {
        panic!("valid OCSP envelope");
    };
    let query = parser.read(&[], 0).unwrap();
    let basic = ocsp.basic_in(&query).unwrap().unwrap();
    let artifacts = [
        produce::ReferenceArtifact::ocsp::<Cause, _>(&ocsp, &basic, &work).unwrap(),
        produce::ReferenceArtifact::certificate(&cert),
        produce::ReferenceArtifact::crl(&crl),
    ];
    let values = [
        produce::Material::ocsp::<Cause, _>(&ocsp, &basic, &work).unwrap(),
        produce::Material::certificate(&cert),
        produce::Material::crl(&crl),
    ];
    let xml = Tree::normal();
    for syntax in [ReferenceSyntax::Original, ReferenceSyntax::V2] {
        let mut draft = Draft::new(&xml, Some(7));
        let selection = produce::References {
            syntax,
            role: produce::ReferenceRole::Signature,
            method: "http://www.w3.org/2001/04/xmlenc#sha256",
            artifacts: &artifacts,
        };
        selection
            .write(&mut draft, &provider, &work, |method, _| {
                assert_eq!(method, selection.method);
                Ok(DigestResolution::Supported((
                    (),
                    structured_xades::hashes::HashClass::OtherKnown,
                )))
            })
            .unwrap();
        let wire = if syntax == ReferenceSyntax::Original {
            Written::Begin(XADES, "CompleteCertificateRefs")
        } else {
            Written::Begin(XADES_141, "CompleteCertificateRefsV2")
        };
        assert_eq!(draft.events.first(), Some(&wire));
        assert_eq!(
            draft
                .events
                .contains(&Written::Begin(XADES, "IssuerSerial")),
            syntax == ReferenceSyntax::Original
        );
        assert!(draft.events.contains(&Written::Text("37".into())));
        let hashes: Vec<_> = draft
            .events
            .iter()
            .filter_map(|event| match event {
                Written::Binary(bytes) if bytes.len() == 32 => Some(bytes.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(
            hashes,
            [&cert_bytes, &crl_bytes, &ocsp_bytes].map(|bytes| Sha256::digest(bytes).to_vec())
        );
        let mut values_draft = Draft::new(&xml, Some(7));
        produce::write_extended_values(
            &values,
            produce::ReferenceRole::Signature,
            &mut values_draft,
            &work,
        )
        .unwrap();
        assert_eq!(
            values_draft.events.first(),
            Some(&Written::Begin(XADES, "CertificateValues"))
        );
        for bytes in [&cert_bytes, &crl_bytes, &ocsp_bytes] {
            assert!(
                values_draft
                    .events
                    .contains(&Written::Binary(bytes.clone()))
            );
        }
    }
}
