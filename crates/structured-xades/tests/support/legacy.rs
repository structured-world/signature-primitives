//! Historical profile construction and original-source checks.

use super::*;
use structured_xades::legacy::timestamp::LegacyXml as _;
use structured_xades::{
    binding::SIGNED_PROPERTIES_122,
    container::{Selected, Syntaxes, XADES_122},
    legacy::{self, Profile, SignerCertificate, timestamp as old},
    scalar::{Datatype, Error as ScalarError, Fact},
};

impl old::LegacyXml for Tree {
    fn resolve_legacy_element<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        include: usize,
        work: &W,
    ) -> Result<Resolution<usize>, Cause> {
        self.check(snapshot, include)?;
        work.charge_work(self.include_routes.len() as u64)
            .map_err(Cause::Resource)?;
        Ok(self
            .include_routes
            .iter()
            .find(|route| route.0 == include)
            .map_or(Resolution::Unresolved, |route| {
                Resolution::Resolved(route.1)
            }))
    }

    fn canonicalize_legacy_default<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Cause> {
        self.check(snapshot, node)?;
        let node = u8::try_from(node).map_err(|_| Cause::Source)?;
        self.emit(&[b'E', node], receiver, work)
    }
}

fn append(xml: &mut Tree, parent: usize, ns: &'static str, local: &'static str) -> usize {
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(parent), ns, local));
    node
}

fn tree() -> Tree {
    let mut xml = Tree::normal();
    for (node, parent, name) in [
        (2, 1, "QualifyingProperties"),
        (3, 2, "SignedProperties"),
        (4, 3, "SignedSignatureProperties"),
        (5, 4, "SigningTime"),
        (6, 2, "UnsignedProperties"),
        (7, 6, "UnsignedSignatureProperties"),
    ] {
        xml.nodes[node] = element(Some(parent), XADES_122, name);
    }
    xml.nodes[8] = Record {
        parent: Some(7),
        value: Node::Other,
    };
    xml.references[1].kind = Some(SIGNED_PROPERTIES_122);
    xml
}

fn with_cert_reference(xml: Tree) -> Tree {
    with_serial(xml, "42", Fact::Valid).0
}

fn with_serial(xml: Tree, text: &'static str, fact: Fact) -> (Tree, usize) {
    with_serial_in(xml, text, fact, Profile::V122)
}

impl structured_xades::produce::HistoricalTimestampWriter for lifecycle::Draft {
    fn signature_value_uri<W: Work>(
        &mut self,
        value: usize,
        attribute: Name<'static>,
        work: &W,
    ) -> Result<(), Cause> {
        assert_eq!(value, 12);
        work.charge_work(1).map_err(Cause::Resource)?;
        self.events.push(lifecycle::Written::Attribute(
            attribute.local,
            "#value".into(),
        ));
        Ok(())
    }

    fn canonicalization_transform<W: Work>(
        &mut self,
        method: usize,
        work: &W,
    ) -> Result<(), Cause> {
        use structured_xades::produce::Transaction;
        self.events.push(lifecycle::Written::Begin(DS, "Transform"));
        self.method(method, work)?;
        self.events.push(lifecycle::Written::End);
        Ok(())
    }
}

#[test]
fn historical_request_and_response_emit_the_same_source_in_each_profile() {
    // Exercise the shared request and actual RFC 3161 signature check with
    // the original SignatureValue for every historical wire variant.
    use structured_cms::timestamp::{HashAlgorithmReading, Request, Requested, Response};
    use structured_xades::produce;
    for profile in [Profile::V111, Profile::V122, Profile::PreEn] {
        let mut xml = profile_tree(profile);
        let method = append(&mut xml, 0, DS, "CanonicalizationMethod");
        let source = [b'E', 12, b'M', u8::try_from(method).unwrap()];
        let (provider, token, certificate, request_bytes) =
            timestamp_oracle::fixture_unstated_accuracy(&source);
        let work = funded();
        let parser = structured_asn1::Parser::der(work.clone());
        let mut query = parser.read(&request_bytes, 1000).unwrap();
        let element = query.next_element().unwrap().unwrap();
        let original = Request::read(&query, &element).unwrap();
        let HashAlgorithmReading::Identifier(algorithm) = *original.imprint().algorithm() else {
            panic!("generated SHA-256");
        };
        let response_bytes = timestamp_oracle::tlv(48, &[&[48, 3, 2, 1, 0][..], &token].concat());
        let mut response_reader = parser.read(&response_bytes, 2000).unwrap();
        let response = Response::read(&mut response_reader).unwrap();
        let tsa = structured_pkix::Certificate::read(&parser, &certificate, 3000).unwrap();
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
        let access = Access::new(&xml, xml.snapshot(), &work);
        let bound =
            legacy::prepare(&access, &legacy::locate(&access, 0, profile).unwrap()).unwrap();
        let mut plan = produce::ExtendedAugmentation::prepare_historical_signature(
            &xml, &bound, method, &work,
        )
        .unwrap();
        let request = produce::ContentRequest {
            algorithm,
            nonce: Some(&[7]),
            policy: None,
            cert_req: true,
            extensions: &[],
        };
        assert_eq!(
            plan.request(&provider, &query, &request).unwrap(),
            request_bytes
        );
        let check = produce::ResponseCheck {
            response: &response,
            provider: &provider,
            query: &response_reader,
            context: &context,
        };
        let checked = plan
            .check_response(&check, |_, _| Ok::<_, ()>(false))
            .unwrap();
        let mut writer = lifecycle::Draft::new(&xml, Some(7));
        let namespace = profile.namespace();
        let explicit = match profile {
            Profile::V111 => Some(("HashDataInfo", "uri")),
            Profile::V122 => Some(("Include", "URI")),
            Profile::PreEn => None,
        };
        if let Some((element, attribute)) = explicit {
            plan.write_historical_timestamp(&checked, &mut writer, &work)
                .unwrap();
            assert!(
                writer
                    .events
                    .contains(&lifecycle::Written::Begin(namespace, element))
            );
            assert!(
                writer
                    .events
                    .contains(&lifecycle::Written::Attribute(attribute, "#value".into()))
            );
        } else {
            plan.write_timestamp(&checked, &mut writer, &work).unwrap();
            assert_eq!(writer.events[1], lifecycle::Written::Method(method));
        }
        assert_eq!(
            writer.events[0],
            lifecycle::Written::Begin(namespace, "SignatureTimeStamp")
        );
        assert!(writer.events.contains(&lifecycle::Written::Begin(
            namespace,
            "EncapsulatedTimeStamp"
        )));
        assert!(writer.events.contains(&lifecycle::Written::Binary(token)));
    }
}

fn with_serial_in(
    mut xml: Tree,
    text: &'static str,
    fact: Fact,
    profile: Profile,
) -> (Tree, usize) {
    let namespace = profile.namespace();
    let signing = append(&mut xml, 4, namespace, "SigningCertificate");
    let cert = append(&mut xml, signing, namespace, "Cert");
    let digest = append(&mut xml, cert, namespace, "CertDigest");
    append(&mut xml, digest, profile.digest_namespace(), "DigestMethod");
    append(&mut xml, digest, profile.digest_namespace(), "DigestValue");
    let issuer = append(&mut xml, cert, namespace, "IssuerSerial");
    append(&mut xml, issuer, DS, "X509IssuerName");
    let serial = append(&mut xml, issuer, DS, "X509SerialNumber");
    xml.nodes.push(Record {
        parent: Some(serial),
        value: Node::Text(text),
    });
    xml.scalar_routes
        .push(scalar_checks::route(serial, Datatype::Integer, fact));
    (xml, serial)
}

pub(super) fn profile_tree(profile: Profile) -> Tree {
    let namespace = profile.namespace();
    let mut xml = tree();
    for node in &mut xml.nodes[2..8] {
        if let Node::Element(name) = &mut node.value {
            name.namespace = namespace;
        }
    }
    xml.references[1].kind = Some(profile.signed_properties_type());
    let (mut xml, _) = with_serial_in(xml, "42", Fact::Valid, profile);
    let policy = append(&mut xml, 4, namespace, "SignaturePolicyIdentifier");
    append(&mut xml, policy, namespace, "SignaturePolicyImplied");
    xml
}

#[test]
fn original_extended_preparation_accepts_original_signed_certificate() {
    // Original C/X/XL/A signatures protect SigningCertificate, not its
    // later V2 replacement. The same wire input remains outside EN baseline.
    let xml = profile_tree(Profile::PreEn);
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(
        prepare::prepare_extended_original(&access, 0, unsigned::Requirements::Basic, None,)
            .is_ok()
    );
    assert!(prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).is_err());
}

#[test]
fn historical_policy_checks_documentation_in_the_original_namespace() {
    // Both older schemas carry the documentation URI in their own namespace.
    use structured_xades::{identifier, policy::Declaration};
    let work = funded();
    for profile in [Profile::V111, Profile::V122] {
        let mut xml = profile_tree(profile);
        let explicit = xml.nodes.len() - 1;
        let namespace = profile.namespace();
        let parent = xml.nodes[explicit].parent;
        xml.nodes[explicit] = element(parent, namespace, "SignaturePolicyId");
        let policy = append(&mut xml, explicit, namespace, "SigPolicyId");
        let id = append(&mut xml, policy, namespace, "Identifier");
        let refs = append(&mut xml, policy, namespace, "DocumentationReferences");
        let doc = append(&mut xml, refs, namespace, "DocumentationReference");
        let hash = append(&mut xml, explicit, namespace, "SigPolicyHash");
        append(&mut xml, hash, profile.digest_namespace(), "DigestMethod");
        append(&mut xml, hash, profile.digest_namespace(), "DigestValue");
        let uri = "https://example.test/policy";
        xml.uri_routes.push(scalar_checks::UriRoute::valid(id, uri));
        xml.scalar_routes
            .push(scalar_checks::route(doc, Datatype::AnyUri, Fact::Valid));
        let access = Access::new(&xml, xml.snapshot(), &work);
        let layout = legacy::locate(&access, 0, profile).unwrap();
        let prepared = legacy::prepare(&access, &layout).unwrap();
        let policy = prepared.policy(&access).unwrap().unwrap();
        let Declaration::Explicit(policy) = policy.declaration() else {
            panic!("explicit policy")
        };
        assert!(matches!(
            identifier::check(&access, &policy.identifier),
            Ok(identifier::Meaning::Uri)
        ));
        assert_eq!(xml.scalar_calls.get(), 2);
    }
}

#[test]
fn historical_signature_timestamp_tail_respects_unsigned_schema_order() {
    // The old ordered sequences cannot append a T timestamp after C material.
    use structured_xades::produce::ExtendedAugmentation;
    let work = funded();
    for profile in [Profile::V111, Profile::V122, Profile::PreEn] {
        let mut xml = profile_tree(profile);
        let method = append(&mut xml, 0, DS, "CanonicalizationMethod");
        let tail = append(&mut xml, 7, profile.namespace(), "CompleteCertificateRefs");
        let access = Access::new(&xml, xml.snapshot(), &work);
        let layout = legacy::locate(&access, 0, profile).unwrap();
        let prepared = legacy::prepare(&access, &layout).unwrap();
        let result =
            ExtendedAugmentation::prepare_historical_signature(&xml, &prepared, method, &work);
        if profile == Profile::PreEn {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(InputError::Order { node }) if node == tail));
        }
    }
}

/// Exercise the common signer check with original data extracted independently.
/// # Panics
/// Fails when the pinned fixture's XML vocabulary or certificate hash disagrees.
pub fn check_independent_signer(directory: &std::path::Path, profile: Profile) {
    let vocabulary = std::fs::read_to_string(directory.join("vocabulary.txt")).unwrap();
    assert_eq!(
        vocabulary.lines().collect::<Vec<_>>(),
        [
            profile.signed_properties_type(),
            profile.digest_namespace(),
            profile.digest_namespace()
        ]
    );
    let mut xml = profile_tree(profile);
    xml.binary = std::fs::read(directory.join("digest.bin")).unwrap();
    xml.digest_algorithm = Some("http://www.w3.org/2001/04/xmlenc#sha256");
    let bytes = std::fs::read(directory.join("signer.der")).unwrap();
    let work = funded();
    let parser = structured_asn1::Parser::der(work.clone());
    let certificate = structured_pkix::Certificate::read(&parser, &bytes, 0).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = legacy::locate(&access, 0, profile).unwrap();
    let prepared = legacy::prepare(&access, &layout).unwrap();
    let digest = xml_digest::Oracle::new(xml_digest::Mode::Ready);
    let facts = legacy::check_signer(
        &xml,
        &prepared,
        &certificate,
        structured_pkix::path::EffectiveKey::standing(certificate.tbs().public_key()),
        &digest,
        &work,
    )
    .unwrap();
    assert!(matches!(
        facts.certificate,
        legacy::CertificateMatch::Digest(_)
    ));
}

impl old::HashDataXml for Tree {
    fn resolve_hash_data<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        data: old::HashDataInfo<usize>,
        work: &W,
    ) -> Result<Resolution<old::HashDataTarget<usize>>, Cause> {
        self.check(snapshot, signature)?;
        assert!(data.transforms.is_some());
        self.resolve_legacy_element(snapshot, data.node, work)
            .map(|answer| answer.map(old::HashDataTarget::Element))
    }

    fn replay_hash_data<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        data: old::HashDataInfo<usize>,
        expected: old::HashDataTarget<usize>,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<ReplayOutcome<Cause>, Cause> {
        if self.resolve_hash_data(snapshot, signature, data, work)?
            != Resolution::Resolved(expected)
        {
            return Err(Cause::Source);
        }
        let old::HashDataTarget::Element(target) = expected else {
            return Err(Cause::Source);
        };
        self.canonicalize_legacy_default(snapshot, target, receiver, work)?;
        Ok(ReplayOutcome::Complete)
    }
}

#[test]
fn v111_hash_data_cannot_timestamp_the_whole_signature_instead_of_its_value() {
    // TS 101 903 V1.1.1 §7.3 selects the actual SignatureValue. Uppercase
    // compatibility changes only syntax; source matching remains mandatory.
    let profile = Profile::V111;
    let ns = profile.namespace();
    let mut xml = profile_tree(profile);
    let stamp = append(&mut xml, 7, ns, "SignatureTimeStamp");
    let input = append(&mut xml, stamp, ns, "HashDataInfo");
    let transforms = append(&mut xml, input, ns, "Transforms");
    let transform = append(&mut xml, transforms, DS, "Transform");
    xml.digest_algorithms
        .push((transform, "http://www.w3.org/2001/10/xml-exc-c14n#"));
    let token = append(&mut xml, stamp, ns, "EncapsulatedTimeStamp");
    let work = funded();
    for (attribute, target) in [("uri", 12), ("URI", 0)] {
        xml.hash_data_uri = Some((attribute, "#selected"));
        xml.include_routes = vec![(input, target, Boolean::Absent)];
        let access = Access::new(&xml, xml.snapshot(), &work);
        let prepared =
            legacy::prepare(&access, &legacy::locate(&access, 0, profile).unwrap()).unwrap();
        assert!(matches!(
            prepared.policy(&access).unwrap().unwrap().declaration(),
            structured_xades::policy::Declaration::Implied(_)
        ));
        if target == 12 {
            let stamp =
                old::HashDataStamp::read(&access, &prepared, stamp, old::HashDataUri::Standard)
                    .unwrap();
            assert_eq!(stamp.token(), old::Token::Encapsulated(token));
            let mut source = old::HashDataInput::prepare(&access, &prepared, &stamp).unwrap();
            let mut sink = Collect::new(&work);
            stream::run(&mut source, &mut sink, &work, "historical.timestamp", 0).unwrap();
            assert_eq!(sink.bytes(), &[b'E', 12]);
        } else {
            assert!(
                matches!(old::HashDataStamp::read(&access, &prepared, stamp, old::HashDataUri::Standard), Err(InputError::Unexpected { node }) if node == input)
            );
            let stamp =
                old::HashDataStamp::read(&access, &prepared, stamp, old::HashDataUri::Uppercase)
                    .unwrap();
            assert!(
                matches!(old::HashDataInput::prepare(&access, &prepared, &stamp), Err(InputError::Reference { node, .. }) if node == input)
            );
        }
    }
}

#[test]
fn historical_writers_use_the_selected_digest_and_material_namespaces() {
    // All three historical writers bind the V1 certificate and preserve the
    // source DER while placing it in the actual historical values vocabulary.
    use structured_xades::produce;
    let work = funded();
    let bytes = candidate_certificate();
    let parser = structured_asn1::Parser::der(work.clone());
    let certificate = structured_pkix::Certificate::read(&parser, &bytes, 0).unwrap();
    let data = [produce::DataObject {
        reference: "#content-reference",
        mime_type: "text/plain",
    }];
    let basic = produce::Basic {
        target: "#sig",
        signed_properties_id: "properties",
        signing_time: "2025-01-30T00:00:00Z",
        certificate: &certificate,
        certificate_digest_method: "urn:digest",
        certificate_digest: &[1, 0],
        objects: &data,
        counter_signature: None,
    };
    for profile in [Profile::V111, Profile::V122, Profile::PreEn] {
        let mut xml = profile_tree(profile);
        let namespace = profile.namespace();
        let value_container = append(&mut xml, 7, namespace, "CertificateValues");
        let value = append(
            &mut xml,
            value_container,
            namespace,
            "EncapsulatedX509Certificate",
        );
        xml.binary_routes.push((value, bytes.clone()));
        let access = Access::new(&xml, xml.snapshot(), &work);
        let layout = legacy::locate(&access, 0, profile).unwrap();
        let prepared = legacy::prepare(&access, &layout).unwrap();
        assert_eq!(layout.profile(), profile);
        let mut draft = lifecycle::Draft::new(&xml, Some(7));
        let policy = produce::SignaturePolicy::Implied;
        basic
            .write_historical(profile, Some(&policy), &mut draft, &work)
            .unwrap();
        assert!(
            draft
                .events
                .contains(&lifecycle::Written::Begin(namespace, "SigningCertificate"))
        );
        assert!(draft.events.contains(&lifecycle::Written::Begin(
            profile.digest_namespace(),
            "DigestMethod"
        )));
        assert!(
            draft
                .events
                .contains(&lifecycle::Written::Begin(DS, "X509SerialNumber"))
        );
        produce::write_historical_values(
            &[produce::Material::certificate(&certificate)],
            profile,
            produce::ReferenceRole::Signature,
            &mut draft,
            &work,
        )
        .unwrap();
        let values = prepared.values(&access, value_container).unwrap();
        let operation = parser.read(&[], 0).unwrap();
        let value = material::retain_entry(&xml, &values, 0, &operation)
            .unwrap()
            .unwrap();
        assert_eq!(value.bytes(), bytes);
    }
}

fn layout<W: Work>(access: &Access<'_, Tree, W>) -> legacy::Layout<Tree> {
    let Selected::Ts101903V122(value) =
        container::locate_with_syntax(access, 0, Syntaxes::WithTs101903V122).unwrap()
    else {
        panic!("expected original V1.2.2");
    };
    value
}

#[test]
fn issuer_serial_requires_an_integer_from_the_original_xml_owner() {
    // Malformed simple text must fail at the original value node. The valid
    // case exercises an xs:integer wider than common machine integer types.
    for (text, fact) in [
        ("not-an-integer", Fact::Malformed),
        (" \t+340282366920938463463374607431768211456\n", Fact::Valid),
    ] {
        let (xml, serial) = with_serial(tree(), text, fact);
        let work = funded();
        let access = Access::new(&xml, xml.snapshot(), &work);
        let result = legacy::prepare(&access, &layout(&access));
        if fact == Fact::Valid {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(legacy::Error::Serial(ScalarError::Value {
                    node,
                    datatype: Datatype::Integer,
                    fact: Fact::Malformed,
                })) if node == serial
            ));
        }
        assert_eq!(xml.scalar_calls.get(), 1);
    }
}

#[test]
fn issuer_serial_preserves_unsupported_integer_validation() {
    // The serial is numeric, but the adapter does not support the requested
    // datatype. Preparation must refuse without diagnosing malformed XML.
    let (xml, serial) = with_serial(tree(), "42", Fact::Unsupported);
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        legacy::prepare(&access, &layout(&access)),
        Err(legacy::Error::Serial(ScalarError::Value {
            node,
            datatype: Datatype::Integer,
            fact: Fact::Unsupported,
        })) if node == serial
    ));
}

#[test]
fn original_namespace_requires_explicit_opt_in_and_same_reference_type() {
    // Empty UnsignedSignatureProperties is valid in the old schema.
    let mut xml = with_cert_reference(tree());
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        container::locate(&access, 0),
        Err(ContainerError::Missing { .. })
    ));
    let prepared = legacy::prepare(&access, &layout(&access)).unwrap();
    assert_eq!(prepared.reference(), 11);
    assert!(prepared.unsigned().is_empty());
    let SignerCertificate::References(references) = prepared.signer() else {
        panic!("expected V1 certificate references");
    };
    assert!(references.entries()[0].issuer_serial().is_some());
    xml.references[1].kind = Some(SIGNED_PROPERTIES);
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        legacy::prepare(&access, &layout(&access)),
        Err(legacy::Error::Binding(BindingError::Missing { node: 3 }))
    ));
}

#[test]
fn disallows_a_mixed_property_namespace_and_enforces_unsigned_sequence() {
    // The modern namespace and modern choice ordering cannot substitute for
    // the older expanded names and ordered grammar.
    let mut xml = with_cert_reference(tree());
    let first = append(&mut xml, 7, XADES_122, "CertificateValues");
    let second = append(&mut xml, 7, XADES, "CompleteCertificateRefs");
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        legacy::prepare(&access, &layout(&access)),
        Err(legacy::Error::Property(properties::Error::Unexpected { node })) if node == second
    ));
    xml.nodes[second] = element(Some(7), XADES_122, "CompleteCertificateRefs");
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        legacy::prepare(&access, &layout(&access)),
        Err(legacy::Error::Property(properties::Error::Order { node })) if node == second
    ));
    xml.nodes[first] = element(Some(7), XADES_122, "SigAndRefsTimeStamp");
    xml.nodes[second] = element(Some(7), XADES_122, "RefsOnlyTimeStamp");
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        legacy::prepare(&access, &layout(&access)),
        Err(legacy::Error::Property(properties::Error::Unexpected { node })) if node == second
    ));
}

#[test]
fn bes_requires_complete_key_info_coverage_in_the_absence_of_signing_certificate() {
    // A real signer certificate must be under a whole-element KeyInfo receipt.
    let mut xml = tree();
    xml.nodes[5] = Record {
        parent: Some(4),
        value: Node::Other,
    };
    let x509_data = append(&mut xml, 13, DS, "X509Data");
    let certificate = append(&mut xml, x509_data, DS, "X509Certificate");
    xml.references[0].target = Some(13);
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        legacy::prepare(&access, &layout(&access)),
        Err(legacy::Error::Binding(BindingError::Reference { node: 10 }))
    ));
    xml.references[0].coverage = Coverage::ElementContent;
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = legacy::prepare(&access, &layout(&access)).unwrap();
    assert!(prepared.signed().is_empty());
    assert!(matches!(
        prepared.signer(),
        SignerCertificate::KeyInfo { node: 13, reference: 10, certificates }
            if certificates.as_ref() == [certificate]
    ));
}

#[test]
fn bes_binds_the_actual_embedded_certificate_and_selected_key_separately() {
    // A different certificate in signed KeyInfo does not protect the candidate
    // even when the owner reports that the actual verification key matches.
    let (leaf, issuer) = timestamp_oracle::certificate_pair();
    let work = funded();
    let parser = structured_asn1::Parser::der(work.clone());
    let certificate = structured_pkix::Certificate::read(&parser, &leaf, 0).unwrap();
    let key = structured_pkix::path::EffectiveKey::standing(certificate.tbs().public_key());
    let mut xml = tree();
    let x509_data = append(&mut xml, 13, DS, "X509Data");
    let node = append(&mut xml, x509_data, DS, "X509Certificate");
    xml.references[0].target = Some(13);
    xml.references[0].coverage = Coverage::ElementContent;
    xml.binary_routes.push((node, issuer));
    xml.key_association = certificate::KeyAssociation::Same;
    let digest = WholeCertificate {
        mode: DigestMode::Available,
        method: usize::MAX,
        calls: Cell::new(0),
        pointer: Cell::new(0),
    };
    let check = |xml: &Tree| {
        let access = Access::new(xml, xml.snapshot(), &work);
        let prepared = legacy::prepare(&access, &layout(&access)).unwrap();
        legacy::check_signer(xml, &prepared, &certificate, key, &digest, &work).unwrap()
    };
    let different = check(&xml);
    assert_eq!(different.key, certificate::KeyAssociation::Same);
    assert_eq!(different.certificate, legacy::CertificateMatch::Differs);
    xml.binary_routes[0].1 = leaf.clone();
    let embedded = check(&xml);
    assert_eq!(embedded.key, certificate::KeyAssociation::Same);
    assert_eq!(
        embedded.certificate,
        legacy::CertificateMatch::Embedded(node)
    );
    assert_eq!(digest.calls.get(), 0);
}

fn include(xml: &mut Tree, stamp: usize, link: usize, flag: Boolean) -> usize {
    let include = append(xml, stamp, XADES_122, "Include");
    xml.include_routes.push((include, link, flag));
    include
}

#[test]
fn archive_indexes_reference_targets_without_reordering_inputs() {
    // Each original instruction is read once. Two references to one object
    // stay in the imprint, while that object's element occurs zero times.
    let mut xml = with_cert_reference(tree());
    xml.references[0].target = Some(1);
    xml.validation_uri = Some("#fixture");
    let certificates = append(&mut xml, 7, XADES_122, "CertificateValues");
    let revocations = append(&mut xml, 7, XADES_122, "RevocationValues");
    let archive = append(&mut xml, 7, XADES_122, "ArchiveTimeStamp");
    let first = append(&mut xml, 0, DS, "Object");
    let latter = append(&mut xml, 0, DS, "Object");
    let last = append(&mut xml, 0, DS, "Object");
    for target in [Some(latter), None, Some(latter), None, None, None, None] {
        let node = append(&mut xml, 9, DS, "Reference");
        xml.references.push(Reference {
            node,
            target,
            kind: None,
            status: Status::Valid,
            coverage: Coverage::ElementContent,
        });
    }
    let references = xml.references.len();
    for ordinal in 0..references {
        include(&mut xml, archive, ordinal, Boolean::Value(true));
    }
    let elements = [9, 12, 13, certificates, revocations, first, last];
    for node in elements {
        include(&mut xml, archive, node, Boolean::Absent);
    }
    append(&mut xml, archive, XADES_122, "EncapsulatedTimeStamp");
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = legacy::prepare(&access, &layout(&access)).unwrap();
    let stamp = old::read(&access, &prepared, archive).unwrap();
    xml.reference_queries.set(0);
    let mut source = old::input(&access, &prepared, &stamp).unwrap();
    assert_eq!(xml.reference_queries.get(), references);
    let mut sink = Collect::new(&work);
    stream::run(&mut source, &mut sink, &work, "legacy archive", 0).unwrap();
    let mut expected = Vec::new();
    for ordinal in 0..references {
        expected.extend([b'D', u8::try_from(ordinal).unwrap()]);
    }
    for node in elements {
        expected.extend([b'E', u8::try_from(node).unwrap()]);
    }
    assert_eq!(sink.bytes(), expected);
}

#[test]
fn legacy_signature_timestamp_uses_explicit_include_and_default_method() {
    // §7.3 mandates an Include for the original SignatureValue. A different
    // target cannot be rescued by canonicalizing the expected node anyway.
    let mut xml = with_cert_reference(tree());
    xml.validation_uri = Some("#fixture");
    let stamp = append(&mut xml, 7, XADES_122, "SignatureTimeStamp");
    let include = include(&mut xml, stamp, 12, Boolean::Absent);
    let token = append(&mut xml, stamp, XADES_122, "EncapsulatedTimeStamp");
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = legacy::prepare(&access, &layout(&access)).unwrap();
    let stamp = old::read(&access, &prepared, stamp).unwrap();
    assert_eq!(stamp.token(), old::Token::Encapsulated(token));
    assert_eq!(stamp.method(), None);
    let mut source = old::input(&access, &prepared, &stamp).unwrap();
    let mut sink = Collect::new(&work);
    stream::run(&mut source, &mut sink, &work, "legacy timestamp", 0).unwrap();
    assert_eq!(sink.bytes(), &[b'E', 12]);
    let node = stamp.node();
    xml.include_routes[0].1 = 13;
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = legacy::prepare(&access, &layout(&access)).unwrap();
    let stamp = old::read(&access, &prepared, node).unwrap();
    assert!(matches!(
        old::input(&access, &prepared, &stamp),
        Err(InputError::Reference { node, .. }) if node == include
    ));
    assert_eq!(xml.streamed.get(), 1);
}

#[test]
fn archive_orders_v122_inputs_and_requires_true_on_reference_includes() {
    // §7.7 puts timestamp before counters and covers values before prior
    // archive timestamps, independently of the unsigned XML sequence.
    let mut xml = with_cert_reference(tree());
    xml.references[0].target = Some(1);
    xml.reference_routes = vec![(10, vec![b'A']), (11, vec![b'B'])];
    xml.validation_uri = Some("#fixture");
    let counter = append(&mut xml, 7, XADES_122, "CounterSignature");
    let signature = append(&mut xml, 7, XADES_122, "SignatureTimeStamp");
    let certificates = append(&mut xml, 7, XADES_122, "CertificateValues");
    let revocations = append(&mut xml, 7, XADES_122, "RevocationValues");
    let prior = append(&mut xml, 7, XADES_122, "ArchiveTimeStamp");
    let archive = append(&mut xml, 7, XADES_122, "ArchiveTimeStamp");
    include(&mut xml, archive, 0, Boolean::Value(true));
    include(&mut xml, archive, 1, Boolean::Value(true));
    let elements = [
        9,
        12,
        13,
        signature,
        counter,
        certificates,
        revocations,
        prior,
    ];
    for target in elements {
        include(&mut xml, archive, target, Boolean::Value(false));
    }
    let token = append(&mut xml, archive, XADES_122, "XMLTimeStamp");
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = legacy::prepare(&access, &layout(&access)).unwrap();
    let stamp = old::read(&access, &prepared, archive).unwrap();
    assert_eq!(stamp.token(), old::Token::Xml(token));
    let mut source = old::input(&access, &prepared, &stamp).unwrap();
    let mut sink = Collect::new(&work);
    stream::run(&mut source, &mut sink, &work, "legacy archive", 0).unwrap();
    let mut expected = vec![b'A', b'B'];
    for element in elements {
        expected.extend([b'E', u8::try_from(element).unwrap()]);
    }
    assert_eq!(sink.bytes(), expected);

    xml.include_routes[0].2 = Boolean::Absent;
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = legacy::prepare(&access, &layout(&access)).unwrap();
    let stamp = old::read(&access, &prepared, archive).unwrap();
    assert!(matches!(
        old::input(&access, &prepared, &stamp),
        Err(InputError::ReferencedData {
            value: Boolean::Absent,
            ..
        })
    ));
}
