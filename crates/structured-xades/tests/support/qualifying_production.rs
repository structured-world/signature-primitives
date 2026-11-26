//! Public construction paths with an observing XML owner and real TSA math.

use super::lifecycle::{Draft, Written};
use super::{Arc, Cause, MemoryAccount, Tree, XADES, XADES_141, memory, timestamp_oracle};
use structured_asn1::{
    Parser, Reader,
    memory::{Memory, Work},
};
use structured_cms::timestamp::{CheckContext, Request, Requested, Response};
use structured_pkix::{
    path::EffectiveKey,
    temporal::{Instant, LeapTable},
};
use structured_xades::{
    identifier::Qualifier,
    produce::{
        self, ContentInput, ContentReference, ContentRequest, ContentScope, ContentSource,
        ContentWriter, Error, FragmentSlot, Identifier, ObjectMetadata, PolicyTransform,
        PolicyWriter, PropertyWriter,
    },
    reference::ReplayOutcome,
};

impl PropertyWriter for Draft {
    type Fragment = &'static str;

    fn data_reference<W: Work>(
        &self,
        uri: &str,
        work: &W,
    ) -> Result<Option<ObjectMetadata<'_>>, Cause> {
        work.charge_work(uri.len() as u64)
            .map_err(Cause::Resource)?;
        Ok((uri == "#ref").then_some(ObjectMetadata {
            mime_type: Some("text/plain"),
            encoding: Some("urn:encoding"),
        }))
    }

    fn fragment<W: Work>(
        &mut self,
        slot: FragmentSlot,
        value: &&'static str,
        work: &W,
    ) -> Result<(), Cause> {
        work.charge_work(value.len() as u64)
            .map_err(Cause::Resource)?;
        self.events.push(Written::Text(match slot {
            FragmentSlot::AnyContent => (*value).to_owned(),
            FragmentSlot::PolicyTransforms => format!("transforms:{value}"),
        }));
        Ok(())
    }

    fn integer<W: Work>(&mut self, lexical: &str, work: &W) -> Result<(), Cause> {
        work.charge_work(lexical.len() as u64)
            .map_err(Cause::Resource)?;
        self.events.push(Written::Text(lexical.to_owned()));
        Ok(())
    }
}

impl PolicyWriter for Draft {
    type Digest = [u8; 2];

    fn policy_digest<W: Work>(
        &self,
        document: &[u8],
        method: &str,
        transform: &PolicyTransform<'_, Self::Fragment>,
        work: &W,
    ) -> Result<Self::Digest, Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        assert_eq!(document, b"actual policy document");
        assert_eq!(method, "urn:digest");
        match transform {
            PolicyTransform::None => Ok([1, 0]),
            PolicyTransform::Xml(plan) if *plan == &"same plan" => Ok([2, 0]),
            PolicyTransform::InSpecification(spec) if spec.uri == "urn:oid:1.2.3" => Ok([3, 0]),
            PolicyTransform::Xml(_) | PolicyTransform::InSpecification(_) => Err(Cause::Source),
        }
    }

    fn matches_policy<W: Work>(
        &self,
        policy: &produce::ExplicitPolicy<'_, Self::Fragment>,
        work: &W,
    ) -> Result<bool, Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        Ok(self.signature == 0 && policy.identifier.uri == "urn:policy:v1")
    }
}

fn id(uri: &str) -> Identifier<'_> {
    Identifier {
        uri,
        qualifier: None,
        description: None,
        documentation: &[],
    }
}

fn names(draft: &Draft) -> Vec<(&'static str, &'static str)> {
    draft
        .events
        .iter()
        .filter_map(|event| match event {
            Written::Begin(ns, local) => Some((*ns, *local)),
            _ => None,
        })
        .collect()
}

#[test]
fn object_format_uses_schema_order_and_actual_reference_metadata() {
    // The URI resolves to the instruction, and MimeType and Encoding must
    // agree with its actual ds:Object attributes before producing output.
    let tree = Tree::normal();
    let mut draft = Draft::new(&tree, None);
    let work = memory(100_000);
    let format = produce::DataObjectFormat {
        reference: "#ref",
        description: Some("text"),
        identifier: Some(id("urn:type")),
        mime_type: Some("text/plain"),
        encoding: Some("urn:encoding"),
    };
    for format in [
        produce::DataObjectFormat {
            reference: "#other",
            ..format
        },
        produce::DataObjectFormat {
            encoding: Some("urn:other"),
            ..format
        },
        produce::DataObjectFormat {
            mime_type: Some("text/html"),
            ..format
        },
    ] {
        assert!(format.write(&mut draft, &work).is_err());
        assert_eq!(draft.events, [] as [Written; 0]);
    }
    format.write(&mut draft, &work).unwrap();
    assert_eq!(
        names(&draft),
        [
            (XADES, "DataObjectFormat"),
            (XADES, "Description"),
            (XADES, "ObjectIdentifier"),
            (XADES, "Identifier"),
            (XADES, "MimeType"),
            (XADES, "Encoding"),
        ]
    );
}

#[test]
fn commitment_uses_the_selected_reference_form() {
    // An explicitly selected commitment rejects foreign and empty references.
    // The All form emits the alternate element instead of an empty list.
    let tree = Tree::normal();
    let mut draft = Draft::new(&tree, None);
    let work = memory(100_000);
    for scope in [
        produce::CommitmentScope::References(&[]),
        produce::CommitmentScope::References(&["#other"]),
        produce::CommitmentScope::References(&["#ref"]),
        produce::CommitmentScope::All,
    ] {
        draft.events.clear();
        let result = produce::Commitment {
            identifier: Identifier {
                description: Some("proof"),
                documentation: &["urn:doc"],
                ..id("urn:commitment")
            },
            scope,
            qualifiers: &["extension"],
        }
        .write(&mut draft, &work);
        let expected = match scope {
            produce::CommitmentScope::References([] | ["#other"]) => {
                assert!(result.is_err());
                assert_eq!(draft.events, [] as [Written; 0]);
                continue;
            }
            produce::CommitmentScope::References(_) => "ObjectReference",
            produce::CommitmentScope::All => "AllSignedDataObjects",
        };
        result.unwrap();
        assert_eq!(
            names(&draft),
            [
                (XADES, "CommitmentTypeIndication"),
                (XADES, "CommitmentTypeId"),
                (XADES, "Identifier"),
                (XADES, "Description"),
                (XADES, "DocumentationReferences"),
                (XADES, "DocumentationReference"),
                (XADES, expected),
                (XADES, "CommitmentTypeQualifiers"),
                (XADES, "CommitmentTypeQualifier"),
            ]
        );
    }
}

#[test]
fn place_and_role_producers_preserve_ordered_fields() {
    // The actual V2 sequence has StreetAddress and forbids an empty address.
    let tree = Tree::normal();
    let mut draft = Draft::new(&tree, None);
    let work = memory(100_000);
    assert!(
        produce::ProductionPlace::default()
            .write(&mut draft, &work)
            .is_err()
    );
    assert_eq!(draft.events, [] as [Written; 0]);
    produce::ProductionPlace {
        city: Some("City"),
        street: Some("Street"),
        state_or_province: Some("State"),
        postal_code: Some("123"),
        country: Some("Country"),
    }
    .write(&mut draft, &work)
    .unwrap();
    assert_eq!(
        names(&draft),
        [
            (XADES, "SignatureProductionPlaceV2"),
            (XADES, "City"),
            (XADES, "StreetAddress"),
            (XADES, "StateOrProvince"),
            (XADES, "PostalCode"),
            (XADES, "CountryName"),
        ]
    );

    // Native and extension credentials have distinct wrappers; claims and
    // third-party assertions retain both their content and ordering.
    draft.events.clear();
    produce::SignerRole {
        claimed: &["claimed"],
        certified: &[produce::CertifiedRole::Other("certificate")],
        assertions: &["signed assertion"],
    }
    .write(&mut draft, &work)
    .unwrap();
    assert_eq!(
        names(&draft),
        [
            (XADES, "SignerRoleV2"),
            (XADES, "ClaimedRoles"),
            (XADES, "ClaimedRole"),
            (XADES, "CertifiedRolesV2"),
            (XADES, "CertifiedRole"),
            (XADES, "OtherAttributeCertificate"),
            (XADES, "SignedAssertions"),
            (XADES, "SignedAssertion"),
        ]
    );
}

#[test]
fn policy_uses_the_same_transform_plan_and_original_store_document() {
    // Hashing and XML emission share the typed transform plan; the special
    // ETSI transform emits the exact specification used by its digest.
    let work = memory(100_000);
    let tree = Tree::normal();
    let spec = Identifier {
        qualifier: Some(Qualifier::Urn),
        ..id("urn:oid:1.2.3")
    };
    let mut draft = Draft::new(&tree, None);
    for (transform, digest) in [
        (PolicyTransform::None, 1),
        (PolicyTransform::Xml(&"same plan"), 2),
        (PolicyTransform::InSpecification(spec), 3),
    ] {
        draft.events.clear();
        let argument = produce::SignaturePolicy::Explicit(produce::ExplicitPolicy {
            identifier: id("urn:policy:v1"),
            document: b"actual policy document",
            digest_method: "urn:digest",
            transform,
            qualifiers: &[
                produce::PolicyQualifier::Uri("urn:location"),
                produce::PolicyQualifier::Notice(produce::UserNotice {
                    reference: Some(produce::NoticeReference {
                        organization: "org",
                        numbers: &["-10000000000000000000000000000000"],
                    }),
                    text: Some("notice"),
                }),
            ],
        });
        argument.write(&mut draft, &work).unwrap();
        let events = names(&draft);
        assert!(draft.events.contains(&Written::Binary(vec![digest, 0])));
        assert_eq!(
            events.contains(&(XADES_141, "SPDocSpecification")),
            digest == 3
        );
        assert_eq!(
            draft
                .events
                .contains(&Written::Text("transforms:same plan".into())),
            digest == 2
        );
        assert!(events.contains(&(XADES, "SPURI")));
        assert!(events.contains(&(XADES, "SPUserNotice")));
        assert!(events.contains(&(XADES, "int")));
        let produce::SignaturePolicy::Explicit(policy) = argument else {
            unreachable!()
        };
        draft.events.clear();
        draft.signature = 1;
        let store = produce::PolicyStore {
            specification: spec,
            document: produce::PolicyDocument::Embedded,
        };
        assert!(matches!(
            policy.write_store(&store, &mut draft, &work),
            Err(Error::Foreign)
        ));
        assert_eq!(draft.events, [] as [Written; 0]);
        draft.signature = 0;
        for document in [
            produce::PolicyDocument::Embedded,
            produce::PolicyDocument::LocalUri("urn:local"),
        ] {
            let embedded = matches!(document, produce::PolicyDocument::Embedded);
            draft.events.clear();
            policy
                .write_store(
                    &produce::PolicyStore {
                        specification: spec,
                        document,
                    },
                    &mut draft,
                    &work,
                )
                .unwrap();
            assert_eq!(names(&draft)[0], (XADES_141, "SignaturePolicyStore"));
            assert_eq!(
                draft
                    .events
                    .contains(&Written::Binary(b"actual policy document".to_vec())),
                embedded,
            );
            assert_eq!(
                names(&draft).contains(&(XADES_141, "SigPolDocLocalURI")),
                !embedded
            );
        }
    }
}

#[test]
fn implied_policy_has_its_own_choice_and_retains_budget_refusal() {
    // The implied branch carries no digest or external policy acquisition.
    let work = memory(100_000);
    let tree = Tree::normal();
    let mut draft = Draft::new(&tree, None);
    produce::SignaturePolicy::Implied
        .write(&mut draft, &work)
        .unwrap();
    assert_eq!(
        names(&draft),
        [
            (XADES, "SignaturePolicyIdentifier"),
            (XADES, "SignaturePolicyImplied")
        ]
    );

    // Budget refusal happens before digest callbacks and producer output.
    draft.events.clear();
    assert!(matches!(
        produce::SignaturePolicy::Implied.write(&mut draft, &memory(0)),
        Err(Error::Resource(_))
    ));
    assert_eq!(draft.events, [] as [Written; 0]);
}

#[test]
fn supplied_policy_resolves_only_the_method_and_preserves_the_asserted_digest() {
    // These bytes already belong to a policy version. Producer admission
    // checks the method and width without ever requesting policy bytes.
    let tree = Tree::normal();
    let mut draft = Draft::new(&tree, None);
    let work = memory(100_000);
    let policy = produce::SuppliedPolicy {
        identifier: id("urn:policy:v1"),
        digest_method: "urn:digest",
        digest: &[7; 32],
        transform: PolicyTransform::None,
        qualifiers: &[produce::PolicyQualifier::Uri("urn:location")],
    };
    assert!(matches!(
        policy.write(&mut draft, &work, |_, _| Ok(48)),
        Err(Error::Value("signaturePolicyId.digestWidth"))
    ));
    assert!(matches!(
        policy.write(&mut draft, &work, |_, _| Err(Cause::Source)),
        Err(Error::Writer(Cause::Source))
    ));
    assert!(matches!(
        policy.write(&mut draft, &memory(0), |_, _| panic!(
            "resource refusal must precede resolution"
        )),
        Err(Error::Resource(_))
    ));
    assert_eq!(draft.events, [] as [Written; 0]);
    policy
        .write(&mut draft, &work, |method, execution| {
            assert_eq!(method, "urn:digest");
            execution.charge_work(1).map_err(Cause::Resource)?;
            Ok(32)
        })
        .unwrap();
    assert_eq!(
        names(&draft),
        [
            (XADES, "SignaturePolicyIdentifier"),
            (XADES, "SignaturePolicyId"),
            (XADES, "SigPolicyId"),
            (XADES, "Identifier"),
            (XADES, "SigPolicyHash"),
            (super::DS, "DigestMethod"),
            (super::DS, "DigestValue"),
            (XADES, "SigPolicyQualifiers"),
            (XADES, "SigPolicyQualifier"),
            (XADES, "SPURI"),
        ]
    );
    assert!(draft.events.contains(&Written::Binary(vec![7; 32])));
}

#[test]
fn certified_role_preserves_whole_der_and_rejects_a_ber_envelope() {
    // A valid signed acinfo can sit in a non-DER outer envelope accepted in
    // CMS. The XAdES certified-role producer requires the whole DER value.
    use timestamp_oracle::tlv;
    let algorithm = tlv(0x30, &[6, 1, 42]);
    let holder = tlv(0x30, &tlv(0xa1, &tlv(0x82, b"holder.test")));
    let issuer = tlv(0xa0, &tlv(0x30, &tlv(0x82, b"issuer.test")));
    let validity = tlv(
        0x30,
        &[tlv(24, b"20261021000000Z"), tlv(24, b"20271021000000Z")].concat(),
    );
    let attributes = tlv(0x30, &tlv(0x30, &[6, 1, 44, 0x31, 2, 5, 0]));
    let info = tlv(
        0x30,
        &[
            &[2, 1, 1][..],
            &holder,
            &issuer,
            &algorithm,
            &[2, 1, 5],
            &validity,
            &attributes,
        ]
        .concat(),
    );
    let fields = [&*info, &algorithm, &[3, 3, 0, 9, 10]].concat();
    let der = tlv(0x30, &fields);
    let ber = [&[0x30, 0x80][..], &fields, &[0, 0]].concat();
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 100_000)));
    let parser = Parser::ber(work.clone());
    let mut parent = parser.read(&ber, 90).unwrap();
    assert!(matches!(
        produce::RoleCertificate::read(&mut parent),
        Err(produce::RoleCertificateError::Encoding(_))
    ));
    let mut parent = parser.read(&der, 140).unwrap();
    let certificate = produce::RoleCertificate::read(&mut parent).unwrap();
    let tree = Tree::normal();
    let mut draft = Draft::new(&tree, None);
    produce::SignerRole {
        claimed: &[],
        certified: &[produce::CertifiedRole::X509(certificate)],
        assertions: &[],
    }
    .write(&mut draft, &work)
    .unwrap();
    assert_eq!(
        names(&draft),
        [
            (XADES, "SignerRoleV2"),
            (XADES, "CertifiedRolesV2"),
            (XADES, "CertifiedRole"),
            (XADES, "X509AttributeCertificate"),
        ]
    );
    assert!(draft.events.contains(&Written::Binary(der)));
}

struct Staged {
    direct: [ContentReference<'static, usize>; 3],
    manifest: ContentReference<'static, usize>,
}

impl ContentSource for Staged {
    type Id = usize;
    type Error = Cause;

    fn signed_info<W: Work>(&self, work: &W) -> Result<&[ContentReference<'_, usize>], Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        Ok(&self.direct)
    }

    fn reference<W: Work>(
        &self,
        node: usize,
        work: &W,
    ) -> Result<Option<ContentReference<'_, usize>>, Cause> {
        work.charge_work(4).map_err(Cause::Resource)?;
        Ok(self
            .direct
            .iter()
            .copied()
            .chain([self.manifest])
            .find(|reference| reference.node == node))
    }

    fn admit_method<W: Work>(&self, method: usize, work: &W) -> Result<(), Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        if method != 9 {
            return Err(Cause::Source);
        }
        Ok(())
    }

    fn replay<W: Work>(
        &self,
        reference: usize,
        method: usize,
        receiver: &mut impl structured_cms::stream::Receiver,
        work: &W,
    ) -> Result<ReplayOutcome<Cause>, Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        assert_eq!(method, 9);
        let bytes = match reference {
            1 => b"A",
            2 => b"B",
            4 => b"C",
            _ => return Ok(ReplayOutcome::Unavailable(Cause::Unavailable)),
        };
        receiver.write(bytes).map_err(|_| Cause::Source)?;
        Ok(ReplayOutcome::Complete)
    }
}

impl ContentWriter<Staged> for Draft {
    fn matches_content<W: Work>(&self, _: &Staged, work: &W) -> Result<bool, Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        Ok(self.signature == 0)
    }

    fn content_method<W: Work>(&mut self, method: usize, work: &W) -> Result<(), Cause> {
        produce::Transaction::method(self, method, work)
    }
}

fn parse_request<'a>(bytes: &'a [u8], parser: &'a Parser) -> (Request<'a>, Reader<'a>) {
    let mut reader = parser.read(bytes, 400).unwrap();
    let root = reader.next_element().unwrap().unwrap();
    let request = Request::read(&reader, &root).unwrap();
    assert_eq!(request.as_bytes(), bytes);
    (request, reader)
}

#[test]
fn content_requests_follow_reference_roles_and_checked_tokens_stay_in_their_draft() {
    // All uses SignedInfo order and excludes SignedProperties/Manifest
    // leaves. Individual keeps Include order, including a selected Manifest.
    let source = Staged {
        direct: [
            ContentReference {
                node: 1,
                include_uri: Some("#a"),
                signed_properties: false,
            },
            ContentReference {
                node: 2,
                include_uri: None,
                signed_properties: false,
            },
            ContentReference {
                node: 3,
                include_uri: Some("#props"),
                signed_properties: true,
            },
        ],
        manifest: ContentReference {
            node: 4,
            include_uri: Some("#m"),
            signed_properties: false,
        },
    };
    let work = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1_000_000)));
    for node in [2, 3, 999] {
        assert!(matches!(
            ContentInput::prepare(&source, 9, ContentScope::Individual(&[node]), &work),
            Err(produce::ContentInputError::Reference(reference)) if reference == node
        ));
    }
    let tree = Tree::normal();
    for (scope, bytes, leaf) in [
        (
            ContentScope::All,
            b"AB".as_slice(),
            "AllDataObjectsTimeStamp",
        ),
        (
            ContentScope::Individual(&[4, 1]),
            b"CA".as_slice(),
            "IndividualDataObjectsTimeStamp",
        ),
    ] {
        assert_checked_content(&source, scope, bytes, leaf, &tree, &work);
    }
}

fn assert_checked_content(
    source: &Staged,
    scope: ContentScope<'_, usize>,
    bytes: &[u8],
    property: &'static str,
    tree: &Tree,
    work: &Memory,
) {
    let (provider, token, tsa_bytes, request_bytes) =
        timestamp_oracle::fixture_unstated_accuracy(bytes);
    let parser = Parser::der(work.clone());
    let (original, algorithm_reader) = parse_request(&request_bytes, &parser);
    let structured_cms::timestamp::HashAlgorithmReading::Identifier(algorithm) =
        *original.imprint().algorithm()
    else {
        panic!("the generated fixture has a SHA-256 identifier");
    };
    let plan = ContentInput::prepare(source, 9, scope, work).unwrap();
    let request = |nonce| ContentRequest {
        algorithm,
        policy: None,
        nonce,
        cert_req: true,
        extensions: &[],
    };
    let pending = plan
        .request(&provider, &algorithm_reader, &request(Some(&[7])))
        .unwrap();
    assert_eq!(pending.request_bytes(), request_bytes);
    let response_bytes = timestamp_oracle::tlv(48, &[&[48, 3, 2, 1, 0][..], &token].concat());
    let mut response_reader = parser.read(&response_bytes, 900).unwrap();
    let response = Response::read(&mut response_reader).unwrap();
    let tsa = structured_pkix::Certificate::read(&parser, &tsa_bytes, 2000).unwrap();
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let context = CheckContext {
        certificate: &tsa,
        certificate_parent: &algorithm_reader,
        key: EffectiveKey::standing(tsa.tbs().public_key()),
        requested: Some(Requested {
            request: &original,
            parent: &algorithm_reader,
        }),
        utc: &utc,
        reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
        window: None,
        policy_accuracy: None,
    };
    let check = produce::ResponseCheck {
        response: &response,
        provider: &provider,
        query: &response_reader,
        context: &context,
    };
    // A different nonce for the identical content cannot reuse this response.
    let other = plan
        .request(&provider, &algorithm_reader, &request(Some(&[8])))
        .unwrap();
    assert!(matches!(
        other.check_response(&check, |_, _| Ok::<_, ()>(false)),
        Err(produce::ContentResponseError::ForeignRequest)
    ));
    let checked = pending
        .check_response(&check, |_, _| Ok::<_, ()>(false))
        .unwrap();
    let stamps = [checked];
    assert!(stamps[0].facts().timestamp().unwrap().evidence().is_some());
    let mut draft = Draft::new(tree, None);
    draft.signature = 1;
    assert!(matches!(
        plan.write(&stamps, &mut draft, work),
        Err(Error::Foreign)
    ));
    assert_eq!(draft.events, [] as [Written; 0]);
    draft.signature = 0;
    let independent = ContentInput::prepare(source, 9, scope, work).unwrap();
    assert!(matches!(
        independent.write(&stamps, &mut draft, work),
        Err(Error::Foreign)
    ));
    assert_eq!(draft.events, [] as [Written; 0]);
    plan.write(&stamps, &mut draft, work).unwrap();
    assert_eq!(names(&draft)[0], (XADES, property));
    assert!(draft.events.contains(&Written::Method(9)));
    assert!(draft.events.contains(&Written::Binary(token)));
    let includes: Vec<_> = draft
        .events
        .iter()
        .filter_map(|event| match event {
            Written::Attribute("URI", uri) => Some(uri.as_str()),
            _ => None,
        })
        .collect();
    match scope {
        ContentScope::All => assert_eq!(includes, [] as [&str; 0]),
        ContentScope::Individual(_) => {
            assert_eq!(includes, ["#m", "#a"]);
            assert_eq!(draft.events.iter().filter(|event|
                matches!(event, Written::Attribute("referencedData", value) if value == "true")
            ).count(), 2);
        }
    }
}
