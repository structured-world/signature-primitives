use super::*;
#[path = "../support/native.rs"]
mod oracle;
use super::super::support::{File, Input, finish, memory, zip};
use oracle::{Oracle, certificate, message, signer, tlv};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use structured_asic::{Limits, Session, manifest, references, zip::Archive};
use structured_asn1::{Parser, Reader, digest::Resolution, memory::OwnedVec};
use structured_cms::{
    evidence::{
        ArchiveTimeStamp,
        verify::{Authorities, Decision, Selection},
    },
    oid,
};
use structured_pkix::{
    Certificate,
    path::WorkingKey,
    temporal::{Instant, LeapTable},
};
use structured_xades::{
    binary::{BinaryXml, Decoded, OwnedBinaryXml, OwnedDecoded},
    certificate::{Agreement, DigestProvider},
    scalar::{Datatype, Fact, ScalarXml, UriValue, UriXml},
    xml::Access,
};

impl UriXml for Tree {
    fn with_uri<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        source: LexicalSource<'_>,
        work: &W,
        visit: impl for<'a> FnOnce(UriValue<'a>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Failure, VE>> {
        let LexicalSource::Attribute(name) = source else {
            return visit(UriValue::Unsupported).map_err(VisitError::Visitor);
        };
        self.attribute(snapshot, node, name, work, |value| {
            visit(match value {
                None => UriValue::Absent,
                Some(value) => UriValue::Valid(value),
            })
        })
        .map_err(VisitError::Processing)?
        .map_err(VisitError::Visitor)
    }
}
impl ScalarXml for Tree {
    fn scalar<W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        source: LexicalSource<'_>,
        datatype: Datatype,
        work: &W,
    ) -> Result<Fact, Failure> {
        if datatype != Datatype::AnyUri {
            return Ok(Fact::Unsupported);
        }
        match self.with_uri(snapshot, node, source, work, |value| {
            Ok::<_, Infallible>(match value {
                UriValue::Absent => Fact::Absent,
                UriValue::Valid(_) => Fact::Valid,
                UriValue::Malformed => Fact::Malformed,
                UriValue::ComplexContent => Fact::ComplexContent,
                UriValue::Unsupported => Fact::Unsupported,
            })
        }) {
            Ok(value) => Ok(value),
            Err(VisitError::Processing(cause)) => Err(cause),
            Err(VisitError::Visitor(never)) => match never {},
        }
    }
}
impl BinaryXml for Tree {
    fn with_octets<R, C, W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        work: &W,
        visit: impl for<'a> FnOnce(&'a [u8]) -> Result<R, C>,
    ) -> Result<Result<R, C>, Failure> {
        let bytes = self
            .row(snapshot, node, work)?
            .binary
            .as_deref()
            .ok_or(Failure::Unsupported)?;
        work.charge_work(bytes.len() as u64)
            .map_err(Failure::Resource)?;
        Ok(visit(bytes))
    }
    fn with_binary<R, C>(
        &self,
        _snapshot: Snapshot<usize, u64>,
        _node: usize,
        _operation: &Reader<'_>,
        _visit: impl for<'a> FnOnce(Decoded<'a>) -> Result<R, C>,
    ) -> Result<Result<R, C>, Failure> {
        // This fixture supplies predecoded digest octets, not an ASN.1 source.
        Err(Failure::Unsupported)
    }
}
impl OwnedBinaryXml for Tree {
    fn decode_owned<W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        work: &W,
    ) -> Result<OwnedVec<u8>, Failure> {
        self.with_octets(snapshot, node, work, |bytes| {
            let mut out = work.vector();
            out.try_reserve_exact(bytes.len())?;
            out.try_extend_from_slice(bytes)?;
            Ok::<_, MemoryError>(out.into_owned())
        })?
        .map_err(Failure::Resource)
    }
    fn decode_binary_owned(
        &self,
        _snapshot: Snapshot<usize, u64>,
        _node: usize,
        _operation: &Reader<'_>,
    ) -> Result<OwnedDecoded, Failure> {
        Err(Failure::Unsupported)
    }
}
impl DigestProvider<'_, Tree> for Oracle {
    fn resolve<W: Work>(
        &self,
        access: &Access<'_, Tree, W>,
        method: usize,
    ) -> Result<Resolution<()>, oracle::Fault> {
        if self.refuse_xml {
            return Err(oracle::Fault::WrongMode);
        }
        let value = access
            .attribute(
                method,
                Name {
                    namespace: "",
                    local: "Algorithm",
                },
                |value| value == Some("http://www.w3.org/2001/04/xmlenc#sha256"),
            )
            .map_err(|cause| match cause {
                AccessError::Resource { cause, .. }
                | AccessError::Xml(Failure::Resource(cause)) => oracle::Fault::Resource(cause),
                AccessError::Changed { .. }
                | AccessError::Xml(Failure::Foreign | Failure::Unsupported) => {
                    oracle::Fault::WrongMode
                }
            })?;
        Ok(if value {
            Resolution::Supported(())
        } else {
            Resolution::Unsupported
        })
    }
    fn classify(&self, (): &()) -> structured_xades::hashes::HashClass {
        structured_xades::hashes::HashClass::OtherKnown
    }
}
fn attribute(tree: &mut Tree, node: usize, local: &'static str, value: &'static str) {
    tree.rows[node].attributes.push((
        Name {
            namespace: "",
            local,
        },
        value,
    ));
}
pub(super) fn manifest_tree(
    expected: &[u8],
    signature: &'static str,
    object: &'static str,
) -> Tree {
    let mut tree = Tree::new(ASI, "ASiCManifest");
    let sig = tree.element(0, ASI, "SigReference");
    attribute(&mut tree, sig, "URI", signature);
    let data = tree.element(0, ASI, "DataObjectReference");
    attribute(&mut tree, data, "URI", object);
    let method = tree.element(data, DS, "DigestMethod");
    attribute(
        &mut tree,
        method,
        "Algorithm",
        "http://www.w3.org/2001/04/xmlenc#sha256",
    );
    let value = tree.element(data, DS, "DigestValue");
    tree.rows[value].binary = Some(expected.to_vec());
    tree
}
struct Authority<'a> {
    certificate: &'a Certificate<'a>,
    parent: &'a Reader<'a>,
}
impl<'d> Authorities<'d> for Authority<'_> {
    type Error = Infallible;
    fn select<'a, W: Work>(
        &'a self,
        _index: usize,
        _stamp: &'a ArchiveTimeStamp<'d>,
        _work: &W,
    ) -> Result<Selection<'a>, Infallible>
    where
        'd: 'a,
    {
        Ok(Selection {
            policy_accuracy: None,
            certificate: self.certificate,
            certificate_parent: self.parent,
            key: WorkingKey::standing(self.certificate.tbs().public_key()),
        })
    }
}
fn token(data: &[u8], certificate: &[u8], root: &[u8], key: &SigningKey) -> Vec<u8> {
    let info = tlv(
        0x30,
        &[
            vec![2, 1, 1],
            tlv(6, &[42, 3]),
            tlv(
                0x30,
                &[
                    tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
                    tlv(4, &Sha256::digest(data)),
                ]
                .concat(),
            ),
            vec![2, 1, 1],
            tlv(24, b"20260101000100Z"),
            tlv(0x30, &[]),
        ]
        .concat(),
    );
    let signed = signer(
        Some(oid::TST_INFO.as_bytes()),
        &info,
        certificate,
        key,
        &[],
        &[],
    );
    assert_ne!(oracle::signature_octets(&signed), []);
    message(
        oid::TST_INFO.as_bytes(),
        Some(&info),
        &[root.to_vec(), certificate.to_vec()],
        &[],
        &[signed],
    )
}

#[test]
fn native_ers_and_manifest_hash_share_the_actual_original_object_pass() {
    // This checks the member/ERS/digest adapters with a predecoded XML fixture.
    // It does not assert ZIP-to-XML production, XMLDSig or application trust.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let tsa = certificate("TSA", "Root", &tsa_key, &root_key, true);
    let data = b"original object";
    let token = token(data, &tsa, &root, &tsa_key);
    let stamp = tlv(0x30, &token);
    let record = tlv(
        0x30,
        &[
            vec![2, 1, 1],
            tlv(0x30, &tlv(0x30, &tlv(6, oid::SHA256.as_bytes()))),
            tlv(0x30, &tlv(0x30, &stamp)),
        ]
        .concat(),
    );
    let input = Input::new(
        zip(&[
            File::stored(b"document.bin", data),
            File::stored(b"META-INF/evidence.ers", &record),
            File::stored(b"META-INF/ASiCManifest.xml", b"predecoded XML fixture"),
        ])
        .bytes,
        11,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let cert_parser = Parser::der(oracle::memory());
    let cert = Certificate::read(&cert_parser, &tsa, 100).unwrap();
    let cert_parent = cert_parser.read(&[], 100).unwrap();
    let authority = Authority {
        certificate: &cert,
        parent: &cert_parent,
    };
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    let now = Instant::new(1_767_312_000, 0).unwrap();
    let content = finish(archive.member(1, &work).unwrap().unwrap().content(&work)).unwrap();
    let (record, parent) = content.read_evidence(&work).unwrap();
    for (wrong_hash, uri, refuse) in [
        (false, "document.bin", false),
        (true, "document.bin", false),
        (false, "missing", false),
        (false, "document.bin", true),
    ] {
        let expected = if wrong_hash {
            Sha256::digest(b"wrong object")
        } else {
            Sha256::digest(data)
        };
        let tree = manifest_tree(&expected, "META-INF/evidence.ers", uri);
        let access = Access::new(&tree, tree.snapshot(), &work);
        let reading = manifest::inspect(&access, 0).unwrap();
        assert!(reading.faults().is_empty());
        let base = archive.member(2, &work).unwrap().unwrap();
        let catalogue = references::resolve_manifest(base, reading, &tree, &work).unwrap();
        let mut provider = Oracle::new();
        provider.refuse_xml = refuse;
        let checked = finish(content.check_manifest_evidence(
            &record,
            &parent,
            &provider,
            &authority,
            &utc,
            now,
            &catalogue,
            &tree,
            |_, _, _| Ok::<_, Infallible>(true),
            |_, _| Ok::<_, Infallible>(Decision::Valid),
            |_, _| Ok::<_, structured_cms::timestamp::ProfileFailure<Infallible>>(()),
        ));
        if refuse {
            // Original method/policy refusal must precede ALL hash states and
            // object I/O, rather than being discovered after ERS execution.
            assert!(checked.is_err());
            assert_eq!(provider.starts.get(), 0);
            continue;
        }
        let checked = checked.unwrap();
        if uri == "missing" {
            assert!(checked.is_none());
            assert_eq!(provider.starts.get(), 0);
        } else {
            let checked = checked.unwrap();
            assert_eq!(
                checked.object_digests(),
                &[references::DigestReading::Checked(if wrong_hash {
                    Agreement::Differs
                } else {
                    Agreement::Matches
                })]
            );
            assert!(checked.evidence().report().verified().is_some());
            assert_eq!(provider.signatures.get(), 1);
            assert_eq!(provider.objects.get(), 1);
        }
    }
    drop(record);
    drop(parent);
    drop(content);
    drop(archive);
    assert_eq!(work.used(), 0);
}

#[test]
fn all_manifest_aliases_share_one_native_state_and_keep_every_negative_slot() {
    // Three original references resolve to two whole-input outcomes. Both
    // aliases share one pass/state; a wrong value and missing member survive.
    let data = b"original object";
    let input = Input::new(
        zip(&[
            File::stored(b"document.bin", data),
            File::stored(b"META-INF/evidence.ers", b""),
            File::stored(b"META-INF/ASiCManifest.xml", b"predecoded fixture"),
        ])
        .bytes,
        7,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let mut tree = manifest_tree(
        &Sha256::digest(data),
        "META-INF/evidence.ers",
        "document.bin",
    );
    for (uri, expected) in [
        ("./document.bin", Sha256::digest(b"wrong")),
        ("missing", Sha256::digest(data)),
    ] {
        let object = tree.element(0, ASI, "DataObjectReference");
        attribute(&mut tree, object, "URI", uri);
        let method = tree.element(object, DS, "DigestMethod");
        attribute(
            &mut tree,
            method,
            "Algorithm",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        );
        let value = tree.element(object, DS, "DigestValue");
        tree.rows[value].binary = Some(expected.to_vec());
    }
    let reading = manifest::inspect(&Access::new(&tree, tree.snapshot(), &work), 0).unwrap();
    assert!(reading.faults().is_empty());
    let catalogue = references::resolve_manifest(
        archive.member(2, &work).unwrap().unwrap(),
        reading,
        &tree,
        &work,
    )
    .unwrap();
    let provider = Oracle::new();
    let checks = finish(catalogue.check_objects(&tree, &provider, &work)).unwrap();
    assert_eq!(
        checks.answers(),
        &[
            references::DigestReading::Checked(Agreement::Matches),
            references::DigestReading::Checked(Agreement::Differs),
            references::DigestReading::Unchecked(references::Unchecked::Input),
        ]
    );
    assert!(!checks.all_match(&work).unwrap());
    assert_eq!(provider.starts.get(), 1);
    assert_eq!(provider.objects.get(), 1);
    drop(checks);
    let mut refused = Oracle::new();
    refused.refuse_xml = true;
    assert!(finish(catalogue.check_objects(&tree, &refused, &work)).is_err());
    assert_eq!(refused.starts.get(), 0);
    drop(catalogue);
    drop(archive);
    assert_eq!(work.used(), 0);
}

#[test]
fn retained_original_payload_reuses_crc_proof_without_input_io_or_decode_credit_reset() {
    // The same immutable original allocation can feed another actual query,
    // without rereading ZIP or charging decoded output twice. Each query still
    // observes source/current work and an original generation change.
    use structured_asic::payload::Payload;
    use structured_cms::stream::{AsyncSource, Receiver, Refused};
    struct Count(usize);
    impl Receiver for Count {
        fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
            self.0 += bytes.len();
            Ok(())
        }
    }
    let data = b"original object";
    let input = Input::new(zip(&[File::stored(b"data", data)]).bytes, 7);
    let work = memory();
    let limits = Limits {
        max_decoded: data.len() as u64,
        ..Limits::default()
    };
    let session = Session::new(limits, work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let content = finish(archive.member(0, &work).unwrap().unwrap().content(&work)).unwrap();
    let calls = input.calls.get();
    for _ in 0..2 {
        let mut source = Payload::source(&content, &work).unwrap();
        let mut count = Count(0);
        finish(source.stream(&mut count, &work)).unwrap();
        assert_eq!(count.0, data.len());
        assert_eq!(input.calls.get(), calls);
    }
    let zero = Memory::new(Arc::new(MemoryAccount::new(1024, 0)));
    assert!(Payload::source(&content, &zero).is_err());
    input.generation.set(2);
    assert!(Payload::source(&content, &work).is_err());
    drop(content);
    drop(archive);
    assert_eq!(work.used(), 0);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one native two-signer matrix proves preflight-before-state and retains changed-payload negatives under the same production flow"
)]
fn native_detached_cades_checks_all_original_roots_and_exact_payload_in_one_pass() {
    // Real P-256 mathematics covers one actual ASiC member. Missing a root
    // refuses before hash initialization, and changed payload keeps negatives.
    use structured_cms::{
        binding::Scope,
        prepare::{self, Preparation},
        provider::SignatureAnswer,
        verify::ContentAgreement,
    };
    let key = SigningKey::from_bytes((&[5; 32]).into()).unwrap();
    let cert_bytes = certificate("Signer", "Root", &key, &key, false);
    let data = b"original object";
    let first = signer(
        Some(oid::DATA.as_bytes()),
        data,
        &cert_bytes,
        &key,
        &[],
        &[],
    );
    let marker = oracle::attribute(&[42, 3, 4], &[2, 1, 1]);
    let second = signer(
        Some(oid::DATA.as_bytes()),
        data,
        &cert_bytes,
        &key,
        &[],
        &[marker],
    );
    let encoded = message(
        oid::DATA.as_bytes(),
        None,
        core::slice::from_ref(&cert_bytes),
        &[],
        &[first, second],
    );
    for (payload, missing, valid) in [
        (data.as_slice(), false, true),
        (b"changed input".as_slice(), false, false),
        (data.as_slice(), true, true),
    ] {
        let input = Input::new(
            zip(&[
                File::stored(b"document.bin", payload),
                File::stored(b"META-INF/signature.p7s", &encoded),
            ])
            .bytes,
            7,
        );
        let work = memory();
        let session = Session::new(Limits::default(), work.clone());
        let archive = finish(Archive::read(&input, &session, &work)).unwrap();
        let content = finish(archive.member(1, &work).unwrap().unwrap().content(&work)).unwrap();
        let (message, parent) = content.read(&work).unwrap();
        assert_eq!(message.signers().len(), 2);
        let cert = &message.certificates()[0];
        let provider = Oracle::new();
        let mut requests = parent.execution().vector();
        for (index, signer) in message.signers().iter().enumerate() {
            if missing && index == 1 {
                continue;
            }
            let Preparation::Ready(request) = prepare::resolve(
                &provider,
                signer,
                WorkingKey::standing(cert.tbs().public_key()),
                &parent,
                Scope::Content(oid::DATA),
            )
            .unwrap() else {
                panic!("native fixture has supported algorithms");
            };
            requests.try_push(request).unwrap();
        }
        let payload = archive.member(0, &work).unwrap().unwrap();
        {
            let checked = finish(content.check_cades(
                structured_asic::cades::Challenge {
                    message: &message,
                    parent: &parent,
                    provider: &provider,
                    requests: requests.into_owned(),
                },
                &payload,
            ));
            match checked {
                Err(structured_asic::cades::Error::MissingSigner(_)) => {
                    assert!(missing);
                    assert_eq!(provider.starts.get(), 0);
                }
                Ok(checked) => {
                    assert!(!missing);
                    assert_eq!(checked.payload(), payload.id());
                    assert_eq!(checked.checks().checks().len(), 2);
                    for answer in checked.checks().checks() {
                        if valid {
                            assert!(matches!(answer.content(), ContentAgreement::Matches));
                            assert_eq!(answer.signature(), Some(SignatureAnswer::Valid));
                        } else {
                            assert!(matches!(answer.content(), ContentAgreement::Differs));
                            assert_eq!(answer.signature(), None);
                        }
                    }
                    if valid {
                        assert_eq!(provider.objects.get(), 1);
                    }
                }
                Err(cause) => panic!("unexpected native CAdES failure: {cause:?}"),
            }
        }
        drop(message);
        drop(parent);
        drop(content);
        drop(archive);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn native_time_assertion_binds_actual_token_and_complete_original_input() {
    // Common RFC3161/ESS/TSA checking is reused on the exact original data,
    // with independent negative imprint and immutable token/input identities.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let tsa = certificate("TSA", "Root", &tsa_key, &root_key, true);
    let data = b"original object";
    let encoded = token(data, &tsa, &root, &tsa_key);
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    for (payload, valid) in [
        (data.as_slice(), true),
        (b"changed input".as_slice(), false),
    ] {
        let input = Input::new(
            zip(&[
                File::stored(b"document.bin", payload),
                File::stored(b"META-INF/timestamp.tst", &encoded),
            ])
            .bytes,
            11,
        );
        let work = memory();
        let session = Session::new(Limits::default(), work.clone());
        let archive = finish(Archive::read(&input, &session, &work)).unwrap();
        let content = finish(archive.member(1, &work).unwrap().unwrap().content(&work)).unwrap();
        let (token, parent) = content.read_timestamp(&work).unwrap();
        {
            // The actual carried SignedData supplies the material index. The
            // complete carrier census and current refusal remain independent
            // of the later timestamp's positive or negative mathematics.
            let carried_material = content.material(token.message(), &parent).unwrap();
            let index = carried_material.index(&work).unwrap();
            let query = archive.ltv_query(&work);
            let occurrences = index
                .all_occurrences(&query)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(occurrences.len(), 2);
            assert!(
                occurrences
                    .iter()
                    .all(|entry| entry.location().node == structured_asic::source::Node::Member(1))
            );
            drop(index);
            let census = structured_asic::layout::Census::read(&archive, &work).unwrap();
            let missing = structured_asic::material::Sources::read(&census, &[], &work).unwrap();
            assert!(!missing.all_sources_inspected());
            assert_eq!(missing.slots().len(), 1);
            let sources =
                structured_asic::material::Sources::read(&census, &[&carried_material], &work)
                    .unwrap();
            assert!(sources.all_sources_inspected());
            let index = sources.index(&work).unwrap();
            assert_eq!(
                index
                    .all_occurrences(&query)
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
                    .len(),
                2
            );
            let zero = Memory::new(Arc::new(MemoryAccount::new(1024, 0)));
            assert!(sources.index(&zero).is_err());
        }
        let cert_parser = Parser::der(oracle::memory());
        let cert = Certificate::read(&cert_parser, &tsa, 100).unwrap();
        let provider = Oracle::new();
        let verification = structured_cms::timestamp::CheckContext {
            policy_accuracy: None,
            certificate: &cert,
            certificate_parent: &cert_parser.read(&[], 100).unwrap(),
            key: WorkingKey::standing(cert.tbs().public_key()),
            requested: None,
            utc: &utc,
            reference: None,
            window: None,
        };
        let payload = archive.member(0, &work).unwrap().unwrap();
        let checked = finish(content.check_assertion_actor(
            &token,
            &parent,
            &provider,
            &verification,
            &payload,
            structured_asic::timestamp::InputKind::Data,
            |_, _| Ok::<_, Infallible>(true),
        ))
        .unwrap();
        assert_eq!(checked.token(), content.member().id());
        assert_eq!(checked.input(), payload.id());
        assert_eq!(checked.actor().is_some(), valid);
        assert!(checked.facts().evidence().is_none());
        if valid {
            assert_eq!(provider.signatures.get(), 1);
            assert_eq!(provider.objects.get(), 1);
        }
        drop(checked);
        drop(token);
        drop(parent);
        drop(content);
        drop(archive);
        assert_eq!(work.used(), 0);
    }
}
