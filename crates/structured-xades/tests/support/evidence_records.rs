//! Independent signed timestamp bytes over exact original ERS input groups.

use super::*;
use core::convert::Infallible;
use sha2::{Digest, Sha256, Sha512};
use structured_asn1::Parser;
use structured_cms::evidence::{
    ArchiveTimeStamp,
    verify::{Authorities, Decision, Selection},
};
use structured_pkix::{
    Certificate,
    algorithm::digest::Algorithm,
    path::EffectiveKey,
    temporal::{Instant, LeapTable},
};
use structured_xades::evidence::{
    self, Edit, EditError, Format, Placement, SealingDraft, SealingWriter, Transition, XADES_ERS,
    XML_ERS, xmlers,
};
use structured_xades::produce;
use timestamp_oracle::{fixture, fixture_sha512, tlv};

fn add(xml: &mut Tree, parent: usize, namespace: &'static str, local: &'static str) -> usize {
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(parent), namespace, local));
    node
}

fn group(xml: &mut Tree, format: Format) -> (usize, usize) {
    let group = add(xml, 7, XADES_ERS, "SealingEvidenceRecords");
    let (ns, name) = match format {
        Format::Asn1 => (XADES_ERS, "ASN1EvidenceRecord"),
        Format::Xml => (XML_ERS, "EvidenceRecord"),
    };
    (group, add(xml, group, ns, name))
}

impl SealingWriter for lifecycle::Draft {
    fn sealing_placement(&self) -> Placement<usize> {
        Placement::Serial(self.parent)
    }
}

impl SealingDraft for Tree {
    fn check_sealing_transition<W: Work>(
        &self,
        transition: Transition<usize, u8, u8>,
        work: &W,
    ) -> Result<bool, Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        self.check(transition.staged, transition.staged_member)?;
        Ok(transition.first_seal
            && transition.original_signature == 0
            && transition.staged_signature == 0
            && matches!(transition.placement, Placement::Serial(Some(7)))
            && !self.incomplete)
    }
}

#[test]
fn parallel_objects_exclude_their_own_group_and_serial_objects_cover_it_once() {
    // Original unsigned properties and the earlier sealing group are protected
    // complete objects, without flattening the two parallel member values.
    let mut xml = preparation_tree();
    let (first, left) = group(&mut xml, Format::Asn1);
    let right = add(&mut xml, first, XADES_ERS, "ASN1EvidenceRecord");
    let (second, serial) = group(&mut xml, Format::Asn1);
    let other_property = add(&mut xml, 7, XADES, "CertificateValues");
    let unrelated = add(&mut xml, 0, DS, "Object");
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let records = evidence::read(&access, &bound).unwrap();
    assert_eq!(records.groups()[0].members(), 0..2);
    assert_eq!(records.groups()[1].members(), 2..3);
    let nodes = |index| {
        records
            .objects(&xml, index, &work)
            .unwrap()
            .sources()
            .iter()
            .map(evidence::Object::node)
            .collect::<Vec<_>>()
    };
    let earlier = nodes(0);
    assert_eq!(earlier, nodes(1));
    for node in [left, right, serial, first, second, 1] {
        assert!(!earlier.contains(&node));
    }
    assert!(earlier.contains(&unrelated));
    assert!(earlier.contains(&other_property));
    let later = nodes(2);
    assert_eq!(
        later.iter().copied().filter(|&node| node == first).count(),
        1
    );
    assert!(!later.contains(&second));
    assert!(!records.ordinary_edits_allowed());
    assert!(
        matches!(records.edit(&access, Edit::Parallel(Format::Asn1), None).unwrap().placement(), Placement::Parallel(node) if node == second)
    );
    assert!(matches!(
        records.edit(&access, Edit::Serial(Format::Xml), None),
        Err(EditError::Placement(0))
    ));
    let method = xml.element_child(9, DS, "CanonicalizationMethod");
    assert!(
        matches!(Input::prepare_append(&xml, &bound, timestamp::AppendKind::Signature, method, &work), Err(InputError::Unexpected { node }) if node == first)
    );

    xml.generation.set(2);
    assert!(records.objects(&xml, 0, &work).is_err());
}

#[test]
fn the_sealing_vocabulary_refuses_mixed_or_empty_groups() {
    // A positive prefix never hides a different type in a later group.
    let mut xml = preparation_tree();
    group(&mut xml, Format::Asn1);
    let (empty, member) = group(&mut xml, Format::Xml);
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    assert!(
        matches!(evidence::read(&access, &bound), Err(evidence::Error::Mixed(node)) if node == member)
    );
    xml.nodes[member].parent = None;
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(
        matches!(evidence::read(&access, &bound), Err(evidence::Error::Empty(node)) if node == empty)
    );
}

#[test]
fn manifest_replay_includes_leaf_bytes_without_counting_intermediate_manifest_links() {
    // TS 119 132-3 §5.2.2.1 step 6 expands nested authenticated Manifests;
    // the outer SignedInfo input is protected independently under step 1.
    let mut xml = preparation_tree();
    let manifest = add(&mut xml, 1, DS, "Manifest");
    let child = add(&mut xml, 1, DS, "Manifest");
    xml.references[0].target = Some(manifest);
    let link = add(&mut xml, manifest, DS, "Reference");
    let leaf = add(&mut xml, child, DS, "Reference");
    xml.references.extend([
        Reference {
            node: link,
            target: Some(child),
            kind: None,
            status: Status::Valid,
            coverage: Coverage::Transformed,
        },
        Reference {
            node: leaf,
            target: None,
            kind: None,
            status: Status::Valid,
            coverage: Coverage::Transformed,
        },
    ]);
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let records = evidence::read(&access, &bound).unwrap();
    let mut objects = records.serial_objects(&xml, &work).unwrap();
    let original: Vec<_> = objects
        .sources()
        .iter()
        .map(evidence::Object::node)
        .collect();
    assert!(original.contains(&xml.references[0].node));
    assert!(original.contains(&leaf));
    assert!(!original.contains(&link));
    drop(objects);
    xml.references.last_mut().unwrap().status = Status::Invalid;
    assert!(matches!(
        records.serial_objects(&xml, &work),
        Err(evidence::ObjectError::Reference { node, status: Status::Invalid }) if node == leaf
    ));
}

fn original_octets(xml: &Tree, index: usize, memory: &Memory) -> Vec<Vec<u8>> {
    let access = Access::new(xml, xml.snapshot(), memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let records = evidence::read(&access, &bound).unwrap();
    let mut input = records.objects(xml, index, memory).unwrap();
    let mut objects = Vec::new();
    for source in input.sources() {
        let mut bytes = Collect::new(memory);
        stream::run(source, &mut bytes, memory, "fixture", 0).unwrap();
        objects.push(bytes.bytes().to_vec());
    }
    objects
}

fn hash_original(xml: &Tree, index: usize, memory: &Memory) -> Vec<[u8; 32]> {
    let mut hashes: Vec<_> = original_octets(xml, index, memory)
        .iter()
        .map(|bytes| Sha256::digest(bytes).into())
        .collect();
    hashes.sort_unstable();
    hashes
}

struct Select<'a> {
    parent: &'a structured_asn1::Reader<'a>,
    certificate: &'a Certificate<'a>,
}

impl Select<'_> {
    fn selection(&self) -> Selection<'_> {
        Selection {
            certificate: self.certificate,
            certificate_parent: self.parent,
            key: EffectiveKey::standing(self.certificate.tbs().public_key()),
            policy_accuracy: None,
        }
    }
}

impl<'document> Authorities<'document> for Select<'_> {
    type Error = Infallible;
    fn select<'a, W: Work>(
        &'a self,
        _: usize,
        _: &'a ArchiveTimeStamp<'document>,
        _: &W,
    ) -> Result<Selection<'a>, Self::Error>
    where
        'document: 'a,
    {
        Ok(self.selection())
    }
}

impl xmlers::Authority<usize> for Select<'_> {
    type Error = Infallible;
    fn select<'a, W: Work>(
        &'a self,
        _: &xmlers::Stamp<usize>,
        _: &structured_cms::timestamp::Token<'_>,
        _: &structured_asn1::Reader<'_>,
        _: &W,
    ) -> Result<Selection<'a>, Self::Error> {
        Ok(self.selection())
    }
}

fn asn1_record(hashes: &[[u8; 32]], token: &[u8]) -> Vec<u8> {
    let algorithm = tlv(0x30, &tlv(6, Algorithm::Sha256.identifier().as_bytes()));
    let mut first = Vec::new();
    for hash in hashes {
        first.extend(tlv(4, hash));
    }
    let mut stamp = tlv(0xa2, &tlv(0x30, &first));
    stamp.extend(token);
    tlv(
        0x30,
        &[
            vec![2, 1, 1],
            tlv(0x30, &algorithm),
            tlv(0x30, &tlv(0x30, &tlv(0x30, &stamp))),
        ]
        .concat(),
    )
}

#[test]
fn rfc4998_seals_verify_the_committed_group_with_real_tsa_math() {
    // One exact DER RFC 4998 record over the selected original reference and
    // XML sources. The issuer above retains proof only after the complete check.
    let mut xml = preparation_tree();
    let work = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 8_000_000)));
    let plan = {
        let access = Access::new(&xml, xml.snapshot(), &work);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        evidence::read(&access, &bound)
            .unwrap()
            .edit(&access, Edit::Serial(Format::Asn1), None)
            .unwrap()
    };
    let mut draft = lifecycle::Draft::new(&xml, Some(7));
    let (_, node) = group(&mut xml, Format::Asn1);
    xml.generation.set(xml.generation.get() + 1);
    let hashes = hash_original(&xml, 0, &work);
    let (provider, token, cert) = fixture(&hashes.concat());
    let value = asn1_record(&hashes, &token);
    plan.write_asn1(&mut draft, &value, &work).unwrap();
    assert!(matches!(
        draft.events.as_slice(),
        [lifecycle::Written::Begin(XADES_ERS, "SealingEvidenceRecords"),
         lifecycle::Written::Begin(XADES_ERS, "ASN1EvidenceRecord"),
         lifecycle::Written::Binary(written), lifecycle::Written::End, lifecycle::Written::End]
        if written == &value
    ));
    draft.parent = Some(node);
    let count = draft.events.len();
    assert!(matches!(
        plan.write_asn1(&mut draft, &value, &work),
        Err(produce::Error::Foreign)
    ));
    assert_eq!(draft.events.len(), count);
    xml.binary_routes.push((node, value));
    let parser = Parser::der(work.clone());
    let operation = parser.read(&[], 0).unwrap();
    let certificate = Certificate::read(&parser, &cert, 3000).unwrap();
    let select = Select {
        parent: &operation,
        certificate: &certificate,
    };
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let time = Instant::new(1_800_000_000, 0).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let records = evidence::read(&access, &bound).unwrap();
    let proof = records
        .with_asn1(&xml, 0, &operation, |mut record| {
            let (reader, original) = record.original();
            let previous = record.hash_tree_renewal().unwrap();
            let mut prefix = Vec::new();
            previous
                .stream_der(reader, |bytes, _| {
                    prefix.extend_from_slice(bytes);
                    Ok::<_, Infallible>(())
                })
                .unwrap();
            assert_eq!(
                prefix,
                tlv(0x30, original.chains()[0].original().element().as_bytes())
            );
            assert_eq!(
                record.timestamp_renewal().unwrap().element().as_bytes(),
                token
            );
            let result = record
                .verify(
                    &provider,
                    &select,
                    &utc,
                    time,
                    |_, _, _| Ok::<_, ()>(false),
                    |_, _| Ok::<_, ()>(Decision::Valid),
                )
                .unwrap();
            let proof = result.verified().unwrap();
            assert_eq!(proof.location().node, node);
            assert_eq!(proof.signature(), 0);
            Ok::<_, ()>(proof)
        })
        .unwrap();
    plan.authorize_commit(&access, &records, &proof).unwrap();
    let exhausted = memory(0);
    let refused = Access::new(&xml, xml.snapshot(), &exhausted);
    assert!(matches!(
        plan.authorize_commit(&refused, &records, &proof),
        Err(EditError::Resource(_, MemoryError::WorkExceeded))
    ));
    xml.incomplete = true;
    let changed = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        plan.authorize_commit(&changed, &records, &proof),
        Err(EditError::Changed(at)) if at == node
    ));
}

impl xmlers::XmlRecordXml for Tree {
    fn evidence_digest<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        method: usize,
        _: &W,
    ) -> Result<structured_asn1::digest::Resolution<Algorithm>, Cause> {
        self.check(snapshot, method)?;
        let sha512 = self.evidence_attributes.iter().any(|&(node, key, value)| {
            node == method
                && key == "Algorithm"
                && value == "http://www.w3.org/2001/04/xmlenc#sha512"
        });
        Ok(structured_asn1::digest::Resolution::Supported(if sha512 {
            Algorithm::Sha512
        } else {
            Algorithm::Sha256
        }))
    }

    fn canonicalize_evidence<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        method: usize,
        input: xmlers::CanonicalInput<'_, usize>,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Cause> {
        self.canonicalize(snapshot, input.node(), method, receiver, work)?;
        if let xmlers::CanonicalInput::Sequence { chains, .. } = input {
            for chain in chains {
                self.canonicalize(snapshot, chain.chain.node, method, receiver, work)?;
            }
        }
        Ok(())
    }
}

fn xml_stamp<const WIDTH: usize>(
    xml: &mut Tree,
    parent: usize,
    order: &'static str,
    hashes: &[[u8; WIDTH]],
) -> usize {
    let stamp = add(xml, parent, XML_ERS, "ArchiveTimeStamp");
    xml.evidence_attributes.push((stamp, "Order", order));
    if !hashes.is_empty() {
        let tree = add(xml, stamp, XML_ERS, "HashTree");
        let first = add(xml, tree, XML_ERS, "Sequence");
        xml.evidence_attributes.push((first, "Order", "1"));
        for hash in hashes {
            let value = add(xml, first, XML_ERS, "DigestValue");
            xml.binary_routes.push((value, hash.to_vec()));
        }
    }
    let timestamp = add(xml, stamp, XML_ERS, "TimeStamp");
    let token = add(xml, timestamp, XML_ERS, "TimeStampToken");
    xml.evidence_attributes.push((token, "Type", "RFC3161"));
    token
}

#[test]
fn rfc6283_initial_and_renewal_follow_order_and_verify_actual_octets() {
    // The second timestamp appears first in the document. The explicit Order
    // determines which exact TimeStamp subtree is hashed during renewal.
    let mut xml = preparation_tree();
    let (_, member) = group(&mut xml, Format::Xml);
    let work = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 8_000_000)));
    let hashes = hash_original(&xml, 0, &work);
    xml.evidence_attributes.push((member, "Version", "1.0"));
    let sequence = add(&mut xml, member, XML_ERS, "ArchiveTimeStampSequence");
    let chain = add(&mut xml, sequence, XML_ERS, "ArchiveTimeStampChain");
    xml.evidence_attributes.push((chain, "Order", "1"));
    let digest = add(&mut xml, chain, XML_ERS, "DigestMethod");
    let method = add(&mut xml, chain, XML_ERS, "CanonicalizationMethod");
    xml.evidence_attributes.extend([
        (
            digest,
            "Algorithm",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ),
        (
            method,
            "Algorithm",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
        ),
    ]);
    let renewed = xml_stamp::<32>(&mut xml, chain, "2", &[]);
    let initial = xml_stamp(&mut xml, chain, "1", &hashes);
    let (provider, original, cert) = fixture(&hashes.concat());
    let time_stamp = xml.nodes[initial].parent.unwrap();
    let covered = [
        b'E',
        u8::try_from(time_stamp).unwrap(),
        b'M',
        u8::try_from(method).unwrap(),
    ];
    let (_, renewal, _) = fixture(&covered);
    xml.binary_routes
        .extend([(initial, original), (renewed, renewal)]);
    let parser = Parser::der(work.clone());
    let operation = parser.read(&[], 0).unwrap();
    let certificate = Certificate::read(&parser, &cert, 3000).unwrap();
    let select = Select {
        parent: &operation,
        certificate: &certificate,
    };
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let reference = Instant::new(1_800_000_000, 0).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let records = evidence::read(&access, &bound).unwrap();
    let check = xmlers::Check {
        provider: &provider,
        operation: &operation,
        authorities: &select,
        utc: &utc,
        reference,
    };
    let report = check
        .xml(
            &xml,
            &records,
            0,
            |_, _, _| Ok::<_, ()>(false),
            |history, _| {
                assert_eq!(
                    history.evidence.following.is_some(),
                    history.stamp.token == initial
                );
                Ok::<_, ()>(Decision::Valid)
            },
        )
        .unwrap();
    assert_eq!(
        report
            .findings()
            .map(xmlers::Finding::token)
            .collect::<Vec<_>>(),
        [initial, renewed]
    );
    assert!(report.findings().all(|stamp| stamp.evidence().is_some()));
    let exhausted = memory(0);
    let refused = Access::new(&xml, xml.snapshot(), &exhausted);
    assert!(matches!(
        xmlers::read(&refused, &records, 0),
        Err(xmlers::Error::Access(AccessError::Resource { .. })
            | xmlers::Error::Resource(_, MemoryError::WorkExceeded))
    ));

    let renewal_node = xml.nodes[xml.nodes[renewed].parent.unwrap()]
        .parent
        .unwrap();
    xml.evidence_attributes
        .iter_mut()
        .find(|attribute| attribute.0 == renewal_node && attribute.1 == "Order")
        .unwrap()
        .2 = "1";
    let access = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        xmlers::read(&access, &records, 0),
        Err(xmlers::Error::Order(_))
    ));
}

fn xml_chain(
    xml: &mut Tree,
    sequence: usize,
    order: &'static str,
    digest: &'static str,
) -> (usize, usize) {
    let chain = add(xml, sequence, XML_ERS, "ArchiveTimeStampChain");
    let digest_method = add(xml, chain, XML_ERS, "DigestMethod");
    let canonical = add(xml, chain, XML_ERS, "CanonicalizationMethod");
    xml.evidence_attributes.extend([
        (chain, "Order", order),
        (digest_method, "Algorithm", digest),
        (
            canonical,
            "Algorithm",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
        ),
    ]);
    (chain, canonical)
}

#[test]
fn xml_writer_preserves_sorted_full_hashes_and_stages_only_at_the_selected_tail() {
    // Construction emits XMLERS grammar through the original transaction and
    // leaves the token bytes untouched for post-staging verification.
    let xml = preparation_tree();
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let records = evidence::read(&access, &bound).unwrap();
    let plan = records
        .edit(&access, Edit::Serial(Format::Xml), None)
        .unwrap();
    let (provider, token, _) = fixture(b"synthetic root");
    let mut objects = records.serial_objects(&xml, &work).unwrap();
    let imprint = objects
        .initial_imprint(&provider, Algorithm::Sha256, &work)
        .unwrap();
    let hashes: Vec<_> = imprint.hashes().collect();
    assert_eq!(
        imprint.root().as_bytes(),
        Sha256::digest(hashes.concat()).as_slice()
    );
    let archive = |first_hashes| xmlers::Archive {
        methods: Some(xmlers::Methods {
            digest: xmlers::Method::Uri("http://www.w3.org/2001/04/xmlenc#sha256"),
            canonicalization: xmlers::Method::Uri("http://www.w3.org/2001/10/xml-exc-c14n#"),
        }),
        first_hashes,
        token: &token,
    };
    let descending: Vec<_> = hashes.iter().rev().copied().collect();
    let mut draft = lifecycle::Draft::new(&xml, Some(7));
    assert!(matches!(
        plan.write_xml(&mut draft, archive(&descending), &work),
        Err(produce::Error::Value("HashTree"))
    ));
    assert_eq!(draft.events, [] as [lifecycle::Written; 0]);
    plan.write_xml(&mut draft, archive(&hashes), &work).unwrap();
    let binary: Vec<_> = draft
        .events
        .iter()
        .filter_map(|event| match event {
            lifecycle::Written::Binary(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(
        binary.split_last(),
        Some((&token.as_slice(), hashes.as_slice()))
    );
}

#[test]
fn xml_hash_tree_renewal_binds_every_object_and_only_the_prior_sequence() {
    // RFC 6283 §4.2.2 adds the exact prior sequence to all current object
    // digests under the new method. A changed prefix has no positive receipt.
    let mut xml = preparation_tree();
    let (_, member) = group(&mut xml, Format::Xml);
    let work = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)));
    let hashes = hash_original(&xml, 0, &work);
    xml.evidence_attributes.push((member, "Version", "1.0"));
    let sequence = add(&mut xml, member, XML_ERS, "ArchiveTimeStampSequence");
    let (initial_chain, _) = xml_chain(
        &mut xml,
        sequence,
        "1",
        "http://www.w3.org/2001/04/xmlenc#sha256",
    );
    let initial = xml_stamp(&mut xml, initial_chain, "1", &hashes);
    let (renewed_chain, method) = xml_chain(
        &mut xml,
        sequence,
        "2",
        "http://www.w3.org/2001/04/xmlenc#sha512",
    );
    let method = u8::try_from(method).unwrap();
    let prefix = [
        b'E',
        u8::try_from(sequence).unwrap(),
        b'M',
        method,
        b'E',
        u8::try_from(initial_chain).unwrap(),
        b'M',
        method,
    ];
    let mut renewed_hashes: Vec<[u8; 64]> = original_octets(&xml, 0, &work)
        .iter()
        .map(|bytes| Sha512::digest(bytes).into())
        .collect();
    renewed_hashes.push(Sha512::digest(prefix).into());
    renewed_hashes.sort_unstable();
    let renewed = xml_stamp(&mut xml, renewed_chain, "1", &renewed_hashes);
    let (provider, token, cert) = fixture(&hashes.concat());
    let (_, next, _) = fixture_sha512(&renewed_hashes.concat());
    xml.binary_routes
        .extend([(initial, token), (renewed, next)]);
    let parser = Parser::der(work.clone());
    let operation = parser.read(&[], 0).unwrap();
    let certificate = Certificate::read(&parser, &cert, 3000).unwrap();
    let select = Select {
        parent: &operation,
        certificate: &certificate,
    };
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let reference = Instant::new(1_800_000_000, 0).unwrap();
    let check = xmlers::Check {
        provider: &provider,
        operation: &operation,
        authorities: &select,
        utc: &utc,
        reference,
    };
    let check_record = |xml: &Tree, valid| {
        let access = Access::new(xml, xml.snapshot(), &work);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let records = evidence::read(&access, &bound).unwrap();
        let result = check.xml(
            xml,
            &records,
            0,
            |_, _, _| Ok::<_, ()>(false),
            |history, _| {
                assert_eq!(
                    history.evidence.following_chain.is_some(),
                    history.stamp.token == initial
                );
                Ok::<_, ()>(Decision::Valid)
            },
        );
        if valid {
            assert!(result.unwrap().verified().is_some());
        } else {
            assert!(matches!(result, Err(xmlers::CheckError::Check(node, _)) if node == renewed));
        }
    };
    check_record(&xml, true);
    xml.canonical_routes
        .push((initial_chain, b"changed original prefix".to_vec()));
    check_record(&xml, false);
}
