//! Annex A timestamp census and original, implicit reference coverage.

use super::*;

fn add(xml: &mut Tree, parent: usize, namespace: &'static str, local: &'static str) -> usize {
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(parent), namespace, local));
    node
}

fn fixture() -> (Tree, [usize; 2], [usize; 2]) {
    let mut xml = attribute_checks::fixture();
    let certificates = add(&mut xml, 7, XADES_141, "CompleteCertificateRefsV2");
    let list = add(&mut xml, certificates, XADES_141, "CertRefs");
    let cert = add(&mut xml, list, XADES, "Cert");
    let digest = add(&mut xml, cert, XADES, "CertDigest");
    add(&mut xml, digest, DS, "DigestMethod");
    add(&mut xml, digest, DS, "DigestValue");
    let revocation = add(&mut xml, 7, XADES, "CompleteRevocationRefs");
    let others = add(&mut xml, revocation, XADES, "OtherRefs");
    add(&mut xml, others, XADES, "OtherRef");
    let mut stamps = [0; 2];
    for (slot, local) in stamps
        .iter_mut()
        .zip(["SigAndRefsTimeStampV2", "RefsOnlyTimeStampV2"])
    {
        *slot = add(&mut xml, 7, XADES_141, local);
        add(&mut xml, *slot, DS, "CanonicalizationMethod");
        add(&mut xml, *slot, XADES, "EncapsulatedTimeStamp");
    }
    (xml, stamps, [certificates, revocation])
}

#[test]
fn preparation_keeps_every_annex_a_timestamp_in_the_actual_token_census() {
    // Optional B-B/B-T reference timestamps are real RFC3161 participants;
    // skipping them must not produce an apparently complete TSA census.
    let (xml, stamps, _) = fixture();
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    assert_eq!(prepared.timestamps().len(), 3);
    assert_eq!(prepared.timestamps()[1].node(), stamps[0]);
    assert_eq!(prepared.timestamps()[2].node(), stamps[1]);
    let census =
        timestamp::requirements(&access, &prepared, timestamp::TimestampSelection::All).unwrap();
    assert_eq!(census.entries().len(), 3);
}

#[test]
fn reference_timestamp_inputs_use_original_order_and_exclude_unrelated_parts() {
    // Annex A implicit input is not archive input: no Reference replay,
    // SignedInfo, KeyInfo, unrelated values, own tokens or later properties.
    // Reverse the two reference properties to distinguish source from role order.
    let (mut xml, nodes, refs) = fixture();
    xml.nodes[refs[0]].value = Node::Element(Name {
        namespace: XADES,
        local: "CompleteRevocationRefs",
    });
    xml.nodes[refs[1]].value = Node::Element(Name {
        namespace: XADES_141,
        local: "CompleteCertificateRefsV2",
    });
    let unrelated = add(&mut xml, 7, XADES, "CertificateValues");
    for (index, expected_nodes) in [vec![12, 8, refs[0], refs[1]], vec![refs[0], refs[1]]]
        .into_iter()
        .enumerate()
    {
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp = timestamp::read(&access, &bound, nodes[index]).unwrap();
        assert_eq!(
            stamp.role(),
            [Role::SignatureAndReferences, Role::ReferencesOnly][index]
        );
        let method = xml.element_child(nodes[index], DS, "CanonicalizationMethod");
        let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
        let mut sink = Collect::new(&memory);
        stream::run(&mut input, &mut sink, &memory, "fixture", 0).unwrap();
        let expected: Vec<_> = expected_nodes
            .into_iter()
            .flat_map(|node| {
                [
                    b'E',
                    u8::try_from(node).unwrap(),
                    b'M',
                    u8::try_from(method).unwrap(),
                ]
            })
            .collect();
        assert_eq!(sink.bytes(), expected);
        assert!(
            !sink
                .bytes()
                .as_chunks::<4>()
                .0
                .iter()
                .any(|part| part[1] == u8::try_from(unrelated).unwrap())
        );
    }
}

#[test]
fn later_or_duplicate_references_do_not_repair_timestamp_coverage() {
    // Both mandatory reference roles must precede the timestamp. A later
    // property cannot be silently covered; duplicate singleton input is refused.
    for index in 0..2 {
        let (mut xml, stamps, refs) = fixture();
        xml.nodes[refs[1]].parent = Some(0);
        add(&mut xml, 7, XADES, "CompleteRevocationRefs");
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp = timestamp::read(&access, &bound, stamps[index]).unwrap();
        let held = memory.used();
        assert!(
            matches!(Input::prepare(&xml, &bound, &stamp, &memory), Err(InputError::Missing {node, local: "CompleteRevocationRefs"}) if node == stamps[index])
        );
        assert_eq!(memory.used(), held);
        assert_eq!(xml.streamed.get(), 0);
    }
    let (mut xml, stamps, refs) = fixture();
    // Reuse an earlier harmless field's position for a second direct role.
    let duplicate = refs[0] + 1;
    xml.nodes[duplicate] = element(Some(7), XADES_141, "CompleteCertificateRefsV2");
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read(&access, &bound, stamps[0]).unwrap();
    assert!(
        matches!(Input::prepare(&xml, &bound, &stamp, &memory), Err(InputError::Duplicate {node}) if node == duplicate)
    );
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn reference_timestamp_selection_is_funded_by_current_work_before_any_streaming() {
    // Retained models do not credit a later query: both memory and local CPU
    // refusals release temporary parts and preserve the source account.
    let (xml, stamps, _) = fixture();
    let original = funded();
    let access = Access::new(&xml, xml.snapshot(), &original);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read(&access, &bound, stamps[0]).unwrap();
    let held = original.used();
    let paid = original.work_used();
    for query in [
        Memory::new(Arc::new(MemoryAccount::new(0, 1_000_000))),
        Memory::new(Arc::new(MemoryAccount::new(1_000_000, 0))),
    ] {
        assert!(matches!(
            Input::prepare(&xml, &bound, &stamp, &query),
            Err(InputError::Access(AccessError::Resource { .. })
                | InputError::Resource { .. }
                | InputError::Child(structured_xades::xml::ChildError::Access(
                    AccessError::Resource { .. }
                )))
        ));
        assert_eq!(query.used(), 0);
        assert_eq!(original.used(), held);
        assert_eq!(original.work_used(), paid);
    }
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn nested_counter_reference_timestamps_remain_in_the_complete_participant_set() {
    // A nested actor's optional reference timestamp is not root-only metadata;
    // the shared counter census must retain each actual token and its role.
    xml_digest::with_checked_path(|path, _, _, memory| {
        let mut xml = preparation_tree();
        xml.key_association = certificate::KeyAssociation::Same;
        let (child, _, parent) = append_nested_counter(&mut xml, 7, 12, true);
        let parent = parent.unwrap();
        let (first, first_tokens) =
            append_timestamp(&mut xml, parent, Role::SignatureAndReferences, 2);
        let (second, second_tokens) = append_timestamp(&mut xml, parent, Role::ReferencesOnly, 1);
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
        assert_eq!(stamps.entries().len(), 2);
        let required = timestamp::requirements_with_counters(
            &access,
            &prepared,
            &stamps,
            timestamp::TimestampSelection::All,
        )
        .unwrap();
        let actual: Vec<_> = required
            .entries()
            .iter()
            .filter(|entry| entry.signature == child)
            .map(|entry| (entry.property, entry.token, entry.role))
            .collect();
        assert_eq!(
            actual,
            [
                (first, first_tokens[0], Role::SignatureAndReferences),
                (first, first_tokens[1], Role::SignatureAndReferences),
                (second, second_tokens[0], Role::ReferencesOnly),
            ]
        );
    });
}

#[test]
fn both_reference_timestamp_roles_drive_real_rfc3161_checks_over_exact_inputs() {
    // Framing is synthetic, but token mathematics, ESS and message imprint use
    // the real common RFC3161/ECDSA checker. An unrelated imprint gives no proof.
    use structured_cms::timestamp::CheckContext;
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    for index in 0..2 {
        for agrees in [true, false] {
            let (mut xml, stamps, _) = fixture();
            let memory = funded();
            let (provider, token, certificate_bytes) = {
                let access = Access::new(&xml, xml.snapshot(), &memory);
                let layout = container::locate(&access, 0).unwrap();
                let bound = binding::bind(&access, &layout).unwrap();
                let stamp = timestamp::read(&access, &bound, stamps[index]).unwrap();
                let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
                let mut sink = Collect::new(&memory);
                stream::run(&mut input, &mut sink, &memory, "fixture", 0).unwrap();
                timestamp_oracle::fixture(if agrees {
                    sink.bytes()
                } else {
                    b"unrelated reference timestamp input"
                })
            };
            xml.binary = token;
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            let certificate =
                structured_pkix::Certificate::read(&parser, &certificate_bytes, 400).unwrap();
            let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
            let context = CheckContext {
                certificate: &certificate,
                certificate_parent: &operation,
                key: WorkingKey::standing(certificate.tbs().public_key()),
                requested: None,
                utc: &utc,
                reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
                window: None,
            };
            let access = Access::new(&xml, xml.snapshot(), &memory);
            let layout = container::locate(&access, 0).unwrap();
            let bound = binding::bind(&access, &layout).unwrap();
            let stamp = timestamp::read(&access, &bound, stamps[index]).unwrap();
            let check = timestamp::Check {
                xml: &xml,
                provider: &provider,
                context: &context,
            };
            let verified = check
                .retain(&bound, &stamp, 0, &operation, |_, _| Ok::<_, ()>(false))
                .unwrap();
            assert_eq!(verified.is_some(), agrees);
            if let Some(verified) = verified {
                assert_eq!(verified.property(), stamps[index]);
                assert_eq!(verified.purpose(), stamp.role().purpose());
            }
            assert_eq!(provider.verified.get(), 1);
        }
    }
}
