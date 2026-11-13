//! Source-bound augmentation with actual RFC3161 ECDSA/ESS/imprint checks.

use super::super::{
    Collect,
    lifecycle::{Draft, Written},
    stream,
};
use super::*;
use sha2::{Digest as _, Sha256};
use structured_asn1::{Parser, length::DerLength};
use structured_cms::timestamp::{
    CheckContext, NewRequest, Request, RequestWindow, Requested, Response,
};
use structured_xades::produce::{self, Augmentation, TimestampKind};

pub(super) fn assert_material_construction(
    report: &LongTermReport<'_>,
    xml: &Tree,
    work: &impl Work,
) {
    // Missing-material emission is driven by the same actual complete/delta
    // and participant census as validation, without caller-written counts.
    let prepared = report.timed().basic().inputs().fields.prepared();
    let plan = Augmentation::new(xml, prepared);
    let mut draft = Draft::new(xml, prepared.unsigned().parent());
    let presence = report.x509().presence();
    plan.write_materials(
        presence,
        &mut draft,
        work,
        |_, _| -> Result<_, super::super::Cause> { panic!("this input uses CRLs, not OCSP") },
    )
    .unwrap();
    let expected: Vec<_> = presence
        .entries()
        .iter()
        .filter(|e| e.occurrence().is_none())
        .map(|e| {
            Written::Binary(match e.artifact() {
                structured_ltv::material::ArtifactRef::Certificate(value) => {
                    value.as_bytes().to_vec()
                }
                structured_ltv::material::ArtifactRef::Crl(value) => value.as_bytes().to_vec(),
                structured_ltv::material::ArtifactRef::Ocsp(_) => panic!("fixture has only CRLs"),
            })
        })
        .collect();
    let actual: Vec<_> = draft
        .events
        .into_iter()
        .filter(|e| matches!(e, Written::Binary(_)))
        .collect();
    assert_eq!(actual.len(), expected.len());
    for value in expected {
        assert!(actual.contains(&value));
    }
    if prepared.requirements() == unsigned::Requirements::LongTerm {
        let assessed = baseline::assess(baseline::Evidence::LongTerm(report)).unwrap();
        let method = prepared.timestamps()[0].method();
        let result = plan.input(&assessed, TimestampKind::Archive, method, work);
        assert_eq!(result.is_ok(), report.all_material_requirements_met());
        if report.all_material_requirements_met() {
            let mut input = result.unwrap();
            let mut sink = Collect::new(work.memory());
            stream::run(&mut input, &mut sink, work, "archiveCreation", 0).unwrap();
            assert_ne!(sink.bytes(), []);
        }
    }
}

fn response(token: &[u8]) -> Vec<u8> {
    let mut value = vec![0x30];
    value.extend(DerLength::new(5 + token.len() as u64).as_bytes());
    value.extend([0x30, 3, 2, 1, 0]);
    value.extend(token);
    value
}

#[test]
fn live_response_is_bound_to_the_actual_proposed_input_and_append_generation() {
    // XML framing is the existing synthetic owner. Real ECDSA, ESS, full
    // certificate, request correlation and mathematical evidence execute here.
    // This is not native XML C14N or downstream interoperability qualification.
    xml_digest::with_checked_path(|path, leaf, root, memory| {
        let (xml, provider, tsa) = fixture(leaf, root, values::Pool::Complete);
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let fields = prepare::check_fields(&prepared, &access).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        let hashes::ParticipantBinding::Bound(hashes) =
            hashes::check_participants(&prepared, &counters, &access).unwrap()
        else {
            panic!("complete actual hashes");
        };
        let selected = xml_digest::checked_certificate(&xml, &prepared, path, memory);
        let parser = Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let basic = baseline::basic(
            baseline::BasicInput {
                fields: &fields,
                hashes: &hashes,
                certificate: &selected,
                counters: &counters,
            },
            &xml,
            &operation,
        )
        .unwrap();
        let assessment = baseline::assess(baseline::Evidence::basic(&basic)).unwrap();
        assert!(assessment.all_requirements_met());
        let plan = Augmentation::new(&xml, &prepared);
        let method = prepared.timestamps()[0].method();
        let calls = xml.streamed.get();
        assert!(matches!(
            plan.input(&assessment, TimestampKind::Archive, method, memory),
            Err(produce::PreparationError::Admission(
                produce::Error::Prerequisites
            ))
        ));
        assert_eq!(xml.streamed.get(), calls);
        let mut input = plan
            .input(&assessment, TimestampKind::Signature, method, memory)
            .unwrap();
        let mut bytes = Collect::new(memory);
        stream::run(&mut input, &mut bytes, memory, "newTimestamp", 0).unwrap();
        let (algorithm, algorithm_reader) = sha256_identifier(&parser);
        let tsa = structured_pkix::Certificate::read(&parser, &tsa, 400).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let response_bytes = response(&xml.binary);
        let mut response_reader = parser.read(&response_bytes, 2500).unwrap();
        let response = Response::read(&mut response_reader).unwrap();
        for correct in [true, false] {
            let digest = if correct {
                Sha256::digest(bytes.bytes())
            } else {
                Sha256::digest(b"other source")
            };
            let request_bytes = encode_request(algorithm, &algorithm_reader, &digest);
            let mut request_reader = parser.read(&request_bytes, 3500).unwrap();
            let element = request_reader.next_element().unwrap().unwrap();
            let request = Request::read(&request_reader, &element).unwrap();
            let context = CheckContext {
                certificate: &tsa,
                certificate_parent: &operation,
                key: EffectiveKey::standing(tsa.tbs().public_key()),
                requested: Some(Requested {
                    request: &request,
                    parent: &request_reader,
                }),
                utc: &utc,
                reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
                window: Some(unique_request_window()),
                policy_accuracy: None,
            };
            let result = plan
                .check_response(
                    &assessment,
                    TimestampKind::Signature,
                    method,
                    &produce::ResponseCheck {
                        response: &response,
                        provider: &provider,
                        query: &operation,
                        context: &context,
                    },
                    |_, _| Ok::<_, ()>(false),
                )
                .unwrap();
            assert_acceptance(
                &result,
                correct,
                &plan,
                &xml,
                prepared.unsigned().parent(),
                memory,
            );
        }
    });
}

fn unique_request_window() -> RequestWindow {
    // The test explicitly supplies the outstanding-request uniqueness fact;
    // the library must not invent replay history or read a local clock.
    RequestWindow::for_unique_imprint(
        Instant::new(1_700_000_000, 0).unwrap(),
        Instant::new(1_800_000_000, 0).unwrap(),
    )
    .unwrap()
}

fn sha256_identifier(
    parser: &Parser,
) -> (
    structured_pkix::AlgorithmIdentifier<'_>,
    structured_asn1::Reader<'_>,
) {
    const BYTES: &[u8] = &[48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1];
    let mut reader = parser.read(BYTES, 1900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let algorithm = structured_pkix::algorithm::read(&reader, &element, "hash").unwrap();
    (algorithm, reader)
}

fn encode_request<'a>(
    algorithm: structured_pkix::AlgorithmIdentifier<'a>,
    reader: &structured_asn1::Reader<'a>,
    digest: &[u8],
) -> structured_asn1::memory::OwnedVec<u8> {
    NewRequest {
        algorithm,
        hashed_message: digest,
        policy: None,
        nonce: None,
        cert_req: true,
        extensions: &[],
    }
    .encode_der(reader)
    .unwrap()
}

fn assert_acceptance(
    result: &produce::Checked<'_, u8, u8, usize>,
    correct: bool,
    plan: &Augmentation<'_, Tree>,
    xml: &Tree,
    parent: Option<usize>,
    memory: &structured_asn1::memory::Memory,
) {
    // Same-response proof permits only the matching original transaction. A
    // mismatched request or later generation cannot emit an accepted token.
    if !correct {
        assert!(
            result.timestamp().is_none(),
            "different request must not be accepted"
        );
        assert!(result.facts().timestamp().unwrap().evidence().is_none());
        return;
    }
    let token = result
        .timestamp()
        .expect("complete response should be constructible");
    assert_eq!(token.snapshot(), xml.snapshot());
    let mut draft = Draft::new(xml, parent);
    plan.write_timestamp(&token, &mut draft, memory).unwrap();
    assert_eq!(
        draft.events,
        vec![
            Written::Begin(super::super::XADES, "SignatureTimeStamp"),
            Written::Method(token.method()),
            Written::Begin(super::super::XADES, "EncapsulatedTimeStamp"),
            Written::Binary(xml.binary.clone()),
            Written::End,
            Written::End
        ]
    );
    draft.events.clear();
    draft.base.document += 1;
    assert!(matches!(
        plan.write_timestamp(&token, &mut draft, memory),
        Err(produce::Error::Foreign)
    ));
    assert_eq!(draft.events, []);
    draft.base = xml.snapshot();
    xml.generation.set(xml.generation.get() + 1);
    assert!(matches!(
        plan.write_timestamp(&token, &mut draft, memory),
        Err(produce::Error::Foreign)
    ));
    assert_eq!(draft.events, []);
    xml.generation.set(xml.generation.get() - 1);
}
