//! Construction input selection shares validation's original ordering kernel.

use super::*;
use structured_cms::stream::Source;
use structured_xades::produce::{self, Event, Transaction, Writer};
use structured_xades::timestamp::AppendKind;

#[test]
fn future_archive_input_is_exactly_the_later_occurrence_input() {
    // A future archive protects the complete current unsigned tail, including
    // earlier archives. Its own method/token must never enter that input.
    for preceding in [0, 1, 3] {
        let (mut xml, original, method) = Tree::stamped(Role::Archive);
        let parent = xml.nodes[original].parent.unwrap();
        // Remove the original timestamp from this parent's child list, retaining
        // its method as an owner-controlled staging node in the same snapshot.
        xml.nodes[original].parent = None;
        for _ in 0..preceding {
            append_timestamp(&mut xml, parent, Role::Archive, 1);
        }
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let mut future =
            Input::prepare_append(&xml, &bound, AppendKind::Archive, method, &memory).unwrap();
        let mut before = Collect::new(&memory);
        stream::run(&mut future, &mut before, &memory, "future", 0).unwrap();
        drop(future);
        let new = xml.nodes.len();
        xml.nodes
            .push(element(Some(parent), XADES_141, "ArchiveTimeStamp"));
        xml.nodes[method].parent = Some(new);
        xml.nodes
            .push(element(Some(new), XADES, "EncapsulatedTimeStamp"));
        xml.generation.set(xml.generation.get() + 1);
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp = timestamp::read(&access, &bound, new).unwrap();
        let mut actual = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
        let mut after = Collect::new(&memory);
        stream::run(&mut actual, &mut after, &memory, "actual", 0).unwrap();
        assert_eq!(before.bytes(), after.bytes());
        assert_eq!(before.bytes().len(), 24 + preceding * 4);
    }
}

#[test]
fn future_signature_input_needs_no_token_and_retains_stale_and_refusal_causes() {
    // No placeholder token is introduced to select canonical SignatureValue.
    // Staleness and exhausted work stop before source callbacks.
    let (xml, _, method) = Tree::stamped(Role::Signature);
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let mut future =
        Input::prepare_append(&xml, &bound, AppendKind::Signature, method, &memory).unwrap();
    let mut sink = Collect::new(&memory);
    stream::run(&mut future, &mut sink, &memory, "future", 0).unwrap();
    assert_eq!(
        sink.bytes(),
        &[b'E', 12, b'M', u8::try_from(method).unwrap()]
    );
    let calls = xml.streamed.get();
    xml.generation.set(xml.generation.get() + 1);
    assert!(matches!(
        future.stream(&mut Reject, &memory),
        Err(InputError::Access(AccessError::Changed { .. }))
    ));
    assert_eq!(xml.streamed.get(), calls);
    xml.generation.set(xml.generation.get() - 1);
    let exhausted = super::memory(0);
    assert!(
        Input::prepare_append(&xml, &bound, AppendKind::Signature, method, &exhausted).is_err()
    );
    assert_eq!(xml.streamed.get(), calls);
}

struct Reject;
impl Receiver for Reject {
    fn write(&mut self, _: &[u8]) -> Result<(), stream::Refused> {
        Err(stream::Refused)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Written {
    Begin(&'static str, &'static str),
    Attribute(&'static str, String),
    Text(String),
    Binary(Vec<u8>),
    Method(usize),
    End,
}

// Observation storage is test instrumentation, not a production XML owner or
// proof of accounting inside an opaque adapter. The common callbacks are real.
pub(super) struct Draft {
    pub(super) base: Snapshot<u8, u8>,
    pub(super) signature: usize,
    pub(super) parent: Option<usize>,
    pub(super) events: Vec<Written>,
    pub(super) fail_at: Option<usize>,
}
impl Draft {
    pub(super) fn new(xml: &Tree, parent: Option<usize>) -> Self {
        Self {
            base: xml.snapshot(),
            signature: 0,
            parent,
            events: Vec::new(),
            fail_at: None,
        }
    }
}
impl Writer for Draft {
    type Error = Cause;
    fn write<W: Work>(&mut self, event: Event<'_>, work: &W) -> Result<(), Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        if self.fail_at == Some(self.events.len()) {
            return Err(Cause::Source);
        }
        self.events.push(match event {
            Event::Begin(name) => Written::Begin(name.namespace, name.local),
            Event::Attribute(name, value) => {
                Written::Attribute(name.local, value.lexical.to_owned())
            }
            Event::Text(value) => Written::Text(value.lexical.to_owned()),
            Event::Binary(value) => Written::Binary(value.to_vec()),
            Event::End => Written::End,
        });
        Ok(())
    }
}
impl Transaction for Draft {
    type Id = usize;
    type Document = u8;
    type Generation = u8;
    fn base(&self) -> Snapshot<u8, u8> {
        self.base
    }
    fn signature(&self) -> usize {
        self.signature
    }
    fn unsigned_parent(&self) -> Option<usize> {
        self.parent
    }
    fn method<W: Work>(&mut self, method: usize, work: &W) -> Result<(), Cause> {
        work.charge_work(1).map_err(Cause::Resource)?;
        if self.fail_at == Some(self.events.len()) {
            return Err(Cause::Source);
        }
        self.events.push(Written::Method(method));
        Ok(())
    }
}

#[test]
fn basic_and_counter_construction_keep_mandatory_order_and_original_certificate() {
    // Mandatory new properties and XMLDSig instructions are generated without
    // a serializer, key custody or a second signature engine in the core.
    xml_digest::with_checked_path(|path, _, _, memory| {
        let certificate = path.members()[0].certificate();
        let xml = Tree::normal();
        for counter in [None, Some("#parent-value")] {
            let objects = [produce::DataObject {
                reference: "#content-reference",
                mime_type: "text/plain; charset=utf-8",
            }];
            let basic = produce::Basic {
                target: "#signature",
                signed_properties_id: "properties",
                signing_time: "2026-11-05T12:00:00Z",
                certificate,
                certificate_digest_method: "http://www.w3.org/2001/04/xmlenc#sha256",
                certificate_digest: &[42; 32],
                objects: if counter.is_some() { &[] } else { &objects },
                counter_signature: counter,
            };
            let mut draft = Draft::new(&xml, None);
            let references = basic.write(&mut draft, memory).unwrap();
            assert_eq!(references.signed_properties, "properties");
            assert_eq!(references.counter_signature, counter);
            let starts: Vec<_> = draft
                .events
                .iter()
                .filter_map(|e| match e {
                    Written::Begin(_, local) => Some(*local),
                    _ => None,
                })
                .collect();
            let mut expected = vec![
                "QualifyingProperties",
                "SignedProperties",
                "SignedSignatureProperties",
                "SigningTime",
                "SigningCertificateV2",
                "Cert",
                "CertDigest",
                "DigestMethod",
                "DigestValue",
            ];
            if counter.is_none() {
                expected.extend(["SignedDataObjectProperties", "DataObjectFormat", "MimeType"]);
            }
            assert_eq!(starts, expected);
            assert_eq!(
                draft
                    .events
                    .iter()
                    .filter(|e| matches!(e, Written::Attribute("URI", _)))
                    .count(),
                0
            );
            let count = draft.events.len();
            for stop in 0..count {
                let mut refused = Draft::new(&xml, None);
                refused.fail_at = Some(stop);
                assert!(matches!(
                    basic.write(&mut refused, memory),
                    Err(produce::Error::Writer(Cause::Source))
                ));
                assert_eq!(refused.events.len(), stop);
            }
            let mut key_info = Draft::new(&xml, None);
            basic.write_key_info(&mut key_info, memory).unwrap();
            assert!(
                key_info
                    .events
                    .contains(&Written::Binary(certificate.as_bytes().to_vec()))
            );
            assert_eq!(
                produce::ReferenceKind::SignedProperties.type_uri(),
                binding::SIGNED_PROPERTIES
            );
            assert_eq!(
                produce::ReferenceKind::CounterSignature.type_uri(),
                "http://uri.etsi.org/01903#CountersignedSignature"
            );
        }
    });
}

#[test]
fn construction_rejects_malformed_values_and_work_before_writer_effects() {
    // MIME validation uses the existing grammar, not an HTTP approximation.
    // An exhausted operation cannot emit even the opening construction event.
    xml_digest::with_checked_path(|path, _, _, memory| {
        let xml = Tree::normal();
        let objects = [produce::DataObject {
            reference: "#ref",
            mime_type: "text/plain; broken",
        }];
        let basic = produce::Basic {
            target: "#signature",
            signed_properties_id: "props",
            signing_time: "2026-11-05T12:00:00Z",
            certificate: path.members()[0].certificate(),
            certificate_digest_method: "urn:hash",
            certificate_digest: &[0; 32],
            objects: &objects,
            counter_signature: None,
        };
        let mut draft = Draft::new(&xml, None);
        assert!(matches!(
            basic.write(&mut draft, memory),
            Err(produce::Error::Value("dataObject.mimeType"))
        ));
        assert_eq!(draft.events, []);
        let exhausted = super::memory(0);
        assert!(matches!(
            basic.write(&mut draft, &exhausted),
            Err(produce::Error::Resource(MemoryError::WorkExceeded))
        ));
        assert_eq!(draft.events, []);
    });
}

#[test]
fn material_construction_uses_the_whole_original_ocsp_envelope_and_both_origins() {
    // OCSPResponse and its signed BasicOCSPResponse are different byte inputs.
    // A foreign payload must not acquire the required body's material identity.
    let original = funded();
    let parser = structured_asn1::Parser::new(structured_asn1::Encoding::Der, structured_asn1::Limits { max_work: 100_000, ..structured_asn1::Limits::default() }, original.clone());
    let bytes = timestamp_oracle::ocsp_response(2);
    let foreign = timestamp_oracle::ocsp_response(3);
    let structured_pkix::ocsp::Response::Successful(envelope) =
        structured_pkix::ocsp::Response::read(&parser, &bytes, 500).unwrap()
    else {
        panic!("successful fixture");
    };
    let structured_pkix::ocsp::Response::Successful(other) =
        structured_pkix::ocsp::Response::read(&parser, &foreign, 1500).unwrap()
    else {
        panic!("successful fixture");
    };
    let query = parser.read(&[], 0).unwrap();
    let basic = envelope.basic_in(&query).unwrap().unwrap();
    let work = funded();
    let value = produce::Material::ocsp::<(), _>(&envelope, &basic, &work).unwrap();
    assert!(matches!(
        produce::Material::ocsp::<(), _>(&other, &basic, &work),
        Err(produce::Error::Value("ocsp.envelope"))
    ));
    let xml = Tree::normal();
    let mut draft = Draft::new(&xml, None);
    produce::write_material(&[value], &mut draft, &work).unwrap();
    assert!(draft.events.contains(&Written::Binary(bytes.clone())));
    assert!(
        !draft
            .events
            .contains(&Written::Binary(basic.as_bytes().to_vec()))
    );
    let value = produce::Material::ocsp::<(), _>(&envelope, &basic, &work).unwrap();
    let source = query.execution();
    source.charge_work(source.work_remaining() as u64).unwrap();
    let mut refused = Draft::new(&xml, None);
    assert!(matches!(
        produce::write_material(&[value], &mut refused, &work),
        Err(produce::Error::Resource(MemoryError::WorkExceeded))
    ));
    assert!(
        !refused
            .events
            .iter()
            .any(|value| matches!(value, Written::Binary(_)))
    );
}
