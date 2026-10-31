//! Direct-incorporation structure tests; these do not assert cryptographic trust.

use structured_cms::timestamp::CheckContext;

#[path = "support/timestamp_oracle.rs"]
mod timestamp_oracle;

#[path = "support/token_profiles.rs"]
mod token_profiles;

#[path = "support/independent_corpus.rs"]
pub mod independent_corpus;

#[path = "support/baseline.rs"]
mod baseline_checks;
#[path = "support/credential.rs"]
mod credential_checks;
#[path = "support/xml_digest.rs"]
mod xml_digest;

#[path = "support/renewed_check.rs"]
mod renewed_check;

#[path = "support/hash_uses.rs"]
mod hash_checks;

#[path = "support/scalar.rs"]
mod scalar_checks;

#[path = "support/attributes.rs"]
mod attribute_checks;

#[path = "support/reference_fields.rs"]
mod reference_fields;

#[path = "support/digest_class.rs"]
mod digest_class;

#[path = "support/query_boundary.rs"]
mod query_boundary;

#[path = "support/reference_timestamps.rs"]
mod reference_timestamps;

use std::{
    cell::{Cell, RefCell},
    cmp::Ordering,
    sync::Arc,
};
use structured_asn1::digest::{Digest, Resolution as DigestResolution};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, OwnedVec, Work};
use structured_cms::stream::{self, Receiver, Sink};
use structured_xades::{
    binary::{self, BinaryXml, Location},
    binding::{
        self, BindingError, Coverage, Reference, SIGNED_PROPERTIES, SignatureXml, Status, Target,
    },
    certificate, commitment,
    container::{self, ContainerError, DS, XADES},
    counter, format, header, identifier, material, policy, prepare, properties,
    reference::{
        Boolean, Completeness, Descriptor, LexicalSource, ObjectLocation, Parent, ReferenceXml,
        Replay, ReplayOutcome, Resolution, VisitError,
    },
    role,
    timestamp::{self, Input, InputError, Role, TimestampXml, XADES_141},
    unsigned, validation,
    xml::{Access, AccessError, Name, Node, Snapshot, Xml},
};

#[derive(Clone, Copy)]
struct Record {
    parent: Option<usize>,
    value: Node<'static>,
}

struct Edges {
    first: Vec<Option<usize>>,
    next: Vec<Option<usize>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyProjection {
    key: usize,
    parameters: Option<(usize, usize)>,
}

impl KeyProjection {
    fn of(key: structured_pkix::path::WorkingKey<'_>) -> Self {
        Self {
            key: key.key().as_bytes().as_ptr() as usize,
            parameters: key
                .parameters()
                .map(|bytes| (bytes.as_ptr() as usize, bytes.len())),
        }
    }
}

enum Decoding {
    Ready,
    Refuse,
}

struct Tree {
    document: u8,
    nodes: Vec<Record>,
    signature_status: Status,
    references: Vec<Reference<'static, usize>>,
    target: Target<usize>,
    target_routes: Vec<(usize, Target<usize>)>,
    generation: Cell<u8>,
    streamed: Cell<usize>,
    canonical_routes: Vec<(usize, Vec<u8>)>,
    reference_routes: Vec<(usize, Vec<u8>)>,
    ignore_refusal: bool,
    incomplete: bool,
    binary: Vec<u8>,
    binary_routes: Vec<(usize, Vec<u8>)>,
    text_routes: Vec<(usize, &'static str)>,
    calendar_routes: Vec<(usize, properties::CalendarFact<'static>)>,
    binary_depth: u32,
    binary_parser: RefCell<Option<structured_asn1::Parser>>,
    mutate_binary: bool,
    decoding: Decoding,
    binary_encoding: Option<&'static str>,
    key_association: certificate::KeyAssociation,
    key_projection: Cell<Option<KeyProjection>>,
    digest_algorithm: Option<&'static str>,
    digest_algorithms: Vec<(usize, &'static str)>,
    object_reference: Option<&'static str>,
    object_mime: Option<&'static str>,
    identifier_qualifier: Option<&'static str>,
    validation_uri: Option<&'static str>,
    counter_evidence: Option<CounterEvidence>,
    nested_counters: Vec<CounterEvidence>,
    indexed: Option<Edges>,
    include_routes: Vec<(usize, usize, Boolean)>,
    reference_completeness: Completeness<usize>,
    reference_locations: Vec<(usize, ObjectLocation)>,
    unavailable_reference: Option<usize>,
    decoded_pointer: Cell<usize>,
    cached_binary: RefCell<Option<OwnedVec<u8>>>,
    date_time: properties::DateTimeFact,
    date_time_calls: Cell<usize>,
    hash_uses: Vec<structured_xades::hashes::HashUse<usize>>,
    hash_selection: hash_checks::Selection,
    hash_completeness: structured_xades::hashes::HashCompleteness<usize>,
    hash_calls: Cell<usize>,
    hash_visits: Cell<usize>,
    hash_refusal: hash_checks::RefusalMutation,
    scalar_routes: Vec<scalar_checks::Route>,
    scalar_calls: Cell<usize>,
    uri_routes: Vec<scalar_checks::UriRoute>,
    attribute_routes: Vec<attribute_checks::Route>,
    qname_routes: Vec<attribute_checks::TypeRoute>,
    attribute_calls: Cell<usize>,
}

struct CounterEvidence {
    child: usize,
    status: Status,
    references: Vec<Reference<'static, usize>>,
}

#[derive(Debug)]
enum Cause {
    Source,
    Resource(MemoryError),
    Incomplete,
    Unavailable,
}

fn element(parent: Option<usize>, namespace: &'static str, local: &'static str) -> Record {
    Record {
        parent,
        value: Node::Element(Name { namespace, local }),
    }
}

impl Tree {
    fn element_child(&self, parent: usize, namespace: &str, local: &str) -> usize {
        self.nodes.iter().position(|record|record.parent==Some(parent)&&matches!(record.value,Node::Element(name) if name.namespace==namespace&&name.local==local)).expect("fixture child")
    }
    fn reference_location<W: Work>(&self, node: usize, work: &W) -> Result<ObjectLocation, Cause> {
        work.charge_work(self.reference_locations.len() as u64)
            .map_err(Cause::Resource)?;
        Ok(self
            .reference_locations
            .iter()
            .find(|entry| entry.0 == node)
            .map_or(ObjectLocation::Unknown, |entry| entry.1))
    }
    // Build the synthetic DOM's links before starting an operation. Wide/deep
    // tests exercise the common walker, not quadratic array rescans under Miri.
    fn index_edges(&mut self) {
        let mut first = vec![None; self.nodes.len()];
        let mut last: Vec<Option<usize>> = vec![None; self.nodes.len()];
        let mut next = vec![None; self.nodes.len()];
        for (node, record) in self.nodes.iter().enumerate() {
            if let Some(parent) = record.parent {
                if let Some(previous) = last[parent] {
                    next[previous] = Some(node);
                } else {
                    first[parent] = Some(node);
                }
                last[parent] = Some(node);
            }
        }
        self.indexed = Some(Edges { first, next });
    }
    fn counter_receipt<W: Work>(
        &self,
        signature: usize,
        work: &W,
    ) -> Result<Option<&CounterEvidence>, Cause> {
        work.charge_work(self.nested_counters.len() as u64 + 1)
            .map_err(Cause::Resource)?;
        if let Some(counter) = &self.counter_evidence
            && signature == counter.child
        {
            return Ok(Some(counter));
        }
        Ok(self
            .nested_counters
            .iter()
            .find(|counter| counter.child == signature))
    }

    fn mime(&mut self, parent: usize) -> usize {
        let node = self.nodes.len();
        self.nodes.push(element(Some(parent), XADES, "MimeType"));
        self.nodes.push(Record {
            parent: Some(node),
            value: Node::Text("text/plain"),
        });
        node
    }

    fn normal() -> Self {
        Self {
            document: 9,
            signature_status: Status::Valid,
            generation: Cell::new(1),
            streamed: Cell::new(0),
            canonical_routes: Vec::new(),
            reference_routes: Vec::new(),
            ignore_refusal: false,
            incomplete: false,
            binary: Vec::new(),
            binary_routes: Vec::new(),
            text_routes: Vec::new(),
            calendar_routes: Vec::new(),
            binary_depth: 0,
            binary_parser: RefCell::new(None),
            mutate_binary: false,
            decoding: Decoding::Ready,
            binary_encoding: None,
            key_association: certificate::KeyAssociation::Unproven,
            key_projection: Cell::new(None),
            digest_algorithm: Some("urn:test:checksum"),
            digest_algorithms: Vec::new(),
            object_reference: None,
            object_mime: None,
            identifier_qualifier: None,
            validation_uri: None,
            counter_evidence: None,
            nested_counters: Vec::new(),
            indexed: None,
            include_routes: Vec::new(),
            reference_completeness: Completeness::Complete,
            reference_locations: Vec::new(),
            unavailable_reference: None,
            decoded_pointer: Cell::new(0),
            cached_binary: RefCell::new(None),
            date_time: properties::DateTimeFact::Unsupported,
            date_time_calls: Cell::new(0),
            hash_uses: Vec::new(),
            hash_selection: hash_checks::Selection::Single,
            hash_completeness: structured_xades::hashes::HashCompleteness::Unprocessed(0),
            hash_calls: Cell::new(0),
            hash_visits: Cell::new(0),
            hash_refusal: hash_checks::RefusalMutation::Keep,
            scalar_routes: Vec::new(),
            scalar_calls: Cell::new(0),
            uri_routes: Vec::new(),
            attribute_routes: Vec::new(),
            qname_routes: Vec::new(),
            attribute_calls: Cell::new(0),
            references: vec![
                Reference {
                    node: 10,
                    target: None,
                    kind: None,
                    status: Status::Valid,
                    coverage: Coverage::Transformed,
                },
                Reference {
                    node: 11,
                    target: Some(3),
                    kind: Some(SIGNED_PROPERTIES),
                    status: Status::Valid,
                    coverage: Coverage::ElementContent,
                },
            ],
            target: Target::LocalBareName(0),
            target_routes: Vec::new(),
            nodes: vec![
                element(None, DS, "Signature"),
                element(Some(0), DS, "Object"),
                element(Some(1), XADES, "QualifyingProperties"),
                element(Some(2), XADES, "SignedProperties"),
                element(Some(3), XADES, "SignedSignatureProperties"),
                element(Some(4), XADES, "SigningTime"),
                element(Some(2), XADES, "UnsignedProperties"),
                element(Some(6), XADES, "UnsignedSignatureProperties"),
                element(Some(7), XADES, "SignatureTimeStamp"),
                element(Some(0), DS, "SignedInfo"),
                element(Some(9), DS, "Reference"),
                element(Some(9), DS, "Reference"),
                element(Some(0), DS, "SignatureValue"),
                element(Some(0), DS, "KeyInfo"),
            ],
        }
    }

    fn check(&self, snapshot: Snapshot<u8, u8>, node: usize) -> Result<(), Cause> {
        if snapshot != self.snapshot() || node >= self.nodes.len() {
            return Err(Cause::Source);
        }
        Ok(())
    }

    fn stamped(role: Role) -> (Self, usize, usize) {
        let mut xml = Self::normal();
        let node = if role == Role::Signature {
            8
        } else {
            let index = xml.nodes.len();
            xml.nodes
                .push(element(Some(7), XADES_141, "ArchiveTimeStamp"));
            index
        };
        let method = xml.nodes.len();
        xml.nodes
            .push(element(Some(node), DS, "CanonicalizationMethod"));
        xml.nodes
            .push(element(Some(node), XADES, "EncapsulatedTimeStamp"));
        (xml, node, method)
    }

    fn emit<W: Work>(
        &self,
        bytes: &[u8],
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Cause> {
        work.charge_work(u64::try_from(bytes.len()).unwrap())
            .map_err(Cause::Resource)?;
        self.streamed.set(self.streamed.get() + 1);
        let wrote = receiver.write(bytes);
        if self.ignore_refusal {
            let _ = receiver.write(bytes);
        } else {
            wrote.map_err(|_| Cause::Source)?;
        }
        if self.incomplete {
            return Err(Cause::Incomplete);
        }
        Ok(())
    }
}

impl TimestampXml for Tree {
    fn canonicalize<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        method: usize,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<(), Cause> {
        self.check(snapshot, node)?;
        self.check(snapshot, method)?;
        execution
            .charge_work(self.canonical_routes.len() as u64)
            .map_err(Cause::Resource)?;
        if let Some((_, bytes)) = self.canonical_routes.iter().find(|entry| entry.0 == node) {
            return self.emit(bytes, receiver, execution);
        }
        let node = u8::try_from(node).map_err(|_| Cause::Source)?;
        let method = u8::try_from(method).map_err(|_| Cause::Source)?;
        // Synthetic framing tests common input order, not XML C14N equivalence.
        self.emit(&[b'E', node, b'M', method], receiver, execution)
    }
}

impl ReferenceXml for Tree {
    fn visit_authenticated_references<VE, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        execution: &W,
        mut visitor: impl for<'view> FnMut(Descriptor<'view, usize>) -> Result<(), VE>,
    ) -> Result<Completeness<usize>, VisitError<Cause, VE>> {
        self.check(snapshot, signature)
            .map_err(VisitError::Processing)?;
        for reference in &self.references {
            execution
                .charge_work(1)
                .map_err(|cause| VisitError::Processing(Cause::Resource(cause)))?;
            let container = self.nodes[reference.node]
                .parent
                .ok_or(VisitError::Processing(Cause::Source))?;
            let parent = if container == 9 {
                Parent::SignedInfo(container)
            } else {
                Parent::Manifest(container)
            };
            visitor(Descriptor {
                reference: *reference,
                parent,
                object_location: self
                    .reference_location(reference.node, execution)
                    .map_err(VisitError::Processing)?,
            })
            .map_err(VisitError::Visitor)?;
        }
        Ok(self.reference_completeness)
    }

    fn resolve_reference<R, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        property: usize,
        source: LexicalSource<'_>,
        execution: &W,
        visitor: impl for<'view> FnOnce(Descriptor<'view, usize>) -> R,
    ) -> Result<Resolution<R>, Cause> {
        self.check(snapshot, signature)?;
        self.check(snapshot, property)?;
        execution.charge_work(1).map_err(Cause::Resource)?;
        if let LexicalSource::Attribute(attribute) = source
            && (!attribute.namespace.is_empty()
                || !matches!(attribute.local, "URI" | "ObjectReference"))
        {
            return Err(Cause::Source);
        }
        // Synthetic resolver routing; URI grammar belongs to the real XML owner.
        execution
            .charge_work(self.include_routes.len() as u64)
            .map_err(Cause::Resource)?;
        let routed = self
            .include_routes
            .iter()
            .find(|entry| entry.0 == property)
            .map(|entry| entry.1);
        let target = self.object_reference;
        let ordinal = if let Some(ordinal) = routed {
            ordinal
        } else if let Some(target) = target {
            match target {
                "#direct" => 0,
                "#manifest" => 2,
                "#bad-digest" => 3,
                "#foreign" => return Ok(Resolution::Unauthenticated),
                "#unsupported" => return Ok(Resolution::Unsupported),
                _ => return Ok(Resolution::Unresolved),
            }
        } else {
            return Ok(Resolution::Missing);
        };
        let reference = *self.references.get(ordinal).ok_or(Cause::Source)?;
        let container = self.nodes[reference.node].parent.ok_or(Cause::Source)?;
        let parent = if container == 9 {
            Parent::SignedInfo(container)
        } else {
            Parent::Manifest(container)
        };
        Ok(Resolution::Resolved(visitor(Descriptor {
            reference,
            parent,
            object_location: self.reference_location(reference.node, execution)?,
        })))
    }

    fn boolean_attribute<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        attribute: Name<'_>,
        execution: &W,
    ) -> Result<Boolean, Cause> {
        self.check(snapshot, node)?;
        execution.charge_work(1).map_err(Cause::Resource)?;
        if attribute
            != (Name {
                namespace: "",
                local: "referencedData",
            })
        {
            return Err(Cause::Source);
        }
        execution
            .charge_work(self.include_routes.len() as u64)
            .map_err(Cause::Resource)?;
        if let Some(entry) = self.include_routes.iter().find(|entry| entry.0 == node) {
            return Ok(entry.2);
        }
        Ok(match self.validation_uri {
            None => Boolean::Absent,
            Some("true" | "1") => Boolean::Value(true),
            Some("false" | "0") => Boolean::Value(false),
            Some(_) => Boolean::Malformed,
        })
    }

    fn replay_reference<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        reference: usize,
        mode: Replay<usize>,
        receiver: &mut impl Receiver,
        execution: &W,
    ) -> Result<ReplayOutcome<Cause>, Cause> {
        self.check(snapshot, signature)?;
        self.check(snapshot, reference)?;
        let ordinal = self
            .references
            .iter()
            .position(|entry| entry.node == reference)
            .ok_or(Cause::Source)?;
        let ordinal = u8::try_from(ordinal).map_err(|_| Cause::Source)?;
        if self.unavailable_reference == Some(reference) {
            return Ok(ReplayOutcome::Unavailable(Cause::Unavailable));
        }
        execution
            .charge_work(self.reference_routes.len() as u64)
            .map_err(Cause::Resource)?;
        if let Some((_, bytes)) = self
            .reference_routes
            .iter()
            .find(|entry| entry.0 == reference)
        {
            self.emit(bytes, receiver, execution)?;
            return Ok(ReplayOutcome::Complete);
        }
        match mode {
            Replay::Timestamp(method) => {
                self.check(snapshot, method)?;
                let method = u8::try_from(method).map_err(|_| Cause::Source)?;
                self.emit(&[b'R', ordinal, b'M', method], receiver, execution)
            }
            Replay::ReferenceOutput => self.emit(&[b'D', ordinal], receiver, execution),
        }?;
        Ok(ReplayOutcome::Complete)
    }
}

#[derive(Debug)]
enum SinkError {
    Account,
    Resource(MemoryError),
    Refused,
}

struct Collect {
    bytes: Option<OwnedVec<u8>>,
    refuse: bool,
}

impl Collect {
    fn new(memory: &Memory) -> Self {
        Self {
            bytes: Some(memory.vector()),
            refuse: false,
        }
    }
    fn bytes(&self) -> &[u8] {
        self.bytes.as_ref().unwrap()
    }
}

impl Sink for Collect {
    type Error = SinkError;
    fn write<W: Work>(&mut self, bytes: &[u8], execution: &W) -> Result<(), Self::Error> {
        if self.refuse {
            return Err(SinkError::Refused);
        }
        let retained = self.bytes.take().unwrap();
        match retained.with_execution(execution) {
            Ok(mut scoped) => {
                let copied = scoped.try_extend_from_slice(bytes);
                self.bytes = Some(scoped.into_owned());
                copied.map_err(SinkError::Resource)
            }
            Err(retained) => {
                self.bytes = Some(retained);
                Err(SinkError::Account)
            }
        }
    }
}

fn funded() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65_536, 300_000)))
}

impl SignatureXml for Tree {
    fn signature_status<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        execution: &W,
    ) -> Result<Status, Cause> {
        self.check(snapshot, signature)?;
        if let Some(counter) = self.counter_receipt(signature, execution)? {
            return Ok(counter.status);
        }
        Ok(self.signature_status)
    }

    fn reference_count<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        execution: &W,
    ) -> Result<usize, Cause> {
        self.check(snapshot, signature)?;
        if let Some(counter) = self.counter_receipt(signature, execution)? {
            return Ok(counter.references.len());
        }
        Ok(self.references.len())
    }

    fn reference<R, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        ordinal: usize,
        execution: &W,
        visitor: impl for<'view> FnOnce(Reference<'view, usize>) -> R,
    ) -> Result<R, Cause> {
        self.check(snapshot, signature)?;
        if let Some(counter) = self.counter_receipt(signature, execution)? {
            let reference = counter.references.get(ordinal).ok_or(Cause::Source)?;
            return Ok(visitor(*reference));
        }
        let reference = self.references.get(ordinal).ok_or(Cause::Source)?;
        Ok(visitor(*reference))
    }

    fn qualifying_target<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        qualifying: usize,
        execution: &W,
    ) -> Result<Target<usize>, Cause> {
        self.check(snapshot, qualifying)?;
        for (node, target) in &self.target_routes {
            execution.charge_work(1).map_err(Cause::Resource)?;
            if *node == qualifying {
                return Ok(*target);
            }
        }
        if self.nested_counters.is_empty() && self.counter_evidence.is_none() {
            return Ok(self.target);
        }
        // Synthetic original evidence can represent selected child signatures
        // independently of the root receipt, without changing XML generation.
        execution.charge_work(2).map_err(Cause::Resource)?;
        if let Some(object) = self.nodes[qualifying].parent
            && let Some(signature) = self.nodes[object].parent
            && self.counter_receipt(signature, execution)?.is_some()
        {
            return Ok(Target::LocalBareName(signature));
        }
        Ok(self.target)
    }
}

impl Xml for Tree {
    type Id = usize;
    type Document = u8;
    type Generation = u8;
    type Error = Cause;

    fn snapshot(&self) -> Snapshot<u8, u8> {
        Snapshot {
            document: self.document,
            generation: self.generation.get(),
        }
    }

    fn inspect<R, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        _execution: &W,
        visitor: impl for<'view> FnOnce(Node<'view>) -> R,
    ) -> Result<R, Cause> {
        self.check(snapshot, node)?;
        Ok(visitor(self.nodes[node].value))
    }

    fn attribute<R, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        name: Name<'_>,
        execution: &W,
        visitor: impl for<'view> FnOnce(Option<&'view str>) -> R,
    ) -> Result<R, Cause> {
        self.check(snapshot, node)?;
        Ok(visitor(
            if name.namespace.is_empty() && name.local == "Qualifier" {
                self.identifier_qualifier
            } else if name.namespace.is_empty() && name.local == "MimeType" {
                self.object_mime
            } else if name.namespace.is_empty() && name.local == "Encoding" {
                self.binary_encoding
            } else if name.namespace.is_empty() && name.local == "Algorithm" {
                execution
                    .charge_work(self.digest_algorithms.len() as u64)
                    .map_err(Cause::Resource)?;
                self.digest_algorithms
                    .iter()
                    .find(|entry| entry.0 == node)
                    .map_or(self.digest_algorithm, |entry| Some(entry.1))
            } else if name.namespace.is_empty() && name.local == "ObjectReference" {
                self.object_reference
            } else if name.namespace.is_empty() && name.local == "URI" {
                self.validation_uri
            } else {
                None
            },
        ))
    }

    fn first_child<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        parent: usize,
        execution: &W,
    ) -> Result<Option<usize>, Cause> {
        self.check(snapshot, parent)?;
        if let Some(index) = &self.indexed {
            if index.first.len() != self.nodes.len() {
                return Err(Cause::Source);
            }
            execution.charge_work(1).map_err(Cause::Resource)?;
            return Ok(index.first[parent]);
        }
        for index in 0..self.nodes.len() {
            execution.charge_work(1).map_err(Cause::Resource)?;
            if self.nodes[index].parent == Some(parent) {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }

    fn next_sibling<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        parent: usize,
        node: usize,
        execution: &W,
    ) -> Result<Option<usize>, Cause> {
        self.check(snapshot, node)?;
        if self.nodes[node].parent != Some(parent) {
            return Err(Cause::Source);
        }
        if let Some(index) = &self.indexed {
            if index.next.len() != self.nodes.len() {
                return Err(Cause::Source);
            }
            execution.charge_work(1).map_err(Cause::Resource)?;
            return Ok(index.next[node]);
        }
        for index in node + 1..self.nodes.len() {
            execution.charge_work(1).map_err(Cause::Resource)?;
            if self.nodes[index].parent == Some(parent) {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }
}

impl properties::DateTimeXml for Tree {
    fn date_time<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        execution: &W,
    ) -> Result<properties::DateTimeFact, Cause> {
        // Metadata projection oracle only. Actual XSD lexical qualification is
        // the XML owner's public scalar suite, not this synthetic tree.
        self.check(snapshot, node)?;
        self.date_time_calls.set(self.date_time_calls.get() + 1);
        execution.charge_work(1).map_err(Cause::Resource)?;
        Ok(self.date_time)
    }
}

impl certificate::CertificateXml for Tree {
    fn key_association<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        signature: usize,
        _certificate: &structured_pkix::Certificate<'_>,
        key: structured_pkix::path::WorkingKey<'_>,
        execution: &W,
    ) -> Result<certificate::KeyAssociation, Cause> {
        // Explicit synthetic owner receipt, not real crypto/key qualification.
        self.check(snapshot, signature)?;
        execution.charge_work(1).map_err(Cause::Resource)?;
        self.key_projection.set(Some(KeyProjection::of(key)));
        Ok(self.key_association)
    }
}

impl binary::OwnedBinaryXml for Tree {
    fn decode_owned<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        execution: &W,
    ) -> Result<OwnedVec<u8>, Cause> {
        self.check(snapshot, node)?;
        execution.charge_work(1).map_err(Cause::Resource)?;
        if matches!(self.decoding, Decoding::Refuse) {
            return Err(Cause::Source);
        }
        if let Some(buffer) = self.cached_binary.borrow_mut().take() {
            return Ok(buffer);
        }
        // Fixture source already has decoded octets. A real adapter must admit
        // and reuse its original lexical/base64 kernel, not this fixture copy.
        let mut decoded = execution.vector();
        execution
            .charge_work(self.binary_routes.len() as u64)
            .map_err(Cause::Resource)?;
        let bytes = match self
            .binary_routes
            .iter()
            .find(|(original, _)| *original == node)
        {
            Some((_, bytes)) => bytes,
            None => &self.binary,
        };
        decoded
            .try_extend_from_slice(bytes)
            .map_err(Cause::Resource)?;
        self.decoded_pointer.set(decoded.as_ptr() as usize);
        if self.mutate_binary {
            self.generation.set(self.generation.get() + 1);
        }
        Ok(decoded.into_owned())
    }

    fn decode_binary_owned(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        operation: &structured_asn1::Reader<'_>,
    ) -> Result<binary::OwnedDecoded, Cause> {
        let bytes =
            binary::OwnedBinaryXml::decode_owned(self, snapshot, node, &operation.execution())?;
        // Synthetic fresh source, as in with_binary. Cached real sources must
        // move their original Parser too, rather than use this fixture constructor.
        let parser = match self.binary_parser.borrow_mut().take() {
            Some(original) => original,
            None => structured_asn1::Parser::ber(operation.memory().clone()),
        };
        Ok(binary::OwnedDecoded {
            parser,
            bytes,
            base: 0,
            depth: self.binary_depth,
        })
    }
}

impl BinaryXml for Tree {
    fn with_octets<R, C, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        execution: &W,
        visitor: impl for<'source> FnOnce(&'source [u8]) -> Result<R, C>,
    ) -> Result<Result<R, C>, Cause> {
        let decoded = binary::OwnedBinaryXml::decode_owned(self, snapshot, node, execution)?;
        let result = visitor(&decoded);
        Ok(result)
    }

    fn with_binary<R, C>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: usize,
        operation: &structured_asn1::Reader<'_>,
        visitor: impl for<'source> FnOnce(binary::Decoded<'source>) -> Result<R, C>,
    ) -> Result<Result<R, C>, Cause> {
        self.with_octets(snapshot, node, &operation.execution(), |decoded| {
            let parser = structured_asn1::Parser::ber(operation.memory().clone());
            visitor(binary::Decoded {
                parser: &parser,
                bytes: decoded,
                base: 0,
                depth: self.binary_depth,
            })
        })
    }
}

fn memory(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(0, work)))
}

#[test]
fn original_containers_and_snapshot_survive_without_dom_or_string_copies() {
    // Structural selection preserves every original role; it makes no trust claim.
    let xml = Tree::normal();
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let found = container::locate(&access, 0).unwrap();
    assert_eq!(found.snapshot(), xml.snapshot());
    assert_eq!(found.signature(), 0);
    assert_eq!(found.object(), 1);
    assert_eq!(found.qualifying(), 2);
    assert_eq!(found.signed(), 3);
    assert_eq!(found.unsigned(), Some(6));
}

#[test]
fn nested_signature_properties_cannot_substitute_for_selected_signature() {
    // A descendant search would accept a wrapping attack's different Signature.
    let mut xml = Tree::normal();
    let nested = xml.nodes.len();
    xml.nodes.push(element(Some(1), DS, "Signature"));
    let nested_object = xml.nodes.len();
    xml.nodes.push(element(Some(nested), DS, "Object"));
    xml.nodes[2].parent = Some(nested_object);
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        container::locate(&access, 0),
        Err(ContainerError::Missing {
            parent: 0,
            local: "QualifyingProperties"
        })
    ));
}

#[test]
fn duplicate_qualifying_properties_in_another_object_are_not_first_match_success() {
    // The single-container rule applies across all direct ds:Object children.
    let mut xml = Tree::normal();
    let object = xml.nodes.len();
    xml.nodes.push(element(Some(0), DS, "Object"));
    let duplicate = xml.nodes.len();
    xml.nodes
        .push(element(Some(object), XADES, "QualifyingProperties"));
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        container::locate(&access, 0),
        Err(ContainerError::Duplicate { node }) if node == duplicate
    ));
}

#[test]
fn baseline_direct_properties_cannot_hide_an_indirect_reference_in_another_object() {
    // EN6.3 requires direct-only incorporation at every current baseline level.
    // A valid direct SignedProperties cannot conceal a second indirect branch.
    for same_object in [true, false] {
        let mut xml = Tree::normal();
        let object = if same_object {
            1
        } else {
            let object = xml.nodes.len();
            xml.nodes.push(element(Some(0), DS, "Object"));
            object
        };
        let reference = xml.nodes.len();
        xml.nodes.push(element(
            Some(object),
            XADES,
            "QualifyingPropertiesReference",
        ));
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        assert!(
            matches!(container::locate(&access, 0), Err(ContainerError::Unexpected { node }) if node == reference)
        );
        assert_eq!(xml.streamed.get(), 0);
    }
}

#[test]
fn mixed_content_of_other_objects_is_not_a_property_schema_violation() {
    // ds:Object's opaque application payload is allowed to contain character data.
    let mut xml = Tree::normal();
    let object = xml.nodes.len();
    xml.nodes.push(element(Some(0), DS, "Object"));
    xml.nodes.push(Record {
        parent: Some(object),
        value: Node::Text("opaque application payload"),
    });
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert_eq!(container::locate(&access, 0).unwrap().qualifying(), 2);
}

#[test]
fn namespace_spelling_cannot_impersonate_xades() {
    // Namespace identity is exact even when a URI looks similar to the real one.
    let mut xml = Tree::normal();
    xml.nodes[2].value = Node::Element(Name {
        namespace: "HTTP://uri.etsi.org/01903/v1.3.2#",
        local: "QualifyingProperties",
    });
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        container::locate(&access, 0),
        Err(ContainerError::Missing { .. })
    ));
}

#[test]
fn signed_after_unsigned_is_rejected_and_empty_signed_is_not_a_valid_layout() {
    // XSD sequence order and the normative nonempty rule are separate constraints.
    let mut xml = Tree::normal();
    xml.nodes[3].value = Node::Element(Name {
        namespace: XADES,
        local: "UnsignedProperties",
    });
    xml.nodes[6].value = Node::Element(Name {
        namespace: XADES,
        local: "SignedProperties",
    });
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        container::locate(&access, 0),
        Err(ContainerError::Order { node: 6 })
    ));

    let mut xml = Tree::normal();
    xml.nodes[4].parent = Some(1);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        container::locate(&access, 0),
        Err(ContainerError::Empty { node: 3 })
    ));
}

#[test]
fn original_resource_cause_is_not_missing_properties() {
    // Locating a container cannot turn work exhaustion into document absence.
    let xml = Tree::normal();
    let memory = memory(0);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        container::locate(&access, 0),
        Err(ContainerError::Access(AccessError::Resource {
            node: 0,
            cause: MemoryError::WorkExceeded
        }))
    ));

    // Initial container traversal fits; the later QName comparison must refuse.
    let memory = self::memory(100);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        container::locate(&access, 0),
        Err(ContainerError::Access(AccessError::Resource {
            node: 2,
            cause: MemoryError::WorkExceeded
        }))
    ));

    // Exactly the signature QName and dispatch fit; owner scanning then refuses.
    let memory = self::memory(45);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        container::locate(&access, 0),
        Err(ContainerError::Child(
            structured_xades::xml::ChildError::Access(AccessError::Xml(Cause::Resource(
                MemoryError::WorkExceeded
            )))
        ))
    ));
}

#[test]
fn selected_binding_uses_exact_reference_target_type_and_generation() {
    // The result keeps the exact selected signature and its SignedInfo ordinal.
    let xml = Tree::normal();
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    assert_eq!(bound.containers().signature(), 0);
    assert_eq!(bound.containers().signed(), 3);
    assert_eq!(bound.reference(), 11);
    assert_eq!(bound.ordinal(), 1);
    assert_eq!(bound.containers().snapshot(), xml.snapshot());
}

#[test]
fn binding_does_not_substitute_another_signature_or_unresolved_target() {
    // A successful reference somewhere else cannot authenticate the chosen node.
    let mut xml = Tree::normal();
    xml.target = Target::LocalBareName(8);
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    assert!(matches!(
        binding::bind(&access, &layout),
        Err(BindingError::Target { node: 2 })
    ));

    xml.target = Target::Other;
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        binding::bind(&access, &layout),
        Err(BindingError::Target { node: 2 })
    ));

    xml.target = Target::LocalBareName(0);
    xml.signature_status = Status::Invalid;
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        binding::bind(&access, &layout),
        Err(BindingError::Signature {
            node: 0,
            status: Status::Invalid
        })
    ));
}

#[test]
fn matching_type_without_complete_original_coverage_cannot_be_bound() {
    // Valid digest over an arbitrary filtered node-set does not cover the property.
    let mut xml = Tree::normal();
    xml.references[1].coverage = Coverage::Transformed;
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    assert!(matches!(
        binding::bind(&access, &layout),
        Err(BindingError::Reference { node: 11 })
    ));
}

#[test]
fn repeated_valid_reference_to_the_same_properties_does_not_invent_cardinality_rule() {
    // EN 319132-1 §4.4.2 requires a protecting reference, not at most one reference.
    let mut xml = Tree::normal();
    let mut repeated = xml.references[1];
    repeated.node = 12;
    xml.references.push(repeated);
    let memory = memory(10000);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    assert_eq!(binding::bind(&access, &layout).unwrap().reference(), 11);
}

#[test]
fn signature_timestamp_covers_original_signature_value_element_only() {
    // Core selects the element for the owner, never decoded signature octets.
    let (xml, node, method) = Tree::stamped(Role::Signature);
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read(&access, &bound, node).unwrap();
    assert_eq!(stamp.role(), Role::Signature);
    assert_eq!(stamp.method(), method);
    assert_eq!(stamp.tokens(), &[method + 1]);
    let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
    assert_eq!(input.location(), (xml.snapshot(), node));
    let mut sink = Collect::new(&memory);
    stream::run(&mut input, &mut sink, &memory, "logical.timestamp.input", 0).unwrap();
    assert_eq!(
        sink.bytes(),
        &[b'E', 12, b'M', u8::try_from(method).unwrap()]
    );
    assert_eq!(xml.streamed.get(), 1);
}

#[test]
fn timestamp_md5_imprint_is_a_baseline_refusal_before_original_input_replay() {
    // EN319132-1 §6.2.1 prohibits MD5 even when the CMS signature itself uses
    // an allowed digest. A generic Unsupported result after reading XML would
    // miss the baseline rule and perform observable work before its refusal.
    use structured_cms::{ess::Version, timestamp::ProfileSource};
    assert_timestamp_digest_prohibition(
        timestamp_oracle::fixture_md5_imprint(),
        timestamp::DigestUse::Imprint,
        ProfileSource::Information,
    );
    assert_timestamp_digest_prohibition(
        timestamp_oracle::fixture_md5_signer(),
        timestamp::DigestUse::Signer,
        ProfileSource::Envelope,
    );
    for index in [0, 1] {
        assert_timestamp_digest_prohibition(
            timestamp_oracle::fixture_md5_ess(index),
            timestamp::DigestUse::Certificate {
                version: Version::V2,
                index,
            },
            ProfileSource::Envelope,
        );
    }
}

fn assert_timestamp_digest_prohibition(
    (provider, token, certificate_bytes): (timestamp_oracle::Oracle, Vec<u8>, Vec<u8>),
    usage: timestamp::DigestUse,
    domain: structured_cms::timestamp::ProfileSource,
) {
    // Both original source domains must survive the same complete-check bridge,
    // including a later signed restriction after the allowed first identity.
    use structured_cms::timestamp::CheckContext;
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    let (mut xml, node, _) = Tree::stamped(Role::Signature);
    xml.binary = token;
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let certificate = structured_pkix::Certificate::read(&parser, &certificate_bytes, 400).unwrap();
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let context = CheckContext {
        certificate: &certificate,
        certificate_parent: &operation,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: None,
        utc: &utc,
        reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
        window: None,
        policy_accuracy: None,
    };
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read(&access, &bound, node).unwrap();
    let check = timestamp::Check {
        xml: &xml,
        provider: &provider,
        context: &context,
    };
    let answer = check.retain(&bound, &stamp, 0, &operation, |_, _| Ok::<_, ()>(false));
    let Err(timestamp::CheckError::Token(binary::Error::Callback {
        location,
        cause:
            binary::TokenError::Callback(structured_cms::timestamp::ProfileCheckError::Profile {
                source,
                context: map,
            }),
    })) = answer
    else {
        panic!("MD5 refusal lost its original profile class and source")
    };
    assert_eq!(location.node, stamp.tokens()[0]);
    assert_eq!(location.snapshot, xml.snapshot());
    assert_eq!(source.source, domain);
    let timestamp::DigestError::Prohibited {
        usage: actual,
        offset,
    } = source.cause
    else {
        panic!("MD5 became a resource or provider refusal")
    };
    assert_eq!(actual, usage);
    let physical = if domain == structured_cms::timestamp::ProfileSource::Information {
        map.project_offset(offset, &memory).unwrap()
    } else {
        offset
    };
    assert!(physical < xml.binary.len() as u64);
    assert_eq!(xml.streamed.get(), 0, "prohibited imprint replayed XML");
    assert_eq!(provider.verified.get(), 0);
}

#[test]
fn original_signature_and_archive_inputs_drive_real_timestamp_signature_and_retained_evidence() {
    // This proves the actual common RFC3161 complete checker receives our
    // prepared original input, verifies ECDSA/ESS/imprint and retains evidence.
    // Framing is synthetic: this does not qualify real XML C14N or B profiles.
    use structured_cms::timestamp::CheckContext;
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    for role in [Role::Signature, Role::Archive] {
        for agrees in [true, false] {
            let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)));
            let located = {
                let (mut xml, node, method) = Tree::stamped(role);
                let m = u8::try_from(method).unwrap();
                let expected = if role == Role::Signature {
                    vec![b'E', 12, b'M', m]
                } else {
                    vec![
                        b'R', 0, b'M', m, b'R', 1, b'M', m, b'E', 9, b'M', m, b'E', 12, b'M', m,
                        b'E', 13, b'M', m, b'E', 8, b'M', m,
                    ]
                };
                let covered = if agrees {
                    expected.as_slice()
                } else {
                    b"unrelated original input"
                };
                let (provider, token, certificate_bytes) = if role == Role::Signature && agrees {
                    // The baseline forbids actual MD5 use, not an unused
                    // advertised entry in the generic CMS algorithm catalogue.
                    timestamp_oracle::fixture_unused_md5(covered)
                } else {
                    timestamp_oracle::fixture(covered)
                };
                {
                    let inspection = structured_asn1::Parser::der(memory.clone());
                    let decoded =
                        structured_cms::timestamp::Token::read(&inspection, &token, 0).unwrap();
                    assert!(decoded.faults().is_empty(), "{:?}", decoded.faults());
                    assert!(
                        decoded.message().faults().is_empty(),
                        "{:?}",
                        decoded.message().faults()
                    );
                    assert!(
                        decoded.signer().faults().is_empty(),
                        "{:?}",
                        decoded.signer().faults()
                    );
                }
                xml.binary = token;
                let parser = structured_asn1::Parser::der(memory.clone());
                let operation = parser.read(&[], 900).unwrap();
                let cert_parser = structured_asn1::Parser::der(memory.clone());
                let certificate =
                    structured_pkix::Certificate::read(&cert_parser, &certificate_bytes, 400)
                        .unwrap();
                let certificate_parent = cert_parser.read(&[], 400).unwrap();
                let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
                let context = CheckContext {
                    certificate: &certificate,
                    certificate_parent: &certificate_parent,
                    key: WorkingKey::standing(certificate.tbs().public_key()),
                    requested: None,
                    utc: &utc,
                    reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
                    window: None,
                    policy_accuracy: None,
                };
                let access = Access::new(&xml, xml.snapshot(), &memory);
                let layout = container::locate(&access, 0).unwrap();
                let bound = binding::bind(&access, &layout).unwrap();
                let stamp = timestamp::read(&access, &bound, node).unwrap();
                let check = timestamp::Check {
                    xml: &xml,
                    provider: &provider,
                    context: &context,
                };
                let located = check
                    .retain(&bound, &stamp, 0, &operation, |_, _| Ok::<_, ()>(false))
                    .unwrap();
                assert_eq!(located.is_some(), agrees);
                if let Some(verified) = &located {
                    assert_eq!(verified.token().node, stamp.tokens()[0]);
                    assert_eq!(verified.token().snapshot, xml.snapshot());
                    assert_eq!(verified.property(), stamp.node());
                    assert_eq!(verified.signature(), layout.signature());
                    assert_eq!(verified.purpose(), role.purpose());
                    assert_verified_element_coverage(&xml, &bound, &stamp, verified, &memory);
                }
                assert_eq!(provider.verified.get(), 1);
                located
            };
            if agrees {
                assert!(memory.used() > 0);
                // The privately bound XML identity and common evidence survive
                // every XML/parser/provider source; endpoints reuse common UTC.
                let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
                let interval = located.as_ref().unwrap().interval(&utc, &memory).unwrap();
                assert_eq!(interval.earliest, Instant::new(1_767_225_600, 0).unwrap());
                assert_eq!(interval.latest, interval.earliest);
            }
            drop(located);
            assert_eq!(memory.used(), 0);
        }
    }
}

fn assert_verified_element_coverage(
    xml: &Tree,
    bound: &binding::Selected<Tree>,
    stamp: &timestamp::Timestamp<Tree>,
    verified: &timestamp::VerifiedTimestamp<Tree>,
    memory: &Memory,
) {
    let access = Access::new(xml, xml.snapshot(), memory);
    let input = Input::prepare(xml, bound, stamp, memory).unwrap();
    let coverage = input.element_coverage(memory).unwrap();
    let signature = bound.containers().signature();
    let value = xml.element_child(signature, DS, "SignatureValue");
    let key = xml.element_child(signature, DS, "KeyInfo");
    assert!(coverage.covers(verified, value, &access).unwrap());
    // Retained timestamp evidence cannot spend its earlier account when a
    // later coverage query has no work, even for the same original identities.
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let denied_access = Access::new(xml, xml.snapshot(), &denied);
    assert!(matches!(
        coverage.covers(verified, value, &denied_access),
        Err(structured_ltv::material::CoverageError::Scope(_))
    ));
    assert_eq!(
        coverage.covers(verified, key, &access).unwrap(),
        stamp.role() == Role::Archive
    );
    assert!(
        !coverage
            .covers(verified, stamp.tokens()[0], &access)
            .unwrap()
    );
    let foreign = Access::new(
        xml,
        Snapshot {
            document: xml.document + 1,
            generation: xml.generation.get(),
        },
        memory,
    );
    assert!(matches!(
        coverage.covers(verified, value, &foreign),
        Err(structured_ltv::material::CoverageError::Foreign { .. })
    ));
}

#[test]
fn archive_element_coverage_excludes_its_own_and_later_material_and_non_elements() {
    // The prepared input set is the SAME sequence as replay. Earlier material
    // is included, but the archive token cannot authenticate its own material
    // or a later property merely because both share an unsigned container.
    let (mut xml, archive, _) = Tree::stamped(Role::Archive);
    let earlier = xml.element_child(0, DS, "SignatureValue");
    let later = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "AnyValidationData"));
    let token = xml.element_child(archive, XADES, "EncapsulatedTimeStamp");
    let ignored = xml.nodes.len();
    xml.nodes.push(Record {
        parent: Some(earlier),
        value: Node::Other,
    });
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read(&access, &bound, archive).unwrap();
    let input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
    let held = memory.used();
    let coverage = input.element_coverage(&memory).unwrap();
    assert!(coverage.selects(earlier, &access).unwrap());
    assert!(!coverage.selects(archive, &access).unwrap());
    assert!(!coverage.selects(token, &access).unwrap());
    assert!(!coverage.selects(later, &access).unwrap());
    assert!(!coverage.selects(ignored, &access).unwrap());
    let zero = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let denied = Access::new(&xml, xml.snapshot(), &zero);
    assert!(matches!(
        coverage.selects(earlier, &denied),
        Err(structured_ltv::material::CoverageError::Scope(
            structured_ltv::source::ScopeError::Resource { .. }
        ))
    ));
    xml.generation.set(2);
    assert!(matches!(
        coverage.selects(earlier, &access),
        Err(structured_ltv::material::CoverageError::Scope(
            structured_ltv::source::ScopeError::Changed { .. }
        ))
    ));
    drop(coverage);
    assert_eq!(memory.used(), held);
}

#[test]
fn timestamp_element_coverage_requires_explicit_successful_whole_target_receipt() {
    // Authenticated reference instructions alone do not prove their targets'
    // original element contents survived arbitrary transforms or were checked.
    for (coverage, status, expected) in [
        (Coverage::Transformed, Status::Valid, false),
        (Coverage::ElementContent, Status::Unchecked, false),
        (Coverage::ElementContent, Status::Valid, true),
    ] {
        let (mut xml, archive, _) = Tree::stamped(Role::Archive);
        let envelope = xml.nodes.len();
        xml.nodes.push(element(None, "urn:test", "Envelope"));
        xml.nodes[0].parent = Some(envelope);
        let payload = xml.nodes.len();
        xml.nodes
            .push(element(Some(envelope), "urn:test", "DetachedFromSignature"));
        let inner = xml.nodes.len();
        xml.nodes.push(element(Some(payload), "urn:test", "Binary"));
        xml.references[0].target = Some(payload);
        xml.references[0].coverage = coverage;
        xml.references[0].status = status;
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp = timestamp::read(&access, &bound, archive).unwrap();
        let input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
        let selection = input.element_coverage(&memory).unwrap();
        assert_eq!(selection.selects(payload, &access).unwrap(), expected);
        assert_eq!(selection.selects(inner, &access).unwrap(), expected);
    }
}

#[test]
fn timestamp_reference_document_root_is_a_traversal_boundary_not_a_covered_element() {
    // The XML owner's DocumentNode may be its virtual document root. This is
    // a receipt-shape fixture, not a claim of a valid self-referencing signature.
    let (mut xml, archive, _) = Tree::stamped(Role::Archive);
    let root = xml.nodes.len();
    xml.nodes.push(Record {
        parent: None,
        value: Node::Other,
    });
    xml.nodes[0].parent = Some(root);
    let payload = xml.nodes.len();
    xml.nodes.push(element(Some(root), "urn:test", "Payload"));
    xml.references[0].target = Some(root);
    xml.references[0].coverage = Coverage::ElementContent;
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read(&access, &bound, archive).unwrap();
    let input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
    let selection = input.element_coverage(&memory).unwrap();
    assert!(!selection.selects(root, &access).unwrap());
    assert!(selection.selects(payload, &access).unwrap());
}

#[test]
fn archive_element_coverage_uses_iterative_frames_for_deep_original_payloads() {
    // Other Object payloads can be deeply nested without recursive traversal.
    // A refused partial index releases both identity storage and active frames.
    let (mut xml, archive, _) = Tree::stamped(Role::Archive);
    let object = xml.nodes.len();
    xml.nodes.push(element(Some(0), DS, "Object"));
    let mut leaf = object;
    for _ in 0..512 {
        let parent = leaf;
        leaf = xml.nodes.len();
        xml.nodes.push(element(Some(parent), "urn:test", "Nested"));
    }
    xml.index_edges();
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_048_576, 10_000_000)));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read(&access, &bound, archive).unwrap();
    let input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
    let held = memory.used();
    let coverage = input.element_coverage(&memory).unwrap();
    assert!(coverage.selects(object, &access).unwrap());
    assert!(coverage.selects(leaf, &access).unwrap());
    drop(coverage);
    assert_eq!(memory.used(), held);
    let small = Memory::new(Arc::new(MemoryAccount::new(1024, 10_000_000)));
    assert!(input.element_coverage(&small).is_err());
    assert_eq!(small.used(), 0);
    assert_eq!(memory.used(), held);
}

fn token_pipeline_tree() -> (Tree, usize, usize) {
    let mut xml = preparation_tree();
    let first = xml
        .nodes
        .iter()
        .position(|record| {
            record.parent == Some(8)
                && matches!(
                    record.value,
                    Node::Element(Name {
                        local: "EncapsulatedTimeStamp",
                        ..
                    })
                )
        })
        .unwrap();
    let archive = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES_141, "ArchiveTimeStamp"));
    xml.nodes
        .push(element(Some(archive), DS, "CanonicalizationMethod"));
    let second = xml.nodes.len();
    xml.nodes
        .push(element(Some(archive), XADES, "EncapsulatedTimeStamp"));
    (xml, first, second)
}

fn inspection_token() -> Vec<u8> {
    inspection_token_with_choices(&[], 3)
}

fn inspection_token_with_choices(revocations: &[u8], version: u8) -> Vec<u8> {
    inspection_token_with_carriage(revocations, &[], version)
}

fn inspection_token_with_carriage(revocations: &[u8], certificates: &[u8], version: u8) -> Vec<u8> {
    // A schema-only CMS token. Its carried empty TSTInfo is deliberately NOT
    // usable evidence; this fixture exercises source retention, not crypto.
    use structured_cms::oid;
    use timestamp_oracle::tlv;
    let algorithm = tlv(0x30, &tlv(6, &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1]));
    let mut signer = vec![2, 1, 3, 0x80, 1, 7];
    signer.extend(&algorithm);
    signer.extend(tlv(0x30, &tlv(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2])));
    signer.extend([4, 1, 1]);
    let mut content = tlv(6, oid::TST_INFO.as_bytes());
    content.extend(tlv(0xa0, &tlv(4, &[0x30, 0])));
    let mut body = vec![2, 1, version];
    body.extend(tlv(0x31, &algorithm));
    body.extend(tlv(0x30, &content));
    if !certificates.is_empty() {
        body.extend(tlv(0xa0, certificates));
    }
    if !revocations.is_empty() {
        body.extend(tlv(0xa1, revocations));
    }
    body.extend(tlv(0x31, &tlv(0x30, &signer)));
    let mut envelope = tlv(6, oid::SIGNED_DATA.as_bytes());
    envelope.extend(tlv(0xa0, &tlv(0x30, &body)));
    tlv(0x30, &envelope)
}

#[test]
fn material_index_combines_xml_and_token_pools_without_losing_original_placement() {
    // Equal DER carried in three storage roles keeps five distinct actual
    // occurrences. Source-pool tags prevent token ordinal 0 aliasing XML 0.
    let certificate = candidate_certificate();
    let (mut xml, first, second) = token_pipeline_tree();
    let header = xml
        .nodes
        .iter()
        .position(|record| {
            matches!(
                record.value,
                Node::Element(Name {
                    namespace: DS,
                    local: "X509Certificate"
                })
            )
        })
        .unwrap();
    xml.binary_routes.push((header, certificate.clone()));
    xml.binary = inspection_token_with_carriage(
        &carried_ocsp_choice(&ocsp_material_with_certificate(&certificate)),
        &certificate,
        5,
    );
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let held = memory.used();
    material::with_values(&xml, &prepared, &operation, |query, values| {
        timestamp::with_tokens(&xml, &prepared, query, timestamp::TokenProfile::Etsi, |current, tokens| {
            let carried = tokens.material_in(current).unwrap();
            let execution = current.execution();
            let access = Access::new(&xml, xml.snapshot(), &execution);
            // Source-pair identity is new work even though both parsed views
            // are already retained. Refuse before constructing any index.
            for budget in [0, 1] {
                let limited = Memory::new(Arc::new(MemoryAccount::new(0, budget)));
                let lower = Access::new(&xml, xml.snapshot(), &limited);
                assert!(matches!(
                    material::index_with_tokens(&values, &carried, &lower),
                    Err(structured_ltv::material::IndexError::Resource { cause: MemoryError::WorkExceeded, .. })
                ));
                assert_eq!(limited.used(), 0);
            }
            let index = material::index_with_tokens(&values, &carried, &access).unwrap();
            let material::Value::Certificate(certificate) = &values.values()[0].value else { panic!("original header certificate") };
            let copies = index.certificate(certificate, &access).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
            assert_eq!(copies.len(), 5);
            assert_eq!(copies[0].source(), structured_ltv::material::ArtifactSource::Material(0));
            for token in 0..2 {
                assert_eq!(copies[1 + token].source(), structured_ltv::material::ArtifactSource::TokenCertificate { token, certificate: 0 });
                assert_eq!(copies[3 + token].source(), structured_ltv::material::ArtifactSource::TokenRevocation(structured_ltv::material::CarriedOrigin { token, choice: 0 }));
                assert_eq!(copies[1 + token].embedded_certificate(), None);
                assert_eq!(copies[3 + token].embedded_certificate(), Some(0));
                let node = if token == 0 { first } else { second };
                for copy in [copies[1 + token], copies[3 + token]] {
                    assert_eq!(copy.location().node, node);
                    assert!(matches!(copy.placement(), material::Placement::TimestampToken { property, token: actual, role } if actual == node && property == tokens.sources()[token].property() && role == tokens.sources()[token].role()));
                }
            }
            let statuses = index.ocsp(&carried.basic_responses()[0].value, &access).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
            assert_eq!(statuses.len(), 2);
            assert_eq!(statuses[0].location().node, first);
            assert_eq!(statuses[1].location().node, second);
            // Calibrate actual XML-only index capacity, then prove that exact
            // capacity cannot produce a successful truncated combined index.
            drop(index);
            let before = memory.used();
            let baseline = material::index(&values, &access).unwrap();
            let capacity = memory.used() - before;
            drop(baseline);
            let limited = Memory::new(Arc::new(MemoryAccount::new(capacity, 1_048_576)));
            let lower = Access::new(&xml, xml.snapshot(), &limited);
            drop(material::index(&values, &lower).unwrap());
            assert_eq!(limited.used(), 0);
            let Err(error) = material::index_with_tokens(&values, &carried, &lower) else { panic!("late index growth must refuse") };
            assert!(matches!(error, structured_ltv::material::IndexError::Resource { .. }));
            assert_eq!(limited.used(), 0);
            Ok::<_, ()>(())
        }).unwrap();
        Ok::<_, ()>(())
    }).unwrap();
    assert_eq!(memory.used(), held);
    drop(prepared);
    assert_eq!(memory.used(), 0);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArchiveOrder {
    Late,
    Early,
    BaseEarly,
}

fn archive_material_fixture(
    order: ArchiveOrder,
) -> (Tree, usize, timestamp_oracle::Oracle, Vec<u8>, Vec<u8>) {
    // Synthetic XML framing isolates exact original archive selection; actual
    // P256/ESS/imprint verification below does not qualify XML C14N itself.
    struct Collect(Vec<u8>);
    impl Receiver for Collect {
        fn write(&mut self, bytes: &[u8]) -> Result<(), stream::Refused> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }
    let mut xml = preparation_tree();
    let early = order != ArchiveOrder::Late;
    let deferred = if early {
        append_crl_pair(&mut xml, order == ArchiveOrder::BaseEarly)
    } else {
        None
    };
    let archive = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES_141, "ArchiveTimeStamp"));
    xml.nodes
        .push(element(Some(archive), DS, "CanonicalizationMethod"));
    xml.nodes
        .push(element(Some(archive), XADES, "EncapsulatedTimeStamp"));
    if !early {
        assert!(append_crl_pair(&mut xml, false).is_none());
    }
    if let Some(delta) = deferred {
        let general = xml.nodes.len();
        xml.nodes
            .push(element(Some(7), XADES_141, "AnyValidationData"));
        let revocation = xml.nodes.len();
        xml.nodes
            .push(element(Some(general), XADES, "RevocationValues"));
        let group = xml.nodes.len();
        xml.nodes
            .push(element(Some(revocation), XADES, "CRLValues"));
        append_crl_value(&mut xml, group, delta);
    }
    let header = xml
        .nodes
        .iter()
        .position(|record| {
            matches!(
                record.value,
                Node::Element(Name {
                    namespace: DS,
                    local: "X509Certificate"
                })
            )
        })
        .unwrap();
    xml.binary_routes.push((header, candidate_certificate()));
    let (_, _, later_certificate, root) = timestamp_oracle::fixture_with_root(b"setup");
    let late = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "CertificateValues"));
    let late_value = xml.nodes.len();
    xml.nodes
        .push(element(Some(late), XADES, "EncapsulatedX509Certificate"));
    xml.binary_routes
        .push((late_value, later_certificate.clone()));
    if early {
        let value = xml.nodes.len();
        xml.nodes
            .push(element(xml.nodes[header].parent, DS, "X509Certificate"));
        xml.binary_routes.push((value, later_certificate));
        let value = xml.nodes.len();
        xml.nodes
            .push(element(xml.nodes[header].parent, DS, "X509Certificate"));
        xml.binary_routes.push((value, root));
    }
    let work = funded();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read(&access, &bound, archive).unwrap();
    let mut input = Input::prepare(&xml, &bound, &stamp, &work).unwrap();
    let mut octets = Collect(Vec::new());
    stream::Source::stream(&mut input, &mut octets, &work).unwrap();
    drop(input);
    let (provider, token, certificate, root) = timestamp_oracle::fixture_with_root(&octets.0);
    xml.binary = token;
    (xml, archive, provider, certificate, root)
}

fn append_crl_pair(xml: &mut Tree, defer_delta: bool) -> Option<Vec<u8>> {
    let property = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "RevocationValues"));
    let group = xml.nodes.len();
    xml.nodes.push(element(Some(property), XADES, "CRLValues"));
    let (base, delta) = timestamp_oracle::crl_pair();
    append_crl_value(xml, group, base);
    let deferred = if defer_delta {
        Some(delta)
    } else {
        append_crl_value(xml, group, delta);
        None
    };
    let group = xml.nodes.len();
    xml.nodes.push(element(Some(property), XADES, "OCSPValues"));
    let value = xml.nodes.len();
    xml.nodes
        .push(element(Some(group), XADES, "EncapsulatedOCSPValue"));
    xml.binary_routes
        .push((value, timestamp_oracle::ocsp_response(2)));
    deferred
}

fn append_crl_value(xml: &mut Tree, group: usize, bytes: Vec<u8>) {
    let value = xml.nodes.len();
    xml.nodes
        .push(element(Some(group), XADES, "EncapsulatedCRLValue"));
    xml.binary_routes.push((value, bytes));
}

#[test]
fn an_archive_tokens_own_certificate_cannot_complete_its_prior_material() {
    // Availability in the token being checked is too late to be part of its
    // own imprint. An earlier token here intentionally carries no certificate;
    // otherwise that legitimately covered earlier copy could satisfy lookup.
    use structured_cms::timestamp::CheckContext;
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    let (mut xml, archive, provider, certificate_bytes, _) =
        archive_material_fixture(ArchiveOrder::Late);
    let prior = xml
        .nodes
        .iter()
        .position(|record| {
            record.parent == Some(8)
                && matches!(
                    record.value,
                    Node::Element(Name {
                        local: "EncapsulatedTimeStamp",
                        ..
                    })
                )
        })
        .unwrap();
    xml.binary_routes.push((
        prior,
        timestamp_oracle::fixture(b"unrelated earlier imprint").1,
    ));
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let certificate = structured_pkix::Certificate::read(&parser, &certificate_bytes, 400).unwrap();
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let context = CheckContext {
        certificate: &certificate,
        certificate_parent: &operation,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: None,
        utc: &utc,
        reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
        window: None,
        policy_accuracy: None,
    };
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let stamp = prepared
        .timestamps()
        .iter()
        .find(|stamp| stamp.node() == archive)
        .unwrap();
    let check = timestamp::Check {
        xml: &xml,
        provider: &provider,
        context: &context,
    };
    let evidence = check
        .retain(prepared.bound(), stamp, 0, &operation, |_, _| {
            Ok::<_, ()>(false)
        })
        .unwrap()
        .unwrap();
    let input = Input::prepare(&xml, prepared.bound(), stamp, &memory).unwrap();
    let coverage = input.element_coverage(&memory).unwrap();
    material::with_values(&xml,&prepared,&operation,|query,values| {
        timestamp::with_tokens(&xml,&prepared,query,timestamp::TokenProfile::Etsi,|query,tokens| {
            let carried=tokens.material_in(query).unwrap();
            let work=query.execution();let access=Access::new(&xml,xml.snapshot(),&work);
            let index=material::index_with_tokens(&values,&carried,&access).unwrap();
            let mut own=0;
            for copy in index.certificate(&certificate,&access).unwrap() {
                let copy=copy.unwrap();
                if matches!(copy.source(),structured_ltv::material::ArtifactSource::TokenCertificate {..}) {
                    assert!(matches!(copy.placement(),material::Placement::TimestampToken {property,..} if property==archive));
                    own+=1;
                }
            }
            assert_eq!(own,1);
            assert!(matches!(index.archived(structured_ltv::material::ArtifactRef::Certificate(&certificate),&coverage,&evidence,&access).unwrap(),material::Archived::Uncovered));
            Ok::<_,()>(())
        }).unwrap();
        Ok::<_,()>(())
    }).unwrap();
    assert_eq!(provider.verified.get(), 1);
}

#[test]
fn archive_artifact_lookup_requires_a_covered_copy_and_exact_original_identity() {
    // A later copy is not material present before this archive. Adding an early
    // duplicate can satisfy availability without changing the required bytes;
    // unknown DER and a foreign source/current resource refusal stay distinct.
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    for order in [
        ArchiveOrder::Late,
        ArchiveOrder::Early,
        ArchiveOrder::BaseEarly,
    ] {
        let early = order != ArchiveOrder::Late;
        let (xml, archive, provider, certificate_bytes, root_bytes) =
            archive_material_fixture(order);
        let memory = funded();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let certificate =
            structured_pkix::Certificate::read(&parser, &certificate_bytes, 400).unwrap();
        let root = structured_pkix::Certificate::read(&parser, &root_bytes, 2000).unwrap();
        let parent = parser.read(&[], 400).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared =
            prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
        let stamp = prepared
            .timestamps()
            .iter()
            .find(|stamp| stamp.node() == archive)
            .unwrap();
        let actor = {
            let context = CheckContext {
                certificate: &certificate,
                certificate_parent: &parent,
                key: WorkingKey::standing(certificate.tbs().public_key()),
                requested: None,
                utc: &utc,
                reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
                window: None,
                policy_accuracy: None,
            };
            let check = timestamp::Check {
                xml: &xml,
                provider: &provider,
                context: &context,
            };
            check
                .retain_actor(prepared.bound(), stamp, 0, &operation, |_, _| {
                    Ok::<_, ()>(false)
                })
                .unwrap()
                .unwrap()
        };
        // The successful actor retains the actual certificate/key, not the
        // temporary Check/CheckContext used to perform this one verification.
        assert!(core::ptr::eq(actor.certificate(), &raw const certificate));
        assert_eq!(
            actor.key().key().as_bytes().as_ptr(),
            certificate.tbs().public_key().as_bytes().as_ptr()
        );
        let path = assert_timestamp_path(&actor, &root, &operation, &utc);
        let evidence = actor.into_verified();
        let input = Input::prepare(&xml, prepared.bound(), stamp, &memory).unwrap();
        let coverage = input.element_coverage(&memory).unwrap();
        let mut missing = certificate_bytes.clone();
        *missing.last_mut().unwrap() ^= 1;
        let missing = structured_pkix::Certificate::read(&parser, &missing, 1600).unwrap();
        material::with_values(&xml,&prepared,&operation,|query,view| {
            let work=query.execution();let access=Access::new(&xml,xml.snapshot(),&work);
            let index=material::index(&view,&access).unwrap();
            assert_crl_archive(&view,&index,&coverage,&evidence,&access,(&certificate,&root,order),&xml);
            assert_ocsp_archive(&view,&index,&coverage,&evidence,&access,(&certificate,&root,early,&path),&xml);
            let artifact=structured_ltv::material::ArtifactRef::Certificate(&certificate);
            let census=index.archived_path(&path,&coverage,&evidence,&access).unwrap();
            assert!(core::ptr::eq(census.path(), &raw const path));
            assert_eq!(census.archive(),evidence.token());
            assert_eq!(census.all_certificates_covered(),early);
            assert_eq!(census.entries().len(),2);
            assert_eq!(census.entries()[0].role,structured_ltv::material::PathCertificate::Anchor);
            if early {assert!(matches!(census.entries()[0].availability,material::Archived::Present(_)));}
            else {assert!(matches!(census.entries()[0].availability,material::Archived::Missing));}
            assert_eq!(census.entries()[1].role,structured_ltv::material::PathCertificate::Member(0));
            if early {assert!(matches!(census.entries()[1].availability,material::Archived::Present(_)));}
            else {assert!(matches!(census.entries()[1].availability,material::Archived::Uncovered));}
            let found=index.archived(artifact,&coverage,&evidence,&access).unwrap();
            if early {assert!(matches!(found,material::Archived::Present(copy) if matches!(copy.placement(),material::Placement::KeyInfo(_))));}
            else {assert!(matches!(found,material::Archived::Uncovered));}
            assert!(matches!(index.archived(structured_ltv::material::ArtifactRef::Certificate(&missing),&coverage,&evidence,&access).unwrap(),material::Archived::Missing));
            let denied=Memory::new(Arc::new(MemoryAccount::new(0,0)));
            let denied=Access::new(&xml,xml.snapshot(),&denied);
            assert!(matches!(index.archived(artifact,&coverage,&evidence,&denied),Err(structured_ltv::material::ArchiveError::Index(structured_ltv::material::IndexError::Scope(_) | structured_ltv::material::IndexError::Resource {..}))));
            let no_capacity=Memory::new(Arc::new(MemoryAccount::new(0,1<<24)));
            let no_capacity_access=Access::new(&xml,xml.snapshot(),&no_capacity);
            assert!(matches!(index.archived_path(&path,&coverage,&evidence,&no_capacity_access),Err(structured_ltv::material::ArchiveError::Index(structured_ltv::material::IndexError::Resource {..}))));
            assert_eq!(no_capacity.used(),0);
            // Retry is a NEW operation with the unchanged test limits. It must
            // not borrow the nearly exhausted fuel of the preceding independent
            // archive/status assertions; the retained index stays on its source.
            // Failed allocation cannot turn that retry into an empty census.
            let retry=funded();
            let retry_access=Access::new(&xml,xml.snapshot(),&retry);
            assert_eq!(index.archived_path(&path,&coverage,&evidence,&retry_access).unwrap().entries().len(),2);
            let foreign=Access::new(&xml,Snapshot {document:xml.document+1,generation:xml.generation.get()},&work);
            assert!(matches!(index.archived(artifact,&coverage,&evidence,&foreign),Err(structured_ltv::material::ArchiveError::Index(structured_ltv::material::IndexError::Foreign {..}))));
            Ok::<_,()>(())
        }).unwrap();
        assert_eq!(provider.verified.get(), 1);
    }
}

fn assert_crl_archive<'source, W: Work + 'source, C: Work>(
    view: &material::View<'source, usize, u8, u8>,
    index: &material::Index<'source, usize, u8, u8, W>,
    coverage: &structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    access: &Access<'_, Tree, W>,
    actor: (
        &'source structured_pkix::Certificate<'source>,
        &'source structured_pkix::Certificate<'source>,
        ArchiveOrder,
    ),
    xml: &Tree,
) {
    // Actual issuer signatures and common complete/delta semantics select the
    // original lists. Retaining only the updating delta must never suffice.
    use structured_ltv::material::status::{self, StatusPart, StatusSource};
    use structured_pkix::crl::{
        Authentication, Coverage, DeltaBinding, DeltaEvidence, Evaluation, SourceOrigin,
    };
    let (target, issuer, order) = actor;
    let early = order != ArchiveOrder::Late;
    let lists: Vec<_> = view
        .values()
        .iter()
        .filter_map(|value| match &value.value {
            material::Value::Crl(crl) => Some(crl),
            _ => None,
        })
        .collect();
    assert_eq!(lists.len(), 2);
    let verifier = timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let key = structured_pkix::path::WorkingKey::standing(issuer.tbs().public_key());
    let Authentication::Authenticated(base) = lists[0]
        .authenticate(issuer, key, &verifier, access.execution())
        .unwrap()
    else {
        panic!("actual base signature")
    };
    let Authentication::Authenticated(delta) = lists[1]
        .authenticate(issuer, key, &verifier, access.execution())
        .unwrap()
    else {
        panic!("actual delta signature")
    };
    let DeltaBinding::Bound(pair) = base.bind_delta(&delta, access.execution()).unwrap() else {
        panic!("same original issuer and scope")
    };
    let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let time = Evaluation {
        now: structured_pkix::temporal::Instant::new(1_767_225_600, 0)
            .unwrap()
            .into(),
        utc: &utc,
        execution: access.execution(),
        origin: SourceOrigin::Cached,
    };
    let DeltaEvidence::Facts(facts) = pair.evaluate(target, &time).unwrap() else {
        panic!("applicable actual pair")
    };
    let qualified = Coverage::new(facts.absence().unwrap(), access.execution()).unwrap();
    assert!(core::ptr::eq(qualified.target(), target));
    assert_eq!(qualified.evaluated_at(), time.now);
    assert!(qualified.reasons().is_complete());
    let path = assert_crl_target(&qualified, issuer, &utc, access.execution());
    let report = status::archived(
        StatusSource::Crl(&qualified),
        index,
        coverage,
        evidence,
        access,
    )
    .unwrap();
    assert_eq!(report.archive(), evidence.token());
    assert!(
        matches!(report.source(),StatusSource::Crl(original) if core::ptr::eq(original,&raw const qualified))
    );
    assert_eq!(report.entries().len(), 4);
    assert_eq!(report.entries()[0].part, StatusPart::CompleteCrl);
    assert_eq!(report.entries()[1].part, StatusPart::DeltaCrl);
    for entry in report.entries() {
        assert_eq!(entry.source, 0);
        let covered = if entry.part == StatusPart::DeltaCrl {
            order == ArchiveOrder::Early
        } else {
            early
        };
        assert_eq!(
            matches!(entry.availability, material::Archived::Present(_)),
            covered
        );
    }
    assert_eq!(report.all_artifacts_covered(), order == ArchiveOrder::Early);
    assert_crl_path_archive(
        &path,
        &qualified,
        (&utc, order, xml),
        index,
        coverage,
        evidence,
        access,
    );
    assert_crl_archive_refusal(&qualified, index, coverage, evidence, access, xml);
    assert_eq!(verifier.calls.get(), 2);
}

fn assert_crl_archive_refusal<W: Work, C: Work>(
    qualified: &structured_pkix::crl::Coverage<'_, '_>,
    index: &material::Index<'_, usize, u8, u8, W>,
    coverage: &structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    access: &Access<'_, Tree, W>,
    xml: &Tree,
) {
    // Refused report allocation must remain terminal and release partial data.
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 24)));
    let denied_access = Access::new(xml, access.snapshot(), &denied);
    assert!(matches!(
        structured_ltv::material::status::archived(
            structured_ltv::material::status::StatusSource::Crl(qualified),
            index,
            coverage,
            evidence,
            &denied_access
        ),
        Err(structured_ltv::material::ArchiveError::Index(
            structured_ltv::material::IndexError::Resource { .. }
        ))
    ));
    assert_eq!(denied.used(), 0);
}

fn assert_crl_path_archive<'source, W: Work, C: Work>(
    path: &structured_ltv::pki::CheckedPath<'source>,
    qualified: &structured_pkix::crl::Coverage<'_, 'source>,
    expected: (
        &structured_pkix::temporal::LeapTable<'_>,
        ArchiveOrder,
        &Tree,
    ),
    index: &material::Index<'_, usize, u8, u8, W>,
    coverage: &structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    access: &Access<'_, Tree, W>,
) {
    // A complete actor census must use one actual path and all original status
    // contributors. Late delta material cannot disappear in a combined report.
    use structured_ltv::pki::{CrlAuthorities, CrlAuthority, CrlCoverageBinding, MemberStatus};
    let authorities = [CrlAuthorities::Delta {
        base: CrlAuthority::Anchor,
        delta: CrlAuthority::Anchor,
    }];
    let CrlCoverageBinding::Bound(bound) = path
        .bind_crl_coverage(0, qualified, &authorities, expected.0, access.execution())
        .unwrap()
    else {
        panic!("same actual complete/delta authorities")
    };
    let entries = [MemberStatus::Crl(&bound)];
    let inputs = path
        .status_census(qualified.evaluated_at(), &entries, access.execution())
        .unwrap();
    xml_digest::assert_participant_status_closure(path, &inputs);
    let whole =
        structured_ltv::material::status::archived_path(&inputs, index, coverage, evidence, access)
            .unwrap();
    assert_unusable_crl_readings(path, qualified, expected, index, coverage, evidence, access);
    assert!(core::ptr::eq(whole.inputs(), &raw const inputs));
    assert!(core::ptr::eq(whole.certificates().path(), path));
    assert_eq!(whole.certificates().entries().len(), 2);
    assert_eq!(whole.statuses().len(), 1);
    assert_eq!(whole.statuses()[0].entries().len(), 4);
    assert_eq!(
        whole.all_artifacts_covered(),
        expected.1 == ArchiveOrder::Early
    );
    {
        // The authority closure and archive use the same actual path/status
        // inputs. Complete/delta artifacts remain four separate obligations.
        use structured_ltv::pki::{AuthorityNode, close_authorities};
        let nodes = [AuthorityNode {
            statuses: &inputs,
            responders: &[],
        }];
        let roots = [&inputs];
        let closed = close_authorities(&roots, &nodes, access.execution()).unwrap();
        let report = structured_ltv::material::status::archived_authorities(
            &closed, index, coverage, evidence, access,
        )
        .unwrap();
        assert!(core::ptr::eq(report.inputs(), &raw const closed));
        assert_eq!(report.paths().len(), 1);
        assert!(core::ptr::eq(report.paths()[0].inputs(), &raw const inputs));
        assert_eq!(report.paths()[0].statuses()[0].entries().len(), 4);
        assert_eq!(
            report.all_artifacts_covered(),
            expected.1 == ArchiveOrder::Early
        );
    }
    let before = access.execution().memory().used();
    let probe = index
        .archived_path(path, coverage, evidence, access)
        .unwrap();
    let certificate_capacity = access.execution().memory().used() - before;
    drop(probe);
    assert_eq!(access.execution().memory().used(), before);
    // Admit exactly the certificate report, then refuse the status catalogue.
    // The parent report's capacity must be returned with no successful prefix.
    let limited = Memory::new(Arc::new(MemoryAccount::new(certificate_capacity, 1 << 24)));
    let limited_access = Access::new(expected.2, access.snapshot(), &limited);
    assert!(matches!(
        structured_ltv::material::status::archived_path(
            &inputs,
            index,
            coverage,
            evidence,
            &limited_access
        ),
        Err(structured_ltv::material::ArchiveError::Index(
            structured_ltv::material::IndexError::Resource { .. }
        ))
    ));
    assert_eq!(limited.used(), 0);
}

fn assert_crl_target<'a, W: Work + 'a>(
    coverage: &structured_pkix::crl::Coverage<'a, 'a>,
    issuer: &'a structured_pkix::Certificate<'a>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    work: &W,
) -> structured_ltv::pki::CheckedPath<'a> {
    // Shared absence already checked signature/scope/entries/time. Association
    // must additionally bind the actual target and each complete/delta signer
    // to this checked path's anchor, without checking CRL signatures again.
    use structured_ltv::pki::{
        self, CrlAuthorities, CrlAuthority, CrlBinding, CrlBindingError, CrlBindingFailure,
        PathOutcome,
    };
    use structured_pkix::path::{Anchor, Interval, ValidationBounds, ValidationContext};
    let verifier = timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let context = ValidationContext {
        execution: work,
        interval: Interval::at_instant(coverage.evaluated_at().start()),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(path) = pki::check_path(
        &[coverage.target()],
        Anchor::from_certificate(issuer),
        &context,
    )
    .unwrap() else {
        panic!("actual target chain")
    };
    let evidence = &coverage.sources()[0];
    let authorities = || CrlAuthorities::Delta {
        base: CrlAuthority::Anchor,
        delta: CrlAuthority::Anchor,
    };
    let CrlBinding::Bound(bound) = path
        .bind_crl(0, evidence, authorities(), utc, work)
        .unwrap()
    else {
        panic!("both actual original lists are signed by the selected anchor")
    };
    assert!(core::ptr::eq(bound.path(), &raw const path));
    assert_eq!(bound.member(), 0);
    assert!(core::ptr::eq(bound.evidence().target(), coverage.target()));
    assert!(matches!(bound.authorities(), CrlAuthorities::Delta { .. }));
    assert!(matches!(
        path.bind_crl(1, evidence, authorities(), utc, work),
        Err(CrlBindingError::MemberIndex { index: 1 })
    ));
    assert!(matches!(
        path.bind_crl(
            0,
            evidence,
            CrlAuthorities::Complete(CrlAuthority::Anchor),
            utc,
            work
        ),
        Err(CrlBindingError::SourceKind)
    ));
    assert!(matches!(
        path.bind_crl(
            0,
            evidence,
            CrlAuthorities::Delta {
                base: CrlAuthority::Anchor,
                delta: CrlAuthority::Path(&path)
            },
            utc,
            work
        )
        .unwrap(),
        CrlBinding::Rejected(CrlBindingFailure::Signer)
    ));
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(matches!(
        path.bind_crl(0, evidence, authorities(), utc, &denied),
        Err(CrlBindingError::Resource(_))
    ));
    assert_eq!(verifier.calls.get(), 1);
    path
}

#[test]
fn crl_authority_paths_require_same_anchor_and_full_evaluation_reading() {
    // A valid certificate path and a valid CRL signature under its actual key
    // are insufficient if that path uses a different anchor. Correct same-root
    // authorities must also cover the original status-evaluation reading.
    use structured_ltv::pki::{
        self, CrlAuthorities, CrlAuthority, CrlBinding, CrlBindingFailure, PathOutcome,
    };
    use structured_pkix::{
        Certificate, crl,
        path::{Anchor, Interval, ValidationBounds, ValidationContext},
        temporal::{Instant, LeapTable},
    };
    #[cfg(miri)]
    eprintln!("CRL association: generating and verifying original target path");
    xml_digest::with_checked_path(|target_path, _, original_root, work| {
        #[cfg(miri)]
        eprintln!("CRL association: target path accepted");
        let target = target_path.members()[0].certificate();
        let bytes = timestamp_oracle::complete_crl_for(5);
        let parser = structured_asn1::Parser::der(work.clone());
        let list = crl::CertificateList::read(&parser, &bytes, 2000).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let now = Instant::new(1_767_225_600, 0).unwrap();
        for root_seed in [2, 4] {
            #[cfg(miri)]
            eprintln!("CRL association: creating authority certified by root{root_seed}");
            let (signer_bytes, anchor_bytes) =
                timestamp_oracle::crl_authority_with_root(root_seed, original_root);
            let signer = Certificate::read(&parser, &signer_bytes, 3000).unwrap();
            let anchor = Certificate::read(&parser, &anchor_bytes, 4000).unwrap();
            let verifier = timestamp_oracle::PathOracle {
                calls: Cell::new(0),
            };
            let key = structured_pkix::path::WorkingKey::standing(signer.tbs().public_key());
            let crl::Authentication::Authenticated(source) =
                list.authenticate(&signer, key, &verifier, work).unwrap()
            else {
                panic!("real CRL signature")
            };
            let time = crl::Evaluation {
                now: now.into(),
                utc: &utc,
                execution: work,
                origin: crl::SourceOrigin::Cached,
            };
            let crl::CompleteEvidence::Facts(facts) = source.evaluate(target, &time).unwrap()
            else {
                panic!("actual complete CRL scope")
            };
            let evidence = facts.absence().unwrap();
            let context = ValidationContext {
                execution: work,
                interval: Interval::at_instant(now),
                policy: structured_pkix::path::Policy::default(),
                bounds: ValidationBounds::default(),
                verifier: &verifier,
                watch: &(),
                recognizer: &(),
            };
            let signer_path =
                match pki::check_path(&[&signer], Anchor::from_certificate(&anchor), &context)
                    .unwrap()
                {
                    PathOutcome::Accepted(path) => path,
                    PathOutcome::Rejected(reason) => {
                        panic!("actual CRL signer path root{root_seed}: {reason:?}")
                    }
                    PathOutcome::Incomplete(reason) => panic!("actual CRL signer path: {reason:?}"),
                };
            let result = target_path
                .bind_crl(
                    0,
                    &evidence,
                    CrlAuthorities::Complete(CrlAuthority::Path(&signer_path)),
                    &utc,
                    work,
                )
                .unwrap();
            if root_seed == 4 {
                assert!(matches!(
                    result,
                    CrlBinding::Rejected(CrlBindingFailure::Anchor)
                ));
                assert_eq!(verifier.calls.get(), 2);
                continue;
            }
            let CrlBinding::Bound(bound) = result else {
                panic!("same-anchor original authority")
            };
            assert!(core::ptr::eq(bound.evidence(), &raw const evidence));
            let signer_status = crl_signer_status(&source, &signer, &time);
            assert_crl_authority_closure(
                target_path,
                &signer_path,
                &evidence,
                &signer_status,
                &utc,
                work,
            );
            assert_crl_time_reading(target_path, &evidence, &signer_path, &utc, work);
            assert_eq!(verifier.calls.get(), 2);
        }
    });
}

fn crl_signer_status<'r, 'a, W: Work>(
    source: &structured_pkix::crl::Authenticated<'r, 'a>,
    signer: &'r structured_pkix::Certificate<'a>,
    time: &structured_pkix::crl::Evaluation<'_, W>,
) -> structured_pkix::crl::AbsenceEvidence<'r, 'a> {
    // Reuse the already authenticated original list to evaluate its actual
    // signing certificate; there is no second parse or signature verification.
    let structured_pkix::crl::CompleteEvidence::Facts(facts) =
        source.evaluate(signer, time).unwrap()
    else {
        panic!("actual signer status scope")
    };
    facts.absence().unwrap()
}

fn assert_crl_authority_closure<'a, W: Work>(
    target: &structured_ltv::pki::CheckedPath<'a>,
    signer: &structured_ltv::pki::CheckedPath<'a>,
    target_status: &structured_pkix::crl::AbsenceEvidence<'_, 'a>,
    signer_status: &structured_pkix::crl::AbsenceEvidence<'_, 'a>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    work: &W,
) {
    // Both actual certificates use the same authenticated CRL. The signer
    // path's self-dependency must terminate by receipt identity, not recurse
    // or replay verification; omitting that signer census is not completion.
    use structured_ltv::pki::{
        AuthorityClosureError, AuthorityNode, AuthorityOrigin, CrlAuthorities, CrlAuthority,
        CrlCoverageBinding, MemberStatus, close_authorities,
    };
    use structured_pkix::crl::Coverage;
    let target_sources = Coverage::new(*target_status, work).unwrap();
    let signer_sources = Coverage::new(*signer_status, work).unwrap();
    let authorities = [CrlAuthorities::Complete(CrlAuthority::Path(signer))];
    let CrlCoverageBinding::Bound(target_bound) = target
        .bind_crl_coverage(0, &target_sources, &authorities, utc, work)
        .unwrap()
    else {
        panic!("actual target CRL authority")
    };
    let CrlCoverageBinding::Bound(signer_bound) = signer
        .bind_crl_coverage(0, &signer_sources, &authorities, utc, work)
        .unwrap()
    else {
        panic!("actual signer CRL authority")
    };
    let target_entries = [MemberStatus::Crl(&target_bound)];
    let signer_entries = [MemberStatus::Crl(&signer_bound)];
    let parent = target
        .status_census(target_sources.evaluated_at(), &target_entries, work)
        .unwrap();
    let child = signer
        .status_census(signer_sources.evaluated_at(), &signer_entries, work)
        .unwrap();
    let nodes = [
        AuthorityNode {
            statuses: &parent,
            responders: &[],
        },
        AuthorityNode {
            statuses: &child,
            responders: &[],
        },
    ];
    xml_digest::assert_participant_nodes(target, &parent, &nodes);
    let roots = [&parent];
    let before = work.memory().used();
    {
        let closure = close_authorities(&roots, &nodes, work).unwrap();
        assert_eq!(closure.nodes().len(), 2);
        assert!(core::ptr::eq(closure.nodes()[1].statuses.path(), signer));
    }
    assert_eq!(work.memory().used(), before);
    assert!(matches!(
        close_authorities(&roots, &nodes[..1], work),
        Err(AuthorityClosureError::MissingPath {
            origin: AuthorityOrigin::Crl {
                node: 0,
                member: 0,
                source: 0,
                delta: false
            }
        })
    ));
    assert_eq!(work.memory().used(), before);
}

fn assert_crl_time_reading<'a, W: Work + 'a>(
    target_path: &structured_ltv::pki::CheckedPath<'a>,
    evidence: &structured_pkix::crl::AbsenceEvidence<'_, 'a>,
    signer_path: &structured_ltv::pki::CheckedPath<'a>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    work: &W,
) {
    // Missing UTC coverage is a processing uncertainty; a later valid path is
    // a completed interval mismatch. Neither can assert authority at the
    // original status-reading instant, and the original CRL is not reverified.
    use structured_ltv::pki::{
        self, CrlAuthorities, CrlAuthority, CrlBinding, CrlBindingError, CrlBindingFailure,
        PathOutcome,
    };
    use structured_pkix::{
        path::{Interval, ValidationBounds, ValidationContext},
        temporal::LeapTable,
    };
    assert_crl_foreign_status(target_path, evidence, signer_path, utc, work);
    let now = evidence.evaluated_at().start();
    let unknown = LeapTable::new(now.seconds() + 1, 2_000_000_000, &[]).unwrap();
    assert!(matches!(
        target_path.bind_crl(
            0,
            evidence,
            CrlAuthorities::Complete(CrlAuthority::Path(signer_path)),
            &unknown,
            work
        ),
        Err(CrlBindingError::Time(_))
    ));
    let verifier = timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let later = ValidationContext {
        execution: work,
        interval: Interval::at(now.seconds() + 1),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let signer = signer_path.members().last().unwrap().certificate();
    let PathOutcome::Accepted(later_path) =
        pki::check_path(&[signer], signer_path.anchor(), &later).unwrap()
    else {
        panic!("same signer valid a second later")
    };
    assert!(matches!(
        target_path
            .bind_crl(
                0,
                evidence,
                CrlAuthorities::Complete(CrlAuthority::Path(&later_path)),
                utc,
                work
            )
            .unwrap(),
        CrlBinding::Rejected(CrlBindingFailure::Interval)
    ));
    assert_eq!(verifier.calls.get(), 1);
}

fn assert_crl_foreign_status<'a, W: Work>(
    target_path: &structured_ltv::pki::CheckedPath<'a>,
    evidence: &structured_pkix::crl::AbsenceEvidence<'_, 'a>,
    signer_path: &structured_ltv::pki::CheckedPath<'a>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    work: &W,
) {
    // Equal member counts cannot relabel another actor's original status.
    // Reuse the already authenticated source and checked authority path.
    use structured_ltv::pki::{
        CrlAuthorities, CrlAuthority, CrlCoverageBinding, MemberStatus, StatusCensusError,
    };
    let coverage = structured_pkix::crl::Coverage::new(*evidence, work).unwrap();
    let authorities = [CrlAuthorities::Complete(CrlAuthority::Path(signer_path))];
    let CrlCoverageBinding::Bound(bound) = target_path
        .bind_crl_coverage(0, &coverage, &authorities, utc, work)
        .unwrap()
    else {
        panic!("same actual original target and signer")
    };
    let entries = [MemberStatus::Crl(&bound)];
    assert!(matches!(
        signer_path.status_census(coverage.evaluated_at(), &entries, work),
        Err(StatusCensusError::Member { index: 0 })
    ));
}

fn assert_unusable_crl_readings<'source, W: Work, C: Work>(
    path: &structured_ltv::pki::CheckedPath<'source>,
    qualified: &structured_pkix::crl::Coverage<'_, 'source>,
    expected: (
        &structured_pkix::temporal::LeapTable<'_>,
        ArchiveOrder,
        &Tree,
    ),
    index: &material::Index<'_, usize, u8, u8, W>,
    coverage: &structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    access: &Access<'_, Tree, W>,
) {
    // Actual stale processing facts cannot qualify absence, but still retain
    // their exact target/time, original whole lists and signing authorities.
    use structured_ltv::pki::CrlReading;
    use structured_pkix::{crl, temporal::Instant};
    let crl::EvidenceSource::Delta { base, delta } = qualified.sources()[0].source() else {
        panic!("original pair")
    };
    let time = crl::Evaluation {
        now: Instant::new(1_925_000_000, 0).unwrap().into(),
        utc: expected.0,
        execution: access.execution(),
        origin: crl::SourceOrigin::Cached,
    };
    let crl::CompleteEvidence::Facts(complete) = base.evaluate(qualified.target(), &time).unwrap()
    else {
        panic!("same applicable original base")
    };
    assert_eq!(complete.freshness(), crl::Freshness::Stale);
    assert!(complete.absence().is_none());
    assert_crl_reading_archive(
        path,
        CrlReading::Complete(&complete),
        (expected.0, expected.1 != ArchiveOrder::Late, 2),
        index,
        coverage,
        evidence,
        access,
    );
    let crl::DeltaBinding::Bound(pair) = base.bind_delta(&delta, access.execution()).unwrap()
    else {
        panic!("same actual base/delta pair")
    };
    let crl::DeltaEvidence::Facts(combined) = pair.evaluate(qualified.target(), &time).unwrap()
    else {
        panic!("same applicable original pair")
    };
    assert_eq!(combined.delta_freshness(), crl::Freshness::Stale);
    assert!(combined.absence().is_none());
    assert_crl_reading_archive(
        path,
        CrlReading::Delta(&combined),
        (expected.0, expected.1 == ArchiveOrder::Early, 4),
        index,
        coverage,
        evidence,
        access,
    );
    assert_revoked_crl_reading_archive(
        path, qualified, expected.0, index, coverage, evidence, access,
    );
}

fn assert_revoked_crl_reading_archive<'source, W: Work, C: Work>(
    path: &structured_ltv::pki::CheckedPath<'source>,
    qualified: &structured_pkix::crl::Coverage<'_, 'source>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    index: &material::Index<'_, usize, u8, u8, W>,
    coverage: &structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    access: &Access<'_, Tree, W>,
) {
    // A current CRL with an actual revoked entry is not absence. Its missing
    // original encoding cannot be substituted by the different carried CRL
    // having the same issuer/update fields but no revoked serial.
    use structured_pkix::crl;
    let crl::EvidenceSource::Delta { base, .. } = qualified.sources()[0].source() else {
        panic!("original issuer")
    };
    let work = access.execution();
    let bytes = timestamp_oracle::revoking_crl_for(2, 1);
    let parser = structured_asn1::Parser::der(work.memory().clone());
    let list = crl::CertificateList::read(&parser, &bytes, 12000).unwrap();
    let verifier = timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let crl::Authentication::Authenticated(source) = list
        .authenticate(base.issuer(), base.key(), &verifier, work)
        .unwrap()
    else {
        panic!("actual revoked-list signature")
    };
    let time = crl::Evaluation {
        now: qualified.evaluated_at(),
        utc,
        execution: work,
        origin: crl::SourceOrigin::Cached,
    };
    let crl::CompleteEvidence::Facts(facts) = source.evaluate(qualified.target(), &time).unwrap()
    else {
        panic!("same actual applicable target")
    };
    assert_eq!(facts.freshness(), crl::Freshness::Current);
    assert!(matches!(facts.entry(), crl::EntryLookup::Found(_)));
    assert!(facts.absence().is_none());
    assert_crl_reading_archive(
        path,
        structured_ltv::pki::CrlReading::Complete(&facts),
        (utc, false, 2),
        index,
        coverage,
        evidence,
        access,
    );
    let crl::CompleteEvidence::Facts(other) = source.evaluate(base.issuer(), &time).unwrap() else {
        panic!("same-named original root target")
    };
    assert!(matches!(
        path.bind_crl_reading(
            0,
            structured_ltv::pki::CrlReading::Complete(&other),
            structured_ltv::pki::CrlAuthorities::Complete(
                structured_ltv::pki::CrlAuthority::Anchor
            ),
            utc,
            work
        )
        .unwrap(),
        structured_ltv::pki::CrlReadingBinding::Rejected(
            structured_ltv::pki::CrlBindingFailure::Target
        )
    ));
    assert_eq!(verifier.calls.get(), 1);
}

fn assert_crl_reading_archive<'source, W: Work, C: Work>(
    path: &structured_ltv::pki::CheckedPath<'source>,
    reading: structured_ltv::pki::CrlReading<'_, '_, 'source>,
    expected: (&structured_pkix::temporal::LeapTable<'_>, bool, usize),
    index: &material::Index<'_, usize, u8, u8, W>,
    coverage: &structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    access: &Access<'_, Tree, W>,
) {
    // Archive availability and negative status facts are independent. The
    // source/authority binder is the same for complete and paired readings.
    use structured_ltv::pki::{
        AuthorityNode, CrlAuthorities, CrlAuthority, CrlReading, CrlReadingBinding, MemberStatus,
        close_authorities,
    };
    let authorities = match reading {
        CrlReading::Complete(_) => CrlAuthorities::Complete(CrlAuthority::Anchor),
        CrlReading::Delta(_) => CrlAuthorities::Delta {
            base: CrlAuthority::Anchor,
            delta: CrlAuthority::Anchor,
        },
    };
    let work = access.execution();
    let wrong_kind = match reading {
        CrlReading::Complete(_) => CrlAuthorities::Delta {
            base: CrlAuthority::Anchor,
            delta: CrlAuthority::Anchor,
        },
        CrlReading::Delta(_) => CrlAuthorities::Complete(CrlAuthority::Anchor),
    };
    assert!(matches!(
        path.bind_crl_reading(0, reading, wrong_kind, expected.0, work),
        Err(structured_ltv::pki::CrlBindingError::SourceKind)
    ));
    assert!(matches!(
        path.bind_crl_reading(1, reading, authorities, expected.0, work),
        Err(structured_ltv::pki::CrlBindingError::MemberIndex { index: 1 })
    ));
    let CrlReadingBinding::Bound(bound) = path
        .bind_crl_reading(0, reading, authorities, expected.0, work)
        .unwrap()
    else {
        panic!("same actual negative result and authorities")
    };
    assert!(core::ptr::eq(bound.reading().target(), reading.target()));
    let entries = [MemberStatus::CrlReading(&bound)];
    let inputs = path
        .status_census(reading.evaluated_at(), &entries, work)
        .unwrap();
    let nodes = [AuthorityNode {
        statuses: &inputs,
        responders: &[],
    }];
    let roots = [&inputs];
    let closed = close_authorities(&roots, &nodes, work).unwrap();
    let report = structured_ltv::material::status::archived_authorities(
        &closed, index, coverage, evidence, access,
    )
    .unwrap();
    assert_eq!(report.all_artifacts_covered(), expected.1);
    assert_eq!(report.paths()[0].statuses()[0].entries().len(), expected.2);
    assert!(matches!(
        report.paths()[0].statuses()[0].source(),
        structured_ltv::material::status::StatusSource::CrlReading(_)
    ));
    assert_eq!(
        report.paths()[0].statuses()[0].source().evaluated_at(),
        reading.evaluated_at()
    );
    let empty = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(matches!(
        path.bind_crl_reading(0, reading, authorities, expected.0, &empty),
        Err(structured_ltv::pki::CrlBindingError::Resource(_))
    ));
}

fn assert_ocsp_archive<'source, W: Work + 'source, C: Work>(
    view: &material::View<'source, usize, u8, u8>,
    index: &material::Index<'source, usize, u8, u8, W>,
    coverage: &structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    access: &Access<'_, Tree, W>,
    actor: (
        &'source structured_pkix::Certificate<'source>,
        &'source structured_pkix::Certificate<'source>,
        bool,
        &'source structured_ltv::pki::CheckedPath<'source>,
    ),
    xml: &Tree,
) {
    // The actual whole response, signer binding, issuer scope and CertID
    // matching run through the common kernel; the archive needs the envelope.
    use structured_ltv::material::status::{self, StatusPart, StatusSource};
    // This independent OCSP query keeps the same per-operation limits instead
    // of spending fuel left by the preceding complete/delta CRL assertions.
    let operation = funded();
    let access = &Access::new(xml, access.snapshot(), &operation);
    let (target, issuer, early, path) = actor;
    assert_eq!(view.basic_responses().len(), 1);
    let response = view.basic_responses()[0].response();
    let qualified = checked_ocsp(response, target, issuer, access.execution(), false);
    assert_ocsp_target(path, &qualified, access.execution());
    let configured = checked_ocsp(response, target, issuer, access.execution(), true);
    assert_ocsp_target(path, &configured, access.execution());
    assert!(configured.evidence().source().issuing_key().is_none());
    if early {
        assert_no_check_archive(path, index, coverage, evidence, access);
    }
    let report = status::archived(
        StatusSource::Ocsp(&qualified),
        index,
        coverage,
        evidence,
        access,
    )
    .unwrap();
    assert!(core::ptr::eq(report.source().target(), target));
    assert_eq!(report.entries().len(), 2);
    assert_eq!(report.entries()[0].part, StatusPart::OcspResponse);
    assert_eq!(report.entries()[1].part, StatusPart::SigningCertificate);
    assert_eq!(report.all_artifacts_covered(), early);
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 24)));
    let denied_access = Access::new(xml, access.snapshot(), &denied);
    assert!(matches!(
        status::archived(
            StatusSource::Ocsp(&qualified),
            index,
            coverage,
            evidence,
            &denied_access
        ),
        Err(structured_ltv::material::ArchiveError::Index(
            structured_ltv::material::IndexError::Resource { .. }
        ))
    ));
    assert_eq!(denied.used(), 0);
    for entry in report.entries() {
        assert_eq!(
            matches!(entry.availability, material::Archived::Present(_)),
            early
        );
    }
}

fn assert_no_check_archive<W: Work, C: Work, Q: Work>(
    target: &structured_ltv::pki::CheckedPath<'_>,
    index: &material::Index<'_, usize, u8, u8, W>,
    coverage: &structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    access: &Access<'_, Tree, Q>,
) {
    // An actually exempt responder needs its original certificate in archive
    // material, but no fabricated status. Here that certificate is absent from
    // XML: skipping its revocation lookup must not make availability positive.
    use structured_ltv::pki::{
        self, AuthorityNode, MemberStatus, OcspBinding, PathOutcome, ResponderBinding,
        close_authorities,
    };
    use structured_pkix::{
        Certificate, ocsp,
        path::{Anchor, Interval, ValidationBounds, ValidationContext, WorkingKey},
        temporal::{Instant, LeapTable},
    };
    let work = access.execution();
    let parser = structured_asn1::Parser::der(work.memory().clone());
    let (bytes, root_bytes) = timestamp_oracle::ocsp_delegate_no_check(2);
    let delegate = Certificate::read(&parser, &bytes, 9000).unwrap();
    let root = Certificate::read(&parser, &root_bytes, 10000).unwrap();
    let verifier = timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let now = Instant::new(1_767_225_600, 0).unwrap();
    let context = ValidationContext {
        execution: work,
        interval: Interval::at_instant(now),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let ocsp::Delegation::Accepted(local) = ocsp::check_delegate(
        &delegate,
        &root,
        WorkingKey::standing(root.tbs().public_key()),
        &context,
    )
    .unwrap() else {
        panic!("actual noCheck delegation")
    };
    let bytes = timestamp_oracle::ocsp_response_signed(2, 5);
    let query = parser.read(&[], 11000).unwrap();
    let ocsp::Response::Successful(envelope) =
        ocsp::Response::read(&parser, &bytes, 11000).unwrap()
    else {
        panic!("actual whole response")
    };
    let response = envelope.basic_in(&query).unwrap().unwrap();
    let scoped = authenticate_delegate(&response, &local, &verifier, work);
    let request = ocsp::Request {
        target: target.members()[0].certificate(),
        nonce: None,
        intended_signer: Some(&delegate),
    };
    let time = ocsp::Evaluation {
        now: now.into(),
        utc: &utc,
        execution: work,
    };
    let read = scoped
        .evaluate_with_target(&request, &time, &verifier)
        .unwrap();
    let facts = read.evidence().unwrap();
    let OcspBinding::Bound(bound) = target.bind_ocsp(0, &facts, work).unwrap() else {
        panic!("original target")
    };
    let PathOutcome::Accepted(path) =
        pki::check_path(&[&delegate], Anchor::from_certificate(&root), &context).unwrap()
    else {
        panic!("actual full responder path")
    };
    let ResponderBinding::Bound(responder) = bound.bind_responder_path(&path, &utc, work).unwrap()
    else {
        panic!("original root/time")
    };
    let entries = [MemberStatus::ResponderNoCheck(&responder)];
    let inputs = path
        .status_census(facts.evaluated_at(), &entries, work)
        .unwrap();
    let nodes = [AuthorityNode {
        statuses: &inputs,
        responders: &[],
    }];
    let roots = [&inputs];
    let closed = close_authorities(&roots, &nodes, work).unwrap();
    let before = verifier.calls.get();
    let material = structured_ltv::material::status::archived_authorities(
        &closed, index, coverage, evidence, access,
    )
    .unwrap();
    assert!(!material.all_artifacts_covered());
    assert_eq!(material.paths().len(), 1);
    assert!(material.paths()[0].statuses().is_empty());
    assert_eq!(material.paths()[0].certificates().entries().len(), 2);
    assert!(matches!(
        material.paths()[0].certificates().entries()[1].availability,
        material::Archived::Missing
    ));
    assert_eq!(verifier.calls.get(), before);
}

fn checked_ocsp<'a, W: Work + 'a>(
    response: &'a structured_pkix::ocsp::BasicResponse<'a>,
    target: &'a structured_pkix::Certificate<'a>,
    issuer: &'a structured_pkix::Certificate<'a>,
    execution: &W,
    configured: bool,
) -> structured_pkix::ocsp::BoundEvidence<'a, 'a, 'a, 'a> {
    // The result must survive this temporary provider/request/UTC/context.
    use structured_pkix::ocsp::{self, AuthorityBinding, SignatureAuthentication};
    let verifier = timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let key = structured_pkix::path::WorkingKey::standing(issuer.tbs().public_key());
    let SignatureAuthentication::Signed(signed) = response
        .authenticate_signature(issuer, key, &verifier, &verifier, execution)
        .unwrap()
    else {
        panic!("actual OCSP issuer signature")
    };
    let scoped = if configured {
        signed.trust_for_issuer(issuer)
    } else {
        let AuthorityBinding::Bound(scoped) = signed.bind_issuer(issuer, key, execution).unwrap()
        else {
            panic!("actual target issuer")
        };
        scoped
    };
    let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let time = ocsp::Evaluation {
        now: structured_pkix::temporal::Instant::new(1_767_225_600, 0)
            .unwrap()
            .into(),
        utc: &utc,
        execution,
    };
    let request = ocsp::Request {
        target,
        nonce: None,
        intended_signer: Some(issuer),
    };
    let reading = scoped
        .evaluate_with_target(&request, &time, &verifier)
        .unwrap();
    let qualified = reading.evidence().expect("actual requested certificate");
    assert!(core::ptr::eq(qualified.target(), target));
    assert_eq!(
        qualified.evidence().assertion().status(),
        ocsp::Status::Good
    );
    assert_eq!(verifier.calls.get(), 1);
    qualified
}

#[test]
fn delegated_ocsp_requires_original_root_signer_and_full_status_reading() {
    // A real locally delegated OCSP signer is not a full ancestor-path proof.
    // Bind only the exact original signer under the target root at the original
    // evaluation Reading; preserve unresolved revocation and reject relabeling.
    assert_delegated_ocsp_path(false);
    assert_delegated_ocsp_path(true);
}

fn assert_delegated_ocsp_path(no_check: bool) {
    // Both actual extension branches preserve the common revocation fact.
    // noCheck never exempts the responder's original-root path/time binding.
    use structured_ltv::pki::{self, OcspBinding, PathOutcome, ResponderBinding, ResponderFailure};
    use structured_pkix::{
        Certificate, ocsp,
        path::{Anchor, Interval, ValidationBounds, ValidationContext, WorkingKey},
        temporal::{Instant, LeapTable},
    };
    xml_digest::with_checked_path(|target_path, _, _, work| {
        let parser = structured_asn1::Parser::der(work.clone());
        let (delegate_bytes, root_bytes) = if no_check {
            timestamp_oracle::ocsp_delegate_no_check(2)
        } else {
            timestamp_oracle::ocsp_delegate(2)
        };
        let delegate = Certificate::read(&parser, &delegate_bytes, 3000).unwrap();
        let root = Certificate::read(&parser, &root_bytes, 4000).unwrap();
        let verifier = timestamp_oracle::PathOracle {
            calls: Cell::new(0),
        };
        let now = Instant::new(1_767_225_600, 0).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = ValidationContext {
            execution: work,
            interval: Interval::at_instant(now),
            policy: structured_pkix::path::Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &verifier,
            watch: &(),
            recognizer: &(),
        };
        let ocsp::Delegation::Accepted(local) = ocsp::check_delegate(
            &delegate,
            &root,
            WorkingKey::standing(root.tbs().public_key()),
            &context,
        )
        .unwrap() else {
            panic!("real direct OCSP delegation")
        };
        let bytes = timestamp_oracle::ocsp_response_signed(2, 5);
        let ocsp::Response::Successful(envelope) =
            ocsp::Response::read(&parser, &bytes, 5000).unwrap()
        else {
            panic!("original response envelope")
        };
        let query = parser.read(&[], 5000).unwrap();
        let response = envelope.basic_in(&query).unwrap().unwrap();
        let scoped = authenticate_delegate(&response, &local, &verifier, work);
        let request = ocsp::Request {
            target: target_path.members()[0].certificate(),
            nonce: None,
            intended_signer: Some(&delegate),
        };
        let time = ocsp::Evaluation {
            now: now.into(),
            utc: &utc,
            execution: work,
        };
        let reading = scoped
            .evaluate_with_target(&request, &time, &verifier)
            .unwrap();
        let facts = reading.evidence().unwrap();
        let OcspBinding::Bound(target) = target_path.bind_ocsp(0, &facts, work).unwrap() else {
            panic!("actual target and issuing key")
        };
        let PathOutcome::Accepted(path) =
            pki::check_path(&[&delegate], Anchor::from_certificate(&root), &context).unwrap()
        else {
            panic!("full responder path")
        };
        let before = verifier.calls.get();
        let ResponderBinding::Bound(bound) = target.bind_responder_path(&path, &utc, work).unwrap()
        else {
            panic!("same original root/signer/time")
        };
        assert!(core::ptr::eq(bound.path(), &raw const path));
        assert!(core::ptr::eq(bound.target(), &raw const target));
        assert_responder_census(&bound, work);
        assert_eq!(
            bound.revocation(),
            if no_check {
                ocsp::ResponderRevocation::NoCheck
            } else {
                ocsp::ResponderRevocation::Unresolved
            }
        );
        assert!(matches!(
            target.bind_responder_path(target_path, &utc, work).unwrap(),
            ResponderBinding::Rejected(ResponderFailure::Signer)
        ));
        assert_responder_boundaries(&target, &path, &utc, work, &verifier);
        assert_eq!(verifier.calls.get(), before + 2);
        assert_responder_fine_reading(target_path, &path, &scoped, &utc, work, &verifier);
    });
}

fn authenticate_delegate<'a, W: Work>(
    response: &'a structured_pkix::ocsp::BasicResponse<'a>,
    local: &structured_pkix::ocsp::DelegateFacts<'a>,
    verifier: &timestamp_oracle::PathOracle,
    work: &W,
) -> structured_pkix::ocsp::ScopedResponse<'a, 'a> {
    // Preserve the same actual signer/key and common local-delegation receipt.
    use structured_pkix::ocsp::{AuthorityBinding, SignatureAuthentication};
    let SignatureAuthentication::Signed(signed) = response
        .authenticate_signature(local.responder(), local.key(), verifier, verifier, work)
        .unwrap()
    else {
        panic!("actual delegated signature")
    };
    let AuthorityBinding::Bound(scoped) = signed.bind_delegate(*local, work).unwrap() else {
        panic!("exact original signer")
    };
    scoped
}

fn assert_responder_census<W: Work>(
    bound: &structured_ltv::pki::ResponderPath<'_, '_, '_, '_>,
    work: &W,
) {
    // Only the actual shared noCheck fact exempts the exact responder target.
    // An unresolved delegate, missing entry or other actor is not a complete
    // status census; noCheck never turns into a caller-written Good flag.
    use structured_ltv::pki::{MemberStatus, StatusCensusError};
    use structured_pkix::ocsp::ResponderRevocation;
    let entries = [MemberStatus::ResponderNoCheck(bound)];
    let at = bound.target().evidence().evaluated_at();
    let result = bound.path().status_census(at, &entries, work);
    if bound.revocation() == ResponderRevocation::Unresolved {
        assert!(matches!(
            result,
            Err(StatusCensusError::Exemption { index: 0 })
        ));
        return;
    }
    let census = result.unwrap();
    assert!(core::ptr::eq(census.path(), bound.path()));
    assert!(matches!(
        census.entries(),
        [MemberStatus::ResponderNoCheck(_)]
    ));
    assert_authority_closure(bound, &census, work);
    assert!(matches!(
        bound.target().path().status_census(at, &entries, work),
        Err(StatusCensusError::Member { index: 0 })
    ));
    assert!(matches!(
        bound.path().status_census(at, &[], work),
        Err(StatusCensusError::Count)
    ));
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(matches!(
        bound.path().status_census(at, &entries, &denied),
        Err(StatusCensusError::Resource(_))
    ));
}

fn assert_authority_closure<W: Work>(
    responder: &structured_ltv::pki::ResponderPath<'_, '_, '_, '_>,
    child: &structured_ltv::pki::PathStatuses<'_, '_, '_>,
    work: &W,
) {
    // Closure derives the actual delegated authority, not a successful subset
    // chosen by the caller. A repeated root shares its exact dependency once;
    // missing responder/path, duplicate nodes and resource failure stay typed.
    use structured_ltv::pki::{
        AuthorityClosureError, AuthorityNode, AuthorityOrigin, MemberStatus, close_authorities,
    };
    let entries = [MemberStatus::Ocsp(responder.target())];
    let parent = responder
        .target()
        .path()
        .status_census(child.evaluated_at(), &entries, work)
        .unwrap();
    let bindings = [responder];
    let nodes = [
        AuthorityNode {
            statuses: &parent,
            responders: &bindings,
        },
        AuthorityNode {
            statuses: child,
            responders: &[],
        },
    ];
    let roots = [&parent, &parent];
    let before = work.memory().used();
    {
        let closed = {
            // Returned accounted metadata must outlive the short current
            // operation, while borrowing only the original external receipts.
            let operation = structured_asn1::Parser::der(work.memory().clone());
            close_authorities(&roots, &nodes, &operation.execution_in(work.memory())).unwrap()
        };
        assert_eq!(closed.roots().len(), 2);
        assert_eq!(closed.nodes().len(), 2);
        assert!(core::ptr::eq(closed.nodes()[0], &raw const nodes[0]));
        assert!(core::ptr::eq(closed.nodes()[1], &raw const nodes[1]));
        assert_root_dependencies(&closed, &nodes, work);
        assert!(work.memory().used() > before);
    }
    assert_eq!(work.memory().used(), before);
    assert!(matches!(
        close_authorities(&roots, &nodes[..1], work),
        Err(AuthorityClosureError::MissingPath {
            origin: AuthorityOrigin::Responder { node: 0, member: 0 }
        })
    ));
    let missing = [AuthorityNode {
        statuses: &parent,
        responders: &[],
    }];
    assert!(matches!(
        close_authorities(&roots, &missing, work),
        Err(AuthorityClosureError::MissingResponder {
            origin: AuthorityOrigin::Responder { node: 0, member: 0 }
        })
    ));
    let duplicate = [
        AuthorityNode {
            statuses: &parent,
            responders: &[],
        },
        AuthorityNode {
            statuses: &parent,
            responders: &[],
        },
    ];
    assert!(matches!(
        close_authorities(&roots, &duplicate, work),
        Err(AuthorityClosureError::DuplicateNode { index: 1 })
    ));
    let empty = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 24)));
    assert!(matches!(
        close_authorities(&roots, &nodes, &empty),
        Err(AuthorityClosureError::Resource(_))
    ));
    assert_eq!(empty.used(), 0);
    let denied = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 0)));
    assert!(matches!(
        close_authorities(&roots, &nodes, &denied),
        Err(AuthorityClosureError::Resource(_))
    ));
    assert_eq!(denied.used(), 0);
    let local = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..Default::default()
        },
        work.memory().clone(),
    );
    assert!(matches!(
        close_authorities(&roots, &nodes, &local.execution_in(work.memory())),
        Err(AuthorityClosureError::Resource(MemoryError::WorkExceeded))
    ));
    assert_eq!(work.memory().used(), before);
}

fn assert_root_dependencies<W: Work>(
    closed: &structured_ltv::pki::AuthorityClosure<'_, '_, '_>,
    nodes: &[structured_ltv::pki::AuthorityNode<'_, '_, '_>],
    work: &W,
) {
    // Duplicate actor roots independently reach the actual OCSP delegate.
    // Preserve both associations, not merely the first or a purpose union.
    let mut visits = [[0usize; 2]; 2];
    closed
        .visit_roots(work, |root, node| {
            let ordinal = if core::ptr::eq(node, &raw const nodes[0]) {
                0
            } else {
                assert!(core::ptr::eq(node, &raw const nodes[1]));
                1
            };
            visits[root][ordinal] += 1;
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(visits, [[1, 1], [1, 1]]);
}

fn assert_responder_fine_reading<'a, W: Work>(
    target_path: &structured_ltv::pki::CheckedPath<'a>,
    path: &structured_ltv::pki::CheckedPath<'a>,
    scoped: &structured_pkix::ocsp::ScopedResponse<'_, 'a>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    work: &W,
    verifier: &timestamp_oracle::PathOracle,
) {
    // Subnanosecond readings need both bounding nanoseconds. A path checked
    // only at the lower label cannot silently supply the upper endpoint.
    use structured_ltv::pki::{self, OcspBinding, PathOutcome, ResponderBinding, ResponderFailure};
    use structured_pkix::{
        ocsp,
        path::{Interval, ValidationBounds, ValidationContext},
        temporal,
    };
    let parser = structured_asn1::Parser::der(work.memory().clone());
    let mut source = parser
        .read(b"\x18\x1a20260101000000.0000000001Z", 8000)
        .unwrap();
    let element = source.next_element().unwrap().unwrap();
    let now = temporal::read_generalized(&source, &element, "evaluation").unwrap();
    assert!(now.has_subnanosecond_remainder());
    let request = ocsp::Request {
        target: target_path.members()[0].certificate(),
        nonce: None,
        intended_signer: Some(scoped.signed().signer()),
    };
    let time = ocsp::Evaluation {
        now,
        utc,
        execution: work,
    };
    let reading = scoped
        .evaluate_with_target(&request, &time, verifier)
        .unwrap();
    let facts = reading.evidence().unwrap();
    let OcspBinding::Bound(bound) = target_path.bind_ocsp(0, &facts, work).unwrap() else {
        panic!("same target")
    };
    assert!(matches!(
        bound.bind_responder_path(path, utc, work).unwrap(),
        ResponderBinding::Rejected(ResponderFailure::Interval)
    ));
    let context = ValidationContext {
        execution: work,
        interval: Interval::between_instants(now.start(), now.upper_bound(utc).unwrap()),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(full) =
        pki::check_path(&[path.members()[0].certificate()], path.anchor(), &context).unwrap()
    else {
        panic!("full nanosecond envelope")
    };
    let before = verifier.calls.get();
    assert!(matches!(
        bound.bind_responder_path(&full, utc, work).unwrap(),
        ResponderBinding::Bound(_)
    ));
    assert_eq!(verifier.calls.get(), before);
}

fn assert_responder_boundaries<'a, W: Work>(
    target: &structured_ltv::pki::OcspTarget<'_, '_, 'a>,
    path: &structured_ltv::pki::CheckedPath<'a>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    work: &W,
    verifier: &timestamp_oracle::PathOracle,
) {
    // Valid alternative chains do not prove the original root/time association.
    // Work/UTC refusal stays terminal, and binding never repeats signatures.
    use structured_ltv::pki::{
        self, PathOutcome, ResponderBinding, ResponderError, ResponderFailure,
    };
    use structured_pkix::{
        Certificate,
        path::{Anchor, Interval, ValidationBounds, ValidationContext},
        temporal::LeapTable,
    };
    let at = target.evidence().evaluated_at().start();
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(matches!(
        target.bind_responder_path(path, utc, &denied),
        Err(ResponderError::Resource(_))
    ));
    let unknown = LeapTable::new(at.seconds() + 1, 2_000_000_000, &[]).unwrap();
    assert!(matches!(
        target.bind_responder_path(path, &unknown, work),
        Err(ResponderError::Time(_))
    ));
    let context = ValidationContext {
        execution: work,
        interval: Interval::at(at.seconds() + 1),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(later) =
        pki::check_path(&[path.members()[0].certificate()], path.anchor(), &context).unwrap()
    else {
        panic!("same signer later valid")
    };
    assert!(matches!(
        target.bind_responder_path(&later, utc, work).unwrap(),
        ResponderBinding::Rejected(ResponderFailure::Interval)
    ));
    let (delegate_bytes, root_bytes) = timestamp_oracle::ocsp_delegate(4);
    let parser = structured_asn1::Parser::der(work.memory().clone());
    let delegate = Certificate::read(&parser, &delegate_bytes, 6000).unwrap();
    let root = Certificate::read(&parser, &root_bytes, 7000).unwrap();
    let PathOutcome::Accepted(other) =
        pki::check_path(&[&delegate], Anchor::from_certificate(&root), &context).unwrap()
    else {
        panic!("other root actual valid path")
    };
    assert!(matches!(
        target.bind_responder_path(&other, utc, work).unwrap(),
        ResponderBinding::Rejected(ResponderFailure::Anchor)
    ));
}

fn assert_ocsp_target<W: Work>(
    path: &structured_ltv::pki::CheckedPath<'_>,
    evidence: &structured_pkix::ocsp::BoundEvidence<'_, '_, '_, '_>,
    execution: &W,
) {
    use structured_ltv::pki::{OcspBinding, OcspBindingError};
    let OcspBinding::Bound(bound) = path.bind_ocsp(0, evidence, execution).unwrap() else {
        panic!("same actual target and issuing key")
    };
    let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    assert!(matches!(
        bound.bind_responder_path(path, &utc, execution),
        Err(structured_ltv::pki::ResponderError::SourceKind)
    ));
    assert!(core::ptr::eq(bound.path(), path));
    assert!(core::ptr::eq(bound.evidence(), evidence));
    assert_eq!(bound.member(), 0);
    assert_eq!(bound.authority(), evidence.evidence().source().source());
    assert!(matches!(
        path.bind_ocsp(1, evidence, execution),
        Err(OcspBindingError::MemberIndex { index: 1 })
    ));
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(matches!(
        path.bind_ocsp(0, evidence, &denied),
        Err(OcspBindingError::Resource(_))
    ));
}

#[test]
fn ocsp_name_and_serial_cannot_substitute_another_issuer_or_path_target() {
    // The server signature and CertID can be valid under a caller-selected
    // configured-responder scope while the caller supplied the WRONG target
    // issuer. Root composition must bind it to the actual checked path key.
    use structured_ltv::pki::{OcspBinding, OcspBindingFailure};
    use structured_pkix::{
        ocsp,
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    xml_digest::with_checked_path(|path, _, _, memory| {
        let target = path.members()[0].certificate();
        let signer = path.anchor().certificate().unwrap();
        let bytes = timestamp_oracle::ocsp_response(3);
        let other_bytes = timestamp_oracle::other_issuer();
        let parser = structured_asn1::Parser::der(memory.clone());
        let query = parser.read(&[], 3000).unwrap();
        let other = structured_pkix::Certificate::read(&parser, &other_bytes, 4000).unwrap();
        let ocsp::Response::Successful(payload) =
            ocsp::Response::read(&parser, &bytes, 5000).unwrap()
        else {
            panic!("successful whole response")
        };
        let response = payload.basic_in(&query).unwrap().unwrap();
        let verifier = timestamp_oracle::PathOracle {
            calls: Cell::new(0),
        };
        let ocsp::SignatureAuthentication::Signed(authenticated) = response
            .authenticate_signature(
                signer,
                WorkingKey::standing(signer.tbs().public_key()),
                &verifier,
                &verifier,
                memory,
            )
            .unwrap()
        else {
            panic!("actual configured server signature")
        };
        let scoped = authenticated.trust_for_issuer(&other);
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let time = ocsp::Evaluation {
            now: Instant::new(1_767_225_600, 0).unwrap().into(),
            utc: &utc,
            execution: memory,
        };
        for (selected, failure) in [
            (target, OcspBindingFailure::Issuer),
            (&other, OcspBindingFailure::Target),
        ] {
            let request = ocsp::Request {
                target: selected,
                nonce: None,
                intended_signer: Some(signer),
            };
            let reading = scoped
                .evaluate_with_target(&request, &time, &verifier)
                .unwrap();
            let facts = reading.evidence().unwrap();
            assert_eq!(facts.evidence().assertion().status(), ocsp::Status::Good);
            assert!(
                matches!(path.bind_ocsp(0,&facts,memory).unwrap(),OcspBinding::Rejected(actual) if actual==failure)
            );
        }
        assert_eq!(verifier.calls.get(), 1);
    });
}

fn assert_timestamp_path<'a, N: Copy, D: Copy, G: Copy>(
    actor: &structured_ltv::timestamp::CheckedActor<'a, 'a, N, D, G, structured_xades::Xades>,
    root: &'a structured_pkix::Certificate<'a>,
    operation: &'a structured_asn1::Reader<'a>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
) -> structured_ltv::pki::CheckedPath<'a> {
    // The actual TSA certificate must be the target of the checked path, over
    // the entire generation interval. A later valid chain is insufficient.
    use structured_ltv::pki::{
        self, PathOutcome, TimestampBinding, TimestampBindingError, TimestampBindingFailure,
    };
    use structured_pkix::path::{Anchor, Interval, ValidationBounds, ValidationContext};
    let verifier = timestamp_oracle::PathOracle {
        calls: core::cell::Cell::new(0),
    };
    let work = operation.execution();
    let context = ValidationContext {
        execution: &work,
        interval: Interval::at(1_767_225_600),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(path) = pki::check_path(
        &[actor.certificate()],
        Anchor::from_certificate(root),
        &context,
    )
    .unwrap() else {
        panic!("actual TSA chain must validate")
    };
    let TimestampBinding::Bound(bound) = path.bind_timestamp(actor, utc, &work).unwrap() else {
        panic!("actual token signer and checked path must bind")
    };
    assert!(core::ptr::eq(bound.actor(), actor));
    assert!(core::ptr::eq(bound.path(), &raw const path));
    assert_eq!(
        bound.generation().earliest,
        structured_pkix::temporal::Instant::new(1_767_225_600, 0).unwrap()
    );
    assert_eq!(verifier.calls.get(), 1);
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(matches!(
        path.bind_timestamp(actor, utc, &denied),
        Err(TimestampBindingError::Resource(_))
    ));
    let later = ValidationContext {
        interval: Interval::at(1_767_225_601),
        ..context
    };
    let PathOutcome::Accepted(later_path) = pki::check_path(
        &[actor.certificate()],
        Anchor::from_certificate(root),
        &later,
    )
    .unwrap() else {
        panic!("same chain remains valid one second later")
    };
    assert!(matches!(
        later_path.bind_timestamp(actor, utc, &work).unwrap(),
        TimestampBinding::Rejected(TimestampBindingFailure::Interval)
    ));
    assert_eq!(verifier.calls.get(), 2);
    path
}

fn carried_ocsp_choice(response: &[u8]) -> Vec<u8> {
    let mut fields = timestamp_oracle::tlv(6, structured_cms::oid::OCSP_RESPONSE.as_bytes());
    fields.extend(response);
    timestamp_oracle::tlv(0xa1, &fields)
}

#[test]
fn timestamp_carried_material_keeps_token_pool_identity_and_embedded_ocsp_certificates() {
    // Both timestamp sources retain their actual choice ordinals. This is
    // original-source availability, not OCSP signature/status authentication.
    let certificate = candidate_certificate();
    // DER SET OF order compares whole original TLVs: the shorter opaque
    // context-tagged member precedes the long OCSP member.
    let mut choices = timestamp_oracle::tlv(0xa1, &[6, 1, 42, 5, 0]);
    choices.extend(carried_ocsp_choice(&ocsp_material_with_certificate(
        &certificate,
    )));
    let (mut xml, _, _) = token_pipeline_tree();
    xml.binary = inspection_token_with_choices(&choices, 5);
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let held = memory.used();
    timestamp::with_tokens(
        &xml,
        &prepared,
        &operation,
        timestamp::TokenProfile::Etsi,
        |query, view| {
            let material = view.material_in(query).unwrap();
            assert!(material.crls().is_empty());
            assert_eq!(material.responses().len(), 2);
            assert_eq!(material.basic_responses().len(), 2);
            assert_eq!(material.other().len(), 2);
            for ordinal in 0..2 {
                let basic = &material.basic_responses()[ordinal];
                assert_eq!(
                    basic.origin,
                    structured_ltv::material::CarriedOrigin {
                        token: ordinal,
                        choice: 1
                    }
                );
                assert_eq!(
                    basic.value.as_bytes().as_ptr(),
                    material.responses()[ordinal].value.payload().as_ptr()
                );
                assert_eq!(basic.value.certificates()[0].as_bytes(), certificate);
                assert_eq!(
                    material.other()[ordinal].origin,
                    structured_ltv::material::CarriedOrigin {
                        token: ordinal,
                        choice: 0
                    }
                );
                assert_eq!(material.other()[ordinal].value.kind.as_bytes(), &[42]);
                assert_eq!(material.other()[ordinal].value.value.as_bytes(), &[5, 0]);
            }
            Ok::<_, ()>(())
        },
    )
    .unwrap();
    assert_eq!(memory.used(), held);
    drop(prepared);
    assert_eq!(memory.used(), 0);
}

#[test]
fn timestamp_carried_material_late_known_failure_drops_all_partial_catalogues() {
    // Earlier usable syntax cannot hide a late unsigned OCSP protocol failure;
    // original token/choice and XML location survive the entire scope's drop.
    let (mut xml, _, second) = token_pipeline_tree();
    xml.binary = inspection_token_with_choices(
        &carried_ocsp_choice(&ocsp_material_with_certificate(&candidate_certificate())),
        5,
    );
    xml.binary_routes.push((
        second,
        inspection_token_with_choices(&carried_ocsp_choice(&[0x30, 3, 10, 1, 3]), 5),
    ));
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let held = memory.used();
    let result = timestamp::with_tokens(&xml, &prepared, &operation, timestamp::TokenProfile::Etsi, |query, view| {
        let Err(error) = view.material_in(query) else { panic!("late invalid status must refuse") };
        assert_eq!(error.location.node, second);
        assert_eq!(error.origin, structured_ltv::material::CarriedOrigin { token: 1, choice: 0 });
        assert!(matches!(&error.cause, timestamp::CarriedCause::Cms(cause) if cause.code() == structured_cms::ErrorCode::MalformedValue));
        Ok::<_, ()>(error)
    }).unwrap();
    assert_eq!(result.location.snapshot, xml.snapshot());
    drop(result);
    assert_eq!(memory.used(), held);
}

#[test]
fn timestamp_carried_material_empty_set_still_pays_current_metadata_admission() {
    // Source parsing is no work credit for a later narrower operation. Even
    // empty revocation sets must not create successful unfunded traversals.
    let (mut xml, first, _) = token_pipeline_tree();
    xml.binary = inspection_token();
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    timestamp::with_tokens(&xml, &prepared, &operation, timestamp::TokenProfile::Etsi, |_, view| {
        let denied = structured_asn1::Parser::new(
            structured_asn1::Encoding::Der,
            structured_asn1::Limits {
                max_work: 0,
                ..structured_asn1::Limits::default()
            },
            memory.clone(),
        );
        let query = denied.read(&[], 0).unwrap();
        let Err(error) = view.material_in(&query) else {
            panic!("unfunded metadata must refuse")
        };
        assert_eq!(error.location.node, first);
        assert!(
            matches!(error.cause, timestamp::CarriedCause::Encoding(cause) if cause.is_resource())
        );
        Ok::<_, ()>(())
    })
    .unwrap();
}

#[test]
fn timestamp_carried_crl_uses_original_choice_bytes_and_actual_enclosing_depth() {
    // CMS CRL choices have no extra OCTET STRING wrapper. Reading must keep
    // the original whole CertificateList and actual nested source coordinates.
    use timestamp_oracle::tlv;
    let algorithm = [48, 3, 6, 1, 42];
    let name = [48, 12, 49, 10, 48, 8, 6, 3, 0x55, 4, 3, 12, 1, b'a'];
    let tbs = tlv(
        48,
        &[algorithm.as_slice(), &name, &tlv(23, b"261012120000Z")].concat(),
    );
    let crl = tlv(48, &[&tbs, algorithm.as_slice(), &[3, 2, 0, 8]].concat());
    let (mut xml, _, _) = token_pipeline_tree();
    xml.binary = inspection_token_with_choices(&crl, 3);
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let held = memory.used();
    timestamp::with_tokens(
        &xml,
        &prepared,
        &operation,
        timestamp::TokenProfile::Etsi,
        |query, view| {
            let material = view.material_in(query).unwrap();
            assert_eq!(material.crls().len(), 2);
            assert!(material.responses().is_empty());
            assert!(material.basic_responses().is_empty());
            assert!(material.other().is_empty());
            for ordinal in 0..2 {
                let value = &material.crls()[ordinal];
                let original = view.readings()[ordinal].token().message().revocations()[0];
                assert_eq!(
                    value.origin,
                    structured_ltv::material::CarriedOrigin {
                        token: ordinal,
                        choice: 0
                    }
                );
                assert_eq!(value.value.as_bytes(), crl);
                assert_eq!(
                    value.value.as_bytes().as_ptr(),
                    original.as_bytes().as_ptr()
                );
                assert_eq!(value.value.span(), original.span());
            }
            Ok::<_, ()>(())
        },
    )
    .unwrap();
    assert_eq!(memory.used(), held);
}

#[test]
fn timestamp_carried_material_new_operation_cannot_bypass_storage_or_original_depth() {
    // Retained source capacity is not moved to the new account. A later
    // decoder must pay its own catalogues and respect the original CMS depth.
    let (mut xml, first, _) = token_pipeline_tree();
    xml.binary = inspection_token_with_choices(
        &carried_ocsp_choice(&ocsp_material_with_certificate(&candidate_certificate())),
        5,
    );
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    timestamp::with_tokens(
        &xml,
        &prepared,
        &operation,
        timestamp::TokenProfile::Etsi,
        |_, view| {
            for (capacity, depth) in [(0, 64), (1_048_576, 3)] {
                let account = Memory::new(Arc::new(MemoryAccount::new(capacity, 1_048_576)));
                let current = structured_asn1::Parser::new(
                    structured_asn1::Encoding::Der,
                    structured_asn1::Limits {
                        max_depth: depth,
                        ..structured_asn1::Limits::default()
                    },
                    account.clone(),
                );
                let query = current.read(&[], 0).unwrap();
                let held = memory.used();
                let Err(error) = view.material_in(&query) else {
                    panic!("refusal must precede usable material")
                };
                assert_eq!(error.location.node, first);
                assert_eq!(
                    error.origin,
                    structured_ltv::material::CarriedOrigin {
                        token: 0,
                        choice: 0
                    }
                );
                assert!(match &error.cause {
                    timestamp::CarriedCause::Cms(cause) => cause.is_resource(),
                    timestamp::CarriedCause::Pkix(cause) => cause.is_resource(),
                    timestamp::CarriedCause::Encoding(cause) => cause.is_resource(),
                    timestamp::CarriedCause::Resource(_) => true,
                });
                drop(error);
                assert_eq!(account.used(), 0);
                assert_eq!(memory.used(), held);
            }
            Ok::<_, ()>(())
        },
    )
    .unwrap();
}

#[test]
fn timestamp_source_set_freezes_ownership_before_borrowing_original_tokens_and_readers() {
    // Original buffers/parser contexts coexist without self-reference, token
    // clones, a second decoder or borrowing movable source-vector entries.
    let (mut xml, first, second) = token_pipeline_tree();
    xml.binary = inspection_token();
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let held = memory.used();
    timestamp::with_tokens(
        &xml,
        &prepared,
        &operation,
        timestamp::TokenProfile::Etsi,
        |_, view| {
            assert_eq!(view.sources().len(), 2);
            assert_eq!(view.readings().len(), 2);
            for (index, (source, reading)) in view.sources().iter().zip(view.readings()).enumerate()
            {
                assert_eq!(source.location().node, [first, second][index]);
                assert_eq!(source.location().snapshot, xml.snapshot());
                assert_eq!(source.stamp_index(), index);
                assert_eq!(source.token_index(), 0);
                assert_eq!(source.property(), prepared.timestamps()[index].node());
                assert_eq!(source.role(), [Role::Signature, Role::Archive][index]);
                assert!(reading.reader().is_empty());
                assert_eq!(reading.reader().depth(), 0);
                assert_eq!(reading.token().message().signers().len(), 1);
                let bytes = reading.token().message().as_bytes();
                assert!(bytes.as_ptr() >= source.bytes().as_ptr());
                assert!(bytes.as_ptr_range().end <= source.bytes().as_ptr_range().end);
            }
            Ok::<_, ()>(())
        },
    )
    .unwrap();
    assert_eq!(memory.used(), held);
    drop(prepared);
    assert_eq!(memory.used(), 0);
}

#[test]
fn timestamp_source_set_runs_complete_common_checks_and_retains_independent_evidence_without_redecode()
 {
    // This tests the real P256/ESS/imprint common checker over the frozen source
    // set, not full XML C14N, signer trust or a completed XAdES baseline level.
    use structured_cms::timestamp::CheckContext;
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 10_000_000)));
    let (proofs, node) = {
        let mut xml = preparation_tree();
        let method = xml.element_child(8, DS, "CanonicalizationMethod");
        let node = xml.element_child(8, XADES, "EncapsulatedTimeStamp");
        let value = xml.element_child(0, DS, "SignatureValue");
        let expected = [
            b'E',
            u8::try_from(value).unwrap(),
            b'M',
            u8::try_from(method).unwrap(),
        ];
        let (provider, token, certificate_bytes) =
            timestamp_oracle::fixture_with_certificate(&expected);
        xml.binary = token;
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let cert_parser = structured_asn1::Parser::der(memory.clone());
        let certificate =
            structured_pkix::Certificate::read(&cert_parser, &certificate_bytes, 400).unwrap();
        let certificate_parent = cert_parser.read(&[], 400).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = CheckContext {
            certificate: &certificate,
            certificate_parent: &certificate_parent,
            key: WorkingKey::standing(certificate.tbs().public_key()),
            requested: None,
            utc: &utc,
            reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
            window: None,
            policy_accuracy: None,
        };
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared =
            prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
        let proofs = timestamp::with_tokens(
            &xml,
            &prepared,
            &operation,
            timestamp::TokenProfile::Etsi,
            |query, view| {
                let execution = query.execution();
                let mut proofs = execution.vector();
                for (source, reading) in view.sources().iter().zip(view.readings()) {
                    assert_eq!(reading.token().message().certificates().len(), 1);
                    let stamp = &prepared.timestamps()[source.stamp_index()];
                    let mut input = Input::prepare(
                        &xml,
                        prepared.bound(),
                        stamp,
                        &reading.reader().execution(),
                    )
                    .unwrap();
                    let checked = reading
                        .token()
                        .check(&provider, reading.reader(), &context, &mut input, |_, _| {
                            Ok::<_, ()>(false)
                        })
                        .unwrap();
                    let evidence = checked
                        .into_evidence()
                        .expect("complete real timestamp check");
                    proofs
                        .try_push(binary::Located {
                            location: source.location(),
                            value: evidence,
                        })
                        .unwrap();
                }
                Ok::<_, ()>(proofs.into_owned())
            },
        )
        .unwrap();
        assert_eq!(provider.verified.get(), 1);
        (proofs, node)
    };
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].location.node, node);
    assert_eq!(
        proofs[0].value.facts().gen_time().start(),
        Instant::new(1_767_225_600, 0).unwrap()
    );
    assert!(memory.used() > 0);
    drop(proofs);
    assert_eq!(memory.used(), 0);
}

#[test]
fn timestamp_source_set_never_exposes_a_parsed_prefix_when_a_later_token_is_broken() {
    // The early token parses, but a late CMS failure must precede the callback
    // and release all temporary source and parsed-catalogue capacity.
    let (mut xml, _, second) = token_pipeline_tree();
    xml.binary = inspection_token();
    xml.binary_routes.push((second, vec![0x30, 0]));
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let held = memory.used();
    let called = Cell::new(false);
    let result = timestamp::with_tokens(
        &xml,
        &prepared,
        &operation,
        timestamp::TokenProfile::Etsi,
        |_, _| {
            called.set(true);
            Ok::<_, ()>(())
        },
    );
    assert!(
        matches!(result,Err(timestamp::TokenPipelineError::Token{location,..}) if location.node==second)
    );
    assert!(!called.get());
    // The original ASN.1 error legitimately retains its own diagnostic path;
    // release it before checking that every temporary allocation was returned.
    drop(result);
    assert_eq!(memory.used(), held);
}

#[test]
fn timestamp_source_set_preserves_visitor_cause_current_budget_and_generation_rollback() {
    // No fresh source read may escape the current operation. A source mutation
    // drops the visitor's retained result; its explicit error is otherwise intact.
    for mutate in [false, true] {
        let (mut xml, _, _) = token_pipeline_tree();
        xml.binary = inspection_token();
        let memory = funded();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared =
            prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
        let held = memory.used();
        let result = timestamp::with_tokens(
            &xml,
            &prepared,
            &operation,
            timestamp::TokenProfile::Etsi,
            |_, _| {
                if !mutate {
                    return Err("visitor refused");
                }
                let mut owned = memory.vector();
                owned.try_push(7u8).unwrap();
                xml.generation.set(2);
                Ok(owned)
            },
        );
        if mutate {
            assert!(matches!(
                result,
                Err(timestamp::TokenPipelineError::Access(
                    AccessError::Changed { .. }
                ))
            ));
        } else {
            assert!(matches!(
                result,
                Err(timestamp::TokenPipelineError::Visitor("visitor refused"))
            ));
        }
        assert_eq!(memory.used(), held);
    }
    let (mut xml, _, _) = token_pipeline_tree();
    xml.binary = inspection_token();
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let parser = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..Default::default()
        },
        memory.clone(),
    );
    let operation = parser.read(&[], 900).unwrap();
    assert!(matches!(
        timestamp::with_tokens(
            &xml,
            &prepared,
            &operation,
            timestamp::TokenProfile::Etsi,
            |_, _| Ok::<_, ()>(())
        ),
        Err(timestamp::TokenPipelineError::Access(
            AccessError::Resource { .. }
        ))
    ));
    assert_eq!(xml.decoded_pointer.get(), 0);
}

#[test]
fn archive_preserves_reference_order_prior_properties_and_other_objects() {
    // Exact EN319132-1 §5.5.2.3 concatenation; current/later properties excluded.
    let (mut xml, node, method) = Tree::stamped(Role::Archive);
    let object = xml.nodes.len();
    xml.nodes.push(element(Some(0), DS, "Object"));
    xml.nodes.push(Record {
        parent: Some(object),
        value: Node::Text("application payload"),
    });
    xml.nodes.push(element(Some(7), XADES, "AnyValidationData"));
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read(&access, &bound, node).unwrap();
    let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
    let mut sink = Collect::new(&memory);
    stream::run(&mut input, &mut sink, &memory, "logical.archive.input", 0).unwrap();
    let method = u8::try_from(method).unwrap();
    assert_eq!(
        sink.bytes(),
        &[
            b'R',
            0,
            b'M',
            method,
            b'R',
            1,
            b'M',
            method,
            b'E',
            9,
            b'M',
            method,
            b'E',
            12,
            b'M',
            method,
            b'E',
            13,
            b'M',
            method,
            b'E',
            8,
            b'M',
            method,
            b'E',
            u8::try_from(object).unwrap(),
            b'M',
            method,
        ]
    );
    assert_eq!(xml.streamed.get(), 7);
}

#[test]
fn unavailable_original_reference_is_incomplete_timestamp_input_not_a_processing_error_or_empty_success()
 {
    // Only the owner's typed absent-source outcome is unavailable. An opaque
    // acquisition failure must retain its real error class and original node.
    for unavailable in [false, true] {
        let (mut xml, node, _) = Tree::stamped(Role::Archive);
        if unavailable {
            xml.unavailable_reference = Some(10);
        } else {
            xml.incomplete = true;
        }
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp = timestamp::read(&access, &bound, node).unwrap();
        let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
        let mut sink = Collect::new(&memory);
        let result = stream::run(&mut input, &mut sink, &memory, "virtual.archive.input", 0);
        if unavailable {
            assert!(matches!(
                result,
                Err(stream::StreamError::Source(InputError::Unavailable {
                    node: 10,
                    cause: Cause::Unavailable
                }))
            ));
            assert_eq!(sink.bytes(), []);
            assert_eq!(xml.streamed.get(), 0);
        } else {
            assert!(matches!(
                result,
                Err(stream::StreamError::Source(InputError::Access(
                    AccessError::Xml(Cause::Incomplete)
                )))
            ));
            assert_eq!(xml.streamed.get(), 1);
        }
    }
}

#[test]
fn timestamp_method_and_rfc3161_cardinality_are_not_defaulted_or_dropped() {
    // Missing method does not invent C14N; SignatureTimeStamp cannot hide a token.
    let (mut xml, node, method) = Tree::stamped(Role::Signature);
    xml.nodes[method].parent = Some(1);
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let bound = binding::bind(&access, &container::locate(&access, 0).unwrap()).unwrap();
    assert!(matches!(
        timestamp::read(&access, &bound, node),
        Err(InputError::Missing {
            local: "CanonicalizationMethod",
            ..
        })
    ));
    xml.nodes[method].parent = Some(node);
    let extra = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "EncapsulatedTimeStamp"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(timestamp::read(&access, &bound, node), Err(InputError::Duplicate { node }) if node == extra)
    );
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn timestamp_preparation_funds_signature_identity_before_xml_traversal() {
    use structured_asn1::{Encoding, Limits, Parser};

    // The retained stamp/binding cannot pay for a new operation's identity
    // comparison. Refusal belongs to the stamp before any child traversal.
    for role in [Role::Signature, Role::Archive] {
        let (xml, node, _) = Tree::stamped(role);
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let bound = binding::bind(&access, &container::locate(&access, 0).unwrap()).unwrap();
        let stamp = timestamp::read(&access, &bound, node).unwrap();
        for budget in [0, 1] {
            let current = Memory::new(Arc::new(MemoryAccount::new(0, budget)));
            assert!(matches!(
                Input::prepare(&xml, &bound, &stamp, &current),
                Err(InputError::Resource { node: at, cause: MemoryError::WorkExceeded }) if at == node
            ));
            assert_eq!(current.used(), 0);
        }
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 1,
                ..Limits::default()
            },
            funded(),
        );
        let reader = parser.read(&[], 0).unwrap();
        assert!(matches!(
            Input::prepare(&xml, &bound, &stamp, &reader.execution()),
            Err(InputError::Resource { node: at, cause: MemoryError::WorkExceeded }) if at == node
        ));
        assert_eq!(xml.streamed.get(), 0);
    }
}

#[test]
fn timestamp_membership_pays_after_child_lookup_and_before_field_decoding() {
    // XML traversal has already succeeded when the last unit remains. It
    // cannot fund the two-operand membership comparison or begin decoding.
    let (xml, node, _) = Tree::stamped(Role::Signature);
    let original = funded();
    let access = Access::new(&xml, xml.snapshot(), &original);
    let bound = binding::bind(&access, &container::locate(&access, 0).unwrap()).unwrap();
    let current = funded();
    let observed = query_boundary::Boundary::after_inspection(&xml, node, &current, 1);
    let access = Access::new(&observed, xml.snapshot(), &current);
    assert!(matches!(timestamp::read(&access, &bound, node),
        Err(InputError::Resource { node: at, cause: MemoryError::WorkExceeded }) if at == node));
    assert_eq!(current.work_remaining(), 1);
    assert_eq!(current.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn signed_timestamp_membership_preserves_current_refusal_after_catalogue_admission() {
    // The catalogue metadata query fits, but the following identifier scan
    // must not use retained parsing credit or turn refusal into field access.
    let (mut xml, _) = certificate_tree();
    let objects = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    let node = xml.nodes.len();
    xml.nodes
        .push(element(Some(objects), XADES, "AllDataObjectsTimeStamp"));
    xml.nodes
        .push(element(Some(node), DS, "CanonicalizationMethod"));
    xml.nodes
        .push(element(Some(node), XADES, "EncapsulatedTimeStamp"));
    let original = funded();
    let signed = signed_roles(&xml, &original).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &original);
    let bound = binding::bind(&access, &container::locate(&access, 0).unwrap()).unwrap();
    let current = funded();
    let observed = query_boundary::Boundary::exhaust(&xml, 2, &current, 1);
    let access = Access::new(&observed, xml.snapshot(), &current);
    assert!(
        matches!(timestamp::read_all_data_objects(&access, &bound, &signed, node),
        Err(InputError::Resource { node: at, cause: MemoryError::WorkExceeded }) if at == node)
    );
    assert_eq!(current.work_remaining(), 1);
    assert_eq!(current.used(), 0);
}

#[test]
fn stale_generation_and_capacity_refusal_precede_timestamp_side_effects() {
    // Plans cannot escape the original generation, and no C14N begins on refusal.
    let (xml, node, _) = Tree::stamped(Role::Archive);
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let bound = binding::bind(&access, &container::locate(&access, 0).unwrap()).unwrap();
    let stamp = timestamp::read(&access, &bound, node).unwrap();
    let empty = self::memory(300_000);
    assert!(matches!(
        Input::prepare(&xml, &bound, &stamp, &empty),
        Err(InputError::Resource {
            cause: MemoryError::LimitExceeded,
            ..
        })
    ));
    assert_eq!(xml.streamed.get(), 0);
    let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
    xml.generation.set(2);
    let mut sink = Collect::new(&memory);
    assert!(matches!(
        stream::run(&mut input, &mut sink, &memory, "logical.archive.input", 0),
        Err(stream::StreamError::Source(InputError::Access(
            AccessError::Changed { .. }
        )))
    ));
    assert_eq!(sink.bytes(), []);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn sticky_sink_refusal_stops_later_archive_components_even_if_owner_ignores_it() {
    // The existing CMS driver holds the cause; input stops additional XML calls.
    let (mut xml, node, _) = Tree::stamped(Role::Archive);
    xml.ignore_refusal = true;
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let bound = binding::bind(&access, &container::locate(&access, 0).unwrap()).unwrap();
    let stamp = timestamp::read(&access, &bound, node).unwrap();
    let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
    let mut sink = Collect::new(&memory);
    sink.refuse = true;
    assert!(matches!(
        stream::run(&mut input, &mut sink, &memory, "logical.archive.input", 0),
        Err(stream::StreamError::Callback(SinkError::Refused))
    ));
    assert_eq!(xml.streamed.get(), 1);
    assert_eq!(sink.bytes(), []);
}

#[test]
fn incomplete_xml_source_is_not_a_completed_timestamp_input() {
    // A prefix reaching the hash sink does not erase the source's exact cause.
    let (mut xml, node, _) = Tree::stamped(Role::Signature);
    xml.incomplete = true;
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let bound = binding::bind(&access, &container::locate(&access, 0).unwrap()).unwrap();
    let stamp = timestamp::read(&access, &bound, node).unwrap();
    let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
    let mut sink = Collect::new(&memory);
    assert!(matches!(
        stream::run(&mut input, &mut sink, &memory, "logical.timestamp.input", 0),
        Err(stream::StreamError::Source(InputError::Access(
            AccessError::Xml(Cause::Incomplete)
        )))
    ));
    assert_eq!(sink.bytes().len(), 4);
}

fn binary_token() -> Vec<u8> {
    // Synthetic readable CMS/TSTInfo, deliberately not a cryptographic proof.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        assert!(contents.len() < 128);
        let mut value = vec![tag, u8::try_from(contents.len()).unwrap()];
        value.extend_from_slice(contents);
        value
    }
    let mut info = vec![
        2, 1, 1, 6, 1, 43, 0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, 97, 98, 2, 1, 7,
    ];
    info.extend(tlv(0x18, b"20260101000000Z"));
    let info = tlv(0x30, &info);
    let mut content = tlv(6, structured_cms::oid::TST_INFO.as_bytes());
    content.extend(tlv(0xa0, &tlv(4, &info)));
    let signer = tlv(
        0x30,
        &[
            2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, 8,
        ],
    );
    let mut message = vec![2, 1, 3, 0x31, 0];
    message.extend(tlv(0x30, &content));
    message.extend(tlv(0x31, &signer));
    let mut envelope = tlv(6, structured_cms::oid::SIGNED_DATA.as_bytes());
    envelope.extend(tlv(0xa0, &tlv(0x30, &message)));
    tlv(0x30, &envelope)
}

#[test]
fn scoped_binary_token_uses_common_info_and_retains_only_paid_results() {
    // No borrowed token or decoded scratch escapes; the selected result's
    // independent capacity survives both scoped producing parsers.
    let memory = funded();
    let retained = {
        let mut xml = Tree::normal();
        xml.binary = binary_token();
        let parser = structured_asn1::Parser::ber(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let location = Location {
            snapshot: xml.snapshot(),
            node: 8,
        };
        binary::with_token(&xml, location, &operation, |token, reader| {
            let result = token
                .with_info(reader, |info, parent, _| {
                    assert_eq!(info.serial().value().as_u64(), Some(7));
                    assert!(!info.has_faults());
                    let execution = parent.execution();
                    let mut result = execution.vector();
                    result.try_extend_from_slice(info.policy().as_bytes())?;
                    Ok::<_, MemoryError>(result.into_owned())
                })
                .unwrap();
            Ok::<_, ()>(result)
        })
        .unwrap()
    };
    assert_eq!(&*retained, &[43]);
    assert!(memory.used() > 0);
    drop(retained);
    assert_eq!(memory.used(), 0);
}

#[test]
fn binary_callback_and_processing_errors_keep_xml_and_decoded_coordinates() {
    // A decoded ASN offset is not physical XML position 900, and callback
    // failure is never rewritten into syntax or a timestamp mismatch.
    let memory = funded();
    let parser = structured_asn1::Parser::ber(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = Tree::normal();
    xml.binary = vec![0x30, 0];
    let location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    match binary::with_token(&xml, location, &operation, |_, _| Ok::<_, u8>(())) {
        Err(binary::Error::Callback {
            location: actual,
            cause: binary::TokenError::Processing(cause),
        }) => {
            assert_eq!(actual, location);
            assert!(cause.offset() < 900);
        }
        other => panic!("unexpected {other:?}"),
    }
    xml.binary = binary_token();
    assert!(matches!(
        binary::with_token(&xml, location, &operation, |_, _| Err::<(), _>(17_u8)),
        Err(binary::Error::Callback {
            cause: binary::TokenError::Callback(17),
            ..
        })
    ));
    assert_eq!(memory.used(), 0);
}

#[test]
fn binary_scopes_reject_stale_generation_and_fund_current_local_copy() {
    // Scratch copy cannot bypass the operation's local work ceiling. A stale
    // successful callback cannot publish retained output or updated evidence.
    let memory = funded();
    let limits = structured_asn1::Limits {
        max_work: 3,
        ..structured_asn1::Limits::default()
    };
    let parser =
        structured_asn1::Parser::new(structured_asn1::Encoding::Ber, limits, memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = Tree::normal();
    xml.binary = binary_token();
    let location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    let called = Cell::new(false);
    assert!(matches!(
        binary::with_token(&xml, location, &operation, |_, _| {
            called.set(true);
            Ok::<_, ()>(())
        }),
        Err(binary::Error::Access {
            cause: AccessError::Xml(Cause::Resource(MemoryError::WorkExceeded)),
            ..
        })
    ));
    assert!(!called.get());
    assert_eq!(memory.work_used(), 3);
    assert_eq!(memory.used(), 0);
    let parser = structured_asn1::Parser::ber(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    xml.mutate_binary = true;
    assert!(matches!(
        binary::with_token(&xml, location, &operation, |_, _| Ok::<_, ()>(())),
        Err(binary::Error::Access {
            cause: AccessError::Changed { node: 8 },
            ..
        })
    ));
    assert_eq!(memory.used(), 0);
}

#[test]
fn binary_reader_creation_refusal_preserves_typed_depth_cause_before_visitor() {
    // Common Reader creation preserves the ASN resource refusal before the
    // token visitor, rather than reporting base64 syntax or missing timestamp.
    let memory = funded();
    let limits = structured_asn1::Limits {
        max_depth: 0,
        ..structured_asn1::Limits::default()
    };
    let parser =
        structured_asn1::Parser::new(structured_asn1::Encoding::Ber, limits, memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = Tree::normal();
    xml.binary = binary_token();
    // Emulate an existing decoded window at ASN depth1; a fresh root is depth0.
    xml.binary_depth = 1;
    let location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    let called = Cell::new(false);
    let result = binary::with_token(&xml, location, &operation, |_, _| {
        called.set(true);
        Ok::<_, ()>(())
    });
    match result {
        Err(binary::Error::ReaderCreation {
            cause,
            location: actual,
        }) => {
            assert_eq!(actual, location);
            assert_eq!(
                cause.code(),
                structured_asn1::ErrorCode::LimitExceeded(structured_asn1::Limit::Depth)
            );
            assert_eq!(cause.offset(), 0);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!called.get());
    assert_eq!(memory.used(), 0);
}

fn signed_roles(
    xml: &Tree,
    memory: &Memory,
) -> properties::PropertyResult<properties::Reading<Tree>, Tree> {
    let access = Access::new(xml, xml.snapshot(), memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    properties::read(&access, &bound)
}

#[test]
fn signing_time_requires_a_qualified_explicit_zone_without_canonical_z_or_epoch_conversion() {
    // The owner's complete scalar receipt is a CLAIM, not a timestamp. Keep
    // original source/offset and never require a narrowed POSIX/calendar value.
    use properties::{ClaimedTimeBinding, ClaimedTimeFailure, DateTimeFact};
    for timezone in [-840, -60, 0, 60, 840] {
        let memory = funded();
        let mut xml = preparation_tree();
        xml.date_time = DateTimeFact::Valid {
            timezone_minutes: Some(timezone),
        };
        let signed = signed_roles(&xml, &memory).unwrap();
        let before = memory.used();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let ClaimedTimeBinding::Bound(claim) = properties::check_time(&signed, &access).unwrap()
        else {
            panic!("complete original zoned scalar")
        };
        assert_eq!(claim.snapshot(), signed.snapshot());
        assert_eq!(claim.signature(), signed.signature());
        assert_eq!(claim.node(), signed.signing_time());
        assert_eq!(claim.timezone_minutes(), timezone);
        assert_eq!(xml.date_time_calls.get(), 1);
        assert_eq!(memory.used(), before);
        assert_eq!(xml.streamed.get(), 0);
    }
    for (fact, expected) in [
        (DateTimeFact::Malformed, ClaimedTimeFailure::Malformed),
        (DateTimeFact::Unsupported, ClaimedTimeFailure::Unsupported),
        (
            DateTimeFact::Valid {
                timezone_minutes: None,
            },
            ClaimedTimeFailure::TimezoneUnstated,
        ),
    ] {
        let mut xml = preparation_tree();
        xml.date_time = fact;
        let memory = funded();
        let signed = signed_roles(&xml, &memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        assert!(matches!(properties::check_time(&signed, &access).unwrap(),
            ClaimedTimeBinding::Unproven { node, cause }
            if node == signed.signing_time() && cause == expected));
        assert_eq!(xml.date_time_calls.get(), 1);
    }
}

#[test]
fn signing_time_uses_current_admission_and_preserves_source_and_owner_refusals() {
    // Retaining SignedProperties does not pay a later scalar query. Zero work
    // refuses before owner dispatch; an owner failure stays its original cause.
    use properties::{ClaimedTimeBinding, ClaimedTimeError, DateTimeFact};
    let mut xml = preparation_tree();
    xml.date_time = DateTimeFact::Valid {
        timezone_minutes: Some(0),
    };
    let original = funded();
    let signed = signed_roles(&xml, &original).unwrap();
    let before = original.used();
    let denied = memory(0);
    let access = Access::new(&xml, xml.snapshot(), &denied);
    assert!(matches!(
        properties::check_time(&signed, &access),
        Err(ClaimedTimeError::Access(AccessError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        }))
    ));
    assert_eq!(xml.date_time_calls.get(), 0);
    let owner_denied = memory(1);
    let access = Access::new(&xml, xml.snapshot(), &owner_denied);
    assert!(matches!(
        properties::check_time(&signed, &access),
        Err(ClaimedTimeError::Access(AccessError::Xml(Cause::Resource(
            MemoryError::WorkExceeded
        ))))
    ));
    assert_eq!(xml.date_time_calls.get(), 1);
    let exact = memory(2);
    let access = Access::new(&xml, xml.snapshot(), &exact);
    assert!(matches!(
        properties::check_time(&signed, &access).unwrap(),
        ClaimedTimeBinding::Bound(_)
    ));
    assert_eq!(exact.used(), 0);
    assert_eq!(exact.work_used(), 2);
    let calls = xml.date_time_calls.get();
    xml.generation.set(xml.generation.get() + 1);
    let access = Access::new(&xml, xml.snapshot(), &original);
    assert!(matches!(properties::check_time(&signed, &access),
        Err(ClaimedTimeError::Foreign { node }) if node == signed.signing_time()));
    assert_eq!(xml.date_time_calls.get(), calls);
    assert_eq!(original.used(), before);
}

#[test]
fn signed_roles_require_current_baseline_properties_and_preserve_foreign_extensions() {
    // Schema-optional fields can be mandatory in the selected baseline. An
    // extension is retained for explicit checking, never treated as a certificate.
    let mut xml = Tree::normal();
    let memory = funded();
    assert!(matches!(
        signed_roles(&xml, &memory),
        Err(properties::Error::Missing {
            parent: 4,
            local: "SigningCertificateV2"
        })
    ));
    let cert = xml.nodes.len();
    xml.nodes
        .push(element(Some(4), XADES, "SigningCertificateV2"));
    let extra = xml.nodes.len();
    xml.nodes.push(element(Some(4), "urn:extension", "Claim"));
    let reading = signed_roles(&xml, &memory).unwrap();
    assert_eq!(reading.parent(), 4);
    assert_eq!(reading.signing_time(), 5);
    assert_eq!(reading.signing_certificate(), cert);
    assert_eq!(reading.snapshot(), xml.snapshot());
    assert_eq!(reading.signature(), 0);
    assert_eq!(reading.policy(), None);
    assert_eq!(reading.place(), None);
    assert_eq!(reading.role(), None);
    assert_eq!(reading.extensions(), &[extra]);
    assert!(memory.used() > 0);
    drop(reading);
    assert_eq!(memory.used(), 0);
}

#[test]
fn signed_roles_reject_legacy_duplicate_and_out_of_order_nodes() {
    // Coverage does not override the baseline's forbidden legacy forms or
    // sequence/singleton rules, even when their signed bytes are authentic.
    let memory = funded();
    let mut xml = Tree::normal();
    let cert = xml.nodes.len();
    xml.nodes
        .push(element(Some(4), XADES, "SigningCertificate"));
    assert!(
        matches!(signed_roles(&xml, &memory), Err(properties::Error::Forbidden { node }) if node == cert)
    );
    xml.nodes[cert] = element(Some(4), XADES, "SigningCertificateV2");
    let repeated = xml.nodes.len();
    xml.nodes
        .push(element(Some(4), XADES, "SigningCertificateV2"));
    assert!(
        matches!(signed_roles(&xml, &memory), Err(properties::Error::Duplicate { node }) if node == repeated)
    );
    xml.nodes[repeated] = element(Some(4), XADES, "SignaturePolicyIdentifier");
    xml.nodes[cert] = element(Some(4), XADES, "SignerRoleV2");
    assert!(
        matches!(signed_roles(&xml, &memory), Err(properties::Error::Order { node }) if node == repeated)
    );
    assert_eq!(memory.used(), 0);
}

#[test]
fn signed_role_wildcard_does_not_admit_absent_namespace() {
    // XSD 1.0 ##other excludes both the target namespace and absent namespace;
    // an unqualified property must not hide in an unchecked extension catalogue.
    let memory = funded();
    let mut xml = Tree::normal();
    xml.nodes
        .push(element(Some(4), XADES, "SigningCertificateV2"));
    let unqualified = xml.nodes.len();
    xml.nodes.push(element(Some(4), "", "SigningCertificateV2"));
    assert!(
        matches!(signed_roles(&xml, &memory), Err(properties::Error::Unexpected { node }) if node == unqualified)
    );
    assert_eq!(memory.used(), 0);
}

#[test]
fn digest_value_octets_do_not_acquire_a_fictitious_asn_depth() {
    // The same owner decode kernel supports arbitrary hash octets under a
    // zero ASN depth ceiling. Only actual embedded ASN.1 needs nested depth.
    let memory = funded();
    let limits = structured_asn1::Limits {
        max_depth: 0,
        ..structured_asn1::Limits::default()
    };
    let parser =
        structured_asn1::Parser::new(structured_asn1::Encoding::Ber, limits, memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = Tree::normal();
    xml.binary = vec![0xff, 0x80, 0x00];
    let location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    let result = binary::with_octets(&xml, location, &operation.execution(), |bytes| {
        assert_eq!(bytes, &[0xff, 0x80, 0]);
        Ok::<_, ()>(bytes.len())
    })
    .unwrap();
    assert_eq!(result, 3);
    assert_eq!(memory.used(), 0);
}

fn certificate_tree() -> (Tree, [usize; 6]) {
    let mut xml = Tree::normal();
    let property = xml.nodes.len();
    xml.nodes
        .push(element(Some(4), XADES, "SigningCertificateV2"));
    let cert = xml.nodes.len();
    xml.nodes.push(element(Some(property), XADES, "Cert"));
    let digest = xml.nodes.len();
    xml.nodes.push(element(Some(cert), XADES, "CertDigest"));
    let method = xml.nodes.len();
    xml.nodes.push(element(Some(digest), DS, "DigestMethod"));
    let value = xml.nodes.len();
    xml.nodes.push(element(Some(digest), DS, "DigestValue"));
    let issuer = xml.nodes.len();
    xml.nodes.push(element(Some(cert), XADES, "IssuerSerialV2"));
    (xml, [property, cert, digest, method, value, issuer])
}

fn header_tree() -> (Tree, usize, usize, usize) {
    let (mut xml, _) = certificate_tree();
    let data = xml.nodes.len();
    xml.nodes.push(element(Some(13), DS, "X509Data"));
    let cert = xml.nodes.len();
    xml.nodes.push(element(Some(data), DS, "X509Certificate"));
    let method = xml.nodes.len();
    xml.nodes
        .push(element(Some(9), DS, "CanonicalizationMethod"));
    xml.digest_algorithm = Some("http://www.w3.org/2006/12/xml-c14n11");
    (xml, data, cert, method)
}

fn preparation_tree() -> Tree {
    let (mut xml, _, _, _) = header_tree();
    let objects = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    let format = xml.nodes.len();
    xml.nodes
        .push(element(Some(objects), XADES, "DataObjectFormat"));
    xml.mime(format);
    xml.object_reference = Some("#direct");
    xml.nodes
        .push(element(Some(8), DS, "CanonicalizationMethod"));
    xml.nodes
        .push(element(Some(8), XADES, "EncapsulatedTimeStamp"));
    xml
}

#[test]
fn preparation_ownership_depends_on_original_identities_not_the_xml_view_type() {
    // A scoped owner may be dropped after HRTB inspection. Retained preparation
    // owns node identities/capacity, so equal identity domains must not pin its
    // nominal XML adapter type or require copying the prepared catalogues.
    fn identities_only<
        X: Xml,
        Y: Xml<Id = X::Id, Document = X::Document, Generation = X::Generation>,
    >(
        prepared: prepare::Prepared<X>,
    ) -> prepare::Prepared<Y> {
        prepared
    }
    let memory = funded();
    let xml = preparation_tree();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let pointer = prepared.formats().as_ptr();
    let held = memory.used();
    let moved = identities_only::<Tree, Tree>(prepared);
    assert_eq!(moved.formats().as_ptr(), pointer);
    assert_eq!(moved.bound().containers().snapshot(), xml.snapshot());
    assert_eq!(memory.used(), held);
    drop(moved);
    assert_eq!(memory.used(), 0);
}

#[test]
fn selected_source_preparation_connects_header_properties_formats_and_timestamp_models() {
    // One entrypoint preserves original stage models and their charges. This
    // is source preparation, not verified SigningTime/MIME/certificate/TSA facts.
    let memory = funded();
    let prepared = {
        let xml = preparation_tree();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared =
            prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
        assert_eq!(prepared.bound().containers().signature(), 0);
        assert_eq!(prepared.signed().signature(), 0);
        assert_eq!(prepared.header().key_info(), 13);
        assert_eq!(prepared.certificates().entries().len(), 1);
        assert_eq!(prepared.formats().len(), 1);
        assert_eq!(prepared.formats()[0].reference(), 10);
        assert!(prepared.roles().is_none());
        assert_eq!(prepared.unsigned().entries().len(), 1);
        assert_eq!(prepared.timestamps().len(), 1);
        assert_eq!(prepared.timestamps()[0].node(), 8);
        assert!(prepared.material().is_empty());
        assert!(prepared.validation().is_empty());
        assert_eq!(xml.streamed.get(), 0);
        assert_eq!(xml.decoded_pointer.get(), 0);
        prepared
    };
    assert!(memory.used() > 0);
    drop(prepared);
    assert_eq!(memory.used(), 0);
}

fn append_timestamp(
    xml: &mut Tree,
    parent: usize,
    role: Role,
    count: usize,
) -> (usize, Vec<usize>) {
    let property = xml.nodes.len();
    let (namespace, local) = match role {
        Role::Signature => (XADES, "SignatureTimeStamp"),
        Role::Archive => (XADES_141, "ArchiveTimeStamp"),
        Role::SignatureAndReferences => (XADES_141, "SigAndRefsTimeStampV2"),
        Role::ReferencesOnly => (XADES_141, "RefsOnlyTimeStampV2"),
        Role::AllDataObjects => (XADES, "AllDataObjectsTimeStamp"),
        Role::IndividualDataObjects => panic!("this fixture has no Include instructions"),
    };
    xml.nodes.push(element(Some(parent), namespace, local));
    xml.nodes
        .push(element(Some(property), DS, "CanonicalizationMethod"));
    let mut tokens = Vec::new();
    for _ in 0..count {
        tokens.push(xml.nodes.len());
        xml.nodes
            .push(element(Some(property), XADES, "EncapsulatedTimeStamp"));
    }
    (property, tokens)
}

#[test]
fn complete_timestamp_requirements_keep_own_archive_and_later_tokens() {
    // LT covers ALL incorporated tokens; the same selector's archive scope
    // excludes its own/later unsigned tokens without dropping signed ones.
    use structured_ltv::timestamp::{TimestampPathBinding, TimestampPathFailure, TimestampScope};
    use timestamp::TimestampSelection;
    let work = funded();
    let mut xml = preparation_tree();
    let (earlier, earlier_tokens) = append_timestamp(&mut xml, 7, Role::Archive, 2);
    let (archive, own) = append_timestamp(&mut xml, 7, Role::Archive, 2);
    let (later, later_tokens) = append_timestamp(&mut xml, 7, Role::Signature, 1);
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let at = prepared
        .timestamps()
        .iter()
        .position(|stamp| stamp.node() == archive)
        .unwrap();
    let first = &prepared.timestamps()[0];
    let before = work.used();
    let all = timestamp::requirements(&access, &prepared, TimestampSelection::All).unwrap();
    assert_eq!(
        all.scope(),
        TimestampScope::All(Location {
            snapshot: xml.snapshot(),
            node: 0
        })
    );
    let expected = [
        (first.node(), first.tokens()[0], Role::Signature.purpose()),
        (earlier, earlier_tokens[0], Role::Archive.purpose()),
        (earlier, earlier_tokens[1], Role::Archive.purpose()),
        (archive, own[0], Role::Archive.purpose()),
        (archive, own[1], Role::Archive.purpose()),
        (later, later_tokens[0], Role::Signature.purpose()),
    ];
    let actual: Vec<_> = all
        .entries()
        .iter()
        .map(|entry| (entry.property, entry.token, entry.purpose))
        .collect();
    assert_eq!(actual, expected);
    assert!(matches!(
        all.bind_paths(&[], &access).unwrap(),
        TimestampPathBinding::Unproven(TimestampPathFailure::Count)
    ));
    let prior =
        timestamp::requirements(&access, &prepared, TimestampSelection::BeforeArchive(at)).unwrap();
    assert_eq!(
        prior.scope(),
        TimestampScope::BeforeArchive(Location {
            snapshot: xml.snapshot(),
            node: archive
        })
    );
    let actual: Vec<_> = prior
        .entries()
        .iter()
        .map(|entry| (entry.property, entry.token, entry.purpose))
        .collect();
    assert_eq!(actual, expected[..3]);
    drop(prior);
    drop(all);
    assert_eq!(work.used(), before);
    assert_eq!(xml.streamed.get(), 0);
    for limit in [
        Memory::new(Arc::new(MemoryAccount::new(0, 1 << 24))),
        Memory::new(Arc::new(MemoryAccount::new(1 << 20, 0))),
    ] {
        let denied = Access::new(&xml, xml.snapshot(), &limit);
        assert!(matches!(
            timestamp::requirements(&denied, &prepared, TimestampSelection::All),
            Err(timestamp::RequirementError::Input(
                InputError::Resource { .. } | InputError::Access(AccessError::Resource { .. })
            ))
        ));
        assert_eq!(limit.used(), 0);
    }
    xml.generation.set(xml.generation.get() + 1);
    let stale = Access::new(&xml, xml.snapshot(), &work);
    assert!(matches!(
        timestamp::requirements(&stale, &prepared, TimestampSelection::All),
        Err(timestamp::RequirementError::Input(
            InputError::Foreign { .. }
        ))
    ));
}

#[test]
fn archive_prior_timestamp_census_includes_signed_tokens_and_every_earlier_archive_token() {
    // Discovery uses complete original preparation, not a supplied successful
    // token subset. Current/later unsigned tokens cannot be their own antecedents.
    let work = funded();
    let mut xml = preparation_tree();
    let (first, first_tokens) = append_timestamp(&mut xml, 7, Role::Archive, 2);
    let (current, own_tokens) = append_timestamp(&mut xml, 7, Role::Archive, 2);
    let (_, later_tokens) = append_timestamp(&mut xml, 7, Role::Signature, 1);
    let objects = xml
        .nodes
        .iter()
        .position(|record| {
            matches!(
                record.value,
                Node::Element(Name {
                    namespace: XADES,
                    local: "SignedDataObjectProperties"
                })
            )
        })
        .unwrap();
    let (signed, signed_tokens) = append_timestamp(&mut xml, objects, Role::AllDataObjects, 1);
    let access = Access::new(&xml, xml.snapshot(), &work);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let at = prepared
        .timestamps()
        .iter()
        .position(|stamp| stamp.node() == current)
        .unwrap();
    let original_signature = &prepared.timestamps()[0];
    let expected = [
        (
            original_signature.node(),
            original_signature.tokens()[0],
            Role::Signature.purpose(),
        ),
        (first, first_tokens[0], Role::Archive.purpose()),
        (first, first_tokens[1], Role::Archive.purpose()),
        (signed, signed_tokens[0], Role::AllDataObjects.purpose()),
    ];
    let before = work.used();
    let required = timestamp::requirements(
        &access,
        &prepared,
        timestamp::TimestampSelection::BeforeArchive(at),
    )
    .unwrap();
    assert_eq!(
        required.signature(),
        prepared.bound().containers().signature()
    );
    assert_eq!(
        required.scope(),
        structured_ltv::timestamp::TimestampScope::BeforeArchive(Location {
            snapshot: xml.snapshot(),
            node: current
        })
    );
    let actual: Vec<_> = required
        .entries()
        .iter()
        .map(|entry| (entry.property, entry.token, entry.purpose))
        .collect();
    assert_eq!(actual, expected);
    assert!(required.entries().iter().all(|entry| !own_tokens.contains(&entry.token) && !later_tokens.contains(&entry.token)));
    assert_eq!(xml.streamed.get(), 0);
    assert!(work.used() > before);
    drop(required);
    assert_eq!(work.used(), before);
    assert_prior_timestamp_refusals(&xml, &prepared, at);
    drop(prepared);
    assert_eq!(work.used(), 0);
}

fn assert_prior_timestamp_refusals(xml: &Tree, prepared: &prepare::Prepared<Tree>, at: usize) {
    // Caller misuse, storage/work exhaustion and stale generation never yield
    // an empty successful set or trigger token acquisition/provider side effects.
    use timestamp::{RequirementError, TimestampSelection};
    let work = funded();
    let access = Access::new(xml, xml.snapshot(), &work);
    assert!(matches!(
        timestamp::requirements(
            &access,
            prepared,
            TimestampSelection::BeforeArchive(prepared.timestamps().len())
        ),
        Err(RequirementError::Index { .. })
    ));
    assert!(matches!(
        timestamp::requirements(&access, prepared, TimestampSelection::BeforeArchive(0)),
        Err(RequirementError::Role { .. })
    ));
    assert_eq!(work.used(), 0);
    for limit in [
        Memory::new(Arc::new(MemoryAccount::new(0, 1 << 24))),
        Memory::new(Arc::new(MemoryAccount::new(1 << 20, 0))),
    ] {
        let access = Access::new(xml, xml.snapshot(), &limit);
        assert!(matches!(
            timestamp::requirements(&access, prepared, TimestampSelection::BeforeArchive(at)),
            Err(RequirementError::Input(
                InputError::Resource { .. } | InputError::Access(AccessError::Resource { .. })
            ))
        ));
        assert_eq!(limit.used(), 0);
    }
    xml.generation.set(xml.generation.get() + 1);
    let access = Access::new(xml, xml.snapshot(), &work);
    assert!(matches!(
        timestamp::requirements(&access, prepared, TimestampSelection::BeforeArchive(at)),
        Err(RequirementError::Input(InputError::Foreign { .. }))
    ));
    assert_eq!(work.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn prior_timestamp_paths_require_each_actual_original_token_not_one_repeated_success() {
    // A real common token check plus actual TSA path can satisfy its own
    // antecedent. It cannot cover a different, still unchecked archive token.
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    xml_digest::with_checked_path(|path, _, _, work| {
        let mut xml = preparation_tree();
        append_timestamp(&mut xml, 7, Role::Archive, 1);
        append_timestamp(&mut xml, 7, Role::Archive, 1);
        let access = Access::new(&xml, xml.snapshot(), work);
        let prepared =
            prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
        let stamp = &prepared.timestamps()[0];
        let method = u8::try_from(stamp.method()).unwrap();
        let (provider, token, cert_bytes, _) =
            timestamp_oracle::fixture_with_root(&[b'E', 12, b'M', method]);
        xml.binary = token;
        let parser = structured_asn1::Parser::der(work.clone());
        let certificate = structured_pkix::Certificate::read(&parser, &cert_bytes, 400).unwrap();
        let parent = parser.read(&[], 400).unwrap();
        let operation = parser.read(&[], 1200).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = structured_cms::timestamp::CheckContext {
            certificate: &certificate,
            certificate_parent: &parent,
            key: WorkingKey::standing(certificate.tbs().public_key()),
            requested: None,
            utc: &utc,
            reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
            window: None,
            policy_accuracy: None,
        };
        let check = timestamp::Check {
            xml: &xml,
            provider: &provider,
            context: &context,
        };
        let actor = check
            .retain_actor(prepared.bound(), stamp, 0, &operation, |_, _| {
                Ok::<_, ()>(false)
            })
            .unwrap()
            .expect("actual complete timestamp math and source binding");
        let structured_ltv::pki::TimestampBinding::Bound(bound) =
            path.bind_timestamp(&actor, &utc, work).unwrap()
        else {
            panic!("same original TSA certificate/key and complete generation interval")
        };
        assert_prior_path_receipts(&xml, &prepared, &bound, work);
        assert_eq!(provider.verified.get(), 1);
    });
}

fn assert_prior_path_receipts(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    path: &structured_ltv::pki::TimestampPath<'_, '_, '_, usize, u8, u8, structured_xades::Xades>,
    work: &Memory,
) {
    use structured_ltv::source::ScopeError;
    use structured_ltv::timestamp::{ObligationError, TimestampPathBinding, TimestampPathFailure};
    use timestamp::TimestampSelection;
    let access = Access::new(xml, xml.snapshot(), work);
    let archives: Vec<_> = prepared
        .timestamps()
        .iter()
        .enumerate()
        .filter_map(|(index, stamp)| (stamp.role() == Role::Archive).then_some(index))
        .collect();
    let first = timestamp::requirements(
        &access,
        prepared,
        TimestampSelection::BeforeArchive(archives[0]),
    )
    .unwrap();
    let paths = [path];
    let before = work.used();
    let TimestampPathBinding::Bound(bound) = first.bind_paths(&paths, &access).unwrap() else {
        panic!("complete actual original antecedent")
    };
    assert!(core::ptr::eq(bound.required(), &raw const first));
    assert_eq!(bound.paths().as_ptr(), paths.as_ptr());
    assert_eq!(work.used(), before);
    // Dispatch/metadata fit, but comparing the three original identity pairs
    // must also be admitted. One step per node is not its HashWork bound.
    let limited = Memory::new(Arc::new(MemoryAccount::new(0, 8)));
    let limited_access = Access::new(xml, xml.snapshot(), &limited);
    assert!(matches!(
        first.bind_paths(&paths, &limited_access),
        Err(ObligationError::Scope(ScopeError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        }))
    ));
    assert_eq!(limited.used(), 0);
    assert!(matches!(
        first.bind_paths(&[], &access).unwrap(),
        TimestampPathBinding::Unproven(TimestampPathFailure::Count)
    ));
    let second = timestamp::requirements(
        &access,
        prepared,
        TimestampSelection::BeforeArchive(archives[1]),
    )
    .unwrap();
    let repeats = [path, path];
    assert!(matches!(
        second.bind_paths(&repeats, &access).unwrap(),
        TimestampPathBinding::Unproven(TimestampPathFailure::Source { index: 1 })
    ));
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let denied_access = Access::new(xml, xml.snapshot(), &denied);
    assert!(matches!(
        first.bind_paths(&paths, &denied_access),
        Err(ObligationError::Scope(ScopeError::Resource { .. }))
    ));
    xml.generation.set(xml.generation.get() + 1);
    let stale = Access::new(xml, xml.snapshot(), work);
    assert!(matches!(
        first.bind_paths(&paths, &stale),
        Err(ObligationError::Foreign { .. })
    ));
}

#[test]
fn selected_source_preparation_never_leaves_signed_commitment_unprocessed() {
    // The cohesive entrypoint must reject malformed optional commitments and
    // retain valid associations before any timestamp/certificate execution.
    let memory = funded();
    let mut xml = preparation_tree();
    let parent = xml
        .nodes
        .iter()
        .position(|record| {
            matches!(
                record.value,
                Node::Element(Name {
                    namespace: XADES,
                    local: "SignedDataObjectProperties"
                })
            )
        })
        .unwrap();
    let node = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "CommitmentTypeIndication"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None),
        Err(prepare::Error::Commitment(commitment::AssociationError::Property(properties::Error::Missing { parent, local: "CommitmentTypeId" }))) if parent == node)
    );
    assert_eq!(memory.used(), 0);
    let kind = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "CommitmentTypeId"));
    let identifier = xml.nodes.len();
    xml.nodes.push(element(Some(kind), XADES, "Identifier"));
    xml.nodes.push(Record {
        parent: Some(identifier),
        value: Node::Text("https://example.test/commitment"),
    });
    xml.nodes
        .push(element(Some(node), XADES, "AllSignedDataObjects"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    assert_eq!(prepared.commitments().len(), 1);
    assert_eq!(prepared.commitments()[0].original().node(), node);
    assert_eq!(prepared.commitments()[0].objects().len(), 1);
    assert_eq!(prepared.commitments()[0].objects()[0].reference, 10);
    assert_eq!(xml.streamed.get(), 0);
    drop(prepared);
    assert_eq!(memory.used(), 0);
}

#[test]
fn preparation_refuses_policy_store_without_a_signed_explicit_policy_hash() {
    // EN6.3(m): unsigned policy bytes cannot qualify a signature with absent or
    // implied policy. Refusal must precede base64 decode/source/provider work.
    let memory = funded();
    let mut xml = preparation_tree();
    let store = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES_141, "SignaturePolicyStore"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None),
        Err(prepare::Error::Property(properties::Error::Forbidden { node })) if node == store)
    );
    assert_eq!(memory.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
    assert_eq!(xml.decoded_pointer.get(), 0);
    let declaration = xml.nodes.len();
    xml.nodes
        .push(element(Some(4), XADES, "SignaturePolicyIdentifier"));
    xml.nodes
        .push(element(Some(declaration), XADES, "SignaturePolicyImplied"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None),
        Err(prepare::Error::Property(properties::Error::Forbidden { node })) if node == store)
    );
    assert_eq!(memory.used(), 0);
    assert_eq!(xml.decoded_pointer.get(), 0);
}

#[test]
fn selected_source_preparation_refuses_partial_catalogue_and_rolls_back_all_storage() {
    // An incomplete authenticated Manifest catalogue cannot become a successful
    // Prepared value, even though the original signature binding was valid.
    let memory = funded();
    let mut xml = preparation_tree();
    xml.reference_completeness = Completeness::Unchecked(1);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        prepare::prepare(&access, 0, unsigned::Requirements::Basic, None),
        Err(prepare::Error::Format(format::CoverageError::Incomplete {
            node: 1
        }))
    ));
    assert_eq!(memory.used(), 0);
    xml.reference_completeness = Completeness::Complete;
    let no_storage = Memory::new(Arc::new(MemoryAccount::new(0, 300_000)));
    let access = Access::new(&xml, xml.snapshot(), &no_storage);
    assert!(matches!(
        prepare::prepare(&access, 0, unsigned::Requirements::Basic, None),
        Err(prepare::Error::Property(properties::Error::Resource { .. }))
    ));
    assert_eq!(no_storage.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn preparation_never_ignores_an_empty_renewed_digest_property() {
    // Optional-but-present archive input must satisfy its schema. Preserving
    // its outer name alone must not let missing methods/digests disappear.
    let mut xml = preparation_tree();
    let node = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES_141, "RenewedDigestsV2"));
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(prepare::prepare(&access, 0, unsigned::Requirements::Basic, None),
        Err(prepare::Error::Property(properties::Error::Missing { parent, local: "CanonicalizationMethod" })) if parent == node)
    );
    assert_eq!(memory.used(), 0);
}

fn renewed_tree() -> (Tree, usize, usize, usize, usize, usize) {
    let mut xml = preparation_tree();
    let node = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES_141, "RenewedDigestsV2"));
    let canonicalization = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), DS, "CanonicalizationMethod"));
    let digest = xml.nodes.len();
    xml.nodes.push(element(Some(node), DS, "DigestMethod"));
    let pair = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES_141, "RecomputedDigestValue"));
    let object = xml.nodes.len();
    xml.nodes
        .push(element(Some(pair), XADES_141, "NewSDODigestValue"));
    let reference = xml.nodes.len();
    xml.nodes
        .push(element(Some(pair), XADES_141, "OriginalRefDigest"));
    (xml, node, canonicalization, digest, object, reference)
}

#[test]
fn renewed_digest_preparation_retains_both_original_roles_without_hashing_or_promotion() {
    // Reference-instruction and detached-object digests are different inputs.
    // Ordered pairs must survive preparation without replay, acquisition or
    // treating their mere presence as authenticated Manifest/digest agreement.
    let (mut xml, node, method, digest, object, reference) = renewed_tree();
    let second = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES_141, "RecomputedDigestValue"));
    xml.nodes
        .push(element(Some(second), XADES_141, "NewSDODigestValue"));
    xml.nodes
        .push(element(Some(second), XADES_141, "OriginalRefDigest"));
    let memory = funded();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let value = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
    assert_eq!(value.renewed().len(), 1);
    let renewed = &value.renewed()[0];
    assert_eq!(renewed.snapshot(), xml.snapshot());
    assert_eq!(renewed.signature(), 0);
    assert_eq!(renewed.node(), node);
    assert_eq!(renewed.canonicalization(), method);
    assert_eq!(renewed.digest(), digest);
    assert_eq!(renewed.pairs().len(), 2);
    assert_eq!(renewed.pairs()[0].object, object);
    assert_eq!(renewed.pairs()[0].reference, reference);
    assert_eq!(renewed.pairs()[1].node, second);
    assert_eq!(renewed.pairs()[1].object, second + 1);
    assert_eq!(renewed.pairs()[1].reference, second + 2);
    assert_eq!(xml.streamed.get(), 0);
    assert_eq!(xml.decoded_pointer.get(), 0);
    drop(value);
    assert_eq!(memory.used(), 0);
}

#[test]
fn renewed_digest_shape_rejects_swapped_extra_missing_and_complex_digest_values() {
    // All optional-but-present fields follow the 1.4.1 schema. Never confuse
    // the two digest roles or flatten nested elements into a base64 value.
    for kind in 0..4 {
        let (mut xml, node, _, _, object, reference) = renewed_tree();
        let bad = match kind {
            0 => {
                xml.nodes.swap(object, reference);
                object
            }
            1 => {
                let bad = xml.nodes.len();
                xml.nodes
                    .push(element(Some(object - 1), XADES_141, "OriginalRefDigest"));
                bad
            }
            2 => {
                xml.nodes.pop();
                object - 1
            }
            _ => {
                let bad = xml.nodes.len();
                xml.nodes
                    .push(element(Some(object), "urn:payload", "nested"));
                bad
            }
        };
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let result = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None);
        if kind == 2 {
            assert!(
                matches!(result, Err(prepare::Error::Property(properties::Error::Missing { parent, local: "OriginalRefDigest" })) if parent == bad)
            );
        } else {
            assert!(
                matches!(result, Err(prepare::Error::Property(properties::Error::Unexpected { node })) if node == bad)
            );
        }
        assert_eq!(memory.used(), 0);
        assert_eq!(xml.streamed.get(), 0);
        assert!(node < xml.nodes.len());
    }
}

#[test]
fn renewed_digest_catalogue_uses_current_work_and_releases_partial_capacity() {
    // Retained unsigned metadata supplies no credit for a later query. Stale
    // sources and current storage/work refusal must not produce an empty set.
    let (xml, _, _, _, _, _) = renewed_tree();
    let storage = funded();
    let access = Access::new(&xml, xml.snapshot(), &storage);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::Basic).unwrap();
    let index = inventory
        .entries()
        .iter()
        .position(|e| e.role == unsigned::Role::RenewedDigests)
        .unwrap();
    let execution = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    let query = Access::new(&xml, xml.snapshot(), &execution);
    assert!(matches!(
        structured_xades::renewed::read(&query, &inventory, index),
        Err(properties::Error::Resource { .. })
    ));
    assert_eq!(execution.used(), 0);
    let execution = Memory::new(Arc::new(MemoryAccount::new(100_000, 0)));
    let query = Access::new(&xml, xml.snapshot(), &execution);
    assert!(matches!(
        structured_xades::renewed::read(&query, &inventory, index),
        Err(properties::Error::Access(AccessError::Resource { .. }))
    ));
    xml.generation.set(2);
    let query = Access::new(&xml, xml.snapshot(), &storage);
    assert!(matches!(
        structured_xades::renewed::read(&query, &inventory, index),
        Err(properties::Error::Access(AccessError::Changed { .. }))
    ));
    drop(inventory);
    assert_eq!(storage.used(), 0);
}

#[test]
fn selected_source_preparation_checks_late_timestamp_shape_without_hashing_or_dropping_it() {
    // Valid early properties do not excuse a malformed later timestamp. The
    // complete preparation fails before source/hash/provider callbacks.
    let memory = funded();
    let mut xml = preparation_tree();
    xml.nodes.pop();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None),
        Err(prepare::Error::Timestamp(InputError::Missing {
            node: 8,
            local: "EncapsulatedTimeStamp"
        }))
    ));
    assert_eq!(memory.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
    assert_eq!(xml.decoded_pointer.get(), 0);
}

fn role_tree() -> (Tree, usize, usize, usize) {
    let (mut xml, _) = certificate_tree();
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(4), XADES, "SignerRoleV2"));
    let claims = xml.nodes.len();
    xml.nodes.push(element(Some(node), XADES, "ClaimedRoles"));
    xml.nodes.push(element(Some(claims), XADES, "ClaimedRole"));
    let certificates = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "CertifiedRolesV2"));
    let certified = xml.nodes.len();
    xml.nodes
        .push(element(Some(certificates), XADES, "CertifiedRole"));
    xml.nodes
        .push(element(Some(certified), XADES, "X509AttributeCertificate"));
    let assertions = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "SignedAssertions"));
    xml.nodes
        .push(element(Some(assertions), XADES, "SignedAssertion"));
    (xml, node, certified, assertions)
}

#[test]
fn signed_role_catalogue_keeps_all_original_credential_kinds_without_trust_promotion() {
    // Role claims, an X509 attribute certificate and signed assertion retain
    // independent syntax/provenance, not a single fabricated authenticated role.
    let memory = funded();
    let (xml, node, _, _) = role_tree();
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let reading = role::read(&access, &signed).unwrap().unwrap();
    assert_eq!(reading.snapshot(), xml.snapshot());
    assert_eq!(reading.signature(), 0);
    assert_eq!(reading.node(), node);
    assert_eq!(reading.entries().len(), 3);
    assert_eq!(reading.entries()[0].kind, role::Kind::Claimed);
    assert_eq!(reading.entries()[1].kind, role::Kind::AttributeCertificate);
    assert_eq!(reading.entries()[2].kind, role::Kind::Assertion);
    let held = memory.used();
    drop(reading);
    assert!(memory.used() < held);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn signed_role_groups_preserve_order_nonempty_members_and_exclusive_certificate_choice() {
    // One valid credential cannot hide a second child in its exclusive choice.
    let memory = funded();
    let (mut xml, _, certified, assertions) = role_tree();
    let extra = xml.nodes.len();
    xml.nodes
        .push(element(Some(certified), XADES, "OtherAttributeCertificate"));
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(role::read(&access, &signed), Err(properties::Error::Unexpected { node }) if node == extra)
    );
    xml.nodes.pop();
    xml.nodes[assertions + 1].parent = Some(1);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(role::read(&access, &signed), Err(properties::Error::Missing { parent, .. }) if parent == assertions)
    );
}

#[test]
fn role_credential_presence_conditions_attribute_material_without_authenticating_it() {
    // §6.3(r/s/w) forbids attribute material with no independent credential.
    // Passing this presence test is not validation of the assertion/certificate.
    let memory = funded();
    let (mut xml, _, _, _) = role_tree();
    let material = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES, "AttributeRevocationValues"));
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::LongTerm).unwrap();
    assert!(
        matches!(unsigned::check_credential_material(&access, &inventory, None), Err(properties::Error::Forbidden { node }) if node == material)
    );
    let roles = role::read(&access, &signed).unwrap().unwrap();
    // Credential presence is a new retained-source query: reject an unfunded
    // signature equality before traversing roles or inventory entries.
    let short = Memory::new(Arc::new(MemoryAccount::new(0, 1)));
    let lower = Access::new(&xml, xml.snapshot(), &short);
    assert!(matches!(
        unsigned::check_credential_material(&lower, &inventory, Some(&roles)),
        Err(properties::Error::Access(AccessError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        }))
    ));
    assert_eq!(short.work_remaining(), 1);
    unsigned::check_credential_material(&access, &inventory, Some(&roles)).unwrap();
    let zero = self::memory(0);
    let access = Access::new(&xml, xml.snapshot(), &zero);
    assert!(matches!(
        unsigned::check_credential_material(&access, &inventory, Some(&roles)),
        Err(properties::Error::Access(AccessError::Resource { .. }))
    ));
}

#[test]
fn unsigned_inventory_preserves_profile_requirements_without_claiming_timestamp_evidence() {
    // Table2 has required container presence; it does not make an empty token
    // cryptographically valid or make a material count prove B-LT completeness.
    let memory = funded();
    let mut xml = Tree::normal();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    for requirements in [
        unsigned::Requirements::Basic,
        unsigned::Requirements::Timestamped,
        unsigned::Requirements::LongTerm,
    ] {
        let inventory = unsigned::read(&access, &bound, requirements).unwrap();
        assert_eq!(inventory.snapshot(), xml.snapshot());
        assert_eq!(inventory.signature(), 0);
        assert_eq!(inventory.parent(), Some(7));
        assert_eq!(inventory.entries().len(), 1);
        assert_eq!(
            inventory.entries()[0].role,
            unsigned::Role::SignatureTimestamp
        );
    }
    assert!(matches!(
        unsigned::read(&access, &bound, unsigned::Requirements::Archival),
        Err(properties::Error::Missing {
            parent: 0,
            local: "ArchiveTimeStamp"
        })
    ));
    let archive = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES_141, "ArchiveTimeStamp"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::Archival).unwrap();
    assert_eq!(inventory.entries()[1].node, archive);
    assert_eq!(inventory.entries()[1].role, unsigned::Role::Archive);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn unsigned_reference_only_forms_are_not_long_term_validation_material() {
    // Current baseline forbids legacy spellings at all levels. V2 reference-only
    // forms remain readable for B-B/B-T but cannot substitute for LT/LTA values.
    let memory = funded();
    let mut xml = Tree::normal();
    let reference = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES_141, "CompleteCertificateRefsV2"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::Timestamped).unwrap();
    assert_eq!(
        inventory.entries()[1].role,
        unsigned::Role::CertificateReferences
    );
    for requirements in [
        unsigned::Requirements::LongTerm,
        unsigned::Requirements::Archival,
    ] {
        assert!(
            matches!(unsigned::read(&access, &bound, requirements), Err(properties::Error::Forbidden { node }) if node == reference)
        );
    }
    xml.nodes[reference].value = Node::Element(Name {
        namespace: XADES,
        local: "CompleteCertificateRefs",
    });
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(unsigned::read(&access, &bound, unsigned::Requirements::Basic), Err(properties::Error::Forbidden { node }) if node == reference)
    );
}

#[test]
fn unsigned_catalogue_rejects_duplicate_material_and_preserves_foreign_extensions_and_data() {
    // AnyValidationData is repeatable; CertificateValues is singleton. Unknown
    // foreign properties stay explicit, while absent-namespace nodes are invalid.
    let memory = funded();
    let mut xml = Tree::normal();
    let entry = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "CertificateValues"));
    let extra = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "CertificateValues"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let before = memory.used();
    assert!(
        matches!(unsigned::read(&access, &bound, unsigned::Requirements::Basic), Err(properties::Error::Duplicate { node }) if node == extra)
    );
    assert_eq!(memory.used(), before);
    xml.nodes[entry].value = Node::Element(Name {
        namespace: XADES_141,
        local: "AnyValidationData",
    });
    xml.nodes[extra].value = Node::Element(Name {
        namespace: XADES_141,
        local: "AnyValidationData",
    });
    let foreign = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), "urn:foreign", "FutureProperty"));
    let data = xml.nodes.len();
    xml.nodes
        .push(element(Some(6), XADES, "UnsignedDataObjectProperties"));
    xml.nodes
        .push(element(Some(data), XADES, "UnsignedDataObjectProperty"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::Basic).unwrap();
    assert_eq!(inventory.entries().len(), 4);
    assert_eq!(inventory.entries()[3].role, unsigned::Role::Extension);
    assert_eq!(inventory.data_objects(), Some(data));
    xml.nodes[foreign].value = Node::Element(Name {
        namespace: "",
        local: "FutureProperty",
    });
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(unsigned::read(&access, &bound, unsigned::Requirements::Basic), Err(properties::Error::Unexpected { node }) if node == foreign)
    );
}

#[test]
fn unsigned_inventory_capacity_refusal_releases_partial_catalogue() {
    // A failed catalogue cannot be used as an empty successful material set.
    let memory = funded();
    let xml = Tree::normal();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let no_storage = Memory::new(Arc::new(MemoryAccount::new(0, 300_000)));
    let access = Access::new(&xml, xml.snapshot(), &no_storage);
    assert!(matches!(
        unsigned::read(&access, &bound, unsigned::Requirements::Basic),
        Err(properties::Error::Resource { node: 8, .. })
    ));
    assert_eq!(no_storage.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn baseline_header_requires_original_x509_data_and_selected_certificate_bytes() {
    // EN6.3(a) requires actual signing-certificate inclusion. A nonempty
    // X509Data, certificate count or key-association receipt cannot substitute
    // for comparing the candidate's complete original DER.
    let memory = funded();
    let bytes = candidate_certificate();
    let parser = structured_asn1::Parser::der(memory.clone());
    let candidate = structured_pkix::Certificate::read(&parser, &bytes, 900).unwrap();
    let (mut xml, data, cert, method) = header_tree();
    xml.binary = bytes.clone();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let reading = header::read(&access, &bound).unwrap();
    assert_eq!(reading.snapshot(), xml.snapshot());
    assert_eq!(reading.signature(), 0);
    assert_eq!(reading.key_info(), 13);
    assert_eq!(reading.x509_data(), data);
    assert_eq!(reading.method(), method);
    assert_eq!(reading.certificates(), &[cert]);
    let location = header::included(&xml, &reading, &candidate, &memory)
        .unwrap()
        .unwrap();
    assert_eq!(location.node, cert);
    assert_eq!(location.snapshot, xml.snapshot());
    xml.binary[bytes.len() - 1] ^= 1;
    assert!(
        header::included(&xml, &reading, &candidate, &memory)
            .unwrap()
            .is_none()
    );
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn baseline_header_rejects_missing_or_duplicate_roles_and_unknown_canonicalization() {
    // The baseline fixes one X509Data, at least one certificate and six
    // canonicalization identities, independently of a permissive XML provider.
    let memory = funded();
    let (mut xml, data, cert, method) = header_tree();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    xml.nodes[cert].value = Node::Element(Name {
        namespace: DS,
        local: "X509SubjectName",
    });
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(header::read(&access, &bound), Err(properties::Error::Missing { parent, local: "X509Certificate" }) if parent == data)
    );
    xml.nodes[cert].value = Node::Element(Name {
        namespace: DS,
        local: "X509Certificate",
    });
    let duplicate = xml.nodes.len();
    xml.nodes.push(element(Some(13), DS, "X509Data"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(header::read(&access, &bound), Err(properties::Error::Duplicate { node }) if node == duplicate)
    );
    xml.nodes.pop();
    for algorithm in [None, Some("urn:unknown-canonicalizer")] {
        xml.digest_algorithm = algorithm;
        let access = Access::new(&xml, xml.snapshot(), &memory);
        assert!(
            matches!(header::read(&access, &bound), Err(properties::Error::Unexpected { node }) if node == method)
        );
    }
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn baseline_header_keeps_resource_and_generation_failure_separate_from_missing_certificate() {
    // All header catalogue capacity and certificate scans belong to the current
    // operation. Failure cannot return a partial successful header or mismatch.
    let memory = funded();
    let (xml, _, _, _) = header_tree();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let zero = self::memory(0);
    let access = Access::new(&xml, xml.snapshot(), &zero);
    assert!(matches!(
        header::read(&access, &bound),
        Err(properties::Error::Child(
            structured_xades::xml::ChildError::Access(AccessError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            })
        ))
    ));
    let no_storage = Memory::new(Arc::new(MemoryAccount::new(0, 300_000)));
    let access = Access::new(&xml, xml.snapshot(), &no_storage);
    assert!(matches!(
        header::read(&access, &bound),
        Err(properties::Error::Resource { .. })
    ));
    assert_eq!(no_storage.used(), 0);
    xml.generation.set(2);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        header::read(&access, &bound),
        Err(properties::Error::Access(AccessError::Changed { node: 0 }))
    ));
}

#[test]
fn signing_certificate_references_preserve_all_original_roles_and_owned_capacity() {
    // First reference remains first: an acquisition/issuer hint is not a digest
    // binding and this schema reading cannot promote it into path acceptance.
    let memory = funded();
    let (xml, [property, cert, _, method, value, issuer]) = certificate_tree();
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let refs = certificate::read(&access, &signed).unwrap();
    assert_eq!(refs.snapshot(), xml.snapshot());
    assert_eq!(refs.signature(), 0);
    assert_eq!(refs.node(), property);
    assert_eq!(refs.entries().len(), 1);
    let reference = refs.entries()[0];
    assert_eq!(reference.node(), cert);
    assert_eq!(reference.method(), method);
    assert_eq!(reference.digest(), value);
    assert_eq!(reference.issuer_serial(), Some(issuer));
    assert!(memory.used() > 0);
    drop(refs);
    assert_eq!(memory.used(), 0);
}

#[test]
fn certificate_reference_schema_never_borrows_fields_from_adjacent_roles() {
    // Exact expanded names and direct order are required. Empty or incomplete
    // certificate entries cannot borrow digest fields from another subtree.
    let memory = funded();
    let (mut xml, [property, cert, digest, _, value, _]) = certificate_tree();
    xml.nodes[value] = element(Some(digest), XADES, "DigestValue");
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(certificate::read(&access, &signed), Err(properties::Error::Unexpected { node }) if node == value)
    );
    xml.nodes[value] = element(Some(cert), DS, "DigestValue");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(certificate::read(&access, &signed), Err(properties::Error::Unexpected { node }) if node == value)
    );
    xml.nodes[cert].parent = None;
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(certificate::read(&access, &signed), Err(properties::Error::Missing { parent, local: "Cert" }) if parent == property)
    );
    assert_eq!(memory.used(), 0);
}

#[test]
fn certificate_reference_retention_refusal_is_not_an_empty_success() {
    // Header traversal needs no storage, but publishing the actual catalogue
    // reserves its complete capacity first and preserves an admission error.
    let memory = memory(100_000);
    let (xml, _) = certificate_tree();
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        certificate::read(&access, &signed),
        Err(properties::Error::Resource { .. })
    ));
    assert_eq!(memory.used(), 0);
}

fn candidate_certificate() -> Vec<u8> {
    // Synthetic readable certificate, not a signature or trust fixture.
    fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
        assert!(bytes.len() < 128);
        let mut value = vec![tag, u8::try_from(bytes.len()).unwrap()];
        value.extend_from_slice(bytes);
        value
    }
    let algorithm = [0x30, 3, 6, 1, 42];
    let name = [0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, b'a'];
    let mut tbs = vec![0xa0, 3, 2, 1, 2, 2, 1, 1];
    tbs.extend(algorithm);
    tbs.extend(name);
    let mut validity = tlv(0x17, b"260101000000Z");
    validity.extend(tlv(0x17, b"270101000000Z"));
    tbs.extend(tlv(0x30, &validity));
    tbs.extend(name);
    let mut key = algorithm.to_vec();
    key.extend([3, 2, 0, 1]);
    tbs.extend(tlv(0x30, &key));
    let mut cert = tlv(0x30, &tbs);
    cert.extend(algorithm);
    cert.extend([3, 2, 0, 8]);
    tlv(0x30, &cert)
}

#[derive(Clone, Copy)]
enum DigestMode {
    Available,
    Unsupported,
    Malformed,
    Refused,
}

struct WholeCertificate {
    mode: DigestMode,
    method: usize,
    calls: Cell<usize>,
    pointer: Cell<usize>,
}

impl certificate::DigestProvider<'_, Tree> for WholeCertificate {
    fn classify(&self, (): &()) -> structured_xades::hashes::HashClass {
        // Scripted non-MD5 capability for byte-flow controls only; this
        // checksum oracle is explicitly not cryptographic qualification.
        structured_xades::hashes::HashClass::OtherKnown
    }

    fn resolve<W: Work>(
        &self,
        access: &Access<'_, Tree, W>,
        method: usize,
    ) -> Result<DigestResolution<()>, MemoryError> {
        // Test-only resolver: it checks source selection, not real URI policy.
        assert_eq!(method, self.method);
        assert!(
            access
                .has_name(
                    method,
                    Name {
                        namespace: DS,
                        local: "DigestMethod"
                    }
                )
                .unwrap()
        );
        match self.mode {
            DigestMode::Available => Ok(DigestResolution::Supported(())),
            DigestMode::Unsupported => Ok(DigestResolution::Unsupported),
            DigestMode::Malformed => Ok(DigestResolution::Malformed),
            DigestMode::Refused => Err(MemoryError::WorkExceeded),
        }
    }
}

// Deliberate non-cryptographic XOR checksum checks data flow and admission.
// This test cannot qualify cryptographic math, XML policy or path trust.
impl Digest<'_> for WholeCertificate {
    type Identity = ();
    type State = u8;
    type Output = [u8; 1];
    type Error = MemoryError;

    fn width(&self, (): &()) -> Option<usize> {
        Some(1)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), _: &W) -> Result<Ordering, MemoryError> {
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), _: &W) -> Result<DigestResolution<u8>, MemoryError> {
        Ok(DigestResolution::Supported(0))
    }
    fn update<W: Work>(
        &self,
        checksum: &mut u8,
        certificate: &[u8],
        execution: &W,
    ) -> Result<(), MemoryError> {
        execution.charge_work(u64::try_from(certificate.len()).unwrap())?;
        self.calls.set(self.calls.get() + 1);
        self.pointer.set(certificate.as_ptr() as usize);
        for byte in certificate {
            *checksum ^= byte;
        }
        Ok(())
    }
    fn finish<W: Work>(&self, checksum: u8, _: &W) -> Result<[u8; 1], MemoryError> {
        Ok([checksum])
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &[u8; 1],
        expected: &[u8],
        execution: &W,
    ) -> Result<bool, MemoryError> {
        execution.charge_work(u64::try_from(expected.len()).unwrap())?;
        Ok(expected == output)
    }
}

#[test]
fn certificate_digest_compares_complete_original_bytes_without_materialization() {
    // Only the selected provider hashes: the core passes the exact original
    // certificate pointer and never re-encodes or accumulates a chunk copy.
    let memory = funded();
    let bytes = candidate_certificate();
    let parser = structured_asn1::Parser::der(memory.clone());
    let candidate = structured_pkix::Certificate::read(&parser, &bytes, 900).unwrap();
    let mut checksum = 0;
    for byte in &bytes {
        checksum ^= byte;
    }
    let (mut xml, [_, _, _, method, _, _]) = certificate_tree();
    xml.binary = vec![checksum];
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let refs = certificate::read(&access, &signed).unwrap();
    let provider = WholeCertificate {
        mode: DigestMode::Available,
        method,
        calls: Cell::new(0),
        pointer: Cell::new(0),
    };
    let held = memory.used();
    assert_eq!(
        certificate::compare(&xml, &refs, 0, &candidate, &provider, &memory).unwrap(),
        certificate::Agreement::Matches
    );
    assert_eq!(provider.calls.get(), 1);
    assert_eq!(provider.pointer.get(), bytes.as_ptr() as usize);
    assert_eq!(memory.used(), held);
    xml.binary = vec![checksum ^ 1];
    assert_eq!(
        certificate::compare(&xml, &refs, 0, &candidate, &provider, &memory).unwrap(),
        certificate::Agreement::Differs
    );
}

#[test]
fn certificate_digest_preflights_width_and_keeps_provider_refusal_distinct() {
    // Unsupported/malformed method and impossible value width do not hash the
    // certificate. A callback resource error never becomes a semantic mismatch.
    let memory = funded();
    let bytes = candidate_certificate();
    let parser = structured_asn1::Parser::der(memory.clone());
    let candidate = structured_pkix::Certificate::read(&parser, &bytes, 900).unwrap();
    let (mut xml, [_, _, _, method, _, _]) = certificate_tree();
    xml.binary = vec![0, 0];
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let refs = certificate::read(&access, &signed).unwrap();
    let mut provider = WholeCertificate {
        mode: DigestMode::Available,
        method,
        calls: Cell::new(0),
        pointer: Cell::new(0),
    };
    for (mode, expected) in [
        (
            DigestMode::Available,
            certificate::Agreement::MalformedValue,
        ),
        (DigestMode::Unsupported, certificate::Agreement::Unsupported),
        (
            DigestMode::Malformed,
            certificate::Agreement::MalformedMethod,
        ),
    ] {
        provider.mode = mode;
        assert_eq!(
            certificate::compare(&xml, &refs, 0, &candidate, &provider, &memory).unwrap(),
            expected
        );
    }
    assert_eq!(provider.calls.get(), 0);
    provider.mode = DigestMode::Refused;
    assert!(matches!(
        certificate::compare(&xml, &refs, 0, &candidate, &provider, &memory),
        Err(binary::Error::Callback {
            cause: certificate::DigestError::Provider(MemoryError::WorkExceeded),
            ..
        })
    ));
    assert!(matches!(
        certificate::compare(&xml, &refs, 1, &candidate, &provider, &memory),
        Err(binary::Error::Callback {
            cause: certificate::DigestError::ReferenceIndex { index: 1 },
            ..
        })
    ));
    assert_eq!(provider.calls.get(), 0);
}

#[test]
fn encapsulated_default_der_does_not_accept_a_ber_outer_header() {
    // EN319132-1 §5.1.3 makes absent Encoding mean DER. A readable BER token
    // must not silently inherit the envelope reader's leniency in that branch.
    let memory = funded();
    let parser = structured_asn1::Parser::ber(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = Tree::normal();
    xml.binary = binary_token();
    let length = xml.binary[1];
    xml.binary[1] = 0x81;
    xml.binary.insert(2, length);
    let location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    let called = Cell::new(false);
    assert!(
        binary::with_token(&xml, location, &operation, |_, _| {
            called.set(true);
            Ok::<_, ()>(())
        })
        .is_err()
    );
    assert!(!called.get());
    assert_eq!(memory.used(), 0);
    xml.binary_encoding = Some(" \thttp://uri.etsi.org/01903/v1.2.2#BER\n");
    binary::with_token(&xml, location, &operation, |_, _| {
        called.set(true);
        Ok::<_, ()>(())
    })
    .unwrap();
    assert!(called.get());
    assert_eq!(memory.used(), 0);
}

#[test]
fn unsupported_pki_encoding_is_not_malformed_or_silently_treated_as_ber() {
    // Recognized unimplemented codecs and unknown Encoding URIs have distinct
    // outcomes, both before decoded-capacity admission and token callbacks.
    let memory = funded();
    let parser = structured_asn1::Parser::ber(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = Tree::normal();
    xml.binary = binary_token();
    let location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    let called = Cell::new(false);
    for (uri, encoding) in [
        (
            "http://uri.etsi.org/01903/v1.2.2#CER",
            binary::PkiEncoding::Cer,
        ),
        (
            "http://uri.etsi.org/01903/v1.2.2#PER",
            binary::PkiEncoding::Per,
        ),
        (
            "http://uri.etsi.org/01903/v1.2.2#XER",
            binary::PkiEncoding::Xer,
        ),
    ] {
        xml.binary_encoding = Some(uri);
        assert!(
            matches!(binary::with_token(&xml, location, &operation, |_, _| {
            called.set(true);
            Ok::<_, ()>(())
        }), Err(binary::Error::UnsupportedEncoding { encoding: actual, .. }) if actual == encoding)
        );
    }
    xml.binary_encoding = Some("urn:unknown");
    assert!(matches!(
        binary::with_token(&xml, location, &operation, |_, _| {
            called.set(true);
            Ok::<_, ()>(())
        }),
        Err(binary::Error::UnknownEncoding { .. })
    ));
    assert!(!called.get());
    assert_eq!(memory.used(), 0);
}

#[test]
fn certificate_digest_alone_does_not_prove_selected_signature_key_association() {
    // A missing receipt is distinct from failed math or distrust. Even a full
    // digest match must not manufacture the missing selected-key association.
    fn identity_domain<
        'v,
        'd,
        X: Xml,
        Y: Xml<Id = X::Id, Document = X::Document, Generation = X::Generation>,
    >(
        value: certificate::Checked<'v, 'd, X>,
    ) -> certificate::Checked<'v, 'd, Y> {
        value
    }
    let memory = funded();
    let bytes = candidate_certificate();
    let parser = structured_asn1::Parser::der(memory.clone());
    let candidate = structured_pkix::Certificate::read(&parser, &bytes, 900).unwrap();
    let mut checksum = 0;
    for byte in &bytes {
        checksum ^= byte;
    }
    let (mut xml, [_, _, _, method, _, _]) = certificate_tree();
    xml.binary = vec![checksum];
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let signed = properties::read(&access, &bound).unwrap();
    let refs = certificate::read(&access, &signed).unwrap();
    let provider = WholeCertificate {
        mode: DigestMode::Available,
        method,
        calls: Cell::new(0),
        pointer: Cell::new(0),
    };
    for association in [
        certificate::KeyAssociation::Unproven,
        certificate::KeyAssociation::Differs,
        certificate::KeyAssociation::Same,
    ] {
        xml.key_association = association;
        let checked =
            certificate::check(&xml, &bound, &refs, &candidate, &provider, &memory).unwrap();
        let checked = identity_domain::<Tree, Tree>(checked);
        assert_eq!(checked.digest(), certificate::Agreement::Matches);
        assert_eq!(checked.key(), association);
        assert_eq!(
            checked.is_bound(),
            association == certificate::KeyAssociation::Same
        );
        assert!(core::ptr::eq(
            checked.certificate(),
            core::ptr::from_ref(&candidate)
        ));
        assert!(core::ptr::eq(
            checked.reference(),
            core::ptr::from_ref(&refs)
        ));
    }
}

#[test]
fn certificate_catalogue_from_another_signature_is_rejected_before_provider_work() {
    // Both signatures are in one source generation. Matching node-local numbers
    // or certificate digests cannot move one signature's signed properties to another.
    let memory = funded();
    let bytes = candidate_certificate();
    let parser = structured_asn1::Parser::der(memory.clone());
    let candidate = structured_pkix::Certificate::read(&parser, &bytes, 900).unwrap();
    let (mut xml, [_, _, _, method, _, _]) = certificate_tree();
    let other_signature = xml.nodes.len();
    xml.nodes.push(element(Some(1), DS, "Signature"));
    let object = xml.nodes.len();
    xml.nodes.push(element(Some(other_signature), DS, "Object"));
    let qualifying = xml.nodes.len();
    xml.nodes
        .push(element(Some(object), XADES, "QualifyingProperties"));
    let properties = xml.nodes.len();
    xml.nodes
        .push(element(Some(qualifying), XADES, "SignedProperties"));
    let parent = xml.nodes.len();
    xml.nodes.push(element(
        Some(properties),
        XADES,
        "SignedSignatureProperties",
    ));
    xml.nodes.push(element(Some(parent), XADES, "SigningTime"));
    let signed_info = xml.nodes.len();
    xml.nodes
        .push(element(Some(other_signature), DS, "SignedInfo"));
    let first = xml.nodes.len();
    xml.nodes.push(element(Some(signed_info), DS, "Reference"));
    let second = xml.nodes.len();
    xml.nodes.push(element(Some(signed_info), DS, "Reference"));
    xml.nodes
        .push(element(Some(other_signature), DS, "SignatureValue"));
    let refs = {
        let signed = signed_roles(&xml, &memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        certificate::read(&access, &signed).unwrap()
    };
    xml.target = Target::LocalBareName(other_signature);
    xml.references[0].node = first;
    xml.references[1].node = second;
    xml.references[1].target = Some(properties);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, other_signature).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let provider = WholeCertificate {
        mode: DigestMode::Available,
        method,
        calls: Cell::new(0),
        pointer: Cell::new(0),
    };
    // Even a foreign catalogue cannot perform its identity comparison for free.
    // Admission must precede ForeignCatalogue and all provider callbacks.
    for budget in [0, 1] {
        let current = Memory::new(Arc::new(MemoryAccount::new(0, budget)));
        assert!(matches!(
            certificate::check(&xml, &bound, &refs, &candidate, &provider, &current),
            Err(certificate::CheckError::Access(AccessError::Resource {
                node, cause: MemoryError::WorkExceeded
            })) if node == refs.node()
        ));
        assert_eq!(current.used(), 0);
        assert_eq!(provider.calls.get(), 0);
    }
    assert!(
        matches!(certificate::check(&xml, &bound, &refs, &candidate, &provider, &memory), Err(certificate::CheckError::ForeignCatalogue { signature, .. }) if signature == other_signature)
    );
    assert_eq!(provider.calls.get(), 0);
}

#[test]
fn issuer_hint_reuses_shared_kernel_and_retains_faults_with_xml_location() {
    // The hint is a standalone RFC5035 IssuerSerial, not a fake ESS attribute.
    // Empty GeneralNames remains readable with its original adverse diagnostic.
    let memory = funded();
    let retained = {
        let (mut xml, [_, _, _, _, _, issuer]) = certificate_tree();
        xml.binary = vec![0x30, 5, 0x30, 0, 2, 1, 7];
        let signed = signed_roles(&xml, &memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let refs = certificate::read(&access, &signed).unwrap();
        let parser = structured_asn1::Parser::ber(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let value = certificate::with_issuer_serial(&xml, &refs, 0, &operation, |reading| {
            assert_eq!(reading.value().serial().as_u64(), Some(7));
            let (_, faults) = reading.into_parts();
            Ok::<_, ()>(faults)
        })
        .unwrap()
        .unwrap();
        assert_eq!(
            value.location,
            Location {
                snapshot: xml.snapshot(),
                node: issuer
            }
        );
        value
    };
    assert_eq!(retained.value.len(), 1);
    assert_eq!(
        retained.value[0].code(),
        structured_cms::ErrorCode::AttributeSyntax
    );
    assert_eq!(retained.value[0].field(), "xades.issuerSerialV2");
    assert_eq!(retained.value[0].offset(), 2); // Decoded source, never XML byte 902.
    assert!(memory.used() > 0);
    drop(retained);
    assert_eq!(memory.used(), 0);
}

#[test]
fn issuer_hint_comparison_reuses_ess_name_semantics_and_current_query_funding() {
    // Standalone hints use the same serial/name comparison as CMS ESS, including
    // matching normalized issuer names from independently retained certificates.
    let certificate_account = funded();
    let bytes = candidate_certificate();
    let cert_parser = structured_asn1::Parser::der(certificate_account.clone());
    let candidate = structured_pkix::Certificate::read(&cert_parser, &bytes, 900).unwrap();
    let held = certificate_account.used();
    let old_work = certificate_account.work_used();
    for (name, serial, matches) in [
        (b'a', 1, true),
        (b'A', 1, true),
        (b'b', 1, false),
        (b'a', 2, false),
    ] {
        let memory = funded();
        let (mut xml, [_, _, _, _, _, issuer]) = certificate_tree();
        xml.binary = vec![
            0x30, 21, 0x30, 16, 0xa4, 14, 0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1,
            name, 2, 1, serial,
        ];
        let signed = signed_roles(&xml, &memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let refs = certificate::read(&access, &signed).unwrap();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let located = certificate::with_issuer_serial(&xml, &refs, 0, &operation, |reading| {
            assert!(reading.faults().is_empty());
            reading.matches_certificate(&candidate, &operation)
        })
        .unwrap()
        .unwrap();
        assert_eq!(located.location.node, issuer);
        assert_eq!(
            located.value,
            if matches {
                structured_cms::ess::IssuerAgreement::Matches
            } else {
                structured_cms::ess::IssuerAgreement::Differs
            }
        );
        assert_eq!(certificate_account.used(), held);
        assert_eq!(certificate_account.work_used(), old_work);
    }
}

#[test]
fn issuer_hint_comparison_preserves_query_local_refusal_instead_of_mismatch() {
    // Comparing a retained hint under a new query is legitimate. Its exhausted
    // local work ceiling must refuse before normalization, not ForeignReader.
    let memory = funded();
    let bytes = candidate_certificate();
    let certificate_parser = structured_asn1::Parser::der(memory.clone());
    let candidate = structured_pkix::Certificate::read(&certificate_parser, &bytes, 900).unwrap();
    let (mut xml, _) = certificate_tree();
    xml.binary = vec![
        0x30, 21, 0x30, 16, 0xa4, 14, 0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, b'a',
        2, 1, 1,
    ];
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let refs = certificate::read(&access, &signed).unwrap();
    let source = structured_asn1::Parser::der(memory.clone());
    let operation = source.read(&[], 900).unwrap();
    let exhausted = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..structured_asn1::Limits::default()
        },
        memory.clone(),
    );
    let query = exhausted.read(&[], 1000).unwrap();
    let held = memory.used();
    let error = certificate::with_issuer_serial(&xml, &refs, 0, &operation, |reading| {
        reading.matches_certificate(&candidate, &query)
    })
    .unwrap_err();
    let binary::Error::Callback {
        cause: certificate::IssuerError::Callback(cause),
        ..
    } = error
    else {
        panic!("comparison refusal was rewritten");
    };
    assert!(cause.is_resource());
    assert_eq!(cause.field(), "xades.issuerSerialV2");
    assert_eq!(cause.offset(), 0);
    assert_eq!(memory.used(), held);
}

#[test]
fn issuer_hint_schema_fixed_der_cannot_be_overridden_by_an_encoding_attribute() {
    // IssuerSerialV2 is fixed DER by §5.2.2, unlike generic EncapsulatedPKIData.
    // An unrelated attribute cannot grant permissive ASN.1 parsing or a callback.
    let memory = funded();
    let (mut xml, _) = certificate_tree();
    xml.binary = vec![0x30, 0x81, 5, 0x30, 0, 2, 1, 7];
    xml.binary_encoding = Some("http://uri.etsi.org/01903/v1.2.2#BER");
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let refs = certificate::read(&access, &signed).unwrap();
    let parser = structured_asn1::Parser::ber(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let called = Cell::new(false);
    assert!(matches!(
        certificate::with_issuer_serial(&xml, &refs, 0, &operation, |_| {
            called.set(true);
            Ok::<_, ()>(())
        }),
        Err(binary::Error::Callback {
            cause: certificate::IssuerError::Encoding(_),
            ..
        })
    ));
    assert!(!called.get());
}

#[test]
fn absent_issuer_hint_still_checks_generation_without_inventing_asn_work() {
    // Absence is optional metadata, not a fictitious nested ASN.1 value. The
    // original-generation guard still runs before returning that absence.
    let memory = funded();
    let (mut xml, [_, _, _, _, _, issuer]) = certificate_tree();
    xml.nodes[issuer].parent = None;
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let refs = certificate::read(&access, &signed).unwrap();
    let limits = structured_asn1::Limits {
        max_depth: 0,
        ..structured_asn1::Limits::default()
    };
    let parser =
        structured_asn1::Parser::new(structured_asn1::Encoding::Ber, limits, memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    assert!(
        certificate::with_issuer_serial(&xml, &refs, 0, &operation, |_| Ok::<_, ()>(()))
            .unwrap()
            .is_none()
    );
    xml.generation.set(2);
    assert!(matches!(
        certificate::with_issuer_serial(&xml, &refs, 0, &operation, |_| Ok::<_, ()>(())),
        Err(binary::Error::Access {
            cause: AccessError::Changed { .. },
            ..
        })
    ));
}

#[test]
fn baseline_md5_and_missing_method_refuse_before_provider_or_value_decode() {
    // The baseline's unconditional MD5 exclusion is a format rule, distinct
    // from provider availability or caller-deployment algorithm preferences.
    let memory = funded();
    let bytes = candidate_certificate();
    let parser = structured_asn1::Parser::der(memory.clone());
    let candidate = structured_pkix::Certificate::read(&parser, &bytes, 900).unwrap();
    let (mut xml, [_, _, _, method, _, _]) = certificate_tree();
    xml.binary = vec![0; 100_000]; // Copying this would exceed the account.
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let refs = certificate::read(&access, &signed).unwrap();
    let provider = WholeCertificate {
        mode: DigestMode::Refused,
        method,
        calls: Cell::new(0),
        pointer: Cell::new(0),
    };
    let held = memory.used();
    for (uri, answer) in [
        (
            Some(" \thttp://www.w3.org/2001/04/xmldsig-more#md5\n"),
            certificate::Agreement::ProhibitedAlgorithm,
        ),
        (None, certificate::Agreement::MalformedMethod),
    ] {
        xml.digest_algorithm = uri;
        assert_eq!(
            certificate::compare(&xml, &refs, 0, &candidate, &provider, &memory).unwrap(),
            answer
        );
        assert_eq!(memory.used(), held);
    }
    assert_eq!(provider.calls.get(), 0);
}

#[test]
fn owned_binary_transfer_keeps_pointer_source_and_charge_after_owner_drop() {
    // Material retention uses the decoder's actual allocation, not a second
    // copy. XML source identity and charge survive owner/scope destruction.
    let memory = funded();
    let retained = {
        let mut xml = Tree::normal();
        xml.binary = vec![3, 4, 5];
        let location = Location {
            snapshot: xml.snapshot(),
            node: 8,
        };
        let retained = binary::owned(&xml, location, &memory).unwrap();
        assert_eq!(retained.location, location);
        assert_eq!(retained.value.as_ptr() as usize, xml.decoded_pointer.get());
        retained
    };
    assert_eq!(&*retained.value, &[3, 4, 5]);
    assert_eq!(memory.used(), retained.value.capacity());
    drop(retained);
    assert_eq!(memory.used(), 0);
}

#[test]
fn moved_cached_binary_storage_stays_on_its_original_account() {
    // A real move does not charge storage a second time to a new operation.
    // Current traversal/dispatch work is still paid by that new operation.
    let storage = funded();
    let mut buffer = storage.vector();
    buffer.try_extend_from_slice(&[3, 4, 5]).unwrap();
    let pointer = buffer.as_ptr();
    let charged = storage.used();
    let xml = Tree::normal();
    *xml.cached_binary.borrow_mut() = Some(buffer);
    let query = memory(2);
    let value = binary::owned(
        &xml,
        Location {
            snapshot: xml.snapshot(),
            node: 8,
        },
        &query,
    )
    .unwrap();
    assert_eq!(value.value.as_ptr(), pointer);
    assert_eq!(query.used(), 0);
    assert_eq!(query.work_used(), 2);
    assert_eq!(storage.used(), charged);
    drop(value);
    assert_eq!(storage.used(), 0);
}

#[test]
fn owned_binary_generation_and_capacity_refusals_release_partial_output() {
    // A generation change cannot publish the new owned value; failed storage
    // admission is an error, not a successful empty collateral buffer.
    let memory = funded();
    let mut xml = Tree::normal();
    xml.binary = vec![3, 4, 5];
    xml.mutate_binary = true;
    let location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    assert!(matches!(
        binary::owned(&xml, location, &memory),
        Err(AccessError::Changed { node: 8 })
    ));
    assert_eq!(memory.used(), 0);
    xml.mutate_binary = false;
    let query = memory_for_owned_refusal();
    assert!(matches!(
        binary::owned(
            &xml,
            Location {
                snapshot: xml.snapshot(),
                node: 8
            },
            &query
        ),
        Err(AccessError::Xml(Cause::Resource(
            MemoryError::LimitExceeded
        )))
    ));
    assert_eq!(query.used(), 0);
}

fn memory_for_owned_refusal() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(0, 1000)))
}

#[test]
fn simultaneous_owned_sources_keep_independent_bytes_and_xml_locations() {
    // Two material models can borrow distinct retained sources simultaneously;
    // neither requires nested callbacks, a second copy or a synthetic joined source.
    let memory = funded();
    let operation_parser = structured_asn1::Parser::der(memory.clone());
    let operation = operation_parser.read(&[], 900).unwrap();
    let mut xml = Tree::normal();
    xml.binary = vec![2, 1, 7];
    let first_location = Location {
        snapshot: xml.snapshot(),
        node: 5,
    };
    let first = binary::owned_source(&xml, first_location, &operation).unwrap();
    let first_pointer = first.value.bytes.as_ptr();
    xml.binary = vec![2, 1, 9];
    let second_location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    let second = binary::owned_source(&xml, second_location, &operation).unwrap();
    drop(xml);
    let mut catalogue = memory.vector();
    catalogue.try_push(first).unwrap();
    catalogue.try_push(second).unwrap();
    assert_eq!(catalogue[0].value.bytes.as_ptr(), first_pointer);
    assert_eq!(catalogue[0].location, first_location);
    assert_eq!(catalogue[1].location, second_location);
    {
        let mut left = catalogue[0]
            .value
            .reader_in(&operation, structured_asn1::Encoding::Der)
            .unwrap();
        let mut right = catalogue[1]
            .value
            .reader_in(&operation, structured_asn1::Encoding::Der)
            .unwrap();
        let a = left.next_element().unwrap().unwrap();
        let b = right.next_element().unwrap().unwrap();
        assert_eq!(left.integer(&a).unwrap().as_u64(), Some(7));
        assert_eq!(right.integer(&b).unwrap().as_u64(), Some(9));
        assert_eq!(a.as_bytes().as_ptr(), first_pointer);
    }
    drop(catalogue);
    assert_eq!(memory.used(), 0);
}

#[test]
fn owned_source_preserves_origin_work_depth_and_current_operation_refusal() {
    // Moving a source cannot reset its cumulative local budget or divert work
    // to its storage account. Both original coordinates and current limits apply.
    let storage = funded();
    let mut bytes = storage.vector();
    bytes.try_extend_from_slice(&[2, 1, 7]).unwrap();
    let source = binary::OwnedDecoded {
        parser: structured_asn1::Parser::new(
            structured_asn1::Encoding::Ber,
            structured_asn1::Limits {
                max_work: 1,
                ..Default::default()
            },
            storage.clone(),
        ),
        bytes,
        base: 700,
        depth: 3,
    };
    let storage_work = storage.work_used();
    let query = funded();
    let operation_parser = structured_asn1::Parser::der(query.clone());
    let operation = operation_parser.read(&[], 900).unwrap();
    {
        let reader = source
            .reader_in(&operation, structured_asn1::Encoding::Der)
            .unwrap();
        assert_eq!(reader.depth(), 3);
        assert_eq!(reader.offset(), 700);
    }
    let moved = source;
    let error = moved
        .reader_in(&operation, structured_asn1::Encoding::Der)
        .unwrap_err();
    assert_eq!(
        error.code(),
        structured_asn1::ErrorCode::LimitExceeded(structured_asn1::Limit::Work)
    );
    assert_eq!(error.offset(), 700);
    assert_eq!(query.work_used(), 1);
    assert_eq!(storage.work_used(), storage_work);

    let zero_parser = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..Default::default()
        },
        query.clone(),
    );
    let zero = zero_parser.read(&[], 900).unwrap();
    let fresh_source = binary::OwnedDecoded {
        parser: structured_asn1::Parser::ber(storage.clone()),
        bytes: moved.bytes,
        base: 700,
        depth: 3,
    };
    let error = fresh_source
        .reader_in(&zero, structured_asn1::Encoding::Der)
        .unwrap_err();
    assert_eq!(
        error.code(),
        structured_asn1::ErrorCode::LimitExceeded(structured_asn1::Limit::Work)
    );
    assert_eq!(error.offset(), 700);
    assert_eq!(query.work_used(), 1);
    drop(fresh_source);
    assert_eq!(storage.used(), 0);
}

fn material_tree(local: &'static str, bytes: Vec<u8>) -> Tree {
    let mut xml = Tree::normal();
    xml.nodes[8] = element(Some(7), XADES, local);
    xml.binary = bytes;
    xml
}

#[test]
fn complete_material_pass_parses_all_known_sources_and_preserves_open_formats() {
    // Frozen source buffers back one shared PKIX pass. Original storage roles
    // and opaque entries survive, without claiming trust or LT completeness.
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = preparation_tree();
    xml.binary = candidate_certificate();
    let ordinary = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "CertificateValues"));
    xml.nodes.push(element(
        Some(ordinary),
        XADES,
        "EncapsulatedX509Certificate",
    ));
    let opaque = xml.nodes.len();
    xml.nodes
        .push(element(Some(ordinary), XADES, "OtherCertificate"));
    let general = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES_141, "AnyValidationData"));
    let certificates = xml.nodes.len();
    xml.nodes
        .push(element(Some(general), XADES, "CertificateValues"));
    xml.nodes.push(element(
        Some(certificates),
        XADES,
        "EncapsulatedX509Certificate",
    ));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let held = memory.used();
    let count = material::with_values(&xml, &prepared, &operation, |_, view| {
        assert_eq!(view.sources().len(), 3);
        assert_eq!(view.values().len(), 3);
        assert!(matches!(view.sources()[0].placement(), material::Placement::KeyInfo(0)));
        assert!(matches!(view.sources()[1].placement(), material::Placement::Signature(node) if node == ordinary));
        assert!(matches!(view.sources()[2].placement(), material::Placement::General(node) if node == general));
        for (original, parsed) in view.sources().iter().zip(view.values()) {
            assert_eq!(parsed.location, original.source().location());
            let material::Value::Certificate(certificate) = &parsed.value else { panic!("not certificate") };
            assert_eq!(certificate.as_bytes().as_ptr(), original.source().bytes().as_ptr());
        }
        assert_eq!(view.opaque().len(), 1);
        assert_eq!(view.opaque()[0].location.node, opaque);
        Ok::<_, ()>(view.values().len())
    }).unwrap();
    assert_eq!(count, 3);
    assert_eq!(memory.used(), held);
    assert_eq!(xml.streamed.get(), 0);
    drop(prepared);
    assert_eq!(memory.used(), 0);
}

#[test]
fn original_key_info_crls_enter_the_same_validation_material_pool() {
    // XMLDSig1.1 §4.5.4 permits X509CRL in the original X509Data. Losing it
    // would falsely report missing validation data and invite duplicate copies.
    let memory = funded();
    let mut xml = preparation_tree();
    xml.binary = candidate_certificate();
    let key_info = xml.element_child(0, DS, "KeyInfo");
    let data = xml.element_child(key_info, DS, "X509Data");
    // This checks decoding/provenance, not authentication. Do not generate
    // unrelated ECDSA CRL/OCSP signatures: those have separate real-math tests.
    for update in [b"260101000000Z", b"270101000000Z"] {
        let node = xml.nodes.len();
        xml.nodes.push(element(Some(data), DS, "X509CRL"));
        xml.binary_routes.push((node, readable_crl_fixture(update)));
    }
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let before = memory.used();
    material::with_values(&xml, &prepared, &operation, |_, view| {
        assert_eq!(view.sources().len(), 3);
        assert_eq!(view.values().len(), 3);
        for (source, value) in view.sources()[1..].iter().zip(&view.values()[1..]) {
            assert_eq!(source.source().kind(), material::Kind::Crl);
            assert!(matches!(
                source.placement(),
                material::Placement::KeyInfo(0)
            ));
            let material::Value::Crl(crl) = &value.value else {
                panic!("original X509CRL")
            };
            assert_eq!(crl.as_bytes(), source.source().bytes());
            assert_eq!(crl.as_bytes().as_ptr(), source.source().bytes().as_ptr());
        }
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(memory.used(), before);
}

fn readable_crl_fixture(update: &[u8]) -> Vec<u8> {
    readable_crl_fixture_as(update, structured_pkix::time::Form::Utc)
}

fn readable_crl_fixture_as(update: &[u8], form: structured_pkix::time::Form) -> Vec<u8> {
    // Trusted DER metadata writer; unknown algorithm/dummy signature MUST NOT
    // be used as an authentication oracle. Same fixture in native and Miri.
    use timestamp_oracle::tlv;
    let algorithm = tlv(0x30, &tlv(6, &[42, 3]));
    let name = [0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, b'a'];
    let body = tlv(
        0x30,
        &[
            tlv(2, &[1]),
            algorithm.clone(),
            name.to_vec(),
            tlv(
                match form {
                    structured_pkix::time::Form::Utc => 0x17,
                    structured_pkix::time::Form::Generalized => 0x18,
                },
                update,
            ),
        ]
        .concat(),
    );
    tlv(0x30, &[body, algorithm, tlv(3, &[0, 1])].concat())
}

fn ocsp_material_envelope(payload: &[u8], kind: &[u8]) -> Vec<u8> {
    use timestamp_oracle::tlv;
    let mut fields = tlv(6, kind);
    fields.extend(tlv(4, payload));
    let mut envelope = vec![10, 1, 0];
    envelope.extend(tlv(0xa0, &tlv(0x30, &fields)));
    tlv(0x30, &envelope)
}

fn ocsp_material_with_certificate(certificate: &[u8]) -> Vec<u8> {
    use timestamp_oracle::tlv;
    let algorithm = tlv(0x30, &tlv(6, &[42]));
    let mut id = algorithm.clone();
    id.extend(tlv(4, &[0x11; 20]));
    id.extend(tlv(4, &[0x22; 20]));
    id.extend([2, 1, 1]);
    let mut assertion = tlv(0x30, &id);
    assertion.extend([0x80, 0]);
    assertion.extend(tlv(24, b"20260101000000Z"));
    let mut data = tlv(0xa2, &tlv(4, &[0x33; 20]));
    data.extend(tlv(24, b"20260101000000Z"));
    data.extend(tlv(0x30, &tlv(0x30, &assertion)));
    let mut basic = tlv(0x30, &data);
    basic.extend(algorithm);
    basic.extend([3, 2, 0, 0xab]);
    basic.extend(tlv(0xa0, &tlv(0x30, certificate)));
    ocsp_material_envelope(
        &tlv(0x30, &basic),
        structured_pkix::oid::OCSP_BASIC.as_bytes(),
    )
}

fn ocsp_pipeline_tree(bytes: Vec<u8>) -> (Tree, usize) {
    let mut xml = preparation_tree();
    xml.binary = candidate_certificate();
    let property = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "RevocationValues"));
    let group = xml.nodes.len();
    xml.nodes.push(element(Some(property), XADES, "OCSPValues"));
    let node = xml.nodes.len();
    xml.nodes
        .push(element(Some(group), XADES, "EncapsulatedOCSPValue"));
    xml.binary_routes.push((node, bytes));
    (xml, node)
}

#[test]
fn material_pipeline_reads_basic_payload_and_embedded_certificates_from_the_original_whole_response()
 {
    // EN5.4.2 permits certificates embedded in status material. The basic model
    // must borrow its whole OCSP source, not reparse copied certificate bytes or
    // confuse syntactically good status with authenticated revocation evidence.
    let expected = candidate_certificate();
    let (xml, node) = ocsp_pipeline_tree(ocsp_material_with_certificate(&expected));
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let held = memory.used();
    material::with_values(&xml, &prepared, &operation, |_, view| {
        assert_eq!(view.values().len(), 2);
        assert_eq!(view.basic_responses().len(), 1);
        let basic = &view.basic_responses()[0];
        assert_eq!(basic.source_index(), 1);
        assert_eq!(basic.location().node, node);
        assert_eq!(basic.location().snapshot, xml.snapshot());
        let material::Value::Ocsp(structured_pkix::ocsp::Response::Successful(envelope)) =
            &view.values()[1].value
        else {
            panic!("whole success envelope");
        };
        assert_eq!(
            basic.response().as_bytes().as_ptr(),
            envelope.payload().as_ptr()
        );
        assert_eq!(basic.response().span(), envelope.span());
        assert_eq!(basic.response().certificates().len(), 1);
        assert_eq!(basic.response().certificates()[0].as_bytes(), expected);
        assert_eq!(basic.response().responses().len(), 1);
        assert_eq!(
            basic.response().responses()[0].status(),
            structured_pkix::ocsp::Status::Good
        );
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(memory.used(), held);
    drop(prepared);
    assert_eq!(memory.used(), 0);
}

#[test]
fn material_pipeline_refuses_a_broken_known_basic_payload_before_exposing_the_set() {
    // A successful wire envelope cannot hide a malformed known BasicResponse.
    // Error coordinates remain decoded OCSP source + original XML enclosure.
    let bytes = ocsp_material_envelope(&[0x25, 0], structured_pkix::oid::OCSP_BASIC.as_bytes());
    let (xml, node) = ocsp_pipeline_tree(bytes);
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let held = memory.used();
    let calls = Cell::new(0);
    let result = material::with_values(&xml, &prepared, &operation, |_, _| {
        calls.set(calls.get() + 1);
        Ok::<_, ()>(())
    });
    let Err(material::PipelineError::Parse(error)) = result else {
        panic!("must reject basic syntax");
    };
    assert_eq!(error.location.node, node);
    assert_eq!(error.location.snapshot, xml.snapshot());
    let material::Cause::Pki(cause) = error.value else {
        panic!("PKIX cause");
    };
    assert!(!cause.is_resource());
    assert!(cause.offset() > 0);
    assert_eq!(calls.get(), 0);
    assert_eq!(memory.used(), held);
}

#[test]
fn material_pipeline_preserves_ocsp_protocol_failures_and_unknown_types_without_basic_promotion() {
    // Parsing neither hides failure envelopes nor interprets unsupported opaque
    // response syntaxes as good status or an empty successful basic response.
    for unknown in [false, true] {
        let bytes = if unknown {
            ocsp_material_envelope(&[0x25, 0], &[42])
        } else {
            vec![48, 3, 10, 1, 3]
        };
        let (xml, node) = ocsp_pipeline_tree(bytes);
        let memory = funded();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let prepared =
            prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
        let held = memory.used();
        material::with_values(&xml, &prepared, &operation, |_, view| {
            assert!(view.basic_responses().is_empty());
            assert_eq!(view.values().len(), 2);
            assert_eq!(view.values()[1].location.node, node);
            if unknown {
                assert!(matches!(&view.values()[1].value, material::Value::Ocsp(structured_pkix::ocsp::Response::Successful(value)) if value.kind().as_bytes() == [42]));
            } else {
                assert!(matches!(&view.values()[1].value, material::Value::Ocsp(structured_pkix::ocsp::Response::Failure { failure: structured_pkix::ocsp::Failure::TryLater, .. })));
            }
            Ok::<_, ()>(())
        }).unwrap();
        assert_eq!(memory.used(), held);
    }
}

#[test]
fn material_index_keeps_every_exact_certificate_copy_including_ocsp_placement() {
    // The same certificate may occur before/after an archive cutoff or in a
    // different actor's material. Availability must retain every original
    // location, not collapse duplicates to one arbitrary or latest copy.
    let expected = candidate_certificate();
    let (mut xml, ocsp) = ocsp_pipeline_tree(ocsp_material_with_certificate(&expected));
    let ordinary = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "CertificateValues"));
    let direct = xml.nodes.len();
    xml.nodes.push(element(
        Some(ordinary),
        XADES,
        "EncapsulatedX509Certificate",
    ));
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let held = memory.used();
    material::with_values(&xml, &prepared, &operation, |query, view| {
        let execution = query.execution();
        let access = Access::new(&xml, xml.snapshot(), &execution);
        let index = material::index(&view, &access).unwrap();
        let material::Value::Certificate(certificate) = &view.values()[0].value else {
            panic!("header certificate");
        };
        let copies = index
            .certificate(certificate, &access)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(copies.len(), 3);
        assert_eq!(
            copies
                .iter()
                .map(material::Occurrence::source)
                .collect::<Vec<_>>(),
            [
                structured_ltv::material::ArtifactSource::Material(0),
                structured_ltv::material::ArtifactSource::Material(1),
                structured_ltv::material::ArtifactSource::Material(2)
            ]
        );
        assert_eq!(
            copies[0].location().node,
            prepared.header().certificates()[0]
        );
        assert!(matches!(
            copies[0].placement(),
            material::Placement::KeyInfo(0)
        ));
        assert_eq!(copies[0].embedded_certificate(), None);
        assert_eq!(copies[1].location().node, ocsp);
        assert_eq!(copies[1].embedded_certificate(), Some(0));
        assert_eq!(copies[2].location().node, direct);
        assert_eq!(copies[2].embedded_certificate(), None);
        let statuses = index
            .ocsp(view.basic_responses()[0].response(), &access)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(
            statuses[0].source(),
            structured_ltv::material::ArtifactSource::Material(1)
        );
        assert_eq!(statuses[0].location().node, ocsp);
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(memory.used(), held);
    drop(prepared);
    assert_eq!(memory.used(), 0);
}

#[test]
fn material_index_queries_use_current_work_and_fuse_after_a_source_or_resource_refusal() {
    // Storage ownership supplies no query credit. Source changes and traversal
    // refusal cannot silently turn remaining copies into an empty successful set.
    let mut xml = preparation_tree();
    xml.binary = candidate_certificate();
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let held = memory.used();
    let result = material::with_values(&xml, &prepared, &operation, |query, view| {
        let execution = query.execution();
        let access = Access::new(&xml, xml.snapshot(), &execution);
        let index = material::index(&view, &access).unwrap();
        let material::Value::Certificate(certificate) = &view.values()[0].value else {
            panic!("header certificate");
        };
        let empty_work = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        let current = Access::new(&xml, xml.snapshot(), &empty_work);
        assert!(matches!(
            index.certificate(certificate, &current),
            Err(structured_ltv::material::IndexError::Scope(
                structured_ltv::source::ScopeError::Resource { .. }
            ))
        ));
        let current_work = funded();
        let current = Access::new(&xml, xml.snapshot(), &current_work);
        let mut copies = index.certificate(certificate, &current).unwrap();
        current_work
            .charge_work(current_work.work_remaining() as u64)
            .unwrap();
        assert!(matches!(
            copies.next(),
            Some(Err(structured_ltv::material::IndexError::Scope(
                structured_ltv::source::ScopeError::Resource { .. }
            )))
        ));
        assert!(copies.next().is_none());
        let foreign = Access::new(
            &xml,
            Snapshot {
                document: 10,
                generation: 1,
            },
            &execution,
        );
        assert!(matches!(
            index.certificate(certificate, &foreign),
            Err(structured_ltv::material::IndexError::Foreign { .. })
        ));
        let mut copies = index.certificate(certificate, &access).unwrap();
        xml.generation.set(2);
        assert!(matches!(
            copies.next(),
            Some(Err(structured_ltv::material::IndexError::Scope(
                structured_ltv::source::ScopeError::Changed { .. }
            )))
        ));
        assert!(copies.next().is_none());
        assert!(matches!(
            index.certificate(certificate, &access),
            Err(structured_ltv::material::IndexError::Scope(
                structured_ltv::source::ScopeError::Changed { .. }
            ))
        ));
        Ok::<_, ()>(())
    });
    assert!(matches!(
        result,
        Err(material::PipelineError::Access(AccessError::Changed { .. }))
    ));
    assert_eq!(memory.used(), held);
}

#[test]
fn material_index_requires_whole_artifact_identity_and_drops_partial_construction_on_refusal() {
    // Equal subject/TBS is insufficient: another certificate signature denotes
    // a different original artifact. Failed index construction returns no prefix
    // and frees temporary entries even if map admission fails after entry growth.
    let mut xml = preparation_tree();
    xml.binary = candidate_certificate();
    let mut other = xml.binary.clone();
    *other.last_mut().unwrap() = 9;
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let other_parser = structured_asn1::Parser::der(memory.clone());
    let other = structured_pkix::Certificate::read(&other_parser, &other, 0).unwrap();
    let held = memory.used();
    material::with_values(&xml, &prepared, &operation, |query, view| {
        let execution = query.execution();
        let access = Access::new(&xml, xml.snapshot(), &execution);
        let index = material::index(&view, &access).unwrap();
        assert!(index.certificate(&other, &access).unwrap().next().is_none());
        for capacity in [0, 400] {
            let limited = Memory::new(Arc::new(MemoryAccount::new(capacity, 100_000)));
            let current = Access::new(&xml, xml.snapshot(), &limited);
            assert!(matches!(
                material::index(&view, &current),
                Err(structured_ltv::material::IndexError::Resource { .. })
            ));
            assert_eq!(limited.used(), 0);
        }
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(memory.used(), held);
}

#[test]
fn complete_material_pass_never_exposes_a_successful_subset_before_late_parse_failure() {
    // The header certificate parses successfully, but an OCSP-labelled member
    // containing certificate bytes must fail before any visitor can see it.
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = preparation_tree();
    xml.binary = candidate_certificate();
    let property = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "RevocationValues"));
    let group = xml.nodes.len();
    xml.nodes.push(element(Some(property), XADES, "OCSPValues"));
    let wrong = xml.nodes.len();
    xml.nodes
        .push(element(Some(group), XADES, "EncapsulatedOCSPValue"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let held = memory.used();
    let called = Cell::new(false);
    let result = material::with_values(&xml, &prepared, &operation, |_, _| {
        called.set(true);
        Ok::<_, ()>(())
    });
    assert!(
        matches!(&result, Err(material::PipelineError::Parse(cause)) if cause.location.node == wrong)
    );
    drop(result);
    assert!(!called.get());
    assert_eq!(memory.used(), held);
}

#[test]
fn complete_material_pass_drops_visitor_results_on_source_change_and_keeps_original_errors() {
    // Visitor failure is opaque and terminal. A successful owned result cannot
    // escape a generation change; its capacity and all temporary sources drop.
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = preparation_tree();
    xml.binary = candidate_certificate();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let held = memory.used();
    assert!(matches!(
        material::with_values(&xml, &prepared, &operation, |_, _| Err::<(), _>("visitor")),
        Err(material::PipelineError::Visitor("visitor"))
    ));
    assert_eq!(memory.used(), held);
    let result = material::with_values(&xml, &prepared, &operation, |current, _| {
        let mut result = current.execution().vector();
        result.try_extend_from_slice(b"independent result")?;
        xml.generation.set(2);
        Ok::<_, MemoryError>(result.into_owned())
    });
    assert!(matches!(
        result,
        Err(material::PipelineError::Access(AccessError::Changed { .. }))
    ));
    assert_eq!(xml.generation.get(), 2);
    assert_eq!(memory.used(), held);
}

#[test]
fn complete_material_pass_funds_current_local_and_storage_budgets_before_decode() {
    // Preparation's old storage account is not credit for this new operation;
    // both the current local ceiling and current allocation account are enforced.
    let storage = funded();
    let mut xml = preparation_tree();
    xml.binary = candidate_certificate();
    let access = Access::new(&xml, xml.snapshot(), &storage);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Timestamped, None).unwrap();
    let query = funded();
    let parser = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..Default::default()
        },
        query.clone(),
    );
    let operation = parser.read(&[], 900).unwrap();
    let called = Cell::new(false);
    assert!(matches!(
        material::with_values(&xml, &prepared, &operation, |_, _| {
            called.set(true);
            Ok::<_, ()>(())
        }),
        Err(material::PipelineError::Access(AccessError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        }))
    ));
    assert!(!called.get());
    assert_eq!(xml.decoded_pointer.get(), 0);
    let no_storage = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    let parser = structured_asn1::Parser::der(no_storage.clone());
    let operation = parser.read(&[], 900).unwrap();
    let result = material::with_values(&xml, &prepared, &operation, |_, _| {
        called.set(true);
        Ok::<_, ()>(())
    });
    assert!(matches!(
        result,
        Err(material::PipelineError::Retain {
            cause: material::RetainError::Access(AccessError::Xml(Cause::Resource(
                MemoryError::LimitExceeded
            ))),
            ..
        })
    ));
    assert!(!called.get());
    assert_eq!(no_storage.used(), 0);
    assert_eq!(xml.decoded_pointer.get(), 0);
}

#[test]
fn key_info_material_reuses_owned_source_and_pkix_without_a_second_certificate_codec() {
    // Original selected header certificates use the same retained source/PKIX
    // route as embedded material. Invalid ordinals never start decoding.
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let source = {
        let (mut xml, _, node, _) = header_tree();
        xml.binary = candidate_certificate();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let header = header::read(&access, &bound).unwrap();
        assert!(matches!(
            material::retain_header(&xml, &header, 1, &operation),
            Err(material::RetainError::HeaderIndex {
                signature: 0,
                index: 1
            })
        ));
        assert_eq!(xml.decoded_pointer.get(), 0);
        let source = material::retain_header(&xml, &header, 0, &operation).unwrap();
        assert_eq!(
            source.location(),
            Location {
                snapshot: xml.snapshot(),
                node
            }
        );
        assert_eq!(source.bytes().as_ptr() as usize, xml.decoded_pointer.get());
        source
    };
    {
        let value = source.read_in(&operation).unwrap();
        let material::Value::Certificate(certificate) = &value.value else {
            panic!("not certificate")
        };
        assert_eq!(certificate.as_bytes().as_ptr(), source.bytes().as_ptr());
    }
    drop(source);
    assert_eq!(memory.used(), 0);
}

#[test]
fn embedded_certificate_and_whole_ocsp_response_reuse_pkix_and_retain_locations() {
    // Simultaneous original material is parsed by the common PKIX kernels.
    // An OCSP error envelope stays a failure; parsing cannot confer good status.
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let certificate_xml = material_tree("EncapsulatedX509Certificate", candidate_certificate());
    let mut ocsp_xml = material_tree("EncapsulatedOCSPValue", vec![48, 3, 10, 1, 3]);
    ocsp_xml.document = 10;
    let location = Location {
        snapshot: certificate_xml.snapshot(),
        node: 8,
    };
    let cert = material::retain(
        &certificate_xml,
        location,
        material::Kind::Certificate,
        &operation,
    )
    .unwrap();
    assert_eq!(
        cert.bytes().as_ptr() as usize,
        certificate_xml.decoded_pointer.get()
    );
    let response_location = Location {
        snapshot: ocsp_xml.snapshot(),
        node: 8,
    };
    let response = material::retain(
        &ocsp_xml,
        response_location,
        material::Kind::Ocsp,
        &operation,
    )
    .unwrap();
    drop(certificate_xml);
    drop(ocsp_xml);
    {
        let a = cert.read_in(&operation).unwrap();
        let b = response.read_in(&operation).unwrap();
        assert_eq!(a.location, location);
        assert_eq!(b.location, response_location);
        assert_ne!(a.location, b.location);
        match a.value {
            material::Value::Certificate(value) => {
                assert_eq!(value.as_bytes().as_ptr(), cert.bytes().as_ptr());
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            b.value,
            material::Value::Ocsp(structured_pkix::ocsp::Response::Failure {
                failure: structured_pkix::ocsp::Failure::TryLater,
                ..
            })
        ));
    }
    drop(cert);
    drop(response);
    assert_eq!(memory.used(), 0);
}

#[test]
fn embedded_crl_reuses_original_der_certificate_list() {
    // This is a schema/provenance fixture, deliberately not authenticated math.
    // The original CRL TLV, rather than a reconstructed TBS, reaches PKIX.
    fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
        assert!(bytes.len() < 128);
        [
            vec![tag, u8::try_from(bytes.len()).unwrap()],
            bytes.to_vec(),
        ]
        .concat()
    }
    let algorithm = [48, 3, 6, 1, 42];
    let name = [48, 12, 49, 10, 48, 8, 6, 3, 0x55, 4, 3, 12, 1, b'a'];
    let tbs = tlv(
        48,
        &[algorithm.as_slice(), &name, &tlv(23, b"261012120000Z")].concat(),
    );
    let bytes = tlv(48, &[&tbs, algorithm.as_slice(), &[3, 2, 0, 8]].concat());
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let xml = material_tree("EncapsulatedCRLValue", bytes);
    let source = material::retain(
        &xml,
        Location {
            snapshot: xml.snapshot(),
            node: 8,
        },
        material::Kind::Crl,
        &operation,
    )
    .unwrap();
    let read = source.read_in(&operation).unwrap();
    assert!(matches!(read.value, material::Value::Crl(_)));
    drop(read);
    drop(source);
    assert_eq!(memory.used(), 0);
}

#[test]
fn material_schema_tail_and_current_resource_refusals_are_not_missing_status() {
    // DER, whole-envelope and exact-value boundaries are independent of XML's
    // Encoding hint. No syntax/resource failure becomes successful absent data.
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = material_tree("EncapsulatedOCSPValue", vec![48, 3, 10, 1, 3, 0]);
    let location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    let source = material::retain(&xml, location, material::Kind::Ocsp, &operation).unwrap();
    let error = source.read_in(&operation).unwrap_err();
    assert_eq!(error.location, location);
    assert!(matches!(
        error.value,
        material::Cause::Trailing { offset: 5 }
    ));
    drop(source);
    xml.binary = vec![48, 0x81, 3, 10, 1, 3];
    xml.binary_encoding = Some("http://uri.etsi.org/01903/v1.2.2#BER");
    let source = material::retain(&xml, location, material::Kind::Ocsp, &operation).unwrap();
    assert!(matches!(
        source.read_in(&operation),
        Err(binary::Located {
            value: material::Cause::Encoding(_),
            ..
        })
    ));
    drop(source);
    xml.binary = vec![48, 3, 10, 1, 3];
    let source = material::retain(&xml, location, material::Kind::Ocsp, &operation).unwrap();
    let zero_parser = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 0,
            ..Default::default()
        },
        memory.clone(),
    );
    let zero = zero_parser.read(&[], 900).unwrap();
    let error = source.read_in(&zero).unwrap_err();
    match error.value {
        material::Cause::Encoding(cause) => assert_eq!(
            cause.code(),
            structured_asn1::ErrorCode::LimitExceeded(structured_asn1::Limit::Work)
        ),
        other => panic!("unexpected {other:?}"),
    }
    drop(source);
    assert_eq!(memory.used(), 0);
}

#[test]
fn material_expanded_name_refuses_before_decode_or_retention() {
    // A lookalike from another namespace cannot be promoted to a PKI source.
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = material_tree("EncapsulatedOCSPValue", vec![0; 100_000]);
    xml.nodes[8] = element(Some(7), "urn:other", "EncapsulatedOCSPValue");
    assert!(matches!(
        material::retain(
            &xml,
            Location {
                snapshot: xml.snapshot(),
                node: 8
            },
            material::Kind::Ocsp,
            &operation
        ),
        Err(material::RetainError::Name {
            node: 8,
            kind: material::Kind::Ocsp
        })
    ));
    assert_eq!(xml.decoded_pointer.get(), 0);
    assert_eq!(memory.used(), 0);
}

#[test]
fn certificate_material_catalogue_preserves_opaque_and_x509_values_in_order() {
    // The normative choice permits repeated X509 values and opaque other
    // certificates. Keeping either is not a completeness/authentication claim.
    let memory = funded();
    let mut xml = material_tree("CertificateValues", vec![]);
    let first = xml.nodes.len();
    xml.nodes.push(element(Some(8), XADES, "OtherCertificate"));
    let second = xml.nodes.len();
    xml.nodes
        .push(element(Some(8), XADES, "EncapsulatedX509Certificate"));
    let third = xml.nodes.len();
    xml.nodes
        .push(element(Some(8), XADES, "EncapsulatedX509Certificate"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let catalogue = material::read(&access, 8).unwrap();
    assert_eq!(catalogue.snapshot(), xml.snapshot());
    assert_eq!(catalogue.parent(), 8);
    assert_eq!(
        catalogue.entries(),
        &[
            material::Entry::OtherCertificate { node: first },
            material::Entry::Encapsulated {
                node: second,
                kind: material::Kind::Certificate
            },
            material::Entry::Encapsulated {
                node: third,
                kind: material::Kind::Certificate
            },
        ]
    );
    assert!(memory.used() > 0);
    assert_eq!(xml.decoded_pointer.get(), 0);
    drop(catalogue);
    assert_eq!(memory.used(), 0);
}

#[test]
fn attribute_material_uses_the_same_certificate_and_status_value_grammar() {
    // Annex C aliases these property types. Attribute-role presence conditions
    // and issuer trust do not justify copying or weakening the value decoder.
    let memory = funded();
    let mut xml = Tree::normal();
    let certificates = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES, "AttrAuthoritiesCertValues"));
    let certificate = xml.nodes.len();
    xml.nodes.push(element(
        Some(certificates),
        XADES,
        "EncapsulatedX509Certificate",
    ));
    let revocation = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES, "AttributeRevocationValues"));
    let group = xml.nodes.len();
    xml.nodes
        .push(element(Some(revocation), XADES, "OCSPValues"));
    let response = xml.nodes.len();
    xml.nodes
        .push(element(Some(group), XADES, "EncapsulatedOCSPValue"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let certs = material::read(&access, certificates).unwrap();
    assert_eq!(
        certs.entries(),
        &[material::Entry::Encapsulated {
            node: certificate,
            kind: material::Kind::Certificate
        }]
    );
    let status = material::read(&access, revocation).unwrap();
    assert_eq!(
        status.entries(),
        &[material::Entry::Encapsulated {
            node: response,
            kind: material::Kind::Ocsp
        }]
    );
    assert_eq!(xml.decoded_pointer.get(), 0);
}

#[test]
fn revocation_material_catalogue_preserves_each_group_without_decoding() {
    // CRL, whole OCSP and other status are distinct schema roles, not an
    // interchangeable count of "validation values" or a last-group overwrite.
    let memory = funded();
    let mut xml = material_tree("RevocationValues", vec![]);
    let crls = xml.nodes.len();
    xml.nodes.push(element(Some(8), XADES, "CRLValues"));
    let first = xml.nodes.len();
    xml.nodes
        .push(element(Some(crls), XADES, "EncapsulatedCRLValue"));
    let second = xml.nodes.len();
    xml.nodes
        .push(element(Some(crls), XADES, "EncapsulatedCRLValue"));
    let ocsp = xml.nodes.len();
    xml.nodes.push(element(Some(8), XADES, "OCSPValues"));
    let third = xml.nodes.len();
    xml.nodes
        .push(element(Some(ocsp), XADES, "EncapsulatedOCSPValue"));
    let other = xml.nodes.len();
    xml.nodes.push(element(Some(8), XADES, "OtherValues"));
    let fourth = xml.nodes.len();
    xml.nodes.push(element(Some(other), XADES, "OtherValue"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let catalogue = material::read(&access, 8).unwrap();
    assert_eq!(
        catalogue.entries(),
        &[
            material::Entry::Encapsulated {
                node: first,
                kind: material::Kind::Crl
            },
            material::Entry::Encapsulated {
                node: second,
                kind: material::Kind::Crl
            },
            material::Entry::Encapsulated {
                node: third,
                kind: material::Kind::Ocsp
            },
            material::Entry::OtherStatus { node: fourth },
        ]
    );
    assert_eq!(xml.decoded_pointer.get(), 0);
    drop(catalogue);
    assert_eq!(memory.used(), 0);
}

#[test]
fn material_empty_property_and_empty_group_have_different_schema_meanings() {
    // Empty properties are schema-valid; present empty groups are not. Neither
    // case is a shortcut to deciding conditional B-LT material completeness.
    let memory = funded();
    for property in ["CertificateValues", "RevocationValues"] {
        let xml = material_tree(property, vec![]);
        let access = Access::new(&xml, xml.snapshot(), &memory);
        assert_eq!(material::read(&access, 8).unwrap().entries(), []);
    }
    for (group, member) in [
        ("CRLValues", "EncapsulatedCRLValue"),
        ("OCSPValues", "EncapsulatedOCSPValue"),
        ("OtherValues", "OtherValue"),
    ] {
        let mut xml = material_tree("RevocationValues", vec![]);
        let child = xml.nodes.len();
        xml.nodes.push(element(Some(8), XADES, group));
        let access = Access::new(&xml, xml.snapshot(), &memory);
        match material::read(&access, 8) {
            Err(properties::Error::Missing { parent, local }) => {
                assert_eq!(parent, child);
                assert_eq!(local, member);
            }
            _ => panic!("empty group must refuse"),
        }
    }
    assert_eq!(memory.used(), 0);
}

#[test]
fn material_group_order_duplicate_and_catalogue_capacity_refuse_atomically() {
    // A partial first group cannot hide a duplicate/out-of-order later group,
    // and a storage failure cannot publish a truncated successful catalogue.
    let memory = funded();
    let mut xml = material_tree("RevocationValues", vec![]);
    let first = xml.nodes.len();
    xml.nodes.push(element(Some(8), XADES, "OCSPValues"));
    xml.nodes
        .push(element(Some(first), XADES, "EncapsulatedOCSPValue"));
    let second = xml.nodes.len();
    xml.nodes.push(element(Some(8), XADES, "CRLValues"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(material::read(&access, 8), Err(properties::Error::Order { node }) if node == second)
    );
    assert_eq!(memory.used(), 0);
    xml.nodes[second] = element(Some(8), XADES, "OCSPValues");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(material::read(&access, 8), Err(properties::Error::Duplicate { node }) if node == second)
    );
    assert_eq!(memory.used(), 0);
    xml.nodes.pop();
    let no_storage = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    let access = Access::new(&xml, xml.snapshot(), &no_storage);
    assert!(matches!(
        material::read(&access, 8),
        Err(properties::Error::Resource {
            cause: MemoryError::LimitExceeded,
            ..
        })
    ));
    assert_eq!(no_storage.used(), 0);
    assert_eq!(xml.decoded_pointer.get(), 0);
}

#[test]
fn signed_data_object_properties_do_not_skip_invalid_child_schema() {
    // Whole SignedProperties coverage cannot excuse an invalid authenticated
    // data-object property. The old structural reader never inspected this child.
    let memory = funded();
    let (mut xml, _) = certificate_tree();
    assert!(signed_roles(&xml, &memory).is_ok());
    let objects = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    let invalid = xml.nodes.len();
    xml.nodes.push(element(Some(objects), XADES, "SigningTime"));
    assert!(matches!(signed_roles(&xml, &memory),
        Err(properties::Error::Unexpected { node }) if node == invalid));
    assert_eq!(memory.used(), 0);
}

#[test]
fn signed_data_object_roles_keep_repetitions_order_and_original_covered_nodes() {
    // Each schema member is repeatable, so two formats are not a duplicate.
    // The full catalogue stays under the selected SignedProperties binding.
    let memory = funded();
    let (mut xml, _) = certificate_tree();
    let parent = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    let mut expected = Vec::new();
    for (namespace, local, role) in [
        (
            XADES,
            "DataObjectFormat",
            properties::DataObjectRole::Format,
        ),
        (
            XADES,
            "DataObjectFormat",
            properties::DataObjectRole::Format,
        ),
        (
            XADES,
            "CommitmentTypeIndication",
            properties::DataObjectRole::Commitment,
        ),
        (
            XADES,
            "AllDataObjectsTimeStamp",
            properties::DataObjectRole::AllTimestamp,
        ),
        (
            XADES,
            "IndividualDataObjectsTimeStamp",
            properties::DataObjectRole::IndividualTimestamp,
        ),
        (
            "urn:extension",
            "Property",
            properties::DataObjectRole::Extension,
        ),
    ] {
        let node = xml.nodes.len();
        xml.nodes.push(element(Some(parent), namespace, local));
        expected.push(properties::DataObject { node, role });
    }
    let signed = signed_roles(&xml, &memory).unwrap();
    assert_eq!(signed.signature(), 0);
    assert_eq!(signed.snapshot(), xml.snapshot());
    let objects = signed.data_objects().unwrap();
    assert_eq!(objects.parent(), parent);
    assert_eq!(objects.entries(), expected);
    assert!(memory.used() > 0);
    drop(signed);
    assert_eq!(memory.used(), 0);
}

#[test]
fn signed_data_object_sequence_and_wildcard_are_not_first_match_acceptance() {
    // Known properties cannot follow a later group or foreign extension;
    // an absent namespace is never admitted by ##other.
    let memory = funded();
    let (mut xml, _) = certificate_tree();
    let parent = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    let first = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "CommitmentTypeIndication"));
    let later = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "DataObjectFormat"));
    assert!(
        matches!(signed_roles(&xml, &memory), Err(properties::Error::Order { node }) if node == later)
    );
    assert_eq!(memory.used(), 0);
    xml.nodes[first] = element(Some(parent), "urn:extension", "Property");
    assert!(
        matches!(signed_roles(&xml, &memory), Err(properties::Error::Order { node }) if node == later)
    );
    assert_eq!(memory.used(), 0);
    xml.nodes.pop();
    xml.nodes[first] = element(Some(parent), "", "Property");
    assert!(
        matches!(signed_roles(&xml, &memory), Err(properties::Error::Unexpected { node }) if node == first)
    );
    assert_eq!(memory.used(), 0);
}

#[test]
fn signed_data_objects_preserve_absent_empty_and_capacity_refusal() {
    // Absence and present-empty differ structurally. Failed retention of an
    // actual member cannot be returned as either of those successful outcomes.
    let memory = funded();
    let (mut xml, _) = certificate_tree();
    assert!(
        signed_roles(&xml, &memory)
            .unwrap()
            .data_objects()
            .is_none()
    );
    let parent = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    let signed = signed_roles(&xml, &memory).unwrap();
    assert_eq!(signed.data_objects().unwrap().entries(), []);
    drop(signed);
    let node = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "DataObjectFormat"));
    let no_storage = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    assert!(matches!(signed_roles(&xml, &no_storage),
        Err(properties::Error::Resource { node: at, cause: MemoryError::LimitExceeded }) if at == node));
    assert_eq!(no_storage.used(), 0);
}

#[test]
fn signed_data_object_catalogue_keeps_current_local_work_and_owned_lifetime() {
    // The same full public path must pay every repeated member under the current
    // producing operation. A retained result keeps capacity after that scope ends.
    let memory = funded();
    let (mut xml, _) = certificate_tree();
    let parent = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    for _ in 0..32 {
        xml.nodes
            .push(element(Some(parent), XADES, "DataObjectFormat"));
    }
    let full = signed_roles(&xml, &memory).unwrap();
    let complete_work = memory.work_used();
    assert_eq!(full.data_objects().unwrap().entries().len(), 32);
    drop(full);
    assert_eq!(memory.used(), 0);

    let query = funded();
    let parser = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: u64::try_from(complete_work - 1).unwrap(),
            ..Default::default()
        },
        query.clone(),
    );
    let operation = parser.read(&[], 0).unwrap();
    let execution = operation.execution();
    let access = Access::new(&xml, xml.snapshot(), &execution);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    assert!(matches!(
        properties::read(&access, &bound),
        Err(properties::Error::Access(
            AccessError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            } | AccessError::Xml(Cause::Resource(MemoryError::WorkExceeded))
        ) | properties::Error::Child(structured_xades::xml::ChildError::Access(
            AccessError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            }
        )) | properties::Error::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert_eq!(query.used(), 0);

    let retained = {
        let parser = structured_asn1::Parser::der(query.clone());
        let operation = parser.read(&[], 0).unwrap();
        let execution = operation.execution();
        let access = Access::new(&xml, xml.snapshot(), &execution);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        properties::read(&access, &bound).unwrap()
    };
    assert_eq!(retained.data_objects().unwrap().entries().len(), 32);
    assert!(query.used() > 0);
    drop(retained);
    assert_eq!(query.used(), 0);
}

fn all_data_timestamp_tree() -> (Tree, usize, usize) {
    let (mut xml, _) = certificate_tree();
    let objects = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    let stamp = xml.nodes.len();
    xml.nodes
        .push(element(Some(objects), XADES, "AllDataObjectsTimeStamp"));
    let method = xml.nodes.len();
    xml.nodes
        .push(element(Some(stamp), DS, "CanonicalizationMethod"));
    xml.nodes
        .push(element(Some(stamp), XADES, "EncapsulatedTimeStamp"));
    (xml, stamp, method)
}

fn individual_timestamp_tree() -> (Tree, usize, usize, [usize; 2]) {
    let (mut xml, node, method) = all_data_timestamp_tree();
    xml.nodes[node].value = Node::Element(Name {
        namespace: XADES,
        local: "IndividualDataObjectsTimeStamp",
    });
    // The fixture keeps original sibling order by inserting Include records
    // before the existing method/token records. Existing ids below method stay.
    xml.nodes
        .insert(method, element(Some(node), XADES, "Include"));
    xml.nodes
        .insert(method + 1, element(Some(node), XADES, "Include"));
    let manifest = xml.nodes.len();
    xml.nodes.push(element(Some(1), DS, "Manifest"));
    let reference = xml.nodes.len();
    xml.nodes.push(element(Some(manifest), DS, "Reference"));
    xml.references.push(Reference {
        node: reference,
        target: None,
        kind: None,
        status: Status::Valid,
        coverage: Coverage::Transformed,
    });
    xml.include_routes = vec![
        (method, 2, Boolean::Value(true)),
        (method + 1, 0, Boolean::Value(true)),
    ];
    (xml, node, method + 2, [method, method + 1])
}

#[test]
fn individual_timestamp_replays_signed_manifest_and_direct_references_in_include_order() {
    // EN5.2.8.2 does not restrict Include to SignedInfo. The synthetic adapter
    // maps first Include to Manifest and second to SignedInfo; output framing
    // tests original identity/order, not canonicalization interoperability.
    for outside_signature in [false, true] {
        let memory = funded();
        let (mut xml, node, method, _) = individual_timestamp_tree();
        if outside_signature {
            // Authentication comes from the selected owner's receipt, not a
            // requirement that every signed Manifest be inside ds:Signature.
            let manifest = xml.nodes[xml.references[2].node].parent.unwrap();
            let document = xml.nodes.len();
            xml.nodes.push(Record {
                parent: None,
                value: Node::Other,
            });
            xml.nodes[0].parent = Some(document);
            xml.nodes[manifest].parent = Some(document);
        }
        let signed = signed_roles(&xml, &memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp =
            timestamp::read_individual_data_objects(&access, &bound, &signed, node).unwrap();
        assert_eq!(stamp.role(), Role::IndividualDataObjects);
        let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
        let mut sink = Collect::new(&memory);
        stream::run(&mut input, &mut sink, &memory, "individual.input", 0).unwrap();
        let method = u8::try_from(method).unwrap();
        assert_eq!(
            sink.bytes(),
            &[b'R', 2, b'M', method, b'R', 0, b'M', method]
        );
        assert_eq!(xml.streamed.get(), 2);
    }
}

#[test]
fn individual_include_requires_explicit_true_and_authenticated_eligible_reference_before_replay() {
    // Absent/false/bad boolean, unauthenticated reference and recursion through
    // SignedProperties cannot be hidden as an empty timestamp input.
    for value in [Boolean::Absent, Boolean::Value(false), Boolean::Malformed] {
        let memory = funded();
        let (mut xml, node, _, includes) = individual_timestamp_tree();
        xml.include_routes[0].2 = value;
        let signed = signed_roles(&xml, &memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp =
            timestamp::read_individual_data_objects(&access, &bound, &signed, node).unwrap();
        assert!(
            matches!(Input::prepare(&xml, &bound, &stamp, &memory), Err(InputError::ReferencedData { node, value: actual }) if node == includes[0] && actual == value)
        );
        assert_eq!(xml.streamed.get(), 0);
    }
    for ordinal in [1, 2] {
        let memory = funded();
        let (mut xml, node, _, includes) = individual_timestamp_tree();
        xml.include_routes[0].1 = ordinal;
        if ordinal == 2 {
            xml.references[2].status = Status::Unchecked;
        }
        let signed = signed_roles(&xml, &memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp =
            timestamp::read_individual_data_objects(&access, &bound, &signed, node).unwrap();
        assert!(
            matches!(Input::prepare(&xml, &bound, &stamp, &memory), Err(InputError::Reference { node, resolution: Resolution::Resolved(()) }) if node == includes[0])
        );
        assert_eq!(xml.streamed.get(), 0);
    }
}

#[test]
fn individual_include_order_scope_and_resource_refusal_never_return_partial_input() {
    // Property membership and all Include preparation finish before any source
    // output. Failure must roll back temporary parts, retaining only stamp data.
    let memory = funded();
    let (xml, node, _, _) = individual_timestamp_tree();
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read_individual_data_objects(&access, &bound, &signed, node).unwrap();
    let unfunded = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    assert!(matches!(
        Input::prepare(&xml, &bound, &stamp, &unfunded),
        Err(InputError::Resource { .. })
    ));
    assert_eq!(unfunded.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
    assert!(matches!(
        timestamp::read_all_data_objects(&access, &bound, &signed, node),
        Err(InputError::Unexpected { .. })
    ));
    drop(stamp);
    drop(signed);
    let mut xml = xml;
    let late = xml.nodes.len();
    xml.nodes.push(element(Some(node), XADES, "Include"));
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(timestamp::read_individual_data_objects(&access, &bound, &signed, node), Err(InputError::Order { node }) if node == late)
    );
}

#[test]
fn all_data_timestamp_uses_reference_order_and_excludes_each_properties_reference() {
    // EN5.2.8.1 uses direct reference OUTPUTS, not XML elements or nested
    // Manifest targets. Repeated protecting references never include the timestamp
    // itself recursively through SignedProperties. Framing is not a C14N oracle.
    let memory = funded();
    let (mut xml, node, method) = all_data_timestamp_tree();
    let repeat = xml.nodes.len();
    xml.nodes.push(element(Some(9), DS, "Reference"));
    let mut reference = xml.references[1];
    reference.node = repeat;
    xml.references.push(reference);
    let manifest_reference = xml.nodes.len();
    xml.nodes.push(element(Some(9), DS, "Reference"));
    xml.references.push(Reference {
        node: manifest_reference,
        target: Some(1),
        kind: Some("http://www.w3.org/2000/09/xmldsig#Manifest"),
        status: Status::Valid,
        coverage: Coverage::Transformed,
    });
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read_all_data_objects(&access, &bound, &signed, node).unwrap();
    assert_eq!(stamp.role(), Role::AllDataObjects);
    let mut input = Input::prepare(&xml, &bound, &stamp, &memory).unwrap();
    let mut sink = Collect::new(&memory);
    stream::run(
        &mut input,
        &mut sink,
        &memory,
        "all-data.timestamp.input",
        0,
    )
    .unwrap();
    let method = u8::try_from(method).unwrap();
    assert_eq!(
        sink.bytes(),
        &[b'R', 0, b'M', method, b'R', 3, b'M', method]
    );
    assert_eq!(xml.streamed.get(), 2);
}

#[test]
fn all_data_timestamp_keeps_multiple_tokens_and_refuses_explicit_include() {
    // AllDataObjects uses implicit input; Individual's Include/referencedData
    // mechanism is different. More than one RFC3161 token is permitted here.
    let memory = funded();
    let (mut xml, node, method) = all_data_timestamp_tree();
    let extra = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "EncapsulatedTimeStamp"));
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let stamp = timestamp::read_all_data_objects(&access, &bound, &signed, node).unwrap();
    assert_eq!(stamp.tokens(), &[method + 1, extra]);
    drop(stamp);
    drop(signed);
    xml.nodes[extra] = element(Some(node), XADES, "Include");
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(timestamp::read_all_data_objects(&access, &bound, &signed, node),
        Err(InputError::Unexpected { node: at }) if at == extra)
    );
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn all_data_timestamp_cannot_substitute_unsigned_or_another_signature_property() {
    // Identical QName is insufficient: membership in this selected signature's
    // authenticated SignedDataObjectProperties is checked before input execution.
    let memory = funded();
    let (mut xml, node, _) = all_data_timestamp_tree();
    let wrong = xml.nodes.len();
    xml.nodes
        .push(element(Some(7), XADES, "AllDataObjectsTimeStamp"));
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    assert!(
        matches!(timestamp::read_all_data_objects(&access, &bound, &signed, wrong),
        Err(InputError::Foreign { node: at }) if at == wrong)
    );
    assert!(matches!(
        timestamp::read(&access, &bound, node),
        Err(InputError::Foreign { .. })
    ));
    let mut foreign = xml;
    foreign.document = 10;
    let foreign_signed = signed_roles(&foreign, &memory).unwrap();
    let access = Access::new(&foreign, foreign.snapshot(), &memory);
    assert!(matches!(
        timestamp::read_all_data_objects(&access, &bound, &foreign_signed, node),
        Err(InputError::Foreign { .. })
    ));
    assert_eq!(foreign.streamed.get(), 0);
}

fn data_format_tree() -> (Tree, usize, usize) {
    let (mut xml, _) = certificate_tree();
    let parent = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    let node = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "DataObjectFormat"));
    let mime = xml.mime(node);
    xml.object_reference = Some("#data-reference");
    (xml, node, mime)
}

fn commitment_tree(all: bool) -> (Tree, usize, usize) {
    let (mut xml, _) = certificate_tree();
    let parent = xml.nodes.len();
    xml.nodes
        .push(element(Some(3), XADES, "SignedDataObjectProperties"));
    let node = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "CommitmentTypeIndication"));
    let kind = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "CommitmentTypeId"));
    let identifier = xml.nodes.len();
    xml.nodes.push(element(Some(kind), XADES, "Identifier"));
    xml.nodes.push(Record {
        parent: Some(identifier),
        value: Node::Text("https://example.test/commitment"),
    });
    let choice = xml.nodes.len();
    xml.nodes.push(element(
        Some(node),
        XADES,
        if all {
            "AllSignedDataObjects"
        } else {
            "ObjectReference"
        },
    ));
    if !all {
        xml.nodes.push(Record {
            parent: Some(choice),
            value: Node::Text("#data-reference"),
        });
        xml.include_routes.push((choice, 0, Boolean::Absent));
    }
    (xml, node, choice)
}

fn policy_tree(implied: bool, special: bool) -> (Tree, usize, usize) {
    let (mut xml, _) = certificate_tree();
    let property = xml.nodes.len();
    xml.nodes
        .push(element(Some(4), XADES, "SignaturePolicyIdentifier"));
    let node = xml.nodes.len();
    xml.nodes.push(element(
        Some(property),
        XADES,
        if implied {
            "SignaturePolicyImplied"
        } else {
            "SignaturePolicyId"
        },
    ));
    if !implied {
        let id = xml.nodes.len();
        xml.nodes.push(element(Some(node), XADES, "SigPolicyId"));
        let identifier = xml.nodes.len();
        xml.nodes.push(element(Some(id), XADES, "Identifier"));
        xml.nodes.push(Record {
            parent: Some(identifier),
            value: Node::Text("https://example.test/policy/v1"),
        });
        if special {
            let transforms = xml.nodes.len();
            xml.nodes.push(element(Some(node), DS, "Transforms"));
            xml.nodes.push(element(Some(transforms), DS, "Transform"));
            xml.digest_algorithm = Some(
                "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification",
            );
        }
        let hash = xml.nodes.len();
        xml.nodes.push(element(Some(node), XADES, "SigPolicyHash"));
        xml.nodes.push(element(Some(hash), DS, "DigestMethod"));
        xml.nodes.push(element(Some(hash), DS, "DigestValue"));
    }
    (xml, property, node)
}

#[test]
fn explicit_policy_store_preserves_embedded_or_local_source_without_acquisition() {
    // The unsigned source choice does not authenticate its content. It only
    // becomes eligible for comparison under the original explicit signed hash.
    let memory = funded();
    for local in [false, true] {
        let (mut xml, _, _) = policy_tree(false, false);
        let store = xml.nodes.len();
        xml.nodes
            .push(element(Some(7), XADES_141, "SignaturePolicyStore"));
        let specification = xml.nodes.len();
        xml.nodes
            .push(element(Some(store), XADES_141, "SPDocSpecification"));
        let identifier = xml.nodes.len();
        xml.nodes
            .push(element(Some(specification), XADES, "Identifier"));
        xml.nodes.push(Record {
            parent: Some(identifier),
            value: Node::Text("https://example.test/spec"),
        });
        let value = xml.nodes.len();
        xml.nodes.push(element(
            Some(store),
            XADES_141,
            if local {
                "SigPolDocLocalURI"
            } else {
                "SignaturePolicyDocument"
            },
        ));
        let signed = signed_roles(&xml, &memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let declaration = policy::read(&access, &signed).unwrap().unwrap();
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let unsigned = unsigned::read(&access, &bound, unsigned::Requirements::Basic).unwrap();
        // The source dispatch consumes one unit; the retained policy pair
        // still needs two. Preserve the last unit rather than entering fields.
        let short = Memory::new(Arc::new(MemoryAccount::new(0, 2)));
        let lower = Access::new(&xml, xml.snapshot(), &short);
        assert!(matches!(
            policy::read_store(&lower, &unsigned, Some(&declaration)),
            Err(properties::Error::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            })
        ));
        assert_eq!(short.work_remaining(), 1);
        let source = policy::read_store(&access, &unsigned, Some(&declaration))
            .unwrap()
            .unwrap();
        assert_eq!(source.snapshot(), xml.snapshot());
        assert_eq!(source.signature(), 0);
        assert_eq!(source.node(), store);
        assert_eq!(source.specification().identifier, identifier);
        match source.document() {
            policy::StoredDocument::Local(node) => {
                assert!(local);
                assert_eq!(node, value);
            }
            policy::StoredDocument::Embedded(node) => {
                assert!(!local);
                assert_eq!(node, value);
            }
        }
        assert_eq!(xml.streamed.get(), 0);
        assert_eq!(xml.decoded_pointer.get(), 0);
    }
    assert_eq!(memory.used(), 0);
}

#[test]
fn signed_policy_implied_is_an_original_empty_choice_not_an_accepted_policy() {
    // Implied remains explicit original syntax: neither absent policy nor an
    // empty marker selects an application policy or proves a document digest.
    let memory = funded();
    let (mut xml, property, node) = policy_tree(true, false);
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let reading = policy::read(&access, &signed).unwrap().unwrap();
    assert_eq!(reading.snapshot(), xml.snapshot());
    assert_eq!(reading.signature(), 0);
    assert_eq!(reading.node(), property);
    assert!(
        matches!(reading.declaration(), policy::Declaration::Implied(original) if *original == node)
    );
    let unexpected = xml.nodes.len();
    xml.nodes.push(element(Some(node), XADES, "not-empty"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(policy::read(&access, &signed), Err(properties::Error::Unexpected { node }) if node == unexpected)
    );
    xml.nodes.pop();
    let extra = xml.nodes.len();
    xml.nodes
        .push(element(Some(property), XADES, "SignaturePolicyId"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(policy::read(&access, &signed), Err(properties::Error::Unexpected { node }) if node == extra)
    );
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn policy_specification_transform_requires_original_qualifier_before_execution() {
    // EN5.2.9.1 requires an actual SPDocSpecification for its special transform.
    // AnyType can contain multiple direct specifications; parsing preserves all
    // of them without pretending to choose/execute one technical specification.
    let memory = funded();
    let (mut xml, _, node) = policy_tree(false, true);
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        policy::read(&access, &signed),
        Err(properties::Error::Missing {
            local: "SPDocSpecification",
            ..
        })
    ));
    assert_eq!(memory.used(), 0);
    let qualifiers = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "SigPolicyQualifiers"));
    let wrapper = xml.nodes.len();
    xml.nodes
        .push(element(Some(qualifiers), XADES, "SigPolicyQualifier"));
    let mut originals = Vec::new();
    for value in [
        "https://example.test/spec/one",
        "https://example.test/spec/two",
    ] {
        let specification = xml.nodes.len();
        originals.push(specification);
        xml.nodes
            .push(element(Some(wrapper), XADES_141, "SPDocSpecification"));
        let identifier = xml.nodes.len();
        xml.nodes
            .push(element(Some(specification), XADES, "Identifier"));
        xml.nodes.push(Record {
            parent: Some(identifier),
            value: Node::Text(value),
        });
    }
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let reading = policy::read(&access, &signed).unwrap().unwrap();
    let policy::Declaration::Explicit(explicit) = reading.declaration() else {
        panic!("not explicit")
    };
    assert_eq!(explicit.qualifiers.len(), 1);
    assert_eq!(&*explicit.qualifiers[0].specifications, &originals);
    assert!(memory.used() > 0);
    drop(reading);
    assert_eq!(memory.used(), 0);
    let empty = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    let access = Access::new(&xml, xml.snapshot(), &empty);
    assert!(matches!(
        policy::read(&access, &signed),
        Err(properties::Error::Resource { .. })
    ));
    assert_eq!(empty.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn absent_optional_signed_properties_still_check_the_live_source_generation() {
    // An absent optional property must not turn stale original evidence into
    // a successful None result merely because no inner node needs decoding.
    let memory = funded();
    let (xml, _) = certificate_tree();
    let signed = signed_roles(&xml, &memory).unwrap();
    xml.generation.set(2);
    let access = Access::new(&xml, signed.snapshot(), &memory);
    assert!(matches!(
        role::read(&access, &signed),
        Err(properties::Error::Access(AccessError::Changed { .. }))
    ));
    assert!(matches!(
        policy::read(&access, &signed),
        Err(properties::Error::Access(AccessError::Changed { .. }))
    ));
}

#[test]
fn signed_commitment_all_and_explicit_manifest_share_original_reference_authority() {
    // All expands the actual authenticated catalogue except SignedProperties;
    // explicit element-content URI resolves through that same owner authority.
    let memory = funded();
    for all in [true, false] {
        let (mut xml, node, choice) = commitment_tree(all);
        let manifest = xml.nodes.len();
        xml.nodes.push(element(Some(1), DS, "Manifest"));
        let reference = xml.nodes.len();
        xml.nodes.push(element(Some(manifest), DS, "Reference"));
        xml.references.push(Reference {
            node: reference,
            target: None,
            kind: None,
            status: Status::Valid,
            coverage: Coverage::Transformed,
        });
        if !all {
            xml.include_routes[0] = (choice, 2, Boolean::Absent);
        }
        let signed = signed_roles(&xml, &memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let original = commitment::read(&access, &signed, 0).unwrap();
        assert_eq!(original.node(), node);
        // Retained commitment evidence cannot spend an unadmitted comparison
        // before this operation's first source query or output allocation.
        let short = Memory::new(Arc::new(MemoryAccount::new(0, 1)));
        let lower = Access::new(&xml, xml.snapshot(), &short);
        assert!(matches!(
            commitment::associate(&lower, &bound, &original),
            Err(commitment::AssociationError::Property(
                properties::Error::Resource {
                    cause: MemoryError::WorkExceeded,
                    ..
                }
            ))
        ));
        assert_eq!(short.work_remaining(), 1);
        let objects = commitment::associate(&access, &bound, &original).unwrap();
        if all {
            assert_eq!(
                objects
                    .iter()
                    .map(|object| object.reference)
                    .collect::<Vec<_>>(),
                [10, reference]
            );
        } else {
            assert_eq!(objects.len(), 1);
            assert_eq!(objects[0].reference, reference);
        }
        assert_eq!(objects.last().unwrap().parent, Parent::Manifest(manifest));
        assert_eq!(xml.streamed.get(), 0);
    }
}

#[test]
fn signed_commitment_refuses_mixed_choices_qualifiers_and_nonempty_all_marker() {
    // Choice/cardinality and the commitment-specific no-Qualifier rule are
    // schema/normative requirements, independent of the commitment URI meaning.
    let memory = funded();
    let (mut xml, node, choice) = commitment_tree(true);
    let extra = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "ObjectReference"));
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(commitment::read(&access, &signed, 0), Err(properties::Error::Unexpected { node }) if node == extra)
    );
    xml.nodes.pop();
    xml.identifier_qualifier = Some("OIDAsURI");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        commitment::read(&access, &signed, 0),
        Err(properties::Error::Forbidden { .. })
    ));
    xml.identifier_qualifier = None;
    let nested = xml.nodes.len();
    xml.nodes.push(element(Some(choice), XADES, "bad"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(commitment::read(&access, &signed, 0), Err(properties::Error::Unexpected { node }) if node == nested)
    );
    xml.nodes.pop();
    xml.nodes.push(Record {
        parent: Some(choice),
        value: Node::Text("not empty"),
    });
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        commitment::read(&access, &signed, 0),
        Err(properties::Error::Child(_))
    ));
}

#[test]
fn signed_commitment_catalogue_refusal_rolls_back_without_partial_association() {
    // Retained output is dropped if catalogue completion fails; a resource
    // refusal cannot become an empty successful all-objects commitment.
    let storage = funded();
    let (mut xml, _, _) = commitment_tree(true);
    let signed = signed_roles(&xml, &storage).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &storage);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let original = commitment::read(&access, &signed, 0).unwrap();
    xml.reference_completeness = Completeness::Incomplete(10);
    let query = funded();
    let access = Access::new(&xml, xml.snapshot(), &query);
    assert!(matches!(
        commitment::associate(&access, &bound, &original),
        Err(commitment::AssociationError::Incomplete { node: 10 })
    ));
    assert_eq!(query.used(), 0);
    let empty = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    let access = Access::new(&xml, xml.snapshot(), &empty);
    assert!(matches!(
        commitment::associate(&access, &bound, &original),
        Err(commitment::AssociationError::Property(
            properties::Error::Resource { .. }
        ))
    ));
    assert_eq!(empty.used(), 0);
    xml.document += 1;
    let access = Access::new(&xml, xml.snapshot(), &query);
    assert!(matches!(
        commitment::associate(&access, &bound, &original),
        Err(commitment::AssociationError::Property(
            properties::Error::Access(AccessError::Changed { .. })
        ))
    ));
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn data_format_identifier_uses_one_auxiliary_schema_and_exact_qualifier() {
    // An optional ObjectIdentifier still has required inner syntax; Qualifier
    // uses the official schema's case-sensitive enumeration, never a default.
    let storage = funded();
    let (mut xml, property, object_identifier) = data_format_tree();
    xml.nodes.last_mut().unwrap().value = Node::Other;
    xml.nodes[object_identifier].value = Node::Element(Name {
        namespace: XADES,
        local: "ObjectIdentifier",
    });
    let signed = signed_roles(&xml, &storage).unwrap();
    let query = memory(100_000);
    let access = Access::new(&xml, xml.snapshot(), &query);
    assert!(matches!(format::read(&access, &signed, 0),
        Err(format::FormatError::Property(properties::Error::Missing { parent, local: "Identifier" })) if parent == object_identifier));
    let identifier = xml.nodes.len();
    xml.nodes
        .push(element(Some(object_identifier), XADES, "Identifier"));
    xml.nodes.push(Record {
        parent: Some(identifier),
        value: Node::Text("urn:oid:1.2.3"),
    });
    xml.mime(property);
    xml.identifier_qualifier = Some("OIDAsURN");
    let access = Access::new(&xml, xml.snapshot(), &query);
    assert!(format::read(&access, &signed, 0).is_ok());
    let read = identifier::read(&access, object_identifier).unwrap();
    assert_eq!(read.identifier, identifier);
    assert_eq!(read.qualifier, Some(identifier::Qualifier::Urn));
    xml.identifier_qualifier = Some("OIDASURN");
    let access = Access::new(&xml, xml.snapshot(), &query);
    assert!(matches!(identifier::read(&access, object_identifier),
        Err(properties::Error::Unexpected { node }) if node == identifier));
    xml.identifier_qualifier = None;
    let documentation = xml.nodes.len();
    xml.nodes.push(element(
        Some(object_identifier),
        XADES,
        "DocumentationReferences",
    ));
    let access = Access::new(&xml, xml.snapshot(), &query);
    assert!(matches!(identifier::read(&access, object_identifier),
        Err(properties::Error::Missing { parent, local: "DocumentationReference" }) if parent == documentation));
    let reference = xml.nodes.len();
    xml.nodes.push(element(
        Some(documentation),
        XADES,
        "DocumentationReference",
    ));
    xml.nodes.push(Record {
        parent: Some(reference),
        value: Node::Text("https://example.test/spec"),
    });
    let access = Access::new(&xml, xml.snapshot(), &query);
    let read = identifier::read(&access, object_identifier).unwrap();
    assert_eq!(read.qualifier, None);
    assert_eq!(read.documentation, Some(documentation));
    assert_eq!(query.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn production_place_requires_a_nonempty_ordered_current_schema() {
    // EN §5.2.5 forbids an empty place even though all XSD fields are optional.
    // Once present, the fields keep the V2 sequence and singleton cardinality.
    let memory = funded();
    let (mut xml, _) = certificate_tree();
    let place = xml.nodes.len();
    xml.nodes
        .push(element(Some(4), XADES, "SignatureProductionPlaceV2"));
    assert!(matches!(signed_roles(&xml, &memory),
        Err(properties::Error::Missing { parent, .. }) if parent == place));
    let city = xml.nodes.len();
    xml.nodes.push(element(Some(place), XADES, "City"));
    xml.nodes.push(Record {
        parent: Some(city),
        value: Node::Text("Kyiv"),
    });
    assert_eq!(signed_roles(&xml, &memory).unwrap().place(), Some(place));
    let country = xml.nodes.len();
    xml.nodes.push(element(Some(place), XADES, "CountryName"));
    let late_street = xml.nodes.len();
    xml.nodes.push(element(Some(place), XADES, "StreetAddress"));
    assert!(matches!(signed_roles(&xml, &memory),
        Err(properties::Error::Order { node }) if node == late_street));
    xml.nodes.pop();
    xml.nodes[country].value = Node::Element(Name {
        namespace: XADES,
        local: "City",
    });
    assert!(matches!(signed_roles(&xml, &memory),
        Err(properties::Error::Duplicate { node }) if node == country));
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn baseline_data_format_keeps_covered_original_nodes_without_allocating() {
    // This validates baseline structure only, not URI resolution, MIME syntax
    // or agreement with the data object's own attributes.
    let storage = funded();
    let (xml, node, mime) = data_format_tree();
    let signed = signed_roles(&xml, &storage).unwrap();
    let original_access = Access::new(&xml, xml.snapshot(), &storage);
    let bound = binding::bind(
        &original_access,
        &container::locate(&original_access, 0).unwrap(),
    )
    .unwrap();
    let query = memory(100_000);
    let access = Access::new(&xml, xml.snapshot(), &query);
    let original = format::read(&access, &signed, 0).unwrap();
    // Reusing a retained format does not pay its new binding comparison.
    let short = Memory::new(Arc::new(MemoryAccount::new(0, 1)));
    let lower = Access::new(&xml, xml.snapshot(), &short);
    assert!(matches!(
        format::resolve(&lower, &bound, &original),
        Err(format::FormatError::Property(properties::Error::Access(
            AccessError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            }
        )))
    ));
    assert_eq!(short.work_remaining(), 1);
    assert_eq!(original.snapshot(), xml.snapshot());
    assert_eq!(original.signature(), 0);
    assert_eq!(original.node(), node);
    assert_eq!(original.mime(), mime);
    assert_eq!(original.description(), None);
    assert_eq!(original.identifier(), None);
    assert_eq!(original.encoding(), None);
    assert_eq!(query.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn data_format_object_metadata_is_exact_across_text_fragments_and_comments() {
    // EN §5.2.4 requires exact values, not MIME case folding. Character-data
    // fragments concatenate, comments contribute nothing, and mismatch refuses.
    let memory = funded();
    let (mut xml, property, mime) = data_format_tree();
    xml.nodes.last_mut().unwrap().value = Node::Other;
    xml.object_mime = Some("text/plain");
    xml.nodes.push(Record {
        parent: Some(mime),
        value: Node::Text("text/"),
    });
    xml.nodes.push(Record {
        parent: Some(mime),
        value: Node::Other,
    });
    let last = xml.nodes.len();
    xml.nodes.push(Record {
        parent: Some(mime),
        value: Node::Text("plain"),
    });
    xml.references[0].target = Some(1);
    xml.include_routes.push((property, 0, Boolean::Absent));
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let original = format::read(&access, &signed, 0).unwrap();
    assert!(matches!(
        format::resolve(&access, &bound, &original),
        Ok(Resolution::Resolved(_))
    ));
    xml.nodes[last].value = Node::Text("PLAIN");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(format::resolve(&access, &bound, &original).is_err());
    // A nested element is not simple content, even if its text would match.
    xml.nodes[last].value = Node::Element(Name {
        namespace: XADES,
        local: "nested",
    });
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(format::resolve(&access, &bound, &original).is_err());
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn data_format_encoding_agreement_preserves_absence_and_original_target_kind() {
    // A present Encoding must match exactly. Absent object metadata adds no
    // default, and similarly named attributes on a non-ds:Object are irrelevant.
    let storage = funded();
    let (mut xml, property, _) = data_format_tree();
    let encoding = xml.nodes.len();
    xml.nodes.push(element(Some(property), XADES, "Encoding"));
    let text = xml.nodes.len();
    xml.nodes.push(Record {
        parent: Some(encoding),
        value: Node::Text("urn:encoding:one"),
    });
    xml.references[0].target = Some(1);
    xml.include_routes.push((property, 0, Boolean::Absent));
    let signed = signed_roles(&xml, &storage).unwrap();
    let query = memory(100_000);
    let access = Access::new(&xml, xml.snapshot(), &query);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let original = format::read(&access, &signed, 0).unwrap();
    assert!(matches!(
        format::resolve(&access, &bound, &original),
        Ok(Resolution::Resolved(_))
    ));
    xml.binary_encoding = Some("urn:encoding:one");
    let access = Access::new(&xml, xml.snapshot(), &query);
    assert!(matches!(
        format::resolve(&access, &bound, &original),
        Ok(Resolution::Resolved(_))
    ));
    xml.nodes[text].value = Node::Text("urn:encoding:ONE");
    let access = Access::new(&xml, xml.snapshot(), &query);
    assert!(matches!(format::resolve(&access, &bound, &original),
        Err(format::FormatError::Metadata { node, object: 1, local: "Encoding" }) if node == encoding));
    xml.nodes[1].value = Node::Element(Name {
        namespace: "urn:application",
        local: "Object",
    });
    let access = Access::new(&xml, xml.snapshot(), &query);
    assert!(matches!(
        format::resolve(&access, &bound, &original),
        Ok(Resolution::Resolved(_))
    ));
    assert_eq!(query.used(), 0);
    let exhausted = memory(0);
    let access = Access::new(&xml, xml.snapshot(), &exhausted);
    assert!(matches!(
        format::resolve(&access, &bound, &original),
        Err(format::FormatError::Property(properties::Error::Access(
            AccessError::Resource { .. }
        )))
    ));
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn data_format_simple_values_reject_nested_elements_without_object_metadata() {
    // Simple-typed property content cannot hide a child element merely because
    // no ds:Object attribute is present to trigger the agreement comparison.
    let memory = funded();
    let (mut xml, _, mime) = data_format_tree();
    xml.nodes
        .push(element(Some(mime), "urn:application", "nested"));
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        format::read(&access, &signed, 0),
        Err(format::FormatError::Property(
            properties::Error::Unexpected { .. }
        ))
    ));
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn data_format_empty_mime_is_malformed_not_an_implied_default() {
    // RFC2045 subtype and type are mandatory. XAdES has no missing/empty
    // MimeType fallback to text/plain, regardless of ds:Object metadata.
    let memory = funded();
    let (mut xml, _, mime) = data_format_tree();
    xml.nodes.last_mut().unwrap().value = Node::Other;
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(format::read(&access, &signed, 0),
        Err(format::FormatError::Property(properties::Error::Lexical { node, local: "MimeType" })) if node == mime));
}

#[test]
fn baseline_data_format_requires_mime_and_original_reference_attribute() {
    // The general schema permits absent MimeType; the baseline table does not.
    // Neither omission receives a fabricated MIME value or default reference.
    let memory = funded();
    let (mut xml, node, _) = data_format_tree();
    // Remove the complete MimeType field, including its text child.
    xml.nodes.pop();
    xml.nodes.pop();
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(format::read(&access, &signed, 0),
        Err(format::FormatError::Property(properties::Error::Missing { parent, local: "MimeType" })) if parent == node));
    xml.object_reference = None;
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(format::read(&access, &signed, 0),
        Err(format::FormatError::Property(properties::Error::Missing { parent, local: "ObjectReference" })) if parent == node));
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn baseline_format_resolves_signed_manifest_without_promoting_foreign_or_unchecked_references() {
    // Same resolver as timestamp Include: a signed Manifest instruction is
    // eligible, a foreign instruction or unchecked target is not a digest fact.
    let memory = funded();
    let (mut xml, node, _) = data_format_tree();
    let manifest = xml.nodes.len();
    xml.nodes.push(element(Some(1), DS, "Manifest"));
    let reference = xml.nodes.len();
    xml.nodes.push(element(Some(manifest), DS, "Reference"));
    xml.references.push(Reference {
        node: reference,
        target: Some(1),
        kind: None,
        status: Status::Valid,
        coverage: Coverage::ElementContent,
    });
    xml.object_reference = Some("#manifest");
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let original = format::read(&access, &signed, 0).unwrap();
    let Resolution::Resolved(resolved) = format::resolve(&access, &bound, &original).unwrap()
    else {
        panic!("signed Manifest reference unresolved");
    };
    assert_eq!(resolved.reference, reference);
    assert_eq!(resolved.target, Some(1));
    assert_eq!(resolved.parent, Parent::Manifest(manifest));
    assert_eq!(xml.streamed.get(), 0);
    xml.object_reference = Some("#foreign");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        format::resolve(&access, &bound, &original),
        Ok(Resolution::Unauthenticated)
    ));
    xml.object_reference = Some("#manifest");
    xml.references[2].status = Status::Unchecked;
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(format::resolve(&access, &bound, &original), Err(format::FormatError::Reference { node: at, status: Status::Unchecked }) if at == reference)
    );
    xml.generation.set(2);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(format::resolve(&access, &bound, &original), Err(format::FormatError::Property(properties::Error::Access(AccessError::Changed { node: at }))) if at == node)
    );
}

#[test]
fn format_coverage_requires_every_authenticated_manifest_object_not_just_resolved_properties() {
    // A missing format for an indirectly signed object used to be invisible
    // to property-only traversal. Complete instruction enumeration detects it.
    let memory = funded();
    let (mut xml, format_node, _) = data_format_tree();
    xml.object_reference = Some("#direct");
    let manifest = xml.nodes.len();
    xml.nodes.push(element(Some(1), DS, "Manifest"));
    let reference = xml.nodes.len();
    xml.nodes.push(element(Some(manifest), DS, "Reference"));
    xml.references.push(Reference {
        node: reference,
        target: None,
        kind: None,
        status: Status::Valid,
        coverage: Coverage::Transformed,
    });
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let before = memory.used();
    assert!(
        matches!(format::check_references(&access, &bound, &signed, None), Err(format::CoverageError::Missing { reference: at }) if at == reference)
    );
    assert_eq!(memory.used(), before);
    let parent = xml.nodes[format_node].parent.unwrap();
    let additional = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "DataObjectFormat"));
    xml.mime(additional);
    xml.include_routes = vec![
        (format_node, 0, Boolean::Absent),
        (additional, 2, Boolean::Absent),
    ];
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let complete = format::check_references(&access, &bound, &signed, None).unwrap();
    assert_eq!(complete.len(), 2);
    assert_eq!(complete[0].reference(), 10);
    assert_eq!(complete[0].original().node(), format_node);
    assert_eq!(complete[1].reference(), reference);
    assert_eq!(complete[1].original().node(), additional);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn format_coverage_preserves_incomplete_manifest_and_duplicate_association_refusals() {
    // A fail-fast/unchecked Manifest array cannot prove catalogue completeness,
    // even when all descriptors present so far have their format.
    let memory = funded();
    let (mut xml, node, _) = data_format_tree();
    xml.object_reference = Some("#direct");
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    xml.reference_completeness = Completeness::Unchecked(1);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        format::check_references(&access, &bound, &signed, None),
        Err(format::CoverageError::Incomplete { node: 1 })
    ));
    xml.reference_completeness = Completeness::Incomplete(1);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        format::check_references(&access, &bound, &signed, None),
        Err(format::CoverageError::Incomplete { node: 1 })
    ));
    xml.reference_completeness = Completeness::Complete;
    let parent = xml.nodes[node].parent.unwrap();
    let duplicate = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "DataObjectFormat"));
    xml.mime(duplicate);
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        format::check_references(&access, &bound, &signed, None),
        Err(format::CoverageError::Repeated { reference: 10 })
    ));
}

#[test]
fn format_counter_exemption_pays_identity_before_reporting_foreign() {
    // A genuine counter receipt for another selected signature is foreign,
    // but the current operation must fund that conclusion before comparing.
    let mut xml = preparation_tree();
    let (child, _, _) = append_nested_counter(&mut xml, 7, 12, true);
    let counter_node = xml.nodes[child].parent.unwrap();
    let original = funded();
    let signed = signed_roles(&xml, &original).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &original);
    let bound = binding::bind(&access, &container::locate(&access, 0).unwrap()).unwrap();
    let receipt = counter::bind(
        &access,
        counter::read(&access, &bound, counter_node).unwrap(),
    )
    .unwrap();
    let short = Memory::new(Arc::new(MemoryAccount::new(0, 3)));
    let lower = Access::new(&xml, xml.snapshot(), &short);
    assert!(
        matches!(format::check_references(&lower, &bound, &signed, Some(&receipt)),
        Err(format::CoverageError::Access(AccessError::Resource {
            node, cause: MemoryError::WorkExceeded })) if node == counter_node)
    );
    assert_eq!(short.work_remaining(), 1);
    assert_eq!(short.used(), 0);
    assert!(matches!(
        format::check_references(&access, &bound, &signed, Some(&receipt)),
        Err(format::CoverageError::ForeignCounter { .. })
    ));
}

#[test]
fn format_coverage_keeps_resource_lookup_and_unchecked_target_separate() {
    // Missing/foreign lookup is a semantic disposition. Memory/work refusal and
    // unchecked target digest cannot become a successful empty association list.
    let memory = funded();
    let (mut xml, _, _) = data_format_tree();
    xml.object_reference = Some("#direct");
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    // The source signature equality costs two units before any XML query or
    // output allocation. A short admission must preserve the remaining unit.
    let short = Memory::new(Arc::new(MemoryAccount::new(0, 1)));
    let lower = Access::new(&xml, xml.snapshot(), &short);
    assert!(matches!(
        format::check_references(&lower, &bound, &signed, None),
        Err(format::CoverageError::Access(AccessError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        }))
    ));
    assert_eq!(short.work_remaining(), 1);
    assert_eq!(short.used(), 0);
    let no_storage = Memory::new(Arc::new(MemoryAccount::new(0, 300_000)));
    let access = Access::new(&xml, xml.snapshot(), &no_storage);
    assert!(matches!(
        format::check_references(&access, &bound, &signed, None),
        Err(format::CoverageError::Access(AccessError::Resource { .. }))
    ));
    assert_eq!(no_storage.used(), 0);
    xml.object_reference = Some("#foreign");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        format::check_references(&access, &bound, &signed, None),
        Err(format::CoverageError::Lookup {
            resolution: Resolution::Unauthenticated,
            ..
        })
    ));
    xml.object_reference = Some("#direct");
    xml.references[0].status = Status::Unchecked;
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        format::check_references(&access, &bound, &signed, None),
        Err(format::CoverageError::Format(
            format::FormatError::Reference {
                node: 10,
                status: Status::Unchecked
            }
        ))
    ));
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn wide_format_identity_index_releases_scratch_and_retains_only_admitted_result_capacity() {
    // Identity indexing avoids scanning every format for each reference. The
    // existing map still conservatively prepays its possible hidden probes;
    // this test does not claim a linear worst-case admission bound.
    let memory = Memory::new(Arc::new(MemoryAccount::new(2_000_000, 10_000_000)));
    let (mut xml, first, _) = data_format_tree();
    let parent = xml.nodes[first].parent.unwrap();
    xml.include_routes.push((first, 0, Boolean::Absent));
    for _ in 1..128 {
        let reference = xml.nodes.len();
        xml.nodes.push(element(Some(9), DS, "Reference"));
        let ordinal = xml.references.len();
        xml.references.push(Reference {
            node: reference,
            target: None,
            kind: None,
            status: Status::Valid,
            coverage: Coverage::Transformed,
        });
        let property = xml.nodes.len();
        xml.nodes
            .push(element(Some(parent), XADES, "DataObjectFormat"));
        xml.mime(property);
        xml.include_routes
            .push((property, ordinal, Boolean::Absent));
    }
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let held = memory.used();
    let covered = format::check_references(&access, &bound, &signed, None).unwrap();
    assert_eq!(covered.len(), 128);
    assert_eq!(
        covered.last().unwrap().reference(),
        xml.references.last().unwrap().node
    );
    assert_eq!(
        memory.used() - held,
        covered.capacity() * core::mem::size_of::<format::CoveredFormat<usize, u8, u8>>()
    );
    drop(covered);
    assert_eq!(memory.used(), held);
}

#[test]
fn empty_format_catalogue_cannot_rebind_evidence_to_another_document() {
    // The empty fast path must apply the same source guard as nonempty formats.
    // Coincident numeric node IDs in another document are not original identity.
    let memory = funded();
    let (xml, _) = certificate_tree();
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let mut foreign = xml;
    foreign.document = 10;
    foreign.references[0].target = Some(3);
    let access = Access::new(&foreign, foreign.snapshot(), &memory);
    assert!(matches!(
        format::check_references(&access, &bound, &signed, None),
        Err(format::CoverageError::Access(AccessError::Changed {
            node: 0
        }))
    ));
}

#[test]
fn baseline_data_format_rejects_duplicate_order_and_unrecognized_children() {
    // A correct first MimeType cannot hide a later malformed member.
    let memory = funded();
    let (mut xml, node, _) = data_format_tree();
    let later = xml.nodes.len();
    xml.nodes.push(element(Some(node), XADES, "MimeType"));
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(format::read(&access, &signed, 0),
        Err(format::FormatError::Property(properties::Error::Duplicate { node: at })) if at == later));
    xml.nodes[later] = element(Some(node), XADES, "Description");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(format::read(&access, &signed, 0),
        Err(format::FormatError::Property(properties::Error::Order { node: at })) if at == later));
    xml.nodes[later] = element(Some(node), "urn:foreign", "Encoding");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(format::read(&access, &signed, 0),
        Err(format::FormatError::Property(properties::Error::Unexpected { node: at })) if at == later));
}

#[test]
fn baseline_data_format_distinguishes_caller_selection_source_and_resource_refusal() {
    // Invalid caller index, changed document and a spent operation are terminal
    // causes, not malformed MIME text, missing data or a successful empty format.
    let memory = funded();
    let (xml, _, _) = data_format_tree();
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        format::read(&access, &signed, 1),
        Err(format::FormatError::Selection {
            signature: 0,
            index: 1
        })
    ));
    let zero = self::memory(0);
    let access = Access::new(&xml, xml.snapshot(), &zero);
    assert!(matches!(
        format::read(&access, &signed, 0),
        Err(format::FormatError::Property(properties::Error::Access(
            AccessError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            }
        )))
    ));
    assert_eq!(zero.used(), 0);
    xml.generation.set(2);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        format::read(&access, &signed, 0),
        Err(format::FormatError::Property(properties::Error::Access(
            AccessError::Changed { .. }
        )))
    ));
    assert_eq!(xml.streamed.get(), 0);
}

fn validation_tree(local: &'static str) -> (Tree, usize, usize) {
    let mut xml = Tree::normal();
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES_141, local));
    let certificates = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "CertificateValues"));
    xml.nodes.push(element(
        Some(certificates),
        XADES,
        "EncapsulatedX509Certificate",
    ));
    (xml, node, certificates)
}

#[test]
fn validation_data_preserves_material_and_adjacent_timestamp_over_wrong_uri_hint() {
    // EN5.5.1.2 gives adjacent timestamp priority; a wrong URI hint cannot discard
    // otherwise usable material. No timestamp authentication is asserted here.
    let memory = funded();
    let (mut xml, node, certificates) = validation_tree("TimeStampValidationData");
    xml.validation_uri = Some("#another-timestamp");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    // Membership follows a successful original child lookup. Leave too little
    // for both identities and require refusal before deriving an adjacent hint.
    let current = funded();
    let observed = query_boundary::Boundary::after_inspection(&xml, node, &current, 1);
    let lower = Access::new(&observed, xml.snapshot(), &current);
    assert!(matches!(validation::read(&lower, &bound, node),
        Err(validation::Error::Input(InputError::Resource {
            node: at, cause: MemoryError::WorkExceeded })) if at == node));
    assert_eq!(current.work_remaining(), 1);
    let data = validation::read(&access, &bound, node).unwrap();
    assert_eq!(data.role(), validation::Role::Timestamp);
    assert_eq!(data.node(), node);
    assert_eq!(data.signature(), 0);
    assert_eq!(data.snapshot(), xml.snapshot());
    assert_eq!(data.hint(), Some(validation::Hint::Adjacent(8)));
    assert_eq!(data.certificates().unwrap().parent(), certificates);
    assert_eq!(
        data.certificates().unwrap().entries(),
        &[material::Entry::Encapsulated {
            node: certificates + 1,
            kind: material::Kind::Certificate
        },]
    );
    assert!(data.revocations().is_none());
    assert_eq!(xml.decoded_pointer.get(), 0);
    drop(data);
    assert_eq!(memory.used(), 0);
}

#[test]
fn nonadjacent_timestamp_validation_uri_stays_an_unresolved_hint() {
    // No private URI grammar, synthetic ordinal, or guessed preceding property
    // can create an association to a different timestamp.
    let memory = funded();
    let (mut xml, node, _) = validation_tree("TimeStampValidationData");
    xml.nodes[8] = element(Some(7), XADES_141, "AnyValidationData");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let data = validation::read(&access, &bound, node).unwrap();
    assert_eq!(
        data.hint(),
        Some(validation::Hint::Unresolved { uri_present: false })
    );
    drop(data);
    xml.validation_uri = Some("not-a-qualified-timestamp-target");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let data = validation::read(&access, &bound, node).unwrap();
    assert_eq!(
        data.hint(),
        Some(validation::Hint::Unresolved { uri_present: true })
    );
}

#[test]
fn any_validation_data_forbids_uri_and_requires_actual_material_entries() {
    // URI is prohibited by prose despite being permitted by the common XSD type.
    // Two empty material containers cannot satisfy the required actual values.
    let memory = funded();
    let (mut xml, node, certificates) = validation_tree("AnyValidationData");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let data = validation::read(&access, &bound, node).unwrap();
    assert_eq!(data.role(), validation::Role::Any);
    assert_eq!(data.hint(), None);
    drop(data);
    xml.validation_uri = Some("");
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(validation::read(&access, &bound, node), Err(validation::Error::ForbiddenUri { node: at }) if at == node)
    );
    assert_eq!(memory.used(), 0);
    xml.validation_uri = None;
    xml.nodes.pop();
    assert_eq!(xml.nodes.len(), certificates + 1);
    xml.nodes
        .push(element(Some(node), XADES, "RevocationValues"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        matches!(validation::read(&access, &bound, node), Err(validation::Error::Empty { node: at }) if at == node)
    );
    assert_eq!(memory.used(), 0);
}

#[test]
fn validation_data_schema_and_capacity_errors_drop_partial_catalogues() {
    // A later error returns no successful partial material set and releases
    // capacity held by the earlier certificate catalogue.
    let memory = funded();
    let (mut xml, node, _) = validation_tree("TimeStampValidationData");
    let later = xml.nodes.len();
    xml.nodes
        .push(element(Some(node), XADES, "CertificateValues"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    assert!(matches!(validation::read(&access, &bound, node),
        Err(validation::Error::Property(properties::Error::Duplicate { node: at })) if at == later));
    assert_eq!(memory.used(), 0);
    xml.nodes.pop();
    let no_storage = self::memory(100_000);
    let access = Access::new(&xml, xml.snapshot(), &no_storage);
    assert!(matches!(
        validation::read(&access, &bound, node),
        Err(validation::Error::Property(properties::Error::Resource {
            cause: MemoryError::LimitExceeded,
            ..
        }))
    ));
    assert_eq!(no_storage.used(), 0);
    let mut foreign = xml;
    foreign.document = 10;
    let access = Access::new(&foreign, foreign.snapshot(), &memory);
    assert!(matches!(
        validation::read(&access, &bound, node),
        Err(validation::Error::Input(InputError::Access(
            AccessError::Changed { .. }
        )))
    ));
}

#[test]
fn selected_certificate_preflight_refuses_baseline_cert_uri_before_provider() {
    // EN6.3(i) forbids Cert/@URI in the current baseline, despite its presence
    // in the general XAdES schema. Inspection may retain it; baseline checking
    // must not start selected-key/digest work on this nonconforming property.
    let memory = funded();
    let bytes = candidate_certificate();
    let parser = structured_asn1::Parser::der(memory.clone());
    let candidate = structured_pkix::Certificate::read(&parser, &bytes, 900).unwrap();
    let (mut xml, [_, cert, _, method, _, _]) = certificate_tree();
    xml.key_association = certificate::KeyAssociation::Same;
    xml.binary = vec![bytes.iter().fold(0_u8, |sum, byte| sum ^ byte)];
    xml.validation_uri = Some("#a-certificate-hint");
    let signed = signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let refs = certificate::read(&access, &signed).unwrap();
    let provider = WholeCertificate {
        mode: DigestMode::Available,
        method,
        calls: Cell::new(0),
        pointer: Cell::new(0),
    };
    for uri in ["#a-certificate-hint", ""] {
        xml.validation_uri = Some(uri);
        match certificate::check(&xml, &bound, &refs, &candidate, &provider, &memory) {
            Err(certificate::CheckError::ForbiddenCertificateUri { location }) => {
                assert_eq!(location.snapshot, xml.snapshot());
                assert_eq!(location.node, cert);
            }
            Err(error) => panic!("wrong refusal {error:?}"),
            Ok(_) => panic!("baseline Cert URI must be reported before callbacks"),
        }
        assert_eq!(provider.calls.get(), 0);
        assert_eq!(xml.decoded_pointer.get(), 0);
    }
}

#[test]
fn fresh_xml_binary_source_has_real_asn_root_depth_without_a_phantom_container() {
    // XML base64 is not an enclosing ASN.1 element. A fresh ASN primitive at
    // depth zero is allowed by max_depth=0; entering a SEQUENCE still is not.
    let memory = funded();
    let parser = structured_asn1::Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_depth: 0,
            ..Default::default()
        },
        memory.clone(),
    );
    let operation = parser.read(&[], 900).unwrap();
    let mut xml = Tree::normal();
    xml.binary = vec![2, 1, 7];
    let location = Location {
        snapshot: xml.snapshot(),
        node: 8,
    };
    let value = binary::with_der_reader(&xml, location, &operation, |reader| {
        assert_eq!(reader.depth(), 0);
        reader.read_integer().map(structured_asn1::Integer::as_u64)
    })
    .unwrap();
    assert_eq!(value, Some(7));
    assert_eq!(memory.used(), 0);
}

fn counter_tree() -> (Tree, usize, usize, usize) {
    let mut xml = Tree::normal();
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(7), XADES, "CounterSignature"));
    let child = xml.nodes.len();
    xml.nodes.push(element(Some(node), DS, "Signature"));
    let info = xml.nodes.len();
    xml.nodes.push(element(Some(child), DS, "SignedInfo"));
    let reference = xml.nodes.len();
    xml.nodes.push(element(Some(info), DS, "Reference"));
    xml.nodes.push(element(Some(child), DS, "SignatureValue"));
    xml.counter_evidence = Some(CounterEvidence {
        child,
        status: Status::Valid,
        references: vec![Reference {
            node: reference,
            target: Some(12),
            kind: None,
            status: Status::Valid,
            coverage: Coverage::ElementContent,
        }],
    });
    (xml, node, child, reference)
}

#[test]
fn enveloped_counter_binds_exact_parent_value_with_one_plain_dsig_reference() {
    // XML owner receipts are synthetic here: this checks common binding, not
    // signature arithmetic. Plain XMLDSig counter need not have SignedProperties.
    let memory = funded();
    let (xml, node, child, reference) = counter_tree();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    // A complete child lookup does not include membership equality work.
    let current = funded();
    let observed = query_boundary::Boundary::after_inspection(&xml, node, &current, 1);
    let lower = Access::new(&observed, xml.snapshot(), &current);
    assert!(matches!(counter::read(&lower, &bound, node),
        Err(counter::Error::Input(InputError::Resource {
            node: at, cause: MemoryError::WorkExceeded })) if at == node));
    assert_eq!(current.work_remaining(), 1);
    let original = counter::read(&access, &bound, node).unwrap();
    assert_eq!(original.node(), node);
    assert_eq!(original.child(), child);
    assert_eq!(original.parent(), 0);
    assert_eq!(original.value(), 12);
    // The callback dispatch fits; matching its target is separate work. Both
    // eligibility and selection reuse that same admitted comparison.
    let short = funded();
    let observed = query_boundary::Boundary::exhaust(&xml, 5, &short, 3);
    let lower = Access::new(&observed, xml.snapshot(), &short);
    assert!(matches!(counter::bind(&lower, original),
        Err(counter::Error::Binding(BindingError::Access(AccessError::Resource {
            node, cause: MemoryError::WorkExceeded }))) if node == reference));
    assert_eq!(short.work_remaining(), 1);
    let original = counter::read(&access, &bound, node).unwrap();
    let checked = counter::bind(&access, original).unwrap();
    assert_eq!(checked.reference(), reference);
    assert_eq!(checked.ordinal(), 0);
    assert_eq!(checked.original().snapshot(), xml.snapshot());
    assert_eq!(memory.used(), 0);
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn properties_binding_admits_target_after_reference_callback() {
    // The eligible Reference has been read completely, but its target relation
    // is still a new two-operand scan under the current operation.
    let xml = Tree::normal();
    let original = funded();
    let access = Access::new(&xml, xml.snapshot(), &original);
    let layout = container::locate(&access, 0).unwrap();
    let short = funded();
    let observed = query_boundary::Boundary::exhaust(&xml, 10, &short, 1);
    let lower = Access::new(&observed, xml.snapshot(), &short);
    assert!(matches!(
        binding::bind(&lower, &layout),
        Err(BindingError::Access(AccessError::Resource {
            node: 11,
            cause: MemoryError::WorkExceeded
        }))
    ));
    assert_eq!(short.work_remaining(), 1);
    assert_eq!(short.used(), 0);
}

fn append_nested_counter(
    xml: &mut Tree,
    parent: usize,
    value: usize,
    nested: bool,
) -> (usize, usize, Option<usize>) {
    let node = xml.nodes.len();
    xml.nodes
        .push(element(Some(parent), XADES, "CounterSignature"));
    let child = xml.nodes.len();
    xml.nodes.push(element(Some(node), DS, "Signature"));
    let info = xml.nodes.len();
    xml.nodes.push(element(Some(child), DS, "SignedInfo"));
    let reference = xml.nodes.len();
    xml.nodes.push(element(Some(info), DS, "Reference"));
    let child_value = xml.nodes.len();
    xml.nodes.push(element(Some(child), DS, "SignatureValue"));
    xml.nested_counters.push(CounterEvidence {
        child,
        status: Status::Valid,
        references: vec![Reference {
            node: reference,
            target: Some(value),
            kind: None,
            status: Status::Valid,
            coverage: Coverage::ElementContent,
        }],
    });
    let unsigned = if nested {
        let object = xml.nodes.len();
        xml.nodes.push(element(Some(child), DS, "Object"));
        let qualifying = xml.nodes.len();
        xml.nodes
            .push(element(Some(object), XADES, "QualifyingProperties"));
        let signed = xml.nodes.len();
        xml.nodes
            .push(element(Some(qualifying), XADES, "SignedProperties"));
        xml.nodes
            .push(element(Some(signed), XADES, "SignedSignatureProperties"));
        let unsigned = xml.nodes.len();
        xml.nodes
            .push(element(Some(qualifying), XADES, "UnsignedProperties"));
        let properties = xml.nodes.len();
        xml.nodes.push(element(
            Some(unsigned),
            XADES,
            "UnsignedSignatureProperties",
        ));
        Some(properties)
    } else {
        None
    };
    (child, child_value, unsigned)
}

#[test]
fn iterative_counter_walk_preserves_nested_parent_binding_and_direct_sibling_order() {
    // Deep children cover the immediately preceding parent's value, never the
    // root value; no recursive Rust call or parent catalogue clone is required.
    let mut xml = Tree::normal();
    let (first, mut value, mut parent) = append_nested_counter(&mut xml, 7, 12, true);
    let mut expected = vec![first];
    for depth in 0..128 {
        let (child, next, container) =
            append_nested_counter(&mut xml, parent.unwrap(), value, depth != 127);
        expected.push(child);
        value = next;
        parent = container;
    }
    for _ in 0..32 {
        let (child, _, _) = append_nested_counter(&mut xml, 7, 12, false);
        expected.push(child);
    }
    xml.index_edges();
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 100_000_000)));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let results = counter::walk(&access, &bound, |checked, layout| {
        if let Some(layout) = layout {
            assert_eq!(layout.signature(), checked.original().child());
        }
        Ok::<_, ()>(checked.original().child())
    })
    .unwrap();
    assert_eq!(&results[..], expected);
    assert!(memory.used() > 0);
    drop(results);
    assert_eq!(memory.used(), 0);
}

#[test]
fn counter_walk_terminates_on_late_child_math_or_visitor_refusal_without_partial_results() {
    // An earlier successful callback cannot turn an invalid later sibling into a
    // successful prefix. Caller side effects remain visible, retained results do not.
    for visitor_refusal in [false, true] {
        let mut xml = Tree::normal();
        append_nested_counter(&mut xml, 7, 12, false);
        let (bad, _, _) = append_nested_counter(&mut xml, 7, 12, false);
        if !visitor_refusal {
            xml.nested_counters[1].status = Status::Invalid;
        }
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let visits = Cell::new(0);
        let result = counter::walk(&access, &bound, |checked, _| {
            visits.set(visits.get() + 1);
            if checked.original().child() == bad {
                return Err("visitor refused");
            }
            let mut owned = memory.vector();
            owned.try_extend_from_slice(b"retained diagnostic").unwrap();
            Ok(owned)
        });
        if visitor_refusal {
            assert!(matches!(
                result,
                Err(counter::WalkError::Visitor("visitor refused"))
            ));
            assert_eq!(visits.get(), 2);
        } else {
            assert!(
                matches!(result, Err(counter::WalkError::Counter(counter::Error::Binding(BindingError::Signature { node, status: Status::Invalid }))) if node == bad)
            );
            assert_eq!(visits.get(), 1);
        }
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn counter_walk_rejects_current_resource_and_mutated_source_instead_of_returning_empty() {
    // Source invalidation drops the callback's accounted result; zero current
    // capacity/work refuses before any child callback or successful empty set.
    let mut xml = Tree::normal();
    append_nested_counter(&mut xml, 7, 12, false);
    let storage = funded();
    let access = Access::new(&xml, xml.snapshot(), &storage);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    for work in [
        Memory::new(Arc::new(MemoryAccount::new(0, 100_000))),
        Memory::new(Arc::new(MemoryAccount::new(4096, 0))),
    ] {
        let access = Access::new(&xml, xml.snapshot(), &work);
        let called = Cell::new(false);
        assert!(
            counter::walk(&access, &bound, |_, _| {
                called.set(true);
                Ok::<_, ()>(())
            })
            .is_err()
        );
        assert!(!called.get());
        assert_eq!(work.used(), 0);
    }
    let result = counter::walk(&access, &bound, |_, _| {
        let mut owned = storage.vector();
        owned.try_push(1u8).unwrap();
        xml.generation.set(2);
        Ok::<_, ()>(owned)
    });
    assert!(matches!(
        result,
        Err(counter::WalkError::Access(AccessError::Changed { .. }))
    ));
    assert_eq!(storage.used(), 0);
}

#[test]
fn counter_walk_never_relabels_broken_child_properties_as_a_plain_dsig_leaf() {
    // Only missing QualifyingProperties means a plain XMLDSig leaf. A broken
    // property container or counter wrapper is a terminal located schema error.
    for malformed_wrapper in [false, true] {
        let mut xml = Tree::normal();
        append_nested_counter(&mut xml, 7, 12, false);
        let bad = if malformed_wrapper {
            let node = xml.nodes.len();
            xml.nodes.push(element(Some(7), XADES, "CounterSignature"));
            node
        } else {
            let (child, _, _) = append_nested_counter(&mut xml, 7, 12, false);
            let object = xml.nodes.len();
            xml.nodes.push(element(Some(child), DS, "Object"));
            let node = xml.nodes.len();
            xml.nodes
                .push(element(Some(object), XADES, "QualifyingProperties"));
            node
        };
        let memory = funded();
        let access = Access::new(&xml, xml.snapshot(), &memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let calls = Cell::new(0);
        let result = counter::walk(&access, &bound, |_, _| {
            calls.set(calls.get() + 1);
            let mut result = memory.vector();
            result.try_push(7u8).unwrap();
            Ok::<_, ()>(result)
        });
        if malformed_wrapper {
            assert!(
                matches!(result, Err(counter::WalkError::Counter(counter::Error::Input(InputError::Missing { node, local: "Signature" }))) if node == bad)
            );
        } else {
            assert!(
                matches!(result, Err(counter::WalkError::Container(ContainerError::Missing { parent, local: "SignedProperties" })) if parent == bad)
            );
        }
        assert_eq!(calls.get(), 1);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn enveloped_counter_never_substitutes_parent_status_wrong_target_or_filtered_coverage() {
    // A successful parent signature and a located nested Signature do not prove
    // that the child authenticates the complete parent SignatureValue element.
    let memory = funded();
    let (mut xml, node, child, reference) = counter_tree();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    xml.counter_evidence.as_mut().unwrap().status = Status::Invalid;
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let original = counter::read(&access, &bound, node).unwrap();
    assert!(matches!(counter::bind(&access, original),
        Err(counter::Error::Binding(BindingError::Signature { node: at, status: Status::Invalid })) if at == child));
    xml.counter_evidence.as_mut().unwrap().status = Status::Valid;
    xml.counter_evidence.as_mut().unwrap().references[0].target = Some(child);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let original = counter::read(&access, &bound, node).unwrap();
    assert!(matches!(
        counter::bind(&access, original),
        Err(counter::Error::Binding(BindingError::Missing { node: 12 }))
    ));
    xml.counter_evidence.as_mut().unwrap().references[0].target = Some(12);
    xml.counter_evidence.as_mut().unwrap().references[0].coverage = Coverage::Transformed;
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let original = counter::read(&access, &bound, node).unwrap();
    assert!(matches!(counter::bind(&access, original),
        Err(counter::Error::Binding(BindingError::Reference { node: at })) if at == reference));
    assert_eq!(xml.streamed.get(), 0);
}

#[test]
fn enveloped_counter_schema_generation_and_work_refusals_remain_terminal() {
    // Extra child signatures are not first-match recovery; source changes and
    // operation exhaustion cannot be reported as a successful bound counter.
    let memory = funded();
    let (mut xml, node, _, _) = counter_tree();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let duplicate = xml.nodes.len();
    xml.nodes.push(element(Some(node), DS, "Signature"));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(counter::read(&access, &bound, node),
        Err(counter::Error::Input(InputError::Duplicate { node: at })) if at == duplicate));
    xml.nodes.pop();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let original = counter::read(&access, &bound, node).unwrap();
    let zero = self::memory(0);
    let access = Access::new(&xml, xml.snapshot(), &zero);
    assert!(matches!(
        counter::bind(&access, original),
        Err(counter::Error::Binding(BindingError::Access(
            AccessError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            }
        )))
    ));
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let original = counter::read(&access, &bound, node).unwrap();
    xml.generation.set(2);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        counter::bind(&access, original),
        Err(counter::Error::Input(InputError::Access(
            AccessError::Changed { .. }
        )))
    ));
    assert_eq!(memory.used(), 0);
}

#[test]
fn collecting_sink_retains_resource_cause_and_rolls_back_failed_copy() {
    // The fixture sink itself must not bypass accounting while testing streams.
    let memory = memory(1000);
    let mut sink = Collect::new(&memory);
    assert!(matches!(
        sink.write(&[1, 2, 3, 4], &memory),
        Err(SinkError::Resource(MemoryError::LimitExceeded))
    ));
    assert_eq!(sink.bytes(), []);
}

fn checked_with_local_operation<'source>(
    leaf: &'source structured_pkix::Certificate<'source>,
    root: &'source structured_pkix::Certificate<'source>,
    current: &Memory,
) -> structured_ltv::pki::CheckedPath<'source> {
    use structured_ltv::pki::{self, PathOutcome};
    use structured_pkix::path::{self, Anchor, Interval, ValidationBounds, ValidationContext};
    let operation = structured_asn1::Parser::der(current.clone());
    let query = operation.read(&[], 1200).unwrap();
    let execution = query.execution();
    let verifier = timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let context = ValidationContext {
        execution: &execution,
        interval: Interval::at(1_767_225_600),
        policy: path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(result) =
        pki::check_path(&[leaf], Anchor::from_certificate(root), &context).unwrap()
    else {
        panic!("actual original actor path")
    };
    assert_eq!(verifier.calls.get(), 1);
    result
}

#[test]
fn checked_actor_path_outlives_operation_and_keeps_original_key_and_charge() {
    // Static facts/member capacity outlive temporary operations; original
    // certificate/key views retain their source without repeating verification.
    #[cfg(miri)]
    eprintln!("retained path: generating two original certificates");
    let (leaf_bytes, root_bytes) = timestamp_oracle::certificate_pair();
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let source = structured_asn1::Parser::der(memory.clone());
    let leaf = structured_pkix::Certificate::read(&source, &leaf_bytes, 400).unwrap();
    let root = structured_pkix::Certificate::read(&source, &root_bytes, 1600).unwrap();
    let current = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    #[cfg(miri)]
    eprintln!("retained path: parsing complete; verifying original path");
    let path = checked_with_local_operation(&leaf, &root, &current);
    assert!(core::ptr::eq(
        path.members()[0].certificate(),
        &raw const leaf
    ));
    assert_eq!(
        path.facts().key.key().as_bytes().as_ptr(),
        leaf.tbs().public_key().as_bytes().as_ptr()
    );
    assert!(current.used() > 0);
    drop(path);
    assert_eq!(current.used(), 0);
}

#[test]
fn crl_reason_union_binds_every_original_authority_without_partial_receipts() {
    // All-reason absence cannot inherit the first source's authority: changing
    // only the second authority must reject with its exact contributor ordinal.
    use structured_ltv::pki::{
        CrlAuthorities, CrlAuthority, CrlBindingError, CrlBindingFailure, CrlCoverageBinding,
        CrlCoverageError,
    };
    use structured_pkix::{
        crl,
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    xml_digest::with_checked_path(|path, _, _, work| {
        let (first, second) = timestamp_oracle::crl_reason_partitions(2);
        let parser = structured_asn1::Parser::der(work.clone());
        let lists = [
            crl::CertificateList::read(&parser, &first, 2000).unwrap(),
            crl::CertificateList::read(&parser, &second, 3000).unwrap(),
        ];
        let issuer = path.anchor().certificate().unwrap();
        let verifier = timestamp_oracle::PathOracle {
            calls: Cell::new(0),
        };
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = crl::Evaluation {
            now: Instant::new(1_767_225_600, 0).unwrap().into(),
            utc: &utc,
            execution: work,
            origin: crl::SourceOrigin::Cached,
        };
        let mut coverage = None;
        for list in &lists {
            let crl::Authentication::Authenticated(source) = list
                .authenticate(
                    issuer,
                    WorkingKey::standing(issuer.tbs().public_key()),
                    &verifier,
                    work,
                )
                .unwrap()
            else {
                panic!("real reason-partition signature")
            };
            let crl::CompleteEvidence::Facts(facts) = source
                .evaluate(path.members()[0].certificate(), &context)
                .unwrap()
            else {
                panic!("applicable original partition")
            };
            let absence = facts.absence().unwrap();
            assert!(!absence.reasons().is_complete());
            match &mut coverage {
                None => coverage = Some(crl::Coverage::new(absence, work).unwrap()),
                Some(coverage) => assert_eq!(
                    coverage.add(absence, work).unwrap(),
                    crl::CoverageAdmission::Added
                ),
            }
        }
        let coverage = coverage.unwrap();
        assert!(coverage.reasons().is_complete());
        assert_eq!(coverage.sources().len(), 2);
        assert_crl_reason_authorities(path, &coverage, &utc, work);
        let bad = [
            CrlAuthorities::Complete(CrlAuthority::Anchor),
            CrlAuthorities::Complete(CrlAuthority::Path(path)),
        ];
        assert!(matches!(
            path.bind_crl_coverage(0, &coverage, &bad, &utc, work)
                .unwrap(),
            CrlCoverageBinding::Rejected {
                source: 1,
                cause: CrlBindingFailure::Signer
            }
        ));
        let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        assert!(matches!(
            path.bind_crl_coverage(0, &coverage, &bad, &utc, &denied),
            Err(CrlCoverageError::Source {
                source: 0,
                cause: CrlBindingError::Resource(_)
            })
        ));
        assert_eq!(verifier.calls.get(), 2);
    });
}

fn assert_crl_reason_authorities<'a>(
    path: &structured_ltv::pki::CheckedPath<'a>,
    coverage: &structured_pkix::crl::Coverage<'_, 'a>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    work: &Memory,
) {
    use structured_ltv::pki::{CrlAuthorities, CrlAuthority, CrlCoverageBinding, CrlCoverageError};
    let authorities = [CrlAuthorities::Complete(CrlAuthority::Anchor); 2];
    let before = work.used();
    let CrlCoverageBinding::Bound(bound) = path
        .bind_crl_coverage(0, coverage, &authorities, utc, work)
        .unwrap()
    else {
        panic!("every contributor uses actual common anchor")
    };
    assert!(core::ptr::eq(bound.path(), path));
    assert!(core::ptr::eq(bound.coverage(), coverage));
    assert_eq!(bound.authorities().as_ptr(), authorities.as_ptr());
    assert_eq!(bound.member(), 0);
    assert_eq!(work.used(), before);
    assert_crl_status_census(path, &bound, work);
    let before_work = work.work_used();
    assert!(matches!(
        path.bind_crl(0, &coverage.sources()[0], authorities[0], utc, work)
            .unwrap(),
        structured_ltv::pki::CrlBinding::Bound(_)
    ));
    let first_work = work.work_used() - before_work;
    let limited = Memory::new(Arc::new(MemoryAccount::new(1 << 20, first_work + 2)));
    assert!(matches!(
        path.bind_crl_coverage(0, coverage, &authorities, utc, &limited),
        Err(CrlCoverageError::Source {
            source: 1,
            cause: structured_ltv::pki::CrlBindingError::Resource(_)
        })
    ));
    assert_eq!(limited.used(), 0);
    assert!(matches!(
        path.bind_crl_coverage(0, coverage, &authorities[..1], utc, work),
        Err(CrlCoverageError::AuthorityCount)
    ));
}

fn assert_crl_status_census<'a>(
    path: &structured_ltv::pki::CheckedPath<'a>,
    coverage: &structured_ltv::pki::CrlCoverage<'_, '_, 'a>,
    work: &Memory,
) {
    // A valid all-reason source is still incomplete when omitted, supplied
    // twice, relabelled in time, or queried without current execution admission.
    use structured_ltv::pki::{MemberStatus, StatusCensusError};
    let at = coverage.coverage().evaluated_at();
    let entries = [MemberStatus::Crl(coverage)];
    let before = work.used();
    let census = path.status_census(at, &entries, work).unwrap();
    assert!(core::ptr::eq(census.path(), path));
    assert_eq!(census.evaluated_at(), at);
    assert_eq!(census.entries().as_ptr(), entries.as_ptr());
    assert_eq!(work.used(), before);
    assert!(matches!(
        path.status_census(at, &[], work),
        Err(StatusCensusError::Count)
    ));
    let twice = [MemberStatus::Crl(coverage), MemberStatus::Crl(coverage)];
    assert!(matches!(
        path.status_census(at, &twice, work),
        Err(StatusCensusError::Count)
    ));
    let later = structured_pkix::temporal::Instant::new(at.start().seconds() + 1, 0)
        .unwrap()
        .into();
    assert!(matches!(
        path.status_census(later, &entries, work),
        Err(StatusCensusError::Time { index: 0 })
    ));
    let denied = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(matches!(
        path.status_census(at, &entries, &denied),
        Err(StatusCensusError::Resource(_))
    ));
    assert_eq!(denied.used(), 0);
}
