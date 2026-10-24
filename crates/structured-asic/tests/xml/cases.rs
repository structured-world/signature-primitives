use std::{cell::Cell, sync::Arc};
use structured_asic::xml::{self, FaultKind, Wrapper};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_xades::{
    attributes::AttributeXml,
    reference::{LexicalSource, VisitError},
    scalar::{QNameFact, QNameReading, QNameXml},
    xml::{AccessError, Name, Node, Snapshot, Xml},
};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const ASI: &str = "http://uri.etsi.org/02918/v1.2.1#";

#[path = "archive_cases.rs"]
mod archive_cases;
#[path = "native_cases.rs"]
mod native;
#[path = "package_cases.rs"]
mod package_cases;
#[path = "producer_cases.rs"]
mod producer_cases;
#[path = "signed_cases.rs"]
mod signed_cases;

// An already-parsed-node fixture exercises the public owner boundary. It is
// deliberately not a production XML parser or native XMLDSig qualification.
struct Row {
    value: Node<'static>,
    parent: Option<usize>,
    first: Option<usize>,
    next: Option<usize>,
    attributes: Vec<(Name<'static>, &'static str)>,
    binary: Option<Vec<u8>>,
}
struct Tree {
    rows: Vec<Row>,
    identity: usize,
    generation: Cell<u64>,
    change: Cell<Option<usize>>,
}
#[derive(Debug)]
enum Failure {
    Resource(MemoryError),
    Foreign,
    Unsupported,
}
impl Tree {
    fn new(namespace: &'static str, local: &'static str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
        Self {
            rows: vec![Row {
                value: Node::Element(Name { namespace, local }),
                parent: None,
                first: None,
                next: None,
                attributes: Vec::new(),
                binary: None,
            }],
            identity: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            generation: Cell::new(1),
            change: Cell::new(None),
        }
    }
    fn add(&mut self, parent: usize, value: Node<'static>) -> usize {
        let id = self.rows.len();
        if let Some(mut at) = self.rows[parent].first {
            while let Some(next) = self.rows[at].next {
                at = next;
            }
            self.rows[at].next = Some(id);
        } else {
            self.rows[parent].first = Some(id);
        }
        self.rows.push(Row {
            value,
            parent: Some(parent),
            first: None,
            next: None,
            attributes: Vec::new(),
            binary: None,
        });
        id
    }
    fn element(&mut self, parent: usize, namespace: &'static str, local: &'static str) -> usize {
        self.add(parent, Node::Element(Name { namespace, local }))
    }
    fn row<W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        work: &W,
    ) -> Result<&Row, Failure> {
        work.charge_work(1).map_err(Failure::Resource)?;
        if snapshot != self.snapshot() {
            return Err(Failure::Foreign);
        }
        self.rows.get(node).ok_or(Failure::Foreign)
    }
}
impl Xml for Tree {
    type Id = usize;
    type Document = usize;
    type Generation = u64;
    type Error = Failure;
    fn snapshot(&self) -> Snapshot<usize, u64> {
        Snapshot {
            document: self.identity,
            generation: self.generation.get(),
        }
    }
    fn inspect<R, W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        work: &W,
        visit: impl for<'a> FnOnce(Node<'a>) -> R,
    ) -> Result<R, Failure> {
        let row = self.row(snapshot, node, work)?;
        let bytes = match row.value {
            Node::Element(name) => name.namespace.len() + name.local.len(),
            Node::Text(text) => text.len(),
            Node::Other => 0,
        };
        work.charge_work(bytes as u64).map_err(Failure::Resource)?;
        let result = visit(row.value);
        if self.change.get() == Some(node) {
            self.change.set(None);
            self.generation.set(self.generation.get() + 1);
        }
        Ok(result)
    }
    fn attribute<R, W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        name: Name<'_>,
        work: &W,
        visit: impl for<'a> FnOnce(Option<&'a str>) -> R,
    ) -> Result<R, Failure> {
        let row = self.row(snapshot, node, work)?;
        for (other, value) in &row.attributes {
            work.charge_work((name.namespace.len() + name.local.len() + value.len() + 1) as u64)
                .map_err(Failure::Resource)?;
            if *other == name {
                return Ok(visit(Some(value)));
            }
        }
        Ok(visit(None))
    }
    fn first_child<W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        work: &W,
    ) -> Result<Option<usize>, Failure> {
        Ok(self.row(snapshot, node, work)?.first)
    }
    fn next_sibling<W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        parent: usize,
        node: usize,
        work: &W,
    ) -> Result<Option<usize>, Failure> {
        self.row(snapshot, parent, work)?;
        let row = self.row(snapshot, node, work)?;
        if row.parent != Some(parent) {
            return Err(Failure::Foreign);
        }
        Ok(row.next)
    }
}
impl QNameXml for Tree {
    fn with_qname<R, VE, W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        _source: LexicalSource<'_>,
        work: &W,
        visit: impl for<'a> FnOnce(QNameReading<'a>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Failure, VE>> {
        self.row(snapshot, node, work)
            .map_err(VisitError::Processing)?;
        visit(QNameReading {
            lexical: None,
            fact: QNameFact::Unsupported,
        })
        .map_err(VisitError::Visitor)
    }
}
impl AttributeXml for Tree {
    fn visit_attributes<VE, W: Work>(
        &self,
        snapshot: Snapshot<usize, u64>,
        node: usize,
        work: &W,
        mut visit: impl for<'a> FnMut(Name<'a>) -> Result<(), VE>,
    ) -> Result<(), VisitError<Failure, VE>> {
        let row = self
            .row(snapshot, node, work)
            .map_err(VisitError::Processing)?;
        for (name, _) in &row.attributes {
            work.charge_work((name.namespace.len() + name.local.len() + 1) as u64)
                .map_err(|cause| VisitError::Processing(Failure::Resource(cause)))?;
            visit(*name).map_err(VisitError::Visitor)?;
        }
        Ok(())
    }
}

#[test]
fn general_e_preserves_all_five_wrapper_forms_and_odf_fixed_version() {
    // General E permits all roots; baseline/simple restrictions must be applied
    // separately. A wrapper's namespace and exact ODF version remain facts.
    for (namespace, local, expected) in [
        (ASI, "XAdESSignatures", Wrapper::Asic),
        (xml::ODF, "document-signatures", Wrapper::Odf),
        (xml::OCF, "signatures", Wrapper::Ocf),
        ("urn:test:original", "other", Wrapper::Other),
        (DS, "Signature", Wrapper::Bare),
    ] {
        let mut tree = Tree::new(namespace, local);
        if expected != Wrapper::Bare {
            tree.element(0, DS, "Signature");
        }
        if expected == Wrapper::Odf {
            tree.rows[0].attributes.push((
                Name {
                    namespace: xml::ODF,
                    local: "version",
                },
                " \t1.2\r\n",
            ));
        }
        let work = super::support::memory();
        let reading = xml::inspect(&tree, 0, &work).unwrap();
        assert_eq!(reading.wrapper(), expected);
        assert_eq!(reading.signatures().len(), 1);
        assert!(reading.signatures()[0].direct);
        assert!(reading.faults().is_empty());
        assert_eq!(reading.root(), 0);
        assert_eq!(reading.snapshot(), tree.snapshot());
        drop(reading);
        assert_eq!(work.used(), 0);
    }
    for version in [None, Some("1.3")] {
        let mut tree = Tree::new(xml::ODF, "document-signatures");
        if let Some(value) = version {
            tree.rows[0].attributes.push((
                Name {
                    namespace: xml::ODF,
                    local: "version",
                },
                value,
            ));
        }
        tree.element(0, DS, "Signature");
        let reading = xml::inspect(&tree, 0, &super::support::memory()).unwrap();
        assert!(
            reading
                .faults()
                .iter()
                .any(|fault| fault.kind == FaultKind::OdfVersion)
        );
    }
}

#[test]
fn every_nested_or_misplaced_signature_survives_readable_wrapper_faults() {
    // Unrecognized children/text cannot hide later siblings or signatures
    // below them. An enclosing signature is identity, not legal counter proof.
    let mut tree = Tree::new(ASI, "XAdESSignatures");
    tree.add(0, Node::Text("bad text"));
    let first = tree.element(0, DS, "Signature");
    let object = tree.element(first, DS, "Object");
    let nested = tree.element(object, DS, "Signature");
    let bad = tree.element(0, "urn:test", "unknown");
    let misplaced = tree.element(bad, DS, "Signature");
    let last = tree.element(0, DS, "Signature");
    let reading = xml::inspect(&tree, 0, &super::support::memory()).unwrap();
    assert_eq!(
        reading
            .signatures()
            .iter()
            .map(|s| s.node)
            .collect::<Vec<_>>(),
        [first, nested, misplaced, last]
    );
    assert_eq!(reading.signatures()[1].enclosing, Some(first));
    assert!(!reading.signatures()[1].direct);
    assert_eq!(reading.signatures()[2].parent, Some(bad));
    assert_eq!(reading.signatures()[2].enclosing, None);
    for (node, kind) in [
        (0, FaultKind::Text),
        (bad, FaultKind::Child),
        (misplaced, FaultKind::Misplaced),
    ] {
        // Text faults retain the actual text node rather than its wrapper.
        let node = if kind == FaultKind::Text { 1 } else { node };
        assert!(
            reading
                .faults()
                .iter()
                .any(|fault| fault.node == node && fault.kind == kind)
        );
    }
}

#[test]
fn deeply_nested_original_nodes_are_iterative_and_refusal_releases_all_frames() {
    // Thousands of untrusted ancestors use paid heap frames, never call-stack
    // recursion. A tighter query must return refusal, not the leading census.
    let mut tree = Tree::new(ASI, "XAdESSignatures");
    let mut parent = tree.element(0, DS, "Signature");
    for _ in 0..5000 {
        parent = tree.element(parent, DS, "Object");
    }
    let nested = tree.element(parent, DS, "Signature");
    let work = super::support::memory();
    let reading = xml::inspect(&tree, 0, &work).unwrap();
    assert_eq!(reading.signatures().len(), 2);
    assert_eq!(reading.signatures()[1].node, nested);
    drop(reading);
    assert_eq!(work.used(), 0);
    let tight = Memory::new(Arc::new(MemoryAccount::new(2048, 100_000_000)));
    assert!(matches!(
        xml::inspect(&tree, 0, &tight),
        Err(xml::Error::Resource {
            cause: MemoryError::LimitExceeded,
            ..
        })
    ));
    assert_eq!(tight.used(), 0);
}

#[test]
fn changed_original_generation_is_terminal_after_the_actual_owner_callback() {
    // A source change during the final selected node cannot return a successful
    // reading whose earlier identities belong to the old XML generation.
    let mut tree = Tree::new(ASI, "XAdESSignatures");
    let signature = tree.element(0, DS, "Signature");
    tree.change.set(Some(signature));
    let work = super::support::memory();
    assert!(matches!(
        xml::inspect(&tree, 0, &work),
        Err(xml::Error::Access(AccessError::Changed { .. }))
    ));
    assert_eq!(work.used(), 0);
    let zero = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(matches!(
        tree.inspect(tree.snapshot(), 0, &zero, |_| ()),
        Err(Failure::Resource(MemoryError::WorkExceeded))
    ));
}
