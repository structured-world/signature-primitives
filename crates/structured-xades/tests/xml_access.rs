//! Snapshot, provenance and pre-admission boundaries of the scoped XML adapter.

use core::cell::Cell;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_xades::xml::{Access, AccessError, ChildError, Name, Node, Snapshot, Xml};

#[derive(Debug, PartialEq, Eq)]
enum Cause {
    Foreign,
    Stale,
    Resource(MemoryError),
}

struct Document {
    generation: Cell<u8>,
    calls: Cell<usize>,
    mutate: bool,
    width: u8,
    text: &'static str,
}

impl Document {
    fn new(mutate: bool) -> Self {
        Self {
            generation: Cell::new(1),
            calls: Cell::new(0),
            mutate,
            width: 2,
            text: "abc",
        }
    }

    fn admit(&self, snapshot: Snapshot<u8, u8>, node: u8) -> Result<(), Cause> {
        if snapshot != self.snapshot() {
            return Err(Cause::Stale);
        }
        if node > self.width {
            return Err(Cause::Foreign);
        }
        self.calls.set(self.calls.get() + 1);
        Ok(())
    }
}

impl Xml for Document {
    type Id = u8;
    type Document = u8;
    type Generation = u8;
    type Error = Cause;

    fn snapshot(&self) -> Snapshot<u8, u8> {
        Snapshot {
            document: 7,
            generation: self.generation.get(),
        }
    }

    fn inspect<R, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: u8,
        execution: &W,
        visitor: impl for<'view> FnOnce(Node<'view>) -> R,
    ) -> Result<R, Cause> {
        self.admit(snapshot, node)?;
        if node == 0 {
            return Ok(visitor(Node::Element(Name {
                namespace: "urn:x",
                local: "root",
            })));
        }
        // The owner pays the actual three-character text scan in advance.
        execution.charge_work(3).map_err(Cause::Resource)?;
        let result = visitor(Node::Text(self.text));
        if self.mutate {
            self.generation.set(self.generation.get() + 1);
        }
        Ok(result)
    }

    fn attribute<R, W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        node: u8,
        name: Name<'_>,
        _execution: &W,
        visitor: impl for<'view> FnOnce(Option<&'view str>) -> R,
    ) -> Result<R, Cause> {
        self.admit(snapshot, node)?;
        Ok(visitor(if name.local == "empty" {
            Some("")
        } else {
            None
        }))
    }

    fn first_child<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        parent: u8,
        _execution: &W,
    ) -> Result<Option<u8>, Cause> {
        self.admit(snapshot, parent)?;
        Ok(if parent == 0 && self.width != 0 {
            Some(1)
        } else {
            None
        })
    }

    fn next_sibling<W: Work>(
        &self,
        snapshot: Snapshot<u8, u8>,
        parent: u8,
        node: u8,
        _execution: &W,
    ) -> Result<Option<u8>, Cause> {
        self.admit(snapshot, node)?;
        if parent != 0 || node == 0 {
            return Err(Cause::Foreign);
        }
        Ok(if node == self.width {
            None
        } else {
            Some(node + 1)
        })
    }
}

fn memory(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(0, work)))
}

#[test]
fn zero_work_refuses_before_xml_or_visitor_side_effects() {
    // Metadata admission precedes both adapter scanning and callback effects.
    let xml = Document::new(false);
    let memory = memory(0);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let called = Cell::new(false);
    assert!(matches!(
        access.inspect(1, |_| called.set(true)),
        Err(AccessError::Resource {
            node: 1,
            cause: MemoryError::WorkExceeded
        })
    ));
    assert_eq!(xml.calls.get(), 0);
    assert!(!called.get());
}

#[test]
fn owner_scan_refusal_keeps_cause_and_never_invokes_visitor() {
    // Common dispatch does not hide or replace the owner's transitive refusal.
    let xml = Document::new(false);
    let memory = memory(3);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let called = Cell::new(false);
    assert!(matches!(
        access.inspect(1, |_| called.set(true)),
        Err(AccessError::Xml(Cause::Resource(MemoryError::WorkExceeded)))
    ));
    assert!(!called.get());
    assert_eq!(xml.calls.get(), 1);
}

#[test]
fn exact_work_reads_without_storage_or_double_charging_scan() {
    // One metadata step plus the owner's three scanned characters is sufficient.
    let xml = Document::new(false);
    let memory = memory(4);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let length = access
        .inspect(1, |node| match node {
            Node::Text(text) => text.len(),
            _ => 0,
        })
        .unwrap();
    assert_eq!(length, 3);
    assert!(matches!(
        access.first_child(0),
        Err(AccessError::Resource { .. })
    ));
}

#[test]
fn stale_snapshot_rejects_before_dispatch_and_mutation_invalidates_result() {
    // A successful adapter callback cannot legitimize a changed generation.
    let xml = Document::new(true);
    let memory = memory(100);
    let snapshot = xml.snapshot();
    let access = Access::new(&xml, snapshot, &memory);
    assert!(matches!(
        access.inspect(1, |_| 42),
        Err(AccessError::Changed { node: 1 })
    ));
    assert!(matches!(
        access.first_child(0),
        Err(AccessError::Changed { node: 0 })
    ));
    assert_eq!(xml.calls.get(), 1);
}

#[test]
fn foreign_node_keeps_original_processing_cause() {
    // Identity misuse is distinct from malformed XML or an absent property.
    let xml = Document::new(false);
    let memory = memory(100);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        access.inspect(9, |_| ()),
        Err(AccessError::Xml(Cause::Foreign))
    ));
}

#[test]
fn child_order_boundaries_and_empty_attribute_are_preserved() {
    // Direct child order and lexical absence survive the scoped view boundary.
    let xml = Document::new(false);
    let memory = memory(100);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert_eq!(access.first_child(0).unwrap(), Some(1));
    assert_eq!(access.next_sibling(0, 1).unwrap(), Some(2));
    assert_eq!(access.next_sibling(0, 2).unwrap(), None);
    assert_eq!(access.first_child(2).unwrap(), None);
    assert!(matches!(
        access.next_sibling(2, 1),
        Err(AccessError::Xml(Cause::Foreign))
    ));
    assert_eq!(
        access
            .attribute(
                1,
                Name {
                    namespace: "",
                    local: "empty"
                },
                |value| value.map(str::len)
            )
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        access
            .attribute(
                1,
                Name {
                    namespace: "",
                    local: "absent"
                },
                |value| value.map(str::len)
            )
            .unwrap(),
        None
    );
}

#[test]
fn expanded_name_scans_are_paid_and_namespace_identity_is_exact() {
    // Metadata + five namespace bytes + four local bytes is the exact gate.
    let xml = Document::new(false);
    let memory = memory(10);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        access
            .has_name(
                0,
                Name {
                    namespace: "urn:x",
                    local: "root"
                }
            )
            .unwrap()
    );
    assert!(matches!(
        access.first_child(0),
        Err(AccessError::Resource { .. })
    ));

    let memory = self::memory(9);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        access.has_name(
            0,
            Name {
                namespace: "urn:x",
                local: "root"
            }
        ),
        Err(AccessError::Resource {
            node: 0,
            cause: MemoryError::WorkExceeded
        })
    ));

    // URI spelling/case is never normalized for XML namespace comparison.
    let memory = self::memory(6);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        !access
            .has_name(
                0,
                Name {
                    namespace: "URN:x",
                    local: "root"
                }
            )
            .unwrap()
    );
}

#[test]
fn name_length_mismatch_does_not_scan_or_consume_local_name_work() {
    // Rejection by namespace length uses only the admitted metadata dispatch.
    let xml = Document::new(false);
    let memory = memory(1);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(
        !access
            .has_name(
                0,
                Name {
                    namespace: "urn:longer",
                    local: "root"
                }
            )
            .unwrap()
    );
}

#[test]
fn element_only_iterator_never_discards_text_and_is_fused_after_error() {
    // A schema container with unexpected character data is not an empty list.
    let xml = Document::new(false);
    let memory = memory(100);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let mut children = access.children(0);
    assert_eq!(xml.calls.get(), 0);
    assert!(matches!(
        children.next(),
        Some(Err(ChildError::Text { node: 1 }))
    ));
    assert!(children.next().is_none());
    assert!(children.next().is_none());
    assert_eq!(xml.calls.get(), 2);
}

#[test]
fn iterator_resource_refusal_is_not_successful_empty_result() {
    // The first child query itself must fund metadata before access.
    let xml = Document::new(false);
    let memory = memory(0);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let mut children = access.children(0);
    assert!(matches!(
        children.next(),
        Some(Err(ChildError::Access(AccessError::Resource {
            node: 0,
            cause: MemoryError::WorkExceeded
        })))
    ));
    assert!(children.next().is_none());
    assert_eq!(xml.calls.get(), 0);
}

#[test]
fn wide_whitespace_only_container_pays_every_node_and_final_eof() {
    // An attacker cannot hide a wide traversal behind zero returned elements.
    let mut xml = Document::new(false);
    xml.width = 200;
    xml.text = "\t \n";
    let memory = memory(1601);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(access.children(0).next().is_none());
    assert_eq!(xml.calls.get(), 401);
    assert!(matches!(
        access.first_child(0),
        Err(AccessError::Resource { .. })
    ));

    // One less step refuses at the final sibling/EOF query, not empty success.
    let memory = self::memory(1600);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let mut children = access.children(0);
    assert!(matches!(
        children.next(),
        Some(Err(ChildError::Access(AccessError::Resource {
            node: 200,
            cause: MemoryError::WorkExceeded
        })))
    ));
    assert!(children.next().is_none());
}

#[test]
fn unicode_nonbreaking_space_is_not_xml_schema_whitespace() {
    // Unicode-wide trimming would silently drop non-whitespace character data.
    let mut xml = Document::new(false);
    xml.text = "\u{a0}";
    let memory = memory(100);
    let access = Access::new(&xml, xml.snapshot(), &memory);
    assert!(matches!(
        access.children(0).next(),
        Some(Err(ChildError::Text { node: 1 }))
    ));
}
