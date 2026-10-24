//! Scoped XML access without retaining DOM or callback-local string borrows.

use structured_asn1::memory::{HashWork, MemoryError, Work};
use structured_ltv::source::{Query, ScopeError};

// The snapshot is part of this trait's vocabulary: implementors name it here.
pub use structured_ltv::source::Snapshot;

/// An expanded XML name; prefix spelling does not participate in identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name<'a> {
    /// Namespace name, empty for an unqualified name.
    pub namespace: &'a str,
    /// Local name after the XML owner's namespace processing.
    pub local: &'a str,
}

/// One callback-local XML node view, preserving text-node distinctions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node<'a> {
    /// An element's expanded name.
    Element(Name<'a>),
    /// XML-normalized character data, not original encoded document bytes.
    Text(&'a str),
    /// A comment, processing instruction or other non-element node.
    Other,
}

/// The XML owner's stable, snapshot-checked access boundary.
///
/// Every method must reject a foreign node and a stale snapshot before access.
/// The owner admits its complete data-dependent scans and allocations through
/// `execution` and its own compiled XML policy before doing that work. Common
/// dispatch admission does not prove accounting inside arbitrary adapter code.
/// Access must not implicitly reparse, fetch a resource or change the document.
///
/// The higher-ranked visitors cannot retain view-local names/text in their
/// return value. An adapter can therefore resolve nodes inside a temporary
/// document view, without exposing its DOM types or extending that view's life.
pub trait Xml {
    /// Stable node identity scoped to this document, independent of a DOM borrow.
    /// Its trusted `HashWork` bound covers all hashing/equality bytes so identity
    /// indexes can admit their complete work before querying attacker input.
    type Id: Copy + Eq + HashWork;
    /// Stable document identity.
    type Document: Copy + Eq;
    /// Exact document generation.
    type Generation: Copy + Eq;
    /// Original XML processing/policy/resource failure.
    type Error;

    /// Returns identity/generation in constant time, without allocation or I/O.
    fn snapshot(&self) -> Snapshot<Self::Document, Self::Generation>;

    /// Inspects one original node within the expected snapshot.
    fn inspect<R, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        execution: &W,
        visitor: impl for<'view> FnOnce(Node<'view>) -> R,
    ) -> Result<R, Self::Error>;

    /// Reads an attribute by expanded name, preserving absence versus empty.
    ///
    /// Generic XML attribute normalization and namespace rules belong to the
    /// owner. Unqualified attributes use the empty namespace, regardless of an
    /// element's default namespace. Returned text is XML-normalized lexical data.
    fn attribute<R, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        name: Name<'_>,
        execution: &W,
        visitor: impl for<'view> FnOnce(Option<&'view str>) -> R,
    ) -> Result<R, Self::Error>;

    /// Returns the first direct child, including text and non-element children.
    fn first_child<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        parent: Self::Id,
        execution: &W,
    ) -> Result<Option<Self::Id>, Self::Error>;

    /// Returns the next direct sibling in original document order.
    ///
    /// `parent` pins the traversal boundary; the owner rejects a node outside
    /// that parent's child list rather than continuing in another subtree.
    fn next_sibling<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        parent: Self::Id,
        node: Self::Id,
        execution: &W,
    ) -> Result<Option<Self::Id>, Self::Error>;
}

/// An XML access refusal located by original node identity, not a fake byte offset.
#[derive(Debug)]
pub enum AccessError<E, N> {
    /// The XML owner's original cause.
    Xml(E),
    /// Common admission failed before callback dispatch.
    Resource {
        /// Original node associated with the attempted operation.
        node: N,
        /// Original execution refusal.
        cause: MemoryError,
    },
    /// Document identity or generation changed; previous evidence is unusable.
    Changed {
        /// Node associated with the attempted operation.
        node: N,
    },
}

/// Result retaining the selected XML adapter's cause and original node identity.
pub type AccessResult<T, X> = Result<T, AccessError<<X as Xml>::Error, <X as Xml>::Id>>;
/// Original XML admission and scoped visitor failures with separate causes.
pub type VisitResult<T, X, E> =
    Result<T, AccessError<crate::reference::VisitError<<X as Xml>::Error, E>, <X as Xml>::Id>>;

/// Failure to traverse an element-only property container.
#[derive(Debug)]
pub enum ChildError<E, N> {
    /// Original access, generation or execution refusal.
    Access(AccessError<E, N>),
    /// Character data is not XML whitespace in an element-only container.
    Text {
        /// Original text-node identity; no document byte position is invented.
        node: N,
    },
}

/// One snapshot and current operation shared by all scoped XML queries.
///
/// This guard checks the snapshot before and after every successful callback.
/// The adapter must also check at actual access, so these checks do not replace
/// owner synchronization or immutable-view guarantees. No clone, allocation or
/// reference-count increment is required to construct the guard.
pub struct Access<'a, X: Xml, W: Work> {
    xml: &'a X,
    snapshot: Snapshot<X::Document, X::Generation>,
    execution: &'a W,
}

impl<'a, X: Xml, W: Work> Access<'a, X, W> {
    /// Attaches the expected original snapshot and current operation.
    #[must_use]
    pub fn new(
        xml: &'a X,
        snapshot: Snapshot<X::Document, X::Generation>,
        execution: &'a W,
    ) -> Self {
        Self {
            xml,
            snapshot,
            execution,
        }
    }

    /// The source snapshot associated with node locations and selection evidence.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<X::Document, X::Generation> {
        self.snapshot
    }

    /// Borrows the actual current execution used by this access boundary.
    /// Provider/resolver lexical scans and owned results must be admitted here,
    /// rather than on an earlier source/storage account. No clone, allocation
    /// or account/reference-count change occurs. The borrow cannot outlive this
    /// access handle and does not expose the XML owner's internal DOM.
    #[must_use]
    pub fn execution(&self) -> &W {
        self.execution
    }

    pub(crate) fn owner(&self) -> &'a X {
        self.xml
    }

    /// Traverses direct element children, skipping comments and XML whitespace.
    ///
    /// Character data is rejected rather than silently dropped. Each skipped
    /// node is admitted and checked in the same operation, so an empty result
    /// cannot bypass a large whitespace/comment fan-out. Construction allocates
    /// nothing. The first error is returned once, then iteration is fused.
    #[must_use]
    pub fn children(&self, parent: X::Id) -> Children<'_, 'a, X, W> {
        Children {
            access: self,
            parent,
            previous: None,
            started: false,
            done: false,
        }
    }

    fn unchanged<E>(&self, node: X::Id) -> Result<(), AccessError<E, X::Id>> {
        if self.xml.snapshot() != self.snapshot {
            return Err(AccessError::Changed { node });
        }
        Ok(())
    }

    fn call<R, E>(
        &self,
        node: X::Id,
        callback: impl FnOnce() -> Result<R, E>,
    ) -> Result<R, AccessError<E, X::Id>> {
        self.unchanged(node)?;
        self.execution
            .charge_work(1)
            .map_err(|cause| AccessError::Resource { node, cause })?;
        let result = callback().map_err(AccessError::Xml)?;
        self.unchanged(node)?;
        Ok(result)
    }

    pub(crate) fn query<R>(
        &self,
        node: X::Id,
        callback: impl FnOnce(&X, Snapshot<X::Document, X::Generation>, &W) -> Result<R, X::Error>,
    ) -> AccessResult<R, X> {
        self.call(node, || callback(self.xml, self.snapshot, self.execution))
    }

    // Same dispatch/generation/admission core, preserving visitor errors before
    // the post-success generation check. No side channel or error substitution.
    pub(crate) fn query_fallible<R, E>(
        &self,
        node: X::Id,
        callback: impl FnOnce(&X, Snapshot<X::Document, X::Generation>, &W) -> Result<R, E>,
    ) -> Result<R, AccessError<E, X::Id>> {
        self.call(node, || callback(self.xml, self.snapshot, self.execution))
    }

    pub(crate) fn equal(&self, left: &str, right: &str) -> Result<bool, MemoryError> {
        equal_text(left, right, self.execution)
    }

    pub(crate) fn equal_id(&self, left: X::Id, right: X::Id) -> Result<bool, MemoryError> {
        equal_id(left, right, self.execution)
    }

    pub(crate) fn trim_xml_whitespace<'value>(
        &self,
        value: &'value str,
    ) -> Result<&'value str, MemoryError> {
        self.execution
            .charge_work(u64::try_from(value.len()).map_err(|_| MemoryError::WorkExceeded)?)?;
        Ok(value.trim_matches([' ', '\t', '\r', '\n']))
    }

    /// Inspects one node without leaking callback-local XML borrows.
    ///
    /// ```compile_fail
    /// use structured_xades::xml::{Access, AccessError, Node, Xml};
    /// use structured_asn1::memory::Work;
    /// fn escape<'a, X: Xml, W: Work>(access: &Access<'a, X, W>, node: X::Id)
    ///     -> Result<Option<&'a str>, AccessError<X::Error, X::Id>>
    /// {
    ///     access.inspect(node, |value| match value {
    ///         Node::Text(text) => Some(text),
    ///         _ => None,
    ///     })
    /// }
    /// ```
    pub fn inspect<R>(
        &self,
        node: X::Id,
        visitor: impl for<'view> FnOnce(Node<'view>) -> R,
    ) -> AccessResult<R, X> {
        self.call(node, || {
            self.xml
                .inspect(self.snapshot, node, self.execution, visitor)
        })
    }

    /// Compares an element's expanded name with admission before each byte scan.
    ///
    /// A different node kind or name length needs no string scan. Namespace
    /// names are compared exactly, without URI resolution or normalization.
    pub fn has_name(&self, node: X::Id, expected: Name<'_>) -> AccessResult<bool, X> {
        let compared = self.inspect(node, |value| {
            let Node::Element(actual) = value else {
                return Ok(false);
            };
            // Namespaces in XML 1.0 Third Edition §2.3: namespace-name identity
            // is exact character-string comparison, not URI equivalence.
            // https://www.w3.org/TR/2009/REC-xml-names-20091208/#ComparingURIReferences
            if !equal_text(actual.namespace, expected.namespace, self.execution)? {
                return Ok(false);
            }
            equal_text(actual.local, expected.local, self.execution)
        })?;
        compared.map_err(|cause| AccessError::Resource { node, cause })
    }

    /// Reads a normalized attribute, preserving absence versus an empty value.
    pub fn attribute<R>(
        &self,
        node: X::Id,
        name: Name<'_>,
        visitor: impl for<'view> FnOnce(Option<&'view str>) -> R,
    ) -> AccessResult<R, X> {
        self.call(node, || {
            self.xml
                .attribute(self.snapshot, node, name, self.execution, visitor)
        })
    }

    /// Begins a direct-child traversal, admitting even the empty-list query.
    pub fn first_child(&self, parent: X::Id) -> AccessResult<Option<X::Id>, X> {
        self.call(parent, || {
            self.xml.first_child(self.snapshot, parent, self.execution)
        })
    }

    /// Advances within the same direct-child list in original order.
    pub fn next_sibling(&self, parent: X::Id, node: X::Id) -> AccessResult<Option<X::Id>, X> {
        self.call(node, || {
            self.xml
                .next_sibling(self.snapshot, parent, node, self.execution)
        })
    }
}

// Long-term validation checks run under the same snapshot guard and current
// operation as every XML query, so one admission path serves both.
impl<X: Xml, W: Work> Query for Access<'_, X, W> {
    type Id = X::Id;
    type Document = X::Document;
    type Generation = X::Generation;
    type Work = W;

    fn snapshot(&self) -> Snapshot<X::Document, X::Generation> {
        self.snapshot
    }

    fn execution(&self) -> &W {
        self.execution
    }

    fn admit(&self, node: X::Id, units: u64) -> Result<(), ScopeError<X::Id>> {
        let changed = |_: AccessError<(), X::Id>| ScopeError::Changed { node };
        self.unchanged(node).map_err(changed)?;
        self.execution
            .charge_work(units)
            .map_err(|cause| ScopeError::Resource { node, cause })?;
        self.unchanged(node).map_err(changed)
    }
}

impl<E, N> From<ScopeError<N>> for AccessError<E, N> {
    fn from(cause: ScopeError<N>) -> Self {
        match cause {
            ScopeError::Changed { node } => Self::Changed { node },
            ScopeError::Resource { node, cause } => Self::Resource { node, cause },
        }
    }
}

pub(crate) fn equal_id<N: Copy + HashWork, W: Work>(
    left: N,
    right: N,
    execution: &W,
) -> Result<bool, MemoryError> {
    let cost = left
        .hash_work()?
        .checked_add(right.hash_work()?)
        .ok_or(MemoryError::WorkExceeded)?;
    execution.charge_work(cost)?;
    Ok(left == right)
}

/// An iterative, snapshot-checked direct-child traversal for property containers.
pub struct Children<'a, 'xml, X: Xml, W: Work> {
    access: &'a Access<'xml, X, W>,
    parent: X::Id,
    previous: Option<X::Id>,
    started: bool,
    done: bool,
}

impl<X: Xml, W: Work> Iterator for Children<'_, '_, X, W> {
    type Item = Result<X::Id, ChildError<X::Error, X::Id>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            let advanced = if self.started {
                let Some(previous) = self.previous else {
                    self.done = true;
                    return None;
                };
                self.access.next_sibling(self.parent, previous)
            } else {
                self.started = true;
                self.access.first_child(self.parent)
            };
            let node = match advanced {
                Ok(Some(node)) => node,
                Ok(None) => {
                    self.done = true;
                    return None;
                }
                Err(error) => {
                    self.done = true;
                    return Some(Err(ChildError::Access(error)));
                }
            };
            self.previous = Some(node);
            let inspected = self.access.inspect(node, |value| match value {
                Node::Element(_) => Ok(Some(true)),
                Node::Other => Ok(None),
                Node::Text(text) => {
                    let length =
                        u64::try_from(text.len()).map_err(|_| MemoryError::WorkExceeded)?;
                    self.access.execution.charge_work(length)?;
                    // XML 1.0 Fifth Edition §2.3, production S: only these four
                    // characters are XML whitespace, irrespective of Unicode.
                    // https://www.w3.org/TR/2008/REC-xml-20081126/#NT-S
                    for byte in text.bytes() {
                        if !matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                            return Ok(Some(false));
                        }
                    }
                    Ok(None)
                }
            });
            match inspected {
                Ok(Ok(Some(true))) => return Some(Ok(node)),
                Ok(Ok(None)) => {}
                Ok(Ok(Some(false))) => {
                    self.done = true;
                    return Some(Err(ChildError::Text { node }));
                }
                Ok(Err(cause)) => {
                    self.done = true;
                    return Some(Err(ChildError::Access(AccessError::Resource {
                        node,
                        cause,
                    })));
                }
                Err(error) => {
                    self.done = true;
                    return Some(Err(ChildError::Access(error)));
                }
            }
        }
    }
}

impl<X: Xml, W: Work> core::iter::FusedIterator for Children<'_, '_, X, W> {}

fn equal_text<W: Work>(left: &str, right: &str, execution: &W) -> Result<bool, MemoryError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    let length = u64::try_from(left.len()).map_err(|_| MemoryError::WorkExceeded)?;
    execution.charge_work(length)?;
    Ok(left == right)
}
