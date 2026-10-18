//! Exact original element selection for implicit timestamp input coverage.

use super::{Input, Part, TimestampXml};
use crate::xml::{Access, AccessError, Node, Snapshot, Xml};
use structured_asn1::memory::{HashWork, MemoryError, OwnedMap, Work};
use structured_ltv::timestamp::{Purpose, Verified};

/// Original prepared element coverage. Transformed reference octets grant no
/// whole-element coverage unless the original XML owner explicitly certified
/// `ElementContent` for that successful reference and its actual target.
/// Selection alone does not establish successful canonicalization or evidence.
pub struct ElementCoverage<N: HashWork, D, G, W: Work> {
    snapshot: Snapshot<D, G>,
    signature: N,
    timestamp: N,
    purpose: Purpose,
    elements: OwnedMap<N, bool, W>,
}

/// Element selection using the XML owner's original identity domain.
pub type CoverageFor<X, W> =
    ElementCoverage<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, W>;

/// Source/current admission and foreign evidence are independent of absence.
#[derive(Debug)]
pub enum CoverageError<E, N> {
    /// Actual XML/current-operation processing refused.
    Access(AccessError<E, N>),
    /// Element index or iterative traversal storage/work was not admitted.
    Resource {
        /// Original root/input node whose admission failed.
        node: N,
        /// Original capacity/work refusal.
        cause: MemoryError,
    },
    /// Input/evidence/current view refer to different signature/property/source.
    Foreign {
        /// Original requested element.
        node: N,
    },
}

type Result<T, X> = core::result::Result<T, CoverageError<<X as Xml>::Error, <X as Xml>::Id>>;

struct Frame<N> {
    parent: N,
    next: Option<N>,
}

impl<X: TimestampXml> Input<'_, X> {
    /// Indexes the original elements canonicalized in their entirety by this
    /// prepared input, including nested counter-signature/material enclosures.
    /// Comments/text are not element claims; arbitrary transformed reference
    /// output grants no subtree coverage. The same original Part sequence and
    /// explicit successful `ElementContent` receipts drive replay and selection.
    /// Iterative O(depth) cursor frames and an identity set avoid recursive
    /// traversal and repeated scans of overlapping original subtrees.
    pub fn element_coverage<W: Work>(&self, execution: &W) -> Result<CoverageFor<X, W>, X> {
        let access = Access::new(self.xml, self.snapshot, execution);
        access
            .query(self.timestamp, |_, _, _| Ok(()))
            .map_err(CoverageError::Access)?;
        let mut elements = execution.map();
        let mut frames = execution.vector();
        for ordinal in 0..self.parts.len() {
            access
                .query(self.timestamp, |_, _, work| Ok(work.charge_work(1)))
                .map_err(CoverageError::Access)?
                .map_err(|cause| CoverageError::Resource {
                    node: self.timestamp,
                    cause,
                })?;
            let root = match self.parts[ordinal] {
                Part::Element(root)
                | Part::Reference {
                    covered: Some(root),
                    ..
                } => root,
                Part::Reference { covered: None, .. } => continue,
            };
            let resource = |cause| CoverageError::Resource { node: root, cause };
            if elements.get(&root, execution).map_err(resource)?.is_some() {
                continue;
            }
            // A reference may identify the XML document's virtual root. It
            // carries descendants but is not itself an element claim. Keep
            // its visited flag too, avoiding repeated root traversal.
            let element = access
                .inspect(root, |value| matches!(value, Node::Element(_)))
                .map_err(CoverageError::Access)?;
            elements.try_insert(root, element).map_err(resource)?;
            let next = access.first_child(root).map_err(CoverageError::Access)?;
            frames
                .try_push(Frame { parent: root, next })
                .map_err(resource)?;
            while let Some(frame) = frames.last_mut() {
                let Some(node) = frame.next else {
                    frames.pop();
                    continue;
                };
                frame.next = access
                    .next_sibling(frame.parent, node)
                    .map_err(CoverageError::Access)?;
                let element = access
                    .inspect(node, |value| matches!(value, Node::Element(_)))
                    .map_err(CoverageError::Access)?;
                if !element {
                    continue;
                }
                if elements.get(&node, execution).map_err(resource)?.is_some() {
                    continue;
                }
                elements.try_insert(node, true).map_err(resource)?;
                let next = access.first_child(node).map_err(CoverageError::Access)?;
                frames
                    .try_push(Frame { parent: node, next })
                    .map_err(resource)?;
            }
        }
        access
            .query(self.timestamp, |_, _, _| Ok(()))
            .map_err(CoverageError::Access)?;
        Ok(ElementCoverage {
            snapshot: self.snapshot,
            signature: self.signature,
            timestamp: self.timestamp,
            purpose: self.role.purpose(),
            elements,
        })
    }
}

impl<N: Copy + Eq + structured_asn1::memory::HashWork, D: Copy + Eq, G: Copy + Eq, W: Work>
    ElementCoverage<N, D, G, W>
{
    /// Tests prepared whole-element selection under a current source query.
    /// True alone is not proof that any timestamp was mathematically checked.
    pub fn selects<X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &self,
        node: N,
        access: &Access<'_, X, Q>,
    ) -> Result<bool, X> {
        if self.snapshot != access.snapshot() {
            return Err(CoverageError::Foreign { node });
        }
        access
            .query(node, |_, _, work| {
                Ok(self
                    .elements
                    .get(&node, work)
                    .map(|value| value == Some(&true)))
            })
            .map_err(CoverageError::Access)?
            .map_err(|cause| CoverageError::Resource { node, cause })
    }

    /// Binds element selection to the privately constructed successful token
    /// evidence for this exact original input. This establishes mathematical
    /// coverage only; TSA/path/status/chronology acceptance remains separate.
    pub fn covers<X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &self,
        evidence: &Verified<N, D, G>,
        node: N,
        access: &Access<'_, X, Q>,
    ) -> Result<bool, X> {
        self.require_evidence(evidence, node, access)?;
        self.selects(node, access)
    }

    pub(crate) fn require_evidence<X: Xml<Id = N, Document = D, Generation = G>, Q: Work>(
        &self,
        evidence: &Verified<N, D, G>,
        node: N,
        access: &Access<'_, X, Q>,
    ) -> Result<(), X> {
        if self.snapshot != access.snapshot() {
            return Err(CoverageError::Foreign { node });
        }
        access
            .query(node, |_, _, work| {
                Ok(self.require_identity(
                    evidence.token().snapshot,
                    evidence.signature(),
                    evidence.property(),
                    evidence.purpose(),
                    node,
                    work,
                ))
            })
            .map_err(CoverageError::Access)?
    }

    fn require_identity<E, Q: Work>(
        &self,
        snapshot: Snapshot<D, G>,
        signature: N,
        timestamp: N,
        purpose: Purpose,
        node: N,
        execution: &Q,
    ) -> core::result::Result<(), CoverageError<E, N>> {
        let resource = |cause| CoverageError::Resource { node, cause };
        if snapshot != self.snapshot
            || !crate::xml::equal_id(signature, self.signature, execution).map_err(resource)?
            || !crate::xml::equal_id(timestamp, self.timestamp, execution).map_err(resource)?
            || purpose != self.purpose
        {
            return Err(CoverageError::Foreign { node });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::{
        cell::Cell,
        hash::{Hash, Hasher},
    };
    use structured_asn1::memory::{Memory, MemoryAccount};

    #[derive(Clone, Copy, Debug)]
    struct CountedId<'a>(&'a Cell<usize>, u8);

    impl PartialEq for CountedId<'_> {
        fn eq(&self, other: &Self) -> bool {
            self.0.set(self.0.get() + 1);
            self.1 == other.1
        }
    }
    impl Eq for CountedId<'_> {}
    impl Hash for CountedId<'_> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.1.hash(state);
        }
    }
    impl HashWork for CountedId<'_> {
        fn hash_work(&self) -> core::result::Result<u64, MemoryError> {
            Ok(64)
        }
    }

    #[test]
    fn evidence_identity_admits_each_comparison_before_equality() {
        // Data-dependent Id equality must not execute under a zero/short
        // current query budget, even though its retained map is already funded.
        let calls = Cell::new(0);
        let id = CountedId(&calls, 1);
        let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1000)));
        let snapshot = Snapshot {
            document: 1u8,
            generation: 1u8,
        };
        let coverage = ElementCoverage {
            snapshot,
            signature: id,
            timestamp: id,
            purpose: Purpose::Archive,
            elements: memory.map(),
        };
        for (budget, expected_calls) in [(0, 0), (127, 0), (128, 1), (255, 1)] {
            calls.set(0);
            let current = Memory::new(Arc::new(MemoryAccount::new(0, budget)));
            assert!(matches!(
                coverage.require_identity::<(), _>(
                    snapshot,
                    id,
                    id,
                    Purpose::Archive,
                    id,
                    &current,
                ),
                Err(CoverageError::Resource {
                    cause: MemoryError::WorkExceeded,
                    ..
                })
            ));
            assert_eq!(calls.get(), expected_calls);
        }
        calls.set(0);
        let exact = Memory::new(Arc::new(MemoryAccount::new(0, 256)));
        coverage
            .require_identity::<(), _>(snapshot, id, id, Purpose::Archive, id, &exact)
            .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(exact.charge_work(1), Err(MemoryError::WorkExceeded));
        assert_eq!(exact.used(), 0);
    }
}
