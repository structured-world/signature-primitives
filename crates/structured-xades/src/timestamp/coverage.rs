//! Exact original element selection for implicit timestamp input coverage.

use super::{Input, Part, TimestampXml};
use crate::xml::{Access, AccessError, Node, Xml};
use crate::{ISSUER, Xades};
use structured_asn1::memory::{MemoryError, Work};
use structured_ltv::material::Coverage;

/// Element coverage in the XML owner's original identity domain. Transformed
/// reference octets grant no whole-element coverage unless the original XML
/// owner explicitly certified `ElementContent` for that successful reference
/// and its actual target.
pub type CoverageFor<X, W> =
    Coverage<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, W, Xades>;

/// Refusal while selecting the original elements of one timestamp input.
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
        elements(
            &Access::new(self.xml, self.snapshot, execution),
            structured_ltv::source::Location {
                snapshot: self.snapshot,
                node: self.timestamp,
            },
            self.signature,
            self.role,
            self.parts.iter().map(|part| {
                Ok(match *part {
                    Part::Element(root)
                    | Part::Reference {
                        covered: Some(root),
                        ..
                    } => Some(root),
                    Part::Reference { covered: None, .. } => None,
                })
            }),
        )
    }
}

pub(crate) fn elements<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    location: structured_ltv::source::Location<X::Id, X::Document, X::Generation>,
    signature: X::Id,
    role: super::Role,
    roots: impl Iterator<Item = Result<Option<X::Id>, X>>,
) -> Result<CoverageFor<X, W>, X> {
    let execution = access.execution();
    let timestamp = location.node;
    access
        .query(timestamp, |_, _, _| Ok(()))
        .map_err(CoverageError::Access)?;
    let mut elements = execution.map();
    let mut frames = execution.vector();
    for root in roots {
        access
            .query(timestamp, |_, _, work| Ok(work.charge_work(1)))
            .map_err(CoverageError::Access)?
            .map_err(|cause| CoverageError::Resource {
                node: timestamp,
                cause,
            })?;
        let Some(root) = root? else {
            continue;
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
        .query(timestamp, |_, _, _| Ok(()))
        .map_err(CoverageError::Access)?;
    Ok(Coverage::new(
        ISSUER,
        location.snapshot,
        signature,
        timestamp,
        role.purpose(),
        elements,
    ))
}
