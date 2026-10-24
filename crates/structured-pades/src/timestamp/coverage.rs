//! Exact checked PDF input coverage of the complete original material index.

use super::{ISSUER, Node, Pades, Requirements};
use crate::{
    material::{Placement, Unified},
    query::Query,
    range::RangeSource,
};
use structured_asn1::memory::{Execution, Work};
use structured_ltv::{
    material::{Coverage, CoverageError, IndexError},
    source::Query as _,
    timestamp::CheckedActor,
};

/// Original source/current admission versus an inconsistent material scope.
#[derive(Debug)]
pub enum Error {
    /// Wrong source, root, token or input selection.
    Pdf(crate::Error),
    /// Original exact material-index refusal.
    Index(IndexError<Node>),
    /// Original coverage/current source refusal.
    Coverage(CoverageError<Node>),
}

impl<D: Copy + Eq, G: Copy + Eq> Requirements<'_, '_, D, G> {
    /// Builds coverage from the actual checked whole-revision input. Every
    /// historical occurrence is visited, including late copies and the DTS's
    /// excluded own token. No successful subset or caller mask is accepted.
    pub fn material_coverage<'q, S: RangeSource<Document = D, Generation = G>>(
        &self,
        ordinal: usize,
        actor: &CheckedActor<'_, '_, Node, D, G, Pades>,
        material: &Unified<'_, '_, D, G>,
        query: &Query<'q, '_, S>,
    ) -> Result<Coverage<Node, D, G, Execution<'q>, Pades>, Error> {
        let root = self.all().signature();
        if !query.belongs(self.root.owner().value.session)
            || !query.belongs(material.session)
            || query.snapshot() != self.root.owner().value.stamp.snapshot
            || !core::ptr::eq(material.required, self.all())
        {
            return Err(Error::Coverage(CoverageError::Foreign { node: root }));
        }
        let signature = self
            .archive(ordinal, actor, query.execution())
            .map_err(Error::Pdf)?;
        let index = &material.index;
        index.require_signature(root, query).map_err(Error::Index)?;
        let mut items = query.execution().map();
        for original in index.all_occurrences(query).map_err(Error::Index)? {
            let original = original.map_err(Error::Index)?;
            let node = original.location().node;
            let covered = super::requirements::covers_node(signature, node, query.execution())
                .map_err(Error::Pdf)?;
            // Placement is source metadata; it must agree with its sealed
            // historical node even if two windows reference the same body.
            match original.placement() {
                Placement::Dss { revision, .. } | Placement::VriTimestamp { revision, .. }
                    if node.material_revision() != Some(revision) =>
                {
                    return Err(Error::Coverage(CoverageError::Foreign { node }));
                }
                _ => {}
            }
            items
                .try_insert(node, covered)
                .map_err(|cause| Error::Coverage(CoverageError::Resource { node, cause }))?;
        }
        let proof = actor.verified();
        Ok(Coverage::for_token(
            ISSUER,
            query.snapshot(),
            root,
            proof.property(),
            proof.token().node,
            proof.purpose(),
            items,
        ))
    }
}
