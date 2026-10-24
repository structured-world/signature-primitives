//! Sealed translation of actual CMS facts into their original PDF enclosure.

use crate::{
    error::{Error, ErrorKind},
    model::admit,
    source::Location,
    timestamp::{ISSUER, Node, Pades},
};
use structured_asn1::memory::Work;
use structured_cades::{
    Cades,
    source::{DocumentId, Node as CmsNode},
};
use structured_ltv::{
    source::{Location as Original, Snapshot},
    timestamp::{CheckedActor, Verified},
};

pub(crate) struct InnerQuery<'q, 'm, 'd, D, G, Q> {
    pub(crate) outer: &'q Q,
    pub(crate) mapping: Mapping<'m, 'd, D, G>,
}
impl<
    'm,
    'd,
    D: Copy + Eq,
    G: Copy + Eq,
    Q: structured_ltv::source::Query<Id = Node, Document = D, Generation = G>,
> structured_ltv::source::Query for InnerQuery<'_, 'm, 'd, D, G, Q>
{
    type Id = CmsNode;
    type Document = DocumentId<'m, 'd>;
    type Generation = ();
    type Work = Q::Work;
    fn snapshot(&self) -> Snapshot<Self::Document, ()> {
        self.mapping.cms
    }
    fn execution(&self) -> &Q::Work {
        self.outer.execution()
    }
    fn admit(
        &self,
        node: CmsNode,
        units: u64,
    ) -> Result<(), structured_ltv::source::ScopeError<CmsNode>> {
        self.outer
            .admit(self.mapping.node(node), units)
            .map_err(|cause| match cause {
                structured_ltv::source::ScopeError::Changed { .. } => {
                    structured_ltv::source::ScopeError::Changed { node }
                }
                structured_ltv::source::ScopeError::Resource { cause, .. } => {
                    structured_ltv::source::ScopeError::Resource { node, cause }
                }
            })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Mapping<'m, 'd, D, G> {
    pub(crate) snapshot: Snapshot<D, G>,
    pub(crate) root: Node,
    pub(crate) carrier: Location,
    pub(crate) cms_root: CmsNode,
    pub(crate) cms: Snapshot<DocumentId<'m, 'd>, ()>,
}

impl<D: Copy, G: Copy> Mapping<'_, '_, D, G> {
    pub(crate) fn node(self, member: CmsNode) -> Node {
        if member == self.cms_root {
            self.root
        } else {
            Node::inside(self.carrier, member)
        }
    }
}

impl<'m, 'd, D: Copy + Eq, G: Copy + Eq> Mapping<'m, 'd, D, G> {
    pub(crate) fn actor<'p>(
        self,
        actor: CheckedActor<'p, 'd, CmsNode, DocumentId<'m, 'd>, (), Cades>,
        work: &impl Work,
    ) -> crate::Result<CheckedActor<'p, 'd, Node, D, G, Pades>> {
        admit(work, self.carrier, 1)?;
        let original = actor.verified();
        if original.token().snapshot != self.cms {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: self.carrier,
            });
        }
        let token = Original {
            snapshot: self.snapshot,
            node: self.node(original.token().node),
        };
        let signature = self.node(original.signature());
        let property = self.node(original.property());
        let purpose = original.purpose();
        let certificate = actor.certificate();
        let key = actor.key();
        let evidence = actor.into_verified().into_evidence();
        Ok(CheckedActor::new(
            ISSUER,
            Verified::new(ISSUER, token, signature, property, purpose, evidence),
            certificate,
            key,
        ))
    }
}
