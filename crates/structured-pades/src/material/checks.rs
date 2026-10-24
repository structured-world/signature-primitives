//! Complete actual X.509 material, independent of status usability and trust.

use super::{Placement, Unified};
use crate::{
    query::Query,
    range::RangeSource,
    timestamp::{Node, Pades},
};
use structured_ltv::{
    baseline::X509Material,
    material::{self, Incorporation, IncorporationError, IndexError},
    pki::{self, ParticipantClosure, ParticipantRequirements, UsesError},
    source::Query as _,
    timestamp::TimestampScope,
};

/// All actual actor/credential/status-authority artifacts and their original
/// incorporated copies. A late copy establishes presence, never earlier `PoE`.
pub struct Checks<'cl, 'r, 'v, 'c, 'd, D, G> {
    inputs: &'cl ParticipantClosure<'r, 'v, 'c, 'd, Node, D, G, Pades>,
    presence: Incorporation<'c, 'd, Node, D, G, Placement>,
    source_conforming: bool,
    revision: usize,
}
impl<'c, 'd, D: Copy, G: Copy> Checks<'_, '_, '_, 'c, 'd, D, G> {
    /// Every actual required artifact, preserving each missing value.
    #[must_use]
    pub fn presence(&self) -> &Incorporation<'c, 'd, Node, D, G, Placement> {
        &self.presence
    }
    /// Whole-source syntax and required presence only, not Good status,
    /// historical coverage, credential-format completeness or application trust.
    #[must_use]
    pub fn all_x509_requirements_met(&self) -> bool {
        self.source_conforming && self.presence.all_present()
    }
    /// Original revision whose available material was assessed. Later DSS
    /// windows cannot repair this report's presence or source findings.
    #[must_use]
    pub fn revision(&self) -> usize {
        self.revision
    }
}
impl<'v, 'd, D: Copy, G: Copy> X509Material<'v, 'd> for Checks<'_, '_, 'v, '_, 'd, D, G> {
    type Id = Node;
    type Document = D;
    type Generation = G;
    type Issuer = Pades;
    fn requirements(&self) -> &ParticipantRequirements<'v, 'd, Node, D, G, Pades> {
        self.inputs.requirements()
    }
    fn all_x509_requirements_met(&self) -> bool {
        Self::all_x509_requirements_met(self)
    }
}

/// Complete actor attribution or original source/current admission refusal.
#[derive(Debug)]
pub enum Error {
    /// An earlier-archive subset cannot establish whole-signature material.
    Scope,
    /// Original source/index refusal.
    Index(IndexError<Node>),
    /// Complete actual authority/status input census refused.
    Uses(UsesError<Node>),
    /// Original exact-artifact incorporation query refused.
    Presence(IncorporationError<Node>),
}
impl<D: Copy + Eq, G: Copy + Eq> Unified<'_, '_, D, G> {
    /// Uses all real root/counter/credential/TSA paths and their reached status
    /// authorities, without replaying a parser, signature or status evaluation.
    /// EN319142-1 §6.3(r,t) includes every used certificate/status artifact;
    /// status usability and historical protection remain separate obligations.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
    pub fn check_participants<'cl, 'r, 'v, 'c, 'd, S: RangeSource<Document = D, Generation = G>>(
        &self,
        inputs: &'cl ParticipantClosure<'r, 'v, 'c, 'd, Node, D, G, Pades>,
        paths: &structured_ltv::timestamp::TimestampPaths<'_, '_, '_, Node, D, G, Pades>,
        query: &Query<'_, '_, S>,
    ) -> Result<Checks<'cl, 'r, 'v, 'c, 'd, D, G>, Error> {
        let required = inputs.requirements();
        if !matches!(required.scope(), TimestampScope::All(_)) {
            return Err(Error::Scope);
        }
        if !query.belongs(self.session)
            || required.signature() != self.root
            || required.scope().location().snapshot != query.snapshot()
        {
            return Err(Error::Index(IndexError::Foreign {
                signature: self.root,
            }));
        }
        query
            .admit(self.root, 2)
            .map_err(|cause| Error::Index(IndexError::Scope(cause)))?;
        if !core::ptr::eq(paths.required(), self.required) || !required.same_timestamps(paths) {
            return Err(Error::Scope);
        }
        self.index
            .require_signature(self.root, query)
            .map_err(Error::Index)?;
        let uses = pki::authority_uses(inputs, query).map_err(Error::Uses)?;
        let artifacts = material::artifact_uses(&uses, query).map_err(Error::Uses)?;
        let presence =
            material::incorporation(&artifacts, &self.index, query).map_err(Error::Presence)?;
        Ok(Checks {
            inputs,
            presence,
            source_conforming: self.complete,
            revision: self.revision,
        })
    }

    /// Requires each actual preceding actor's X.509/status artifacts inside
    /// this exact checked original PDF input. The archive's own contents and
    /// later DSS copies do not count as prior protection.
    #[expect(
        clippy::result_large_err,
        reason = "the common participant archive error preserves original typed artifact failures and cannot allocate an envelope after refusal"
    )]
    pub fn archived_participants<'cl, 'r, 'v, 'c, 'd, S, W>(
        &self,
        inputs: &'cl ParticipantClosure<'r, 'v, 'c, 'd, Node, D, G, Pades>,
        coverage: &material::Coverage<Node, D, G, W, Pades>,
        actor: &structured_ltv::timestamp::CheckedActor<'_, '_, Node, D, G, Pades>,
        query: &Query<'_, '_, S>,
    ) -> Result<
        material::ParticipantMaterial<'cl, 'r, 'v, 'c, 'd, Node, D, G, Placement, Pades>,
        material::ParticipantArchiveError<Node>,
    >
    where
        S: RangeSource<Document = D, Generation = G>,
        W: structured_asn1::memory::Work,
    {
        if !query.belongs(self.session) || inputs.requirements().signature() != self.root {
            return Err(material::ParticipantArchiveError::Foreign {
                expected: self.root,
                actual: inputs.requirements().signature(),
            });
        }
        material::archived_participants(inputs, &self.index, coverage, actor.verified(), query)
    }
}
