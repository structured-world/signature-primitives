//! Exact original A.7 actors, preceding obligations and protected material input.

use super::{
    ArchiveError, AssertionScope, Graph, InputAssociation, MemberId, RangeSource, Work, resource,
};
use crate::{
    Asic, ISSUER,
    content::Content,
    source::{DocumentId, Node as SourceNode},
    timestamp,
};
use structured_asn1::{Reader, memory::Execution};
use structured_cms::{
    provider::SignatureProvider,
    timestamp::{CheckContext, CheckedTimestamp, Token, TokenExtension},
};
use structured_ltv::{
    material::Coverage,
    source::{Location, Query},
    timestamp::{
        CheckedActor, Purpose, RequiredToken, TimestampRequirements, TimestampScope, Verified,
    },
};

/// Actual common check, with its independently retained evidence moved exactly
/// once into the selected TSA actor. It performs no second signature or copy.
pub struct ActorCheck<'c, 'd, 'v, 's, S: RangeSource> {
    token: MemberId<S::Document, S::Generation>,
    input: MemberId<S::Document, S::Generation>,
    facts: CheckedTimestamp<'d>,
    actor: Option<CheckedActor<'c, 'd, SourceNode, DocumentId<'v, 's, S>, (), Asic>>,
}
impl<'c, 'd, 'v, 's, S: RangeSource> ActorCheck<'c, 'd, 'v, 's, S> {
    /// Actual original time-assertion member.
    #[must_use]
    pub fn token(&self) -> MemberId<S::Document, S::Generation> {
        self.token
    }
    /// Actual original complete manifest input, not its name or a rebuilt XML.
    #[must_use]
    pub fn input(&self) -> MemberId<S::Document, S::Generation> {
        self.input
    }
    /// All original check facts; mathematical evidence has moved into `actor()`.
    #[must_use]
    pub fn facts(&self) -> &CheckedTimestamp<'d> {
        &self.facts
    }
    /// Same actual certificate/key used by complete checking. None preserves
    /// a negative original check and cannot create a TSA path or material proof.
    #[must_use]
    pub fn actor(
        &self,
    ) -> Option<&CheckedActor<'c, 'd, SourceNode, DocumentId<'v, 's, S>, (), Asic>> {
        self.actor.as_ref()
    }
}

/// Complete original actor result, preserving large retained failure context.
pub type ActorResult<'c, 'd, 'v, 's, S, PE, RE> = Result<
    ActorCheck<'c, 'd, 'v, 's, S>,
    timestamp::Error<
        <S as RangeSource>::Error,
        PE,
        RE,
        <S as RangeSource>::Document,
        <S as RangeSource>::Generation,
    >,
>;
/// Complete source-derived preceding TSA requirements, or explicit unavailability.
pub type RequirementsResult<'v, 's, S> = Result<
    Option<TimestampRequirements<SourceNode, DocumentId<'v, 's, S>, (), Asic>>,
    ArchiveError<<S as RangeSource>::Error>,
>;
/// Actual protected original-member selection, independently of trust/material.
pub type CoverageResult<'q, 'v, 's, S> = Result<
    Option<Coverage<SourceNode, DocumentId<'v, 's, S>, (), Execution<'q>, Asic>>,
    ArchiveError<<S as RangeSource>::Error>,
>;

impl<'v, 's, S: RangeSource> Content<'v, 's, S> {
    /// Checks one actual historical assertion over an original complete input.
    /// The role selects data versus archive-input mathematics, not container
    /// conformance. Only the source-derived graph can mint archive coverage.
    #[expect(
        clippy::too_many_arguments,
        reason = "actual source, provider, selected TSA context, complete input and its explicit role are independent contracts"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "preserve admitted original diagnostic maps when an allocation cannot be made"
    )]
    pub async fn check_assertion_actor<'c, 'd, P, PE, RE>(
        &'d self,
        token: &'d Token<'d>,
        parent: &Reader<'d>,
        provider: &'d P,
        context: &CheckContext<'d, 'c>,
        input: &impl crate::payload::Payload<'v, 's, S>,
        kind: timestamp::InputKind,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> ActorResult<'c, 'd, 'v, 's, S, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let work = parent.execution();
        let checked = self
            .check_timestamp(
                token,
                parent,
                provider,
                timestamp::Context::Historical(context),
                input,
                recognizes,
            )
            .await?;
        let mut facts = checked.into_common();
        let query = self.member().archive().ltv_query(&work);
        let purpose = match kind {
            timestamp::InputKind::Data => Purpose::Content,
            timestamp::InputKind::Archive => Purpose::Archive,
        };
        let actor = facts.take_evidence().map(|evidence| {
            let verified = Verified::new(
                ISSUER,
                Location {
                    snapshot: query.snapshot(),
                    node: SourceNode::Member(self.member().id().ordinal()),
                },
                SourceNode::Root,
                SourceNode::Member(input.member().id().ordinal()),
                purpose,
                evidence,
            );
            CheckedActor::new(ISSUER, verified, context.certificate, context.key)
        });
        self.member()
            .archive()
            .admit(&work, self.enclosure())
            .map_err(timestamp::Error::Archive)?;
        Ok(ActorCheck {
            token: self.member().id(),
            input: input.member().id(),
            facts,
            actor,
        })
    }
}

impl<'v, 's, N: Copy, D: Copy + Eq, G: Copy + Eq, S: RangeSource> Graph<'v, 's, N, D, G, S> {
    /// Checks the actual original token of this graph node against its complete
    /// original manifest bytes, then records the exact selected TSA actor for
    /// the existing LTV path/status/material machinery. No generic attach exists.
    #[expect(
        clippy::too_many_arguments,
        reason = "the unchanged common token/provider/TSA/UTC context and selected source node remain explicit"
    )]
    #[expect(
        clippy::result_large_err,
        reason = "original source maps and processing causes must survive resource refusal without an error allocation"
    )]
    pub async fn check_actor<'c, 'd, P, PE, RE>(
        &self,
        index: usize,
        carried: &'d Content<'v, 's, S>,
        token: &'d Token<'d>,
        parent: &Reader<'d>,
        provider: &'d P,
        context: &CheckContext<'d, 'c>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> ActorResult<'c, 'd, 'v, 's, S, PE, RE>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let work = parent.execution();
        let foreign = || {
            timestamp::Error::Archive(ArchiveError::Foreign {
                range: self.archive.directory_span(),
            })
        };
        let node = self.nodes.get(index).ok_or_else(foreign)?;
        if !core::ptr::eq(carried.member().archive(), self.archive)
            || node.timestamp != Some(carried.member().id())
        {
            return Err(foreign());
        }
        let input = self
            .archive
            .original(node.member, &work)
            .map_err(timestamp::Error::Archive)?;
        carried
            .check_assertion_actor(
                token,
                parent,
                provider,
                context,
                &input,
                timestamp::InputKind::Archive,
                recognizes,
            )
            .await
    }

    /// Complete preceding TSA obligations for exactly this original archive
    /// input. A broken/uninspected graph yields no complete census. The first
    /// timestamp has no preceding TSA, while its own new-TSA material remains
    /// a separate incorporation/placement obligation.
    pub fn requirements<W: Work>(
        &self,
        index: usize,
        layout: &crate::layout::Inspection<'_, 'v, 's, S>,
        work: &W,
    ) -> RequirementsResult<'v, 's, S> {
        let original = self.timestamp_inputs(index, layout, work)?;
        if !original.complete() {
            return Ok(None);
        }
        let query = self.archive.ltv_query(work);
        let execution = query.execution();
        self.archive
            .admit(execution, self.archive.directory_span())?;
        let signature = SourceNode::Root;
        let mut entries = execution.vector();
        for prior in original.entries() {
            execution
                .charge_work(1)
                .map_err(|cause| resource(self.archive.directory_span(), cause))?;
            if prior.scope != AssertionScope::Declared {
                continue;
            }
            let InputAssociation::Known { member, purpose } = prior.association else {
                return Ok(None);
            };
            entries
                .try_push(RequiredToken {
                    signature,
                    property: SourceNode::Member(member.ordinal()),
                    token: SourceNode::Member(prior.token.ordinal()),
                    purpose,
                })
                .map_err(|cause| resource(self.archive.directory_span(), cause))?;
        }
        let current = &self.nodes[index];
        let Some(token) = current.timestamp else {
            return Ok(None);
        };
        Ok(Some(TimestampRequirements::new(
            ISSUER,
            signature,
            TimestampScope::BeforeArchive(Location {
                snapshot: query.snapshot(),
                node: SourceNode::Member(token.ordinal()),
            }),
            entries.into_owned(),
        )))
    }

    /// Mints protected whole-member coverage only after this ACTUAL TST covers
    /// its original manifest and EVERY declared object digest matched. Neither
    /// geometry alone nor an arbitrary later successful token supplies it.
    pub fn coverage<'q, 'c, 'd, W: Work>(
        &self,
        index: usize,
        checked: &ActorCheck<'c, 'd, 'v, 's, S>,
        work: &'q W,
    ) -> CoverageResult<'q, 'v, 's, S>
    where
        'v: 'q,
    {
        let query = self.archive.ltv_query(work);
        let execution = query.execution();
        self.archive
            .admit(execution, self.archive.directory_span())?;
        let Some(node) = self.nodes.get(index) else {
            return Ok(None);
        };
        if checked.input != node.member || Some(checked.token) != node.timestamp {
            return Err(ArchiveError::Foreign {
                range: self.archive.directory_span(),
            });
        }
        if !self.geometry_complete() {
            return Ok(None);
        }
        let Some(actor) = checked.actor.as_ref() else {
            return Ok(None);
        };
        let Some(facts) = node
            .facts
            .and_then(|index| self.facts[index].object_digests())
        else {
            return Ok(None);
        };
        if facts.is_empty() {
            return Ok(None);
        }
        for fact in facts {
            execution
                .charge_work(1)
                .map_err(|cause| resource(self.archive.directory_span(), cause))?;
            if *fact
                != crate::references::DigestReading::Checked(
                    structured_xades::certificate::Agreement::Matches,
                )
            {
                return Ok(None);
            }
        }
        if actor.verified().token().snapshot != query.snapshot() {
            return Err(ArchiveError::Foreign {
                range: self.archive.directory_span(),
            });
        }
        let mut items = execution.map();
        items
            .try_insert(SourceNode::Member(node.member.ordinal()), true)
            .map_err(|cause| resource(self.archive.directory_span(), cause))?;
        for member in node.objects().iter().flatten() {
            items
                .try_insert(SourceNode::Member(member.ordinal()), true)
                .map_err(|cause| resource(self.archive.directory_span(), cause))?;
        }
        Ok(Some(Coverage::for_token(
            ISSUER,
            query.snapshot(),
            actor.verified().signature(),
            SourceNode::Member(node.member.ordinal()),
            SourceNode::Member(checked.token.ordinal()),
            Purpose::Archive,
            items,
        )))
    }
}
