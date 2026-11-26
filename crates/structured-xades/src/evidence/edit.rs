//! Authorize one checked transition of an unpublished sealing draft.

use super::{Format, Records, Verified};
use crate::produce::{self, Emit, Transaction};
use crate::xml::{Access, AccessError, Snapshot, Xml};
use structured_asn1::memory::{MemoryError, Work};

/// Only these original group transitions are permitted after sealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edit {
    /// Append a new property sealing all previous groups.
    Serial(Format),
    /// Append a record within the last existing sealing property.
    Parallel(Format),
    /// Extend a verified member of the last existing sealing property.
    Renew(Renewal),
}

/// Distinct RFC 4998 and RFC 6283 renewal transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Renewal {
    /// Add the next timestamp to the last chain using its digest algorithm.
    Timestamp,
    /// Add the first timestamp of a new chain and bind the prior sequence.
    HashTree,
}

/// Exact original location at which the owner stages this operation.
#[derive(Debug, Clone, Copy)]
pub enum Placement<N> {
    /// Append the whole new property, under this existing parent if present.
    Serial(Option<N>),
    /// Append one parallel member to this original group.
    Parallel(N),
    /// Renew this exact original record within the last group.
    Renew(N, Renewal),
}

/// The old and new source identities the owner's transaction must compare.
#[derive(Debug, Clone, Copy)]
pub struct Transition<N, D, G> {
    /// The original immutable base of this operation.
    pub base: Snapshot<D, G>,
    /// Original selected signature.
    pub original_signature: N,
    /// Only the particular selected edit and source placement may differ.
    pub placement: Placement<N>,
    /// Original last sealing group, when any existed in the base. A serial
    /// append takes the required validation material from this group's tails.
    pub preceding_group: Option<N>,
    /// Actual staged generation, including the new/renewed evidence record.
    pub staged: Snapshot<D, G>,
    /// Exact selected signature in the draft.
    pub staged_signature: N,
    /// Exact member in the draft verified by the shared ERS kernel.
    pub staged_member: N,
    /// Whether the owner must close every original signed component before
    /// the signature receives its first seal.
    pub first_seal: bool,
}

/// XML owner's check that a specific unpublished transaction has applied only
/// the supported mutation. This extends the existing source/generation guard
/// used for ordinary `XAdES` drafts, without permitting a validated copy of a
/// different signature to stand in for this one.
pub trait SealingDraft: Xml {
    /// Check the original bounded delta. All sealed XML/object inputs, previous
    /// members and original chain prefixes must remain intact except for the
    /// precisely scoped material below. All such edits preserve token math.
    /// Apply ETSI TS 119 132-3 §5.1.2 to the actual old and staged inputs. For
    /// the first seal, close the original signed components' material. For a
    /// serial append, close all last timestamps in the preceding property.
    /// For a renewal, close only the original last token of that member.
    /// Presence elsewhere must be established from actual values and scoped
    /// occurrences. All material required by the new timestamp must be part
    /// of its protected input where the standard asks for it. Admission
    /// covers comparisons and preserves the original accounts.
    fn check_sealing_transition<W: Work>(
        &self,
        transition: Transition<Self::Id, Self::Document, Self::Generation>,
        work: &W,
    ) -> Result<bool, Self::Error>;
}

/// Open unpublished transaction at the original position required by a sealing
/// plan. For binary renewal the position replaces the old member atomically;
/// XML renewal inserts at the original last chain or sequence as appropriate.
pub trait SealingWriter: Transaction {
    /// Exact base placement represented by this writer.
    fn sealing_placement(&self) -> Placement<Self::Id>;
}

/// Typed refusal before staging or before authorizing publication of a draft.
#[derive(Debug)]
pub enum EditError<E, N> {
    /// Actual source, generation, callback or execution refusal.
    Access(AccessError<E, N>),
    /// The edit does not follow the previous record's format or scope.
    Placement(N),
    /// The supplied complete proof does not name the result of the edit.
    Foreign(N),
    /// The staged record did not extend the expected census or chain.
    Shape(N),
    /// The draft changed something outside the permitted edit.
    Changed(N),
    /// Original Work refused during source identity or shape processing.
    Resource(N, MemoryError),
}

/// Construction result in this XML owner's identity and cause types.
pub type EditResult<T, X> = Result<T, EditError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Edit plan using the XML owner's identity types.
pub type PlanFor<X> = EditPlan<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Source-bound staging instruction. Only verification of the actual staged
/// record and the XML owner's exact delta can authorize the final commit.
pub struct EditPlan<N, D, G> {
    base: Snapshot<D, G>,
    signature: N,
    placement: Placement<N>,
    preceding_group: Option<N>,
    format: Format,
    group: usize,
    groups: usize,
    member: usize,
    members: usize,
    renewal: Option<(usize, usize)>,
    pub(super) xml_order: Option<i32>,
}

impl<X: Xml> Records<'_, X> {
    /// Plan a new or renewed seal under the original authenticated scope.
    /// A renewal requires a positive receipt for the exact member it will
    /// extend. Serial and parallel installation need only the current census.
    pub fn edit<W: Work>(
        &self,
        access: &Access<'_, X, W>,
        edit: Edit,
        prior: Option<&Verified<X::Id, X::Document, X::Generation>>,
    ) -> EditResult<PlanFor<X>, X> {
        let base = self.snapshot();
        let signature = self.signature();
        if base != access.snapshot() {
            return Err(EditError::Foreign(signature));
        }
        access
            .query(signature, |_, _, _| Ok(()))
            .map_err(EditError::Access)?;
        let groups = self.groups.len();
        let members = self.members.len();
        let increment = |count: usize| {
            count
                .checked_add(1)
                .ok_or(EditError::Resource(signature, MemoryError::WorkExceeded))
        };
        let selected = |format| {
            if self.format().is_some_and(|old| old != format) {
                return Err(EditError::Placement(signature));
            }
            Ok(format)
        };
        let mut xml_order = None;
        let (placement, format, group, groups, member, members, renewal) = match edit {
            Edit::Serial(format) if prior.is_none() => (
                Placement::Serial(self.parent),
                selected(format)?,
                groups,
                increment(groups)?,
                members,
                increment(members)?,
                None,
            ),
            Edit::Parallel(format) if prior.is_none() => {
                let tail = self.groups.last().ok_or(EditError::Placement(signature))?;
                (
                    Placement::Parallel(tail.node),
                    selected(format)?,
                    groups - 1,
                    groups,
                    members,
                    increment(members)?,
                    None,
                )
            }
            Edit::Renew(kind) => {
                let prior = prior.ok_or(EditError::Placement(signature))?;
                let format = self.format().ok_or(EditError::Placement(signature))?;
                let original = self
                    .members
                    .get(prior.index)
                    .ok_or(EditError::Foreign(signature))?;
                if original.group + 1 != groups
                    || !matches_original(self, access, prior, original.node)?
                {
                    return Err(EditError::Foreign(original.node));
                }
                if let Some((chain, stamp)) = prior.xml_tail {
                    let last = match kind {
                        Renewal::HashTree => chain,
                        Renewal::Timestamp => stamp,
                    };
                    xml_order = Some(last.checked_add(1).ok_or(EditError::Shape(original.node))?);
                }
                let chains = if kind == Renewal::HashTree {
                    increment(prior.chains)?
                } else {
                    prior.chains
                };
                let shape = (chains, increment(prior.stamps)?);
                (
                    Placement::Renew(original.node, kind),
                    format,
                    original.group,
                    groups,
                    prior.index,
                    members,
                    Some(shape),
                )
            }
            _ => return Err(EditError::Placement(signature)),
        };
        Ok(EditPlan {
            base,
            signature,
            placement,
            preceding_group: self.groups.last().map(super::Group::node),
            format,
            group,
            groups,
            member,
            members,
            renewal,
            xml_order,
        })
    }

    /// Whether the owner can stage ordinary unsigned-property modifications.
    /// Post-seal construction must instead use a source-bound [`EditPlan`].
    #[must_use]
    pub fn ordinary_edits_allowed(&self) -> bool {
        self.groups.is_empty()
    }
}

impl<N: Copy, D: Copy, G: Copy> EditPlan<N, D, G> {
    /// Exact location at which to create the unpublished staged change.
    #[must_use]
    pub fn placement(&self) -> Placement<N> {
        self.placement
    }

    /// Required wire format of the resulting record.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }

    /// Expected ordinal of the record to verify in the staged signature.
    #[must_use]
    pub fn member_index(&self) -> usize {
        self.member
    }
}

impl<N, D, G> EditPlan<N, D, G>
where
    N: Copy + Eq + structured_asn1::memory::HashWork,
    D: Copy + Eq,
    G: Copy + Eq,
{
    /// Stage one complete RFC 4998 payload at the checked base placement.
    /// The actual staged payload and delta must pass [`Self::authorize_commit`].
    pub fn write_asn1<B, W>(
        &self,
        writer: &mut B,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), produce::Error<B::Error>>
    where
        B: SealingWriter<Id = N, Document = D, Generation = G>,
        W: Work,
    {
        if self.format != Format::Asn1 || bytes.is_empty() {
            return Err(produce::Error::Value("ASN1EvidenceRecord"));
        }
        let mut emit = self.start(writer, work)?;
        emit.binary(super::ASN_MEMBER.namespace, super::ASN_MEMBER.local, bytes)?;
        self.finish(&mut emit)
    }

    pub(super) fn start<'a, B, W>(
        &self,
        writer: &'a mut B,
        work: &'a W,
    ) -> Result<Emit<'a, B, W>, produce::Error<B::Error>>
    where
        B: SealingWriter<Id = N, Document = D, Generation = G>,
        W: Work,
    {
        let resource = produce::Error::Resource;
        if writer.base() != self.base
            || !structured_ltv::source::equal_id(writer.signature(), self.signature, work)
                .map_err(resource)?
            || !same_placement(self.placement, writer.sealing_placement(), work)
                .map_err(resource)?
        {
            return Err(produce::Error::Foreign);
        }
        let mut emit = Emit { writer, work };
        if matches!(self.placement, Placement::Serial(_)) {
            emit.begin(super::PROPERTY.namespace, super::PROPERTY.local)?;
        }
        Ok(emit)
    }

    pub(super) fn finish<B, W>(
        &self,
        emit: &mut Emit<'_, B, W>,
    ) -> Result<(), produce::Error<B::Error>>
    where
        B: SealingWriter<Id = N, Document = D, Generation = G>,
        W: Work,
    {
        if matches!(self.placement, Placement::Serial(_)) {
            emit.end()?;
        }
        let resource = produce::Error::Resource;
        if emit.writer.base() != self.base
            || !structured_ltv::source::equal_id(emit.writer.signature(), self.signature, emit.work)
                .map_err(resource)?
            || !same_placement(self.placement, emit.writer.sealing_placement(), emit.work)
                .map_err(resource)?
        {
            return Err(produce::Error::Foreign);
        }
        Ok(())
    }

    /// Verify that the authorized operation is present in this actual draft
    /// before the XML owner commits it. The proof names original staged bytes.
    /// A wrong generation, changed prefix or unrelated re-sealing is refused.
    pub fn authorize_commit<X, W: Work>(
        &self,
        access: &Access<'_, X, W>,
        staged: &Records<'_, X>,
        proof: &Verified<N, D, G>,
    ) -> EditResult<(), X>
    where
        X: SealingDraft<Id = N, Document = D, Generation = G>,
    {
        let signature = staged.signature();
        let snapshot = staged.snapshot();
        let member = staged
            .members
            .get(self.member)
            .ok_or(EditError::Shape(signature))?;
        if snapshot.document != self.base.document
            || snapshot == self.base
            || snapshot != access.snapshot()
            || self.member != proof.index
            || !matches_original(staged, access, proof, member.node)?
        {
            return Err(EditError::Foreign(member.node));
        }
        if staged.format() != Some(self.format)
            || staged.members.len() != self.members
            || staged.groups.len() != self.groups
            || member.group != self.group
            || self
                .renewal
                .is_some_and(|shape| shape != (proof.chains, proof.stamps))
            || self
                .xml_order
                .is_some_and(|order| match (self.placement, proof.xml_tail) {
                    (Placement::Renew(_, Renewal::HashTree), Some((chain, 1))) => chain != order,
                    (Placement::Renew(_, Renewal::Timestamp), Some((_, stamp))) => stamp != order,
                    _ => true,
                })
        {
            return Err(EditError::Shape(member.node));
        }
        let transition = Transition {
            base: self.base,
            original_signature: self.signature,
            placement: self.placement,
            preceding_group: self.preceding_group,
            staged: snapshot,
            staged_signature: signature,
            staged_member: member.node,
            first_seal: self.group == 0
                && self.groups == 1
                && self.member == 0
                && self.members == 1
                && matches!(self.placement, Placement::Serial(_)),
        };
        if !access
            .query(member.node, |xml, _, work| {
                xml.check_sealing_transition(transition, work)
            })
            .map_err(EditError::Access)?
        {
            return Err(EditError::Changed(member.node));
        }
        Ok(())
    }
}

fn same_placement<N: Copy + Eq + structured_asn1::memory::HashWork, W: Work>(
    expected: Placement<N>,
    actual: Placement<N>,
    work: &W,
) -> Result<bool, MemoryError> {
    match (expected, actual) {
        (Placement::Serial(left), Placement::Serial(right)) => {
            produce::same_parent(left, right, work)
        }
        (Placement::Parallel(left), Placement::Parallel(right)) => {
            structured_ltv::source::equal_id(left, right, work)
        }
        (Placement::Renew(left, kind), Placement::Renew(right, actual)) if kind == actual => {
            structured_ltv::source::equal_id(left, right, work)
        }
        _ => Ok(false),
    }
}

fn matches_original<X: Xml, W: Work>(
    records: &Records<'_, X>,
    access: &Access<'_, X, W>,
    proof: &Verified<X::Id, X::Document, X::Generation>,
    node: X::Id,
) -> EditResult<bool, X> {
    let resource = |cause| EditError::Resource(node, cause);
    Ok(proof.location.snapshot == records.snapshot()
        && access
            .equal_id(proof.signature, records.signature())
            .map_err(resource)?
        && access
            .equal_id(proof.location.node, node)
            .map_err(resource)?)
}
