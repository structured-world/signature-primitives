//! Complete original time-assertion census for one protected archive input.

use super::{ArchiveError, Graph, MemberId, Role, resource};
use crate::layout::{Form, Inspection, Principal};
use structured_asn1::{
    memory::{Execution, OwnedMap, OwnedVec, Work},
    range::RangeSource,
};
use structured_ltv::timestamp::Purpose;

type SourceResult<T, S> = Result<T, ArchiveError<<S as RangeSource>::Error>>;
type Associations<S> =
    OwnedMap<usize, InputAssociation<<S as RangeSource>::Document, <S as RangeSource>::Generation>>;
type MemberOf<S> = MemberId<<S as RangeSource>::Document, <S as RangeSource>::Generation>;

/// Actual membership in this original manifest's input, independently of time
/// claims, digest agreement or trusted chronology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionScope {
    /// This timestamp file is declared as a whole protected input object.
    Declared,
    /// This is the token that protects the selected manifest, not an earlier TSA.
    Current,
    /// The complete input does not declare this original timestamp occurrence.
    Outside,
    /// Missing/broken graph prevents a complete original membership claim.
    Unavailable,
}
/// Original source-derived input association, not a selected successful check.
#[derive(Debug, Clone, Copy)]
pub enum InputAssociation<D, G> {
    /// Exactly one original manifest or explicit simple-container data input.
    Known {
        /// Actual original input member.
        member: MemberId<D, G>,
        /// Selected input role, independently of mathematical evidence.
        purpose: Purpose,
    },
    /// No original source establishes this assertion's input.
    Missing,
    /// Several original source declarations select this same token.
    Ambiguous,
}
/// Every original timestamp file remains represented, including unavailable and
/// out-of-scope occurrences. Later success cannot erase an earlier obligation.
#[derive(Debug, Clone, Copy)]
pub struct AssertionInput<D, G> {
    /// Actual original token member, not its filename after successful checking.
    pub token: MemberId<D, G>,
    /// This current protected input's factual membership selection.
    pub scope: AssertionScope,
    /// Original input association, retaining missing/ambiguous sources.
    pub association: InputAssociation<D, G>,
}
/// Full original assertion-source census. Complete input geometry and known
/// associations do not prove token mathematics, historical trust or material.
pub struct TimestampInputs<D, G> {
    entries: OwnedVec<AssertionInput<D, G>>,
    complete: bool,
}
impl<D, G> TimestampInputs<D, G> {
    /// Every original token occurrence, in central-directory order.
    #[must_use]
    pub fn entries(&self) -> &[AssertionInput<D, G>] {
        &self.entries
    }
    /// All declared original assertions have a unique source-defined input.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.complete
    }
}
impl<'v, 's, N: Copy, D: Copy + Eq, G: Copy + Eq, S: RangeSource> Graph<'v, 's, N, D, G, S> {
    fn input_associations(
        &self,
        layout: &Inspection<'_, 'v, 's, S>,
        execution: &Execution<'_>,
    ) -> SourceResult<Associations<S>, S> {
        let refusal = |cause| resource(self.archive.directory_span(), cause);
        let mut associations = execution.map();
        for fact in &self.facts {
            execution.charge_work(1).map_err(refusal)?;
            let catalogue = fact.catalogue();
            let Some(token) = catalogue.signature_member(execution)? else {
                continue;
            };
            let role = layout
                .census()
                .occurrence(token.id().ordinal(), execution)?
                .map(|(_, role)| role);
            if role != Some(Role::Timestamp) {
                continue;
            }
            let source = catalogue.base();
            let purpose = match layout
                .census()
                .occurrence(source.id().ordinal(), execution)?
                .map(|(_, role)| role)
            {
                Some(Role::ArchiveManifest) => Purpose::Archive,
                Some(Role::Manifest) => Purpose::Content,
                _ => continue,
            };
            if associations
                .try_insert(
                    token.id().ordinal(),
                    InputAssociation::Known {
                        member: source.id(),
                        purpose,
                    },
                )
                .map_err(refusal)?
                .is_some()
            {
                associations
                    .try_insert(token.id().ordinal(), InputAssociation::Ambiguous)
                    .map_err(refusal)?;
            }
        }
        Ok(associations.into_owned())
    }
    fn simple_data(
        layout: &Inspection<'_, 'v, 's, S>,
        execution: &Execution<'_>,
    ) -> SourceResult<Option<MemberOf<S>>, S> {
        if layout.form() != Form::Simple(Principal::Timestamp) {
            return Ok(None);
        }
        let mut simple = None;
        for ordinal in 0..layout.census().len() {
            let Some((member, role)) = layout.census().occurrence(ordinal, execution)? else {
                continue;
            };
            if role != Role::Data {
                continue;
            }
            if simple.is_some() {
                return Ok(None);
            }
            simple = Some(member.id());
        }
        Ok(simple)
    }
    /// Includes ordinary manifest assertions as well as archive-manifest
    /// renewals. The simple timestamp's implied input is admitted only under
    /// the explicitly selected S-timestamp form and its one actual data file.
    pub fn timestamp_inputs<W: Work>(
        &self,
        index: usize,
        layout: &Inspection<'_, 'v, 's, S>,
        work: &W,
    ) -> SourceResult<TimestampInputs<S::Document, S::Generation>, S> {
        if !core::ptr::eq(layout.census().archive(), self.archive) {
            return Err(ArchiveError::Foreign {
                range: self.archive.directory_span(),
            });
        }
        let execution = self.archive.session().query(work);
        self.archive
            .admit(&execution, self.archive.directory_span())?;
        let refusal = |cause| resource(self.archive.directory_span(), cause);
        let current = self.nodes.get(index).ok_or(ArchiveError::Foreign {
            range: self.archive.directory_span(),
        })?;
        let associations = self.input_associations(layout, &execution)?;
        let mut declared = execution.map();
        for member in current.objects().iter().flatten() {
            declared.try_insert(member.ordinal(), ()).map_err(refusal)?;
        }
        let simple = Self::simple_data(layout, &execution)?;
        let geometry = self.geometry_complete();
        let mut complete = geometry;
        let mut entries = execution.vector();
        for ordinal in 0..layout.census().len() {
            let Some((member, role)) = layout.census().occurrence(ordinal, &execution)? else {
                continue;
            };
            if role != Role::Timestamp {
                continue;
            }
            let mut association = match associations.get(&ordinal, &execution).map_err(refusal)? {
                Some(value) => *value,
                None => InputAssociation::Missing,
            };
            if let Some(data) = simple
                && matches!(association, InputAssociation::Missing)
            {
                execution
                    .charge_work(member.name().len() as u64)
                    .map_err(refusal)?;
                if member.name() == b"META-INF/timestamp.tst" {
                    association = InputAssociation::Known {
                        member: data,
                        purpose: Purpose::Content,
                    };
                }
            }
            let scope = if current.timestamp == Some(member.id()) {
                AssertionScope::Current
            } else if !geometry {
                AssertionScope::Unavailable
            } else if declared
                .get(&ordinal, &execution)
                .map_err(refusal)?
                .is_some()
            {
                AssertionScope::Declared
            } else {
                AssertionScope::Outside
            };
            if scope == AssertionScope::Declared
                && !matches!(association, InputAssociation::Known { .. })
            {
                complete = false;
            }
            entries
                .try_push(AssertionInput {
                    token: member.id(),
                    scope,
                    association,
                })
                .map_err(refusal)?;
        }
        self.archive
            .admit(&execution, self.archive.directory_span())?;
        Ok(TimestampInputs {
            entries: entries.into_owned(),
            complete,
        })
    }
}
