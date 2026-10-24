//! Complete per-occurrence historical protection, without erasing early B-T.

use crate::{
    material::Placement,
    query::Query,
    range::RangeSource,
    timestamp::{Node, Pades, Requirements},
};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_ltv::{
    baseline::ArchiveMaterial,
    material::ParticipantMaterial,
    source::{Location, Query as _, ScopeError},
    timestamp::TimestampScope,
};

/// Both original material predicates under one exact document timestamp.
pub type Seal<'a, 'cl, 'r, 'v, 'c, 'd, 'auth, D, G, C> = ArchiveMaterial<
    'a,
    ParticipantMaterial<'cl, 'r, 'v, 'c, 'd, Node, D, G, Placement, Pades>,
    crate::material::credentials::Report<'auth, C, D, G>,
>;

/// Original-order optional material receipts for the complete DTS census.
pub type SealReports<'s, 'a, 'cl, 'r, 'v, 'c, 'd, 'auth, D, G, C> =
    &'s [Option<&'s Seal<'a, 'cl, 'r, 'v, 'c, 'd, 'auth, D, G, C>>];

/// Concrete source-bound `PAdES` document-timestamp material census.
pub type SealsOf<'s, 'a, 'cl, 'r, 'v, 'c, 'd, 'auth, D, G, C> =
    Seals<'s, Seal<'a, 'cl, 'r, 'v, 'c, 'd, 'auth, D, G, C>, D, G>;

/// Every original document timestamp in source order. An absent report is an
/// explicitly unassessed occurrence, not successful absence of a timestamp.
/// Early signature-existence timestamps need not already carry LT material;
/// no aggregate here relabels them as failed LTA renewals or hides their facts.
pub struct Seals<'s, R, D, G> {
    pub(super) sources: OwnedVec<Occurrence<D, G>>,
    pub(super) reports: &'s [Option<&'s R>],
    pub(super) required: &'s structured_ltv::timestamp::TimestampRequirements<Node, D, G, Pades>,
    pub(super) session: &'s crate::Session,
    pub(super) vri_revisions: OwnedVec<usize>,
}
pub(super) struct Occurrence<D, G> {
    pub(super) location: Location<Node, D, G>,
    pub(super) revision: Option<usize>,
}
impl<'s, R, D: Copy, G: Copy> Seals<'s, R, D, G> {
    /// Complete original count, including unassessed and failed occurrences.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }
    /// Actual absence of document timestamp occurrences.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
    /// Exact original token location, with an explicit missing-Contents node.
    #[must_use]
    pub fn source(&self, ordinal: usize) -> Option<Location<Node, D, G>> {
        self.sources.get(ordinal).map(|source| source.location)
    }
    /// Exact whole-revision coverage, absent for an unreadable/partial source.
    #[must_use]
    pub fn revision(&self, ordinal: usize) -> Option<usize> {
        self.sources.get(ordinal).and_then(|source| source.revision)
    }
    /// Original paired material report at this ordinal. Its negative findings
    /// remain available independently of another occurrence's successful seal.
    #[must_use]
    pub fn report(&self, ordinal: usize) -> Option<&'s R> {
        self.reports.get(ordinal).copied().flatten()
    }
}

/// Source/current refusal versus a substituted or incomplete source census.
#[derive(Debug)]
pub enum Error {
    /// Report count or actual source/root/scope was substituted.
    Foreign {
        /// Original selecting root or timestamp.
        node: Node,
    },
    /// Original source changed or its current operation refused.
    Scope(ScopeError<Node>),
    /// Original report metadata storage refused before copying.
    Resource {
        /// Actual original root.
        node: Node,
        /// Original capacity/work cause.
        cause: MemoryError,
    },
}

/// Join one slot for EVERY original PDF DTS with its exact common material
/// receipt. No trust, chronology, algorithm-longevity or successful-suffix
/// inference occurs. EN319142-1 §§6.3(w,x) and EN319102-1 §5.6.3 keep historic
/// input obligations distinct from the signature-existence service of B-T.
pub fn seals<'s, 'a, 'cl, 'r, 'v, 'c, 'd, 'auth, C, S: RangeSource>(
    required: &'s Requirements<'_, '_, S::Document, S::Generation>,
    reports: SealReports<'s, 'a, 'cl, 'r, 'v, 'c, 'd, 'auth, S::Document, S::Generation, C>,
    query: &Query<'_, '_, S>,
) -> Result<SealsOf<'s, 'a, 'cl, 'r, 'v, 'c, 'd, 'auth, S::Document, S::Generation, C>, Error> {
    let root = required.all().signature();
    query.admit(root, 1).map_err(Error::Scope)?;
    if !query.belongs(required.signature().owner().value.session)
        || required.revision().is_some()
        || reports.len() != required.document_timestamps().len()
    {
        return Err(Error::Foreign { node: root });
    }
    let mut sources = query.execution().vector();
    sources
        .try_reserve_exact(reports.len())
        .map_err(|cause| Error::Resource { node: root, cause })?;
    for (source, report) in required.document_timestamps().iter().zip(reports) {
        query.admit(root, 1).map_err(Error::Scope)?;
        let node = source.token();
        if let Some(report) = report {
            let actual = report.x509().inputs().requirements();
            if actual.signature() != root
                || !matches!(actual.scope(), TimestampScope::BeforeArchive(location)
                if location.snapshot == query.snapshot() && location.node == node)
            {
                return Err(Error::Foreign { node });
            }
        }
        let revision = source
            .signature()
            .and_then(|signature| match signature.coverage() {
                crate::signature::Coverage::Revision(revision) => Some(revision),
                crate::signature::Coverage::Partial => None,
            });
        sources
            .try_push(Occurrence {
                location: Location {
                    snapshot: query.snapshot(),
                    node,
                },
                revision,
            })
            .map_err(|cause| Error::Resource { node, cause })?;
    }
    query.admit(root, 1).map_err(Error::Scope)?;
    let mut vri_revisions = query.execution().vector();
    for source in required.vri_timestamps() {
        query.admit(root, 1).map_err(Error::Scope)?;
        vri_revisions
            .try_push(source.revision)
            .map_err(|cause| Error::Resource { node: root, cause })?;
    }
    Ok(Seals {
        sources: sources.into_owned(),
        reports,
        required: required.all(),
        session: required.signature().owner().value.session,
        vri_revisions: vri_revisions.into_owned(),
    })
}
