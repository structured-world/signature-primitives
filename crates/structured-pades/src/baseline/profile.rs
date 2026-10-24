//! Explicit current versus original-occurrence validation-data protection.

use super::{LongTermOf, Seal, Seals, SealsError};
use crate::{query::Query, range::RangeSource};
use structured_ltv::source::Query as _;

/// A requested source window, never a search for successful timestamp results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// One ordinal in the complete original document-timestamp census.
    AtSource(usize),
    /// The last written occurrence, including an unreadable or failed one.
    Current,
}

/// Closed format/static-cryptographic and material facts for one original
/// occurrence. Historical continuity, algorithm longevity, status usability
/// and application trust remain distinct from these profile requirements.
pub struct Assessment<'s, L, R, D, G> {
    long_term: Option<&'s L>,
    seals: &'s Seals<'s, R, D, G>,
    selection: Selection,
    ordinal: Option<usize>,
    revision: Option<usize>,
    long_term_complete: bool,
    material_covered: Option<bool>,
}
impl<'s, L, R, D, G> Assessment<'s, L, R, D, G> {
    /// Actual caller-selected projection; current never means last successful.
    #[must_use]
    pub fn selection(&self) -> Selection {
        self.selection
    }
    /// Exact original occurrence, absent only when no DTS exists.
    #[must_use]
    pub fn ordinal(&self) -> Option<usize> {
        self.ordinal
    }
    /// Source revision, absent for an unreadable or partial-range occurrence.
    #[must_use]
    pub fn revision(&self) -> Option<usize> {
        self.revision
    }
    /// Actual linked LT report, retaining all its negative findings.
    #[must_use]
    pub fn long_term(&self) -> Option<&'s L> {
        self.long_term
    }
    /// Complete original census, including earlier unsuccessful occurrences.
    #[must_use]
    pub fn seals(&self) -> &'s Seals<'s, R, D, G> {
        self.seals
    }
    /// Basic, all required TSA paths/static time and complete LT material hold.
    #[must_use]
    pub fn all_long_term_requirements_met(&self) -> bool {
        self.long_term_complete
    }
    /// Selected original input covers every preceding required material value;
    /// None is unassessed, false retains a completed negative material result.
    #[must_use]
    pub fn material_covered(&self) -> Option<bool> {
        self.material_covered
    }
    /// Closed B-LTA format/static-cryptographic/material requirements only.
    /// This is not historical `PoE` continuity, longevity or a trust verdict.
    #[must_use]
    pub fn all_profile_requirements_met(&self) -> bool {
        self.revision.is_some() && self.long_term_complete && self.material_covered == Some(true)
    }
}

/// A complete source-ordinal assessment with independently retained details.
pub type AssessmentOf<'s, 'a, 'cl, 'r, 'c, 'd, 'auth, 'v, C, D, G> = Assessment<
    's,
    LongTermOf<'s, 'a, 'cl, 'r, 'c, 'd, 'auth, C, D, G>,
    Seal<'a, 'cl, 'r, 'v, 'c, 'd, 'auth, D, G, C>,
    D,
    G,
>;

/// Joins closed same-source LT and preceding-material reports at an explicit
/// original DTS. EN319142-1 §6.3 Table1 and (w,x) require protection of the
/// complete preceding validation material, including every earlier TSA. An
/// early B-T DTS need not itself already provide the later LT service. All
/// occurrences remain in `seals`; no failed last occurrence is replaced.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
pub fn assess<'s, 'a, 'cl, 'r, 'c, 'd, 'auth, 'v, C, S: RangeSource>(
    selection: Selection,
    long_term: Option<
        &'s LongTermOf<'s, 'a, 'cl, 'r, 'c, 'd, 'auth, C, S::Document, S::Generation>,
    >,
    seals: &'s super::archives::SealsOf<
        's,
        'a,
        'cl,
        'r,
        'v,
        'c,
        'd,
        'auth,
        S::Document,
        S::Generation,
        C,
    >,
    query: &Query<'_, '_, S>,
) -> Result<
    AssessmentOf<'s, 'a, 'cl, 'r, 'c, 'd, 'auth, 'v, C, S::Document, S::Generation>,
    SealsError,
> {
    let root = seals.required.signature();
    query.admit(root, 1).map_err(SealsError::Scope)?;
    if !query.belongs(seals.session)
        || seals.required.scope().location().snapshot != query.snapshot()
    {
        return Err(SealsError::Foreign { node: root });
    }
    let ordinal = match selection {
        Selection::Current => seals.sources.len().checked_sub(1),
        Selection::AtSource(ordinal) => {
            if ordinal >= seals.sources.len() {
                return Err(SealsError::Foreign { node: root });
            }
            Some(ordinal)
        }
    };
    let revision = ordinal.and_then(|ordinal| seals.sources[ordinal].revision);
    let material_covered = ordinal.and_then(|ordinal| {
        seals.reports[ordinal].map(structured_ltv::baseline::ArchiveMaterial::all_material_covered)
    });
    let mut long_term_complete = false;
    if let Some(long_term) = long_term {
        let signature = long_term
            .timed()
            .basic()
            .binding()
            .prepared()
            .container
            .signature();
        let required = long_term.timed().paths().required();
        if !query.belongs(signature.owner().value.session)
            || required.signature() != root
            || required.scope().location().snapshot != query.snapshot()
        {
            return Err(SealsError::Foreign { node: root });
        }
        let (Some(revision), Some(ordinal)) = (revision, ordinal) else {
            return Err(SealsError::Foreign { node: root });
        };
        if long_term.x509().revision() != revision {
            return Err(SealsError::Foreign { node: root });
        }
        let prefix =
            seals.required.entries().len() - seals.sources.len() - seals.vri_revisions.len();
        let pdf_end = prefix + ordinal + 1;
        let vri_start = prefix + seals.sources.len();
        let mut cursor = 0;
        for (index, expected) in seals.required.entries().iter().enumerate() {
            query.admit(root, 5).map_err(SealsError::Scope)?;
            if index >= pdf_end
                && (index < vri_start || seals.vri_revisions[index - vri_start] > revision)
            {
                continue;
            }
            let Some(actual) = required.entries().get(cursor) else {
                return Err(SealsError::Foreign { node: root });
            };
            if actual.signature != expected.signature
                || actual.property != expected.property
                || actual.token != expected.token
                || actual.purpose != expected.purpose
            {
                return Err(SealsError::Foreign { node: root });
            }
            cursor += 1;
        }
        if cursor != required.entries().len() {
            return Err(SealsError::Foreign { node: root });
        }
        long_term_complete = long_term.timed().all_static_time_requirements_met()
            && long_term.all_material_requirements_met();
    }
    query.admit(root, 1).map_err(SealsError::Scope)?;
    Ok(Assessment {
        long_term,
        seals,
        selection,
        ordinal,
        revision,
        long_term_complete,
        material_covered,
    })
}
