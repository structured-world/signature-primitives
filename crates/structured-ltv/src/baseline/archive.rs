//! Join every participant's material under one original archive's coverage.

use super::{ArchiveCensus, CredentialMaterial};
use crate::material::ParticipantMaterial;
use crate::pki::ParticipantError;
use crate::source::{Query, ScopeError};
use crate::timestamp::TimestampScope;
use structured_asn1::memory::{MemoryError, Work};

/// Original X.509 and credential-format material checked BEFORE the SAME
/// archive. Construction requires the same authenticated credential census,
/// not equivalent node IDs or separately selected authority contexts.
///
/// This proves only the combined incorporation/coverage predicates. Each
/// archive's own TSA path/status, chronology, renewal, longevity and caller
/// trust remain separate facts; this is not an unconditional B-LTA verdict.
pub struct ArchiveMaterial<'a, M, C> {
    x509: &'a M,
    credentials: &'a C,
    covered: bool,
}

impl<M, C> ArchiveMaterial<'_, M, C> {
    /// Complete original actor/status-authority material and all coverage gaps.
    #[must_use]
    pub fn x509(&self) -> &M {
        self.x509
    }
    /// Every actual credential's original format-material result and gaps.
    #[must_use]
    pub fn credentials(&self) -> &C {
        self.credentials
    }
    /// All required material has an original copy inside THIS archive input.
    /// A later copy or an unsupported format cannot satisfy this predicate.
    #[must_use]
    pub fn all_material_covered(&self) -> bool {
        self.covered
    }
}

type X509<'a, 'r, 'v, 'c, 'd, P, Q, I> = ParticipantMaterial<
    'a,
    'r,
    'v,
    'c,
    'd,
    <Q as Query>::Id,
    <Q as Query>::Document,
    <Q as Query>::Generation,
    P,
    I,
>;

/// Source, scope or input-receipt refusal, not a missing-material finding.
pub type ArchiveMaterialResult<'a, M, C, N> =
    Result<ArchiveMaterial<'a, M, C>, ParticipantError<N>>;

/// Combine both original material reports for one exact preceding-archive
/// scope. The X.509 report already establishes the original coverage and
/// mathematical token binding; the format report must use that SAME scope and
/// actual authenticated credential input. Neither source work nor provider
/// interpretation is replayed; the fresh metadata query is still admitted.
///
/// EN319132-1 V1.3.1 §6.3(aa) requires all validation data before generation of
/// each archive; final-document availability cannot repair an earlier input.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn archive_material<'s, 'a, 'r, 'v, 'c, 'd, P, C, Q, I>(
    x509: &'s X509<'a, 'r, 'v, 'c, 'd, P, Q, I>,
    credentials: &'s C,
    query: &Q,
) -> ArchiveMaterialResult<'s, X509<'a, 'r, 'v, 'c, 'd, P, Q, I>, C, Q::Id>
where
    C: CredentialMaterial<Id = Q::Id, Document = Q::Document, Generation = Q::Generation>,
    Q: Query,
{
    let required = x509.inputs().requirements();
    let scope = required.scope();
    let original = scope.location();
    let supplied = credentials.scope();
    let foreign = || ParticipantError::Foreign {
        signature: required.signature(),
    };
    if !matches!(scope, TimestampScope::BeforeArchive(_))
        || !matches!(supplied, TimestampScope::BeforeArchive(_))
        || original.snapshot != query.snapshot()
        || supplied.location().snapshot != original.snapshot
        || credentials.snapshot() != original.snapshot
    {
        return Err(foreign());
    }
    // One dispatch plus the paid identity metadata pass.
    query.admit(original.node, 2)?;
    if !required.same_credentials(credentials.credentials())
        || !query
            .equal(original.node, supplied.location().node)
            .map_err(|cause| ParticipantError::Resource {
                node: original.node,
                cause,
            })?
    {
        return Err(foreign());
    }
    Ok(ArchiveMaterial {
        x509,
        credentials,
        covered: x509.all_x509_artifacts_covered() && credentials.all_requirements_met(),
    })
}

/// Every original root archive's paired material facts in source order. The
/// original timestamp census determines the set; a supplied successful subset
/// cannot create it. Historical authority/path contexts remain on each report,
/// since they need not be identical at different original archive times.
pub struct Archives<'a, P, R> {
    census: &'a P,
    reports: &'a [&'a R],
    covered: bool,
}

impl<P, R> Archives<'_, P, R> {
    /// Same original timestamp census.
    #[must_use]
    pub fn census(&self) -> &P {
        self.census
    }
    /// Every actual root archive once, preserving all its detailed gaps.
    #[must_use]
    pub fn reports(&self) -> &[&R] {
        self.reports
    }
    /// At least one root archive exists and all its required material is
    /// covered. This alone asserts neither complete B-LTA nor historical trust.
    #[must_use]
    pub fn all_archive_material_covered(&self) -> bool {
        self.covered
    }
}

/// Original processing/admission failure, never a failed document digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveCensusError<N> {
    /// The supplied census/report belongs to a different source or root.
    Foreign {
        /// Original expected signature/archive.
        node: N,
    },
    /// An actual original archive has no corresponding complete material report.
    Missing {
        /// Original unassessed archive property.
        property: N,
    },
    /// Extra/duplicate supplied reports do not belong to this exact census.
    Extra,
    /// Original source/current query failure.
    Scope(ScopeError<N>),
    /// Admission refused before metadata traversal or identity comparison.
    Resource {
        /// Original selecting signature/archive.
        node: N,
        /// Actual work/storage refusal.
        cause: MemoryError,
    },
}

/// Complete original root-archive material census or a typed processing refusal.
pub type ArchivesResult<'a, P, R, N> = Result<Archives<'a, P, R>, ArchiveCensusError<N>>;

type Proof<'a, 'cl, 'r, 'v, 'c, 'd, P, C, Q, I> =
    ArchiveMaterial<'a, X509<'cl, 'r, 'v, 'c, 'd, P, Q, I>, C>;

/// Require one paired report for EACH original root archive, not only archives
/// whose material happened to succeed. Counter timestamps retain their separate
/// whole-signature TSA obligations; this does not impose root baseline properties
/// on a countersignature. No crypto, source acquisition, artifact lookup,
/// allocation or report copy occurs in this current-query census.
pub fn archives<'s, 'a, 'cl, 'r, 'v, 'c, 'd, A, P, C, Q, I>(
    census: &'s A,
    reports: &'s [&'s Proof<'a, 'cl, 'r, 'v, 'c, 'd, P, C, Q, I>],
    query: &Q,
) -> ArchivesResult<'s, A, Proof<'a, 'cl, 'r, 'v, 'c, 'd, P, C, Q, I>, Q::Id>
where
    A: ArchiveCensus<Id = Q::Id, Document = Q::Document, Generation = Q::Generation>,
    Q: Query,
{
    let selected = census.signature();
    let signature = selected.node;
    if selected.snapshot != query.snapshot() {
        return Err(ArchiveCensusError::Foreign { node: signature });
    }
    query
        .admit(signature, 1)
        .map_err(ArchiveCensusError::Scope)?;
    let mut cursor = 0;
    let mut covered = true;
    for ordinal in 0..census.timestamps() {
        query
            .execution()
            .charge_work(1)
            .map_err(|cause| ArchiveCensusError::Resource {
                node: signature,
                cause,
            })?;
        let Some(node) = census.archive(ordinal) else {
            continue;
        };
        let resource = |cause| ArchiveCensusError::Resource { node, cause };
        let Some(report) = reports.get(cursor) else {
            return Err(ArchiveCensusError::Missing { property: node });
        };
        let required = report.x509.inputs().requirements();
        let location = required.scope().location();
        if location.snapshot != query.snapshot()
            || !query
                .equal(required.signature(), signature)
                .map_err(resource)?
            || !query.equal(location.node, node).map_err(resource)?
        {
            return Err(ArchiveCensusError::Foreign { node });
        }
        if !report.covered {
            covered = false;
        }
        cursor += 1;
    }
    if cursor != reports.len() {
        return Err(ArchiveCensusError::Extra);
    }
    if cursor == 0 {
        covered = false;
    }
    query
        .admit(signature, 1)
        .map_err(ArchiveCensusError::Scope)?;
    Ok(Archives {
        census,
        reports,
        covered,
    })
}
