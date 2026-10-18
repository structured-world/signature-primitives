//! Join every participant's material under one original archive's coverage.

use crate::{
    material::{self, Placement},
    xml::{Access, Xml},
};
use structured_asn1::memory::{MemoryError, Work};
use structured_ltv::material::ParticipantMaterial;
use structured_ltv::pki::ParticipantError;
use structured_ltv::source::Query;
use structured_ltv::timestamp::TimestampScope;

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

type X509<'a, 'r, 'v, 'c, 'd, X> = ParticipantMaterial<
    'a,
    'r,
    'v,
    'c,
    'd,
    <X as Xml>::Id,
    <X as Xml>::Document,
    <X as Xml>::Generation,
    Placement<<X as Xml>::Id>,
>;
type Credentials<'a, 'p, 'd, A, X> = material::credentials::Report<
    'a,
    'p,
    'd,
    A,
    <X as Xml>::Id,
    <X as Xml>::Document,
    <X as Xml>::Generation,
>;
/// Source, scope or input-receipt refusal, not a missing-material finding.
pub type ArchiveMaterialResult<'a, M, C, X> =
    Result<ArchiveMaterial<'a, M, C>, ParticipantError<<X as Xml>::Id>>;

/// Combine both original material reports for one exact preceding-archive
/// scope. The X.509 report already establishes the original element coverage
/// and mathematical token binding; the format report must use that SAME scope
/// and actual authenticated credential input. Neither source work nor provider
/// interpretation is replayed; the fresh metadata query is still admitted.
///
/// EN319132-1 V1.3.1 §6.3(aa) requires all validation data before generation of
/// each archive; final-document availability cannot repair an earlier input.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn archive_material<'s, 'a, 'r, 'v, 'c, 'd, 'au, 'p, A, X: Xml, W: Work>(
    x509: &'s X509<'a, 'r, 'v, 'c, 'd, X>,
    credentials: &'s Credentials<'au, 'p, 'd, A, X>,
    access: &Access<'_, X, W>,
) -> ArchiveMaterialResult<'s, X509<'a, 'r, 'v, 'c, 'd, X>, Credentials<'au, 'p, 'd, A, X>, X> {
    let required = x509.inputs().requirements();
    let scope = required.scope();
    let original = scope.location();
    let supplied = credentials.scope();
    let foreign = || ParticipantError::Foreign {
        signature: required.signature(),
    };
    if !matches!(scope, TimestampScope::BeforeArchive(_))
        || !matches!(supplied, TimestampScope::BeforeArchive(_))
        || original.snapshot != access.snapshot()
        || supplied.location().snapshot != original.snapshot
        || credentials.snapshot() != original.snapshot
    {
        return Err(foreign());
    }
    // One dispatch plus the paid identity metadata pass.
    Query::admit(access, original.node, 2)?;
    if !required.same_credentials(credentials.credentials())
        || !access
            .equal_id(original.node, supplied.location().node)
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
/// original preparation determines the census; a supplied successful subset
/// cannot create it. Historical authority/path contexts remain on each report,
/// since they need not be identical at different original archive times.
pub struct Archives<'a, P, R> {
    prepared: &'a P,
    reports: &'a [&'a R],
    covered: bool,
}

impl<P, R> Archives<'_, P, R> {
    /// Same selected original preparation, including requested profile.
    #[must_use]
    pub fn prepared(&self) -> &P {
        self.prepared
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
#[derive(Debug)]
pub enum ArchiveCensusError<E, N> {
    /// The supplied preparation/report belongs to a different source or root.
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
    Access(crate::xml::AccessError<E, N>),
    /// Admission refused before metadata traversal or identity comparison.
    Resource {
        /// Original selecting signature/archive.
        node: N,
        /// Actual work/storage refusal.
        cause: MemoryError,
    },
}

type Proof<'a, 'cl, 'r, 'v, 'c, 'd, 'au, 'p, A, X> =
    ArchiveMaterial<'a, X509<'cl, 'r, 'v, 'c, 'd, X>, Credentials<'au, 'p, 'd, A, X>>;
/// Complete original root-archive material census or a typed processing refusal.
pub type ArchivesResult<'a, P, R, X> =
    Result<Archives<'a, P, R>, ArchiveCensusError<<X as Xml>::Error, <X as Xml>::Id>>;

/// Require one paired report for EACH original root archive, not only archives
/// whose material happened to succeed. Counter timestamps retain their separate
/// whole-signature TSA obligations; this does not impose root baseline properties
/// on a plain `XMLDSig` countersignature. No crypto, source acquisition, artifact
/// lookup, allocation or report copy occurs in this current-query census.
pub fn archives<'s, 'a, 'cl, 'r, 'v, 'c, 'd, 'au, 'p, A, X: Xml, W: Work>(
    prepared: &'s crate::prepare::Prepared<X>,
    reports: &'s [&'s Proof<'a, 'cl, 'r, 'v, 'c, 'd, 'au, 'p, A, X>],
    access: &Access<'_, X, W>,
) -> ArchivesResult<'s, crate::prepare::Prepared<X>, Proof<'a, 'cl, 'r, 'v, 'c, 'd, 'au, 'p, A, X>, X>
{
    let layout = prepared.bound().containers();
    let signature = layout.signature();
    if layout.snapshot() != access.snapshot() {
        return Err(ArchiveCensusError::Foreign { node: signature });
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(ArchiveCensusError::Access)?;
    let mut cursor = 0;
    let mut covered = true;
    for stamp in prepared.timestamps() {
        let node = stamp.node();
        let resource = |cause| ArchiveCensusError::Resource { node, cause };
        access.execution().charge_work(1).map_err(resource)?;
        if stamp.role() != crate::timestamp::Role::Archive {
            continue;
        }
        let Some(report) = reports.get(cursor) else {
            return Err(ArchiveCensusError::Missing { property: node });
        };
        let required = report.x509.inputs().requirements();
        let location = required.scope().location();
        if location.snapshot != access.snapshot()
            || !access
                .equal_id(required.signature(), signature)
                .map_err(resource)?
            || !access.equal_id(location.node, node).map_err(resource)?
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
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(ArchiveCensusError::Access)?;
    Ok(Archives {
        prepared,
        reports,
        covered,
    })
}
