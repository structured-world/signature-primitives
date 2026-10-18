//! Original status artifacts derived from common authenticated evidence.

use super::{ArchiveError, Archived, ArtifactRef, Coverage, Index, IndexError, PathCertificates};
use crate::pki::{AuthorityClosure, CrlReading, MemberStatus, PathStatuses};
use crate::source::{Location, Query, ScopeError};
use crate::timestamp::Verified;
use structured_asn1::memory::{HashWork, MemoryError, OwnedVec, Work};
use structured_pkix::{crl, ocsp};

/// Archive-material census for every path actually reached through the selected
/// actor/status-authority inputs. This proves artifact availability only; it
/// preserves every original status/time/authority fact without accepting it.
pub struct AuthorityMaterial<'closure, 'view, 'certificate, 'document, N, D, G, P> {
    inputs: &'closure AuthorityClosure<'view, 'certificate, 'document>,
    paths: OwnedVec<PathMaterial<'view, 'certificate, 'document, N, D, G, P>>,
    all_covered: bool,
}

impl<'closure, 'view, 'certificate, 'document, N, D, G, P>
    AuthorityMaterial<'closure, 'view, 'certificate, 'document, N, D, G, P>
{
    /// Complete original root/authority input closure, not a selected subset.
    #[must_use]
    pub fn inputs(&self) -> &'closure AuthorityClosure<'view, 'certificate, 'document> {
        self.inputs
    }
    /// Material for every reached path, preserving the same closure order.
    #[must_use]
    pub fn paths(&self) -> &[PathMaterial<'view, 'certificate, 'document, N, D, G, P>] {
        &self.paths
    }
    /// Whether all actually required original artifacts precede this archive.
    /// Status acceptance, all actor roots and historical trust remain separate.
    #[must_use]
    pub fn all_artifacts_covered(&self) -> bool {
        self.all_covered
    }
}

/// Census every path/status/authority artifact actually required by this input
/// closure under the SAME original archive input. Reuses `archived_path`, its
/// source index and complete/delta/whole-OCSP rules. No provider is repeated and
/// an allocation/work/source refusal drops every partial material report.
pub fn archived_authorities<'closure, 'view, 'certificate, 'document, N, D, G, P, O, W, Q, C, I>(
    inputs: &'closure AuthorityClosure<'view, 'certificate, 'document>,
    index: &Index<'_, N, D, G, P, O, W, I>,
    coverage: &Coverage<N, D, G, C, I>,
    evidence: &Verified<N, D, G, I>,
    query: &Q,
) -> Result<AuthorityMaterial<'closure, 'view, 'certificate, 'document, N, D, G, P>, ArchiveError<N>>
where
    N: Copy + Eq + HashWork,
    D: Copy + Eq,
    G: Copy + Eq,
    P: Copy,
    W: Work,
    C: Work,
    Q: Query<Id = N, Document = D, Generation = G>,
{
    let signature = evidence.signature();
    let resource = |cause| ArchiveError::Index(IndexError::Resource { signature, cause });
    let scope = |cause| ArchiveError::Index(IndexError::Scope(cause));
    query.admit(signature, 1).map_err(scope)?;
    let mut paths = query.execution().vector();
    paths
        .try_reserve_exact(inputs.nodes().len())
        .map_err(resource)?;
    let mut all_covered = true;
    for node in inputs.nodes() {
        query.admit(signature, 2).map_err(scope)?;
        let material = archived_path(node.statuses, index, coverage, evidence, query)?;
        if !material.all_artifacts_covered() {
            all_covered = false;
        }
        paths.try_push(material).map_err(resource)?;
    }
    Ok(AuthorityMaterial {
        inputs,
        paths: paths.into_owned(),
        all_covered,
    })
}

/// Complete certificate/status artifact census for the SAME actual path and
/// original evaluation inputs. This is one actor's contribution to an archive;
/// other actors, status acceptance and historical trust remain separate.
pub struct PathMaterial<'view, 'certificate, 'document, N, D, G, P> {
    inputs: &'view PathStatuses<'view, 'certificate, 'document>,
    certificates: PathCertificates<'view, 'document, N, D, G, P>,
    statuses: OwnedVec<StatusMaterial<'view, 'certificate, 'document, N, D, G, P>>,
    all_covered: bool,
}

impl<'view, 'certificate, 'document, N, D, G, P>
    PathMaterial<'view, 'certificate, 'document, N, D, G, P>
{
    /// Original complete per-member input census; no caller-written actor count.
    #[must_use]
    pub fn inputs(&self) -> &'view PathStatuses<'view, 'certificate, 'document> {
        self.inputs
    }
    /// Same actual checked-path certificate set, including its existing anchor.
    #[must_use]
    pub fn certificates(&self) -> &PathCertificates<'view, 'document, N, D, G, P> {
        &self.certificates
    }
    /// Original contributing status sources/signers for members requiring a
    /// status lookup. The original input census separately retains a validated
    /// responder noCheck exemption; it never manufactures an OCSP Good result.
    #[must_use]
    pub fn statuses(&self) -> &[StatusMaterial<'view, 'certificate, 'document, N, D, G, P>] {
        &self.statuses
    }
    /// Whether all these exact inputs have covered original copies. This is
    /// neither a Good assertion nor completeness for counters/credentials/TSAs.
    #[must_use]
    pub fn all_artifacts_covered(&self) -> bool {
        self.all_covered
    }
}

/// Derive archive obligations from a complete original path-status census.
/// Reuses the same exact-source index and archive coverage for certificates and
/// all complete/delta/OCSP contributors. No signature/hash check is repeated,
/// and refusal drops the accumulated reports rather than returning a subset.
pub fn archived_path<'view, 'certificate, 'document, N, D, G, P, O, W, Q, C, I>(
    inputs: &'view PathStatuses<'view, 'certificate, 'document>,
    index: &Index<'_, N, D, G, P, O, W, I>,
    coverage: &Coverage<N, D, G, C, I>,
    evidence: &Verified<N, D, G, I>,
    query: &Q,
) -> Result<PathMaterial<'view, 'certificate, 'document, N, D, G, P>, ArchiveError<N>>
where
    N: Copy + Eq + HashWork,
    D: Copy + Eq,
    G: Copy + Eq,
    P: Copy,
    W: Work,
    C: Work,
    Q: Query<Id = N, Document = D, Generation = G>,
{
    let certificates = index.archived_path(inputs.path(), coverage, evidence, query)?;
    let mut all_covered = certificates.all_certificates_covered();
    let signature = evidence.signature();
    let resource = |cause| ArchiveError::Index(IndexError::Resource { signature, cause });
    let scope = |cause| ArchiveError::Index(IndexError::Scope(cause));
    query.admit(signature, 1).map_err(scope)?;
    let mut statuses = query.execution().vector();
    let mut count = 0;
    for input in inputs.entries() {
        query.admit(signature, 2).map_err(scope)?;
        if !matches!(input, MemberStatus::ResponderNoCheck(_)) {
            count += 1;
        }
    }
    statuses.try_reserve_exact(count).map_err(resource)?;
    for input in inputs.entries() {
        query.admit(signature, 2).map_err(scope)?;
        let Some(source) = member_source(input) else {
            continue;
        };
        let status = archived(source, index, coverage, evidence, query)?;
        if !status.all_artifacts_covered() {
            all_covered = false;
        }
        statuses.try_push(status).map_err(resource)?;
    }
    Ok(PathMaterial {
        inputs,
        certificates,
        statuses: statuses.into_owned(),
        all_covered,
    })
}

/// Actual common status evidence, not a caller-written Good assertion.
#[derive(Clone, Copy)]
pub enum StatusSource<'view, 'certificate, 'document> {
    /// Qualified reason union. Each contributing complete/delta source stays
    /// visible; partial reasons alone still do not establish all-reason absence.
    Crl(&'view crl::Coverage<'certificate, 'document>),
    /// Original complete/delta facts whose entry/window may be negative. This
    /// retains actual sources without constructing an absence assertion.
    CrlReading(CrlReading<'view, 'certificate, 'document>),
    /// Common issuer/request/time result. Its original status may be Good,
    /// Unknown or Revoked; incorporation does not change that status.
    Ocsp(&'view ocsp::BoundEvidence<'certificate, 'document, 'certificate, 'document>),
}

/// The status source of one member's status input; `None` for a validated
/// responder noCheck exemption, whose responder certificate stays in the path.
/// One mapping serves archive material and every format's placement checks.
#[must_use]
pub fn member_source<'view, 'certificate, 'document>(
    input: &'view MemberStatus<'view, 'certificate, 'document>,
) -> Option<StatusSource<'view, 'certificate, 'document>> {
    match input {
        MemberStatus::Crl(bound) => Some(StatusSource::Crl(bound.coverage())),
        MemberStatus::CrlReading(bound) => Some(StatusSource::CrlReading(bound.reading())),
        MemberStatus::Ocsp(bound) => Some(StatusSource::Ocsp(bound.evidence())),
        MemberStatus::ResponderNoCheck(_) => None,
    }
}

impl<'certificate, 'document> StatusSource<'_, 'certificate, 'document> {
    /// Actual original target processed by this same common status result.
    #[must_use]
    pub fn target(self) -> &'certificate structured_pkix::Certificate<'document> {
        match self {
            Self::Crl(qualified) => qualified.target(),
            Self::CrlReading(reading) => reading.target(),
            Self::Ocsp(qualified) => qualified.target(),
        }
    }
    /// Exact label used by the original common status processing.
    #[must_use]
    pub fn evaluated_at(self) -> structured_pkix::temporal::Reading {
        match self {
            Self::Crl(qualified) => qualified.evaluated_at(),
            Self::CrlReading(reading) => reading.evaluated_at(),
            Self::Ocsp(qualified) => qualified.evaluated_at(),
        }
    }
}

/// Role of one original artifact in common status evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusPart {
    /// Authenticated whole complete CRL, also required for a delta source.
    CompleteCrl,
    /// Authenticated whole updating delta CRL; never a replacement for the base.
    DeltaCrl,
    /// Whole successful OCSP envelope containing the exact basic response.
    OcspResponse,
    /// Actual CRL/OCSP signer certificate from the same authentication receipt.
    SigningCertificate,
}

/// One required source artifact; ordinals address the retained evidence below.
#[derive(Debug)]
pub struct ArchivedStatus<N, D, G, P> {
    /// Contributing CRL reason-source ordinal, or zero for one OCSP response.
    pub source: usize,
    /// Exact artifact role, not inferred from how many values were carried.
    pub part: StatusPart,
    /// Mathematical availability under this particular archive input.
    pub availability: Archived<N, D, G, P>,
}

/// Complete artifact census for exactly one borrowed common status result.
/// Status usability, actor/path association and additional delegated-responder
/// checking remain explicit; this is not an attained baseline-level receipt.
pub struct StatusMaterial<'view, 'certificate, 'document, N, D, G, P> {
    source: StatusSource<'view, 'certificate, 'document>,
    archive: Location<N, D, G>,
    entries: OwnedVec<ArchivedStatus<N, D, G, P>>,
    all_covered: bool,
}

impl<'view, 'certificate, 'document, N: Copy, D: Copy, G: Copy, P>
    StatusMaterial<'view, 'certificate, 'document, N, D, G, P>
{
    /// Same original common result; another target/status cannot replace it.
    #[must_use]
    pub fn source(&self) -> StatusSource<'view, 'certificate, 'document> {
        self.source
    }
    /// Original archive token whose mathematical input was checked.
    #[must_use]
    pub fn archive(&self) -> Location<N, D, G> {
        self.archive
    }
    /// Every original status source and actual signer, including missing copies.
    #[must_use]
    pub fn entries(&self) -> &[ArchivedStatus<N, D, G, P>] {
        &self.entries
    }
    /// Whether all these exact artifacts have covered copies. This does not
    /// mean every path member has status, nor that an OCSP status is Good.
    #[must_use]
    pub fn all_artifacts_covered(&self) -> bool {
        self.all_covered
    }
}

/// Checks original status artifacts without reconstructing a CRL or OCSP value.
///
/// EN319132-1 V1.3.1 §§5.4.3/5.5.2.2/6.3(aa) require the full set used for
/// validation before each archive. For a delta this includes both whole lists;
/// RFC5940 §3 requires the whole `OCSPResponse` envelope. Actual source/key
/// authentication, applicability and temporal facts come from the shared PKIX
/// result, never from a count or a fresh private status parser here.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
/// <https://www.rfc-editor.org/rfc/rfc5940#section-3>
pub fn archived<'view, 'certificate, 'document, N, D, G, P, O, W, Q, C, I>(
    source: StatusSource<'view, 'certificate, 'document>,
    index: &Index<'_, N, D, G, P, O, W, I>,
    coverage: &Coverage<N, D, G, C, I>,
    evidence: &Verified<N, D, G, I>,
    query: &Q,
) -> Result<StatusMaterial<'view, 'certificate, 'document, N, D, G, P>, ArchiveError<N>>
where
    N: Copy + Eq + HashWork,
    D: Copy + Eq,
    G: Copy + Eq,
    P: Copy,
    W: Work,
    C: Work,
    Q: Query<Id = N, Document = D, Generation = G>,
{
    let signature = evidence.signature();
    query
        .admit(signature, 1)
        .map_err(|cause| ArchiveError::Index(IndexError::Scope(cause)))?;
    let mut entries = query.execution().vector();
    let mut all_covered = true;
    let mut record = |artifact, ordinal, part| {
        let availability = index.archived(artifact, coverage, evidence, query)?;
        if !matches!(availability, Archived::Present(_)) {
            all_covered = false;
        }
        entries
            .try_push(ArchivedStatus {
                source: ordinal,
                part,
                availability,
            })
            .map_err(|cause| ArchiveError::Index(IndexError::Resource { signature, cause }))
    };
    visit_artifacts(source, signature, query, &mut record).map_err(|cause| match cause {
        ArtifactVisitError::Scope(cause) => ArchiveError::Index(IndexError::Scope(cause)),
        ArtifactVisitError::Visitor(cause) => cause,
    })?;
    Ok(StatusMaterial {
        source,
        archive: evidence.token(),
        entries: entries.into_owned(),
        all_covered,
    })
}

fn record_crl<'certificate, 'document, E>(
    source: &crl::EvidenceSource<'certificate, 'document>,
    ordinal: usize,
    mut record: impl FnMut(ArtifactRef<'certificate, 'document>, usize, StatusPart) -> Result<(), E>,
) -> Result<(), E> {
    match source {
        crl::EvidenceSource::Complete(complete) => {
            record(
                ArtifactRef::Crl(complete.crl()),
                ordinal,
                StatusPart::CompleteCrl,
            )?;
            record(
                ArtifactRef::Certificate(complete.issuer()),
                ordinal,
                StatusPart::SigningCertificate,
            )?;
        }
        crl::EvidenceSource::Delta { base, delta } => {
            record(
                ArtifactRef::Crl(base.crl()),
                ordinal,
                StatusPart::CompleteCrl,
            )?;
            record(ArtifactRef::Crl(delta.crl()), ordinal, StatusPart::DeltaCrl)?;
            record(
                ArtifactRef::Certificate(base.issuer()),
                ordinal,
                StatusPart::SigningCertificate,
            )?;
            record(
                ArtifactRef::Certificate(delta.issuer()),
                ordinal,
                StatusPart::SigningCertificate,
            )?;
        }
    }
    Ok(())
}

/// A source refusal while enumerating status artifacts, or the visitor's own.
#[derive(Debug)]
pub enum ArtifactVisitError<V, N> {
    /// Source generation or current operation refused.
    Scope(ScopeError<N>),
    /// The visitor's unchanged cause.
    Visitor(V),
}

/// Enumerates every original complete/delta/OCSP source and actual
/// authentication signer of one status result, each step admitted under the
/// current query. Archive availability and every format's placement check
/// share this one walk; a visitor failure keeps its cause.
pub fn visit_artifacts<'certificate, 'document, Q: Query, V>(
    source: StatusSource<'_, 'certificate, 'document>,
    signature: Q::Id,
    query: &Q,
    mut record: impl FnMut(ArtifactRef<'certificate, 'document>, usize, StatusPart) -> Result<(), V>,
) -> Result<(), ArtifactVisitError<V, Q::Id>> {
    let pay = || query.admit(signature, 2).map_err(ArtifactVisitError::Scope);
    let record = |artifact, ordinal, part| {
        record(artifact, ordinal, part).map_err(ArtifactVisitError::Visitor)
    };
    walk_artifacts(source, pay, record)
}

/// The same walk when the enclosing operation has already checked the source
/// and needs only current admission.
pub fn visit_artifacts_in<'c, 'd, W: Work>(
    source: StatusSource<'_, 'c, 'd>,
    work: &W,
    record: impl FnMut(ArtifactRef<'c, 'd>, usize, StatusPart) -> Result<(), MemoryError>,
) -> Result<(), MemoryError> {
    walk_artifacts(source, || work.charge_work(1), record)
}

fn walk_artifacts<'c, 'd, E>(
    source: StatusSource<'_, 'c, 'd>,
    mut pay: impl FnMut() -> Result<(), E>,
    mut record: impl FnMut(ArtifactRef<'c, 'd>, usize, StatusPart) -> Result<(), E>,
) -> Result<(), E> {
    match source {
        StatusSource::Crl(qualified) => {
            for (ordinal, entry) in qualified.sources().iter().enumerate() {
                pay()?;
                record_crl(&entry.source(), ordinal, &mut record)?;
            }
        }
        StatusSource::CrlReading(reading) => {
            pay()?;
            record_crl(&reading.source(), 0, &mut record)?;
        }
        StatusSource::Ocsp(qualified) => {
            pay()?;
            let signed = qualified.evidence().source().signed();
            record(
                ArtifactRef::Ocsp(signed.response()),
                0,
                StatusPart::OcspResponse,
            )?;
            record(
                ArtifactRef::Certificate(signed.signer()),
                0,
                StatusPart::SigningCertificate,
            )?;
        }
    }
    Ok(())
}
