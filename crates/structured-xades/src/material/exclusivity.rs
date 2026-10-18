//! Exclusive CA material in ordinary CertificateValues/RevocationValues.

use super::{Index, Occurrence, Placement};
use crate::Xades;
use crate::xml::{Access, Snapshot, Xml};
use core::fmt;
use structured_asn1::memory::{MemoryError, OwnedMap, OwnedVec, Work};
use structured_ltv::material::{ArtifactRef, ArtifactUses, IndexError};
use structured_ltv::pki::Uses;
use structured_ltv::timestamp::TimestampScope;
use structured_pkix::{Certificate, Version};

/// Result for one ordinary-container occurrence of actually used material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExclusiveFindingKind {
    /// A CA certificate/status value is exclusively for credentials or TSAs.
    ForbiddenCa,
    /// An old certificate supplies no CA classification. This cannot establish
    /// that an exclusive value is allowed or that it violates the prohibition.
    UnstatedCa,
}

/// One original occurrence and the certificate whose CA fact matters. For a
/// CRL/OCSP value this is its actual target, not its authentication signer.
pub struct ExclusiveFinding<'certificate, 'document, N, D, G> {
    artifact: ArtifactRef<'certificate, 'document>,
    certificate: &'certificate Certificate<'document>,
    occurrence: Occurrence<N, D, G>,
    kind: ExclusiveFindingKind,
}

impl<'certificate, 'document, N: Copy, D: Copy, G: Copy>
    ExclusiveFinding<'certificate, 'document, N, D, G>
{
    /// Exact original certificate/whole CRL/basic-response identity.
    #[must_use]
    pub fn artifact(&self) -> ArtifactRef<'certificate, 'document> {
        self.artifact
    }
    /// Original subject certificate, preserving its own PKIX source coordinates.
    #[must_use]
    pub fn certificate(&self) -> &'certificate Certificate<'document> {
        self.certificate
    }
    /// Original offending/indeterminate ordinary-container copy.
    #[must_use]
    pub fn occurrence(&self) -> Occurrence<N, D, G> {
        self.occurrence
    }
    /// Prohibition versus insufficient CA evidence, never a resource fallback.
    #[must_use]
    pub fn kind(&self) -> ExclusiveFindingKind {
        self.kind
    }
}

/// Checks ONLY EN319132-1 §§5.4.2(5)/5.4.3(4) on actually used X.509 material.
/// Empty findings do not prove other presence/placement, usable status, unknown
/// credential-format data, timestamp coverage, chronology or a baseline grade.
pub struct ExclusivePlacement<'certificate, 'document, N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    findings: OwnedVec<ExclusiveFinding<'certificate, 'document, N, D, G>>,
}

impl<'certificate, 'document, N: Copy, D: Copy, G: Copy>
    ExclusivePlacement<'certificate, 'document, N, D, G>
{
    /// Same immutable source generation used for the complete actor census.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original selected signature, not any signature in the document.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Every relevant ordinary copy, in artifact/occurrence order. Unstated CA
    /// facts remain explicit rather than disappearing as successful absence.
    #[must_use]
    pub fn findings(&self) -> &[ExclusiveFinding<'certificate, 'document, N, D, G>] {
        &self.findings
    }
}

/// Source/current-operation and PKIX errors are terminal, not findings.
pub enum ExclusivityError<'certificate, 'document, N> {
    /// Whole-signature requirements are needed; a preceding-archive subset
    /// cannot classify all original incorporated material.
    Scope {
        /// Actual enclosing scope node.
        node: N,
    },
    /// Original index/generation or current execution refusal.
    Index(IndexError<N>),
    /// Current traversal, cache or retained report capacity was not admitted.
    Resource {
        /// Original enclosing selected signature.
        node: N,
        /// Original admission cause.
        cause: MemoryError,
    },
    /// Original certificate query failed; offsets stay in THAT certificate's
    /// binary source, not fabricated XML coordinates. Includes resource and
    /// processing causes such as `ForeignReader` without converting them to No.
    Certificate {
        /// Actual original subject whose CA query refused.
        certificate: &'certificate Certificate<'document>,
        /// Unchanged shared PKIX error.
        cause: structured_pkix::Error,
    },
}

impl<N: fmt::Debug> fmt::Debug for ExclusivityError<'_, '_, N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scope { node } => formatter.debug_struct("Scope").field("node", node).finish(),
            Self::Index(cause) => formatter.debug_tuple("Index").field(cause).finish(),
            Self::Resource { node, cause } => formatter
                .debug_struct("Resource")
                .field("node", node)
                .field("cause", cause)
                .finish(),
            // The original certificate is available programmatically; diagnostic
            // formatting must not traverse/dump its untrusted parsed catalogues.
            Self::Certificate { cause, .. } => formatter
                .debug_struct("Certificate")
                .field("cause", cause)
                .finish_non_exhaustive(),
        }
    }
}

/// Result using this owner's unchanged XML/source identities and causes.
pub type ExclusivityResult<'certificate, 'document, X> = Result<
    ExclusivePlacement<
        'certificate,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    ExclusivityError<'certificate, 'document, <X as Xml>::Id>,
>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaFact {
    Asserted,
    NotAsserted,
    Unstated,
}

pub(crate) enum CaError<'certificate, 'document> {
    Resource(MemoryError),
    Certificate(&'certificate Certificate<'document>, structured_pkix::Error),
}

impl fmt::Debug for CaError<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource(cause) => formatter.debug_tuple("Resource").field(cause).finish(),
            Self::Certificate(_, cause) => formatter
                .debug_struct("Certificate")
                .field("cause", cause)
                .finish_non_exhaustive(),
        }
    }
}

fn exclusive(uses: Uses) -> bool {
    if uses.signature() {
        return false;
    }
    uses.credential() || uses.timestamp()
}

// Annex A.1.1 forbids exclusively credential CA references. Unlike the
// ordinary value-container rule, TSA-only and shared credential/TSA uses are
// not forbidden here. Keep the two normative predicates distinct.
// https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
fn exclusive_credential(uses: Uses) -> bool {
    uses.credential() && !uses.signature() && !uses.timestamp()
}

fn certificate_ca<W: Work>(
    certificate: &Certificate<'_>,
    work: &W,
) -> Result<CaFact, structured_pkix::Error> {
    let basic = certificate.tbs().extensions().basic_constraints(work)?;
    // RFC5280 4.2.1.9 defines cA/default FALSE and absent BC in V3.
    // 6.1.4(k) requires out-of-band CA evidence for V1/V2: absence alone
    // cannot establish that an old certificate is not a CA.
    // https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
    // https://www.rfc-editor.org/rfc/rfc5280#section-6.1.4
    Ok(match basic {
        Some(basic) if basic.is_authority() => CaFact::Asserted,
        Some(_) => CaFact::NotAsserted,
        None if certificate.tbs().version() == Version::V3 => CaFact::NotAsserted,
        None => CaFact::Unstated,
    })
}

pub(crate) struct ReferenceCa<'certificate, 'document> {
    pub(crate) certificate: &'certificate Certificate<'document>,
    pub(crate) fact: CaFact,
}

pub(crate) struct ReferenceStatus<'certificate, 'document> {
    pub(crate) artifact: ArtifactRef<'certificate, 'document>,
    pub(crate) certificate: &'certificate Certificate<'document>,
    pub(crate) fact: CaFact,
}

pub(crate) fn reference_status_candidates<'certificate, 'document, N, D, G, I, W: Work>(
    artifacts: &ArtifactUses<'_, '_, '_, 'certificate, 'document, N, D, G, I>,
    work: &W,
) -> Result<OwnedVec<ReferenceStatus<'certificate, 'document>, W>, CaError<'certificate, 'document>>
{
    let mut candidates = work.vector();
    let mut scan = CaScan {
        artifacts,
        cache: work.map(),
        work,
    };
    for (ordinal, entry) in artifacts.entries().iter().enumerate() {
        work.charge_work(1)?;
        if !exclusive_credential(entry.uses())
            || matches!(entry.artifact(), ArtifactRef::Certificate(_))
        {
            continue;
        }
        // Annex A.1.2(5) concerns the revocation TARGET CA, not the
        // authentication signer. The same target/cache kernel serves values.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
        if let Some((fact, target)) = scan.witness(ordinal, exclusive_credential)? {
            candidates.try_push(ReferenceStatus {
                artifact: entry.artifact(),
                certificate: scan.certificate(target),
                fact,
            })?;
        }
    }
    Ok(candidates)
}

pub(crate) fn reference_certificate_candidates<'certificate, 'document, N, D, G, I, W: Work>(
    artifacts: &ArtifactUses<'_, '_, '_, 'certificate, 'document, N, D, G, I>,
    work: &W,
) -> Result<OwnedVec<ReferenceCa<'certificate, 'document>, W>, CaError<'certificate, 'document>> {
    let mut candidates = work.vector();
    for entry in artifacts.entries() {
        work.charge_work(1)?;
        if !exclusive_credential(entry.uses()) {
            continue;
        }
        let ArtifactRef::Certificate(certificate) = entry.artifact() else {
            continue;
        };
        let fact = certificate_ca(certificate, work)
            .map_err(|cause| CaError::Certificate(certificate, cause))?;
        if fact != CaFact::NotAsserted {
            candidates.try_push(ReferenceCa { certificate, fact })?;
        }
    }
    Ok(candidates)
}

impl From<MemoryError> for CaError<'_, '_> {
    fn from(cause: MemoryError) -> Self {
        Self::Resource(cause)
    }
}

// The artifact census a CA scan reads, by artifact ordinal.
trait Census<'certificate, 'document> {
    fn artifact(&self, ordinal: usize) -> ArtifactRef<'certificate, 'document>;
    fn uses(&self, ordinal: usize) -> Uses;
    fn targets(&self, ordinal: usize) -> impl Iterator<Item = usize>;
}

impl<'certificate, 'document, N, D, G, I> Census<'certificate, 'document>
    for ArtifactUses<'_, '_, '_, 'certificate, 'document, N, D, G, I>
{
    fn artifact(&self, ordinal: usize) -> ArtifactRef<'certificate, 'document> {
        self.entries()[ordinal].artifact()
    }
    fn uses(&self, ordinal: usize) -> Uses {
        self.entries()[ordinal].uses()
    }
    fn targets(&self, ordinal: usize) -> impl Iterator<Item = usize> {
        ArtifactUses::targets(self, ordinal)
    }
}

struct CaScan<'query, C, W: Work> {
    artifacts: &'query C,
    cache: OwnedMap<usize, CaFact, W>,
    work: &'query W,
}

impl<'certificate, 'document, C: Census<'certificate, 'document>, W: Work> CaScan<'_, C, W> {
    fn certificate(&self, index: usize) -> &'certificate Certificate<'document> {
        let ArtifactRef::Certificate(certificate) = self.artifacts.artifact(index) else {
            unreachable!("a status target is an admitted certificate ordinal")
        };
        certificate
    }

    fn class(&mut self, index: usize) -> Result<CaFact, CaError<'certificate, 'document>> {
        self.work.charge_work(1)?;
        if let Some(&fact) = self.cache.get(&index, self.work)? {
            return Ok(fact);
        }
        let certificate = self.certificate(index);
        let fact = certificate_ca(certificate, self.work)
            .map_err(|cause| CaError::Certificate(certificate, cause))?;
        self.cache.try_insert(index, fact)?;
        Ok(fact)
    }

    fn witness(
        &mut self,
        index: usize,
        accepts: impl Fn(Uses) -> bool,
    ) -> Result<Option<(CaFact, usize)>, CaError<'certificate, 'document>> {
        if matches!(self.artifacts.artifact(index), ArtifactRef::Certificate(_)) {
            return match self.class(index)? {
                CaFact::NotAsserted => Ok(None),
                fact => Ok(Some((fact, index))),
            };
        }
        let mut unstated = None;
        let artifacts = self.artifacts;
        for certificate in artifacts.targets(index) {
            self.work.charge_work(1)?;
            let uses = artifacts.uses(certificate);
            if !accepts(uses) {
                continue;
            }
            match self.class(certificate)? {
                CaFact::Asserted => return Ok(Some((CaFact::Asserted, certificate))),
                CaFact::Unstated => unstated = Some((CaFact::Unstated, certificate)),
                CaFact::NotAsserted => {}
            }
        }
        Ok(unstated)
    }
}

/// Enforce the two explicit CA exclusivity prohibitions after ALL actor uses
/// have been unioned by exact original artifact identity. Shared ordinary use
/// prevents an artifact being called exclusive to credentials/TSAs. EE values
/// and other containers are not covered by these prohibitions; duplicate
/// avoidance SHOULDs are not converted into extra bans. Embedded OCSP signer
/// certificates are not standalone `CertificateValues` children.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
///
/// Queries use current Work and the existing lazy PKIX decoder/provenance;
/// scratch classifications are cached once per original certificate. A late
/// refusal drops the entire report. This is a component check, not a level.
///
/// # Panics
/// Only for a violated private census invariant: certificate/linked-target
/// ordinals are recorded before publication and the catalogue is immutable.
pub fn exclusivity<'certificate, 'document, X: Xml, W: Work, Q: Work>(
    artifacts: &ArtifactUses<
        '_,
        '_,
        '_,
        'certificate,
        'document,
        X::Id,
        X::Document,
        X::Generation,
        Xades,
    >,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    access: &Access<'_, X, Q>,
) -> ExclusivityResult<'certificate, 'document, X> {
    let required = artifacts.inputs().requirements();
    let scope = required.scope();
    if !matches!(scope, TimestampScope::All(_)) || scope.location().snapshot != access.snapshot() {
        return Err(ExclusivityError::Scope {
            node: scope.location().node,
        });
    }
    let signature = required.signature();
    index
        .require_signature(signature, access)
        .map_err(ExclusivityError::Index)?;
    let work = access.execution();
    let resource = |cause| ExclusivityError::Resource {
        node: signature,
        cause,
    };
    let mut findings = work.vector();
    let mut scan = CaScan {
        artifacts,
        cache: work.map(),
        work,
    };
    for (ordinal, entry) in artifacts.entries().iter().enumerate() {
        work.charge_work(1).map_err(resource)?;
        let uses = entry.uses();
        if !exclusive(uses) {
            continue;
        }
        let mut classified = false;
        let mut witness = None;
        for copy in index
            .artifact(entry.artifact(), access)
            .map_err(ExclusivityError::Index)?
        {
            let copy = copy.map_err(ExclusivityError::Index)?;
            if !matches!(copy.placement(), Placement::Signature(_))
                || copy.embedded_certificate().is_some()
            {
                continue;
            }
            if !classified {
                witness = scan
                    .witness(ordinal, exclusive)
                    .map_err(|cause| match cause {
                        CaError::Resource(cause) => resource(cause),
                        CaError::Certificate(certificate, cause) => {
                            ExclusivityError::Certificate { certificate, cause }
                        }
                    })?;
                classified = true;
            }
            if let Some((fact, certificate)) = witness {
                let kind = match fact {
                    CaFact::Asserted => ExclusiveFindingKind::ForbiddenCa,
                    CaFact::Unstated => ExclusiveFindingKind::UnstatedCa,
                    CaFact::NotAsserted => unreachable!("non-CA produces no witness"),
                };
                findings
                    .try_push(ExclusiveFinding {
                        artifact: entry.artifact(),
                        certificate: scan.certificate(certificate),
                        occurrence: copy,
                        kind,
                    })
                    .map_err(resource)?;
            }
        }
    }
    Ok(ExclusivePlacement {
        snapshot: access.snapshot(),
        signature,
        findings: findings.into_owned(),
    })
}

#[cfg(test)]
mod tests;
