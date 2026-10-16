//! Exclusive CA material in ordinary CertificateValues/RevocationValues.

use super::uses::{ArtifactUse, StatusTarget};
use super::{ArtifactRef, ArtifactUses, Index, IndexError, Occurrence, Placement};
use crate::pki::Uses;
use crate::timestamp::TimestampScope;
use crate::xml::{Access, Snapshot, Xml};
use core::fmt;
use structured_asn1::memory::{MemoryError, OwnedMap, OwnedVec, Work};
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
pub enum ExclusivityError<'certificate, 'document, E, N> {
    /// Whole-signature requirements are needed; a preceding-archive subset
    /// cannot classify all original incorporated material.
    Scope {
        /// Actual enclosing scope node.
        node: N,
    },
    /// Original XML/index/generation or current execution refusal.
    Index(IndexError<E, N>),
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

impl<E: fmt::Debug, N: fmt::Debug> fmt::Debug for ExclusivityError<'_, '_, E, N> {
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
    ExclusivityError<'certificate, 'document, <X as Xml>::Error, <X as Xml>::Id>,
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

pub(crate) fn reference_status_candidates<'certificate, 'document, N, D, G, W: Work>(
    artifacts: &ArtifactUses<'_, '_, '_, 'certificate, 'document, N, D, G>,
    work: &W,
) -> Result<OwnedVec<ReferenceStatus<'certificate, 'document>, W>, CaError<'certificate, 'document>>
{
    let mut candidates = work.vector();
    let mut scan = CaScan {
        entries: artifacts.entries(),
        targets: &artifacts.targets,
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

pub(crate) fn reference_certificate_candidates<'certificate, 'document, N, D, G, W: Work>(
    artifacts: &ArtifactUses<'_, '_, '_, 'certificate, 'document, N, D, G>,
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

struct CaScan<'query, 'certificate, 'document, W: Work> {
    entries: &'query [ArtifactUse<'certificate, 'document>],
    targets: &'query [StatusTarget],
    cache: OwnedMap<usize, CaFact, W>,
    work: &'query W,
}

impl<'certificate, 'document, W: Work> CaScan<'_, 'certificate, 'document, W> {
    fn certificate(&self, index: usize) -> &'certificate Certificate<'document> {
        let ArtifactRef::Certificate(certificate) = self.entries[index].artifact() else {
            unreachable!("private status target is an admitted certificate ordinal")
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
        if matches!(self.entries[index].artifact(), ArtifactRef::Certificate(_)) {
            return match self.class(index)? {
                CaFact::NotAsserted => Ok(None),
                fact => Ok(Some((fact, index))),
            };
        }
        let mut next = self.entries[index].targets;
        let mut unstated = None;
        while let Some(index) = next {
            self.work.charge_work(1)?;
            let target = &self.targets[index];
            let certificate = target.certificate;
            next = target.next;
            let uses = self.entries[certificate].uses();
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
        entries: artifacts.entries(),
        targets: &artifacts.targets,
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
mod tests {
    use super::*;
    use crate::material::fixture;
    use crate::pki::Participant;
    use alloc::sync::Arc;
    use structured_asn1::{
        Parser,
        memory::{Memory, MemoryAccount},
    };

    fn memory(capacity: usize, work: usize) -> Memory {
        Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
    }

    #[test]
    fn references_and_value_containers_keep_distinct_exclusive_ca_rules() {
        // Annex A permits TSA references, unlike ordinary value containers.
        // Union every role before deciding exclusivity, independent of order.
        let signer = Uses::participant(Participant::Signer(0usize));
        let credential = Uses::participant(Participant::Credential {
            signature: 0usize,
            node: 0,
            authority: 0,
        });
        let tsa = Uses::participant(Participant::Timestamp {
            property: 0usize,
            token: 0,
        });
        for (roles, reference, values) in [
            (&[credential][..], true, true),
            (&[tsa][..], false, true),
            (&[credential, tsa][..], false, true),
            (&[tsa, credential][..], false, true),
            (&[credential, signer][..], false, false),
            (&[tsa, signer][..], false, false),
        ] {
            let mut uses = roles[0];
            for &other in &roles[1..] {
                uses.merge(other);
            }
            assert_eq!(exclusive_credential(uses), reference);
            assert_eq!(exclusive(uses), values);
        }
    }

    #[test]
    fn status_classifies_its_actual_target_not_the_crl_signer() {
        // Distinct CA/EE signers and targets deliberately oppose one another.
        // Shared target CA use is not exclusive, even for a credential-only CRL.
        for (version, ca, shared, expected) in [
            (Version::V3, Some(false), false, None),
            (Version::V3, None, false, None),
            (Version::V3, Some(true), false, Some(CaFact::Asserted)),
            (Version::V3, Some(true), true, None),
            (Version::V1, None, false, Some(CaFact::Unstated)),
            (Version::V2, None, false, Some(CaFact::Unstated)),
        ] {
            let target_bytes = fixture::certificate(1, version, ca);
            let signer_bytes = fixture::certificate(2, Version::V3, Some(true));
            let crl_bytes = fixture::crl();
            let source = memory(65_536, 1_000_000);
            let parser = Parser::der(source.clone());
            let target = Certificate::read(&parser, &target_bytes, 100).unwrap();
            let signer = Certificate::read(&parser, &signer_bytes, 900).unwrap();
            let crl =
                structured_pkix::crl::CertificateList::read(&parser, &crl_bytes, 1800).unwrap();
            let timestamp = Uses::participant(Participant::Timestamp {
                property: 0usize,
                token: 1,
            });
            let mut target_uses = timestamp;
            if shared {
                target_uses.merge(Uses::participant(Participant::Signer(0usize)));
            }
            let entries = [
                ArtifactUse {
                    artifact: ArtifactRef::Certificate(&target),
                    uses: target_uses,
                    targets: None,
                },
                ArtifactUse {
                    artifact: ArtifactRef::Certificate(&signer),
                    uses: timestamp,
                    targets: None,
                },
                ArtifactUse {
                    artifact: ArtifactRef::Crl(&crl),
                    uses: timestamp,
                    targets: Some(0),
                },
            ];
            let targets = [StatusTarget {
                certificate: 0,
                next: None,
            }];
            let work = memory(65_536, 1_000_000);
            let before = source.used();
            let mut scan = CaScan {
                entries: &entries,
                targets: &targets,
                cache: work.map(),
                work: &work,
            };
            let witness = scan.witness(2, exclusive).unwrap().map(|(fact, index)| {
                assert_eq!(index, 0);
                fact
            });
            assert_eq!(witness, expected);
            assert_eq!(
                scan.witness(1, exclusive).unwrap(),
                Some((CaFact::Asserted, 1))
            );
            assert_eq!(scan.witness(2, exclusive_credential).unwrap(), None);
            drop(scan);
            assert_eq!(work.used(), 0);
            assert_eq!(source.used(), before);
        }
    }

    #[test]
    fn ca_query_refusal_is_never_an_unstated_or_non_ca_fact() {
        // Both decoding and the classification cache are current-operation
        // work/storage. Refusal cannot permit material or fabricate a finding.
        let bytes = fixture::certificate(1, Version::V3, Some(true));
        let source = memory(65_536, 1_000_000);
        let parser = Parser::der(source.clone());
        let certificate = Certificate::read(&parser, &bytes, 100).unwrap();
        let before = source.used();
        let entries = [ArtifactUse {
            artifact: ArtifactRef::Certificate(&certificate),
            uses: Uses::participant(Participant::Timestamp {
                property: 0usize,
                token: 1,
            }),
            targets: None,
        }];
        for work in [memory(0, 1_000_000), memory(65_536, 0)] {
            let mut scan = CaScan {
                entries: &entries,
                targets: &[],
                cache: work.map(),
                work: &work,
            };
            match scan.witness(0, exclusive) {
                Err(CaError::Resource(MemoryError::LimitExceeded | MemoryError::WorkExceeded)) => {}
                Err(CaError::Certificate(actual, cause)) => {
                    assert!(core::ptr::eq(actual, &raw const certificate));
                    assert!(cause.is_resource());
                }
                _ => panic!("current resource refusal must remain terminal"),
            }
            drop(scan);
            assert_eq!(work.used(), 0);
            assert_eq!(source.used(), before);
        }
    }
}
