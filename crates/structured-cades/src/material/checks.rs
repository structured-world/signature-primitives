//! Whole-source X.509 material requirements from the actual shared closure.

use super::{Index, Placement, Pool};
use crate::{
    Cades, Error,
    prepare::Preparation,
    source::{DocumentId, Node},
};
use structured_asn1::memory::{OwnedVec, Work};
use structured_ltv::{
    baseline::X509Material,
    material::{self, ArtifactRef, Incorporation, IncorporationError, IndexError},
    pki::{self, ParticipantClosure, ParticipantRequirements, UsesError},
    source::Query,
    timestamp::TimestampScope,
};

/// One real artifact whose required original incorporation was not established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finding {
    /// No exact original DER copy is incorporated in root or timestamp sources.
    Missing {
        /// Actual artifact-census ordinal, not a document byte offset.
        artifact: usize,
    },
    /// An actual copy exists but not in its required certificate/revocation set.
    Placement {
        /// Actual artifact-census ordinal.
        artifact: usize,
    },
    /// A known original validation value violates its selected syntax.
    Malformed {
        /// Original material enclosure.
        node: Node,
    },
}

/// Complete whole-signature X.509 presence and placement facts. Actual actor,
/// member/status and authority requirements come from the SAME LTV closure;
/// certificate-free credentials do not waive other format-specific material.
pub struct Checks<'closure, 'requirements, 'view, 'certificate, 'document, 'model> {
    inputs: &'closure ParticipantClosure<
        'requirements,
        'view,
        'certificate,
        'document,
        Node,
        DocumentId<'model, 'document>,
        (),
        Cades,
    >,
    presence:
        Incorporation<'certificate, 'document, Node, DocumentId<'model, 'document>, (), Placement>,
    findings: OwnedVec<Finding>,
}
impl<'d, 'm> Checks<'_, '_, '_, '_, 'd, 'm> {
    /// Every actual required certificate/complete+delta CRL/OCSP artifact.
    #[must_use]
    pub fn presence(&self) -> &Incorporation<'_, 'd, Node, DocumentId<'m, 'd>, (), Placement> {
        &self.presence
    }
    /// Missing/misplaced/known-malformed facts, independently of status usability.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    /// Presence and mandatory container placement only; not Good status,
    /// historical trust, complete credential material or attained B-LT.
    #[must_use]
    pub fn all_x509_requirements_met(&self) -> bool {
        self.findings.is_empty() && self.presence.all_present()
    }
}
impl<'v, 'd, 'm> X509Material<'v, 'd> for Checks<'_, '_, 'v, '_, 'd, 'm> {
    type Id = Node;
    type Document = DocumentId<'m, 'd>;
    type Generation = ();
    type Issuer = Cades;
    fn requirements(
        &self,
    ) -> &ParticipantRequirements<'v, 'd, Node, DocumentId<'m, 'd>, (), Cades> {
        self.inputs.requirements()
    }
    fn all_x509_requirements_met(&self) -> bool {
        Self::all_x509_requirements_met(self)
    }
}

/// Actual source/census/index refusal; no successful partial material report.
#[derive(Debug)]
pub enum CheckError {
    /// Complete whole-signature source/selection preflight refused.
    Processing(Error),
    /// Original actual actor/status-authority graph attribution refused.
    Uses(UsesError<Node>),
    /// Original complete incorporation lookup refused.
    Presence(IncorporationError<Node>),
    /// Exact original indexed-occurrence lookup refused.
    Index(IndexError<Node>),
}

/// Check ALL actual validation artifacts using the existing LTV role closure,
/// exact-artifact index and incorporation kernel. Root/counter/credential/TSA
/// and reached status-authority artifacts cannot be replaced with an arbitrary
/// nonempty bag. B-LT requires certificates in the root certificate set
/// (§6.3(d)); archive augmentation may reuse existing timestamp material
/// (§5.5.3 Note5). CRLs and whole OCSP values use their actual revocation choices
/// (§§5.4.2/6.3(q,r)). No parser, math, path or status evaluation is replayed.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf>
pub fn check_participants<'cl, 'r, 'v, 'c, 'd, 'm, Q, W>(
    prepared: &Preparation<'m, 'd>,
    pool: &Pool<'_, 'm, 'd>,
    inputs: &'cl ParticipantClosure<'r, 'v, 'c, 'd, Node, DocumentId<'m, 'd>, (), Cades>,
    index: &Index<'_, 'm, 'd, W>,
    query: &Q,
) -> Result<Checks<'cl, 'r, 'v, 'c, 'd, 'm>, CheckError>
where
    Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
    W: Work,
{
    let selected = prepared.document().locate(prepared.signer().span());
    query
        .admit(selected.node, 1)
        .map_err(|cause| CheckError::Index(IndexError::Scope(cause)))?;
    if !core::ptr::eq(pool.prepared(), prepared)
        || inputs.requirements().signature() != selected.node
        || query.snapshot() != selected.snapshot
        || !matches!(inputs.requirements().scope(), TimestampScope::All(_))
    {
        return Err(CheckError::Processing(Error::Foreign {
            at: selected.node.span().start,
        }));
    }
    index
        .require_signature(selected.node, query)
        .map_err(CheckError::Index)?;
    let uses = pki::authority_uses(inputs, query).map_err(CheckError::Uses)?;
    let artifacts = material::artifact_uses(&uses, query).map_err(CheckError::Uses)?;
    let presence =
        material::incorporation(&artifacts, index, query).map_err(CheckError::Presence)?;
    let mut findings = query.execution().vector();
    let archive_augmentation = prepared.requested() == crate::Level::Archival;
    let resource = |cause| {
        CheckError::Processing(Error::resource(
            cause,
            "cades.material",
            selected.node.span().start,
        ))
    };
    for (ordinal, entry) in artifacts.entries().iter().enumerate() {
        query.execution().charge_work(1).map_err(resource)?;
        let artifact = entry.artifact();
        let mut copies = index.artifact(artifact, query).map_err(CheckError::Index)?;
        let mut present = false;
        let mut allowed = false;
        while let Some(copy) = copies.next().transpose().map_err(CheckError::Index)? {
            present = true;
            allowed |= match artifact {
                ArtifactRef::Certificate(_) => {
                    // EN319122-1 §6.3(d) names SignedData.certificates for
                    // B-LT. §5.5.3 Note5's reuse of token validation data is
                    // specific to archive augmentation, not a B-LT waiver.
                    matches!(copy.placement(), Placement::RootCertificate(_))
                        || (archive_augmentation
                            && (matches!(copy.placement(), Placement::TokenCertificate { .. })
                                || matches!(copy.placement(), Placement::CertificateValues(location)
                                    if archived_values(prepared, location))
                                || (copy.embedded_certificate().is_some()
                                    && embedded_placement(prepared, copy.placement()))))
                }
                ArtifactRef::Crl(_) | ArtifactRef::Ocsp(_) => {
                    matches!(
                        copy.placement(),
                        Placement::RootRevocation(_) | Placement::TokenRevocation { .. }
                    ) || (archive_augmentation
                        && matches!(copy.placement(), Placement::CrlValues(location)
                            | Placement::OcspValues(location) if archived_values(prepared, location)))
                }
            };
        }
        if !present {
            findings
                .try_push(Finding::Missing { artifact: ordinal })
                .map_err(resource)?;
        } else if !allowed {
            findings
                .try_push(Finding::Placement { artifact: ordinal })
                .map_err(resource)?;
        }
    }
    for entry in pool.open() {
        query.execution().charge_work(1).map_err(resource)?;
        if entry.cause.is_some() {
            findings
                .try_push(Finding::Malformed { node: entry.node })
                .map_err(resource)?;
        }
    }
    super::legacy::malformed(
        pool,
        |node| {
            query
                .admit(node, 1)
                .map_err(|cause| CheckError::Index(IndexError::Scope(cause)))
        },
        |node, fault| {
            query.execution().charge_work(24).map_err(resource)?;
            if fault.attribute == crate::properties::legacy::LEGACY[2]
                || fault.attribute == crate::properties::legacy::LEGACY[3]
            {
                findings
                    .try_push(Finding::Malformed { node })
                    .map_err(resource)?;
            }
            Ok(())
        },
    )?;
    Ok(Checks {
        inputs,
        presence,
        findings: findings.into_owned(),
    })
}

fn archived_values(prepared: &Preparation<'_, '_>, location: super::LegacyLocation) -> bool {
    // These are immutable, format-produced placement facts. This branch does
    // NOT waive §6.3(d)'s root certificate-set rule for ordinary B-LT, nor
    // admit signed legacy values. §5.5.3 permits reusing archive-token material.
    if !location.unsigned {
        return false;
    }
    let Some(token) = location.token else {
        return false;
    };
    prepared
        .timestamps()
        .get(token)
        .is_some_and(|entry| entry.purpose() == structured_ltv::timestamp::Purpose::Archive)
}

fn embedded_placement(prepared: &Preparation<'_, '_>, placement: Placement) -> bool {
    match placement {
        Placement::CertificateValues(location)
        | Placement::CrlValues(location)
        | Placement::OcspValues(location) => archived_values(prepared, location),
        _ => true,
    }
}
