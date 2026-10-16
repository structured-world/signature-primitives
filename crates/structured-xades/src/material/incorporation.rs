//! Actual X.509 validation inputs incorporated into the original signature.

use super::{ArtifactRef, ArtifactUses, Index, IndexError, Occurrence};
use crate::timestamp::TimestampScope;
use crate::xml::{Access, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

/// One actual validation input and an exact original incorporated copy, if any.
/// An acquired/caller-supplied value alone is not an incorporated occurrence.
pub struct IncorporatedArtifact<'certificate, 'document, N, D, G> {
    artifact: ArtifactRef<'certificate, 'document>,
    occurrence: Option<Occurrence<N, D, G>>,
}

impl<'certificate, 'document, N: Copy, D: Copy, G: Copy>
    IncorporatedArtifact<'certificate, 'document, N, D, G>
{
    /// Original actual checked-path or contributing status input.
    #[must_use]
    pub fn artifact(&self) -> ArtifactRef<'certificate, 'document> {
        self.artifact
    }
    /// First exact incorporated copy; absence never implies usable status.
    #[must_use]
    pub fn occurrence(&self) -> Option<Occurrence<N, D, G>> {
        self.occurrence
    }
}

/// Complete X.509 input presence for whole-signature LT requirements. This
/// preserves missing artifacts rather than accepting a caller-written subset.
/// Placement, format-specific credentials, status usability, historical trust,
/// chronology and archive coverage are SEPARATE obligations, not inferred here.
pub struct Incorporation<'certificate, 'document, N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    entries: OwnedVec<IncorporatedArtifact<'certificate, 'document, N, D, G>>,
    all_present: bool,
}

impl<'certificate, 'document, N: Copy, D: Copy, G: Copy>
    Incorporation<'certificate, 'document, N, D, G>
{
    /// Actual immutable source under which every copy was located.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Original root signature whose complete participant set was used.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Every actual artifact once, preserving first-encounter order.
    #[must_use]
    pub fn entries(&self) -> &[IncorporatedArtifact<'certificate, 'document, N, D, G>] {
        &self.entries
    }
    /// Only incorporated presence, not allowed placement, Good status or grade.
    #[must_use]
    pub fn all_present(&self) -> bool {
        self.all_present
    }
}

/// Incomplete scope and original source/resource errors are not missing values.
#[derive(Debug)]
pub enum IncorporationError<E, N> {
    /// A preceding-archive subset cannot establish whole-signature presence.
    Scope,
    /// Current original source/index/generation/admission refused.
    Index(IndexError<E, N>),
}

/// Complete original report or an unchanged terminal source/admission cause.
pub type IncorporationResult<'certificate, 'document, X> = Result<
    Incorporation<
        'certificate,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    IncorporationError<<X as Xml>::Error, <X as Xml>::Id>,
>;

/// Locate every actual X.509 validation input, including independently retained
/// anchors and reached CRL/delta/OCSP authentication paths, through the SAME
/// exact-artifact index used for archive coverage and TSA placement.
/// EN319132-1 §6.3(cc) permits missing validation data in `AnyValidationData`;
/// §§5.4.2–5.4.6 and6.3(x) additionally constrain particular container roles.
/// This necessary presence check does not replace those placement checks or
/// assert that Unknown/stale/revoked input is Good. No parse/crypto is repeated.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn incorporation<'certificate, 'document, X: Xml, W: Work, Q: Work>(
    uses: &ArtifactUses<'_, '_, '_, 'certificate, 'document, X::Id, X::Document, X::Generation>,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    access: &Access<'_, X, Q>,
) -> IncorporationResult<'certificate, 'document, X> {
    let required = uses.inputs().requirements();
    let TimestampScope::All(location) = required.scope() else {
        return Err(IncorporationError::Scope);
    };
    if location.snapshot != access.snapshot() {
        return Err(IncorporationError::Index(IndexError::Foreign {
            signature: required.signature(),
        }));
    }
    index
        .require_signature(required.signature(), access)
        .map_err(IncorporationError::Index)?;
    let resource = |cause| {
        IncorporationError::Index(IndexError::Resource {
            signature: required.signature(),
            cause,
        })
    };
    let mut entries = access.execution().vector();
    entries
        .try_reserve_exact(uses.entries().len())
        .map_err(resource)?;
    let mut all_present = true;
    for ordinal in 0..uses.entries().len() {
        access
            .query(required.signature(), |_, _, work| Ok(work.charge_work(1)))
            .map_err(|cause| IncorporationError::Index(IndexError::Access(cause)))?
            .map_err(resource)?;
        let artifact = uses.entries()[ordinal].artifact();
        let mut copies = index
            .artifact(artifact, access)
            .map_err(IncorporationError::Index)?;
        let occurrence = copies
            .next()
            .transpose()
            .map_err(IncorporationError::Index)?;
        if occurrence.is_none() {
            all_present = false;
        }
        entries
            .try_push(IncorporatedArtifact {
                artifact,
                occurrence,
            })
            .map_err(resource)?;
    }
    index
        .require_signature(required.signature(), access)
        .map_err(IncorporationError::Index)?;
    Ok(Incorporation {
        snapshot: location.snapshot,
        signature: required.signature(),
        entries: entries.into_owned(),
        all_present,
    })
}
