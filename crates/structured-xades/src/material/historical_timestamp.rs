//! Original per-token material for historical augmentation and archive checking.

use super::timestamp_placement::{Closure, TimestampItem, admit_index, resource, visit_timestamps};
use super::{Archived, Index, Occurrence, Placement, TimestampPlacementError};
use crate::Xades;
use crate::xml::{Access, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};
use structured_ltv::material::{ArtifactRef, Coverage, CoverageError};
use structured_ltv::pki::AuthorityNode;
use structured_ltv::timestamp::{Purpose, TimestampScope, Verified};

/// One reached validation authority for an original timestamp token.
pub struct HistoricalTimestampAuthority<'view, 'certificate, 'document, N> {
    /// Timestamp property carrying the token.
    pub property: N,
    /// The actual token, distinct from parallel tokens in the same property.
    pub token: N,
    /// The original path, its status inputs and delegated responder bindings.
    pub authority: &'view AuthorityNode<'view, 'certificate, 'document>,
}

/// Exact material needed by one token. Identical copies need not be emitted again.
pub struct HistoricalTimestampArtifact<'certificate, 'document, N, D, G> {
    /// Timestamp property carrying the token and the insertion point for new data.
    pub property: N,
    /// The actual token that needs the material.
    pub token: N,
    /// Exact required certificate, CRL or OCSP artifact.
    pub artifact: ArtifactRef<'certificate, 'document>,
    /// First copy carried by this token itself.
    pub own_token: Option<Occurrence<N, D, G>>,
    /// First copy in a TSVD immediately after this timestamp property.
    pub adjacent: Option<Occurrence<N, D, G>>,
    /// First other copy in the selected signature's material inventory.
    pub elsewhere: Option<Occurrence<N, D, G>>,
    /// Exact protected-input availability when a checked archive was selected.
    /// A covered duplicate may differ from a reported representative copy.
    pub archive: Option<Archived<N, D, G>>,
}

impl<N, D, G> HistoricalTimestampArtifact<'_, '_, N, D, G> {
    /// No exact incorporated copy exists. Use this for whole-signature
    /// augmentation. For a checked archive use its separate coverage result.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        self.own_token.is_none() && self.adjacent.is_none() && self.elsewhere.is_none()
    }
}

/// Historical TSA material census derived from a closed participant inventory.
pub struct HistoricalTimestampMaterial<'view, 'certificate, 'document, N, D, G> {
    snapshot: Snapshot<D, G>,
    authorities: OwnedVec<HistoricalTimestampAuthority<'view, 'certificate, 'document, N>>,
    artifacts: OwnedVec<HistoricalTimestampArtifact<'certificate, 'document, N, D, G>>,
}

impl<'view, 'certificate, 'document, N, D: Copy, G: Copy>
    HistoricalTimestampMaterial<'view, 'certificate, 'document, N, D, G>
{
    /// Original immutable XML generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }

    /// Every reached path and status input per token, in authority traversal order.
    #[must_use]
    pub fn authorities(
        &self,
    ) -> &[HistoricalTimestampAuthority<'view, 'certificate, 'document, N>] {
        &self.authorities
    }

    /// Each exact artifact once per token, with representative original locations.
    #[must_use]
    pub fn artifacts(&self) -> &[HistoricalTimestampArtifact<'certificate, 'document, N, D, G>] {
        &self.artifacts
    }
}

/// Historical input or processing refusal, separate from missing material.
#[derive(Debug)]
pub enum HistoricalTimestampError<N> {
    /// Source, closure, resource or index refusal.
    Material(TimestampPlacementError<N>),
    /// The checked archive does not match the selected original signature/scope.
    Archive {
        /// Original node of the supplied archive property.
        property: N,
    },
    /// Failed to bind or query original archive input coverage.
    Coverage(CoverageError<N>),
}

impl<N> From<TimestampPlacementError<N>> for HistoricalTimestampError<N> {
    fn from(cause: TimestampPlacementError<N>) -> Self {
        Self::Material(cause)
    }
}

/// Historical TSA material in the original XML identity domain.
pub type HistoricalTimestampResult<'view, 'certificate, 'document, X> = Result<
    HistoricalTimestampMaterial<
        'view,
        'certificate,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    HistoricalTimestampError<<X as Xml>::Id>,
>;

/// Inspect the TSA paths and exact material of every timestamp, including
/// the last archive. Supply the historical index built with token material
/// via [`super::index_with_tokens`] to include token-carried copies.
///
/// ETSI TS 101 903 V1.4.2 §§8.1–8.1.1 allows usable copies elsewhere in the
/// signature. Emit only missing values immediately after their unsigned
/// timestamp property before preparing the next archive input.
/// <https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf>
pub fn historical_timestamp_material<'view, 'certificate, 'document, X: Xml, W: Work, Q: Work>(
    inputs: &Closure<'_, 'view, 'certificate, 'document, X>,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    access: &Access<'_, X, Q>,
) -> HistoricalTimestampResult<'view, 'certificate, 'document, X> {
    if !matches!(inputs.requirements().scope(), TimestampScope::All(_)) {
        return Err(TimestampPlacementError::Scope.into());
    }
    assess(inputs, index, access, None::<&fn(X::Id) -> _>)
}

/// Inspect the TSA material in a specific checked archive's original input.
/// The participant closure must be derived for that archive's antecedents.
/// A late or self-carried copy cannot repair its covered input.
pub fn historical_timestamp_material_before_archive<
    'view,
    'certificate,
    'document,
    X: Xml,
    W: Work,
    Q: Work,
    C: Work,
>(
    inputs: &Closure<'_, 'view, 'certificate, 'document, X>,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    coverage: &Coverage<X::Id, X::Document, X::Generation, C, Xades>,
    evidence: &Verified<X::Id, X::Document, X::Generation, Xades>,
    access: &Access<'_, X, Q>,
) -> HistoricalTimestampResult<'view, 'certificate, 'document, X> {
    let required = inputs.requirements();
    let signature = required.signature();
    let property = evidence.property();
    let foreign = HistoricalTimestampError::Archive { property };
    let TimestampScope::BeforeArchive(at) = required.scope() else {
        return Err(foreign);
    };
    if evidence.purpose() != Purpose::Archive
        || at.snapshot != access.snapshot()
        || !access
            .equal_id(at.node, property)
            .map_err(|cause| resource(signature, cause))?
        || !access
            .equal_id(signature, evidence.signature())
            .map_err(|cause| resource(signature, cause))?
    {
        return Err(foreign);
    }
    coverage
        .require_evidence(evidence, property, access)
        .map_err(HistoricalTimestampError::Coverage)?;
    assess(
        inputs,
        index,
        access,
        Some(&|node| coverage.selects(node, access)),
    )
}

fn assess<'view, 'certificate, 'document, X: Xml, W: Work, Q: Work>(
    inputs: &Closure<'_, 'view, 'certificate, 'document, X>,
    index: &Index<'_, X::Id, X::Document, X::Generation, W>,
    access: &Access<'_, X, Q>,
    covered: Option<&impl Fn(X::Id) -> Result<bool, CoverageError<X::Id>>>,
) -> HistoricalTimestampResult<'view, 'certificate, 'document, X> {
    let signature = admit_index(inputs, index, access)?;
    let work = access.execution();
    let mut authorities = work.vector();
    let mut artifacts = work.vector();
    visit_timestamps(inputs, access, |(property, token), item| {
        match item {
            TimestampItem::Authority(authority) => {
                authorities.try_push(HistoricalTimestampAuthority {
                    property,
                    token,
                    authority,
                })
            }
            TimestampItem::Artifact(artifact) => {
                let mut row = HistoricalTimestampArtifact {
                    property,
                    token,
                    artifact,
                    own_token: None,
                    adjacent: None,
                    elsewhere: None,
                    archive: covered.map(|_| Archived::Missing),
                };
                for copy in index
                    .artifact(artifact, access)
                    .map_err(TimestampPlacementError::Index)?
                {
                    let copy = copy.map_err(TimestampPlacementError::Index)?;
                    row.record(copy, covered, access)
                        .map_err(|cause| match cause {
                            RecordError::Coverage(cause) => {
                                HistoricalTimestampError::Coverage(cause)
                            }
                            RecordError::Resource(cause) => resource(signature, cause).into(),
                        })?;
                }
                artifacts.try_push(row)
            }
        }
        .map_err(|cause| HistoricalTimestampError::from(resource(signature, cause)))
    })?;
    index
        .require_signature(signature, access)
        .map_err(TimestampPlacementError::Index)?;
    Ok(HistoricalTimestampMaterial {
        snapshot: access.snapshot(),
        authorities: authorities.into_owned(),
        artifacts: artifacts.into_owned(),
    })
}

enum RecordError<N> {
    Resource(structured_asn1::memory::MemoryError),
    Coverage(CoverageError<N>),
}

impl<N: Copy, D: Copy, G: Copy> HistoricalTimestampArtifact<'_, '_, N, D, G> {
    fn record<X: Xml<Id = N, Document = D, Generation = G>, W: Work>(
        &mut self,
        copy: Occurrence<N, D, G>,
        covered: Option<&impl Fn(N) -> Result<bool, CoverageError<N>>>,
        access: &Access<'_, X, W>,
    ) -> Result<(), RecordError<N>> {
        let equal = |left, right| access.equal_id(left, right).map_err(RecordError::Resource);
        let slot = match copy.placement() {
            Placement::TimestampToken {
                property, token, ..
            } if equal(property, self.property)? && equal(token, self.token)? => {
                &mut self.own_token
            }
            Placement::AssociatedTimestamp { property, .. } if equal(property, self.property)? => {
                &mut self.adjacent
            }
            _ => &mut self.elsewhere,
        };
        slot.get_or_insert(copy);
        if let Some(selects) = covered
            && !matches!(self.archive, Some(Archived::Present(_)))
        {
            self.archive = Some(
                if selects(copy.location().node).map_err(RecordError::Coverage)? {
                    Archived::Present(copy)
                } else {
                    Archived::Uncovered
                },
            );
        }
        Ok(())
    }
}
