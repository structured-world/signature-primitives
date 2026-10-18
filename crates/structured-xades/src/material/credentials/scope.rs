//! Whole incorporation or one exact earlier archive's original coverage.

use super::{Error, Missing};
use crate::binary::Location;
use crate::material::{ArchiveError, Archived, ArtifactRef, Index};
use crate::timestamp::{ElementCoverage, TimestampRequirements, TimestampScope};
use crate::xml::{Access, Xml};
use structured_asn1::memory::{HashWork, Memory, Work};
use structured_ltv::timestamp::{Purpose, Verified};

/// Optional original archive coverage; only these constructors expose it.
/// The check verifies its source/role/property against the source-derived scope
/// BEFORE handler calls. A whole-signature check cannot impersonate an archive.
pub struct Scope<'a, N: HashWork, D, G, C: Work = Memory> {
    archive: Option<Archive<'a, N, D, G, C>>,
}

type Archive<'a, N, D, G, C> = (&'a ElementCoverage<N, D, G, C>, &'a Verified<N, D, G>);

impl<N: HashWork, D, G> Scope<'_, N, D, G> {
    /// Whole-signature incorporation, with no archive implication.
    #[must_use]
    pub fn whole() -> Self {
        Self { archive: None }
    }
}

impl<'a, N: HashWork, D, G, C: Work> Scope<'a, N, D, G, C> {
    /// Exact selected archive input and its private mathematical token receipt.
    #[must_use]
    pub fn before_archive(
        coverage: &'a ElementCoverage<N, D, G, C>,
        evidence: &'a Verified<N, D, G>,
    ) -> Self {
        Self {
            archive: Some((coverage, evidence)),
        }
    }
}

impl<N: Copy + Eq + HashWork, D: Copy + Eq, G: Copy + Eq, C: Work> Scope<'_, N, D, G, C> {
    pub(super) fn require<X: Xml<Id = N, Document = D, Generation = G>, W: Work, Q: Work, PE>(
        &self,
        required: &TimestampRequirements<N, D, G>,
        index: &Index<'_, N, D, G, W>,
        access: &Access<'_, X, Q>,
    ) -> Result<(), Error<X::Error, PE, N>> {
        let location = required.scope().location();
        let node = location.node;
        if location.snapshot != access.snapshot() {
            return Err(Error::Foreign { node });
        }
        index
            .require_signature(required.signature(), access)
            .map_err(Error::Index)?;
        match (required.scope(), self.archive) {
            (TimestampScope::All(_), None) => Ok(()),
            (TimestampScope::BeforeArchive(_), Some((coverage, evidence))) => {
                if evidence.purpose() != Purpose::Archive
                    || evidence.token().snapshot != location.snapshot
                    || !access
                        .equal_id(evidence.signature(), required.signature())
                        .map_err(|cause| Error::Resource { node, cause })?
                    || !access
                        .equal_id(evidence.property(), node)
                        .map_err(|cause| Error::Resource { node, cause })?
                {
                    return Err(Error::Foreign { node });
                }
                coverage
                    .require_evidence(evidence, node, access)
                    .map_err(|cause| Error::Archive(ArchiveError::Coverage(cause)))
            }
            _ => Err(Error::Foreign { node }),
        }
    }

    pub(super) fn known<X: Xml<Id = N, Document = D, Generation = G>, W: Work, Q: Work, PE>(
        &self,
        need: ArtifactRef<'_, '_>,
        index: &Index<'_, N, D, G, W>,
        access: &Access<'_, X, Q>,
    ) -> Result<Option<Missing>, Error<X::Error, PE, N>> {
        if let Some((coverage, evidence)) = self.archive {
            return index
                .archived(need, coverage, evidence, access)
                .map(|value| match value {
                    Archived::Present(_) => None,
                    Archived::Missing => Some(Missing::Absent),
                    Archived::Uncovered => Some(Missing::Uncovered),
                })
                .map_err(Error::Archive);
        }
        let mut copies = index.artifact(need, access).map_err(Error::Index)?;
        copies
            .next()
            .transpose()
            .map(|value| {
                if value.is_some() {
                    None
                } else {
                    Some(Missing::Absent)
                }
            })
            .map_err(Error::Index)
    }

    pub(super) fn open<X: Xml<Id = N, Document = D, Generation = G>, Q: Work, PE>(
        &self,
        location: Location<N, D, G>,
        access: &Access<'_, X, Q>,
    ) -> Result<Option<Missing>, Error<X::Error, PE, N>> {
        if let Some((coverage, evidence)) = self.archive {
            return coverage
                .covers(evidence, location.node, access)
                .map(|covered| {
                    if covered {
                        None
                    } else {
                        Some(Missing::Uncovered)
                    }
                })
                .map_err(|cause| Error::Archive(ArchiveError::Coverage(cause)));
        }
        Ok(None)
    }
}
