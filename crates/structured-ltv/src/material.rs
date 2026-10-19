//! Exact incorporated validation material and its coverage by archive inputs.
//!
//! The format layer builds an [`Index`] of every original certificate, CRL and
//! OCSP value it carries, with its own placement of each occurrence, and a
//! [`Coverage`] for each archive timestamp input. These modules then locate
//! the material that actual actor paths and status results need. Availability
//! is never authentication, freshness, placement acceptance or a level.

mod coverage;
pub use coverage::{Coverage, CoverageError};
#[cfg(test)]
mod fixture;
mod incorporation;
pub use incorporation::{IncorporatedArtifact, Incorporation, IncorporationError, incorporation};
mod index;
pub use index::{
    ArchiveError, Archived, ArchivedCertificate, ArtifactKey, ArtifactRef, ArtifactSource,
    CarriedOrigin, Index, IndexError, Occurrence, Occurrences, PathCertificate, PathCertificates,
};
mod participants;
pub use participants::{
    AnchorMaterial, ParticipantArchiveError, ParticipantMaterial, archived_participants,
};
pub mod status;
mod uses;
pub use uses::{ArtifactUse, ArtifactUses, ArtifactUsesResult, Targets, artifact_uses};
