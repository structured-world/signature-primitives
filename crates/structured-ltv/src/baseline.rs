//! Composition of source-bound long-term facts over a format's stage reports.
//!
//! Each format supplies its own basic stage and material reports through the
//! traits here. [`timestamped`] joins the whole TSA-path census with every
//! signature timestamp's static association; [`long_term`] links the X.509 and
//! credential material reports to the SAME participant census; for each
//! archive [`archive_material`] joins that archive's reports and [`archives`]
//! requires one for every original archive. Additional reports never promote
//! a requested level and no report here is a trust verdict.

use crate::pki::{CounterReceipts, ParticipantRequirements, SignerReceipt};
use crate::source::{Location, Snapshot};
use crate::timestamp::TimestampScope;

mod archive;
mod material;
mod timed;

pub use archive::{
    ArchiveCensusError, ArchiveMaterial, ArchiveMaterialResult, Archives, ArchivesResult,
    archive_material, archives,
};
pub use material::{LongTerm, MaterialResult, long_term};
pub use timed::{
    SignatureTimeFact, TimeError, TimeResult, Timed, timestamped, timestamped_existence,
};

/// A format's basic stage: the signer and countersignature receipts it was
/// built from, and whether every requirement of the format's basic level holds.
pub trait BasicStage<'path, 'document> {
    /// Original node identity.
    type Id: Copy;
    /// Stable document identity.
    type Document: Copy;
    /// Exact document generation.
    type Generation: Copy;
    /// The signing-certificate binding receipt.
    type Signer: SignerReceipt<
            'path,
            'document,
            Id = Self::Id,
            Document = Self::Document,
            Generation = Self::Generation,
        >;
    /// The complete countersignature census.
    type Counters: CounterReceipts<
            'path,
            'document,
            Id = Self::Id,
            Document = Self::Document,
            Generation = Self::Generation,
        >;

    /// Same signer receipt the stage checked.
    fn signer(&self) -> &Self::Signer;
    /// Same countersignature census the stage checked.
    fn counters(&self) -> &Self::Counters;
    /// Every condition of the format's basic level holds.
    fn all_requirements_met(&self) -> bool;
}

/// A format's whole-signature X.509 material report.
pub trait X509Material<'path, 'document> {
    /// Original node identity.
    type Id: Copy;
    /// Stable document identity.
    type Document: Copy;
    /// Exact document generation.
    type Generation: Copy;
    /// Issuer of the receipts the report was derived from.
    type Issuer;

    /// The participant census the report was derived from.
    fn requirements(
        &self,
    ) -> &ParticipantRequirements<
        'path,
        'document,
        Self::Id,
        Self::Document,
        Self::Generation,
        Self::Issuer,
    >;
    /// Every X.509 presence and placement requirement of the format holds.
    fn all_x509_requirements_met(&self) -> bool;
}

/// A format's credential-material report for one validation-data scope.
pub trait CredentialMaterial {
    /// Original node identity.
    type Id: Copy;
    /// Stable document identity.
    type Document: Copy;
    /// Exact document generation.
    type Generation: Copy;
    /// The authenticated credential census the report checked.
    type Credentials;

    /// Whole-signature or preceding-archive scope of the report.
    fn scope(&self) -> TimestampScope<Self::Id, Self::Document, Self::Generation>;
    /// Source generation of the authenticated credential census.
    fn snapshot(&self) -> Snapshot<Self::Document, Self::Generation>;
    /// Same authenticated credential census, by reference.
    fn credentials(&self) -> &Self::Credentials;
    /// Every credential's own format material is present and interpreted.
    fn all_requirements_met(&self) -> bool;
}

/// A format's census of one signature's timestamps, in original order.
pub trait ArchiveCensus {
    /// Original node identity.
    type Id: Copy;
    /// Stable document identity.
    type Document: Copy;
    /// Exact document generation.
    type Generation: Copy;

    /// The signature whose timestamps these are.
    fn signature(&self) -> Location<Self::Id, Self::Document, Self::Generation>;
    /// Number of timestamps of every kind.
    fn timestamps(&self) -> usize;
    /// The original archive input subject at this ordinal, or `None` for
    /// another kind of input. Match the format's `Coverage::subject`: a token
    /// for member-specific inputs, or the property for property-shared input.
    ///
    /// # Panics
    /// When `ordinal` is not below [`Self::timestamps`].
    fn archive(&self, ordinal: usize) -> Option<Self::Id>;
}
