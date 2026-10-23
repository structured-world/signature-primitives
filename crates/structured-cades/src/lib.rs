#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod baseline;
pub mod basic;
pub mod counters;
pub mod credential;
pub mod evidence;
pub mod material;
pub mod participants;
pub mod prepare;
pub mod preservation;
pub mod properties;
pub mod source;
pub mod timestamp;

/// Terminal processing refusal, distinct from a completed format finding.
#[derive(Debug)]
pub enum Error {
    /// Original common CMS failure, preserving all underlying diagnostics.
    Cms(structured_cms::Error),
    /// Original ASN.1 failure, without changing its coordinates or cause.
    Encoding {
        /// Original protocol field whose decoding refused.
        field: &'static str,
        /// Original ASN.1 cause, including its retained diagnostic path.
        cause: structured_asn1::Error,
    },
    /// Shared PKIX schema/DER refusal, preserving its field and location.
    Pkix(structured_pkix::Error),
    /// Format schema failure at an actual original value.
    Syntax {
        /// Exact format/schema category.
        code: structured_cms::ErrorCode,
        /// Original protocol field.
        field: &'static str,
        /// Original source offset.
        at: u64,
    },
    /// Current work/storage refused before use at this original position.
    Resource {
        /// Actual original source position.
        at: u64,
        /// Exact refusal, never converted to missing material.
        cause: structured_asn1::memory::MemoryError,
        /// Original operation field.
        field: &'static str,
    },
    /// A receipt or selected model belongs to another original source.
    Foreign {
        /// Actual selecting position, never a fabricated decode offset.
        at: u64,
    },
}

impl Error {
    pub(crate) fn resource(
        cause: structured_asn1::memory::MemoryError,
        field: &'static str,
        at: u64,
    ) -> Self {
        Self::Resource { at, cause, field }
    }
    pub(crate) fn encoding(cause: structured_asn1::Error, field: &'static str) -> Self {
        Self::Encoding { cause, field }
    }
    /// A refusal of the run, rather than a recoverable document finding.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Cms(error) => error.is_terminal(),
            Self::Encoding { cause, .. } => {
                cause.is_resource() || cause.code() == structured_asn1::ErrorCode::TagTooLarge
            }
            Self::Pkix(error) => {
                error.is_resource() || error.code() == structured_pkix::ErrorCode::ForeignReader
            }
            Self::Resource { .. } | Self::Foreign { .. } => true,
            Self::Syntax { .. } => false,
        }
    }
    /// Original source position of the failure.
    #[must_use]
    pub fn offset(&self) -> u64 {
        match self {
            Self::Cms(error) => error.offset(),
            Self::Encoding { cause, .. } => cause.offset(),
            Self::Pkix(error) => error.offset(),
            Self::Resource { at, .. } | Self::Foreign { at } | Self::Syntax { at, .. } => *at,
        }
    }
    /// Original protocol field, when this failure originates in document
    /// processing. A foreign receipt is caller misuse and has no invented field.
    #[must_use]
    pub fn field(&self) -> Option<&'static str> {
        match self {
            Self::Cms(cause) => Some(cause.field()),
            Self::Pkix(cause) => Some(cause.field()),
            Self::Encoding { field, .. }
            | Self::Syntax { field, .. }
            | Self::Resource { field, .. } => Some(*field),
            Self::Foreign { .. } => None,
        }
    }
}

impl From<structured_cms::Error> for Error {
    fn from(cause: structured_cms::Error) -> Self {
        Self::Cms(cause)
    }
}

/// Complete operation or terminal processing refusal; never a successful prefix.
pub type Result<T> = core::result::Result<T, Error>;

/// Explicitly requested format profile, never inferred from unsigned attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Mandatory signed baseline fields and signer association.
    Basic,
    /// Basic plus the complete signature-timestamp obligations.
    Timestamped,
    /// Timestamped plus all required incorporated validation material.
    LongTerm,
    /// Long-term plus every original archive's protected validation material.
    Archival,
}

/// Issuer of source-derived `CAdES` receipts in the format-neutral LTV core.
/// Only this crate constructs it, after selecting the original CMS source.
#[derive(Debug, Clone, Copy)]
pub struct Cades(());

pub(crate) const ISSUER: Cades = Cades(());
