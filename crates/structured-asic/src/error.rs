//! Container processing failures, distinct from readable negative facts.

use structured_asn1::{Span, memory::MemoryError, range::InputError};

/// Original-source processing result without erasing its source error type.
pub type SourceResult<T, S> = Result<T, Error<<S as structured_asn1::range::RangeSource>::Error>>;

/// Structural ambiguity or syntax that prevents an original member census.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// No complete end-of-directory record reaches the original EOF.
    End,
    /// Two complete directory interpretations reach the same original EOF.
    AmbiguousDirectory,
    /// Directory count, extent, record or ZIP64 field is inconsistent.
    Directory,
    /// A variable record or checked arithmetic exceeds its original enclosure.
    Bounds,
    /// A required local file header or descriptor cannot be interpreted.
    Local,
}

/// A configured cumulative mechanism allowance was exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Original member catalogue admissions.
    Entries,
    /// Cumulative decoded output, including failed envelopes.
    Decoded,
}

/// Processing refused before a successful complete result could be returned.
#[derive(Debug)]
pub enum Error<E> {
    /// Original acquisition, snapshot or current/source execution refusal.
    Input(InputError<E>),
    /// Current execution or actual-capacity refusal before work.
    Resource {
        /// Physical original enclosure of the attempted operation.
        range: Span,
        /// Unchanged refusal cause.
        cause: MemoryError,
    },
    /// A cumulative mechanism allowance refused the next operation.
    Limit {
        /// Physical original enclosure.
        range: Span,
        /// Exhausted allowance.
        kind: Limit,
    },
    /// No unambiguous structural reading is available.
    Syntax {
        /// Physical original enclosure.
        range: Span,
        /// Original structural cause.
        kind: Syntax,
    },
    /// The operation requires an unavailable ZIP capability.
    Unsupported {
        /// Physical original enclosure.
        range: Span,
        /// Exact unavailable capability.
        kind: Unsupported,
    },
    /// A member, receipt or input belongs to another original archive view.
    Foreign {
        /// Actual attempted enclosure, without an invented inner position.
        range: Span,
    },
}

/// Unsupported capabilities never masquerade as successful empty content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// Multi-volume source acquisition is outside the single-source contract.
    Volumes,
    /// The directory or member is encrypted.
    Encryption,
    /// Exact unimplemented compression method.
    Compression(u16),
    /// Central-directory compression/encryption profile.
    DirectoryVersion(u16),
}

impl<E> From<InputError<E>> for Error<E> {
    fn from(cause: InputError<E>) -> Self {
        Self::Input(cause)
    }
}

pub(crate) fn syntax<E>(range: Span, kind: Syntax) -> Error<E> {
    Error::Syntax { range, kind }
}

pub(crate) fn resource<E>(range: Span, cause: MemoryError) -> Error<E> {
    Error::Resource { range, cause }
}
