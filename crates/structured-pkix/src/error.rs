//! What was wrong with a certificate, and which field it was in.
//!
//! The reader below this one reports a path of element indices, because it does
//! not know the schema. This crate does know it, so it reports the field by
//! name: `tbsCertificate.validity.notAfter` says the same thing as `/0/4/1` and
//! says it to a person. Neither carries bytes from the document.

use core::fmt;

mod callback;
pub use callback::{CallbackError, CallbackResult};

/// Why a certificate could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The bytes are not the encoding the schema asks for here.
    Encoding(structured_asn1::ErrorCode),
    /// A field the schema requires is absent.
    MissingField,
    /// A field is present that this version of the structure does not have.
    UnexpectedField,
    /// Bytes after the end of a structure that should have used all of them.
    TrailingData,
    /// A sequence that must hold at least one member holds none.
    EmptySequence,
    /// The same extension appears more than once, leaving no answer to which
    /// of them applies.
    DuplicateExtension,
    /// A time that is not the fixed-width form with seconds and `Z` that
    /// certificates are required to use.
    MalformedTime,
    /// A time whose fields name a moment that does not exist.
    TimeOutOfRange,
    /// A version number this crate does not know.
    UnsupportedVersion,
    /// An RFC 4514 attribute requires unavailable syntax or equality semantics.
    UnsupportedNameSyntax,
    /// The algorithm named outside the signed bytes is not the one named
    /// inside them.
    AlgorithmMismatch,
    /// A value the schema constrains further than its encoding does.
    MalformedValue,
    /// A value too large for the type this crate represents it in.
    ValueTooLarge,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(code) => write!(f, "{code}"),
            Self::MissingField => f.write_str("required field absent"),
            Self::UnexpectedField => f.write_str("field not part of this version"),
            Self::TrailingData => f.write_str("bytes left over"),
            Self::EmptySequence => f.write_str("sequence with no members"),
            Self::DuplicateExtension => f.write_str("extension appears more than once"),
            Self::MalformedTime => f.write_str("malformed time"),
            Self::TimeOutOfRange => f.write_str("time names a moment that does not exist"),
            Self::UnsupportedVersion => f.write_str("unknown version"),
            Self::UnsupportedNameSyntax => f.write_str("unsupported distinguished-name syntax"),
            Self::AlgorithmMismatch => {
                f.write_str("signed and unsigned algorithm identifiers differ")
            }
            Self::MalformedValue => f.write_str("value the schema does not allow"),
            Self::ValueTooLarge => f.write_str("value too large to represent"),
        }
    }
}

/// A certificate that could not be read, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    field: &'static str,
    offset: u64,
}

impl Error {
    /// A resource failure at the originating document offset, without allocation.
    #[must_use]
    pub fn resource(
        reason: structured_asn1::memory::MemoryError,
        field: &'static str,
        offset: u64,
    ) -> Self {
        Self::new(ErrorCode::Encoding(reason.into()), field, offset)
    }
    /// An error in a named field, at a known offset in the document.
    #[must_use]
    pub fn new(code: ErrorCode, field: &'static str, offset: u64) -> Self {
        Self {
            code,
            field,
            offset,
        }
    }

    /// Why it stopped.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The field of the schema, outermost first.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Where the trouble is, counted in the whole document.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Whether this run declined to finish rather than the certificate being
    /// wrong. A spent budget says nothing about the document, and reporting it
    /// as a broken certificate would tell somebody their document is damaged
    /// when the truth is that this device gave up.
    #[must_use]
    pub fn is_limit(&self) -> bool {
        matches!(
            self.code,
            ErrorCode::Encoding(
                structured_asn1::ErrorCode::LimitExceeded(_)
                    | structured_asn1::ErrorCode::TagTooLarge
            )
        )
    }

    /// Whether resource exhaustion stopped the run, including allocator failure.
    #[must_use]
    pub fn is_resource(&self) -> bool {
        self.is_limit()
            || matches!(
                self.code,
                ErrorCode::Encoding(
                    structured_asn1::ErrorCode::AllocatorExhausted
                        | structured_asn1::ErrorCode::CapacityOverflow
                )
            )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in {} at {}", self.code, self.field, self.offset)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// The result of reading one thing.
pub type Result<T> = core::result::Result<T, Error>;

/// Names the field an encoding error was found in.
pub(crate) trait Located<T> {
    /// Turns a reader error into one that says which field was being read.
    fn field(self, name: &'static str) -> Result<T>;
}

impl<T> Located<T> for core::result::Result<T, structured_asn1::Error> {
    fn field(self, name: &'static str) -> Result<T> {
        self.map_err(|error| Error::new(ErrorCode::Encoding(error.code()), name, error.offset()))
    }
}

/// Splits a fallible step inside a yes-or-no gate: a spent budget leaves as
/// the error it is, because it says the device gave up rather than anything
/// about the document, while any other failure answers that the value was not
/// understood.
pub(crate) fn gate<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.is_resource() => Err(error),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorCode, gate};

    #[test]
    fn a_tag_header_ceiling_survives_optional_field_probing() {
        // Refusing a wide header cannot make an optional value disappear.
        let error = Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::TagTooLarge),
            "extension",
            42,
        );
        assert!(error.is_limit());
        let result: super::Result<Option<()>> = gate(Err(error.clone()));
        assert_eq!(result.unwrap_err(), error);
    }

    #[test]
    fn allocator_failure_is_not_a_document_fault() {
        // Optional-field probing must propagate resource failures rather than
        // classify the field as absent or malformed when storage is unavailable.
        let error = Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::AllocatorExhausted),
            "extension",
            42,
        );
        let result: super::Result<Option<()>> = gate(Err(error.clone()));
        assert_eq!(result.unwrap_err(), error);
    }
}
