//! Located processing failures, retaining the original ASN.1 diagnostic.

use core::fmt;
use structured_asn1::memory::MemoryError;

/// A processing failure, distinct from a provider's signature answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// The producing ASN.1 reader refused the encoding or its resources.
    Encoding(structured_asn1::ErrorCode),
    /// A shared PKIX semantic or conformance mechanism refused.
    Pkix(structured_pkix::ErrorCode),
    /// An element has the wrong tag for the selected schema field.
    UnexpectedTag,
    /// The logical content length cannot be represented.
    LengthOverflow,
    /// A required schema component was not present.
    MissingField,
    /// A container includes an additional component beyond its schema.
    TrailingData,
    /// A required nonempty attribute collection is empty.
    EmptyAttributes,
    /// An attribute that requires one value holds none or several.
    AttributeCardinality,
    /// Another instance was written where the selected type requires uniqueness.
    DuplicateAttribute,
    /// Signed attribute encodings are not in DER SET OF order.
    AttributeOrder,
    /// The numeric schema version does not fit its representation.
    ValueTooLarge,
    /// The declared version disagrees with the encoded schema choices.
    VersionMismatch,
    /// `ContentInfo` selected a type other than the requested protocol schema.
    UnexpectedContentType,
    /// A DER SET OF catalogue is not ordered by original encodings.
    SetOrder,
    /// The content-type attribute disagrees with its enclosing signed content.
    ContentTypeMismatch,
    /// A recognized attribute is in a placement its protocol forbids.
    AttributePlacement,
    /// A recognized attribute value violates its selected type or profile syntax.
    AttributeSyntax,
    /// A fixed digest identity cannot produce the declared message-digest width.
    DigestWidth,
    /// The selected algorithm's identifier violates its own parameter syntax.
    AlgorithmSyntax,
    /// Protected algorithms disagree under the selected provider's full semantics.
    AlgorithmProtection,
    /// A request uses another provider, or lacks a stable selection owner.
    ProviderMismatch,
    /// A readable schema default was explicitly encoded where DER omits it.
    DefaultWritten,
    /// A bounded schema container has an unrecognized field.
    UnknownField,
    /// A field is repeated; readable identical recovery retains a fault.
    DuplicateField,
    /// Recognized fields were written outside their required SEQUENCE order.
    FieldOrder,
    /// A readable value violates the selected schema's scalar bounds.
    MalformedValue,
    /// The written protocol version has no implemented schema interpretation.
    UnsupportedVersion,
    /// A readable open encoding needs a schema-specific DER projection codec.
    UnsupportedEncoding,
    /// A caller supplied a location outside the reader's source window.
    InvalidLocation,
    /// A timestamp token has no signer or conflicting multiple signer values.
    SignerCount,
    /// Timestamp information was detached instead of carried in the token.
    DetachedContent,
    /// An additional timestamp signature was retained for readable inspection.
    ExtraSignature,
}

#[derive(Debug)]
enum Detail {
    Schema { code: ErrorCode, offset: u64 },
    Encoding(structured_asn1::Error),
    Pkix(structured_pkix::Error),
}

/// A source-located failure with independently retained diagnostic storage.
#[derive(Debug)]
pub struct Error {
    field: &'static str,
    detail: Detail,
}

impl Error {
    pub(crate) fn schema(code: ErrorCode, field: &'static str, offset: u64) -> Self {
        Self {
            field,
            detail: Detail::Schema { code, offset },
        }
    }

    pub(crate) fn encoding(source: structured_asn1::Error, field: &'static str) -> Self {
        Self {
            field,
            detail: Detail::Encoding(source),
        }
    }

    pub(crate) fn pkix(source: structured_pkix::Error) -> Self {
        Self {
            field: source.field(),
            detail: Detail::Pkix(source),
        }
    }

    pub(crate) fn resource(reason: MemoryError, field: &'static str, offset: u64) -> Self {
        Self::encoding(structured_asn1::Error::resource(reason, offset), field)
    }

    /// The processing failure category.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match &self.detail {
            Detail::Schema { code, .. } => *code,
            Detail::Encoding(source) => ErrorCode::Encoding(source.code()),
            Detail::Pkix(source) => ErrorCode::Pkix(source.code()),
        }
    }

    /// The schema field being processed.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// The original source position where processing refused.
    #[must_use]
    pub fn offset(&self) -> u64 {
        match &self.detail {
            Detail::Schema { offset, .. } => *offset,
            Detail::Encoding(source) => source.offset(),
            Detail::Pkix(source) => source.offset(),
        }
    }

    /// The original reader diagnostic, including any available path.
    #[must_use]
    pub fn encoding_source(&self) -> Option<&structured_asn1::Error> {
        match &self.detail {
            Detail::Encoding(source) => Some(source),
            _ => None,
        }
    }

    /// Whether processing refused resources rather than document syntax.
    #[must_use]
    pub fn is_resource(&self) -> bool {
        match &self.detail {
            Detail::Encoding(source) => source.is_resource(),
            Detail::Pkix(source) => source.is_resource(),
            Detail::Schema { .. } => false,
        }
    }

    /// An inspection recovery must abort instead of retaining a document fault.
    /// Resource refusals and a foreign producing reader are operation failures;
    /// neither can establish a malformed value, mismatch or successful absence.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.is_resource()
            || self.code() == ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
            || self.code() == ErrorCode::InvalidLocation
            || self.code() == ErrorCode::UnsupportedEncoding
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at {}: {:?}",
            self.field,
            self.offset(),
            self.code()
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.detail {
            Detail::Encoding(source) => Some(source),
            Detail::Pkix(source) => Some(source),
            Detail::Schema { .. } => None,
        }
    }
}

/// A fallible CMS processing operation.
pub type Result<T> = core::result::Result<T, Error>;
