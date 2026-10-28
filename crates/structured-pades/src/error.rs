//! Located syntax, ambiguity, unsupported capability and processing refusals.

use crate::source::Location;
use core::fmt;
use structured_asn1::memory::MemoryError;

/// A concrete PDF grammar or document-structure violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// Missing or malformed file header.
    Header,
    /// Unexpected token for the selected grammar.
    Token,
    /// Value or delimiter extends beyond its original source.
    End,
    /// Invalid integer or real spelling.
    Number,
    /// Invalid name escape or forbidden zero byte.
    Name,
    /// Invalid literal or hexadecimal string.
    String,
    /// Invalid dictionary entry or conflicting duplicate key.
    Dictionary,
    /// Invalid stream extent, encoding or decoding parameters.
    Stream,
    /// Invalid indirect object definition or reference identity.
    Object,
    /// Invalid cross-reference section or object location.
    CrossReference,
    /// Invalid terminal startxref record.
    StartXref,
    /// Invalid document trailer.
    Trailer,
    /// The carried signature container has the wrong format or extent.
    Container,
    /// Reference or cross-reference chain returns to itself.
    Cycle,
}

/// Caller-selected mechanism limit, separate from malformed syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Container or resolution nesting limit.
    Depth,
    /// Cumulative original and decoded object count.
    Objects,
    /// Cumulative revision count.
    Revisions,
    /// Cumulative decoded output allowance.
    Decoded,
}

/// An explicitly unavailable processing capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// Requested stream filter has no selected structural decoder.
    Filter,
    /// External stream bytes were not supplied by a caller.
    ExternalStream,
    /// Required encrypted source bytes are unavailable.
    Encryption,
    /// A number cannot be represented for this particular query.
    NumericRange,
}

/// Independent failure classes; processing causes cannot become syntax faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Unreadable syntax with its actual domain and range.
    Syntax(Syntax),
    /// Two incompatible readings; selecting the first would lose meaning.
    Ambiguous(Syntax),
    /// Caller-selected resource count exhausted before the operation.
    Limit(Limit),
    /// Actual shared allocator, capacity, or current/source work refusal.
    Resource(MemoryError),
    /// Required capability is explicitly unavailable.
    Unsupported(Unsupported),
    /// A caller mixed source/session/document identities.
    Foreign,
}

/// Failure preserving both logical coordinates and honest physical enclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// Original failure classification and cause.
    pub kind: ErrorKind,
    /// Original range, with its source discriminator.
    pub location: Location,
}
impl Error {
    /// Processing and source misuse cannot become a recoverable syntax slot.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::Limit(_) | ErrorKind::Resource(_) | ErrorKind::Foreign
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{:?} at {:?}", self.kind, self.location)
    }
}

impl core::error::Error for Error {}

/// Recoverable original format fault, never an allocator/work/processing cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    /// Specific readable format violation.
    pub code: Syntax,
    /// Original source location.
    pub location: Location,
}

/// Result of a PDF mechanism operation.
pub type Result<T> = core::result::Result<T, Error>;

/// A format operation may fail independently in PDF processing or in the
/// caller's asynchronous source. Opaque causes are never syntax diagnostics.
#[derive(Debug)]
pub enum ReadFailure<E> {
    /// Original located PDF syntax, ambiguity, resource or capability cause.
    Format(Error),
    /// Original source snapshot/acquisition/resource cause and range.
    Input(crate::range::InputError<E>),
}
impl<E> ReadFailure<E> {
    /// Opaque acquisition, resource and source-identity refusals are terminal.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Format(cause) => cause.is_terminal(),
            Self::Input(_) => true,
        }
    }
}

impl<E> From<Error> for ReadFailure<E> {
    fn from(error: Error) -> Self {
        Self::Format(error)
    }
}

impl<E> From<crate::range::InputError<E>> for ReadFailure<E> {
    fn from(error: crate::range::InputError<E>) -> Self {
        Self::Input(error)
    }
}
