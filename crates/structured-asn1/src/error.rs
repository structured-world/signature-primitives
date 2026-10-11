//! What went wrong, where, and under which element.
//!
//! An error carries a stable code, an offset and a path of element indices,
//! and never bytes from the document: these values travel into diagnostics
//! that leave the device when somebody sends feedback.

use crate::memory::{Memory, MemoryError, OwnedVec};
use core::fmt;

/// Why a parse stopped.
///
/// Malformed input is a statement about the bytes. A spent budget is a
/// statement about this run, and the two must not be confused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The element claims more bytes than the enclosing element has left.
    UnexpectedEnd,
    /// A tag number was encoded with a leading zero byte, or does not end.
    MalformedTag,
    /// A tag number too large to represent.
    TagTooLarge,
    /// A definite length was not encoded in the fewest bytes DER allows.
    LengthNotMinimal,
    /// A length too large to represent as an offset on this target.
    LengthTooLarge,
    /// An offset that would not fit, given where this window starts.
    OffsetTooLarge,
    /// An indefinite length where the schema requires a definite one.
    IndefiniteLengthNotAllowed,
    /// An indefinite-length element that never reached its end-of-contents.
    UnterminatedContents,
    /// End-of-contents was encoded with a non-zero length.
    MalformedEndOfContents,
    /// A primitive element encoded as constructed, or the reverse.
    WrongConstruction,
    /// The element is not the one the schema asked for.
    UnexpectedTag,
    /// An integer with a redundant leading `0x00` or `0xff` byte.
    IntegerNotMinimal,
    /// An integer with no content bytes at all.
    IntegerEmpty,
    /// An object identifier that is empty, ends mid-arc, or pads an arc.
    MalformedOid,
    /// A bit string with no count of padding bits, a count above seven, or,
    /// under DER, padding bits that are not zero.
    MalformedBitString,
    /// A boolean of the wrong length, or, under DER, a true that is not `0xff`.
    MalformedBoolean,
    /// A null with contents.
    MalformedNull,
    /// A real whose octets are not a value of the type: a reserved base or
    /// number representation, a part written in more octets than it needs,
    /// or a mantissa the normalization forbids.
    MalformedReal,
    /// The work this input asks for is more than the caller allowed.
    ///
    /// Distinct from every code above on purpose: nothing is wrong with the
    /// input, and reporting it as malformed would tell somebody their document
    /// is broken when the truth is that this device declined to finish.
    LimitExceeded(Limit),
    /// The allocator could not supply storage, independently of configured limits.
    AllocatorExhausted,
    /// A requested allocation's capacity cannot be represented on this target.
    CapacityOverflow,
}

/// Which budget ran out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limit {
    /// Elements nested more deeply than allowed.
    Depth,
    /// More elements than allowed, across the whole parse.
    Elements,
    /// A single element longer than allowed.
    ElementLength,
    /// More input examined than allowed.
    Work,
    /// Aggregate live allocation capacity, including replacement peaks.
    Memory,
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Depth => "nesting depth",
            Self::Elements => "element count",
            Self::ElementLength => "element length",
            Self::Work => "work",
            Self::Memory => "memory",
        })
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => {
                f.write_str("element runs past the end of the one containing it")
            }
            Self::MalformedTag => f.write_str("malformed tag number"),
            Self::TagTooLarge => f.write_str("tag number too large"),
            Self::LengthNotMinimal => f.write_str("length not encoded in the fewest bytes"),
            Self::LengthTooLarge => f.write_str("length too large"),
            Self::OffsetTooLarge => f.write_str("offset too large for this window"),
            Self::IndefiniteLengthNotAllowed => f.write_str("indefinite length not allowed here"),
            Self::UnterminatedContents => f.write_str("indefinite length never terminated"),
            Self::MalformedEndOfContents => f.write_str("end-of-contents with a length"),
            Self::WrongConstruction => {
                f.write_str("primitive and constructed are the wrong way round")
            }
            Self::UnexpectedTag => f.write_str("not the element expected here"),
            Self::IntegerNotMinimal => f.write_str("integer has a redundant leading byte"),
            Self::IntegerEmpty => f.write_str("integer has no content"),
            Self::MalformedOid => f.write_str("malformed object identifier"),
            Self::MalformedBitString => f.write_str("malformed bit string"),
            Self::MalformedBoolean => f.write_str("malformed boolean"),
            Self::MalformedNull => f.write_str("null with contents"),
            Self::MalformedReal => f.write_str("malformed real"),
            Self::LimitExceeded(limit) => write!(f, "{limit} budget spent"),
            Self::AllocatorExhausted => f.write_str("allocator could not supply storage"),
            Self::CapacityOverflow => f.write_str("storage capacity overflow"),
        }
    }
}

/// Where in the structure an error was found: the index of each element
/// entered, outermost first.
///
/// Indices rather than names, because this layer does not know the schema. A
/// caller that does can turn `[0, 2, 1]` into something a person reads. What it
/// deliberately does not hold is any part of the document.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Path {
    indices: Option<OwnedVec<u32>>,
    unavailable: Option<MemoryError>,
}

impl Path {
    /// The indices, outermost first.
    #[must_use]
    pub fn indices(&self) -> &[u32] {
        self.indices.as_deref().unwrap_or(&[])
    }

    /// Whether this is the top level.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.unavailable.is_none() && self.indices().is_empty()
    }

    /// Why the full path could not be retained; None means the path is complete.
    #[must_use]
    pub fn unavailable(&self) -> Option<MemoryError> {
        self.unavailable
    }

    pub(crate) fn missing(reason: MemoryError) -> Self {
        Self {
            indices: None,
            unavailable: Some(reason),
        }
    }

    pub(crate) fn try_copy_in(&self, memory: &Memory) -> core::result::Result<Self, MemoryError> {
        Ok(Self {
            indices: match &self.indices {
                Some(indices) => {
                    let mut copy = memory.vector();
                    copy.try_extend_from_slice(indices)?;
                    Some(copy)
                }
                None => None,
            },
            unavailable: self.unavailable,
        })
    }

    pub(crate) fn push(
        &mut self,
        memory: &Memory,
        index: u32,
    ) -> core::result::Result<(), MemoryError> {
        self.indices
            .get_or_insert_with(|| memory.vector())
            .try_push(index)
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(reason) = self.unavailable {
            return write!(f, "path unavailable: {reason}");
        }
        if self.indices().is_empty() {
            return f.write_str("/");
        }
        for index in self.indices() {
            write!(f, "/{index}")?;
        }
        Ok(())
    }
}

/// A parse that stopped, and enough to say where without quoting the input.
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    offset: u64,
    path: Path,
}

impl Error {
    pub(crate) fn new(code: ErrorCode, offset: u64, path: Path) -> Self {
        Self { code, offset, path }
    }

    /// An allocation-free resource failure, with an explicitly unavailable path.
    #[must_use]
    pub fn resource(reason: MemoryError, offset: u64) -> Self {
        Self::new(ErrorCode::from(reason), offset, Path::missing(reason))
    }

    /// Why the parse stopped.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The offset in the document where the trouble is, counted from the start
    /// of the whole document rather than of the slice being read.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Which element it was under.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this run declined to finish rather than the input being wrong.
    #[must_use]
    pub fn is_limit(&self) -> bool {
        // X.690 §8.1.2.4.2 does not bound the tag number; our absolute header
        // ceiling declines processing rather than declaring the input invalid.
        // https://www.itu.int/rec/T-REC-X.690-202102-I/en
        matches!(
            self.code,
            ErrorCode::LimitExceeded(_) | ErrorCode::TagTooLarge
        )
    }

    /// Whether resource exhaustion, rather than malformed input, stopped this run.
    #[must_use]
    pub fn is_resource(&self) -> bool {
        self.is_limit()
            || matches!(
                self.code,
                ErrorCode::AllocatorExhausted | ErrorCode::CapacityOverflow
            )
    }
}

impl From<MemoryError> for ErrorCode {
    fn from(reason: MemoryError) -> Self {
        match reason {
            MemoryError::LimitExceeded => Self::LimitExceeded(Limit::Memory),
            MemoryError::WorkExceeded => Self::LimitExceeded(Limit::Work),
            MemoryError::OutOfMemory => Self::AllocatorExhausted,
            MemoryError::CapacityOverflow => Self::CapacityOverflow,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {} ({})", self.code, self.offset, self.path)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// The result of reading one thing.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests;
