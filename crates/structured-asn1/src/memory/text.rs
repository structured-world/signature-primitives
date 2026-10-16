//! Independently retained UTF-8 over an existing accounted buffer.

use super::{HashWork, Memory, MemoryError, OwnedVec, Work, allocator::ValidatedText};
use core::{
    borrow::Borrow,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
    str::Utf8Error,
};

/// Why an existing byte buffer could not become immutable UTF-8 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextErrorKind {
    /// Work admission refused before UTF-8 validation began.
    Resource(MemoryError),
    /// Admitted validation found invalid UTF-8, relative to the original bytes.
    Utf8(Utf8Error),
}

/// Failed text construction retaining the unchanged original buffer.
///
/// Consumed work is not refunded. Storage remains charged until the recovered
/// buffer or this error is dropped; failure never copies or reallocates it.
pub struct TextError<W: Work = Memory> {
    kind: TextErrorKind,
    bytes: OwnedVec<u8, W>,
}

impl<W: Work> TextError<W> {
    /// The original resource or UTF-8 cause, without inspecting bytes.
    #[must_use]
    pub fn kind(&self) -> TextErrorKind {
        self.kind
    }

    /// Recovers the original pointer, initialized bytes, capacity and account.
    #[must_use]
    pub fn into_bytes(self) -> OwnedVec<u8, W> {
        self.bytes
    }
}

impl<W: Work> fmt::Debug for TextError<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TextError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Single-owner validated UTF-8 retaining its original capacity charge.
///
/// Construction from bytes validates once under their execution before closing
/// raw mutable access. Construction from a `str` copies its already validated
/// bytes. Exclusive [`Self::try_push_str`] appends preserve UTF-8 without
/// revalidating the accumulated prefix.
/// No reference count, extra allocation or unsafe thread-safety implementation
/// is introduced. The default owned [`Memory`] form is `Send + Sync`; scoped
/// forms retain their execution's actual lifetime and thread-safety bounds.
/// Views are O(1); callers fund their own hashing, equality, formatting and
/// traversal. [`HashWork`] supports paid [`super::OwnedMap`] lookups by `str`.
///
/// ```
/// use std::sync::Arc;
/// use structured_asn1::memory::{Memory, MemoryAccount, OwnedText};
/// let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
/// let mut bytes = memory.vector();
/// bytes.try_extend_from_slice("retained 🦀".as_bytes())?;
/// let text = OwnedText::from_utf8(bytes).unwrap();
/// assert_eq!(text.as_str(), "retained 🦀");
/// drop(text);
/// assert_eq!(memory.used(), 0);
/// # Ok::<(), structured_asn1::memory::MemoryError>(())
/// ```
///
/// The invariant cannot be invalidated while a string view exists:
/// ```compile_fail
/// use structured_asn1::memory::OwnedText;
/// fn invalidate(text: OwnedText) {
///     let view = text.as_str();
///     let mut bytes = text.into_bytes();
///     bytes[0] = 0xff;
///     println!("{view}");
/// }
/// ```
pub struct OwnedText<W: Work = Memory> {
    text: ValidatedText<W>,
}

impl<W: Work> OwnedText<W> {
    /// Validates and takes ownership without copying or changing capacity.
    ///
    /// Admission pays the full initialized byte length before the first byte is
    /// examined, against the vector's original local and aggregate ceilings.
    /// Both failure classes return the unchanged vector through [`TextError`].
    pub fn from_utf8(bytes: OwnedVec<u8, W>) -> Result<Self, TextError<W>> {
        ValidatedText::from_utf8(bytes)
            .map(|text| Self { text })
            .map_err(|(kind, bytes)| TextError { kind, bytes })
    }

    /// Copies valid UTF-8 using the existing accounted allocation/copy path.
    /// No validation scan is needed because the input is already a `str`.
    pub fn try_from_str(text: &str, execution: &W) -> Result<Self, MemoryError> {
        Ok(Self {
            text: ValidatedText::from_str(text, execution)?,
        })
    }

    /// Appends valid UTF-8 under this owner's original execution.
    ///
    /// Admits copying the suffix and any actual capacity growth before mutation.
    /// The existing prefix is not validated again; growth alone can require
    /// moving it. Spare capacity still requires paying for the suffix copy.
    /// On refusal the original bytes, pointer, capacity and storage charge remain
    /// intact. Consumed work is not refunded. Empty suffixes require no work.
    ///
    /// Existing views must end before this exclusive mutation:
    /// ```compile_fail
    /// use structured_asn1::memory::OwnedText;
    /// fn append(text: &mut OwnedText) {
    ///     let view = text.as_str();
    ///     text.try_push_str("suffix").unwrap();
    ///     println!("{view}");
    /// }
    /// ```
    pub fn try_push_str(&mut self, suffix: &str) -> Result<(), MemoryError> {
        self.text.try_push_str(suffix)
    }

    /// Prepares space for at least `additional` more UTF-8 bytes.
    ///
    /// Uses the existing vector's exact reservation strategy, without changing
    /// length, scanning the prefix or adding amortized spare capacity. Actual
    /// growth and its old/new storage peak use this owner's original execution.
    /// Refusal preserves initialized bytes, pointer, capacity and storage charge;
    /// consumed work is not refunded. Sufficient capacity requires no work.
    pub fn try_reserve_exact(&mut self, additional: usize) -> Result<(), MemoryError> {
        self.text.try_reserve_exact(additional)
    }

    /// The original account retaining this allocation.
    #[must_use]
    pub fn memory(&self) -> &Memory {
        self.text.bytes().memory()
    }

    /// The initialized UTF-8 byte length, without traversal.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.bytes().len()
    }

    /// Whether the text contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.bytes().is_empty()
    }

    /// Allocated byte capacity, including retained spare capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.text.bytes().capacity()
    }

    /// Borrows immutable initialized bytes; callers admit subsequent traversal.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.text.bytes()
    }

    /// Borrows validated immutable UTF-8 in O(1), without scanning or copying.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }

    /// Finishes construction by moving the existing buffer's account keeper.
    /// No copy, validation, allocation, work or capacity change occurs.
    #[must_use]
    pub fn into_owned(self) -> OwnedText {
        OwnedText {
            text: self.text.into_owned(),
        }
    }

    /// Recovers mutable bytes by consuming the text, ending its UTF-8 invariant.
    /// Existing borrowed views must have ended before this move is possible.
    #[must_use]
    pub fn into_bytes(self) -> OwnedVec<u8, W> {
        self.text.into_bytes()
    }
}

impl<W: Work> fmt::Debug for OwnedText<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl<W: Work> Deref for OwnedText<W> {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl<W: Work> Borrow<str> for OwnedText<W> {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl<W: Work> AsRef<str> for OwnedText<W> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<W: Work> fmt::Display for OwnedText<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<W: Work, V: Work> PartialEq<OwnedText<V>> for OwnedText<W> {
    fn eq(&self, other: &OwnedText<V>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<W: Work> Eq for OwnedText<W> {}

impl<W: Work> Hash for OwnedText<W> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl<W: Work> HashWork for OwnedText<W> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        (self.len() as u64)
            .checked_add(1)
            .ok_or(MemoryError::WorkExceeded)
    }
}
