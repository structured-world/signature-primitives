//! Paid PDF name/string decoding without canonicalizing signed source bytes.

use crate::byte_machine::{Decoder, Step};
use crate::error::{Error, ErrorKind, Result, Syntax};
use crate::source::Location;
use core::cmp::Ordering;
use structured_asn1::memory::{OwnedVec, Work};

/// PDF spelling of a byte value, excluding its outer delimiters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// Name bytes after the leading slash; valid #xx escapes denote one byte.
    Name,
    /// Literal string bytes between parentheses, with PDF escapes and EOL rules.
    Literal,
    /// Hexadecimal string bytes between angle brackets, including whitespace.
    Hexadecimal,
}

/// Original encoded body and its exact source location. This is an inspection
/// input, not an assertion that its enclosing PDF object or signature is valid.
#[derive(Debug, Clone, Copy)]
pub struct Bytes<'a> {
    raw: &'a [u8],
    form: Form,
    location: Location,
}

impl<'a> Bytes<'a> {
    /// Associates an original body with an equal-length source range without
    /// traversal or allocation. Syntax is checked by the paid decoding methods.
    pub fn new(raw: &'a [u8], form: Form, location: Location) -> Result<Self> {
        if location.span().length != raw.len() as u64 {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            });
        }
        Ok(Self {
            raw,
            form,
            location,
        })
    }

    /// Unmodified original body, not a decoded or re-encoded signature input.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.raw
    }

    /// Original byte range and its coordinate domain.
    #[must_use]
    pub fn location(self) -> Location {
        self.location
    }

    /// Decodes under the current work/account. Actual allocated capacity stays
    /// charged for the returned owner's lifetime; refusal drops partial output.
    pub fn decode_in<W: Work>(self, work: &W) -> Result<OwnedVec<u8, W>> {
        let mut cursor = Cursor::new(self);
        let mut out = work.vector();
        while let Some(byte) = cursor.next(work)? {
            out.try_push(byte).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: cursor.point(),
            })?;
        }
        Ok(out)
    }

    /// Streaming decoded equality, without a scratch allocation or an
    /// infallible `PartialEq` traversal. Each original byte is paid before read.
    pub fn matches_in(self, other: Self, work: &impl Work) -> Result<bool> {
        Ok(self.compare_in(other, work)? == Ordering::Equal)
    }

    /// Lexicographic decoded byte order, using the same streaming kernel as
    /// equality. Neither case folding nor text normalization is performed.
    pub fn compare_in(self, other: Self, work: &impl Work) -> Result<Ordering> {
        let mut left = Cursor::new(self);
        let mut right = Cursor::new(other);
        loop {
            match (left.next(work)?, right.next(work)?) {
                (None, None) => return Ok(Ordering::Equal),
                (Some(a), Some(b)) if a == b => {}
                (None, Some(_)) => return Ok(Ordering::Less),
                (Some(_), None) => return Ok(Ordering::Greater),
                (Some(a), Some(b)) => return Ok(a.cmp(&b)),
            }
        }
    }

    /// Compares a PDF name/string with already decoded caller bytes. Caller
    /// bytes are admitted before comparison as well; mismatches stop the scan.
    pub fn equals_in(self, expected: &[u8], work: &impl Work) -> Result<bool> {
        let mut cursor = Cursor::new(self);
        let mut index = 0;
        while let Some(byte) = cursor.next(work)? {
            work.charge_work(1).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: cursor.point(),
            })?;
            if expected.get(index) != Some(&byte) {
                return Ok(false);
            }
            index += 1;
        }
        Ok(index == expected.len())
    }
}

struct Cursor<'a> {
    value: Bytes<'a>,
    index: usize,
    decoder: Decoder,
}

impl<'a> Cursor<'a> {
    fn new(value: Bytes<'a>) -> Self {
        Self {
            value,
            index: 0,
            decoder: Decoder::new(value.form),
        }
    }

    fn point(&self) -> Location {
        // Both the body range and this bounded cursor were checked at entry.
        Location::new(
            self.value.location.source(),
            self.value.location.span().start + self.index as u64,
            0,
        )
        .expect("a point inside the checked original body")
    }

    fn malformed(&self) -> Error {
        Error {
            kind: ErrorKind::Syntax(match self.value.form {
                Form::Name => Syntax::Name,
                Form::Literal | Form::Hexadecimal => Syntax::String,
            }),
            location: self.point(),
        }
    }

    fn next(&mut self, work: &impl Work) -> Result<Option<u8>> {
        loop {
            let input = if self.index < self.value.raw.len() {
                work.charge_work(1).map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: self.point(),
                })?;
                Some(self.value.raw[self.index])
            } else {
                None
            };
            match self.decoder.step(input) {
                Step::More => {
                    debug_assert!(input.is_some());
                    self.index += 1;
                }
                Step::Byte { value, consumed } => {
                    if consumed {
                        self.index += 1;
                    }
                    return Ok(Some(value));
                }
                Step::End => return Ok(None),
                Step::Malformed => {
                    if input.is_some() {
                        self.index += 1;
                    }
                    return Err(self.malformed());
                }
            }
        }
    }
}

pub(crate) const fn is_space(byte: u8) -> bool {
    matches!(byte, 0 | 9 | 10 | 12 | 13 | 32)
}
