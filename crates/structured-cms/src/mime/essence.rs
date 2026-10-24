//! Known type/subtype comparisons inside the existing incremental grammar.

use super::{Head, Syntax};
use structured_asn1::memory::{MemoryError, Work};

struct Pattern<'a> {
    media_type: &'a [u8],
    subtype: &'a [u8],
    matches: bool,
}

impl Pattern<'_> {
    fn compare(remaining: &mut &[u8], matches: &mut bool, byte: u8) {
        if !*matches {
            return;
        }
        if remaining.is_empty() {
            *matches = false;
            return;
        }
        if !remaining[0].eq_ignore_ascii_case(&byte) {
            *matches = false;
        }
        *remaining = &remaining[1..];
    }
}

impl<const N: usize> Head for [Pattern<'_>; N] {
    fn cost(&self) -> Result<u64, MemoryError> {
        u64::try_from(N)
            .ok()
            .and_then(|count| count.checked_mul(2))
            .ok_or(MemoryError::WorkExceeded)
    }
    fn type_byte(&mut self, byte: u8) {
        for pattern in self {
            Pattern::compare(&mut pattern.media_type, &mut pattern.matches, byte);
        }
    }
    fn subtype_byte(&mut self, byte: u8) {
        for pattern in self {
            Pattern::compare(&mut pattern.subtype, &mut pattern.matches, byte);
        }
    }
}

/// One incremental MIME grammar pass and fixed, allocation-free comparisons
/// against known type/subtype pairs. Parameters remain syntax-checked but do
/// not participate in this comparison. This is not full MIME-value equality.
///
/// RFC2045 §§2 and 5.1: type/subtype are case-insensitive; comments and linear
/// whitespace separate tokens. Token fragments cannot be joined across CFWS.
/// <https://www.rfc-editor.org/rfc/rfc2045.html#section-5.1>
pub struct Essences<'a, const N: usize, const XML_NORMALIZED: bool = false> {
    syntax: Syntax<XML_NORMALIZED>,
    patterns: [Pattern<'a>; N],
}

impl<'a, const N: usize, const XML_NORMALIZED: bool> Essences<'a, N, XML_NORMALIZED> {
    /// Borrows the caller's known pairs without allocation or registration
    /// lookup. The number of pairs is a compile-time mechanism parameter.
    #[must_use]
    pub fn new(patterns: [(&'a str, &'a str); N]) -> Self {
        Self {
            syntax: Syntax::new(),
            patterns: patterns.map(|(media_type, subtype)| Pattern {
                media_type: media_type.as_bytes(),
                subtype: subtype.as_bytes(),
                matches: true,
            }),
        }
    }

    /// Admits grammar and all comparison work before consuming this fragment.
    /// A refusal leaves both syntax and comparisons unchanged.
    pub fn feed<W: Work>(
        &mut self,
        bytes: impl AsRef<[u8]>,
        work: &W,
    ) -> Result<bool, MemoryError> {
        self.syntax.scan(bytes.as_ref(), work, &mut self.patterns)
    }

    /// Whether the entire original input is a complete MIME value.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.syntax.complete()
    }

    /// Compares a known pair only if the complete original grammar succeeded.
    /// None denotes an out-of-range caller index, not a missing media type.
    #[must_use]
    pub fn matches(&self, index: usize) -> Option<bool> {
        self.patterns.get(index).map(|pattern| {
            self.complete()
                && pattern.matches
                && pattern.media_type.is_empty()
                && pattern.subtype.is_empty()
        })
    }
}
