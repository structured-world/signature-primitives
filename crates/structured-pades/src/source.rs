//! Honest physical and decoded coordinates, without fabricated file offsets.

use core::num::NonZeroUsize;
use structured_asn1::Span;

/// The domain in which a byte range has meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Original unmodified PDF file bytes.
    File,
    /// Logical bytes of one decoded PDF value, such as an object stream or
    /// signature string. Its original physical enclosure and the revision
    /// that selected the decoding remain available independently.
    Decoded {
        /// Original physical encoded data, not the logical object's span.
        stream: Span,
        /// Revision whose stream-control objects selected this decoding.
        revision: usize,
        /// Zero identifies the final decoded value. A positive ordinal
        /// identifies an intermediate filter input, preserving its distinct
        /// logical offsets without claiming a physical byte projection.
        stage: usize,
    },
}

/// A range paired with its actual coordinate domain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Location {
    // A real revision is an index into a nonempty owning collection, so its
    // index plus one is representable. The zero niche denotes physical bytes.
    revision: Option<NonZeroUsize>,
    stream: Span,
    stage: usize,
    span: Span,
}

impl core::fmt::Debug for Location {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        output
            .debug_struct("Location")
            .field("source", &self.source())
            .field("span", &self.span)
            .finish_non_exhaustive()
    }
}

impl Location {
    /// Checks range arithmetic before admitting a source location.
    #[must_use]
    pub fn new(source: Source, start: u64, length: u64) -> Option<Self> {
        start.checked_add(length)?;
        let (revision, stream, stage) = match source {
            Source::File => (
                None,
                Span {
                    start: 0,
                    length: 0,
                },
                0,
            ),
            Source::Decoded {
                stream,
                revision,
                stage,
            } => {
                stream.start.checked_add(stream.length)?;
                (
                    Some(NonZeroUsize::new(revision.checked_add(1)?)?),
                    stream,
                    stage,
                )
            }
        };
        Some(Self {
            revision,
            stream,
            stage,
            span: Span { start, length },
        })
    }

    /// Exact original coordinate domain.
    #[must_use]
    pub fn source(self) -> Source {
        match self.revision {
            None => Source::File,
            Some(revision) => Source::Decoded {
                stream: self.stream,
                revision: revision.get() - 1,
                stage: self.stage,
            },
        }
    }

    /// Range in [`Self::source`], never implicitly a physical file span.
    #[must_use]
    pub fn span(self) -> Span {
        self.span
    }

    /// Physical enclosing range. For a decoded value this deliberately returns
    /// the encoded stream, not a guessed one-to-one projection.
    #[must_use]
    pub fn enclosing(self) -> Span {
        if self.revision.is_some() {
            self.stream
        } else {
            self.span
        }
    }

    /// End in this source domain; construction already checked overflow.
    #[must_use]
    pub fn end(self) -> u64 {
        self.span.start + self.span.length
    }

    /// Whether a point belongs to this half-open range.
    #[must_use]
    pub fn contains(self, offset: u64) -> bool {
        offset >= self.span.start && offset < self.end()
    }
}

#[cfg(test)]
mod tests;
