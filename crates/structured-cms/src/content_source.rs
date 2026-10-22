//! Scoped decoding of carried encodings with explicit physical provenance.

use crate::{Error, ErrorCode, Octets, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Encoding, Reader, Span};

/// Coordinate system used by the scoped reader and its located diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coordinates {
    /// Original document offsets; a single fragment is borrowed directly.
    Original,
    /// Offsets into joined content starting at zero, excluding fragment headers.
    Logical,
}

#[derive(Debug)]
enum Ranges {
    One(Span),
    Many(OwnedVec<Span>),
}

/// Independently retained mapping from a scoped reader to the original bytes.
///
/// This owns only range metadata, never the temporary joined bytes. Keeping it
/// with a callback error preserves provenance after that temporary buffer and
/// its parser-bound view disappear. Projection uses the current query's work;
/// retained capacity remains charged to the original account.
#[derive(Debug)]
pub struct SourceMap {
    ranges: Ranges,
    carrier: Span,
    length: u64,
    empty_end: u64,
    field: &'static str,
}

impl SourceMap {
    /// Copies source metadata for an independently retained result/error.
    /// Capacity and copying are admitted by current work; neither source bytes
    /// nor parser/query references are kept. Original/Logical coordinates and
    /// physical fragment boundaries remain unchanged after either parser drops.
    pub fn try_copy_in<W: Work>(&self, work: &W) -> Result<Self> {
        let fail = |reason| Error::resource(reason, self.field, self.carrier.start);
        work.charge_work(1).map_err(fail)?;
        let ranges = match &self.ranges {
            Ranges::One(span) => Ranges::One(*span),
            Ranges::Many(spans) => {
                let mut copy = work.vector();
                copy.try_extend_from_slice(spans).map_err(fail)?;
                Ranges::Many(copy.into_owned())
            }
        };
        Ok(Self {
            ranges,
            carrier: self.carrier,
            length: self.length,
            empty_end: self.empty_end,
            field: self.field,
        })
    }

    pub(crate) fn of(
        content: &Octets<'_>,
        parent: &Reader<'_>,
        field: &'static str,
    ) -> Result<Self> {
        let ranges = if let [piece] = content.pieces() {
            Ranges::One(piece.span())
        } else {
            let execution = parent.execution();
            let refusal = |reason| Error::resource(reason, field, content.span().start);
            execution
                .charge_work(content.pieces().len() as u64)
                .map_err(refusal)?;
            let mut ranges = execution.vector();
            ranges
                .try_reserve_exact(content.pieces().len())
                .map_err(refusal)?;
            for piece in content.pieces() {
                ranges.try_push(piece.span()).map_err(refusal)?;
            }
            Ranges::Many(ranges.into_owned())
        };
        Ok(Self {
            ranges,
            carrier: content.span(),
            length: content.len() as u64,
            empty_end: content.content_span().end(),
            field,
        })
    }

    fn mapped(
        content: &Octets<'_>,
        parent: &Reader<'_>,
        field: &'static str,
        origin: &Self,
    ) -> Result<Self> {
        let work = parent.execution();
        let start = origin.project_offset(content.span().start, &work)?;
        let end = origin.project_offset(content.span().end(), &work)?;
        let empty_end = origin.project_offset(content.content_span().end(), &work)?;
        if origin.coordinates() == Coordinates::Original {
            // These already are physical positions in one original range.
            // Validate through the supplied context without allocating a map.
            return Self::of(content, parent, field);
        }
        let carrier = Span {
            start,
            length: end - start,
        };
        let refusal = |reason| Error::resource(reason, field, carrier.start);
        work.charge_work(content.pieces().len() as u64)
            .map_err(refusal)?;
        let mut ranges = work.vector();
        for piece in content.pieces() {
            origin.append_projection(piece.span(), &work, &mut ranges)?;
        }
        Ok(Self {
            ranges: Ranges::Many(ranges.into_owned()),
            carrier,
            length: content.len() as u64,
            empty_end,
            field,
        })
    }

    /// Whether located errors and element spans are physical or logical.
    #[must_use]
    pub fn coordinates(&self) -> Coordinates {
        match self.ranges {
            Ranges::One(_) => Coordinates::Original,
            Ranges::Many(_) => Coordinates::Logical,
        }
    }

    /// Honest physical enclosing range, not a claim of contiguous payload.
    #[must_use]
    pub fn carrier(&self) -> Span {
        self.carrier
    }

    fn ranges(&self) -> &[Span] {
        match &self.ranges {
            Ranges::One(span) => core::slice::from_ref(span),
            Ranges::Many(spans) => spans,
        }
    }

    fn logical_offset(&self, offset: u64) -> Result<u64> {
        match self.ranges {
            Ranges::One(span) if offset >= span.start && offset <= span.end() => {
                Ok(offset - span.start)
            }
            Ranges::Many(_) if offset <= self.length => Ok(offset),
            _ => Err(self.invalid()),
        }
    }

    fn invalid(&self) -> Error {
        Error::schema(ErrorCode::InvalidLocation, self.field, self.carrier.start)
    }

    fn admit(&self, execution: &impl Work) -> Result<()> {
        execution
            .charge_work(self.ranges().len() as u64)
            .map_err(|reason| Error::resource(reason, self.field, self.carrier.start))
    }

    fn point(&self, logical: u64) -> u64 {
        let mut base = 0;
        for span in self.ranges() {
            if logical < base + span.length {
                return span.start + logical - base;
            }
            base += span.length;
        }
        self.ranges()
            .last()
            .map_or(self.empty_end, |span| span.end())
    }

    /// Maps a reader offset to one original physical point.
    ///
    /// A fragment boundary belongs to the next nonempty fragment. EOF maps to
    /// the end of the last fragment, including a trailing empty fragment; an
    /// empty constructed value maps to its original contents end, before EOC.
    /// An out-of-window offset is terminal caller misuse, not document syntax.
    pub fn project_offset(&self, offset: u64, execution: &impl Work) -> Result<u64> {
        let logical = self.logical_offset(offset)?;
        self.admit(execution)?;
        Ok(self.point(logical))
    }

    /// Maps a reader range to its actual disjoint physical ranges.
    ///
    /// The returned capacity is accounted independently. No contiguous span is
    /// invented across fragment headers. A zero-length range yields one actual
    /// boundary point. Invalid endpoints are refused before work or allocation.
    pub fn project_span(&self, span: Span, execution: &impl Work) -> Result<OwnedVec<Span>> {
        let mut output = execution.vector();
        self.append_projection(span, execution, &mut output)?;
        Ok(output.into_owned())
    }

    fn append_projection<W: Work>(
        &self,
        span: Span,
        execution: &W,
        output: &mut OwnedVec<Span, W>,
    ) -> Result<()> {
        let end = span
            .start
            .checked_add(span.length)
            .ok_or_else(|| self.invalid())?;
        let start = self.logical_offset(span.start)?;
        let end = self.logical_offset(end)?;
        self.admit(execution)?;
        let refusal = |reason| Error::resource(reason, self.field, self.carrier.start);
        if start == end {
            output
                .try_push(Span {
                    start: self.point(start),
                    length: 0,
                })
                .map_err(refusal)?;
        } else {
            let mut base = 0;
            for original in self.ranges() {
                let next = base + original.length;
                let low = start.max(base);
                let high = end.min(next);
                if low < high {
                    output
                        .try_push(Span {
                            start: original.start + low - base,
                            length: high - low,
                        })
                        .map_err(refusal)?;
                }
                base = next;
            }
        }
        Ok(())
    }
}

/// Failure of a scoped carried-content operation.
#[derive(Debug)]
pub enum ContentError<E> {
    /// Admission or reader creation failed at the physical enclosing source.
    Processing(Error),
    /// Reader creation failed in the explicitly identified source coordinates.
    Decoding {
        /// Original reader failure, with its diagnostic storage unchanged.
        source: Error,
        /// Retained mapping identifying the reader's source coordinates.
        context: SourceMap,
    },
    /// The callback's opaque cause and its independently retained source context.
    ///
    /// The cause is not rewritten. Offsets produced by the supplied reader use
    /// `context.coordinates()`; callers can project their known error types
    /// inside the callback or afterwards through this retained context. Arbitrary
    /// callback errors need not have an inner location; `context.carrier()` is
    /// their honest physical enclosure. Projection refusal remains a separate
    /// terminal error and must not replace the original cause.
    Callback {
        /// The caller's unchanged error cause.
        source: E,
        /// Retained mapping for locations derived from the supplied reader.
        context: SourceMap,
    },
}

impl Octets<'_> {
    /// Decodes carried bytes without letting a temporary joined buffer escape.
    ///
    /// One fragment is borrowed; several are explicitly materialized. The
    /// original parser, carrying depth, cumulative local ceiling and current
    /// aggregate execution survive. `R` and `E` cannot borrow the scoped reader,
    /// model or joined bytes. Owned outputs must admit their own retained copies.
    /// Mapping metadata and joins are admitted before invoking the callback.
    /// The content must use original document coordinates. For content decoded
    /// inside a scoped mapped reader, use [`Self::with_nested_reader_mapped`].
    #[expect(
        clippy::result_large_err,
        reason = "the failure owns both the original cause and its source map; boxing would require another admitted allocation on the refusal path"
    )]
    pub fn with_nested_reader<R, E>(
        &self,
        parent: &Reader<'_>,
        encoding: Encoding,
        field: &'static str,
        callback: impl for<'scope> FnOnce(&mut Reader<'scope>, &SourceMap) -> core::result::Result<R, E>,
    ) -> core::result::Result<R, ContentError<E>> {
        self.nested(parent, encoding, field, None, callback)
    }

    /// Decodes content inside an existing source context, composing provenance.
    ///
    /// Supply the context that produced this content. Parent logical ranges are
    /// flattened to actual physical ranges before any callback; retained errors
    /// borrow neither the parent map nor its temporary buffer. Even a borrowed
    /// single piece can have disjoint physical provenance. The carrier is a
    /// physical enclosure including gaps, not a fabricated contiguous encoding.
    #[expect(
        clippy::result_large_err,
        reason = "retain original cause and source context without another allocation on refusal"
    )]
    pub fn with_nested_reader_mapped<R, E>(
        &self,
        parent: &Reader<'_>,
        source: &SourceMap,
        encoding: Encoding,
        field: &'static str,
        callback: impl for<'scope> FnOnce(&mut Reader<'scope>, &SourceMap) -> core::result::Result<R, E>,
    ) -> core::result::Result<R, ContentError<E>> {
        self.nested(parent, encoding, field, Some(source), callback)
    }

    #[expect(
        clippy::result_large_err,
        reason = "the owned source context must accompany its unchanged original cause"
    )]
    fn nested<R, E>(
        &self,
        parent: &Reader<'_>,
        encoding: Encoding,
        field: &'static str,
        origin: Option<&SourceMap>,
        callback: impl for<'scope> FnOnce(&mut Reader<'scope>, &SourceMap) -> core::result::Result<R, E>,
    ) -> core::result::Result<R, ContentError<E>> {
        if !core::ptr::eq(self.parser(), parent.parser()) {
            // Refuse before traversing the map. A mapped input has an honest
            // physical enclosure available in O(1), not a physical child offset.
            let at = origin.map_or(self.span().start, |source| source.carrier().start);
            return Err(ContentError::Processing(Error::pkix(
                structured_pkix::Error::new(structured_pkix::ErrorCode::ForeignReader, field, at),
            )));
        }
        let context = match origin {
            Some(origin) => SourceMap::mapped(self, parent, field, origin),
            None => SourceMap::of(self, parent, field),
        }
        .map_err(ContentError::Processing)?;
        let joined;
        let (bytes, base) = if let [piece] = self.pieces() {
            let base = if context.coordinates() == Coordinates::Original {
                piece.span().start
            } else {
                0
            };
            (piece.as_bytes(), base)
        } else {
            joined = self
                .copy_in(parent, field, context.carrier().start)
                .map_err(ContentError::Processing)?;
            (&*joined, 0)
        };
        let reader =
            self.parser()
                .read_nested_query_in(parent, bytes, base, encoding, self.outer_depth());
        let mut reader = match reader {
            Ok(reader) => reader,
            Err(source) => {
                return Err(ContentError::Decoding {
                    source: Error::encoding(source, field),
                    context,
                });
            }
        };
        match callback(&mut reader, &context) {
            Ok(output) => Ok(output),
            Err(source) => Err(ContentError::Callback { source, context }),
        }
    }
}
