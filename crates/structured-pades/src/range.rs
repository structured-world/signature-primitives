//! Asynchronous original-range access, with bounded accounted scratch.
//!
//! This boundary performs no filesystem, JavaScript, network or blocking I/O.
//! A source owner supplies those operations and a stable immutable snapshot.

use crate::Session;
use crate::byte_machine::{Decoder, Step};
use crate::bytes::Form;
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::source::{Location, Source};
use core::future::{Future, ready};
use structured_asn1::Span;
use structured_asn1::memory::{Execution, MemoryError, OwnedVec, Work};
use structured_ltv::source::Snapshot;

/// One immutable view of an original file. PDF incremental revisions are
/// historical ranges INSIDE this view, not mutations of its generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp<D, G> {
    /// Source-owner identity and immutable generation.
    pub snapshot: Snapshot<D, G>,
    /// Exact file length, including all incremental updates.
    pub length: u64,
}

/// Failure inside the caller's range acquisition.
#[derive(Debug)]
pub enum ReadError<E> {
    /// Original typed resource refusal; never malformed PDF or EOF.
    Resource(MemoryError),
    /// Original opaque I/O/source cause.
    Cause(E),
}

/// A seekable source that can suspend while acquiring a bounded range.
///
/// The core admits the requested copy bytes BEFORE calling `read_at`. The
/// implementation must fund any additional processing and retained capacity
/// through `work`. It writes only `output`, returns the number written, and
/// may return a short read. Zero means EOF. It must not load the whole source
/// as an implementation detail. Futures need neither allocation nor `Send`.
pub trait RangeSource {
    /// Stable, constant-time comparable caller-owned document identity.
    type Document: Copy + Eq;
    /// Stable, constant-time comparable immutable view identity.
    type Generation: Copy + Eq;
    /// Opaque acquisition failure, independent of PDF syntax.
    type Error;

    /// Constant-time metadata only: no allocation, traversal or I/O.
    fn stamp(&self) -> Stamp<Self::Document, Self::Generation>;

    /// Fills part or all of the bounded original range at `offset`.
    fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        work: &'q W,
    ) -> impl Future<Output = Result<usize, ReadError<Self::Error>>> + 'q;
}

/// A source processing failure with an honest original file location.
#[derive(Debug)]
pub enum InputError<E> {
    /// Original execution denied work or scratch capacity.
    Resource {
        /// Original requested file range or cached/EOF point.
        location: Location,
        /// Preserved memory or work admission failure.
        cause: MemoryError,
    },
    /// The owner changed identity, generation or length. Prior evidence cannot
    /// be reused; this is not an unreadable PDF field.
    Changed {
        /// Original requested file range or cached/EOF point.
        location: Location,
    },
    /// The acquisition violated its advertised length or output contract.
    Contract {
        /// Original range that was not delivered as advertised.
        location: Location,
    },
    /// Original opaque source failure.
    Cause {
        /// Original requested file range.
        location: Location,
        /// Unmodified caller/source error, separate from its physical context.
        cause: E,
    },
}

/// Convenience source for an already resident immutable slice. It does not
/// impose slice materialization on other [`RangeSource`] implementations.
pub struct Slice<'a, D, G> {
    bytes: &'a [u8],
    snapshot: Snapshot<D, G>,
}

impl<'a, D, G> Slice<'a, D, G> {
    /// Attaches explicit trusted source identity, without copying the slice.
    #[must_use]
    pub fn new(bytes: &'a [u8], snapshot: Snapshot<D, G>) -> Self {
        Self { bytes, snapshot }
    }
}

impl<D: Copy + Eq, G: Copy + Eq> RangeSource for Slice<'_, D, G> {
    type Document = D;
    type Generation = G;
    type Error = core::convert::Infallible;

    fn stamp(&self) -> Stamp<D, G> {
        Stamp {
            snapshot: self.snapshot,
            length: self.bytes.len() as u64,
        }
    }

    fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        _work: &'q W,
    ) -> impl Future<Output = Result<usize, ReadError<Self::Error>>> + 'q {
        // An offset outside a resident slice is necessarily beyond its EOF,
        // including on platforms whose address space is narrower than u64.
        let Ok(start) = usize::try_from(offset) else {
            return ready(Ok(0));
        };
        if start >= self.bytes.len() {
            return ready(Ok(0));
        }
        let length = output.len().min(self.bytes.len() - start);
        output[..length].copy_from_slice(&self.bytes[start..start + length]);
        ready(Ok(length))
    }
}

// A performance/scratch-window size, not a maximum PDF/document size. All
// source positions and lengths remain u64, including on wasm32/thumb targets.
const WINDOW: usize = 4096;
const ZERO_WINDOW: [u8; WINDOW] = [0; WINDOW];

/// One reusable original-file window. Parser lookahead and seek operations
/// share this buffer; large file/stream bodies need not be materialized.
/// Dropping a suspended read releases its scratch with the actual allocation.
pub struct RangeReader<'q, S: RangeSource> {
    source: &'q S,
    session: &'q Session,
    domain: Source,
    bounds: Span,
    stamp: Stamp<S::Document, S::Generation>,
    work: Execution<'q>,
    bytes: OwnedVec<u8, Execution<'q>>,
    start: u64,
    filled: usize,
    aligned: bool,
}

impl<'q, S: RangeSource> RangeReader<'q, S> {
    /// Creates bounded scratch under the original AND current execution.
    /// Construction performs no acquisition and never copies the source.
    pub fn new<W: Work>(
        source: &'q S,
        session: &'q Session,
        operation: &'q W,
    ) -> Result<Self, InputError<S::Error>> {
        Self::in_source(source, session, operation, Source::File)
    }

    pub(crate) fn in_source<W: Work>(
        source: &'q S,
        session: &'q Session,
        operation: &'q W,
        domain: Source,
    ) -> Result<Self, InputError<S::Error>> {
        let stamp = source.stamp();
        Self::window(
            source,
            session,
            operation,
            domain,
            stamp,
            Span {
                start: 0,
                length: stamp.length,
            },
        )
    }

    pub(crate) fn in_region<W: Work>(
        source: &'q S,
        session: &'q Session,
        operation: &'q W,
        domain: Source,
        bounds: Span,
    ) -> Result<Self, InputError<S::Error>> {
        Self::window(source, session, operation, domain, source.stamp(), bounds)
    }

    fn window<W: Work>(
        source: &'q S,
        session: &'q Session,
        operation: &'q W,
        domain: Source,
        stamp: Stamp<S::Document, S::Generation>,
        bounds: Span,
    ) -> Result<Self, InputError<S::Error>> {
        let work = session.query(operation);
        let location = Location::new(domain, bounds.start, 0).expect("validated source enclosure");
        work.charge_work(1)
            .map_err(|cause| InputError::Resource { location, cause })?;
        if bounds.start > stamp.length || bounds.length > stamp.length - bounds.start {
            return Err(InputError::Contract { location });
        }
        let count =
            usize::try_from(bounds.length.min(WINDOW as u64)).expect("window length fits usize");
        let mut bytes = work.vector();
        bytes
            .try_extend_from_slice(&ZERO_WINDOW[..count])
            .map_err(|cause| InputError::Resource { location, cause })?;
        Ok(Self {
            source,
            session,
            domain,
            bounds,
            stamp,
            work,
            bytes,
            start: 0,
            filled: 0,
            aligned: true,
        })
    }

    /// Original immutable view captured before parsing.
    #[must_use]
    pub fn stamp(&self) -> Stamp<S::Document, S::Generation> {
        self.stamp
    }

    /// Current original/source operation boundary, without a retained clone.
    #[must_use]
    pub fn execution(&self) -> Execution<'q> {
        self.work
    }

    pub(crate) fn session(&self) -> &'q Session {
        self.session
    }

    pub(crate) fn location(&self, start: u64, length: u64) -> Location {
        Location::new(self.domain, start, length).expect("bounded original-domain range")
    }

    // Comparing two distant encoded strings must not alternate one cache
    // between two pages for every byte. A second bounded window borrows the
    // SAME source snapshot/execution and owns only its actual scratch charge.
    pub(crate) fn fork(&self) -> Result<Self, InputError<S::Error>> {
        let location = self.location(self.start, 0);
        self.check(location)?;
        let mut bytes = self.work.vector();
        bytes
            .try_extend_from_slice(&ZERO_WINDOW[..self.bytes.len()])
            .map_err(|cause| InputError::Resource { location, cause })?;
        Ok(Self {
            source: self.source,
            session: self.session,
            domain: self.domain,
            bounds: self.bounds,
            stamp: self.stamp,
            work: self.work,
            bytes,
            start: 0,
            filled: 0,
            aligned: self.aligned,
        })
    }

    /// Reads one original byte, suspending only on a missing window. EOF is
    /// separate from source failure, changed snapshot or exhausted work.
    ///
    /// # Panics
    /// Panics if an offset inside the bounded resident window cannot index it.
    pub async fn byte_at(&mut self, offset: u64) -> Result<Option<u8>, InputError<S::Error>> {
        let location = self.location(offset, 0);
        self.check(location)?;
        if offset < self.bounds.start {
            return Err(InputError::Contract { location });
        }
        let end = self.bounds.start + self.bounds.length;
        if offset >= end {
            return Ok(None);
        }
        if offset >= self.start && offset - self.start < self.filled as u64 {
            let index = usize::try_from(offset - self.start).expect("cached index fits window");
            return Ok(Some(self.bytes[index]));
        }
        loop {
            // Reverse startxref/EOF scans must use the same fetched window as
            // forward parsing. A short-reading source instead uses the exact
            // queried offset, avoiding a refill loop through an unused prefix.
            let mut start = if self.aligned {
                offset / WINDOW as u64 * WINDOW as u64
            } else {
                offset
            };
            if start < self.bounds.start {
                start = self.bounds.start;
            }
            let wanted = usize::try_from((end - start).min(self.bytes.len() as u64))
                .expect("requested length fits window");
            let location = self.location(start, wanted as u64);
            // Cancellation/failure cannot leave a stale successful cache.
            self.filled = 0;
            self.work
                .charge_work(wanted as u64)
                .map_err(|cause| InputError::Resource { location, cause })?;
            let count = self
                .source
                .read_at(start, &mut self.bytes[..wanted], &self.work)
                .await
                .map_err(|error| match error {
                    ReadError::Resource(cause) => InputError::Resource { location, cause },
                    ReadError::Cause(cause) => InputError::Cause { location, cause },
                })?;
            self.check(location)?;
            if count == 0 || count > wanted {
                return Err(InputError::Contract { location });
            }
            self.start = start;
            self.filled = count;
            if count < wanted {
                self.aligned = false;
            }
            let index = usize::try_from(offset - start).expect("query is inside window");
            if index < count {
                return Ok(Some(self.bytes[index]));
            }
            // Only an aligned short read can reach this point. The next
            // request starts at offset, so any positive count completes it:
            // at most TWO acquisitions, independent of source/data length.
            debug_assert!(!self.aligned);
        }
    }

    pub(crate) async fn chunk_at(
        &mut self,
        offset: u64,
        end: u64,
    ) -> Result<&[u8], InputError<S::Error>> {
        let location = self.location(offset, 0);
        if end > self.bounds.start + self.bounds.length || offset > end {
            return Err(InputError::Contract { location });
        }
        if offset == end {
            self.check(location)?;
            return Ok(&[]);
        }
        self.byte_at(offset).await?;
        let start = usize::try_from(offset - self.start).expect("cached offset");
        let count = usize::try_from((end - offset).min((self.filled - start) as u64))
            .expect("bounded chunk");
        Ok(&self.bytes[start..start + count])
    }

    /// Decodes an original name/string BODY (without its delimiters) through
    /// the same grammar as resident [`crate::bytes::Bytes`]. It neither parses
    /// the enclosing PDF nor proves that the caller selected a signed field.
    /// All output has actual-capacity ownership; failure returns no prefix.
    pub async fn decode_bytes(
        &mut self,
        body: Span,
        form: Form,
    ) -> Result<OwnedVec<u8, Execution<'q>>, ReadFailure<S::Error>> {
        self.decode_bytes_limit(body, form, usize::MAX).await
    }

    pub(crate) async fn decode_bytes_limit(
        &mut self,
        body: Span,
        form: Form,
        maximum: usize,
    ) -> Result<OwnedVec<u8, Execution<'q>>, ReadFailure<S::Error>> {
        let enclosure = self.location(self.bounds.start, self.bounds.length);
        self.check(enclosure)?;
        let Some(end) = body.start.checked_add(body.length) else {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: enclosure,
            }
            .into());
        };
        if body.start < self.bounds.start || end > self.bounds.start + self.bounds.length {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: enclosure,
            }
            .into());
        }
        let mut output = self.work.vector();
        let mut decoder = Decoder::new(form);
        let mut at = body.start;
        loop {
            let input = if at < end {
                self.byte_at(at).await?
            } else {
                None
            };
            match decoder.step(input) {
                Step::More => {
                    debug_assert!(input.is_some());
                    at += 1;
                }
                Step::Byte { value, consumed } => {
                    if output.len() == maximum {
                        return Err(Error {
                            kind: ErrorKind::Syntax(Syntax::String),
                            location: self.location(at, 0),
                        }
                        .into());
                    }
                    if consumed {
                        at += 1;
                    }
                    output.try_push(value).map_err(|cause| Error {
                        kind: ErrorKind::Resource(cause),
                        location: self.location(at, 0),
                    })?;
                }
                Step::End => {
                    self.check(self.location(at, 0))?;
                    return Ok(output);
                }
                Step::Malformed => {
                    if input.is_some() {
                        at += 1;
                    }
                    return Err(Error {
                        kind: ErrorKind::Syntax(match form {
                            Form::Name => Syntax::Name,
                            Form::Literal | Form::Hexadecimal => Syntax::String,
                        }),
                        location: self.location(at, 0),
                    }
                    .into());
                }
            }
        }
    }

    pub(crate) fn check(&self, location: Location) -> Result<(), InputError<S::Error>> {
        debug_assert_eq!(location.source(), self.domain);
        self.work
            .charge_work(1)
            .map_err(|cause| InputError::Resource { location, cause })?;
        if self.source.stamp() != self.stamp {
            return Err(InputError::Changed { location });
        }
        Ok(())
    }
}
