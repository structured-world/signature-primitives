//! Asynchronous original-range access, with bounded accounted scratch.
//!
//! This boundary performs no filesystem, JavaScript, network or blocking I/O.
//! A source owner supplies those operations and a stable immutable snapshot.

use crate::Session;
use crate::byte_machine::{Decoder, Step};
use crate::bytes::Form;
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::source::{Location, Source};
use structured_asn1::Span;
use structured_asn1::memory::{Execution, MemoryError, OwnedVec, Work};
use structured_asn1::range::Window;

pub use structured_asn1::range::{RangeSource, ReadError, Slice, Stamp};

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

/// One reusable original-file window. Parser lookahead and seek operations
/// share this buffer; large file/stream bodies need not be materialized.
/// Dropping a suspended read releases its scratch with the actual allocation.
pub struct RangeReader<'q, S: RangeSource> {
    session: &'q Session,
    domain: Source,
    window: Window<'q, S>,
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
        let window = Window::new(source, stamp, bounds, session.query(operation))
            .map_err(|error| located(domain, error))?;
        Ok(Self {
            session,
            domain,
            window,
        })
    }

    /// Original immutable view captured before parsing.
    #[must_use]
    pub fn stamp(&self) -> Stamp<S::Document, S::Generation> {
        self.window.stamp()
    }

    /// Current original/source operation boundary, without a retained clone.
    #[must_use]
    pub fn execution(&self) -> Execution<'q> {
        self.window.execution()
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
        Ok(Self {
            session: self.session,
            domain: self.domain,
            window: self
                .window
                .fork()
                .map_err(|error| located(self.domain, error))?,
        })
    }

    /// Reads one original byte, suspending only on a missing window. EOF is
    /// separate from source failure, changed snapshot or exhausted work.
    ///
    /// # Panics
    /// Panics if an offset inside the bounded resident window cannot index it.
    pub async fn byte_at(&mut self, offset: u64) -> Result<Option<u8>, InputError<S::Error>> {
        self.window
            .byte_at(offset)
            .await
            .map_err(|error| located(self.domain, error))
    }

    pub(crate) async fn chunk_at(
        &mut self,
        offset: u64,
        end: u64,
    ) -> Result<&[u8], InputError<S::Error>> {
        let domain = self.domain;
        self.window
            .chunk_at(offset, end)
            .await
            .map_err(|error| located(domain, error))
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
        let bounds = self.window.bounds();
        let enclosure = self.location(bounds.start, bounds.length);
        self.check(enclosure)?;
        let Some(end) = body.start.checked_add(body.length) else {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: enclosure,
            }
            .into());
        };
        if body.start < bounds.start || end > bounds.end() {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: enclosure,
            }
            .into());
        }
        let mut output = self.execution().vector();
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
        self.window
            .check(location.span())
            .map_err(|error| located(self.domain, error))
    }
}

fn located<E>(domain: Source, error: structured_asn1::range::InputError<E>) -> InputError<E> {
    use structured_asn1::range::InputError as RangeError;
    let location = |range: Span| {
        Location::new(domain, range.start, range.length).expect("bounded source range")
    };
    match error {
        RangeError::Resource { range, cause } => InputError::Resource {
            location: location(range),
            cause,
        },
        RangeError::Changed { range } => InputError::Changed {
            location: location(range),
        },
        RangeError::Contract { range } => InputError::Contract {
            location: Location::new(domain, range.start, 0).expect("original invalid-range point"),
        },
        RangeError::Cause { range, cause } => InputError::Cause {
            location: location(range),
            cause,
        },
    }
}
