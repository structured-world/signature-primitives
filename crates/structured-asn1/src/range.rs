//! Bounded asynchronous original-range acquisition under one execution.

use crate::Span;
use crate::memory::{Execution, MemoryError, OwnedVec, Work};
use crate::source::Snapshot;
use core::future::{Future, ready};

/// One immutable original byte source, including its exact length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp<D, G> {
    /// Source-owner identity and immutable generation.
    pub snapshot: Snapshot<D, G>,
    /// Exact byte length of this view.
    pub length: u64,
}

/// Failure inside caller-owned range acquisition.
#[derive(Debug)]
pub enum ReadError<E> {
    /// Original typed resource refusal, independent of syntax and EOF.
    Resource(MemoryError),
    /// Original opaque acquisition cause.
    Cause(E),
}

/// A stable range source that may suspend during bounded acquisition.
///
/// The window admits requested copy bytes before dispatch. Implementations
/// fund additional processing/storage through `work`, write only `output`,
/// and return its written length. Short reads and zero at EOF are allowed.
/// Whole-source materialization is not an implementation detail of this API.
pub trait RangeSource {
    /// Stable, constant-time comparable source-owner identity.
    type Document: Copy + Eq;
    /// Constant-time comparable immutable generation.
    type Generation: Copy + Eq;
    /// Original acquisition failure.
    type Error;

    /// Constant-time metadata, without allocation, traversal or I/O.
    fn stamp(&self) -> Stamp<Self::Document, Self::Generation>;

    /// Fills a bounded original range; no executor, `Send` or heap future bound.
    fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        work: &'q W,
    ) -> impl Future<Output = Result<usize, ReadError<Self::Error>>> + 'q;
}

/// A borrowed resident source using the same original-range contract.
pub struct Slice<'a, D, G> {
    bytes: &'a [u8],
    stamp: Stamp<D, G>,
}

impl<'a, D, G> Slice<'a, D, G> {
    /// Binds original bytes to their caller-owned source identity.
    #[must_use]
    pub fn new(bytes: &'a [u8], snapshot: Snapshot<D, G>) -> Self {
        Self {
            bytes,
            stamp: Stamp {
                snapshot,
                length: bytes.len() as u64,
            },
        }
    }
}

impl<D: Copy + Eq, G: Copy + Eq> RangeSource for Slice<'_, D, G> {
    type Document = D;
    type Generation = G;
    type Error = core::convert::Infallible;

    fn stamp(&self) -> Stamp<D, G> {
        self.stamp
    }

    fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        _work: &'q W,
    ) -> impl Future<Output = Result<usize, ReadError<Self::Error>>> + 'q {
        let count = if let Ok(offset) = usize::try_from(offset)
            && let Some(input) = self.bytes.get(offset..)
        {
            let count = input.len().min(output.len());
            output[..count].copy_from_slice(&input[..count]);
            count
        } else {
            0
        };
        ready(Ok(count))
    }
}

/// Failure at an original source range, without inventing format coordinates.
#[derive(Debug)]
pub enum InputError<E> {
    /// Original source/current execution refusal.
    Resource {
        /// Requested original range or EOF point.
        range: Span,
        /// Preserved work or capacity cause.
        cause: MemoryError,
    },
    /// Identity, generation or length changed.
    Changed {
        /// Requested original range or point.
        range: Span,
    },
    /// Invalid bounds, premature EOF or an impossible returned count.
    Contract {
        /// Requested original range or point.
        range: Span,
    },
    /// Original opaque acquisition failure.
    Cause {
        /// Requested original range.
        range: Span,
        /// Preserved cause.
        cause: E,
    },
}

// Cache granularity, not a document-size policy or acceptance ceiling.
const WINDOW: usize = 4096;
const ZERO_WINDOW: [u8; WINDOW] = [0; WINDOW];

/// A bounded resident window over one exact source view and execution.
/// Cache hits still check source identity and current admission. Scratch is
/// released with this owner; retaining metadata never prepays a later query.
pub struct Window<'q, S: RangeSource> {
    source: &'q S,
    stamp: Stamp<S::Document, S::Generation>,
    bounds: Span,
    work: Execution<'q>,
    bytes: OwnedVec<u8, Execution<'q>>,
    start: u64,
    filled: usize,
    aligned: bool,
    quantum: usize,
}

impl<'q, S: RangeSource> Window<'q, S> {
    /// Opens a bounded region of an already selected immutable view.
    ///
    /// # Panics
    /// Only if the internal fixed scratch size no longer fits target `usize`.
    /// The selected input length is bounded by that fixed size before conversion.
    pub fn new(
        source: &'q S,
        stamp: Stamp<S::Document, S::Generation>,
        bounds: Span,
        work: Execution<'q>,
    ) -> Result<Self, InputError<S::Error>> {
        let Some(end) = bounds.start.checked_add(bounds.length) else {
            return Err(InputError::Contract { range: bounds });
        };
        if end > stamp.length {
            return Err(InputError::Contract { range: bounds });
        }
        Self::guard(source, stamp, &work, bounds)?;
        let mut bytes = work.vector();
        let size = usize::try_from(bounds.length.min(WINDOW as u64))
            .expect("bounded window length fits usize");
        bytes
            .try_extend_from_slice(&ZERO_WINDOW[..size])
            .map_err(|cause| InputError::Resource {
                range: bounds,
                cause,
            })?;
        Ok(Self {
            source,
            stamp,
            bounds,
            work,
            bytes,
            start: 0,
            filled: 0,
            aligned: true,
            quantum: WINDOW,
        })
    }

    /// The selected source/current operation, without changing account ownership.
    #[must_use]
    pub fn execution(&self) -> Execution<'q> {
        self.work
    }

    /// Selected immutable source metadata.
    #[must_use]
    pub fn stamp(&self) -> Stamp<S::Document, S::Generation> {
        self.stamp
    }

    /// Original bounded source region.
    #[must_use]
    pub fn bounds(&self) -> Span {
        self.bounds
    }

    /// Independent bounded cache with the same snapshot/execution. Comparing
    /// distant regions does not evict one window for every compared byte.
    pub fn fork(&self) -> Result<Self, InputError<S::Error>> {
        let mut fork = Self::new(self.source, self.stamp, self.bounds, self.work)?;
        fork.aligned = self.aligned;
        fork.quantum = self.quantum;
        Ok(fork)
    }

    /// Requires the original view and current admission before cached/EOF work.
    pub fn check(&self, range: Span) -> Result<(), InputError<S::Error>> {
        Self::guard(self.source, self.stamp, &self.work, range)
    }

    fn guard(
        source: &S,
        stamp: Stamp<S::Document, S::Generation>,
        work: &Execution<'_>,
        range: Span,
    ) -> Result<(), InputError<S::Error>> {
        work.charge_work(1)
            .map_err(|cause| InputError::Resource { range, cause })?;
        if source.stamp() != stamp {
            return Err(InputError::Changed { range });
        }
        Ok(())
    }

    async fn refill(
        &mut self,
        start: u64,
        length: usize,
        complete: bool,
    ) -> Result<(), InputError<S::Error>> {
        // Invalidated before the first mutable borrow: cancellation or any
        // later failure cannot expose a partially overwritten old cache page.
        self.filled = 0;
        let mut used = 0;
        loop {
            let wanted = (length - used).min(self.quantum);
            let range = Span {
                start: start + used as u64,
                length: wanted as u64,
            };
            self.check(range)?;
            self.work
                .charge_work(wanted as u64)
                .map_err(|cause| InputError::Resource { range, cause })?;
            let count = self
                .source
                .read_at(
                    range.start,
                    &mut self.bytes[used..used + wanted],
                    &self.work,
                )
                .await
                .map_err(|error| match error {
                    ReadError::Resource(cause) => InputError::Resource { range, cause },
                    ReadError::Cause(cause) => InputError::Cause { range, cause },
                })?;
            self.check(range)?;
            if count == 0 || count > wanted {
                return Err(InputError::Contract { range });
            }
            if count < wanted {
                // A short read adapts acquisition granularity, not semantics.
                // Subsequent copies are admitted for the smaller requested
                // buffer instead of repeatedly prepaying a whole 4KiB page.
                self.quantum = count;
                self.aligned = false;
            }
            used += count;
            if !complete || used == length {
                self.start = start;
                self.filled = used;
                return Ok(());
            }
        }
    }

    /// Reads one original byte, suspending only when acquisition is required.
    ///
    /// # Panics
    /// Panics if an internally bounded resident offset cannot index its window.
    pub async fn byte_at(&mut self, offset: u64) -> Result<Option<u8>, InputError<S::Error>> {
        let point = Span {
            start: offset,
            length: 0,
        };
        self.check(point)?;
        if offset < self.bounds.start {
            return Err(InputError::Contract { range: point });
        }
        let end = self.bounds.end();
        if offset >= end {
            return Ok(None);
        }
        if offset >= self.start && offset - self.start < self.filled as u64 {
            let index = usize::try_from(offset - self.start).expect("cached window index");
            return Ok(Some(self.bytes[index]));
        }
        loop {
            let mut start = if self.aligned {
                offset / WINDOW as u64 * WINDOW as u64
            } else {
                offset
            };
            if start < self.bounds.start {
                start = self.bounds.start;
            }
            let wanted = usize::try_from((end - start).min(self.bytes.len() as u64))
                .expect("bounded requested length");
            self.refill(start, wanted, false).await?;
            let index = usize::try_from(offset - start).expect("query is inside window");
            if index < self.filled {
                return Ok(Some(self.bytes[index]));
            }
            // After an aligned short read, retry exactly at the queried byte.
            // Any positive result completes it: at most two acquisitions.
            debug_assert!(!self.aligned);
        }
    }

    /// Borrows the next bounded original chunk, without an intermediate copy.
    ///
    /// # Panics
    /// Panics if a resident range cannot index its bounded window.
    pub async fn chunk_at(&mut self, offset: u64, end: u64) -> Result<&[u8], InputError<S::Error>> {
        let range = Span {
            start: offset,
            length: 0,
        };
        if end > self.bounds.end() || offset < self.bounds.start || offset > end {
            return Err(InputError::Contract { range });
        }
        if offset == end {
            self.check(range)?;
            return Ok(&[]);
        }
        self.byte_at(offset).await?;
        let start = usize::try_from(offset - self.start).expect("cached offset");
        let count = usize::try_from((end - offset).min((self.filled - start) as u64))
            .expect("bounded chunk");
        Ok(&self.bytes[start..start + count])
    }

    /// Borrows a bounded chunk ending at `end` for reverse metadata scans.
    /// Reverse refill completes one bounded page despite short reads. This
    /// preserves every byte and linear acquisition/admission during scans.
    ///
    /// # Panics
    /// Panics if an internally bounded resident range cannot index its window.
    pub async fn chunk_before(
        &mut self,
        end: u64,
        minimum: u64,
    ) -> Result<&[u8], InputError<S::Error>> {
        let point = Span {
            start: end,
            length: 0,
        };
        if minimum < self.bounds.start || end > self.bounds.end() || minimum > end {
            return Err(InputError::Contract { range: point });
        }
        if end == minimum {
            self.check(point)?;
            return Ok(&[]);
        }
        self.check(point)?;
        let last = end - 1;
        if last < self.start || last - self.start >= self.filled as u64 {
            let start = minimum.max(end - end.min(self.bytes.len() as u64));
            let length = usize::try_from(end - start).expect("bounded reverse page");
            self.refill(start, length, true).await?;
        }
        let start =
            usize::try_from(minimum.max(self.start) - self.start).expect("resident reverse start");
        let stop = usize::try_from(end - self.start).expect("resident reverse end");
        Ok(&self.bytes[start..stop])
    }
}

#[cfg(test)]
mod tests;
