use super::{Acquisition, Error, Limits};
use core::cell::{Cell, RefCell};
use structured_asn1::{
    Span,
    memory::{Execution, MemoryError, OwnedVec, Work},
    range::{InputError, RangeSource, ReadError, Stamp, Window},
};

pub(super) struct Source<'a, S: RangeSource> {
    original: &'a S,
    stamp: Stamp<S::Document, S::Generation>,
    bytes: Cell<u64>,
    reads: Cell<u64>,
    ranges: RefCell<OwnedVec<Span, Execution<'a>>>,
}

impl<'a, S: RangeSource> Source<'a, S> {
    pub(super) fn new(source: &'a S, limits: Limits, work: Execution<'a>) -> Self {
        Self {
            original: source,
            stamp: source.stamp(),
            bytes: Cell::new(limits.bytes),
            reads: Cell::new(limits.reads),
            ranges: RefCell::new(work.vector()),
        }
    }

    pub(super) fn check(&self, range: Span) -> Result<(), Error<S::Error>> {
        if self.stamp != self.original.stamp() {
            return Err(Error::Input(InputError::Changed { range }));
        }
        Ok(())
    }

    pub(super) fn original_stamp(&self) -> Stamp<S::Document, S::Generation> {
        self.stamp
    }

    pub(super) fn ranges(self) -> OwnedVec<Span> {
        self.ranges.into_inner().into_owned()
    }

    pub(super) async fn read<'q>(
        &self,
        range: Span,
        work: &Execution<'q>,
    ) -> Result<OwnedVec<u8, Execution<'q>>, Error<S::Error>> {
        if range.length > self.bytes.get() {
            return Err(Error::Input(InputError::Cause {
                range,
                cause: Acquisition::Bytes,
            }));
        }
        if range.length != 0 && self.reads.get() == 0 {
            return Err(Error::Input(InputError::Cause {
                range,
                cause: Acquisition::Reads,
            }));
        }
        let mut result = work.vector();
        let mut window = Window::new(self, self.stamp, range, *work).map_err(Error::Input)?;
        let len = usize::try_from(range.length).map_err(|_| Error::Resource {
            range,
            cause: MemoryError::CapacityOverflow,
        })?;
        result
            .try_reserve_exact(len)
            .map_err(|cause| Error::Resource { range, cause })?;
        let mut at = range.start;
        while at < range.end() {
            let chunk = window
                .chunk_at(at, range.end())
                .await
                .map_err(Error::Input)?;
            result
                .try_extend_from_slice(chunk)
                .map_err(|cause| Error::Resource { range, cause })?;
            at += chunk.len() as u64;
        }
        Ok(result)
    }
}

impl<S: RangeSource> RangeSource for Source<'_, S> {
    type Document = S::Document;
    type Generation = S::Generation;
    type Error = Acquisition<S::Error>;

    fn stamp(&self) -> Stamp<Self::Document, Self::Generation> {
        self.original.stamp()
    }

    async fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        work: &'q W,
    ) -> Result<usize, ReadError<Self::Error>> {
        if self.original.stamp() != self.stamp {
            return Err(ReadError::Cause(Acquisition::Changed));
        }
        let length = output.len() as u64;
        let remaining = self.bytes.get();
        if length > remaining {
            return Err(ReadError::Cause(Acquisition::Bytes));
        }
        let calls = self.reads.get();
        if calls == 0 {
            return Err(ReadError::Cause(Acquisition::Reads));
        }
        self.bytes.set(remaining - length);
        self.reads.set(calls - 1);
        let index = {
            let mut ranges = self.ranges.borrow_mut();
            let index = ranges.len();
            ranges
                .try_push(Span {
                    start: offset,
                    length: 0,
                })
                .map_err(ReadError::Resource)?;
            index
        };
        let count =
            self.original
                .read_at(offset, output, work)
                .await
                .map_err(|error| match error {
                    ReadError::Resource(cause) => ReadError::Resource(cause),
                    ReadError::Cause(cause) => ReadError::Cause(Acquisition::Source(cause)),
                })?;
        self.ranges.borrow_mut()[index].length = count as u64;
        Ok(count)
    }
}
