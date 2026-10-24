use super::*;
use crate::memory::{Memory, MemoryAccount};
use crate::{Encoding, Limits, Parser};
use alloc::sync::Arc;
use core::cell::Cell;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

fn finish<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => return result,
            Poll::Pending => {}
        }
    }
}

fn parser(capacity: usize, work: usize) -> Parser {
    Parser::new(
        Encoding::Der,
        Limits {
            max_work: work as u64,
            ..Limits::default()
        },
        Memory::new(Arc::new(MemoryAccount::new(capacity, work))),
    )
}

fn stamp(length: u64) -> Stamp<u64, u64> {
    Stamp {
        snapshot: Snapshot {
            document: 7,
            generation: 11,
        },
        length,
    }
}

struct Short {
    stamp: Cell<Stamp<u64, u64>>,
    reads: Cell<usize>,
    maximum: usize,
    change: bool,
}

impl RangeSource for Short {
    type Document = u64;
    type Generation = u64;
    type Error = ();

    fn stamp(&self) -> Stamp<u64, u64> {
        self.stamp.get()
    }

    fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        _work: &'q W,
    ) -> impl Future<Output = Result<usize, ReadError<()>>> + 'q {
        self.reads.set(self.reads.get() + 1);
        let count = self.maximum.min(output.len());
        for (index, byte) in output[..count].iter_mut().enumerate() {
            *byte = (offset + index as u64).to_le_bytes()[0];
        }
        if self.change {
            let mut next = self.stamp.get();
            next.snapshot.generation += 1;
            self.stamp.set(next);
        }
        ready(Ok(count))
    }
}

#[test]
fn original_slice_chunks_keep_bounds_and_release_actual_capacity() {
    // The shared window borrows actual source chunks and releases its one
    // funded buffer; an empty region needs no scratch allocation or source I/O.
    let parser = parser(8192, 100_000);
    let work = parser.execution_in(parser.memory());
    let bytes = [19_u8; 5000];
    let source = Slice::new(&bytes, stamp(0).snapshot);
    let mut window = Window::new(
        &source,
        source.stamp(),
        Span {
            start: 7,
            length: 4500,
        },
        work,
    )
    .unwrap();
    let before = parser.memory().used();
    assert!(before >= 4096);
    assert_eq!(finish(window.chunk_at(7, 4507)).unwrap().len(), 4096);
    assert_eq!(finish(window.byte_at(4506)).unwrap(), Some(19));
    assert_eq!(finish(window.byte_at(4507)).unwrap(), None);
    assert!(matches!(
        finish(window.chunk_at(6, 7)),
        Err(InputError::Contract { .. })
    ));
    drop(window);
    assert_eq!(parser.memory().used(), 0);
    let mut empty = Window::new(
        &source,
        source.stamp(),
        Span {
            start: 5000,
            length: 0,
        },
        work,
    )
    .unwrap();
    assert_eq!(parser.memory().used(), 0);
    assert_eq!(finish(empty.byte_at(5000)).unwrap(), None);
}

#[test]
fn aligned_short_read_retries_once_at_exact_requested_offset() {
    // A reverse scan cannot loop through short prefixes of the same aligned
    // page. The second read starts at the queried byte, even above 4 GiB.
    let parser = parser(8192, 100_000);
    let work = parser.execution_in(parser.memory());
    let at = (1_u64 << 35) + 4000;
    let source = Short {
        stamp: Cell::new(stamp(at + 200)),
        reads: Cell::new(0),
        maximum: 3,
        change: false,
    };
    let mut window = Window::new(
        &source,
        source.stamp(),
        Span {
            start: 0,
            length: at + 200,
        },
        work,
    )
    .unwrap();
    assert_eq!(
        finish(window.byte_at(at)).unwrap(),
        Some(at.to_le_bytes()[0])
    );
    assert_eq!(source.reads.get(), 2);
    assert_eq!(
        finish(window.byte_at(at + 1)).unwrap(),
        Some((at + 1).to_le_bytes()[0])
    );
    assert_eq!(source.reads.get(), 2);
}

#[test]
fn changed_snapshot_refuses_cached_bytes_eof_and_post_acquisition() {
    // A cache hit and EOF cannot reuse a different generation. A source
    // changing during acquisition likewise produces no successful byte.
    let parser = parser(8192, 100_000);
    let work = parser.execution_in(parser.memory());
    let source = Short {
        stamp: Cell::new(stamp(20)),
        reads: Cell::new(0),
        maximum: 20,
        change: false,
    };
    let mut window = Window::new(
        &source,
        source.stamp(),
        Span {
            start: 0,
            length: 20,
        },
        work,
    )
    .unwrap();
    assert_eq!(finish(window.byte_at(0)).unwrap(), Some(0));
    source.stamp.set(stamp(21));
    assert!(matches!(
        finish(window.byte_at(0)),
        Err(InputError::Changed { .. })
    ));
    assert!(matches!(
        finish(window.byte_at(20)),
        Err(InputError::Changed { .. })
    ));
    assert_eq!(source.reads.get(), 1);
    drop(window);
    let changing = Short {
        change: true,
        ..source
    };
    let mut window = Window::new(
        &changing,
        changing.stamp(),
        Span {
            start: 0,
            length: 20,
        },
        work,
    )
    .unwrap();
    assert!(matches!(
        finish(window.byte_at(0)),
        Err(InputError::Changed { .. })
    ));
}

#[test]
fn origin_and_current_refusal_precede_storage_or_source_dispatch() {
    // A wide current account cannot discard a source's exhausted producing
    // ceiling. A narrow current ceiling also applies before any acquisition.
    let source_parser = parser(8192, 100_000);
    let current = parser(8192, 100_000);
    let source = Short {
        stamp: Cell::new(stamp(20)),
        reads: Cell::new(0),
        maximum: 20,
        change: false,
    };
    let origin = source_parser.execution_in(source_parser.memory());
    origin.charge_work(origin.work_remaining() as u64).unwrap();
    let current_work = current.execution_in(current.memory());
    let joined = current_work.execution_for(&source_parser);
    assert!(matches!(
        Window::new(
            &source,
            source.stamp(),
            Span {
                start: 0,
                length: 20
            },
            joined
        ),
        Err(InputError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert_eq!(source.reads.get(), 0);
    assert_eq!(current.memory().used(), 0);

    let tight = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        current.memory().clone(),
    );
    let fresh_source = parser(8192, 100_000);
    let tight_work = tight.execution_in(tight.memory());
    let joined = tight_work.execution_for(&fresh_source);
    assert!(matches!(
        Window::new(
            &source,
            source.stamp(),
            Span {
                start: 0,
                length: 20
            },
            joined
        ),
        Err(InputError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert_eq!(source.reads.get(), 0);
}

#[test]
fn invalid_bounds_and_capacity_failure_have_no_source_side_effects() {
    // Checked original bounds reject overflow before allocation; actual
    // capacity refusal must not be converted to EOF or malformed source data.
    let parser = parser(19, 100_000);
    let work = parser.execution_in(parser.memory());
    let source = Short {
        stamp: Cell::new(stamp(20)),
        reads: Cell::new(0),
        maximum: 20,
        change: false,
    };
    assert!(matches!(
        Window::new(
            &source,
            source.stamp(),
            Span {
                start: u64::MAX,
                length: 1
            },
            work
        ),
        Err(InputError::Contract { .. })
    ));
    assert!(matches!(
        Window::new(
            &source,
            source.stamp(),
            Span {
                start: 0,
                length: 20
            },
            work
        ),
        Err(InputError::Resource {
            cause: MemoryError::LimitExceeded,
            ..
        })
    ));
    assert_eq!(source.reads.get(), 0);
    assert_eq!(parser.memory().used(), 0);
}

struct Suspended {
    reads: Cell<usize>,
    suspend: Cell<bool>,
}
impl RangeSource for Suspended {
    type Document = u64;
    type Generation = u64;
    type Error = ();
    fn stamp(&self) -> Stamp<u64, u64> {
        stamp(16_384)
    }
    async fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        _work: &'q W,
    ) -> Result<usize, ReadError<()>> {
        self.reads.set(self.reads.get() + 1);
        output.fill(if offset == 0 { 17 } else { 29 });
        core::future::poll_fn(|context| {
            if offset != 0 && self.suspend.replace(false) {
                context.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        Ok(output.len())
    }
}

#[test]
fn cancelled_refill_never_relabels_overwritten_bytes_as_the_previous_page() {
    // Acquisition can write scratch and then suspend. Cancelling that future
    // invalidates the old cache instead of exposing the new page under its ID.
    let parser = parser(8192, 100_000);
    let work = parser.execution_in(parser.memory());
    let source = Suspended {
        reads: Cell::new(0),
        suspend: Cell::new(true),
    };
    let mut window = Window::new(
        &source,
        source.stamp(),
        Span {
            start: 0,
            length: 16_384,
        },
        work,
    )
    .unwrap();
    assert_eq!(finish(window.byte_at(0)).unwrap(), Some(17));
    {
        let mut refill = pin!(window.byte_at(8192));
        let mut context = Context::from_waker(Waker::noop());
        assert!(refill.as_mut().poll(&mut context).is_pending());
    }
    assert_eq!(finish(window.byte_at(0)).unwrap(), Some(17));
    assert_eq!(source.reads.get(), 3);
    assert_eq!(finish(window.byte_at(8192)).unwrap(), Some(29));
    drop(window);
    assert_eq!(parser.memory().used(), 0);
}

#[test]
fn reverse_short_reads_fill_each_page_once_with_linear_admission() {
    // Reverse ZIP metadata scans must not degenerate into one-byte windows
    // and a full 4KiB prepayment for every seven-byte source acquisition.
    let length = 16_385;
    let parser = parser(8192, 100_000);
    let work = parser.execution_in(parser.memory());
    let source = Short {
        stamp: Cell::new(stamp(length)),
        reads: Cell::new(0),
        maximum: 7,
        change: false,
    };
    let mut window = Window::new(&source, source.stamp(), Span { start: 0, length }, work).unwrap();
    let mut end = length;
    let before = parser.memory().work_used();
    let mut pages = 0;
    while end != 0 {
        let bytes = finish(window.chunk_before(end, 0)).unwrap();
        assert_ne!(bytes, []);
        let start = end - bytes.len() as u64;
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(*byte, (start + index as u64).to_le_bytes()[0]);
        }
        end = start;
        pages += 1;
    }
    assert_eq!(pages, 5);
    assert!(source.reads.get() <= 2350);
    assert!(parser.memory().work_used() - before < 30_000);
}

struct Refusing(Cell<Stamp<u64, u64>>);
impl RangeSource for Refusing {
    type Document = u64;
    type Generation = u64;
    type Error = u8;
    fn stamp(&self) -> Stamp<u64, u64> {
        self.0.get()
    }
    fn read_at<'q, W: Work + 'q>(
        &'q self,
        _offset: u64,
        _output: &'q mut [u8],
        _work: &'q W,
    ) -> impl Future<Output = Result<usize, ReadError<u8>>> + 'q {
        let mut changed = self.0.get();
        changed.snapshot.generation += 1;
        self.0.set(changed);
        ready(Err(ReadError::Cause(73)))
    }
}

#[test]
fn opaque_acquisition_refusal_precedes_its_later_snapshot_change() {
    // A source refusal is not overwritten by the post-success generation
    // fence, which only runs when acquisition actually succeeds.
    let parser = parser(8192, 100_000);
    let work = parser.execution_in(parser.memory());
    let source = Refusing(Cell::new(stamp(10)));
    let mut window = Window::new(
        &source,
        source.stamp(),
        Span {
            start: 0,
            length: 10,
        },
        work,
    )
    .unwrap();
    assert!(matches!(
        finish(window.byte_at(0)),
        Err(InputError::Cause { cause: 73, .. })
    ));
    assert!(matches!(
        finish(window.byte_at(0)),
        Err(InputError::Changed { .. })
    ));
}
