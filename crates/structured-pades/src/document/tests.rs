use super::Document;
use crate::test_support::{Pdf, ready};
use crate::{
    Limits, Session,
    error::ReadFailure,
    range::{InputError, RangeSource, ReadError, Stamp},
};
use alloc::sync::Arc;
use core::{
    cell::Cell,
    future::{Future, ready as completed},
};
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_ltv::source::Snapshot;

struct Updating<'a> {
    bytes: &'a [u8],
    generation: Cell<u32>,
    reads: Cell<usize>,
}
impl RangeSource for Updating<'_> {
    type Document = u32;
    type Generation = u32;
    type Error = core::convert::Infallible;

    fn stamp(&self) -> Stamp<u32, u32> {
        Stamp {
            snapshot: Snapshot {
                document: 1,
                generation: self.generation.get(),
            },
            length: self.bytes.len() as u64,
        }
    }

    fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        _work: &'q W,
    ) -> impl Future<Output = Result<usize, ReadError<Self::Error>>> + 'q {
        self.reads.set(self.reads.get() + 1);
        let start = usize::try_from(offset).unwrap();
        let length = output.len().min(self.bytes.len() - start);
        output[..length].copy_from_slice(&self.bytes[start..start + length]);
        completed(Ok(length))
    }
}

#[test]
fn catalogue_refuses_a_new_source_generation_before_acquisition() {
    // A fresh reader must not stamp old xref facts with a new source generation,
    // even when the replacement has exactly the same bytes and file length.
    let pdf = Pdf::new(&[(1, b"<< /Type /Catalog >>")]);
    let source = Updating {
        bytes: &pdf.bytes,
        generation: Cell::new(0),
        reads: Cell::new(0),
    };
    let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 100_000_000)));
    let session = Session::new(Limits::default(), memory);
    let work = session.execution();
    let document = ready(Document::read(&source, &session, &work)).unwrap();
    let before = source.reads.get();
    source.generation.set(1);
    let error = ready(document.catalogue(&work))
        .err()
        .expect("stale document must refuse");
    assert!(matches!(
        error,
        ReadFailure::Input(InputError::Changed { .. })
    ));
    assert_eq!(source.reads.get(), before);
}
