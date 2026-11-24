use super::*;
use crate::test_support as support;
use crate::{Limits, Session, range::Slice};
use alloc::sync::Arc;
use core::cell::Cell;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_ltv::source::Snapshot;

struct Counted<'a> {
    source: Slice<'a, u8, u8>,
    checks: Cell<usize>,
}

impl RangeSource for Counted<'_> {
    type Document = u8;
    type Generation = u8;
    type Error = core::convert::Infallible;

    fn stamp(&self) -> Stamp<u8, u8> {
        self.checks.set(self.checks.get() + 1);
        self.source.stamp()
    }

    fn read_at<'q, W: Work + 'q>(
        &'q self,
        offset: u64,
        output: &'q mut [u8],
        work: &'q W,
    ) -> impl Future<Output = Result<usize, ReadError<Self::Error>>> + 'q {
        self.source.read_at(offset, output, work)
    }
}

#[test]
fn historical_graph_equality_compares_stream_bodies_not_only_dictionaries() {
    // A reference keeps the same object number/header while its later body
    // changes. Ignoring stream bytes would authorize a modified page input.
    let mut pdf = support::Pdf::new(&[
        (1, b"<< /Type /Catalog /Pages 2 0 R /TestPayload 4 0 R >>"),
        (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] >>"),
        (4, b"<< /Length 5 >>\nstream\nalpha\nendstream"),
    ]);
    pdf.append(&[(4, b"<< /Length 5 >>\nstream\nomega\nendstream")]);
    let source = Slice::new(
        &pdf.bytes,
        Snapshot {
            document: 1u8,
            generation: 0u8,
        },
    );
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24)));
    let session = Session::new(Limits::default(), memory);
    let work = session.execution();
    let document = support::ready(Document::read(&source, &session, &work)).unwrap();
    let first = support::ready(document.graph(0, &work)).unwrap();
    let second = support::ready(document.graph(1, &work)).unwrap();
    let old = first.root().get(b"TestPayload", &work).unwrap().unwrap();
    let new = second.root().get(b"TestPayload", &work).unwrap().unwrap();
    assert!(!support::ready(document.same_graph_values(old, new, &work)).unwrap());
}

#[test]
fn stream_equality_crosses_misaligned_windows_and_respects_work() {
    // Two revisions put the same stream on different page boundaries. A
    // third changes its final byte, beyond both readers' first windows.
    let body = |fill: u8| {
        let mut data = b"<< /Length 8201 >>\nstream\n".to_vec();
        data.extend(core::iter::repeat_n(b'a', 8200));
        data.push(fill);
        data.extend_from_slice(b"\nendstream");
        data
    };
    let original = body(b'a');
    let changed = body(b'b');
    let mut pdf = support::Pdf::new(&[
        (1, b"<< /Type /Catalog /Pages 2 0 R /TestPayload 4 0 R >>"),
        (2, b"<< /Type /Pages /Count 0 /Kids [] >>"),
        (3, b"null"),
        (4, &original),
    ]);
    pdf.append(&[(4, &original)]);
    pdf.append(&[(4, &changed)]);
    let source = Counted {
        source: Slice::new(
            &pdf.bytes,
            Snapshot {
                document: 1,
                generation: 0,
            },
        ),
        checks: Cell::new(0),
    };
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24)));
    let session = Session::new(Limits::default(), memory);
    let work = session.execution();
    let document = support::ready(Document::read(&source, &session, &work)).unwrap();
    let [old, same, other] = [0, 1, 2].map(|revision| {
        support::ready(document.object(revision, 4, 0, &work))
            .unwrap()
            .unwrap()
    });
    let location = old.value.root().location();
    let funded = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24)));
    source.checks.set(0);
    assert!(
        support::ready(document.same_streams_in(old.stream, same.stream, location, &funded))
            .unwrap()
    );
    // A handful of page crossings should not check the snapshot per byte.
    assert!(source.checks.get() < 64, "{}", source.checks.get());
    let constrained = Memory::new(Arc::new(MemoryAccount::new(
        1 << 22,
        funded.work_used() - 1,
    )));
    assert!(matches!(
        support::ready(document.same_streams_in(old.stream, same.stream, location, &constrained)),
        Err(
            ReadFailure::Input(crate::range::InputError::Resource { .. })
                | ReadFailure::Format(Error {
                    kind: ErrorKind::Resource(_),
                    ..
                })
        )
    ));
    assert!(
        !support::ready(document.same_streams_in(old.stream, other.stream, location, &work))
            .unwrap()
    );
}
