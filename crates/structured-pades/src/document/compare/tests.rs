use super::*;
use crate::test_support as support;
use crate::{Limits, Session, range::Slice};
use alloc::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_ltv::source::Snapshot;

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
