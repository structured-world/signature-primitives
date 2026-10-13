//! Producing-session accounting of opaque DER traversal frames.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};

#[test]
fn empty_opaque_container_cannot_allocate_frames_past_local_work() {
    // CMS signedAttrs must validate unknown nested values. An empty SEQUENCE
    // spends header/path work but cannot use aggregate slack for uncharged
    // parser-local frame allocation and then silently succeed at EOF.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 20,
            ..Limits::default()
        },
        memory.clone(),
    );
    let encoded = [0x30, 0];
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = structured_pkix::der::conforms(&reader, &element, "signedAttrs.value")
        .expect_err("original local allowance cannot admit a frame allocation");
    assert!(error.is_resource());
    assert_eq!(error.field(), "signedAttrs.value");
    assert_eq!(error.offset(), 400);
    assert_eq!(memory.used(), 0);
    assert!(memory.work_used() <= 20);
}
