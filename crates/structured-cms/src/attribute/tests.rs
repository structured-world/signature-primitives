use super::*;
use alloc::{sync::Arc, vec};

#[test]
fn placement_kernel_preserves_collecting_strict_and_callback_refusal() {
    // Both consumers must see the same placement facts; a sink's own
    // resource refusal stops immediately and retains its original cause.
    let mut attribute = vec![0x30, 15, 6, 9];
    attribute.extend(crate::oid::COUNTERSIGNATURE.as_bytes());
    attribute.extend([0x31, 2, 5, 0]);
    let mut bytes = vec![0xa0, 34];
    bytes.extend(attribute.repeat(2));
    let memory = Memory::new(Arc::new(structured_asn1::memory::MemoryAccount::new(
        65536, 65536,
    )));
    let parser = Parser::ber(memory);
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let attributes = Attributes::read(&parent, &element, Placement::Signed).unwrap();
    let first = attributes.items()[0].span().start;
    let mut count = 0;
    attributes
        .placement_faults_in(&parent, |fault| {
            assert_eq!(fault.code(), ErrorCode::AttributePlacement);
            assert_eq!(fault.offset(), attributes.items()[count].span().start);
            count += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 2);
    let mut calls = 0;
    let error = attributes
        .placement_faults_in(&parent, |fault| {
            calls += 1;
            Err(fault)
        })
        .unwrap_err();
    assert_eq!(calls, 1);
    assert_eq!(error.code(), ErrorCode::AttributePlacement);
    assert_eq!(error.offset(), first);
    let error = attributes
        .placement_faults_in(&parent, |_| {
            Err(Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                "report",
                first,
            ))
        })
        .unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "report");
    assert_eq!(error.offset(), first);
}
