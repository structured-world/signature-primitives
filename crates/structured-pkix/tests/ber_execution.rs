//! All BER base-string scratch belongs to its original producing work ceiling.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)))
}

#[test]
fn ber_name_string_validation_cannot_bypass_local_scratch_admission() {
    // Catalogue funding alone does not cover the BER base-string walker and
    // its temporary joined validation bytes. Aggregate slack must not finance
    // either one beyond the producing session's ceiling.
    let encoded = [
        0x30, 14, 0x31, 12, 0x30, 10, 6, 3, 0x55, 4, 3, 0x2c, 3, 4, 1, b'A',
    ];
    let sufficient = memory();
    let parser = Parser::ber(sufficient.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let name = structured_pkix::name::read(&reader, &element, "issuer").unwrap();
    let full = u64::try_from(sufficient.work_used()).unwrap();
    drop(name);
    assert_eq!(sufficient.used(), 0);
    let limited = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: full - 1,
            ..Limits::default()
        },
        limited.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = structured_pkix::name::read(&reader, &element, "issuer")
        .expect_err("BER frame and validation-buffer growth are local work too");
    assert!(error.is_resource());
    assert_eq!(error.field(), "issuer");
    assert_eq!(limited.used(), 0);
    assert!(u64::try_from(limited.work_used()).unwrap() < full);
}

#[test]
fn constructed_time_copy_and_frames_cannot_use_only_aggregate_funding() {
    // A successful complete label pays its semantic decode plus every frame,
    // allocation and copied OCTET fragment through the same original Reader.
    let encoded = [
        0x38, 19, 4, 8, b'2', b'0', b'2', b'6', b'0', b'1', b'0', b'1', 4, 7, b'0', b'0', b'0',
        b'0', b'0', b'0', b'Z',
    ];
    let sufficient = memory();
    let parser = Parser::ber(sufficient.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    structured_pkix::temporal::read_generalized(&reader, &element, "tstInfo.genTime").unwrap();
    let full = u64::try_from(sufficient.work_used()).unwrap();
    assert_eq!(sufficient.used(), 0);
    let limited = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: full - 1,
            ..Limits::default()
        },
        limited.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = structured_pkix::temporal::read_generalized(&reader, &element, "tstInfo.genTime")
        .expect_err("time output cannot bypass local frame/copy admission");
    assert!(error.is_resource());
    assert_eq!(error.field(), "tstInfo.genTime");
    assert_eq!(limited.used(), 0);
    assert!(u64::try_from(limited.work_used()).unwrap() < full);
}
