//! Name catalogue growth must respect the original producing work ceiling.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

#[test]
fn retained_segmented_name_query_keeps_current_element_ceiling() {
    // Retained queries have no producing Reader argument. A new bounded source
    // for BER string preparation must still debit the current query's element
    // ceiling, rather than using aggregate availability alone.
    let segmented = [
        0x30, 14, 0x31, 12, 0x30, 10, 6, 3, 0x55, 4, 3, 0x2c, 3, 4, 1, b'a',
    ];
    let primitive = [0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 12, 1, b'A'];
    let left_parser = Parser::ber(memory());
    let right_parser = Parser::der(memory());
    let left = {
        let mut reader = left_parser.read(&segmented, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        structured_pkix::name::read(&reader, &element, "subject").unwrap()
    };
    let right = {
        let mut reader = right_parser.read(&primitive, 800).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        structured_pkix::name::read(&reader, &element, "issuer").unwrap()
    };
    let funded = memory();
    assert!(left.matches(&right, &funded).unwrap());
    assert_eq!(funded.used(), 0);
    let current = memory();
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_elements: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let reader = parser.read(&[], 900).unwrap();
    let error = left
        .matches(&right, &reader.execution())
        .expect_err("a fresh retained source cannot bypass the current query element ceiling");
    assert!(error.is_resource());
    assert_eq!(error.offset(), 411);
    drop(reader);
    assert_eq!(current.used(), 0);
}

#[test]
fn issuer_name_storage_cannot_use_aggregate_slack_past_local_work() {
    // CMS IssuerAndSerial calls this same PKIX core. Measure the exact admitted
    // work of a successful parse, then tighten only the original local ceiling.
    // Name parts and RDN attributes must not allocate outside that ceiling.
    let encoded = [0x30, 9, 0x31, 7, 0x30, 5, 6, 1, 42, 5, 0];
    let sufficient = memory();
    let parser = Parser::der(sufficient.clone());
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let name = structured_pkix::name::read(&reader, &element, "signerInfo.sid").unwrap();
    let full_work = u64::try_from(sufficient.work_used()).unwrap();
    drop(name);
    drop(reader);
    assert_eq!(sufficient.used(), 0);
    let limited = memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: full_work - 1,
            ..Limits::default()
        },
        limited.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = structured_pkix::name::read(&reader, &element, "signerInfo.sid")
        .expect_err("all catalogue allocation work belongs to this producing session");
    assert!(error.is_resource());
    assert_eq!(error.field(), "signerInfo.sid");
    drop(reader);
    assert_eq!(limited.used(), 0);
    assert!(u64::try_from(limited.work_used()).unwrap() < full_work);
}

#[test]
fn repeated_rdns_cannot_bypass_the_producing_catalogue_allowance() {
    // A small syntactically valid name can require much more catalogue work
    // than input scanning: 64 CN=a RDNs must refuse the 8000 local allowance
    // despite abundant aggregate funding, then release partial catalogues.
    let mut encoded = vec![0x30, 0x82, 3, 0];
    for _ in 0..64 {
        encoded.extend_from_slice(&[0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 12, 1, b'a']);
    }
    assert_eq!(encoded.len(), 772);
    let memory = Memory::new(Arc::new(MemoryAccount::new(100_000_000, 100_000_000)));
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 8000,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = structured_pkix::name::read(&reader, &element, "subject")
        .expect_err("RDN storage must use the producing local allowance");
    assert!(error.is_resource());
    assert_eq!(error.field(), "subject");
    assert!(error.offset() >= 400);
    assert!(memory.work_used() <= 8000);
    assert_eq!(memory.used(), 0);
}

#[test]
fn decoded_name_storage_survives_reader_and_releases_with_the_result() {
    // Independently retained metadata keeps its original account after local
    // construction ends. The existing borrowed Name lifetime contract remains
    // unchanged; releasing its producing Reader must not release its capacity.
    let encoded = [0x30, 9, 0x31, 7, 0x30, 5, 6, 1, 42, 5, 0];
    let memory = memory();
    let parser = Parser::der(memory.clone());
    let name;
    {
        let mut reader = parser.read(&encoded, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        name = structured_pkix::name::read(&reader, &element, "subject").unwrap();
    }
    assert!(memory.used() > 0);
    assert_eq!(name.as_bytes(), &encoded);
    drop(name);
    assert_eq!(memory.used(), 0);
}
