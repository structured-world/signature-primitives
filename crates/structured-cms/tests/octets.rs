//! Original BER content ranges and execution boundary qualification.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::{ErrorCode, Octets};

#[test]
fn ia5_contents_preserve_borrowed_fragments_and_reject_non_ascii() {
    // Primitive input stays borrowed; the shared constructed base-string walk
    // keeps original OCTET fragment spans and frees its paid catalogue on drop.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let primitive = [22, 2, b'a', b'b'];
    let mut reader = parser.read(&primitive, 100).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = Octets::read_ia5(&reader, &element, "policy.uri").unwrap();
    assert_eq!(
        value.pieces()[0].as_bytes().as_ptr(),
        primitive[2..].as_ptr()
    );
    assert_eq!(memory.used(), 0);
    drop(value);
    let constructed = [0x36, 0x80, 4, 1, b'a', 4, 1, b'b', 0, 0];
    let mut reader = parser.read(&constructed, 500).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let value = Octets::read_ia5(&reader, &element, "policy.uri").unwrap();
    assert_eq!(value.len(), 2);
    assert_eq!(value.pieces()[0].span().start, 504);
    assert_eq!(value.pieces()[1].span().start, 507);
    assert!(memory.used() > 0);
    drop(value);
    assert_eq!(memory.used(), 0);
    let bad = [22, 1, 0xff];
    let mut reader = parser.read(&bad, 700).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = Octets::read_ia5(&reader, &element, "policy.uri").unwrap_err();
    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.offset(), 702);
}

#[test]
fn empty_ia5_still_requires_current_work() {
    // Zero output is not free admission: no exhausted-operation fast path may
    // return a successful empty reading or allocate a fragment catalogue.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let bytes = [22, 0];
    let mut reader = parser.read(&bytes, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    memory.charge_work(memory.work_remaining() as u64).unwrap();
    let error = Octets::read_ia5(&reader, &element, "policy.uri").unwrap_err();
    assert!(error.is_terminal());
    assert_eq!(memory.used(), 0);
    assert_eq!(element.as_bytes(), bytes);
}

#[test]
fn primitive_content_is_borrowed_without_storage() {
    // A primitive payload must not be copied or create a catalogue.
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 1024)));
    let parser = Parser::ber(memory.clone());
    let data = [4, 2, b'a', b'b'];
    let mut reader = parser.read(&data, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let octets = Octets::read(&reader, &element, "content").unwrap();
    assert_eq!(octets.len(), 2);
    assert_eq!(octets.pieces()[0].as_bytes().as_ptr(), data[2..].as_ptr());
    assert_eq!(octets.pieces()[0].span().start, 402);
    assert_eq!(memory.used(), 0);
}

#[test]
fn nested_ber_retains_original_ranges_and_catalogue_charge() {
    // Constructed headers/EOC never become payload bytes; metadata survives
    // reader drop and releases its capacity only when the content is dropped.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let data = [0x24, 0x80, 4, 2, b'a', b'b', 0x24, 3, 4, 1, b'c', 0, 0];
    let octets;
    {
        let mut reader = parser.read(&data, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        octets = Octets::read(&reader, &element, "content").unwrap();
    }
    assert_eq!(octets.len(), 3);
    assert_eq!(octets.pieces().len(), 2);
    assert_eq!(octets.pieces()[0].as_bytes(), b"ab");
    assert_eq!(octets.pieces()[1].as_bytes(), b"c");
    assert_eq!(octets.pieces()[0].span().start, 404);
    assert_eq!(octets.pieces()[1].span().start, 410);
    assert!(memory.used() > 0);
    drop(octets);
    assert_eq!(memory.used(), 0);
}

#[test]
fn unrelated_fragment_is_refused_and_scratch_released() {
    // Only OCTET STRING children can contribute logical content.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let data = [0x24, 6, 4, 1, b'a', 2, 1, 7];
    let mut reader = parser.read(&data, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = Octets::read(&reader, &element, "content").unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnexpectedTag);
    assert_eq!(error.offset(), 405);
    assert_eq!(memory.used(), 0);
}

#[test]
fn original_local_work_refuses_before_catalogue_construction() {
    // Header allowance alone cannot authorize parser paths/frame allocations.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 2,
            ..Limits::default()
        },
        memory.clone(),
    );
    let data = [0x24, 3, 4, 1, b'a'];
    let mut reader = parser.read(&data, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let error = Octets::read(&reader, &element, "content").unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "content");
    assert_eq!(memory.used(), 0);
    assert_eq!(memory.work_used(), 2);
}

#[test]
fn der_refuses_constructed_content() {
    // BER segmentation must not silently change the caller's DER contract.
    let parser = Parser::der(Memory::new(Arc::new(MemoryAccount::new(65536, 65536))));
    let data = [0x24, 3, 4, 1, b'a'];
    let mut reader = parser.read(&data, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    assert_eq!(
        Octets::read(&reader, &element, "content")
            .unwrap_err()
            .code(),
        ErrorCode::UnexpectedTag
    );
}

#[test]
fn copied_content_retains_exact_capacity_independently_of_parser() {
    // Explicit retention must assemble only content bytes, transfer its keeper
    // without another allocation, and outlive the source model/parser.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let bytes = [0x24, 7, 4, 1, b'a', 4, 2, b'b', b'c'];
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let content = Octets::read(&reader, &element, "content").unwrap();
    let copy = content
        .copy_in(&reader, "tstInfo.hashedMessage", 400)
        .unwrap();
    assert_eq!(copy.capacity(), 3);
    assert_eq!(&*copy, b"abc");
    drop(content);
    drop(reader);
    drop(parser);
    assert_eq!(memory.used(), 3);
    assert_eq!(&*copy, b"abc");
    drop(copy);
    assert_eq!(memory.used(), 0);
}

#[test]
fn foreign_copy_refuses_before_work_or_capacity_admission() {
    // A shared account is not authority to replace the producing local budget.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let foreign = Parser::ber(memory.clone());
    let bytes = [4, 1, b'a'];
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let content = Octets::read(&reader, &element, "content").unwrap();
    let other = foreign.read(&[], 0).unwrap();
    let work = memory.work_used();
    let error = content
        .copy_in(&other, "tstInfo.hashedMessage", 400)
        .unwrap_err();
    assert!(error.is_terminal());
    assert!(!error.is_resource());
    assert_eq!(
        error.code(),
        ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
    assert_eq!(error.offset(), 400);
    assert_eq!(memory.work_used(), work);
    assert_eq!(memory.used(), 0);
    assert_eq!(content.as_one(), Some(&b"a"[..]));
}

#[test]
fn empty_fragment_fanout_is_paid_even_without_output_capacity() {
    // Zero output length cannot hide traversal of attacker-controlled fragments.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::ber(memory.clone());
    let bytes = [0x24, 6, 4, 0, 4, 0, 4, 0];
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let content = Octets::read(&reader, &element, "content").unwrap();
    assert_eq!(content.len(), 0);
    assert_eq!(content.pieces().len(), 3);
    let held = memory.used();
    memory
        .charge_work((memory.work_remaining() - 2) as u64)
        .unwrap();
    let error = content
        .copy_in(&reader, "tstInfo.hashedMessage", 400)
        .unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "tstInfo.hashedMessage");
    assert_eq!(memory.used(), held);
    assert_eq!(content.pieces().len(), 3);
}

#[test]
fn spare_capacity_copy_refusal_releases_partial_output_and_keeps_source() {
    // Allocate exact capacity, copy the first fragment, then refuse the second
    // through the original local ceiling despite sufficient aggregate work.
    let bytes = [0x24, 8, 4, 2, b'a', b'b', 4, 2, b'c', b'd'];
    let measured = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let measuring_parser = Parser::ber(measured.clone());
    let mut measuring_reader = measuring_parser.read(&bytes, 400).unwrap();
    let element = measuring_reader.next_element().unwrap().unwrap();
    let measured_content = Octets::read(&measuring_reader, &element, "content").unwrap();
    let parsing_work = measured.work_used();
    drop(measured_content);
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: u64::try_from(parsing_work + 8).unwrap(),
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let content = Octets::read(&reader, &element, "content").unwrap();
    let held = memory.used();
    let error = content
        .copy_in(&reader, "tstInfo.hashedMessage", 400)
        .unwrap_err();
    assert!(error.is_resource());
    assert_eq!(memory.work_used(), parsing_work + 8);
    assert!(memory.work_remaining() > 1000);
    assert_eq!(memory.used(), held);
    assert_eq!(content.pieces()[0].as_bytes(), b"ab");
    assert_eq!(content.pieces()[1].as_bytes(), b"cd");
}
