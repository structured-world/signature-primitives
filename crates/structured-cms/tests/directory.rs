//! Catalogue answers, provenance, current query funding and rollback.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::directory::{Directory, Error, Match};
use structured_cms::signer::SignerIdentifier;
use structured_pkix::Certificate;

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if contents.len() < 128 {
        bytes.push(u8::try_from(contents.len()).unwrap());
    } else {
        bytes.extend_from_slice(&[0x81, u8::try_from(contents.len()).unwrap()]);
    }
    bytes.extend_from_slice(contents);
    bytes
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn name(value: &str) -> Vec<u8> {
    seq(&[tlv(
        0x31,
        &seq(&[tlv(6, &[0x55, 4, 3]), tlv(12, value.as_bytes())]),
    )])
}
fn certificate(issuer: &str, serial: u8, identifier: Option<&[u8]>) -> Vec<u8> {
    // Synthetic DER cert; this suite tests hints, never cryptographic trust.
    let algorithm = seq(&[tlv(6, &[42])]);
    let mut fields = vec![
        tlv(0xa0, &[2, 1, 2]),
        tlv(2, &[serial]),
        algorithm.clone(),
        name(issuer),
        seq(&[tlv(23, b"240101000000Z"), tlv(23, b"300101000000Z")]),
        name("subject"),
        seq(&[algorithm.clone(), tlv(3, &[0, 1])]),
    ];
    if let Some(identifier) = identifier {
        let extension = seq(&[tlv(6, &[0x55, 0x1d, 0x0e]), tlv(4, identifier)]);
        fields.push(tlv(0xa3, &seq(&[extension])));
    }
    seq(&[seq(&fields), algorithm, tlv(3, &[0, 1])])
}

fn identifier<'a>(parser: &'a Parser, encoded: &'a [u8]) -> SignerIdentifier<'a> {
    let mut reader = parser.read(encoded, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    SignerIdentifier::SubjectKeyIdentifier(
        structured_cms::Octets::read(&reader, &element, "sid").unwrap(),
    )
}

fn issuer<'a>(parser: &'a Parser, encoded: &'a [u8], serial: &'a [u8]) -> SignerIdentifier<'a> {
    let mut reader = parser.read(encoded, 900).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let issuer = structured_pkix::name::read(&reader, &element, "sid.issuer").unwrap();
    let mut reader = parser.read(serial, 950).unwrap();
    let serial = reader.read_integer().unwrap();
    SignerIdentifier::IssuerAndSerial { issuer, serial }
}

#[test]
fn retained_and_scoped_indexes_share_name_order_and_complete_hint_answers() {
    // Issuer preparation is once per candidate/query, including full folding;
    // repeated certificates are ambiguity, never an arbitrary selected signer.
    let storage = memory(1_000_000, 1_000_000);
    let parser = Parser::der(storage.clone());
    let left_bytes = certificate("Straße", 7, Some(&[4, 1, 9]));
    let right_bytes = certificate("other", 8, Some(&[4, 1, 10]));
    let left = Certificate::read(&parser, &left_bytes, 400).unwrap();
    let right = Certificate::read(&parser, &right_bytes, 700).unwrap();
    let query_name = name(" STRASSE ");
    let query = issuer(&parser, &query_name, &[2, 1, 7]);
    let parent = parser.read(&[], 1000).unwrap();
    let original_used = storage.used();
    let retained = Directory::of(&[&right, &left], &storage).unwrap();
    let scoped = Directory::of_in(&[&right, &left], &parent).unwrap();
    for answer in [
        retained.find(&query, &storage),
        scoped.find_in(&query, &parent),
    ] {
        let Match::One(found) = answer.unwrap() else {
            panic!("lost unique hint")
        };
        assert!(core::ptr::eq(found, &raw const left));
    }
    let duplicate = Directory::of(&[&left, &left], &storage).unwrap();
    assert!(matches!(
        duplicate.find(&query, &storage).unwrap(),
        Match::Ambiguous
    ));
    drop(duplicate);
    drop(retained);
    drop(scoped);
    assert_eq!(storage.used(), original_used);
}

#[test]
fn segmented_ski_is_borrowed_and_unreadable_gap_is_not_absence_or_unique() {
    // One unreadable extension leaves uniqueness unproved; two known answers
    // already prove ambiguity, independently of any unreadable remainder.
    let storage = memory(1_000_000, 1_000_000);
    let parser = Parser::ber(storage.clone());
    let good_bytes = certificate("issuer", 1, Some(&[4, 2, 7, 8]));
    let bad_bytes = certificate("issuer", 2, Some(&[2, 1, 7]));
    let good = Certificate::read(&parser, &good_bytes, 400).unwrap();
    let bad = Certificate::read(&parser, &bad_bytes, 700).unwrap();
    let segmented = identifier(&parser, &[0x24, 6, 4, 1, 7, 4, 1, 8]);
    let primitive = identifier(&parser, &[4, 2, 7, 8]);
    let absent = identifier(&parser, &[4, 1, 99]);
    let directory = Directory::of(&[&bad, &good], &storage).unwrap();
    assert_eq!(directory.unreadable_identifiers().len(), 1);
    let held = directory.unreadable_identifiers()[0].certificate();
    assert!(core::ptr::eq(held, &raw const bad));
    assert!(!directory.unreadable_identifiers()[0].reason().is_resource());
    for query in [&segmented, &primitive, &absent] {
        assert!(matches!(
            directory.find(query, &storage).unwrap(),
            Match::Unreadable
        ));
    }
    let duplicates = Directory::of(&[&bad, &good, &good], &storage).unwrap();
    for query in [&segmented, &primitive] {
        assert!(matches!(
            duplicates.find(query, &storage).unwrap(),
            Match::Ambiguous
        ));
    }
    let valid = Directory::of(&[&good], &storage).unwrap();
    assert!(matches!(
        valid.find(&absent, &storage).unwrap(),
        Match::None
    ));
    let Match::One(found) = valid.find(&segmented, &storage).unwrap() else {
        panic!("segmented identifier lost")
    };
    assert!(core::ptr::eq(found, &raw const good));
}

#[test]
fn foreign_pool_preflight_uses_parser_identity_before_allocating_or_lazy_ski() {
    // Shared account is not shared Parser identity. Even a later foreign
    // candidate must refuse before retained handles/Name/SKI scratch exist.
    let storage = memory(1_000_000, 1_000_000);
    let left_parser = Parser::der(storage.clone());
    let right_parser = Parser::der(storage.clone());
    let left_bytes = certificate("issuer", 1, None);
    let right_bytes = certificate("issuer", 2, Some(&[2, 1, 1]));
    let left = Certificate::read(&left_parser, &left_bytes, 400).unwrap();
    let right = Certificate::read(&right_parser, &right_bytes, 700).unwrap();
    let parent = left_parser.read(&[], 1000).unwrap();
    let held = storage.used();
    let Err(error) = Directory::of_in(&[&left, &right], &parent) else {
        panic!("foreign source accepted");
    };
    let Error::Processing(error) = error else {
        panic!("missing located session error")
    };
    assert_eq!(
        error.code(),
        structured_cms::ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
    assert_eq!(error.offset(), 700);
    assert_eq!(storage.used(), held);
    let retained = Directory::of(&[&left, &right], &storage).unwrap();
    assert_eq!(retained.len(), 2);
    assert_eq!(retained.unreadable_identifiers().len(), 1);
}

#[test]
fn new_query_budget_is_independent_of_retained_storage_and_refusal_is_not_none() {
    // A retained pool can be queried under another operation, but its existing
    // storage account cannot pay the new traversal or hide a local refusal.
    let storage = memory(1_000_000, 1_000_000);
    let parser = Parser::der(storage.clone());
    let encoded = certificate("issuer", 1, Some(&[4, 1, 7]));
    let certificate = Certificate::read(&parser, &encoded, 400).unwrap();
    let directory = Directory::of(&[&certificate], &storage).unwrap();
    let query = identifier(&parser, &[4, 1, 7]);
    let held = storage.used();
    let previous_work = storage.work_used();
    let current = memory(1_000_000, 1_000_000);
    let current_parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let parent = current_parser.read(&[], 1234).unwrap();
    let Error::Processing(error) = directory.find_in(&query, &parent).unwrap_err() else {
        panic!("missing current location")
    };
    assert!(error.is_resource());
    assert_eq!(error.offset(), 1234);
    assert_eq!(current.used(), 0);
    assert_eq!(current.work_used(), 0);
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), previous_work);
    let exhausted = memory(1_000_000, 0);
    assert!(matches!(
        directory.find(&query, &exhausted),
        Err(Error::Resource(_))
    ));
    assert_eq!(storage.work_used(), previous_work);
}

#[test]
fn construction_storage_refusal_rolls_back_without_inventing_a_document_position() {
    // Source-free retained handle storage reports its own resource cause;
    // a failed scoped construction releases every temporary allocation.
    let storage = memory(1_000_000, 1_000_000);
    let parser = Parser::der(storage.clone());
    let encoded = certificate("Straße", 1, Some(&[4, 1, 7]));
    let certificate = Certificate::read(&parser, &encoded, 400).unwrap();
    let exhausted = memory(0, 1_000_000);
    assert!(matches!(
        Directory::of(&[&certificate], &exhausted),
        Err(Error::Resource(_))
    ));
    assert_eq!(exhausted.used(), 0);
    let parent = parser.read(&[], 1500).unwrap();
    let parent = parent.with_execution(&exhausted);
    let Error::Processing(error) = (match Directory::of_in(&[&certificate], &parent) {
        Ok(_) => panic!("unfunded storage accepted"),
        Err(error) => error,
    }) else {
        panic!("missing scoped storage refusal")
    };
    assert!(error.is_resource());
    assert_eq!(error.offset(), 1500);
    assert_eq!(exhausted.used(), 0);
}

#[test]
fn partial_preparation_and_sort_refusals_release_all_temporary_capacity() {
    // Sweep real admission boundaries across handle retention, canonical name
    // preparation, parallel index growth and sort. A partial directory never
    // survives refusal and no source certificate storage is charged twice.
    let storage = memory(1_000_000, 1_000_000);
    let parser = Parser::der(storage.clone());
    let a_bytes = certificate("Straße", 7, Some(&[4, 1, 9]));
    let b_bytes = certificate("other", 8, Some(&[4, 1, 10]));
    let a = Certificate::read(&parser, &a_bytes, 400).unwrap();
    let b = Certificate::read(&parser, &b_bytes, 700).unwrap();
    let original_capacity = storage.used();
    let original_work = storage.work_used();
    for limit in [0, 8, 32, 64, 128, 256, 512, 1024] {
        let current = memory(limit, 1_000_000);
        match Directory::of(&[&a, &b], &current) {
            Ok(directory) => drop(directory),
            Err(Error::Resource(_)) => {}
            Err(Error::Processing(error)) => assert!(error.is_resource()),
        }
        assert_eq!(current.used(), 0);
        assert_eq!(storage.used(), original_capacity);
    }
    // This fixture has no repeated lazy parse after the first read, except
    // its SKI decoder, whose original session meter intentionally remains.
    assert!(storage.work_used() >= original_work);
    for limit in [0, 8, 32, 64, 128, 256, 512, 1024] {
        let current = memory(1_000_000, limit);
        match Directory::of(&[&a, &b], &current) {
            Ok(directory) => drop(directory),
            Err(Error::Resource(_)) => {}
            Err(Error::Processing(error)) => assert!(error.is_resource()),
        }
        assert_eq!(current.used(), 0);
        assert_eq!(storage.used(), original_capacity);
    }
}

#[test]
fn lazy_ski_resource_error_does_not_become_an_unreadable_catalogue_gap() {
    // Retained construction preserves the original parser-local ceiling for
    // deferred SKI reads, even when its new aggregate account has room.
    let storage = memory(1_000_000, 1_000_000);
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 100_000,
            ..Limits::default()
        },
        storage.clone(),
    );
    let encoded = certificate("issuer", 1, Some(&[4, 1, 7]));
    let certificate = Certificate::read(&parser, &encoded, 400).unwrap();
    let parent = parser.read(&[], 1500).unwrap();
    // Exhaust exactly the same allowance without a hundred thousand interpreter
    // calls. Refused admission consumes nothing, so halve until the final unit.
    let mut step = 100_000;
    while step > 0 {
        while parent.charge(step).is_ok() {}
        step /= 2;
    }
    let current = memory(1_000_000, 1_000_000);
    let Err(Error::Processing(error)) = Directory::of(&[&certificate], &current) else {
        panic!("local refusal hidden by catalogue answer");
    };
    assert!(error.is_resource());
    assert_eq!(error.field(), "extensions.subjectKeyIdentifier");
    assert_eq!(current.used(), 0);
}
#[test]
fn scoped_directory_lazy_ski_cannot_bypass_current_query_work() {
    // Compare the same complete construction's aggregate cost with a stricter
    // current local allowance. A lazy SKI reader must not disappear from that
    // allowance while still billing the same aggregate account.
    let bytes = certificate("Issuer", 7, Some(&[4, 3, 7, 8, 9]));
    let mut full_cost = None;
    for limited in [false, true] {
        let storage = memory(1_000_000, 1_000_000);
        let source = Parser::der(storage);
        let certificate = Certificate::read(&source, &bytes, 400).unwrap();
        let current = memory(1_000_000, 1_000_000);
        let maximum = if limited {
            u64::try_from(full_cost.unwrap() - 1).unwrap()
        } else {
            u64::MAX
        };
        let operation = Parser::new(
            structured_asn1::Encoding::Der,
            structured_asn1::Limits {
                max_work: maximum,
                ..structured_asn1::Limits::default()
            },
            current.clone(),
        );
        let query = operation.read(&[], 900).unwrap();
        let parent = source.read(&[], 400).unwrap().with_query(&query).unwrap();
        let answer = Directory::of_in(&[&certificate], &parent);
        if limited {
            assert!(
                answer.is_err(),
                "lazy SKI work escaped current query ceiling"
            );
        } else {
            assert!(answer.is_ok());
            full_cost = Some(current.work_used());
        }
        drop(answer);
        drop(parent);
        assert_eq!(current.used(), 0);
    }
}
