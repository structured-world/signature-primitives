use super::*;
use crate::material::fixture;
use crate::pki::Participant;
use alloc::sync::Arc;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_pkix::{Certificate, Version};

fn funded() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65_536, 1_000_000)))
}

#[test]
fn independent_parsed_copies_merge_roles_by_original_der() {
    // Distinct source allocations and parser sessions still denote ONE
    // artifact; a changed serial is another artifact even with the same key.
    let first_bytes = fixture::certificate(1, Version::V1);
    let copy_bytes = first_bytes.clone();
    let changed_bytes = fixture::certificate(2, Version::V1);
    assert_ne!(first_bytes.as_ptr(), copy_bytes.as_ptr());
    let source = funded();
    let first_parser = Parser::der(source.clone());
    let copy_parser = Parser::der(source.clone());
    let first = Certificate::read(&first_parser, &first_bytes, 100).unwrap();
    let copy = Certificate::read(&copy_parser, &copy_bytes, 900).unwrap();
    let changed = Certificate::read(&copy_parser, &changed_bytes, 1800).unwrap();
    let source_used = source.used();
    let work = funded();
    let mut census = Census {
        index: work.map(),
        entries: work.vector(),
        targets: work.vector(),
    };
    let timestamp = Uses::participant(Participant::Timestamp {
        property: 0usize,
        token: 1,
    });
    let signature = Uses::participant(Participant::Signer(0usize));
    let credential = Uses::participant(Participant::Credential {
        signature: 0usize,
        node: 3,
        authority: 0,
    });
    census
        .record(ArtifactRef::Certificate(&first), timestamp, &work)
        .unwrap();
    census
        .record(ArtifactRef::Certificate(&copy), signature, &work)
        .unwrap();
    census
        .record(ArtifactRef::Certificate(&copy), credential, &work)
        .unwrap();
    census
        .record(ArtifactRef::Certificate(&changed), credential, &work)
        .unwrap();
    assert_eq!(census.entries.len(), 2);
    assert!(census.entries[0].uses.signature());
    assert!(census.entries[0].uses.credential());
    assert!(census.entries[0].uses.timestamp());
    assert!(!census.entries[1].uses.signature());
    assert!(census.entries[1].uses.credential());
    assert!(!census.entries[1].uses.timestamp());
    assert!(matches!(census.entries[0].artifact,
        ArtifactRef::Certificate(value) if core::ptr::eq(value, &raw const first)));
    drop(census);
    assert_eq!(work.used(), 0);
    assert_eq!(source.used(), source_used);
}

#[test]
fn refused_merge_preserves_first_roles_and_releases_scratch() {
    // Refuse before inspecting/mutating an already seen artifact. A denied
    // additional role cannot partially change classification or source data.
    let bytes = fixture::certificate(1, Version::V1);
    let source = funded();
    let parser = Parser::der(source.clone());
    let value = Certificate::read(&parser, &bytes, 100).unwrap();
    let source_used = source.used();
    let work = funded();
    let mut census = Census {
        index: work.map(),
        entries: work.vector(),
        targets: work.vector(),
    };
    census
        .record(
            ArtifactRef::Certificate(&value),
            Uses::participant(Participant::Timestamp {
                property: 0usize,
                token: 1,
            }),
            &work,
        )
        .unwrap();
    work.charge_work(u64::try_from(work.work_remaining()).unwrap())
        .unwrap();
    let held = work.used();
    assert_eq!(
        census.record(
            ArtifactRef::Certificate(&value),
            Uses::participant(Participant::Signer(0usize)),
            &work
        ),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(census.entries.len(), 1);
    assert!(census.entries[0].uses.timestamp());
    assert!(!census.entries[0].uses.signature());
    assert_eq!(work.used(), held);
    drop(census);
    assert_eq!(work.used(), 0);
    assert_eq!(source.used(), source_used);
}
