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
fn artifact_census_respects_the_producing_ceiling_before_hashing() {
    // Artifact role propagation precedes incorporation lookup. It must not
    // hash/copy an exhausted external source before the index can refuse it.
    let source = funded();
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 10_000,
            ..structured_asn1::Limits::default()
        },
        source,
    );
    let bytes = fixture::certificate(1, Version::V1);
    let certificate = Certificate::read(&parser, &bytes, 100).unwrap();
    let reader = parser.read(&[], 0).unwrap();
    let producing = reader.execution();
    producing
        .charge_work(u64::try_from(producing.work_remaining()).unwrap())
        .unwrap();
    let work = funded();
    let mut census = Census {
        index: Some(work.map()),
        entries: work.vector(),
        targets: work.vector(),
    };
    assert_eq!(
        census.record(
            ArtifactRef::Certificate(&certificate),
            Uses::participant(Participant::Signer(0usize)),
            &work
        ),
        Err(MemoryError::WorkExceeded)
    );
    assert!(census.entries.is_empty());
    assert_eq!(work.used(), 0);
}

#[test]
fn cached_hash_collision_keeps_distinct_artifacts_and_merges_only_exact_values() {
    // A table-local fingerprint is only a bucket hint. Force the same hint
    // for different DER identities and revisit the older collision member.
    let first_bytes = fixture::certificate(1, Version::V1);
    let second_bytes = fixture::certificate(2, Version::V1);
    let source = funded();
    let parser = Parser::der(source);
    let first = Certificate::read(&parser, &first_bytes, 100).unwrap();
    let second = Certificate::read(&parser, &second_bytes, 900).unwrap();
    let work = funded();
    let mut census = Census {
        index: Some(work.map()),
        entries: work.vector(),
        targets: work.vector(),
    };
    let bucket = Bucket {
        kind: Kind::Certificate,
        hash: 7,
    };
    assert_eq!(
        census
            .record_hashed(
                ArtifactRef::Certificate(&first),
                Uses::participant(Participant::Signer(0usize)),
                &work,
                bucket
            )
            .unwrap(),
        0
    );
    assert_eq!(
        census
            .record_hashed(
                ArtifactRef::Certificate(&second),
                Uses::participant(Participant::Timestamp {
                    property: 1usize,
                    token: 2
                }),
                &work,
                bucket
            )
            .unwrap(),
        1
    );
    assert_eq!(
        census
            .record_hashed(
                ArtifactRef::Certificate(&first),
                Uses::participant(Participant::Credential {
                    signature: 0usize,
                    node: 3,
                    authority: 0
                }),
                &work,
                bucket
            )
            .unwrap(),
        0
    );
    assert_eq!(census.entries.len(), 2);
    assert!(census.entries[0].uses.signature());
    assert!(census.entries[0].uses.credential());
    assert!(!census.entries[0].uses.timestamp());
    assert!(census.entries[1].uses.timestamp());
    assert!(!census.entries[1].uses.signature());
}

#[test]
fn collision_comparison_keeps_the_retained_operand_producing_ceiling() {
    // A wider new source must not fund an old source's byte comparison after
    // that original reader's local budget has been exhausted.
    let first_bytes = fixture::certificate(1, Version::V1);
    let second_bytes = first_bytes.clone();
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 10_000,
            ..structured_asn1::Limits::default()
        },
        funded(),
    );
    let other = Parser::der(funded());
    let first = Certificate::read(&parser, &first_bytes, 100).unwrap();
    let second = Certificate::read(&other, &second_bytes, 900).unwrap();
    let work = funded();
    let mut census = Census {
        index: Some(work.map()),
        entries: work.vector(),
        targets: work.vector(),
    };
    let bucket = Bucket {
        kind: Kind::Certificate,
        hash: 7,
    };
    census
        .record_hashed(
            ArtifactRef::Certificate(&first),
            Uses::participant(Participant::Signer(0usize)),
            &work,
            bucket,
        )
        .unwrap();
    let reader = parser.read(&[], 0).unwrap();
    let producing = reader.execution();
    producing
        .charge_work(u64::try_from(producing.work_remaining()).unwrap())
        .unwrap();
    assert_eq!(
        census.record_hashed(
            ArtifactRef::Certificate(&second),
            Uses::participant(Participant::Timestamp {
                property: 1usize,
                token: 2
            }),
            &work,
            bucket
        ),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(census.entries.len(), 1);
    assert!(!census.entries[0].uses.timestamp());
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
        index: Some(work.map()),
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
        index: Some(work.map()),
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
