use super::*;
use crate::{
    material::fixture,
    source::{Scope, Source},
};
use alloc::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount},
};

struct Original;
impl Source for Original {
    type Id = usize;
    type Document = u8;
    type Generation = u8;
    fn snapshot(&self) -> Snapshot<u8, u8> {
        Snapshot {
            document: 1,
            generation: 0,
        }
    }
}
fn funded() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65_536, 1_000_000)))
}

#[test]
fn external_artifact_lookup_keeps_its_producing_ceiling_even_in_an_empty_index() {
    // A wide current query or equal aggregate account cannot turn an exhausted
    // external certificate's source ceiling into successful material absence.
    for shared_account in [false, true] {
        let original = funded();
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 10_000,
                ..Limits::default()
            },
            original.clone(),
        );
        let bytes = fixture::certificate(1, structured_pkix::Version::V1);
        let certificate = Certificate::read(&parser, &bytes, 400).unwrap();
        let reader = parser.read(&[], 0).unwrap();
        let source_work = reader.execution();
        source_work
            .charge_work(u64::try_from(source_work.work_remaining()).unwrap())
            .unwrap();
        assert_eq!(source_work.charge_work(1), Err(MemoryError::WorkExceeded));
        let current = if shared_account { original } else { funded() };
        let source = Original;
        let query = Scope::new(&source, source.snapshot(), &current);
        let index: Index<'_, usize, u8, u8, (), (), Memory, ()> =
            Index::new((), 0, &[], &query).unwrap();
        assert!(matches!(
            index.certificate(&certificate, &query),
            Err(IndexError::Resource {
                signature: 0,
                cause: MemoryError::WorkExceeded
            })
        ));
        assert!(matches!(
            index.artifact(ArtifactRef::Certificate(&certificate), &query),
            Err(IndexError::Resource {
                signature: 0,
                cause: MemoryError::WorkExceeded
            })
        ));
    }
}

#[test]
fn independently_parsed_lookup_cannot_scan_an_exhausted_stored_source() {
    // Equal DER in a fresh, wider parser is not permission to compare bytes
    // retained from an exhausted producer. Check both original operands.
    let original = funded();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 10_000,
            ..Limits::default()
        },
        original,
    );
    let bytes = fixture::certificate(1, structured_pkix::Version::V1);
    let certificate = Certificate::read(&parser, &bytes, 400).unwrap();
    let current = funded();
    let target_parser = Parser::der(current.clone());
    let target = Certificate::read(&target_parser, &bytes, 700).unwrap();
    let source = Original;
    let query = Scope::new(&source, source.snapshot(), &current);
    let mut index: Index<'_, usize, u8, u8, (), (), Memory, ()> =
        Index::new((), 0, &[], &query).unwrap();
    index
        .insert(
            (),
            ArtifactRef::Certificate(&certificate),
            Occurrence::new(
                ArtifactSource::Material(0),
                Location {
                    snapshot: source.snapshot(),
                    node: 1,
                },
                (),
            ),
            &query,
        )
        .unwrap();
    let reader = parser.read(&[], 0).unwrap();
    let work = reader.execution();
    work.charge_work(u64::try_from(work.work_remaining()).unwrap())
        .unwrap();
    assert!(matches!(
        index.certificate(&target, &query),
        Err(IndexError::Resource {
            signature: 0,
            cause: MemoryError::WorkExceeded
        })
    ));
}

#[test]
fn failed_insertion_cannot_expose_a_successful_partial_index() {
    // A caller cannot ignore an incomplete build's refusal and then promote
    // an earlier successful prefix using a fresh query budget.
    let producer_memory = funded();
    let parser = Parser::der(producer_memory);
    let bytes = fixture::certificate(1, structured_pkix::Version::V1);
    let certificate = Certificate::read(&parser, &bytes, 400).unwrap();
    let storage = funded();
    let source = Original;
    let query = Scope::new(&source, source.snapshot(), &storage);
    let mut index: Index<'_, usize, u8, u8, (), (), Memory, ()> =
        Index::new((), 0, &[], &query).unwrap();
    let occurrence = Occurrence::new(
        ArtifactSource::Material(0),
        Location {
            snapshot: source.snapshot(),
            node: 1,
        },
        (),
    );
    index
        .insert(
            (),
            ArtifactRef::Certificate(&certificate),
            occurrence,
            &query,
        )
        .unwrap();
    storage
        .charge_work(storage.work_remaining() as u64)
        .unwrap();
    let refusal = index
        .insert(
            (),
            ArtifactRef::Certificate(&certificate),
            occurrence,
            &query,
        )
        .unwrap_err();
    let current = funded();
    let current = Scope::new(&source, source.snapshot(), &current);
    assert_eq!(
        index.certificate(&certificate, &current).err(),
        Some(refusal)
    );
}

#[test]
fn cached_bucket_collisions_still_compare_exact_original_artifacts() {
    // A table-local fingerprint only selects candidates. Force two distinct
    // DER values into one candidate chain and retain exact identity semantics.
    let bytes_a = fixture::certificate(1, structured_pkix::Version::V1);
    let bytes_b = fixture::certificate(2, structured_pkix::Version::V1);
    let bytes_c = fixture::certificate(3, structured_pkix::Version::V1);
    let parser = Parser::der(funded());
    let a = Certificate::read(&parser, &bytes_a, 100).unwrap();
    let b = Certificate::read(&parser, &bytes_b, 200).unwrap();
    let c = Certificate::read(&parser, &bytes_c, 300).unwrap();
    let storage = funded();
    let source = Original;
    let query = Scope::new(&source, source.snapshot(), &storage);
    let mut index: Index<'_, usize, u8, u8, (), (), Memory, ()> =
        Index::new((), 0, &[], &query).unwrap();
    for (ordinal, value) in [&a, &b].into_iter().enumerate() {
        index
            .insert(
                (),
                ArtifactRef::Certificate(value),
                Occurrence::new(
                    ArtifactSource::Material(ordinal),
                    Location {
                        snapshot: source.snapshot(),
                        node: ordinal + 1,
                    },
                    (),
                ),
                &query,
            )
            .unwrap();
    }
    let key = ArtifactRef::Certificate(&a).identity();
    let bucket = Bucket {
        kind: key.kind,
        hash: index
            .keys
            .as_ref()
            .unwrap()
            .fingerprint(&key, &storage)
            .unwrap(),
    };
    index.classes[0].next = Some(1);
    assert_eq!(
        index
            .class(
                &bucket,
                ArtifactRef::Certificate(&b).identity(),
                b.signature_algorithm().execution_origin(),
                &query
            )
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        index
            .class(
                &bucket,
                ArtifactRef::Certificate(&c).identity(),
                c.signature_algorithm().execution_origin(),
                &query
            )
            .unwrap(),
        None
    );
}

#[test]
fn growing_new_metadata_never_rehashes_an_exhausted_original_der_source() {
    // Independent new artifacts may grow and rehash table METADATA. They
    // cannot charge or scan an old producer's DER as a side effect of growth.
    let first_bytes = fixture::certificate(1, structured_pkix::Version::V1);
    let old_parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 10_000,
            ..Limits::default()
        },
        funded(),
    );
    let first = Certificate::read(&old_parser, &first_bytes, 100).unwrap();
    let rest: alloc::vec::Vec<_> = (2..=64)
        .map(|number| fixture::certificate(number, structured_pkix::Version::V1))
        .collect();
    let parser = Parser::der(funded());
    let rest: alloc::vec::Vec<_> = rest
        .iter()
        .map(|bytes| Certificate::read(&parser, bytes, 200).unwrap())
        .collect();
    let storage = funded();
    let source = Original;
    let query = Scope::new(&source, source.snapshot(), &storage);
    let mut index: Index<'_, usize, u8, u8, (), (), Memory, ()> =
        Index::new((), 0, &[], &query).unwrap();
    index
        .insert(
            (),
            ArtifactRef::Certificate(&first),
            Occurrence::new(
                ArtifactSource::Material(0),
                Location {
                    snapshot: source.snapshot(),
                    node: 1,
                },
                (),
            ),
            &query,
        )
        .unwrap();
    let reader = old_parser.read(&[], 0).unwrap();
    let old = reader.execution();
    old.charge_work(u64::try_from(old.work_remaining()).unwrap())
        .unwrap();
    for (ordinal, value) in rest.iter().enumerate() {
        index
            .insert(
                (),
                ArtifactRef::Certificate(value),
                Occurrence::new(
                    ArtifactSource::Material(ordinal + 1),
                    Location {
                        snapshot: source.snapshot(),
                        node: ordinal + 2,
                    },
                    (),
                ),
                &query,
            )
            .unwrap();
    }
    let count = index
        .all_occurrences(&query)
        .unwrap()
        .collect::<Result<alloc::vec::Vec<_>, _>>()
        .unwrap()
        .len();
    assert_eq!(count, 64);
    assert_eq!(old.work_remaining(), 0);
    drop(index);
    assert_eq!(storage.used(), 0);
}
