use super::{Arena, Children, Kind, Node};
use crate::error::ErrorKind;
use crate::source::{Location, Source};
use alloc::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

#[test]
fn deep_object_ownership_drops_without_recursion_or_drop_time_allocation() {
    // A child-owning tree would overflow nextest's stack at this depth;
    // an allocating custom Drop would fail after capacity is exhausted.
    // Flat nodes/edges retain the same pointers when finished as owners.
    let work = Memory::new(Arc::new(MemoryAccount::new(64 * 1024 * 1024, usize::MAX)));
    let mut arena = Arena::new(&work);
    let location = Location::new(Source::File, 0, 1).unwrap();
    let mut root = arena
        .node(Node {
            kind: Kind::Null,
            location,
        })
        .unwrap();
    for _ in 0..100_000 {
        let mut children = Children::default();
        arena.append(&mut children, root, &work).unwrap();
        root = arena
            .node(Node {
                kind: Kind::Array(children),
                location,
            })
            .unwrap();
    }
    let node_pointer = arena.nodes.as_ptr();
    let link_pointer = arena.links.as_ptr();
    let arena = arena.into_owned();
    assert_eq!(arena.nodes.as_ptr(), node_pointer);
    assert_eq!(arena.links.as_ptr(), link_pointer);
    assert!(work.used() > 0);
    drop(arena);
    assert_eq!(work.used(), 0);
}

#[test]
fn failed_edge_admission_preserves_existing_children() {
    // Refusal must not splice a dangling new edge into the existing list
    // or increment its visible length before that edge actually exists.
    let work = Memory::new(Arc::new(MemoryAccount::new(4096, 10000)));
    let mut arena = Arena::new(&work);
    let location = Location::new(Source::File, 17, 1).unwrap();
    let value = arena
        .node(Node {
            kind: Kind::Null,
            location,
        })
        .unwrap();
    let mut children = Children::default();
    arena.append(&mut children, value, &work).unwrap();
    let original_first = children.first;
    let original_length = children.length;
    let denied = Memory::new(Arc::new(MemoryAccount::new(4096, 0)));
    let error = arena.append(&mut children, value, &denied).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Resource(MemoryError::WorkExceeded));
    assert_eq!(error.location, location);
    assert_eq!(children.first, original_first);
    assert_eq!(children.length, original_length);
    assert_eq!(arena.links.len(), 1);
    assert!(arena.links[children.first.unwrap()].next.is_none());
    drop(arena);
    assert_eq!(work.used(), 0);
}

#[test]
fn retained_arena_rebinding_keeps_buffers_and_applies_current_work_to_every_write() {
    // A new current query must fund writes even when the old owner has
    // spare capacity. All five buffers transfer without copy; refusal
    // preserves their values/capacity and the retained allocation charge.
    use super::{Entry, Link};
    use structured_asn1::{Encoding, Limits, Parser};
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 1_000_000)));
    let place = Location::new(Source::File, 17, 1).unwrap();
    let mut arena = Arena::new(&memory);
    let node = arena
        .node(Node {
            kind: Kind::Null,
            location: place,
        })
        .unwrap();
    arena.links.try_reserve_exact(8).unwrap();
    arena.names.try_extend_from_slice(b"name").unwrap();
    arena.fields.try_reserve_exact(8).unwrap();
    arena.faults.try_reserve_exact(8).unwrap();
    let pointer = arena.nodes.as_ptr();
    let held = memory.used();
    let limited = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Default::default()
        },
        memory.clone(),
    );
    let current = limited.execution_in(&memory);
    let mut scoped = arena
        .with_execution(&current)
        .unwrap_or_else(|_| panic!("same account"));
    assert_eq!(scoped.nodes.as_ptr(), pointer);
    assert!(
        scoped
            .node(Node {
                kind: Kind::Null,
                location: place
            })
            .is_err()
    );
    assert_eq!(
        scoped.links.try_push(Link {
            value: node,
            next: None
        }),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(scoped.names.try_push(b'x'), Err(MemoryError::WorkExceeded));
    assert_eq!(
        scoped.fields.try_push(Entry {
            key: node,
            value: node
        }),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(
        scoped.faults.try_push(crate::error::Fault {
            code: crate::error::Syntax::Dictionary,
            location: place
        }),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(scoped.nodes.len(), 1);
    assert!(scoped.links.is_empty());
    assert_eq!(&*scoped.names, b"name");
    assert!(scoped.fields.is_empty());
    assert!(scoped.faults.is_empty());
    assert_eq!(memory.used(), held);
    let owner = scoped.into_owned();
    drop(limited);
    assert_eq!(owner.nodes.as_ptr(), pointer);
    assert_eq!(memory.used(), held);
    drop(owner);
    assert_eq!(memory.used(), 0);
}
