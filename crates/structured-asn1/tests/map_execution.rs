//! Storage mutation must admit value movement as well as hash/probe work.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Limits, Parser};

#[test]
fn replacement_refuses_before_unfunded_value_copy_and_preserves_old_entry() {
    // Same-key lookup admits four fixed hash/probe/equality units in a table
    // with one usize key. Replacing a 256-byte value still needs its own move
    // admission; no allocation during replace does not make copying free.
    let measured = Memory::new(Arc::new(MemoryAccount::new(16384, 65536)));
    let mut first = measured.map();
    first.try_insert(1_usize, [1_u8; 256]).unwrap();
    let initial = measured.work_used();
    drop(first);
    let limited = Memory::new(Arc::new(MemoryAccount::new(16384, initial + 4)));
    let mut map = limited.map();
    map.try_insert(1_usize, [1_u8; 256]).unwrap();
    assert_eq!(
        map.try_insert(1_usize, [2_u8; 256]),
        Err(MemoryError::WorkExceeded)
    );
    let query = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
    assert_eq!(map.get(&1, &query).unwrap(), Some(&[1_u8; 256]));
    drop(map);
    assert_eq!(limited.used(), 0);
}

#[test]
fn scoped_table_growth_and_probes_stop_at_the_producing_ceiling() {
    // Hashbrown's allocator and insertion/equality paths must all use sealed
    // Execution while this table is scratch; aggregate slack cannot fund a
    // grow/hash/probe outside the original parser's allowance.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 1024,
            ..Limits::default()
        },
        memory.clone(),
    );
    let reader = parser.read(&[], 0).unwrap();
    let mut map = reader.execution().map();
    let mut refused = false;
    for key in 0..100_usize {
        match map.try_insert(key, key) {
            Ok(None) => {}
            Err(MemoryError::WorkExceeded) => {
                refused = true;
                break;
            }
            other => panic!("unexpected insertion: {other:?}"),
        }
    }
    assert!(refused);
    let current = Memory::new(Arc::new(MemoryAccount::new(0, 65536)));
    assert_eq!(map.get(&0, &current).unwrap(), Some(&0));
    assert!(map.get(&99, &current).unwrap().is_none());
    assert!(memory.work_used() <= 1024);
    drop(map);
    assert_eq!(memory.used(), 0);
}
