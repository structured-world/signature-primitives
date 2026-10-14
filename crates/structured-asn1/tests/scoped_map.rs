//! Scoped map mutation admits value copying even without table growth.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, Work},
};

#[test]
fn scoped_value_moves_refuse_without_table_growth() {
    // Enough local work remains for hashing/equality, but not two value moves.
    // A replacement must leave original data and capacity intact on refusal.
    for (key, remaining) in [(2, 1024), (1, 4)] {
        let limit = 100_000;
        let memory = Memory::new(Arc::new(MemoryAccount::new(1_000_000, 1_000_000)));
        let parser = Parser::new(
            Encoding::Der,
            Limits {
                max_work: limit,
                ..Limits::default()
            },
            memory.clone(),
        );
        let parent = parser.read(&[], 0).unwrap();
        let mut map = parent.execution().map();
        map.try_insert(1_usize, [1_u8; 4096]).unwrap();
        let capacity = memory.used();
        parent
            .charge(limit - u64::try_from(memory.work_used()).unwrap() - remaining)
            .unwrap();
        assert!(
            map.try_insert(key, [2; 4096]).is_err(),
            "unfunded value move for key {key}"
        );
        let query = Memory::new(Arc::new(MemoryAccount::new(0, 1000)));
        assert_eq!(map.get(&1, &query).unwrap(), Some(&[1; 4096]));
        assert!(map.get(&2, &query).unwrap().is_none());
        assert_eq!(memory.used(), capacity);
        drop(map);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn prepaid_iteration_does_not_borrow_the_query_cursor() {
    // Payment belongs to the query, but the iterator borrows only stored data.
    let memory = Memory::new(Arc::new(MemoryAccount::new(1000, 10_000)));
    let mut map = memory.map();
    map.try_insert(1_usize, 2_usize).unwrap();
    let query = Memory::new(Arc::new(MemoryAccount::new(0, 1000)));
    let mut entries = {
        let parser = Parser::der(query.clone());
        let parent = parser.read(&[], 0).unwrap();
        map.try_iter(&parent.execution()).unwrap()
    };
    assert_eq!(entries.next(), Some((&1, &2)));
    assert!(entries.next().is_none());
    assert!(query.work_used() > 0);
}
