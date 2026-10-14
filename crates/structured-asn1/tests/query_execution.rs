//! Original-source and current-operation ceilings fund deferred readers once.

use std::sync::Arc;
use structured_asn1::{
    Encoding, ErrorCode, Limit, Limits, Parser,
    memory::{Memory, MemoryAccount, Work},
};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

#[test]
fn foreign_source_scan_and_scratch_obey_current_query_ceiling() {
    // The stored document's generous budget is not credit for a zero-budget
    // later query. Current account and local ceiling are both checked before
    // reader creation, scanning and scratch allocation/copy.
    let storage = memory();
    let current = memory();
    let origin = Parser::der(storage.clone());
    let none = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = none.read(&[], 900).unwrap();
    let error = origin
        .read_nested_query_in(&query, &[2, 1, 7], 400, Encoding::Der, 0)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Work));
    assert_eq!(error.offset(), 400);
    assert_eq!(current.work_used(), 0);
    assert_eq!(storage.work_used(), 0);
    let limited = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 3,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = limited.read(&[], 900).unwrap();
    let mut reader = origin
        .read_nested_query_in(&query, &[2, 1, 7], 400, Encoding::Der, 0)
        .unwrap();
    assert!(reader.next_element().unwrap().is_some());
    assert_eq!(current.work_used(), 3);
    assert_eq!(storage.work_used(), 0);
    let mut scratch = reader.execution().vector();
    assert!(scratch.try_push(7_u8).is_err());
    assert_eq!(current.used(), 0);
    assert_eq!(current.work_used(), 3);
}

#[test]
fn same_source_operation_deduplicates_local_and_aggregate_accounting() {
    // One creation plus one short header costs exactly three units, even when
    // the source and current-operation Budget are the very same object.
    let current = memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 3,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = parser.read(&[], 900).unwrap();
    let mut reader = parser
        .read_nested_query_in(&query, &[2, 1, 7], 400, Encoding::Der, 0)
        .unwrap();
    assert!(reader.next_element().unwrap().is_some());
    assert_eq!(current.work_used(), 3);
    assert!(reader.charge(1).unwrap_err().is_resource());
    assert_eq!(current.work_used(), 3);
}

#[test]
fn foreign_transition_retains_root_operation_and_original_depth() {
    // The intermediate source is not a fresh operation ceiling. A second
    // foreign source must retain the root's remaining one unit and its depth.
    let current = memory();
    let root = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 2,
            max_depth: 2,
            ..Limits::default()
        },
        current.clone(),
    );
    let first = Parser::der(memory());
    let second = Parser::der(memory());
    let query = root.read(&[], 900).unwrap();
    let first_reader = first
        .read_nested_query_in(&query, &[], 400, Encoding::Der, 0)
        .unwrap();
    let mut second_reader = second
        .read_nested_query_in(&first_reader, &[2, 1, 7], 700, Encoding::Der, 0)
        .unwrap();
    assert!(core::ptr::eq(
        second_reader.parser(),
        core::ptr::from_ref(&second)
    ));
    assert_eq!(second_reader.depth(), 1);
    assert_eq!(second_reader.next_element().unwrap_err().offset(), 700);
    assert_eq!(current.work_used(), 2);
    let error = second
        .read_nested_query_in(&query, &[], 700, Encoding::Der, 2)
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Depth));
    assert_eq!(current.work_used(), 2);
}

#[test]
fn clone_reread_and_descent_keep_current_element_ceiling() {
    // Cursor copying, rereading and entering must not reset the later query's
    // element counter, even though the stored source permits many elements.
    let current = memory();
    let root = Parser::new(
        Encoding::Ber,
        Limits {
            max_elements: 1,
            ..Limits::default()
        },
        current.clone(),
    );
    let source = Parser::ber(memory());
    let query = root.read(&[], 900).unwrap();
    let mut reader = source
        .read_nested_query_in(&query, &[0x30, 3, 2, 1, 7], 400, Encoding::Ber, 0)
        .unwrap();
    let sequence = reader.next_element().unwrap().unwrap();
    let mut copied = reader.try_clone().unwrap();
    assert!(copied.next_element().unwrap().is_none());
    let mut repeated = copied.reread(&sequence, Encoding::Ber).unwrap();
    assert_eq!(
        repeated.next_element().unwrap_err().code(),
        ErrorCode::LimitExceeded(Limit::Elements)
    );
    let mut child = copied.enter(&sequence).unwrap();
    assert_eq!(
        child.next_element().unwrap_err().code(),
        ErrorCode::LimitExceeded(Limit::Elements)
    );
    assert_eq!(child.depth(), 2);
    assert!(core::ptr::eq(child.parser(), core::ptr::from_ref(&source)));
}

#[test]
fn query_length_refusal_precedes_indefinite_descendant_scan() {
    // Both definite contents and BER indefinite scanning must obey the current
    // query's length ceiling, not only the source's original large allowance.
    let current = memory();
    let root = Parser::new(
        Encoding::Ber,
        Limits {
            max_element_length: 2,
            ..Limits::default()
        },
        current.clone(),
    );
    let source = Parser::ber(memory());
    let query = root.read(&[], 900).unwrap();
    let mut definite = source
        .read_nested_query_in(&query, &[4, 3, 1, 2, 3], 400, Encoding::Ber, 0)
        .unwrap();
    assert_eq!(
        definite.next_element().unwrap_err().code(),
        ErrorCode::LimitExceeded(Limit::ElementLength)
    );
    let mut indefinite = source
        .read_nested_query_in(
            &query,
            &[0x30, 0x80, 4, 3, 1, 2, 3, 0, 0],
            700,
            Encoding::Ber,
            0,
        )
        .unwrap();
    assert_eq!(
        indefinite.next_element().unwrap_err().code(),
        ErrorCode::LimitExceeded(Limit::ElementLength)
    );
    assert_eq!(current.used(), 0);
}
