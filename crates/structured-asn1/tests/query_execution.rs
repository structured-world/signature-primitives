//! Original-source and current-operation ceilings fund deferred readers once.

use std::sync::Arc;
use structured_asn1::{
    Encoding, ErrorCode, Limit, Limits, Parser,
    memory::{Memory, MemoryAccount, Work},
};

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, 65536)))
}

fn lazy_from_work<'source, W: Work + 'source>(
    execution: &W,
    source: &'source Parser,
    bytes: &'source [u8],
) -> structured_asn1::Result<structured_asn1::Reader<'source>> {
    execution.read_nested(source, bytes, 400, Encoding::Ber, 2)
}

#[test]
fn generic_work_fresh_source_uses_actual_depth_zero_without_a_fake_carrier() {
    // Retained original windows (e.g. BER Name string preparation) can need a
    // fresh depth-zero view. A generic Work route must preserve the operation,
    // not replace it with a new Memory-only parser or an extra nesting level.
    let current = memory();
    let root = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        memory(),
    );
    let query = root.read(&[], 900).unwrap();
    let mut fresh = query
        .execution()
        .read_source(&source, &[2, 1, 7], 400, Encoding::Der, 0)
        .unwrap();
    assert_eq!(fresh.depth(), 0);
    assert_eq!(fresh.offset(), 400);
    assert_eq!(fresh.next_element().unwrap().unwrap().contents(), &[7]);
    assert_eq!(current.work_used(), 3);
    assert_eq!(
        query
            .execution()
            .read_nested(&source, &[2, 1, 7], 400, Encoding::Der, 0)
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded(Limit::Depth)
    );
    assert_eq!(current.work_used(), 3);
}

#[test]
fn generic_work_lazy_reader_does_not_borrow_the_temporary_execution_object() {
    // The caller keeps the actual source/root budgets, not the stack-local
    // execution wrapper. Data, account, encoding and actual depth stay original.
    let storage = memory();
    let current = memory();
    let source = Parser::ber(storage.clone());
    let root = Parser::der(current.clone());
    let query = root.read(&[], 900).unwrap();
    let bytes = [0x30, 0x80, 2, 1, 7, 0, 0];
    let mut lazy = lazy_from_work(&query.execution(), &source, &bytes).unwrap();
    assert_eq!(lazy.offset(), 400);
    assert_eq!(lazy.depth(), 3);
    assert_eq!(lazy.encoding(), Encoding::Ber);
    assert!(core::ptr::eq(lazy.parser(), &raw const source));
    assert!(lazy.memory().same_account(&current));
    let value = lazy.next_element().unwrap().unwrap();
    assert_eq!(value.as_bytes().as_ptr(), bytes.as_ptr());
    assert_eq!(value.span().start, 400);
    assert_eq!(storage.work_used(), 0);
    assert!(current.work_used() > 0);
    drop(lazy);
    assert_eq!(current.used(), 0);
}

#[test]
fn generic_work_lazy_reader_enforces_each_local_and_aggregate_boundary() {
    // Original parsing, operation admission and aggregate work remain three
    // independent checks; no result is created by falling back to Memory.
    for (source_work, operation_work, aggregate_work) in
        [(0, 100, 100), (100, 0, 100), (100, 100, 0)]
    {
        let source = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: source_work,
                ..Limits::default()
            },
            memory(),
        );
        let current = Memory::new(Arc::new(MemoryAccount::new(65536, aggregate_work)));
        let root = Parser::new(
            Encoding::Ber,
            Limits {
                max_work: operation_work,
                ..Limits::default()
            },
            current.clone(),
        );
        let query = root.read(&[], 900).unwrap();
        let error = lazy_from_work(&query.execution(), &source, &[2, 1, 7]).unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Work));
        assert_eq!(error.offset(), 400);
        drop(error);
        assert_eq!(current.work_used(), 0);
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn generic_work_lazy_reader_deduplicates_same_session_and_drops_past_foreign_ceiling() {
    // Same-session admission charges once. A foreign transition replaces its
    // previous source ceiling while retaining the actual root operation.
    let current = memory();
    let root = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 3,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = root.read(&[], 900).unwrap();
    let middle = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1,
            ..Limits::default()
        },
        memory(),
    );
    let first = query
        .execution()
        .read_nested(&middle, &[], 400, Encoding::Der, 0)
        .unwrap();
    let last = Parser::der(memory());
    let second = first
        .execution()
        .read_nested(&last, &[], 700, Encoding::Der, 0)
        .unwrap();
    second.execution().charge_work(1).unwrap();
    assert_eq!(current.work_used(), 3);
    assert!(second.execution().charge_work(1).is_err());
    assert_eq!(current.work_used(), 3);

    let account = memory();
    let same = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 1,
            ..Limits::default()
        },
        account.clone(),
    );
    let original = same.read(&[], 0).unwrap();
    let lazy = original
        .execution()
        .read_nested(&same, &[], 400, Encoding::Der, 0)
        .unwrap();
    assert_eq!(account.work_used(), 1);
    assert!(lazy.execution().charge_work(1).is_err());
    assert_eq!(account.work_used(), 1);
}

#[test]
fn aggregate_work_reader_keeps_the_existing_memory_only_source_semantics() {
    // Default Memory callers keep their existing source lifetime/admission,
    // rather than obtaining an invented additional parser/operation budget.
    let current = memory();
    let source = Parser::ber(memory());
    let lazy = lazy_from_work(&current, &source, &[2, 1, 7]).unwrap();
    let original = source
        .read_nested_in(&[2, 1, 7], 400, Encoding::Ber, 2, &current)
        .unwrap();
    assert_eq!(lazy.depth(), original.depth());
    assert_eq!(lazy.offset(), original.offset());
    assert_eq!(lazy.encoding(), original.encoding());
    assert_eq!(current.work_used(), 0);
    assert!(lazy.memory().same_account(&current));
}

#[test]
fn fresh_foreign_document_uses_depth_zero_under_the_same_query_limits() {
    // A non-ASN carrier adds no ASN container. Root primitives fit depth0,
    // while descending into a root SEQUENCE still requires depth1 permission.
    let storage = memory();
    let current = memory();
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        storage.clone(),
    );
    let root = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = root.read(&[], 900).unwrap();
    let mut primitive = source
        .read_query_in(&query, &[2, 1, 7], 400, Encoding::Der, 0)
        .unwrap();
    assert_eq!(primitive.depth(), 0);
    assert_eq!(primitive.next_element().unwrap().unwrap().contents(), &[7]);
    assert_eq!(current.work_used(), 3);
    assert_eq!(storage.work_used(), 0);
    let mut constructed = source
        .read_query_in(&query, &[48, 3, 2, 1, 7], 700, Encoding::Der, 0)
        .unwrap();
    let sequence = constructed.next_element().unwrap().unwrap();
    let error = constructed.enter(&sequence).unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded(Limit::Depth));
    // Descent refusal is located at the original contents start, after its
    // two-byte SEQUENCE header, as Reader::enter documents/implements.
    assert_eq!(error.offset(), sequence.contents_span().start);
    assert_eq!(error.offset(), 702);
    // The located diagnostic itself retains its admitted path capacity until
    // the error is dropped; that charge belongs to the current account.
    assert!(current.used() > 0);
    assert_eq!(storage.used(), 0);
    drop(error);
    assert_eq!(current.used(), 0);
}

#[test]
fn actual_depth_query_and_nested_query_have_identical_provenance_and_admission() {
    // Both entry points must share the same original/current budget core;
    // nested computes outer+1, while a decoded window already knows its depth.
    let current = memory();
    let root = Parser::der(current.clone());
    let source = Parser::der(memory());
    let query = root.read(&[], 900).unwrap();
    let actual = source
        .read_query_in(&query, &[], 400, Encoding::Der, 2)
        .unwrap();
    let nested = source
        .read_nested_query_in(&query, &[], 400, Encoding::Der, 1)
        .unwrap();
    assert_eq!(actual.depth(), nested.depth());
    assert_eq!(actual.offset(), nested.offset());
    assert!(core::ptr::eq(actual.parser(), nested.parser()));
    assert_eq!(current.work_used(), 2);
    assert_eq!(
        source
            .read_nested_query_in(&query, &[], 400, Encoding::Der, u32::MAX)
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded(Limit::Depth)
    );
    assert_eq!(current.work_used(), 2);
}

#[test]
fn actual_depth_query_refuses_both_source_and_current_limits_before_work() {
    // Explicit depth cannot reset the original source or bypass a narrower
    // current operation. Refused creation has no storage or aggregate charge.
    let current = memory();
    let root = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 1,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = root.read(&[], 900).unwrap();
    let source = Parser::der(memory());
    assert_eq!(
        source
            .read_query_in(&query, &[], 400, Encoding::Der, 2)
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded(Limit::Depth)
    );
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(),
    );
    assert_eq!(
        source
            .read_query_in(&query, &[], 700, Encoding::Der, 0)
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded(Limit::Work)
    );
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        memory(),
    );
    assert_eq!(
        source
            .read_query_in(&query, &[], 1100, Encoding::Der, 1)
            .unwrap_err()
            .code(),
        ErrorCode::LimitExceeded(Limit::Depth)
    );
    assert_eq!(current.work_used(), 0);
    assert_eq!(current.used(), 0);
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
