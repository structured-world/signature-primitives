//! Borrowed metadata execution across original and current work domains.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, Work},
};

fn parser(work: u64) -> Parser {
    Parser::new(
        Encoding::Der,
        Limits {
            max_work: work,
            ..Limits::default()
        },
        Memory::new(Arc::new(MemoryAccount::new(0, 100))),
    )
}

#[test]
fn metadata_execution_borrows_account_without_allocating_or_cloning_it() {
    // Reader creation would clone the current account; this metadata-only
    // bridge must leave the actual account's strong reference count unchanged.
    let account = Arc::new(MemoryAccount::new(0, 10));
    let current = Memory::new(account.clone());
    let source = parser(10);
    let before = Arc::strong_count(&account);
    {
        let work = current.execution_for(&source);
        assert_eq!(Arc::strong_count(&account), before);
        work.charge_work(1).unwrap();
        assert_eq!(current.used(), 0);
    }
    assert_eq!(Arc::strong_count(&account), before);
    assert_eq!(current.work_used(), 1);
}

#[test]
fn original_source_ceiling_survives_new_aggregate_accounts() {
    // Starting a request on a fresh account cannot replenish source work.
    let source = parser(3);
    let current = Memory::new(Arc::new(MemoryAccount::new(0, 10)));
    current.execution_for(&source).charge_work(3).unwrap();
    let fresh = Memory::new(Arc::new(MemoryAccount::new(0, 10)));
    assert!(fresh.execution_for(&source).charge_work(1).is_err());
    assert_eq!(fresh.work_used(), 0);
    assert_eq!(source.memory().work_used(), 0);
}

#[test]
fn foreign_source_transitions_keep_the_current_root_operation() {
    // A -> B -> C changes the current source, not the operation budget;
    // ancestors' source-only limits are not accumulated into a growing chain.
    let operation = parser(3);
    let a = parser(0);
    let b = parser(0);
    let c = parser(10);
    let reader = operation.read(&[], 0).unwrap();
    let root = reader.execution();
    let first = root.execution_for(&a);
    let second = first.execution_for(&b);
    let third = second.execution_for(&c);
    third.charge_work(3).unwrap();
    assert!(third.charge_work(1).is_err());
    assert_eq!(operation.memory().work_used(), 3);
    assert_eq!(c.memory().work_used(), 0);
}

#[test]
fn same_session_rebinding_charges_once_and_does_not_clone_current_owner() {
    // Deduplicate an identical source/operation budget, and preserve its
    // owning account count during repeated borrowed rebindings.
    let account = Arc::new(MemoryAccount::new(0, 10));
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 3,
            ..Limits::default()
        },
        Memory::new(account.clone()),
    );
    let reader = operation.read(&[], 0).unwrap();
    let before = Arc::strong_count(&account);
    let root = reader.execution();
    let first = root.execution_for(&operation);
    let second = first.execution_for(&operation);
    assert_eq!(Arc::strong_count(&account), before);
    second.charge_work(3).unwrap();
    assert!(second.charge_work(1).is_err());
    assert_eq!(operation.memory().work_used(), 3);
}

#[test]
fn aggregate_refusal_does_not_consume_source_local_allowance() {
    // Failed pre-admission cannot consume source allowance before a funded
    // operation. Work is charged exactly once to the selected account.
    let source = parser(3);
    let empty = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    assert!(empty.execution_for(&source).charge_work(1).is_err());
    let funded = Memory::new(Arc::new(MemoryAccount::new(0, 3)));
    funded.execution_for(&source).charge_work(3).unwrap();
    assert_eq!(funded.work_used(), 3);
}
