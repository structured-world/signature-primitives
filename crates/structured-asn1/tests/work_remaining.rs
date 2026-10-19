//! Remaining work is exactly what `charge_work` would admit next.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, Work},
};

fn memory(work_limit: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(65536, work_limit)))
}

fn parser(max_work: u64, memory: Memory) -> Parser {
    Parser::new(
        Encoding::Der,
        Limits {
            max_work,
            ..Limits::default()
        },
        memory,
    )
}

/// One unit beyond the observation is refused without spending anything, the
/// observation itself is admitted in full, and nothing remains afterwards.
fn assert_exact<W: Work>(work: &W, expected: usize, account: &Memory) {
    let remaining = work.work_remaining();
    assert_eq!(remaining, expected);
    let before = account.work_used();
    let beyond = u64::try_from(remaining).unwrap() + 1;
    assert!(work.charge_work(beyond).is_err());
    assert_eq!(account.work_used(), before);
    work.charge_work(u64::try_from(remaining).unwrap()).unwrap();
    assert_eq!(account.work_used(), before + remaining);
    assert_eq!(work.work_remaining(), 0);
    assert!(work.charge_work(1).is_err());
}

#[test]
fn memory_reports_the_aggregate_account_remainder() {
    // The aggregate account is the only ceiling of Memory; earlier admission
    // reduces it, and observing it reserves nothing.
    let account = memory(100);
    account.charge_work(30).unwrap();
    assert_eq!(Work::work_remaining(&account), 70);
    assert_eq!(account.work_used(), 30);
    assert_exact(&account, 70, &account);
}

#[test]
fn execution_reports_the_parser_session_when_it_is_tightest() {
    // A generous account cannot lift the parser session ceiling.
    let account = memory(1000);
    let session = parser(10, account.clone());
    let reader = session.read(&[], 0).unwrap();
    let execution = reader.execution();
    let spent = u64::try_from(account.work_used()).unwrap();
    assert_exact(&execution, usize::try_from(10 - spent).unwrap(), &account);
}

#[test]
fn execution_reports_the_aggregate_account_when_it_is_tightest() {
    // A generous parser session cannot lift the shared account ceiling.
    let account = memory(5);
    let session = parser(1000, account.clone());
    let reader = session.read(&[], 0).unwrap();
    let execution = reader.execution();
    let expected = 5 - account.work_used();
    assert_exact(&execution, expected, &account);
}

#[test]
fn query_execution_reports_the_tightest_of_source_operation_and_account() {
    // A metadata query checks the original source, the current operation and
    // the current account; whichever is tightest bounds the observation.
    for (source_work, operation_work, account_work, expected) in [
        (3, 100, 100, 3),
        (100, 4, 100, 4),
        (100, 100, 5, 5),
        (0, 100, 100, 0),
    ] {
        let original = memory(65536);
        let current = memory(account_work);
        let source = parser(source_work, original.clone());
        let operation = parser(operation_work, current.clone());
        let origin = source.read(&[], 400).unwrap();
        let query = operation.read(&[], 900).unwrap();
        assert_eq!(original.work_used(), 0);
        assert_eq!(current.work_used(), 0);
        assert_exact(&origin.execution_query(&query), expected, &current);
        assert_eq!(original.work_used(), 0);
    }
}
