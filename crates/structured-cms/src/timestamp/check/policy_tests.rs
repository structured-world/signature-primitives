use super::*;
use alloc::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount},
};

#[test]
fn policy_comparison_refuses_spent_origin_and_current_before_resolving_accuracy() {
    // Token facts are already parsed. A replacement account cannot reset the
    // origin, and empty current work must not become policy mismatch/absence.
    let mut fields = alloc::vec![
        2, 1, 1, 6, 1, 43, 48, 8, 48, 3, 6, 1, 42, 4, 1, 7, 2, 1, 7, 24, 15
    ];
    fields.extend_from_slice(b"20260101000000Z");
    let mut bytes = alloc::vec![48, u8::try_from(fields.len()).unwrap()];
    bytes.extend(fields);
    let memory = Memory::new(Arc::new(MemoryAccount::new(100_000, 100_000)));
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 4096,
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut parent = parser.read(&bytes, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let info = super::super::TokenInfo::read(&parent, &element).unwrap();
    let policy = super::super::PolicyAccuracy::new(
        structured_asn1::Oid::from_bytes(&[43]),
        super::super::Accuracy::new(1, 0, 0),
    )
    .unwrap();
    let empty = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
    let current = parent.with_execution(&empty);
    match resolve_accuracy::<(), (), ()>(&info, &current, Some(policy)) {
        Err(InfoCheckError::Processing(cause)) => {
            assert!(cause.is_resource());
            assert_eq!(cause.field(), "tstInfo.policy");
            assert_eq!(cause.offset(), 700);
        }
        _ => panic!("current work refusal must remain typed"),
    }
    let source = parser.execution_in(&memory);
    source
        .charge_work(u64::try_from(source.work_remaining()).unwrap())
        .unwrap();
    let replacement = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
    let current = current.with_execution(&replacement);
    match resolve_accuracy::<(), (), ()>(&info, &current, Some(policy)) {
        Err(InfoCheckError::Processing(cause)) => assert!(cause.is_resource()),
        _ => panic!("spent producing session must remain terminal"),
    }
    assert_eq!(replacement.work_used(), 0);
    assert_eq!(replacement.used(), 0);
}
