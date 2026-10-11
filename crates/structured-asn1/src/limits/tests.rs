use super::{Budget, Limits};
use crate::error::Limit;

#[test]
fn the_defaults_are_not_a_small_document_ceiling() {
    let limits = Limits::default();

    // A large but ordinary signed document must not be refused for its size:
    // a ceiling low enough to stop a hostile input stops real ones first.
    assert!(limits.max_element_length >= 1 << 32);
    assert!(limits.max_elements >= 100_000);
    assert!(limits.max_depth >= 100);
}

#[test]
fn elements_are_counted_and_then_refused() {
    let budget = Budget::new(
        Limits {
            max_elements: 2,
            ..Limits::default()
        },
        crate::test_memory(),
    );

    assert!(budget.element().is_ok());
    assert!(budget.element().is_ok());
    assert_eq!(budget.element().unwrap_err(), Limit::Elements);
}

#[test]
fn work_accumulates_across_calls() {
    let budget = Budget::new(
        Limits {
            max_work: 3,
            ..Limits::default()
        },
        crate::test_memory(),
    );

    assert!(budget.work(2).is_ok());
    assert_eq!(budget.work(2).unwrap_err(), Limit::Work);
}

#[test]
fn refused_work_does_not_consume_unexecuted_local_work() {
    // A failed admission must leave the last available unit usable. Recording
    // the rejected request first poisons all later attempts on the same parser.
    let budget = Budget::new(
        Limits {
            max_work: 3,
            ..Limits::default()
        },
        crate::test_memory(),
    );
    budget.work(2).unwrap();
    assert_eq!(budget.work(2), Err(Limit::Work));
    assert_eq!(budget.work(1), Ok(()));
    assert_eq!(budget.work.get(), 3);
    assert_eq!(budget.memory().work_used(), 3);
}

#[test]
fn refused_elements_do_not_advance_the_element_counter() {
    // Admission at the largest counter value must remain within its bound,
    // without poisoning the counter or wrapping on the next refusal.
    let budget = Budget::new(
        Limits {
            max_elements: 1,
            ..Limits::default()
        },
        crate::test_memory(),
    );
    budget.element().unwrap();
    assert_eq!(budget.element(), Err(Limit::Elements));
    assert_eq!(budget.elements.get(), 1);
}

#[test]
fn depth_and_length_are_checked_without_being_spent() {
    let budget = Budget::new(
        Limits {
            max_depth: 2,
            max_element_length: 8,
            ..Limits::default()
        },
        crate::test_memory(),
    );

    // Asking twice about the same depth answers the same way: these are
    // questions about a value, not withdrawals from a balance.
    assert!(budget.depth(2).is_ok());
    assert!(budget.depth(2).is_ok());
    assert_eq!(budget.depth(3).unwrap_err(), Limit::Depth);

    assert!(budget.length(8).is_ok());
    assert!(budget.length(8).is_ok());
    assert_eq!(budget.length(9).unwrap_err(), Limit::ElementLength);
}

#[test]
fn a_budget_of_none_refuses_the_first_element() {
    let budget = Budget::new(Limits::none(), crate::test_memory());

    assert_eq!(budget.element().unwrap_err(), Limit::Elements);
    assert_eq!(budget.depth(1).unwrap_err(), Limit::Depth);
    assert_eq!(budget.length(1).unwrap_err(), Limit::ElementLength);
    assert_eq!(budget.work(1).unwrap_err(), Limit::Work);
}

#[test]
fn a_spent_counter_saturates_rather_than_wrapping() {
    let budget = Budget::new(
        Limits {
            max_work: 1,
            ..Limits::default()
        },
        crate::test_memory(),
    );

    // Wrapping would turn a document that asked for an enormous amount of work
    // into one that appears to have asked for almost none.
    assert!(budget.work(u64::MAX).is_err());
    assert!(budget.work(u64::MAX).is_err());
}
