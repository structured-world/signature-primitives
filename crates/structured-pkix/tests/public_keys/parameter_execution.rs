//! Retained curve queries must not substitute the subject's source for the issuer.

use super::*;
use structured_asn1::memory::{Execution, MemoryError};

fn classify<W: Work>(key: &ec::PublicKey<'_>, work: &W) -> Result<bool, structured_pkix::Error> {
    let ec::Curve::Named(curve) = key.curve() else {
        return Ok(false);
    };
    key.parameters_execution_in(work)
        .charge_work(curve.as_bytes().len() as u64)
        .map_err(|cause| {
            structured_pkix::Error::resource(cause, "curve", key.parameters().span().start)
        })?;
    Ok(curve.as_bytes() == PRIME256V1)
}

#[test]
fn inherited_query_refuses_spent_issuer_before_classification() {
    // Successful prior decoding does not prepay a later provider's OID query.
    // A funded subject and fresh current account cannot reset the issuer ceiling.
    for parameters in [None, Some(&[5, 0][..])] {
        let root_bytes = certificate("Root", &ec_spki(Some(&named()), &[4, 1, 2]));
        let leaf_bytes = certificate("Leaf", &ec_spki(parameters, &[3, 7]));
        let root_source = bounded_source();
        let leaf_source = bounded_source();
        let root = Certificate::read(&root_source, &root_bytes, 400).unwrap();
        let leaf = Certificate::read(&leaf_source, &leaf_bytes, 9000).unwrap();
        let setup = memory(100_000);
        let key = WorkingKey::standing(root.tbs().public_key())
            .subject(&leaf, &setup)
            .unwrap();
        let view = ec::read(key, &setup).unwrap();
        let at = view.parameters().span().start;
        let bytes = view.parameters().as_bytes().as_ptr();
        exhaust_source(&root_source);
        let current = memory(100_000);
        let error = classify(&view, &current).unwrap_err();
        assert!(error.is_resource());
        assert_eq!((error.field(), error.offset()), ("curve", at));
        assert_eq!(current.work_used(), 0);
        assert_eq!(view.parameters().as_bytes().as_ptr(), bytes);
        assert!(
            leaf_source
                .execution_in(leaf_source.memory())
                .work_remaining()
                > 0
        );
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn current_local_and_aggregate_limits_and_exact_boundary_survive() {
    // The eight-byte named curve query admits every ceiling before comparison.
    for (source_left, local, aggregate, success) in [
        (8, 8, 8, true),
        (7, 8, 8, false),
        (8, 7, 8, false),
        (8, 8, 7, false),
    ] {
        let root_bytes = certificate("Root", &ec_spki(Some(&named()), &[4, 1, 2]));
        let leaf_bytes = certificate("Leaf", &ec_spki(None, &[3, 7]));
        let root_source = bounded_source();
        let leaf_source = bounded_source();
        let root = Certificate::read(&root_source, &root_bytes, 400).unwrap();
        let leaf = Certificate::read(&leaf_source, &leaf_bytes, 9000).unwrap();
        let setup = memory(100_000);
        let working = WorkingKey::standing(root.tbs().public_key())
            .subject(&leaf, &setup)
            .unwrap();
        let view = ec::read(working, &setup).unwrap();
        let origin = root_source.execution_in(root_source.memory());
        origin
            .charge_work((origin.work_remaining() - source_left) as u64)
            .unwrap();
        let current = Memory::new(Arc::new(MemoryAccount::new(0, aggregate)));
        let operation = Parser::new(
            Encoding::Der,
            Limits {
                max_work: local,
                ..Limits::default()
            },
            current.clone(),
        );
        let query = operation.read(&[], 80000).unwrap();
        let result = classify(&view, &query.execution());
        if success {
            assert!(result.unwrap());
            assert_eq!(current.work_used(), 8);
            assert_eq!(origin.work_remaining(), 0);
        } else {
            assert!(result.unwrap_err().is_resource());
            assert_eq!(current.work_used(), 0);
            assert_eq!(origin.work_remaining(), source_left);
        }
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn direct_implicit_and_specified_parameters_keep_their_source_and_bytes() {
    // Every readable ECParameters choice uses its actual source, including lone NULL.
    for (encoding, parameters) in [
        (Encoding::Der, named()),
        (
            Encoding::Ber,
            [vec![6, 0x81, 8], PRIME256V1.to_vec()].concat(),
        ),
        (Encoding::Der, vec![5, 0]),
        (Encoding::Der, vec![48, 0]),
    ] {
        let source = Parser::new(
            encoding,
            Limits {
                max_work: 10_000,
                ..Limits::default()
            },
            memory(100_000),
        );
        let bytes = ec_spki(Some(&parameters), &[4, 1, 2]);
        let original = info(&source, &bytes);
        let setup = memory(100_000);
        let view = ec::read(WorkingKey::standing(original), &setup).unwrap();
        assert_eq!(view.parameters().as_bytes(), parameters);
        assert_eq!(
            view.parameters().span().start,
            position(&bytes, &parameters)
        );
        let current = Memory::new(Arc::new(MemoryAccount::new(0, 1000)));
        let before = source.memory().work_used();
        {
            // Temporary views need not remain alive to admit a query.
            let transient = view;
            let execution = transient.parameters_execution_in(&current);
            execution.charge_work(1).unwrap();
        }
        assert_eq!(current.work_used(), 1);
        assert_eq!(source.memory().work_used(), before + 1);
        exhaust_source(&source);
        assert_eq!(
            view.parameters_execution_in(&current).charge_work(1),
            Err(MemoryError::WorkExceeded)
        );
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn same_session_queries_charge_once_and_construction_does_no_work() {
    // A repeated query needs admission each time but never double aggregate billing.
    let source = bounded_source();
    let bytes = ec_spki(Some(&named()), &[3, 7]);
    let view = ec::read(WorkingKey::standing(info(&source, &bytes)), source.memory()).unwrap();
    let work = source.execution_in(source.memory());
    let before = source.memory().work_used();
    let first = view.parameters_execution_in(&work);
    let second = view.parameters_execution_in(&work);
    assert_eq!(source.memory().work_used(), before);
    first.charge_work(8).unwrap();
    second.charge_work(8).unwrap();
    assert_eq!(source.memory().work_used(), before + 16);
}

#[test]
fn parameter_query_does_not_spend_point_source_or_pin_old_operation() {
    // The retained curve view borrows source data, not its completed read operation.
    // Spending the subject cannot prohibit a query over independently sourced parameters.
    let root_bytes = certificate("Root", &ec_spki(Some(&named()), &[4, 1, 2]));
    let leaf_bytes = certificate("Leaf", &ec_spki(None, &[3, 7]));
    let root_source = bounded_source();
    let leaf_source = bounded_source();
    let root = Certificate::read(&root_source, &root_bytes, 400).unwrap();
    let leaf = Certificate::read(&leaf_source, &leaf_bytes, 9000).unwrap();
    let working;
    let view = {
        let setup = memory(100_000);
        let operation = Parser::der(setup);
        let query = operation.read(&[], 80000).unwrap();
        working = WorkingKey::standing(root.tbs().public_key())
            .subject(&leaf, &query.execution())
            .unwrap();
        ec::read(working, &query.execution()).unwrap()
    };
    exhaust_source(&leaf_source);
    let current = Memory::new(Arc::new(MemoryAccount::new(0, 1000)));
    assert!(classify(&view, &current).unwrap());
    let point = working.key().algorithm().execution_origin();
    assert_eq!(
        point.execution_in(&current).charge_work(1),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(
        view.as_bytes().as_ptr(),
        leaf.tbs().public_key().key_octets().unwrap().as_ptr()
    );
    assert_eq!(current.used(), 0);
}

#[test]
fn query_keeps_current_root_when_switching_from_another_foreign_source() {
    // The intermediate source is not the root operation and cannot widen its ceiling.
    let source = bounded_source();
    let bytes = ec_spki(Some(&named()), &[3, 7]);
    let view = ec::read(WorkingKey::standing(info(&source, &bytes)), source.memory()).unwrap();
    let other = bounded_source();
    let current = memory(100_000);
    let operation = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 7,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = operation.read(&[], 80000).unwrap();
    let foreign = query.execution().execution_for(&other);
    assert!(classify(&view, &foreign).unwrap_err().is_resource());
    assert_eq!(current.work_used(), 0);
}

// Returned execution borrows current Work and the source, not the transient view.
fn independent_view_borrow<'source: 'query, 'query, W: Work>(
    key: &ec::PublicKey<'source>,
    work: &'query W,
) -> Execution<'query> {
    key.parameters_execution_in(work)
}

#[test]
fn query_borrow_is_independent_of_the_view() {
    // An immutable descriptor may end before its query, without owning an account.
    let source = bounded_source();
    let bytes = ec_spki(Some(&named()), &[3, 7]);
    let view = ec::read(WorkingKey::standing(info(&source, &bytes)), source.memory()).unwrap();
    let current = Memory::new(Arc::new(MemoryAccount::new(0, 1000)));
    let execution = {
        let transient = view;
        independent_view_borrow(&transient, &current)
    };
    execution.charge_work(8).unwrap();
    assert_eq!(current.work_used(), 8);
}
