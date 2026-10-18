//! Actual fixed-curve math for original actor-path composition, not trust.

mod support;

use core::cell::Cell;
use p256::ecdsa::SigningKey;
use structured_asn1::Parser;
use structured_ltv::pki::{self, PathOutcome};
use structured_pkix::{
    Certificate,
    path::{self, Anchor, Interval, ValidationBounds, ValidationContext},
};
use support::{Oracle, certificate, memory};

#[test]
fn actor_path_keeps_original_members_and_does_not_verify_projection_twice() {
    // Only the common validator produces the witness. Its path, effective
    // keys and owned member storage remain source-correct across Reader drop.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let leaf_key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let root_bytes = certificate("Root", "Root", &root_key, &root_key);
    let leaf_bytes = certificate("Leaf", "Root", &leaf_key, &root_key);
    let source = Parser::der(memory(1 << 20));
    let root = Certificate::read(&source, &root_bytes, 400).unwrap();
    let leaf = Certificate::read(&source, &leaf_bytes, 800).unwrap();
    let current = memory(1 << 20);
    let operation = Parser::der(current.clone());
    let query = operation.read(&[], 1200).unwrap();
    let work = query.execution();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    let context = ValidationContext {
        execution: &work,
        interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
        policy: path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &oracle,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(checked) =
        pki::check_path(&[&leaf], Anchor::from_certificate(&root), &context).unwrap()
    else {
        panic!("actual P256 leaf signature must pass")
    };
    assert_eq!(oracle.calls.get(), 1);
    assert_eq!(checked.members().len(), 1);
    assert!(core::ptr::eq(
        checked.members()[0].certificate(),
        &raw const leaf
    ));
    assert_eq!(
        checked.members()[0].key().key().as_bytes().as_ptr(),
        leaf.tbs().public_key().as_bytes().as_ptr()
    );
    assert!(core::ptr::eq(
        checked.anchor().certificate().unwrap(),
        &raw const root
    ));
    assert_eq!(checked.interval(), context.interval);
    assert_eq!(
        checked.facts().key.key().as_bytes(),
        leaf.tbs().public_key().as_bytes()
    );
    let held = current.used();
    assert!(held > 0);
    drop(checked);
    assert_eq!(current.used(), 0);
    let mut forged = leaf_bytes.clone();
    *forged.last_mut().unwrap() ^= 1;
    let changed = Certificate::read(&source, &forged, 1600).unwrap();
    assert!(
        matches!(pki::check_path(&[&changed],Anchor::from_certificate(&root),&context).unwrap(),PathOutcome::Rejected(reason) if reason.reason==path::RejectionReason::Signature)
    );
    assert_eq!(oracle.calls.get(), 2);
    assert_eq!(current.used(), 0);
}

#[test]
fn actor_path_refuses_resource_and_local_incomplete_without_partial_members() {
    // Resource, common rejection and local truncation are different outcomes;
    // no failure may leave an accepted partial actor census or leaked scratch.
    let key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let root_bytes = certificate("Root", "Root", &key, &key);
    let leaf_bytes = certificate("Leaf", "Root", &key, &key);
    let source = Parser::der(memory(1 << 20));
    let root = Certificate::read(&source, &root_bytes, 400).unwrap();
    let leaf = Certificate::read(&source, &leaf_bytes, 800).unwrap();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    for (capacity, localwork, incomplete) in [(0, 1_000_000, false), (1 << 20, 0, true)] {
        let current = memory(capacity);
        let operation = Parser::der(current.clone());
        let query = operation.read(&[], 1200).unwrap();
        let work = query.execution();
        let context = ValidationContext {
            execution: &work,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: path::Policy::default(),
            bounds: ValidationBounds {
                work: localwork,
                ..ValidationBounds::default()
            },
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let result = pki::check_path(&[&leaf], Anchor::from_certificate(&root), &context);
        if incomplete {
            assert!(matches!(
                result.unwrap(),
                PathOutcome::Incomplete(path::Truncation::Work)
            ));
        } else {
            assert!(
                matches!(result,Err(path::BuildError::Processing(error)) if error.is_resource())
            );
        }
        assert_eq!(oracle.calls.get(), 0);
        assert_eq!(current.used(), 0);
        assert!(
            matches!(pki::check_path(&[],Anchor::from_certificate(&root),&context).unwrap(),PathOutcome::Rejected(reason) if reason.reason==path::RejectionReason::EmptyPath)
        );
    }
}
