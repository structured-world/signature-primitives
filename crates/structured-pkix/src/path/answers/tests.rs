use super::{Edge, Error, SignatureAnswers};
use crate::path::Verified;
use alloc::sync::Arc;
use core::cell::Cell;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

const EDGE: Edge<'static> = Edge {
    algorithm: b"algorithm",
    signed: b"signed",
    signature: b"signature",
    issuer_spki: b"effective SPKI",
};

fn account(bytes: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(bytes, work)))
}

#[test]
fn answers_are_exact_and_belong_to_one_verifier() {
    // A different algorithm, payload, signature or effective key misses.
    let work = account(4096, 4096);
    let calls = Cell::new(0);
    let answers = SignatureAnswers::new(&work, |_: Edge<'_>, _: &Memory| {
        calls.set(calls.get() + 1);
        Ok::<_, ()>(Verified::Yes)
    });
    assert_eq!(answers.verify(EDGE, &work), Ok(Verified::Yes));
    let signed = *b"signed";
    assert_eq!(
        answers.verify(
            Edge {
                signed: &signed,
                ..EDGE
            },
            &work
        ),
        Ok(Verified::Yes)
    );
    assert_eq!(calls.get(), 1);
    for edge in [
        Edge {
            algorithm: b"Algorithm",
            ..EDGE
        },
        Edge {
            signed: b"Signed",
            ..EDGE
        },
        Edge {
            signature: b"Signature",
            ..EDGE
        },
        Edge {
            issuer_spki: b"Effective SPKI",
            ..EDGE
        },
    ] {
        assert_eq!(answers.verify(edge, &work), Ok(Verified::Yes));
    }
    assert_eq!(calls.get(), 5);
    let calls = Cell::new(0);
    let other = SignatureAnswers::new(&work, |_: Edge<'_>, _: &Memory| {
        calls.set(calls.get() + 1);
        Ok::<_, ()>(Verified::No)
    });
    assert_eq!(other.verify(EDGE, &work), Ok(Verified::No));
    assert_eq!(other.verify(EDGE, &work), Ok(Verified::No));
    assert_eq!(calls.get(), 1);
    assert_eq!(
        other.verify(EDGE, &account(4096, 4096)),
        Err(Error::ForeignAccount)
    );
    assert!(work.used() > 0);
    drop(other);
    drop(answers);
    assert_eq!(work.used(), 0);
}

#[test]
fn unequal_lengths_still_spend_work_before_math() {
    // An input differing in width from every stored edge cannot evade the
    // scan budget, even though it never reaches a byte comparison.
    let work = account(65536, 65536);
    let calls = Cell::new(0);
    let answers = SignatureAnswers::new(&work, |_: Edge<'_>, _: &Memory| {
        calls.set(calls.get() + 1);
        Ok::<_, ()>(Verified::Yes)
    });
    let signed = [0_u8; 64];
    for width in 0..signed.len() {
        assert_eq!(
            answers.verify(
                Edge {
                    signed: &signed[..width],
                    ..EDGE
                },
                &work
            ),
            Ok(Verified::Yes)
        );
    }
    let before = work.work_used();
    work.charge_work((65536 - before - 63) as u64).unwrap();
    assert_eq!(
        answers.verify(
            Edge {
                signed: &signed,
                ..EDGE
            },
            &work
        ),
        Err(Error::Work(MemoryError::WorkExceeded))
    );
    assert_eq!(work.work_used(), 65536);
    assert_eq!(calls.get(), 64);
}

#[test]
fn storage_refusal_leaves_the_answer_unkept() {
    // Cover refusal of the byte copy and refusal of the catalog growth after
    // the byte copy succeeded. Neither leaks a charge or changes the answer.
    for limit in [0, EDGE.parts().iter().map(|part| part.len()).sum()] {
        let work = account(limit, 4096);
        let calls = Cell::new(0);
        let answers = SignatureAnswers::new(&work, |_: Edge<'_>, _: &Memory| {
            calls.set(calls.get() + 1);
            Ok::<_, ()>(Verified::Yes)
        });
        assert_eq!(answers.verify(EDGE, &work), Ok(Verified::Yes));
        assert_eq!(answers.verify(EDGE, &work), Ok(Verified::Yes));
        assert_eq!(calls.get(), 2);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn errors_and_unsupported_answers_are_not_kept() {
    // A transient failure or an unjudged edge can be answered on retry.
    let work = account(4096, 4096);
    let calls = Cell::new(0);
    let answers = SignatureAnswers::new(&work, |_: Edge<'_>, _: &Memory| {
        let call = calls.get();
        calls.set(call + 1);
        match call {
            0 => Err("provider"),
            1 => Ok(Verified::Unsupported),
            _ => Ok(Verified::Yes),
        }
    });
    assert_eq!(
        answers.verify(EDGE, &work),
        Err(Error::Verification("provider"))
    );
    assert_eq!(answers.verify(EDGE, &work), Ok(Verified::Unsupported));
    assert_eq!(work.used(), 0);
    assert_eq!(answers.verify(EDGE, &work), Ok(Verified::Yes));
    assert_eq!(answers.verify(EDGE, &work), Ok(Verified::Yes));
    assert_eq!(calls.get(), 3);
}
