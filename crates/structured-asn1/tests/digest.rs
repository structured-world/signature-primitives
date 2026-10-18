//! The one-shot path runs the same start/update/finish/matches contract as a
//! stream and keeps provider answers, provider faults and contract failures apart.

use std::cell::Cell;
use std::cmp::Ordering;
use std::sync::Arc;
use structured_asn1::digest::{self, Digest, OnceError, Resolution};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};

/// What `start` answers, and what `finish` returns, for one test case.
#[derive(Clone, Copy)]
enum Start {
    Stream,
    Unsupported,
    Malformed,
}

/// An additive checksum whose output width the test can contradict.
struct Checksum {
    start: Start,
    output_width: usize,
    updates: Cell<usize>,
}

impl Checksum {
    fn new(start: Start) -> Self {
        Self {
            start,
            output_width: 1,
            updates: Cell::new(0),
        }
    }
}

impl Digest<'_> for Checksum {
    type Identity = ();
    type State = u8;
    type Output = Vec<u8>;
    type Error = MemoryError;

    fn width(&self, (): &()) -> Option<usize> {
        Some(1)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), _: &W) -> Result<Ordering, MemoryError> {
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), execution: &W) -> Result<Resolution<u8>, MemoryError> {
        execution.charge_work(1)?;
        Ok(match self.start {
            Start::Stream => Resolution::Supported(0),
            Start::Unsupported => Resolution::Unsupported,
            Start::Malformed => Resolution::Malformed,
        })
    }
    fn update<W: Work>(
        &self,
        state: &mut u8,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), MemoryError> {
        execution.charge_work(bytes.len() as u64)?;
        self.updates.set(self.updates.get() + 1);
        *state = bytes
            .iter()
            .fold(*state, |sum, byte| sum.wrapping_add(*byte));
        Ok(())
    }
    fn finish<W: Work>(&self, state: u8, _: &W) -> Result<Vec<u8>, MemoryError> {
        Ok(vec![state; self.output_width])
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &Vec<u8>,
        expected: &[u8],
        execution: &W,
    ) -> Result<bool, MemoryError> {
        execution.charge_work(expected.len() as u64)?;
        Ok(output.as_slice() == expected)
    }
}

fn funded(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(0, work)))
}

#[test]
fn one_update_then_comparison_in_both_directions() {
    // The input is hashed once and its output compared; a different expected
    // value is a completed `false`, not an error.
    let digest = Checksum::new(Start::Stream);
    let execution = funded(64);
    let matching = digest::matches_once(&digest, &(), &[1, 2], &[3], &execution).unwrap();
    assert_eq!(matching, Resolution::Supported(true));
    let differing = digest::matches_once(&digest, &(), &[1, 2], &[4], &execution).unwrap();
    assert_eq!(differing, Resolution::Supported(false));
    assert_eq!(digest.updates.get(), 2);
}

#[test]
fn start_answers_return_before_any_byte_is_hashed() {
    // A backend without streaming capability, or one refusing the identity,
    // answers at start; no update runs and no comparison is invented.
    for (start, answer) in [
        (Start::Unsupported, Resolution::Unsupported),
        (Start::Malformed, Resolution::Malformed),
    ] {
        let digest = Checksum::new(start);
        let result = digest::matches_once(&digest, &(), &[1], &[1], &funded(64)).unwrap();
        assert_eq!(result, answer);
        assert_eq!(digest.updates.get(), 0);
    }
}

#[test]
fn output_contradicting_the_identity_width_is_a_contract_failure() {
    // Two bytes from a one-byte identity must not reach the comparison.
    let digest = Checksum {
        output_width: 2,
        ..Checksum::new(Start::Stream)
    };
    let error = digest::matches_once(&digest, &(), &[1], &[1, 1], &funded(64)).unwrap_err();
    assert_eq!(
        error,
        OnceError::OutputWidth {
            expected: 1,
            actual: 2
        }
    );
}

#[test]
fn spent_work_is_the_provider_error_not_a_mismatch() {
    // Start costs one unit and the update two: with two units the update is
    // refused, and the refusal stays an error rather than `false`.
    let digest = Checksum::new(Start::Stream);
    let error = digest::matches_once(&digest, &(), &[1, 2], &[3], &funded(2)).unwrap_err();
    assert_eq!(error, OnceError::Provider(MemoryError::WorkExceeded));
}
