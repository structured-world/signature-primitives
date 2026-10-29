use super::{Hash, State};
use crate::Error;

/// Counter overflow refuses before either the engine or its pending buffer
/// consumes input. Artificial boundary setup avoids feeding exabytes of data.
#[test]
fn cumulative_input_overflow_does_not_mutate_engine() {
    let mut state = State::new(Hash::Kupyna(32)).unwrap();
    state.bytes = u64::MAX - 1;
    assert!(matches!(state.update_work(2), Err(Error::InputTooLong)));
    assert!(matches!(state.update(&[1, 2]), Err(Error::InputTooLong)));
    assert_eq!(state.bytes, u64::MAX - 1);
    assert_eq!(
        state.finalize().as_ref(),
        State::new(Hash::Kupyna(32)).unwrap().finalize().as_ref()
    );
}

/// Wrong caller-output width leaves that buffer untouched and performs no
/// permissive truncation. The state is consumed exactly once either way.
#[test]
fn wrong_output_width_preserves_caller_buffer() {
    let state = State::new(Hash::Kupyna(48)).unwrap();
    let mut output = [0xa5; 47];
    assert!(matches!(
        state.finalize_into(&mut output),
        Err(Error::InvalidOutputSize)
    ));
    assert_eq!(output, [0xa5; 47]);
}
