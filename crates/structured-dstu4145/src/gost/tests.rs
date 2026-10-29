use super::{DEFAULT_DKE, Dke, Gost34311};
use crate::Error;

/// The raw GOST core's256-bit bit-length counter refuses carry out before
/// changing hash, sum, buffer or length, independently of the u64 facade.
#[test]
fn full_bit_length_overflow_is_transactional() {
    let dke = Dke::new(&DEFAULT_DKE).unwrap();
    let mut state = Gost34311::new(&dke);
    state.length = [u64::MAX - 7, u64::MAX, u64::MAX, u64::MAX];
    let length = state.length;
    let hash = state.hash;
    let sum = state.sum;
    let buffer = state.buffer;
    assert!(matches!(state.update(&[1]), Err(Error::InputTooLong)));
    assert_eq!(state.length, length);
    assert_eq!(state.hash, hash);
    assert_eq!(state.sum, sum);
    assert_eq!(state.buffer, buffer);
    assert_eq!(state.used, 0);
}
