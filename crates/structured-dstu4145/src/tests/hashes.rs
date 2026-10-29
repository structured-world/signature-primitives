use crate::{
    Error,
    gost::{DEFAULT_DKE, Dke, Gost34311},
    hash::{Hash, State},
};
use gost94::{Digest, Gost94UA};

struct Alternate;
impl gost94::params::Gost94Params for Alternate {
    const S_BOX: [[u8; 16]; 8] = {
        let original = <gost94::params::GOST28147UAParam as gost94::params::Gost94Params>::S_BOX;
        let mut modified = original;
        modified[0][0] = original[0][2];
        modified[0][1] = original[0][3];
        modified[0][2] = original[0][0];
        modified[0][3] = original[0][1];
        modified
    };
    const H0: [u8; 32] = [0; 32];
    const NAME: &'static str = "ExplicitAlternateDke";
}

/// The runtime-DKE compression agrees with RustCrypto's independently selected
/// Ukrainian parameter implementation at every padding and chunk boundary.
#[test]
fn gost_streaming_matches_rustcrypto() {
    let dke = Dke::new(&DEFAULT_DKE).unwrap();
    let message: [u8; 1025] = core::array::from_fn(|i| i.to_le_bytes()[0]);
    for length in [0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1024, 1025] {
        let expected = Gost94UA::digest(&message[..length]);
        for chunk in [1, 7, 31, 32, 33, 64, 1025] {
            let mut state = Gost34311::new(&dke);
            for part in message[..length].chunks(chunk) {
                state.update(part).unwrap();
            }
            assert_eq!(
                &state.finalize()[..],
                &expected[..],
                "length {length}, chunk {chunk}"
            );
        }
    }
}

/// A DKE is part of semantic identity, never a table address or implicit OID
/// default. Invalid permutations refuse before a prepared table is returned.
#[test]
fn dke_identity_and_validation() {
    let a = Dke::new(&DEFAULT_DKE).unwrap();
    let b = Dke::new(&DEFAULT_DKE).unwrap();
    assert_eq!(
        Hash::Gost34311(&a).compare(Hash::Gost34311(&b)),
        core::cmp::Ordering::Equal
    );
    let mut alternate = DEFAULT_DKE;
    alternate.swap(0, 1);
    let c = Dke::new(&alternate).unwrap();
    assert_ne!(
        Hash::Gost34311(&a).compare(Hash::Gost34311(&c)),
        core::cmp::Ordering::Equal
    );
    let mut state = State::new(Hash::Gost34311(&a)).unwrap();
    state.update(b"sample").unwrap();
    let expected = state.finalize();
    let mut state = State::new(Hash::Gost34311(&c)).unwrap();
    state.update(b"sample").unwrap();
    let actual = state.finalize();
    assert_ne!(actual.as_ref(), expected.as_ref());
    let oracle = gost94::Gost94::<Alternate>::digest(b"sample");
    assert_eq!(actual.as_ref(), &oracle[..]);
    alternate[0] = 0;
    assert!(matches!(Dke::new(&alternate), Err(Error::InvalidDke)));
}

/// Fixed widths and both variable-output cores preserve RustCrypto results;
/// caller-owned output is exact-width and gets no implicit truncation.
#[test]
fn kupyna_streaming_and_caller_output() {
    let message: [u8; 257] = core::array::from_fn(|i| i.to_le_bytes()[0]);
    for width in [1, 6, 31, 32, 33, 48, 63, 64] {
        let mut whole = State::new(Hash::Kupyna(width)).unwrap();
        whole.update(&message).unwrap();
        let expected = whole.finalize();
        for chunk in [1, 7, 64, 127, 257] {
            let mut split = State::new(Hash::Kupyna(width)).unwrap();
            for part in message.chunks(chunk) {
                split.update(part).unwrap();
            }
            let mut output = [0; 64];
            split
                .finalize_into(&mut output[..usize::from(width)])
                .unwrap();
            assert_eq!(&output[..usize::from(width)], expected.as_ref());
        }
    }
    for width in [0, 65, 255] {
        assert!(State::new(Hash::Kupyna(width)).is_err());
    }
    assert!(
        State::new(Hash::Kupyna(32))
            .unwrap()
            .finalize_into(&mut [0; 31])
            .is_err()
    );
    for (width, expected) in [
        (32, kupyna::Kupyna256::digest(&message).to_vec()),
        (48, kupyna::Kupyna384::digest(&message).to_vec()),
        (64, kupyna::Kupyna512::digest(&message).to_vec()),
    ] {
        let mut state = State::new(Hash::Kupyna(width)).unwrap();
        state.update(&message).unwrap();
        assert_eq!(state.finalize().as_ref(), expected);
    }
}

/// Tiny updates pay copies and actual compression only, not a whole fictitious
/// block on every byte. Work is computable before the state is mutated.
#[test]
fn update_work_tracks_completed_blocks() {
    let mut state = State::new(Hash::Kupyna(32)).unwrap();
    assert_eq!(state.update_work(0).unwrap(), 1);
    assert_eq!(state.update_work(63).unwrap(), 127);
    state.update(&[0; 63]).unwrap();
    assert_eq!(state.update_work(1).unwrap(), 8_195);
    assert_eq!(state.update_work(65).unwrap(), 16_515);
    assert_eq!(state.finalize_work(), 24_704);
}
