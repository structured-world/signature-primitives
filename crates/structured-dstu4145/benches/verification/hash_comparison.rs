//! Compare complete streaming calls, including each implementation's output.

use kupyna::{Digest, Kupyna256, Kupyna384, Kupyna512};
use std::hint::black_box;
use structured_dstu4145::hash::{Hash, State};
use ua_cryptography_dstu7564::{HashSize, Kupyna};

fn own(input: &[u8], width: u8) {
    let mut state = State::new(Hash::Kupyna(width)).unwrap();
    for bytes in input.chunks(8192) {
        state.update(black_box(bytes)).unwrap();
    }
    black_box(state.finalize());
}

fn direct<D: Digest>(input: &[u8]) {
    let mut state = D::new();
    for bytes in input.chunks(8192) {
        state.update(black_box(bytes));
    }
    black_box(state.finalize());
}

fn independent(input: &[u8], size: HashSize) {
    let mut state = Kupyna::new(size);
    for bytes in input.chunks(8192) {
        state.update(black_box(bytes));
    }
    black_box(state.finalize());
}

pub(super) fn run() {
    let input = vec![0x73; 1 << 20];
    println!("Kupyna comparison: full streaming API, 50 samples, p50 and sample tail, nanoseconds");
    for (width, size) in [
        (32, HashSize::Bits256),
        (48, HashSize::Bits384),
        (64, HashSize::Bits512),
    ] {
        for length in [0, 64, 4096, 1 << 20] {
            let input = &input[..length];
            let own = super::timing(|| own(input, width), 50);
            let direct = super::timing(
                || match width {
                    32 => direct::<Kupyna256>(input),
                    48 => direct::<Kupyna384>(input),
                    64 => direct::<Kupyna512>(input),
                    _ => unreachable!(),
                },
                50,
            );
            let independent = super::timing(|| independent(input, size), 50);
            println!(
                "Kupyna width={width} bytes={length} own_p50={} own_tail={} rustcrypto_p50={} rustcrypto_tail={} independent_p50={} independent_tail={}",
                own.0.as_nanos(),
                own.1.as_nanos(),
                direct.0.as_nanos(),
                direct.1.as_nanos(),
                independent.0.as_nanos(),
                independent.1.as_nanos()
            );
        }
    }
}
