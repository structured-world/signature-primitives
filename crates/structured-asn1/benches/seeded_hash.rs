//! Integer table hashing: standard hashing, shared state and the previous word kernel.
//! Run: `cargo bench -p structured-asn1 --features std --bench seeded_hash`

use core::{
    hash::{BuildHasher, Hash},
    hint::black_box,
};
use std::{hash::RandomState, time::Instant};
use structured_asn1::hash::SeededState;

const ITERATIONS: u32 = 5_000_000;

fn measure(label: &str, mut hash: impl FnMut(u64) -> u64) {
    let start = Instant::now();
    let mut result = 0;
    for key in 0..ITERATIONS {
        result ^= hash(u64::from(black_box(key)));
    }
    black_box(result);
    println!(
        "{label}: {:.3} ns/key",
        start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERATIONS)
    );
}

fn fold(left: u64, right: u64) -> u64 {
    let product = u128::from(left) * u128::from(right);
    let low = u64::try_from(product & u128::from(u64::MAX)).expect("masked half");
    let high = u64::try_from(product >> 64).expect("shifted half");
    low ^ high
}

fn previous_words(seed: u64, words: impl IntoIterator<Item = u64>) -> u64 {
    // Integer-only comparator: the prior per-word folded-multiply algorithm,
    // not a complete replacement for its byte hasher or a production engine.
    let mut state = seed;
    for word in words {
        state = fold(state ^ word, seed);
    }
    fold(state, seed.rotate_left(32) | 1)
}

fn main() {
    let bytes = RandomState::new();
    let seed = black_box(bytes.hash_one(0x5eed_u64) | 1);
    let shared = SeededState::new(seed, bytes.clone());
    println!("{ITERATIONS} keys/sample; release profile; no table allocation");
    measure("u64 standard", |key| bytes.hash_one(key));
    measure("u64 shared", |key| shared.hash_one(key));
    measure("u64 previous kernel", |key| previous_words(seed, [key]));
    measure("identity standard", |key| {
        bytes.hash_one((7_u64, key, 3_u8))
    });
    measure("identity shared", |key| shared.hash_one((7_u64, key, 3_u8)));
    measure("identity previous kernel", |key| {
        previous_words(seed, [7, key, 3])
    });
    measure("mixed standard", |key| {
        bytes.hash_one((key, "subject", 3_u8))
    });
    measure("mixed shared", |key| {
        shared.hash_one((key, "subject", 3_u8))
    });
    // A consumed Hash value also exercises the blanket standard integration.
    black_box((7_u64, "subject")).hash(&mut shared.build_hasher());
}
