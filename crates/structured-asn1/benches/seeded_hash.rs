//! Integer table hashing against standard hashing and the complete donor.
//! Run: `cargo bench -p structured-asn1 --features std --bench seeded_hash`
//! Optional positional arguments: case (default `all`), iterations (default 5000000).

use core::{hash::BuildHasher, hint::black_box};
use std::{hash::RandomState, time::Instant};
use structured_asn1::hash::SeededState;

#[path = "seeded_hash/donor.rs"]
mod donor;

fn measure(label: &str, iterations: u32, mut hash: impl FnMut(u64) -> u64) {
    let start = Instant::now();
    let mut result = 0;
    for key in 0..iterations {
        result ^= hash(u64::from(black_box(key)));
    }
    black_box(result);
    println!(
        "{label}: {:.3} ns/key",
        start.elapsed().as_secs_f64() * 1e9 / f64::from(iterations)
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let case = arguments.next().unwrap_or_else(|| "all".to_owned());
    let iterations = match arguments.next() {
        Some(value) => value.parse::<u32>()?,
        None => 5_000_000,
    };
    if iterations == 0 {
        return Err("iterations must be positive".into());
    }
    let names = [
        "u64-standard",
        "u64-shared",
        "u64-donor",
        "identity-standard",
        "identity-shared",
        "identity-donor",
        "mixed-standard",
        "mixed-shared",
        "mixed-donor",
    ];
    if case != "all" && !names.contains(&case.as_str()) {
        return Err("unknown benchmark case".into());
    }
    let bytes = RandomState::new();
    let seed = black_box(bytes.hash_one(0x5eed_u64) | 1);
    let shared = SeededState::new(seed, bytes.clone());
    let donor = donor::State::new(seed, bytes.clone());
    println!("{iterations} keys/sample; release profile; no table allocation");
    macro_rules! run {
        ($name:literal, $hash:expr) => {
            if case == "all" || case == $name {
                measure($name, iterations, $hash);
            }
        };
    }
    run!("u64-standard", |key| bytes.hash_one(key));
    run!("u64-shared", |key| shared.hash_one(key));
    run!("u64-donor", |key| donor.hash_one(key));
    run!("identity-standard", |key| bytes
        .hash_one((7_u64, key, 3_u8)));
    run!("identity-shared", |key| shared.hash_one((7_u64, key, 3_u8)));
    run!("identity-donor", |key| donor.hash_one((7_u64, key, 3_u8)));
    run!("mixed-standard", |key| bytes
        .hash_one((key, "subject", 3_u8)));
    run!("mixed-shared", |key| shared
        .hash_one((key, "subject", 3_u8)));
    run!("mixed-donor", |key| donor.hash_one((key, "subject", 3_u8)));
    Ok(())
}
