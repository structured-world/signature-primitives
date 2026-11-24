//! Comparison against the consumer's scalar STANDARD engine, using reused buffers.

use base64::{Engine as _, engine::general_purpose};
use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use structured_base64::{Base64Codec, STANDARD, URL_SAFE_NO_PAD};

fn time(iterations: usize, mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    start.elapsed()
}

fn compare(size: usize, name: &str, mut ours: impl FnMut(), mut reference: impl FnMut()) {
    let iterations = (32 * 1024 * 1024 / size).max(32);
    let mut samples = [0.0; 7];
    ours();
    reference();
    for (index, sample) in samples.iter_mut().enumerate() {
        let (a, b) = if index % 2 == 0 {
            (
                time(iterations, &mut ours),
                time(iterations, &mut reference),
            )
        } else {
            let reference = time(iterations, &mut reference);
            (time(iterations, &mut ours), reference)
        };
        *sample = b.as_secs_f64() / a.as_secs_f64();
    }
    samples.sort_by(f64::total_cmp);
    println!(
        "{size:>8} B {name:<20} {:.3}x reference throughput",
        samples[3]
    );
}

fn main() {
    for size in [64, 4096, 1024 * 1024] {
        let mut state = 0x1234_5678_u32;
        let payload: Vec<_> = (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[0]
            })
            .collect();
        let standard = general_purpose::STANDARD.encode(&payload);
        let url = general_purpose::URL_SAFE_NO_PAD.encode(&payload);
        let mut ours = vec![0; standard.len()];
        let mut reference = ours.clone();
        let mut test = |name, profile: structured_base64::Profile, wire: &str| {
            let written = profile.encode_slice(&payload, &mut ours).unwrap();
            assert_eq!(&ours[..written], wire.as_bytes());
            assert_eq!(
                profile.decode_slice(wire.as_bytes(), &mut ours).unwrap(),
                size
            );
            assert_eq!(&ours[..size], payload);
            compare(
                size,
                name,
                || {
                    black_box(
                        profile
                            .encode_slice(black_box(&payload), black_box(&mut ours))
                            .unwrap(),
                    );
                },
                || {
                    black_box(
                        general_purpose::STANDARD
                            .encode_slice(black_box(&payload), black_box(&mut reference))
                            .unwrap(),
                    );
                },
            );
            compare(
                size,
                if profile == STANDARD {
                    "standard decode"
                } else {
                    "URL decode"
                },
                || {
                    black_box(
                        profile
                            .decode_slice(black_box(wire.as_bytes()), black_box(&mut ours))
                            .unwrap(),
                    );
                },
                || {
                    black_box(
                        general_purpose::STANDARD
                            .decode_slice(black_box(standard.as_bytes()), black_box(&mut reference))
                            .unwrap(),
                    );
                },
            );
        };
        test("standard encode", STANDARD, &standard);
        test("URL encode", URL_SAFE_NO_PAD, &url);
        compare(
            size,
            "stream decode",
            || {
                let mut decoder = Base64Codec::new(false, 0);
                black_box(
                    decoder
                        .update(black_box(standard.as_bytes()), black_box(&mut ours))
                        .unwrap(),
                );
                decoder.finish(&mut []).unwrap();
            },
            || {
                black_box(
                    general_purpose::STANDARD
                        .decode_slice(black_box(standard.as_bytes()), black_box(&mut reference))
                        .unwrap(),
                );
            },
        );
    }
}
