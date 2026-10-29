//! Repeated verification and preparation are measured separately. The external
//! implementation is a performance reference, not a normative/security oracle.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use structured_dstu4145::{
    Basis, ByteOrder,
    domain::Domain,
    gost::{DEFAULT_DKE, Dke},
    hash::{Hash, State},
};

fn timing(mut operation: impl FnMut(), count: usize) -> (Duration, Duration) {
    for _ in 0..5 {
        operation();
    }
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let start = Instant::now();
        operation();
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    (samples[count / 2], samples[count * 99 / 100])
}

fn main() {
    println!("verification samples=500, warmup=5, times=nanoseconds");
    for (basis, degree) in [
        (Basis::Polynomial, 163),
        (Basis::Polynomial, 257),
        (Basis::Polynomial, 431),
        (Basis::OptimalNormal, 173),
        (Basis::OptimalNormal, 233),
    ] {
        let reference = match basis {
            Basis::Polynomial => ua_cryptography_dstu4145::get_polynomial_curve(degree),
            Basis::OptimalNormal => ua_cryptography_dstu4145::get_optimal_normal_curve(degree),
        }
        .unwrap();
        let public = reference
            .curve()
            .compress_to_bytes(reference.base_point())
            .unwrap();
        reference
            .validate_public_key(reference.base_point())
            .unwrap();
        let reference_signer = ua_cryptography_dstu4145::Signer::new(&reference);
        let make_key = || {
            Domain::named(basis, usize::try_from(degree).unwrap())
                .unwrap()
                .public_key(&public, ByteOrder::BigEndian)
                .unwrap()
        };
        let key = make_key();
        let width = key.order_bits().div_ceil(8);
        let mut signature = vec![0; 2 * width];
        for (half, bit) in [(0, key.order_bits() - 3), (1, key.order_bits() - 2)] {
            signature[half * width + width - 1 - bit / 8] = 1 << (bit % 8);
            signature[(half + 1) * width - 1] |= 1;
        }
        let hash = [0xa5; 32];
        assert!(
            !key.verify_prehash(&hash, &signature, ByteOrder::BigEndian)
                .unwrap()
        );
        assert!(!reference_signer.verify_hash(reference.base_point(), &hash, &signature));
        let prepared = timing(
            || {
                black_box(make_key());
            },
            50,
        );
        let own = timing(
            || {
                black_box(
                    key.verify_prehash(
                        black_box(&hash),
                        black_box(&signature),
                        ByteOrder::BigEndian,
                    )
                    .unwrap(),
                );
            },
            500,
        );
        let external = timing(
            || {
                black_box(reference_signer.verify_hash(
                    reference.base_point(),
                    black_box(&hash),
                    black_box(&signature),
                ));
            },
            500,
        );
        println!(
            "{basis:?} m={degree} prepare_p50={} prepare_p99={} verify_p50={} verify_p99={} reference_verify_p50={} reference_verify_p99={}",
            prepared.0.as_nanos(),
            prepared.1.as_nanos(),
            own.0.as_nanos(),
            own.1.as_nanos(),
            external.0.as_nanos(),
            external.1.as_nanos()
        );
        #[cfg(feature = "allocation-tests")]
        {
            let own = allocation_counter::measure(|| {
                black_box(
                    key.verify_prehash(&hash, &signature, ByteOrder::BigEndian)
                        .unwrap(),
                );
            });
            let external = allocation_counter::measure(|| {
                black_box(reference_signer.verify_hash(reference.base_point(), &hash, &signature));
            });
            println!(
                "{basis:?} m={degree} own_allocations={} own_bytes={} reference_allocations={} reference_bytes={}",
                own.count_total, own.bytes_total, external.count_total, external.bytes_total
            );
        }
    }
    let dke = Dke::new(&DEFAULT_DKE).unwrap();
    let input = vec![0x5a; 1 << 20];
    for identity in [
        Hash::Gost34311(&dke),
        Hash::Kupyna(32),
        Hash::Kupyna(48),
        Hash::Kupyna(64),
    ] {
        let time = timing(
            || {
                let mut state = State::new(identity).unwrap();
                for chunk in input.chunks(8192) {
                    state.update(black_box(chunk)).unwrap();
                }
                black_box(state.finalize());
            },
            10,
        );
        let name = match identity {
            Hash::Gost34311(_) => "GOST34311",
            Hash::Kupyna(_) => "Kupyna",
        };
        println!(
            "{name} width={} bytes={} hash_p50={} hash_p99={}",
            identity.width().unwrap(),
            input.len(),
            time.0.as_nanos(),
            time.1.as_nanos()
        );
    }
}
