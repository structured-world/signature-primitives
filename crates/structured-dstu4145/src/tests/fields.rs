use super::{compressed, encoded, normal, polynomial};
use crate::{
    Basis, ByteOrder, Error,
    domain::Domain,
    domains,
    field::{Arithmetic, Normal, Polynomial},
    multiplication::{Hardware, Kernel, Portable},
    words::{self, Words},
};

/// A bitwise oracle detects lost high carry-less product bits and window errors.
#[test]
fn window_products_match_bitwise_oracle() {
    let left = Words([u64::MAX, 0x1234_5678_9012_abcd, 3, 7, 13, 17, 19, 23]);
    let right = Words([0x8000_0000_0000_0001, 3, 5, 7, 11, 13, 17, 19]);
    for count in 1..=8 {
        let mut expected = [0; 16];
        for i in 0..count * 64 {
            if left.bit(i) {
                for j in 0..count {
                    words::xor_shift(&mut expected, right.0[j], i + j * 64);
                }
            }
        }
        assert_eq!(words::product(left, right, count), expected);
        assert_eq!(
            words::square(left, count),
            words::product(left, left, count)
        );
    }
}

fn axioms<F: Arithmetic>(field: &F) {
    let mut a = Words::hex("1234567890ABCDEFFEDCBA09876543211234567890ABCDEF");
    let mut b = Words::hex("9876543210FEDCBA0123456789ABCDEF");
    a.clear_above(field.degree());
    b.clear_above(field.degree());
    let a = field.import(a);
    let b = field.import(b);
    assert_eq!(field.import(field.export(a)), a);
    assert_eq!(field.multiply(a, field.one()), a);
    assert_eq!(field.square(a), field.multiply(a, a));
    assert_eq!(field.multiply(a, b), field.multiply(b, a));
    assert_eq!(
        field.multiply(a, a.add(b)),
        field.square(a).add(field.multiply(a, b))
    );
    assert_eq!(field.multiply(a, field.inverse(a)), field.one());
    assert_eq!(field.square_times(a, field.degree()), a);
    assert_eq!(field.square(field.sqrt(a)), a);
    let trace_zero = field.square(a).add(a);
    assert!(!field.trace(trace_zero));
    let root = field.half_trace(trace_zero);
    assert_eq!(field.square(root).add(root), trace_zero);
}

/// Every standard PB polynomial, including the largest fallback reductions,
/// must agree with field axioms rather than only exercised named domains.
#[test]
fn all_standard_polynomial_fields() {
    for row in domains::POLYNOMIALS {
        let count = if row[2] == 0 { 1 } else { 3 };
        axioms(&Polynomial::new(row[0], &row[1..=count], Portable).unwrap());
        if let Some(kernel) = Hardware::detect() {
            axioms(&Polynomial::new(row[0], &row[1..=count], kernel).unwrap());
        }
    }
}

/// ONB import/export, cyclic square and reflected products share one field.
#[test]
fn all_standard_normal_fields() {
    for degree in [
        173, 179, 191, 233, 239, 251, 281, 293, 359, 419, 431, 443, 491, 509,
    ] {
        axioms(&Normal::new(degree, Portable).unwrap());
        if let Some(kernel) = Hardware::detect() {
            axioms(&Normal::new(degree, kernel).unwrap());
        }
    }
    assert!(matches!(
        Normal::new(163, Portable),
        Err(Error::UnsupportedDomain)
    ));
}

/// Every supported limb count must preserve all unreduced bits, including
/// carries across output limbs. This exercises the actual detected backend.
#[test]
fn native_products_match_portable() {
    let Some(kernel) = Hardware::detect() else {
        return;
    };
    let mut state = 0xdead_beef_1234_5678_u64;
    for count in 0..=8 {
        for sample in 0..128 {
            let left = Words(core::array::from_fn(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                match sample {
                    0 => 0,
                    1 => u64::MAX,
                    2 => 1 << 63,
                    _ => state,
                }
            }));
            let right = Words(core::array::from_fn(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                match sample {
                    0 | 1 => u64::MAX,
                    2 => 1,
                    _ => state,
                }
            }));
            assert_eq!(
                kernel.product(&left, &right, count),
                Portable.product(&left, &right, count)
            );
        }
    }
}

fn points<F: Arithmetic>(curve: &crate::curve::Curve<F>, spec: &domains::Spec) {
    let base = crate::curve::Point {
        x: curve.field.import(spec.x),
        y: curve.field.import(spec.y),
    };
    assert!(curve.contains(base), "domain {} point", spec.m);
    assert_eq!(curve.decompress(compressed(curve, base)).unwrap(), base);
    assert!(
        curve.multiply(base, spec.order).is_none(),
        "domain {} order",
        spec.m
    );
    assert!(curve.multiply(base, Words::ZERO).is_none());
    assert_eq!(curve.multiply(base, Words::ONE), Some(base));
    let twice = curve.add(Some(base), Some(base));
    assert_eq!(curve.multiply(base, Words::hex("2")), twice);
    assert_eq!(
        curve.multiply(base, Words::hex("3")),
        curve.add(twice, Some(base))
    );
    assert_eq!(
        curve.multiply(base, Words::hex("7")),
        curve.add(
            curve.multiply(base, Words::hex("3")),
            curve.multiply(base, Words::hex("4"))
        )
    );
    let encoded = encoded(
        compressed(curve, base),
        spec.m.div_ceil(8),
        ByteOrder::LittleEndian,
    );
    let basis = if domains::PB
        .iter()
        .any(|candidate| core::ptr::eq(candidate, spec))
    {
        Basis::Polynomial
    } else {
        Basis::OptimalNormal
    };
    assert!(
        Domain::named(basis, spec.m)
            .unwrap()
            .public_key(&encoded, ByteOrder::LittleEndian)
            .is_ok()
    );
}

/// All15 published domains are qualified as complete point/order tuples.
#[test]
fn all_recommended_domain_points_and_subgroups() {
    for spec in &domains::PB {
        points(&polynomial(spec), spec);
    }
    for spec in &domains::ONB {
        points(&normal(spec), spec);
    }
}

/// Order-two, over-width and unsupported values never become accepted keys.
#[test]
fn key_validation_rejects_invalid_inputs() {
    assert!(matches!(
        Domain::named(Basis::Polynomial, 509),
        Err(Error::UnsupportedDomain)
    ));
    let zero = [0; 21];
    assert!(matches!(
        Domain::named(Basis::Polynomial, 163)
            .unwrap()
            .public_key(&zero, ByteOrder::BigEndian),
        Err(Error::InvalidKey)
    ));
    assert!(matches!(
        Domain::named(Basis::Polynomial, 163)
            .unwrap()
            .public_key(&zero[..20], ByteOrder::BigEndian),
        Err(Error::InvalidEncoding)
    ));
    let mut wide = zero;
    wide[0] = 128;
    assert!(matches!(
        Domain::named(Basis::Polynomial, 163)
            .unwrap()
            .public_key(&wide, ByteOrder::BigEndian),
        Err(Error::InvalidEncoding)
    ));
}

/// A Frobenius-isomorphic curve is not the named domain's original coefficient.
/// These three rows agree with DSTU TableG.2 and UAPKI ec-default-params.c.
#[test]
fn normal_domains_use_original_standard_coefficients() {
    assert_eq!(
        domains::ONB[1].b,
        Words::hex("19C9EBC4FD8308193D3A61762C547C82F2E6B2182CBCB")
    );
    assert_eq!(
        domains::ONB[2].b,
        Words::hex("13871C9D29D6CEEA740FD57444F72FDBAE559C13A1E31EF8")
    );
    assert_eq!(
        domains::ONB[4].b,
        Words::hex(
            "53FB7AF7B4407000A6F226AD6BAD28378646BD83F1F940810A4C19536EE65E53F40F973F2F06C5E80EFE3B43651BD5FF8B06BA5F9299"
        )
    );
}

/// Positive allocation instrumentation first proves it observes heap use.
/// Key preparation, subgroup checks, actual two-scalar verification, DKE
/// preparation and both hash families then execute without any allocation.
#[cfg(feature = "allocation-tests")]
#[test]
fn complete_backend_paths_do_not_allocate() {
    let control = allocation_counter::measure(|| {
        let bytes = std::vec![core::hint::black_box(7_u8); 100];
        core::hint::black_box(bytes);
    });
    assert!(control.count_total > 0);
    let spec = &domains::PB[0];
    let curve = polynomial(spec);
    let point = crate::curve::Point {
        x: spec.x,
        y: spec.y,
    };
    let public = encoded(compressed(&curve, point), 21, ByteOrder::LittleEndian);
    let measured = allocation_counter::measure(|| {
        let key = Domain::named(Basis::Polynomial, 163)
            .unwrap()
            .public_key(&public, ByteOrder::LittleEndian)
            .unwrap();
        let mut signature = [0; 42];
        signature[0] = 2;
        signature[21] = 3;
        core::hint::black_box(
            key.verify_prehash(&[1; 32], &signature, ByteOrder::LittleEndian)
                .unwrap(),
        );
        let dke = crate::gost::Dke::new(&crate::gost::DEFAULT_DKE).unwrap();
        for identity in [
            crate::hash::Hash::Gost34311(&dke),
            crate::hash::Hash::Kupyna(32),
            crate::hash::Hash::Kupyna(48),
            crate::hash::Hash::Kupyna(64),
        ] {
            let mut state = crate::hash::State::new(identity).unwrap();
            state.update(&[7; 257]).unwrap();
            core::hint::black_box(state.finalize());
        }
    });
    assert_eq!(measured.count_total, 0);
    assert_eq!(measured.bytes_total, 0);
}
