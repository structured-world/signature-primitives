use super::{compressed, encoded, polynomial};
use crate::{
    ByteOrder, Error,
    curve::Point,
    domain::{Domain, Explicit},
    domains,
    validation::{Custom, Known, ValidationError, Validator},
    words::Words,
};
use structured_pkix::algorithm::dstu4145::Reduction;

#[derive(Debug, PartialEq, Eq)]
struct Unavailable;
impl core::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("entropy unavailable")
    }
}
impl core::error::Error for Unavailable {}
struct NoEntropy;
impl rand_core::TryRng for NoEntropy {
    type Error = Unavailable;
    fn try_next_u32(&mut self) -> Result<u32, Unavailable> {
        Err(Unavailable)
    }
    fn try_next_u64(&mut self) -> Result<u64, Unavailable> {
        Err(Unavailable)
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Unavailable> {
        Err(Unavailable)
    }
}
impl rand_core::TryCryptoRng for NoEntropy {}

/// Standard facts consume no entropy, while unknown orders require evidence.
/// Original RNG failures survive before any assertion of primality or MOV.
#[test]
fn explicit_order_validation_preserves_entropy_failure() {
    let spec = &domains::PB[0];
    assert!(Known.order(spec.order, 163).is_ok());
    let mut custom = Custom {
        factors: &[],
        random: &mut NoEntropy,
    };
    assert!(custom.order(spec.order, 163).is_ok());
    // 2^163-1 is not divisible by the small screening primes; RNG is required.
    let candidate = Words::hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    assert!(matches!(
        Known.order(candidate, 163),
        Err(Error::ValidationEvidenceRequired)
    ));
    assert!(matches!(
        custom.order(candidate, 163),
        Err(ValidationError::Entropy(Unavailable))
    ));
}

/// Unchecked explicit domains are never admitted merely because their base
/// point lies on the curve. Zero/order-two bases, tiny/composite orders and
/// noncanonical field framing all refuse through the same preparation path.
#[test]
fn explicit_domains_validate_base_and_order() {
    let spec = &domains::PB[0];
    let curve = polynomial(spec);
    let b = encoded(spec.b, 21, ByteOrder::BigEndian);
    let base = encoded(
        compressed(
            &curve,
            Point {
                x: spec.x,
                y: spec.y,
            },
        ),
        21,
        ByteOrder::BigEndian,
    );
    let order = encoded(spec.order, 21, ByteOrder::BigEndian);
    let input = Explicit {
        degree: 163,
        reduction: Reduction::Pentanomial { k: 3, j: 6, l: 7 },
        a: true,
        b: &b,
        base_point: &base,
        order: &order,
        byte_order: ByteOrder::BigEndian,
    };
    assert!(Domain::explicit(input).is_ok());
    assert!(Domain::explicit_with_evidence(input, &[], &mut NoEntropy).is_ok());
    let invalid = [0; 21];
    assert!(matches!(
        Domain::explicit(Explicit {
            base_point: &invalid,
            ..input
        }),
        Err(Error::InvalidDomain)
    ));
    assert!(matches!(
        Domain::explicit(Explicit {
            b: &invalid,
            ..input
        }),
        Err(Error::InvalidDomain)
    ));
    for order in [&[1][..], &[2][..], &[3][..], &[0; 22][..]] {
        assert!(Domain::explicit(Explicit { order, ..input }).is_err());
    }
    assert!(matches!(
        Domain::explicit(Explicit {
            reduction: Reduction::Trinomial(3),
            ..input
        }),
        Err(Error::ValidationEvidenceRequired)
    ));
    assert!(
        Domain::explicit(Explicit {
            b: &b[..20],
            ..input
        })
        .is_err()
    );
}
