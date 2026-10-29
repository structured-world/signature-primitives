use super::{compressed, encoded, polynomial};
use crate::{
    ByteOrder, Error,
    curve::Point,
    domain::{Domain, Explicit},
    domains,
    validation::{Custom, Known, ValidationError, Validator},
    words::Words,
};
use rand_core::SeedableRng;
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

struct ZeroEntropy {
    draws: usize,
}
impl rand_core::TryRng for ZeroEntropy {
    type Error = Unavailable;
    fn try_next_u32(&mut self) -> Result<u32, Unavailable> {
        self.draws += 1;
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Unavailable> {
        self.draws += 1;
        Ok(0)
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Unavailable> {
        self.draws += 1;
        bytes.fill(0);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for ZeroEntropy {}

/// An entropy source yielding only rejected bases must terminate at the
/// fixed sampling ceiling, without a deterministic substitute or a hang.
#[test]
fn rejected_random_bases_have_a_fixed_call_bound() {
    let mut random = ZeroEntropy { draws: 0 };
    let mut custom = Custom {
        factors: &[],
        random: &mut random,
    };
    let candidate = Words::hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    assert!(matches!(
        custom.order(candidate, 163),
        Err(ValidationError::Input(Error::RandomSampleRefused))
    ));
    assert_eq!(random.draws, 128);
}

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

/// A different prime-order curve must take the full probabilistic validation
/// path, rather than being accepted by the named-domain catalogue. Constants
/// are from Standards for Efficient Cryptography2, version2, section3.2.1.
/// https://www.secg.org/sec2-v2.pdf
#[test]
fn custom_curve_validation_succeeds_with_caller_entropy() {
    let field = crate::field::Polynomial::new(163, &[3, 6, 7]).unwrap();
    let curve = crate::curve::Curve::new(field, true, Words::ONE).unwrap();
    let base = Point {
        x: Words::hex("02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8"),
        y: Words::hex("0289070FB05D38FF58321F2E800536D538CCDAA3D9"),
    };
    assert!(curve.contains(base));
    let b = encoded(Words::ONE, 21, ByteOrder::BigEndian);
    let n = super::bytes("04000000000000000000020108A2E0CC0D99F8A5EF");
    let base = encoded(compressed(&curve, base), 21, ByteOrder::BigEndian);
    let input = Explicit {
        degree: 163,
        reduction: Reduction::Pentanomial { k: 3, j: 6, l: 7 },
        a: true,
        b: &b,
        order: &n,
        base_point: &base,
        byte_order: ByteOrder::BigEndian,
    };
    assert!(matches!(
        Domain::explicit(input),
        Err(Error::ValidationEvidenceRequired)
    ));
    let mut random = rand_chacha::ChaCha20Rng::from_seed([7; 32]);
    let domain = Domain::explicit_with_evidence(input, &[], &mut random).unwrap();
    assert!(domain.public_key(&base, ByteOrder::BigEndian).is_ok());
    // The original ASN route must reach the same custom-domain validation,
    // preserving both actual entropy failures and the producing work ceiling.
    use super::accounting::{SIGNATURE_OID, memory, parser, read, tlv};
    use structured_asn1::memory::Work;
    let mut exponents = tlv(2, &[3]);
    exponents.extend(tlv(2, &[6]));
    exponents.extend(tlv(2, &[7]));
    let mut field = tlv(2, &[0, 163]);
    field.extend(tlv(48, &exponents));
    let mut curve = tlv(48, &field);
    curve.extend(tlv(2, &[1]));
    let b_le: std::vec::Vec<_> = b.iter().rev().copied().collect();
    let base_le: std::vec::Vec<_> = base.iter().rev().copied().collect();
    curve.extend(tlv(4, &b_le));
    curve.extend(tlv(2, &n));
    curve.extend(tlv(4, &base_le));
    let mut algorithm = tlv(6, SIGNATURE_OID);
    algorithm.extend(tlv(48, &tlv(48, &curve)));
    let mut key_bytes = tlv(48, &algorithm);
    let mut bits = std::vec![0];
    bits.extend(tlv(4, &base_le));
    key_bytes.extend(tlv(3, &bits));
    let key_bytes = tlv(48, &key_bytes);
    let memory = memory();
    let parser = parser(memory.clone());
    let spki = read(&parser, &key_bytes, 1200);
    let dke = crate::gost::Dke::new(&crate::gost::DEFAULT_DKE).unwrap();
    assert!(matches!(
        crate::accounted::Key::prepare_with_evidence(spki, &dke, &memory, &[], &mut NoEntropy),
        Err(crate::accounted::Failure::Entropy {
            source: Unavailable,
            ..
        })
    ));
    assert!(
        crate::accounted::Key::prepare_with_evidence(spki, &dke, &memory, &[], &mut random).is_ok()
    );
    let work = parser.execution_in(&memory);
    work.charge_work(u64::try_from(work.work_remaining()).unwrap())
        .unwrap();
    assert!(matches!(
        crate::accounted::Key::prepare_with_evidence(spki, &dke, &memory, &[], &mut NoEntropy),
        Err(crate::accounted::Failure::Resource { .. })
    ));
}

/// The reciprocal of a known primitive polynomial is primitive. Complete
/// factor evidence must be checked, including primality and final product;
/// neither irreducibility alone nor a proper subset establishes primitivity.
#[test]
fn primitive_polynomial_requires_complete_factor_evidence() {
    let primes = [
        "024b0f",
        "0abea1",
        "0691b191",
        "0671353d59",
        "01f6cc6e796f81d5c9",
    ]
    .map(super::bytes);
    let factors: std::vec::Vec<_> = primes
        .iter()
        .map(|prime| crate::validation::Factor {
            prime,
            multiplicity: 1,
        })
        .collect();
    let field = crate::field::Polynomial::new(163, &[156, 157, 160]).unwrap();
    let mut random = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
    let mut custom = Custom {
        factors: &factors,
        random: &mut random,
    };
    custom.polynomial(&field, &[156, 157, 160]).unwrap();
    let mut partial = Custom {
        factors: &factors[..4],
        random: &mut random,
    };
    assert!(matches!(
        partial.polynomial(&field, &[156, 157, 160]),
        Err(ValidationError::Input(Error::ValidationEvidenceRequired))
    ));
    let mut no_proof = Custom {
        factors: &[],
        random: &mut random,
    };
    assert!(matches!(
        no_proof.polynomial(&field, &[156, 157, 160]),
        Err(ValidationError::Input(Error::ValidationEvidenceRequired))
    ));
}
