//! Explicit-domain validation, without hidden randomness or factoring services.

use crate::{
    Error, domains,
    field::{Arithmetic, Polynomial},
    words::Words,
};
use core::fmt;
use crypto_bigint::{
    NonZero, Odd, U512,
    modular::{FixedMontyForm, FixedMontyParams},
};
use rand_core::TryCryptoRng;

type Monty = FixedMontyForm<{ U512::LIMBS }>;

/// Original entropy failure or a mathematical/representation refusal.
#[derive(Debug)]
pub enum ValidationError<E> {
    /// Invalid or unsupported supplied validation inputs.
    Input(Error),
    /// The original caller-provided entropy-source failure.
    Entropy(E),
}

impl<E: fmt::Display> fmt::Display for ValidationError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::Entropy(error) => error.fmt(f),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ValidationError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(match self {
            Self::Input(error) => error,
            Self::Entropy(error) => error,
        })
    }
}

impl<E> From<Error> for ValidationError<E> {
    fn from(value: Error) -> Self {
        Self::Input(value)
    }
}

/// One prime factor of 2^m-1 and its positive multiplicity.
/// Factors are unsigned big-endian, distinct and strictly increasing.
#[derive(Debug, Clone, Copy)]
pub struct Factor<'a> {
    /// Unsigned factor, at most64 octets.
    pub prime: &'a [u8],
    /// Multiplicity in the complete factorization.
    pub multiplicity: u16,
}

pub(crate) trait Validator {
    type Error: From<Error>;
    fn polynomial(&mut self, field: &Polynomial, terms: &[usize]) -> Result<(), Self::Error>;
    fn order(&mut self, value: Words, degree: usize) -> Result<(), Self::Error>;
}

pub(crate) struct Known;

pub(crate) fn standard_polynomial(degree: usize, terms: &[usize]) -> bool {
    for row in domains::POLYNOMIALS {
        if row[0] == degree {
            let count = if row[2] == 0 { 1 } else { 3 };
            return terms == &row[1..=count];
        }
    }
    false
}

fn known_order(value: Words, degree: usize) -> bool {
    domains::PB
        .iter()
        .any(|spec| spec.m == degree && spec.order == value)
}

impl Validator for Known {
    type Error = Error;
    fn polynomial(&mut self, field: &Polynomial, terms: &[usize]) -> Result<(), Error> {
        if standard_polynomial(field.degree(), terms) {
            Ok(())
        } else {
            Err(Error::ValidationEvidenceRequired)
        }
    }
    fn order(&mut self, value: Words, degree: usize) -> Result<(), Error> {
        if known_order(value, degree) {
            Ok(())
        } else {
            Err(Error::ValidationEvidenceRequired)
        }
    }
}

pub(crate) struct Custom<'a, R> {
    pub(crate) factors: &'a [Factor<'a>],
    pub(crate) random: &'a mut R,
}

impl<R: TryCryptoRng> Validator for Custom<'_, R> {
    type Error = ValidationError<R::Error>;

    fn polynomial(&mut self, field: &Polynomial, terms: &[usize]) -> Result<(), Self::Error> {
        let degree = field.degree();
        if standard_polynomial(degree, terms) {
            return Ok(());
        }
        if !domains::POLYNOMIALS.iter().any(|row| row[0] == degree) {
            return Err(Error::UnsupportedDomain.into());
        }
        let mut polynomial_t = Words::ZERO;
        polynomial_t.flip(1);
        // Every allowed m is prime and f(0)=f(1)=1. Rabin's criterion
        // therefore reduces irreducibility to t^(2^m)=t modulo f.
        if field.square_times(polynomial_t, degree) != polynomial_t {
            return Err(Error::InvalidField.into());
        }
        if self.factors.is_empty() || self.factors.len() > degree {
            return Err(Error::ValidationEvidenceRequired.into());
        }
        let mut all_ones = Words([u64::MAX; 8]);
        all_ones.clear_above(degree);
        let mersenne = integer(all_ones);
        let mut remaining = mersenne;
        let mut previous = U512::ONE;
        let mut multiplicities = 0;
        for factor in self.factors {
            multiplicities += usize::from(factor.multiplicity);
            if factor.multiplicity == 0 || multiplicities > degree {
                return Err(Error::InvalidField.into());
            }
            let prime = integer(Words::read(factor.prime, crate::ByteOrder::BigEndian)?);
            if prime <= previous || !probable_prime(prime, self.random)? {
                return Err(Error::InvalidField.into());
            }
            previous = prime;
            let divisor =
                Option::<NonZero<U512>>::from(NonZero::new(prime)).ok_or(Error::InvalidField)?;
            for _ in 0..factor.multiplicity {
                let (quotient, remainder) = remaining.div_rem_vartime(&divisor);
                if remainder != U512::ZERO {
                    return Err(Error::InvalidField.into());
                }
                remaining = quotient;
            }
            let exponent = mersenne.div_rem_vartime(&divisor).0;
            if power(field, polynomial_t, exponent) == Words::ONE {
                return Err(Error::InvalidField.into());
            }
        }
        if remaining != U512::ONE {
            return Err(Error::ValidationEvidenceRequired.into());
        }
        Ok(())
    }

    fn order(&mut self, value: Words, degree: usize) -> Result<(), Self::Error> {
        if known_order(value, degree) {
            return Ok(());
        }
        let candidate = integer(value);
        if !probable_prime(candidate, self.random)? {
            return Err(Error::InvalidDomain.into());
        }
        let odd = Option::<Odd<U512>>::from(Odd::new(candidate)).ok_or(Error::InvalidDomain)?;
        let params = FixedMontyParams::new_vartime(odd);
        let two = Monty::new(&U512::from_u32(2), &params);
        let degree = u32::try_from(degree).map_err(|_| Error::UnsupportedDomain)?;
        let step = two.pow_vartime(&U512::from_u32(degree));
        let mut product = Monty::one(&params);
        for _ in 0..32 {
            product *= step;
            if product.retrieve() == U512::ONE {
                return Err(Error::InvalidDomain.into());
            }
        }
        Ok(())
    }
}

pub(crate) fn integer(value: Words) -> U512 {
    let mut bytes = [0; 64];
    for (chunk, limb) in bytes.chunks_exact_mut(8).zip(value.0) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    U512::from_le_slice(&bytes)
}

pub(crate) fn order_bounds(value: Words, degree: usize) -> Result<(), Error> {
    if !value.bit(0) || value.bits() < 161 || value.bits() > degree + 1 {
        return Err(Error::InvalidDomain);
    }
    // Section8.2(5): n >= max(2^160, 4*(floor(sqrt(2^m))+1)).
    let power = U512::ONE.shl_vartime(u32::try_from(degree).map_err(|_| Error::UnsupportedDomain)?);
    let bound = power
        .floor_sqrt_vartime()
        .wrapping_add(&U512::ONE)
        .shl_vartime(2);
    if integer(value) < bound {
        return Err(Error::InvalidDomain);
    }
    Ok(())
}

fn probable_prime<R: TryCryptoRng>(
    candidate: U512,
    random: &mut R,
) -> Result<bool, ValidationError<R::Error>> {
    for small in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let prime = U512::from_u32(small);
        if candidate == prime {
            return Ok(true);
        }
        if candidate < prime {
            return Ok(false);
        }
        let divisor =
            Option::<NonZero<U512>>::from(NonZero::new(prime)).ok_or(Error::InvalidDomain)?;
        if candidate.rem_vartime(&divisor) == U512::ZERO {
            return Ok(false);
        }
    }
    let odd = Option::<Odd<U512>>::from(Odd::new(candidate)).ok_or(Error::InvalidDomain)?;
    let params = FixedMontyParams::new_vartime(odd);
    let minus_one = candidate.wrapping_sub(&U512::ONE);
    let twos = minus_one.trailing_zeros_vartime();
    let exponent = minus_one.shr_vartime(twos);
    let bits = candidate.bits_vartime();
    let bytes = usize::try_from(bits.div_ceil(8)).map_err(|_| Error::InvalidDomain)?;
    // DSTU6.12 prescribes50 independent random bases. Rejection sampling
    // is bounded, uses caller entropy, and never reduces biased bytes mod n.
    for _ in 0..50 {
        let mut selected = None;
        for _ in 0..128 {
            let mut sample = [0; 64];
            random
                .try_fill_bytes(&mut sample[..bytes])
                .map_err(ValidationError::Entropy)?;
            if bits % 8 != 0 {
                sample[bytes - 1] &= (1 << (bits % 8)) - 1;
            }
            let base = U512::from_le_slice(&sample);
            if base > U512::ONE && base < candidate {
                selected = Some(base);
                break;
            }
        }
        let base = selected.ok_or(Error::RandomSampleRefused)?;
        let mut witness = Monty::new(&base, &params).pow_vartime(&exponent);
        let answer = witness.retrieve();
        if answer == U512::ONE || answer == minus_one {
            continue;
        }
        let mut passed = false;
        for _ in 1..twos {
            witness *= witness;
            let answer = witness.retrieve();
            if answer == minus_one {
                passed = true;
                break;
            }
            if answer == U512::ONE {
                return Ok(false);
            }
        }
        if !passed {
            return Ok(false);
        }
    }
    Ok(true)
}

fn power<F: Arithmetic>(field: &F, value: Words, exponent: U512) -> Words {
    let bytes = exponent.to_le_bytes();
    let mut result = field.one();
    for bit in (0..exponent.bits_vartime()).rev() {
        result = field.square(result);
        let index = bit as usize;
        if bytes[index / 8] & (1 << (index % 8)) != 0 {
            result = field.multiply(result, value);
        }
    }
    result
}
