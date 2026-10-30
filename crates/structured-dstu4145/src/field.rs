//! Public binary-field arithmetic, without element-owned context or storage.

use crate::multiplication::{Kernel, Portable};
use crate::words::{self, LIMBS, Product, Words};
use crate::{Error, MAX_DEGREE};

pub(crate) trait Arithmetic {
    fn degree(&self) -> usize;
    fn one(&self) -> Words;
    fn multiply(&self, left: Words, right: Words) -> Words;
    fn square(&self, value: Words) -> Words;
    fn trace(&self, value: Words) -> bool;
    fn import(&self, value: Words) -> Words;
    fn export(&self, value: Words) -> Words;

    fn square_times(&self, mut value: Words, times: usize) -> Words {
        for _ in 0..times {
            value = self.square(value);
        }
        value
    }

    fn inverse(&self, value: Words) -> Words {
        // DSTU4145 annex C.4 (original Cyrillic V.4): Itoh-Tsujii's
        // addition chain uses m-1 squarings and O(log m) multiplications.
        let exponent = self.degree() - 1;
        let top = usize::BITS - 1 - exponent.leading_zeros();
        let mut result = value;
        let mut length = 1;
        for bit in (0..top).rev() {
            result = self.multiply(result, self.square_times(result, length));
            length *= 2;
            if exponent & (1 << bit) != 0 {
                result = self.multiply(self.square(result), value);
                length += 1;
            }
        }
        self.square(result)
    }

    fn sqrt(&self, value: Words) -> Words {
        self.square_times(value, self.degree() - 1)
    }

    fn half_trace(&self, value: Words) -> Words {
        let mut result = value;
        for _ in 0..(self.degree() - 1) / 2 {
            result = self.square(self.square(result)).add(value);
        }
        result
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Polynomial<K: Kernel = Portable> {
    kernel: K,
    degree: usize,
    terms: [usize; 4],
    count: usize,
    trace_mask: Words,
}

impl<K: Kernel> Polynomial<K> {
    // This checks representation, not primitivity. Domain preparation owns
    // the independent validation mandated by DSTU4145 section8.1.
    pub(crate) fn new(degree: usize, exponents: &[usize], kernel: K) -> Result<Self, Error> {
        if !(163..=MAX_DEGREE).contains(&degree) || degree.is_multiple_of(2) {
            return Err(Error::UnsupportedDomain);
        }
        if exponents.len() != 1 && exponents.len() != 3 {
            return Err(Error::InvalidField);
        }
        let mut terms = [0; 4];
        let mut previous = 0;
        for (i, &exponent) in exponents.iter().enumerate() {
            if exponent <= previous || exponent >= degree {
                return Err(Error::InvalidField);
            }
            terms[i + 1] = exponent;
            previous = exponent;
        }
        // Newton sums recover Tr(t^k) from the sparse reduction polynomial.
        // This avoids m independent m-step traces or a lazy global cache.
        let mut trace_mask = Words::ONE;
        for power in 1..degree {
            let mut trace = false;
            for &term in exponents {
                let coefficient = degree - term;
                if coefficient == power {
                    trace ^= power % 2 != 0;
                } else if coefficient < power {
                    trace ^= trace_mask.bit(power - coefficient);
                }
            }
            if trace {
                trace_mask.flip(power);
            }
        }
        Ok(Self {
            kernel,
            degree,
            terms,
            count: exponents.len() + 1,
            trace_mask,
        })
    }

    fn reduce(&self, mut product: Product) -> Words {
        let degree = self.degree;
        let terms = &self.terms[..self.count];
        if terms[self.count - 1] > degree - 64 {
            // Custom sparse polynomials may fold back into the current word.
            // The bounded bit path shares exactly the same reduction rule.
            for bit in (degree..2 * degree - 1).rev() {
                if product[bit / 64] & (1 << (bit % 64)) != 0 {
                    product[bit / 64] ^= 1 << (bit % 64);
                    for &term in terms {
                        let at = bit - degree + term;
                        product[at / 64] ^= 1 << (at % 64);
                    }
                }
            }
        } else {
            let top = degree / 64;
            for i in (top + 1..2 * degree.div_ceil(64)).rev() {
                let word = product[i];
                product[i] = 0;
                for &term in terms {
                    words::xor_shift(&mut product, word, i * 64 - degree + term);
                }
            }
            let tail = product[top] >> (degree % 64);
            product[top] &= (1 << (degree % 64)) - 1;
            for &term in terms {
                words::xor_shift(&mut product, tail, term);
            }
        }
        Words(core::array::from_fn(|i| product[i]))
    }
}

impl<K: Kernel> Arithmetic for Polynomial<K> {
    fn degree(&self) -> usize {
        self.degree
    }
    fn one(&self) -> Words {
        Words::ONE
    }
    fn multiply(&self, left: Words, right: Words) -> Words {
        self.reduce(self.kernel.product(&left, &right, self.degree.div_ceil(64)))
    }
    fn square(&self, value: Words) -> Words {
        self.reduce(words::square(value, self.degree.div_ceil(64)))
    }
    fn trace(&self, value: Words) -> bool {
        let mut parity = 0;
        for i in 0..self.degree.div_ceil(64) {
            parity ^= (value.0[i] & self.trace_mask.0[i]).count_ones();
        }
        parity % 2 != 0
    }
    fn import(&self, value: Words) -> Words {
        value
    }
    fn export(&self, value: Words) -> Words {
        value
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Normal<K: Kernel = Portable> {
    kernel: K,
    degree: usize,
}

impl<K: Kernel> Normal<K> {
    pub(crate) fn new(degree: usize, kernel: K) -> Result<Self, Error> {
        // Table2 gives exactly these type-II Gaussian normal bases.
        if ![
            173, 179, 191, 233, 239, 251, 281, 293, 359, 419, 431, 443, 491, 509,
        ]
        .contains(&degree)
        {
            return Err(Error::UnsupportedDomain);
        }
        Ok(Self { kernel, degree })
    }

    fn count(self) -> usize {
        (self.degree + 1).div_ceil(64)
    }

    fn trim(self, mut value: Words) -> Words {
        value.0[0] &= !1;
        value.clear_above(self.degree + 1);
        value
    }

    fn reflect(self, value: Words) -> Words {
        let count = self.count();
        let mut result = Words::ZERO;
        let mut carry = 0;
        let extent = count * 64;
        if extent >= self.degree + 2 {
            let shift = extent - self.degree - 2;
            // All admitted degrees are odd, so this shift is nonzero.
            debug_assert!(shift > 0 && shift < 64);
            for i in (0..count).rev() {
                let word = value.0[count - 1 - i].reverse_bits();
                result.0[i] = (word >> shift) | carry;
                carry = word << (64 - shift);
            }
        } else {
            // m=191 has no spare high bit after its mandatory zero bit0.
            for i in 0..count {
                let word = value.0[count - 1 - i].reverse_bits();
                result.0[i] = (word << 1) | carry;
                carry = word >> 63;
            }
        }
        result
    }

    fn shifted(product: &Product, bit: usize, limb: usize) -> u64 {
        let offset = bit / 64 + limb;
        let shift = bit % 64;
        let mut value = product[offset] >> shift;
        if shift != 0 {
            value |= product[offset + 1] << (64 - shift);
        }
        value
    }
}

impl<K: Kernel> Arithmetic for Normal<K> {
    fn degree(&self) -> usize {
        self.degree
    }
    fn one(&self) -> Words {
        self.trim(Words([u64::MAX; LIMBS]))
    }
    fn multiply(&self, left: Words, right: Words) -> Words {
        // In the palindromic basis s_i=z^i+z^-i, s_i*s_j=s_(i+j)+s_|i-j|.
        // Two polynomial products replace an m-by-m multiplication matrix.
        let count = self.count();
        let reflected = self.reflect(right);
        let [product, difference] = self.kernel.products(&left, [&right, &reflected], count);
        let mut high = Words::ZERO;
        for (i, word) in high.0[..count].iter_mut().enumerate() {
            *word = Self::shifted(&product, self.degree, i) ^ difference[i];
        }
        let mut result = self.reflect(self.trim(high));
        for (i, word) in result.0[..count].iter_mut().enumerate() {
            *word ^= product[i] ^ Self::shifted(&difference, self.degree + 1, i);
        }
        self.trim(result)
    }
    fn square(&self, value: Words) -> Words {
        let count = self.count();
        let square = words::square(value, count);
        let mut high = Words::ZERO;
        for (i, word) in high.0[..count].iter_mut().enumerate() {
            *word = Self::shifted(&square, self.degree, i);
        }
        let mut result = self.reflect(self.trim(high));
        for (word, low) in result.0[..count].iter_mut().zip(&square) {
            *word ^= low;
        }
        self.trim(result)
    }
    fn trace(&self, value: Words) -> bool {
        value
            .0
            .iter()
            .fold(0, |parity, word| parity ^ word.count_ones())
            % 2
            != 0
    }
    fn import(&self, value: Words) -> Words {
        let mut internal = Words::ZERO;
        let modulus = 2 * self.degree + 1;
        let mut exponent = 1;
        for i in 0..self.degree {
            if value.bit(self.degree - 1 - i) {
                internal.flip(if exponent <= self.degree {
                    exponent
                } else {
                    modulus - exponent
                });
            }
            exponent = (2 * exponent) % modulus;
        }
        internal
    }
    fn export(&self, value: Words) -> Words {
        let mut standard = Words::ZERO;
        let modulus = 2 * self.degree + 1;
        let mut exponent = 1;
        for i in 0..self.degree {
            if value.bit(if exponent <= self.degree {
                exponent
            } else {
                modulus - exponent
            }) {
                standard.flip(self.degree - 1 - i);
            }
            exponent = (2 * exponent) % modulus;
        }
        standard
    }
}
