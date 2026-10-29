//! Fixed storage for public field elements and their unreduced products.

use crate::{ByteOrder, Error};

pub(crate) const LIMBS: usize = 8;
pub(crate) type Product = [u64; 2 * LIMBS];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Words(pub(crate) [u64; LIMBS]);

impl Words {
    pub(crate) const ZERO: Self = Self([0; LIMBS]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);

    pub(crate) const fn hex(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut value = Self::ZERO;
        let mut at = 0;
        while at < bytes.len() {
            let digit = match bytes[at] {
                b'0'..=b'9' => bytes[at] - b'0',
                b'A'..=b'F' => bytes[at] - b'A' + 10,
                b'a'..=b'f' => bytes[at] - b'a' + 10,
                _ => panic!("invalid constant hex digit"),
            };
            let mut carry = u64::from_le_bytes([digit, 0, 0, 0, 0, 0, 0, 0]);
            let mut i = 0;
            while i < LIMBS {
                let next = value.0[i] >> 60;
                value.0[i] = (value.0[i] << 4) | carry;
                carry = next;
                i += 1;
            }
            assert!(carry == 0, "constant exceeds fixed width");
            at += 1;
        }
        value
    }

    pub(crate) fn read(bytes: &[u8], order: ByteOrder) -> Result<Self, Error> {
        if bytes.len() > LIMBS * 8 {
            return Err(Error::InvalidEncoding);
        }
        let mut value = Self::ZERO;
        for (i, &byte) in bytes.iter().enumerate() {
            let at = match order {
                ByteOrder::LittleEndian => i,
                ByteOrder::BigEndian => bytes.len() - 1 - i,
            };
            value.0[at / 8] |= u64::from(byte) << (8 * (at % 8));
        }
        Ok(value)
    }

    pub(crate) fn bit(self, bit: usize) -> bool {
        debug_assert!(bit < LIMBS * 64);
        self.0[bit / 64] & (1 << (bit % 64)) != 0
    }

    pub(crate) fn flip(&mut self, bit: usize) {
        debug_assert!(bit < LIMBS * 64);
        self.0[bit / 64] ^= 1 << (bit % 64);
    }

    pub(crate) fn bits(self) -> usize {
        for i in (0..LIMBS).rev() {
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    pub(crate) fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    pub(crate) fn add(self, other: Self) -> Self {
        Self(core::array::from_fn(|i| self.0[i] ^ other.0[i]))
    }

    pub(crate) fn clear_above(&mut self, bits: usize) {
        debug_assert!(bits <= LIMBS * 64);
        let whole = bits / 64;
        let rest = bits % 64;
        if whole == LIMBS {
            return;
        }
        if rest == 0 {
            self.0[whole..].fill(0);
        } else {
            self.0[whole] &= (1 << rest) - 1;
            self.0[whole + 1..].fill(0);
        }
    }

    pub(crate) fn cmp(self, other: Self) -> core::cmp::Ordering {
        for i in (0..LIMBS).rev() {
            let order = self.0[i].cmp(&other.0[i]);
            if !order.is_eq() {
                return order;
            }
        }
        core::cmp::Ordering::Equal
    }
}

pub(crate) fn xor_shift(out: &mut Product, word: u64, shift: usize) {
    let index = shift / 64;
    let bits = shift % 64;
    out[index] ^= word << bits;
    if bits != 0 {
        out[index + 1] ^= word >> (64 - bits);
    }
}

pub(crate) fn shr(input: &[u64], bits: usize) -> Words {
    let offset = bits / 64;
    let shift = bits % 64;
    Words(core::array::from_fn(|i| {
        let at = offset + i;
        if at >= input.len() {
            return 0;
        }
        let mut word = input[at] >> shift;
        if shift != 0 && at + 1 < input.len() {
            word |= input[at + 1] << (64 - shift);
        }
        word
    }))
}

pub(crate) fn product(left: Words, right: Words, count: usize) -> Product {
    let mut result = [0; 2 * LIMBS];
    // Public operands permit indexed windows. Build once per right limb,
    // not for each pair; the full u128 entries retain carry-less high bits.
    for j in 0..count {
        let mut table = [0_u128; 16];
        table[1] = u128::from(right.0[j]);
        for k in 2..16 {
            table[k] = (table[k >> 1] << 1) ^ table[k & 1];
        }
        for i in 0..count {
            let mut value = 0_u128;
            let mut word = left.0[i];
            for shift in (0..64).step_by(4) {
                value ^= table[(word & 15) as usize] << shift;
                word >>= 4;
            }
            let halves = value.to_le_bytes();
            result[i + j] ^= u64::from_le_bytes(halves[..8].try_into().expect("eight bytes"));
            result[i + j + 1] ^= u64::from_le_bytes(halves[8..].try_into().expect("eight bytes"));
        }
    }
    result
}

pub(crate) fn square(value: Words, count: usize) -> Product {
    fn spread(mut word: u64) -> u64 {
        word = (word | word << 16) & 0x0000_ffff_0000_ffff;
        word = (word | word << 8) & 0x00ff_00ff_00ff_00ff;
        word = (word | word << 4) & 0x0f0f_0f0f_0f0f_0f0f;
        word = (word | word << 2) & 0x3333_3333_3333_3333;
        (word | word << 1) & 0x5555_5555_5555_5555
    }
    let mut result = [0; 2 * LIMBS];
    for i in 0..count {
        result[2 * i] = spread(value.0[i] & 0xffff_ffff);
        result[2 * i + 1] = spread(value.0[i] >> 32);
    }
    result
}
