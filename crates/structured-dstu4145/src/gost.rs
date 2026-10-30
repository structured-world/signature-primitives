//! Runtime-DKE GOST 34.311 with fixed state and borrowed prepared tables.
//!
//! Compression follows RFC5831 sections5-6 and the `RustCrypto` gost94
//! implementation. Ukrainian parameter selection is explicit, not `CryptoPro`.
//! <https://www.rfc-editor.org/rfc/rfc5831.html#section-5>

use crate::Error;

#[cfg(test)]
mod tests;

/// Packed DKE number one from the pinned Ukrainian certificate profile3.12.
pub const DEFAULT_DKE: [u8; 64] = [
    0xa9, 0xd6, 0xeb, 0x45, 0xf1, 0x3c, 0x70, 0x82, 0x80, 0xc4, 0x96, 0x7b, 0x23, 0x1f, 0x5e, 0xad,
    0xf6, 0x58, 0xeb, 0xa4, 0xc0, 0x37, 0x29, 0x1d, 0x38, 0xd9, 0x6b, 0xf0, 0x25, 0xca, 0x4e, 0x17,
    0xf8, 0xe9, 0x72, 0x0d, 0xc6, 0x15, 0xb4, 0x3a, 0x28, 0x97, 0x5f, 0x0b, 0xc1, 0xde, 0xa3, 0x64,
    0x38, 0xb5, 0x64, 0xea, 0x2c, 0x17, 0x9f, 0xd0, 0x12, 0x3e, 0x6d, 0xb8, 0xfa, 0xc5, 0x79, 0x04,
];

/// Immutable substitution identity and four prepared byte-lookup tables.
///
/// Own this once and borrow it from all hash states. Preparation allocates
/// nothing; copies and atomic reference counting are absent from hash updates.
#[derive(Debug)]
pub struct Dke {
    packed: [u8; 64],
    tables: [[u32; 256]; 4],
}

impl Dke {
    /// Checks eight permutations, then prepares the complete round lookup.
    /// The caller funds this fixed preparation before constructing the value.
    pub fn new(packed: &[u8; 64]) -> Result<Self, Error> {
        let mut unpacked = [[0_u8; 16]; 8];
        for (row, values) in unpacked.iter_mut().enumerate() {
            let mut seen = 0_u16;
            for (i, value) in values.iter_mut().enumerate() {
                let byte = packed[row * 8 + i / 2];
                *value = if i % 2 == 0 { byte >> 4 } else { byte & 15 };
                let bit = 1 << *value;
                if seen & bit != 0 {
                    return Err(Error::InvalidDke);
                }
                seen |= bit;
            }
        }
        let mut tables = [[0; 256]; 4];
        for (position, table) in tables.iter_mut().enumerate() {
            for byte in 0..256 {
                let low = u32::from(unpacked[position * 2][byte & 15]);
                let high = u32::from(unpacked[position * 2 + 1][byte >> 4]);
                table[byte] = ((low | high << 4) << (8 * position)).rotate_left(11);
            }
        }
        Ok(Self {
            packed: *packed,
            tables,
        })
    }

    /// Full semantic identity, independent of table addresses.
    #[must_use]
    pub const fn packed(&self) -> &[u8; 64] {
        &self.packed
    }

    fn round(&self, value: u32) -> u32 {
        let bytes = value.to_le_bytes();
        self.tables[0][usize::from(bytes[0])]
            ^ self.tables[1][usize::from(bytes[1])]
            ^ self.tables[2][usize::from(bytes[2])]
            ^ self.tables[3][usize::from(bytes[3])]
    }
}

/// One incremental GOST 34.311 stream with zero initial hash vector.
/// Output is the original digest octet sequence, without signature reversal.
pub struct Gost34311<'a> {
    dke: &'a Dke,
    hash: [u8; 32],
    length: [u64; 4],
    sum: [u64; 4],
    buffer: [u8; 32],
    used: usize,
}

impl<'a> Gost34311<'a> {
    /// Starts an explicitly selected DKE. No implicit default is selected.
    #[must_use]
    pub const fn new(dke: &'a Dke) -> Self {
        Self {
            dke,
            hash: [0; 32],
            length: [0; 4],
            sum: [0; 4],
            buffer: [0; 32],
            used: 0,
        }
    }

    /// Processes a chunk without retaining or copying the complete message.
    /// Length overflow refuses before mutating the state or consuming input.
    pub fn update(&mut self, mut input: &[u8]) -> Result<(), Error> {
        let length_bits = (input.len() as u128 * 8).to_le_bytes();
        let chunks = length_bits.as_chunks::<8>().0;
        let increments = [
            u64::from_le_bytes(chunks[0]),
            u64::from_le_bytes(chunks[1]),
            0,
            0,
        ];
        let mut length = self.length;
        let mut carry = false;
        for (part, increment) in length.iter_mut().zip(increments) {
            let (sum, first) = part.overflowing_add(increment);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            *part = sum;
            carry = first || second;
        }
        if carry {
            return Err(Error::InputTooLong);
        }
        self.length = length;
        if self.used != 0 {
            let take = input.len().min(32 - self.used);
            self.buffer[self.used..self.used + take].copy_from_slice(&input[..take]);
            self.used += take;
            input = &input[take..];
            if self.used != 32 {
                return Ok(());
            }
            let block = self.buffer;
            self.compress(&block);
            self.used = 0;
        }
        let (blocks, tail) = input.as_chunks::<32>();
        for block in blocks {
            self.compress(block);
        }
        self.buffer[..tail.len()].copy_from_slice(tail);
        self.used = tail.len();
        Ok(())
    }

    /// Consumes the state and returns exactly 32 original digest octets.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        if self.used != 0 {
            self.buffer[self.used..].fill(0);
            let block = self.buffer;
            self.compress(&block);
        }
        let length = encode(self.length);
        self.transform(&length);
        let sum = encode(self.sum);
        self.transform(&sum);
        self.hash
    }

    fn compress(&mut self, block: &[u8; 32]) {
        self.transform(block);
        let mut carry = false;
        for (part, bytes) in self.sum.iter_mut().zip(block.as_chunks::<8>().0) {
            let word = u64::from_le_bytes(*bytes);
            let (sum, first) = part.overflowing_add(word);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            *part = sum;
            carry = first || second;
        }
    }

    fn transform(&mut self, block: &[u8; 32]) {
        const CONSTANT: [u8; 32] = [
            0, 255, 0, 255, 0, 255, 0, 255, 255, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 0, 255, 0,
            0, 255, 255, 0, 0, 0, 255, 255, 0, 255,
        ];
        let mut left = self.hash;
        let mut right = *block;
        let mut encrypted = self.hash;
        for quarter in 0..4 {
            let mut key = [0; 32];
            for row in 0..4 {
                for column in 0..8 {
                    key[row + 4 * column] = left[8 * row + column] ^ right[8 * row + column];
                }
            }
            encrypt(&mut encrypted[quarter * 8..quarter * 8 + 8], &key, self.dke);
            if quarter == 3 {
                break;
            }
            left = mix_a(left);
            if quarter == 1 {
                for (value, constant) in left.iter_mut().zip(CONSTANT) {
                    *value ^= constant;
                }
            }
            right = mix_a(mix_a(right));
        }
        psi(&mut encrypted, 12);
        xor(&mut encrypted, block);
        psi(&mut encrypted, 1);
        xor(&mut self.hash, &encrypted);
        psi(&mut self.hash, 61);
    }
}

fn encode(words: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn xor(target: &mut [u8; 32], source: &[u8; 32]) {
    for (left, right) in target.iter_mut().zip(source) {
        *left ^= right;
    }
}

fn mix_a(mut block: [u8; 32]) -> [u8; 32] {
    let tail: [u8; 8] = core::array::from_fn(|i| block[i] ^ block[i + 8]);
    block.copy_within(8.., 0);
    block[24..].copy_from_slice(&tail);
    block
}

fn encrypt(block: &mut [u8], key: &[u8; 32], dke: &Dke) {
    let keys: [u32; 8] = core::array::from_fn(|i| {
        u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().expect("four bytes"))
    });
    let mut left = u32::from_le_bytes(block[..4].try_into().expect("four bytes"));
    let mut right = u32::from_le_bytes(block[4..].try_into().expect("four bytes"));
    for round in 0..32 {
        let index = if round < 24 { round % 8 } else { 31 - round };
        let next = right ^ dke.round(left.wrapping_add(keys[index]));
        right = left;
        left = next;
    }
    block[..4].copy_from_slice(&right.to_le_bytes());
    block[4..].copy_from_slice(&left.to_le_bytes());
}

fn psi(block: &mut [u8; 32], steps: usize) {
    // A circular 16-word recurrence avoids shifting all 32 bytes per step.
    let mut words: [u16; 16] =
        core::array::from_fn(|i| u16::from_le_bytes([block[2 * i], block[2 * i + 1]]));
    let mut head = 0;
    for _ in 0..steps {
        let feedback = words[head]
            ^ words[(head + 1) & 15]
            ^ words[(head + 2) & 15]
            ^ words[(head + 3) & 15]
            ^ words[(head + 12) & 15]
            ^ words[(head + 15) & 15];
        words[head] = feedback;
        head = (head + 1) & 15;
    }
    for (i, chunk) in block.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        chunk.copy_from_slice(&words[(head + i) & 15].to_le_bytes());
    }
}
