use structured_asn1::{Integer, Reader, memory::MemoryError};
use structured_pkix::AlgorithmIdentifier;
use zeroize::Zeroizing;

use super::{
    Error, Octets, add,
    derive::{join, joined_len, pbkdf2},
    key_length, mul, protection, scan, units,
};

pub(super) struct Params<'a> {
    salt: Octets<'a>,
    n: usize,
    lane: usize,
    lanes: usize,
}

impl<'a> Params<'a> {
    pub(super) fn read(
        id: AlgorithmIdentifier<'a>,
        query: &Reader<'a>,
        expected: Option<usize>,
    ) -> Result<(Self, usize), Error> {
        query.charge(12).map_err(super::super::encoding)?;
        if id.algorithm().as_bytes() != [43, 6, 1, 4, 1, 218, 71, 4, 11] {
            return Err(Error::Unsupported);
        }
        let mut reader = protection::parameters(id, query)?;
        let seq = crate::signer::required(&mut reader, "personal.scrypt")?;
        let mut inside = super::super::sequence(&reader, &seq)?;
        super::super::end(&reader)?;
        let element = crate::signer::required(&mut inside, "personal.scrypt")?;
        let salt = Octets::read(&inside, &element, "personal.scrypt")?;
        let n = scalar(super::super::number(&mut inside)?)?;
        let r = scalar(super::super::number(&mut inside)?)?;
        let lanes = scalar(super::super::number(&mut inside)?)?;
        let written = if inside.is_empty() {
            None
        } else {
            Some(super::super::number(&mut inside)?)
        };
        super::super::end(&inside)?;
        // RFC 7914 §§2, 6 and 7. B uses at most 2^32-1 PBKDF2 blocks.
        if n < 2
            || !n.is_power_of_two()
            || r == 0
            || lanes == 0
            || u64::from(n.ilog2()) >= mul(16, units(r)?)?
            || mul(units(r)?, units(lanes)?)? >= (1 << 30)
        {
            return Err(Error::Malformed);
        }
        let lane = r.checked_mul(128).ok_or(MemoryError::LimitExceeded)?;
        let params = Self {
            salt,
            n,
            lane,
            lanes,
        };
        let length = key_length(written, expected)?;
        params.cost(length)?;
        Ok((params, length))
    }

    pub(super) fn cost(&self, length: usize) -> Result<(u64, usize), Error> {
        let b = self
            .lane
            .checked_mul(self.lanes)
            .ok_or(MemoryError::LimitExceeded)?;
        let v = self
            .lane
            .checked_mul(self.n)
            .ok_or(MemoryError::LimitExceeded)?;
        let scratch = b
            .checked_add(v)
            .and_then(|size| size.checked_add(self.lane))
            .and_then(|size| size.checked_add(joined_len(&self.salt)))
            .ok_or(MemoryError::LimitExceeded)?;
        let first = units(b / 32)?;
        let last = units(length.div_ceil(32))?;
        if last > u64::from(u32::MAX) {
            return Err(MemoryError::WorkExceeded.into());
        }
        let mixing = mul(8, mul(units(self.n)?, units(b)?)?)?;
        let pbkdf = add(
            mul(first, add(1, scan(&self.salt)?)?)?,
            mul(last, add(1, units(b)?)?)?,
        )?;
        Ok((add(add(mixing, pbkdf)?, units(scratch)?)?, scratch))
    }

    pub(super) fn derive(
        &self,
        password: &[u8],
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        let (blocks, workspace) = scratch.split_at_mut(self.lane * self.lanes);
        let (table, workspace) = workspace.split_at_mut(self.lane * self.n);
        let (temp, joined) = workspace.split_at_mut(self.lane);
        let salt = join(&self.salt, joined);
        pbkdf2::<sha2::Sha256>(password, salt, 1, blocks)?;
        for lane in blocks.chunks_exact_mut(self.lane) {
            romix(lane, table, temp, self.n);
        }
        pbkdf2::<sha2::Sha256>(password, blocks, 1, output)
    }
}

fn scalar(value: Integer<'_>) -> Result<usize, Error> {
    if value.is_negative() {
        return Err(Error::Malformed);
    }
    let value = value.as_u64().ok_or(MemoryError::LimitExceeded)?;
    Ok(usize::try_from(value).map_err(|_| MemoryError::LimitExceeded)?)
}

// RFC 7914 §5. Reuse the same V and T for all lanes.
fn romix(lane: &mut [u8], table: &mut [u8], temp: &mut [u8], n: usize) {
    let width = lane.len();
    for previous in table.chunks_exact_mut(width) {
        previous.copy_from_slice(lane);
        block_mix(previous, lane);
    }
    for _ in 0..n {
        let last = width - 64;
        let mut index = [0; 8];
        index.copy_from_slice(&lane[last..last + 8]);
        let index = u64::from_le_bytes(index) & ((n - 1) as u64);
        // The mask is derived from a usize, so the result always fits it.
        let index = usize::try_from(index).expect("scrypt index is bounded by the table");
        let previous = &table[index * width..(index + 1) * width];
        for ((target, current), previous) in temp.iter_mut().zip(lane.iter()).zip(previous) {
            *target = current ^ previous;
        }
        block_mix(temp, lane);
    }
}

// RFC 7914 §§3–4. RustCrypto supplies Salsa20/8; this only arranges the blocks.
fn block_mix(input: &[u8], output: &mut [u8]) {
    let mut state = Zeroizing::new([0_u32; 16]);
    for (word, bytes) in state
        .iter_mut()
        .zip(input[input.len() - 64..].as_chunks::<4>().0)
    {
        *word = u32::from_le_bytes(*bytes);
    }
    let half = input.len() / 128;
    for (index, input) in input.as_chunks::<64>().0.iter().enumerate() {
        for (word, bytes) in state.iter_mut().zip(input.as_chunks::<4>().0) {
            *word ^= u32::from_le_bytes(*bytes);
        }
        salsa8(&mut state);
        let slot = index / 2 + (index % 2) * half;
        for (word, bytes) in state
            .iter()
            .zip(output[slot * 64..(slot + 1) * 64].as_chunks_mut::<4>().0)
        {
            *bytes = word.to_le_bytes();
        }
    }
}

// RFC 7914 §3 takes an arbitrary 512-bit block. RustCrypto's stream API
// advances a 64-bit counter, which can overflow on such an input.
fn salsa8(state: &mut [u32; 16]) {
    let mut words = Zeroizing::new(*state);
    for _ in 0..4 {
        quarter(&mut words, [0, 4, 8, 12]);
        quarter(&mut words, [5, 9, 13, 1]);
        quarter(&mut words, [10, 14, 2, 6]);
        quarter(&mut words, [15, 3, 7, 11]);
        quarter(&mut words, [0, 1, 2, 3]);
        quarter(&mut words, [5, 6, 7, 4]);
        quarter(&mut words, [10, 11, 8, 9]);
        quarter(&mut words, [15, 12, 13, 14]);
    }
    for (word, mixed) in state.iter_mut().zip(words.iter()) {
        *word = word.wrapping_add(*mixed);
    }
}

#[inline]
fn quarter(words: &mut [u32; 16], [first, second, third, fourth]: [usize; 4]) {
    words[second] ^= words[first].wrapping_add(words[fourth]).rotate_left(7);
    words[third] ^= words[second].wrapping_add(words[first]).rotate_left(9);
    words[fourth] ^= words[third].wrapping_add(words[second]).rotate_left(13);
    words[first] ^= words[fourth].wrapping_add(words[third]).rotate_left(18);
}

#[cfg(test)]
mod tests;
