//! Explicit streaming hash identities, fixed states and inline outputs.

use crate::Error;

#[cfg(test)]
mod tests;
use crate::gost::{Dke, Gost34311};
use core::cmp::Ordering;
use kupyna::block_api::{KupynaLongVarCore, KupynaShortVarCore};
use kupyna::digest::block_api::{Buffer, UpdateCore, VariableOutputCore};

/// Complete hash identity. GOST includes the actual immutable DKE.
#[derive(Debug, Clone, Copy)]
pub enum Hash<'a> {
    /// GOST34.311 with the supplied DKE and zero initial vector.
    Gost34311(&'a Dke),
    /// Kupyna with an explicitly requested byte-aligned output, 1 through64.
    Kupyna(u8),
}

impl Hash<'_> {
    /// Validated fixed output width; zero is never an implicit default.
    pub fn width(self) -> Result<usize, Error> {
        let width = self.output_width();
        if width == 0 || width > 64 {
            return Err(Error::InvalidOutputSize);
        }
        Ok(width)
    }

    pub(crate) fn output_width(self) -> usize {
        match self {
            Self::Gost34311(_) => 32,
            Self::Kupyna(bytes) => usize::from(bytes),
        }
    }

    /// Complete semantic order, independent of storage addresses.
    /// This raw comparison is funded by the calling adapter.
    #[must_use]
    pub fn compare(self, other: Self) -> Ordering {
        match (self, other) {
            (Self::Gost34311(left), Self::Gost34311(right)) => {
                if core::ptr::eq(left, right) {
                    Ordering::Equal
                } else {
                    left.packed().cmp(right.packed())
                }
            }
            (Self::Gost34311(_), Self::Kupyna(_)) => Ordering::Less,
            (Self::Kupyna(_), Self::Gost34311(_)) => Ordering::Greater,
            (Self::Kupyna(left), Self::Kupyna(right)) => left.cmp(&right),
        }
    }
}

/// Finished digest in its original byte order. No heap buffer escapes.
#[derive(Debug)]
pub struct Output {
    bytes: [u8; 64],
    len: usize,
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Incremental execution of the selected complete hash identity.
pub struct State<'a> {
    inner: Inner<'a>,
    bytes: u64,
    width: usize,
}

enum Inner<'a> {
    Gost(Gost34311<'a>),
    Short {
        core: KupynaShortVarCore,
        buffer: Buffer<KupynaShortVarCore>,
    },
    Long {
        core: KupynaLongVarCore,
        buffer: Buffer<KupynaLongVarCore>,
    },
}

impl<'a> State<'a> {
    /// Starts one exact identity without allocating or retaining its wrapper.
    pub fn new(identity: Hash<'a>) -> Result<Self, Error> {
        let width = identity.width()?;
        let inner = match identity {
            Hash::Gost34311(dke) => Inner::Gost(Gost34311::new(dke)),
            Hash::Kupyna(_) if width <= 32 => Inner::Short {
                core: KupynaShortVarCore::new(width).map_err(|_| Error::InvalidOutputSize)?,
                buffer: Buffer::<KupynaShortVarCore>::default(),
            },
            Hash::Kupyna(_) => Inner::Long {
                core: KupynaLongVarCore::new(width).map_err(|_| Error::InvalidOutputSize)?,
                buffer: Buffer::<KupynaLongVarCore>::default(),
            },
        };
        Ok(Self {
            inner,
            bytes: 0,
            width,
        })
    }

    /// Upper work bound for the next update, including actual complete blocks
    /// and input/buffer copies. The unit counts elementary round/word work,
    /// not elapsed cycles. No future partial block is charged as compression.
    pub fn update_work(&self, length: usize) -> Result<u64, Error> {
        let added = u64::try_from(length).map_err(|_| Error::InputTooLong)?;
        self.bytes.checked_add(added).ok_or(Error::InputTooLong)?;
        let (block, cost) = self.block_cost();
        let complete = added / block + (self.bytes % block + added % block) / block;
        complete
            .checked_mul(cost)
            .and_then(|value| {
                added
                    .checked_mul(2)
                    .and_then(|copy| value.checked_add(copy))
            })
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::InputTooLong)
    }

    /// Bounds padding, length/checksum and output transformations before finish.
    #[must_use]
    pub fn finalize_work(&self) -> u64 {
        let (_, cost) = self.block_cost();
        3 * cost + 128
    }

    fn block_cost(&self) -> (u64, u64) {
        // GOST:4 cipher calls and74 word recurrences. Kupyna:two permutations
        // of10x8 or14x16 words plus feed-forward. Bounds include table work.
        match self.inner {
            Inner::Gost(_) => (32, 8_192),
            Inner::Short { .. } => (64, 8_192),
            Inner::Long { .. } => (128, 16_384),
        }
    }

    /// Processes one borrowed chunk. No whole-message buffering or prehashing.
    /// The supported interface bounds cumulative input to `u64::MAX` bytes.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let added = u64::try_from(bytes.len()).map_err(|_| Error::InputTooLong)?;
        let total = self.bytes.checked_add(added).ok_or(Error::InputTooLong)?;
        match &mut self.inner {
            Inner::Gost(state) => state.update(bytes)?,
            Inner::Short { core, buffer } => {
                buffer.digest_blocks(bytes, |blocks| core.update_blocks(blocks));
            }
            Inner::Long { core, buffer } => {
                buffer.digest_blocks(bytes, |blocks| core.update_blocks(blocks));
            }
        }
        self.bytes = total;
        Ok(())
    }

    /// Finalizes once to the declared output width. Variable Kupyna uses its
    /// specified right truncation and short/long core, never a caller guess.
    #[must_use]
    pub fn finalize(self) -> Output {
        let mut result = Output {
            bytes: [0; 64],
            len: self.width,
        };
        self.finish(&mut result.bytes[..result.len]);
        result
    }

    /// Finalizes directly into an exact-width caller-owned output buffer.
    /// A length error refuses before performing final hash transformations.
    pub fn finalize_into(self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() != self.width {
            return Err(Error::InvalidOutputSize);
        }
        self.finish(output);
        Ok(())
    }

    fn finish(self, result: &mut [u8]) {
        match self.inner {
            Inner::Gost(state) => result.copy_from_slice(&state.finalize()),
            Inner::Short {
                mut core,
                mut buffer,
            } => {
                let mut output = kupyna::digest::Output::<KupynaShortVarCore>::default();
                core.finalize_variable_core(&mut buffer, &mut output);
                result.copy_from_slice(&output[32 - self.width..]);
            }
            Inner::Long {
                mut core,
                mut buffer,
            } => {
                let mut output = kupyna::digest::Output::<KupynaLongVarCore>::default();
                core.finalize_variable_core(&mut buffer, &mut output);
                result.copy_from_slice(&output[64 - self.width..]);
            }
        }
    }
}
