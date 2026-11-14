use ::hmac::{EagerHash, Hmac, KeyInit, Mac as _};
use sha2::Digest;
use structured_asn1::memory::MemoryError;
use zeroize::Zeroize;

use super::{Algorithm, Cost, Error, Kdf, KdfCost, Octets, Password, add, copy, mul, scan, units};

macro_rules! with_hash {
    ($hash:expr, $digest:ident, $body:expr) => {
        match $hash {
            Algorithm::Sha1 => {
                type $digest = sha1::Sha1;
                $body
            }
            Algorithm::Sha224 => {
                type $digest = sha2::Sha224;
                $body
            }
            Algorithm::Sha256 => {
                type $digest = sha2::Sha256;
                $body
            }
            Algorithm::Sha384 => {
                type $digest = sha2::Sha384;
                $body
            }
            Algorithm::Sha512 => {
                type $digest = sha2::Sha512;
                $body
            }
            #[cfg(feature = "legacy-hmac")]
            Algorithm::Md5 | Algorithm::Ripemd160 => return Err(Error::Unsupported),
        }
    };
}

fn block(hash: Algorithm) -> usize {
    match hash {
        Algorithm::Sha384 | Algorithm::Sha512 => 128,
        _ => 64,
    }
}

fn rounded(length: usize, block: usize) -> Result<usize, Error> {
    Ok(length
        .div_ceil(block)
        .checked_mul(block)
        .ok_or(MemoryError::LimitExceeded)?)
}

fn legacy_blocks(length: usize, iv: usize, hash: Algorithm) -> Result<u64, Error> {
    add(
        units(length.div_ceil(hash.output_len()))?,
        units(iv.div_ceil(hash.output_len()))?,
    )
}

impl Kdf<'_, '_> {
    pub(super) fn policy_cost(&self, length: usize, iv: usize) -> Result<KdfCost, Error> {
        Ok(match *self {
            Self::Pbkdf2 { hash, rounds, .. } => KdfCost::Pbkdf2 {
                iterations: rounds,
                blocks: length.div_ceil(hash.output_len()),
            },
            Self::Legacy { hash, rounds, .. } => KdfCost::Pkcs12 {
                iterations: rounds,
                key_blocks: length.div_ceil(hash.output_len()),
                iv_blocks: iv.div_ceil(hash.output_len()),
            },
            Self::Scrypt(ref params) => return params.policy_cost(),
        })
    }

    pub(super) fn cost(
        &self,
        length: usize,
        iv: usize,
        password_len: usize,
    ) -> Result<Cost, Error> {
        let (work, scratch) = match *self {
            Self::Pbkdf2 { hash, rounds, salt } => {
                let blocks = units(length.div_ceil(hash.output_len()))?;
                if blocks > u64::from(u32::MAX) {
                    return Err(MemoryError::WorkExceeded.into());
                }
                // Each output block runs c PRFs. Its first PRF reads the salt.
                let salt_cost = add(scan(salt)?, units(salt.len())?)?;
                (
                    add(mul(u64::from(rounds), blocks)?, mul(salt_cost, blocks)?)?,
                    joined_len(salt),
                )
            }
            Self::Scrypt(ref params) => params.cost(length)?,
            Self::Legacy { hash, rounds, salt } => {
                let width = block(hash);
                let blocks = legacy_blocks(length, iv, hash)?;
                let scratch = rounded(salt.len(), width)?
                    .checked_add(rounded(password_len, width)?)
                    .ok_or(MemoryError::LimitExceeded)?;
                // Each output digest reads I and, except the last, adds B+1
                // to each block. Include initialization and the eventual wipe.
                let per_block = add(
                    u64::from(rounds),
                    add(mul(4, units(scratch)?)?, scan(salt)?)?,
                )?;
                (mul(blocks, per_block)?, scratch)
            }
        };
        Ok(Cost {
            work,
            scratch,
            output: 0,
        })
    }

    pub(super) fn password_cost(
        &self,
        length: usize,
        iv: usize,
        password: Password<'_>,
    ) -> Result<Cost, Error> {
        match (self, password) {
            (Self::Legacy { .. }, Password::Legacy(bytes)) => {
                if !bytes.len().is_multiple_of(2) {
                    return Err(Error::Malformed);
                }
                let base = self.cost(length, iv, 0)?;
                let full = self.cost(length, iv, bytes.len())?;
                Ok(Cost {
                    work: full.work - base.work,
                    scratch: full.scratch - base.scratch,
                    output: 0,
                })
            }
            (Self::Pbkdf2 { hash, .. }, Password::Octets(bytes)) => Ok(Cost {
                work: units(bytes.len().div_ceil(block(*hash)))?,
                ..Cost::default()
            }),
            (Self::Scrypt(_), Password::Octets(bytes)) => Ok(Cost {
                work: mul(2, units(bytes.len().div_ceil(64))?)?,
                ..Cost::default()
            }),
            _ => Err(Error::Malformed),
        }
    }

    pub(super) fn derive(
        &self,
        password: &[u8],
        output: &mut [u8],
        scratch: &mut [u8],
        purpose: u8,
    ) -> Result<(), Error> {
        match self {
            Self::Pbkdf2 { hash, rounds, salt } => {
                let salt = join(salt, scratch);
                with_hash!(*hash, D, pbkdf2::<D>(password, salt, *rounds, output))?;
            }
            Self::Scrypt(params) => params.derive(password, output, scratch)?,
            Self::Legacy { hash, rounds, salt } => {
                let width = block(*hash);
                let slen = rounded(salt.len(), width)?;
                let plen = rounded(password.len(), width)?;
                let input = &mut scratch[..slen + plen];
                let (salt_block, pass_block) = input.split_at_mut(slen);
                copy(salt, salt_block);
                if !salt_block.is_empty() {
                    repeat_prefix(salt_block, salt.len());
                }
                pass_block[..password.len()].copy_from_slice(password);
                if !pass_block.is_empty() {
                    repeat_prefix(pass_block, password.len());
                }
                with_hash!(
                    *hash,
                    D,
                    legacy::<D>(input, width, purpose, *rounds, output)
                );
            }
        }
        Ok(())
    }
}

// RFC 8018 §5.2. Keep the PRF output in explicit wiping storage between
// rounds. The upstream PBKDF2 entry point does not wipe these intermediate U's.
pub(super) fn pbkdf2<D: EagerHash>(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    output: &mut [u8],
) -> Result<(), Error> {
    use ::hmac::digest::OutputSizeUser;

    let prf = Hmac::<D>::new_from_slice(password).map_err(|_| Error::Malformed)?;
    for (index, block) in output.chunks_mut(Hmac::<D>::output_size()).enumerate() {
        let index = u32::try_from(index + 1).map_err(|_| MemoryError::WorkExceeded)?;
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&index.to_be_bytes());
        let mut digest = mac.finalize().into_bytes();
        block.copy_from_slice(&digest[..block.len()]);
        for _ in 1..rounds {
            let mut mac = prf.clone();
            mac.update(&digest);
            digest.as_mut_slice().zeroize();
            digest = mac.finalize().into_bytes();
            for (target, byte) in block.iter_mut().zip(digest.iter()) {
                *target ^= byte;
            }
        }
        digest.as_mut_slice().zeroize();
    }
    Ok(())
}

pub(super) fn joined_len(salt: &Octets<'_>) -> usize {
    if salt.as_one().is_some() {
        0
    } else {
        salt.len()
    }
}

pub(super) fn join<'b>(salt: &'b Octets<'_>, scratch: &'b mut [u8]) -> &'b [u8] {
    if let Some(salt) = salt.as_one() {
        return salt;
    }
    let joined = &mut scratch[..salt.len()];
    copy(salt, joined);
    joined
}

fn repeat_prefix(output: &mut [u8], len: usize) {
    let mut filled = len;
    while filled < output.len() {
        let next = filled.min(output.len() - filled);
        output.copy_within(..next, filled);
        filled += next;
    }
}

// RFC 7292 Appendix B.2. I is the caller's wiping workspace.
fn legacy<D: Digest>(input: &mut [u8], block: usize, purpose: u8, rounds: u32, output: &mut [u8]) {
    let diversifier = [purpose; 128];
    let mut remaining = output;
    while !remaining.is_empty() {
        let mut hash = D::new();
        hash.update(&diversifier[..block]);
        hash.update(&*input);
        let mut digest = hash.finalize();
        for _ in 1..rounds {
            let next = D::digest(digest.as_slice());
            digest.as_mut_slice().zeroize();
            digest = next;
        }
        let (prefix, rest) = remaining.split_at_mut(remaining.len().min(digest.len()));
        prefix.copy_from_slice(&digest[..prefix.len()]);
        remaining = rest;
        if !remaining.is_empty() {
            for chunk in input.chunks_exact_mut(block) {
                let mut carry = 1_u16;
                for (index, byte) in chunk.iter_mut().enumerate().rev() {
                    carry += u16::from(*byte) + u16::from(digest[index % digest.len()]);
                    let [low, high] = carry.to_le_bytes();
                    *byte = low;
                    carry = u16::from(high);
                }
            }
        }
        digest.as_mut_slice().zeroize();
    }
}
