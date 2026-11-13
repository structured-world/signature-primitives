//! Opt-in password protection for PKCS#12 and encrypted PKCS#8.
//!
//! Prepare a plan and inspect its cost before acquiring a password. Supply
//! caller-owned wiping output and scratch storage. The engine charges both the
//! producing session and current operation before touching the buffers.

mod derive;
mod scrypt;

use super::{EncryptedData, Integrity, ShroudedKey, protection};
use crate::{
    Octets,
    cbc::Cipher,
    hmac::{Algorithm, Mac},
};
use structured_asn1::{
    Integer, Reader,
    memory::{MemoryError, Work},
};
use structured_pkix::AlgorithmIdentifier;
use zeroize::{Zeroize, Zeroizing};

/// A password operation refusal.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Located structural error, including resource refusal while reading.
    #[error(transparent)]
    Encoding(#[from] crate::Error),
    /// A producing or current work ceiling refused the operation.
    #[error(transparent)]
    Resource(#[from] MemoryError),
    /// A protection algorithm or KDF is unavailable.
    #[error("unsupported password protection")]
    Unsupported,
    /// Parameters or ciphertext do not match the selected protection scheme.
    #[error("invalid password protection parameters")]
    Malformed,
    /// The supplied scratch or output slice has insufficient capacity.
    #[error("password operation buffer is too short")]
    Buffer,
    /// Padding or the authentication tag was invalid.
    #[error("password protection check failed")]
    Rejected,
}

impl Error {
    /// Whether admission refused processing rather than the protection check.
    #[must_use]
    pub fn is_resource(&self) -> bool {
        match self {
            Self::Encoding(error) => error.is_resource(),
            Self::Resource(_) | Self::Buffer => true,
            _ => false,
        }
    }
}

/// Password-independent or password-dependent additions to the admission cost.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Cost {
    /// Work units charged to the operation.
    pub work: u64,
    /// Bytes of caller-provided scratch. Add the two costs for total scratch.
    pub scratch: usize,
    /// Bytes of caller-provided output.
    pub output: usize,
}

/// Password input in the encoding selected by the plan.
#[derive(Clone, Copy)]
pub enum Password<'a> {
    /// PBES2 or PBMAC1 password octets. PKCS#12 PBMAC1 uses UTF-8.
    Octets(&'a [u8]),
    /// RFC 7292 Appendix B.1 input, as produced by [`super::legacy_password`].
    /// Supply the exact encoded bytes, including the terminator where present.
    Legacy(&'a [u8]),
}

impl Password<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Octets(bytes) | Self::Legacy(bytes) => bytes,
        }
    }
}

enum Kdf<'s, 'a> {
    Pbkdf2 {
        hash: Algorithm,
        rounds: u32,
        salt: &'s Octets<'a>,
    },
    Scrypt(scrypt::Params<'a>),
    Legacy {
        hash: Algorithm,
        rounds: u32,
        salt: &'s Octets<'a>,
    },
}

/// Borrowed password-decryption plan for a protected safe or private key.
pub struct Decryption<'s, 'a> {
    kdf: Kdf<'s, 'a>,
    cipher: Cipher,
    iv: [u8; 16],
    ciphertext: &'s Octets<'a>,
}

impl<'s, 'a> Decryption<'s, 'a> {
    /// Whether the plan requires RFC 7292 Appendix B.1 password bytes.
    #[must_use]
    pub fn uses_legacy_password(&self) -> bool {
        matches!(self.kdf, Kdf::Legacy { .. })
    }

    /// Prepare an encrypted PKCS#8 key or a PKCS#12 shrouded key.
    pub fn key(key: &'s ShroudedKey<'a>, query: &Reader<'a>) -> Result<Self, Error> {
        Self::prepare(key.algorithm, &key.protection, &key.encrypted, query)
    }

    /// Prepare an attached PKCS#12 encrypted safe.
    pub fn safe(safe: &'s EncryptedData<'a>, query: &Reader<'a>) -> Result<Self, Error> {
        let ciphertext = safe.content.ciphertext.as_ref().ok_or(Error::Malformed)?;
        Self::prepare(safe.content.algorithm, &safe.protection, ciphertext, query)
    }

    fn prepare(
        identifier: AlgorithmIdentifier<'a>,
        protection: &'s protection::Protection<'a>,
        ciphertext: &'s Octets<'a>,
        query: &Reader<'a>,
    ) -> Result<Self, Error> {
        check_source(ciphertext, query)?;
        protection::session(identifier, query)?;
        let mut iv = [0; 16];
        let (cipher, kdf) = match protection {
            protection::Protection::Pbes2(pair) => {
                protection::session(pair.scheme, query)?;
                query.charge(12).map_err(super::encoding)?;
                let cipher = match pair.scheme.algorithm().as_bytes() {
                    [96, 134, 72, 1, 101, 3, 4, 1, 2] => Cipher::Aes128,
                    [96, 134, 72, 1, 101, 3, 4, 1, 22] => Cipher::Aes192,
                    [96, 134, 72, 1, 101, 3, 4, 1, 42] => Cipher::Aes256,
                    [42, 134, 72, 134, 247, 13, 3, 7] => Cipher::DesEde3,
                    _ => return Err(Error::Unsupported),
                };
                let mut reader = protection::parameters(pair.scheme, query)?;
                let element = crate::signer::required(&mut reader, "personal.password")?;
                let source = Octets::read(&reader, &element, "personal.password")?;
                super::end(&reader)?;
                if source.len() != cipher.block_len() {
                    return Err(Error::Malformed);
                }
                reader.charge(scan(&source)?).map_err(super::encoding)?;
                copy(&source, &mut iv[..cipher.block_len()]);
                (cipher, pair_kdf(pair, Some(cipher.key_len()), query)?.0)
            }
            protection::Protection::Pkcs12(legacy) => {
                query.charge(12).map_err(super::encoding)?;
                let cipher = match identifier.algorithm().as_bytes() {
                    [42, 134, 72, 134, 247, 13, 1, 12, 1, 3] => Cipher::DesEde3,
                    [42, 134, 72, 134, 247, 13, 1, 12, 1, 4] => Cipher::DesEde,
                    _ => return Err(Error::Unsupported),
                };
                check_source(&legacy.salt, query)?;
                (
                    cipher,
                    Kdf::Legacy {
                        hash: Algorithm::Sha1,
                        rounds: rounds(legacy.iterations)?,
                        salt: &legacy.salt,
                    },
                )
            }
            _ => return Err(Error::Unsupported),
        };
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(cipher.block_len()) {
            return Err(Error::Malformed);
        }
        Ok(Self {
            kdf,
            cipher,
            iv,
            ciphertext,
        })
    }

    /// Cost before acquiring a password, including the ciphertext-sized output.
    pub fn cost(&self) -> Result<Cost, Error> {
        let mut cost = self.kdf.cost(self.cipher.key_len(), self.legacy_iv(), 0)?;
        cost.work = add(
            cost.work,
            add(
                scan(self.ciphertext)?,
                mul(2, units(self.ciphertext.len())?)?,
            )?,
        )?;
        cost.output = self.ciphertext.len();
        Ok(cost)
    }

    /// Additional cost for the actual password representation.
    pub fn password_cost(&self, password: Password<'_>) -> Result<Cost, Error> {
        self.kdf
            .password_cost(self.cipher.key_len(), self.legacy_iv(), password)
    }

    fn legacy_iv(&self) -> usize {
        if self.uses_legacy_password() {
            self.cipher.block_len()
        } else {
            0
        }
    }

    /// Copy the original logical ciphertext once, then decrypt in place.
    /// Returns the unpadded output length. CBC provides no authentication.
    /// On padding failure the entire used output is wiped. Used scratch is
    /// wiped before return. Bytes beyond the admitted prefixes are untouched.
    pub fn decrypt(
        &self,
        password: Password<'_>,
        output: &mut [u8],
        scratch: &mut [u8],
        query: &Reader<'_>,
    ) -> Result<usize, Error> {
        check_source(self.ciphertext, query)?;
        let base = self.cost()?;
        let extra = self.password_cost(password)?;
        let output = output.get_mut(..base.output).ok_or(Error::Buffer)?;
        let scratch = scratch_for(scratch, base, extra, query)?;
        copy(self.ciphertext, output);
        self.open(password, output, scratch.0)
    }

    /// Produce the wiping, accounted owner required by [`super::Backend`].
    /// The ciphertext is copied once into the final plaintext allocation.
    pub fn decrypt_owned(
        &self,
        password: Password<'_>,
        scratch: &mut [u8],
        query: &Reader<'_>,
    ) -> Result<super::Plaintext, Error> {
        check_source(self.ciphertext, query)?;
        let mut cost = self.kdf.cost(self.cipher.key_len(), self.legacy_iv(), 0)?;
        // Plaintext::copy_octets charges the copy, traversal and lifetime wipe.
        cost.work = add(cost.work, mul(2, units(self.ciphertext.len())?)?)?;
        let scratch = scratch_for(scratch, cost, self.password_cost(password)?, query)?;
        let mut output = super::Plaintext::copy_octets(self.ciphertext, query)?;
        let length = self.open(password, output.as_mut_bytes(), scratch.0)?;
        output.truncate(length);
        Ok(output)
    }

    fn open(
        &self,
        password: Password<'_>,
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<usize, Error> {
        let mut key = Zeroizing::new([0; 32]);
        let key = &mut key[..self.cipher.key_len()];
        let mut iv = Zeroizing::new(self.iv);
        let mut output = Wiping(output);
        self.kdf.derive(password.bytes(), key, scratch, 1)?;
        let width = self.cipher.block_len();
        if self.legacy_iv() != 0 {
            self.kdf
                .derive(password.bytes(), &mut iv[..width], scratch, 2)?;
        }
        self.cipher
            .decrypt(key, &iv[..width], core::mem::take(&mut output.0))
            .ok_or(Error::Rejected)
    }
}

/// Borrowed integrity plan over the original `AuthenticatedSafe` octets.
pub struct Authentication<'s, 'a> {
    kdf: Kdf<'s, 'a>,
    hash: Algorithm,
    key_len: usize,
    safe: &'s Octets<'a>,
    expected: &'s Octets<'a>,
}

impl<'s, 'a> Authentication<'s, 'a> {
    /// Whether the plan requires RFC 7292 Appendix B.1 password bytes.
    #[must_use]
    pub fn uses_legacy_password(&self) -> bool {
        matches!(self.kdf, Kdf::Legacy { .. })
    }

    /// Prepare the written password MAC. Absent MAC returns `None`.
    pub fn prepare(
        integrity: &'s Integrity<'a>,
        query: &Reader<'a>,
    ) -> Result<Option<Self>, Error> {
        let Integrity::Password { safe, mac } = integrity else {
            return Err(Error::Unsupported);
        };
        let Some(mac) = mac else { return Ok(None) };
        check_source(safe, query)?;
        check_source(&mac.digest, query)?;
        protection::session(mac.algorithm, query)?;
        let (hash, kdf, key_len) = if let Some(pair) = &mac.pbmac1 {
            let hash = hmac(pair.scheme, query)?;
            let (kdf, key_len) = pair_kdf(pair, None, query)?;
            (hash, kdf, key_len)
        } else {
            check_source(&mac.salt, query)?;
            query.charge(12).map_err(super::encoding)?;
            let hash = match mac.algorithm.algorithm().as_bytes() {
                [43, 14, 3, 2, 26] => Algorithm::Sha1,
                [96, 134, 72, 1, 101, 3, 4, 2, 4] => Algorithm::Sha224,
                [96, 134, 72, 1, 101, 3, 4, 2, 1] => Algorithm::Sha256,
                [96, 134, 72, 1, 101, 3, 4, 2, 2] => Algorithm::Sha384,
                [96, 134, 72, 1, 101, 3, 4, 2, 3] => Algorithm::Sha512,
                _ => return Err(Error::Unsupported),
            };
            let rounds = mac.iterations.map(rounds).transpose()?.unwrap_or(1);
            (
                hash,
                Kdf::Legacy {
                    hash,
                    rounds,
                    salt: &mac.salt,
                },
                hash.output_len(),
            )
        };
        if mac.digest.len() != hash.output_len() {
            return Err(Error::Malformed);
        }
        Ok(Some(Self {
            kdf,
            hash,
            key_len,
            safe,
            expected: &mac.digest,
        }))
    }

    /// Cost before acquiring a password. The derived MAC key lives in scratch.
    pub fn cost(&self) -> Result<Cost, Error> {
        let mut cost = self.kdf.cost(self.key_len, 0, 0)?;
        cost.scratch = cost
            .scratch
            .checked_add(self.key_len)
            .ok_or(MemoryError::LimitExceeded)?;
        cost.work = add(
            cost.work,
            add(
                scan(self.safe)?,
                add(scan(self.expected)?, units(self.key_len)?)?,
            )?,
        )?;
        Ok(cost)
    }

    /// Additional cost for the actual password representation.
    pub fn password_cost(&self, password: Password<'_>) -> Result<Cost, Error> {
        self.kdf.password_cost(self.key_len, 0, password)
    }

    /// Authenticate the original logical bytes, streaming each BER fragment.
    pub fn verify(
        &self,
        password: Password<'_>,
        scratch: &mut [u8],
        query: &Reader<'_>,
    ) -> Result<(), Error> {
        check_source(self.safe, query)?;
        let scratch = scratch_for(scratch, self.cost()?, self.password_cost(password)?, query)?;
        let (key, workspace) = scratch.0.split_at_mut(self.key_len);
        self.kdf.derive(password.bytes(), key, workspace, 3)?;
        let mut mac = Mac::begin(self.hash, key).map_err(|_| Error::Malformed)?;
        for piece in self.safe.pieces() {
            mac.update(piece.as_bytes());
        }
        let mut expected = [0; 64];
        let expected = &mut expected[..self.hash.output_len()];
        copy(self.expected, expected);
        mac.verify_truncated(expected, expected.len() * 8)
            .map_err(|_| Error::Rejected)
    }
}

fn scratch_for<'s>(
    scratch: &'s mut [u8],
    base: Cost,
    extra: Cost,
    query: &Reader<'_>,
) -> Result<Wiping<'s>, Error> {
    let size = base
        .scratch
        .checked_add(extra.scratch)
        .ok_or(MemoryError::LimitExceeded)?;
    let scratch = scratch.get_mut(..size).ok_or(Error::Buffer)?;
    query.execution().charge_work(add(base.work, extra.work)?)?;
    Ok(Wiping(scratch))
}

struct Wiping<'a>(&'a mut [u8]);

impl Drop for Wiping<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn check_source(octets: &Octets<'_>, query: &Reader<'_>) -> Result<(), Error> {
    if core::ptr::eq(octets.parser(), query.parser()) {
        Ok(())
    } else {
        Err(crate::Error::pkix(structured_pkix::Error::new(
            structured_pkix::ErrorCode::ForeignReader,
            "personal.password",
            octets.span().start,
        ))
        .into())
    }
}

fn hmac(identifier: AlgorithmIdentifier<'_>, query: &Reader<'_>) -> Result<Algorithm, Error> {
    protection::hmac_width(identifier, query)?;
    match identifier.algorithm().as_bytes() {
        [42, 134, 72, 134, 247, 13, 2, 7] => Ok(Algorithm::Sha1),
        [42, 134, 72, 134, 247, 13, 2, 8] => Ok(Algorithm::Sha224),
        [42, 134, 72, 134, 247, 13, 2, 9] => Ok(Algorithm::Sha256),
        [42, 134, 72, 134, 247, 13, 2, 10] => Ok(Algorithm::Sha384),
        [42, 134, 72, 134, 247, 13, 2, 11] => Ok(Algorithm::Sha512),
        _ => Err(Error::Unsupported),
    }
}

fn pair_kdf<'s, 'a>(
    pair: &'s protection::Pair<'a>,
    expected: Option<usize>,
    query: &Reader<'a>,
) -> Result<(Kdf<'s, 'a>, usize), Error> {
    protection::session(pair.derivation, query)?;
    if let Some(kdf) = &pair.pbkdf2 {
        let protection::Salt::Specified(salt) = &kdf.salt else {
            return Err(Error::Unsupported);
        };
        check_source(salt, query)?;
        let hash = match kdf.prf {
            protection::Prf::DefaultSha1 => Algorithm::Sha1,
            protection::Prf::Written(id) => hmac(id, query)?,
        };
        let length = key_length(kdf.key_length, expected)?;
        Ok((
            Kdf::Pbkdf2 {
                hash,
                rounds: rounds(kdf.iterations)?,
                salt,
            },
            length,
        ))
    } else {
        let (params, length) = scrypt::Params::read(pair.derivation, query, expected)?;
        Ok((Kdf::Scrypt(params), length))
    }
}

fn key_length(value: Option<Integer<'_>>, expected: Option<usize>) -> Result<usize, Error> {
    let written = value
        .map(|value| {
            let length = value.as_u64().ok_or(MemoryError::LimitExceeded)?;
            usize::try_from(length).map_err(|_| MemoryError::LimitExceeded)
        })
        .transpose()?;
    match (written, expected) {
        (Some(actual), Some(expected)) if actual != expected => Err(Error::Malformed),
        (Some(0), _) | (None, None) => Err(Error::Malformed),
        (Some(length), _) | (None, Some(length)) => Ok(length),
    }
}

fn rounds(value: Integer<'_>) -> Result<u32, Error> {
    let value = value.as_u64().ok_or(MemoryError::WorkExceeded)?;
    let value = u32::try_from(value).map_err(|_| MemoryError::WorkExceeded)?;
    if value == 0 {
        return Err(Error::Malformed);
    }
    Ok(value)
}

fn scan(octets: &Octets<'_>) -> Result<u64, Error> {
    add(units(octets.len())?, units(octets.pieces().len())?)
}

fn units(value: usize) -> Result<u64, Error> {
    Ok(u64::try_from(value).map_err(|_| MemoryError::WorkExceeded)?)
}

fn add(left: u64, right: u64) -> Result<u64, Error> {
    Ok(left.checked_add(right).ok_or(MemoryError::WorkExceeded)?)
}

fn mul(left: u64, right: u64) -> Result<u64, Error> {
    Ok(left.checked_mul(right).ok_or(MemoryError::WorkExceeded)?)
}

fn copy(octets: &Octets<'_>, mut output: &mut [u8]) {
    for piece in octets.pieces() {
        let bytes = piece.as_bytes();
        let (target, rest) = output.split_at_mut(bytes.len());
        target.copy_from_slice(bytes);
        output = rest;
    }
}
