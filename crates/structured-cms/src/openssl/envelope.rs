use crate::cbc::Cipher;
use md5::{Digest, Md5};
use structured_asn1::memory::Work;
use zeroize::{Zeroize, Zeroizing};

use super::{Error, charge};

const MD5_OUTPUT_LEN: usize = 16;

/// Structural `EVP_BytesToKey` cost for application policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct KdfCost {
    /// MD5 rounds per derived key block.
    pub rounds: u32,
    /// MD5 output blocks needed to fill the cipher key.
    pub blocks: usize,
}

/// A validated traditional PEM password envelope.
#[derive(Clone, Copy)]
pub struct Envelope {
    cipher: Cipher,
    iv: [u8; 16],
}

impl Envelope {
    /// Read the borrowed PEM headers, excluding the BEGIN line and base64 body.
    ///
    /// An empty header section returns `Ok(None)`. Once either encryption header
    /// appears, missing, repeated, malformed or unknown headers return a protected
    /// error. The header values and IV are public.
    pub fn read(headers: &str, work: &impl Work) -> Result<Option<Self>, Error> {
        charge(work, headers.len())?;
        let mut proc_type = None;
        let mut dek_info = None;
        let mut invalid = false;
        for line in headers
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let (name, value) = line.split_once(':').unwrap_or((line, ""));
            match name.trim() {
                "Proc-Type" if proc_type.is_none() => proc_type = Some(value.trim()),
                "DEK-Info" if dek_info.is_none() => dek_info = Some(value.trim()),
                _ => invalid = true,
            }
        }
        if proc_type.is_none() && dek_info.is_none() {
            return if invalid {
                Err(Error::NotTraditional)
            } else {
                Ok(None)
            };
        }
        // RFC 1421 §4.6.1.1 and §4.6.1.3. OpenSSL supplies the cipher and IV.
        if invalid || proc_type != Some("4,ENCRYPTED") {
            return Err(Error::Protected);
        }
        let (name, hex) = dek_info
            .and_then(|value| value.split_once(','))
            .ok_or(Error::Protected)?;
        let cipher = Cipher::named(name).ok_or(Error::Protected)?;
        if hex.len() != 2 * cipher.block_len() {
            return Err(Error::Protected);
        }
        let mut iv = [0; 16];
        for (octet, &[hi, lo]) in iv.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
            *octet = (nibble(hi)? << 4) | nibble(lo)?;
        }
        Ok(Some(Self { cipher, iv }))
    }

    /// Report KDF rounds and blocks before acquiring a password.
    ///
    /// Traditional PEM derives only the key. The IV comes from the header.
    /// Decryption separately charges work for processing the password and body.
    #[must_use]
    pub fn kdf_cost(&self) -> KdfCost {
        KdfCost {
            rounds: 1,
            blocks: self.cipher.key_len().div_ceil(MD5_OUTPUT_LEN),
        }
    }

    /// Replace decoded ciphertext with plaintext and return its unpadded length.
    ///
    /// Use wiping storage for `buffer` and for the caller-owned password. On
    /// success the suffix is zeroed. On a padding failure the whole buffer is
    /// zeroed. Missing passwords, malformed lengths and resource refusals leave
    /// ciphertext intact. CBC padding is not authentication.
    pub fn decrypt_in_place(
        &self,
        buffer: &mut [u8],
        password: Option<&[u8]>,
        work: &impl Work,
    ) -> Result<usize, Error> {
        let password = password.ok_or(Error::Protected)?;
        let width = self.cipher.block_len();
        if buffer.is_empty() || !buffer.len().is_multiple_of(width) {
            return Err(Error::Protected);
        }
        let key_len = self.cipher.key_len();
        let hash_work = password
            .len()
            .checked_add(24)
            .and_then(|length| length.checked_mul(self.kdf_cost().blocks))
            .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)?;
        charge(work, hash_work)?;
        charge(work, buffer.len())?;
        let key = envelope_key(password, &self.iv[..8], key_len);
        let iv = &self.iv[..width];
        self.cipher
            .decrypt(&key[..key_len], iv, buffer)
            .ok_or(Error::Protected)
    }
}

fn nibble(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Protected),
    }
}

impl Cipher {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "AES-128-CBC" => Self::Aes128,
            "AES-192-CBC" => Self::Aes192,
            "AES-256-CBC" => Self::Aes256,
            "DES-CBC" => Self::Des,
            "DES-EDE-CBC" => Self::DesEde,
            "DES-EDE3-CBC" => Self::DesEde3,
            _ => return None,
        })
    }
}

// OpenSSL EVP_BytesToKey: MD5, one iteration, and the first eight IV octets.
fn envelope_key(password: &[u8], salt: &[u8], key_len: usize) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    let mut digest = Md5::new();
    digest.update(password);
    digest.update(salt);
    let mut block = digest.finalize();
    key[..16].copy_from_slice(&block);
    if key_len > 16 {
        let mut digest = Md5::new();
        digest.update(block.as_slice());
        block.zeroize();
        digest.update(password);
        digest.update(salt);
        block = digest.finalize();
        key[16..].copy_from_slice(&block);
    }
    block.zeroize();
    key
}
