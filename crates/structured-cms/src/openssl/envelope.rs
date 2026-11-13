use cbc::cipher::{BlockModeDecrypt, KeyIvInit, inout::InOutBuf};
use md5::{Digest, Md5};
use structured_asn1::memory::Work;
use zeroize::{Zeroize, Zeroizing};

use super::{Error, charge};

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
            .and_then(|length| length.checked_mul(key_len.div_ceil(16)))
            .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)?;
        charge(work, hash_work)?;
        charge(work, buffer.len())?;
        let key = envelope_key(password, &self.iv[..8], key_len);
        let iv = &self.iv[..width];
        macro_rules! decrypt {
            ($cipher:ty) => {{
                let mut mode = cbc::Decryptor::<$cipher>::new_from_slices(&key[..key_len], iv)
                    .map_err(|_| Error::Protected)?;
                let (blocks, tail) = InOutBuf::from(&mut *buffer).into_chunks();
                debug_assert!(tail.is_empty());
                mode.decrypt_blocks_inout(blocks);
            }};
        }
        match self.cipher {
            Cipher::Aes128 => decrypt!(aes::Aes128),
            Cipher::Aes192 => decrypt!(aes::Aes192),
            Cipher::Aes256 => decrypt!(aes::Aes256),
            Cipher::Des => decrypt!(des::Des),
            Cipher::DesEde => decrypt!(des::TdesEde2),
            Cipher::DesEde3 => decrypt!(des::TdesEde3),
        }
        let padding_byte = buffer[buffer.len() - 1];
        let padding = usize::from(padding_byte);
        // Scan the entire final block regardless of the decrypted padding length.
        let mut invalid = u8::from(padding == 0 || padding > width);
        for (index, byte) in buffer.iter().rev().take(width).enumerate() {
            let mask = 0_u8.wrapping_sub(u8::from(index < padding));
            invalid |= (*byte ^ padding_byte) & mask;
        }
        if invalid != 0 {
            buffer.zeroize();
            return Err(Error::Protected);
        }
        let length = buffer.len() - padding;
        buffer[length..].zeroize();
        Ok(length)
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

#[derive(Clone, Copy)]
enum Cipher {
    Aes128,
    Aes192,
    Aes256,
    Des,
    DesEde,
    DesEde3,
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

    fn key_len(self) -> usize {
        match self {
            Self::Aes128 | Self::DesEde => 16,
            Self::Aes192 | Self::DesEde3 => 24,
            Self::Aes256 => 32,
            Self::Des => 8,
        }
    }

    fn block_len(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => 16,
            Self::Des | Self::DesEde | Self::DesEde3 => 8,
        }
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
