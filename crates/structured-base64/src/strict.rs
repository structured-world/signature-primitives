use crate::{ALPHABET, Base64Error, sextet};

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Strict standard Base64 with canonical padding, as used by JOSE `x5c`.
pub const STANDARD: Profile = Profile { url: false };

/// Strict base64url without padding, as used by JWS.
pub const URL_SAFE_NO_PAD: Profile = Profile { url: true };

/// A canonical Base64 alphabet and padding profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    url: bool,
}

impl Profile {
    /// Return the exact encoded length, or `None` on overflow.
    #[must_use]
    pub const fn encoded_len(self, input_len: usize) -> Option<usize> {
        let tail = match input_len % 3 {
            0 => 0,
            rem if self.url => rem + 1,
            _ => 4,
        };
        let Some(groups) = (input_len / 3).checked_mul(4) else {
            return None;
        };
        groups.checked_add(tail)
    }

    /// Encode into a caller-provided slice and return the bytes written.
    ///
    /// A short output returns [`Base64Error::OutputFull`] before writing.
    pub fn encode_slice(self, input: &[u8], output: &mut [u8]) -> Result<usize, Base64Error> {
        let len = self
            .encoded_len(input.len())
            .ok_or(Base64Error::OutputFull)?;
        let output = output.get_mut(..len).ok_or(Base64Error::OutputFull)?;
        let alphabet = if self.url { URL_ALPHABET } else { ALPHABET };
        let (groups, tail) = input.as_chunks::<3>();
        let (head, end) = output.split_at_mut(groups.len() * 4);
        for (&[a, b, c], group) in groups.iter().zip(head.as_chunks_mut::<4>().0.iter_mut()) {
            *group = [
                alphabet[usize::from(a >> 2)],
                alphabet[usize::from((a & 3) << 4 | b >> 4)],
                alphabet[usize::from((b & 15) << 2 | c >> 6)],
                alphabet[usize::from(c & 63)],
            ];
        }
        if let [a, rest @ ..] = tail {
            let b = rest.first().copied().unwrap_or(0);
            end.fill(b'=');
            end[0] = alphabet[usize::from(a >> 2)];
            end[1] = alphabet[usize::from((a & 3) << 4 | b >> 4)];
            if !rest.is_empty() {
                end[2] = alphabet[usize::from((b & 15) << 2)];
            }
        }
        Ok(len)
    }

    /// Decode canonical input into a caller-provided slice.
    ///
    /// Whitespace, foreign alphabet characters, incorrect padding and
    /// nonzero unused bits are invalid. Discard output on error.
    pub fn decode_slice(self, input: &[u8], output: &mut [u8]) -> Result<usize, Base64Error> {
        let symbols = self.symbols(input)?;
        let len = decoded_len(symbols.len());
        let output = output.get_mut(..len).ok_or(Base64Error::OutputFull)?;
        let (groups, tail) = symbols.as_chunks::<4>();
        let (head, end) = output.split_at_mut(groups.len() * 3);
        for (&[a, b, c, d], group) in groups.iter().zip(head.as_chunks_mut::<3>().0.iter_mut()) {
            let (a, b, c, d) = (
                self.value(a)?,
                self.value(b)?,
                self.value(c)?,
                self.value(d)?,
            );
            *group = [a << 2 | b >> 4, b << 4 | c >> 2, c << 6 | d];
        }
        if let [a, b, rest @ ..] = tail {
            let (a, b) = (self.value(*a)?, self.value(*b)?);
            // RFC 4648 section 3.5 requires unused bits to be zero.
            if let [c] = rest {
                let c = self.value(*c)?;
                if c & 3 != 0 {
                    return Err(Base64Error::Invalid);
                }
                end[1] = b << 4 | c >> 2;
            } else if b & 15 != 0 {
                return Err(Base64Error::Invalid);
            }
            end[0] = a << 2 | b >> 4;
        }
        Ok(len)
    }

    fn symbols(self, input: &[u8]) -> Result<&[u8], Base64Error> {
        if self.url {
            if input.len() % 4 == 1 {
                return Err(Base64Error::Truncated);
            }
            return Ok(input);
        }
        if !input.len().is_multiple_of(4) {
            return Err(Base64Error::Truncated);
        }
        Ok(if let Some(symbols) = input.strip_suffix(b"==") {
            symbols
        } else if let Some(symbols) = input.strip_suffix(b"=") {
            symbols
        } else {
            input
        })
    }

    fn value(self, byte: u8) -> Result<u8, Base64Error> {
        let byte = match (self.url, byte) {
            (true, b'-') => b'+',
            (true, b'_') => b'/',
            (true, b'+' | b'/') => return Err(Base64Error::Invalid),
            _ => byte,
        };
        sextet(byte).ok_or(Base64Error::Invalid)
    }
}

const fn decoded_len(symbols: usize) -> usize {
    symbols / 4 * 3 + symbols % 4 * 3 / 4
}

/// Failure of an allocating Base64 operation.
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub enum OwnedError {
    /// Invalid input or unrepresentable output length.
    Codec(Base64Error),
    /// The requested output capacity could not be reserved.
    Reserve(alloc::collections::TryReserveError),
}

#[cfg(feature = "alloc")]
impl core::fmt::Display for OwnedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(error) => error.fmt(f),
            Self::Reserve(error) => error.fmt(f),
        }
    }
}

#[cfg(feature = "alloc")]
impl core::error::Error for OwnedError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(match self {
            Self::Codec(error) => error,
            Self::Reserve(error) => error,
        })
    }
}

#[cfg(feature = "alloc")]
impl Profile {
    /// Encode into a string with fallible allocation.
    pub fn encode(self, input: &[u8]) -> Result<alloc::string::String, OwnedError> {
        let len = self
            .encoded_len(input.len())
            .ok_or(OwnedError::Codec(Base64Error::OutputFull))?;
        let mut out = buffer(len)?;
        self.encode_slice(input, &mut out)
            .map_err(OwnedError::Codec)?;
        alloc::string::String::from_utf8(out).map_err(|_| OwnedError::Codec(Base64Error::Invalid))
    }

    /// Decode into a byte vector with fallible allocation.
    pub fn decode(self, input: &[u8]) -> Result<alloc::vec::Vec<u8>, OwnedError> {
        let symbols = self.symbols(input).map_err(OwnedError::Codec)?;
        let mut out = buffer(decoded_len(symbols.len()))?;
        self.decode_slice(input, &mut out)
            .map_err(OwnedError::Codec)?;
        Ok(out)
    }
}

#[cfg(feature = "alloc")]
fn buffer(len: usize) -> Result<alloc::vec::Vec<u8>, OwnedError> {
    let mut out = alloc::vec::Vec::new();
    out.try_reserve_exact(len).map_err(OwnedError::Reserve)?;
    out.resize(len, 0);
    Ok(out)
}
