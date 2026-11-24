use crate::{ALPHABET, Base64Error};

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
pub(super) const INVALID: u8 = 0xff;
pub(super) static STANDARD_VALUES: [u8; 256] = values(ALPHABET);
static URL_VALUES: [u8; 256] = values(URL_ALPHABET);
static STANDARD_PAIRS: [u16; 4096] = pairs(ALPHABET);
static URL_PAIRS: [u16; 4096] = pairs(URL_ALPHABET);
static STANDARD_WORDS: [[u32; 256]; 4] = words(ALPHABET);
static URL_WORDS: [[u32; 256]; 4] = words(URL_ALPHABET);

const fn words(alphabet: &[u8; 64]) -> [[u32; 256]; 4] {
    let mut table = [[1 << 31; 256]; 4];
    let mut lane = 0;
    while lane < 4 {
        let mut n = 0u8;
        while n < 64 {
            // The low three bytes are in output order. Swapping here keeps
            // byte-order conversion out of the little-endian decode loop.
            let value = (n as u32) << (18 - lane * 6);
            table[lane][alphabet[n as usize] as usize] = value.swap_bytes() >> 8;
            n += 1;
        }
        lane += 1;
    }
    table
}

#[inline]
fn word([a, b, c, d]: [u8; 4], table: &[[u32; 256]; 4]) -> u32 {
    table[0][usize::from(a)]
        | table[1][usize::from(b)]
        | table[2][usize::from(c)]
        | table[3][usize::from(d)]
}

/// Decodes an aligned prefix with full output space, stopping before the
/// first whitespace, padding or non-alphabet byte. The streaming state
/// machine owns interpretation and diagnostics at that boundary.
pub(super) fn decode_standard_prefix(input: &[u8], output: &mut [u8]) -> usize {
    let mut written = 0;
    for (input, output) in input
        .as_chunks::<4>()
        .0
        .iter()
        .zip(output.as_chunks_mut::<3>().0)
    {
        let decoded = word(*input, &STANDARD_WORDS);
        if decoded >> 31 != 0 {
            break;
        }
        let [a, b, c, _] = decoded.to_le_bytes();
        *output = [a, b, c];
        written += 3;
    }
    written
}

/// Decode two quartets at a time when the stream begins with enough space.
/// Retry a partially valid pair through the same quartet and scalar paths.
pub(super) fn decode_wide_standard_prefix(input: &[u8], output: &mut [u8]) -> usize {
    let mut written = 0;
    for (input, output) in input
        .as_chunks::<8>()
        .0
        .iter()
        .zip(output.as_chunks_mut::<6>().0)
    {
        let [first, second] = input.as_chunks::<4>().0 else {
            unreachable!("two quartets per wide input");
        };
        let left = word(*first, &STANDARD_WORDS);
        let right = word(*second, &STANDARD_WORDS);
        if (left | right) >> 31 != 0 {
            break;
        }
        let packed = (u64::from(left) | (u64::from(right) << 24)).to_le_bytes();
        output.copy_from_slice(&packed[..6]);
        written += 6;
    }
    let consumed = written / 3 * 4;
    written + decode_standard_prefix(&input[consumed..], &mut output[written..])
}

#[inline]
fn encode_group([a, b, c]: [u8; 3], table: &[u16; 4096]) -> [u8; 4] {
    let [first, second] = table[usize::from(a) << 4 | usize::from(b >> 4)].to_ne_bytes();
    let [third, fourth] = table[usize::from(b & 15) << 8 | usize::from(c)].to_ne_bytes();
    [first, second, third, fourth]
}

const fn values(alphabet: &[u8; 64]) -> [u8; 256] {
    let mut table = [INVALID; 256];
    let mut n = 0u8;
    while n < 64 {
        table[alphabet[n as usize] as usize] = n;
        n += 1;
    }
    table
}

const fn pairs(alphabet: &[u8; 64]) -> [u16; 4096] {
    let mut table = [0; 4096];
    let mut n = 0;
    while n < table.len() {
        table[n] = u16::from_ne_bytes([alphabet[n >> 6], alphabet[n & 63]]);
        n += 1;
    }
    table
}

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
        let pairs = if self.url {
            &URL_PAIRS
        } else {
            &STANDARD_PAIRS
        };
        let (blocks, remainder) = input.as_chunks::<12>();
        let (bulk, output) = output.split_at_mut(blocks.len() * 16);
        for (input, output) in blocks.iter().zip(bulk.as_chunks_mut::<16>().0) {
            let groups = input.as_chunks::<3>().0;
            let groups_out = output.as_chunks_mut::<4>().0;
            groups_out[0] = encode_group(groups[0], pairs);
            groups_out[1] = encode_group(groups[1], pairs);
            groups_out[2] = encode_group(groups[2], pairs);
            groups_out[3] = encode_group(groups[3], pairs);
        }
        let (groups, tail) = remainder.as_chunks::<3>();
        let (head, end) = output.split_at_mut(groups.len() * 4);
        for (&[a, b, c], group) in groups.iter().zip(head.as_chunks_mut::<4>().0.iter_mut()) {
            *group = encode_group([a, b, c], pairs);
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
        self.decode_symbols(symbols, output)
    }

    fn decode_symbols(self, symbols: &[u8], output: &mut [u8]) -> Result<usize, Base64Error> {
        let len = decoded_len(symbols.len());
        let output = output.get_mut(..len).ok_or(Base64Error::OutputFull)?;
        let table = self.values();
        let words = if self.url {
            &URL_WORDS
        } else {
            &STANDARD_WORDS
        };
        let (bulk, rest) = symbols.as_chunks::<32>();
        let (head, output) = output.split_at_mut(bulk.len() * 24);
        for (index, (input, output)) in bulk.iter().zip(head.as_chunks_mut::<24>().0).enumerate() {
            let quads = input.as_chunks::<4>().0;
            let decoded: [u64; 8] =
                core::array::from_fn(|index| u64::from(word(quads[index], words)));
            // RFC 4648 §3.3: one invalid marker is sufficient to reject
            // the block. The cold path locates the first offending byte.
            if decoded.into_iter().fold(0, |mask, value| mask | value) >> 31 != 0 {
                return Err(invalid_block(input, table, index * 32));
            }
            let out = output.as_chunks_mut::<8>().0;
            out[0] = (decoded[0] | decoded[1] << 24 | decoded[2] << 48).to_le_bytes();
            out[1] = (decoded[2] >> 16 | decoded[3] << 8 | decoded[4] << 32 | decoded[5] << 56)
                .to_le_bytes();
            out[2] = (decoded[5] >> 8 | decoded[6] << 16 | decoded[7] << 40).to_le_bytes();
        }
        let mut offset = bulk.len() * 32;
        let (blocks, remainder) = rest.as_chunks::<16>();
        let (head, mut end) = output.split_at_mut(blocks.len() * 12);
        for (input, output) in blocks.iter().zip(head.as_chunks_mut::<12>().0) {
            let quads = input.as_chunks::<4>().0;
            let first = word(quads[0], words);
            let second = word(quads[1], words);
            let third = word(quads[2], words);
            let fourth = word(quads[3], words);
            // RFC 4648 §3.3 rejects symbols outside the selected alphabet.
            // Valid quads use 24 bits. The marker's high bit survives OR.
            if (first | second | third | fourth) >> 31 != 0 {
                return Err(invalid_block(input, table, offset));
            }
            let low = u64::from(first) | u64::from(second) << 24 | u64::from(third) << 48;
            let high = third >> 16 | fourth << 8;
            let (head, tail) = output.split_at_mut(8);
            head.copy_from_slice(&low.to_le_bytes());
            tail.copy_from_slice(&high.to_le_bytes());
            offset += 16;
        }
        let (quads, tail) = remainder.as_chunks::<4>();
        for quad in quads {
            let value = word(*quad, words);
            if value >> 31 != 0 {
                return Err(invalid_block(quad, table, offset));
            }
            end[..3].copy_from_slice(&value.to_le_bytes()[..3]);
            end = &mut end[3..];
            offset += 4;
        }
        if let [a, b, rest @ ..] = tail {
            let first = value(table, offset, *a)?;
            let second = value(table, offset + 1, *b)?;
            // RFC 4648 §3.5 requires unused bits to be zero.
            // https://www.rfc-editor.org/rfc/rfc4648.html#section-3.5
            if let [c] = rest {
                let third = value(table, offset + 2, *c)?;
                if third & 3 != 0 {
                    return Err(Base64Error::InvalidLastSymbol(offset + 2, *c));
                }
                end[1] = second << 4 | third >> 2;
            } else if second & 15 != 0 {
                return Err(Base64Error::InvalidLastSymbol(offset + 1, *b));
            }
            end[0] = first << 2 | second >> 4;
        }
        Ok(len)
    }

    fn symbols(self, input: &[u8]) -> Result<&[u8], Base64Error> {
        if self.url {
            if input.len() % 4 == 1 {
                return Err(self.invalid_length(input));
            }
            return Ok(input);
        }
        if !input.len().is_multiple_of(4) {
            return Err(self.invalid_length(input));
        }
        Ok(if let Some(symbols) = input.strip_suffix(b"==") {
            symbols
        } else if let Some(symbols) = input.strip_suffix(b"=") {
            symbols
        } else {
            input
        })
    }

    #[cold]
    fn invalid_length(self, input: &[u8]) -> Base64Error {
        // A trailing foreign byte can itself be the reason the length is
        // invalid. Preserve that byte, e.g. a newline after a complete quad.
        if let Some((&byte, prefix)) = input.split_last()
            && (self.url || byte != b'=')
            && self.values()[usize::from(byte)] == INVALID
        {
            return Base64Error::InvalidByte(prefix.len(), byte);
        }
        Base64Error::InvalidLength(input.len())
    }

    fn values(self) -> &'static [u8; 256] {
        if self.url {
            &URL_VALUES
        } else {
            &STANDARD_VALUES
        }
    }
}

#[cold]
fn invalid_block(block: &[u8], table: &[u8; 256], offset: usize) -> Base64Error {
    for (index, &byte) in block.iter().enumerate() {
        if table[usize::from(byte)] == INVALID {
            return Base64Error::InvalidByte(offset + index, byte);
        }
    }
    unreachable!("the block failed its alphabet check")
}

fn value(table: &[u8; 256], offset: usize, byte: u8) -> Result<u8, Base64Error> {
    let value = table[usize::from(byte)];
    if value == INVALID {
        Err(Base64Error::InvalidByte(offset, byte))
    } else {
        Ok(value)
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

    /// Append canonical Base64 to a string, reserving the additional capacity
    /// fallibly before changing its contents.
    pub fn encode_string(
        self,
        input: &[u8],
        out: &mut alloc::string::String,
    ) -> Result<(), OwnedError> {
        let len = self
            .encoded_len(input.len())
            .ok_or(OwnedError::Codec(Base64Error::OutputFull))?;
        out.try_reserve(len).map_err(OwnedError::Reserve)?;
        if input.is_empty() {
            return Ok(());
        }
        // Each nonfinal chunk ends at a group boundary. All generated bytes
        // are ASCII, so no partial UTF-8 sequence crosses into the next chunk.
        let mut scratch = [0; 4096];
        for chunk in input.chunks(3072) {
            let written = self
                .encode_slice(chunk, &mut scratch)
                .map_err(OwnedError::Codec)?;
            let encoded = core::str::from_utf8(&scratch[..written])
                .map_err(|_| OwnedError::Codec(Base64Error::Invalid))?;
            out.push_str(encoded);
        }
        Ok(())
    }

    /// Decode into a byte vector with fallible allocation.
    pub fn decode(self, input: &[u8]) -> Result<alloc::vec::Vec<u8>, OwnedError> {
        let symbols = self.symbols(input).map_err(OwnedError::Codec)?;
        let mut out = buffer(decoded_len(symbols.len()))?;
        self.decode_symbols(symbols, &mut out)
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
