#![no_std]
#![doc = include_str!("../README.md")]

use core::fmt;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Failure of a Base64 stream operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// Invalid input, a finished encoder given more data, or invalid state.
    Invalid,
    /// The output buffer is too small for this call.
    OutputFull,
    /// The decoder reached the end with an incomplete group.
    Truncated,
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid Base64 input or state",
            Self::OutputFull => "Base64 output buffer is too small",
            Self::Truncated => "incomplete Base64 group",
        })
    }
}

impl core::error::Error for Base64Error {}

/// Plain state of one Base64 stream, restorable between successful calls.
///
/// Each call checks the state before reading input or writing output. The
/// fields describe a logical state, with no Rust or C layout guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base64Codec {
    /// True for encoding and false for decoding.
    pub encode: bool,
    /// Encoded line width, or zero for a single line. Ignored by the decoder.
    pub columns: usize,
    /// Previous input byte (encoding) or sextet (decoding).
    pub carry: u8,
    /// Bytes carried by the encoder or characters seen in the decoder group.
    pub position: usize,
    /// Number of characters on the current encoded line. Zero for decoding.
    pub line_position: usize,
    /// The stream has finished, or the decoder has started reading padding.
    pub finished: bool,
}

impl Base64Codec {
    /// Start a stream with the specified direction and encoded line width.
    #[must_use]
    pub const fn new(encode: bool, columns: usize) -> Self {
        Self {
            encode,
            columns,
            carry: 0,
            position: 0,
            line_position: 0,
            finished: false,
        }
    }

    /// Upper bound for encoding a chunk and finalizing, including spare room
    /// for a caller's terminator. Returns `None` on arithmetic overflow.
    #[must_use]
    pub fn encoded_capacity(columns: usize, size: usize) -> Option<usize> {
        let symbols = (size.checked_mul(4)? / 3).checked_add(4)?;
        let with_breaks = if let Some(breaks) = symbols.checked_div(columns) {
            symbols.checked_add(breaks)?.checked_add(4)?
        } else {
            symbols
        };
        with_breaks.checked_add(1)
    }

    /// Upper bound for decoding a chunk, including spare room to consume
    /// padding. Returns `None` on arithmetic overflow.
    #[must_use]
    pub fn decoded_capacity(size: usize) -> Option<usize> {
        (size.checked_mul(3)? / 4).checked_add(8)
    }

    /// Consume all input and return the number of output bytes written.
    ///
    /// After an error, discard the stream and any output from this call.
    /// A successful call can be followed by another with a different slice.
    ///
    /// # Errors
    /// Returns [`Base64Error::Invalid`] for invalid input or state, or
    /// [`Base64Error::OutputFull`] when the output has insufficient space.
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Base64Error> {
        self.validate()?;
        if self.encode {
            self.encode_input(input, output)
        } else {
            self.decode_input(input, output)
        }
    }

    /// Complete the stream, writing any final encoded characters and padding.
    ///
    /// A nonempty output slice is required. Encoding leaves one spare byte
    /// for the caller. Decoding returns zero and rejects an incomplete group.
    /// After an error, discard the stream and any output from this call.
    /// A successful call closes the stream.
    ///
    /// # Errors
    /// Returns [`Base64Error::Invalid`] for invalid state,
    /// [`Base64Error::OutputFull`] when the output has insufficient space,
    /// or [`Base64Error::Truncated`] for an incomplete decoder group.
    pub fn finish(&mut self, output: &mut [u8]) -> Result<usize, Base64Error> {
        self.validate()?;
        let (_, output) = output.split_last_mut().ok_or(Base64Error::OutputFull)?;
        let mut written = 0;
        if self.position != 0 {
            if !self.encode {
                return Err(Base64Error::Truncated);
            }
            let shift = if self.position == 1 { 4 } else { 2 };
            self.emit(
                ALPHABET[usize::from((self.carry << shift) & 63)],
                output,
                &mut written,
            )?;
            for _ in self.position..3 {
                self.emit(b'=', output, &mut written)?;
            }
        }
        self.carry = 0;
        self.position = 0;
        self.finished = true;
        Ok(written)
    }

    fn validate(&self) -> Result<(), Base64Error> {
        let valid = if self.encode {
            self.valid_encoder()
        } else {
            self.line_position == 0
                && self.carry < 64
                && match (self.finished, self.position) {
                    (false, 0) => self.carry == 0,
                    (false, 1..=3) | (true, 0 | 3) => true,
                    _ => false,
                }
        };
        if valid {
            Ok(())
        } else {
            Err(Base64Error::Invalid)
        }
    }

    fn valid_encoder(&self) -> bool {
        if self.position > 2
            || (self.position == 0 && self.carry != 0)
            || (self.finished && self.position != 0)
        {
            return false;
        }
        if self.columns == 0 {
            return self.line_position % 4 == self.position;
        }
        if self.line_position == 0 {
            return self.position == 0;
        }
        if self.line_position > self.columns {
            return false;
        }
        // Each previous line contributes columns symbols. Its residue modulo
        // four must be a multiple of gcd(columns, 4).
        let mask = match self.columns % 4 {
            0 => 3,
            2 => 1,
            _ => 0,
        };
        self.line_position & mask == self.position & mask
    }

    fn encode_input(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Base64Error> {
        if self.finished && !input.is_empty() {
            return Err(Base64Error::Invalid);
        }
        let mut written = 0;
        for &byte in input {
            let sextet = match self.position {
                0 => byte >> 2,
                1 => (self.carry & 3) << 4 | byte >> 4,
                _ => (self.carry & 15) << 2 | byte >> 6,
            };
            self.emit(ALPHABET[usize::from(sextet)], output, &mut written)?;
            if self.position == 2 {
                self.emit(ALPHABET[usize::from(byte & 63)], output, &mut written)?;
                self.position = 0;
                self.carry = 0;
            } else {
                self.position += 1;
                self.carry = byte;
            }
        }
        Ok(written)
    }

    fn emit(
        &mut self,
        byte: u8,
        output: &mut [u8],
        written: &mut usize,
    ) -> Result<(), Base64Error> {
        if self.columns != 0 && self.line_position == self.columns {
            write_byte(output, written, b'\n')?;
            self.line_position = 0;
        }
        let next = self
            .line_position
            .checked_add(1)
            .ok_or(Base64Error::Invalid)?;
        write_byte(output, written, byte)?;
        self.line_position = next;
        Ok(())
    }

    fn decode_input(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Base64Error> {
        let mut written = 0;
        for &byte in input {
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                continue;
            }
            // libxmlsec 1.3.13 stops decoding at a full output buffer before
            // inspecting another non-space byte, including padding.
            if written == output.len() {
                return Err(Base64Error::OutputFull);
            }
            if byte == b'=' {
                self.position = match (self.finished, self.position) {
                    (false, 2) => 3,
                    (_, 3) => 0,
                    _ => return Err(Base64Error::Invalid),
                };
                self.finished = true;
                continue;
            }
            if self.finished {
                return Err(Base64Error::Invalid);
            }
            let value = sextet(byte).ok_or(Base64Error::Invalid)?;
            if self.position != 0 {
                let shift = self.position * 2;
                write_byte(
                    output,
                    &mut written,
                    (self.carry << shift) | (value >> (6 - shift)),
                )?;
            }
            self.position = (self.position + 1) % 4;
            self.carry = if self.position == 0 { 0 } else { value };
        }
        Ok(written)
    }
}

fn sextet(byte: u8) -> Option<u8> {
    Some(match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

fn write_byte(output: &mut [u8], written: &mut usize, byte: u8) -> Result<(), Base64Error> {
    *output.get_mut(*written).ok_or(Base64Error::OutputFull)? = byte;
    *written += 1;
    Ok(())
}
