//! Length octets, in both the definite and the indefinite form.

use crate::error::ErrorCode;

/// How long an element's contents are, when that is stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Length {
    /// The contents are this many bytes.
    Definite(u64),
    /// The contents run until an end-of-contents marker. BER only.
    Indefinite,
}

/// Whether the caller will accept the indefinite form here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// DER: definite lengths, encoded in the fewest bytes.
    Der,
    /// BER: also the indefinite form, and long-form lengths that could have
    /// been shorter.
    Ber,
}

impl Encoding {
    /// Whether this encoding requires the fewest possible length bytes.
    #[must_use]
    pub fn is_der(self) -> bool {
        self == Self::Der
    }
}

/// Reads the length octets at the front of `input`.
///
/// Returns the length and how many bytes it took.
///
/// Under DER two spellings are refused that BER allows, and both are refused
/// because they let the same element be written two ways. The long form for a
/// value under 128 is one; a long form carrying leading zero bytes is the
/// other. Where a signature is computed over the bytes as they were sent, a
/// parser that accepts either has agreed that two different documents are the
/// same document.
pub(crate) fn read_accounted(
    input: &[u8],
    encoding: Encoding,
    offset: u64,
    mut charge: impl FnMut(u64) -> Result<(), ErrorCode>,
) -> Result<(Length, usize), (ErrorCode, u64)> {
    let fail = |code| (code, offset);

    charge(1).map_err(fail)?;

    let first = *input
        .first()
        .ok_or_else(|| fail(ErrorCode::UnexpectedEnd))?;

    if first & 0x80 == 0 {
        return Ok((Length::Definite(u64::from(first)), 1));
    }

    let count = usize::from(first & 0x7f);

    if count == 0 {
        return match encoding {
            Encoding::Ber => Ok((Length::Indefinite, 1)),
            Encoding::Der => Err(fail(ErrorCode::IndefiniteLengthNotAllowed)),
        };
    }

    // 0xff is reserved by X.690 and has no meaning in either encoding.
    if count == 0x7f {
        return Err(fail(ErrorCode::LengthTooLarge));
    }

    // Reserve the complete long-form scan before looking at any length octet.
    charge(count as u64).map_err(fail)?;

    let bytes = input
        .get(1..=count)
        .ok_or_else(|| fail(ErrorCode::UnexpectedEnd))?;

    if encoding.is_der() {
        // A leading zero means the same number would fit in fewer bytes.
        if bytes[0] == 0 {
            return Err(fail(ErrorCode::LengthNotMinimal));
        }
        // Anything under 128 belongs in the short form.
        if count == 1 && bytes[0] < 0x80 {
            return Err(fail(ErrorCode::LengthNotMinimal));
        }
    }

    // More than eight significant bytes cannot be an offset into anything this
    // machine can address, so the answer is the same whichever way it is read.
    let significant = bytes.iter().skip_while(|byte| **byte == 0).count();
    if significant > 8 {
        return Err(fail(ErrorCode::LengthTooLarge));
    }

    let mut value: u64 = 0;
    for byte in bytes {
        value = value
            .checked_mul(256)
            .and_then(|shifted| shifted.checked_add(u64::from(*byte)))
            .ok_or_else(|| fail(ErrorCode::LengthTooLarge))?;
    }

    Ok((Length::Definite(value), 1 + count))
}

#[cfg(test)]
fn read(
    input: &[u8],
    encoding: Encoding,
    offset: u64,
) -> Result<(Length, usize), (ErrorCode, u64)> {
    read_accounted(input, encoding, offset, |_| Ok(()))
}

#[cfg(test)]
mod tests;
