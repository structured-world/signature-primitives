//! The contents of primitive elements, read without copying them.
//!
//! Tags are deliberately not checked here. Implicit tagging replaces the tag of
//! a value with the one its position gives it, so a `[0] IMPLICIT INTEGER` is
//! still an integer and the caller is the only one who knows that. What is
//! checked is the encoding of the value itself, which no amount of tagging
//! changes.

use crate::error::ErrorCode;
use crate::length::Encoding;
use crate::memory::{Memory, MemoryError, OwnedString};

mod owned;
mod text;
pub use owned::OwnedOid;

/// An object identifier, as the arcs are encoded, without the tag or length.
///
/// Held encoded rather than decoded because identity is the encoding: two
/// identifiers are the same one when their bytes match, and comparing rendered
/// text instead would make `1.2.840.113549` and a lookalike written with an
/// arc padded to the same digits into the same identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Oid<'a>(&'a [u8]);

impl<'a> Oid<'a> {
    /// An identifier from written-out bytes, validated as it is built.
    ///
    /// For the constants a schema names. The same rules the document reader
    /// enforces are held here by construction, so a table entry cannot name
    /// something no document could: a malformed constant fails the build
    /// during constant evaluation, and a malformed runtime call panics at
    /// the constructor rather than printing nonsense later. Document bytes
    /// never come through here; the parser validates them.
    ///
    /// # Panics
    ///
    /// When the bytes are not a well formed object identifier: empty, a
    /// padded arc, or a truncated continuation. Width is not among them, as
    /// it is not for a document: the encoding bounds no subidentifier
    /// (X.690 8.19.2).
    #[must_use]
    pub const fn from_bytes(bytes: &'a [u8]) -> Self {
        assert!(
            Self::well_formed(bytes),
            "not a well formed object identifier"
        );
        Self(bytes)
    }

    /// The validation the constructor asserts, mirroring the document
    /// reader's rules in a form constant evaluation can run.
    const fn well_formed(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        let mut starting = true;
        let mut at = 0;
        while at < bytes.len() {
            let byte = bytes[at];
            // A leading 0x80 pads the arc with a zero seven-bit group.
            if starting && byte == 0x80 {
                return false;
            }
            starting = byte & 0x80 == 0;
            at += 1;
        }
        // The last byte asked for a continuation that never came.
        starting
    }

    /// The encoded arcs.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Exact dotted-decimal text, admitting conversion work and storage in
    /// the current execution domain. The result retains its capacity charge.
    /// Width is unrestricted by ASN.1; insufficient resources return an error.
    pub fn text(self, execution: &Memory) -> Result<OwnedString, MemoryError> {
        text::oid(self, execution)
    }

    /// The arcs, root first.
    ///
    /// Constructing the iterator is constant work. Advancing it scans the
    /// encoded groups of one subidentifier; the caller must admit that work
    /// when iterating untrusted input. [`Self::text`] accounts for its traversal.
    #[must_use]
    pub fn arcs(self) -> Arcs<'a> {
        Arcs {
            bytes: self.0,
            first: true,
            pending: None,
        }
    }
}

/// One arc of an [`Oid`].
///
/// The encoding bounds no subidentifier (X.690 8.19.2), so an arc may be
/// wider than any integer this crate names. Such an arc keeps the base-128
/// groups it was written in, and the joint offset the first subidentifier
/// carries, so it still prints the number the document holds instead of
/// reporting some other one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arc<'a> {
    /// The value, where it fits.
    value: Option<u64>,
    /// The groups it was written in, for one that does not.
    groups: &'a [u8],
    /// What the first subidentifier's packing adds to this arc: 0, 40 or 80
    /// (X.690 8.19.4). Zero for every later arc.
    offset: u64,
}

impl Arc<'_> {
    /// Exact decimal text, with conversion and retained storage charged to
    /// the current execution domain. No alternate-width rendering is used.
    pub fn text(self, execution: &Memory) -> Result<OwnedString, MemoryError> {
        text::arc(self, execution)
    }

    /// The arc where it fits sixty-four bits, and `None` where nothing that
    /// wide could hold it. This accessor reads the already decoded value in
    /// constant work; decoding occurred when the arcs iterator advanced.
    #[must_use]
    pub fn as_u64(self) -> Option<u64> {
        self.value
    }
}

/// The largest power of ten a remainder fits, and how many digits it writes.
/// Dividing by this rather than by ten is what keeps the number of passes
/// over the groups to a nineteenth of the digits.
const DECIMAL_BLOCK: u128 = 10_000_000_000_000_000_000;
const DECIMAL_BLOCK_DIGITS: usize = 19;

/// An arc's base-128 groups with the joint offset already taken off, read
/// where the document put them.
///
/// The offset comes off the least significant group, and where that group
/// cannot pay it the borrow travels back through the zero groups above it
/// (X.690 8.19.4). That is a suffix and nothing else, so which groups it
/// changes is one index, found by a scan that copies nothing.
struct Groups<'a> {
    encoded: &'a [u8],
    /// What the least significant group owes: 0, 40 or 80.
    offset: u64,
    /// The group the borrow reaches back to and stops at.
    stop: usize,
}

impl<'a> Groups<'a> {
    fn of(encoded: &'a [u8], offset: u64) -> Self {
        let last = encoded.len() - 1;
        let mut stop = last;
        // The borrow cannot travel past the groups: an arc that is read here
        // did not fit sixty-four bits, so it has more groups than the offset
        // spans and the leading one is not zero.
        while stop > 0 {
            let owed = if stop == last { offset } else { 1 };
            if u64::from(encoded[stop] & 0x7f) >= owed {
                break;
            }
            stop -= 1;
        }
        Self {
            encoded,
            offset,
            stop,
        }
    }

    fn count(&self) -> usize {
        self.encoded.len()
    }

    /// The groups from one position on, most significant first.
    fn iter_from(&self, first: usize) -> impl ExactSizeIterator<Item = u8> + '_ {
        (first..self.encoded.len()).map(|at| self.at(at))
    }

    /// The groups, most significant first.
    fn iter(&self) -> impl ExactSizeIterator<Item = u8> + '_ {
        self.iter_from(0)
    }

    /// How many groups the arc has once the leading zeros the borrow can
    /// leave behind are dropped.
    fn significant(&self) -> usize {
        let leading = self.iter().take_while(|group| *group == 0).count();
        self.encoded.len() - leading
    }

    fn at(&self, at: usize) -> u8 {
        let last = self.encoded.len() - 1;
        let group = u64::from(self.encoded[at] & 0x7f);
        let owed = if at == last { self.offset } else { 1 };
        let value = match at.cmp(&self.stop) {
            core::cmp::Ordering::Less => group,
            // The scan stopped here because this group can pay.
            core::cmp::Ordering::Equal => group - owed,
            // Above the group that pays, so this one lends and takes the
            // base back.
            core::cmp::Ordering::Greater => group + 128 - owed,
        };
        u8::try_from(value).expect("a group below the base")
    }
}

/// The arcs of an [`Oid`], root first.
#[derive(Debug, Clone)]
pub struct Arcs<'a> {
    bytes: &'a [u8],
    first: bool,
    pending: Option<Arc<'a>>,
}

impl<'a> Iterator for Arcs<'a> {
    type Item = Arc<'a>;

    fn next(&mut self) -> Option<Arc<'a>> {
        if let Some(second) = self.pending.take() {
            return Some(second);
        }

        // Accumulated wide so that a value one bit past the narrow width is
        // still recognized as not fitting rather than wrapping. Wider than
        // that keeps its groups: the last byte of the slice cannot ask for
        // continuation, which was established when the identifier was read.
        //
        // Multiplied rather than shifted: a shift by seven is always a
        // shift this type permits, so it reports nothing when the seven bits
        // it drops were significant, and the arc would read as whatever
        // survived. The multiplication answers about the value instead.
        let mut value: Option<u128> = Some(0);
        let mut taken = 0;
        for byte in self.bytes {
            taken += 1;
            value = value
                .and_then(|value| value.checked_mul(128)?.checked_add(u128::from(byte & 0x7f)));
            if byte & 0x80 == 0 {
                break;
            }
        }
        let (groups, rest) = self.bytes.split_at(taken);
        self.bytes = rest;
        if taken == 0 {
            return None;
        }

        let arc = |value: Option<u128>, offset: u64| Arc {
            value: value.and_then(|value| u64::try_from(value - u128::from(offset)).ok()),
            groups,
            offset,
        };
        if self.first {
            self.first = false;
            // The first byte carries two arcs. Above 79 the root is 2 and the
            // second arc continues past 39, which is how identifiers such as
            // 2.999 are written. A value too wide to have been compared is
            // above 79 either way: its groups reach past the root's own.
            let root = match value {
                Some(0..=39) => 0,
                Some(40..=79) => 1,
                _ => 2,
            };
            self.pending = Some(arc(value, root * 40));
            return Some(Arc {
                value: Some(root),
                groups: &[],
                offset: 0,
            });
        }

        Some(arc(value, 0))
    }
}

/// An integer, as its two's complement bytes.
///
/// Serial numbers reach twenty bytes and public key moduli are far larger, so
/// this stays as it was encoded and converts on request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Integer<'a>(&'a [u8]);

impl<'a> Integer<'a> {
    /// The two's complement bytes, most significant first.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Whether the value is below zero.
    #[must_use]
    pub fn is_negative(self) -> bool {
        self.0.first().is_some_and(|first| first & 0x80 != 0)
    }

    /// The value as an unsigned number, or `None` when it is negative or wider
    /// than sixty-four bits.
    #[must_use]
    pub fn as_u64(self) -> Option<u64> {
        if self.is_negative() {
            return None;
        }
        // A leading zero is the sign byte of a value whose top bit is set, and
        // carries no magnitude.
        let magnitude = match self.0 {
            [0x00, rest @ ..] => rest,
            all => all,
        };
        if magnitude.len() > 8 {
            return None;
        }
        Some(
            magnitude
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
        )
    }

    /// The value as a signed number, or `None` when it is wider than
    /// sixty-four bits.
    #[must_use]
    pub fn as_i64(self) -> Option<i64> {
        if self.0.len() > 8 {
            return None;
        }
        let sign = if self.is_negative() { -1i64 } else { 0 };
        Some(
            self.0
                .iter()
                .fold(sign, |value, byte| (value << 8) | i64::from(*byte)),
        )
    }

    /// The value as a count, or `None` when it does not fit one.
    #[must_use]
    pub fn as_u32(self) -> Option<u32> {
        self.as_u64().and_then(|value| u32::try_from(value).ok())
    }
}

/// A string of bits, which is not the same as a string of bytes: the last byte
/// may be partly padding, and a key usage of one bit occupies one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitString<'a> {
    bytes: &'a [u8],
    unused: u8,
}

impl<'a> BitString<'a> {
    /// The bytes holding the bits, padding included.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// How many bits of the last byte are padding.
    #[must_use]
    pub fn unused_bits(self) -> u8 {
        self.unused
    }

    /// How many bits the string holds.
    #[must_use]
    pub fn len(self) -> u64 {
        // Every byte holds eight bits less whatever the last one pads, and the
        // count of padding bits is below eight whenever the string is not
        // empty, so neither the multiplication nor the subtraction can wrap.
        (self.bytes.len() as u64) * 8 - u64::from(self.unused)
    }

    /// Whether the string holds no bits at all.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }

    /// Whether the bit at `position` is set, counting from the first bit of the
    /// first byte. Padding and anything past the end read as unset, which is
    /// what a key usage shorter than the bit asked about means.
    #[must_use]
    pub fn bit(self, position: u64) -> bool {
        if position >= self.len() {
            return false;
        }
        // Below the bit count, so the byte it sits in exists and its index fits
        // whatever a slice index is on this target.
        let within = (position % 8) as u32;
        usize::try_from(position / 8)
            .ok()
            .and_then(|byte| self.bytes.get(byte))
            .is_some_and(|value| value & (0x80u8 >> within) != 0)
    }

    /// The bytes with the padding bits of the last one cleared, for a value
    /// meant to be read as octets.
    #[must_use]
    pub fn octets(self) -> Option<&'a [u8]> {
        (self.unused == 0).then_some(self.bytes)
    }
}

/// Reads an object identifier's contents.
pub(crate) fn oid(contents: &[u8]) -> Result<Oid<'_>, ErrorCode> {
    if contents.is_empty() {
        return Err(ErrorCode::MalformedOid);
    }

    // No arc is bounded here. The encoding bounds no subidentifier
    // (X.690 8.19.2), so a width this reader cannot hold in an integer is
    // still a number the document names: refusing it would abort a whole
    // certificate over an arc that only ever gets printed. An arc past the
    // integer keeps its groups and prints from them.
    let mut starting = true;
    for byte in contents {
        // A leading 0x80 pads the arc with a zero seven-bit group, which is a
        // second way to write a number that already has one.
        if starting && *byte == 0x80 {
            return Err(ErrorCode::MalformedOid);
        }
        starting = byte & 0x80 == 0;
    }

    // The last byte asked for a continuation that never came.
    if !starting {
        return Err(ErrorCode::MalformedOid);
    }

    Ok(Oid(contents))
}

/// Reads an integer's contents.
pub(crate) fn integer(contents: &[u8]) -> Result<Integer<'_>, ErrorCode> {
    match contents {
        [] => Err(ErrorCode::IntegerEmpty),
        // Both spellings write a value that one fewer byte already writes, and
        // a signature computed over the bytes makes two spellings of one number
        // into two documents.
        [0x00, second, ..] if second & 0x80 == 0 => Err(ErrorCode::IntegerNotMinimal),
        [0xff, second, ..] if second & 0x80 != 0 => Err(ErrorCode::IntegerNotMinimal),
        _ => Ok(Integer(contents)),
    }
}

/// Reads a bit string's contents.
pub(crate) fn bit_string(contents: &[u8], encoding: Encoding) -> Result<BitString<'_>, ErrorCode> {
    let (unused, bytes) = contents
        .split_first()
        .ok_or(ErrorCode::MalformedBitString)?;
    let unused = *unused;

    if unused > 7 || (bytes.is_empty() && unused != 0) {
        return Err(ErrorCode::MalformedBitString);
    }

    // Padding that carries data is a place to put bytes that a reader ignoring
    // them will not report, and DER settles it by requiring zeroes. BER does
    // not: X.690 places the zero-padding rule in clause 11.2, among the
    // restrictions that only CER and DER add, so a BER document with set
    // padding bits is well formed and is read as it was written. The bits
    // never reach a value either way: the length excludes them, asking for a
    // bit inside them answers unset, and octets() refuses a padded string.
    if encoding.is_der()
        && unused > 0
        && let Some(last) = bytes.last()
        && last & (0xffu8 >> (8 - unused)) != 0
    {
        return Err(ErrorCode::MalformedBitString);
    }

    Ok(BitString { bytes, unused })
}

/// Reads a boolean's contents.
pub(crate) fn boolean(contents: &[u8], encoding: Encoding) -> Result<bool, ErrorCode> {
    match contents {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        // BER lets any non-zero byte mean true. DER settles on one spelling,
        // and accepting the others where a signature covers the bytes would
        // make several documents into one.
        [_] if !encoding.is_der() => Ok(true),
        _ => Err(ErrorCode::MalformedBoolean),
    }
}

/// Reads a real's contents, which the encoding settles down to the last
/// octet (X.690 8.5) and the distinguished rules settle further (11.3).
///
/// Nothing here reads the number: no schema this product parses has a real
/// in it, and one arrives only inside a value preserved for somebody else.
/// What that somebody is promised is that the octets are a value of the type
/// they claim, which is what this decides.
pub(crate) fn real(contents: &[u8], encoding: Encoding) -> Result<(), ErrorCode> {
    let Some((first, rest)) = contents.split_first() else {
        // Plus zero is written with no contents octets at all (8.5.2).
        return Ok(());
    };
    match first & 0xc0 {
        // A special value or minus zero: one octet, and one of the four
        // (8.5.9). The rest of that range is reserved.
        0x40 => (rest.is_empty() && matches!(first, 0x40..=0x43))
            .then_some(())
            .ok_or(ErrorCode::MalformedReal),
        // Decimal (8.5.8): the form octet names an ISO 6093 representation,
        // and the octets after it are that representation.
        0x00 => decimal_real(*first, rest, encoding),
        // Binary (8.5.7): a sign, a base, a scaling factor and an exponent
        // in the first octet, then the exponent and the mantissa.
        _ => binary_real(*first, rest, encoding),
    }
}

/// The decimal form of a real.
fn decimal_real(first: u8, field: &[u8], encoding: Encoding) -> Result<(), ErrorCode> {
    let malformed = || ErrorCode::MalformedReal;
    // NR1, NR2 and NR3 are the three the encoding names; the rest of the
    // range is reserved (8.5.8). The distinguished rules use NR3 alone
    // (11.3.2.1).
    let form = first & 0x3f;
    if !matches!(form, 1..=3) || (encoding.is_der() && form != 3) {
        return Err(malformed());
    }
    if !encoding.is_der() {
        // Outside the distinguished rules the field is ISO 6093 as the
        // sender chose to write it, and reading it is not this crate's
        // business: what is checkable is that there is one.
        return (!field.is_empty()).then_some(()).ok_or_else(malformed);
    }

    // NR3 as 11.3.2 writes it: an optional minus, the mantissa's digits, a
    // full stop, the exponent mark, and the exponent. No space anywhere
    // (11.3.2.2), a leading minus only where the value is negative
    // (11.3.2.3), neither the first nor the last digit of the mantissa a
    // zero (11.3.2.4), the stop immediately after that last digit
    // (11.3.2.5), and a zero exponent written as `+0` with no other
    // exponent signed or led by a zero (11.3.2.6).
    let digits = field.strip_prefix(b"-").unwrap_or(field);
    let (mantissa, exponent) = digits
        .iter()
        .position(|byte| *byte == b'.')
        .map(|stop| digits.split_at(stop))
        .ok_or_else(malformed)?;
    let exponent = exponent.strip_prefix(b".E").ok_or_else(malformed)?;

    let sound_mantissa = mantissa.first().is_some_and(|digit| *digit != b'0')
        && mantissa.last().is_some_and(|digit| *digit != b'0')
        && mantissa.iter().all(u8::is_ascii_digit);
    let sound_exponent = exponent == b"+0"
        || exponent
            .strip_prefix(b"-")
            .unwrap_or(exponent)
            .split_first()
            .is_some_and(|(lead, rest)| {
                lead.is_ascii_digit() && *lead != b'0' && rest.iter().all(u8::is_ascii_digit)
            });
    (sound_mantissa && sound_exponent)
        .then_some(())
        .ok_or_else(malformed)
}

/// The binary form of a real.
fn binary_real(first: u8, rest: &[u8], encoding: Encoding) -> Result<(), ErrorCode> {
    let malformed = || ErrorCode::MalformedReal;
    // The distinguished rules use base two and no scaling factor, and write
    // both parts in the fewest octets (11.3.1). Base 11 is reserved in
    // either encoding (8.5.7.2).
    let base = (first >> 4) & 0x03;
    let scaling = (first >> 2) & 0x03;
    if base == 0x03 || (encoding.is_der() && (base != 0 || scaling != 0)) {
        return Err(malformed());
    }

    // How the exponent is written: one, two or three octets, or a count and
    // then that many (8.5.7.4).
    let (exponent, mantissa) = match first & 0x03 {
        0 => rest.split_at_checked(1),
        1 => rest.split_at_checked(2),
        2 => rest.split_at_checked(3),
        _ => rest.split_first().and_then(|(count, after)| {
            // At least one octet, and the count is not part of the number.
            // Past three the selector cannot say the length itself, which is
            // what this form is for; at three or fewer it spends an octet
            // saying what a selector already says, and the distinguished
            // rules ask for the fewest octets (11.3.1).
            let shortest = !encoding.is_der() || *count > 3;
            (*count >= 1 && shortest).then(|| after.split_at_checked(usize::from(*count)))?
        }),
    }
    .ok_or_else(malformed)?;

    // The first nine bits of an exponent written in more than one octet are
    // neither all zeros nor all ones: that is what the long form says
    // (8.5.7.4 d), and what writing it in the fewest octets means for the
    // shorter forms too.
    if let [lead, next, ..] = exponent {
        let padded = *lead == 0x00 && next & 0x80 == 0;
        let signed = *lead == 0xff && next & 0x80 != 0;
        if padded || signed {
            return Err(malformed());
        }
    }

    // The mantissa is there, written in the fewest octets, and odd: the
    // normalization shifts it until its least significant bit is one, and a
    // mantissa of zero is written as the value zero instead (11.3.1).
    match mantissa {
        // There, and without a leading octet that adds nothing.
        [] | [0x00, ..] => Err(malformed()),
        [.., last] if encoding.is_der() && last & 0x01 == 0 => Err(malformed()),
        _ => Ok(()),
    }
}

/// Reads a null's contents, which are none.
pub(crate) fn null(contents: &[u8]) -> Result<(), ErrorCode> {
    if contents.is_empty() {
        Ok(())
    } else {
        Err(ErrorCode::MalformedNull)
    }
}

#[cfg(test)]
mod tests;
