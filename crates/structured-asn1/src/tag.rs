//! Identifier octets: the class, whether the element is constructed, and the
//! number.

use crate::error::ErrorCode;

/// The two bits that say who defines the tag number's meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Defined by X.680 itself: INTEGER, SEQUENCE and the rest.
    Universal,
    /// Defined by the application.
    Application,
    /// Defined by the position within the enclosing type: `[0]`, `[1]`.
    ContextSpecific,
    /// Defined privately.
    Private,
}

impl Class {
    fn from_bits(bits: u8) -> Self {
        match bits >> 6 {
            0 => Self::Universal,
            1 => Self::Application,
            2 => Self::ContextSpecific,
            _ => Self::Private,
        }
    }
}

/// Universal tag numbers this parser names. Others are read as numbers.
pub mod universal {
    /// BOOLEAN.
    pub const BOOLEAN: u32 = 1;
    /// INTEGER.
    pub const INTEGER: u32 = 2;
    /// BIT STRING.
    pub const BIT_STRING: u32 = 3;
    /// OCTET STRING.
    pub const OCTET_STRING: u32 = 4;
    /// NULL.
    pub const NULL: u32 = 5;
    /// OBJECT IDENTIFIER.
    pub const OID: u32 = 6;
    /// `UTF8String`.
    pub const UTF8_STRING: u32 = 12;
    /// SEQUENCE and SEQUENCE OF.
    pub const SEQUENCE: u32 = 16;
    /// SET and SET OF.
    pub const SET: u32 = 17;
    /// `PrintableString`.
    pub const PRINTABLE_STRING: u32 = 19;
    /// `IA5String`.
    pub const IA5_STRING: u32 = 22;
    /// `UTCTime`.
    pub const UTC_TIME: u32 = 23;
    /// `GeneralizedTime`.
    pub const GENERALIZED_TIME: u32 = 24;
}

/// One element's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    class: Class,
    constructed: bool,
    /// The number, or `None` for one wider than this reader names. The
    /// encoding bounds no tag number (X.690 8.1.2.4.2), and a schema assigns
    /// small ones, so a wide number is not one anything names: it is read
    /// and kept apart from every named tag rather than refused, because
    /// refusing it would block a certificate over an element nothing was
    /// going to interpret anyway.
    ///
    /// Every wide number is the same `None` here, so two tags that are both
    /// beyond naming are equal, which is what the accessor says about them.
    /// What tells two documents apart is their bytes.
    number: Option<u32>,
}

impl Tag {
    /// A tag built from its parts.
    #[must_use]
    pub fn new(class: Class, constructed: bool, number: u32) -> Self {
        Self {
            class,
            constructed,
            number: Some(number),
        }
    }

    /// A tag whose number is wider than this reader names.
    ///
    /// Every such tag is the same tag here, which is what its class and
    /// construction say and nothing more. Two documents writing different
    /// wide numbers are still told apart by their bytes, which is what
    /// identity is compared on; what this decides is only that neither
    /// matches a tag a schema names.
    #[must_use]
    pub fn beyond_naming(class: Class, constructed: bool) -> Self {
        Self {
            class,
            constructed,
            number: None,
        }
    }

    /// A universal primitive tag, the common case for values.
    #[must_use]
    pub fn primitive(number: u32) -> Self {
        Self::new(Class::Universal, false, number)
    }

    /// A universal constructed tag, the common case for containers.
    #[must_use]
    pub fn constructed(number: u32) -> Self {
        Self::new(Class::Universal, true, number)
    }

    /// A context-specific tag, as written `[n]` in a module.
    #[must_use]
    pub fn context(constructed: bool, number: u32) -> Self {
        Self::new(Class::ContextSpecific, constructed, number)
    }

    /// Who defines what this number means.
    #[must_use]
    pub fn class(self) -> Class {
        self.class
    }

    /// Whether the contents are further elements rather than a value.
    #[must_use]
    pub fn is_constructed(self) -> bool {
        self.constructed
    }

    /// The number within the class, where it is one this reader names.
    ///
    /// `None` is a number too wide for that, which no schema assigns and
    /// nothing here interprets. A caller matching against the numbers it
    /// knows gets no match, which is the answer.
    #[must_use]
    pub fn number(self) -> Option<u32> {
        self.number
    }

    /// Whether this is the end-of-contents marker that closes an
    /// indefinite-length element.
    #[must_use]
    pub fn is_end_of_contents(self) -> bool {
        self.class == Class::Universal && !self.constructed && self.number == Some(0)
    }
}

/// Reads the identifier octets at the front of `input`.
///
/// Returns the tag and how many bytes it took. The high-tag-number form is
/// accepted, and two spellings of it are refused: a first byte of `0x80`,
/// which pads the number with a leading zero, and the long form used for a
/// number the short one already writes. Both are ways to write the same
/// number in different bytes, which is how two parsers are made to disagree
/// about what they read.
///
/// A number wider than the reader names is not one of those: it is read, and
/// kept apart from every named tag.
pub(crate) fn read_accounted(
    input: &[u8],
    offset: u64,
    mut charge: impl FnMut(u64) -> Result<(), ErrorCode>,
) -> Result<(Tag, usize), (ErrorCode, u64)> {
    let fail = |code| (code, offset);

    charge(1).map_err(fail)?;

    let first = *input
        .first()
        .ok_or_else(|| fail(ErrorCode::UnexpectedEnd))?;
    let class = Class::from_bits(first);
    let constructed = first & 0x20 != 0;
    let low = first & 0x1f;

    if low != 0x1f {
        // Universal zero belongs to the end-of-contents marker, which is
        // primitive. Constructed, it is neither that marker nor a tag any
        // encoding defines, and returning it hands the reader an element that
        // does not exist.
        if class == Class::Universal && low == 0 && constructed {
            return Err(fail(ErrorCode::MalformedTag));
        }
        return Ok((Tag::new(class, constructed, u32::from(low)), 1));
    }

    // The number, where it fits, and `None` for one wider than that. The
    // encoding bounds no tag number (X.690 8.1.2.4.2), and a schema assigns
    // small ones, so a wide number is not a tag anything names; refusing it
    // would block a certificate over an element nothing was going to
    // interpret. What is still refused is a header spending more bytes on
    // the number than any document has reason to, which is a limit on the
    // size of the header rather than on the size of the number.
    let mut number: Option<u64> = Some(0);
    let mut taken = 1;
    loop {
        charge(1).map_err(fail)?;
        let byte = *input
            .get(taken)
            .ok_or_else(|| fail(ErrorCode::UnexpectedEnd))?;
        taken += 1;

        // A first continuation byte of 0x80 means the number starts with a zero
        // seven-bit group, which is a longer spelling of a shorter number.
        if taken == 2 && byte == 0x80 {
            return Err(fail(ErrorCode::MalformedTag));
        }

        number =
            number.and_then(|value| value.checked_mul(128)?.checked_add(u64::from(byte & 0x7f)));

        if byte & 0x80 == 0 {
            break;
        }

        // Continuing past this would read the rest of the document looking
        // for a byte without the high bit set.
        if taken > TAG_NUMBER_BYTES {
            return Err(fail(ErrorCode::TagTooLarge));
        }
    }

    // The high-tag-number form is only for numbers that do not fit the low form.
    if number.is_some_and(|number| number < 0x1f) {
        return Err(fail(ErrorCode::MalformedTag));
    }

    let tag = match number.and_then(|number| u32::try_from(number).ok()) {
        Some(number) => Tag::new(class, constructed, number),
        None => Tag::beyond_naming(class, constructed),
    };
    Ok((tag, taken))
}

#[cfg(test)]
fn read(input: &[u8], offset: u64) -> Result<(Tag, usize), (ErrorCode, u64)> {
    read_accounted(input, offset, |_| Ok(()))
}

/// How many bytes a tag's number may be written in.
///
/// Not a bound on the number, which the encoding does not bound: a number
/// wider than this reader names is read and kept apart from the named ones.
/// This bounds the header instead. Without it a run of continuation bytes
/// would be followed to the end of the document, so it is the same kind of
/// limit as the one on how deeply elements may nest, and sixteen bytes is
/// several times what any assigned number has ever needed.
const TAG_NUMBER_BYTES: usize = 16;

#[cfg(test)]
mod tests;
