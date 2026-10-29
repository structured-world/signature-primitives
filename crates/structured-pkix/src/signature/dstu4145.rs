//! Original DSTU signature OCTET framing, independent of point arithmetic.

use crate::algorithm::dstu4145::{ByteOrder, Octets};
use crate::error::Located;
use crate::{Error, ErrorCode, Result};
use structured_asn1::{Element, Encoding, ScopedReader, Tag, universal};

/// Exact signature encoding and two borrowed unsigned scalar representations.
///
/// Zero and out-of-order-range values remain visible. A provider must check
/// `0 < r,s < n`, field/group validity and signature math before acceptance.
#[derive(Debug, Clone, Copy)]
pub struct Value<'a> {
    element: Element<'a>,
    r: Octets<'a>,
    s: Octets<'a>,
}

impl<'a> Value<'a> {
    /// Reads one complete carried signature and refuses trailing bytes.
    /// Uses the same field kernel as [`Self::read_element`].
    ///
    /// # Errors
    /// As [`Self::read_element`], plus missing value or trailing data.
    pub fn read(
        reader: &mut ScopedReader<'a, '_>,
        byte_order: ByteOrder,
        order_bits: u32,
        field: &'static str,
    ) -> Result<Self> {
        let element = reader
            .next_element()
            .field(field)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, field, reader.offset()))?;
        let value = Self::read_element(reader, &element, byte_order, order_bits, field)?;
        if !reader.is_empty() {
            return Err(Error::new(ErrorCode::TrailingData, field, reader.offset()));
        }
        Ok(value)
    }
    /// Complete original OCTET STRING including its tag and length.
    #[must_use]
    pub const fn element(self) -> Element<'a> {
        self.element
    }
    /// Unsigned r with original byte order and location, including width padding.
    #[must_use]
    pub const fn r(self) -> Octets<'a> {
        self.r
    }
    /// Unsigned s with original byte order and location, including width padding.
    #[must_use]
    pub const fn s(self) -> Octets<'a> {
        self.s
    }

    /// Reads the original OCTET STRING under the actual producing reader.
    ///
    /// The trusted caller supplies the selected signature representation and
    /// the signing key's subgroup order bit length, never inferring either
    /// from byte length or substituting the field degree m for L(n).
    /// DSTU4145 §§5.7, 5.10–11 defines binary D=S||R. Encoding the whole D
    /// little-endian gives r_LE||s_LE; big-endian gives s_BE||r_BE. The pinned
    /// certificate profile §§3.11.1.6 and 3.14.2 requires the minimum width,
    /// an OCTET wrapper and DER. DSTU §5.7 says LD >= 2 L(n), multiple of 16:
    /// each half therefore has ceil(L(n)/8) octets. A BER parent does not
    /// relax this wrapper. In particular, m=257 need not mean 33-octet scalars.
    /// <https://zakon.rada.gov.ua/laws/show/z1398-12>
    ///
    /// Original and current execution, encoding coordinates and nested depth
    /// remain on the producing reader. No parser, buffer or scalar is copied.
    /// Raw scalar iteration is caller-funded, as for ASN.1 Integer views.
    ///
    /// `parent` must be the reader that produced `element`, as for the
    /// underlying ASN.1 element APIs; no foreign-source identity is fabricated.
    ///
    /// # Errors
    /// Invalid wrapper or width, zero order size, or original resource/encoding
    /// failures. Siblings after `element` belong to the enclosing schema.
    pub fn read_element(
        parent: &ScopedReader<'a, '_>,
        element: &Element<'a>,
        byte_order: ByteOrder,
        order_bits: u32,
        field: &'static str,
    ) -> Result<Self> {
        if parent.encoding().is_der() {
            return Self::fields(parent, *element, byte_order, order_bits, field);
        }
        let mut strict = parent.reread(element, Encoding::Der).field(field)?;
        let written = strict
            .next_element()
            .field(field)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, field, strict.offset()))?;
        Self::fields(&strict, written, byte_order, order_bits, field)
    }

    fn fields(
        parent: &ScopedReader<'a, '_>,
        element: Element<'a>,
        byte_order: ByteOrder,
        order_bits: u32,
        field: &'static str,
    ) -> Result<Self> {
        // Metadata is work too; reject a spent original/current query before
        // inspecting width even when the OCTET payload needs no decoding.
        parent.charge(1).field(field)?;
        if element.tag() != Tag::primitive(universal::OCTET_STRING) {
            return Err(Error::new(
                ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                field,
                element.span().start,
            ));
        }
        let bytes = element.contents();
        let width = u64::from(order_bits).div_ceil(8);
        if order_bits == 0 || bytes.len() as u64 != width * 2 {
            return Err(Error::new(
                ErrorCode::MalformedValue,
                field,
                element.span().start,
            ));
        }
        let half = bytes.len() / 2;
        let (first, last) = bytes.split_at(half);
        let at = element.contents_span().start;
        let first = Octets::new(first, byte_order, at);
        let last = Octets::new(last, byte_order, at + half as u64);
        let (r, s) = match byte_order {
            ByteOrder::LittleEndian => (first, last),
            ByteOrder::BigEndian => (last, first),
        };
        Ok(Self { element, r, s })
    }
}
