//! Original signature source context and DSA/ECDSA structure, separate from verification.
//!
//! RFC 3279 §§2.2.2–2.2.3 define both values as `SEQUENCE { r INTEGER,
//! s INTEGER }`. RFC 5753 §2.1.1 requires DER even inside a BER CMS envelope.
//! [`DssValue`] checks that encoding and structure; it does not check a
//! signature, choose an algorithm, or know a key's group order. In particular,
//! zero and negative integers remain readable. The selected provider must
//! enforce the full scalar range before arithmetic (SEC 1 v2 §4.1.4).
//! <https://www.rfc-editor.org/rfc/rfc3279.html#section-2.2.2>
//! <https://www.secg.org/sec1-v2.pdf>
//!
//! Spans and errors use the supplied reader's coordinate system. When carried
//! fragments have been joined, retain the carrier's source map to project them
//! to physical locations; no contiguous physical range is invented here.

use crate::error::{Error, ErrorCode, Located, Result};
use structured_asn1::memory::Work;
use structured_asn1::{
    BitString, Element, Encoding, Integer, Parser, ScopedReader, Span, Tag, universal,
};

/// An original signature BIT STRING and the context needed to decode its payload.
///
/// Raw algorithms use [`Self::octets`] without opening a reader. A selected
/// DSA/ECDSA adapter opens [`Self::reader_in`] and calls [`DssValue::read`].
/// This is encoding provenance, not algorithm, scalar, signature or trust
/// acceptance. No payload or resource-account ownership is acquired.
#[derive(Debug, Clone, Copy)]
pub struct SignatureValue<'a> {
    value: BitString<'a>,
    span: Span,
    at: u64,
    parser: &'a Parser,
    outer: u32,
    encoding: Encoding,
    field: &'static str,
}

impl<'a> SignatureValue<'a> {
    /// Reads the next primitive BIT STRING once, retaining its original context.
    /// Surrounding siblings belong to the enclosing schema. Padding remains
    /// inspectable; [`Self::reader_in`] requires a whole-octet payload.
    ///
    /// # Errors
    /// Returns the producing reader's located syntax or resource failure.
    ///
    /// # Examples
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
    /// use structured_pkix::signature::{SignatureValue, DssValue};
    /// let work = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
    /// let parser = Parser::der(work.clone());
    /// let mut original = parser.read(b"\x03\x09\x00\x30\x06\x02\x01\x01\x02\x01\x02", 400).unwrap();
    /// let signature = SignatureValue::read(&mut original, "signature")?;
    /// let mut payload = signature.reader_in(&work)?;
    /// let pair = DssValue::read(&mut payload, "signature")?;
    /// assert_eq!(pair.r_span().start, 405);
    /// # Ok::<(), structured_pkix::Error>(())
    /// ```
    pub fn read(parent: &mut ScopedReader<'a, '_>, field: &'static str) -> Result<Self> {
        let element = parent
            .expect(Tag::primitive(universal::BIT_STRING))
            .field(field)?;
        let value = parent.bit_string(&element).field(field)?;
        Ok(Self {
            value,
            span: element.span(),
            at: element.contents_span().start + 1,
            parser: parent.parser(),
            outer: parent.depth(),
            encoding: parent.encoding(),
            field,
        })
    }

    /// Original decoded bits, including the number of unused trailing bits.
    #[must_use]
    pub fn bit_string(&self) -> BitString<'a> {
        self.value
    }

    /// Original payload bytes when no trailing bits are unused; no scan or copy.
    #[must_use]
    pub fn octets(&self) -> Option<&'a [u8]> {
        self.value.octets()
    }

    /// Original bytes holding the bits, including any last-byte padding.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.value.as_bytes()
    }

    /// Whole original BIT STRING range, including its header and padding count.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }

    /// Original payload range, excluding the BIT STRING header and padding count.
    /// Coordinates remain those of the original source; a joined carrier's
    /// source map remains necessary to obtain physical ranges.
    #[must_use]
    pub fn payload_span(&self) -> Span {
        Span {
            start: self.at,
            length: self.value.as_bytes().len() as u64,
        }
    }

    /// Opens only the original payload, under current work and original limits.
    ///
    /// The BIT STRING carrier contributes one nesting level (RFC 3279
    /// §§2.2.2–2.2.3). This uses the existing source bridge, retaining source
    /// encoding, depth, offsets and cumulative ceiling plus the current root
    /// operation. It neither creates a parser/account nor copies payload bytes.
    /// The returned reader borrows `execution`; decoded scalar views borrow
    /// only the original input. Raw algorithms need not call this method.
    ///
    /// # Errors
    /// Padded bits return a located `MalformedValue` before opening a cursor.
    /// Source/current resource refusal remains a terminal processing error.
    /// See [`Self::read`] for a complete example with [`DssValue`].
    pub fn reader_in<'operation, W: Work>(
        &self,
        execution: &'operation W,
    ) -> Result<ScopedReader<'a, 'operation>>
    where
        'a: 'operation,
    {
        let bytes = self
            .octets()
            .ok_or_else(|| Error::new(ErrorCode::MalformedValue, self.field, self.span.start))?;
        execution
            .read_scoped_nested(self.parser, bytes, self.at, self.encoding, self.outer)
            .field(self.field)
    }
}

/// The exact DER INTEGER pair used by DSA and ECDSA signatures.
///
/// Every view borrows the received bytes. Successful decoding is a structural
/// fact, not a claim that either scalar or the signature is valid. `XMLDSig`'s
/// fixed-width concatenation is a different encoding, handled by its caller.
#[derive(Debug, Clone, Copy)]
pub struct DssValue<'a> {
    element: Element<'a>,
    r: Integer<'a>,
    s: Integer<'a>,
    r_span: Span,
    s_span: Span,
}

impl<'a> DssValue<'a> {
    /// Reads a complete signature-value window, refusing any trailing bytes.
    ///
    /// The supplied cursor must describe the original window at its actual
    /// depth. Its current execution and original source ceilings remain in
    /// force; no parser or resource account is created. DER is enforced even
    /// when the cursor accepts BER. Only reader/path metadata may need storage;
    /// the returned value owns none.
    ///
    /// # Errors
    /// Reports located encoding, missing/extra-field, trailing-data or resource
    /// failures. Resource refusal never becomes a malformed scalar or mismatch.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
    /// use structured_pkix::signature::DssValue;
    /// let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1024, 1024))));
    /// let mut reader = parser.read(b"\x30\x07\x02\x02\x00\x80\x02\x01\x01", 400).unwrap();
    /// let value = DssValue::read(&mut reader, "signature")?;
    /// assert_eq!(value.r().as_bytes(), [0, 0x80]); // original sign octet
    /// assert_eq!(value.s().as_u64(), Some(1));
    /// assert_eq!(value.r_span().start, 402);
    /// # Ok::<(), structured_pkix::Error>(())
    /// ```
    pub fn read(parent: &mut ScopedReader<'a, '_>, field: &'static str) -> Result<Self> {
        let element = parent
            .expect(Tag::constructed(universal::SEQUENCE))
            .field(field)?;
        let value = Self::read_element(parent, &element, field)?;
        if !parent.is_empty() {
            return Err(Error::new(ErrorCode::TrailingData, field, parent.offset()));
        }
        Ok(value)
    }

    /// Reads one embedded value; surrounding siblings belong to the caller.
    ///
    /// `parent` must be the reader that produced `element`. A DER parent uses
    /// the already-validated header; a BER parent re-reads that same original
    /// element under DER before entering it. Both routes share the field kernel
    /// and the same source depth, current work and aggregate accounting.
    ///
    /// # Errors
    /// As [`Self::read`], except that bytes after `element` are allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
    /// use structured_pkix::signature::DssValue;
    /// let parser = Parser::der(Memory::new(Arc::new(MemoryAccount::new(1024, 1024))));
    /// let mut reader = parser.read(b"\x30\x06\x02\x01\x01\x02\x01\x02\x05\x00", 0).unwrap();
    /// let element = reader.next_element().unwrap().unwrap();
    /// let value = DssValue::read_element(&reader, &element, "signature")?;
    /// assert_eq!(value.s().as_u64(), Some(2));
    /// assert!(!reader.is_empty()); // the following NULL is outside this value
    /// # Ok::<(), structured_pkix::Error>(())
    /// ```
    pub fn read_element(
        parent: &ScopedReader<'a, '_>,
        element: &Element<'a>,
        field: &'static str,
    ) -> Result<Self> {
        if parent.encoding().is_der() {
            return Self::fields(parent, element, field);
        }
        // RFC 5753 §2.1.1: ECDSA-Sig-Value is DER, even in BER SignedData.
        // https://www.rfc-editor.org/rfc/rfc5753.html#section-2.1.1
        let mut strict = parent.reread(element, Encoding::Der).field(field)?;
        let element = strict
            .expect(Tag::constructed(universal::SEQUENCE))
            .field(field)?;
        Self::fields(&strict, &element, field)
    }

    fn fields(
        parent: &ScopedReader<'a, '_>,
        element: &Element<'a>,
        field: &'static str,
    ) -> Result<Self> {
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::new(
                ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                field,
                element.span().start,
            ));
        }
        let mut inside = parent.enter(element).field(field)?;
        let r = inside
            .expect(Tag::primitive(universal::INTEGER))
            .field(field)?;
        let r_value = inside.integer(&r).field(field)?;
        let s = inside
            .expect(Tag::primitive(universal::INTEGER))
            .field(field)?;
        let s_value = inside.integer(&s).field(field)?;
        if !inside.is_empty() {
            return Err(Error::new(ErrorCode::TrailingData, field, inside.offset()));
        }
        Ok(Self {
            element: *element,
            r: r_value,
            s: s_value,
            r_span: r.span(),
            s_span: s.span(),
        })
    }

    /// The whole original encoding, including its SEQUENCE header.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }

    /// Original minimal two's-complement `r`, including any required sign octet.
    #[must_use]
    pub fn r(&self) -> Integer<'a> {
        self.r
    }

    /// Original minimal two's-complement `s`, including any required sign octet.
    #[must_use]
    pub fn s(&self) -> Integer<'a> {
        self.s
    }

    /// Original whole INTEGER range for `r`, including its tag and length.
    #[must_use]
    pub fn r_span(&self) -> Span {
        self.r_span
    }

    /// Original whole INTEGER range for `s`, including its tag and length.
    #[must_use]
    pub fn s_span(&self) -> Span {
        self.s_span
    }
}
