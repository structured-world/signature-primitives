//! Iterative BER OCTET STRING views with source spans and retained accounting.

use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Parser, Reader, Span, Tag, universal};

/// One original content range, excluding ASN.1 tag and length octets.
#[derive(Debug, Clone, Copy)]
pub struct Piece<'a> {
    bytes: &'a [u8],
    span: Span,
}

impl<'a> Piece<'a> {
    /// The original content bytes; no join or re-encoding is performed.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// The content's original document range.
    #[must_use]
    pub fn span(self) -> Span {
        self.span
    }
}

#[derive(Debug)]
enum Storage<'a> {
    One([Piece<'a>; 1]),
    Many(OwnedVec<Piece<'a>>),
}

/// Borrowed logical octets with independently accounted segment metadata.
///
/// Primitive content stays inline and allocates no catalogue. Constructed BER
/// content retains its original disjoint ranges, flattened only as metadata.
/// The catalogue can outlive the producing reader; its bytes remain borrowed.
#[derive(Debug)]
pub struct Octets<'a> {
    parser: &'a Parser,
    outer_depth: u32,
    carrier: Span,
    contents: Span,
    storage: Storage<'a>,
    length: usize,
    field: &'static str,
}

impl<'a> Octets<'a> {
    /// Reads logical `IA5String` contents through the SAME iterative base-string
    /// walker. BER constructed strings carry OCTET STRING fragments (X.690
    /// §8.23.3); DER remains primitive. ASCII validation is admitted before every
    /// content scan, and original fragment spans are preserved without joining.
    /// <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
    pub fn read_ia5(
        parent: &Reader<'a>,
        element: &Element<'a>,
        field: &'static str,
    ) -> Result<Self> {
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, field))?;
        let value = Self::read_tagged(parent, element, universal::IA5_STRING, false, field)?;
        let execution = parent.execution();
        for piece in value.pieces() {
            execution
                .charge_work(1 + piece.as_bytes().len() as u64)
                .map_err(|cause| Error::resource(cause, field, piece.span().start))?;
            if !piece.as_bytes().is_ascii() {
                return Err(Error::schema(
                    ErrorCode::MalformedValue,
                    field,
                    piece.span().start,
                ));
            }
        }
        Ok(value)
    }

    /// Reads an OCTET STRING using the original parser's encoding and ceilings.
    ///
    /// X.690 §8.7 permits constructed BER strings composed of OCTET STRING
    /// fragments. The iterative traversal preserves inherited depth and source
    /// positions, admitting frame/catalogue growth before allocation. A DER
    /// reader still refuses constructed forms under its own encoding contract.
    /// <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
    pub fn read(parent: &Reader<'a>, element: &Element<'a>, field: &'static str) -> Result<Self> {
        Self::read_tagged(parent, element, universal::OCTET_STRING, false, field)
    }

    /// Reads `[0] IMPLICIT OCTET STRING`, the CMS subject-key identifier.
    ///
    /// Only the outer tag is replaced; constructed children remain universal
    /// OCTET STRINGs (X.690 §§8.7, 8.14). Both forms use the same segment walker.
    pub(crate) fn read_identifier(
        parent: &Reader<'a>,
        element: &Element<'a>,
        field: &'static str,
    ) -> Result<Self> {
        Self::read_tagged(parent, element, 0, true, field)
    }

    fn read_tagged(
        parent: &Reader<'a>,
        element: &Element<'a>,
        number: u32,
        context: bool,
        field: &'static str,
    ) -> Result<Self> {
        let primitive = if context {
            Tag::context(false, number)
        } else {
            Tag::primitive(number)
        };
        let constructed = if context {
            Tag::context(true, number)
        } else {
            Tag::constructed(number)
        };
        if element.tag() == primitive {
            return Ok(Self {
                parser: parent.parser(),
                outer_depth: parent.depth(),
                carrier: element.span(),
                contents: element.contents_span(),
                storage: Storage::One([Piece {
                    bytes: element.contents(),
                    span: element.contents_span(),
                }]),
                length: element.contents().len(),
                field,
            });
        }
        if element.tag() != constructed {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                field,
                element.span().start,
            ));
        }
        if parent.encoding().is_der() {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                field,
                element.span().start,
            ));
        }
        let execution = parent.execution();
        let mut pieces = execution.vector();
        let mut frames = execution.vector();
        frames
            .try_push(
                parent
                    .enter(element)
                    .map_err(|error| Error::encoding(error, field))?,
            )
            .map_err(|reason| Error::resource(reason, field, element.span().start))?;
        let mut length = 0_usize;
        while let Some(reader) = frames.last_mut() {
            let Some(child) = reader
                .next_element()
                .map_err(|error| Error::encoding(error, field))?
            else {
                frames.pop();
                continue;
            };
            if child.tag() == Tag::primitive(universal::OCTET_STRING) {
                length = length.checked_add(child.contents().len()).ok_or_else(|| {
                    Error::schema(ErrorCode::LengthOverflow, field, child.span().start)
                })?;
                pieces
                    .try_push(Piece {
                        bytes: child.contents(),
                        span: child.contents_span(),
                    })
                    .map_err(|reason| Error::resource(reason, field, child.span().start))?;
            } else if child.tag() == Tag::constructed(universal::OCTET_STRING) {
                let nested = reader
                    .enter(&child)
                    .map_err(|error| Error::encoding(error, field))?;
                frames
                    .try_push(nested)
                    .map_err(|reason| Error::resource(reason, field, child.span().start))?;
            } else {
                return Err(Error::schema(
                    ErrorCode::UnexpectedTag,
                    field,
                    child.span().start,
                ));
            }
        }
        Ok(Self {
            parser: parent.parser(),
            outer_depth: parent.depth(),
            carrier: element.span(),
            contents: element.contents_span(),
            storage: Storage::Many(pieces.into_owned()),
            length,
            field,
        })
    }

    /// The original primitive content ranges in logical order.
    #[must_use]
    pub fn pieces(&self) -> &[Piece<'a>] {
        match &self.storage {
            Storage::One(piece) => piece,
            Storage::Many(pieces) => pieces,
        }
    }

    /// The logical octet count, recorded during parsing without a later scan.
    #[must_use]
    pub fn len(&self) -> usize {
        self.length
    }

    /// Whether the logical content is empty, including constructed empty input.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// The original whole carrying element, including its tag and length.
    #[must_use]
    pub fn span(&self) -> Span {
        self.carrier
    }

    pub(crate) fn content_span(&self) -> Span {
        self.contents
    }

    pub(crate) fn outer_depth(&self) -> u32 {
        self.outer_depth
    }

    pub(crate) fn parser(&self) -> &'a Parser {
        self.parser
    }

    /// The borrowed bytes when the logical value occupies one original range.
    #[must_use]
    pub fn as_one(&self) -> Option<&'a [u8]> {
        match self.pieces() {
            [piece] => Some(piece.bytes),
            _ => None,
        }
    }

    /// Copies logical content into independently retained accounted storage.
    ///
    /// This is an explicit materialization; inspection can keep using borrowed
    /// ranges, and an already owned result should be moved instead of copied.
    /// The original producing session is required before any admission or scan.
    /// Metadata traversal, exact capacity and each copy use both its local and
    /// current aggregate ceilings. The result retains charge after reader drop.
    /// `field` and `at` locate the actual enclosing operation, including an
    /// empty constructed value. Refusal releases partial output, not the source.
    pub fn copy_in(
        &self,
        parent: &Reader<'_>,
        field: &'static str,
        at: u64,
    ) -> Result<OwnedVec<u8>> {
        if !core::ptr::eq(self.parser, parent.parser()) {
            return Err(Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                field,
                at,
            )));
        }
        let execution = parent.execution();
        let refusal = |reason| Error::resource(reason, field, at);
        execution
            .charge_work(self.pieces().len() as u64)
            .map_err(refusal)?;
        let mut output = execution.vector();
        // The logical length was checked during the one structural traversal.
        output.try_reserve_exact(self.length).map_err(refusal)?;
        for piece in self.pieces() {
            output.try_extend_from_slice(piece.bytes).map_err(refusal)?;
        }
        Ok(output.into_owned())
    }

    pub(crate) fn same_value(
        &self,
        other: &Octets<'_>,
        parent: &Reader<'_>,
        field: &'static str,
        at: u64,
    ) -> Result<bool> {
        let execution = parent.execution();
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, field, at))?;
        if self.length != other.length {
            return Ok(false);
        }
        for amount in [self.pieces().len(), other.pieces().len(), self.length] {
            execution
                .charge_work(amount as u64)
                .map_err(|reason| Error::resource(reason, field, at))?;
        }
        Ok(self
            .pieces()
            .iter()
            .flat_map(|piece| piece.bytes.iter())
            .eq(other.pieces().iter().flat_map(|piece| piece.bytes.iter())))
    }
}

/// Why feeding attached ranges could not finish.
#[derive(Debug)]
pub enum SourceError {
    /// Metadata traversal refused the current operation's resources.
    Processing(Error),
    /// The stream driver refused a chunk and retains its original cause.
    Receiver(crate::stream::Refused),
}

impl crate::stream::Source for &Octets<'_> {
    type Error = SourceError;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl crate::stream::Receiver,
        execution: &W,
    ) -> core::result::Result<(), Self::Error> {
        for piece in self.pieces() {
            execution.charge_work(1).map_err(|reason| {
                SourceError::Processing(Error::resource(reason, self.field, piece.span.start))
            })?;
            receiver.write(piece.bytes).map_err(SourceError::Receiver)?;
        }
        Ok(())
    }
}
