//! Scoped ASN.1 carried by original XML nodes, without retaining decoded buffers.

use crate::xml::{Access, AccessError, AccessResult, Name, Snapshot, Xml};
use structured_asn1::{
    Encoding, Parser, Reader,
    memory::{OwnedVec, Work},
};
use structured_cms::timestamp::Token;

/// XML-owned lexical decoding of an encapsulated binary value.
///
/// Common processing selects the original `Encoding` attribute/default; the
/// owner validates the XML lexical form,
/// including children and whitespace, before invoking the visitor. It admits
/// traversal, decoded capacity and copies before doing that work. Existing XML
/// base64 processing must be reused rather than reparsing serialized XML.
///
/// The owner supplies the actual decoded buffer and its producing Parser inside
/// the scope. Common processing constructs the Reader with the selected encoding
/// through [`Parser::read_query_in`]. Both original and current operation
/// ceilings are therefore preserved by construction, rather than trusting an
/// adapter to return a Reader with the correct budget. ASN.1 depth is not XML depth.
///
/// Decoded offsets identify this binary source, never physical XML bytes. The
/// original XML node and generation accompany every returned common error.
pub trait BinaryXml: Xml {
    /// Visits decoded octets that are not themselves an ASN.1 value, such as a
    /// `CertDigest` `DigestValue`. No ASN.1 depth gate applies to these octets.
    /// Both entry points reuse one owner lexical/decoding kernel and admit its
    /// complete work/capacity before scanning or decoding. No implicit I/O.
    fn with_octets<R, C, W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        execution: &W,
        visitor: impl for<'source> FnOnce(&'source [u8]) -> Result<R, C>,
    ) -> Result<Result<R, C>, Self::Error>;

    /// Visits the actual decoded source under the current operation.
    ///
    /// The result cannot borrow the temporary buffer or parser. Independent
    /// retained results must retain their allocation charges after scope exit.
    /// The owner must not swallow a visitor refusal or call the visitor twice.
    fn with_binary<R, C>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        operation: &Reader<'_>,
        visitor: impl for<'source> FnOnce(Decoded<'source>) -> Result<R, C>,
    ) -> Result<Result<R, C>, Self::Error>;
}

/// Independent decoded ownership for simultaneous certificate/status checking.
///
/// The same owner lexical/decode kernel serves scoped and owned entry points.
/// Decode directly into admitted caller storage, then move its ownership; do
/// not decode into an ordinary Vec and copy it a second time. Every allocation,
/// initialization, lexical pass and decode is admitted before execution. A moved
/// existing buffer retains its original storage account; new processing work is
/// charged to the current operation. Returning owned data does not qualify an
/// implementation's transitive accounting without testing its actual kernel.
pub trait OwnedBinaryXml: BinaryXml {
    /// Returns the original decoded octets with independent retained capacity.
    fn decode_owned<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        execution: &W,
    ) -> Result<OwnedVec<u8>, Self::Error>;

    /// Moves an ASN.1 source together with its producing session. A cached
    /// source keeps its existing cumulative ceilings; the adapter must not
    /// replace that session merely to start a new query with a clean budget.
    /// The current operation funds decoding and subsequent query execution.
    fn decode_binary_owned(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        node: Self::Id,
        operation: &Reader<'_>,
    ) -> Result<OwnedDecoded, Self::Error>;
}

/// Independently owned decoded bytes and their actual producing session.
///
/// This has no internal borrowed pointers. Move sources into their final
/// accounted catalogue before borrowing parsed certificates or status values.
/// A later borrow cannot outlive the source or coexist with moving it. Storage
/// remains charged to the bytes' original account; a new query pays current work.
///
/// ```compile_fail
/// use structured_asn1::{Encoding, Reader};
/// use structured_xades::binary::OwnedDecoded;
/// fn escape<'a>(source: OwnedDecoded, operation: &Reader<'a>) -> Reader<'a> {
///     source.reader_in(operation, Encoding::Der).unwrap()
/// }
/// ```
#[derive(Debug)]
pub struct OwnedDecoded {
    /// Actual producing session, including work already consumed on this source.
    pub parser: Parser,
    /// Original decoded allocation, transferred without re-encoding or copying.
    pub bytes: OwnedVec<u8>,
    /// Offset of this window in the decoded document, never a physical XML offset.
    pub base: u64,
    /// Actual source-reader ASN.1 depth, independent of XML depth; fresh roots use zero.
    pub depth: u32,
}

impl OwnedDecoded {
    /// Borrows the source without allocation, account cloning or a new Parser.
    #[must_use]
    pub fn view(&self) -> Decoded<'_> {
        Decoded {
            parser: &self.parser,
            bytes: &self.bytes,
            base: self.base,
            depth: self.depth,
        }
    }

    /// Opens the original window under both source and current-operation limits.
    /// The material schema selects its encoding; this never infers a permissive
    /// codec from malformed bytes. Existing source work is not reset or credited.
    pub fn reader_in<'source>(
        &'source self,
        operation: &Reader<'source>,
        encoding: Encoding,
    ) -> structured_asn1::Result<Reader<'source>> {
        self.parser
            .read_query_in(operation, &self.bytes, self.base, encoding, self.depth)
    }
}

/// The actual scoped decoded source and its original ASN.1 provenance.
/// These borrows cannot escape the higher-ranked visitor. A fresh decoded
/// document has base zero and reader depth zero; neither is a physical XML offset.
#[derive(Debug, Clone, Copy)]
pub struct Decoded<'source> {
    /// Producing session for this actual source, with explicit owner limits.
    pub parser: &'source Parser,
    /// Original decoded source window, without re-encoding or an extra copy.
    pub bytes: &'source [u8],
    /// Source-window offset in this decoded document.
    pub base: u64,
    /// Actual source-reader ASN.1 depth, independent of XML depth; fresh roots use zero.
    pub depth: u32,
}

// The original XML enclosure of a decoded binary source is a common source
// location; `Located` and every binary error carry it.
pub use structured_ltv::source::Location;

/// A retained result alongside its original XML/binary-source enclosure.
/// Any ASN.1 offsets inside the value remain decoded-source coordinates.
#[derive(Debug)]
pub struct Located<T, N, D, G> {
    /// Original document generation and encapsulated-value node.
    pub location: Location<N, D, G>,
    /// Retained scoped result; it cannot borrow the temporary decoded source.
    pub value: T,
}

/// A result carrying this XML owner's stable source identity types.
pub type LocatedValue<T, X> =
    Located<T, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Moves an owned decoded source out together with its exact XML enclosure.
///
/// This performs no ASN.1 parse or codec substitution. The caller's material
/// schema must still select and validate its actual PKI format. No buffer copy,
/// allocation or reference-count increment is introduced by this wrapper.
pub fn owned<X: OwnedBinaryXml, W: Work>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    execution: &W,
) -> AccessResult<LocatedValue<OwnedVec<u8>, X>, X> {
    let value = Access::new(xml, location.snapshot, execution)
        .query(location.node, |xml, snapshot, work| {
            xml.decode_owned(snapshot, location.node, work)
        })?;
    Ok(Located { location, value })
}

/// Retains a source for simultaneous material checking without a second decode.
/// Original XML identity accompanies every source in a multi-source catalogue.
/// Like [`owned`], this does not itself establish the material's PKI schema,
/// authenticity, completeness or trust.
pub fn owned_source<X: OwnedBinaryXml>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    operation: &Reader<'_>,
) -> AccessResult<LocatedValue<OwnedDecoded, X>, X> {
    let execution = operation.execution();
    let value = Access::new(xml, location.snapshot, &execution)
        .query(location.node, |xml, snapshot, _| {
            xml.decode_binary_owned(snapshot, location.node, operation)
        })?;
    Ok(Located { location, value })
}

/// Refusal preserving both the XML enclosure and the unchanged inner cause.
#[derive(Debug)]
pub enum Error<E, C, N, D, G> {
    /// The original Encoding attribute does not identify a specified PKI codec.
    UnknownEncoding {
        /// Original encapsulated-value element.
        location: Location<N, D, G>,
    },
    /// A specified codec has no decoder in this ASN.1 processing capability.
    /// This is unsupported processing, not malformed XML or a digest mismatch.
    UnsupportedEncoding {
        /// Original encapsulated-value element.
        location: Location<N, D, G>,
        /// Original specified codec.
        encoding: PkiEncoding,
    },
    /// Common Reader construction refused before the inspection visitor.
    ReaderCreation {
        /// Original encapsulated-value element.
        location: Location<N, D, G>,
        /// Original ASN.1 processing/resource error in decoded-source coordinates.
        cause: structured_asn1::Error,
    },
    /// XML access, decoding, generation or resource refusal.
    Access {
        /// Original XML enclosure, not a fabricated binary byte range.
        location: Location<N, D, G>,
        /// Original access/owner cause, including pre-visitor resource errors.
        cause: AccessError<E, N>,
    },
    /// Scoped ASN.1 inspection/check callback refused.
    Callback {
        /// Inner offsets refer to the decoded source at this XML node.
        location: Location<N, D, G>,
        /// Unchanged cause; retained maps keep their own inner source contexts.
        cause: C,
    },
}

impl<E, C, N, D, G> Error<E, C, N, D, G> {
    // Flatten nested scoped operations without relabelling XML locations or
    // allocating/cloning while already handling an opaque callback refusal.
    /// Maps only the scoped callback cause. Original XML/source locations,
    /// resource refusals and access/generation classifications remain intact.
    pub fn map_callback<T>(self, map: impl FnOnce(C) -> T) -> Error<E, T, N, D, G> {
        match self {
            Self::UnknownEncoding { location } => Error::UnknownEncoding { location },
            Self::UnsupportedEncoding { location, encoding } => {
                Error::UnsupportedEncoding { location, encoding }
            }
            Self::ReaderCreation { location, cause } => Error::ReaderCreation { location, cause },
            Self::Access { location, cause } => Error::Access { location, cause },
            Self::Callback { location, cause } => Error::Callback {
                location,
                cause: map(cause),
            },
        }
    }
}

/// Encoding identifiers defined by EN319132-1 §5.1.3; absence specifically means DER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiEncoding {
    /// ASN.1 distinguished encoding.
    Der,
    /// ASN.1 basic encoding.
    Ber,
    /// ASN.1 canonical encoding, distinct from merely accepting BER syntax.
    Cer,
    /// ASN.1 packed encoding.
    Per,
    /// ASN.1 XML encoding, distinct from the outer base64 XML carrier.
    Xer,
}

/// Original XML declaration, distinct from the caller-selected parser profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingDeclaration {
    /// No Encoding attribute: EN319132-1 §5.1.3 declares DER by absence.
    Absent,
    /// The original recognized Encoding attribute, without changing XML.
    Explicit(PkiEncoding),
}

impl EncodingDeclaration {
    /// Effective declared encoding, including the specified wire default.
    #[must_use]
    pub fn encoding(self) -> PkiEncoding {
        match self {
            Self::Absent => PkiEncoding::Der,
            Self::Explicit(encoding) => encoding,
        }
    }
}

pub(crate) fn pki_encoding<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> core::result::Result<Option<EncodingDeclaration>, AccessError<X::Error, X::Id>> {
    access
        .attribute(
            node,
            Name {
                namespace: "",
                local: "Encoding",
            },
            |value| {
                // EN319132-1 §5.1.3 specifies DER for the absent attribute; this is
                // a wire default, never an implicit permissive parser/policy fallback.
                // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
                let Some(value) = value else {
                    return Ok(Some(EncodingDeclaration::Absent));
                };
                let value = access.trim_xml_whitespace(value)?;
                for (uri, encoding) in [
                    ("http://uri.etsi.org/01903/v1.2.2#DER", PkiEncoding::Der),
                    ("http://uri.etsi.org/01903/v1.2.2#BER", PkiEncoding::Ber),
                    ("http://uri.etsi.org/01903/v1.2.2#CER", PkiEncoding::Cer),
                    ("http://uri.etsi.org/01903/v1.2.2#PER", PkiEncoding::Per),
                    ("http://uri.etsi.org/01903/v1.2.2#XER", PkiEncoding::Xer),
                ] {
                    if access.equal(value, uri)? {
                        return Ok(Some(EncodingDeclaration::Explicit(encoding)));
                    }
                }
                Ok(None)
            },
        )?
        .map_err(|cause| AccessError::Resource { node, cause })
}

/// Scoped binary result using this XML owner's source identity types.
pub type BinaryResult<T, X, C> = core::result::Result<
    T,
    Error<<X as Xml>::Error, C, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
>;

/// Visits an original decoded octet value without inventing an ASN.1 enclosure.
/// The result cannot borrow the temporary decoded buffer.
///
/// ```compile_fail
/// use structured_asn1::memory::Work;
/// use structured_xades::binary::{self, BinaryResult, BinaryXml, Location};
/// fn escape<'a, X: BinaryXml, W: Work>(xml: &X,
///     location: Location<X::Id, X::Document, X::Generation>, work: &W)
///     -> BinaryResult<&'a [u8], X, ()>
/// {
///     binary::with_octets(xml, location, work, |bytes| Ok(bytes))
/// }
/// ```
pub fn with_octets<X: BinaryXml, W: Work, R, C>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    execution: &W,
    visitor: impl for<'source> FnOnce(&'source [u8]) -> Result<R, C>,
) -> BinaryResult<R, X, C> {
    Access::new(xml, location.snapshot, execution)
        .query(location.node, |xml, snapshot, work| {
            xml.with_octets(snapshot, location.node, work, visitor)
        })
        .map_err(|cause| Error::Access { location, cause })?
        .map_err(|cause| Error::Callback { location, cause })
}

/// Visits one original decoded source with snapshot checks around the callback.
pub fn with_reader<X: BinaryXml, R, C>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(&mut Reader<'source>) -> core::result::Result<R, C>,
) -> BinaryResult<R, X, C> {
    let execution = operation.execution();
    let access = Access::new(xml, location.snapshot, &execution);
    let encoding = selected_encoding(&access, location)
        .map_err(|error| error.map_callback(|never| match never {}))?;
    with_reader_as(xml, location, operation, encoding, visitor)
}

pub(crate) fn selected_encoding<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    location: Location<X::Id, X::Document, X::Generation>,
) -> BinaryResult<Encoding, X, core::convert::Infallible> {
    let specified = pki_encoding(access, location.node)
        .map_err(|cause| Error::Access { location, cause })?
        .ok_or(Error::UnknownEncoding { location })?;
    let encoding = match specified.encoding() {
        PkiEncoding::Der => Encoding::Der,
        PkiEncoding::Ber => Encoding::Ber,
        other => {
            return Err(Error::UnsupportedEncoding {
                location,
                encoding: other,
            });
        }
    };
    Ok(encoding)
}

/// Visits a schema-fixed DER value, such as `IssuerSerialV2` (§5.2.2).
/// An unrelated XML attribute cannot make this ASN.1 value permissive BER.
/// Outer XML schema/attribute validation remains a separate obligation.
pub fn with_der_reader<X: BinaryXml, R, C>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(&mut Reader<'source>) -> Result<R, C>,
) -> BinaryResult<R, X, C> {
    with_reader_as(xml, location, operation, Encoding::Der, visitor)
}

fn with_reader_as<X: BinaryXml, R, C>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    operation: &Reader<'_>,
    encoding: Encoding,
    visitor: impl for<'source> FnOnce(&mut Reader<'source>) -> Result<R, C>,
) -> BinaryResult<R, X, C> {
    let execution = operation.execution();
    let result = Access::new(xml, location.snapshot, &execution)
        .query(location.node, |xml, snapshot, _| {
            xml.with_binary(snapshot, location.node, operation, |source| {
                let mut reader = source
                    .parser
                    .read_query_in(operation, source.bytes, source.base, encoding, source.depth)
                    .map_err(ScopedError::Processing)?;
                visitor(&mut reader).map_err(ScopedError::Callback)
            })
        })
        .map_err(|cause| Error::Access { location, cause })?;
    result.map_err(|cause| match cause {
        ScopedError::Processing(cause) => Error::ReaderCreation { location, cause },
        ScopedError::Callback(cause) => Error::Callback { location, cause },
    })
}

enum ScopedError<C> {
    Processing(structured_asn1::Error),
    Callback(C),
}

/// Scoped token refusal, distinct from XML decoding and callback failures.
#[derive(Debug)]
pub enum TokenError<C> {
    /// Original CMS envelope processing error in decoded-source coordinates.
    Processing(structured_cms::Error),
    /// Original inspection or complete timestamp-check refusal.
    Callback(C),
}

/// Reads the carried RFC3161 CMS token through its existing common kernel.
///
/// The visitor can inspect retained faults or run [`Token::check`] against the
/// selected TSA certificate and original covered input. Reading alone establishes
/// neither timestamp mathematics nor authority/trust. Errors from a complete
/// check, including its retained inner `SourceMap`s, keep the binary/XML enclosure.
/// No new grammar, encoded copy or replacement default-budget parser is used.
pub fn with_token<X: BinaryXml, R, C>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(Token<'source>, &Reader<'source>) -> core::result::Result<R, C>,
) -> BinaryResult<R, X, TokenError<C>> {
    with_reader(xml, location, operation, |reader| {
        let token = Token::read_from(reader).map_err(TokenError::Processing)?;
        visitor(token, reader).map_err(TokenError::Callback)
    })
}
