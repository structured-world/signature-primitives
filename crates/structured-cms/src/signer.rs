//! Original signer identities, algorithms, attributes and signature ranges.

use crate::attribute::{Attributes, Placement};
use crate::{Error, ErrorCode, Octets, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Integer, Reader, ScopedReader, Span, Tag, universal};
use structured_pkix::Name;
use structured_pkix::algorithm::AlgorithmReading;

/// The identity actually selected by the document, without certificate selection.
#[derive(Debug)]
pub enum SignerIdentifier<'a> {
    /// The issuer's distinguished name and original certificate serial.
    IssuerAndSerial {
        /// Original issuer name, interpreted by the common PKIX name core.
        issuer: Name<'a>,
        /// Original minimal two's-complement serial; no certificate policy is inferred.
        serial: Integer<'a>,
    },
    /// Logical identifier octets, preserving any BER segmentation.
    SubjectKeyIdentifier(Octets<'a>),
}

impl<'a> SignerIdentifier<'a> {
    fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        Self::read_as(parent, element, "signerInfo.sid")
    }

    pub(crate) fn read_as(
        parent: &Reader<'a>,
        element: &Element<'a>,
        field: &'static str,
    ) -> Result<Self> {
        if element.tag() == Tag::context(false, 0) || element.tag() == Tag::context(true, 0) {
            return Octets::read_identifier(parent, element, field).map(Self::SubjectKeyIdentifier);
        }
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                field,
                element.span().start,
            ));
        }
        let mut inside = parent
            .enter(element)
            .map_err(|error| Error::encoding(error, field))?;
        let name = inside
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|error| Error::encoding(error, field))?;
        let issuer = structured_pkix::name::read(&inside, &name, field).map_err(Error::pkix)?;
        let serial = inside
            .read_integer()
            .map_err(|error| Error::encoding(error, field))?;
        if !inside.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                field,
                inside.offset(),
            ));
        }
        Ok(Self::IssuerAndSerial { issuer, serial })
    }

    /// The version required by this CHOICE (RFC5652 §5.3).
    #[must_use]
    pub fn required_version(&self) -> u64 {
        match self {
            Self::IssuerAndSerial { .. } => 1,
            Self::SubjectKeyIdentifier(_) => 3,
        }
    }
}

/// Original fields required by TS101733 §6.5.1's schema-selected DER recipe.
/// These are the elements already read by the signer kernel, never a new
/// positional parser or caller-created algorithm identifier.
#[derive(Debug, Clone, Copy)]
pub struct Fields<'d> {
    pub(crate) parser: &'d structured_asn1::Parser,
    pub(crate) depth: u32,
    /// Original version, signer identifier and digest algorithm, in that order.
    pub identity: [Element<'d>; 3],
    /// Original signature algorithm and signature OCTET STRING.
    pub signature: [Element<'d>; 2],
}

/// One parsed CMS signer, retaining original byte identity and diagnostic storage.
#[derive(Debug)]
pub struct SignerInfo<'a> {
    parser: &'a structured_asn1::Parser,
    depth: u32,
    fields: Fields<'a>,
    version: u64,
    sid: SignerIdentifier<'a>,
    digest_algorithm: AlgorithmReading<'a>,
    signed_attributes: Option<Attributes<'a>>,
    signature_algorithm: AlgorithmReading<'a>,
    signature: Octets<'a>,
    signed_fields: &'a [u8],
    unsigned_attributes: Option<Attributes<'a>>,
    encoding: Encoding,
    element: Element<'a>,
    faults: OwnedVec<Error>,
}

impl<'a> SignerInfo<'a> {
    /// Already parsed original component elements, with no traversal/copy.
    #[must_use]
    pub fn fields(&self) -> Fields<'a> {
        self.fields
    }
    /// Requires the original producing parser, before a protocol layer reads
    /// retained fields. Equal accounts or equal encodings are not session identity.
    pub fn require_session(&self, parent: &Reader<'_>, field: &'static str) -> Result<()> {
        if !self.digest_algorithm.same_session(parent) {
            return Err(Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                field,
                self.span().start,
            )));
        }
        Ok(())
    }
    /// Reads a signer at the original depth with both producing work ceilings.
    ///
    /// A uniquely readable version mismatch is retained as a fault, never a
    /// successful conformance claim. Signed attributes remain DER and their
    /// original octets are never repaired (RFC5652 §§5.3–5.4).
    /// Each algorithm uses the PKIX inspection reader: a uniquely bounded
    /// malformed parameter stays visible with its located diagnostic, while
    /// missing/ambiguous fields and resource/processing refusals remain errors.
    /// Provider preparation refuses either malformed algorithm before callbacks.
    /// <https://www.rfc-editor.org/rfc/rfc5652#section-5.3>
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        const FIELD: &str = "signerInfo";
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                FIELD,
                element.span().start,
            ));
        }
        let mut inside = parent
            .enter(element)
            .map_err(|error| Error::encoding(error, FIELD))?;
        let execution = parent.execution();
        let mut faults = execution.vector();
        let version_element = inside
            .expect(Tag::primitive(universal::INTEGER))
            .map_err(|error| Error::encoding(error, "signerInfo.version"))?;
        let version = inside
            .integer(&version_element)
            .map_err(|error| Error::encoding(error, "signerInfo.version"))?
            .as_u64()
            .ok_or_else(|| {
                Error::schema(
                    ErrorCode::ValueTooLarge,
                    "signerInfo.version",
                    version_element.span().start,
                )
            })?;
        let named = required(&mut inside, "signerInfo.sid")?;
        let sid = SignerIdentifier::read(&inside, &named)?;
        if version != sid.required_version() {
            faults
                .try_push(Error::schema(
                    ErrorCode::VersionMismatch,
                    "signerInfo.version",
                    version_element.span().start,
                ))
                .map_err(|reason| {
                    Error::resource(reason, "signerInfo.version", version_element.span().start)
                })?;
        }
        let digest = required(&mut inside, "signerInfo.digestAlgorithm")?;
        let digest_algorithm =
            read_algorithm(&inside, &digest, "signerInfo.digestAlgorithm", &mut faults)?;
        let mut next = required(&mut inside, "signerInfo.signatureAlgorithm")?;
        let signed_attributes = if next.tag() == Tag::context(true, 0) {
            let attributes = read_attributes(&inside, &next, Placement::Signed, &mut faults)?;
            next = required(&mut inside, "signerInfo.signatureAlgorithm")?;
            Some(attributes)
        } else {
            None
        };
        let signature_algorithm_element = next;
        let signature_algorithm =
            read_algorithm(&inside, &next, "signerInfo.signatureAlgorithm", &mut faults)?;
        let signature_element = required(&mut inside, "signerInfo.signature")?;
        let signature = Octets::read(&inside, &signature_element, "signerInfo.signature")?;
        let signed_fields = field_range(element, &version_element, &signature_element);
        let unsigned_attributes = match inside
            .next_element()
            .map_err(|error| Error::encoding(error, "signerInfo.unsignedAttrs"))?
        {
            Some(attributes) => Some(read_attributes(
                &inside,
                &attributes,
                Placement::Unsigned,
                &mut faults,
            )?),
            None => None,
        };
        if !inside.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                FIELD,
                inside.offset(),
            ));
        }
        Ok(Self {
            parser: parent.parser(),
            depth: inside.depth(),
            fields: Fields {
                parser: parent.parser(),
                depth: inside.depth(),
                identity: [version_element, named, digest],
                signature: [signature_algorithm_element, signature_element],
            },
            version,
            sid,
            digest_algorithm,
            signed_attributes,
            signature_algorithm,
            signature,
            signed_fields,
            unsigned_attributes,
            encoding: inside.encoding(),
            element: *element,
            faults: faults.into_owned(),
        })
    }

    /// Declared numeric version, independently of any retained mismatch.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }
    /// The document's signer identity CHOICE.
    #[must_use]
    pub fn sid(&self) -> &SignerIdentifier<'a> {
        &self.sid
    }
    /// Original digest inspection, including any parameter syntax fault.
    /// Only the reading's `identifier()` exposes a validated provider input.
    #[must_use]
    pub fn digest_algorithm(&self) -> &AlgorithmReading<'a> {
        &self.digest_algorithm
    }
    /// Original signed attributes, when present.
    #[must_use]
    pub fn signed_attributes(&self) -> Option<&Attributes<'a>> {
        self.signed_attributes.as_ref()
    }
    /// Original signature inspection, including any parameter syntax fault.
    /// A readable malformed algorithm is never a validated provider input.
    #[must_use]
    pub fn signature_algorithm(&self) -> &AlgorithmReading<'a> {
        &self.signature_algorithm
    }
    /// Logical signature octets without joining.
    #[must_use]
    pub fn signature(&self) -> &Octets<'a> {
        &self.signature
    }
    /// Original attributes outside the signature's coverage.
    #[must_use]
    pub fn unsigned_attributes(&self) -> Option<&Attributes<'a>> {
        self.unsigned_attributes.as_ref()
    }

    /// The original encodings of `version` through `signature`, in their order
    /// of appearance and without the unsigned attributes that follow them.
    #[must_use]
    pub fn signed_fields(&self) -> &'a [u8] {
        self.signed_fields
    }

    /// Reads direct unsigned countersignatures lazily through original provenance.
    /// Malformed values remain independent answers; resource refusal stops once.
    pub fn countersignatures_in<'s>(
        &'s self,
        parent: &'s Reader<'a>,
    ) -> crate::counter::Countersignatures<'s, 'a> {
        crate::counter::Countersignatures::new(self, parent)
    }
    /// Encoding contract of the envelope, not that of the signed attributes.
    #[must_use]
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
    /// Original signer range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.element.span()
    }
    /// Original whole element, including its index in the source container.
    ///
    /// This is not a global signer ordinal: nested counter values retain
    /// their own original container positions. Ranges use the producing
    /// reader's coordinates; joined-source projection remains with its source map.
    #[must_use]
    pub fn element(&self) -> &Element<'a> {
        &self.element
    }
    /// Retains the actual original field cursor context without retaining this
    /// movable parsed signer. Counter/PoE inputs can later decode fields under
    /// current Work without a new parser, guessed nesting depth or payload copy.
    #[must_use]
    pub fn fields_source(&self) -> FieldsSource<'a> {
        FieldsSource {
            parser: self.parser,
            data: self.element.contents(),
            base: self.element.contents_span().start,
            encoding: self.encoding,
            depth: self.depth,
            field: "signerInfo",
        }
    }
    /// Entire original encoding, including non-DER envelope spelling.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.element.as_bytes()
    }
    /// Retained document faults; resource refusals never enter this list.
    ///
    /// Registered CMS instance/placement violations are retained independently
    /// of certificate selection. Unknown generic attribute repetition is not
    /// a blanket fault; value syntax and context-specific binding stay separate.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }

    /// Parsed-field identity for duplicate recovery, not signature acceptance.
    ///
    /// BER outer headers and octet segmentation are ignored. Issuer names use
    /// the common PKIX equality rules; serial bytes, opaque parameters and
    /// attribute sets retain encoded identity. Two
    /// present NULL parameters compare by their parsed NULL value, so its
    /// root length spelling cannot create a different reading. Signed
    /// attributes therefore remain byte-identical. RFC5754 §2 SHA-2 digest
    /// absence/NULL defaults share the PKIX comparer; other algorithm defaults
    /// and selected-provider acceptance remain separate operations.
    pub fn same_value(&self, other: &SignerInfo<'_>, parent: &Reader<'_>) -> Result<bool> {
        if !self.same_fields(other, parent)? {
            return Ok(false);
        }
        // Resource refusal belongs to this duplicate query, not a prior
        // retained algorithm's location. Syntax/caller errors keep provenance.
        let comparison_error = |source| duplicate_comparison_error(source, other.span().start);
        // RFC5754 §2 requires SHA224/256/384/512 absent/NULL equivalence.
        // Written identity is checked first so identical opaque malformed
        // parameters remain inspectable, without claiming algorithm acceptance.
        // https://www.rfc-editor.org/rfc/rfc5754#section-2
        if !self
            .digest_algorithm
            .same_written_in(&other.digest_algorithm, parent)
            .map_err(comparison_error)?
        {
            let (Some(left), Some(right)) = (
                self.digest_algorithm.identifier(),
                other.digest_algorithm.identifier(),
            ) else {
                // Malformed parameters have only their original encoded
                // identity. They cannot acquire valid algorithm defaults.
                return Ok(false);
            };
            if !left
                .digest_matches_in(&right, parent)
                .map_err(comparison_error)?
            {
                return Ok(false);
            }
        }
        self.signature_algorithm
            .same_written_in(&other.signature_algorithm, parent)
            .map_err(comparison_error)
    }

    // Shared document-field identity for encoded and selected-provider paths.
    // Provider identities replace only algorithm comparison; original signed
    // octets and signature/SID value checks cannot be bypassed by either path.
    pub(crate) fn same_fields(&self, other: &SignerInfo<'_>, parent: &Reader<'_>) -> Result<bool> {
        let field = "signedData.signerInfos";
        let at = other.span().start;
        self.require_session(parent, field)?;
        other.require_session(parent, field)?;
        parent
            .execution()
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, field, at))?;
        if self.version != other.version {
            return Ok(false);
        }
        let same_sid = match (&self.sid, &other.sid) {
            (
                SignerIdentifier::IssuerAndSerial { issuer, serial },
                SignerIdentifier::IssuerAndSerial {
                    issuer: right,
                    serial: number,
                },
            ) => {
                // RFC5280 §7.1 names denote the same issuer after the shared
                // directory-string preparation; original signedAttrs stay exact.
                // https://www.rfc-editor.org/rfc/rfc5280#section-7.1
                issuer
                    .matches_in(right, parent)
                    .map_err(|source| duplicate_comparison_error(source, at))?
                    && same_bytes(parent, serial.as_bytes(), number.as_bytes(), field, at)?
            }
            (
                SignerIdentifier::SubjectKeyIdentifier(left),
                SignerIdentifier::SubjectKeyIdentifier(right),
            ) => left.same_value(right, parent, field, at)?,
            _ => false,
        };
        if !same_sid {
            return Ok(false);
        }
        for (left, right) in [
            (&self.signed_attributes, &other.signed_attributes),
            (&self.unsigned_attributes, &other.unsigned_attributes),
        ] {
            if !same_optional(
                parent,
                left.as_ref().map(|attrs| attrs.element().as_bytes()),
                right.as_ref().map(|attrs| attrs.element().as_bytes()),
                field,
                at,
            )? {
                return Ok(false);
            }
        }
        self.signature
            .same_value(&other.signature, parent, field, at)
    }
}

/// Original schema-selected CONTENTS with their producing field depth.
/// This small borrowed context survives a counter-walk frame's parsed model
/// and is also shared by CMS certificate/revocation field readers.
#[derive(Debug, Clone, Copy)]
pub struct FieldsSource<'d> {
    pub(crate) parser: &'d structured_asn1::Parser,
    pub(crate) data: &'d [u8],
    pub(crate) base: u64,
    pub(crate) encoding: Encoding,
    pub(crate) depth: u32,
    pub(crate) field: &'static str,
}
impl<'d> FieldsSource<'d> {
    // Called ONLY after the shared field kernel successfully entered this
    // actual container. Its checked enter establishes the exact +1 depth and
    // rules out overflow; this is not a fresh/default parser approximation.
    pub(crate) fn entered(parent: &Reader<'d>, element: Element<'d>, field: &'static str) -> Self {
        debug_assert!(element.tag().is_constructed());
        Self {
            parser: parent.parser(),
            data: element.contents(),
            base: element.contents_span().start,
            encoding: parent.encoding(),
            depth: parent.depth() + 1,
            field,
        }
    }
    /// Opens original fields, not a fabricated outer SEQUENCE. All current
    /// operation and original session/depth ceilings apply before decoding.
    pub fn reader_in<'operation, W: Work>(
        &self,
        work: &'operation W,
    ) -> Result<structured_asn1::ScopedReader<'d, 'operation>>
    where
        'd: 'operation,
    {
        work.read_scoped_source(self.parser, self.data, self.base, self.encoding, self.depth)
            .map_err(|cause| Error::encoding(cause, self.field))
    }
    /// Opens a producing-reader query for models retaining original source
    /// readers. Unlike a callback-local Work borrow, the query's source budget
    /// already has the document lifetime. Current operation funding and the
    /// actual original depth/session remain enforced by the SAME bridge.
    pub fn query_in<'query>(&self, operation: &Reader<'query>) -> Result<Reader<'query>>
    where
        'd: 'query,
    {
        self.parser
            .read_query_in(operation, self.data, self.base, self.encoding, self.depth)
            .map_err(|cause| Error::encoding(cause, self.field))
    }
    /// Original field octets, without a synthesized SEQUENCE header.
    #[must_use]
    pub fn as_bytes(self) -> &'d [u8] {
        self.data
    }
    /// Actual original field depth, not an outer-reader approximation.
    #[must_use]
    pub fn depth(self) -> u32 {
        self.depth
    }
}

fn read_attributes<'a, W: Work>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    placement: Placement,
    faults: &mut OwnedVec<Error, W>,
) -> Result<Attributes<'a>> {
    let reading = Attributes::read_inspection(parent, element, placement)?;
    if let Some(fault) = reading.fault() {
        let field = fault.field();
        let at = fault.offset();
        faults
            .try_push(fault)
            .map_err(|reason| Error::resource(reason, field, at))?;
    }
    reading.inspect_registered(parent, faults)?;
    Ok(reading)
}

fn read_algorithm<'a, W: Work>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
    faults: &mut OwnedVec<Error, W>,
) -> Result<AlgorithmReading<'a>> {
    // RFC5652 §5.3 carries an AlgorithmIdentifier in each slot. Retaining a
    // unique malformed parameter is inspection recovery, not conforming BER
    // or permission to resolve a cryptographic algorithm. PKIX owns that one
    // structural/parameter kernel; resources and ambiguous syntax still refuse.
    // https://www.rfc-editor.org/rfc/rfc5652#section-5.3
    let reading =
        structured_pkix::algorithm::read_inspection(parent, element, field).map_err(Error::pkix)?;
    if let Some(fault) = reading.fault() {
        faults
            .try_push(Error::pkix(fault.clone()))
            .map_err(|reason| Error::resource(reason, fault.field(), fault.offset()))?;
    }
    Ok(reading)
}

fn duplicate_comparison_error(source: structured_pkix::Error, at: u64) -> Error {
    if source.is_resource() {
        Error::pkix(structured_pkix::Error::new(
            source.code(),
            "signedData.signerInfos",
            at,
        ))
    } else {
        Error::pkix(source)
    }
}

// The fields are consecutive members of the signer, so they are one range of
// its own encoding: no element starts before the first or ends after the last.
fn field_range<'a>(signer: &Element<'a>, first: &Element<'a>, last: &Element<'a>) -> &'a [u8] {
    let origin = signer.span().start;
    let start = first.span().start - origin;
    let end = last.span().start + last.span().length - origin;
    let bytes = signer.as_bytes();
    // Both members lie inside the signer, whose encoding holds every offset.
    let start = usize::try_from(start).expect("member offset fits the signer encoding");
    let end = usize::try_from(end).expect("member end fits the signer encoding");
    &bytes[start..end]
}

pub(crate) fn required<'a>(
    reader: &mut ScopedReader<'a, '_>,
    field: &'static str,
) -> Result<Element<'a>> {
    reader
        .next_element()
        .map_err(|error| Error::encoding(error, field))?
        .ok_or_else(|| Error::schema(ErrorCode::MissingField, field, reader.offset()))
}

fn same_bytes(
    parent: &Reader<'_>,
    left: &[u8],
    right: &[u8],
    field: &'static str,
    at: u64,
) -> Result<bool> {
    let execution = parent.execution();
    execution
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, field, at))?;
    if left.len() != right.len() {
        return Ok(false);
    }
    execution
        .charge_work(left.len() as u64)
        .map_err(|reason| Error::resource(reason, field, at))?;
    Ok(left == right)
}

fn same_optional(
    parent: &Reader<'_>,
    left: Option<&[u8]>,
    right: Option<&[u8]>,
    field: &'static str,
    at: u64,
) -> Result<bool> {
    parent
        .execution()
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, field, at))?;
    match (left, right) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => same_bytes(parent, left, right, field, at),
        _ => Ok(false),
    }
}
