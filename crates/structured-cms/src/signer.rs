//! Original signer identities, algorithms, attributes and signature ranges.

use crate::attribute::{Attributes, Placement};
use crate::{Error, ErrorCode, Octets, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Integer, Reader, Span, Tag, universal};
use structured_pkix::{AlgorithmIdentifier, Name};

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
        const FIELD: &str = "signerInfo.sid";
        if element.tag() == Tag::context(false, 0) || element.tag() == Tag::context(true, 0) {
            return Octets::read_identifier(parent, element, FIELD).map(Self::SubjectKeyIdentifier);
        }
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
        let name = inside
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|error| Error::encoding(error, FIELD))?;
        let issuer = structured_pkix::name::read(&inside, &name, FIELD).map_err(Error::pkix)?;
        let serial = inside
            .read_integer()
            .map_err(|error| Error::encoding(error, FIELD))?;
        if !inside.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                FIELD,
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

/// One parsed CMS signer, retaining original byte identity and diagnostic storage.
#[derive(Debug)]
pub struct SignerInfo<'a> {
    version: u64,
    sid: SignerIdentifier<'a>,
    digest_algorithm: AlgorithmIdentifier<'a>,
    signed_attributes: Option<Attributes<'a>>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: Octets<'a>,
    unsigned_attributes: Option<Attributes<'a>>,
    encoding: Encoding,
    element: Element<'a>,
    faults: OwnedVec<Error>,
}

impl<'a> SignerInfo<'a> {
    pub(crate) fn require_session(&self, parent: &Reader<'_>, field: &'static str) -> Result<()> {
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
            structured_pkix::algorithm::read(&inside, &digest, "signerInfo.digestAlgorithm")
                .map_err(Error::pkix)?;
        let mut next = required(&mut inside, "signerInfo.signatureAlgorithm")?;
        let signed_attributes = if next.tag() == Tag::context(true, 0) {
            let attributes = Attributes::read(&inside, &next, Placement::Signed)?;
            next = required(&mut inside, "signerInfo.signatureAlgorithm")?;
            Some(attributes)
        } else {
            None
        };
        let signature_algorithm =
            structured_pkix::algorithm::read(&inside, &next, "signerInfo.signatureAlgorithm")
                .map_err(Error::pkix)?;
        let signature_element = required(&mut inside, "signerInfo.signature")?;
        let signature = Octets::read(&inside, &signature_element, "signerInfo.signature")?;
        let unsigned_attributes = match inside
            .next_element()
            .map_err(|error| Error::encoding(error, "signerInfo.unsignedAttrs"))?
        {
            Some(attributes) => Some(Attributes::read(&inside, &attributes, Placement::Unsigned)?),
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
            version,
            sid,
            digest_algorithm,
            signed_attributes,
            signature_algorithm,
            signature,
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
    /// Original digest algorithm and opaque parameters.
    #[must_use]
    pub fn digest_algorithm(&self) -> AlgorithmIdentifier<'a> {
        self.digest_algorithm
    }
    /// Original signed attributes, when present.
    #[must_use]
    pub fn signed_attributes(&self) -> Option<&Attributes<'a>> {
        self.signed_attributes.as_ref()
    }
    /// Original signature algorithm and opaque parameters.
    #[must_use]
    pub fn signature_algorithm(&self) -> AlgorithmIdentifier<'a> {
        self.signature_algorithm
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
    /// Entire original encoding, including non-DER envelope spelling.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.element.as_bytes()
    }
    /// Retained document faults; resource refusals never enter this list.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }

    /// Narrow parsed-field identity for duplicate recovery, not PKIX equivalence.
    ///
    /// BER outer headers and octet segmentation are ignored. Issuer/serial,
    /// opaque parameters and attribute sets retain encoded identity. Two
    /// present NULL parameters compare by their parsed NULL value, so its
    /// root length spelling cannot create a different reading. Signed
    /// attributes therefore remain byte-identical. No algorithm defaults are
    /// inferred; selected-provider comparison is a separate operation.
    pub fn same_value(&self, other: &SignerInfo<'_>, parent: &Reader<'_>) -> Result<bool> {
        if !self.same_fields(other, parent)? {
            return Ok(false);
        }
        let field = "signedData.signerInfos";
        let at = other.span().start;
        for (left, right) in [
            (self.digest_algorithm, other.digest_algorithm),
            (self.signature_algorithm, other.signature_algorithm),
        ] {
            if !same_bytes(
                parent,
                left.algorithm().as_bytes(),
                right.algorithm().as_bytes(),
                field,
                at,
            )? || !same_parameters(parent, left, right, field, at)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    // Shared document-field identity for encoded and selected-provider paths.
    // Provider identities replace only algorithm comparison; original signed
    // octets and signature/SID value checks cannot be bypassed by either path.
    pub(crate) fn same_fields(&self, other: &SignerInfo<'_>, parent: &Reader<'_>) -> Result<bool> {
        let field = "signedData.signerInfos";
        let at = other.span().start;
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
                same_bytes(parent, issuer.as_bytes(), right.as_bytes(), field, at)?
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

fn same_parameters(
    parent: &Reader<'_>,
    left: AlgorithmIdentifier<'_>,
    right: AlgorithmIdentifier<'_>,
    field: &'static str,
    at: u64,
) -> Result<bool> {
    let execution = parent.execution();
    execution
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, field, at))?;
    let (Some(left_bytes), Some(right_bytes)) = (left.parameters(), right.parameters()) else {
        return Ok(left.parameters().is_none() && right.parameters().is_none());
    };
    if same_bytes(parent, left_bytes, right_bytes, field, at)? {
        return Ok(true);
    }
    // X.690 §8.1.3.3 permits different BER length spellings for the same
    // NULL value. Use the shared primitive reader after checking its tag,
    // rather than a byte grammar or a replacement parser. This neither
    // equates absent with NULL nor normalizes unknown opaque parameters or
    // algorithm-specific defaults; those remain
    // the selected provider's semantic comparison responsibility.
    // https://www.itu.int/rec/T-REC-X.690-202102-I/en
    let mut left_reader = left
        .parameters_reader_in(parent, field)
        .map_err(Error::pkix)?
        .ok_or_else(|| Error::schema(ErrorCode::MissingField, field, left.offset()))?;
    let mut right_reader = right
        .parameters_reader_in(parent, field)
        .map_err(Error::pkix)?
        .ok_or_else(|| Error::schema(ErrorCode::MissingField, field, right.offset()))?;
    let left_value = required(&mut left_reader, field)?;
    let right_value = required(&mut right_reader, field)?;
    execution
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, field, at))?;
    if left_value.tag() != Tag::primitive(universal::NULL)
        || right_value.tag() != Tag::primitive(universal::NULL)
    {
        return Ok(false);
    }
    left_reader
        .null(&left_value)
        .map_err(|error| Error::encoding(error, field))?;
    right_reader
        .null(&right_value)
        .map_err(|error| Error::encoding(error, field))?;
    Ok(true)
}

pub(crate) fn required<'a>(reader: &mut Reader<'a>, field: &'static str) -> Result<Element<'a>> {
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
