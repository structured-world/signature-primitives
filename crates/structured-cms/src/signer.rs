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
            && !self
                .digest_algorithm
                .digest_matches_in(&other.digest_algorithm, parent)
                .map_err(comparison_error)?
        {
            return Ok(false);
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
