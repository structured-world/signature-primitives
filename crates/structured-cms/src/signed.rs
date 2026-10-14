//! `SignedData` catalogues and version facts, without application trust decisions.

use crate::content::{ContentInfo, Encapsulated};
use crate::signer::{SignerInfo, required};
use crate::{Error, ErrorCode, Result, oid};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Parser, Reader, Span, Tag, universal};
use structured_pkix::{AlgorithmIdentifier, Certificate};

/// One original certificate CHOICE (RFC5652 §10.2.2).
///
/// X.509 values live in one flat accounted catalogue, avoiding one Box
/// allocation per certificate and avoiding a large enum slot for opaque kinds.
#[derive(Debug, Clone, Copy)]
pub enum CertificateChoice<'a> {
    /// Index into this message's [`SignedData::certificates`] catalogue.
    X509(usize),
    /// Obsolete PKCS6 extended certificate, preserved without interpreting it.
    Extended(Element<'a>),
    /// Obsolete version-1 attribute certificate, preserved as encoded.
    AttributeV1(Element<'a>),
    /// Version-2 attribute certificate, preserved as encoded.
    AttributeV2(Element<'a>),
    /// Other format with its original format identifier and value.
    Other(Element<'a>),
}

/// Original CMS `SignedData` with independently accounted metadata and faults.
#[derive(Debug)]
pub struct SignedData<'a> {
    version: u64,
    required_version: u64,
    algorithms: OwnedVec<AlgorithmIdentifier<'a>>,
    content: Encapsulated<'a>,
    choices: OwnedVec<CertificateChoice<'a>>,
    certificates: OwnedVec<Certificate<'a>>,
    certificate_field: Option<Span>,
    revocations: OwnedVec<Element<'a>>,
    revocation_field: Option<Span>,
    signers: OwnedVec<SignerInfo<'a>>,
    faults: OwnedVec<Error>,
    element: Element<'a>,
}

impl<'a> SignedData<'a> {
    /// Reads one entire CMS `ContentInfo` and its `SignedData` using the same parser.
    pub fn read(parser: &'a Parser, encoded: &'a [u8], base: u64) -> Result<Self> {
        let mut root = parser
            .read(encoded, base)
            .map_err(|error| Error::encoding(error, "contentInfo"))?;
        let (envelope, parent) = ContentInfo::read(&mut root)?;
        parent
            .execution()
            .charge_work(envelope.kind().as_bytes().len() as u64)
            .map_err(|reason| {
                Error::resource(reason, "contentInfo.contentType", envelope.span().start)
            })?;
        if envelope.kind() != oid::SIGNED_DATA {
            return Err(Error::schema(
                ErrorCode::UnexpectedContentType,
                "contentInfo.contentType",
                envelope.span().start,
            ));
        }
        Self::read_element(&parent, envelope.content())
    }

    /// Reads an original embedded `SignedData`, preserving enclosing depth/work.
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        const FIELD: &str = "signedData";
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
        let (version, version_element) = read_version(&mut inside)?;
        let set = required(&mut inside, "signedData.digestAlgorithms")?;
        let algorithms = catalogue(
            &inside,
            &set,
            Tag::constructed(universal::SET),
            "signedData.digestAlgorithms",
            |members, entry| {
                structured_pkix::algorithm::read(members, entry, "signedData.digestAlgorithms")
                    .map_err(Error::pkix)
            },
        )?;
        let content_element = required(&mut inside, "signedData.encapContentInfo")?;
        let content = Encapsulated::read(&inside, &content_element)?;
        execution
            .charge_work(content.kind().as_bytes().len() as u64)
            .map_err(|reason| {
                Error::resource(
                    reason,
                    "signedData.encapContentInfo.eContentType",
                    content.span().start,
                )
            })?;
        // RFC5652 §5.1 ladder, computed during the admitted schema traversal:
        // 5 (other), 4 (v2 AC), 3 (v1 AC/v3 signer/non-data), otherwise 1.
        // https://www.rfc-editor.org/rfc/rfc5652#section-5.1
        let mut required_version = if content.kind() == oid::DATA { 1 } else { 3 };
        let mut choices = parent.memory().vector();
        let mut certificates = parent.memory().vector();
        let mut revocations = parent.memory().vector();
        let mut certificate_field = None;
        let mut revocation_field = None;
        let mut next = required(&mut inside, "signedData.signerInfos")?;
        if next.tag() == Tag::context(true, 0) {
            certificate_field = Some(next.span());
            (choices, certificates) = read_certificates(&inside, &next, &mut required_version)?;
            next = required(&mut inside, "signedData.signerInfos")?;
        }
        if next.tag() == Tag::context(true, 1) {
            revocation_field = Some(next.span());
            revocations = read_revocations(&inside, &next, &mut required_version)?;
            next = required(&mut inside, "signedData.signerInfos")?;
        }
        let signers = catalogue(
            &inside,
            &next,
            Tag::constructed(universal::SET),
            "signedData.signerInfos",
            |members, entry| {
                let signer = SignerInfo::read(members, entry)?;
                if signer.version() == 3 {
                    required_version = required_version.max(3);
                }
                Ok(signer)
            },
        )?;
        if !inside.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                FIELD,
                inside.offset(),
            ));
        }
        let mut faults = execution.vector();
        if version != required_version {
            faults
                .try_push(Error::schema(
                    ErrorCode::VersionMismatch,
                    "signedData.version",
                    version_element.span().start,
                ))
                .map_err(|reason| {
                    Error::resource(reason, "signedData.version", version_element.span().start)
                })?;
        }
        Ok(Self {
            version,
            required_version,
            algorithms,
            content,
            choices,
            certificates,
            certificate_field,
            revocations,
            revocation_field,
            signers,
            faults: faults.into_owned(),
            element: *element,
        })
    }

    /// Declared version.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }
    /// Version independently required by the encoded choices.
    #[must_use]
    pub fn required_version(&self) -> u64 {
        self.required_version
    }
    /// Original advertised digest algorithms; provider resolution is separate.
    #[must_use]
    pub fn digest_algorithms(&self) -> &[AlgorithmIdentifier<'a>] {
        &self.algorithms
    }
    /// Original attached or absent content.
    #[must_use]
    pub fn content(&self) -> &Encapsulated<'a> {
        &self.content
    }
    /// Certificate choices in their original order.
    #[must_use]
    pub fn certificate_choices(&self) -> &[CertificateChoice<'a>] {
        &self.choices
    }
    /// Parsed X.509 certificates, in the order referenced by X509 choices.
    #[must_use]
    pub fn certificates(&self) -> &[Certificate<'a>] {
        &self.certificates
    }
    /// Original presence of the certificate field, including an empty written set.
    #[must_use]
    pub fn certificate_field(&self) -> Option<Span> {
        self.certificate_field
    }
    /// Original presence of the revocation field, including an empty written set.
    #[must_use]
    pub fn revocation_field(&self) -> Option<Span> {
        self.revocation_field
    }
    /// Original revocation choices, not implicitly authenticated or fetched.
    #[must_use]
    pub fn revocations(&self) -> &[Element<'a>] {
        &self.revocations
    }
    /// Independent signers in their original order, without an all-signers verdict.
    #[must_use]
    pub fn signers(&self) -> &[SignerInfo<'a>] {
        &self.signers
    }
    /// Readable document faults, retaining their allocation lifetime.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }
    /// Original `SignedData` source range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.element.span()
    }
    /// Original encoding without serialization.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.element.as_bytes()
    }
}

fn ordered<'a>(
    parent: &Reader<'a>,
    previous: &mut Option<&'a [u8]>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<()> {
    if parent.encoding().is_der() {
        if let Some(earlier) = *previous
            && !structured_pkix::der::set_ordered(parent, earlier, element, field)
                .map_err(Error::pkix)?
        {
            return Err(Error::schema(
                ErrorCode::SetOrder,
                field,
                element.span().start,
            ));
        }
        *previous = Some(element.as_bytes());
    }
    Ok(())
}

fn other_format(parent: &Reader<'_>, element: &Element<'_>, field: &'static str) -> Result<()> {
    let mut inside = parent
        .enter(element)
        .map_err(|error| Error::encoding(error, field))?;
    inside
        .read_oid()
        .map_err(|error| Error::encoding(error, field))?;
    required(&mut inside, field)?;
    if !inside.is_empty() {
        return Err(Error::schema(
            ErrorCode::TrailingData,
            field,
            inside.offset(),
        ));
    }
    Ok(())
}

fn catalogue<'a, T>(
    parent: &Reader<'a>,
    set: &Element<'a>,
    tag: Tag,
    field: &'static str,
    mut read: impl FnMut(&Reader<'a>, &Element<'a>) -> Result<T>,
) -> Result<OwnedVec<T>> {
    if set.tag() != tag {
        return Err(Error::schema(
            ErrorCode::UnexpectedTag,
            field,
            set.span().start,
        ));
    }
    let mut members = parent
        .enter(set)
        .map_err(|error| Error::encoding(error, field))?;
    let execution = parent.execution();
    let mut values = execution.vector();
    let mut previous = None;
    while let Some(entry) = members
        .next_element()
        .map_err(|error| Error::encoding(error, field))?
    {
        ordered(&members, &mut previous, &entry, field)?;
        values
            .try_reserve(1)
            .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
        let value = read(&members, &entry)?;
        values
            .try_push(value)
            .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
    }
    Ok(values.into_owned())
}

fn read_certificates<'a>(
    parent: &Reader<'a>,
    set: &Element<'a>,
    version: &mut u64,
) -> Result<(OwnedVec<CertificateChoice<'a>>, OwnedVec<Certificate<'a>>)> {
    const FIELD: &str = "signedData.certificates";
    let execution = parent.execution();
    let mut certificates = execution.vector();
    let choices = catalogue(
        parent,
        set,
        Tag::context(true, 0),
        FIELD,
        |members, entry| {
            Ok(match entry.tag() {
                tag if tag == Tag::constructed(universal::SEQUENCE) => {
                    certificates
                        .try_reserve(1)
                        .map_err(|reason| Error::resource(reason, FIELD, entry.span().start))?;
                    let certificate =
                        Certificate::read_element(members, entry).map_err(Error::pkix)?;
                    let index = certificates.len();
                    certificates
                        .try_push(certificate)
                        .map_err(|reason| Error::resource(reason, FIELD, entry.span().start))?;
                    CertificateChoice::X509(index)
                }
                tag if tag == Tag::context(true, 0) => CertificateChoice::Extended(*entry),
                tag if tag == Tag::context(true, 1) => {
                    *version = (*version).max(3);
                    CertificateChoice::AttributeV1(*entry)
                }
                tag if tag == Tag::context(true, 2) => {
                    *version = (*version).max(4);
                    CertificateChoice::AttributeV2(*entry)
                }
                tag if tag == Tag::context(true, 3) => {
                    other_format(members, entry, FIELD)?;
                    *version = 5;
                    CertificateChoice::Other(*entry)
                }
                _ => {
                    return Err(Error::schema(
                        ErrorCode::UnexpectedTag,
                        FIELD,
                        entry.span().start,
                    ));
                }
            })
        },
    )?;
    Ok((choices, certificates.into_owned()))
}

fn read_version<'a>(inside: &mut Reader<'a>) -> Result<(u64, Element<'a>)> {
    const FIELD: &str = "signedData.version";
    let element = inside
        .expect(Tag::primitive(universal::INTEGER))
        .map_err(|error| Error::encoding(error, FIELD))?;
    let version = inside
        .integer(&element)
        .map_err(|error| Error::encoding(error, FIELD))?
        .as_u64()
        .ok_or_else(|| Error::schema(ErrorCode::ValueTooLarge, FIELD, element.span().start))?;
    Ok((version, element))
}

fn read_revocations<'a>(
    parent: &Reader<'a>,
    set: &Element<'a>,
    version: &mut u64,
) -> Result<OwnedVec<Element<'a>>> {
    const FIELD: &str = "signedData.crls";
    catalogue(
        parent,
        set,
        Tag::context(true, 1),
        FIELD,
        |members, entry| {
            if entry.tag() == Tag::context(true, 1) {
                other_format(members, entry, FIELD)?;
                *version = 5;
            } else if entry.tag() != Tag::constructed(universal::SEQUENCE) {
                return Err(Error::schema(
                    ErrorCode::UnexpectedTag,
                    FIELD,
                    entry.span().start,
                ));
            }
            Ok(*entry)
        },
    )
}
