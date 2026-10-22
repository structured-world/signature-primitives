//! `SignedData` catalogues and version facts, without application trust decisions.

use crate::content::{ContentInfo, Encapsulated};
use crate::signer::{SignerInfo, required};
use crate::{Error, ErrorCode, Result, oid};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Oid, Parser, Reader, Span, Tag, universal};
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

/// Original CMS other-revocation format and its untouched ANY value. Decoding
/// a recognized format establishes no signature, authorization or freshness.
#[derive(Debug)]
pub struct OtherRevocationInfo<'a> {
    reader: Reader<'a>,
    kind: Oid<'a>,
    value: Element<'a>,
}

impl<'a> OtherRevocationInfo<'a> {
    /// Reads an original context \[1\] IMPLICIT `OtherRevocationInfoFormat` using
    /// the same field kernel as `SignedData`'s structural catalogue validation.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        const FIELD: &str = "signedData.crls.other";
        if element.tag() != Tag::context(true, 1) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                FIELD,
                element.span().start,
            ));
        }
        let (reader, kind, value) = other_fields(parent, element, FIELD)?;
        Ok(Self {
            reader,
            kind,
            value,
        })
    }

    /// Original open-format identifier, without provider/default normalization.
    #[must_use]
    pub fn kind(&self) -> Oid<'a> {
        self.kind
    }

    /// Whole original ANY element, not its contents or a re-encoded value.
    #[must_use]
    pub fn value(&self) -> Element<'a> {
        self.value
    }

    /// Decodes the successful whole `OCSPResponse` required by RFC5940 §3.
    /// An unknown format returns None; a known malformed response or unsigned
    /// protocol failure returns an error. Unsupported inner response syntax is
    /// preserved by the shared envelope, rather than promoted to a basic body.
    /// <https://www.rfc-editor.org/rfc/rfc5940#section-3>
    pub fn ocsp(self) -> Result<Option<structured_pkix::ocsp::ResponseBytes<'a>>> {
        const FIELD: &str = "signedData.crls.other";
        self.reader
            .charge(9)
            .map_err(|error| Error::encoding(error, FIELD))?;
        if self.kind != oid::OCSP_RESPONSE {
            return Ok(None);
        }
        match structured_pkix::ocsp::Response::read_element(&self.reader, &self.value)
            .map_err(Error::pkix)?
        {
            structured_pkix::ocsp::Response::Successful(response) => Ok(Some(response)),
            structured_pkix::ocsp::Response::Failure { span, .. } => {
                Err(Error::schema(ErrorCode::MalformedValue, FIELD, span.start))
            }
        }
    }
}

/// Original CMS `SignedData` with independently accounted metadata and faults.
#[derive(Debug)]
pub struct SignedData<'a> {
    parser: &'a Parser,
    encoding: Encoding,
    outer: u32,
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
            (choices, certificates) = read_certificates(
                &inside,
                &next,
                &mut required_version,
                "signedData.certificates",
            )?;
            next = required(&mut inside, "signedData.signerInfos")?;
        }
        if next.tag() == Tag::context(true, 1) {
            revocation_field = Some(next.span());
            revocations =
                read_revocations(&inside, &next, &mut required_version, "signedData.crls")?;
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
        let faults = version_fault(&execution, version, required_version, &version_element)?;
        Ok(Self {
            parser: parent.parser(),
            encoding: parent.encoding(),
            outer: inside.depth(),
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
            faults,
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
    /// RFC5652 §§5.1, 5.3 permit zero entries and do not require recipients to
    /// refuse an unlisted signer digest. These advertisements never replace the
    /// original signer algorithm; stricter catalogue acceptance is caller policy.
    /// <https://www.rfc-editor.org/rfc/rfc5652#section-5.1>
    #[must_use]
    pub fn digest_algorithms(&self) -> &[AlgorithmIdentifier<'a>] {
        &self.algorithms
    }
    /// Original attached or absent content.
    #[must_use]
    pub fn content(&self) -> &Encapsulated<'a> {
        &self.content
    }
    /// Whole original `encapContentInfo` TLV, including BER framing/EOC.
    /// No element is reopened, normalized or copied. Historical archive inputs
    /// distinguish this from the logical eContent octets (RFC5126 §6.4.1).
    #[must_use]
    pub fn encap_content_encoding(&self) -> &'a [u8] {
        self.field_encoding(self.content.span())
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
    /// Whole original optional certificate field, including its context tag.
    /// An absent field differs from a written empty set; bytes are borrowed.
    #[must_use]
    pub fn certificate_encoding(&self) -> Option<&'a [u8]> {
        self.certificate_field.map(|span| self.field_encoding(span))
    }
    /// Opens an original non-X.509 certificate CHOICE under the current query.
    ///
    /// Preserves the original parser, encoding, location and certificate-set
    /// depth. The current operation funds new work while original ceilings
    /// remain active. An absent ordinal or X.509 index returns `None` after
    /// metadata admission; parsed X.509 certificates have their own accessors.
    /// No certificate is implicitly trusted or decoded by opening this reader.
    pub fn certificate_choice_reader_in<'query>(
        &self,
        query: &Reader<'query>,
        ordinal: usize,
    ) -> Result<Option<Reader<'query>>>
    where
        'a: 'query,
    {
        const FIELD: &str = "signedData.certificates";
        let at = self.certificate_field.unwrap_or(self.element.span()).start;
        query
            .execution()
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, at))?;
        let entry = match self.choices.get(ordinal) {
            Some(
                CertificateChoice::Extended(entry)
                | CertificateChoice::AttributeV1(entry)
                | CertificateChoice::AttributeV2(entry)
                | CertificateChoice::Other(entry),
            ) => entry,
            Some(CertificateChoice::X509(_)) | None => return Ok(None),
        };
        self.parser
            .read_nested_query_in(
                query,
                entry.as_bytes(),
                entry.span().start,
                self.encoding,
                self.outer,
            )
            .map(Some)
            .map_err(|error| Error::encoding(error, FIELD))
    }
    /// Original presence of the revocation field, including an empty written set.
    #[must_use]
    pub fn revocation_field(&self) -> Option<Span> {
        self.revocation_field
    }
    /// Whole original optional revocation field, not assembled member bytes.
    #[must_use]
    pub fn revocation_encoding(&self) -> Option<&'a [u8]> {
        self.revocation_field.map(|span| self.field_encoding(span))
    }
    /// Original revocation choices, not implicitly authenticated or fetched.
    #[must_use]
    pub fn revocations(&self) -> &[Element<'a>] {
        &self.revocations
    }
    /// Opens one original revocation CHOICE under the current query operation.
    ///
    /// The reader contains the whole original CRL or other-format CHOICE, not
    /// its contents. Original parser, encoding, location and set-member depth
    /// are preserved; the query may come from another document and pays all
    /// new work/storage while both source and operation ceilings remain active.
    /// No bytes are copied and no new parser or authentication is introduced.
    /// An absent ordinal returns `None` only after paid metadata admission.
    pub fn revocation_reader_in<'query>(
        &self,
        query: &Reader<'query>,
        ordinal: usize,
    ) -> Result<Option<Reader<'query>>>
    where
        'a: 'query,
    {
        const FIELD: &str = "signedData.crls";
        let at = self.revocation_field.unwrap_or(self.element.span()).start;
        query
            .execution()
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, at))?;
        let Some(entry) = self.revocations.get(ordinal) else {
            return Ok(None);
        };
        self.parser
            .read_nested_query_in(
                query,
                entry.as_bytes(),
                entry.span().start,
                self.encoding,
                self.outer,
            )
            .map(Some)
            .map_err(|error| Error::encoding(error, FIELD))
    }
    /// Independent signers in their original order, without an all-signers verdict.
    #[must_use]
    pub fn signers(&self) -> &[SignerInfo<'a>] {
        &self.signers
    }
    /// Refuses a reader of another parser session.
    pub fn require_session(&self, parent: &Reader<'_>, field: &'static str) -> Result<()> {
        if !core::ptr::eq(self.parser, parent.parser()) {
            return Err(Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                field,
                self.element.span().start,
            )));
        }
        Ok(())
    }
    /// Refuses a `SignerInfo` that is not one of these signers, by identity.
    ///
    /// Constant work: a reference to one of these signers lies inside their
    /// storage, so an address range test replaces a scan of every signer.
    pub fn require_signer(&self, signer: &SignerInfo<'_>, field: &'static str) -> Result<()> {
        let storage = self.signers.as_ptr_range();
        let address = core::ptr::from_ref(signer).cast::<SignerInfo<'a>>();
        if !storage.contains(&address) {
            return Err(Error::schema(
                ErrorCode::InvalidLocation,
                field,
                signer.span().start,
            ));
        }
        Ok(())
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

    fn field_encoding(&self, span: Span) -> &'a [u8] {
        // Each saved field was produced inside this exact element. Its
        // differences therefore fit the borrowed encoding's usize length.
        let start = usize::try_from(span.start - self.element.span().start)
            .expect("original field starts inside SignedData");
        let length = usize::try_from(span.length).expect("original field length fits SignedData");
        &self.element.as_bytes()[start..start + length]
    }
}

fn version_fault(
    execution: &impl Work,
    version: u64,
    required: u64,
    element: &Element<'_>,
) -> Result<OwnedVec<Error>> {
    let mut faults = execution.vector();
    if version != required {
        faults
            .try_push(Error::schema(
                ErrorCode::VersionMismatch,
                "signedData.version",
                element.span().start,
            ))
            .map_err(|reason| {
                Error::resource(reason, "signedData.version", element.span().start)
            })?;
    }
    Ok(faults.into_owned())
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
    other_fields(parent, element, field).map(|_| ())
}

fn other_fields<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<(Reader<'a>, Oid<'a>, Element<'a>)> {
    let mut inside = parent
        .enter(element)
        .map_err(|error| Error::encoding(error, field))?;
    let kind = inside
        .read_oid()
        .map_err(|error| Error::encoding(error, field))?;
    let value = required(&mut inside, field)?;
    if !inside.is_empty() {
        return Err(Error::schema(
            ErrorCode::TrailingData,
            field,
            inside.offset(),
        ));
    }
    Ok((inside, kind, value))
}

pub(crate) fn catalogue<'a, T>(
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

pub(crate) fn read_certificates<'a>(
    parent: &Reader<'a>,
    set: &Element<'a>,
    version: &mut u64,
    field: &'static str,
) -> Result<(OwnedVec<CertificateChoice<'a>>, OwnedVec<Certificate<'a>>)> {
    let execution = parent.execution();
    let mut certificates = execution.vector();
    let choices = catalogue(
        parent,
        set,
        Tag::context(true, 0),
        field,
        |members, entry| {
            Ok(match entry.tag() {
                tag if tag == Tag::constructed(universal::SEQUENCE) => {
                    certificates
                        .try_reserve(1)
                        .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
                    let certificate =
                        Certificate::read_element(members, entry).map_err(Error::pkix)?;
                    let index = certificates.len();
                    certificates
                        .try_push(certificate)
                        .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
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
                    other_format(members, entry, field)?;
                    *version = 5;
                    CertificateChoice::Other(*entry)
                }
                _ => {
                    return Err(Error::schema(
                        ErrorCode::UnexpectedTag,
                        field,
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

pub(crate) fn read_revocations<'a>(
    parent: &Reader<'a>,
    set: &Element<'a>,
    version: &mut u64,
    field: &'static str,
) -> Result<OwnedVec<Element<'a>>> {
    catalogue(
        parent,
        set,
        Tag::context(true, 1),
        field,
        |members, entry| {
            if entry.tag() == Tag::context(true, 1) {
                other_format(members, entry, field)?;
                *version = 5;
            } else if entry.tag() != Tag::constructed(universal::SEQUENCE) {
                return Err(Error::schema(
                    ErrorCode::UnexpectedTag,
                    field,
                    entry.span().start,
                ));
            }
            Ok(*entry)
        },
    )
}
