//! Borrowed CMS digital envelopes, with explicit provider/key selection.
//!
//! RFC5652 §§6.1–6.4 define this schema, not a cryptographic implementation.
//! Reading never unwraps a key, decrypts content or trusts originator material.
//! Every original algorithm and encrypted fragment remains available to the
//! selected provider. Unsupported algorithms/ORI formats remain its capability
//! result; malformed structures and resources remain processing refusals.
//! <https://www.rfc-editor.org/rfc/rfc5652#section-6>

use crate::signed::{CertificateChoice, catalogue, read_certificates, read_revocations};
use crate::{
    ContentInfo, Error, ErrorCode, Octets, Result, attribute::Attribute, signer::required,
};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Oid, Parser, Reader, Tag, universal};
use structured_pkix::{AlgorithmIdentifier, Certificate};

mod recipient;
pub use recipient::{AgreementIdentifier, KeyIdentifier, Originator, Recipient, RecipientKey};

/// CMS id-envelopedData, RFC5652 §6.1.
pub const IDENTIFIER: Oid<'static> = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 7, 3]);
const FIELD: &str = "envelopedData";

/// Original open field with its actual decoding position. A selected format
/// owner can read it without reconstructing the envelope grammar or resetting
/// depth, encoding, source work or the current operation.
#[derive(Debug, Clone, Copy)]
pub struct EncodedValue<'a> {
    element: Element<'a>,
    parser: &'a Parser,
    encoding: Encoding,
    depth: u32,
}
impl<'a> EncodedValue<'a> {
    fn new(parent: &Reader<'a>, element: Element<'a>) -> Self {
        Self {
            element,
            parser: parent.parser(),
            encoding: parent.encoding(),
            depth: parent.depth(),
        }
    }
    /// Whole original element, including its physical source span.
    #[must_use]
    pub fn element(&self) -> &Element<'a> {
        &self.element
    }
    /// Read the whole original field under original/current ceilings. The
    /// cursor includes its header and retains the exact producing depth.
    pub fn reader_in<'op>(&self, query: &Reader<'op>) -> Result<Reader<'op>>
    where
        'a: 'op,
    {
        self.parser
            .read_query_in(
                query,
                self.element.as_bytes(),
                self.element.span().start,
                self.encoding,
                self.depth,
            )
            .map_err(|e| Error::encoding(e, FIELD))
    }
}

/// Original optional originator material, neither trusted nor authenticated.
#[derive(Debug)]
pub struct OriginatorInfo<'a> {
    parser: &'a Parser,
    encoding: Encoding,
    outer: u32,
    at: u64,
    choices: OwnedVec<CertificateChoice<'a>>,
    certificates: OwnedVec<Certificate<'a>>,
    revocations: OwnedVec<Element<'a>>,
}

impl<'a> OriginatorInfo<'a> {
    /// Original certificate alternatives; X509 ordinals index `certificates`.
    #[must_use]
    pub fn choices(&self) -> &[CertificateChoice<'a>] {
        &self.choices
    }
    /// Original public-key certificates, using the shared `SignedData` kernel.
    #[must_use]
    pub fn certificates(&self) -> &[Certificate<'a>] {
        &self.certificates
    }
    /// Original whole CRL/other alternatives, not implicitly authenticated.
    #[must_use]
    pub fn revocations(&self) -> &[Element<'a>] {
        &self.revocations
    }
    /// Reopen a retained non-X509 certificate alternative at its actual source
    /// depth under current/original ceilings. Parsed X509 entries return None.
    pub fn certificate_reader_in<'op>(
        &self,
        query: &Reader<'op>,
        ordinal: usize,
    ) -> Result<Option<Reader<'op>>>
    where
        'a: 'op,
    {
        self.admit(query)?;
        let Some(
            CertificateChoice::Extended(entry)
            | CertificateChoice::AttributeV1(entry)
            | CertificateChoice::AttributeV2(entry)
            | CertificateChoice::Other(entry),
        ) = self.choices.get(ordinal)
        else {
            return Ok(None);
        };
        self.reopen(query, entry).map(Some)
    }
    /// Reopen the original whole CRL/other alternative, without a parser reset,
    /// copy or format interpretation. Missing indices are paid absence.
    pub fn revocation_reader_in<'op>(
        &self,
        query: &Reader<'op>,
        ordinal: usize,
    ) -> Result<Option<Reader<'op>>>
    where
        'a: 'op,
    {
        self.admit(query)?;
        self.revocations
            .get(ordinal)
            .map(|entry| self.reopen(query, entry))
            .transpose()
    }
    fn admit(&self, query: &Reader<'_>) -> Result<()> {
        query
            .execution()
            .execution_for(self.parser)
            .charge_work(1)
            .map_err(|e| Error::resource(e, "envelopedData.originatorInfo", self.at))
    }
    fn reopen<'op>(&self, query: &Reader<'op>, entry: &Element<'a>) -> Result<Reader<'op>>
    where
        'a: 'op,
    {
        // `outer` is the containing OriginatorInfo level. The set itself adds
        // one level; the returned reader is positioned at its member element.
        self.parser
            .read_nested_query_in(
                query,
                entry.as_bytes(),
                entry.span().start,
                self.encoding,
                self.outer,
            )
            .map_err(|e| Error::encoding(e, "envelopedData.originatorInfo"))
    }
}

/// Original content descriptor and optional ciphertext, not plaintext.
#[derive(Debug)]
pub struct EncryptedContent<'a> {
    /// The actual plaintext format selected by the originator.
    pub kind: Oid<'a>,
    /// Original content algorithm and parameter source context.
    pub algorithm: AlgorithmIdentifier<'a>,
    /// None is detached; attached empty ciphertext is a distinct value.
    pub ciphertext: Option<Octets<'a>>,
}

/// Complete `EnvelopedData` schema with original nested decoding context.
#[derive(Debug)]
pub struct EnvelopedData<'a> {
    parser: &'a Parser,
    element: Element<'a>,
    depth: u32,
    encoding: Encoding,
    /// Declared version, checked against all encoded choices before return.
    pub version: u64,
    /// Optional originator certificates and revocation material.
    pub originator: Option<OriginatorInfo<'a>>,
    /// Every original recipient, in source SET order.
    pub recipients: OwnedVec<Recipient<'a>>,
    /// Original plaintext type, encryption parameters and ciphertext ranges.
    pub content: EncryptedContent<'a>,
    /// Unauthenticated/unprotected attributes, never promoted to signed facts.
    pub unprotected: Option<OwnedVec<Attribute<'a>>>,
}

impl<'a> EnvelopedData<'a> {
    /// Read one complete `ContentInfo` with the enveloped-data content type.
    pub fn read(parent: &mut Reader<'a>) -> Result<Self> {
        let (wrapper, reader) = ContentInfo::read(parent)?;
        Self::from_content_info(&wrapper, &reader)
    }
    /// Read one original embedded `ContentInfo` without rebuilding its encoding.
    pub fn read_content_info(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let (wrapper, reader) = ContentInfo::read_element(parent, element)?;
        Self::from_content_info(&wrapper, &reader)
    }
    fn from_content_info(wrapper: &ContentInfo<'a>, parent: &Reader<'a>) -> Result<Self> {
        oid_is(
            wrapper.kind(),
            IDENTIFIER,
            parent,
            "contentInfo.contentType",
            wrapper.span().start,
        )?;
        Self::read_element(parent, wrapper.content())
    }
    /// Read the original `EnvelopedData` SEQUENCE, retaining its source/depth.
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        tag(element, Tag::constructed(universal::SEQUENCE), FIELD)?;
        let mut inside = enter(parent, element, FIELD)?;
        let (version, at) = number(&mut inside, "envelopedData.version")?;
        let mut next = required(&mut inside, FIELD)?;
        let mut material_version = 0;
        let originator = if next.tag() == Tag::context(true, 0) {
            let original = originator_info(&inside, &next, &mut material_version)?;
            next = required(&mut inside, FIELD)?;
            Some(original)
        } else {
            None
        };
        let mut all_zero = true;
        let mut advanced = false;
        let recipients = catalogue(
            &inside,
            &next,
            Tag::constructed(universal::SET),
            "envelopedData.recipientInfos",
            |reader, entry| {
                let recipient = Recipient::read(reader, entry)?;
                all_zero &= recipient.is_transport_zero();
                advanced |= matches!(
                    recipient,
                    Recipient::Password { .. } | Recipient::Other { .. }
                );
                Ok(recipient)
            },
        )?;
        if recipients.is_empty() {
            return Err(Error::schema(
                ErrorCode::MissingField,
                "envelopedData.recipientInfos",
                next.span().start,
            ));
        }
        let value = required(&mut inside, "envelopedData.encryptedContentInfo")?;
        let content = encrypted_content(&inside, &value)?;
        let unprotected = inside
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?
            .map(|set| {
                let values = catalogue(
                    &inside,
                    &set,
                    Tag::context(true, 1),
                    "envelopedData.unprotectedAttrs",
                    |r, e| Attribute::read(r, e, "envelopedData.unprotectedAttrs"),
                )?;
                if values.is_empty() {
                    return Err(Error::schema(
                        ErrorCode::EmptyAttributes,
                        "envelopedData.unprotectedAttrs",
                        set.span().start,
                    ));
                }
                Ok(values)
            })
            .transpose()?;
        end(&inside, FIELD)?;
        // RFC5652 §6.1's ladder differs from SignedData: other originator
        // formats ->4; v2 AC/pwri/ori ->3; pure transport v0 ->0; otherwise2.
        // https://www.rfc-editor.org/rfc/rfc5652#section-6.1
        let expected = if material_version == 5 {
            4
        } else if material_version >= 4 || advanced {
            3
        } else if originator.is_none() && unprotected.is_none() && all_zero {
            0
        } else {
            2
        };
        if version != expected {
            return Err(Error::schema(
                ErrorCode::VersionMismatch,
                "envelopedData.version",
                at,
            ));
        }
        Ok(Self {
            parser: parent.parser(),
            element: *element,
            depth: parent.depth(),
            encoding: parent.encoding(),
            version,
            originator,
            recipients,
            content,
            unprotected,
        })
    }
    /// Whole original encoding, not reconstructed plaintext or trusted content.
    #[must_use]
    pub fn element(&self) -> &Element<'a> {
        &self.element
    }
    /// Original/current execution for a selected provider's new work.
    pub fn execution_in<'op, W: Work>(
        &self,
        current: &'op W,
    ) -> structured_asn1::memory::Execution<'op>
    where
        'a: 'op,
    {
        current.execution_for(self.parser)
    }
    /// Reopen this whole original envelope at its exact original depth under
    /// the current operation. Descendants' own reader APIs preserve field depth.
    pub fn reader_in<'op>(&self, current: &Reader<'op>) -> Result<Reader<'op>>
    where
        'a: 'op,
    {
        let outer = self.element.span();
        self.parser
            .read_query_in(
                current,
                self.element.as_bytes(),
                outer.start,
                self.encoding,
                self.depth,
            )
            .map_err(|e| Error::encoding(e, FIELD))
    }
}

fn originator_info<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    version: &mut u64,
) -> Result<OriginatorInfo<'a>> {
    let field = "envelopedData.originatorInfo";
    let mut inside = enter(parent, element, field)?;
    let work = parent.execution();
    let mut choices = work.vector().into_owned();
    let mut certificates = work.vector().into_owned();
    let mut revocations = work.vector().into_owned();
    let mut next = inside
        .next_element()
        .map_err(|e| Error::encoding(e, field))?;
    if let Some(set) = next.as_ref().filter(|e| e.tag() == Tag::context(true, 0)) {
        (choices, certificates) =
            read_certificates(&inside, set, version, "envelopedData.originatorInfo.certs")?;
        next = inside
            .next_element()
            .map_err(|e| Error::encoding(e, field))?;
    }
    if let Some(set) = next.as_ref().filter(|e| e.tag() == Tag::context(true, 1)) {
        revocations = read_revocations(&inside, set, version, "envelopedData.originatorInfo.crls")?;
        next = inside
            .next_element()
            .map_err(|e| Error::encoding(e, field))?;
    }
    if let Some(extra) = next {
        return Err(Error::schema(
            ErrorCode::UnknownField,
            field,
            extra.span().start,
        ));
    }
    Ok(OriginatorInfo {
        parser: parent.parser(),
        encoding: parent.encoding(),
        outer: inside.depth(),
        at: element.span().start,
        choices,
        certificates,
        revocations,
    })
}
fn encrypted_content<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
) -> Result<EncryptedContent<'a>> {
    let field = "envelopedData.encryptedContentInfo";
    tag(element, Tag::constructed(universal::SEQUENCE), field)?;
    let mut inside = enter(parent, element, field)?;
    let kind = inside.read_oid().map_err(|e| Error::encoding(e, field))?;
    let value = required(&mut inside, field)?;
    let algorithm = algorithm(&inside, &value, field)?;
    let ciphertext = inside
        .next_element()
        .map_err(|e| Error::encoding(e, field))?
        .map(|value| Octets::read_identifier(&inside, &value, field))
        .transpose()?;
    end(&inside, field)?;
    Ok(EncryptedContent {
        kind,
        algorithm,
        ciphertext,
    })
}
fn enter<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<Reader<'a>> {
    parent.enter(element).map_err(|e| Error::encoding(e, field))
}
fn end(parent: &Reader<'_>, field: &'static str) -> Result<()> {
    if !parent.is_empty() {
        return Err(Error::schema(
            ErrorCode::TrailingData,
            field,
            parent.offset(),
        ));
    }
    Ok(())
}
fn tag(element: &Element<'_>, expected: Tag, field: &'static str) -> Result<()> {
    if element.tag() != expected {
        return Err(Error::schema(
            ErrorCode::UnexpectedTag,
            field,
            element.span().start,
        ));
    }
    Ok(())
}
fn number(parent: &mut Reader<'_>, field: &'static str) -> Result<(u64, u64)> {
    let element = parent
        .expect(Tag::primitive(universal::INTEGER))
        .map_err(|e| Error::encoding(e, field))?;
    let value = parent
        .integer(&element)
        .map_err(|e| Error::encoding(e, field))?
        .as_u64()
        .ok_or_else(|| Error::schema(ErrorCode::ValueTooLarge, field, element.span().start))?;
    Ok((value, element.span().start))
}
fn version(parent: &mut Reader<'_>, expected: u64, field: &'static str) -> Result<()> {
    let (value, at) = number(parent, field)?;
    if value != expected {
        return Err(Error::schema(ErrorCode::UnsupportedVersion, field, at));
    }
    Ok(())
}
fn algorithm<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<AlgorithmIdentifier<'a>> {
    structured_pkix::algorithm::read(parent, element, field).map_err(Error::pkix)
}
pub(crate) fn oid_is(
    value: Oid<'_>,
    expected: Oid<'_>,
    parent: &Reader<'_>,
    field: &'static str,
    at: u64,
) -> Result<()> {
    parent.charge(1).map_err(|e| Error::encoding(e, field))?;
    if value.as_bytes().len() == expected.as_bytes().len() {
        parent
            .charge(value.as_bytes().len() as u64)
            .map_err(|e| Error::encoding(e, field))?;
        if value == expected {
            return Ok(());
        }
    }
    Err(Error::schema(ErrorCode::UnexpectedContentType, field, at))
}
