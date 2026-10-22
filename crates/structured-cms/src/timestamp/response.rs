//! Complete RFC3161 response framing, before request-bound token execution.
//!
//! Status text/flags are unauthenticated transport facts, not a TSA trust
//! assertion. Network acquisition, polling, replay history and clocks are not
//! performed here. RFC3161 §§2.4.2/3 require the status/token rules and DER wire
//! messages. <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2>

use super::Token;
use crate::{Error, ErrorCode, Result, signer::required};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Encoding, Parser, Reader, Span, Tag, universal};

mod check;
pub use check::CheckedResponse;

const FIELD: &str = "timeStampResp";
const STATUS: &str = "pkiStatusInfo";

/// The six understood RFC3161 §2.4.2 status values. Unknown values refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// A requested token is present; its cryptographic checks remain necessary.
    Granted = 0,
    /// A token with modifications is present, still subject to request checks.
    GrantedWithMods = 1,
    /// The request was rejected; this unauthenticated status is no proof.
    Rejection = 2,
    /// A response is not yet available; no polling is performed here.
    Waiting = 3,
    /// An unauthenticated warning of imminent revocation.
    RevocationWarning = 4,
    /// An unauthenticated notification of revocation.
    RevocationNotification = 5,
}
impl Status {
    /// Whether the response is required to carry a timestamp token.
    #[must_use]
    pub fn granted(self) -> bool {
        matches!(self, Self::Granted | Self::GrantedWithMods)
    }
}

/// Defined failure bit positions, not integer status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Failure {
    /// Unrecognized or unsupported algorithm.
    BadAlgorithm = 0,
    /// Transaction is not permitted or supported.
    BadRequest = 2,
    /// Submitted data has the wrong format.
    BadDataFormat = 5,
    /// TSA time source is unavailable.
    TimeNotAvailable = 14,
    /// Requested policy is unsupported.
    UnacceptedPolicy = 15,
    /// Requested extension is unsupported.
    UnacceptedExtension = 16,
    /// Additional information is unavailable or not understood.
    AdditionalInformationUnavailable = 17,
    /// Server system failure.
    SystemFailure = 25,
}

/// Original named-bit field with all understood flags, without width truncation.
#[derive(Debug, Clone, Copy)]
pub struct FailureInfo<'a> {
    element: Element<'a>,
    flags: u32,
}
impl<'a> FailureInfo<'a> {
    /// Constant-time scalar membership in the already validated named-bit value.
    #[must_use]
    pub fn contains(self, reason: Failure) -> bool {
        self.flags & (1u32 << reason as u8) != 0
    }
    /// Original BIT STRING, including source range and padding octet.
    #[must_use]
    pub fn element(self) -> Element<'a> {
        self.element
    }
    fn read(parent: &Reader<'a>, element: Element<'a>) -> Result<Self> {
        const FIELD: &str = "pkiStatusInfo.failInfo";
        const KNOWN: u32 = (1 << Failure::BadAlgorithm as u8)
            | (1 << Failure::BadRequest as u8)
            | (1 << Failure::BadDataFormat as u8)
            | (1 << Failure::TimeNotAvailable as u8)
            | (1 << Failure::UnacceptedPolicy as u8)
            | (1 << Failure::UnacceptedExtension as u8)
            | (1 << Failure::AdditionalInformationUnavailable as u8)
            | (1 << Failure::SystemFailure as u8);
        tag(&element, Tag::primitive(universal::BIT_STRING), FIELD)?;
        let bits = parent
            .bit_string(&element)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let bytes = bits.as_bytes();
        parent
            .charge(1 + bytes.len() as u64)
            .map_err(|e| Error::encoding(e, FIELD))?;
        // X.690 §11.2.2 removes every trailing zero bit of a named-bit type.
        // Ordinary BIT STRING padding validation alone does not enforce this.
        // https://www.itu.int/rec/T-REC-X.690-202102-I/en
        if let Some(last) = bytes.last()
            && (*last == 0 || last.trailing_zeros() != u32::from(bits.unused_bits()))
        {
            return Err(Error::schema(
                ErrorCode::MalformedValue,
                FIELD,
                element.span().start,
            ));
        }
        if bytes.len() > 4 {
            return Err(Error::schema(
                ErrorCode::UnknownField,
                FIELD,
                element.span().start,
            ));
        }
        let mut flags = 0u32;
        for (index, byte) in bytes.iter().enumerate() {
            flags |= u32::from(byte.reverse_bits()) << (index * 8);
        }
        // RFC3161 §2.4.2: clients MUST generate an error for failure values
        // they do not understand; arbitrary-width high bits are not truncated.
        if flags & !KNOWN != 0 {
            return Err(Error::schema(
                ErrorCode::UnknownField,
                FIELD,
                element.span().start,
            ));
        }
        Ok(Self { element, flags })
    }
}

/// One original UTF-8 reason string. It is neither joined nor normalized.
#[derive(Debug, Clone, Copy)]
pub struct StatusText<'a> {
    value: &'a str,
    span: Span,
}
impl<'a> StatusText<'a> {
    /// Already validated borrowed UTF-8; display/output work belongs to caller.
    #[must_use]
    pub fn as_str(self) -> &'a str {
        self.value
    }
    /// Original whole `UTF8String` range.
    #[must_use]
    pub fn span(self) -> Span {
        self.span
    }
}

/// Whole original status, before any signature or request comparison.
#[derive(Debug)]
pub struct StatusInfo<'a> {
    status: Status,
    text: Option<OwnedVec<StatusText<'a>>>,
    failure: Option<FailureInfo<'a>>,
    span: Span,
}
impl<'a> StatusInfo<'a> {
    /// Original understood status; it does not authenticate the response.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status
    }
    /// Optional nonempty reason-string catalogue, preserving separate strings.
    #[must_use]
    pub fn text(&self) -> Option<&[StatusText<'a>]> {
        self.text.as_deref()
    }
    /// Absent and present-empty failure fields remain distinct.
    #[must_use]
    pub fn failure(&self) -> Option<FailureInfo<'a>> {
        self.failure
    }
    /// Original `PKIStatusInfo` enclosure.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
    fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        tag(element, Tag::constructed(universal::SEQUENCE), STATUS)?;
        let mut inside = parent
            .enter(element)
            .map_err(|e| Error::encoding(e, STATUS))?;
        let status_element = required(&mut inside, "pkiStatusInfo.status")?;
        tag(
            &status_element,
            Tag::primitive(universal::INTEGER),
            "pkiStatusInfo.status",
        )?;
        let status = inside
            .integer(&status_element)
            .map_err(|e| Error::encoding(e, "pkiStatusInfo.status"))?;
        let status = match status.as_u64() {
            Some(0) => Status::Granted,
            Some(1) => Status::GrantedWithMods,
            Some(2) => Status::Rejection,
            Some(3) => Status::Waiting,
            Some(4) => Status::RevocationWarning,
            Some(5) => Status::RevocationNotification,
            _ => {
                return Err(Error::schema(
                    ErrorCode::MalformedValue,
                    "pkiStatusInfo.status",
                    status_element.span().start,
                ));
            }
        };
        let mut next = inside
            .next_element()
            .map_err(|e| Error::encoding(e, STATUS))?;
        let text = if let Some(element) = next
            .as_ref()
            .filter(|e| e.tag() == Tag::constructed(universal::SEQUENCE))
        {
            let values = read_text(&inside, element)?;
            next = inside
                .next_element()
                .map_err(|e| Error::encoding(e, STATUS))?;
            Some(values)
        } else {
            None
        };
        let failure = next
            .map(|element| FailureInfo::read(&inside, element))
            .transpose()?;
        end(&inside, STATUS)?;
        Ok(Self {
            status,
            text,
            failure,
            span: element.span(),
        })
    }
}

/// Complete DER response and its original optional token. Private fields keep
/// the status/token association immutable; reading establishes no trust.
///
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_cms::timestamp::{Response, response::Status};
/// let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 65536)));
/// let parser = Parser::der(memory);
/// let mut reader = parser.read(&[0x30, 5, 0x30, 3, 2, 1, 2], 400).unwrap();
/// let response = Response::read(&mut reader).unwrap();
/// assert_eq!(response.status().status(), Status::Rejection);
/// assert!(response.token().is_none()); // no signature evidence on failure
/// ```
#[derive(Debug)]
pub struct Response<'a> {
    status: StatusInfo<'a>,
    token: Option<OriginalToken<'a>>,
    element: Element<'a>,
    parser: &'a Parser,
    token_depth: u32,
}

#[derive(Debug)]
struct OriginalToken<'a> {
    value: Token<'a>,
    element: Element<'a>,
}
impl<'a> Response<'a> {
    /// Read exactly one complete response; refuse any trailing source bytes.
    pub fn read(parent: &mut Reader<'a>) -> Result<Self> {
        let element = parent
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|e| Error::encoding(e, FIELD))?;
        end(parent, FIELD)?;
        Self::read_element(parent, &element)
    }
    /// Read one original embedded response. The response's own DER contract
    /// applies even in a BER carrier, without a replacement parser or account.
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut strict = parent
            .reread(element, Encoding::Der)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let element = strict
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|e| Error::encoding(e, FIELD))?;
        structured_pkix::der::conforms(&strict, &element, FIELD).map_err(Error::pkix)?;
        let mut inside = strict
            .enter(&element)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let status_element = required(&mut inside, STATUS)?;
        let status = StatusInfo::read(&inside, &status_element)?;
        let token_element = inside
            .next_element()
            .map_err(|e| Error::encoding(e, FIELD))?;
        end(&inside, FIELD)?;
        // RFC3161 §2.4.2: statuses 0/1 MUST carry a token; every other status
        // MUST NOT. This preflight runs before even decoding a purported token.
        if status.status.granted() != token_element.is_some() {
            return Err(Error::schema(
                ErrorCode::MalformedValue,
                FIELD,
                element.span().start,
            ));
        }
        let token = token_element
            .as_ref()
            .map(|element| {
                let mut reader = inside
                    .reread(element, Encoding::Der)
                    .map_err(|e| Error::encoding(e, FIELD))?;
                Token::read_from(&mut reader).map(|value| OriginalToken {
                    value,
                    element: *element,
                })
            })
            .transpose()?;
        Ok(Self {
            status,
            token,
            element,
            parser: parent.parser(),
            token_depth: inside.depth(),
        })
    }
    /// Original unauthenticated status metadata.
    #[must_use]
    pub fn status(&self) -> &StatusInfo<'a> {
        &self.status
    }
    /// Original token, only present for granted/grantedWithMods.
    #[must_use]
    pub fn token(&self) -> Option<&Token<'a>> {
        self.token.as_ref().map(|token| &token.value)
    }
    /// Original whole response; no re-encoded token or physical-offset reset.
    #[must_use]
    pub fn element(&self) -> &Element<'a> {
        &self.element
    }
    /// Reopen the actual token at its original nested depth and current/source
    /// ceilings. Absence is paid metadata, not an unlimited lookup fast path.
    pub fn token_reader_in<'op>(&self, query: &Reader<'op>) -> Result<Option<Reader<'op>>>
    where
        'a: 'op,
    {
        self.token_in(query)
            .map(|value| value.map(|(_, reader)| reader))
    }

    fn token_in<'op>(&self, query: &Reader<'op>) -> Result<Option<(&Token<'a>, Reader<'op>)>>
    where
        'a: 'op,
    {
        query
            .execution()
            .execution_for(self.parser)
            .charge_work(1)
            .map_err(|e| Error::resource(e, FIELD, self.element.span().start))?;
        self.token
            .as_ref()
            .map(|token| {
                self.parser
                    .read_query_in(
                        query,
                        token.element.as_bytes(),
                        token.element.span().start,
                        Encoding::Der,
                        self.token_depth,
                    )
                    .map(|reader| (&token.value, reader))
                    .map_err(|e| Error::encoding(e, FIELD))
            })
            .transpose()
    }
}

fn read_text<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<OwnedVec<StatusText<'a>>> {
    const FIELD: &str = "pkiStatusInfo.statusString";
    let mut inside = parent
        .enter(element)
        .map_err(|e| Error::encoding(e, FIELD))?;
    let work = parent.execution();
    let mut text = work.vector();
    while let Some(element) = inside
        .next_element()
        .map_err(|e| Error::encoding(e, FIELD))?
    {
        tag(&element, Tag::primitive(universal::UTF8_STRING), FIELD)?;
        inside
            .charge(element.contents().len() as u64)
            .map_err(|e| Error::encoding(e, FIELD))?;
        let value = core::str::from_utf8(element.contents())
            .map_err(|_| Error::schema(ErrorCode::MalformedValue, FIELD, element.span().start))?;
        text.try_push(StatusText {
            value,
            span: element.span(),
        })
        .map_err(|e| Error::resource(e, FIELD, element.span().start))?;
    }
    // RFC2510 §3.1.1 (incorporated by RFC3161) defines SIZE (1..MAX).
    // https://www.rfc-editor.org/rfc/rfc2510#section-3.1.1
    if text.is_empty() {
        return Err(Error::schema(
            ErrorCode::MissingField,
            FIELD,
            element.span().start,
        ));
    }
    Ok(text.into_owned())
}
fn tag(element: &Element<'_>, expected: Tag, field: &'static str) -> Result<()> {
    if element.tag() == expected {
        Ok(())
    } else {
        Err(Error::schema(
            ErrorCode::UnexpectedTag,
            field,
            element.span().start,
        ))
    }
}
fn end(parent: &Reader<'_>, field: &'static str) -> Result<()> {
    if parent.is_empty() {
        Ok(())
    } else {
        Err(Error::schema(
            ErrorCode::TrailingData,
            field,
            parent.offset(),
        ))
    }
}
