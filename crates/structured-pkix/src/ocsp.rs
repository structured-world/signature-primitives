//! OCSP response evidence over original caller-supplied DER ranges.
//!
//! Decoding does not authenticate a responder, validate a request binding or
//! establish certificate status. No transport, clock or trust discovery occurs.

use crate::algorithm::{self, AlgorithmIdentifier};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extensions};
use crate::name::{self, Name};
use crate::{Certificate, Time, oid, time};
use structured_asn1::memory::{Memory, OwnedVec, Work};
use structured_asn1::{
    BitString, Element, Encoding, Integer, Oid, Parser, Reader, Span, Tag, universal,
};

const FIELD: &str = "ocspResponse";
const BASIC: &str = "ocspResponse.basic";
const DATA: &str = "ocspResponse.responseData";
const SINGLE: &str = "ocspResponse.singleResponse";

mod digest;
pub use digest::{CertMatch, ResponderMatch};

mod nonce;
pub use nonce::{NonceBinding, NonceSizeError, RequestNonce};

mod authentication;
pub use authentication::{
    SignatureAuthentication, SignatureError, SignatureFailure, SignedResponse,
};

mod delegation;
pub(crate) use delegation::read_no_check;

mod lookup;
pub use delegation::{
    DelegateFacts, Delegation, DelegationFailure, ResponderRevocation, check_delegate,
};
pub use lookup::Lookup;

mod freshness;
pub use freshness::UpdateWindow;

mod authority;
pub use authority::{AuthorityBinding, AuthorityFailure, AuthoritySource, ScopedResponse};

mod extensions;
pub use extensions::ExtensionProcessing;

mod retention;

mod evidence;
pub use evidence::{
    BoundEvidence, Evaluation, Evidence, RecipientBinding, Request, TargetEvidence, TargetReading,
};

/// Unsigned protocol failure from RFC6960 §4.2.1, never a certificate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Request did not conform to the protocol.
    MalformedRequest,
    /// Responder reached an inconsistent state.
    InternalError,
    /// Responder cannot currently answer.
    TryLater,
    /// Responder requires a signed request.
    SignatureRequired,
    /// Request unauthorized or responder unable to answer authoritatively.
    Unauthorized,
}

/// A decoded envelope preserves unsupported response types and unsigned errors.
#[derive(Debug)]
pub enum Response<'a> {
    /// Successful wire envelope, whose typed body is decoded on demand.
    Successful(ResponseBytes<'a>),
    /// Protocol error. No signed status information accompanies it.
    Failure {
        /// Error code chosen by the responder.
        failure: Failure,
        /// Original envelope location.
        span: Span,
    },
}

/// Original successful response payload and its producing reader. Keeping the
/// envelope separate avoids allocating a large basic response for protocol
/// failures or unsupported types; decoding moves the existing reader.
#[derive(Debug)]
pub struct ResponseBytes<'a> {
    encoded: &'a [u8],
    kind: Oid<'a>,
    payload: &'a [u8],
    span: Span,
    reader: Reader<'a>,
}

impl<'a> ResponseBytes<'a> {
    /// Whole original successful `OCSPResponse` DER, including status and
    /// `responseBytes` wrapper. RFC6960 §4.2.1 separates this envelope from the
    /// signed `BasicOCSPResponse` payload. Reference digests must not substitute
    /// the payload or a re-encoded envelope for these original bytes.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1>
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.encoded
    }
    /// Original response syntax identifier.
    #[must_use]
    pub fn kind(&self) -> Oid<'a> {
        self.kind
    }
    /// Original encoded response payload.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    /// Original payload content location.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
    /// Borrows the original basic-response payload under a current operation.
    /// The envelope is not consumed or cloned. Its original producing parser,
    /// source offsets and actual depth remain active, while the supplied query
    /// funds new decoding, catalogue growth and lazy certificate processing.
    /// `None` is only an unsupported response syntax, never a malformed known
    /// basic response or a source/current-operation resource refusal.
    pub fn basic_in<'query>(&self, query: &Reader<'query>) -> Result<Option<BasicResponse<'query>>>
    where
        'a: 'query,
    {
        // RFC6960 §4.2.1 leaves an unsupported responseType's octets opaque.
        // Classifying its OID consumes metadata work, not a payload nesting
        // level. Keep both source and current query work ceilings before the
        // comparison; only the known basic syntax opens a nested reader.
        // https://www.rfc-editor.org/rfc/rfc6960.html#section-4.2.1
        self.reader
            .execution_query(query)
            .charge_work(19)
            .map_err(|reason| Error::resource(reason, FIELD, self.span.start))?;
        if self.kind != oid::OCSP_BASIC {
            return Ok(None);
        }
        let mut nested = self
            .reader
            .parser()
            .read_nested_query_in(
                query,
                self.payload,
                self.span.start,
                Encoding::Der,
                self.reader.depth(),
            )
            .field(BASIC)?;
        let root = required(&mut nested, BASIC)?;
        let basic = read_basic(&nested, &root)?;
        end(&nested, BASIC)?;
        Ok(Some(basic))
    }
    /// Decode the mandatory basic response syntax using current execution.
    /// `None` means unsupported syntax. The producing reader's cumulative
    /// work/depth limits remain active; no extra parser or reader copy is made.
    pub fn into_basic(self, execution: &Memory) -> Result<Option<BasicResponse<'a>>> {
        let reader = self.reader.with_execution(execution);
        reader.charge(19).field(FIELD)?;
        if self.kind != oid::OCSP_BASIC {
            return Ok(None);
        }
        let mut nested = reader
            .parser()
            .read_nested_query_in(
                &reader,
                self.payload,
                self.span.start,
                Encoding::Der,
                reader.depth(),
            )
            .field(BASIC)?;
        let root = required(&mut nested, BASIC)?;
        let basic = read_basic(&nested, &root)?;
        end(&nested, BASIC)?;
        Ok(Some(basic))
    }
}

/// Responder identity used to locate the actual signing certificate.
#[derive(Debug)]
pub enum ResponderId<'a> {
    /// Subject distinguished name of the signer.
    Name(Name<'a>),
    /// SHA-1 of original subjectPublicKey contents, excluding ASN.1 wrapper
    /// and the BIT STRING unused-bits count (RFC6960 verified errata6165–6167).
    KeyHash(&'a [u8]),
}

impl<'a> ResponderId<'a> {
    /// Decode one original RFC6960 §4.2.1 `ResponderID` choice using its
    /// producing reader, including the EXPLICIT context wrapper and fixed
    /// SHA-1 key-hash width. Source profile encoding is supplied by that reader;
    /// no new parser, normalized copy or budget reset is introduced.
    /// <https://www.rfc-editor.org/rfc/rfc6960.html#section-4.2.1>
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        read_responder(parent, element)
    }
}

/// Certificate identity retains its original encoded hash algorithm and octets.
#[derive(Debug, Clone, Copy)]
pub struct CertId<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    issuer_name_hash: &'a [u8],
    issuer_key_hash: &'a [u8],
    serial: Integer<'a>,
    span: Span,
}

impl<'a> CertId<'a> {
    /// Hash algorithm, including original parameters.
    #[must_use]
    pub fn algorithm(self) -> AlgorithmIdentifier<'a> {
        self.algorithm
    }
    /// Hash of the target certificate's original issuer DER name.
    #[must_use]
    pub fn issuer_name_hash(self) -> &'a [u8] {
        self.issuer_name_hash
    }
    /// Hash of the issuer's original subjectPublicKey BIT STRING contents.
    #[must_use]
    pub fn issuer_key_hash(self) -> &'a [u8] {
        self.issuer_key_hash
    }
    /// Original arbitrary-width serial INTEGER.
    #[must_use]
    pub fn serial(self) -> Integer<'a> {
        self.serial
    }
    /// Original `CertID` location.
    #[must_use]
    pub fn span(self) -> Span {
        self.span
    }
}

/// A responder's assertion, independently of authentication and applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Positive revocation inquiry; not proof that a certificate was issued.
    Good,
    /// Responder states revocation or hold, retaining its original date/reason.
    Revoked {
        /// Recorded revocation or hold time.
        time: Time,
        /// Encoded optional reason, without substituting a policy decision.
        reason: Option<crate::crl::Reason>,
    },
    /// This responder does not know the requested certificate's status.
    Unknown,
    /// The certificate was never issued (RFC6960 §2.2): a "revoked" hold
    /// dated 1970-01-01T00:00:00Z under the extended revoked definition. Read
    /// through [`BasicResponse::status_of`] or [`Evidence::status`], never from
    /// the assertion alone.
    NotIssued,
}

#[derive(Debug)]
enum RecordedStatus {
    Good,
    Unknown,
    Revoked {
        time: Time,
        reason: Option<crate::crl::Reason>,
        offset: u64,
    },
}

/// One signed assertion with deferred extension semantics.
#[derive(Debug)]
pub struct SingleResponse<'a> {
    id: CertId<'a>,
    status: RecordedStatus,
    this_update: Time,
    next_update: Option<Time>,
    extensions: Extensions<'a>,
    span: Span,
}

impl<'a> SingleResponse<'a> {
    /// Original certificate identity.
    #[must_use]
    pub fn id(&self) -> CertId<'a> {
        self.id
    }
    /// Unauthenticated status assertion read on its own: a non-issued answer
    /// stays [`Status::Revoked`] here, since telling it apart needs the
    /// response-wide extended revoked definition.
    #[must_use]
    pub fn status(&self) -> Status {
        match self.status {
            RecordedStatus::Good => Status::Good,
            RecordedStatus::Unknown => Status::Unknown,
            RecordedStatus::Revoked { time, reason, .. } => Status::Revoked { time, reason },
        }
    }

    /// UTC-qualified recorded revocation time, when this assertion is revoked.
    /// This never decides whether a future date may be ignored by the product.
    pub fn revocation_relation<W: Work>(
        &self,
        now: crate::temporal::Reading,
        utc: &crate::temporal::LeapTable<'_>,
        execution: &W,
    ) -> Result<Option<crate::time::Relation>> {
        match self.status {
            RecordedStatus::Good | RecordedStatus::Unknown => Ok(None),
            RecordedStatus::Revoked { time, offset, .. } => crate::time::relation_in(
                time.instant(),
                now,
                utc,
                execution,
                ("ocspResponse.singleResponse.revocationTime", offset),
            )
            .map(Some),
        }
    }
    /// Most recent time the responder knew this status to be correct.
    #[must_use]
    pub fn this_update(&self) -> Time {
        self.this_update
    }
    /// Recommended update boundary, absent when newer information is always
    /// available. No lifetime is invented for an absent value.
    #[must_use]
    pub fn next_update(&self) -> Option<Time> {
        self.next_update
    }
    /// Deferred extensions, still using their source parser and current account.
    #[must_use]
    pub fn extensions(&self) -> &Extensions<'a> {
        &self.extensions
    }
    /// Original assertion location.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}

/// `BasicOCSPResponse` retains the exact signed `ResponseData` encoding.
#[derive(Debug)]
pub struct BasicResponse<'a> {
    responder: ResponderId<'a>,
    produced_at: Time,
    responses: OwnedVec<SingleResponse<'a>>,
    extensions: Extensions<'a>,
    algorithm: AlgorithmIdentifier<'a>,
    signature: crate::signature::SignatureValue<'a>,
    certificates: OwnedVec<Certificate<'a>>,
    signed: &'a [u8],
    bytes: &'a [u8],
    span: Span,
}

impl<'a> BasicResponse<'a> {
    /// Original responder identity, not a resolved signing authority.
    #[must_use]
    pub fn responder(&self) -> &ResponderId<'a> {
        &self.responder
    }
    /// Time the responder signed this response, not the status update time.
    #[must_use]
    pub fn produced_at(&self) -> Time {
        self.produced_at
    }
    /// Signed assertions in original order; duplicates are not collapsed.
    #[must_use]
    pub fn responses(&self) -> &[SingleResponse<'a>] {
        &self.responses
    }
    /// Response-wide deferred extensions.
    #[must_use]
    pub fn extensions(&self) -> &Extensions<'a> {
        &self.extensions
    }
    /// Signature algorithm selected by the responder.
    #[must_use]
    pub fn signature_algorithm(&self) -> AlgorithmIdentifier<'a> {
        self.algorithm
    }
    /// Original signature BIT STRING.
    #[must_use]
    pub fn signature(&self) -> BitString<'a> {
        self.signature.bit_string()
    }
    /// Signature bytes with original source context for deferred decoding.
    #[must_use]
    pub fn signature_value(&self) -> crate::signature::SignatureValue<'a> {
        self.signature
    }
    /// Untrusted included certificates, not a discovered trust path.
    #[must_use]
    pub fn certificates(&self) -> &[Certificate<'a>] {
        &self.certificates
    }
    /// Exact original DER `ResponseData` bytes supplied to signature verification.
    #[must_use]
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.signed
    }
    /// Original DER `BasicOCSPResponse` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Original basic-response location inside the payload OCTET STRING.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}

impl<'a> Response<'a> {
    /// Read exactly one OCSP response using the supplied source parser.
    /// No new parser, budget reset or serialization bridge is introduced.
    pub fn read(parser: &'a Parser, bytes: &'a [u8], base: u64) -> Result<Self> {
        let mut reader = parser.read(bytes, base).field(FIELD)?;
        let element = required(&mut reader, FIELD)?;
        let result = Self::read_element(&reader, &element)?;
        end(&reader, FIELD)?;
        Ok(result)
    }

    /// Decode an embedded OCSP response under DER with its producing Reader.
    /// RFC6960 §4 uses explicit tagging by default; §§4.2.1/4.2.2 require
    /// original DER `ResponseData` for signatures and strict profile times.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.2.1>
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::new(
                ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                FIELD,
                element.span().start,
            ));
        }
        let mut distinguished = parent.reread(element, Encoding::Der).field(FIELD)?;
        let root = distinguished
            .expect(Tag::constructed(universal::SEQUENCE))
            .field(FIELD)?;
        let mut reader = distinguished.enter(&root).field(FIELD)?;
        let code = reader.expect(Tag::primitive(10)).field(FIELD)?;
        reader.charge(9).field(FIELD)?;
        let code = reader.integer(&code).field(FIELD)?.as_u64();
        let failure = match code {
            Some(0) => None,
            Some(1) => Some(Failure::MalformedRequest),
            Some(2) => Some(Failure::InternalError),
            Some(3) => Some(Failure::TryLater),
            Some(5) => Some(Failure::SignatureRequired),
            Some(6) => Some(Failure::Unauthorized),
            _ => {
                return Err(Error::new(
                    ErrorCode::MalformedValue,
                    FIELD,
                    root.span().start,
                ));
            }
        };
        if let Some(failure) = failure {
            // RFC6960 §4.2.1: error responses do not set responseBytes.
            end(&reader, FIELD)?;
            return Ok(Self::Failure {
                failure,
                span: root.span(),
            });
        }
        let wrapper = reader.expect(Tag::context(true, 0)).field(FIELD)?;
        end(&reader, FIELD)?;
        let mut explicit = reader.enter(&wrapper).field(FIELD)?;
        let response_bytes = explicit
            .expect(Tag::constructed(universal::SEQUENCE))
            .field(FIELD)?;
        end(&explicit, FIELD)?;
        let mut bytes_reader = explicit.enter(&response_bytes).field(FIELD)?;
        let kind = bytes_reader.read_oid().field(FIELD)?;
        let payload = bytes_reader
            .expect(Tag::primitive(universal::OCTET_STRING))
            .field(FIELD)?;
        end(&bytes_reader, FIELD)?;
        Ok(Self::Successful(ResponseBytes {
            encoded: element.as_bytes(),
            kind,
            payload: payload.contents(),
            span: payload.contents_span(),
            reader: bytes_reader,
        }))
    }
}

fn read_basic<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<BasicResponse<'a>> {
    let mut reader = sequence(parent, element, BASIC)?;
    let signed = required(&mut reader, DATA)?;
    let mut data = sequence(&reader, &signed, DATA)?;
    let responder = required(&mut data, DATA)?;
    if responder.tag() == Tag::context(true, 0) {
        let mut version = data.enter(&responder).field(DATA)?;
        let value = version.read_integer().field(DATA)?;
        version.charge(9).field(DATA)?;
        end(&version, DATA)?;
        return Err(Error::new(
            if value.as_u64() == Some(0) {
                ErrorCode::MalformedValue
            } else {
                ErrorCode::UnsupportedVersion
            },
            DATA,
            responder.span().start,
        ));
    }
    let responder = read_responder(&data, &responder)?;
    let produced = required(&mut data, DATA)?;
    let produced_at = generalized(&data, &produced, DATA)?;
    let assertions = data
        .expect(Tag::constructed(universal::SEQUENCE))
        .field(DATA)?;
    let mut assertions_reader = data.enter(&assertions).field(SINGLE)?;
    let work = parent.execution();
    let mut responses = work.vector();
    while let Some(assertion) = assertions_reader.next_element().field(SINGLE)? {
        responses
            .try_push(read_single(&assertions_reader, &assertion)?)
            .map_err(|reason| Error::resource(reason, SINGLE, assertion.span().start))?;
    }
    if responses.is_empty() {
        return Err(Error::new(
            ErrorCode::EmptySequence,
            SINGLE,
            assertions.span().start,
        ));
    }
    let extensions = optional_extensions(&mut data, 1, DATA)?;
    end(&data, DATA)?;
    let algorithm = required(&mut reader, BASIC)?;
    let algorithm = algorithm::read(&reader, &algorithm, BASIC)?;
    let signature = crate::signature::SignatureValue::read(&mut reader, BASIC)?;
    let mut certificates = work.vector();
    if let Some(wrapper) = reader.next_element().field(BASIC)? {
        if wrapper.tag() != Tag::context(true, 0) {
            return Err(Error::new(
                ErrorCode::UnexpectedField,
                BASIC,
                wrapper.span().start,
            ));
        }
        let mut explicit = reader.enter(&wrapper).field(BASIC)?;
        let sequence = explicit
            .expect(Tag::constructed(universal::SEQUENCE))
            .field(BASIC)?;
        end(&explicit, BASIC)?;
        let mut inside = explicit.enter(&sequence).field(BASIC)?;
        while let Some(certificate) = inside.next_element().field(BASIC)? {
            certificates
                .try_push(Certificate::read_element(&inside, &certificate)?)
                .map_err(|reason| Error::resource(reason, BASIC, certificate.span().start))?;
        }
    }
    end(&reader, BASIC)?;
    Ok(BasicResponse {
        responder,
        produced_at,
        responses: responses.into_owned(),
        extensions,
        algorithm,
        signature,
        certificates: certificates.into_owned(),
        signed: signed.as_bytes(),
        bytes: element.as_bytes(),
        span: element.span(),
    })
}

fn read_responder<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<ResponderId<'a>> {
    if element.tag() != Tag::context(true, 1) && element.tag() != Tag::context(true, 2) {
        return Err(Error::new(
            ErrorCode::UnexpectedField,
            DATA,
            element.span().start,
        ));
    }
    let mut wrapper = parent.enter(element).field(DATA)?;
    let value = required(&mut wrapper, DATA)?;
    end(&wrapper, DATA)?;
    match element.tag() {
        tag if tag == Tag::context(true, 1) => {
            Ok(ResponderId::Name(name::read(&wrapper, &value, DATA)?))
        }
        tag if tag == Tag::context(true, 2) => {
            if value.tag() != Tag::primitive(universal::OCTET_STRING)
                || value.contents().len() != 20
            {
                return Err(Error::new(
                    ErrorCode::MalformedValue,
                    DATA,
                    value.span().start,
                ));
            }
            Ok(ResponderId::KeyHash(value.contents()))
        }
        _ => Err(Error::new(
            ErrorCode::UnexpectedField,
            DATA,
            element.span().start,
        )),
    }
}

fn read_single<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<SingleResponse<'a>> {
    let mut reader = sequence(parent, element, SINGLE)?;
    let id = required(&mut reader, SINGLE)?;
    let id = read_id(&reader, &id)?;
    let status = required(&mut reader, SINGLE)?;
    let status = match status.tag() {
        tag if tag == Tag::context(false, 0) => {
            reader.null(&status).field(SINGLE)?;
            RecordedStatus::Good
        }
        tag if tag == Tag::context(false, 2) => {
            reader.null(&status).field(SINGLE)?;
            RecordedStatus::Unknown
        }
        tag if tag == Tag::context(true, 1) => {
            let mut revoked = reader.enter(&status).field(SINGLE)?;
            let date = required(&mut revoked, SINGLE)?;
            let time = generalized(&revoked, &date, SINGLE)?;
            let reason = if let Some(wrapper) = revoked.next_element().field(SINGLE)? {
                if wrapper.tag() != Tag::context(true, 0) {
                    return Err(Error::new(
                        ErrorCode::UnexpectedField,
                        SINGLE,
                        wrapper.span().start,
                    ));
                }
                let mut explicit = revoked.enter(&wrapper).field(SINGLE)?;
                let reason = explicit.expect(Tag::primitive(10)).field(SINGLE)?;
                end(&explicit, SINGLE)?;
                Some(crate::crl::reason_element(&explicit, &reason, SINGLE)?)
            } else {
                None
            };
            end(&revoked, SINGLE)?;
            RecordedStatus::Revoked {
                time,
                reason,
                offset: date.span().start,
            }
        }
        _ => {
            return Err(Error::new(
                ErrorCode::UnexpectedField,
                SINGLE,
                status.span().start,
            ));
        }
    };
    let this = required(&mut reader, SINGLE)?;
    let this_update = generalized(&reader, &this, SINGLE)?;
    let mut next = reader.next_element().field(SINGLE)?;
    let next_update =
        if let Some(wrapper) = next.filter(|element| element.tag() == Tag::context(true, 0)) {
            let mut explicit = reader.enter(&wrapper).field(SINGLE)?;
            let value = required(&mut explicit, SINGLE)?;
            end(&explicit, SINGLE)?;
            let value = generalized(&explicit, &value, SINGLE)?;
            next = reader.next_element().field(SINGLE)?;
            Some(value)
        } else {
            None
        };
    let extensions = extensions_element(&reader, next.as_ref(), 1, SINGLE)?;
    end(&reader, SINGLE)?;
    Ok(SingleResponse {
        id,
        status,
        this_update,
        next_update,
        extensions,
        span: element.span(),
    })
}

fn read_id<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<CertId<'a>> {
    let mut reader = sequence(parent, element, SINGLE)?;
    let algorithm = required(&mut reader, SINGLE)?;
    let algorithm = algorithm::read(&reader, &algorithm, SINGLE)?;
    let name = reader
        .expect(Tag::primitive(universal::OCTET_STRING))
        .field(SINGLE)?;
    let key = reader
        .expect(Tag::primitive(universal::OCTET_STRING))
        .field(SINGLE)?;
    let serial = reader.read_integer().field(SINGLE)?;
    end(&reader, SINGLE)?;
    Ok(CertId {
        algorithm,
        issuer_name_hash: name.contents(),
        issuer_key_hash: key.contents(),
        serial,
        span: element.span(),
    })
}

fn generalized(parent: &Reader<'_>, element: &Element<'_>, field: &'static str) -> Result<Time> {
    if element.tag() != Tag::primitive(universal::GENERALIZED_TIME) {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            field,
            element.span().start,
        ));
    }
    time::read_in(parent, element, field)
}
fn sequence<'a>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<Reader<'a>> {
    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            field,
            element.span().start,
        ));
    }
    parent.enter(element).field(field)
}
fn optional_extensions<'a>(
    reader: &mut Reader<'a>,
    tag: u32,
    field: &'static str,
) -> Result<Extensions<'a>> {
    let element = reader.next_element().field(field)?;
    extensions_element(reader, element.as_ref(), tag, field)
}
fn extensions_element<'a>(
    parent: &Reader<'a>,
    element: Option<&Element<'a>>,
    tag: u32,
    field: &'static str,
) -> Result<Extensions<'a>> {
    let Some(element) = element else {
        return Ok(Extensions::empty(parent.memory()));
    };
    if element.tag() != Tag::context(true, tag) {
        return Err(Error::new(
            ErrorCode::UnexpectedField,
            field,
            element.span().start,
        ));
    }
    let mut explicit = parent.enter(element).field(field)?;
    let value = required(&mut explicit, field)?;
    end(&explicit, field)?;
    extension::read(&explicit, &value, field)
}
fn required<'a>(reader: &mut Reader<'a>, field: &'static str) -> Result<Element<'a>> {
    let at = reader.offset();
    reader
        .next_element()
        .field(field)?
        .ok_or_else(|| Error::new(ErrorCode::MissingField, field, at))
}
fn end(reader: &structured_asn1::ScopedReader<'_, '_>, field: &'static str) -> Result<()> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::TrailingData, field, reader.offset()))
    }
}
