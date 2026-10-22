//! Original RFC6960 requests, independently of transport and server policy.
//!
//! The complete DER request and signed TBS are borrowed. Certificates are
//! candidates, not trust anchors; signature, name, extension, nonce and response
//! identity facts never imply server authorization or certificate status.

use super::{CertId, end, extensions_element, read_id, required, sequence};
use crate::Certificate;
use crate::algorithm::{self, AlgorithmIdentifier};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::Extensions;
use crate::general_name::{self, GeneralName};
use crate::signature::SignatureValue;
use structured_asn1::memory::{Execution, OwnedVec, Work};
use structured_asn1::{Element, Encoding, Parser, Reader, Span, Tag, universal};

mod authentication;
mod binding;
pub use authentication::{
    RequestAuthentication, RequestSignatureError, RequestSignatureFailure, RequestorBinding,
    SignedRequest,
};
pub use binding::{BoundResponse, RequestLookup};

const FIELD: &str = "ocspRequest";
const TBS: &str = "ocspRequest.tbsRequest";
const ENTRY: &str = "ocspRequest.requestList";
const SIGNATURE: &str = "ocspRequest.signature";

/// One original certificate-status request, including its own extension scope.
#[derive(Debug)]
pub struct RequestEntry<'a> {
    id: CertId<'a>,
    extensions: Extensions<'a>,
    span: Span,
}
impl<'a> RequestEntry<'a> {
    /// Original certificate identity; does not authenticate its issuer.
    #[must_use]
    pub fn id(&self) -> CertId<'a> {
        self.id
    }
    /// Only this entry's extensions, distinct from request-wide extensions.
    #[must_use]
    pub fn extensions(&self) -> &Extensions<'a> {
        &self.extensions
    }
    /// Whole original entry range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}

/// Original optional signature and untrusted certificate candidates.
#[derive(Debug)]
pub struct RequestSignature<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    value: SignatureValue<'a>,
    certificates: OwnedVec<Certificate<'a>>,
}
impl<'a> RequestSignature<'a> {
    /// Original algorithm and parameters, without selecting a backend.
    #[must_use]
    pub fn algorithm(&self) -> AlgorithmIdentifier<'a> {
        self.algorithm
    }
    /// Original BIT STRING with its producing source context.
    #[must_use]
    pub fn value(&self) -> SignatureValue<'a> {
        self.value
    }
    /// Included candidates; none is trusted or selected automatically.
    #[must_use]
    pub fn certificates(&self) -> &[Certificate<'a>] {
        &self.certificates
    }
}

/// A complete version-one `OCSPRequest` with exact original signed bytes.
#[derive(Debug)]
pub struct OcspRequest<'a> {
    bytes: &'a [u8],
    signed: Element<'a>,
    span: Span,
    parser: &'a Parser,
    requestor: Option<GeneralName<'a>>,
    entries: OwnedVec<RequestEntry<'a>>,
    extensions: Extensions<'a>,
    signature: Option<RequestSignature<'a>>,
}

impl<'a> OcspRequest<'a> {
    /// Decode one complete request window. No signing, fetching, randomness,
    /// default-budget parser or certificate selection is performed.
    pub fn read(parser: &'a Parser, bytes: &'a [u8], base: u64) -> Result<Self> {
        let mut reader = parser.read(bytes, base).field(FIELD)?;
        let element = required(&mut reader, FIELD)?;
        let request = Self::read_element(&reader, &element)?;
        end(&reader, FIELD)?;
        Ok(request)
    }

    /// Decode an embedded request under DER and its actual producing session.
    /// RFC6960 §§4/4.1.1–4.1.2 require DER TBS, explicit wrappers, at least
    /// one request, and a requestorName when a signature is present.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.1.1>
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut der = parent.reread(element, Encoding::Der).field(FIELD)?;
        let root = der
            .expect(Tag::constructed(universal::SEQUENCE))
            .field(FIELD)?;
        let mut outer = der.enter(&root).field(FIELD)?;
        let signed = required(&mut outer, TBS)?;
        let mut tbs = sequence(&outer, &signed, TBS)?;
        let mut next = required(&mut tbs, TBS)?;
        if next.tag() == Tag::context(true, 0) {
            let mut explicit = tbs.enter(&next).field(TBS)?;
            let version = explicit.read_integer().field(TBS)?;
            explicit.charge(9).field(TBS)?;
            end(&explicit, TBS)?;
            // X.690 §11.5: a DER DEFAULT value must be omitted. Unknown
            // versions are unsupported, not silently treated as version one.
            return Err(Error::new(
                if version.as_u64() == Some(0) {
                    ErrorCode::MalformedValue
                } else {
                    ErrorCode::UnsupportedVersion
                },
                TBS,
                next.span().start,
            ));
        }
        let requestor = if next.tag() == Tag::context(true, 1) {
            let mut explicit = tbs.enter(&next).field(TBS)?;
            let name = required(&mut explicit, TBS)?;
            end(&explicit, TBS)?;
            let name = general_name::read(&explicit, &name, TBS)?;
            next = required(&mut tbs, TBS)?;
            Some(name)
        } else {
            None
        };
        let mut requests = sequence(&tbs, &next, ENTRY)?;
        let work = parent.execution();
        let mut entries = work.vector();
        while let Some(element) = requests.next_element().field(ENTRY)? {
            let mut entry = sequence(&requests, &element, ENTRY)?;
            let id = required(&mut entry, ENTRY)?;
            let id = read_id(&entry, &id, "ocspRequest.certID")?;
            let extra = entry.next_element().field(ENTRY)?;
            let extensions = extensions_element(&entry, extra.as_ref(), 0, ENTRY)?;
            end(&entry, ENTRY)?;
            entries
                .try_push(RequestEntry {
                    id,
                    extensions,
                    span: element.span(),
                })
                .map_err(|reason| Error::resource(reason, ENTRY, element.span().start))?;
        }
        if entries.is_empty() {
            return Err(Error::new(
                ErrorCode::EmptySequence,
                ENTRY,
                next.span().start,
            ));
        }
        let extra = tbs.next_element().field(TBS)?;
        let extensions = extensions_element(&tbs, extra.as_ref(), 2, TBS)?;
        end(&tbs, TBS)?;
        let signature = if let Some(wrapper) = outer.next_element().field(SIGNATURE)? {
            if wrapper.tag() != Tag::context(true, 0) {
                return Err(Error::new(
                    ErrorCode::UnexpectedField,
                    SIGNATURE,
                    wrapper.span().start,
                ));
            }
            if requestor.is_none() {
                return Err(Error::new(
                    ErrorCode::MissingField,
                    TBS,
                    signed.span().start,
                ));
            }
            Some(read_signature(&outer, &wrapper)?)
        } else {
            None
        };
        end(&outer, FIELD)?;
        Ok(Self {
            bytes: element.as_bytes(),
            signed,
            span: element.span(),
            parser: parent.parser(),
            requestor,
            entries: entries.into_owned(),
            extensions,
            signature,
        })
    }

    /// Whole original request DER; no re-encoding or copy.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Exact DER `TBSRequest` signed by the optional signature, excluding its wrapper.
    #[must_use]
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.signed.as_bytes()
    }
    /// Original whole TBS range.
    #[must_use]
    pub fn signed_span(&self) -> Span {
        self.signed.span()
    }
    /// Original whole request range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
    /// Original optional requestor name; not an authenticated identity by itself.
    #[must_use]
    pub fn requestor(&self) -> Option<&GeneralName<'a>> {
        self.requestor.as_ref()
    }
    /// Every original entry in wire order, including duplicate `CertIDs`.
    #[must_use]
    pub fn requests(&self) -> &[RequestEntry<'a>] {
        &self.entries
    }
    /// Request-wide extensions, independently of each entry's extensions.
    #[must_use]
    pub fn extensions(&self) -> &Extensions<'a> {
        &self.extensions
    }
    /// Optional original signature; absent never means an authenticated request.
    #[must_use]
    pub fn signature(&self) -> Option<&RequestSignature<'a>> {
        self.signature.as_ref()
    }
    /// Attach this original request to the current operation without scanning,
    /// cloning an account, or discarding either operation's cumulative ceiling.
    pub fn execution_in<'op, W: Work>(&self, current: &'op W) -> Execution<'op>
    where
        'a: 'op,
    {
        current.execution_for(self.parser)
    }
}

fn read_signature<'a>(parent: &Reader<'a>, wrapper: &Element<'a>) -> Result<RequestSignature<'a>> {
    let mut explicit = parent.enter(wrapper).field(SIGNATURE)?;
    let element = required(&mut explicit, SIGNATURE)?;
    end(&explicit, SIGNATURE)?;
    let mut inside = sequence(&explicit, &element, SIGNATURE)?;
    let algorithm = required(&mut inside, SIGNATURE)?;
    let algorithm = algorithm::read(&inside, &algorithm, SIGNATURE)?;
    let value = SignatureValue::read(&mut inside, SIGNATURE)?;
    let certificates = if let Some(wrapper) = inside.next_element().field(SIGNATURE)? {
        read_certificates(&inside, &wrapper, SIGNATURE)?
    } else {
        parent.execution().vector().into_owned()
    };
    end(&inside, SIGNATURE)?;
    Ok(RequestSignature {
        algorithm,
        value,
        certificates,
    })
}

pub(super) fn read_certificates<'a>(
    parent: &Reader<'a>,
    wrapper: &Element<'a>,
    field: &'static str,
) -> Result<OwnedVec<Certificate<'a>>> {
    if wrapper.tag() != Tag::context(true, 0) {
        return Err(Error::new(
            ErrorCode::UnexpectedField,
            field,
            wrapper.span().start,
        ));
    }
    let mut explicit = parent.enter(wrapper).field(field)?;
    let element = required(&mut explicit, field)?;
    end(&explicit, field)?;
    let mut sequence = sequence(&explicit, &element, field)?;
    let work = parent.execution();
    let mut certificates = work.vector();
    while let Some(element) = sequence.next_element().field(field)? {
        certificates
            .try_push(Certificate::read_element(&sequence, &element)?)
            .map_err(|reason| Error::resource(reason, field, element.span().start))?;
    }
    Ok(certificates.into_owned())
}
