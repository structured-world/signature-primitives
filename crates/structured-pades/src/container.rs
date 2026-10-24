//! The actual decoded Contents owner and its carried DER CMS source context.

use crate::document::Document;
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::model::admit;
use crate::range::RangeSource;
use crate::signature::Signature;
use crate::source::Location;
use structured_asn1::{
    Reader,
    memory::{Memory, OwnedVec, Work},
};
use structured_cms::{ContentInfo, SignedData};

/// An ASN.1 or CMS diagnostic has coordinates in the decoded Contents value.
/// Its physical enclosing string is retained separately, never added as if
/// escape decoding were a one-to-one file-offset translation.
#[derive(Debug)]
pub enum ErrorOf<E> {
    /// Original PDF acquisition/processing failure.
    Pdf(ReadFailure<E>),
    /// Original certificate/status cause with its actual PDF enclosure.
    Pkix {
        /// Original encoded signature or timestamp enclosure.
        enclosure: Location,
        /// Unchanged certificate/status processing cause.
        cause: structured_pkix::Error,
    },
    /// Original ASN.1 decoding cause and honest physical enclosure.
    Encoding {
        /// Original encoded PDF string enclosure.
        enclosure: Location,
        /// Unchanged ASN.1 cause in decoded Contents coordinates.
        cause: structured_asn1::Error,
    },
    /// Original CMS cause and honest physical enclosure.
    Cms {
        /// Original encoded PDF string enclosure.
        enclosure: Location,
        /// Unchanged CMS cause in decoded Contents coordinates.
        cause: structured_cms::Error,
    },
}
impl<E> ErrorOf<E> {
    /// Terminal processing cannot be retained as an unreadable signature slot.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Pdf(cause) => cause.is_terminal(),
            Self::Encoding { cause, .. } => cause.is_resource(),
            Self::Cms { cause, .. } => cause.is_terminal(),
            Self::Pkix { cause, .. } => {
                cause.is_resource() || cause.code() == structured_pkix::ErrorCode::ForeignReader
            }
        }
    }
}

/// One original signature's decoded Contents, including the padding required
/// by VRI naming. This owner keeps the producing PDF Session and signature
/// membership; it cannot be constructed from replacement caller CMS bytes.
pub struct Container<'a, 's, D, G> {
    signature: Signature<'a, 's, D, G>,
    bytes: OwnedVec<u8, Memory>,
    der_length: usize,
    session: &'s crate::Session,
}

impl<'a, 's, D: Copy + Eq, G: Copy + Eq> Container<'a, 's, D, G> {
    pub(crate) fn require(
        &self,
        message: &SignedData<'_>,
        parent: &Reader<'_>,
    ) -> crate::Result<()> {
        let location = self.signature.contents();
        self.session
            .query(&parent.execution())
            .charge_work(1)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        let span = message.span();
        let start = usize::try_from(span.start).map_err(|_| Error {
            kind: ErrorKind::Foreign,
            location,
        })?;
        let end = start.checked_add(message.as_bytes().len()).ok_or(Error {
            kind: ErrorKind::Foreign,
            location,
        })?;
        if !self.session.owns(parent)
            || self
                .der()
                .get(start..end)
                .is_none_or(|bytes| !core::ptr::eq(bytes, message.as_bytes()))
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            });
        }
        Ok(())
    }
    /// The exact original dictionary whose Contents this owner decoded.
    #[must_use]
    pub fn signature(&self) -> Signature<'a, 's, D, G> {
        self.signature
    }

    /// Whole decoded Contents for VRI naming, including every padding octet.
    #[must_use]
    pub fn contents(&self) -> &[u8] {
        &self.bytes
    }

    /// One exact DER `ContentInfo` extent, excluding checked zero padding.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.bytes[..self.der_length]
    }

    /// Opens the original RFC3161 envelope without manufacturing another CMS
    /// input or dropping the PDF producing session's depth/work boundary.
    #[expect(
        clippy::result_large_err,
        reason = "an unchanged timestamp grammar error retains its actual PDF enclosure without allocating an error envelope"
    )]
    pub fn read_timestamp<'q, W: Work + 'q>(
        &'q self,
        operation: &W,
    ) -> Result<
        (structured_cms::timestamp::Token<'q>, Reader<'q>),
        ErrorOf<core::convert::Infallible>,
    > {
        let enclosure = self.signature.contents();
        let mut reader = self
            .session
            .carried(self.der(), operation)
            .map_err(|cause| ErrorOf::Encoding { enclosure, cause })?;
        let token = structured_cms::timestamp::Token::read_from(&mut reader)
            .map_err(|cause| ErrorOf::Cms { enclosure, cause })?;
        self.require(token.message(), &reader)
            .map_err(|cause| ErrorOf::Pdf(cause.into()))?;
        Ok((token, reader))
    }

    /// Opens the same carried document under a current operation. Root ASN.1
    /// depth is zero because a PDF string is not an ASN.1 enclosing element.
    #[expect(
        clippy::result_large_err,
        reason = "the original CMS diagnostic and encoded PDF enclosure must survive the scoped reading without a fallible error allocation"
    )]
    pub fn read<'q, W: Work + 'q>(
        &'q self,
        operation: &W,
    ) -> Result<(SignedData<'q>, Reader<'q>), ErrorOf<core::convert::Infallible>> {
        let enclosure = self.signature.contents();
        let mut root = self
            .session
            .carried(self.der(), operation)
            .map_err(|cause| ErrorOf::Encoding { enclosure, cause })?;
        let (content, parent) =
            ContentInfo::read(&mut root).map_err(|cause| ErrorOf::Cms { enclosure, cause })?;
        let execution = parent.execution();
        execution
            .charge_work(content.kind().as_bytes().len() as u64)
            .map_err(|cause| {
                ErrorOf::Pdf(ReadFailure::Format(Error {
                    kind: ErrorKind::Resource(cause),
                    location: enclosure,
                }))
            })?;
        if content.kind() != structured_cms::oid::SIGNED_DATA {
            return Err(ErrorOf::Pdf(ReadFailure::Format(Error {
                kind: ErrorKind::Syntax(Syntax::Container),
                location: enclosure,
            })));
        }
        let message = SignedData::read_element(&parent, content.content())
            .map_err(|cause| ErrorOf::Cms { enclosure, cause })?;
        Ok((message, parent))
    }
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// Decodes the actual selected Contents and isolates its DER extent before
    /// any crypto callback. EN319142-1 §5.2.1 requires a single DER `SignedData`;
    /// unused signature capacity consists only of zero padding.
    /// <https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
    #[expect(
        clippy::result_large_err,
        reason = "the original source/CMS refusal retains its original coordinate system rather than being boxed or flattened"
    )]
    pub async fn container<'a, W: Work>(
        &self,
        signature: Signature<'a, 's, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<Container<'a, 's, S::Document, S::Generation>, ErrorOf<S::Error>> {
        let bytes = self
            .contents(signature, operation)
            .await
            .map_err(ErrorOf::Pdf)?;
        let enclosure = signature.contents();
        let work = self.session.query(operation);
        let mut reader = self
            .session
            .carried(&bytes, &work)
            .map_err(|cause| ErrorOf::Encoding { enclosure, cause })?;
        let element = reader
            .next_element()
            .map_err(|cause| ErrorOf::Encoding { enclosure, cause })?
            .ok_or_else(|| {
                ErrorOf::Pdf(ReadFailure::Format(Error {
                    kind: ErrorKind::Syntax(Syntax::String),
                    location: enclosure,
                }))
            })?;
        let der_length = element.as_bytes().len();
        admit(&work, enclosure, (bytes.len() - der_length) as u64)
            .map_err(|cause| ErrorOf::Pdf(cause.into()))?;
        if bytes[der_length..].iter().any(|&byte| byte != 0) {
            return Err(ErrorOf::Pdf(
                Error {
                    kind: ErrorKind::Syntax(Syntax::String),
                    location: enclosure,
                }
                .into(),
            ));
        }
        drop(reader);
        Ok(Container {
            signature,
            bytes,
            der_length,
            session: self.session,
        })
    }
}
