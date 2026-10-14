//! Original RFC3161 request fields; no requester identity or server policy.

use super::{HashAlgorithmReading, MessageImprint};
use crate::{Error, ErrorCode, Result};
use structured_asn1::{Element, Integer, Oid, Parser, Reader, Span, Tag, universal};
use structured_pkix::Extensions;

/// A syntactically conforming original `TimeStampReq`.
///
/// Algorithm support/width, extension recognition, replay history and trust
/// are separate decisions. Unlike token inspection, request syntax faults are
/// refused, not silently repaired or passed to the selected provider.
#[derive(Debug)]
pub struct Request<'a> {
    imprint: MessageImprint<'a>,
    policy: Option<Oid<'a>>,
    nonce: Option<Integer<'a>>,
    cert_req: bool,
    extensions: Option<Extensions<'a>>,
    span: Span,
    parser: &'a Parser,
}

impl<'a> Request<'a> {
    /// Reads the original SEQUENCE with inherited depth/current execution.
    /// BER is allowed by the producing reader; the caller selects encoding.
    /// RFC3161 §2.4.1 defines version 1 and the ordered optional fields.
    /// <https://www.rfc-editor.org/rfc/rfc3161.html#section-2.4.1>
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        const FIELD: &str = "timeStampReq";
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                FIELD,
                element.span().start,
            ));
        }
        let mut inside = parent
            .enter(element)
            .map_err(|source| Error::encoding(source, FIELD))?;
        let version = crate::signer::required(&mut inside, "timeStampReq.version")?;
        if version.tag() != Tag::primitive(universal::INTEGER) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                "timeStampReq.version",
                version.span().start,
            ));
        }
        let number = inside
            .integer(&version)
            .map_err(|source| Error::encoding(source, "timeStampReq.version"))?;
        if number.as_u64() != Some(1) {
            return Err(Error::schema(
                ErrorCode::UnsupportedVersion,
                "timeStampReq.version",
                version.span().start,
            ));
        }
        let imprint = crate::signer::required(&mut inside, "timeStampReq.messageImprint")?;
        let imprint = MessageImprint::read_fields(
            &inside,
            &imprint,
            super::imprint::ImprintFields {
                enclosing: "timeStampReq.messageImprint",
                algorithm: "timeStampReq.messageImprint.hashAlgorithm",
                hashed: "timeStampReq.messageImprint.hashedMessage",
            },
        )?;
        if !imprint.faults().is_empty()
            || !matches!(imprint.algorithm(), HashAlgorithmReading::Identifier(_))
        {
            return Err(Error::schema(
                ErrorCode::MalformedValue,
                "timeStampReq.messageImprint",
                imprint.span().start,
            ));
        }
        let mut output = Self {
            imprint,
            policy: None,
            nonce: None,
            cert_req: false,
            extensions: None,
            span: element.span(),
            parser: parent.parser(),
        };
        let mut previous = 0;
        while let Some(element) = inside
            .next_element()
            .map_err(|source| Error::encoding(source, FIELD))?
        {
            let ordinal = match element.tag() {
                tag if tag == Tag::primitive(universal::OID) => 1,
                tag if tag == Tag::primitive(universal::INTEGER) => 2,
                tag if tag == Tag::primitive(universal::BOOLEAN) => 3,
                tag if tag == Tag::context(true, 0) => 4,
                _ => {
                    return Err(Error::schema(
                        ErrorCode::UnknownField,
                        FIELD,
                        element.span().start,
                    ));
                }
            };
            if ordinal <= previous {
                return Err(Error::schema(
                    if ordinal == previous {
                        ErrorCode::DuplicateField
                    } else {
                        ErrorCode::FieldOrder
                    },
                    FIELD,
                    element.span().start,
                ));
            }
            previous = ordinal;
            output.read_optional(&inside, &element, ordinal)?;
        }
        Ok(output)
    }

    fn read_optional(
        &mut self,
        inside: &Reader<'a>,
        element: &Element<'a>,
        ordinal: u8,
    ) -> Result<()> {
        match ordinal {
            1 => {
                self.policy = Some(
                    inside
                        .oid(element)
                        .map_err(|source| Error::encoding(source, "timeStampReq.reqPolicy"))?,
                );
            }
            2 => {
                self.nonce = Some(
                    inside
                        .integer(element)
                        .map_err(|source| Error::encoding(source, "timeStampReq.nonce"))?,
                );
            }
            3 => {
                self.cert_req = inside
                    .boolean(element)
                    .map_err(|source| Error::encoding(source, "timeStampReq.certReq"))?;
                // X.690 §11.5 omits DEFAULT components in DER. BER's explicit
                // FALSE remains the same request value, not a repaired token.
                if !self.cert_req && inside.encoding() == structured_asn1::Encoding::Der {
                    return Err(Error::schema(
                        ErrorCode::DefaultWritten,
                        "timeStampReq.certReq",
                        element.span().start,
                    ));
                }
            }
            4 => {
                self.extensions = Some(
                    Extensions::read_implicit(inside, element, 0, "timeStampReq.extensions")
                        .map_err(Error::pkix)?,
                );
            }
            _ => unreachable!("ordinal comes from the four schema tags above"),
        }
        Ok(())
    }

    /// Full original requested imprint, including original parameter provenance.
    #[must_use]
    pub fn imprint(&self) -> &MessageImprint<'a> {
        &self.imprint
    }
    /// Requested policy, absent when none was specified.
    #[must_use]
    pub fn policy(&self) -> Option<Oid<'a>> {
        self.policy
    }
    /// Original minimal INTEGER view; no nonce bytes are fabricated.
    #[must_use]
    pub fn nonce(&self) -> Option<Integer<'a>> {
        self.nonce
    }
    /// RFC3161 schema default is false when the field is absent.
    #[must_use]
    pub fn cert_req(&self) -> bool {
        self.cert_req
    }
    /// All request extensions require server recognition, not only critical ones.
    #[must_use]
    pub fn extensions(&self) -> Option<&Extensions<'a>> {
        self.extensions.as_ref()
    }
    /// Whole original request span, in its producing source coordinates.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
    /// Original session identity, independent of shared account identity.
    #[must_use]
    pub fn same_session(&self, parent: &Reader<'_>) -> bool {
        core::ptr::eq(self.parser, parent.parser())
    }
}
