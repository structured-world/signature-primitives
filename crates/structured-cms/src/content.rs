//! CMS content envelopes, preserving original elements and producing readers.

use crate::{Error, ErrorCode, Octets, Result};
use structured_asn1::{Element, Oid, Reader, Span, Tag, universal};

/// The CMS `ContentInfo` envelope (RFC 5652 §3).
///
/// Its explicit content field is mandatory. Detached `SignedData` instead omits
/// the inner [`Encapsulated`] `eContent` (RFC 5652 §5.2). This type does not use
/// the older PKCS#7 optional outer-content grammar from RFC 2315 §7.
#[derive(Debug)]
pub struct ContentInfo<'a> {
    kind: Oid<'a>,
    content: Element<'a>,
    span: Span,
}

impl<'a> ContentInfo<'a> {
    /// Reads one complete envelope, refusing bytes after that envelope.
    ///
    /// The returned reader produced the content element and retains the same
    /// parser budget, execution account, diagnostic path and inherited depth.
    /// It is used directly by the selected content schema; no encode/reparse
    /// adapter or replacement parser is created.
    pub fn read(reader: &mut Reader<'a>) -> Result<(Self, Reader<'a>)> {
        let outer = reader
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|error| Error::encoding(error, "contentInfo"))?;
        let result = Self::read_element(reader, &outer)?;
        if !reader.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                "contentInfo",
                reader.offset(),
            ));
        }
        Ok(result)
    }

    /// Reads an embedded envelope from its original producing parent.
    ///
    /// Unlike [`Self::read`], surrounding siblings belong to the enclosing
    /// schema and are not refused. Envelope components themselves remain exact.
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<(Self, Reader<'a>)> {
        const FIELD: &str = "contentInfo";
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
        let kind = inside
            .read_oid()
            .map_err(|error| Error::encoding(error, "contentInfo.contentType"))?;
        // RFC5652 §§3/12.1 require outer content (no OPTIONAL), unlike PKCS#7
        // RFC2315 §7. Detached CMS omits only EncapsulatedContentInfo.eContent
        // (§5.2); it does not omit this wrapper or its single inner value.
        // https://www.rfc-editor.org/rfc/rfc5652#section-3
        let wrapper = inside
            .expect(Tag::context(true, 0))
            .map_err(|error| Error::encoding(error, "contentInfo.content"))?;
        let mut explicit = inside
            .enter(&wrapper)
            .map_err(|error| Error::encoding(error, "contentInfo.content"))?;
        let content = explicit
            .next_element()
            .map_err(|error| Error::encoding(error, "contentInfo.content"))?
            .ok_or_else(|| {
                Error::schema(
                    ErrorCode::MissingField,
                    "contentInfo.content",
                    wrapper.span().start,
                )
            })?;
        if !explicit.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                "contentInfo.content",
                explicit.offset(),
            ));
        }
        if !inside.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                FIELD,
                inside.offset(),
            ));
        }
        Ok((
            Self {
                kind,
                content,
                span: element.span(),
            },
            explicit,
        ))
    }

    /// The original content type identifier, without an application interpretation.
    #[must_use]
    pub fn kind(&self) -> Oid<'a> {
        self.kind
    }

    /// The original embedded content element, including its encoding.
    #[must_use]
    pub fn content(&self) -> &Element<'a> {
        &self.content
    }

    /// The envelope's original source range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}

/// Attached or absent encapsulated content (RFC 5652 §5.2).
#[derive(Debug)]
pub struct Encapsulated<'a> {
    kind: Oid<'a>,
    content: Option<Octets<'a>>,
    span: Span,
}

impl<'a> Encapsulated<'a> {
    /// Reads type and optional explicit OCTET STRING under the original parent.
    ///
    /// Absence denotes detached content. Empty attached content is a distinct
    /// value, and no caller-supplied payload silently replaces attached bytes.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        const FIELD: &str = "signedData.encapContentInfo";
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
        let kind = inside
            .read_oid()
            .map_err(|error| Error::encoding(error, "signedData.encapContentInfo.eContentType"))?;
        let content = if let Some(wrapper) = inside
            .next_element()
            .map_err(|error| Error::encoding(error, FIELD))?
        {
            const CONTENT: &str = "signedData.encapContentInfo.eContent";
            if wrapper.tag() != Tag::context(true, 0) {
                return Err(Error::schema(
                    ErrorCode::UnexpectedTag,
                    CONTENT,
                    wrapper.span().start,
                ));
            }
            let mut explicit = inside
                .enter(&wrapper)
                .map_err(|error| Error::encoding(error, CONTENT))?;
            let octets = explicit
                .next_element()
                .map_err(|error| Error::encoding(error, CONTENT))?
                .ok_or_else(|| {
                    Error::schema(ErrorCode::MissingField, CONTENT, wrapper.span().start)
                })?;
            let content = Octets::read(&explicit, &octets, CONTENT)?;
            if !explicit.is_empty() {
                return Err(Error::schema(
                    ErrorCode::TrailingData,
                    CONTENT,
                    explicit.offset(),
                ));
            }
            Some(content)
        } else {
            None
        };
        if !inside.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                FIELD,
                inside.offset(),
            ));
        }
        Ok(Self {
            kind,
            content,
            span: element.span(),
        })
    }

    /// The original content type identifier.
    #[must_use]
    pub fn kind(&self) -> Oid<'a> {
        self.kind
    }

    /// Attached logical octets, or `None` for detached content.
    #[must_use]
    pub fn content(&self) -> Option<&Octets<'a>> {
        self.content.as_ref()
    }

    /// Whether the envelope omitted the content field.
    #[must_use]
    pub fn is_detached(&self) -> bool {
        self.content.is_none()
    }

    /// The encapsulated content-info's original range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}
