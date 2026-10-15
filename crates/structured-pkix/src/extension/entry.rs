//! Shared Extension grammar; protocol-specific conformance and duplicate policy.

use crate::error::{CallbackError, CallbackResult, Error, ErrorCode, Located, Result};
use structured_asn1::{Element, Oid, ScopedReader, Span, Tag, universal};

/// Original scalar header facts, available before payload decoding/allocation.
///
/// A written DEFAULT FALSE has one readable field value. Its position is
/// available before value parsing; trailing bytes are retained separately by
/// [`ExtensionValue`]. Strict profiles refuse these facts, while inspection
/// profiles can admit and retain diagnostics before decoding.
/// No duplicate-extension or application recognition decision is made here.
#[derive(Debug, Clone, Copy)]
pub struct ExtensionHeader<'a> {
    kind: Oid<'a>,
    critical: bool,
    critical_span: Option<Span>,
    span: Span,
}

impl<'a> ExtensionHeader<'a> {
    /// Original extnID, validated by the producing reader.
    #[must_use]
    pub fn kind(self) -> Oid<'a> {
        self.kind
    }

    /// Written critical value, or the ASN.1 DEFAULT FALSE when absent.
    #[must_use]
    pub fn is_critical(self) -> bool {
        self.critical
    }

    /// Original complete BOOLEAN TLV span, absent when the flag was omitted.
    #[must_use]
    pub fn critical_span(self) -> Option<Span> {
        self.critical_span
    }

    /// Original complete extension SEQUENCE span.
    #[must_use]
    pub fn span(self) -> Span {
        self.span
    }

    /// A FALSE value was written explicitly (DER must omit it: X.690 §11.5).
    #[must_use]
    pub fn default_written(self) -> bool {
        self.critical_span.is_some() && !self.critical
    }
}

/// One structural extension and the caller's interpretation of its octets.
#[derive(Debug)]
pub struct ExtensionValue<'a, V> {
    header: ExtensionHeader<'a>,
    value: V,
    trailing_span: Option<Span>,
}

impl<'a, V> ExtensionValue<'a, V> {
    /// Scalar original header, including readable structural faults.
    #[must_use]
    pub fn header(&self) -> ExtensionHeader<'a> {
        self.header
    }

    /// Borrowed decoded value; accessing it performs no new parsing.
    #[must_use]
    pub fn value(&self) -> &V {
        &self.value
    }

    /// Original remaining range after extnValue, without interpreting it.
    #[must_use]
    pub fn trailing_span(&self) -> Option<Span> {
        self.trailing_span
    }

    /// Moves the decoded value, preserving any owned allocation charge.
    #[must_use]
    pub fn into_value(self) -> V {
        self.value
    }
}

/// Decodes the common Extension grammar before invoking a payload callback.
///
/// RFC5280 §4.1 defines SEQUENCE { OID, BOOLEAN DEFAULT FALSE, OCTET STRING }.
/// X.690 §8.7 permits constructed BER octets; the selected profile/callback
/// decides whether to retain that reading or refuse it. The callback receives
/// header metadata before any payload decoding, the original producing Reader
/// and the original extnValue Element (whole and contents spans stay distinct).
/// It must admit its work/allocations through that reader's Execution.
///
/// Structural grammar errors refuse before the callback. Readable default/
/// trailing facts are metadata, not an implicit permissive certificate mode.
/// Callback failures retain their original cause and are never converted to
/// a malformed-value answer. This function performs no mandatory allocation
/// other than the producing reader's already-accounted path operations.
/// <https://www.rfc-editor.org/rfc/rfc5280#section-4.1>
pub fn read_with<'a: 'operation, 'operation, V, E>(
    parent: &ScopedReader<'a, 'operation>,
    element: &Element<'a>,
    field: &'static str,
    read_value: impl FnOnce(
        &ExtensionHeader<'a>,
        &ScopedReader<'a, 'operation>,
        &Element<'a>,
    ) -> core::result::Result<V, E>,
) -> CallbackResult<ExtensionValue<'a, V>, E> {
    open(parent, element, field)?.read_with(read_value)
}

/// Header and deferred original value reader, without decoding extnValue yet.
///
/// Inspection callers can admit a DEFAULT diagnostic before even reading the
/// next value header. Missing/malformed values then cannot erase that prior
/// header fault. No borrowed callback state or duplicate policy is imposed.
pub struct ScopedExtensionFields<'a: 'operation, 'operation> {
    header: ExtensionHeader<'a>,
    inside: ScopedReader<'a, 'operation>,
    pending: ValueState<'a>,
    field: &'static str,
}

/// Header/value cursor when source and operation have the same lifetime.
pub type ExtensionFields<'a> = ScopedExtensionFields<'a, 'a>;

enum ValueState<'a> {
    Read(Option<Element<'a>>),
    Deferred,
}

impl<'a: 'operation, 'operation> ScopedExtensionFields<'a, 'operation> {
    /// Original header facts, before deferred extnValue parsing.
    #[must_use]
    pub fn header(&self) -> ExtensionHeader<'a> {
        self.header
    }

    /// Producing execution/depth, for header diagnostic admission.
    #[must_use]
    pub fn reader(&self) -> &ScopedReader<'a, 'operation> {
        &self.inside
    }

    /// Reads the one original universal OCTET STRING, then decodes its value.
    /// The callback sees the reader just after that element, so remaining
    /// bytes are trailing structural data. A strict callback can refuse them
    /// before allocation; inspection can retain the returned trailing span.
    pub fn read_with<V, E>(
        mut self,
        read_value: impl FnOnce(
            &ExtensionHeader<'a>,
            &ScopedReader<'a, 'operation>,
            &Element<'a>,
        ) -> core::result::Result<V, E>,
    ) -> CallbackResult<ExtensionValue<'a, V>, E> {
        let value = match self.pending {
            ValueState::Read(value) => value,
            ValueState::Deferred => self.inside.next_element().field(self.field)?,
        }
        .ok_or_else(|| Error::new(ErrorCode::MissingField, self.field, self.header.span.start))?;
        if value.tag() != Tag::primitive(universal::OCTET_STRING)
            && value.tag() != Tag::constructed(universal::OCTET_STRING)
        {
            return Err(Error::new(
                ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                self.field,
                value.span().start,
            )
            .into());
        }
        let trailing_span = if self.inside.is_empty() {
            None
        } else {
            Some(Span {
                start: self.inside.offset(),
                length: self.inside.remaining().len() as u64,
            })
        };
        let decoded =
            read_value(&self.header, &self.inside, &value).map_err(CallbackError::Callback)?;
        Ok(ExtensionValue {
            header: self.header,
            value: decoded,
            trailing_span,
        })
    }
}

/// Reads Extension's OID/optional BOOLEAN, deferring extnValue after a flag.
/// This is the same kernel used by [`read_with`]. Applications needing header
/// diagnostics before payload allocation use this two-stage form.
pub fn open<'a: 'operation, 'operation>(
    parent: &ScopedReader<'a, 'operation>,
    element: &Element<'a>,
    field: &'static str,
) -> Result<ScopedExtensionFields<'a, 'operation>> {
    let fail = |code, offset| Error::new(code, field, offset);
    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(fail(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            element.span().start,
        ));
    }
    let mut inside = parent.enter(element).field(field)?;
    let kind = inside.read_oid().field(field)?;
    let value = inside.next_element().field(field)?;
    let mut pending = ValueState::Read(value);
    let mut critical_span = None;
    let mut critical = false;
    if let Some(flag) = value
        && flag.tag() == Tag::primitive(universal::BOOLEAN)
    {
        critical = inside.boolean(&flag).field(field)?;
        critical_span = Some(flag.span());
        // Defer even reading this value's header until the caller has had
        // the opportunity to admit a written-default diagnostic.
        pending = ValueState::Deferred;
    }
    Ok(ScopedExtensionFields {
        header: ExtensionHeader {
            kind,
            critical,
            critical_span,
            span: element.span(),
        },
        inside,
        pending,
        field,
    })
}
