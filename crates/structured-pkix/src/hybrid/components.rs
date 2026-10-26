use super::{
    ALT_SIGNATURE_ALGORITHM, ALT_SIGNATURE_VALUE, FIELD, Fault, SUBJECT_ALT_PUBLIC_KEY_INFO,
    terminal,
};
use crate::algorithm::{self, AlgorithmIdentifier};
use crate::error::Located;
use crate::signature::SignatureValue;
use crate::{Error, ErrorCode, Extensions, PublicKeyInfo, Result};
use structured_asn1::memory::Work;
use structured_asn1::{Element, ScopedReader, Span};

/// One original component, its criticality when an extension, and its reading.
/// Missing/malformed values remain inspectable; resource/caller failures are terminal.
#[derive(Debug)]
pub struct Component<'a, T> {
    span: Option<Span>,
    critical: Option<bool>,
    bytes: Option<&'a [u8]>,
    value: core::result::Result<Option<T>, Fault>,
    field: &'static str,
    at: u64,
}
impl<'a, T: Copy> Component<'a, T> {
    pub(super) fn absent(field: &'static str) -> Self {
        Self {
            span: None,
            critical: None,
            bytes: None,
            value: Ok(None),
            field,
            at: 0,
        }
    }
    /// Original whole extension or attribute range; absent for a missing component.
    #[must_use]
    pub fn span(&self) -> Option<Span> {
        self.span
    }
    /// An extension's criticality; attributes and absent values have none.
    #[must_use]
    pub fn critical(&self) -> Option<bool> {
        self.critical
    }
    /// Original encoded payload, including malformed bytes when readable.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        self.bytes
    }
    /// Successfully decoded value, actual absence or the original conformance fault.
    pub fn reading(&self) -> core::result::Result<Option<T>, Fault> {
        self.value
    }
    pub(super) fn require(&self) -> Result<T> {
        match self.value {
            Ok(Some(value)) => Ok(value),
            Ok(None) => Err(Error::new(ErrorCode::MissingField, self.field, self.at)),
            Err(fault) => Err(fault.error()),
        }
    }
    pub(super) fn read(
        span: Span,
        critical: Option<bool>,
        bytes: &'a [u8],
        field: &'static str,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<Self> {
        let value = match action() {
            Ok(value) => Ok(Some(value)),
            Err(error) if terminal(&error) => return Err(error),
            Err(error) => Err(Fault::of(&error)),
        };
        Ok(Self {
            span: Some(span),
            critical,
            bytes: Some(bytes),
            value,
            field,
            at: span.start,
        })
    }
}

/// Independent alternative component readings. No mathematical or trust verdict.
#[derive(Debug)]
pub struct Components<'a> {
    /// Subject's alternative SPKI (absent for a normal CRL).
    pub key: Component<'a, PublicKeyInfo<'a>>,
    /// Protected alternative signature algorithm.
    pub algorithm: Component<'a, AlgorithmIdentifier<'a>>,
    /// Alternative signature's original BIT STRING.
    pub signature: Component<'a, SignatureValue<'a>>,
}
impl<'a> Components<'a> {
    pub(super) fn empty(at: u64) -> Self {
        let mut result = Self {
            key: Component::absent("hybrid.subjectAltPublicKeyInfo"),
            algorithm: Component::absent("hybrid.altSignatureAlgorithm"),
            signature: Component::absent("hybrid.altSignatureValue"),
        };
        result.key.at = at;
        result.algorithm.at = at;
        result.signature.at = at;
        result
    }
    pub(super) fn signature_fields(
        &self,
    ) -> Result<(AlgorithmIdentifier<'a>, SignatureValue<'a>, Span)> {
        let algorithm = self.algorithm.require()?;
        let signature = self.signature.require()?;
        Ok((
            algorithm,
            signature,
            self.signature
                .span
                .expect("a decoded signature has a source"),
        ))
    }
}

pub(super) fn extensions<'a, W: Work>(
    extensions: &Extensions<'a>,
    work: &W,
    at: u64,
) -> Result<Components<'a>> {
    work.charge_work(1)
        .map_err(|e| Error::resource(e, FIELD, at))?;
    let mut output = Components::empty(at);
    for extension in extensions.iter(work) {
        let extension = extension?;
        let kind = extension.kind();
        // Admit OID comparisons before inspecting attacker-controlled contents.
        super::identifier_work(kind, work, extension.span().start)?;
        if kind == SUBJECT_ALT_PUBLIC_KEY_INFO {
            output.key = Component::read(
                extension.span(),
                Some(extension.is_critical()),
                extension.value(),
                "hybrid.subjectAltPublicKeyInfo",
                || {
                    let mut reader = extension.reader_scoped(work).field(FIELD)?;
                    let element = one(&mut reader)?;
                    PublicKeyInfo::read_element(&reader, &element, FIELD)
                },
            )?;
        } else if kind == ALT_SIGNATURE_ALGORITHM {
            output.algorithm = Component::read(
                extension.span(),
                Some(extension.is_critical()),
                extension.value(),
                "hybrid.altSignatureAlgorithm",
                || {
                    let mut reader = extension.reader_scoped(work).field(FIELD)?;
                    let element = one(&mut reader)?;
                    algorithm::read(&reader, &element, FIELD)
                },
            )?;
        } else if kind == ALT_SIGNATURE_VALUE {
            output.signature = Component::read(
                extension.span(),
                Some(extension.is_critical()),
                extension.value(),
                "hybrid.altSignatureValue",
                || {
                    let mut reader = extension.reader_scoped(work).field(FIELD)?;
                    let value = SignatureValue::read(&mut reader, FIELD)?;
                    end(&reader)?;
                    Ok(value)
                },
            )?;
        }
    }
    Ok(output)
}

pub(super) fn one<'a>(reader: &mut ScopedReader<'a, '_>) -> Result<Element<'a>> {
    let value = reader
        .next_element()
        .field(FIELD)?
        .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, reader.offset()))?;
    end(reader)?;
    Ok(value)
}
pub(super) fn end(reader: &ScopedReader<'_, '_>) -> Result<()> {
    if !reader.is_empty() {
        return Err(Error::new(ErrorCode::TrailingData, FIELD, reader.offset()));
    }
    Ok(())
}
