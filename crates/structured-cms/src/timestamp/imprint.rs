//! Original `MessageImprint` fields, without a concrete digest backend.

use super::record;
use crate::{Error, ErrorCode, Octets, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Oid, Reader, Span, Tag, universal};
use structured_pkix::AlgorithmIdentifier;

#[derive(Debug, Clone, Copy)]
pub(super) struct ImprintFields {
    pub enclosing: &'static str,
    pub algorithm: &'static str,
    pub hashed: &'static str,
}

const TOKEN: ImprintFields = ImprintFields {
    enclosing: "tstInfo.messageImprint",
    algorithm: "tstInfo.messageImprint.hashAlgorithm",
    hashed: "tstInfo.messageImprint.hashedMessage",
};

/// A written identifier versus uniquely bounded malformed algorithm syntax.
#[derive(Debug)]
pub enum HashAlgorithmReading<'a> {
    /// Original `AlgorithmIdentifier`, with original parameter/depth provenance.
    Identifier(AlgorithmIdentifier<'a>),
    /// No identifier may be dispatched as if its syntax were conforming.
    Malformed {
        /// Whole original malformed field, never retagged or re-encoded.
        element: Element<'a>,
        /// Bare OID only when the shared OID decoder actually read it.
        kind: Option<Oid<'a>>,
    },
}

/// Borrowed algorithm/hash fields and independently accounted diagnostics.
/// Reading is independent of algorithm support, output width and token trust.
#[derive(Debug)]
pub struct MessageImprint<'a> {
    algorithm: HashAlgorithmReading<'a>,
    hashed: Octets<'a>,
    faults: OwnedVec<Error>,
    span: Span,
    fields: ImprintFields,
}

impl<'a> MessageImprint<'a> {
    /// Reads the two original fields of RFC3161 §2.4.1 `MessageImprint`.
    ///
    /// The normative algorithm is `AlgorithmIdentifier`. Inspection retains a
    /// uniquely bounded malformed first field and readable OCTET STRING, with
    /// faults; a bare OID does not become a fabricated valid identifier. This
    /// recovery is not specified by RFC3161. Missing/unreadable hash refuses.
    /// The selected provider resolves written identifiers and their full
    /// parameter/output semantics separately; no fixed hash registry is assumed.
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1>
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        Self::read_fields(parent, element, TOKEN)
    }

    pub(super) fn read_fields(
        parent: &Reader<'a>,
        element: &Element<'a>,
        fields: ImprintFields,
    ) -> Result<Self> {
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                fields.enclosing,
                element.span().start,
            ));
        }
        let mut inside = parent
            .enter(element)
            .map_err(|error| Error::encoding(error, fields.enclosing))?;
        let written = crate::signer::required(&mut inside, fields.algorithm)?;
        let execution = parent.execution();
        let mut faults = execution.vector();
        let algorithm = if written.tag() == Tag::constructed(universal::SEQUENCE) {
            match structured_pkix::algorithm::read(&inside, &written, fields.algorithm)
                .map_err(Error::pkix)
            {
                Ok(identifier) => HashAlgorithmReading::Identifier(identifier),
                Err(error) if error.is_terminal() => return Err(error),
                Err(error) => {
                    record(&mut faults, error)?;
                    HashAlgorithmReading::Malformed {
                        element: written,
                        kind: None,
                    }
                }
            }
        } else {
            let kind = if written.tag() == Tag::primitive(universal::OID) {
                match inside
                    .oid(&written)
                    .map_err(|error| Error::encoding(error, fields.algorithm))
                {
                    Ok(kind) => Some(kind),
                    Err(error) if error.is_terminal() => return Err(error),
                    Err(error) => {
                        record(&mut faults, error)?;
                        None
                    }
                }
            } else {
                None
            };
            record(
                &mut faults,
                Error::schema(
                    ErrorCode::MalformedValue,
                    fields.algorithm,
                    written.span().start,
                ),
            )?;
            HashAlgorithmReading::Malformed {
                element: written,
                kind,
            }
        };
        let hashed = crate::signer::required(&mut inside, fields.hashed)?;
        let hashed = Octets::read(&inside, &hashed, fields.hashed)?;
        if !inside.is_empty() {
            record(
                &mut faults,
                Error::schema(ErrorCode::TrailingData, fields.enclosing, inside.offset()),
            )?;
        }
        Ok(Self {
            algorithm,
            hashed,
            faults: faults.into_owned(),
            span: element.span(),
            fields,
        })
    }

    /// Original written algorithm or explicit unreadable/malformed alternative.
    #[must_use]
    pub fn algorithm(&self) -> &HashAlgorithmReading<'a> {
        &self.algorithm
    }
    /// Original logical hash bytes, including original BER fragment spans.
    #[must_use]
    pub fn hashed(&self) -> &Octets<'a> {
        &self.hashed
    }
    /// Original complete `MessageImprint` range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
    /// Readable faults, which cannot be silently ignored for proof acceptance.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }
    pub(super) fn fields(&self) -> ImprintFields {
        self.fields
    }
}
