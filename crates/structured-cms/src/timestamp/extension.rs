//! `TSTInfo` extensions reuse structural PKIX grammar with inspection recovery.

use super::record;
use crate::{Error, ErrorCode, Octets, Result};
use structured_asn1::memory::{Execution, OwnedVec, Work};
use structured_asn1::{Element, Oid, Parser, Reader, Span, Tag};
use structured_pkix::{error::CallbackError, extension};

const FIELD: &str = "tstInfo.extensions";

/// One original extension, with logical OCTET STRING content still borrowed.
#[derive(Debug)]
pub struct TokenExtension<'a> {
    kind: Oid<'a>,
    critical: bool,
    value: Octets<'a>,
    span: Span,
    value_span: Span,
}

impl<'a> TokenExtension<'a> {
    fn read<W: Work>(
        parent: &Reader<'a>,
        element: &Element<'a>,
        faults: &mut OwnedVec<Error, W>,
    ) -> Result<Self> {
        let fields = extension::open(parent, element, FIELD).map_err(Error::pkix)?;
        let header = fields.header();
        if header.default_written()
            && let Some(span) = header.critical_span()
        {
            record(
                faults,
                Error::schema(ErrorCode::DefaultWritten, FIELD, span.start),
            )?;
        }
        let reading = fields
            .read_with(|_, reader, value| {
                Octets::read(reader, value, FIELD).map(|octets| (octets, value.span()))
            })
            .map_err(|error| match error {
                CallbackError::Processing(source) => Error::pkix(source),
                CallbackError::Callback(source) => source,
            })?;
        if let Some(span) = reading.trailing_span() {
            record(
                faults,
                Error::schema(ErrorCode::TrailingData, FIELD, span.start),
            )?;
        }
        let (value, value_span) = reading.into_value();
        Ok(Self {
            kind: header.kind(),
            critical: header.is_critical(),
            value,
            span: header.span(),
            value_span,
        })
    }
    /// Original extnID validated by the common OID decoder.
    #[must_use]
    pub fn kind(&self) -> Oid<'a> {
        self.kind
    }
    /// Original critical flag or its schema-defined absent FALSE default.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.critical
    }
    /// Original logical value octets, without forced joined retention.
    #[must_use]
    pub fn value(&self) -> &Octets<'a> {
        &self.value
    }
    /// Whole original Extension range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
    /// Whole extnValue TLV, separately from content-fragment spans.
    #[must_use]
    pub fn value_span(&self) -> Span {
        self.value_span
    }
}

/// Recovered first readings plus independently owned source-located faults.
/// These are inspection facts, not extension recognition or token acceptance.
#[derive(Debug)]
pub struct TokenExtensions<'a> {
    entries: OwnedVec<TokenExtension<'a>>,
    faults: OwnedVec<Error>,
    span: Span,
    parser: &'a Parser,
}

/// Recognition cannot erase an execution refusal or an opaque callback cause.
#[derive(Debug)]
pub enum RecognitionError<E> {
    /// Original common processing/resource refusal.
    Processing(Error),
    /// Original extension handler failure at the actual extension enclosure.
    Callback {
        /// Original extension range in the producing reader's coordinates.
        span: Span,
        /// Original handler cause, including its own resource refusal.
        source: E,
    },
}

impl<'a> TokenExtensions<'a> {
    /// Reads `[1] IMPLICIT Extensions` from the original producing reader.
    ///
    /// RFC3161 §2.4.2 uses RFC5280 Extension grammar but specifies no recovery.
    /// This inspection contract retains equal logical duplicate values once
    /// with faults and refuses conflicts; bounded unreadable members leave
    /// independent later members visible. DEFAULT diagnostics precede deferred
    /// value parsing, and trailing diagnostics follow it. The strict certificate
    /// catalogue stays strict; it is not reused as a permissive token profile.
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2>
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        if element.tag() != Tag::context(true, 1) {
            return Err(Error::schema(
                ErrorCode::UnexpectedTag,
                FIELD,
                element.span().start,
            ));
        }
        let mut inside = parent
            .enter(element)
            .map_err(|error| Error::encoding(error, FIELD))?;
        let execution = parent.execution();
        let mut entries: OwnedVec<TokenExtension<'a>, _> = execution.vector();
        let mut faults = execution.vector();
        while let Some(element) = inside
            .next_element()
            .map_err(|error| Error::encoding(error, FIELD))?
        {
            let candidate = TokenExtension::read(&inside, &element, &mut faults);
            let candidate = match candidate {
                Ok(candidate) => candidate,
                Err(error) if error.is_terminal() => return Err(error),
                Err(error) => {
                    record(&mut faults, error)?;
                    continue;
                }
            };
            let at = candidate.span.start;
            let mut duplicate = false;
            for earlier in &entries {
                execution
                    .charge_work(1)
                    .map_err(|reason| Error::resource(reason, FIELD, at))?;
                if earlier.kind.as_bytes().len() != candidate.kind.as_bytes().len() {
                    continue;
                }
                execution
                    .charge_work(candidate.kind.as_bytes().len() as u64)
                    .map_err(|reason| Error::resource(reason, FIELD, at))?;
                if earlier.kind != candidate.kind {
                    continue;
                }
                if earlier.critical != candidate.critical
                    || !earlier
                        .value
                        .same_value(&candidate.value, &inside, FIELD, at)?
                {
                    return Err(Error::schema(ErrorCode::DuplicateField, FIELD, at));
                }
                record(
                    &mut faults,
                    Error::schema(ErrorCode::DuplicateField, FIELD, at),
                )?;
                duplicate = true;
                break;
            }
            if !duplicate {
                entries
                    .try_push(candidate)
                    .map_err(|reason| Error::resource(reason, FIELD, at))?;
            }
        }
        if entries.is_empty() {
            record(
                &mut faults,
                Error::schema(ErrorCode::MalformedValue, FIELD, element.span().start),
            )?;
        }
        Ok(Self {
            entries: entries.into_owned(),
            faults: faults.into_owned(),
            span: element.span(),
            parser: parent.parser(),
        })
    }

    /// Retained first readings in original order; no lookup/traversal is done.
    #[must_use]
    pub fn entries(&self) -> &[TokenExtension<'a>] {
        &self.entries
    }
    /// Structural/recovery diagnostics, distinct from resource refusal.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }
    /// Original implicit wrapper range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }

    /// Recognizes every critical token extension under current query work.
    ///
    /// RFC3161 §2.4.2 defines the extension structure but does not mandate a
    /// client's understanding of all extension semantics. This explicit query
    /// reports unrecognized critical entries for the caller's acceptance rule;
    /// it does not assert that all noncritical entries are acceptable. Request
    /// extensions have a different server-recognition contract (§2.4.1) and
    /// are not processed by this method.
    /// Each catalogue entry is paid before inspection, including noncritical
    /// entries. The handler must admit its own data-dependent OID/value work;
    /// this metadata charge cannot cover an arbitrary extension implementation.
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2>
    pub fn unrecognized_critical<E>(
        &self,
        parent: &Reader<'_>,
        mut recognizes: impl FnMut(&TokenExtension<'a>, &Execution<'_>) -> core::result::Result<bool, E>,
    ) -> core::result::Result<OwnedVec<Oid<'a>>, RecognitionError<E>> {
        if !core::ptr::eq(self.parser, parent.parser()) {
            return Err(RecognitionError::Processing(Error::pkix(
                structured_pkix::Error::new(
                    structured_pkix::ErrorCode::ForeignReader,
                    FIELD,
                    self.span.start,
                ),
            )));
        }
        let work = parent.execution();
        let mut unknown = work.vector();
        for extension in &self.entries {
            work.charge_work(1).map_err(|reason| {
                RecognitionError::Processing(Error::resource(reason, FIELD, extension.span.start))
            })?;
            if !extension.critical {
                continue;
            }
            if !recognizes(extension, &work).map_err(|source| RecognitionError::Callback {
                span: extension.span,
                source,
            })? {
                unknown.try_push(extension.kind).map_err(|reason| {
                    RecognitionError::Processing(Error::resource(
                        reason,
                        FIELD,
                        extension.span.start,
                    ))
                })?;
            }
        }
        Ok(unknown.into_owned())
    }
}
