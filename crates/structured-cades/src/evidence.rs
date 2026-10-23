//! `CAdES` evidence records and historical proof-of-existence composition.
//!
//! RFC4998 Appendix A binds internal/external records to original CMS bytes.
//! TS101733 V2.2.1 §6.5.1 has a different eight-hash `PoE` recipe; its unsigned
//! `poeDate` orders instances and is never authenticated occurrence time.
//! <https://www.rfc-editor.org/rfc/rfc4998#appendix-A>
//! <https://www.etsi.org/deliver/etsi_ts/101700_101799/101733/02.02.01_60/ts_101733v020201p.pdf>

use crate::{Error, Result};
use structured_asn1::{Element, Encoding, Parser, Reader, Span, Tag, universal};
use structured_cms::{
    ErrorCode,
    evidence::EvidenceRecord,
    signed::{CertificateSet, RevocationSet},
    timestamp::Token,
};
use structured_pkix::temporal::{self, Reading};

const FIELD: &str = "cades.longTermValidation";
mod closure;
mod cms_object;
mod coverage;
mod poe;
mod record;
pub use closure::{Closure, ClosureError, History as PreservationHistory, close_preservation};
pub use cms_object::{CmsObject, CmsSnapshot, ObjectError, SnapshotError};
pub use coverage::{Archive as RecordArchive, CoverageError as RecordCoverageError};
pub use poe::{
    CheckError as PoeCheckError, CheckResult as PoeCheckResult, InputError as PoeInputError,
};
pub use record::{
    Authorities, Authority, CheckError as RecordCheckError, CheckResult as RecordCheckResult,
    Checked as RecordChecked, SelectionError as AuthorityError, SourceError as RecordSourceError,
    Verified as VerifiedRecord,
};

/// Original optional `PoE` value. Absence is an unfinished obligation, not an
/// empty successful proof. The two alternatives have different input recipes.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Both first-read alternatives retain quota-backed flat catalogues inline; boxing adds an allocation to every proof."
)]
pub enum PoeValue<'d> {
    /// `[0] EXPLICIT` RFC3161 token covering the complete eight-hash value.
    Timestamp(Token<'d>),
    /// `[1] EXPLICIT` ERS record covering that value for each record algorithm.
    EvidenceRecord(EvidenceRecord<'d>),
}

/// Complete original TS101733 §6.5.1 enclosure, including validation extras.
/// Its date and unprotected material do not establish a successful `PoE`.
#[derive(Debug)]
pub struct LongTermValidation<'d> {
    parser: &'d Parser,
    element: Element<'d>,
    encoding: Encoding,
    depth: u32,
    date: temporal::ExactReading,
    date_element: Element<'d>,
    proof: Option<PoeValue<'d>>,
    token_source: Option<crate::source::Value<'d>>,
    certificates: Option<CertificateSet<'d>>,
    revocations: Option<RevocationSet<'d>>,
}
impl<'d> LongTermValidation<'d> {
    /// Reads one original enclosure, using the existing CMS/PKIX field kernels.
    /// Known explicit wrappers are distinguished from optional IMPLICIT extras
    /// by their inner schema; an unknown ambiguous shape is never guessed.
    pub fn read(parent: &Reader<'d>, element: &Element<'d>) -> Result<Self> {
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(syntax(ErrorCode::UnexpectedTag, element.span()));
        }
        let mut inside = parent.enter(element).map_err(encoding)?;
        let date_element = required(&mut inside)?;
        let date =
            temporal::read_generalized_exact(&inside, &date_element, FIELD).map_err(Error::Pkix)?;
        if parent.encoding().is_der() {
            structured_pkix::der::conforms(&inside, &date_element, FIELD).map_err(Error::Pkix)?;
        }
        let mut next = inside.next_element().map_err(encoding)?;
        let mut token_source = None;
        let proof = if let Some(candidate) = next {
            if is_proof(&inside, &candidate)? {
                let mut wrapper = inside.enter(&candidate).map_err(encoding)?;
                let value = required(&mut wrapper)?;
                let proof = if candidate.tag() == Tag::context(true, 0) {
                    token_source = Some(crate::source::Value::of(&wrapper, value, FIELD));
                    let mut source = wrapper
                        .reread(&value, wrapper.encoding())
                        .map_err(encoding)?;
                    PoeValue::Timestamp(Token::read_from(&mut source)?)
                } else {
                    PoeValue::EvidenceRecord(EvidenceRecord::read(&wrapper, &value)?)
                };
                finish(&wrapper)?;
                next = inside.next_element().map_err(encoding)?;
                Some(proof)
            } else {
                None
            }
        } else {
            None
        };
        let certificates =
            if let Some(candidate) = next.filter(|value| value.tag() == Tag::context(true, 0)) {
                let value = CertificateSet::read(&inside, &candidate, FIELD)?;
                next = inside.next_element().map_err(encoding)?;
                Some(value)
            } else {
                None
            };
        let revocations =
            if let Some(candidate) = next.filter(|value| value.tag() == Tag::context(true, 1)) {
                let value = RevocationSet::read(&inside, &candidate, FIELD)?;
                next = inside.next_element().map_err(encoding)?;
                Some(value)
            } else {
                None
            };
        if let Some(extra) = next {
            return Err(syntax(ErrorCode::TrailingData, extra.span()));
        }
        finish(&inside)?;
        Ok(Self {
            parser: parent.parser(),
            element: *element,
            encoding: parent.encoding(),
            depth: parent.depth(),
            date,
            date_element,
            proof,
            token_source,
            certificates,
            revocations,
        })
    }
    /// Unsigned ordering metadata, never the authenticated `PoE` time.
    #[must_use]
    pub fn date(&self) -> Reading {
        self.date.reading()
    }
    /// Exact order of the unsigned metadata, including arbitrary decimal
    /// precision. This does not establish authenticated `PoE` chronology.
    pub fn compare_date<W: structured_asn1::memory::Work>(
        &self,
        other: &Self,
        utc: &temporal::LeapTable<'_>,
        work: &W,
    ) -> core::result::Result<core::cmp::Ordering, temporal::CompareError> {
        self.date.compare(&other.date, utc, work)
    }
    /// Original whole generalized-time value and physical coordinates.
    #[must_use]
    pub fn date_element(&self) -> Element<'d> {
        self.date_element
    }
    /// Actual optional token/record; absence remains explicit.
    #[must_use]
    pub fn proof(&self) -> Option<&PoeValue<'d>> {
        self.proof.as_ref()
    }
    pub(crate) fn timestamp_source(&self) -> Option<crate::source::Value<'d>> {
        self.token_source
    }
    /// Original additional choices and first-read certificate models.
    #[must_use]
    pub fn certificates(&self) -> Option<&CertificateSet<'d>> {
        self.certificates.as_ref()
    }
    /// Original additional CRL/other-format values, not authenticated status.
    #[must_use]
    pub fn revocations(&self) -> Option<&RevocationSet<'d>> {
        self.revocations.as_ref()
    }
    /// Whole original signed source enclosure.
    #[must_use]
    pub fn element(&self) -> Element<'d> {
        self.element
    }
    /// Reattaches this same source/depth to current operation admission.
    pub fn reader_in<'q>(&self, query: &Reader<'q>) -> Result<Reader<'q>>
    where
        'd: 'q,
    {
        self.parser
            .read_query_in(
                query,
                self.element.as_bytes(),
                self.element.span().start,
                self.encoding,
                self.depth,
            )
            .map_err(encoding)
    }
}

fn is_proof(parent: &Reader<'_>, candidate: &Element<'_>) -> Result<bool> {
    if candidate.tag() != Tag::context(true, 0) && candidate.tag() != Tag::context(true, 1) {
        return Ok(false);
    }
    let mut wrapper = parent.enter(candidate).map_err(encoding)?;
    let Some(value) = wrapper.next_element().map_err(encoding)? else {
        return Ok(false);
    };
    if value.tag() != Tag::constructed(universal::SEQUENCE) {
        return Ok(false);
    }
    let mut fields = wrapper.enter(&value).map_err(encoding)?;
    let first = required(&mut fields)?;
    Ok(if candidate.tag() == Tag::context(true, 0) {
        first.tag() == Tag::primitive(universal::OID)
    } else {
        first.tag() == Tag::primitive(universal::INTEGER)
    })
}
fn required<'d>(reader: &mut Reader<'d>) -> Result<Element<'d>> {
    reader
        .next_element()
        .map_err(encoding)?
        .ok_or(Error::Syntax {
            code: ErrorCode::MissingField,
            field: FIELD,
            at: reader.offset(),
        })
}
fn finish(reader: &Reader<'_>) -> Result<()> {
    if !reader.is_empty() {
        return Err(Error::Syntax {
            code: ErrorCode::TrailingData,
            field: FIELD,
            at: reader.offset(),
        });
    }
    Ok(())
}
fn syntax(code: ErrorCode, span: Span) -> Error {
    Error::Syntax {
        code,
        field: FIELD,
        at: span.start,
    }
}
fn encoding(cause: structured_asn1::Error) -> Error {
    Error::encoding(cause, FIELD)
}

/// One immutable original preservation enclosure from a preparation. Its
/// tokens are the SAME models used by the full TSA census and material pool.
pub struct View<'a, 'm, 'd> {
    pub(crate) prepared: &'a crate::prepare::Preparation<'m, 'd>,
    pub(crate) entry: &'a crate::prepare::proofs::Entry<'d>,
    pub(crate) ordinal: usize,
}
impl<'a, 'm, 'd> View<'a, 'm, 'd> {
    /// Actual original typed mechanism/placement/attribute, not a level claim.
    #[must_use]
    pub fn required(&self) -> crate::preservation::Required<'d> {
        self.entry.required
    }
    /// This preparation's original proof ordinal; it is not a claimed date.
    #[must_use]
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    /// Every actual timestamp ordinal in the SAME complete preparation.
    #[must_use]
    pub fn timestamps(&self) -> core::ops::Range<usize> {
        self.entry.timestamps.clone()
    }
    /// Actual first-read ERS alternative, including a `PoE`-carried ERS record.
    #[must_use]
    pub fn record(&self) -> Option<&'a EvidenceRecord<'d>> {
        self.entry.record()
    }
    /// Original `PoE` enclosure and its additional validation material.
    #[must_use]
    pub fn poe(&self) -> Option<&'a LongTermValidation<'d>> {
        match &self.entry.body {
            crate::prepare::proofs::Body::Poe(poe) => Some(poe),
            crate::prepare::proofs::Body::Record(_) => None,
        }
    }
    /// Same complete original signature preparation, with no new identity.
    #[must_use]
    pub fn prepared(&self) -> &'a crate::prepare::Preparation<'m, 'd> {
        self.prepared
    }
}

impl<'m, 'd> crate::prepare::Preparation<'m, 'd> {
    /// Readable original ERS/PoE enclosures. Failed obligations remain in
    /// `preservation()` and `evidence_faults()`; they cannot be omitted by a close.
    #[must_use]
    pub fn evidence_records(&self) -> usize {
        self.parsed.proofs.entries.len()
    }
    /// Every unreadable original proof enclosure, preserving source/cause.
    #[must_use]
    pub fn evidence_faults(&self) -> &[(crate::source::Node, Error)] {
        &self.parsed.proofs.faults
    }
    /// Paid lookup of one first-read proof under the actual current query.
    pub fn evidence(
        &self,
        ordinal: usize,
        operation: &Reader<'d>,
    ) -> Result<Option<View<'_, 'm, 'd>>> {
        self.document()
            .message()
            .require_session(operation, FIELD)?;
        operation.charge(1).map_err(encoding)?;
        Ok(self.parsed.proofs.entries.get(ordinal).map(|entry| View {
            prepared: self,
            entry,
            ordinal,
        }))
    }
}
