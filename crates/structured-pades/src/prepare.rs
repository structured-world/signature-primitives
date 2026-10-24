//! `PAdES` root obligations over the existing complete CMS/CAdES participant core.

use crate::{
    arena::Kind,
    bytes::Form,
    container::Container,
    date::Date,
    document::Document,
    error::{Error, ErrorKind, ReadFailure},
    model::{admit, get},
    range::RangeSource,
    signature::{Coverage, SubFilter},
    source::Location,
};
use structured_asn1::{
    Reader,
    memory::{Memory, OwnedVec, Work},
};
use structured_cades::prepare::{Preparation as CmsPreparation, Rule as CmsRule, Severity};
use structured_cms::oid;

/// Explicitly requested `PAdES` level. Unsigned contents never select this input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Mandatory PDF/CMS baseline fields and checked signer association.
    Basic,
    /// Basic plus trusted time of the original signature's existence.
    Timestamped,
    /// Timestamped plus complete incorporated validation material.
    LongTerm,
    /// Long-term plus source-bound trusted protection of validation data.
    Archival,
}

/// A completed PDF/CMS profile finding, separate from source/resource refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Exact whole-revision coverage or the PDF signature declaration fails.
    Signature,
    /// Required PDF field is absent or has the wrong selected schema.
    Field(&'static str),
    /// A field or known `CAdES` attribute is forbidden by the `PAdES` table.
    Forbidden,
    /// CMS root, properties, nested counters or timestamps retain a fault.
    Cms,
    /// Reason conflicts with a protected commitment or signature policy.
    Reason,
    /// PDF dates must express the claimed UTC label.
    ClaimedTime,
    /// The original signature is not selected by one actual signature field.
    SignaturePlacement,
}

/// One original finding, retaining its PDF enclosure for CMS coordinates.
#[derive(Debug, Clone, Copy)]
pub struct Finding {
    /// Original physical/decoded PDF location, never an invented ASN offset.
    pub location: Location,
    /// Exact format requirement which failed.
    pub rule: Rule,
}

/// Immutable `PAdES` format preparation. The complete nested CMS participant
/// and token census is borrowed from its owning common preparation unchanged.
/// This is not a signature, authority, chronology or trust verdict.
pub struct Preparation<'p, 'm, 'd, 'a, 's, D, G> {
    pub(crate) container: &'p Container<'a, 's, D, G>,
    pub(crate) cms: &'p CmsPreparation<'m, 'd>,
    requested: Level,
    claimed: Option<Date>,
    placement: Option<crate::permissions::Placement>,
    findings: OwnedVec<Finding, Memory>,
}

/// Terminal PDF acquisition or existing CMS/CAdES processing refusal.
#[derive(Debug)]
pub enum PrepareError<E> {
    /// Original PDF or carried-source refusal.
    Pdf(ReadFailure<E>),
    /// Original common participant/schema refusal.
    Cms(structured_cades::Error),
}

impl<'p, 'm, 'd, 'a, 's, D: Copy + Eq, G: Copy + Eq> Preparation<'p, 'm, 'd, 'a, 's, D, G> {
    async fn read_placement<S: RangeSource<Document = D, Generation = G>>(
        document: &Document<'s, S>,
        signature: crate::signature::Signature<'a, 's, D, G>,
        work: &impl Work,
        record: &mut impl FnMut(Rule, Location) -> Result<(), PrepareError<S::Error>>,
    ) -> Result<Option<crate::permissions::Placement>, PrepareError<S::Error>> {
        let pdf = PrepareError::Pdf;
        let location = signature.location();
        let placement = if let Coverage::Revision(revision) = signature.coverage() {
            let graph = document.graph(revision, work).await.map_err(pdf)?;
            let fields = document.fields(&graph, work).await.map_err(pdf)?;
            let transforms = document
                .transforms(signature, &graph, work)
                .await
                .map_err(pdf)?;
            let placement = document
                .signature_placement(signature, &graph, &fields, &transforms, work)
                .map_err(pdf)?;
            if !placement.all_requirements_met() {
                record(Rule::SignaturePlacement, location)?;
            }
            for node in &graph.nodes {
                admit(work, location, 1).map_err(|cause| pdf(cause.into()))?;
                if let Some(reading) = &node.reading {
                    for fault in reading.value.faults() {
                        admit(work, fault.location, 1).map_err(|cause| pdf(cause.into()))?;
                        record(Rule::Signature, fault.location)?;
                    }
                }
            }
            Some(placement)
        } else {
            None
        };
        Ok(placement)
    }

    async fn read_pdf_fields<S: RangeSource<Document = D, Generation = G>>(
        document: &Document<'s, S>,
        signature: crate::signature::Signature<'a, 's, D, G>,
        work: &impl Work,
        record: &mut impl FnMut(Rule, Location) -> Result<(), PrepareError<S::Error>>,
    ) -> Result<Option<Date>, PrepareError<S::Error>> {
        let pdf = PrepareError::Pdf;
        let location = signature.location();
        let reading = signature.owner();
        let arena = &reading.value.arena;
        let node = signature.node();
        crate::direct::visit(arena, node, work, |location| {
            record(Rule::Signature, location)
        })
        .map_err(|cause| match cause {
            crate::direct::VisitError::Processing(cause) => pdf(cause.into()),
            crate::direct::VisitError::Callback(cause) => cause,
        })?;
        for fault in &arena.faults {
            admit(work, fault.location, 1).map_err(|cause| pdf(cause.into()))?;
            record(Rule::Signature, fault.location)?;
        }
        if !matches!(
            arena.nodes[get(arena, node, b"Contents", work)
                .map_err(|cause| pdf(cause.into()))?
                .expect("inspected Contents")
                .0]
                .kind,
            Kind::String(Form::Hexadecimal)
        ) {
            record(Rule::Field("Contents"), signature.contents())?;
        }
        let filter = get(arena, node, b"Filter", work).map_err(|cause| pdf(cause.into()))?;
        if filter.is_none_or(|node| !matches!(arena.nodes[node.0].kind, Kind::Name(_))) {
            record(Rule::Field("Filter"), location)?;
        }
        if get(arena, node, b"Cert", work)
            .map_err(|cause| pdf(cause.into()))?
            .is_some()
        {
            record(Rule::Forbidden, location)?;
        }
        let date = get(arena, node, b"M", work).map_err(|cause| pdf(cause.into()))?;
        let claimed = if let Some(date) = date {
            let date_location = arena.nodes[date.0].location;
            let bytes = document
                .string(reading, date, 22, work)
                .await
                .map_err(pdf)?;
            match Date::read(&bytes, date_location, work) {
                Ok(date) => {
                    if date.offset_minutes() != 0 {
                        record(Rule::ClaimedTime, date_location)?;
                    }
                    Some(date)
                }
                Err(cause)
                    if matches!(
                        cause.kind,
                        ErrorKind::Resource(_) | ErrorKind::Foreign | ErrorKind::Limit(_)
                    ) =>
                {
                    return Err(pdf(cause.into()));
                }
                Err(_) => {
                    record(Rule::ClaimedTime, arena.nodes[date.0].location)?;
                    None
                }
            }
        } else {
            record(Rule::Field("M"), location)?;
            None
        };
        for key in [b"Location".as_slice(), b"Reason", b"Name", b"ContactInfo"] {
            if let Some(value) = get(arena, node, key, work).map_err(|cause| pdf(cause.into()))? {
                let bytes = document
                    .string(reading, value, usize::MAX, work)
                    .await
                    .map_err(pdf)?;
                crate::text::read(&bytes, arena.nodes[value.0].location, work)
                    .map_err(|cause| pdf(cause.into()))?;
            }
        }
        Ok(claimed)
    }

    fn read_cms_fields<E>(
        cms: &CmsPreparation<'m, 'd>,
        signature: crate::signature::Signature<'a, 's, D, G>,
        work: &impl Work,
        record: &mut impl FnMut(Rule, Location) -> Result<(), PrepareError<E>>,
    ) -> Result<(), PrepareError<E>> {
        let pdf = PrepareError::Pdf;
        let location = signature.location();
        let reading = signature.owner();
        let arena = &reading.value.arena;
        let node = signature.node();
        for finding in cms.findings() {
            admit(work, signature.contents(), 1).map_err(|cause| pdf(cause.into()))?;
            if finding.severity == Severity::Advisory {
                continue;
            }
            if matches!(finding.rule, CmsRule::Missing(kind) if kind == oid::SIGNING_TIME)
                || matches!(
                    finding.rule,
                    CmsRule::SignatureTimestamp | CmsRule::ArchiveTimestamp
                )
            {
                continue;
            }
            record(Rule::Cms, signature.contents())?;
        }
        let reason = get(arena, node, b"Reason", work)
            .map_err(|cause| pdf(cause.into()))?
            .is_some();
        for set in [
            cms.signer().signed_attributes(),
            cms.signer().unsigned_attributes(),
        ]
        .into_iter()
        .flatten()
        {
            for attribute in set.items() {
                admit(
                    work,
                    signature.contents(),
                    attribute.kind().as_bytes().len() as u64 + 1,
                )
                .map_err(|cause| pdf(cause.into()))?;
                let kind = attribute.kind();
                if reason
                    && (kind == oid::COMMITMENT_TYPE_INDICATION
                        || kind == oid::SIGNATURE_POLICY_IDENTIFIER)
                {
                    record(Rule::Reason, location)?;
                }
                if structured_cades::properties::defines(kind, work).map_err(|cause| {
                    pdf(Error {
                        kind: ErrorKind::Resource(cause),
                        location: signature.contents(),
                    }
                    .into())
                })? && !allowed(kind)
                {
                    record(Rule::Forbidden, signature.contents())?;
                }
            }
        }
        Ok(())
    }

    /// Reads all root obligations before key resolution or payload acquisition.
    /// EN319142-1 §§4.1/6.3 Table1 overrides `CAdES`'s root signing-time field;
    /// the existing nested participant/token mechanisms are not reimplemented.
    /// <https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
    ///
    /// # Panics
    /// Panics if the inspected signature loses its original `Contents` member.
    pub async fn read<S: RangeSource<Document = D, Generation = G>, W: Work>(
        document: &Document<'s, S>,
        container: &'p Container<'a, 's, D, G>,
        cms: &'p CmsPreparation<'m, 'd>,
        requested: Level,
        parent: &Reader<'d>,
        operation: &W,
    ) -> Result<Self, PrepareError<S::Error>> {
        let pdf = PrepareError::Pdf;
        let message = cms.document().message();
        container
            .require(message, parent)
            .map_err(|cause| pdf(cause.into()))?;
        message
            .require_session(parent, "pades")
            .map_err(|cause| PrepareError::Cms(cause.into()))?;
        let signature = container.signature();
        let location = signature.location();
        let work = document.session.query(operation);
        document
            .check(&work, location)
            .map_err(|cause| pdf(cause.into()))?;
        let mut findings = work.vector();
        let mut record = |rule, location| {
            findings
                .try_push(Finding { location, rule })
                .map_err(|cause| {
                    pdf(Error {
                        kind: ErrorKind::Resource(cause),
                        location,
                    }
                    .into())
                })
        };
        if signature.sub_filter() != Some(SubFilter::CadesDetached)
            || signature.is_document_timestamp()
            || !matches!(signature.coverage(), Coverage::Revision(_))
        {
            record(Rule::Signature, location)?;
        }
        if message.signers().len() != 1 || !message.content().is_detached() {
            record(Rule::Signature, signature.contents())?;
        }
        let placement = Self::read_placement(document, signature, &work, &mut record).await?;
        let claimed = Self::read_pdf_fields(document, signature, &work, &mut record).await?;
        Self::read_cms_fields(cms, signature, &work, &mut record)?;
        document
            .check(&work, location)
            .map_err(|cause| pdf(cause.into()))?;
        Ok(Self {
            container,
            cms,
            requested,
            claimed,
            placement,
            findings: findings.into_owned(),
        })
    }

    /// Requested level, independent of optional timestamp presence.
    #[must_use]
    pub fn requested(&self) -> Level {
        self.requested
    }
    /// Parsed claimed calendar label, without an occurrence proof.
    #[must_use]
    pub fn claimed_time(&self) -> Option<Date> {
        self.claimed
    }
    /// Actual historical signature-field and certification placement facts.
    #[must_use]
    pub fn placement(&self) -> Option<&crate::permissions::Placement> {
        self.placement.as_ref()
    }
    /// Every retained root preparation finding, without successful-subset filtering.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    /// Only original baseline format facts, before mathematical verification.
    #[must_use]
    pub fn all_basic_format_requirements_met(&self) -> bool {
        self.findings.is_empty()
    }
    /// Existing whole CMS/counter/token preparation, not a copied catalogue.
    #[must_use]
    pub fn cms(&self) -> &'p CmsPreparation<'m, 'd> {
        self.cms
    }
}

fn allowed(kind: structured_asn1::Oid<'_>) -> bool {
    // EN319142-1 §6.3 permits only its Table1 subset of EN319122 attributes.
    [
        oid::CONTENT_TYPE,
        oid::MESSAGE_DIGEST,
        oid::SIGNER_ATTRIBUTES_V2,
        oid::CONTENT_TIMESTAMP,
        oid::SIGNATURE_POLICY_IDENTIFIER,
        oid::COMMITMENT_TYPE_INDICATION,
        oid::SIGNING_CERTIFICATE,
        oid::SIGNING_CERTIFICATE_V2,
        oid::SIGNATURE_TIMESTAMP,
    ]
    .contains(&kind)
}
