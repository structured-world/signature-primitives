//! Source-derived baseline obligations, before keys, provider states or content.

use crate::properties::legacy::LEGACY;
use crate::source::{Document, DocumentId, Node, Original};
use crate::{Cades, Error, ISSUER, Level, Result};
use structured_asn1::memory::{OwnedMap, OwnedVec, Work};
use structured_asn1::{Element, Reader, Span};
use structured_cms::attribute::{Attribute, Attributes};
use structured_cms::cades::{Profile, Role};
use structured_cms::counter::{self, Visit, WalkError};
use structured_cms::signer::SignerInfo;
use structured_cms::{ErrorCode, oid};
use structured_ltv::baseline::ArchiveCensus;
use structured_ltv::timestamp::{Purpose, RequiredToken, TimestampRequirements, TimestampScope};

const FIELD: &str = "cades";
pub(crate) mod encoding;
pub(crate) mod proofs;
pub(crate) mod tokens;
pub use tokens::ReadError;

/// One located mandatory rule or advisory. A SHOULD is not a failed SHALL.
#[derive(Debug)]
pub struct Finding<'model, 'document> {
    /// Original attribute/container coordinates and identity.
    pub location: Original<'model, 'document>,
    /// Normative strength of this finding.
    pub severity: Severity,
    /// The format requirement, distinct from a processing refusal.
    pub rule: Rule,
}

/// Strength of a format requirement, without application severity policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A normative SHALL/SHALL NOT is not met.
    Required,
    /// A normative SHOULD/SHOULD NOT is not met.
    Advisory,
}

/// Format-specific findings preserve their cause instead of a blanket invalid.
#[derive(Debug)]
pub enum Rule {
    /// A present original value fails its attribute's selected schema.
    Value {
        /// Original attribute type, not a guessed value interpretation.
        attribute: structured_asn1::Oid<'static>,
        /// Field of the retained cause on the original property reading.
        field: &'static str,
    },
    /// Existing CMS/ESS/CAdES schema diagnostic.
    Schema {
        /// Exact original CMS/encoding/PKIX diagnostic category.
        code: ErrorCode,
        /// Original protocol field; the finding carries its source location.
        field: &'static str,
    },
    /// Mandatory original attribute is absent.
    Missing(structured_asn1::Oid<'static>),
    /// This original attribute is forbidden or discouraged at the requested
    /// level; the finding severity distinguishes SHALL NOT from SHOULD NOT.
    Forbidden(structured_asn1::Oid<'static>),
    /// No signing-certificate protection service exists.
    SigningCertificate,
    /// Credential references lack this signer's protected certified attribute
    /// or signed assertion (Table1 requirement n).
    CredentialReferences(structured_asn1::Oid<'static>),
    /// The requested level needs a root signature timestamp.
    SignatureTimestamp,
    /// The requested archival level needs a root `ATSv3`.
    ArchiveTimestamp,
    /// A baseline original container needs the signer's certificate.
    Certificate,
    /// CMS content must be id-data for this root baseline signature.
    ContentType,
    /// A data-type description is recommended, not mandatory.
    DataTypeDescription,
    /// A written store lacks its protected, nonzero policy document digest.
    PolicyStore,
    /// Actual use of MD5 violates the format, independently of backend support.
    Md5,
    /// Known archive-index and timestamp-imprint digest identities disagree
    /// (EN319122-1 §5.5.2); no provider or mathematical comparison is implied.
    ArchiveAlgorithm,
    /// A V2 certificate reference uses SHA-1 instead of a different hash.
    SigningCertificateVersion,
    /// Optional issuerSerial hint SHOULD be omitted (§6.3(g)).
    IssuerHint,
}

/// Complete original timestamp occurrence, including unreadable token values.
/// Each carries its actual owning signer, independently of whether it checks.
#[derive(Debug, Clone, Copy)]
pub struct Timestamp<'a> {
    owner: Node,
    property: Node,
    value: Option<crate::source::Value<'a>>,
    purpose: Purpose,
    preservation_kind: Option<crate::preservation::Kind>,
}

impl<'a> Timestamp<'a> {
    /// Original owning root or nested countersignature.
    #[must_use]
    pub fn owner(&self) -> Node {
        self.owner
    }
    /// Original whole timestamp attribute.
    #[must_use]
    pub fn property(&self) -> Node {
        self.property
    }
    /// Original carrier value, not a successful decoded token.
    #[must_use]
    pub fn value(&self) -> Option<Element<'a>> {
        self.value.map(|value| value.element())
    }
    /// Original parser/encoding/depth for a later current-operation query.
    #[must_use]
    pub fn source(&self) -> Option<crate::source::Value<'a>> {
        self.value
    }
    /// Normative input kind, selected from the original attribute.
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// Historical mechanism, when this is not a modern content/signature/ATSv3
    /// occurrence. An archive purpose alone never selects an `ATSHashIndexV3`.
    #[must_use]
    pub fn preservation_kind(&self) -> Option<crate::preservation::Kind> {
        self.preservation_kind
    }
}

/// One original counter value. Malformed values retain a real location and
/// diagnostic and cannot disappear from a later participant census.
pub struct Counter<'a> {
    parent: Node,
    node: Node,
    malformed: Option<structured_cms::Error>,
    signature: core::ops::Range<usize>,
    properties: Option<crate::properties::Properties<'a>>,
    pub(crate) encoding: Option<encoding::SignerEncoding<'a>>,
}

impl<'a> Counter<'a> {
    /// Original direct parent; the child covers its signature content octets.
    #[must_use]
    pub fn parent(&self) -> Node {
        self.parent
    }
    /// Original child node, or the located unreadable-value start.
    #[must_use]
    pub fn node(&self) -> Node {
        self.node
    }
    /// Read failure, separate from successful mathematical verification.
    #[must_use]
    pub fn malformed(&self) -> Option<&structured_cms::Error> {
        self.malformed.as_ref()
    }
    /// Optional original property reading; absent only for an unreadable child.
    #[must_use]
    pub fn properties(&self) -> Option<&crate::properties::Properties<'a>> {
        self.properties.as_ref()
    }
}

/// Immutable source-derived root profile and COMPLETE nested timestamp census.
/// Findings prevent a positive predicate; processing refusal returns no prefix.
pub struct Preparation<'model, 'document> {
    document: &'model Document<'model, 'document>,
    signer: &'model SignerInfo<'document>,
    requested: Level,
    profile: Profile<'document>,
    properties: crate::properties::Properties<'document>,
    findings: OwnedVec<Finding<'model, 'document>>,
    counters: OwnedVec<Counter<'document>>,
    parallel: Option<Parallel<'document>>,
    counter_index: OwnedMap<Node, usize>,
    signatures: OwnedVec<structured_cms::octets::Piece<'document>>,
    timestamps: OwnedVec<Timestamp<'document>>,
    pub(crate) timestamp_ranges: Option<OwnedMap<Node, core::ops::Range<usize>>>,
    required: TimestampRequirements<Node, DocumentId<'model, 'document>, (), Cades>,
    conforming: bool,
    basic_conforming: bool,
    preservation: OwnedVec<crate::preservation::Required<'document>>,
    pub(crate) parsed: tokens::Cache<'model, 'document>,
}

struct Parallel<'d> {
    counters: Option<OwnedVec<Counter<'d>>>,
    index: Option<OwnedMap<Node, usize>>,
    timestamps: Option<OwnedVec<Timestamp<'d>>>,
}

impl<'m, 'd> Preparation<'m, 'd> {
    /// Builds format obligations from the original selected root. All nested
    /// countersignatures are traversed iteratively by the existing CMS walker.
    /// No key lookup, provider, source acquisition or signature check occurs.
    ///
    /// EN319122-1 V1.3.1 §§6.2.2/6.3 table 1 makes the requested level explicit;
    /// '*' is advisory and an optional archive never promotes a lower request.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf>
    #[expect(
        clippy::result_large_err,
        reason = "keep original timestamp syntax failures and their independent source maps without refusal-time allocation"
    )]
    pub fn read(
        document: &'m Document<'m, 'd>,
        signer: &'m SignerInfo<'d>,
        requested: Level,
        parent: &Reader<'d>,
    ) -> core::result::Result<Self, ReadError> {
        let selected = document.signer(signer)?;
        document.message().require_session(parent, FIELD)?;
        let execution = parent.execution();
        let profile = structured_cms::cades::inspect_profile(signer, Role::Signature, parent)?;
        let mut findings = execution.vector();
        let properties =
            root_properties(document, signer, requested, &profile, parent, &mut findings)?;
        let mut timestamps = execution.vector();
        collect_timestamps(signer, parent, &mut timestamps)?;
        let mut signatures = execution.vector();
        let mut preservation = crate::preservation::roots(document.message(), parent, &execution)?;
        let counters = read_counters(
            document,
            signer,
            parent,
            &mut findings,
            &mut timestamps,
            &mut signatures,
            &mut preservation,
        )?;
        let mut parallel =
            read_parallel(document, signer, parent, &mut signatures, &mut preservation)?;
        let (timestamp_ranges, proofs) = history_timestamps(
            &preservation,
            &mut timestamps,
            &mut parallel,
            parent,
            Node::of(signer.span()),
        )?;
        let tokens = token_obligations(&timestamps, &execution, selected.node.span().start)?;
        let CounterCatalogue {
            children,
            index: counter_index,
            mut conforming,
        } = counter_catalogue(&counters, parent, selected.node)?;
        let mut basic_conforming = conforming;
        let mut parsed = tokens::read(
            document,
            &timestamps,
            selected.node,
            &counter_index,
            parent,
            proofs,
            tokens::Findings {
                rows: &mut findings,
                work: &execution,
            },
        )?;
        parallel_findings(document, parallel.as_ref(), &mut parsed, parent)?;
        apply_findings(
            &findings,
            &execution,
            &mut conforming,
            &mut basic_conforming,
        )?;
        let required = TimestampRequirements::with_counters(
            ISSUER,
            selected.node,
            TimestampScope::All(selected),
            tokens.into_owned(),
            children.into_owned(),
            None,
        );
        Ok(Self {
            document,
            signer,
            requested,
            profile,
            properties,
            findings: findings.into_owned(),
            counters,
            parallel,
            counter_index: counter_index.into_owned(),
            signatures: signatures.into_owned(),
            timestamps: timestamps.into_owned(),
            timestamp_ranges,
            required,
            conforming,
            basic_conforming,
            preservation: preservation.into_owned(),
            parsed,
        })
    }

    /// Explicit profile requested before interpreting unsigned augmentation.
    #[must_use]
    pub fn requested(&self) -> Level {
        self.requested
    }
    /// Every historical preservation obligation from ALL parallel root signers
    /// and selected counters. These require their actual older proof processors;
    /// absence of a qualified receipt cannot be replaced with `ATSv3` evidence.
    #[must_use]
    pub fn preservation(&self) -> &[crate::preservation::Required<'d>] {
        &self.preservation
    }
    /// Located preservation findings on OTHER parallel roots/counters. These
    /// do not change the selected root's B-B syntax facts; their TSA actors
    /// are nevertheless mandatory in the full historical timestamp census.
    pub fn preservation_findings(&self) -> &[Finding<'m, 'd>] {
        self.parsed.related.as_deref().unwrap_or(&[])
    }
    /// Original selected root signer.
    #[must_use]
    pub fn signer(&self) -> &'m SignerInfo<'d> {
        self.signer
    }
    /// Full original root `SignedData`, including parallel signer/material fields.
    #[must_use]
    pub fn document(&self) -> &'m Document<'m, 'd> {
        self.document
    }
    /// Already parsed ESS restrictions and profile findings; no second read.
    #[must_use]
    pub fn profile(&self) -> &Profile<'d> {
        &self.profile
    }
    /// Original optional property syntax, open-format obligations and causes.
    #[must_use]
    pub fn properties(&self) -> &crate::properties::Properties<'d> {
        &self.properties
    }
    /// Every original nested counter value in original depth-first order.
    #[must_use]
    pub fn counters(&self) -> &[Counter<'d>] {
        &self.counters
    }
    /// Original counters of OTHER parallel roots, retained only as source and
    /// preservation metadata. Their presence does not assert their signature
    /// math or add their signer paths to this selected root's counter census.
    pub fn parallel_counters(&self) -> &[Counter<'d>] {
        self.parallel
            .as_ref()
            .and_then(|parallel| parallel.counters.as_deref())
            .unwrap_or(&[])
    }
    pub(crate) fn source_timestamps(&self) -> impl Iterator<Item = &Timestamp<'d>> {
        self.timestamps.iter().chain(
            self.parallel
                .as_ref()
                .and_then(|parallel| parallel.timestamps.as_deref())
                .unwrap_or(&[])
                .iter(),
        )
    }
    /// Original signature CONTENT octets of a timestamp's actual owner. A
    /// counter timestamp covers that counter, not the counter's parent/root.
    pub fn signature_input(
        &self,
        timestamp: usize,
        parent: &Reader<'_>,
    ) -> Result<Option<&[structured_cms::octets::Piece<'d>]>> {
        self.document.message().require_session(parent, FIELD)?;
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        let Some(token) = self.timestamps.get(timestamp) else {
            return Ok(None);
        };
        self.signature_of(token.owner, parent).map(Some)
    }
    /// A content timestamp on a counter covers that counter's original input:
    /// its PARENT signature. The root's content timestamp uses eContent and
    /// consequently returns None here, never the root signature as a fallback.
    pub fn counter_content_input(
        &self,
        timestamp: usize,
        parent: &Reader<'_>,
    ) -> Result<Option<&[structured_cms::octets::Piece<'d>]>> {
        self.document.message().require_session(parent, FIELD)?;
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        let Some(token) = self.timestamps.get(timestamp) else {
            return Ok(None);
        };
        match self.counter_parent(token.owner, parent)? {
            None => Ok(None),
            Some(owner) => self.signature_of(owner, parent).map(Some),
        }
    }
    pub(crate) fn signature_of(
        &self,
        owner: Node,
        parent: &Reader<'_>,
    ) -> Result<&[structured_cms::octets::Piece<'d>]> {
        self.signature_of_in(owner, parent, parent)
    }
    pub(crate) fn signature_of_in(
        &self,
        owner: Node,
        origin: &Reader<'_>,
        operation: &Reader<'_>,
    ) -> Result<&[structured_cms::octets::Piece<'d>]> {
        self.document.message().require_session(origin, FIELD)?;
        let work = origin.execution_query(operation);
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, owner.span().start))?;
        if owner == Node::of(self.signer.span()) {
            return Ok(self.signer.signature().pieces());
        }
        for signer in self.document.message().signers() {
            work.charge_work(1)
                .map_err(|cause| Error::resource(cause, FIELD, owner.span().start))?;
            if owner == Node::of(signer.span()) {
                return Ok(signer.signature().pieces());
            }
        }
        Ok(&self.signatures[self.counter_record(owner, &work)?.signature.clone()])
    }
    pub(crate) fn signer_encoding(
        &self,
        owner: Node,
        parent: &Reader<'_>,
    ) -> Result<encoding::SignerView<'_, 'd>> {
        self.document.message().require_session(parent, FIELD)?;
        for signer in self.document.message().signers() {
            parent
                .charge(1)
                .map_err(|cause| Error::encoding(cause, FIELD))?;
            if owner == Node::of(signer.span()) {
                return Ok(encoding::SignerView::Root(signer));
            }
        }
        let work = parent.execution();
        self.counter_record(owner, &work)?
            .encoding
            .as_ref()
            .map(encoding::SignerView::Counter)
            .ok_or(Error::Foreign {
                at: owner.span().start,
            })
    }
    pub(crate) fn counter_parent(&self, owner: Node, parent: &Reader<'_>) -> Result<Option<Node>> {
        self.counter_parent_in(owner, parent, parent)
    }
    pub(crate) fn counter_parent_in(
        &self,
        owner: Node,
        origin: &Reader<'_>,
        operation: &Reader<'_>,
    ) -> Result<Option<Node>> {
        self.document.message().require_session(origin, FIELD)?;
        let work = origin.execution_query(operation);
        for signer in self.document.message().signers() {
            work.charge_work(1)
                .map_err(|cause| Error::resource(cause, FIELD, owner.span().start))?;
            if owner == Node::of(signer.span()) {
                return Ok(None);
            }
        }
        Ok(Some(self.counter_record(owner, &work)?.parent))
    }
    fn counter_record(&self, owner: Node, work: &impl Work) -> Result<&Counter<'d>> {
        let resource = |cause| Error::resource(cause, FIELD, owner.span().start);
        if let Some(index) = self.counter_index.get(&owner, work).map_err(resource)? {
            return Ok(&self.counters[*index]);
        }
        if let Some(parallel) = &self.parallel
            && let Some(index) = &parallel.index
            && let Some(ordinal) = index.get(&owner, work).map_err(resource)?
        {
            return Ok(&parallel
                .counters
                .as_ref()
                .expect("index belongs to its counter catalogue")[*ordinal]);
        }
        Err(Error::Foreign {
            at: owner.span().start,
        })
    }
    /// All original root/counter timestamp occurrences, including failed ones.
    #[must_use]
    pub fn timestamps(&self) -> &[Timestamp<'d>] {
        &self.timestamps
    }
    /// Complete source-derived TSA obligations for the common LTV core.
    #[must_use]
    pub fn timestamp_requirements(
        &self,
    ) -> &TimestampRequirements<Node, DocumentId<'m, 'd>, (), Cades> {
        &self.required
    }
    /// Located mandatory and advisory findings, without product severity policy.
    #[must_use]
    pub fn findings(&self) -> &[Finding<'m, 'd>] {
        &self.findings
    }
    /// Only format preparation; no signature, ESS hash, path or trust assertion.
    #[must_use]
    pub fn all_format_requirements_met(&self) -> bool {
        self.conforming
    }
    /// Mandatory root/counter B-B format conditions only. A missing timestamp
    /// at a higher requested level does not retroactively erase a B-B fact.
    #[must_use]
    pub fn basic_format_requirements_met(&self) -> bool {
        self.basic_conforming
    }
}

impl<'m, 'd> ArchiveCensus for Preparation<'m, 'd> {
    type Id = Node;
    type Document = DocumentId<'m, 'd>;
    type Generation = ();
    fn signature(&self) -> Original<'m, 'd> {
        self.document.locate(self.signer.span())
    }
    fn timestamps(&self) -> usize {
        self.timestamps.len()
    }
    fn archive(&self, ordinal: usize) -> Option<Node> {
        let token = &self.timestamps[ordinal];
        if token.owner == Node::of(self.signer.span()) && token.purpose == Purpose::Archive {
            Some(match token.value {
                Some(value) => Node::of(value.element().span()),
                None => token.property,
            })
        } else {
            None
        }
    }
}

fn root_properties<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'d>,
    requested: Level,
    profile: &structured_cms::cades::Profile<'d>,
    parent: &Reader<'d>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<crate::properties::Properties<'d>> {
    root_rules(document, signer, requested, profile, parent, findings)?;
    let properties = crate::properties::Properties::read(signer, parent)?;
    property_findings(document, &properties, parent, findings)?;
    mechanism_findings(document, signer, profile, &properties, parent, findings)?;
    legacy_rules(
        document,
        signer,
        &properties,
        Some(requested),
        parent,
        findings,
    )?;
    Ok(properties)
}

fn apply_findings<W: Work>(
    findings: &[Finding<'_, '_>],
    work: &W,
    conforming: &mut bool,
    basic_conforming: &mut bool,
) -> Result<()> {
    for finding in findings {
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, finding.location.node.span().start))?;
        if finding.severity == Severity::Required {
            *conforming = false;
            if !matches!(
                finding.rule,
                Rule::SignatureTimestamp | Rule::ArchiveTimestamp | Rule::Forbidden(_)
            ) {
                *basic_conforming = false;
            }
        }
    }
    Ok(())
}

fn schema_findings<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'_>,
    profile: &Profile<'_>,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    if let Some(signed) = signer.signed_attributes() {
        for attribute in signed.items() {
            parent
                .charge(1 + attribute.kind().as_bytes().len().min(11) as u64)
                .map_err(|cause| Error::encoding(cause, FIELD))?;
            if crate::preservation::Kind::from_oid(attribute.kind())
                .is_some_and(crate::preservation::Kind::is_archive)
            {
                // RFC5126 §6.4.1 (and RFC3126 §4.4.1) define an UNSIGNED
                // archive attribute. Retain readable values for inspection,
                // but never turn this placement into format conformance.
                // https://www.rfc-editor.org/rfc/rfc5126#section-6.4.1
                finding(
                    document,
                    attribute.span(),
                    Severity::Required,
                    Rule::Schema {
                        code: ErrorCode::AttributePlacement,
                        field: "cades.historical",
                    },
                    findings,
                )?;
            }
        }
    }
    for error in signer
        .faults()
        .iter()
        .chain(profile.faults())
        .chain(profile.signing().faults())
    {
        parent.charge(1).map_err(|e| Error::encoding(e, FIELD))?;
        finding(
            document,
            Span {
                start: error.offset(),
                length: 0,
            },
            Severity::Required,
            Rule::Schema {
                code: error.code(),
                field: error.field(),
            },
            findings,
        )?;
    }
    for certificate in [profile.signing().v1(), profile.signing().v2()]
        .into_iter()
        .flatten()
    {
        for error in certificate.faults() {
            parent.charge(1).map_err(|e| Error::encoding(e, FIELD))?;
            finding(
                document,
                Span {
                    start: error.offset(),
                    length: 0,
                },
                Severity::Required,
                Rule::Schema {
                    code: error.code(),
                    field: error.field(),
                },
                findings,
            )?;
        }
    }
    Ok(())
}

fn property_findings<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    properties: &crate::properties::Properties<'_>,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    for hint in properties.issuer_hints() {
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        finding(
            document,
            *hint,
            Severity::Advisory,
            Rule::IssuerHint,
            findings,
        )?;
    }
    for fault in properties.faults() {
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        finding(
            document,
            Span {
                start: fault.cause.offset(),
                length: 0,
            },
            Severity::Required,
            match &fault.cause {
                Error::Syntax {
                    code: ErrorCode::AttributeCardinality,
                    field,
                    ..
                } => Rule::Schema {
                    code: ErrorCode::AttributeCardinality,
                    field,
                },
                _ => Rule::Value {
                    attribute: fault.attribute,
                    field: fault.field,
                },
            },
            findings,
        )?;
    }
    Ok(())
}

fn mechanism_findings<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'_>,
    profile: &Profile<'_>,
    properties: &crate::properties::Properties<'_>,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    let md5 = structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 2, 5]);
    parent
        .charge(2 + signer.digest_algorithm().algorithm().as_bytes().len() as u64)
        .map_err(|cause| Error::encoding(cause, FIELD))?;
    // §6.2.1 is a format prohibition, independent of the selected provider's
    // capabilities or application algorithm policy. It applies to actual use.
    if signer.digest_algorithm().algorithm() == md5 {
        finding(
            document,
            signer.span(),
            Severity::Required,
            Rule::Md5,
            findings,
        )?;
    }
    for attribute in [profile.signing().v1(), profile.signing().v2()]
        .into_iter()
        .flatten()
    {
        for certificate in attribute.identifiers() {
            parent
                .charge(1)
                .map_err(|cause| Error::encoding(cause, FIELD))?;
            if let structured_cms::provider::DigestAlgorithm::Written(identifier) =
                certificate.digest_algorithm()
            {
                parent
                    .charge(2 * (1 + identifier.algorithm().as_bytes().len() as u64))
                    .map_err(|cause| Error::encoding(cause, FIELD))?;
                if identifier.algorithm() == md5 {
                    finding(
                        document,
                        certificate.element().span(),
                        Severity::Required,
                        Rule::Md5,
                        findings,
                    )?;
                }
                // EN319122-1 §5.2.2.3 narrows RFC5035: every CAdES V2
                // reference uses a non-SHA1 hash, whether V1 coexists or not.
                // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
                if attribute.version() == structured_cms::ess::Version::V2
                    && identifier.algorithm() == oid::SHA1
                {
                    finding(
                        document,
                        certificate.element().span(),
                        Severity::Required,
                        Rule::SigningCertificateVersion,
                        findings,
                    )?;
                }
            }
            if !matches!(
                certificate.issuer_serial(),
                structured_cms::ess::IssuerReading::Absent
            ) {
                finding(
                    document,
                    certificate.element().span(),
                    Severity::Advisory,
                    Rule::IssuerHint,
                    findings,
                )?;
            }
        }
    }
    if let Some(policy) = properties.policy() {
        parent
            .charge(1 + policy.algorithm.algorithm().as_bytes().len() as u64)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        if policy.algorithm.algorithm() == md5 {
            finding(
                document,
                signer.span(),
                Severity::Required,
                Rule::Md5,
                findings,
            )?;
        }
    }
    // §6.3(k): an unsigned store is allowed ONLY with the actual protected
    // policy digest. Zero-hash explicitly means unknown (§5.2.9.1), any width.
    if properties.store().is_some() && properties.policy().is_none_or(|policy| policy.hash_unknown)
    {
        finding(
            document,
            signer.span(),
            Severity::Required,
            Rule::PolicyStore,
            findings,
        )?;
    }
    Ok(())
}

fn legacy_rules<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'_>,
    properties: &crate::properties::Properties<'_>,
    level: Option<Level>,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    let mut credentials = None;
    let mut seen = 0u8;
    for (protected, set) in [
        (true, signer.signed_attributes()),
        (false, signer.unsigned_attributes()),
    ] {
        let Some(set) = set else {
            continue;
        };
        for attribute in set.items() {
            let Some((ordinal, kind)) = legacy_kind(attribute.kind(), parent)? else {
                continue;
            };
            legacy_cardinality(
                document,
                attribute,
                ordinal,
                &mut seen,
                level.is_some() && !protected,
                parent,
                findings,
            )?;
            // AnnexA defines these as unsigned. Placement is mandatory in
            // root and counter signers, regardless of the baseline-level row.
            // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
            if protected {
                finding(
                    document,
                    attribute.span(),
                    Severity::Required,
                    Rule::Schema {
                        code: ErrorCode::AttributePlacement,
                        field: "cades.legacy.unsignedAttrs",
                    },
                    findings,
                )?;
            }
            // The requested Table1 row belongs to the selected baseline root;
            // counters still receive the same placement and credential rules.
            if let Some(level) = level {
                finding(
                    document,
                    attribute.span(),
                    if level >= Level::LongTerm {
                        Severity::Required
                    } else {
                        Severity::Advisory
                    },
                    Rule::Forbidden(kind),
                    findings,
                )?;
            }
            if kind != LEGACY[6] && kind != LEGACY[7] {
                continue;
            }
            let present = if let Some(present) = credentials {
                present
            } else {
                let present = protected_credential(signer, properties, parent)?;
                credentials = Some(present);
                present
            };
            // §6.3 Table1(n) is SHALL NOT without this protected service,
            // even where the separate '*' presence rule is only advisory.
            if !present {
                finding(
                    document,
                    attribute.span(),
                    Severity::Required,
                    Rule::CredentialReferences(kind),
                    findings,
                )?;
            }
        }
    }
    Ok(())
}

fn legacy_cardinality<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    attribute: &Attribute<'_>,
    ordinal: u8,
    seen: &mut u8,
    root: bool,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    parent
        .charge(2)
        .map_err(|cause| Error::encoding(cause, FIELD))?;
    // Properties::read retains AnnexA.1 value-cardinality faults for EVERY
    // signer, including timestamp signers. This phase only adds Table1's
    // attribute-occurrence rule: repeated timestamp rows, other rows 0 or 1.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
    if root && ordinal != 4 && ordinal != 5 {
        debug_assert!(ordinal < 8);
        let bit = 1u8 << ordinal;
        if *seen & bit != 0 {
            finding(
                document,
                attribute.span(),
                Severity::Required,
                Rule::Schema {
                    code: ErrorCode::DuplicateAttribute,
                    field: "cades.legacy",
                },
                findings,
            )?;
        }
        *seen |= bit;
    }
    Ok(())
}

fn legacy_kind(
    kind: structured_asn1::Oid<'_>,
    parent: &Reader<'_>,
) -> Result<Option<(u8, structured_asn1::Oid<'static>)>> {
    for (ordinal, expected) in (0u8..).zip(LEGACY) {
        parent
            .charge(1 + kind.as_bytes().len().min(expected.as_bytes().len()) as u64)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        if kind == expected {
            return Ok(Some((ordinal, expected)));
        }
    }
    Ok(None)
}

fn protected_credential(
    signer: &SignerInfo<'_>,
    properties: &crate::properties::Properties<'_>,
    parent: &Reader<'_>,
) -> Result<bool> {
    let Some(protected_set) = signer.signed_attributes() else {
        return Ok(false);
    };
    let protected = protected_set.element().span();
    for value in properties.open_values() {
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        let span = value.enclosure.span();
        if span.start >= protected.start
            && span.end() <= protected.end()
            && matches!(
                value.role,
                crate::properties::OpenRole::AttributeCertificate
                    | crate::properties::OpenRole::OtherAttributeCertificate
                    | crate::properties::OpenRole::SignedAssertion
            )
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn root_rules<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'_>,
    requested: Level,
    profile: &Profile<'_>,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    schema_findings(document, signer, profile, parent, findings)?;
    for error in document.message().faults() {
        parent.charge(1).map_err(|e| Error::encoding(e, FIELD))?;
        finding(
            document,
            Span {
                start: error.offset(),
                length: 0,
            },
            Severity::Required,
            Rule::Schema {
                code: error.code(),
                field: error.field(),
            },
            findings,
        )?;
    }
    parent
        .charge(1 + document.message().content().kind().as_bytes().len() as u64)
        .map_err(|e| Error::encoding(e, FIELD))?;
    if document.message().content().kind() != oid::DATA {
        finding(
            document,
            document.message().span(),
            Severity::Required,
            Rule::ContentType,
            findings,
        )?;
    }
    binding_findings(
        document,
        signer,
        structured_cms::binding::Scope::Content(document.message().content().kind()),
        parent,
        findings,
    )?;
    protected_rules(document, signer, profile, parent, findings)?;
    unsigned_rules(document, signer, requested, parent, findings)
}

fn binding_findings<'m, 'd, 'a, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'a>,
    scope: structured_cms::binding::Scope<'a>,
    parent: &Reader<'a>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    match structured_cms::binding::inspect(signer, parent, scope) {
        Ok(_) => {}
        Err(error) if error.is_terminal() => return Err(Error::Cms(error)),
        Err(error) => finding(
            document,
            Span {
                start: error.offset(),
                length: 0,
            },
            Severity::Required,
            Rule::Schema {
                code: error.code(),
                field: error.field(),
            },
            findings,
        )?,
    }
    Ok(())
}

fn protected_rules<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'_>,
    profile: &Profile<'_>,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    let protected = signer.signed_attributes();
    for kind in [oid::CONTENT_TYPE, oid::MESSAGE_DIGEST, oid::SIGNING_TIME] {
        if !present(document, protected, kind, parent, findings)? {
            finding(
                document,
                signer.span(),
                Severity::Required,
                Rule::Missing(kind),
                findings,
            )?;
        }
    }
    if profile.signing().v1().is_none() && profile.signing().v2().is_none() {
        finding(
            document,
            signer.span(),
            Severity::Required,
            Rule::SigningCertificate,
            findings,
        )?;
    }
    if document.message().certificates().is_empty() {
        finding(
            document,
            document.message().span(),
            Severity::Required,
            Rule::Certificate,
            findings,
        )?;
    }
    let hints = present(document, protected, oid::CONTENT_HINTS, parent, findings)?;
    let mime = present(document, protected, oid::MIME_TYPE, parent, findings)?;
    if !hints && !mime {
        finding(
            document,
            signer.span(),
            Severity::Advisory,
            Rule::DataTypeDescription,
            findings,
        )?;
    }
    // Table 1 narrows the generic attribute rules to at most one instance.
    for kind in [
        oid::COMMITMENT_TYPE_INDICATION,
        oid::SIGNER_LOCATION,
        oid::SIGNER_ATTRIBUTES_V2,
        oid::SIGNATURE_POLICY_IDENTIFIER,
        oid::CONTENT_REFERENCE,
        oid::CONTENT_IDENTIFIER,
        oid::SIGNATURE_POLICY_STORE,
    ] {
        let set = if kind == oid::SIGNATURE_POLICY_STORE {
            signer.unsigned_attributes()
        } else {
            protected
        };
        present(document, set, kind, parent, findings)?;
    }
    Ok(())
}

fn unsigned_rules<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'_>,
    requested: Level,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    let mut signature_times = 0;
    let mut archives = 0;
    if let Some(unsigned) = signer.unsigned_attributes() {
        for attribute in unsigned.items() {
            parent
                .charge(1 + attribute.kind().as_bytes().len() as u64)
                .map_err(|e| Error::encoding(e, FIELD))?;
            if attribute.kind() == oid::SIGNATURE_TIMESTAMP {
                signature_times += 1;
            }
            if attribute.kind() == oid::ARCHIVE_TIMESTAMP_V3 {
                archives += 1;
            }
            // Table1 '*' is SHOULD NOT, never a failed SHALL. Count these
            // same original occurrences for mandatory higher levels too.
            if (attribute.kind() == oid::SIGNATURE_TIMESTAMP && requested == Level::Basic)
                || (attribute.kind() == oid::ARCHIVE_TIMESTAMP_V3 && requested < Level::Archival)
            {
                finding(
                    document,
                    attribute.span(),
                    Severity::Advisory,
                    Rule::Forbidden(if attribute.kind() == oid::SIGNATURE_TIMESTAMP {
                        oid::SIGNATURE_TIMESTAMP
                    } else {
                        oid::ARCHIVE_TIMESTAMP_V3
                    }),
                    findings,
                )?;
            }
        }
    }
    if requested >= Level::Timestamped && signature_times == 0 {
        finding(
            document,
            signer.span(),
            Severity::Required,
            Rule::SignatureTimestamp,
            findings,
        )?;
    }
    if requested == Level::Archival && archives == 0 {
        finding(
            document,
            signer.span(),
            Severity::Required,
            Rule::ArchiveTimestamp,
            findings,
        )?;
    }
    Ok(())
}

fn present<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    set: Option<&Attributes<'_>>,
    kind: structured_asn1::Oid<'static>,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<bool> {
    let Some(set) = set else {
        return Ok(false);
    };
    match set.unique_in(kind, parent) {
        Ok(value) => Ok(value.is_some()),
        Err(cause) if cause.is_terminal() => Err(Error::Cms(cause)),
        Err(cause) => {
            // unique_in's nonterminal refusal proves repeated presence, not
            // absence. Retain the violation without truncating the original
            // counter/timestamp census or accepting either duplicate value.
            finding(
                document,
                Span {
                    start: cause.offset(),
                    length: 0,
                },
                Severity::Required,
                Rule::Schema {
                    code: cause.code(),
                    field: cause.field(),
                },
                findings,
            )?;
            Ok(true)
        }
    }
}

fn finding<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    span: Span,
    severity: Severity,
    rule: Rule,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
    findings
        .try_push(Finding {
            location: document.locate(span),
            severity,
            rule,
        })
        .map_err(|cause| Error::resource(cause, FIELD, span.start))
}

fn collect_timestamps<'a, W: Work>(
    signer: &SignerInfo<'a>,
    parent: &Reader<'a>,
    out: &mut OwnedVec<Timestamp<'a>, W>,
) -> Result<()> {
    for set in [signer.signed_attributes(), signer.unsigned_attributes()]
        .into_iter()
        .flatten()
    {
        for attribute in set.items() {
            parent
                .charge(3 * (1 + attribute.kind().as_bytes().len().min(12) as u64))
                .map_err(|e| Error::encoding(e, FIELD))?;
            let purpose = if attribute.kind() == oid::CONTENT_TIMESTAMP {
                Purpose::Content
            } else if attribute.kind() == oid::SIGNATURE_TIMESTAMP {
                Purpose::Signature
            } else if attribute.kind() == oid::ARCHIVE_TIMESTAMP_V3 {
                Purpose::Archive
            } else {
                continue;
            };
            if attribute.values().is_empty() {
                out.try_push(Timestamp {
                    owner: Node::of(signer.span()),
                    property: Node::of(attribute.span()),
                    value: None,
                    purpose,
                    preservation_kind: None,
                })
                .map_err(|cause| Error::resource(cause, FIELD, attribute.span().start))?;
            }
            for (index, value) in attribute.values().iter().enumerate() {
                let source =
                    attribute
                        .value_reader_in(index, parent, FIELD)?
                        .ok_or(Error::Foreign {
                            at: value.span().start,
                        })?;
                out.try_push(Timestamp {
                    owner: Node::of(signer.span()),
                    property: Node::of(attribute.span()),
                    value: Some(crate::source::Value::of(&source, *value, FIELD)),
                    purpose,
                    preservation_kind: None,
                })
                .map_err(|cause| Error::resource(cause, FIELD, value.span().start))?;
            }
        }
    }
    Ok(())
}

fn collect_historical_timestamps<'d, W: Work>(
    required: &[crate::preservation::Required<'d>],
    parent: &Reader<'d>,
    timestamps: &mut OwnedVec<Timestamp<'d>, W>,
) -> Result<()> {
    for entry in required {
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        if !entry.kind.is_archive() && !entry.kind.is_reference_timestamp() {
            continue;
        }
        timestamps
            .try_push(Timestamp {
                owner: entry.signature,
                property: entry.property,
                value: entry.value,
                purpose: if entry.kind.is_archive() {
                    Purpose::Archive
                } else {
                    Purpose::ValidationData
                },
                preservation_kind: Some(entry.kind),
            })
            .map_err(|cause| Error::resource(cause, FIELD, entry.property.span().start))?;
    }
    Ok(())
}

struct CounterCatalogue {
    children: OwnedVec<Node>,
    index: OwnedMap<Node, usize>,
    conforming: bool,
}
fn counter_catalogue(
    counters: &[Counter<'_>],
    parent: &Reader<'_>,
    signature: Node,
) -> Result<CounterCatalogue> {
    let work = parent.execution();
    let mut children = work.vector();
    children
        .try_reserve_exact(counters.len())
        .map_err(|cause| Error::resource(cause, FIELD, signature.span().start))?;
    let mut index = work.map();
    let mut conforming = true;
    for (ordinal, counter) in counters.iter().enumerate() {
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, counter.node.span().start))?;
        if counter.malformed.is_some() {
            conforming = false;
        }
        children
            .try_push(counter.node)
            .map_err(|cause| Error::resource(cause, FIELD, counter.node.span().start))?;
        if index
            .try_insert(counter.node, ordinal)
            .map_err(|cause| Error::resource(cause, FIELD, counter.node.span().start))?
            .is_some()
        {
            return Err(Error::Foreign {
                at: counter.node.span().start,
            });
        }
    }
    Ok(CounterCatalogue {
        children: children.into_owned(),
        index: index.into_owned(),
        conforming,
    })
}

fn timestamp_ranges(
    timestamps: &[Timestamp<'_>],
    parent: &Reader<'_>,
) -> Result<OwnedMap<Node, core::ops::Range<usize>>> {
    let work = parent.execution();
    let mut ranges = work.map();
    for (ordinal, entry) in timestamps.iter().enumerate() {
        let resource = |cause| Error::resource(cause, FIELD, entry.property.span().start);
        work.charge_work(1).map_err(resource)?;
        if let Some(previous) = ranges.get_mut(&entry.property, &work).map_err(resource)? {
            let previous: &mut core::ops::Range<usize> = previous;
            // Each source attribute is collected once, in its original value
            // order. A range must never include another attribute's values.
            if previous.end != ordinal {
                return Err(Error::Foreign {
                    at: entry.property.span().start,
                });
            }
            previous.end += 1;
        } else {
            ranges
                .try_insert(entry.property, ordinal..ordinal + 1)
                .map_err(resource)?;
        }
    }
    Ok(ranges.into_owned())
}

type HistoricalCatalogues<'d> = (
    Option<OwnedMap<Node, core::ops::Range<usize>>>,
    proofs::Proofs<'d>,
);

fn history_timestamps<'d, W: Work>(
    preservation: &[crate::preservation::Required<'d>],
    timestamps: &mut OwnedVec<Timestamp<'d>, W>,
    parallel: &mut Option<Parallel<'d>>,
    parent: &Reader<'d>,
    signer: Node,
) -> Result<HistoricalCatalogues<'d>> {
    let execution = parent.execution();
    let mut historical = false;
    for required in preservation {
        execution
            .charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, required.property.span().start))?;
        if required.kind.is_archive()
            || required.kind.is_reference_timestamp()
            || required.kind.is_evidence()
        {
            historical = true;
            break;
        }
    }
    if historical
        && let Some(parallel) = parallel
        && let Some(extra) = parallel.timestamps.take()
    {
        execution
            .charge_work(extra.len() as u64)
            .map_err(|cause| Error::resource(cause, FIELD, signer.span().start))?;
        for entry in extra {
            timestamps
                .try_push(entry)
                .map_err(|cause| Error::resource(cause, FIELD, signer.span().start))?;
        }
    }
    collect_historical_timestamps(preservation, parent, timestamps)?;
    let proofs = proofs::Proofs::collect(preservation, parent, timestamps)?;
    if historical {
        Ok((Some(timestamp_ranges(timestamps, parent)?), proofs))
    } else {
        Ok((None, proofs))
    }
}

fn parallel_lookup(
    counters: Option<&[Counter<'_>]>,
    parent: &Reader<'_>,
) -> Result<Option<OwnedMap<Node, usize>>> {
    let Some(counters) = counters else {
        return Ok(None);
    };
    let work = parent.execution();
    let mut lookup = work.map();
    for (ordinal, counter) in counters.iter().enumerate() {
        if lookup
            .try_insert(counter.node, ordinal)
            .map_err(|cause| Error::resource(cause, FIELD, counter.node.span().start))?
            .is_some()
        {
            return Err(Error::Foreign {
                at: counter.node.span().start,
            });
        }
    }
    Ok(Some(lookup.into_owned()))
}

fn read_parallel<'d, W: Work>(
    document: &Document<'_, 'd>,
    selected: &SignerInfo<'d>,
    parent: &Reader<'d>,
    signatures: &mut OwnedVec<structured_cms::octets::Piece<'d>, W>,
    preservation: &mut OwnedVec<crate::preservation::Required<'d>, W>,
) -> Result<Option<Parallel<'d>>> {
    let work = parent.execution();
    let mut counters = None;
    let mut timestamps = None;
    for root in document.message().signers() {
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, root.span().start))?;
        if core::ptr::eq(root, selected) {
            continue;
        }
        collect_timestamps(
            root,
            parent,
            timestamps.get_or_insert_with(|| work.vector()),
        )?;
        let visited = counter::walk(root, parent, |visit, reader| -> Result<()> {
            let entry = match visit {
                Visit::Signer {
                    signer,
                    parent: owner,
                    ..
                } => {
                    crate::preservation::collect(signer, reader, preservation)?;
                    collect_timestamps(
                        signer,
                        reader,
                        timestamps.get_or_insert_with(|| work.vector()),
                    )?;
                    let start = signatures.len();
                    signatures
                        .try_extend_from_slice(signer.signature().pieces())
                        .map_err(|cause| Error::resource(cause, FIELD, signer.span().start))?;
                    let properties =
                        if crate::properties::Properties::has_legacy_values(signer, reader)? {
                            Some(crate::properties::Properties::read(signer, reader)?)
                        } else {
                            None
                        };
                    Counter {
                        parent: Node::of(owner),
                        node: Node::of(signer.span()),
                        malformed: None,
                        signature: start..signatures.len(),
                        properties,
                        encoding: Some(encoding::SignerEncoding::read(signer, reader)?),
                    }
                }
                Visit::Malformed {
                    source,
                    parent: owner,
                } => Counter {
                    parent: Node::of(owner),
                    node: Node::of(Span {
                        start: source.offset(),
                        length: 0,
                    }),
                    malformed: Some(source),
                    signature: signatures.len()..signatures.len(),
                    properties: None,
                    encoding: None,
                },
            };
            let at = entry.node.span().start;
            counters
                .get_or_insert_with(|| work.vector())
                .try_push(entry)
                .map_err(|cause| Error::resource(cause, FIELD, at))
        })
        .map_err(|cause| match cause {
            WalkError::Processing(cause) => Error::Cms(cause),
            WalkError::Callback { source, .. } => source,
        })?;
        drop(visited);
    }
    let timestamps = timestamps
        .filter(|rows| !rows.is_empty())
        .map(OwnedVec::into_owned);
    let index = parallel_lookup(counters.as_deref(), parent)?;
    let counters = counters.map(OwnedVec::into_owned);
    if counters.is_none() && timestamps.is_none() {
        return Ok(None);
    }
    Ok(Some(Parallel {
        counters,
        index,
        timestamps,
    }))
}

fn parallel_findings<'m, 'd>(
    document: &Document<'m, 'd>,
    parallel: Option<&Parallel<'d>>,
    parsed: &mut tokens::Cache<'m, 'd>,
    parent: &Reader<'d>,
) -> Result<()> {
    let Some(counters) = parallel.and_then(|parallel| parallel.counters.as_deref()) else {
        return Ok(());
    };
    let work = parent.execution();
    let mut related = None;
    for counter in counters {
        work.charge_work(1)
            .map_err(|cause| Error::resource(cause, FIELD, counter.node.span().start))?;
        let Some(cause) = counter.malformed() else {
            continue;
        };
        if related.is_none() {
            related = Some(match parsed.related.take() {
                Some(saved) => saved.with_execution(&work).map_err(|_| Error::Foreign {
                    at: counter.node.span().start,
                })?,
                None => work.vector(),
            });
        }
        // The full history census cannot treat an unreadable source as an
        // empty set of historical properties. Keep the original cause on the
        // counter and its negative finding SEPARATE from selected B-B syntax.
        finding(
            document,
            counter.node.span(),
            Severity::Required,
            Rule::Schema {
                code: cause.code(),
                field: cause.field(),
            },
            related.as_mut().expect("created for this original finding"),
        )?;
    }
    if let Some(related) = related {
        parsed.related = Some(related.into_owned());
    }
    Ok(())
}

fn read_counters<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'d>,
    parent: &Reader<'d>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
    timestamps: &mut OwnedVec<Timestamp<'d>, W>,
    signatures: &mut OwnedVec<structured_cms::octets::Piece<'d>, W>,
    preservation: &mut OwnedVec<crate::preservation::Required<'d>, W>,
) -> Result<OwnedVec<Counter<'d>>> {
    counter::walk(signer, parent, |visit, reader| -> Result<Counter<'d>> {
        match visit {
            Visit::Signer {
                signer: child,
                parent: owner,
                ..
            } => {
                crate::preservation::collect(child, reader, preservation)?;
                let profile =
                    structured_cms::cades::inspect_profile(child, Role::Countersignature, reader)?;
                schema_findings(document, child, &profile, reader, findings)?;
                // RFC5652 §11.4 gives counters their own protected-field
                // rules. Inspect them before keys/math, using the same kernel
                // as actual counter verification; preserve readable siblings.
                // https://www.rfc-editor.org/rfc/rfc5652#section-11.4
                binding_findings(
                    document,
                    child,
                    structured_cms::binding::Scope::CounterSignature,
                    reader,
                    findings,
                )?;
                let properties = crate::properties::Properties::read(child, reader)?;
                property_findings(document, &properties, reader, findings)?;
                mechanism_findings(document, child, &profile, &properties, reader, findings)?;
                legacy_rules(document, child, &properties, None, reader, findings)?;
                collect_timestamps(child, reader, timestamps)?;
                let start = signatures.len();
                signatures
                    .try_extend_from_slice(child.signature().pieces())
                    .map_err(|cause| Error::resource(cause, FIELD, child.span().start))?;
                let end = signatures.len();
                Ok(Counter {
                    parent: Node::of(owner),
                    node: Node::of(child.span()),
                    malformed: None,
                    signature: start..end,
                    properties: Some(properties),
                    encoding: Some(encoding::SignerEncoding::read(child, reader)?),
                })
            }
            Visit::Malformed {
                source,
                parent: owner,
            } => {
                let at = source.offset();
                Ok(Counter {
                    parent: Node::of(owner),
                    node: Node::of(Span {
                        start: at,
                        length: 0,
                    }),
                    malformed: Some(source),
                    signature: signatures.len()..signatures.len(),
                    properties: None,
                    encoding: None,
                })
            }
        }
    })
    .map_err(|error| match error {
        WalkError::Processing(error) => Error::Cms(error),
        WalkError::Callback { source: error, .. } => error,
    })
}

fn token_obligations<W: Work>(
    timestamps: &[Timestamp<'_>],
    execution: &W,
    at: u64,
) -> Result<OwnedVec<RequiredToken<Node>, W>> {
    let mut tokens = execution.vector();
    tokens
        .try_reserve_exact(timestamps.len())
        .map_err(|cause| Error::resource(cause, FIELD, at))?;
    for entry in timestamps {
        tokens
            .try_push(RequiredToken {
                signature: entry.owner,
                property: entry.property,
                token: entry
                    .value
                    .map_or(entry.property, |value| Node::of(value.element().span())),
                purpose: entry.purpose,
            })
            .map_err(|cause| Error::resource(cause, FIELD, entry.property.span().start))?;
    }
    Ok(tokens)
}
