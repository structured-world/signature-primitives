//! Source-derived baseline obligations, before keys, provider states or content.

use crate::source::{Document, DocumentId, Node, Original};
use crate::{Cades, Error, ISSUER, Level, Result};
use structured_asn1::memory::{OwnedMap, OwnedVec, Work};
use structured_asn1::{Element, Reader, Span};
use structured_cms::attribute::Attributes;
use structured_cms::cades::{Profile, Role};
use structured_cms::counter::{self, Visit, WalkError};
use structured_cms::signer::SignerInfo;
use structured_cms::{ErrorCode, oid};
use structured_ltv::baseline::ArchiveCensus;
use structured_ltv::timestamp::{Purpose, RequiredToken, TimestampRequirements, TimestampScope};

const FIELD: &str = "cades";
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
    /// Requested LT/LTA forbids this original legacy attribute.
    Forbidden(structured_asn1::Oid<'static>),
    /// No signing-certificate protection service exists.
    SigningCertificate,
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
}

/// One original counter value. Malformed values retain a real location and
/// diagnostic and cannot disappear from a later participant census.
pub struct Counter<'a> {
    parent: Node,
    node: Node,
    malformed: Option<structured_cms::Error>,
    signature: core::ops::Range<usize>,
    properties: Option<crate::properties::Properties<'a>>,
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
    counter_index: OwnedMap<Node, usize>,
    signatures: OwnedVec<structured_cms::octets::Piece<'document>>,
    timestamps: OwnedVec<Timestamp<'document>>,
    required: TimestampRequirements<Node, DocumentId<'model, 'document>, (), Cades>,
    conforming: bool,
    basic_conforming: bool,
    preservation: OwnedVec<crate::preservation::Required<'document>>,
    pub(crate) parsed: tokens::Cache<'document>,
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
        let profile = structured_cms::cades::profile(signer, Role::Signature, parent)?;
        let mut findings = execution.vector();
        root_rules(document, signer, requested, &profile, parent, &mut findings)?;
        let properties = crate::properties::Properties::read(signer, parent)?;
        property_findings(document, &properties, parent, &mut findings)?;
        mechanism_findings(
            document,
            signer,
            &profile,
            &properties,
            parent,
            &mut findings,
        )?;
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
        let tokens = token_obligations(&timestamps, &execution, selected.node.span().start)?;
        let mut children = execution.vector();
        children
            .try_reserve_exact(counters.len())
            .map_err(|cause| Error::resource(cause, FIELD, selected.node.span().start))?;
        let mut conforming = true;
        let mut basic_conforming = true;
        let mut counter_index = execution.map();
        for (ordinal, counter) in counters.iter().enumerate() {
            execution
                .charge_work(1)
                .map_err(|cause| Error::resource(cause, FIELD, counter.node.span().start))?;
            if counter.malformed.is_some() {
                conforming = false;
                basic_conforming = false;
            }
            children
                .try_push(counter.node)
                .map_err(|cause| Error::resource(cause, FIELD, counter.node.span().start))?;
            if counter_index
                .try_insert(counter.node, ordinal)
                .map_err(|cause| Error::resource(cause, FIELD, counter.node.span().start))?
                .is_some()
            {
                return Err(Error::Foreign {
                    at: counter.node.span().start,
                }
                .into());
            }
        }
        let parsed = tokens::read(document, &timestamps, parent, &mut findings)?;
        for finding in &findings {
            execution.charge_work(1).map_err(|cause| {
                Error::resource(cause, FIELD, finding.location.node.span().start)
            })?;
            if finding.severity == Severity::Required {
                conforming = false;
                if !matches!(
                    finding.rule,
                    Rule::SignatureTimestamp | Rule::ArchiveTimestamp | Rule::Forbidden(_)
                ) {
                    basic_conforming = false;
                }
            }
        }
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
            counter_index: counter_index.into_owned(),
            signatures: signatures.into_owned(),
            timestamps: timestamps.into_owned(),
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
        if token.owner == Node::of(self.signer.span()) {
            return Ok(None);
        }
        let Some(ordinal) = self
            .counter_index
            .get(&token.owner, &parent.execution())
            .map_err(|cause| Error::resource(cause, FIELD, token.property.span().start))?
        else {
            return Err(Error::Foreign {
                at: token.property.span().start,
            });
        };
        self.signature_of(self.counters[*ordinal].parent, parent)
            .map(Some)
    }
    fn signature_of(
        &self,
        owner: Node,
        parent: &Reader<'_>,
    ) -> Result<&[structured_cms::octets::Piece<'d>]> {
        if owner == Node::of(self.signer.span()) {
            return Ok(self.signer.signature().pieces());
        }
        let Some(ordinal) = self
            .counter_index
            .get(&owner, &parent.execution())
            .map_err(|cause| Error::resource(cause, FIELD, owner.span().start))?
        else {
            return Err(Error::Foreign {
                at: owner.span().start,
            });
        };
        Ok(&self.signatures[self.counters[*ordinal].signature.clone()])
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
            Some(token.property)
        } else {
            None
        }
    }
}

fn schema_findings<'m, 'd, W: Work>(
    document: &Document<'m, 'd>,
    signer: &SignerInfo<'_>,
    profile: &Profile<'_>,
    parent: &Reader<'_>,
    findings: &mut OwnedVec<Finding<'m, 'd>, W>,
) -> Result<()> {
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
            Rule::Value {
                attribute: fault.attribute,
                field: fault.field,
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
    match structured_cms::binding::inspect(
        signer,
        parent,
        structured_cms::binding::Scope::Content(document.message().content().kind()),
    ) {
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
    protected_rules(document, signer, profile, parent, findings)?;
    unsigned_rules(document, signer, requested, parent, findings)
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
            // §6.3 table1 explicitly forbids the AnnexA reference/value forms
            // at LT/LTA, but '*' at B-B/B-T is only an advisory.
            // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
            for kind in LEGACY {
                parent
                    .charge(1 + attribute.kind().as_bytes().len().min(kind.as_bytes().len()) as u64)
                    .map_err(|e| Error::encoding(e, FIELD))?;
                if attribute.kind() == kind {
                    finding(
                        document,
                        attribute.span(),
                        if requested >= Level::LongTerm {
                            Severity::Required
                        } else {
                            Severity::Advisory
                        },
                        Rule::Forbidden(kind),
                        findings,
                    )?;
                    break;
                }
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
                })
                .map_err(|cause| Error::resource(cause, FIELD, value.span().start))?;
            }
        }
    }
    Ok(())
}

// EN319122-1 AnnexA/Table1: complete cert/revocation refs, values,
// credential refs, and the two reference timestamps. Pure wire identifiers.
const LEGACY: [structured_asn1::Oid<'static>; 8] = [
    structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 21]),
    structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 22]),
    structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 23]),
    structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 24]),
    structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 25]),
    structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 26]),
    structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 44]),
    structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 45]),
];

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
                    structured_cms::cades::profile(child, Role::Countersignature, reader)?;
                schema_findings(document, child, &profile, reader, findings)?;
                let properties = crate::properties::Properties::read(child, reader)?;
                property_findings(document, &properties, reader, findings)?;
                mechanism_findings(document, child, &profile, &properties, reader, findings)?;
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
