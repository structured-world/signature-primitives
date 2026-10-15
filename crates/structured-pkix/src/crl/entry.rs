//! Deferred entry extension decoding in the current execution account.

use super::{Authenticated, IssuingDistributionPoint, RevokedCertificate};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extension};
use crate::general_name::{self, GeneralName};
use crate::{Certificate, Time, oid};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Oid, Reader, Span, Tag, universal};

/// Entry search over an authenticated source. This is not a freshness or
/// distribution-point applicability decision.
#[derive(Debug, Clone, Copy)]
pub enum EntryLookup<'r, 'a> {
    /// No entry with the target's issuer and serial was listed.
    Absent,
    /// Exactly one matching entry was listed.
    Found(&'r RevokedCertificate<'a>),
    /// Multiple matching entries leave their intended status ambiguous.
    Conflict {
        /// Earlier original entry.
        first: &'r RevokedCertificate<'a>,
        /// Later original entry.
        second: &'r RevokedCertificate<'a>,
    },
    /// A critical demand prevents using this CRL for any certificate status.
    Unsupported {
        /// Unknown critical extension identifier.
        kind: Oid<'a>,
        /// Original location, including an unmatched entry's demand.
        span: Span,
    },
}

impl<'r, 'a> Authenticated<'r, 'a> {
    /// Search by issuer plus serial, retaining indirect issuer inheritance.
    /// Unknown critical extensions anywhere in the list invalidate use for all
    /// statuses, including demands on entries unrelated to this target.
    pub fn entry<W: Work + 'a>(
        &self,
        target: &Certificate<'_>,
        execution: &W,
    ) -> Result<EntryLookup<'r, 'a>> {
        const FIELD: &str = "certificateList.entryLookup";
        let crl = self.crl();
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, crl.span().start))?;
        let extensions = crl.tbs().extensions();
        let is_delta = delta_source(crl, execution)?;
        let idp = extensions
            .get(oid::ISSUING_DISTRIBUTION_POINT, execution)?
            .map(|extension| IssuingDistributionPoint::read(extension, execution))
            .transpose()?;
        let indirect = idp
            .as_ref()
            .is_some_and(IssuingDistributionPoint::is_indirect);
        if let Some(extension) = check_source_metadata(crl, is_delta, execution)? {
            return Ok(EntryLookup::Unsupported {
                kind: extension.kind(),
                span: extension.span(),
            });
        }
        let target_serial = target.tbs().serial().as_bytes();
        let target_issuer = target.tbs().issuer().as_bytes();
        let mut inherited = None;
        let mut default_matches = None;
        let mut found = None;
        let mut conflict = None;
        for entry in crl.tbs().revoked_certificates() {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, FIELD, entry.span.start))?;
            // RFC 5280 §5.3: an unknown critical entry extension prevents
            // using this CRL for the status of ANY certificate.
            // https://www.rfc-editor.org/rfc/rfc5280#section-5.3
            for extension in entry.extensions.criticals(execution) {
                let extension = extension?;
                let kind = extension.kind();
                execution
                    .charge_work(19)
                    .map_err(|reason| Error::resource(reason, FIELD, extension.span().start))?;
                if kind != oid::CRL_REASON
                    && kind != oid::INVALIDITY_DATE
                    && kind != oid::CERTIFICATE_ISSUER
                {
                    return Ok(EntryLookup::Unsupported {
                        kind,
                        span: extension.span(),
                    });
                }
            }
            // Known extension syntax is checked even on unmatched entries.
            validate_status_extensions(entry, is_delta, execution)?;
            if let Some(names) = validated_issuer(entry, indirect, execution)? {
                inherited = Some(names);
            }
            // Explicit certificateIssuer inherits §5.3.3's original DN
            // encoding identity rule. The default CRL issuer instead uses
            // the ordinary DN equality rules of §7.1.
            // https://www.rfc-editor.org/rfc/rfc5280#section-5.3.3
            let mut issuer_matches = false;
            if let Some(names) = &inherited {
                for name in names {
                    execution
                        .charge_work(1)
                        .map_err(|reason| Error::resource(reason, FIELD, entry.span.start))?;
                    if let GeneralName::Directory(name) = name
                        && equal_bytes(name.as_bytes(), target_issuer, execution, entry.span.start)?
                    {
                        issuer_matches = true;
                        break;
                    }
                }
            } else {
                issuer_matches = if let Some(matched) = default_matches {
                    matched
                } else {
                    let matched = crl
                        .tbs()
                        .issuer()
                        .matches(target.tbs().issuer(), execution)?;
                    default_matches = Some(matched);
                    matched
                };
            }
            if issuer_matches
                && equal_bytes(
                    entry.serial.as_bytes(),
                    target_serial,
                    execution,
                    entry.span.start,
                )?
            {
                if let Some(previous) = found {
                    if conflict.is_none() {
                        conflict = Some((previous, entry));
                    }
                } else {
                    found = Some(entry);
                }
            }
        }
        if let Some((first, second)) = conflict {
            return Ok(EntryLookup::Conflict { first, second });
        }
        Ok(match found {
            Some(entry) => EntryLookup::Found(entry),
            None => EntryLookup::Absent,
        })
    }
}

fn validate_status_extensions<'a, W: Work + 'a>(
    entry: &RevokedCertificate<'a>,
    delta: bool,
    execution: &W,
) -> Result<()> {
    // RFC5280 §5.3.1: removeFromCRL may only appear in deltas, including
    // when the malformed entry is unrelated to the requested certificate.
    // https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1
    if entry.reason(execution)? == Some(Reason::RemoveFromCrl) && !delta {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            "extensions.reasonCode",
            entry.span.start,
        ));
    }
    entry.invalidity_date(execution)?;
    Ok(())
}

fn delta_source<'a, W: Work + 'a>(crl: &super::CertificateList<'a>, execution: &W) -> Result<bool> {
    let Some(indicator) = crl
        .tbs()
        .extensions()
        .get(oid::DELTA_CRL_INDICATOR, execution)?
    else {
        return Ok(false);
    };
    if !indicator.is_critical() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            "extensions.deltaCRLIndicator",
            indicator.span().start,
        ));
    }
    super::delta::number(indicator, execution)?;
    Ok(true)
}

fn check_source_metadata<'r, 'a, W: Work + 'a>(
    crl: &'r super::CertificateList<'a>,
    is_delta: bool,
    execution: &W,
) -> Result<Option<&'r Extension<'a>>> {
    const FIELD: &str = "certificateList.extensions";
    for extension in crl.tbs().extensions().iter(execution) {
        let extension = extension?;
        execution
            // Metadata admission belongs to the common iterator; this
            // previously combined cost retains only the OID/profile work.
            .charge_work(52)
            .map_err(|reason| Error::resource(reason, FIELD, extension.span().start))?;
        let kind = extension.kind();
        let malformed = || Error::new(ErrorCode::MalformedValue, FIELD, extension.span().start);
        if kind == oid::ISSUING_DISTRIBUTION_POINT {
            // RFC5280 §5.2.5: this extension MUST be critical. The caller
            // already decoded its scope once before this metadata pass.
            if !extension.is_critical() {
                return Err(malformed());
            }
        } else if kind == oid::CRL_NUMBER {
            // RFC5280 §5.2.3: noncritical INTEGER (0..MAX), including on
            // ordinary complete sources, not only delta binding.
            // https://www.rfc-editor.org/rfc/rfc5280#section-5.2.3
            if extension.is_critical() {
                return Err(malformed());
            }
            super::delta::number(extension, execution)?;
        } else if kind == oid::DELTA_CRL_INDICATOR {
            // delta_source validated the critical indicator's number once.
        } else if kind == oid::AUTHORITY_KEY_IDENTIFIER {
            // RFC5280 §§5.2.1/4.2.1.1: present CRL AKI uses keyIdentifier
            // and is noncritical. Absence is not a blanket v1 receiver refusal.
            // https://www.rfc-editor.org/rfc/rfc5280#section-5.2.1
            if extension.is_critical() {
                return Err(malformed());
            }
            let identifier = crate::identifier::AuthorityKeyIdentifier::read(extension, execution)?;
            if identifier.key_id().is_none() {
                return Err(malformed());
            }
        } else if kind == oid::ISSUER_ALT_NAME {
            general_name::read_alternative(extension, execution)?;
        } else if kind == oid::AUTHORITY_INFO_ACCESS {
            // RFC5280 §5.2.7 forbids critical AIA. Noncritical fetch hints are
            // preserved, not interpreted or used to establish status here.
            // https://www.rfc-editor.org/rfc/rfc5280#section-5.2.7
            if extension.is_critical() {
                return Err(malformed());
            }
        } else if kind == oid::FRESHEST_CRL {
            // RFC5280 §5.2.6: noncritical, complete sources only, with no
            // reasons or cRLIssuer in its distribution points. No fetching.
            // https://www.rfc-editor.org/rfc/rfc5280#section-5.2.6
            if extension.is_critical() || is_delta {
                return Err(malformed());
            }
            let points = crate::access::DistributionPoints::read(extension, execution)?;
            for point in points.points() {
                execution
                    .charge_work(1)
                    .map_err(|reason| Error::resource(reason, FIELD, extension.span().start))?;
                if point.reasons().is_some() || !point.issuer().is_empty() {
                    return Err(malformed());
                }
            }
        } else if extension.is_critical() {
            return Ok(Some(extension));
        }
    }
    Ok(None)
}

fn validated_issuer<'a, W: Work + 'a>(
    entry: &RevokedCertificate<'a>,
    indirect: bool,
    execution: &W,
) -> Result<Option<OwnedVec<GeneralName<'a>>>> {
    const FIELD: &str = "extensions.certificateIssuer";
    let Some(extension) = entry.extensions.get(oid::CERTIFICATE_ISSUER, execution)? else {
        return Ok(None);
    };
    if !indirect || !extension.is_critical() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            extension.span().start,
        ));
    }
    let mut reader = extension::sequence(extension, FIELD, execution)?;
    let names = general_name::read_list(&mut reader, FIELD, extension.span().start)?;
    let mut directory = false;
    for name in &names {
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, extension.span().start))?;
        if matches!(name, GeneralName::Directory(name) if !name.is_empty()) {
            directory = true;
        }
    }
    if !directory {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            extension.span().start,
        ));
    }
    Ok(Some(names))
}

fn equal_bytes(left: &[u8], right: &[u8], execution: &impl Work, at: u64) -> Result<bool> {
    let work = (left.len().max(right.len()) as u64)
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| {
            Error::resource(
                structured_asn1::memory::MemoryError::WorkExceeded,
                "certificateList.entryLookup",
                at,
            )
        })?;
    execution
        .charge_work(work)
        .map_err(|reason| Error::resource(reason, "certificateList.entryLookup", at))?;
    Ok(left == right)
}

/// RFC 5280 §5.3.1 reasonCode values. Enumeration numbers differ from
/// `ReasonFlags` bit positions for privilegeWithdrawn and aACompromise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No more specific reason was stated.
    Unspecified,
    /// Subject private key compromise.
    KeyCompromise,
    /// Certification authority private key compromise.
    AuthorityCompromise,
    /// Subject affiliation changed.
    AffiliationChanged,
    /// Certificate replaced.
    Superseded,
    /// The certified operation ceased.
    CessationOfOperation,
    /// Temporary suspension.
    CertificateHold,
    /// Delta CRL removes a prior hold or expired entry; not a new revocation.
    RemoveFromCrl,
    /// Privilege withdrawn (enumeration 9, reason flag 7).
    PrivilegeWithdrawn,
    /// Attribute authority compromise (enumeration 10, reason flag 8).
    AttributeAuthorityCompromise,
}

impl<'a> RevokedCertificate<'a> {
    /// Stated reason, independently of whether this CRL is a valid complete or
    /// delta list. An omitted extension stays absent rather than rewritten.
    pub fn reason<W: Work + 'a>(&self, execution: &W) -> Result<Option<Reason>> {
        self.extensions
            .get(oid::CRL_REASON, execution)?
            .map(|extension| read_reason(extension, execution))
            .transpose()
    }

    /// When the issuer believes invalidity began, distinct from revocationDate.
    pub fn invalidity_date<W: Work + 'a>(&self, execution: &W) -> Result<Option<Time>> {
        const FIELD: &str = "extensions.invalidityDate";
        let Some(extension) = self.extensions.get(oid::INVALIDITY_DATE, execution)? else {
            return Ok(None);
        };
        let mut reader = extension.reader(execution).field(FIELD)?;
        let element = reader
            .expect(Tag::primitive(universal::GENERALIZED_TIME))
            .field(FIELD)?;
        super::end(&reader, FIELD, extension.span().start)?;
        crate::time::read_in(&reader, &element, FIELD).map(Some)
    }

    /// Explicit issuer names on this entry. None means inheritance from the
    /// previous entry (or CRL issuer on the first), never an absent identity.
    pub fn certificate_issuer<W: Work + 'a>(
        &self,
        execution: &W,
    ) -> Result<Option<OwnedVec<GeneralName<'a>>>> {
        const FIELD: &str = "extensions.certificateIssuer";
        let Some(extension) = self.extensions.get(oid::CERTIFICATE_ISSUER, execution)? else {
            return Ok(None);
        };
        let mut reader = extension::sequence(extension, FIELD, execution)?;
        general_name::read_list(&mut reader, FIELD, extension.span().start).map(Some)
    }
}

fn read_reason<'a, W: Work + 'a>(extension: &Extension<'a>, execution: &W) -> Result<Reason> {
    const FIELD: &str = "extensions.reasonCode";
    let mut reader = extension.reader(execution).field(FIELD)?;
    let element = reader.expect(Tag::primitive(10)).field(FIELD)?;
    super::end(&reader, FIELD, extension.span().start)?;
    reason_element(&reader, &element, FIELD)
}

/// Shared reasonCode schema for CRL entries and OCSP `RevokedInfo`.
pub(crate) fn reason_element(
    parent: &Reader<'_>,
    element: &structured_asn1::Element<'_>,
    field: &'static str,
) -> Result<Reason> {
    parent.charge(9).field(field)?;
    let value = parent.integer(element).field(field)?;
    // ENUMERATED content uses the same two's-complement/minimal encoding as
    // INTEGER (X.690 §8.4); the reason schema selects the permitted values.
    // https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1
    match value.as_u64() {
        Some(0) => Ok(Reason::Unspecified),
        Some(1) => Ok(Reason::KeyCompromise),
        Some(2) => Ok(Reason::AuthorityCompromise),
        Some(3) => Ok(Reason::AffiliationChanged),
        Some(4) => Ok(Reason::Superseded),
        Some(5) => Ok(Reason::CessationOfOperation),
        Some(6) => Ok(Reason::CertificateHold),
        Some(8) => Ok(Reason::RemoveFromCrl),
        Some(9) => Ok(Reason::PrivilegeWithdrawn),
        Some(10) => Ok(Reason::AttributeAuthorityCompromise),
        _ => Err(Error::new(
            ErrorCode::MalformedValue,
            field,
            element.span().start,
        )),
    }
}
