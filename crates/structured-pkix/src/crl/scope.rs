//! CRL issuing-distribution-point grammar shares certificate DP name parsing.

use crate::access::{self, DistributionPoint, PointName};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extension};
use crate::general_name::GeneralName;
use crate::name::{self, Name, RelativeName};
use crate::{Certificate, Version, oid};
use structured_asn1::BitString;
use structured_asn1::memory::Work;

/// The eight revocation reasons in RFC 5280 §6.3.2, excluding unspecified
/// and removeFromCRL. `ReasonFlags` unused(0) never contributes coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reasons(u16);

impl Reasons {
    /// Every reason required by the standard CRL-processing algorithm.
    pub const ALL: Self = Self(0x1fe);
    /// No authenticated reason coverage.
    pub const NONE: Self = Self(0);
    /// Union of already established coverage facts.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    /// Whether the coverage includes all eight reasons.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.0 == Self::ALL.0
    }
    /// Whether coverage is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    /// Original `ReasonFlags` positions (1 through 8), without unused(0).
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// Geometric issuer/name/category scope mismatch, not a signature verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeFailure {
    /// Candidate CRL does not name the applicable issuer.
    Issuer,
    /// A DP naming a separate CRL issuer requires an indirect CRL.
    IndirectRequired,
    /// Expanded distribution-point names do not match.
    DistributionName,
    /// Category does not cover this public-key certificate.
    CertificateKind,
    /// A user-only/CA-only IDP cannot cover a v1/v2 certificate.
    CertificateVersion,
    /// The reason intersection covers none of the legal reasons.
    NoReasons,
}

/// Applicable scope says nothing about freshness or unknown critical demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeOutcome {
    /// Reason coverage for which this CRL's issuer and DP scope match.
    Applicable(Reasons),
    /// This source does not apply under the attempted distribution scope.
    NotApplicable(ScopeFailure),
}

impl<'a> super::Authenticated<'_, 'a> {
    /// Derive applicability from the target's own signed DP extension. Relative
    /// names are compared as borrowed composed RDN views, never encoded again.
    /// If no explicit DP applies, also consider the RFC 5280 §6.3.3 issuer-name
    /// fallback over supplied CRLs; this performs no fetching or discovery.
    pub fn scope<W: Work + 'a>(
        &self,
        target: &Certificate<'a>,
        execution: &W,
    ) -> Result<ScopeOutcome> {
        const FIELD: &str = "certificateList.scope";
        let crl = self.crl();
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, crl.span().start))?;
        let idp = crl
            .tbs()
            .extensions()
            .get(oid::ISSUING_DISTRIBUTION_POINT, execution)?
            .map(|extension| IssuingDistributionPoint::read(extension, execution))
            .transpose()?;
        if let Some(idp) = &idp {
            match idp.kind {
                CertificateKind::Attribute => {
                    return Ok(ScopeOutcome::NotApplicable(ScopeFailure::CertificateKind));
                }
                CertificateKind::EndEntity | CertificateKind::Authority => {
                    // RFC5280 §5.2.5 excludes v1/v2 for BOTH user-only and
                    // CA-only CRLs. The cA tests in §6.3.3(b)(2)(ii–iii) are
                    // additional conditions, not an exception to that scope.
                    // <https://www.rfc-editor.org/rfc/rfc5280#section-5.2.5>
                    if target.tbs().version() != Version::V3 {
                        return Ok(ScopeOutcome::NotApplicable(
                            ScopeFailure::CertificateVersion,
                        ));
                    }
                    let ca = target
                        .tbs()
                        .extensions()
                        .basic_constraints(execution)?
                        .is_some_and(crate::constraints::BasicConstraints::is_authority);
                    if ca != (idp.kind == CertificateKind::Authority) {
                        return Ok(ScopeOutcome::NotApplicable(ScopeFailure::CertificateKind));
                    }
                }
                CertificateKind::All => (),
            }
        }
        if let Some(outcome) = specified_scope(crl.tbs().issuer(), idp.as_ref(), target, execution)?
        {
            return Ok(outcome);
        }
        // RFC 5280 §6.3.3 final paragraph: synthetic DP names comprise the
        // target issuer DN and issuerAltName, with no cRLIssuer or reasons.
        // https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3
        if !crl
            .tbs()
            .issuer()
            .matches(target.tbs().issuer(), execution)?
        {
            return Ok(ScopeOutcome::NotApplicable(ScopeFailure::Issuer));
        }
        if let Some(idp) = &idp
            && idp.name.is_some()
        {
            let mut matched = point_name_matches_directory(
                idp,
                crl.tbs().issuer(),
                target.tbs().issuer(),
                execution,
            )?;
            if !matched && let Some(names) = target.tbs().extensions().issuer_alt_name(execution)? {
                matched =
                    point_name_matches_names::<false>(idp, crl.tbs().issuer(), &names, execution)?;
            }
            if !matched {
                return Ok(ScopeOutcome::NotApplicable(ScopeFailure::DistributionName));
            }
        }
        Ok(ScopeOutcome::Applicable(reason_mask(
            idp.as_ref().and_then(|idp| idp.reasons),
            execution,
            crl.span().start,
        )?))
    }
}

fn specified_scope<'a, W: Work + 'a>(
    issuer: &Name<'_>,
    idp: Option<&IssuingDistributionPoint<'_>>,
    target: &Certificate<'a>,
    execution: &W,
) -> Result<Option<ScopeOutcome>> {
    let mut coverage = Reasons::NONE;
    let mut failure = None;
    if let Some(points) = target
        .tbs()
        .extensions()
        .crl_distribution_points(execution)?
    {
        for point in points.points() {
            execution.charge_work(1).map_err(|reason| {
                Error::resource(reason, "certificateList.scope", target.span().start)
            })?;
            match point_scope(issuer, idp, target, point, execution)? {
                ScopeOutcome::Applicable(reasons) => coverage = coverage.union(reasons),
                ScopeOutcome::NotApplicable(ScopeFailure::NoReasons) => {
                    failure = Some(ScopeFailure::NoReasons);
                }
                ScopeOutcome::NotApplicable(ScopeFailure::DistributionName)
                    if failure.is_none()
                        && idp.is_some_and(|idp| idp.name.is_some())
                        && (!point.full_name().is_empty()
                            || point.name_relative_to_issuer().is_some()) =>
                {
                    // Both fields are present: §5.2.5 requires an identical
                    // selected name. The §6.3.3 synthetic fallback cannot
                    // discard this explicit field or its reason restriction.
                    failure = Some(ScopeFailure::DistributionName);
                }
                ScopeOutcome::NotApplicable(_) => (),
            }
        }
    }
    if !coverage.is_empty() {
        return Ok(Some(ScopeOutcome::Applicable(coverage)));
    }
    Ok(failure.map(ScopeOutcome::NotApplicable))
}

fn reason_mask(flags: Option<BitString<'_>>, execution: &impl Work, at: u64) -> Result<Reasons> {
    execution
        .charge_work(9)
        .map_err(|reason| Error::resource(reason, "certificateList.scope", at))?;
    let Some(flags) = flags else {
        return Ok(Reasons::ALL);
    };
    let mut mask = 0;
    for bit in 1..=8 {
        if flags.bit(bit) {
            mask |= 1 << bit;
        }
    }
    Ok(Reasons(mask))
}

fn point_scope(
    issuer: &Name<'_>,
    idp: Option<&IssuingDistributionPoint<'_>>,
    target: &Certificate<'_>,
    point: &DistributionPoint<'_>,
    execution: &impl Work,
) -> Result<ScopeOutcome> {
    if !point.issuer().is_empty() {
        if !idp.is_some_and(IssuingDistributionPoint::is_indirect) {
            return Ok(ScopeOutcome::NotApplicable(ScopeFailure::IndirectRequired));
        }
        let mut matches = false;
        for name in point.issuer() {
            execution.charge_work(1).map_err(|reason| {
                Error::resource(reason, "certificateList.scope", target.span().start)
            })?;
            if let GeneralName::Directory(name) = name
                && issuer_encoding_matches(issuer, name, execution)?
            {
                matches = true;
                break;
            }
        }
        if !matches {
            return Ok(ScopeOutcome::NotApplicable(ScopeFailure::Issuer));
        }
    } else if !issuer.matches(target.tbs().issuer(), execution)? {
        return Ok(ScopeOutcome::NotApplicable(ScopeFailure::Issuer));
    }
    if let Some(idp) = idp
        && idp.name.is_some()
    {
        let matched = if let Some(relative) = point.name_relative_to_issuer() {
            let base = if point.issuer().is_empty() {
                target.tbs().issuer()
            } else {
                match &point.issuer()[0] {
                    GeneralName::Directory(name) => name,
                    _ => unreachable!("DP reader requires directory issuers"),
                }
            };
            point_name_matches_composed::<true>(idp, issuer, base, Some(relative), execution)?
        } else if !point.full_name().is_empty() {
            // RFC5280 5.2.5 requires identical selected name encoding when
            // both DP fields are present; semantic name equality is used only
            // for issuer-only/synthetic fields in 6.3.3(b)(2)(i).
            // <https://www.rfc-editor.org/rfc/rfc5280#section-5.2.5>
            point_name_matches_names::<true>(idp, issuer, point.full_name(), execution)?
        } else {
            point_name_matches_names::<false>(idp, issuer, point.issuer(), execution)?
        };
        if !matched {
            return Ok(ScopeOutcome::NotApplicable(ScopeFailure::DistributionName));
        }
    }
    let left = reason_mask(
        idp.and_then(|idp| idp.reasons),
        execution,
        target.span().start,
    )?;
    let right = reason_mask(point.reasons(), execution, target.span().start)?;
    let reasons = Reasons(left.0 & right.0);
    if reasons.is_empty() {
        return Ok(ScopeOutcome::NotApplicable(ScopeFailure::NoReasons));
    }
    Ok(ScopeOutcome::Applicable(reasons))
}

fn issuer_encoding_matches(
    issuer: &Name<'_>,
    named: &Name<'_>,
    execution: &impl Work,
) -> Result<bool> {
    // RFC5280 §4.2.1.13 requires exactly the same encoding for explicit
    // cRLIssuer; ordinary DN equality remains applicable to the default issuer.
    // <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13>
    let left = issuer.as_bytes();
    let right = named.as_bytes();
    let work = u64::try_from(left.len().max(right.len()))
        .ok()
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| named.resource(structured_asn1::memory::MemoryError::WorkExceeded))?;
    execution
        .charge_work(work)
        .map_err(|reason| named.resource(reason))?;
    Ok(left == right)
}

fn point_name_matches_directory(
    idp: &IssuingDistributionPoint<'_>,
    issuer: &Name<'_>,
    directory: &Name<'_>,
    execution: &impl Work,
) -> Result<bool> {
    point_name_matches_composed::<false>(idp, issuer, directory, None, execution)
}

fn point_name_matches_composed<const ENCODED: bool>(
    idp: &IssuingDistributionPoint<'_>,
    issuer: &Name<'_>,
    base: &Name<'_>,
    relative: Option<&RelativeName<'_>>,
    execution: &impl Work,
) -> Result<bool> {
    match &idp.name {
        Some(PointName::Relative(suffix)) => {
            if ENCODED && relative.is_none() {
                return Ok(false);
            }
            name::matches_composed::<ENCODED>(issuer, Some(suffix), base, relative, execution)
        }
        Some(PointName::Full(names)) => {
            if ENCODED && relative.is_some() {
                return Ok(false);
            }
            for name in names {
                execution
                    .charge_work(1)
                    .map_err(|reason| base.resource(reason))?;
                if let GeneralName::Directory(directory) = name
                    && name::matches_composed::<ENCODED>(
                        directory, None, base, relative, execution,
                    )?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        None => Ok(true),
    }
}

fn point_name_matches_names<const ENCODED: bool>(
    idp: &IssuingDistributionPoint<'_>,
    issuer: &Name<'_>,
    names: &[GeneralName<'_>],
    execution: &impl Work,
) -> Result<bool> {
    for right in names {
        execution
            .charge_work(1)
            .map_err(|reason| issuer.resource(reason))?;
        match &idp.name {
            Some(PointName::Relative(relative)) => {
                if ENCODED {
                    return Ok(false);
                }
                if let GeneralName::Directory(directory) = right
                    && name::matches_composed::<ENCODED>(
                        issuer,
                        Some(relative),
                        directory,
                        None,
                        execution,
                    )?
                {
                    return Ok(true);
                }
            }
            Some(PointName::Full(left)) => {
                for left in left {
                    execution
                        .charge_work(1)
                        .map_err(|reason| issuer.resource(reason))?;
                    if names_match::<ENCODED>(left, right, issuer, execution)? {
                        return Ok(true);
                    }
                }
            }
            None => return Ok(true),
        }
    }
    Ok(false)
}

fn names_match<const ENCODED: bool>(
    left: &GeneralName<'_>,
    right: &GeneralName<'_>,
    source: &Name<'_>,
    execution: &impl Work,
) -> Result<bool> {
    if !ENCODED {
        return crate::general_name::matches_at(
            left,
            right,
            execution,
            source.offset(),
            source.field(),
        );
    }
    let (left, right) = match (left, right) {
        (GeneralName::Directory(left), GeneralName::Directory(right)) => {
            return name::matches_composed::<ENCODED>(left, None, right, None, execution);
        }
        (GeneralName::Uri(left), GeneralName::Uri(right))
        | (GeneralName::Dns(left), GeneralName::Dns(right))
        | (GeneralName::Email(left), GeneralName::Email(right)) => {
            (left.as_bytes(), right.as_bytes())
        }
        (GeneralName::X400(left), GeneralName::X400(right))
        | (GeneralName::EdiParty(left), GeneralName::EdiParty(right))
        | (GeneralName::IpAddress(left), GeneralName::IpAddress(right)) => (*left, *right),
        (GeneralName::RegisteredId(left), GeneralName::RegisteredId(right)) => {
            (left.as_bytes(), right.as_bytes())
        }
        (
            GeneralName::Other {
                type_id: left_kind,
                value: left,
            },
            GeneralName::Other {
                type_id: right_kind,
                value: right,
            },
        ) => {
            let work = (left_kind.as_bytes().len().max(right_kind.as_bytes().len()) as u64)
                .checked_mul(2)
                .ok_or_else(|| {
                    source.resource(structured_asn1::memory::MemoryError::WorkExceeded)
                })?;
            execution
                .charge_work(work)
                .map_err(|reason| source.resource(reason))?;
            if left_kind != right_kind {
                return Ok(false);
            }
            (*left, *right)
        }
        _ => return Ok(false),
    };
    let work = (left.len().max(right.len()) as u64)
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| source.resource(structured_asn1::memory::MemoryError::WorkExceeded))?;
    execution
        .charge_work(work)
        .map_err(|reason| source.resource(reason))?;
    Ok(left == right)
}

/// Which certificate category an issuing distribution point covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateKind {
    /// No category restriction was encoded.
    All,
    /// End entity public-key certificates only.
    EndEntity,
    /// Certification authority certificates only.
    Authority,
    /// Attribute certificates only, preserved separately from public-key scope.
    Attribute,
}

/// Parsed CRL scope, without claiming applicability to a target certificate.
#[derive(Debug)]
pub struct IssuingDistributionPoint<'a> {
    name: Option<PointName<'a>>,
    kind: CertificateKind,
    reasons: Option<BitString<'a>>,
    indirect: bool,
}

impl<'a> IssuingDistributionPoint<'a> {
    /// Full distribution-point names, if that alternative was written.
    #[must_use]
    pub fn full_name(&self) -> &[GeneralName<'a>] {
        match &self.name {
            Some(PointName::Full(names)) => names,
            _ => &[],
        }
    }

    /// Relative RDN, if that alternative was written.
    #[must_use]
    pub fn name_relative_to_issuer(&self) -> Option<&RelativeName<'a>> {
        match &self.name {
            Some(PointName::Relative(name)) => Some(name),
            _ => None,
        }
    }

    /// Category restriction; it does not classify any supplied certificate.
    #[must_use]
    pub fn certificate_kind(&self) -> CertificateKind {
        self.kind
    }

    /// Encoded `ReasonFlags`. Absent means all reasons, not an empty mask.
    #[must_use]
    pub fn reasons(&self) -> Option<BitString<'a>> {
        self.reasons
    }

    /// Whether entries may belong to issuers other than this CRL's issuer.
    #[must_use]
    pub fn is_indirect(&self) -> bool {
        self.indirect
    }

    /// Decode through the extension's original parser with current execution.
    pub fn read<W: Work + 'a>(extension: &Extension<'a>, execution: &W) -> Result<Self> {
        const FIELD: &str = "extensions.issuingDistributionPoint";
        let fail = |code, at| Error::new(code, FIELD, at);
        let mut reader = extension::sequence(extension, FIELD, execution)?;
        let mut result = Self {
            name: None,
            kind: CertificateKind::All,
            reasons: None,
            indirect: false,
        };
        let mut last = None;
        while let Some(element) = reader.next_element().field(FIELD)? {
            let (number, constructed) = extension::context_of(element.tag())
                .ok_or_else(|| fail(ErrorCode::UnexpectedField, element.span().start))?;
            if last.is_some_and(|previous| number <= previous) {
                return Err(fail(ErrorCode::UnexpectedField, element.span().start));
            }
            last = Some(number);
            match (number, constructed) {
                (0, true) => {
                    result.name = Some(access::read_distribution_name(&reader, &element, FIELD)?);
                }
                (3, false) => {
                    let reasons = reader.bit_string(&element).field(FIELD)?;
                    reader.charge(9).field(FIELD)?;
                    // RFC 5280 §5.2.5 references ReasonFlags of §4.2.1.13;
                    // X.690 §11.2.2 trims a DER named bit list to its final one.
                    // https://www.rfc-editor.org/rfc/rfc5280#section-5.2.5
                    if reasons.len() > 9
                        || !(1..=8).any(|bit| reasons.bit(bit))
                        || !reasons.bit(reasons.len() - 1)
                    {
                        return Err(fail(ErrorCode::MalformedValue, element.span().start));
                    }
                    result.reasons = Some(reasons);
                }
                (1 | 2 | 4 | 5, false) => {
                    // These BOOLEANs default to FALSE and DER omits defaults.
                    if !reader.boolean(&element).field(FIELD)? {
                        return Err(fail(ErrorCode::MalformedValue, element.span().start));
                    }
                    if number == 4 {
                        result.indirect = true;
                        continue;
                    }
                    if result.kind != CertificateKind::All {
                        return Err(fail(ErrorCode::MalformedValue, element.span().start));
                    }
                    result.kind = match number {
                        1 => CertificateKind::EndEntity,
                        2 => CertificateKind::Authority,
                        _ => CertificateKind::Attribute,
                    };
                }
                _ => return Err(fail(ErrorCode::UnexpectedField, element.span().start)),
            }
        }
        // RFC 5280 §5.2.5 disallows an entirely empty IDP. Attribute scope is
        // kept as its actual category, never treated as public-key coverage.
        if result.name.is_none()
            && result.kind == CertificateKind::All
            && result.reasons.is_none()
            && !result.indirect
        {
            return Err(fail(ErrorCode::EmptySequence, extension.span().start));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::general_name::GeneralName::{Dns, Email};
    #[test]
    fn dns_and_mailbox_scope_follow_their_separate_case_rules() {
        // RFC5280 §§7.2/7.5 require DNS and mail host case-insensitive
        // identity, while the mailbox local-part remains an exact match.
        let bytes = crate::fixtures::CertificateParts::default().build();
        let parser = structured_asn1::Parser::der(crate::fixtures::memory());
        let source = crate::Certificate::read(&parser, &bytes, 100).unwrap();
        let execution = crate::fixtures::memory();
        for (left, right, expected) in [
            (Dns("EXAMPLE.com"), Dns("example.COM"), true),
            (Email("user@EXAMPLE.com"), Email("user@example.COM"), true),
            (Email("User@example.com"), Email("user@example.com"), false),
            (
                Email("\"a@b\"@EXAMPLE.com"),
                Email("\"a@b\"@example.com"),
                true,
            ),
        ] {
            assert_eq!(
                super::names_match::<false>(&left, &right, source.tbs().issuer(), &execution)
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn uri_scope_compares_normalized_identity_without_folding_path_or_query() {
        // RFC5280 §7.4 requires scheme/host case, percent, path-segment
        // and recognized scheme normalization before exact comparison.
        let bytes = crate::fixtures::CertificateParts::default().build();
        let parser = structured_asn1::Parser::der(crate::fixtures::memory());
        let source = crate::Certificate::read(&parser, &bytes, 100).unwrap();
        let execution = crate::fixtures::memory();
        for (left, right, expected) in [
            (
                "HTTP://Example.com:080/a/../%7e",
                "http://example.com/~",
                true,
            ),
            ("https://example.com:443", "https://example.com/", true),
            (
                "ldap://example.com/",
                "ldap://EXAMPLE.com:389/??BASE?(objectClass=*)",
                true,
            ),
            ("ftp://example.com:21", "ftp://example.com/", true),
            (
                "http://example.com/A?q=A",
                "http://example.com/a?q=A",
                false,
            ),
            (
                "http://example.com/a?q=A",
                "http://example.com/a?q=a",
                false,
            ),
            ("http://example.com/%2f", "http://example.com//", false),
            ("http://example.com/?", "http://example.com/", false),
            (
                "ftp://example.com/a;type=a",
                "ftp://example.com/a;type=i",
                false,
            ),
        ] {
            assert_eq!(
                super::names_match::<false>(
                    &crate::general_name::GeneralName::Uri(left),
                    &crate::general_name::GeneralName::Uri(right),
                    source.tbs().issuer(),
                    &execution
                )
                .unwrap(),
                expected,
                "{left} versus {right}"
            );
        }
    }
}
