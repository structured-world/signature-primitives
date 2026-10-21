use super::{Check, DigestedObject, IssuerForm, Reason, charge, directory, proxy, refused, target};
use crate::attribute_certificate::AttributeCertificate;
use crate::{Error, Result};
use structured_asn1::memory::Work;
use structured_asn1::{Oid, Tag, universal};
use structured_pkix::access::{DistributionPoints, InfoAccess};
use structured_pkix::general_name::GeneralName;
use structured_pkix::identifier::AuthorityKeyIdentifier;
use structured_pkix::{Extension, oid};

/// `id-pe-ac-auditIdentity`, RFC5755 §4.3.1.
pub const AUDIT_IDENTITY: Oid<'static> = Oid::from_bytes(&[43, 6, 1, 5, 5, 7, 1, 4]);
/// `id-ce-noRevAvail`, RFC5755 §4.3.6.
pub const NO_REV_AVAILABLE: Oid<'static> = Oid::from_bytes(&[85, 29, 56]);

/// The issuer's written revocation scheme, not an authenticated status answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// A well-formed `NoRevAvail` without any contradictory revocation pointer.
    NoRevAvailable,
    /// Revocation checking remains required; absence of a pointer is no exemption.
    Required,
}

/// Static profile facts borrowing the original AC and owning decoded catalogues.
/// A critical extension's effect must still be enforced before using the AC.
#[derive(Debug)]
pub struct Profile<'r, 'a> {
    certificate: &'r AttributeCertificate<'a>,
    audit: Option<&'a [u8]>,
    targets: Option<target::TargetInformation<'a>>,
    proxy: Option<proxy::ProxyInfo<'a>>,
    authority_key: Option<AuthorityKeyIdentifier<'a>>,
    access: Option<InfoAccess<'a>>,
    distribution: Option<DistributionPoints<'a>>,
    revocation: Revocation,
}

impl<'r, 'a> Profile<'r, 'a> {
    fn new(certificate: &'r AttributeCertificate<'a>) -> Self {
        Self {
            certificate,
            audit: None,
            targets: None,
            proxy: None,
            authority_key: None,
            access: None,
            distribution: None,
            revocation: Revocation::Required,
        }
    }
    /// Original AC, including exact signed bytes and unchanged attributes.
    #[must_use]
    pub fn certificate(&self) -> &AttributeCertificate<'a> {
        self.certificate
    }
    /// Opaque original audit identity, for the caller's audit handling (§4.3.1).
    /// Parsing does not establish unlinkability or enforce an audit policy.
    #[must_use]
    pub fn audit_identity(&self) -> Option<&'a [u8]> {
        self.audit
    }
    /// Present targeting is a mandatory effect check, not satisfied by parsing.
    #[must_use]
    pub fn targeting(&self) -> Option<&target::TargetInformation<'a>> {
        self.targets.as_ref()
    }
    /// Present proxying requires the authenticated sender/recipient/hop check.
    #[must_use]
    pub fn proxying(&self) -> Option<&proxy::ProxyInfo<'a>> {
        self.proxy.as_ref()
    }
    /// Original authority key assertion, not proof that a supplied key belongs to it.
    #[must_use]
    pub fn authority_key(&self) -> Option<&AuthorityKeyIdentifier<'a>> {
        self.authority_key.as_ref()
    }
    /// Original unresolved access locations; no acquisition occurred.
    #[must_use]
    pub fn access(&self) -> Option<&InfoAccess<'a>> {
        self.access.as_ref()
    }
    /// Original unresolved single distribution point, if present.
    #[must_use]
    pub fn distribution(&self) -> Option<&DistributionPoints<'a>> {
        self.distribution.as_ref()
    }
    /// Written revocation scheme. Required never means a successful status check.
    #[must_use]
    pub fn revocation(&self) -> Revocation {
        self.revocation
    }
    /// Number of written Holder alternatives, for explicit protocol selection.
    /// Zero cannot authenticate a holder; several are not silently prioritized.
    #[must_use]
    pub fn holder_alternatives(&self) -> u8 {
        let holder = &self.certificate.information().holder;
        u8::from(holder.base_certificate.is_some())
            + u8::from(holder.entity_names.is_some())
            + u8::from(holder.object_digest.is_some())
    }
}

fn url(text: &str, schemes: &[&[u8]]) -> bool {
    // GeneralName has already applied the shared absolute URI grammar. This
    // only enforces RFC5755 §§4.3.4/4.3.5's schemes. HTTP needs a host;
    // LDAP may omit its server (RFC4516 §2), with DN/CRL attributes already
    // enforced by the shared DistributionPoints location decoder.
    // <https://www.rfc-editor.org/rfc/rfc4516#section-2>
    let bytes = text.as_bytes();
    for scheme in schemes {
        if bytes.len() > scheme.len()
            && bytes[..scheme.len()].eq_ignore_ascii_case(scheme)
            && (*scheme == b"ldap://" || !matches!(bytes[scheme.len()], b'/' | b'?' | b'#'))
        {
            return true;
        }
    }
    false
}

fn critical<T>(extension: &Extension<'_>, expected: bool) -> Option<Check<T>> {
    (extension.is_critical() != expected).then(|| refused(Reason::Criticality, extension.span()))
}

fn check_fields<W: Work>(ac: &AttributeCertificate<'_>, work: &W) -> Result<Check<()>> {
    let at = ac.signed_element().span();
    let info = ac.information();
    charge(work, info.serial.as_bytes().len() as u64 + 8, at.start)?;
    // RFC5755 §§4.2.3/4.2.5/4.2.6. These are profile checks, while
    // readability and exact signature inputs remain available on the AC.
    // <https://www.rfc-editor.org/rfc/rfc5755#section-4.2>
    if info.issuer.form != IssuerForm::V2
        || info.issuer.base_certificate.is_some()
        || info.issuer.object_digest.is_some()
        || info.issuer.names.as_deref().and_then(directory).is_none()
    {
        return Ok(refused(Reason::IssuerForm, at));
    }
    if info.serial.is_negative()
        || info.serial.as_bytes().len() > 20
        || info.serial.as_bytes().iter().all(|b| *b == 0)
    {
        return Ok(refused(Reason::Serial, at));
    }
    if info.not_before > info.not_after {
        return Ok(refused(Reason::Validity, at));
    }
    if let Some(base) = &info.holder.base_certificate
        && directory(&base.issuer).is_none()
    {
        return Ok(refused(Reason::HolderIssuer, at));
    }
    if let Some(digest) = &info.holder.object_digest
        && (digest.object_type == DigestedObject::Other || digest.other_type.is_some())
    {
        return Ok(refused(Reason::ObjectDigest, at));
    }
    Ok(Check::Accepted(()))
}

fn read_audit<'a>(extension: &Extension<'a>, work: &impl Work) -> Result<Check<&'a [u8]>> {
    let mut reader = extension
        .reader_scoped(work)
        .map_err(|e| Error::encoding(e, super::FIELD))?;
    let value = reader
        .expect(Tag::primitive(universal::OCTET_STRING))
        .map_err(|e| Error::encoding(e, super::FIELD))?;
    super::super::end(&reader, super::FIELD)?;
    if value.contents().is_empty() || value.contents().len() > 20 {
        return Ok(refused(Reason::AuditIdentity, value.span()));
    }
    Ok(Check::Accepted(value.contents()))
}

fn read_access<'a>(
    extension: &Extension<'a>,
    work: &impl Work,
) -> Result<Check<(InfoAccess<'a>, bool)>> {
    let at = extension.span();
    let access = InfoAccess::read(extension, work).map_err(Error::pkix)?;
    let mut pointer = false;
    for entry in access.descriptions() {
        charge(work, entry.method().as_bytes().len() as u64 + 1, at.start)?;
        if entry.method() == oid::OCSP {
            let GeneralName::Uri(uri) = entry.location() else {
                return Ok(refused(Reason::OcspLocation, at));
            };
            charge(work, 8, at.start)?;
            if !url(uri, &[b"http://"]) {
                return Ok(refused(Reason::OcspLocation, at));
            }
            pointer = true;
        }
    }
    Ok(Check::Accepted((access, pointer)))
}

fn read_distribution<'a>(
    extension: &Extension<'a>,
    work: &impl Work,
) -> Result<Check<DistributionPoints<'a>>> {
    let at = extension.span();
    let points = DistributionPoints::read(extension, work).map_err(Error::pkix)?;
    let [point] = points.points() else {
        return Ok(refused(Reason::DistributionPoint, at));
    };
    let valid = match point.full_name() {
        [GeneralName::Directory(name)] => !name.is_empty(),
        [GeneralName::Uri(uri)] => {
            charge(work, 16, at.start)?;
            url(uri, &[b"http://", b"ldap://"])
        }
        _ => false,
    };
    if !valid || point.name_relative_to_issuer().is_some() {
        return Ok(refused(Reason::DistributionPoint, at));
    }
    Ok(Check::Accepted(points))
}

fn read_no_revocation(extension: &Extension<'_>, work: &impl Work) -> Result<()> {
    let mut reader = extension
        .reader_scoped(work)
        .map_err(|e| Error::encoding(e, super::FIELD))?;
    let value = reader
        .expect(Tag::primitive(universal::NULL))
        .map_err(|e| Error::encoding(e, super::FIELD))?;
    reader
        .null(&value)
        .map_err(|e| Error::encoding(e, super::FIELD))?;
    super::super::end(&reader, super::FIELD)
}

pub(super) fn check<'r, 'a, W: Work>(
    ac: &'r AttributeCertificate<'a>,
    work: &W,
) -> Result<Check<Profile<'r, 'a>>> {
    let execution = work.execution_for(ac.parser);
    if let Check::Rejected(reason) = check_fields(ac, &execution)? {
        return Ok(Check::Rejected(reason));
    }
    let info = ac.information();
    let at = ac.signed_element().span();
    let mut facts = Profile::new(ac);
    let Some(extensions) = &info.extensions else {
        return Ok(Check::Accepted(facts));
    };
    let mut pointer = false;
    for extension in extensions.iter(&execution) {
        let extension = extension.map_err(Error::pkix)?;
        let at = extension.span();
        // Bound the fixed dispatch's OID scans before any equality test.
        charge(
            &execution,
            extension.kind().as_bytes().len() as u64 * 8 + 8,
            at.start,
        )?;
        match extension.kind() {
            kind if kind == AUDIT_IDENTITY => {
                if let Some(failure) = critical(extension, true) {
                    return Ok(failure);
                }
                facts.audit = Some(match read_audit(extension, &execution)? {
                    Check::Accepted(value) => value,
                    Check::Rejected(reason) => return Ok(Check::Rejected(reason)),
                });
            }
            kind if kind == target::IDENTIFIER => {
                if let Some(failure) = critical(extension, true) {
                    return Ok(failure);
                }
                let targets = target::TargetInformation::read(extension, &execution)?;
                if let Some(forbidden) = targets.certificates().first() {
                    return Ok(refused(Reason::TargetCertificate, forbidden.element.span()));
                }
                facts.targets = Some(targets);
            }
            kind if kind == proxy::IDENTIFIER => {
                if let Some(failure) = critical(extension, true) {
                    return Ok(failure);
                }
                let proxy = proxy::ProxyInfo::read(extension, &execution)?;
                if let Some(forbidden) = proxy.certificates().first() {
                    return Ok(refused(Reason::TargetCertificate, forbidden.element.span()));
                }
                facts.proxy = Some(proxy);
            }
            kind if kind == oid::AUTHORITY_KEY_IDENTIFIER => {
                if let Some(failure) = critical(extension, false) {
                    return Ok(failure);
                }
                let key =
                    AuthorityKeyIdentifier::read(extension, &execution).map_err(Error::pkix)?;
                // RFC5280 §4.2.1.1, incorporated by RFC5755 §4.3.3.
                if key.key_id().is_none() {
                    return Ok(refused(Reason::AuthorityKeyIdentifier, at));
                }
                facts.authority_key = Some(key);
            }
            kind if kind == oid::AUTHORITY_INFO_ACCESS => {
                if let Some(failure) = critical(extension, false) {
                    return Ok(failure);
                }
                let (access, has_pointer) = match read_access(extension, &execution)? {
                    Check::Accepted(value) => value,
                    Check::Rejected(reason) => return Ok(Check::Rejected(reason)),
                };
                pointer |= has_pointer;
                facts.access = Some(access);
            }
            kind if kind == oid::CRL_DISTRIBUTION_POINTS => {
                if let Some(failure) = critical(extension, false) {
                    return Ok(failure);
                }
                facts.distribution = Some(match read_distribution(extension, &execution)? {
                    Check::Accepted(value) => value,
                    Check::Rejected(reason) => return Ok(Check::Rejected(reason)),
                });
                pointer = true;
            }
            kind if kind == NO_REV_AVAILABLE => {
                if let Some(failure) = critical(extension, false) {
                    return Ok(failure);
                }
                read_no_revocation(extension, &execution)?;
                facts.revocation = Revocation::NoRevAvailable;
            }
            _ if extension.is_critical() => {
                return Ok(refused(Reason::UnknownCritical, at));
            }
            _ => {}
        }
    }
    // §6 forbids NoRevAvail together with a revocation pointer, in either order.
    if pointer && facts.revocation == Revocation::NoRevAvailable {
        return Ok(refused(Reason::RevocationConflict, at));
    }
    Ok(Check::Accepted(facts))
}
