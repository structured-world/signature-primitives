//! RFC5755 profile and supplied-certificate checks, without an authorization verdict.
//!
//! Signature arithmetic, authenticated certificate paths and holder identity,
//! explicit AA trust, evaluation time, targeting/proxy effects, and revocation
//! remain separate obligations (RFC5755 §5). A parsed critical extension is
//! not, by itself, an enforced critical extension.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-5>

use super::{AttributeCertificate, DigestedObject, IssuerForm, proxy, target};
use crate::{Error, Result};
use structured_asn1::memory::Work;
use structured_asn1::{BitString, Span};
use structured_pkix::general_name::{self, GeneralName};
use structured_pkix::{Certificate, Name};

pub mod aa_path;
mod profile;
pub use profile::{AUDIT_IDENTITY, NO_REV_AVAILABLE, Profile, Revocation};

const FIELD: &str = "attributeCertificate.validation";

/// A completed check or a located semantic refusal. Execution failures use Result.
#[derive(Debug)]
pub enum Check<T> {
    /// The named check completed; other validation obligations are independent.
    Accepted(T),
    /// A completed comparison/profile check found a contradiction.
    Rejected(Rejection),
}

/// Original source of a completed profile or binding refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection {
    /// Why this particular check refused.
    pub reason: Reason,
    /// The real enclosing original field; None for an empty caller path with
    /// no document source. Never a fabricated parameter offset.
    pub source: Option<Span>,
}

/// A semantic refusal, never a substitute for resource or decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// Issuer is not V2 with exactly one nonempty directoryName and no other forms.
    IssuerForm,
    /// Serial is zero, negative, or exceeds the twenty encoded octet limit.
    Serial,
    /// The inclusive validity interval is reversed.
    Validity,
    /// A holder baseCertificateID has an out-of-profile issuer name.
    HolderIssuer,
    /// Optional objectDigestInfo names a forbidden object/type combination.
    ObjectDigest,
    /// Criticality contradicts the extension's profile.
    Criticality,
    /// An unrecognized critical extension cannot be accepted by this profile.
    UnknownCritical,
    /// Audit identity is outside the one-through-twenty octet range.
    AuditIdentity,
    /// A forbidden targetCert alternative was written.
    TargetCertificate,
    /// The issuer key identifier required by the PKIX profile is absent.
    AuthorityKeyIdentifier,
    /// An OCSP access location is not an HTTP URL.
    OcspLocation,
    /// CRL distribution points do not have the single fullName/profile form.
    DistributionPoint,
    /// `NoRevAvail` contradicts a written OCSP/CRL revocation pointer.
    RevocationConflict,
    /// Explicitly selected Holder alternative is absent.
    HolderAbsent,
    /// Supplied certificate's issuer or serial does not match the base identity.
    HolderCertificate,
    /// None of the written entity names identifies the supplied certificate.
    HolderName,
    /// A present holder issuerUID is absent/different in the supplied PKC.
    HolderUniqueId,
    /// AC issuer DN does not identify the supplied authority certificate.
    AuthorityName,
    /// AC issuer UID does not agree with the authority's subject UID.
    AuthorityUniqueId,
    /// An AC authority cannot also be a certificate authority.
    AuthorityIsCa,
    /// Present keyUsage permits neither digitalSignature nor contentCommitment.
    AuthorityUsage,
    /// A supplied AA path is empty.
    EmptyPath,
    /// A certificate below the explicitly selected AA CA lacks `AAControls`.
    MissingControls,
    /// `AAControls` pathLenConstraint is smaller than the actual distance.
    ControlDistance,
}

fn refused<T>(reason: Reason, source: Span) -> Check<T> {
    Check::Rejected(Rejection {
        reason,
        source: Some(source),
    })
}

pub(super) fn charge(work: &impl Work, amount: u64, at: u64) -> Result<()> {
    work.charge_work(amount)
        .map_err(|e| Error::resource(e, FIELD, at))
}

fn same_bits(left: BitString<'_>, right: BitString<'_>, work: &impl Work, at: u64) -> Result<bool> {
    charge(work, 1, at)?;
    if left.len() != right.len() {
        return Ok(false);
    }
    charge(work, left.as_bytes().len() as u64, at)?;
    Ok(left.as_bytes() == right.as_bytes())
}

fn directory<'n, 'a>(names: &'n [GeneralName<'a>]) -> Option<&'n Name<'a>> {
    match names {
        [GeneralName::Directory(name)] if !name.is_empty() => Some(name),
        _ => None,
    }
}

/// A Holder alternative explicitly chosen by the authenticating protocol.
/// No fallback or precedence is inferred when several alternatives are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderMethod {
    /// RFC5755 §4.2.2: issuer DN, complete serial and optional issuer UID.
    BaseCertificate,
    /// RFC5755 §4.2.2: subject DN or a subjectAltName of the authenticated PKC.
    EntityName,
}

impl<'a> AttributeCertificate<'a> {
    /// Check static profile rules and decode all recognized extension values.
    ///
    /// All fields remain inspectable through `information()` on refusal. The
    /// accepted facts retain targeting/proxy obligations; they are not evidence
    /// that those effects, signatures, trust, time or revocation were checked.
    pub fn profile<W: Work>(&self, work: &W) -> Result<Check<Profile<'_, 'a>>> {
        profile::check(self, work)
    }

    /// Bind one explicitly chosen Holder method to a supplied authenticated PKC.
    ///
    /// This checks identity only: it does not authenticate the PKC or select
    /// which Holder method the surrounding protocol trusts. Optional
    /// objectDigestInfo is not silently treated as an entityName or a base ID.
    /// RFC5755 §4.2.2: <https://www.rfc-editor.org/rfc/rfc5755#section-4.2.2>
    pub fn bind_holder<W: Work>(
        &self,
        certificate: &Certificate<'_>,
        method: HolderMethod,
        work: &W,
    ) -> Result<Check<()>> {
        let execution = work.execution_for(self.parser);
        let at = self.signed.span();
        charge(&execution, 1, at.start)?;
        let certificate_execution = certificate.execution_in(&execution);
        charge(&certificate_execution, 1, certificate.span().start)?;
        match method {
            HolderMethod::BaseCertificate => {
                let Some(base) = &self.information.holder.base_certificate else {
                    return Ok(refused(Reason::HolderAbsent, at));
                };
                let Some(name) = directory(&base.issuer) else {
                    return Ok(refused(Reason::HolderIssuer, at));
                };
                let left = base.serial.as_bytes();
                let right = certificate.tbs().serial().as_bytes();
                charge(&execution, left.len() as u64 + 1, at.start)?;
                charge(
                    &certificate_execution,
                    right.len() as u64 + 1,
                    certificate.span().start,
                )?;
                // Both objects came from DER readers, so minimal INTEGER
                // encodings preserve arbitrary-width numeric identity.
                if left != right
                    || !name
                        .matches(certificate.tbs().issuer(), &certificate_execution)
                        .map_err(Error::pkix)?
                {
                    return Ok(refused(Reason::HolderCertificate, at));
                }
                if let Some(uid) = base.issuer_uid {
                    let Some(other) = certificate.tbs().issuer_unique_id() else {
                        return Ok(refused(Reason::HolderUniqueId, at));
                    };
                    if !same_bits(uid, other, &certificate_execution, at.start)? {
                        return Ok(refused(Reason::HolderUniqueId, at));
                    }
                }
            }
            HolderMethod::EntityName => {
                let Some(names) = &self.information.holder.entity_names else {
                    return Ok(refused(Reason::HolderAbsent, at));
                };
                // §4.2.2 permits subject OR SAN identity. A matching subject
                // needs no SAN parsing/storage; certificate profile/path
                // validation is independent of this identity-only operation.
                for name in names {
                    charge(&execution, 1, at.start)?;
                    if let GeneralName::Directory(name) = name
                        && !name.is_empty()
                        && name
                            .matches(certificate.tbs().subject(), &certificate_execution)
                            .map_err(Error::pkix)?
                    {
                        return Ok(Check::Accepted(()));
                    }
                }
                let Some(sans) = certificate
                    .tbs()
                    .extensions()
                    .subject_alt_name(&certificate_execution)
                    .map_err(Error::pkix)?
                else {
                    return Ok(refused(Reason::HolderName, at));
                };
                for name in names {
                    charge(&execution, 1, at.start)?;
                    for alternative in &sans {
                        charge(&certificate_execution, 1, at.start)?;
                        if general_name::matches_at(
                            name,
                            alternative,
                            &certificate_execution,
                            at.start,
                            FIELD,
                        )
                        .map_err(Error::pkix)?
                        {
                            return Ok(Check::Accepted(()));
                        }
                    }
                }
                return Ok(refused(Reason::HolderName, at));
            }
        }
        Ok(Check::Accepted(()))
    }

    /// Bind issuer DN/UID and check the authority PKC's AA-specific purpose.
    ///
    /// RFC5755 §§4.2.3/4.2.8/4.5 require a non-CA authority permitted to sign
    /// data (digitalSignature or contentCommitment). The AC issuerUID identifies
    /// that authority itself, hence compares with its subjectUniqueID, whereas
    /// Holder.baseCertificateID.issuerUID
    /// identifies the holder PKC's issuer. The original authority's path,
    /// effective key, algorithm agreement and AC signature still need checking.
    /// <https://www.rfc-editor.org/rfc/rfc5755#section-4.2.8>
    pub fn bind_authority<W: Work>(
        &self,
        authority: &Certificate<'_>,
        work: &W,
    ) -> Result<Check<()>> {
        let execution = work.execution_for(self.parser);
        let at = self.signed.span();
        charge(&execution, 1, at.start)?;
        let authority_execution = authority.execution_in(&execution);
        charge(&authority_execution, 1, authority.span().start)?;
        let issuer = &self.information.issuer;
        if issuer.form != IssuerForm::V2
            || issuer.base_certificate.is_some()
            || issuer.object_digest.is_some()
        {
            return Ok(refused(Reason::IssuerForm, at));
        }
        let Some(name) = issuer.names.as_deref().and_then(directory) else {
            return Ok(refused(Reason::IssuerForm, at));
        };
        if !name
            .matches(authority.tbs().subject(), &authority_execution)
            .map_err(Error::pkix)?
        {
            return Ok(refused(Reason::AuthorityName, at));
        }
        match (
            self.information.issuer_uid,
            authority.tbs().subject_unique_id(),
        ) {
            (None, None) => {}
            (Some(left), Some(right))
                if same_bits(left, right, &authority_execution, at.start)? => {}
            _ => return Ok(refused(Reason::AuthorityUniqueId, at)),
        }
        let extensions = authority.tbs().extensions();
        if extensions
            .basic_constraints(&authority_execution)
            .map_err(Error::pkix)?
            .is_some_and(structured_pkix::constraints::BasicConstraints::is_authority)
        {
            return Ok(refused(Reason::AuthorityIsCa, authority.span()));
        }
        // RFC5755 §4.5 forbids a KU explicitly denying signature use, rather
        // than mandating just bit 0. RFC5280 §4.2.1.3 assigns bit 1 to digital
        // signatures as well, for content commitment. Both uses are accepted.
        // <https://www.rfc-editor.org/rfc/rfc5755#section-4.5>
        if extensions
            .key_usage(&authority_execution)
            .map_err(Error::pkix)?
            .is_some_and(|value| !value.digital_signature() && !value.content_commitment())
        {
            return Ok(refused(Reason::AuthorityUsage, authority.span()));
        }
        Ok(Check::Accepted(()))
    }
}
