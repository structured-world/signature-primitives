//! TSA certificate restrictions, distinct from signature/path/trust results.

use super::TokenInfo;
use crate::{Error, ErrorCode};
use structured_asn1::{Reader, Tag, memory::Work, universal};
use structured_pkix::{
    Certificate,
    general_name::{self, GeneralName},
    oid,
    usage::ExtendedKeyUsage,
};

/// Source in whose original coordinates a refusal is located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthoritySource {
    /// Original `TSTInfo` source, which may have a composed logical source map.
    Token,
    /// Original certificate source and its independently retained provenance.
    Certificate,
}

/// Execution refusal, never a negative TSA identity or usage answer.
#[derive(Debug)]
pub struct AuthorityError {
    /// Original source role, including independently parsed certificate input.
    pub source: AuthoritySource,
    /// Original common processing/resource cause.
    pub cause: Error,
}

/// RFC3161 §2.3 requires exclusive critical timestamping EKU.
#[derive(Debug)]
pub enum TsaUsage {
    /// The critical extension admits timestamping and nothing else.
    TimeStampingOnly,
    /// No EKU was written.
    Missing,
    /// The written EKU is not critical.
    NotCritical,
    /// The purposes do not exclusively admit timestamping.
    OtherPurposes,
    /// The certificate's original lazy extension cannot be interpreted.
    Unreadable(Error),
}

/// Optional TSA subject-name agreement, without a trust assertion.
#[derive(Debug)]
pub enum TsaIdentity {
    /// The optional name was absent, not a mandatory-field failure.
    Absent,
    /// A shared subject/SAN comparison matched, with the whole SAN readable.
    Matches,
    /// No subject/SAN value matched.
    Differs,
    /// Inspection retained an unreadable present TSA name.
    Unreadable,
    /// Original certificate SAN syntax prevents an identity answer.
    CertificateUnreadable(Error),
}

/// Independent usage/name facts; neither proves certificate trust or signature.
#[derive(Debug)]
pub struct AuthorityFacts {
    /// Certificate purpose restriction.
    pub usage: TsaUsage,
    /// Token name binding when one was supplied.
    pub identity: TsaIdentity,
}

impl TokenInfo<'_> {
    /// Checks two original sources without rebuilding or selecting a trust path.
    ///
    /// RFC3161 §§2.3/2.4.2 require exclusive critical EKU and correspondence to
    /// a certificate subject name. The supplied certificate must separately be
    /// selected, signature-verified and trusted by the caller's common CMS/PKIX
    /// checks. Lookup/comparison use token query work; lazy certificate values
    /// retain their own producing session/depth and its current execution.
    /// <https://www.rfc-editor.org/rfc/rfc3161.html#section-2.3>
    pub fn authority(
        &self,
        certificate: &Certificate<'_>,
        token_parent: &Reader<'_>,
        certificate_parent: &Reader<'_>,
    ) -> Result<AuthorityFacts, AuthorityError> {
        self.imprint()
            .require_session(token_parent)
            .map_err(token_error)?;
        if !certificate
            .tbs()
            .public_key()
            .algorithm()
            .same_session(certificate_parent)
        {
            return Err(cert_error(Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                "certificate",
                certificate.span().start,
            ))));
        }
        Ok(AuthorityFacts {
            usage: usage(certificate, token_parent)?,
            identity: identity(self, certificate, token_parent)?,
        })
    }
}

fn token_error(cause: Error) -> AuthorityError {
    AuthorityError {
        source: AuthoritySource::Token,
        cause,
    }
}
fn cert_error(cause: Error) -> AuthorityError {
    AuthorityError {
        source: AuthoritySource::Certificate,
        cause,
    }
}

fn usage(certificate: &Certificate<'_>, query: &Reader<'_>) -> Result<TsaUsage, AuthorityError> {
    let Some(extension) = certificate
        .tbs()
        .extensions()
        .get(oid::EXT_KEY_USAGE, &query.execution())
        .map_err(Error::pkix)
        .map_err(cert_error)?
    else {
        return Ok(TsaUsage::Missing);
    };
    if !extension.is_critical() {
        return Ok(TsaUsage::NotCritical);
    }
    let purposes = match ExtendedKeyUsage::read_in(extension, query).map_err(Error::pkix) {
        Ok(purposes) => purposes,
        Err(error) if error.is_terminal() => return Err(cert_error(error)),
        Err(error) => return Ok(TsaUsage::Unreadable(error)),
    };
    if purposes.purposes().len() != 1 {
        return Ok(TsaUsage::OtherPurposes);
    }
    query
        .execution()
        .charge_work(1 + purposes.purposes()[0].as_bytes().len() as u64)
        .map_err(|reason| {
            cert_error(Error::resource(
                reason,
                "extensions.extKeyUsage",
                extension.span().start,
            ))
        })?;
    Ok(if purposes.purposes()[0] == oid::TIME_STAMPING {
        TsaUsage::TimeStampingOnly
    } else {
        TsaUsage::OtherPurposes
    })
}

fn identity(
    info: &TokenInfo<'_>,
    certificate: &Certificate<'_>,
    query: &Reader<'_>,
) -> Result<TsaIdentity, AuthorityError> {
    let Some(tsa) = info.tsa() else {
        return Ok(TsaIdentity::Absent);
    };
    let Some(name) = tsa.name() else {
        return Ok(TsaIdentity::Unreadable);
    };
    if let GeneralName::Directory(name) = name
        && name
            .matches_in(certificate.tbs().subject(), query)
            .map_err(|cause| {
                Error::pkix(structured_pkix::Error::new(
                    cause.code(),
                    "tstInfo.tsa",
                    tsa.span().start,
                ))
            })
            .map_err(token_error)?
    {
        return Ok(TsaIdentity::Matches);
    }
    let Some(extension) = certificate
        .tbs()
        .extensions()
        .get(oid::SUBJECT_ALT_NAME, &query.execution())
        .map_err(Error::pkix)
        .map_err(cert_error)?
    else {
        return Ok(TsaIdentity::Differs);
    };
    match san_matches(extension, name, tsa.span().start, query) {
        Ok(true) => Ok(TsaIdentity::Matches),
        Ok(false) => Ok(TsaIdentity::Differs),
        // The comparer deliberately locates its operation at the token's TSA
        // field; certificate decoding failures retain their certificate field.
        Err(error) if error.field() == "tstInfo.tsa" => Err(token_error(error)),
        Err(error) if error.is_terminal() => Err(cert_error(error)),
        Err(error) => Ok(TsaIdentity::CertificateUnreadable(error)),
    }
}

fn san_matches(
    extension: &structured_pkix::Extension<'_>,
    name: &GeneralName<'_>,
    at: u64,
    query: &Reader<'_>,
) -> crate::Result<bool> {
    const FIELD: &str = "extensions.subjectAltName";
    let mut reader = extension
        .reader_in(query)
        .map_err(|source| Error::encoding(source, FIELD))?;
    let sequence = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .map_err(|source| Error::encoding(source, FIELD))?;
    if !reader.is_empty() {
        return Err(Error::schema(
            ErrorCode::TrailingData,
            FIELD,
            reader.offset(),
        ));
    }
    let mut inside = reader
        .enter(&sequence)
        .map_err(|source| Error::encoding(source, FIELD))?;
    let mut matched = false;
    while let Some(element) = inside
        .next_element()
        .map_err(|source| Error::encoding(source, FIELD))?
    {
        let alternative = general_name::read(&inside, &element, FIELD).map_err(Error::pkix)?;
        if !matched
            && general_name::matches(query, name, &alternative, at, "tstInfo.tsa")
                .map_err(Error::pkix)?
        {
            matched = true;
        }
    }
    Ok(matched)
}
