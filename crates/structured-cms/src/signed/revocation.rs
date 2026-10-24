//! First-read CMS revocation choices shared by enclosing signature formats.

use super::OtherRevocationInfo;
use structured_asn1::{Element, Oid, Reader, Tag, universal};
use structured_pkix::{crl::CertificateList, ocsp::BasicResponse};

/// Actual parsed CMS choice, without authentication or freshness claims.
pub enum Reading<'a> {
    /// Whole original `CertificateList`, including complete/delta distinction.
    Crl(CertificateList<'a>),
    /// Basic body from the successful whole RFC5940 `OCSPResponse` choice.
    Ocsp(BasicResponse<'a>),
    /// Original open or unsupported inner response syntax. The caller retains
    /// the original complete choice; this is never a fabricated basic body.
    Open {
        /// Actual parsed other-revocation format identifier.
        format: Oid<'a>,
    },
}

/// Original schema/encoding versus certificate/status refusal.
#[derive(Debug)]
pub enum Error {
    /// Original CMS other-format syntax or successful-response constraint.
    Cms(crate::Error),
    /// Original CRL/basic-response syntax or resource/producing-reader failure.
    Pkix(structured_pkix::Error),
}
impl Error {
    /// Resource and caller/source failures cannot become document findings.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Cms(cause) => cause.is_terminal(),
            Self::Pkix(cause) => {
                cause.is_resource() || cause.code() == structured_pkix::ErrorCode::ForeignReader
            }
        }
    }
}

/// Reads an original root/TSA/PoE choice through the SAME CRL and RFC5940
/// kernels. No new Parser, default budget, encoded wrapper or crypto is used.
/// `parent` must be the original located reader under the active operation,
/// such as the one returned by `SignedData::revocation_reader_in`.
pub fn read<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<Reading<'a>, Error> {
    if element.tag() == Tag::constructed(universal::SEQUENCE) {
        return CertificateList::read_element(parent, element)
            .map(Reading::Crl)
            .map_err(Error::Pkix);
    }
    let other = OtherRevocationInfo::read(parent, element).map_err(Error::Cms)?;
    let format = other.kind();
    let Some(response) = other.ocsp().map_err(Error::Cms)? else {
        return Ok(Reading::Open { format });
    };
    let Some(value) = response.basic_in(parent).map_err(Error::Pkix)? else {
        return Ok(Reading::Open { format });
    };
    Ok(Reading::Ocsp(value))
}
