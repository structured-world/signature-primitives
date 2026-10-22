//! Applicable assertions are selected without discarding duplicate evidence.

use super::{BasicResponse, CertId, CertMatch, SignedResponse, SingleResponse};
use crate::algorithm::digest::AsnDigest;
use crate::error::{CallbackResult, Error};
use crate::{Certificate, revocation::RevocationTarget};
use structured_asn1::memory::Work;

/// Identity lookup within an authenticated response, not a complete verdict.
#[derive(Debug, Clone, Copy)]
pub enum Lookup<'r, 'a> {
    /// No assertion matches the target and actual issuer.
    Missing,
    /// One matching original assertion. Time/extensions/authorization still
    /// have to be checked before interpreting its revocation status.
    Found(&'r SingleResponse<'a>),
    /// Multiple matching assertions are retained, including identical repeats.
    /// Selection must not silently pick first or last.
    Ambiguous {
        /// First matching assertion in wire order.
        first: &'r SingleResponse<'a>,
        /// Next matching assertion in wire order.
        second: &'r SingleResponse<'a>,
    },
    /// A candidate identity uses a hash capability unavailable to this caller.
    UnsupportedHash(&'r SingleResponse<'a>),
    /// Known fixed-output hash width contradicts the original `CertID` bytes.
    MalformedHashWidth(&'r SingleResponse<'a>),
    /// A candidate's hash identifier writes parameters its algorithm does not take.
    MalformedHashAlgorithm(&'r SingleResponse<'a>),
}

impl<'r, 'a> SignedResponse<'r, 'a> {
    /// Locate the target's assertion using actual target/issuer bytes and the
    /// selected provider. RFC6960 §3.2(1) requires binding to the requested
    /// certificate. The caller binds these inputs to its actual request and
    /// checks nonce/intended recipient separately; identity alone is insufficient.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-3.2>
    pub fn find<'t, 'd, T: RevocationTarget<'t>, D: AsnDigest<'d> + ?Sized, E: Work>(
        self,
        target: &T,
        issuer: &Certificate<'_>,
        digest: &'d D,
        execution: &E,
    ) -> CallbackResult<Lookup<'r, 'a>, D::Error> {
        locate(self.response(), execution, |id| {
            id.matches(target, issuer, digest, execution)
        })
    }

    /// Locate an actual sent wire `CertID` without rehashing certificates or
    /// losing duplicates. Full digest identity/width checks use the same
    /// source-aware comparison as the complete request batch binding.
    pub fn find_id<'d, D: AsnDigest<'d> + ?Sized, E: Work>(
        self,
        requested: &CertId<'_>,
        digest: &'d D,
        execution: &E,
    ) -> CallbackResult<Lookup<'r, 'a>, D::Error> {
        locate(self.response(), execution, |id| {
            id.matches_id(requested, digest, execution)
        })
    }
}

fn locate<'r, 'a, E, W: Work>(
    original: &'r BasicResponse<'a>,
    execution: &W,
    mut compare: impl FnMut(CertId<'a>) -> CallbackResult<CertMatch, E>,
) -> CallbackResult<Lookup<'r, 'a>, E> {
    let execution = &original.signature_algorithm().query_in(execution);
    let mut first = None;
    for response in original.responses() {
        execution.charge_work(1).map_err(|reason| {
            Error::resource(reason, "ocspResponse.responses", response.span().start)
        })?;
        match compare(response.id())? {
            CertMatch::Differs => {}
            CertMatch::UnsupportedHash => return Ok(Lookup::UnsupportedHash(response)),
            CertMatch::MalformedHashWidth => return Ok(Lookup::MalformedHashWidth(response)),
            CertMatch::MalformedHashAlgorithm => {
                return Ok(Lookup::MalformedHashAlgorithm(response));
            }
            CertMatch::Matches => match first {
                None => first = Some(response),
                Some(first) => {
                    return Ok(Lookup::Ambiguous {
                        first,
                        second: response,
                    });
                }
            },
        }
    }
    Ok(match first {
        Some(response) => Lookup::Found(response),
        None => Lookup::Missing,
    })
}
