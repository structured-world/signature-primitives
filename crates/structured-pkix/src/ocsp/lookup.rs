//! Applicable assertions are selected without discarding duplicate evidence.

use super::{CertMatch, Digest, SignedResponse, SingleResponse};
use crate::Certificate;
use crate::error::{CallbackResult, Error};
use structured_asn1::memory::Memory;

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
}

impl<'r, 'a> SignedResponse<'r, 'a> {
    /// Locate the target's assertion using actual target/issuer bytes and the
    /// selected provider. RFC6960 §3.2(1) requires binding to the requested
    /// certificate. The caller binds these inputs to its actual request and
    /// checks nonce/intended recipient separately; identity alone is insufficient.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-3.2>
    pub fn find<D: Digest>(
        self,
        target: &Certificate<'_>,
        issuer: &Certificate<'_>,
        digest: &D,
        execution: &Memory,
    ) -> CallbackResult<Lookup<'r, 'a>, D::Error> {
        let mut first = None;
        for response in self.response().responses() {
            execution.charge_work(1).map_err(|reason| {
                Error::resource(reason, "ocspResponse.responses", response.span().start)
            })?;
            match response.id().matches(target, issuer, digest, execution)? {
                CertMatch::Differs => {}
                CertMatch::UnsupportedHash => return Ok(Lookup::UnsupportedHash(response)),
                CertMatch::MalformedHashWidth => return Ok(Lookup::MalformedHashWidth(response)),
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
}
