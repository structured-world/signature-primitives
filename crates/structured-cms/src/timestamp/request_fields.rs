//! Paid nonce/policy comparisons, separate from full imprint or trust checks.

use super::{ImprintOperand, Request, TokenInfo};
use crate::{Error, Result};
use structured_asn1::{Reader, memory::Work};

/// A failure retains the operand whose original source locates the cause.
#[derive(Debug)]
pub struct RequestFieldError {
    /// Token versus original request source.
    pub operand: ImprintOperand,
    /// Original processing/resource cause, never a semantic mismatch.
    pub source: Error,
}

/// Optional requested-field facts; omitted request fields mean unchecked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestFields {
    /// Equality of the requested nonce, including absence from the token.
    pub nonce: Option<bool>,
    /// Equality of the explicitly requested policy identifier.
    pub policy: Option<bool>,
}

impl TokenInfo<'_> {
    /// Compares requested nonce/policy after preflighting both original sessions.
    ///
    /// RFC3161 §2.4.2 requires the same nonce when one was requested. The common
    /// INTEGER decoder supplies minimal numeric views without re-encoding the
    /// original input. Every byte comparison is admitted by current token work.
    /// These facts do not imply complete imprint equality, freshness or trust.
    /// <https://www.rfc-editor.org/rfc/rfc3161.html#section-2.4.2>
    pub fn matches_request_fields(
        &self,
        requested: &Request<'_>,
        token_parent: &Reader<'_>,
        requested_parent: &Reader<'_>,
    ) -> core::result::Result<RequestFields, RequestFieldError> {
        self.imprint()
            .require_session(token_parent)
            .map_err(|source| RequestFieldError {
                operand: ImprintOperand::Token,
                source,
            })?;
        requested
            .imprint()
            .require_session(requested_parent)
            .map_err(|source| RequestFieldError {
                operand: ImprintOperand::Requested,
                source,
            })?;
        token_parent
            .execution()
            .charge_work(3)
            .map_err(|reason| RequestFieldError {
                operand: ImprintOperand::Token,
                source: Error::resource(reason, "tstInfo", self.span().start),
            })?;
        let compare = |left: &[u8], right: &[u8], field, at| {
            same(left, right, token_parent, field, at).map_err(|source| RequestFieldError {
                operand: ImprintOperand::Token,
                source,
            })
        };
        let nonce = match requested.nonce() {
            None => None,
            Some(asked) => Some(match self.nonce() {
                None => false,
                Some(written) => compare(
                    written.value().as_bytes(),
                    asked.as_bytes(),
                    "tstInfo.nonce",
                    written.element().span().start,
                )?,
            }),
        };
        let policy = match requested.policy() {
            None => None,
            Some(asked) => Some(compare(
                self.policy().as_bytes(),
                asked.as_bytes(),
                "tstInfo.policy",
                self.span().start,
            )?),
        };
        Ok(RequestFields { nonce, policy })
    }
}

fn same(
    left: &[u8],
    right: &[u8],
    parent: &Reader<'_>,
    field: &'static str,
    at: u64,
) -> Result<bool> {
    parent
        .execution()
        .charge_work(1 + left.len().min(right.len()) as u64)
        .map_err(|reason| Error::resource(reason, field, at))?;
    Ok(left == right)
}
