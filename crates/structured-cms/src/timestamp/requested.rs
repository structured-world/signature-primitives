//! Full parsed-request imprint comparison with both original source contexts.

use super::imprint_check::Resolved;
use super::{ImprintAgreement, MessageImprint};
use crate::Error;
use core::cmp::Ordering;
use structured_asn1::{Reader, Span};
use structured_pkix::algorithm::digest::AsnDigest;

/// Combined execution preserves request versus covered-content failure classes.
#[derive(Debug)]
pub enum RequestedContentError<SE, PE> {
    /// Original request comparison refusal, with its operand/source role.
    Request(RequestImprintError<PE>),
    /// Original covered-source/digest refusal.
    Content(super::ImprintError<SE, PE>),
}

/// Identifies which original source supplied an operand or located failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImprintOperand {
    /// The timestamp token's original carried information source.
    Token,
    /// The caller's original parsed request source, possibly another session.
    Requested,
}

/// Complete imprint agreement, independently of other request checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAgreement {
    /// Full selected-provider identities and logical declared digest bytes agree.
    Matches,
    /// Selected-provider algorithm/parameter/output identities disagree.
    AlgorithmDiffers,
    /// Complete algorithm identity agrees but declared digest bytes disagree.
    HashDiffers,
    /// An operand cannot establish a conforming supported imprint declaration.
    Unusable {
        /// Original source whose declaration cannot be compared successfully.
        operand: ImprintOperand,
        /// Malformed encoding/algorithm/width or unsupported mechanism.
        reason: ImprintAgreement,
    },
}

/// Request comparison failure retains source role and actual source span.
#[derive(Debug)]
pub enum RequestImprintError<E> {
    /// Processing/resource refusal, not a semantic mismatch or request failure.
    Processing {
        /// Source to use when interpreting the located diagnostic.
        operand: ImprintOperand,
        /// Original common refusal in that source's reader coordinates.
        source: Error,
    },
    /// Original selected-provider cause with honest original-source enclosure.
    Callback {
        /// Source to use for known inner reader diagnostics in the opaque cause.
        operand: ImprintOperand,
        /// Actual original enclosing imprint; it may use logical coordinates.
        span: Span,
        /// Unchanged callback cause, including provider resource refusal.
        source: E,
    },
}

impl<'a> MessageImprint<'a> {
    /// Compares the full request and hashes covered bytes using one token identity.
    /// Request bytes themselves are never hashed. Semantic request disagreement
    /// remains independent of covered-content agreement; an unusable token
    /// declaration starts no digest state or content pass. No identity Clone,
    /// second token parameter resolve, state reconstruction or rehash is used.
    pub fn check_requested_content<P: AsnDigest<'a>, S: crate::stream::Source>(
        &self,
        requested: &MessageImprint<'a>,
        provider: &'a P,
        parents: (&Reader<'a>, &Reader<'a>),
        covered: &mut S,
    ) -> Result<(ImprintAgreement, RequestAgreement), RequestedContentError<S::Error, P::Error>>
    {
        let (token_parent, requested_parent) = parents;
        preflight(self, requested, token_parent, requested_parent)
            .map_err(RequestedContentError::Request)?;
        let token = match resolve(self, provider, token_parent, ImprintOperand::Token)
            .map_err(RequestedContentError::Request)?
        {
            Resolved::Ready(identity) => identity,
            Resolved::Unusable(reason) => {
                return Ok((
                    reason,
                    RequestAgreement::Unusable {
                        operand: ImprintOperand::Token,
                        reason,
                    },
                ));
            }
        };
        let agreement = compare_resolved(
            self,
            requested,
            provider,
            token_parent,
            requested_parent,
            &token,
        )
        .map_err(RequestedContentError::Request)?;
        let content = self
            .compute(provider, token_parent, covered, token)
            .map_err(RequestedContentError::Content)?;
        Ok((content, agreement))
    }
    /// Compares the entire parsed requested imprint under one selected provider.
    ///
    /// RFC3161 §§2.2/2.4.2 requires the requested hash and algorithm. Both operands
    /// use the same semantic resolution/known-width kernel as content checking.
    /// Each reader must be from its own operand's session; legitimate different
    /// sessions are allowed. Comparison uses the token's current execution;
    /// resolution uses each operand's original local/current aggregate ceilings.
    /// Core creates no hash state or content pass, fabricates no identifier and
    /// performs no parameter serialization or replacement-parser decoding. The
    /// provider reads original parameters under each producing reader's budget.
    /// Malformed equal-width declarations cannot produce successful equality.
    /// A joined token location uses its token source map; a requested location
    /// uses its own original provenance. Nonce, policy, `certReq` and timeliness
    /// remain separate checks. <https://www.rfc-editor.org/rfc/rfc3161#section-2.2>
    pub fn matches_request<P: AsnDigest<'a>>(
        &self,
        requested: &MessageImprint<'a>,
        provider: &'a P,
        token_parent: &Reader<'a>,
        requested_parent: &Reader<'a>,
    ) -> Result<RequestAgreement, RequestImprintError<P::Error>> {
        preflight(self, requested, token_parent, requested_parent)?;
        let token = match resolve(self, provider, token_parent, ImprintOperand::Token)? {
            Resolved::Ready(identity) => identity,
            Resolved::Unusable(reason) => {
                return Ok(RequestAgreement::Unusable {
                    operand: ImprintOperand::Token,
                    reason,
                });
            }
        };
        compare_resolved(
            self,
            requested,
            provider,
            token_parent,
            requested_parent,
            &token,
        )
    }
}

fn preflight<E>(
    token: &MessageImprint<'_>,
    requested: &MessageImprint<'_>,
    token_parent: &Reader<'_>,
    requested_parent: &Reader<'_>,
) -> Result<(), RequestImprintError<E>> {
    // Both operands are checked before callbacks, including unusable input.
    for (operand, imprint, parent) in [
        (ImprintOperand::Token, token, token_parent),
        (ImprintOperand::Requested, requested, requested_parent),
    ] {
        imprint
            .require_session(parent)
            .map_err(|source| RequestImprintError::Processing { operand, source })?;
    }
    Ok(())
}

fn compare_resolved<'a, P: AsnDigest<'a>>(
    token_imprint: &MessageImprint<'a>,
    requested: &MessageImprint<'a>,
    provider: &'a P,
    token_parent: &Reader<'a>,
    requested_parent: &Reader<'a>,
    token: &P::Identity,
) -> Result<RequestAgreement, RequestImprintError<P::Error>> {
    let asked = match resolve(
        requested,
        provider,
        requested_parent,
        ImprintOperand::Requested,
    )? {
        Resolved::Ready(identity) => identity,
        Resolved::Unusable(reason) => {
            return Ok(RequestAgreement::Unusable {
                operand: ImprintOperand::Requested,
                reason,
            });
        }
    };
    let execution = token_parent.execution();
    if provider
        .compare(token, &asked, &execution)
        .map_err(|source| RequestImprintError::Callback {
            operand: ImprintOperand::Token,
            span: token_imprint.span(),
            source,
        })?
        != Ordering::Equal
    {
        return Ok(RequestAgreement::AlgorithmDiffers);
    }
    let matches = token_imprint
        .hashed()
        .same_value(
            requested.hashed(),
            token_parent,
            "tstInfo.messageImprint.hashedMessage",
            token_imprint.hashed().span().start,
        )
        .map_err(|source| RequestImprintError::Processing {
            operand: ImprintOperand::Token,
            source,
        })?;
    Ok(if matches {
        RequestAgreement::Matches
    } else {
        RequestAgreement::HashDiffers
    })
}

fn resolve<'a, P: AsnDigest<'a>>(
    imprint: &MessageImprint<'a>,
    provider: &'a P,
    parent: &Reader<'a>,
    operand: ImprintOperand,
) -> Result<Resolved<P::Identity>, RequestImprintError<P::Error>> {
    imprint
        .resolve(provider, parent)
        .map_err(|source| RequestImprintError::Processing { operand, source })
}
