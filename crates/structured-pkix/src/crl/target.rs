//! Borrowed status targets, independent of their containing certificate schema.

use crate::{Certificate, Extensions, Name, Version};
use structured_asn1::memory::{Execution, Work};
use structured_asn1::{Integer, Span};

/// Original certificate category, not a deployment policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A public-key certificate with its actual schema version.
    PublicKey(Version),
    /// An attribute certificate, without an invented public key or cA bit.
    Attribute,
}

/// Written revocation scheme, independently of successful status evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationScheme {
    /// Status sources may be processed; absence of pointers is not an exemption.
    Available,
    /// RFC5755 §6 `NoRevAvail`: do not turn this scheme into CRL absence evidence.
    NoRevAvail,
}

/// Original, coherently associated target fields for the single CRL processor.
///
/// Implementations are trusted adapters: getters are O(1), borrow their original
/// fields and never parse, allocate or normalize. Every field must describe the
/// same original target. This contract does not authenticate the target itself.
/// Deferred work uses the original target session and the current operation.
///
/// The same scope query accepts public-key certificates and checked CMS AC
/// profiles; an applicable scope is only one component of status evidence.
/// ```
/// use structured_asn1::memory::Work;
/// use structured_pkix::{Result, crl::{Authenticated, RevocationTarget, ScopeOutcome}};
/// fn applicable<'a>(source: &Authenticated<'_, '_>, target: &impl RevocationTarget<'a>,
///     work: &impl Work) -> Result<bool> {
///     Ok(matches!(source.scope(target, work)?, ScopeOutcome::Applicable(_)))
/// }
/// ```
pub trait RevocationTarget<'a> {
    /// Original issuer DN, including its parsing provenance.
    fn issuer(&self) -> &Name<'a>;
    /// Original arbitrary-width serial.
    fn serial(&self) -> Integer<'a>;
    /// Original extension catalogue, absent where the schema omitted it.
    fn extensions(&self) -> Option<&Extensions<'a>>;
    /// Actual schema category.
    fn kind(&self) -> TargetKind;
    /// Written status scheme; never inferred from short validity or absent URLs.
    fn revocation_scheme(&self) -> RevocationScheme;
    /// Whole original encoding used to bind coverage contributors to this target.
    fn encoded(&self) -> &'a [u8];
    /// Honest original target enclosure for processing failures.
    fn span(&self) -> Span;
    /// Reuse the original source ceiling and current operation without ownership.
    fn execution_in<'op, W: Work>(&'op self, work: &'op W) -> Execution<'op>
    where
        'a: 'op;
}

impl<'a> RevocationTarget<'a> for Certificate<'a> {
    fn execution_in<'op, W: Work>(&'op self, work: &'op W) -> Execution<'op>
    where
        'a: 'op,
    {
        Certificate::execution_in(self, work)
    }
    fn issuer(&self) -> &Name<'a> {
        self.tbs().issuer()
    }
    fn serial(&self) -> Integer<'a> {
        self.tbs().serial()
    }
    fn extensions(&self) -> Option<&Extensions<'a>> {
        Some(self.tbs().extensions())
    }
    fn kind(&self) -> TargetKind {
        TargetKind::PublicKey(self.tbs().version())
    }
    fn revocation_scheme(&self) -> RevocationScheme {
        RevocationScheme::Available
    }
    fn encoded(&self) -> &'a [u8] {
        self.as_bytes()
    }
    fn span(&self) -> Span {
        Certificate::span(self)
    }
}
