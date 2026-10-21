//! Original borrowed status targets shared by CRL and OCSP processing.

use crate::{Certificate, Extensions, Name, Version};
use structured_asn1::memory::{Execution, Work};
use structured_asn1::{Integer, Parser, Span};

/// Original certificate category, not a deployment policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A public-key certificate with its actual schema version.
    PublicKey(Version),
    /// An RFC5755 attribute certificate, without an invented public key or cA bit.
    Attribute,
}

/// Written revocation scheme, independently of successful status evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationScheme {
    /// Status sources may be processed; absent pointers are not an exemption.
    Available,
    /// RFC5755 §6 `NoRevAvail`, never CRL absence or positive OCSP evidence.
    NoRevAvail,
}

/// Coherently associated original fields for the common status processors.
///
/// Implementations are trusted O(1) adapters: borrow original fields without
/// parsing, allocation or normalization. Every field describes the same target.
/// This does not authenticate it or its issuer. Deferred work retains the source
/// ceiling and the current operation. The issuer/responder remains a real PKC;
/// an AC does not acquire an artificial subject public key.
///
/// ```
/// use structured_asn1::memory::Work;
/// use structured_pkix::{Result, revocation::RevocationTarget,
///     crl::{Authenticated, ScopeOutcome}};
/// fn applicable<'a>(source: &Authenticated<'_, '_>, target: &impl RevocationTarget<'a>,
///     work: &impl Work) -> Result<bool> {
///     Ok(matches!(source.scope(target, work)?, ScopeOutcome::Applicable(_)))
/// }
/// ```
pub trait RevocationTarget<'a> {
    /// Original issuer DN.
    fn issuer(&self) -> &Name<'a>;
    /// Original arbitrary-width serial.
    fn serial(&self) -> Integer<'a>;
    /// Original extension catalogue, absent where the schema omitted it.
    fn extensions(&self) -> Option<&Extensions<'a>>;
    /// Actual schema category.
    fn kind(&self) -> TargetKind;
    /// Written scheme, never inferred from short validity or absent URLs.
    fn revocation_scheme(&self) -> RevocationScheme;
    /// Whole original encoding used to bind evidence contributors.
    fn encoded(&self) -> &'a [u8];
    /// Honest source enclosure for processing failures.
    fn span(&self) -> Span;
    /// Original parser for these fields, including deferred BER depth and limits.
    fn source_parser(&self) -> &'a Parser;
    /// Borrow the original source ceiling and current operation.
    fn execution_in<'op, W: Work>(&'op self, work: &'op W) -> Execution<'op>
    where
        'a: 'op,
    {
        work.execution_for(self.source_parser())
    }
}

impl<'a> RevocationTarget<'a> for Certificate<'a> {
    fn source_parser(&self) -> &'a Parser {
        self.tbs().signature().source_parser()
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
