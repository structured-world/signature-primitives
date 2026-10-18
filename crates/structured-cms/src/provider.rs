//! Selected-provider identities and distinct raw versus finalized-prehash inputs.
//!
//! Digest execution is the shared [`structured_asn1::digest::Digest`]
//! contract; ASN.1 digest identifiers resolve through
//! [`structured_pkix::algorithm::digest`].

use crate::Octets;
use core::cmp::Ordering;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::Work;
use structured_asn1::{Encoding, Reader, Span};
use structured_pkix::AlgorithmIdentifier;
use structured_pkix::algorithm::digest::{self as asn_digest, Algorithm, AsnDigest};
use structured_pkix::path::WorkingKey;
mod session;
pub use session::ProviderSession;

pub(crate) fn require_instance<P>(_: &P, field: &'static str, at: u64) -> crate::Result<()> {
    // Distinct ZST objects may have the same address. Their adapters must use
    // the explicit nonzero ProviderSession owner, not an invented object ID.
    // This constant condition is removed for ordinary monomorphized adapters.
    if core::mem::size_of::<P>() == 0 {
        return Err(crate::Error::schema(
            crate::ErrorCode::ProviderMismatch,
            field,
            at,
        ));
    }
    Ok(())
}

/// Digest algorithms supplied by ESS schema without an encoded identifier.
/// These select identity, not a product policy permission or an engine fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpliedDigest {
    /// `ESSCertID` Hash is SHA-1 (RFC2634 §5.4.1).
    EssSha1,
    /// Omitted `ESSCertIDv2` hashAlgorithm is SHA-256 with absent parameters
    /// (RFC5035 §4, corrected certHash description in verified erratum2364).
    EssV2Sha256,
}

/// Original written algorithm or a normative schema-supplied identity.
///
/// Implied inputs have no encoded `AlgorithmIdentifier` and no parameter TLV.
/// A written unsupported/malformed identifier must never become an implied
/// default. The enclosing field/span locate the implied identity with real
/// document provenance, without synthesizing bytes or a new Parser.
#[derive(Debug, Clone, Copy)]
pub enum DigestAlgorithm<'a> {
    /// The complete original identifier, encoding and parameter provenance.
    Written(AlgorithmIdentifier<'a>),
    /// A schema default/mandatory identity without an original identifier TLV.
    Implied {
        /// Identity selected by the ESS schema, with no implicit NULL fallback.
        algorithm: ImpliedDigest,
        /// Original enclosing ESS field.
        field: &'static str,
        /// Original enclosing ESS identifier span.
        span: Span,
    },
}

impl ImpliedDigest {
    /// The algorithm the ESS schema selects.
    #[must_use]
    pub const fn algorithm(self) -> Algorithm {
        match self {
            Self::EssSha1 => Algorithm::Sha1,
            Self::EssV2Sha256 => Algorithm::Sha256,
        }
    }
}

/// Resolves a written identifier through the shared ASN.1 resolver, under the
/// encoding of the document it came from, or an implied ESS algorithm
/// directly, then asks the provider for its identity.
pub(crate) fn resolve_digest<'a, P: AsnDigest<'a>>(
    provider: &P,
    algorithm: DigestAlgorithm<'_>,
    parent: &Reader<'_>,
) -> crate::Result<Resolution<P::Identity>> {
    match algorithm {
        DigestAlgorithm::Written(identifier) => {
            asn_digest::resolve(provider, &identifier, &parent.execution())
                .map_err(crate::Error::pkix)
        }
        DigestAlgorithm::Implied { algorithm, .. } => {
            Ok(asn_digest::supported(provider, algorithm.algorithm()))
        }
    }
}

/// A cryptographic signature answer after complete input processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAnswer {
    /// Signature arithmetic accepted the exact selected input and key.
    Valid,
    /// Signature arithmetic rejected that input/key, independently of resources.
    Invalid,
}

/// Fully resolved signature input contract; raw never silently becomes prehash.
#[derive(Debug)]
pub enum SignatureMode<T> {
    /// Original logical message octets, as required by `PureEdDSA` (RFC8419 §3).
    Raw(T),
    /// One finalized digest with a typed, fully resolved identity.
    Prehashed(T),
}

/// A finalized output and its complete algorithm identity, without a cloneable state.
#[derive(Debug)]
pub struct Finalized<'p, P, I, O> {
    provider: &'p P,
    identity: I,
    output: O,
}

/// A finalized prehash with independent short identity/output borrows.
///
/// Only common processing constructs this view from a completed state bound
/// to the same resolved identity/provider. Byte width alone never establishes
/// that provenance. There is no public arbitrary digest-plus-OID constructor.
#[derive(Debug)]
pub struct Prehash<'i, 'o, P, I> {
    provider: &'i P,
    identity: &'i I,
    bytes: &'o [u8],
}

/// A finished digest: the provider's own output and identity, and the
/// instance that produced them. Only common processing constructs it, from a
/// state it completed; there is no constructor from arbitrary bytes.
#[derive(Debug)]
pub struct Finished<'v, P, I, O> {
    provider: &'v P,
    identity: &'v I,
    output: &'v O,
}

// Only shared references: copying needs no bound on the referenced types.
impl<P, I, O> Clone for Finished<'_, P, I, O> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<P, I, O> Copy for Finished<'_, P, I, O> {}

impl<'v, P, I, O: AsRef<[u8]>> Finished<'v, P, I, O> {
    pub(crate) fn new(provider: &'v P, identity: &'v I, output: &'v O) -> Self {
        Self {
            provider,
            identity,
            output,
        }
    }
    /// Whether the supplied instance actually completed this output.
    #[must_use]
    pub fn from_provider(&self, provider: &P) -> bool {
        core::ptr::eq(self.provider, provider)
    }
    /// Full selected-provider algorithm identity.
    #[must_use]
    pub fn identity(&self) -> &'v I {
        self.identity
    }
    /// The provider's own finished output.
    #[must_use]
    pub fn output(&self) -> &'v O {
        self.output
    }
}

impl<'i, 'o, P, I> Prehash<'i, 'o, P, I> {
    pub(crate) fn new(provider: &'i P, identity: &'i I, bytes: &'o [u8]) -> Self {
        Self {
            provider,
            identity,
            bytes,
        }
    }
    /// Whether the supplied instance actually completed this finalized input.
    #[must_use]
    pub fn from_provider(&self, provider: &P) -> bool {
        core::ptr::eq(self.provider, provider)
    }
    /// Full selected-provider algorithm identity, including parameters/defaults.
    #[must_use]
    pub fn identity(&self) -> &'i I {
        self.identity
    }

    /// Original finalized output bytes; accessing them performs no new hashing.
    #[must_use]
    pub fn as_bytes(&self) -> &'o [u8] {
        self.bytes
    }
}

impl<'p, P, I, O: AsRef<[u8]>> Finalized<'p, P, I, O> {
    /// Resolved identity, including parameters and output-length semantics.
    #[must_use]
    pub fn identity(&self) -> &I {
        &self.identity
    }
    /// Borrowed final output; providers must implement this as constant-time access.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.output.as_ref()
    }

    /// Borrows a typed prehash without cloning identity, state or output.
    #[must_use]
    pub fn prehash(&self) -> Prehash<'_, '_, P, I> {
        Prehash::new(self.provider, &self.identity, self.output.as_ref())
    }

    /// Borrows the provider's own output for its comparison, with provenance.
    #[must_use]
    pub fn finished(&self) -> Finished<'_, P, I, O> {
        Finished {
            provider: self.provider,
            identity: &self.identity,
            output: &self.output,
        }
    }

    pub(crate) fn new(provider: &'p P, identity: I, output: O) -> Self {
        Self {
            provider,
            identity,
            output,
        }
    }
}

/// Signature operations that stay bound to the same selected provider and key.
///
/// Digest execution and identities come from the provider's
/// [`structured_asn1::digest::Digest`] and [`AsnDigest`] implementations; CMS
/// payload message-digest, ESS certificate hashes and TSP imprints all run
/// through them with their distinct original covered inputs.
///
/// The effective key retains its original SPKI and inherited parameters.
/// Resolution validates key/algorithm compatibility before raw initialization
/// or payload I/O. A contiguous-only backend may explicitly buffer with full
/// admission in its adapter, or report unsupported; it cannot downgrade raw.
///
/// Common processing borrows a stable nonzero-sized selection owner. Ordinary
/// adapters containing engine/context references already satisfy this. Wrap a
/// zero-sized stateless adapter in [`ProviderSession`] before using common
/// processing; otherwise it returns a processing `ProviderMismatch` before
/// dispatch. Distinct ZST addresses cannot supply instance provenance.
pub trait SignatureProvider<'a>: AsnDigest<'a> + Sized {
    /// Fully resolved signature identity, including algorithm-specific defaults.
    type SignatureIdentity;
    /// Raw verification state, initialized with original signature/key first.
    type RawState;

    /// Chooses raw versus prehashed only after complete algorithm/key resolution.
    fn resolve_signature(
        &'a self,
        identifier: AlgorithmIdentifier<'a>,
        digest: &Self::Identity,
        key: WorkingKey<'a>,
        encoding: Encoding,
        parent: &Reader<'a>,
    ) -> core::result::Result<Resolution<SignatureMode<Self::SignatureIdentity>>, Self::Error>;
    /// Semantic signature/default comparison for protected versus outer identifiers.
    fn compare_signature<W: Work>(
        &self,
        left: &Self::SignatureIdentity,
        right: &Self::SignatureIdentity,
        execution: &W,
    ) -> core::result::Result<Ordering, Self::Error>;
    /// Starts the raw challenge with the original signature and effective key.
    fn start_raw<W: Work>(
        &'a self,
        identity: &Self::SignatureIdentity,
        key: WorkingKey<'a>,
        signature: &'a Octets<'a>,
        execution: &W,
    ) -> core::result::Result<Self::RawState, Self::Error>;
    /// Admits and processes original raw message chunks, never digest bytes.
    fn update_raw<W: Work>(
        &self,
        state: &mut Self::RawState,
        bytes: &[u8],
        execution: &W,
    ) -> core::result::Result<(), Self::Error>;
    /// Completes a raw signature only after successful complete source EOF.
    fn finish_raw<W: Work>(
        &self,
        state: Self::RawState,
        execution: &W,
    ) -> core::result::Result<SignatureAnswer, Self::Error>;
    /// Verifies one borrowed finalized digest with its full identity; no rehash.
    fn verify_prehashed<W: Work>(
        &'a self,
        identity: &Self::SignatureIdentity,
        key: WorkingKey<'a>,
        signature: &Octets<'a>,
        digest: Prehash<'_, '_, Self, Self::Identity>,
        execution: &W,
    ) -> core::result::Result<SignatureAnswer, Self::Error>;
}
