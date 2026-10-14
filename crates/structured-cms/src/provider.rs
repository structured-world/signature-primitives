//! Selected-provider identities and distinct raw versus finalized-prehash inputs.

use crate::Octets;
use core::cmp::Ordering;
use structured_asn1::memory::Work;
use structured_asn1::{Encoding, Reader, Span};
use structured_pkix::AlgorithmIdentifier;
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
/// default. The enclosing field/span locate implied callback failures using
/// real document provenance, without synthesizing bytes or a new Parser.
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

/// Semantic resolution, distinct from failure to execute the resolver.
#[derive(Debug)]
pub enum Resolution<T> {
    /// Fully resolved algorithm identity, including parameters/output semantics.
    Supported(T),
    /// The selected provider cannot answer this mechanism.
    Unsupported,
    /// The original algorithm identifier violates the selected algorithm's syntax.
    Malformed,
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

    pub(crate) fn new(provider: &'p P, identity: I, output: O) -> Self {
        Self {
            provider,
            identity,
            output,
        }
    }
}

/// Narrow digest operations from one explicitly selected provider instance.
///
/// Identities must include algorithm parameters/defaults/output semantics, not
/// just an OID or byte width. `compare` is a total semantic order: Equal means
/// the outputs can be shared. Every callback admits its complete transitive
/// work/storage before execution through the supplied domain. Errors preserve
/// provider/resource causes; they are never converted to unsupported/malformed.
/// States/outputs may borrow the selected provider or original document and
/// impose no Clone, Send or Sync requirement. State initialization must not
/// retain a reference to the temporary identity object itself.
///
/// Common processing borrows a stable nonzero-sized selection owner. Ordinary
/// adapters containing engine/context references already satisfy this. Wrap a
/// zero-sized stateless adapter in [`ProviderSession`] before using common
/// processing; otherwise it returns a processing `ProviderMismatch` before
/// dispatch. Distinct ZST addresses cannot supply instance provenance.
pub trait DigestProvider<'a>: Sized {
    /// Original callback failure, including that provider's resource refusal.
    type Error;
    /// Fully resolved digest identity.
    type Identity;
    /// Digest state, independently movable from its identity object.
    type State;
    /// Final output, inline or retaining its own admitted allocation charge.
    type Output: AsRef<[u8]>;

    /// Resolves original parameters under their producing encoding/work domain.
    fn resolve_digest(
        &'a self,
        identifier: DigestAlgorithm<'a>,
        encoding: Encoding,
        parent: &Reader<'a>,
    ) -> core::result::Result<Resolution<Self::Identity>, Self::Error>;
    /// Compares full resolved identities after admitting any parameter traversal.
    fn compare_digest<W: Work>(
        &self,
        left: &Self::Identity,
        right: &Self::Identity,
        execution: &W,
    ) -> core::result::Result<Ordering, Self::Error>;
    /// Expected fixed output width, or None for an identity without a fixed width.
    /// This is O(1) metadata access on the already resolved identity, not parsing.
    fn digest_width(&self, identity: &Self::Identity) -> Option<usize>;
    /// Initializes a state without borrowing the address of `identity`.
    fn start_digest<W: Work>(
        &'a self,
        identity: &Self::Identity,
        execution: &W,
    ) -> core::result::Result<Self::State, Self::Error>;
    /// Admits and processes each complete logical chunk exactly once.
    fn update_digest<W: Work>(
        &self,
        state: &mut Self::State,
        bytes: &[u8],
        execution: &W,
    ) -> core::result::Result<(), Self::Error>;
    /// Consumes a completed state once; no opaque state cloning or repeated finish.
    fn finish_digest<W: Work>(
        &self,
        state: Self::State,
        execution: &W,
    ) -> core::result::Result<Self::Output, Self::Error>;

    /// Compares completed bytes with a declared imprint, without hashing again.
    ///
    /// Common schema processing rejects an impossible fixed expected width
    /// first and checks declared versus actual finalized width even when the
    /// identity has no fixed width. The callback admits the complete byte comparison in `execution`,
    /// preserves resource failures and applies its backend's comparison
    /// strategy, including constant-time equality where its contract requires.
    /// CMS payload message-digest, ESS certificate hashes and TSP imprints use
    /// this same operation with their distinct original covered inputs.
    fn matches_digest<W: Work>(
        &self,
        digest: Prehash<'_, '_, Self, Self::Identity>,
        expected: &[u8],
        execution: &W,
    ) -> core::result::Result<bool, Self::Error>;
}

/// Signature operations that stay bound to the same selected provider and key.
///
/// The effective key retains its original SPKI and inherited parameters.
/// Resolution validates key/algorithm compatibility before raw initialization
/// or payload I/O. A contiguous-only backend may explicitly buffer with full
/// admission in its adapter, or report unsupported; it cannot downgrade raw.
/// The core's digest trait is separate so timestamp imprints need no signer.
pub trait SignatureProvider<'a>: DigestProvider<'a> {
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
