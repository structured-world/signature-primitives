//! One incremental digest execution contract for every format.
//!
//! A consumer implements [`Digest`] once over its own cryptographic backend.
//! Which algorithm a document names is a separate question answered by the
//! format that wrote it: ASN.1 identifiers by `structured-pkix`, XML methods
//! by `structured-xades`. Both hand their resolved identity to this contract.

use crate::memory::Work;
use core::cmp::Ordering;

/// Semantic resolution, distinct from failure to execute the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution<T> {
    /// Fully resolved algorithm identity, including parameters/output semantics.
    Supported(T),
    /// The selected provider cannot answer this mechanism.
    Unsupported,
    /// The original algorithm identifier violates the selected algorithm's syntax.
    Malformed,
}

/// Incremental digest operations of one explicitly selected provider.
///
/// Identities carry complete algorithm semantics, not just an identifier or a
/// byte width. Every callback admits its complete transitive work and storage
/// in the supplied execution before it runs. Errors are a spent ceiling or a
/// provider fault, never a finding about the document. States may borrow the
/// provider for `'a` and carry no `Clone`, `Send` or `Sync` requirement.
pub trait Digest<'a> {
    /// Fully resolved digest identity.
    type Identity;
    /// Digest state, independently movable from its identity object.
    type State;
    /// Final output, inline or retaining its own admitted allocation charge.
    type Output: AsRef<[u8]>;
    /// Original callback failure, including that provider's resource refusal.
    type Error;

    /// Fixed output width, or `None` for an identity without one. This is O(1)
    /// metadata access on the resolved identity, not parsing.
    fn width(&self, identity: &Self::Identity) -> Option<usize>;

    /// Total semantic order: `Equal` means the outputs can be shared.
    fn compare<W: Work>(
        &self,
        left: &Self::Identity,
        right: &Self::Identity,
        execution: &W,
    ) -> Result<Ordering, Self::Error>;

    /// Starts one stream for this identity without retaining a reference to the
    /// identity object. A backend without incremental capability answers
    /// `Unsupported`; it never buffers into a one-shot fallback.
    fn start<W: Work>(
        &'a self,
        identity: &Self::Identity,
        execution: &W,
    ) -> Result<Resolution<Self::State>, Self::Error>;

    /// Admits and processes one complete chunk exactly once.
    fn update<W: Work>(
        &self,
        state: &mut Self::State,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), Self::Error>;

    /// Consumes a completed state once; no state cloning or repeated finish.
    fn finish<W: Work>(
        &self,
        state: Self::State,
        execution: &W,
    ) -> Result<Self::Output, Self::Error>;

    /// Compares this provider's finished output with declared bytes, admitting
    /// the whole scan and applying the backend's comparison strategy.
    ///
    /// The answer is whether `expected` is exactly the bytes of `output`. A
    /// strategy, such as a constant-time scan, governs how those bytes are
    /// compared, never which differing byte strings count as equal; callers
    /// rely on this to find the one output an expected value can name by its
    /// bytes.
    fn matches<W: Work>(
        &self,
        identity: &Self::Identity,
        output: &Self::Output,
        expected: &[u8],
        execution: &W,
    ) -> Result<bool, Self::Error>;
}

/// Failure of a one-shot check, apart from every completed comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnceError<E> {
    /// Original provider failure, including its resource refusal.
    Provider(E),
    /// The provider's output contradicts the fixed width of its own identity.
    /// This is a provider contract failure, not malformed document data.
    OutputWidth {
        /// Width promised by the resolved identity.
        expected: usize,
        /// Width actually returned.
        actual: usize,
    },
}

/// Hashes one contiguous input and compares it with `expected`: start, one
/// update, finish and matches over the same contract as streamed input.
///
/// `Unsupported` and `Malformed` are the provider's start answer, returned
/// before any byte is hashed.
///
/// # Errors
///
/// Returns the provider's failure, or [`OnceError::OutputWidth`] when the
/// output contradicts the identity's fixed width.
///
/// # Examples
///
/// ```
/// # extern crate alloc;
/// # use alloc::sync::Arc;
/// # use core::cmp::Ordering;
/// # use structured_asn1::digest::{self, Digest, Resolution};
/// # use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
/// /// A one-byte additive checksum, enough to show the call sequence.
/// struct Sum;
/// impl Digest<'_> for Sum {
///     type Identity = ();
///     type State = u8;
///     type Output = [u8; 1];
///     type Error = MemoryError;
///     fn width(&self, (): &()) -> Option<usize> { Some(1) }
///     fn compare<W: Work>(&self, (): &(), (): &(), _: &W) -> Result<Ordering, MemoryError> {
///         Ok(Ordering::Equal)
///     }
///     fn start<W: Work>(&self, (): &(), w: &W) -> Result<Resolution<u8>, MemoryError> {
///         w.charge_work(1)?;
///         Ok(Resolution::Supported(0))
///     }
///     fn update<W: Work>(&self, s: &mut u8, bytes: &[u8], w: &W) -> Result<(), MemoryError> {
///         w.charge_work(bytes.len() as u64)?;
///         *s = bytes.iter().fold(*s, |sum, byte| sum.wrapping_add(*byte));
///         Ok(())
///     }
///     fn finish<W: Work>(&self, s: u8, _: &W) -> Result<[u8; 1], MemoryError> { Ok([s]) }
///     fn matches<W: Work>(&self, (): &(), o: &[u8; 1], e: &[u8], w: &W) -> Result<bool, MemoryError> {
///         w.charge_work(1)?;
///         Ok(o.as_slice() == e)
///     }
/// }
/// let execution = Memory::new(Arc::new(MemoryAccount::new(0, 64)));
/// let answer = digest::matches_once(&Sum, &(), b"\x01\x02", &[3], &execution).unwrap();
/// assert_eq!(answer, Resolution::Supported(true));
/// ```
pub fn matches_once<'a, D: Digest<'a> + ?Sized, W: Work>(
    digest: &'a D,
    identity: &D::Identity,
    input: &[u8],
    expected: &[u8],
    execution: &W,
) -> Result<Resolution<bool>, OnceError<D::Error>> {
    let mut state = match digest
        .start(identity, execution)
        .map_err(OnceError::Provider)?
    {
        Resolution::Supported(state) => state,
        Resolution::Unsupported => return Ok(Resolution::Unsupported),
        Resolution::Malformed => return Ok(Resolution::Malformed),
    };
    digest
        .update(&mut state, input, execution)
        .map_err(OnceError::Provider)?;
    let output = digest
        .finish(state, execution)
        .map_err(OnceError::Provider)?;
    if let Some(expected) = digest.width(identity) {
        let actual = output.as_ref().len();
        if actual != expected {
            return Err(OnceError::OutputWidth { expected, actual });
        }
    }
    digest
        .matches(identity, &output, expected, execution)
        .map(Resolution::Supported)
        .map_err(OnceError::Provider)
}
