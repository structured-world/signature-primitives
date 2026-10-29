//! Stable selection ownership, including zero-sized backend adapters.

use super::{Prehash, SignatureAnswer, SignatureDigestError, SignatureMode, SignatureProvider};
use crate::Octets;
use core::cmp::Ordering;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::{Encoding, Reader, memory::Work};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
use structured_pkix::{AlgorithmIdentifier, path::WorkingKey};

/// One explicitly selected backend session with stable nonzero-sized ownership.
///
/// This owns the adapter, not a global registry or cryptographic engine. A
/// borrowed adapter may itself hold the caller's existing engine/policy. Its
/// address remains stable while finalized outputs or challenges borrow it.
/// Distinct selections remain distinct even for zero-sized stateless adapters.
/// There is no implicit Clone, allocation or synchronization requirement.
#[derive(Debug)]
pub struct ProviderSession<P> {
    backend: P,
    marker: u8,
}

impl<P> ProviderSession<P> {
    /// Creates a distinct selection owner before resolving any document input.
    #[must_use]
    pub const fn new(backend: P) -> Self {
        Self { backend, marker: 0 }
    }
    /// The selected adapter; this accessor does not transfer session provenance.
    #[must_use]
    pub const fn backend(&self) -> &P {
        &self.backend
    }
    /// Identity of the live selection owner, even when both adapters are ZSTs.
    #[must_use]
    pub fn same_session(&self, other: &Self) -> bool {
        core::ptr::eq(
            core::ptr::from_ref(&self.marker),
            core::ptr::from_ref(&other.marker),
        )
    }
}

impl<P> core::ops::Deref for ProviderSession<P> {
    type Target = P;
    fn deref(&self) -> &P {
        self.backend()
    }
}

impl<'a, P: Digest<'a>> Digest<'a> for ProviderSession<P> {
    type Identity = P::Identity;
    type State = P::State;
    type Output = P::Output;
    type Error = P::Error;
    fn width(&self, identity: &Self::Identity) -> Option<usize> {
        self.backend.width(identity)
    }
    fn compare<W: Work>(
        &self,
        left: &Self::Identity,
        right: &Self::Identity,
        work: &W,
    ) -> Result<Ordering, Self::Error> {
        self.backend.compare(left, right, work)
    }
    fn start<W: Work>(
        &'a self,
        identity: &Self::Identity,
        work: &W,
    ) -> Result<Resolution<Self::State>, Self::Error> {
        self.backend.start(identity, work)
    }
    fn update<W: Work>(
        &self,
        state: &mut Self::State,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), Self::Error> {
        self.backend.update(state, bytes, work)
    }
    fn finish<W: Work>(&self, state: Self::State, work: &W) -> Result<Self::Output, Self::Error> {
        self.backend.finish(state, work)
    }
    fn matches<W: Work>(
        &self,
        identity: &Self::Identity,
        output: &Self::Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Self::Error> {
        self.backend.matches(identity, output, expected, work)
    }
}

impl<'a, P: AsnDigest<'a>> AsnDigest<'a> for ProviderSession<P> {
    fn identity(&self, algorithm: Algorithm) -> Option<Self::Identity> {
        self.backend.identity(algorithm)
    }
}

impl<'a, P: SignatureProvider<'a>> SignatureProvider<'a> for ProviderSession<P> {
    type SignatureIdentity = P::SignatureIdentity;
    type RawState = P::RawState;
    fn resolve_signature_digest(
        &'a self,
        identifier: AlgorithmIdentifier<'a>,
        key: WorkingKey<'a>,
        parent: &Reader<'a>,
    ) -> Result<Resolution<Self::Identity>, SignatureDigestError<Self::Error>> {
        self.backend
            .resolve_signature_digest(identifier, key, parent)
    }
    fn resolve_signature(
        &'a self,
        algorithm: AlgorithmIdentifier<'a>,
        digest: &Self::Identity,
        key: WorkingKey<'a>,
        encoding: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<SignatureMode<Self::SignatureIdentity>>, Self::Error> {
        self.backend
            .resolve_signature(algorithm, digest, key, encoding, parent)
    }
    fn compare_signature<W: Work>(
        &self,
        left: &Self::SignatureIdentity,
        right: &Self::SignatureIdentity,
        work: &W,
    ) -> Result<Ordering, Self::Error> {
        self.backend.compare_signature(left, right, work)
    }
    fn start_raw<W: Work>(
        &'a self,
        identity: &Self::SignatureIdentity,
        key: WorkingKey<'a>,
        signature: &'a Octets<'a>,
        work: &W,
    ) -> Result<Self::RawState, Self::Error> {
        self.backend.start_raw(identity, key, signature, work)
    }
    fn update_raw<W: Work>(
        &self,
        state: &mut Self::RawState,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), Self::Error> {
        self.backend.update_raw(state, bytes, work)
    }
    fn finish_raw<W: Work>(
        &self,
        state: Self::RawState,
        work: &W,
    ) -> Result<SignatureAnswer, Self::Error> {
        self.backend.finish_raw(state, work)
    }
    fn verify_prehashed<W: Work>(
        &'a self,
        identity: &Self::SignatureIdentity,
        key: WorkingKey<'a>,
        signature: &Octets<'a>,
        digest: Prehash<'_, '_, Self, Self::Identity>,
        work: &W,
    ) -> Result<SignatureAnswer, Self::Error> {
        self.backend.verify_prehashed(
            identity,
            key,
            signature,
            Prehash::new(&self.backend, digest.identity(), digest.as_bytes()),
            work,
        )
    }
}
