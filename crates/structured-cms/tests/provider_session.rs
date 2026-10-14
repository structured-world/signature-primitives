//! Nonzero selected-session provenance for genuinely zero-sized adapters.

use core::cmp::Ordering;
use std::sync::Arc;
use structured_asn1::{
    Encoding, Reader, Span,
    memory::{Memory, MemoryAccount, Work},
};
use structured_cms::provider::{
    DigestAlgorithm, DigestProvider, Prehash, ProviderSession, Resolution,
};

struct Stateless;
std::thread_local! { static STARTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) }; }
impl<'a> DigestProvider<'a> for Stateless {
    type Error = core::convert::Infallible;
    type Identity = ();
    type State = ();
    type Output = [u8; 1];
    fn resolve_digest(
        &'a self,
        _: DigestAlgorithm<'a>,
        _: Encoding,
        _: &Reader<'a>,
    ) -> Result<Resolution<()>, Self::Error> {
        Ok(Resolution::Supported(()))
    }
    fn compare_digest<W: Work>(&self, (): &(), (): &(), _: &W) -> Result<Ordering, Self::Error> {
        Ok(Ordering::Equal)
    }
    fn digest_width(&self, (): &()) -> Option<usize> {
        Some(1)
    }
    fn start_digest<W: Work>(&'a self, (): &(), _: &W) -> Result<(), Self::Error> {
        STARTS.with(|calls| calls.set(calls.get() + 1));
        Ok(())
    }
    fn update_digest<W: Work>(&self, (): &mut (), _: &[u8], _: &W) -> Result<(), Self::Error> {
        Ok(())
    }
    fn finish_digest<W: Work>(&self, (): (), _: &W) -> Result<[u8; 1], Self::Error> {
        Ok([7])
    }
    fn matches_digest<W: Work>(
        &self,
        digest: Prehash<'_, '_, Self, ()>,
        expected: &[u8],
        _: &W,
    ) -> Result<bool, Self::Error> {
        Ok(digest.as_bytes() == expected)
    }
}

#[test]
fn raw_zst_requires_explicit_nonzero_selection_before_state() {
    // A bare ZST has no distinct live instance address. Processing requires an
    // explicit stable session rather than guessing identity or rejecting its
    // cryptographic capability as unsupported.
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let mut identities = memory.vector();
    identities.try_push(()).unwrap();
    let provider = Stateless;
    let result = structured_cms::digest::DigestBatch::prepare(
        &provider, identities, &memory, "payload", 400,
    );
    let Err(structured_cms::digest::DigestError::Processing(error)) = result else {
        panic!("bare ZST is not a stable selection owner")
    };
    assert_eq!(error.code(), structured_cms::ErrorCode::ProviderMismatch);
    assert_eq!(error.offset(), 400);
    STARTS.with(|calls| assert_eq!(calls.get(), 0));
}

#[test]
fn distinct_zst_selections_keep_distinct_borrowed_identity() {
    // Raw ZST addresses coincide, so they cannot define distinct selection
    // identity. The session owner is nonzero and cannot move while borrowed.
    use structured_cms::{
        ErrorCode,
        binding::{self, BindError, DigestBinding},
        digest::DigestBatch,
    };
    let backends = [Stateless, Stateless];
    assert!(core::ptr::eq(
        core::ptr::from_ref(&backends[0]),
        core::ptr::from_ref(&backends[1])
    ));
    let sessions = [
        ProviderSession::new(Stateless),
        ProviderSession::new(Stateless),
    ];
    assert!(!sessions[0].same_session(&sessions[1]));
    assert!(sessions[0].same_session(&sessions[0]));
    let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
    let mut identities = memory.vector();
    identities.try_push(()).unwrap();
    let batch = DigestBatch::prepare(&sessions[0], identities, &memory, "payload", 400).unwrap();
    let mut source = [&b"source"[..]];
    let memo = batch.run(&mut source, &memory).unwrap();
    let digest = memo.for_request(0, &memory).unwrap().unwrap();
    let span = Span {
        start: 700,
        length: 1,
    };
    assert!(matches!(
        binding::matches_digest(
            &sessions[0],
            digest.prehash(),
            &[7],
            &memory,
            "imprint",
            span
        )
        .unwrap(),
        DigestBinding::Matches
    ));
    let BindError::Processing(error) = binding::matches_digest(
        &sessions[1],
        digest.prehash(),
        &[7],
        &memory,
        "imprint",
        span,
    )
    .unwrap_err() else {
        panic!("selection mismatch is processing misuse")
    };
    assert_eq!(error.code(), ErrorCode::ProviderMismatch);
    assert_eq!(error.offset(), 700);
}
