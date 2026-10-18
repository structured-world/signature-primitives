//! Nonzero selected-session provenance for genuinely zero-sized adapters.

use core::cmp::Ordering;
use std::sync::Arc;
use structured_asn1::{
    Span,
    digest::{Digest, Resolution},
    memory::{Memory, MemoryAccount, Work},
};
use structured_cms::provider::ProviderSession;

struct Stateless;
std::thread_local! { static STARTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) }; }
impl Digest<'_> for Stateless {
    type Identity = ();
    type State = ();
    type Output = [u8; 1];
    type Error = core::convert::Infallible;
    fn width(&self, (): &()) -> Option<usize> {
        Some(1)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), _: &W) -> Result<Ordering, Self::Error> {
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), _: &W) -> Result<Resolution<()>, Self::Error> {
        STARTS.with(|calls| calls.set(calls.get() + 1));
        Ok(Resolution::Supported(()))
    }
    fn update<W: Work>(&self, (): &mut (), _: &[u8], _: &W) -> Result<(), Self::Error> {
        Ok(())
    }
    fn finish<W: Work>(&self, (): (), _: &W) -> Result<[u8; 1], Self::Error> {
        Ok([7])
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &[u8; 1],
        expected: &[u8],
        _: &W,
    ) -> Result<bool, Self::Error> {
        Ok(output.as_slice() == expected)
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
            digest.finished(),
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
        digest.finished(),
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
