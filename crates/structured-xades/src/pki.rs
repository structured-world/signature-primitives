//! Countersignature signer paths for the common participant census.
//!
//! Path checking, revocation binding and the participant census itself are
//! format-neutral and live in [`structured_ltv::pki`]. This module associates
//! every incorporated `XMLDSig` countersignature with its signer's checked path
//! and presents that census to it.
//!
//! [`participants`] derives the [`Xades`] participant census from
//! this crate's own receipts. Another crate cannot derive one from receipts it
//! implements itself, such as a signer that reports an unrelated path:
//!
//! ```compile_fail
//! use structured_ltv::pki::{self, CheckedPath, SignerReceipt};
//! use structured_ltv::source::{Location, Query};
//! use structured_ltv::timestamp::TimestampPaths;
//! use structured_xades::{Xades, credential::ParticipantCredentials, pki::CounterPaths};
//!
//! struct Forged<N, D, G>(Location<N, D, G>, &'static CheckedPath<'static>);
//! impl<N: Copy, D: Copy, G: Copy> SignerReceipt<'static, 'static> for Forged<N, D, G> {
//!     type Id = N;
//!     type Document = D;
//!     type Generation = G;
//!     fn signature(&self) -> Location<N, D, G> {
//!         self.0
//!     }
//!     fn path(&self) -> Option<&'static CheckedPath<'static>> {
//!         Some(self.1)
//!     }
//! }
//!
//! fn forge<Q: Query>(
//!     signer: &'static Forged<Q::Id, Q::Document, Q::Generation>,
//!     counters: &'static CounterPaths<'static, 'static, Q::Id, Q::Document, Q::Generation>,
//!     credentials: &'static ParticipantCredentials<
//!         'static, 'static, (), Q::Id, Q::Document, Q::Generation,
//!     >,
//!     timestamps: &'static TimestampPaths<
//!         'static, 'static, 'static, Q::Id, Q::Document, Q::Generation, Xades,
//!     >,
//!     query: &Q,
//! ) {
//!     let _ = pki::participants(signer, counters, credentials, timestamps, query);
//! }
//! ```

use crate::{
    ISSUER, Xades, certificate::CheckedPathCertificate, credential::ParticipantCredentials,
};
use structured_ltv::pki::ParticipantResult;
use structured_ltv::source::Query;
use structured_ltv::timestamp::TimestampPaths;

mod counter;
pub use counter::{
    CounterActor, CounterBinding, CounterPath, CounterPathResult, CounterPaths, CounterPathsResult,
    CounterSelectionError, bind_counter, bind_counters,
};

/// The complete participant census of one validation-data scope, derived by
/// [`structured_ltv::pki::participants`] from this crate's checked signer,
/// complete counter census and authenticated credentials.
///
/// # Errors
///
/// Every refusal of [`structured_ltv::pki::participants`]: inputs of another
/// signature or generation, an unproven signer, timestamp obligations without
/// the counter census, incomplete credential authorities and resource refusal.
pub fn participants<'path, 'document, E, Q: Query>(
    signer: &'path CheckedPathCertificate<'path, 'document, Q::Id, Q::Document, Q::Generation>,
    counters: &'path CounterPaths<'path, 'document, Q::Id, Q::Document, Q::Generation>,
    credentials: &'path ParticipantCredentials<
        'path,
        'document,
        E,
        Q::Id,
        Q::Document,
        Q::Generation,
    >,
    timestamps: &'path TimestampPaths<
        'path,
        '_,
        'document,
        Q::Id,
        Q::Document,
        Q::Generation,
        Xades,
    >,
    query: &Q,
) -> ParticipantResult<'path, 'document, Q, Xades> {
    structured_ltv::pki::participants(ISSUER, signer, counters, credentials, timestamps, query)
}
