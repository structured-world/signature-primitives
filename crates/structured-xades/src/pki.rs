//! Countersignature signer paths for the common participant census.
//!
//! Path checking, revocation binding and the participant census itself are
//! format-neutral and live in [`structured_ltv::pki`]. This module associates
//! every incorporated `XMLDSig` countersignature with its signer's checked path
//! and presents that census to it.

mod counter;
pub use counter::{
    CounterActor, CounterBinding, CounterPath, CounterPathResult, CounterPaths, CounterPathsResult,
    CounterSelectionError, bind_counter, bind_counters,
};
