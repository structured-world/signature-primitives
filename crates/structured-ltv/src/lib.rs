//! Format-neutral long-term signature validation facts.
//!
//! EN 319 102-1 defines path validation at a time, revocation material bound
//! to path members, timestamp generation intervals and the coverage of
//! validation material by archive timestamps once for every `AdES` format. This
//! crate implements those facts over `structured-pkix` and `structured-cms`
//! processors and the caller's [`source::Query`]; `XAdES`, `CAdES` and `PAdES`
//! layers say only where the material and timestamps were written. No XML or PDF type
//! crosses it, and no fact is a trust verdict.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod material;
pub mod pki;
pub mod source;
pub mod timestamp;
