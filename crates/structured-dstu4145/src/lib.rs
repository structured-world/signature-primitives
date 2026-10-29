//! Verification-only DSTU 4145 arithmetic and Ukrainian streaming hashes.
//!
//! Public values use bounded, caller-owned storage. There is no private-key
//! operation, implicit randomness, provider selection or operating-system I/O.
#![no_std]

#[cfg(test)]
extern crate std;

mod curve;
pub mod domain;
mod domains;
mod error;
mod field;
pub mod validation;
mod words;

pub mod accounted;
pub mod gost;
pub mod hash;

pub use error::Error;
pub use structured_pkix::algorithm::dstu4145::{Basis, ByteOrder};

/// Largest field degree in tables 1 and 2 of DSTU 4145-2002.
pub const MAX_DEGREE: usize = 509;

#[cfg(test)]
mod tests;
