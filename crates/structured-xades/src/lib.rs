#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate alloc;

pub mod attributes;
pub mod baseline;
pub mod binary;
pub mod binding;
pub mod certificate;
pub mod commitment;
pub mod container;
pub mod counter;
pub mod credential;
pub mod digest;
pub mod format;
pub mod hashes;
pub mod header;
pub mod identifier;
pub mod material;
mod mime;
pub mod pki;
pub mod policy;
pub mod prepare;
pub mod properties;
pub mod reference;
pub mod renewed;
pub mod role;
pub mod scalar;
pub mod timestamp;
pub mod unsigned;
pub mod validation;
pub mod xml;

/// Issuer of the long-term validation receipts this crate builds from its own
/// checks: timestamp evidence and its signer, archive coverage, the token
/// census, the material index and the participant census
/// ([`pki::participants`]). Only this crate constructs it, so a caller
/// cannot relabel evidence or supply a fabricated receipt to these APIs.
///
/// ```compile_fail
/// let issuer = structured_xades::Xades(());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Xades(());

/// The value this crate passes when it builds a receipt.
pub(crate) const ISSUER: Xades = Xades(());
