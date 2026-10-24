//! Original `ASiC` member identity, container conformance and signature facts.
//!
//! Acquisition belongs to the caller. No filesystem extraction, implicit
//! network access or trust policy is performed by this crate.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod archive;
pub mod cades;
pub mod content;
pub mod error;
pub mod evidence;
pub mod layout;
pub mod manifest;
pub mod material;
pub mod media;
pub mod package;
pub mod payload;
pub mod references;
pub mod session;
pub mod source;
pub mod timestamp;
pub mod uri;
pub mod xml;
pub mod zip;

pub use session::{Limits, Session};

/// Issuer of source-derived `ASiC` facts in the common LTV identity domain.
#[derive(Debug, Clone, Copy)]
pub struct Asic(());
pub(crate) const ISSUER: Asic = Asic(());
