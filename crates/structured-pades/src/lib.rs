//! Original-source PDF signature processing.
//!
//! Source locations distinguish physical file bytes from decoded object-stream
//! coordinates. Document-driven processing uses the shared allocation and work
//! account; a processing refusal is never a negative conformance predicate.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
mod arena;
pub mod baseline;
pub mod basic;
mod binding;
mod byte_machine;
pub mod container;
pub mod credential;
pub mod date;
mod dictionary;
mod direct;
pub mod document;
pub mod fields;
pub mod material;
mod model;
pub mod permissions;
pub mod prepare;
pub mod query;
pub mod signature;
mod stream;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
mod text;
pub mod timestamp;
mod xref;

pub mod bytes;
pub mod error;
pub mod object;
pub mod range;
pub mod session;
pub mod source;
pub mod syntax;

pub use error::{Error, ErrorKind, Result};
pub use session::{Limits, Session};
