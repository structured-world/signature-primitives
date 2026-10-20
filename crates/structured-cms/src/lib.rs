//! CMS `SignedData` mechanisms over original ASN.1 ranges and explicit execution.
//!
//! Content acquisition, cryptographic engines, trust policy and application
//! verdicts belong to the caller. This crate performs no implicit I/O.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod archive;
pub mod attribute;
pub mod binding;
pub mod cades;
pub mod content;
pub mod content_source;
pub mod counter;
pub mod digest;
pub mod directory;
pub mod error;
pub mod ess;
pub mod octets;
pub mod oid;
pub mod payload;
pub mod prepare;
pub mod provider;
pub mod signed;
pub mod signer;
pub mod stream;
pub mod timestamp;
pub mod verify;

pub use content::{ContentInfo, Encapsulated};
pub use error::{Error, ErrorCode, Result};
pub use octets::{Octets, Piece};
pub use signed::SignedData;
