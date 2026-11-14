//! CMS signatures, digital envelopes and timestamps over original ASN.1 ranges.
//!
//! Format processing uses caller-provided engines. The optional HMAC module
//! supplies a standalone MAC primitive. This crate performs no implicit I/O.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod archive;
pub mod attribute;
pub mod attribute_certificate;
pub mod binding;
pub mod cades;
#[cfg(any(feature = "openssl", feature = "password-protection"))]
mod cbc;
pub mod content;
pub mod content_source;
pub mod counter;
pub mod digest;
pub mod directory;
pub mod encoding;
pub mod enveloped;
pub mod error;
pub mod ess;
pub mod evidence;
#[cfg(feature = "hmac")]
pub use structured_asn1::hmac;
pub mod mime;
pub mod octets;
pub mod oid;
#[cfg(feature = "openssl")]
pub mod openssl;
pub mod payload;
pub mod personal;
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
