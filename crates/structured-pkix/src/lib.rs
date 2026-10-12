//! Certificates, read into a model that keeps what a decision needs.
//!
//! A certificate is read once and kept as it arrived: every field borrows the
//! document, and the bytes a signature is computed over are handed back as the
//! range they occupy rather than re-encoded from what was understood. A parser
//! that re-encodes has decided that its own understanding is the document, and
//! a signature checked over that says nothing about the file somebody was sent.
//!
//! Two kinds of fault are kept apart, because they lead to different answers.
//!
//! What cannot be represented honestly is refused: an unreadable encoding, a
//! field the certificate's own version says is not there, two copies of one
//! extension with no way to say which applies, or an algorithm named outside
//! the signed bytes that differs from the one named inside them.
//!
//! What can be represented is reported rather than refused, even when it is
//! wrong: a negative serial number, a validity interval that ends before it
//! starts, a critical extension nobody here knows. Refusing those would leave
//! the product unable to explain a document a person is holding, and
//! explaining is the product.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod fixtures;

#[cfg(test)]
mod revocation_tests;

pub mod access;
pub mod algorithm;
pub mod certificate;
pub mod constraints;
pub mod crl;
pub mod der;
pub mod error;
pub mod extension;
pub mod general_name;
pub mod identifier;
pub mod key;
pub mod name;
pub mod ocsp;
pub mod oid;
pub mod path;
pub mod policy;
pub mod qualified;
pub mod temporal;
pub mod time;
pub mod usage;

pub use algorithm::AlgorithmIdentifier;
pub use certificate::{Certificate, TbsCertificate, Validity, Version};
pub use error::{Error, ErrorCode, Result};
pub use extension::{Extension, Extensions, Recognizer};
pub use key::PublicKeyInfo;
pub use name::{Attribute, Name, Ordered};
pub use time::Time;
