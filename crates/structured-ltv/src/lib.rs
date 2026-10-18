//! Format-neutral long-term signature validation facts.
//!
//! EN 319 102-1 defines path validation at a time, revocation material bound
//! to path members, timestamp generation intervals and the coverage of
//! validation material by archive timestamps once for every `AdES` format. This
//! crate implements those facts over `structured-pkix` and `structured-cms`
//! processors and the caller's [`source::Query`]; `XAdES`, `CAdES` and `PAdES`
//! layers say only where the material and timestamps were written. No XML or PDF type
//! crosses it, and no fact is a trust verdict.
//!
//! - [`source`]: the document owner's identities and the current query.
//! - [`timestamp`]: retained token checks, generation intervals, signature-time
//!   association and the complete token obligations of one scope.
//! - [`pki`]: actor paths, status binding, the authority closure and the
//!   participant census derived from the format's receipts.
//! - [`material`]: incorporated artifacts, their uses and archive coverage.
//! - [`baseline`]: compositions over the format's stage reports.
//!
//! # Examples
//!
//! A document owner implements [`source::Source`] over its own identities; the
//! [`source::Scope`] of one operation then funds every check and refuses a
//! rewritten document.
//!
//! ```
//! use core::cell::Cell;
//! use std::sync::Arc;
//! use structured_asn1::memory::{Memory, MemoryAccount};
//! use structured_ltv::material::Coverage;
//! use structured_ltv::source::{Query, Scope, ScopeError, Snapshot, Source};
//! use structured_ltv::timestamp::Purpose;
//!
//! // A CMS signature whose unsigned attributes are identified by ordinal.
//! struct SignerInfo {
//!     generation: Cell<u8>,
//! }
//! impl Source for SignerInfo {
//!     type Id = usize;
//!     type Document = u8;
//!     type Generation = u8;
//!     fn snapshot(&self) -> Snapshot<u8, u8> {
//!         Snapshot { document: 1, generation: self.generation.get() }
//!     }
//! }
//!
//! let source = SignerInfo { generation: Cell::new(1) };
//! let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 10_000)));
//! let query = Scope::new(&source, source.snapshot(), &memory);
//! // Attribute 3 lies in archive attribute 5's input; attribute 7 does not.
//! let mut items = memory.map();
//! items.try_insert(3, true).unwrap();
//! let coverage = Coverage::new(source.snapshot(), 0, 5, Purpose::Archive, items);
//! assert_eq!(coverage.selects(3, &query), Ok(true));
//! assert_eq!(coverage.selects(7, &query), Ok(false));
//! source.generation.set(2);
//! assert_eq!(query.admit(3, 1), Err(ScopeError::Changed { node: 3 }));
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod baseline;
pub mod material;
pub mod pki;
pub mod source;
pub mod timestamp;
