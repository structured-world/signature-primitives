//! A streaming BER/DER reader for the certificate, CMS and timestamp parsers.
//!
//! What this is for, and what it deliberately is not: it reads the structure of
//! an encoding and hands back the bytes each element occupies. It does not
//! decide what those elements mean. A schema layer above does that, and keeping
//! the two apart is what lets a signature be checked over the bytes as they
//! arrived rather than over a re-encoding of what somebody understood.
//!
//! Three things shape the design.
//!
//! Nothing is copied. Elements borrow from the document and carry the range
//! they occupy in it, so a caller holding one gigabyte does not become a caller
//! holding two.
//!
//! Nothing recurses. Depth is bounded by a budget the caller sets, not by the
//! thread's stack, so a deeply nested document is refused rather than fatal.
//!
//! A refusal to finish is not a verdict about the document. Running out of
//! budget reports [`ErrorCode::LimitExceeded`], which is distinct from every
//! code that says the bytes are malformed, because telling somebody their
//! document is broken when the truth is that this device gave up is a different
//! statement and a worse one.
//!
//! ```
//! use std::sync::Arc;
//! use structured_asn1::{Parser, Tag, universal};
//! use structured_asn1::memory::{Memory, MemoryAccount};
//!
//! // SEQUENCE { INTEGER 1 }
//! let document = [0x30, 0x03, 0x02, 0x01, 0x01];
//!
//! let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
//! let parser = Parser::der(memory);
//! let mut reader = parser.read(&document, 0)?;
//!
//! let sequence = reader.expect(Tag::constructed(universal::SEQUENCE))?;
//! let mut inside = reader.enter(&sequence)?;
//!
//! let integer = inside.expect(Tag::primitive(universal::INTEGER))?;
//! assert_eq!(integer.contents(), &[0x01]);
//!
//! // The range the value occupies in the document, for a signature to cover.
//! assert_eq!(integer.span().start, 2);
//! assert_eq!(integer.span().length, 3);
//! # Ok::<(), structured_asn1::Error>(())
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod digest;
pub mod error;
pub mod length;
pub mod limits;
pub mod memory;
pub mod reader;
pub mod tag;
pub mod value;

pub use error::{Error, ErrorCode, Limit, Path, Result};
pub use length::{Encoding, Length};
pub use limits::Limits;
pub use reader::{Element, IntegerReading, Parser, Reader, ScopedReader, Span};
pub use tag::{Class, Tag, universal};
pub use value::{Arcs, BitString, Integer, Oid, OwnedOid};

#[cfg(test)]
pub(crate) fn test_memory() -> memory::Memory {
    // Trusted test setup: isolate per-parser limits in existing encoding tests.
    memory::Memory::new(alloc::sync::Arc::new(memory::MemoryAccount::new(
        256 * 1024 * 1024,
        1_000_000_000,
    )))
}
