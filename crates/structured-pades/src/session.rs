//! Trusted source-session setup and the shared original/current work boundary.

use crate::error::{Error, ErrorKind, Limit, Result};
use crate::source::Location;
use core::cell::Cell;
use structured_asn1::memory::{Execution, Memory, Work};
use structured_asn1::{Encoding, Parser};

/// Caller-selected mechanism ceilings. These do not select algorithm trust,
/// document permissions or a `PAdES` acceptance policy.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Shared source work and ASN.1 limits for carried CMS/PKIX material. PDF
    /// container nesting also obeys this setup's maximum depth.
    pub processing: structured_asn1::Limits,
    /// Maximum cumulative PDF object admissions.
    pub max_objects: u64,
    /// Maximum cumulative PDF revision admissions.
    pub max_revisions: u32,
    /// Maximum cumulative decoded stream output, independently of live capacity.
    pub max_decoded: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            processing: structured_asn1::Limits::default(),
            max_objects: 500_000,
            max_revisions: 1_000,
            max_decoded: 64 * 1024 * 1024,
        }
    }
}

/// Caller-owned lifetime of one PDF source session and its original work
/// ceiling. The existing shared parser owns the same execution boundary used
/// by genuinely carried DER CMS/PKIX values; PDF bytes are not parsed as ASN.1.
/// Source and current-operation work compose through the existing shared
/// execution kernel, without another account, reset or allocator wrapper.
pub struct Session {
    parser: Parser,
    limits: Limits,
    objects: Cell<u64>,
    revisions: Cell<u64>,
    decoded: Cell<u64>,
}

impl Session {
    /// Constructs trusted session state without allocation or source traversal.
    #[must_use]
    pub fn new(limits: Limits, memory: Memory) -> Self {
        Self {
            parser: Parser::new(Encoding::Der, limits.processing, memory),
            limits,
            objects: Cell::new(0),
            revisions: Cell::new(0),
            decoded: Cell::new(0),
        }
    }

    /// Immutable caller-selected mechanism ceilings.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Original source work and allocation account, without a new cursor or
    /// account-owner clone. Every data-dependent operation must admit work.
    #[must_use]
    pub fn execution(&self) -> Execution<'_> {
        self.parser.execution_in(self.parser.memory())
    }

    /// Attaches the current operation while retaining the original source
    /// ceiling. Cross-source queries preserve the original root operation;
    /// sharing an account does not exempt either ceiling.
    #[must_use]
    pub fn query<'a, W: Work>(&'a self, operation: &'a W) -> Execution<'a> {
        operation.execution_for(&self.parser)
    }

    pub(crate) fn carried<'a, W: Work + 'a>(
        &'a self,
        bytes: &'a [u8],
        operation: &W,
    ) -> structured_asn1::Result<structured_asn1::Reader<'a>> {
        operation.read_source(&self.parser, bytes, 0, Encoding::Der, 0)
    }

    pub(crate) fn owns(&self, reader: &structured_asn1::Reader<'_>) -> bool {
        core::ptr::eq(core::ptr::from_ref(&self.parser), reader.parser())
    }

    pub(crate) fn decoded_remaining(&self) -> u64 {
        self.limits.max_decoded - self.decoded.get()
    }

    /// Counts an object before parsing or allocating its representation.
    pub fn object(&self, location: Location) -> Result<()> {
        Self::admit(
            &self.objects,
            1,
            self.limits.max_objects,
            Limit::Objects,
            location,
        )
    }

    /// Counts a revision before traversing its cross-reference section.
    pub fn revision(&self, location: Location) -> Result<()> {
        Self::admit(
            &self.revisions,
            1,
            u64::from(self.limits.max_revisions),
            Limit::Revisions,
            location,
        )
    }

    /// Counts potential decoded output before running a decoder. This output
    /// allowance is cumulative; discarding storage never refunds completed work.
    pub fn decode(&self, amount: u64, location: Location) -> Result<()> {
        Self::admit(
            &self.decoded,
            amount,
            self.limits.max_decoded,
            Limit::Decoded,
            location,
        )
    }

    fn admit(
        counter: &Cell<u64>,
        amount: u64,
        ceiling: u64,
        limit: Limit,
        location: Location,
    ) -> Result<()> {
        let spent = counter.get();
        debug_assert!(spent <= ceiling);
        if amount > ceiling - spent {
            return Err(Error {
                kind: ErrorKind::Limit(limit),
                location,
            });
        }
        counter.set(spent + amount);
        Ok(())
    }
}
