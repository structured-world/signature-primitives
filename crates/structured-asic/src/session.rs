//! One original `ASiC` source budget and cumulative decode allowance.

use crate::error::{Error, Limit};
use core::cell::Cell;
use structured_asn1::{
    Encoding, Parser, Span,
    memory::{Execution, Memory, Work},
};

/// Caller-selected mechanism bounds, independent of signature/trust policy.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Shared original source and carried ASN.1 work/depth ceilings.
    pub processing: structured_asn1::Limits,
    /// Cumulative original member admissions.
    pub max_entries: u64,
    /// Cumulative decoded output, independent of live scratch capacity.
    pub max_decoded: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            processing: structured_asn1::Limits::default(),
            max_entries: 1_000_000,
            max_decoded: 64 * 1024 * 1024,
        }
    }
}

/// Caller-owned original execution. ZIP input is not parsed as ASN.1; the
/// shared parser supplies one budget for ZIP, carried CMS and PKIX operations.
pub struct Session {
    parser: Parser,
    limits: Limits,
    entries: Cell<u64>,
    decoded: Cell<u64>,
}
impl Session {
    /// Constructs trusted state without allocation or source acquisition.
    #[must_use]
    pub fn new(limits: Limits, memory: Memory) -> Self {
        Self {
            parser: Parser::new(Encoding::Der, limits.processing, memory),
            limits,
            entries: Cell::new(0),
            decoded: Cell::new(0),
        }
    }
    /// Original mechanism ceilings, without mutable policy discovery.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// Original source work, without a new cursor or account owner.
    #[must_use]
    pub fn execution(&self) -> Execution<'_> {
        self.parser.execution_in(self.parser.memory())
    }
    /// Preserves this original source AND the current root-operation ceiling.
    #[must_use]
    pub fn query<'q, W: Work>(&'q self, work: &'q W) -> Execution<'q> {
        work.execution_for(&self.parser)
    }
    pub(crate) fn carried<'q, W: Work + 'q>(
        &'q self,
        bytes: &'q [u8],
        work: &W,
    ) -> structured_asn1::Result<structured_asn1::Reader<'q>> {
        work.read_source(&self.parser, bytes, 0, Encoding::Ber, 0)
    }
    pub(crate) fn owns(&self, reader: &structured_asn1::Reader<'_>) -> bool {
        core::ptr::eq(core::ptr::from_ref(&self.parser), reader.parser())
    }
    pub(crate) fn entries<E>(&self, count: u64, range: Span) -> Result<(), Error<E>> {
        Self::admit(
            &self.entries,
            count,
            self.limits.max_entries,
            range,
            Limit::Entries,
        )
    }
    pub(crate) fn remaining(&self) -> u64 {
        self.limits.max_decoded - self.decoded.get()
    }
    pub(crate) fn decode<E>(&self, count: u64, range: Span) -> Result<(), Error<E>> {
        Self::admit(
            &self.decoded,
            count,
            self.limits.max_decoded,
            range,
            Limit::Decoded,
        )
    }
    fn admit<E>(
        counter: &Cell<u64>,
        count: u64,
        maximum: u64,
        range: Span,
        kind: Limit,
    ) -> Result<(), Error<E>> {
        let used = counter.get();
        debug_assert!(used <= maximum);
        if count > maximum - used {
            return Err(Error::Limit { range, kind });
        }
        counter.set(used + count);
        Ok(())
    }
}
