//! What the caller is willing to spend on one parse.
//!
//! These bound work rather than document size: a fixed ceiling refuses real
//! documents while a hostile input stays under it. Each is checked before the
//! work it guards.

use core::cell::Cell;

use crate::error::Limit;
use crate::memory::Memory;

/// How much a parse may spend.
///
/// The defaults are generous, because they exist to stop a document that is
/// trying to make this run forever, not to decide that real documents are too
/// big. A caller on a device with less to spend lowers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How deeply elements may nest.
    ///
    /// Certificates and signed data nest perhaps a dozen deep. A thousand is a
    /// document doing something else.
    pub max_depth: u32,

    /// How many elements may be read in total.
    pub max_elements: u64,

    /// How long a single element's contents may be.
    pub max_element_length: u64,

    /// How many bytes of header and structure may be examined.
    ///
    /// Content bytes are not counted against this: reading a large certificate
    /// is not the thing worth stopping. What this bounds is the number of
    /// elements-worth of parsing a document can ask for, which is what a deeply
    /// or densely nested input inflates.
    pub max_work: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 1_000,
            max_elements: 1_000_000,
            max_element_length: 1 << 32,
            max_work: 16_000_000,
        }
    }
}

impl Limits {
    /// Limits that allow nothing beyond a single shallow element, for tests
    /// and for callers that want to prove a budget is enforced.
    #[must_use]
    pub fn none() -> Self {
        Self {
            max_depth: 0,
            max_elements: 0,
            max_element_length: 0,
            max_work: 0,
        }
    }
}

/// What has been spent so far, against what was allowed.
///
/// The counters are cells so that a reader entered from another reader shares
/// one budget rather than each getting a fresh one. A per-container budget
/// would bound nothing: a document could ask for any amount of work by asking
/// for a little in each of many containers.
#[derive(Debug)]
pub(crate) struct Budget {
    limits: Limits,
    elements: Cell<u64>,
    work: Cell<u64>,
    memory: Memory,
}

impl Budget {
    pub(crate) fn new(limits: Limits, memory: Memory) -> Self {
        Self {
            limits,
            elements: Cell::new(0),
            work: Cell::new(0),
            memory,
        }
    }

    pub(crate) fn limits(&self) -> Limits {
        self.limits
    }

    pub(crate) fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Charges for one element about to be read, before reading it.
    ///
    /// Reports which budget ran out and nothing else: where it happened is
    /// known to the caller, who assembles that only when there is an error.
    pub(crate) fn element(&self) -> Result<(), Limit> {
        let spent = self.elements.get();
        debug_assert!(spent <= self.limits.max_elements);
        if spent >= self.limits.max_elements {
            return Err(Limit::Elements);
        }
        self.elements.set(spent + 1);
        Ok(())
    }

    /// Charges structure in the original domain for budget unit tests.
    #[cfg(test)]
    pub(crate) fn work(&self, amount: u64) -> Result<(), Limit> {
        self.work_in(amount, &self.memory)
    }

    /// Retains the session ceiling while charging the current execution domain.
    pub(crate) fn work_in(&self, amount: u64, execution: &Memory) -> Result<(), Limit> {
        let spent = self.work.get();
        debug_assert!(spent <= self.limits.max_work);
        if amount > self.limits.max_work - spent {
            return Err(Limit::Work);
        }
        execution.charge_work(amount).map_err(|_| Limit::Work)?;
        self.work.set(spent + amount);
        Ok(())
    }

    /// Checks a depth before descending to it.
    pub(crate) fn depth(&self, depth: u32) -> Result<(), Limit> {
        if depth > self.limits.max_depth {
            return Err(Limit::Depth);
        }
        Ok(())
    }

    /// Checks a stated length before trusting it enough to slice with.
    pub(crate) fn length(&self, length: u64) -> Result<(), Limit> {
        if length > self.limits.max_element_length {
            return Err(Limit::ElementLength);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
