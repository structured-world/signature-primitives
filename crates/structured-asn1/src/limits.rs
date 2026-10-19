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

    /// Cumulative parser and explicitly attached schema work units.
    ///
    /// Header scanning, nested-reader paths and diagnostic copying share this
    /// ceiling. Borrowed payload views do not scan their contents. Explicit
    /// [`crate::Reader::charge`] and [`crate::Reader::execution`] additionally
    /// attach schema scans and scratch to the same cumulative session; rebinding
    /// the aggregate account does not reset it.
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

/// One source ceiling and the current operation ceiling, with one account bill.
/// Foreign-source transitions replace the source, never the operation owner.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BudgetView<'a> {
    origin: &'a Budget,
    operation: Option<&'a Budget>,
}

impl<'a> BudgetView<'a> {
    pub(crate) const fn root(origin: &'a Budget) -> Self {
        Self {
            origin,
            operation: None,
        }
    }
    pub(crate) fn query(origin: &'a Budget, operation: &'a Budget) -> Self {
        Self {
            origin,
            operation: if core::ptr::eq(origin, operation) {
                None
            } else {
                Some(operation)
            },
        }
    }
    pub(crate) fn operation(self) -> &'a Budget {
        self.operation.unwrap_or(self.origin)
    }
    pub(crate) fn work_in(self, amount: u64, execution: &Memory) -> Result<(), Limit> {
        if amount > self.origin.limits.max_work - self.origin.work.get() {
            return Err(Limit::Work);
        }
        if let Some(operation) = self.operation
            && amount > operation.limits.max_work - operation.work.get()
        {
            return Err(Limit::Work);
        }
        execution.charge_work(amount).map_err(|_| Limit::Work)?;
        self.origin.work.set(self.origin.work.get() + amount);
        if let Some(operation) = self.operation {
            operation.work.set(operation.work.get() + amount);
        }
        Ok(())
    }
    /// The largest amount both local ceilings of [`Self::work_in`] admit now.
    pub(crate) fn work_remaining(self) -> u64 {
        let origin = self.origin.limits.max_work - self.origin.work.get();
        match self.operation {
            Some(operation) => origin.min(operation.limits.max_work - operation.work.get()),
            None => origin,
        }
    }
    pub(crate) fn local_work(self, amount: u64) -> Result<(), Limit> {
        if amount > self.origin.limits.max_work - self.origin.work.get() {
            return Err(Limit::Work);
        }
        if let Some(operation) = self.operation
            && amount > operation.limits.max_work - operation.work.get()
        {
            return Err(Limit::Work);
        }
        self.origin.work.set(self.origin.work.get() + amount);
        if let Some(operation) = self.operation {
            operation.work.set(operation.work.get() + amount);
        }
        Ok(())
    }
    pub(crate) fn element(self) -> Result<(), Limit> {
        if self.origin.elements.get() >= self.origin.limits.max_elements {
            return Err(Limit::Elements);
        }
        if let Some(operation) = self.operation
            && operation.elements.get() >= operation.limits.max_elements
        {
            return Err(Limit::Elements);
        }
        self.origin.elements.set(self.origin.elements.get() + 1);
        if let Some(operation) = self.operation {
            operation.elements.set(operation.elements.get() + 1);
        }
        Ok(())
    }
    pub(crate) fn depth(self, depth: u32) -> Result<(), Limit> {
        self.origin.depth(depth)?;
        if let Some(operation) = self.operation {
            operation.depth(depth)?;
        }
        Ok(())
    }
    pub(crate) fn length(self, length: u64) -> Result<(), Limit> {
        self.origin.length(length)?;
        if let Some(operation) = self.operation {
            operation.length(length)?;
        }
        Ok(())
    }
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
    #[cfg(test)]
    pub(crate) fn element(&self) -> Result<(), Limit> {
        BudgetView::root(self).element()
    }

    /// Charges structure in the original domain for budget unit tests.
    #[cfg(test)]
    pub(crate) fn work(&self, amount: u64) -> Result<(), Limit> {
        BudgetView::root(self).work_in(amount, &self.memory)
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
