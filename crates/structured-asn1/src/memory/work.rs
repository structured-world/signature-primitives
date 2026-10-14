//! Borrowed parser execution for transitive scratch work.

use super::{HashWork, Memory, MemoryError, OwnedMap, OwnedVec, allocator};
use crate::limits::BudgetView;

mod private {
    pub trait Sealed {}
}

/// An execution domain used by accounted collections and schema processing.
///
/// [`Memory`] owns an independent aggregate domain. [`Execution`] additionally
/// borrows a parser's cumulative ceiling. The sealed implementations ensure
/// that allocator and collection admission cannot bypass either boundary.
pub trait Work: Clone + private::Sealed {
    /// Storage ownership retained by the allocator independently of borrowed work.
    type Retained: core::fmt::Debug;

    /// Keeps an allocation's account alive even if its collection is forgotten.
    /// Owned [`Memory`] already holds that account; borrowed [`Execution`]
    /// supplies one owning handle per collection without allocating a new account.
    fn retain_storage(&self) -> Self::Retained;

    /// Moves the existing account owner when finishing independently owned storage.
    /// The sealed implementations preserve the account without cloning it.
    fn into_storage_owner(self, retained: Self::Retained) -> Memory;

    /// Attaches current work while moving an existing same-account owner.
    /// The caller verifies account identity before transferring storage.
    fn with_storage_owner(&self, memory: Memory) -> (Self, Self::Retained);

    /// The account retaining allocated capacity.
    fn memory(&self) -> &Memory;

    /// Admits work before execution, against every applicable ceiling.
    fn charge_work(&self, amount: u64) -> Result<(), MemoryError>;

    /// Creates empty accounted scratch retaining this execution boundary.
    ///
    /// No allocation occurs until a fallible growth operation. A collection
    /// borrowing [`Execution`] cannot outlive that parser or execution account.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::{Parser, memory::{Memory, MemoryAccount, Work}};
    /// let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1024, 1024))));
    /// let reader = parser.read(&[], 0).unwrap();
    /// let mut scratch = reader.execution().vector();
    /// scratch.try_push(42_u8)?;
    /// assert_eq!(&*scratch, &[42]);
    /// # Ok::<(), structured_asn1::memory::MemoryError>(())
    /// ```
    #[must_use]
    fn vector<T>(&self) -> OwnedVec<T, Self> {
        OwnedVec {
            values: allocator_api2::vec::Vec::new_in(allocator::AccountAllocator::new(
                self.clone(),
            )),
        }
    }

    /// Creates a bounded scratch map in this storage and execution domain.
    /// Hash/probes, table growth and value movement retain the same ceilings.
    #[must_use]
    fn map<K: HashWork, V>(&self) -> OwnedMap<K, V, Self> {
        OwnedMap::new(self.clone())
    }
}

impl private::Sealed for Memory {}

impl Work for Memory {
    type Retained = ();

    fn retain_storage(&self) {}

    fn into_storage_owner(self, (): ()) -> Memory {
        self
    }

    fn with_storage_owner(&self, memory: Memory) -> (Self, ()) {
        (memory, ())
    }

    fn memory(&self) -> &Memory {
        self
    }

    fn charge_work(&self, amount: u64) -> Result<(), MemoryError> {
        Memory::charge_work(self, amount)
    }
}

/// A borrowed aggregate account and original parser-session work ceiling.
///
/// Obtain this from [`crate::Reader::execution`]. Copies allocate nothing and
/// acquire no shared ownership. Scratch storage and work use the reader's
/// current account; rebinding the account never resets the parser ceiling.
///
/// A parser-bound allocation cannot survive its borrowed owner:
///
/// ```compile_fail
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount, Work}};
/// let mut scratch;
/// {
///     let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1024, 1024))));
///     let reader = parser.read(&[], 0).unwrap();
///     scratch = reader.execution().vector();
///     scratch.try_push(42_u8).unwrap();
/// }
/// drop(scratch);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Execution<'a> {
    memory: &'a Memory,
    budget: BudgetView<'a>,
}

impl<'a> Execution<'a> {
    pub(crate) fn new(memory: &'a Memory, budget: BudgetView<'a>) -> Self {
        Self { memory, budget }
    }
}

impl private::Sealed for Execution<'_> {}

impl Work for Execution<'_> {
    type Retained = Memory;

    fn retain_storage(&self) -> Memory {
        self.memory.clone()
    }

    fn into_storage_owner(self, retained: Memory) -> Memory {
        retained
    }

    fn with_storage_owner(&self, memory: Memory) -> (Self, Memory) {
        (*self, memory)
    }

    fn memory(&self) -> &Memory {
        self.memory
    }

    fn charge_work(&self, amount: u64) -> Result<(), MemoryError> {
        self.budget
            .work_in(amount, self.memory)
            .map_err(|_| MemoryError::WorkExceeded)
    }
}
