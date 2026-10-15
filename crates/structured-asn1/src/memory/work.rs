//! Borrowed parser execution for transitive scratch work.

use super::{HashWork, Memory, MemoryError, OwnedMap, OwnedVec, allocator};
use crate::limits::BudgetView;
use crate::{Encoding, Parser, Reader, ScopedReader};

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

    /// Opens original input while borrowing this operation only for decoding.
    /// Parsed elements and scalar views retain the longer original input
    /// lifetime; no result needs to keep a completed operation alive merely
    /// because it borrows input. Source and current ceilings still apply to
    /// every read, scratch allocation and copy before that work.
    /// A cursor itself cannot escape a local operation:
    ///
    /// ```compile_fail
    /// use structured_asn1::{Encoding, Parser, ScopedReader, memory::Work};
    /// fn escape<'source>(source: &'source Parser, data: &'source [u8])
    ///     -> ScopedReader<'source, 'source>
    /// {
    ///     let operation = Parser::der(source.memory().clone());
    ///     let query = operation.read(&[], 900).unwrap();
    ///     let execution = query.execution();
    ///     execution.read_scoped_source(source, data, 400, Encoding::Der, 0).unwrap()
    /// }
    /// ```
    fn read_scoped_source<'source: 'operation, 'operation>(
        &'operation self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        depth: u32,
    ) -> crate::Result<ScopedReader<'source, 'operation>>;

    /// Nested form of [`Work::read_scoped_source`], retaining actual outer+1
    /// depth. Only decoding borrows this operation; returned input views do not.
    fn read_scoped_nested<'source: 'operation, 'operation>(
        &'operation self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        outer: u32,
    ) -> crate::Result<ScopedReader<'source, 'operation>> {
        let depth = outer.checked_add(1).ok_or_else(|| {
            crate::Error::new(
                crate::ErrorCode::LimitExceeded(crate::Limit::Depth),
                base,
                crate::Path::default(),
            )
        })?;
        self.read_scoped_source(parser, data, base, encoding, depth)
    }

    /// Opens original nested bytes without discarding this execution boundary.
    /// Memory retains its existing source-plus-aggregate admission; Execution
    /// additionally preserves the current root operation before any decode.
    /// Source parser/data/base/encoding and actual `outer + 1` depth remain
    /// original. A transition replaces a previous foreign source ceiling,
    /// never the operation owner. A fresh document uses depth zero through
    /// [`Work::read_source`], rather than inventing a nested carrier level.
    ///
    /// `Self: 'source` retains the real budget lifetimes, not the borrow of a
    /// temporary Execution wrapper. The returned reader owns its account handle;
    /// no parser/diagnostic clone, new domain or budget reset is introduced.
    /// It still cannot outlive either actual parser budget:
    ///
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use structured_asn1::{Parser, Encoding, memory::{Memory,MemoryAccount,Work}};
    /// let memory = Memory::new(Arc::new(MemoryAccount::new(4096,4096)));
    /// let source = Parser::ber(memory.clone());
    /// let mut lazy;
    /// {
    ///     let operation = Parser::ber(memory);
    ///     let query = operation.read(&[],900).unwrap();
    ///     lazy = query.execution().read_nested(&source,&[2,1,7],400,Encoding::Ber,0).unwrap();
    /// }
    /// lazy.next_element().unwrap();
    /// ```
    ///
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use structured_asn1::{Parser, Encoding, memory::{Memory,MemoryAccount,Work}};
    /// let memory = Memory::new(Arc::new(MemoryAccount::new(4096,4096)));
    /// let operation = Parser::ber(memory.clone());
    /// let query = operation.read(&[],900).unwrap();
    /// let mut lazy;
    /// {
    ///     let source = Parser::ber(memory);
    ///     lazy = query.execution().read_nested(&source,&[2,1,7],400,Encoding::Ber,0).unwrap();
    /// }
    /// lazy.next_element().unwrap();
    /// ```
    fn read_nested<'source>(
        &self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        outer: u32,
    ) -> crate::Result<Reader<'source>>
    where
        Self: 'source;

    /// Opens an original source window at its actual ASN.1 depth.
    ///
    /// This has the same source/account and lifetime guarantees as
    /// [`Work::read_nested`], without adding a carrier level. A fresh document
    /// begins at zero; an already nested window must supply its original depth.
    /// Current operation ceilings remain in force even when a retained query
    /// uses a new source parser bounded by the retained input size.
    fn read_source<'source>(
        &self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        depth: u32,
    ) -> crate::Result<Reader<'source>>
    where
        Self: 'source;

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

    fn read_scoped_source<'source: 'operation, 'operation>(
        &'operation self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        depth: u32,
    ) -> crate::Result<ScopedReader<'source, 'operation>> {
        parser.read_scoped_source_in(data, base, encoding, depth, None, self)
    }

    fn read_nested<'source>(
        &self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        outer: u32,
    ) -> crate::Result<Reader<'source>>
    where
        Self: 'source,
    {
        parser.read_nested_in(data, base, encoding, outer, self)
    }

    fn read_source<'source>(
        &self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        depth: u32,
    ) -> crate::Result<Reader<'source>>
    where
        Self: 'source,
    {
        parser.read_source_in(data, base, encoding, depth, self)
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

    fn read_scoped_source<'source: 'operation, 'operation>(
        &'operation self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        depth: u32,
    ) -> crate::Result<ScopedReader<'source, 'operation>> {
        parser.read_scoped_source_in(
            data,
            base,
            encoding,
            depth,
            Some(self.budget.operation()),
            self.memory,
        )
    }

    fn read_nested<'source>(
        &self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        outer: u32,
    ) -> crate::Result<Reader<'source>>
    where
        Self: 'source,
    {
        parser.read_nested_operation_in(
            data,
            base,
            encoding,
            outer,
            self.budget.operation(),
            self.memory,
        )
    }

    fn read_source<'source>(
        &self,
        parser: &'source Parser,
        data: &'source [u8],
        base: u64,
        encoding: Encoding,
        depth: u32,
    ) -> crate::Result<Reader<'source>>
    where
        Self: 'source,
    {
        parser.read_query_budget_in(
            data,
            base,
            encoding,
            depth,
            self.budget.operation(),
            self.memory,
        )
    }
}
