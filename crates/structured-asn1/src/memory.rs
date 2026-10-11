//! Shared storage accounting for independently owned results.
//!
//! The caller creates the trusted account before processing input. Containers
//! retain that account independently of any parser and release their charge
//! only when the backing allocation is deallocated. Input buffers supplied by
//! the caller are outside these allocations; borrowed views do not copy them.

use alloc::sync::Arc;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

use allocator_api2::collections::TryReserveErrorKind;
use allocator_api2::vec::Vec;

mod allocator;
mod map;
mod sort;
mod string;
pub use map::{HashWork, OwnedMap};
pub use sort::SortError;
pub use string::OwnedString;

/// A failed storage operation, distinct from malformed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    /// The shared capacity allowance cannot cover this allocation's peak.
    LimitExceeded,
    /// The underlying allocator could not supply storage.
    OutOfMemory,
    /// The requested capacity cannot be represented by an allocation layout.
    CapacityOverflow,
    /// The shared cumulative work allowance cannot cover this operation.
    WorkExceeded,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LimitExceeded => "memory budget spent",
            Self::OutOfMemory => "allocator could not supply storage",
            Self::CapacityOverflow => "storage capacity overflow",
            Self::WorkExceeded => "work budget spent",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MemoryError {}

/// Caller-owned accounting state, constructed without allocating memory.
///
/// The caller supplies its shared ownership separately, during trusted setup.
/// This keeps account creation out of document-driven allocation paths.
#[derive(Debug)]
pub struct MemoryAccount {
    limit: usize,
    used: AtomicUsize,
    work_limit: usize,
    work: AtomicUsize,
}

impl MemoryAccount {
    /// An immutable capacity allowance, in bytes of allocator-visible storage.
    #[must_use]
    pub const fn new(limit: usize, work_limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
            work_limit,
            work: AtomicUsize::new(0),
        }
    }

    fn reserve(&self, bytes: usize) -> core::result::Result<Reservation<'_>, MemoryError> {
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            debug_assert!(used <= self.limit);
            if bytes > self.limit - used {
                return Err(MemoryError::LimitExceeded);
            }
            match self.used.compare_exchange_weak(
                used,
                used + bytes,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(Reservation {
                        account: self,
                        bytes,
                    });
                }
                Err(current) => used = current,
            }
        }
    }

    fn release(&self, bytes: usize) {
        let previous = self.used.fetch_sub(bytes, Ordering::Relaxed);
        debug_assert!(previous >= bytes);
    }
}

struct Reservation<'a> {
    account: &'a MemoryAccount,
    bytes: usize,
}

impl Reservation<'_> {
    fn commit(mut self) {
        self.bytes = 0;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.account.release(self.bytes);
    }
}

/// A shared storage domain retained by owned results.
///
/// Cloning this handle shares existing state and allocates no new block.
#[derive(Debug, Clone)]
pub struct Memory {
    account: Arc<MemoryAccount>,
}

impl Memory {
    /// Uses caller-supplied shared state; this constructor allocates nothing.
    #[must_use]
    pub fn new(account: Arc<MemoryAccount>) -> Self {
        Self { account }
    }

    /// The immutable allowance in bytes.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.account.limit
    }

    /// Currently reserved bytes, including pending allocations and growth peaks.
    #[must_use]
    pub fn used(&self) -> usize {
        self.account.used.load(Ordering::Relaxed)
    }

    /// Whether two handles share exactly the same account, without allocation.
    #[must_use]
    pub fn same_account(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.account, &other.account)
    }

    /// Cumulative work already admitted, including operations that later failed.
    #[must_use]
    pub fn work_used(&self) -> usize {
        self.account.work.load(Ordering::Relaxed)
    }

    /// Charges work before performing it; storage release never refunds work.
    ///
    /// An amount unrepresentable on this target is refused before any work,
    /// preserving the existing u64 scanning API on 32-bit targets.
    pub fn charge_work(&self, amount: u64) -> core::result::Result<(), MemoryError> {
        let amount = usize::try_from(amount).map_err(|_| MemoryError::WorkExceeded)?;
        let mut spent = self.account.work.load(Ordering::Relaxed);
        loop {
            debug_assert!(spent <= self.account.work_limit);
            if amount > self.account.work_limit - spent {
                return Err(MemoryError::WorkExceeded);
            }
            match self.account.work.compare_exchange_weak(
                spent,
                spent + amount,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => spent = current,
            }
        }
    }

    /// Reserves storage for an adapter-owned allocation before allocating it.
    ///
    /// Keep the returned guard until after deallocation, including rollback on
    /// failure. Reserve the complete actual capacity; a growth must retain the
    /// old guard while admitting the replacement. This bridge does not allocate.
    pub fn reserve(&self, bytes: usize) -> core::result::Result<MemoryReservation, MemoryError> {
        let reservation = self.account.reserve(bytes)?;
        reservation.commit();
        Ok(MemoryReservation {
            memory: self.clone(),
            bytes,
        })
    }

    /// An empty owned collection sharing this domain, without allocating storage.
    #[must_use]
    pub fn vector<T>(&self) -> OwnedVec<T> {
        OwnedVec {
            values: Vec::new_in(allocator::AccountAllocator::new(self.clone())),
        }
    }

    /// An empty accounted hash map, without allocating storage.
    #[must_use]
    pub fn map<K: HashWork, V>(&self) -> OwnedMap<K, V> {
        OwnedMap::new(self.clone())
    }

    /// Empty accounted UTF-8 text, without allocating storage.
    #[must_use]
    pub fn string(&self) -> OwnedString {
        OwnedString::new(self)
    }
}

/// A reservation retained alongside an adapter-owned allocation.
///
/// Its drop releases the reserved charge. The adapter must deallocate its block
/// first; dropping this guard earlier would misreport the allocation's lifetime.
#[derive(Debug)]
#[must_use = "retain the reservation until its allocation has been deallocated"]
pub struct MemoryReservation {
    memory: Memory,
    bytes: usize,
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        self.memory.account.release(self.bytes);
    }
}

/// An owned collection whose capacity remains charged until deallocation.
///
/// It exposes slices rather than the underlying growable container, so callers
/// cannot bypass fallible growth. Moving it retains accounting; copying values
/// requires a fresh reservation. Clearing values does not release capacity.
pub struct OwnedVec<T> {
    values: Vec<T, allocator::AccountAllocator>,
}

impl<T: fmt::Debug> fmt::Debug for OwnedVec<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.values.fmt(f)
    }
}

impl<T: PartialEq> PartialEq for OwnedVec<T> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<T: Eq> Eq for OwnedVec<T> {}

impl<T: PartialEq, const N: usize> PartialEq<[T; N]> for OwnedVec<T> {
    fn eq(&self, other: &[T; N]) -> bool {
        &**self == other
    }
}

impl<T> OwnedVec<T> {
    /// The account retained by this collection, for related adapter operations.
    #[must_use]
    pub fn memory(&self) -> &Memory {
        self.values.allocator().memory()
    }
    /// The allocated capacity in elements (zero-sized types allocate no bytes).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.values.capacity()
    }

    /// Reserves capacity before any allocation, accounting for growth's peak.
    pub fn try_reserve_exact(
        &mut self,
        additional: usize,
    ) -> core::result::Result<(), MemoryError> {
        self.values.allocator().clear_failure();
        self.values
            .try_reserve_exact(additional)
            .map_err(|error| match error.kind() {
                TryReserveErrorKind::CapacityOverflow => MemoryError::CapacityOverflow,
                TryReserveErrorKind::AllocError { .. } => self.values.allocator().failure(),
            })
    }

    /// Reserves amortized growth, charging the actual capacity and growth peak.
    pub fn try_reserve(&mut self, additional: usize) -> core::result::Result<(), MemoryError> {
        self.values.allocator().clear_failure();
        self.values
            .try_reserve(additional)
            .map_err(|error| match error.kind() {
                TryReserveErrorKind::CapacityOverflow => MemoryError::CapacityOverflow,
                TryReserveErrorKind::AllocError { .. } => self.values.allocator().failure(),
            })
    }

    /// Appends one value, acquiring any required storage before moving it.
    pub fn try_push(&mut self, value: T) -> core::result::Result<(), MemoryError> {
        self.values.allocator().memory().charge_work(1)?;
        if self.values.len() == self.values.capacity() {
            self.try_reserve(1)?;
        }
        // Vec guarantees push cannot allocate while capacity is available.
        self.values.push(value);
        Ok(())
    }

    /// Drops the last value, retaining the allocated capacity.
    pub fn pop(&mut self) -> Option<T> {
        self.values.pop()
    }

    /// Drops every value, retaining the allocated capacity and its charge.
    pub fn clear(&mut self) {
        self.values.clear();
    }

    /// Sorts in place without allocating or recursion.
    ///
    /// Comparisons and moves are admitted before execution. The comparator
    /// must admit its own data-dependent work before examining values. On
    /// refusal, values remain a permutation of the input, partially ordered.
    pub fn try_sort_unstable_by<E>(
        &mut self,
        compare: impl FnMut(&T, &T) -> core::result::Result<core::cmp::Ordering, E>,
    ) -> core::result::Result<(), SortError<E>> {
        let memory = self.memory().clone();
        sort::sort(&mut self.values, &memory, compare)
    }
}

impl<T: Copy> OwnedVec<T> {
    /// Copies a slice after reserving storage and cumulative work in this domain.
    pub fn try_extend_from_slice(&mut self, values: &[T]) -> core::result::Result<(), MemoryError> {
        let work = values.len().max(core::mem::size_of_val(values));
        self.memory().charge_work(work as u64)?;
        if self.values.capacity() == 0 {
            self.try_reserve_exact(values.len())?;
        } else {
            self.try_reserve(values.len())?;
        }
        self.values.extend_from_slice(values);
        Ok(())
    }
    /// Copies values into independently charged storage in the same domain.
    pub fn try_copy(&self) -> core::result::Result<Self, MemoryError> {
        let mut copy = self.values.allocator().memory().vector();
        let work = self.values.len().max(core::mem::size_of_val(&**self));
        self.values.allocator().memory().charge_work(work as u64)?;
        copy.try_reserve_exact(self.values.len())?;
        // Reservation above guarantees the Copy specialization cannot allocate.
        copy.values.extend_from_slice(&self.values);
        Ok(copy)
    }
}

impl<T> Deref for OwnedVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.values
    }
}

impl<T> DerefMut for OwnedVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}

impl<'a, T> IntoIterator for &'a OwnedVec<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut OwnedVec<T> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

/// An owning iterator that retains capacity accounting until storage is freed.
pub struct OwnedIter<T> {
    values: allocator_api2::vec::IntoIter<T, allocator::AccountAllocator>,
}

impl<T> Iterator for OwnedIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.values.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.values.size_hint()
    }
}

impl<T> DoubleEndedIterator for OwnedIter<T> {
    fn next_back(&mut self) -> Option<T> {
        self.values.next_back()
    }
}

impl<T> ExactSizeIterator for OwnedIter<T> {}
impl<T> core::iter::FusedIterator for OwnedIter<T> {}

impl<T> IntoIterator for OwnedVec<T> {
    type Item = T;
    type IntoIter = OwnedIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        OwnedIter {
            values: self.values.into_iter(),
        }
    }
}

#[cfg(test)]
mod tests;
