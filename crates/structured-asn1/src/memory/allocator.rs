//! The only unsafe boundary: forwarding valid allocation layouts and pointers.

#![allow(unsafe_code)]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};

use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};

use super::{Memory, MemoryError, Work};

#[derive(Debug)]
pub(super) struct AccountAllocator<W: Work = Memory> {
    execution: W,
    // Budget borrows may end after mem::forget; leaked capacity must still
    // retain the account. Memory already owns it, so its extra keeper is ().
    _retained: W::Retained,
    denied: AtomicU8,
    #[cfg(test)]
    attempts: core::sync::atomic::AtomicUsize,
    #[cfg(test)]
    fail_backend: core::sync::atomic::AtomicBool,
}

impl<W: Work> AccountAllocator<W> {
    pub(super) fn new(execution: W) -> Self {
        let retained = execution.retain_storage();
        Self {
            execution,
            _retained: retained,
            denied: AtomicU8::new(0),
            #[cfg(test)]
            attempts: core::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_backend: core::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(super) fn memory(&self) -> &Memory {
        self.execution.memory()
    }
    pub(super) fn work(&self) -> &W {
        &self.execution
    }
    pub(super) fn clear_failure(&self) {
        self.denied.store(0, Ordering::Relaxed);
    }
    pub(super) fn failure(&self) -> MemoryError {
        match self.denied.load(Ordering::Relaxed) {
            1 => MemoryError::LimitExceeded,
            2 => MemoryError::WorkExceeded,
            _ => MemoryError::OutOfMemory,
        }
    }

    fn reserve(&self, bytes: usize) -> Result<super::Reservation<'_>, AllocError> {
        self.memory().account.reserve(bytes).map_err(|_| {
            self.denied.store(1, Ordering::Relaxed);
            AllocError
        })
    }

    fn admit(&self, bytes: usize) -> Result<(), AllocError> {
        self.execution.charge_work(bytes as u64).map_err(|_| {
            self.denied.store(2, Ordering::Relaxed);
            AllocError
        })
    }

    #[cfg(test)]
    fn backend_attempt(&self) -> Result<(), AllocError> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if self.fail_backend.load(Ordering::Relaxed) {
            Err(AllocError)
        } else {
            Ok(())
        }
    }
}

// SAFETY: Global supplies the exact requested Layout size and alignment. We
// forward pointers/layouts unchanged and never invalidate a block when handles
// move or drop. Memory owns its Arc; borrowed Execution statically retains its
// parser and has an independent account keeper, including for forgotten storage.
// Every keeper outlives container deallocation. Allocation
// failures leave old blocks and their charges intact. No raw storage is exposed.
unsafe impl<W: Work> Allocator for AccountAllocator<W> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let reservation = self.reserve(layout.size())?;
        self.admit(layout.size())?;
        #[cfg(test)]
        self.backend_attempt()?;
        let block = Global.allocate(layout)?;
        reservation.commit();
        Ok(block)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: our caller satisfies Allocator::deallocate's contract; every
        // nonzero block was allocated by Global with this unchanged layout.
        unsafe {
            Global.deallocate(ptr, layout);
        }
        self.memory().account.release(layout.size());
    }

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        // Reserve the whole replacement before realloc: the backend may hold
        // old and new blocks simultaneously, even if it can often grow in place.
        let reservation = self.reserve(new.size())?;
        self.admit(new.size())?;
        self.admit(old.size())?;
        #[cfg(test)]
        self.backend_attempt()?;
        // SAFETY: caller supplies a live pointer and fitting old layout, and
        // new.size() >= old.size(). Global allocated the original block.
        let block = unsafe { Global.grow(ptr, old, new)? };
        self.memory().account.release(old.size());
        reservation.commit();
        Ok(block)
    }

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        let reservation = self.reserve(new.size())?;
        self.admit(new.size())?;
        self.admit(old.size())?;
        #[cfg(test)]
        self.backend_attempt()?;
        // SAFETY: same live-pointer and layout contract as grow; Global also
        // initializes the newly added bytes required by grow_zeroed.
        let block = unsafe { Global.grow_zeroed(ptr, old, new)? };
        self.memory().account.release(old.size());
        reservation.commit();
        Ok(block)
    }
}

// SAFETY: hashbrown 0.17.1's external allocator interface has the same pointer,
// Layout and lifetime contracts as 0.4. Forward to the implementation above;
// quota admission, backend calls, rollback and release have one owner. Only
// the two crates' distinct zero-sized AllocError types are translated.
unsafe impl<W: Work> allocator_api2_hashbrown::alloc::Allocator for AccountAllocator<W> {
    fn allocate(
        &self,
        layout: Layout,
    ) -> Result<NonNull<[u8]>, allocator_api2_hashbrown::alloc::AllocError> {
        <Self as Allocator>::allocate(self, layout)
            .map_err(|_| allocator_api2_hashbrown::alloc::AllocError)
    }

    fn allocate_zeroed(
        &self,
        layout: Layout,
    ) -> Result<NonNull<[u8]>, allocator_api2_hashbrown::alloc::AllocError> {
        <Self as Allocator>::allocate_zeroed(self, layout)
            .map_err(|_| allocator_api2_hashbrown::alloc::AllocError)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: the external caller provides the unchanged live block/layout.
        unsafe {
            <Self as Allocator>::deallocate(self, ptr, layout);
        }
    }

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, allocator_api2_hashbrown::alloc::AllocError> {
        // SAFETY: both interfaces require the same live block and fitting sizes.
        unsafe { <Self as Allocator>::grow(self, ptr, old, new) }
            .map_err(|_| allocator_api2_hashbrown::alloc::AllocError)
    }

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, allocator_api2_hashbrown::alloc::AllocError> {
        // SAFETY: identical grow contract, including initialization of new bytes.
        unsafe { <Self as Allocator>::grow_zeroed(self, ptr, old, new) }
            .map_err(|_| allocator_api2_hashbrown::alloc::AllocError)
    }

    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, allocator_api2_hashbrown::alloc::AllocError> {
        // SAFETY: identical live block, alignment and shrinking-size contract.
        unsafe { <Self as Allocator>::shrink(self, ptr, old, new) }
            .map_err(|_| allocator_api2_hashbrown::alloc::AllocError)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;

    use super::super::{Memory, MemoryAccount, MemoryError};

    #[test]
    fn both_allocator_interfaces_share_live_capacity_and_growth_peak() {
        // The external hashbrown ABI and current vector ABI must retain the
        // same charge, reject the same coexistence peak and release on drop.
        let memory = Memory::new(Arc::new(MemoryAccount::new(24, usize::MAX)));
        let mut current = memory.vector::<u8>();
        current.try_extend_from_slice(&[7; 8]).unwrap();
        let mut table_interface = allocator_api2_hashbrown::vec::Vec::<u8, _>::new_in(
            super::AccountAllocator::new(memory.clone()),
        );
        table_interface.try_reserve_exact(8).unwrap();
        table_interface.push(42);
        assert_eq!(memory.used(), 16);
        let attempts = table_interface.allocator().attempts.load(Ordering::Relaxed);
        assert!(table_interface.try_reserve_exact(8).is_err());
        assert_eq!(
            table_interface.allocator().failure(),
            MemoryError::LimitExceeded
        );
        assert_eq!(
            table_interface.allocator().attempts.load(Ordering::Relaxed),
            attempts
        );
        assert_eq!(&*table_interface, &[42]);
        assert_eq!(table_interface.capacity(), 8);
        assert_eq!(memory.used(), 16);
        drop(current);
        assert_eq!(memory.used(), 8);
        table_interface.try_reserve_exact(8).unwrap();
        assert_eq!(&*table_interface, &[42]);
        assert_eq!(memory.used(), table_interface.capacity());
        drop(table_interface);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn quota_rejection_never_reaches_the_backend() {
        // Post-allocation checks would pass ordinary quota tests but still call
        // the allocator. Count the actual forwarding point to prevent that bug.
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, usize::MAX)));
        let mut bytes = memory.vector::<u8>();
        assert_eq!(bytes.try_reserve_exact(1), Err(MemoryError::LimitExceeded));
        assert_eq!(bytes.values.allocator().attempts.load(Ordering::Relaxed), 0);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn backend_failure_rolls_back_a_pending_reservation() {
        // A genuine allocation failure must release the reservation and must
        // remain distinguishable from a configured quota rejection.
        let memory = Memory::new(Arc::new(MemoryAccount::new(16, usize::MAX)));
        let mut bytes = memory.vector::<u8>();
        bytes
            .values
            .allocator()
            .fail_backend
            .store(true, Ordering::Relaxed);
        assert_eq!(bytes.try_reserve_exact(8), Err(MemoryError::OutOfMemory));
        assert_eq!(bytes.capacity(), 0);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn failed_growth_keeps_old_bytes_and_old_charge() {
        // Failed realloc retains the old pointer and values; only the pending
        // replacement charge is rolled back.
        let memory = Memory::new(Arc::new(MemoryAccount::new(32, usize::MAX)));
        let mut bytes = memory.vector::<u8>();
        bytes.try_reserve_exact(8).unwrap();
        bytes.try_push(42).unwrap();
        bytes
            .values
            .allocator()
            .fail_backend
            .store(true, Ordering::Relaxed);
        assert_eq!(bytes.try_reserve_exact(8), Err(MemoryError::OutOfMemory));
        assert_eq!(&*bytes, &[42]);
        assert_eq!(bytes.capacity(), 8);
        assert_eq!(memory.used(), 8);
    }
}
