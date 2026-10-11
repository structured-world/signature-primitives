//! The only unsafe boundary: forwarding valid allocation layouts and pointers.

#![allow(unsafe_code)]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};

use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};

use super::{Memory, MemoryError};

#[derive(Debug)]
pub(super) struct AccountAllocator {
    memory: Memory,
    denied: AtomicU8,
    #[cfg(test)]
    attempts: core::sync::atomic::AtomicUsize,
    #[cfg(test)]
    fail_backend: core::sync::atomic::AtomicBool,
}

impl AccountAllocator {
    pub(super) fn new(memory: Memory) -> Self {
        Self {
            memory,
            denied: AtomicU8::new(0),
            #[cfg(test)]
            attempts: core::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_backend: core::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(super) fn memory(&self) -> &Memory {
        &self.memory
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
        self.memory.account.reserve(bytes).map_err(|_| {
            self.denied.store(1, Ordering::Relaxed);
            AllocError
        })
    }

    fn work(&self, bytes: usize) -> Result<(), AllocError> {
        self.memory.charge_work(bytes as u64).map_err(|_| {
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
// move or drop. Containers retain Memory (Arc) until after deallocation. Allocation
// failures leave old blocks and their charges intact. No raw storage is exposed.
unsafe impl Allocator for AccountAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let reservation = self.reserve(layout.size())?;
        self.work(layout.size())?;
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
        self.memory.account.release(layout.size());
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
        self.work(new.size())?;
        self.work(old.size())?;
        #[cfg(test)]
        self.backend_attempt()?;
        // SAFETY: caller supplies a live pointer and fitting old layout, and
        // new.size() >= old.size(). Global allocated the original block.
        let block = unsafe { Global.grow(ptr, old, new)? };
        self.memory.account.release(old.size());
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
        self.work(new.size())?;
        self.work(old.size())?;
        #[cfg(test)]
        self.backend_attempt()?;
        // SAFETY: same live-pointer and layout contract as grow; Global also
        // initializes the newly added bytes required by grow_zeroed.
        let block = unsafe { Global.grow_zeroed(ptr, old, new)? };
        self.memory.account.release(old.size());
        reservation.commit();
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;

    use super::super::{Memory, MemoryAccount, MemoryError};

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
