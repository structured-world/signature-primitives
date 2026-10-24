//! The unsafe boundary for allocation layouts, ownership and shared text lifetime.

#![allow(unsafe_code)]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};

use super::{Memory, MemoryError, Work};

mod shared;
mod text;
pub(super) use shared::SharedText;
pub(super) use text::ValidatedText;

/// Transfers storage from sealed work to its existing account owner.
pub(super) fn retain<T, W: Work>(
    values: allocator_api2::vec::Vec<T, AccountAllocator<W>>,
) -> allocator_api2::vec::Vec<T, AccountAllocator> {
    transfer(values, |allocator| {
        let memory = allocator.execution.into_storage_owner(allocator.storage);
        AccountAllocator::new(memory)
    })
}

/// Attaches current work to storage whose account identity was checked.
pub(super) fn scope<T, W: Work>(
    values: allocator_api2::vec::Vec<T, AccountAllocator>,
    execution: &W,
) -> allocator_api2::vec::Vec<T, AccountAllocator<W>> {
    transfer(values, |allocator| {
        let (execution, storage) = execution.with_storage_owner(allocator.execution);
        AccountAllocator::with_storage(execution, storage)
    })
}

/// Moves an allocation between same-account executions and returns old work.
pub(super) fn rebind<T, Old: Work, New: Work>(
    values: allocator_api2::vec::Vec<T, AccountAllocator<Old>>,
    execution: &New,
) -> (allocator_api2::vec::Vec<T, AccountAllocator<New>>, Old) {
    let mut previous = None;
    let values = transfer(values, |allocator| {
        let (old, memory) = allocator.execution.split_storage_owner(allocator.storage);
        previous = Some(old);
        let (execution, storage) = execution.with_storage_owner(memory);
        AccountAllocator::with_storage(execution, storage)
    });
    (
        values,
        previous.expect("the infallible transfer converts exactly one allocator"),
    )
}

/// Only private, infallible keeper-moving closures call this.
fn transfer<T, W: Work, V: Work>(
    values: allocator_api2::vec::Vec<T, AccountAllocator<W>>,
    convert: impl FnOnce(AccountAllocator<W>) -> AccountAllocator<V>,
) -> allocator_api2::vec::Vec<T, AccountAllocator<V>> {
    let (pointer, length, capacity, allocator) = values.into_raw_parts_with_alloc();
    let allocator = convert(allocator);
    // SAFETY: the consumed Vec supplied this pointer, initialized length and
    // capacity for the unchanged T. Both allocator types forward to Global
    // with identical Layout rules and the same account; no block is allocated,
    // released, resized or exposed during transfer. The old Vec cannot drop
    // elements/storage, and the new allocator owns the keeper before any later
    // drop/reallocation. This also preserves empty and zero-sized Vec layouts.
    unsafe { allocator_api2::vec::Vec::from_raw_parts_in(pointer, length, capacity, allocator) }
}

#[derive(Debug)]
pub(super) struct AccountAllocator<W: Work = Memory> {
    execution: W,
    // Budget borrows may end after mem::forget; leaked capacity must still
    // retain the account. Memory already owns it, so its extra keeper is ().
    storage: W::Retained,
    denied: AtomicU8,
    #[cfg(test)]
    attempts: core::sync::atomic::AtomicUsize,
    #[cfg(test)]
    fail_backend: core::sync::atomic::AtomicBool,
}

impl<W: Work> AccountAllocator<W> {
    pub(super) fn new(execution: W) -> Self {
        let retained = execution.retain_storage();
        Self::with_storage(execution, retained)
    }

    fn with_storage(execution: W, storage: W::Retained) -> Self {
        Self {
            execution,
            storage,
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
    fn into_memory(self) -> Memory {
        self.execution.into_storage_owner(self.storage)
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

use allocator_api2_hashbrown::alloc::{
    AllocError as TableAllocError, Allocator as TableAllocatorApi,
};

/// One growth call's current execution, erased so the table type stays fixed.
struct Admission {
    execution: *const (),
    charge: unsafe fn(*const (), u64) -> Result<(), MemoryError>,
}

/// # Safety
/// `execution` must point to a live `W`.
unsafe fn charge<W: Work>(execution: *const (), amount: u64) -> Result<(), MemoryError> {
    // SAFETY: `scoped` erased exactly a `&W` that outlives its installed scope.
    unsafe { &*execution.cast::<W>() }.charge_work(amount)
}

/// Hash-table storage owned by its account, independent of any execution.
///
/// Growth work is admitted through the execution that `scoped` installs for
/// one growth call; without one, allocation is refused before the backend.
/// Deliberately not `Clone`: the pinned hashbrown copies an allocator only in
/// `Clone for RawTable`, so no copy can retain an installed scope.
#[derive(Debug)]
pub(super) struct TableAllocator {
    memory: Memory,
    scope: AtomicPtr<Admission>,
    denied: AtomicU8,
    #[cfg(test)]
    pub(super) attempts: core::sync::atomic::AtomicUsize,
    #[cfg(test)]
    pub(super) fail_backend: core::sync::atomic::AtomicBool,
}

impl TableAllocator {
    pub(super) fn new(memory: Memory) -> Self {
        Self {
            memory,
            scope: AtomicPtr::new(core::ptr::null_mut()),
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
    #[cfg(test)]
    pub(super) fn scope_installed(&self) -> bool {
        !self.scope.load(Ordering::Relaxed).is_null()
    }

    fn reserve(&self, bytes: usize) -> Result<super::Reservation<'_>, TableAllocError> {
        self.memory.account.reserve(bytes).map_err(|_| {
            self.denied.store(1, Ordering::Relaxed);
            TableAllocError
        })
    }

    fn admit(&self, bytes: usize) -> Result<(), TableAllocError> {
        let scope = self.scope.load(Ordering::Relaxed);
        // SAFETY: a non-null scope points to the Admission of the `scoped`
        // call currently growing this table; it is cleared before that frame ends.
        let admitted = match unsafe { scope.as_ref() } {
            // SAFETY: that call erased a live `&W` matching this charge function.
            Some(admission) => unsafe { (admission.charge)(admission.execution, bytes as u64) },
            None => Err(MemoryError::WorkExceeded),
        };
        admitted.map_err(|_| {
            self.denied.store(2, Ordering::Relaxed);
            TableAllocError
        })
    }

    #[cfg(test)]
    fn backend_attempt(&self) -> Result<(), TableAllocError> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if self.fail_backend.load(Ordering::Relaxed) {
            Err(TableAllocError)
        } else {
            Ok(())
        }
    }
}

/// Runs one growth of `owner`'s table with `execution` admitting its work.
///
/// Admission happens inside the allocator, in one `charge_work` call per
/// block, so a key's `Hash` spending the same execution sees the real
/// remainder. The scope is cleared on return and on unwind.
pub(super) fn scoped<T, R>(
    owner: &mut T,
    allocator: fn(&T) -> &TableAllocator,
    execution: &impl Work,
    grow: impl FnOnce(&mut T) -> R,
) -> R {
    fn erase<W: Work>(execution: &W) -> Admission {
        Admission {
            execution: core::ptr::from_ref(execution).cast(),
            charge: charge::<W>,
        }
    }

    struct Clear<T> {
        owner: *mut T,
        allocator: fn(&T) -> &TableAllocator,
    }
    impl<T> Drop for Clear<T> {
        fn drop(&mut self) {
            // SAFETY: the exclusive borrow behind `owner` outlives this guard,
            // and the reborrow given to `grow` has ended (returned or unwound).
            let allocator = (self.allocator)(unsafe { &*self.owner });
            allocator
                .scope
                .store(core::ptr::null_mut(), Ordering::Relaxed);
        }
    }

    let admission = erase(execution);
    let owner: *mut T = owner;
    // SAFETY: `owner` comes from a live exclusive borrow; no reborrow is active.
    let table = allocator(unsafe { &*owner });
    debug_assert!(table.scope.load(Ordering::Relaxed).is_null());
    table.scope.store(
        core::ptr::from_ref(&admission).cast_mut(),
        Ordering::Relaxed,
    );
    let _clear = Clear { owner, allocator };
    // SAFETY: the sole access to `owner` until `grow` ends; the guard touches
    // it only afterwards, and `admission` outlives the guard.
    grow(unsafe { &mut *owner })
}

// SAFETY: Global supplies the exact requested Layout size and alignment. We
// forward pointers/layouts unchanged and never invalidate a block when handles
// move or drop. The owned Memory keeps the account alive through deallocation,
// independently of any scoped execution. Allocation failures leave old blocks
// and their charges intact. No raw storage is exposed.
unsafe impl TableAllocatorApi for TableAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, TableAllocError> {
        let reservation = self.reserve(layout.size())?;
        self.admit(layout.size())?;
        #[cfg(test)]
        self.backend_attempt()?;
        let block = Global.allocate(layout).map_err(|_| TableAllocError)?;
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
    ) -> Result<NonNull<[u8]>, TableAllocError> {
        // Reserve the whole replacement before realloc: the backend may hold
        // old and new blocks simultaneously, even if it can often grow in place.
        let reservation = self.reserve(new.size())?;
        self.admit(new.size())?;
        self.admit(old.size())?;
        #[cfg(test)]
        self.backend_attempt()?;
        // SAFETY: caller supplies a live pointer and fitting old layout, and
        // new.size() >= old.size(). Global allocated the original block.
        let block = unsafe { Global.grow(ptr, old, new) }.map_err(|_| TableAllocError)?;
        self.memory.account.release(old.size());
        reservation.commit();
        Ok(block)
    }

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old: Layout,
        new: Layout,
    ) -> Result<NonNull<[u8]>, TableAllocError> {
        let reservation = self.reserve(new.size())?;
        self.admit(new.size())?;
        self.admit(old.size())?;
        #[cfg(test)]
        self.backend_attempt()?;
        // SAFETY: same live-pointer and layout contract as grow; Global also
        // initializes the newly added bytes required by grow_zeroed.
        let block = unsafe { Global.grow_zeroed(ptr, old, new) }.map_err(|_| TableAllocError)?;
        self.memory.account.release(old.size());
        reservation.commit();
        Ok(block)
    }
}

#[cfg(test)]
mod tests;
