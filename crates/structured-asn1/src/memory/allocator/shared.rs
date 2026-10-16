//! One immutable UTF-8 allocation; all pointer/reference-count operations stay here.

use alloc::rc::Rc;
use core::{cell::Cell, marker::PhantomData, ptr::NonNull};

use super::{AccountAllocator, Allocator, Layout, Memory, MemoryError, Work};

struct Header {
    strong: Cell<usize>,
    length: usize,
    memory: Memory,
}

// No weak references or mutation of the trailing bytes exist. Rc's marker
// prevents Send/Sync even when a caller only observes immutable text.
pub(in super::super) struct SharedText {
    pointer: NonNull<Header>,
    not_send_sync: PhantomData<Rc<()>>,
}

fn layout(length: usize) -> Result<(Layout, usize), MemoryError> {
    let bytes = Layout::array::<u8>(length).map_err(|_| MemoryError::CapacityOverflow)?;
    let (layout, offset) = Layout::new::<Header>()
        .extend(bytes)
        .map_err(|_| MemoryError::CapacityOverflow)?;
    Ok((layout.pad_to_align(), offset))
}

fn allocate<W: Work>(
    text: &str,
    allocator: &AccountAllocator<W>,
) -> Result<(NonNull<u8>, usize), MemoryError> {
    let (layout, offset) = layout(text.len())?;
    // No input byte is examined and no allocation occurs before copy work
    // and allocator layout admission. Failure never refunds consumed work.
    allocator.work().charge_work(text.len() as u64)?;
    let block = allocator
        .allocate(layout)
        .map_err(|_| allocator.failure())?;
    Ok((block.cast(), offset))
}

impl SharedText {
    pub(in super::super) fn new(text: &str, work: &impl Work) -> Result<Self, MemoryError> {
        let allocator = AccountAllocator::new(work.clone());
        let (block, offset) = allocate(text, &allocator)?;
        let memory = allocator.into_memory();
        // SAFETY: allocate returned a fresh block with the Header alignment
        // and enough trailing space for exactly text.len() bytes. Source str
        // is initialized valid UTF-8 and cannot alias this fresh allocation.
        // All following operations are infallible; the account owner is moved
        // into the header, and only this handle can initially release it.
        unsafe {
            block.cast::<Header>().as_ptr().write(Header {
                strong: Cell::new(1),
                length: text.len(),
                memory,
            });
            core::ptr::copy_nonoverlapping(text.as_ptr(), block.as_ptr().add(offset), text.len());
        }
        Ok(Self {
            pointer: block.cast(),
            not_send_sync: PhantomData,
        })
    }

    fn header(&self) -> &Header {
        // SAFETY: every handle contributes one live strong reference. The
        // header stays initialized at its original address until last Drop.
        unsafe { self.pointer.as_ref() }
    }

    pub(in super::super) fn memory(&self) -> &Memory {
        &self.header().memory
    }

    pub(in super::super) fn len(&self) -> usize {
        self.header().length
    }

    pub(in super::super) fn allocated_bytes(&self) -> usize {
        layout(self.len())
            .expect("a live shared allocation has a valid layout")
            .0
            .size()
    }

    pub(in super::super) fn as_str(&self) -> &str {
        let length = self.len();
        // SAFETY: immutable trailing bytes were copied from a valid str, are
        // never exposed mutably, and remain live for this handle's borrow.
        // Validation at every view would re-scan unchanged trusted storage.
        unsafe {
            let bytes = core::slice::from_raw_parts(
                self.pointer
                    .as_ptr()
                    .cast::<u8>()
                    .add(core::mem::size_of::<Header>()),
                length,
            );
            core::str::from_utf8_unchecked(bytes)
        }
    }

    pub(in super::super) fn ptr_eq(&self, other: &Self) -> bool {
        self.pointer == other.pointer
    }
}

impl Clone for SharedText {
    fn clone(&self) -> Self {
        let count = self.header().strong.get();
        // A caught overflow panic must leave the original count unchanged;
        // wrapping would permit use-after-free. No allocation or scan occurs.
        let next = count
            .checked_add(1)
            .expect("shared string reference count overflow");
        self.header().strong.set(next);
        Self {
            pointer: self.pointer,
            not_send_sync: PhantomData,
        }
    }
}

impl Drop for SharedText {
    fn drop(&mut self) {
        let count = self.header().strong.get();
        debug_assert!(count > 0);
        if count > 1 {
            self.header().strong.set(count - 1);
            return;
        }
        let (layout, _) = layout(self.len()).expect("a live shared allocation has a valid layout");
        // SAFETY: count==1 and !Send/!Sync guarantee this is the last handle.
        // Move (not clone/drop) the header's sole account owner to the allocator
        // before releasing the original block with its unchanged exact layout.
        // No Header destructor runs on the moved Memory; bytes contain no Drop.
        // AccountAllocator releases the capacity only after Global.deallocate.
        unsafe {
            let memory = core::ptr::read(core::ptr::addr_of!((*self.pointer.as_ptr()).memory));
            let allocator = AccountAllocator::new(memory);
            allocator.deallocate(self.pointer.cast(), layout);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::memory::MemoryAccount;
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;

    #[test]
    fn shared_text_refusal_precedes_backend_and_backend_failure_rolls_back() {
        // Both pre-admission errors must avoid the allocator; a real backend
        // refusal releases the pending layout reservation, preserving its cause.
        for (storage, work, expected) in [
            (0, usize::MAX, MemoryError::LimitExceeded),
            (4096, 0, MemoryError::WorkExceeded),
            (4096, 4, MemoryError::WorkExceeded),
        ] {
            let memory = Memory::new(Arc::new(MemoryAccount::new(storage, work)));
            let allocator = AccountAllocator::new(memory.clone());
            assert_eq!(allocate("text", &allocator).unwrap_err(), expected);
            assert_eq!(allocator.attempts.load(Ordering::Relaxed), 0);
            assert_eq!(memory.used(), 0);
        }
        let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
        let allocator = AccountAllocator::new(memory.clone());
        allocator.fail_backend.store(true, Ordering::Relaxed);
        assert_eq!(
            allocate("text", &allocator).unwrap_err(),
            MemoryError::OutOfMemory
        );
        assert_eq!(allocator.attempts.load(Ordering::Relaxed), 1);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn shared_text_layout_and_reference_count_overflow_are_refused() {
        // Layout arithmetic and Clone must not wrap into a smaller allocation
        // or count, even when a panic is caught before the original is dropped.
        assert_eq!(
            layout(usize::MAX).unwrap_err(),
            MemoryError::CapacityOverflow
        );
        let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
        let text = SharedText::new("x", &memory).unwrap();
        text.header().strong.set(usize::MAX);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| text.clone()));
        assert!(result.is_err());
        assert_eq!(text.header().strong.get(), usize::MAX);
        text.header().strong.set(1);
        drop(text);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn shared_text_forgetting_a_handle_keeps_capacity_and_account_alive() {
        // Forgetting leaks the charge with the allocation; dropping the last
        // ordinary handle must not refund storage still owned by that leak.
        let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
        let text = SharedText::new("retained", &memory).unwrap();
        let pointer = text.pointer;
        let capacity = memory.used();
        core::mem::forget(text.clone());
        drop(text);
        assert_eq!(memory.used(), capacity);
        // Recover exactly the forgotten owner for test cleanup, with no
        // duplication of a live handle. The count still represents this owner.
        let recovered = SharedText {
            pointer,
            not_send_sync: PhantomData,
        };
        assert_eq!(recovered.header().strong.get(), 1);
        assert_eq!(recovered.as_str(), "retained");
        drop(recovered);
        assert_eq!(memory.used(), 0);
    }
}
