//! Owned UTF-8 storage using the accounted vector's safe allocation API.

use super::{Memory, MemoryError, OwnedVec};

/// Independently owned UTF-8 text with retained capacity accounting.
///
/// Only valid UTF-8 may be appended; raw mutable bytes are never exposed.
/// Borrowing as `str` uses safe UTF-8 validation and admits its scan first.
/// This avoids an additional unchecked conversion outside the allocator adapter.
#[derive(Debug)]
pub struct OwnedString {
    bytes: OwnedVec<u8>,
}

impl OwnedString {
    pub(super) fn new(memory: &Memory) -> Self {
        Self {
            bytes: memory.vector(),
        }
    }

    /// The domain retaining this text's storage.
    #[must_use]
    pub fn memory(&self) -> &Memory {
        self.bytes.memory()
    }

    /// The initialized UTF-8 length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether this text contains no characters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Allocated byte capacity, retained until this text is dropped.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Borrows the text without copying, charging safe UTF-8 validation to the
    /// current execution domain, independently of the retained storage domain.
    ///
    /// # Panics
    ///
    /// Panics if the private UTF-8 invariant is violated. Safe construction
    /// and append operations preserve that invariant.
    pub fn as_str(&self, execution: &Memory) -> Result<&str, MemoryError> {
        execution.charge_work(self.bytes.len() as u64)?;
        Ok(core::str::from_utf8(&self.bytes).expect("only valid UTF-8 is appended"))
    }

    /// The UTF-8 bytes, as an allocation-free view; callers account traversal.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Appends valid UTF-8 after admitting capacity and copying work.
    pub fn try_push_str(&mut self, text: &str) -> Result<(), MemoryError> {
        self.bytes.try_extend_from_slice(text.as_bytes())
    }

    /// Appends one scalar using a fixed stack buffer, without hidden allocation.
    pub fn try_push(&mut self, character: char) -> Result<(), MemoryError> {
        self.memory().charge_work(1)?;
        let mut encoded = [0; 4];
        self.try_push_str(character.encode_utf8(&mut encoded))
    }

    /// Creates an independently charged copy in the same domain.
    pub fn try_copy(&self) -> Result<Self, MemoryError> {
        Ok(Self {
            bytes: self.bytes.try_copy()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::MemoryAccount;
    use super::*;
    use alloc::sync::Arc;

    #[test]
    fn repeated_scalar_append_has_amortized_growth() {
        // Growing by one exact byte for each scalar makes a bounded 32K
        // display quadratic. Actual capacity and work must remain linear.
        const LENGTH: usize = 32_768;
        let memory = Memory::new(Arc::new(MemoryAccount::new(LENGTH * 2, LENGTH * 8)));
        let mut text = memory.string();
        for _ in 0..LENGTH {
            text.try_push('a').unwrap();
        }
        assert_eq!(text.len(), LENGTH);
        assert_eq!(memory.used(), text.capacity());
        assert!(memory.work_used() <= LENGTH * 8);
        drop(text);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn text_is_valid_utf8_and_retains_its_capacity_after_move() {
        // Non-ASCII scalars must keep valid UTF-8 across fallible append and
        // ownership transfer; dropping the original handle cannot refund storage.
        let memory = Memory::new(Arc::new(MemoryAccount::new(64, 1024)));
        let mut text = memory.string();
        text.try_push_str("Дія").unwrap();
        text.try_push('🦀').unwrap();
        assert_eq!(text.as_str(&memory).unwrap(), "Дія🦀");
        let capacity = text.capacity();
        let observer = memory.clone();
        drop(memory);
        assert_eq!(observer.used(), capacity);
        let copy = text.try_copy().unwrap();
        assert_eq!(copy.as_str(&observer).unwrap(), "Дія🦀");
        assert_eq!(observer.used(), capacity + copy.capacity());
        drop(text);
        assert_eq!(observer.used(), copy.capacity());
        drop(copy);
        assert_eq!(observer.used(), 0);
    }

    #[test]
    fn refusal_preserves_text_and_does_not_hide_utf8_scan_work() {
        // A rejected append preserves the original scalar; a later borrowed
        // conversion must refuse before scanning once the work quota is spent.
        let memory = Memory::new(Arc::new(MemoryAccount::new(4, 1024)));
        let mut text = memory.string();
        text.try_push('🦀').unwrap();
        assert_eq!(text.try_push('!'), Err(MemoryError::LimitExceeded));
        assert_eq!(text.as_str(&memory).unwrap(), "🦀");
        memory
            .charge_work((1024 - memory.work_used()) as u64)
            .unwrap();
        assert_eq!(text.as_str(&memory), Err(MemoryError::WorkExceeded));
        assert_eq!(text.as_bytes(), "🦀".as_bytes());
    }

    #[test]
    fn retained_text_cannot_pay_for_a_new_operations_validation() {
        // A long-lived trust-store string keeps its storage charge, but a new
        // request with no work allowance must refuse even if the store has work.
        let storage = Memory::new(Arc::new(MemoryAccount::new(64, 1024)));
        let execution = Memory::new(Arc::new(MemoryAccount::new(64, 0)));
        let mut text = storage.string();
        text.try_push_str("issuer").unwrap();
        let used = storage.work_used();
        assert_eq!(text.as_str(&execution), Err(MemoryError::WorkExceeded));
        assert_eq!(storage.work_used(), used);
        assert_eq!(storage.used(), text.capacity());
        assert_eq!(execution.used(), 0);
    }
}
