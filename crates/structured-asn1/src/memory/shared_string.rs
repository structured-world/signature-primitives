//! Independently retained immutable UTF-8 with one accounted allocation.

use super::{HashWork, Memory, MemoryError, Work, allocator::SharedText};
use core::{
    borrow::Borrow,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
};

/// Shared immutable UTF-8, with non-atomic, allocation-free handle cloning.
///
/// One allocation contains the bytes, reference count and original storage
/// account. The last handle deallocates it before releasing its capacity charge.
/// Creation pays current [`Work`], but no borrowed execution is retained.
/// This type is neither `Send` nor `Sync`; it has no weak or mutable access.
/// Cloning panics before changing the count if `usize::MAX` live handles
/// would be exceeded. Each clone/drop is fixed work; callers admit any
/// input-dependent fan-out producing handles.
/// Borrowed views are O(1). Callers fund their own Hash/Eq/formatting/traversal
/// work; [`HashWork`] enables pre-admission when used as an [`super::OwnedMap`] key.
///
/// ```
/// use std::sync::Arc;
/// use structured_asn1::memory::{Memory, MemoryAccount, SharedString};
/// let memory = Memory::new(Arc::new(MemoryAccount::new(1024, 1024)));
/// let text = SharedString::try_from_str("namespace", &memory)?;
/// let retained = text.clone();
/// assert!(SharedString::ptr_eq(&text, &retained));
/// let capacity = memory.used();
/// drop(text);
/// assert_eq!(memory.used(), capacity);
/// assert_eq!(retained.as_str(), "namespace");
/// drop(retained);
/// assert_eq!(memory.used(), 0);
/// # Ok::<(), structured_asn1::memory::MemoryError>(())
/// ```
///
/// ```compile_fail
/// use structured_asn1::memory::SharedString;
/// fn requires_send<T: Send>() {}
/// requires_send::<SharedString>();
/// ```
///
/// ```compile_fail
/// use structured_asn1::memory::SharedString;
/// fn requires_sync<T: Sync>() {}
/// requires_sync::<SharedString>();
/// ```
#[derive(Clone)]
pub struct SharedString {
    text: SharedText,
}

impl SharedString {
    /// Copies valid UTF-8 after admitting the complete layout and copy work.
    /// Allocation failure and quota/work refusal remain distinct. Empty text
    /// also owns a charged header; there is no unaccounted global empty owner.
    pub fn try_from_str(text: &str, execution: &impl Work) -> Result<Self, MemoryError> {
        Ok(Self {
            text: SharedText::new(text, execution)?,
        })
    }

    /// Original account retaining the allocation until the last handle drops.
    #[must_use]
    pub fn memory(&self) -> &Memory {
        self.text.memory()
    }

    /// Initialized UTF-8 byte length, without traversing the text.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Whether this text contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Full allocator-visible layout size, including metadata and padding.
    #[must_use]
    pub fn allocated_bytes(&self) -> usize {
        self.text.allocated_bytes()
    }

    /// Borrows immutable UTF-8 in O(1), without revalidation or copying.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }

    /// Borrows initialized bytes; callers account their subsequent traversal.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Whether both handles own the same allocation, without comparing bytes.
    #[must_use]
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        left.text.ptr_eq(&right.text)
    }
}

impl Deref for SharedString {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl Borrow<str> for SharedString {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
impl AsRef<str> for SharedString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl fmt::Debug for SharedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}
impl fmt::Display for SharedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl PartialEq for SharedString {
    fn eq(&self, other: &Self) -> bool {
        Self::ptr_eq(self, other) || self.as_str() == other.as_str()
    }
}
impl Eq for SharedString {}
impl Hash for SharedString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}
impl HashWork for SharedString {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        (self.len() as u64)
            .checked_add(1)
            .ok_or(MemoryError::WorkExceeded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryAccount;
    use crate::{Encoding, Limits, Parser};
    use alloc::{format, sync::Arc};

    fn memory(storage: usize, work: usize) -> Memory {
        Memory::new(Arc::new(MemoryAccount::new(storage, work)))
    }

    #[test]
    fn shared_string_exact_layout_and_work_include_header_padding_and_copy() {
        // Exact admission includes metadata/padding, not only string bytes;
        // one byte/work unit below the boundary refuses with zero live storage.
        for value in ["", "a", "Ж", "𐀀🦀", "123456789"] {
            let probe = memory(4096, 4096);
            let text = SharedString::try_from_str(value, &probe).unwrap();
            let bytes = text.allocated_bytes();
            assert_eq!(probe.used(), bytes);
            assert_eq!(probe.work_used(), bytes + value.len());
            drop(text);
            assert_eq!(probe.used(), 0);
            for (storage, work, expected) in [
                (bytes - 1, usize::MAX, MemoryError::LimitExceeded),
                (bytes, bytes + value.len() - 1, MemoryError::WorkExceeded),
            ] {
                let denied = memory(storage, work);
                assert_eq!(
                    SharedString::try_from_str(value, &denied).unwrap_err(),
                    expected
                );
                assert_eq!(denied.used(), 0);
            }
            let exact = memory(bytes, bytes + value.len());
            let text = SharedString::try_from_str(value, &exact).unwrap();
            assert_eq!(text.as_str(), value);
            assert_eq!(text.as_bytes(), value.as_bytes());
            assert_eq!(text.is_empty(), value.is_empty());
            let clone = text.clone();
            assert!(SharedString::ptr_eq(&text, &clone));
            assert_eq!(exact.used(), bytes);
            assert_eq!(exact.work_used(), bytes + value.len());
            drop(text);
            assert_eq!(clone.as_str(), value);
            drop(clone);
            assert_eq!(exact.used(), 0);
        }
    }

    #[test]
    fn shared_string_local_exact_copy_and_layout_admission_share_one_execution() {
        // Admitting copy work cannot bypass a producing Parser's remaining
        // allocation allowance even when aggregate work remains available.
        let probe = memory(4096, 4096);
        let text = SharedString::try_from_str("abc", &probe).unwrap();
        let needed = text.allocated_bytes() + text.len();
        drop(text);
        for local in [needed - 1, needed] {
            let storage = memory(4096, 1_000_000);
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: local as u64,
                    ..Limits::default()
                },
                storage.clone(),
            );
            let reader = parser.read(&[], 0).unwrap();
            let result = SharedString::try_from_str("abc", &reader.execution());
            if local == needed {
                let text = result.unwrap();
                assert!(text.memory().same_account(&storage));
                assert_eq!(text.as_str(), "abc");
                drop(text);
            } else {
                assert_eq!(result.unwrap_err(), MemoryError::WorkExceeded);
            }
            assert_eq!(storage.used(), 0);
        }
    }

    #[test]
    fn shared_string_views_hashes_and_lifetimes_preserve_immutable_utf8() {
        // Equal UTF-8 in distinct allocations must keep the str hash and
        // independently retain the account, without hidden per-clone keepers.
        use core::hash::BuildHasher;
        let owner = memory(4096, 4096);
        let left = SharedString::try_from_str("Straße 🦀", &owner).unwrap();
        let right = SharedString::try_from_str("Straße 🦀", &owner).unwrap();
        assert!(!SharedString::ptr_eq(&left, &right));
        assert_eq!(left, right);
        assert_eq!(Borrow::<str>::borrow(&left), "Straße 🦀");
        assert_eq!(AsRef::<str>::as_ref(&left), "Straße 🦀");
        let hasher = hashbrown::DefaultHashBuilder::default();
        assert_eq!(hasher.hash_one(&left), hasher.hash_one(left.as_str()));
        assert_eq!(left.hash_work().unwrap(), left.len() as u64 + 1);
        assert_eq!(format!("{left}"), "Straße 🦀");
        assert_eq!(format!("{left:?}"), "\"Straße 🦀\"");
        let account = Arc::downgrade(&owner.account);
        drop(owner);
        assert!(account.upgrade().is_some());
        drop(left);
        assert!(account.upgrade().is_some());
        drop(right);
        assert!(account.upgrade().is_none());
    }
}
