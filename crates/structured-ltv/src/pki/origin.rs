//! Borrow-scoped provenance for heterogeneous already checked input receipts.

use core::marker::PhantomData;

// The borrow prevents moving/dropping the input while a dependent proof exists.
// Type erasure permits retaining the identity of opaque credential evidence
// without imposing its concrete type on every authority/material report. There
// is no dereference, unsafe operation, allocation, global ID or refcount.
// ZST addresses do NOT establish distinct instances, so they are excluded at
// monomorphization. All callers select full receipts with actual owned metadata.
pub(super) struct Origin<'a> {
    address: usize,
    borrow: PhantomData<&'a ()>,
}

impl<'a> Origin<'a> {
    pub(super) fn of<T>(value: &'a T) -> Self {
        const {
            assert!(core::mem::size_of::<T>() > 0);
        }
        Self {
            address: core::ptr::from_ref(value).addr(),
            borrow: PhantomData,
        }
    }

    pub(super) fn matches<T>(&self, value: &T) -> bool {
        const {
            assert!(core::mem::size_of::<T>() > 0);
        }
        self.address == core::ptr::from_ref(value).addr()
    }
}

#[cfg(test)]
mod tests {
    use super::Origin;

    #[test]
    fn origin_compares_live_instances_without_copying_their_payload() {
        // Equal payload is not the same selected receipt. The scoped reference
        // keeps identity valid without retaining/cloning an opaque provider.
        let first = [7u8; 8];
        let second = first;
        let origin = Origin::of(&first);
        assert!(origin.matches(&first));
        assert!(!origin.matches(&second));
    }
}
