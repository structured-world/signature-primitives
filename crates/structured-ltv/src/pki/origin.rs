//! Borrow-scoped provenance for heterogeneous already checked input receipts.

use core::marker::PhantomData;

// The borrow prevents moving/dropping the input while a dependent proof exists.
// Type erasure permits retaining the identity of opaque credential evidence
// without imposing its concrete type on every authority/material report. There
// is no dereference, unsafe operation, allocation, global ID or refcount.
// ZST addresses do NOT establish distinct instances, so they are excluded at
// monomorphization. An address alone is shared by a repr(C) wrapper and its
// first field, so the receipt's size and type name are compared too; the
// receipts here are generic and not `'static`, which rules out `TypeId`.
pub(super) struct Origin<'a> {
    address: usize,
    size: usize,
    kind: &'static str,
    borrow: PhantomData<&'a ()>,
}

impl<'a> Origin<'a> {
    pub(super) fn of<T>(value: &'a T) -> Self {
        const {
            assert!(core::mem::size_of::<T>() > 0);
        }
        Self {
            address: core::ptr::from_ref(value).addr(),
            size: core::mem::size_of::<T>(),
            kind: core::any::type_name::<T>(),
            borrow: PhantomData,
        }
    }

    pub(super) fn matches<T>(&self, value: &T) -> bool {
        const {
            assert!(core::mem::size_of::<T>() > 0);
        }
        let kind = core::any::type_name::<T>();
        self.address == core::ptr::from_ref(value).addr()
            && self.size == core::mem::size_of::<T>()
            && (core::ptr::eq(self.kind, kind) || self.kind == kind)
    }
}

#[cfg(test)]
mod tests;
