//! Validated text; the only unchecked operation borrows sealed UTF-8.

use super::super::{Memory, MemoryError, OwnedVec, TextErrorKind, Work};

// No mutable byte access escapes while this owner exists. Both constructors
// establish UTF-8; appending a valid str preserves it. Moving the vector/account
// changes neither length nor bytes.
pub(in super::super) struct ValidatedText<W: Work = Memory> {
    bytes: OwnedVec<u8, W>,
}

impl<W: Work> ValidatedText<W> {
    pub(in super::super) fn from_utf8(
        bytes: OwnedVec<u8, W>,
    ) -> Result<Self, (TextErrorKind, OwnedVec<u8, W>)> {
        if let Err(cause) = bytes
            .values
            .allocator()
            .work()
            .charge_work(bytes.len() as u64)
        {
            return Err((TextErrorKind::Resource(cause), bytes));
        }
        if let Err(cause) = core::str::from_utf8(&bytes) {
            return Err((TextErrorKind::Utf8(cause), bytes));
        }
        Ok(Self { bytes })
    }

    pub(in super::super) fn from_str(text: &str, execution: &W) -> Result<Self, MemoryError> {
        let mut bytes = execution.vector();
        bytes.try_extend_from_slice(text.as_bytes())?;
        Ok(Self { bytes })
    }

    pub(in super::super) fn bytes(&self) -> &OwnedVec<u8, W> {
        &self.bytes
    }

    pub(in super::super) fn try_push_str(&mut self, suffix: &str) -> Result<(), MemoryError> {
        // Concatenating complete valid UTF-8 strings preserves the invariant.
        // Copy/growth admission and rollback belong to the existing vector.
        self.bytes.try_extend_from_slice(suffix.as_bytes())
    }

    pub(in super::super) fn try_reserve_exact(
        &mut self,
        additional: usize,
    ) -> Result<(), MemoryError> {
        self.bytes.try_reserve_exact(additional)
    }

    pub(in super::super) fn as_str(&self) -> &str {
        // SAFETY: constructors either validated these exact initialized bytes
        // or copied them from a valid str. Initialized bytes can only grow by
        // appending a complete valid str through an exclusive borrow; no method
        // exposes &mut bytes or aliases a mutable owner. into_bytes consumes
        // self, so all str borrows must end first.
        // Ordinary OwnedVec ownership keeps the allocation live for this borrow.
        unsafe { core::str::from_utf8_unchecked(&self.bytes) }
    }

    pub(in super::super) fn into_owned(self) -> ValidatedText {
        ValidatedText {
            bytes: self.bytes.into_owned(),
        }
    }

    pub(in super::super) fn into_bytes(self) -> OwnedVec<u8, W> {
        self.bytes
    }
}
