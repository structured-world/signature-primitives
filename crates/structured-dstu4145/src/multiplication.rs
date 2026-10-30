//! Prepared multiplication capability, selected before field arithmetic.

use crate::words::{self, Product, Words};

#[allow(unsafe_code)]
mod native;
pub(crate) use native::Hardware;

pub(crate) trait Kernel: core::fmt::Debug + Copy {
    fn product(self, left: &Words, right: &Words, count: usize) -> Product;
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Portable;

impl Kernel for Portable {
    #[inline]
    fn product(self, left: &Words, right: &Words, count: usize) -> Product {
        words::product(*left, *right, count)
    }
}
