//! Iterative sorting with fallible comparisons and pre-admitted moves.

use core::cmp::Ordering;

use super::{MemoryError, Work};

/// A refused sort, preserving the comparator's own error and provenance.
#[derive(Debug, PartialEq, Eq)]
pub enum SortError<E> {
    /// The sort could not admit its own comparison dispatch or value movement.
    Resource(MemoryError),
    /// The caller's fallible comparison refused further processing.
    Comparison(E),
}

impl From<SortError<MemoryError>> for MemoryError {
    fn from(error: SortError<MemoryError>) -> Self {
        match error {
            SortError::Resource(reason) | SortError::Comparison(reason) => reason,
        }
    }
}

pub(super) fn sort<T, E, W: Work>(
    values: &mut [T],
    memory: &W,
    mut compare: impl FnMut(&T, &T) -> Result<Ordering, E>,
) -> Result<(), SortError<E>> {
    for root in (0..values.len() / 2).rev() {
        sift(values, root, values.len(), memory, &mut compare)?;
    }
    for end in (1..values.len()).rev() {
        exchange(values, 0, end, memory).map_err(SortError::Resource)?;
        sift(values, 0, end, memory, &mut compare)?;
    }
    Ok(())
}

fn sift<T, E, W: Work>(
    values: &mut [T],
    mut root: usize,
    end: usize,
    memory: &W,
    compare: &mut impl FnMut(&T, &T) -> Result<Ordering, E>,
) -> Result<(), SortError<E>> {
    while root < end / 2 {
        // root < end/2 proves both the multiplication and child are in range.
        let mut child = root * 2 + 1;
        memory.charge_work(1).map_err(SortError::Resource)?;
        if child + 1 < end {
            memory.charge_work(1).map_err(SortError::Resource)?;
            if compare(&values[child], &values[child + 1]).map_err(SortError::Comparison)?
                == Ordering::Less
            {
                child += 1;
            }
        }
        memory.charge_work(1).map_err(SortError::Resource)?;
        if compare(&values[root], &values[child]).map_err(SortError::Comparison)? != Ordering::Less
        {
            break;
        }
        exchange(values, root, child, memory).map_err(SortError::Resource)?;
        root = child;
    }
    Ok(())
}

fn exchange<T, W: Work>(
    values: &mut [T],
    left: usize,
    right: usize,
    memory: &W,
) -> Result<(), MemoryError> {
    let cost = (core::mem::size_of::<T>() as u64)
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(MemoryError::WorkExceeded)?;
    memory.charge_work(cost)?;
    values.swap(left, right);
    Ok(())
}
