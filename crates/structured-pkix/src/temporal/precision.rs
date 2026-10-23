//! Arbitrary decimal precision without inventing an exact nanosecond.
use super::{LeapTable, Reading, Uncertainty};
use crate::error::{Error, Result};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

/// Original generalized-time value with every significant subnanosecond digit.
/// Its retained capacity is independent of the source parser. No accuracy,
/// trusted clock or successful timestamp proof is implied.
#[derive(Debug)]
pub struct ExactReading {
    pub(super) reading: Reading,
    tail: Option<OwnedVec<u8>>,
}
/// Comparison refuses unavailable UTC facts separately from resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareError {
    /// Admission failed before comparison/UTC lookup.
    Resource(MemoryError),
    /// The supplied UTC correction facts do not qualify an original label.
    Uncertain(Uncertainty),
}
impl ExactReading {
    pub(super) fn new<W: Work>(
        reading: Reading,
        fraction: Option<(&[u8], i128)>,
        work: &W,
        field: &'static str,
        at: u64,
    ) -> Result<Self> {
        if !reading.has_subnanosecond_remainder() {
            return Ok(Self {
                reading,
                tail: None,
            });
        }
        let (mut digits, unit) =
            fraction.expect("nonzero fractional remainder came from a fraction");
        let failure = |cause| Error::resource(cause, field, at);
        work.charge_work(
            (digits.len() as u64)
                .checked_mul(3)
                .ok_or_else(|| failure(MemoryError::WorkExceeded))?,
        )
        .map_err(failure)?;
        // All grammar units are whole seconds/minutes/hours. Their 10^9
        // factor means only digits beyond nine can contribute to a fractional
        // nanosecond. Do not allocate the already represented integer prefix.
        while digits.last() == Some(&b'0') {
            digits = &digits[..digits.len() - 1];
        }
        debug_assert!(digits.len() > 9 && unit % 1_000_000_000 == 0);
        let digits = &digits[9..];
        let unit = unit / 1_000_000_000;
        let mut tail = work.vector();
        tail.try_reserve_exact(digits.len()).map_err(failure)?;
        let mut carry = 0i128;
        for digit in digits.iter().rev() {
            // Same bounded reverse multiplication as the parser: unit <= an
            // hour in nanoseconds, carry < unit; no big integer or truncation.
            let product = i128::from(digit - b'0') * unit + carry;
            tail.try_push(u8::try_from(product % 10).expect("decimal remainder") + b'0')
                .map_err(failure)?;
            carry = product / 10;
        }
        tail.reverse();
        while tail.last() == Some(&b'0') {
            tail.pop();
        }
        debug_assert!(!tail.is_empty());
        Ok(Self {
            reading,
            tail: Some(tail.into_owned()),
        })
    }
    /// The nanosecond floor and whether an exact finer remainder exists.
    #[must_use]
    pub fn reading(&self) -> Reading {
        self.reading
    }
    /// Copies only retained fractional precision under the current operation.
    pub fn try_copy_in<W: Work>(&self, work: &W, field: &'static str, at: u64) -> Result<Self> {
        let tail = if let Some(tail) = &self.tail {
            let mut copy = work.vector();
            copy.try_extend_from_slice(tail)
                .map_err(|cause| Error::resource(cause, field, at))?;
            Some(copy.into_owned())
        } else {
            None
        };
        Ok(Self {
            reading: self.reading,
            tail,
        })
    }
    /// Full UTC ordering with virtual decimal zero padding (X.680 §46).
    /// Both source labels and all possible comparison work are admitted first.
    pub fn compare<W: Work>(
        &self,
        other: &Self,
        utc: &LeapTable<'_>,
        work: &W,
    ) -> core::result::Result<core::cmp::Ordering, CompareError> {
        let bits = usize::BITS - utc.transitions().len().leading_zeros();
        work.charge_work(32 + 6 * (u64::from(bits) + 1))
            .map_err(CompareError::Resource)?;
        let left = utc
            .shift(self.reading.start(), 0)
            .map_err(CompareError::Uncertain)?;
        let right = utc
            .shift(other.reading.start(), 0)
            .map_err(CompareError::Uncertain)?;
        if left != right {
            return Ok(left.cmp(&right));
        }
        let a = self.tail.as_deref().unwrap_or(&[]);
        let b = other.tail.as_deref().unwrap_or(&[]);
        work.charge_work(1 + a.len().max(b.len()) as u64)
            .map_err(CompareError::Resource)?;
        for index in 0..a.len().max(b.len()) {
            // A missing decimal digit is numeric zero, not an input fallback.
            let left = a.get(index).copied().unwrap_or(b'0');
            let right = b.get(index).copied().unwrap_or(b'0');
            if left != right {
                return Ok(left.cmp(&right));
            }
        }
        Ok(core::cmp::Ordering::Equal)
    }
}
