//! UTC arithmetic with caller-supplied leap-second facts.
//!
//! UTC arithmetic uses no clock, network, built-in correction calendar or
//! allocation. [`ExactReading`] additionally retains finer decimal precision
//! in accounted storage. Applications authenticate and refresh correction
//! facts; their declared coverage is never extended by assumption.

const NANOS: i128 = 1_000_000_000;

mod parse;
mod precision;
pub(crate) use parse::{admit_generalized, generalized};
pub use parse::{read_generalized, read_generalized_exact};
pub use precision::{CompareError, ExactReading};

/// A parsed moment, retaining whether digits finer than a nanosecond remain.
/// The upper endpoint cannot be rounded without UTC correction facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    start: Instant,
    subnanosecond: bool,
}

impl Reading {
    /// The labelled nanosecond containing the moment, rounded down.
    #[must_use]
    pub const fn start(self) -> Instant {
        self.start
    }

    /// Whether the represented moment is strictly later than `start`.
    #[must_use]
    pub const fn has_subnanosecond_remainder(self) -> bool {
        self.subnanosecond
    }

    /// Validate the label and round upward using the supplied UTC facts.
    pub fn upper_bound(self, table: &LeapTable<'_>) -> Result<Instant, Uncertainty> {
        table.shift(self.start, i128::from(self.subnanosecond))
    }
}

impl From<Instant> for Reading {
    fn from(start: Instant) -> Self {
        Self {
            start,
            subnanosecond: false,
        }
    }
}

/// A UTC label with nanosecond precision, preserving an inserted second.
///
/// Ordering is by UTC label, not by POSIX timestamp. Construction preserves
/// a label; only a [`LeapTable`] can establish whether it occurred in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    seconds: i64,
    leap: bool,
    nanos: u32,
}

impl Instant {
    /// Internal infallible construction of an ordinary whole-second label.
    pub(crate) const fn whole(seconds: i64) -> Self {
        Self {
            seconds,
            leap: false,
            nanos: 0,
        }
    }

    /// An ordinary POSIX-labelled second and its fractional nanoseconds.
    #[must_use]
    pub const fn new(seconds: i64, nanos: u32) -> Option<Self> {
        if nanos >= 1_000_000_000 {
            return None;
        }
        Some(Self {
            seconds,
            leap: false,
            nanos,
        })
    }

    /// The inserted second after `seconds`, which must label UTC 23:59:59.
    /// This does not assert that an insertion actually occurred on that date.
    #[must_use]
    pub const fn leap_after(seconds: i64, nanos: u32) -> Option<Self> {
        if seconds == i64::MAX || seconds.rem_euclid(86_400) != 86_399 || nanos >= 1_000_000_000 {
            return None;
        }
        Some(Self {
            seconds,
            leap: true,
            nanos,
        })
    }

    /// The POSIX label, or the preceding second's label for a leap second.
    /// Not an elapsed-seconds coordinate; use [`LeapTable::shift`] for arithmetic.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Whether this labels the inserted second after [`Self::seconds`].
    #[must_use]
    pub const fn is_leap_second(self) -> bool {
        self.leap
    }

    /// Nanoseconds within the labelled second, always less than one billion.
    #[must_use]
    pub const fn nanos(self) -> u32 {
        self.nanos
    }
}

/// A correction effective from a UTC midnight, expressed cumulatively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    at: i64,
    correction: i32,
}

impl Transition {
    /// `at` is the POSIX label of midnight after the changed day.
    /// `correction` is the net inserted minus deleted seconds since coverage
    /// began, not the absolute TAI-UTC offset. [`LeapTable::new`] validates it.
    #[must_use]
    pub const fn new(at: i64, correction: i32) -> Self {
        Self { at, correction }
    }

    /// Midnight from which the new cumulative correction applies.
    #[must_use]
    pub const fn at(self) -> i64 {
        self.at
    }

    /// Cumulative correction relative to the beginning of this table.
    #[must_use]
    pub const fn correction(self) -> i32 {
        self.correction
    }

    fn linear(self) -> i128 {
        i128::from(self.at) + i128::from(self.correction)
    }
}

/// Why a supplied correction table cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidTable {
    /// Coverage is empty, reversed, or begins at a second deleted by a correction.
    Coverage,
    /// Transitions are unordered, duplicated, or outside the stated coverage.
    Order,
    /// A correction changes by something other than one second.
    Correction,
    /// A transition is not at the start of a UTC calendar month.
    Boundary,
}

/// Why elapsed-time arithmetic cannot establish a result.
/// This is not a signature-verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uncertainty {
    /// The source or destination is outside the caller's known interval.
    OutsideCoverage,
    /// The label contradicts the supplied UTC facts: an absent insertion or
    /// an ordinary second removed by a negative correction.
    NotInUtc,
    /// The requested arithmetic exceeds the numeric representation.
    OutOfRange,
}

/// Borrowed, validated UTC corrections for `[start, end)` POSIX labels.
///
/// The caller asserts that every correction in this interval is listed.
/// Empty entries therefore mean no corrections *inside* the interval only.
/// The table authenticates no source and makes no prediction outside it.
#[derive(Debug, Clone, Copy)]
pub struct LeapTable<'a> {
    start: i64,
    end: i64,
    transitions: &'a [Transition],
}

impl<'a> LeapTable<'a> {
    /// Validate the complete table once, without copying its entries.
    /// A transition at `end` is included because it changes the preceding day.
    pub fn new(start: i64, end: i64, transitions: &'a [Transition]) -> Result<Self, InvalidTable> {
        if start >= end {
            return Err(InvalidTable::Coverage);
        }
        let mut previous = start;
        let mut correction = 0i32;
        for entry in transitions {
            if entry.at <= previous || entry.at > end {
                return Err(InvalidTable::Order);
            }
            if (i64::from(entry.correction) - i64::from(correction)).abs() != 1 {
                return Err(InvalidTable::Correction);
            }
            // RFC 3339 §5.7 and Appendix D describe positive and negative
            // corrections at UTC month ends. This is a UTC-facts constraint,
            // not an ASN.1 spelling rule: https://www.rfc-editor.org/rfc/rfc3339#section-5.7
            if entry.at.rem_euclid(86_400) != 0 || super::time::civil_from_seconds(entry.at).2 != 1
            {
                return Err(InvalidTable::Boundary);
            }
            previous = entry.at;
            correction = entry.correction;
        }
        let table = Self {
            start,
            end,
            transitions,
        };
        if table
            .coordinate(Instant {
                seconds: start,
                leap: false,
                nanos: 0,
            })
            .is_err()
        {
            return Err(InvalidTable::Coverage);
        }
        Ok(table)
    }

    /// The exact borrowed correction entries used by this calculation.
    #[must_use]
    pub const fn transitions(&self) -> &'a [Transition] {
        self.transitions
    }

    /// Move by elapsed nanoseconds, including inserted and deleted seconds.
    /// Both endpoints must be covered; since coverage is contiguous, the
    /// whole intervening interval is then covered as well.
    ///
    /// RFC 3161 §2.4.2 specifies subtracting/adding accuracy to `genTime`:
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2>. The supplied
    /// coverage and explicit uncertainty are API decisions, not RFC mandates.
    pub fn shift(&self, at: Instant, nanos: i128) -> Result<Instant, Uncertainty> {
        let here = self.coordinate(at)?;
        let moved = here.checked_add(nanos).ok_or(Uncertainty::OutOfRange)?;
        let second = moved.div_euclid(NANOS);
        let fraction =
            u32::try_from(moved.rem_euclid(NANOS)).map_err(|_| Uncertainty::OutOfRange)?;
        let count = self
            .transitions
            .partition_point(|entry| entry.linear() <= second);
        let correction = self.correction_before(count);
        // A positive transition leaves one extra linear second immediately
        // before midnight; preserve it rather than aliasing either neighbour.
        let result = if let Some(next) = self.transitions.get(count)
            && next.correction > correction
            && second == next.linear() - 1
        {
            Instant {
                seconds: next.at - 1,
                leap: true,
                nanos: fraction,
            }
        } else {
            let seconds = i64::try_from(second - i128::from(correction))
                .map_err(|_| Uncertainty::OutOfRange)?;
            Instant {
                seconds,
                leap: false,
                nanos: fraction,
            }
        };
        self.coordinate(result)?;
        Ok(result)
    }

    fn correction_before(&self, count: usize) -> i32 {
        if count == 0 {
            0
        } else {
            self.transitions[count - 1].correction
        }
    }

    fn coordinate(&self, at: Instant) -> Result<i128, Uncertainty> {
        if at.seconds < self.start || at.seconds >= self.end {
            return Err(Uncertainty::OutsideCoverage);
        }
        let count = self
            .transitions
            .partition_point(|entry| entry.at <= at.seconds);
        let correction = self.correction_before(count);
        let next = self
            .transitions
            .get(count)
            .filter(|entry| i128::from(entry.at) == i128::from(at.seconds) + 1);
        if at.leap {
            if next.is_none_or(|entry| entry.correction <= correction) {
                return Err(Uncertainty::NotInUtc);
            }
        } else if next.is_some_and(|entry| entry.correction < correction) {
            return Err(Uncertainty::NotInUtc);
        }
        Ok(
            (i128::from(at.seconds) + i128::from(correction) + i128::from(at.leap)) * NANOS
                + i128::from(at.nanos),
        )
    }
}

#[cfg(test)]
mod tests;
