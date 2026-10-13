//! Update interval facts using explicitly supplied UTC evidence.

use super::Authenticated;
use crate::error::{Error, Result};
use crate::temporal::{LeapTable, Reading, Uncertainty};
use structured_asn1::memory::Memory;

/// Freshness of an authenticated source, independently of target scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The supplied moment is in [thisUpdate, nextUpdate).
    Current,
    /// Exactly nextUpdate. Cache reuse and newly fetched replacement have
    /// different endpoint rules in RFC 5280 §6.3.3(a); no policy is inferred.
    AtNextUpdate,
    /// The source was issued after the supplied moment.
    NotYetCurrent,
    /// The supplied moment is strictly after nextUpdate.
    Stale,
    /// No next update was supplied; no lifetime is inferred.
    MissingNextUpdate,
    /// The encoded update interval is empty or inverted.
    InvalidUpdateOrder,
    /// UTC facts cannot establish one of the compared labels.
    Uncertain(Uncertainty),
}

pub(crate) fn update_window(
    this: crate::Time,
    next: Option<crate::Time>,
    now: Reading,
    utc: &LeapTable<'_>,
    execution: &Memory,
    origin: (&'static str, u64),
) -> Result<Freshness> {
    let (field, at) = origin;
    execution
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, field, at))?;
    // Three labels, each with three binary searches. Fixed work covers the
    // scalar checks/arithmetic; the full data-dependent cost precedes shifts.
    let searches = u64::from(usize::BITS - utc.transitions().len().leading_zeros() + 1);
    let comparisons = if next.is_some() { 9 } else { 6 };
    execution
        .charge_work(searches * comparisons + 64)
        .map_err(|reason| Error::resource(reason, field, at))?;
    let this = this.instant();
    let remainder = now.has_subnanosecond_remainder();
    let now = now.start();
    for label in [this, now] {
        if let Err(reason) = utc.shift(label, 0) {
            return Ok(Freshness::Uncertain(reason));
        }
    }
    let Some(next) = next else {
        // Missing expiry must not hide a future issue time or unknown UTC
        // label. RFC6960 §4.2.2.1 applies thisUpdate reliability independently.
        // https://www.rfc-editor.org/rfc/rfc6960#section-4.2.2.1
        return Ok(if now < this {
            Freshness::NotYetCurrent
        } else {
            Freshness::MissingNextUpdate
        });
    };
    let next = next.instant();
    if let Err(reason) = utc.shift(next, 0) {
        return Ok(Freshness::Uncertain(reason));
    }
    Ok(if next <= this {
        Freshness::InvalidUpdateOrder
    } else if now < this {
        Freshness::NotYetCurrent
    } else if now == next && !remainder {
        Freshness::AtNextUpdate
    } else if now >= next {
        Freshness::Stale
    } else {
        Freshness::Current
    })
}

impl Authenticated<'_, '_> {
    /// Establish update-interval facts without reading a clock or fetching UTC
    /// announcements. RFC 5280 §§5.1.2.4–5.1.2.5 define whole-second update
    /// times. `Current` covers the half-open interval; exact nextUpdate is
    /// preserved separately because cached and newly obtained sources have
    /// different endpoint requirements in RFC 5280 §6.3.3(a).
    /// <https://www.rfc-editor.org/rfc/rfc5280#section-5.1.2.5>
    ///
    /// A subnanosecond remainder distinguishes exact nextUpdate from after it.
    /// All compared UTC labels are validated against the supplied table first.
    /// Missing coverage and contradicted leap labels remain uncertainty.
    pub fn freshness(
        &self,
        now: Reading,
        utc: &LeapTable<'_>,
        execution: &Memory,
    ) -> Result<Freshness> {
        update_window(
            self.crl().tbs().this_update(),
            self.crl().tbs().next_update(),
            now,
            utc,
            execution,
            ("certificateList.freshness", self.crl().span().start),
        )
    }
}
