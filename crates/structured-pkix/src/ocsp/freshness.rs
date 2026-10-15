//! Update-window facts; maximum age and clock tolerance remain caller policy.

use super::SingleResponse;
use crate::crl::{Freshness, update_window};
use crate::temporal::{LeapTable, Reading, Uncertainty};
use structured_asn1::memory::Work;

/// The current UTC label's relation to one assertion's update window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateWindow {
    /// In [thisUpdate, nextUpdate), without claiming sufficient maximum age.
    Within,
    /// Current label precedes thisUpdate.
    NotYetCurrent,
    /// nextUpdate is at or before the current label; OCSP's endpoint is strict.
    Stale,
    /// No nextUpdate: no expiry or default TTL is invented. The responder may
    /// have newer information continuously (RFC6960 §4.2.2.1).
    NoNextUpdate,
    /// The asserted update interval is empty or inverted.
    InvalidUpdateOrder,
    /// UTC correction evidence cannot establish a compared label.
    Uncertain(Uncertainty),
}

impl SingleResponse<'_> {
    /// Compare update labels using explicit UTC facts and the current account.
    /// RFC6960 §3.2(5) leaves "sufficiently recent" to the client's acceptance
    /// criteria; §3.2(6) requires nextUpdate, when present, greater than now.
    /// This result never supplies a maximum age, clock or clock-skew allowance.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-3.2>
    pub fn update_window<W: Work>(
        &self,
        now: Reading,
        utc: &LeapTable<'_>,
        execution: &W,
    ) -> crate::Result<UpdateWindow> {
        Ok(
            match update_window(
                self.this_update,
                self.next_update,
                now,
                utc,
                execution,
                ("ocspResponse.singleResponse.updateWindow", self.span.start),
            )? {
                Freshness::Current => UpdateWindow::Within,
                Freshness::AtNextUpdate | Freshness::Stale => UpdateWindow::Stale,
                Freshness::NotYetCurrent => UpdateWindow::NotYetCurrent,
                Freshness::MissingNextUpdate => UpdateWindow::NoNextUpdate,
                Freshness::InvalidUpdateOrder => UpdateWindow::InvalidUpdateOrder,
                Freshness::Uncertain(reason) => UpdateWindow::Uncertain(reason),
            },
        )
    }
}
