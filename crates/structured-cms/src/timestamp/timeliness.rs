//! Request freshness facts, without a replay database or implicit clock.

use super::{Accuracy, BoundUncertainty, earliest, latest};
use structured_pkix::temporal::{Instant, LeapTable, Reading};

/// Caller-supplied moving window for a uniquely outstanding complete imprint.
///
/// RFC3161 §6 requires the requester to remember hashes and establish their
/// uniqueness. This value asserts that caller-owned precondition; it neither
/// keeps that history nor proves the request imprint or signature matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestWindow {
    start: Instant,
    end: Instant,
}

impl RequestWindow {
    /// Admits ordered endpoints. Caller tolerance must already be in them.
    #[must_use]
    pub fn for_unique_imprint(start: Instant, end: Instant) -> Option<Self> {
        if start > end {
            return None;
        }
        Some(Self { start, end })
    }
}

/// How the supplied facts establish, fail or leave freshness unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timeliness {
    /// An archived token with a supplied local reference, not a live response.
    NotRequested,
    /// Complete accuracy/precision interval fits the supplied request window.
    LocalWindow,
    /// No usable window comparison; a separately checked nonce matches.
    RequestNonce,
    /// A performed local-reference comparison found the token in the future.
    Future,
    /// A performed interval comparison found it outside the request window.
    OutsideWindow,
    /// Live request context supplied no usable freshness evidence.
    Unverified,
    /// Missing accuracy or UTC facts prevent the supplied temporal comparison.
    Uncertain(BoundUncertainty),
}

/// Evaluates explicit time facts; it does not establish signature or trust.
///
/// `nonce` is the result of comparing the parsed request and token nonce, not
/// merely nonce presence. `requested` distinguishes a live request from archived
/// evidence. No clock is read, no tolerance invented and no replay state kept.
/// Full-interval containment is the explicit supplied-window contract, not an
/// ASN.1 conformance rule. A completed negative comparison takes precedence over
/// nonce fallback; missing facts remain uncertainty when no nonce can help.
#[must_use]
pub fn timeliness(
    reading: Reading,
    accuracy: Option<Accuracy>,
    utc: &LeapTable<'_>,
    reference: Option<Instant>,
    requested: bool,
    nonce: Option<bool>,
    window: Option<RequestWindow>,
) -> Timeliness {
    // RFC3161 §§2.2, 6 permit nonce freshness without a usable local clock.
    // They do not make a nonce erase an already performed negative time check.
    // https://www.rfc-editor.org/rfc/rfc3161.html#section-6
    let lower = earliest(reading, accuracy, utc);
    if let (Some(reference), Ok(lower)) = (reference, lower)
        && lower > reference
    {
        return Timeliness::Future;
    }
    if let Some(window) = window {
        match lower.and_then(|start| latest(reading, accuracy, utc).map(|end| (start, end))) {
            Ok((start, end)) => {
                if start < window.start || end > window.end {
                    return Timeliness::OutsideWindow;
                }
                return Timeliness::LocalWindow;
            }
            Err(reason) => {
                if nonce == Some(true) {
                    return Timeliness::RequestNonce;
                }
                return Timeliness::Uncertain(reason);
            }
        }
    }
    if nonce == Some(true) {
        return Timeliness::RequestNonce;
    }
    if requested {
        return Timeliness::Unverified;
    }
    if reference.is_some() {
        match lower {
            Ok(_) => Timeliness::NotRequested,
            Err(reason) => Timeliness::Uncertain(reason),
        }
    } else {
        Timeliness::Unverified
    }
}
