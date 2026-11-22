//! Caller-established revocation facts, without evidence acquisition or assessment.

use structured_pkix::{
    Time,
    crl::{Reason, Reasons},
    temporal::Uncertainty,
};

/// A recorded revocation, preserving the source date and optional reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revoked {
    /// The date recorded by the source.
    pub at: Time,
    /// The reason recorded by the source.
    pub reason: Option<Reason>,
}

/// A revocation's established relation to the signature interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// Before the earliest moment the signature could have been made.
    Before,
    /// Not proven after the signature, including an unknown lower bound.
    NotProvablyAfter,
}

/// What already authenticated evidence establishes across the interval.
/// Indices refer to the caller's statement catalogue, not a new common store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// An authenticated responder states the certificate was never issued.
    NotIssued {
        /// Deciding statement index.
        basis: usize,
    },
    /// Not revoked during the interval; a later recorded revocation stays visible.
    NotRevoked {
        /// Deciding statement index.
        basis: usize,
        /// A revocation proven after the interval.
        later: Option<Revoked>,
    },
    /// A recorded revocation reaches the interval.
    Revoked {
        /// Deciding statement index.
        basis: usize,
        /// Source revocation facts.
        revoked: Revoked,
        /// Established temporal relation.
        when: When,
    },
    /// A recorded suspension reaches the interval.
    OnHold {
        /// Deciding statement index.
        basis: usize,
    },
    /// Held or revoked at an unknown moment, without evidence distinguishing them.
    HeldOrRevoked {
        /// Deciding statement index.
        basis: usize,
    },
    /// Evidence is not fresh enough under the caller's selected freshness policy.
    NotFresh {
        /// Deciding statement index.
        basis: usize,
    },
    /// Fresh evidence covers only some revocation reasons.
    PartialReasons {
        /// Deciding statement index.
        basis: usize,
        /// Reasons covered by the supplied deciding sources together.
        covered: Reasons,
    },
    /// A supplied responder does not know this certificate's status.
    Unknown {
        /// Deciding statement index.
        basis: usize,
    },
    /// Equally current evidence conflicts.
    Conflict {
        /// First conflicting statement index.
        first: usize,
        /// Second conflicting statement index.
        second: usize,
    },
    /// Supplied UTC facts cannot establish the temporal relation.
    Uncertain(Uncertainty),
    /// No supplied source states this certificate's status.
    NoEvidence,
}
