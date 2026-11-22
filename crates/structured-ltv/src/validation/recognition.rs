//! Anchor recognition supplied by a trust-scheme owner, without list evaluation.

/// What the caller's recognition process establishes for the requested time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recognition {
    /// The supplied recognition rule holds for the complete requested interval.
    Recognized,
    /// Complete history is available and the rule holds nowhere in the interval.
    NotRecognized,
    /// Complete history contains both recognized and unrecognized periods.
    Mixed,
    /// Part of the interval has no admitted history.
    IncompleteHistory,
    /// Overlapping sources prevent choosing a consistent history.
    ConflictingHistory,
    /// Conditions or certificate facts needed by the rule are unavailable.
    UnsupportedConditions,
    /// No applicable recognition rule was supplied.
    NoRule,
    /// Binding, entity and rule validity have no common effective interval.
    OutsideValidity,
    /// Proven temporal bounds are unavailable.
    UnknownTime,
    /// Only an unproven time claim is available.
    ClaimedTime,
    /// Only an existence upper bound is proven.
    UpperBoundOnly,
    /// Only a lower bound is proven.
    LowerBoundOnly,
}
