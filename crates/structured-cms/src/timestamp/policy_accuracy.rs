//! Explicit caller-established policy accuracy, never document discovery.

use super::Accuracy;
use core::fmt;
use structured_asn1::Oid;

/// Trusted accuracy for an explicitly identified TSA policy.
/// The caller authenticates this policy and its association with the selected
/// TSA. The checker compares its identifier to the signed `TSTInfo` policy.
#[derive(Debug, Clone, Copy)]
pub struct PolicyAccuracy<'a> {
    policy: Oid<'a>,
    accuracy: Accuracy,
}

/// A fractional accuracy component exceeds its decomposed 0..=999 range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPolicyAccuracy;

impl fmt::Display for InvalidPolicyAccuracy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("policy accuracy fractional component exceeds 999")
    }
}
impl core::error::Error for InvalidPolicyAccuracy {}

impl<'a> PolicyAccuracy<'a> {
    /// Bind a caller-established deviation to its policy identifier. Zero
    /// denotes an omitted component, not an implicit whole-accuracy default.
    pub const fn new(policy: Oid<'a>, accuracy: Accuracy) -> Result<Self, InvalidPolicyAccuracy> {
        if accuracy.millis() > 999 || accuracy.micros() > 999 {
            return Err(InvalidPolicyAccuracy);
        }
        Ok(Self { policy, accuracy })
    }
    /// Identifier whose equality the checker requires, even if the token
    /// already declares accuracy and therefore takes precedence.
    #[must_use]
    pub const fn policy(self) -> Oid<'a> {
        self.policy
    }
    /// Explicit trusted deviation; no signature or trust verdict is implied.
    #[must_use]
    pub const fn accuracy(self) -> Accuracy {
        self.accuracy
    }
}

/// Effective deviation with its original source kept explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveAccuracy {
    /// Accuracy declared in the signed `TSTInfo`.
    Token(Accuracy),
    /// Accuracy supplied by the caller for the matching signed TSA policy.
    CallerPolicy(Accuracy),
}
impl EffectiveAccuracy {
    /// Deviation to use for generation interval arithmetic.
    #[must_use]
    pub const fn accuracy(self) -> Accuracy {
        match self {
            Self::Token(value) | Self::CallerPolicy(value) => value,
        }
    }
}
