use core::fmt;

/// Invalid input and unavailable capabilities, independent of signature mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A field, basis or domain is outside the implemented capability.
    UnsupportedDomain,
    /// A polynomial fails the required field checks.
    InvalidField,
    /// Curve coefficients, order or base point fail domain validation.
    InvalidDomain,
    /// A custom domain needs independent primitivity/primality evidence.
    ValidationEvidenceRequired,
    /// The caller's random source failed to produce a usable bounded sample.
    RandomSampleRefused,
    /// The public point is malformed, off-curve or outside the subgroup.
    InvalidKey,
    /// The selected encoding has an invalid length or nonzero unused bits.
    InvalidEncoding,
    /// A packed substitution table is not eight permutations of 0 through 15.
    InvalidDke,
    /// The requested hash output length is unsupported.
    InvalidOutputSize,
    /// An input exceeds the bounded interface or hash-length representation.
    InputTooLong,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedDomain => "unsupported DSTU domain",
            Self::InvalidField => "invalid DSTU field",
            Self::InvalidDomain => "invalid DSTU domain",
            Self::ValidationEvidenceRequired => "custom domain validation evidence required",
            Self::RandomSampleRefused => "random sampling bound exhausted",
            Self::InvalidKey => "invalid DSTU public key",
            Self::InvalidEncoding => "invalid DSTU encoding",
            Self::InvalidDke => "invalid GOST substitution table",
            Self::InvalidOutputSize => "invalid hash output size",
            Self::InputTooLong => "input exceeds the supported bound",
        })
    }
}

impl core::error::Error for Error {}
