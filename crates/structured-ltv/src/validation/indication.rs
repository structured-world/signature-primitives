//! The status indications and sub-indications of ETSI EN 319 102-1 V1.4.1
//! clause 5.1.3, Tables 5 to 7, as stable values.

/// The main status indication (Table 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Indication {
    /// The cryptographic checks succeeded and every check the policy
    /// prescribes passed.
    TotalPassed,
    /// The cryptographic checks failed, the format could not be processed, or
    /// the signing certificate is proven invalid when the signature was made.
    TotalFailed,
    /// The available information settles neither.
    Indeterminate,
}

impl Indication {
    /// The token Table 5 writes it as.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Indication::TotalPassed => "TOTAL-PASSED",
            Indication::TotalFailed => "TOTAL-FAILED",
            Indication::Indeterminate => "INDETERMINATE",
        }
    }
}

/// A sub-indication of Table 6, each belonging to exactly one main indication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubIndication {
    /// The signature is not conformant enough to be verified.
    FormatFailure,
    /// The hash of a signed data object does not match.
    HashFailure,
    /// The signature value does not verify under the signing certificate.
    SigCryptoFailure,
    /// Revoked, with proof the signature was made after the revocation.
    Revoked,
    /// Proof the signature was made after the certificate's notAfter.
    Expired,
    /// Proof the signature was made before the certificate's notBefore.
    NotYetValid,
    /// Attributes of the signature do not meet the constraints.
    SigConstraintsFailure,
    /// The chain does not meet the certificate constraints.
    ChainConstraintsFailure,
    /// The certificates available produced an error for another reason.
    CertificateChainGeneralFailure,
    /// An algorithm or key size is below the required level for material
    /// proven produced after it stopped being considered secure.
    CryptoConstraintsFailure,
    /// A formal policy file could not be processed.
    PolicyProcessingError,
    /// The document containing the signature policy is not available.
    SignaturePolicyNotAvailable,
    /// Timestamps do not respect the ordering constraints.
    TimestampOrderFailure,
    /// The signing certificate cannot be identified.
    NoSigningCertificateFound,
    /// No chain was found for the signing certificate.
    NoCertificateChainFound,
    /// The anchor is not trusted at the validation time, and the signing time
    /// cannot be placed against when it was.
    NoCertificateChainFoundNoPoe,
    /// Revoked, and the signing time cannot be placed against the revocation.
    RevokedNoPoe,
    /// An intermediate authority is revoked.
    RevokedCaNoPoe,
    /// Outside the certificate's validity at the validation time, known not
    /// revoked, and the signing time cannot be placed inside the validity.
    OutOfBoundsNotRevoked,
    /// Outside the certificate's validity at the validation time, and the
    /// signing time cannot be placed inside it.
    OutOfBoundsNoPoe,
    /// The revocation data's issuer was outside its validity, with no proof
    /// the data existed within it.
    RevocationOutOfBoundsNoPoe,
    /// An algorithm or key size is below the required level, with no proof
    /// the material was produced while it was considered secure.
    CryptoConstraintsFailureNoPoe,
    /// A proof of existence is missing to place a signed object before a
    /// compromising event.
    NoPoe,
    /// Revocation status information that may be fresh enough later.
    TryLater,
    /// Signed data cannot be obtained.
    SignedDataNotFound,
    /// A diagnostic Table 6 does not name.
    Custom(Custom),
}

/// The implementation diagnostics reported under `CUSTOM`, each a reason clause
/// 5.1.3 leaves to the implementation to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Custom {
    /// The signature value names an algorithm this build does not compute.
    UnsupportedAlgorithm,
    /// A responder does not know the certificate's status.
    RevocationUnknown,
    /// An authenticated OCSP responder explicitly says the certificate was never issued.
    CertificateNotIssued,
    /// Sources issued at the same moment say different things.
    RevocationConflict,
    /// No source covers every revocation reason.
    RevocationReasonsUncovered,
    /// Held or revoked at an unrecorded moment the interval may reach.
    RevocationHeldOrRevoked,
    /// The UTC facts cannot order the evidence against the interval.
    TimeUncertain,
    /// The trusted list's history does not cover the time asked about.
    TrustHistoryIncomplete,
    /// The trusted list's sources disagree about that time.
    TrustHistoryConflicting,
    /// A condition the trusted list sets cannot be evaluated.
    TrustConditionsUnsupported,
}

impl Custom {
    /// A stable code for the diagnostic.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Custom::UnsupportedAlgorithm => "UNSUPPORTED_ALGORITHM",
            Custom::RevocationUnknown => "REVOCATION_UNKNOWN",
            Custom::CertificateNotIssued => "CERTIFICATE_NOT_ISSUED",
            Custom::RevocationConflict => "REVOCATION_CONFLICT",
            Custom::RevocationReasonsUncovered => "REVOCATION_REASONS_UNCOVERED",
            Custom::RevocationHeldOrRevoked => "REVOCATION_HELD_OR_REVOKED",
            Custom::TimeUncertain => "TIME_UNCERTAIN",
            Custom::TrustHistoryIncomplete => "TRUST_HISTORY_INCOMPLETE",
            Custom::TrustHistoryConflicting => "TRUST_HISTORY_CONFLICTING",
            Custom::TrustConditionsUnsupported => "TRUST_CONDITIONS_UNSUPPORTED",
        }
    }
}

/// What would let a rerun reach a different result (Table 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Retry {
    /// A different chain can be constructed.
    OtherChain,
    /// The formal policy file becomes accessible.
    PolicyFile,
    /// The policy document becomes available.
    PolicyDocument,
    /// The signing certificate becomes available.
    SigningCertificate,
    /// Authority certificates that allow a chain become available.
    AuthorityCertificates,
    /// Further proofs of existence become available.
    ProofOfExistence,
    /// Revocation status information that may be fresh enough arrives.
    FresherRevocation,
}

impl SubIndication {
    /// The main indication it belongs to (Table 6).
    #[must_use]
    pub const fn indication(self) -> Indication {
        match self {
            SubIndication::FormatFailure
            | SubIndication::HashFailure
            | SubIndication::SigCryptoFailure
            | SubIndication::Revoked
            | SubIndication::Expired
            | SubIndication::NotYetValid => Indication::TotalFailed,
            _ => Indication::Indeterminate,
        }
    }

    /// The token Table 6 writes it as.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SubIndication::FormatFailure => "FORMAT_FAILURE",
            SubIndication::HashFailure => "HASH_FAILURE",
            SubIndication::SigCryptoFailure => "SIG_CRYPTO_FAILURE",
            SubIndication::Revoked => "REVOKED",
            SubIndication::Expired => "EXPIRED",
            SubIndication::NotYetValid => "NOT_YET_VALID",
            SubIndication::SigConstraintsFailure => "SIG_CONSTRAINTS_FAILURE",
            SubIndication::ChainConstraintsFailure => "CHAIN_CONSTRAINTS_FAILURE",
            SubIndication::CertificateChainGeneralFailure => "CERTIFICATE_CHAIN_GENERAL_FAILURE",
            SubIndication::CryptoConstraintsFailure => "CRYPTO_CONSTRAINTS_FAILURE",
            SubIndication::PolicyProcessingError => "POLICY_PROCESSING_ERROR",
            SubIndication::SignaturePolicyNotAvailable => "SIGNATURE_POLICY_NOT_AVAILABLE",
            SubIndication::TimestampOrderFailure => "TIMESTAMP_ORDER_FAILURE",
            SubIndication::NoSigningCertificateFound => "NO_SIGNING_CERTIFICATE_FOUND",
            SubIndication::NoCertificateChainFound => "NO_CERTIFICATE_CHAIN_FOUND",
            SubIndication::NoCertificateChainFoundNoPoe => "NO_CERTIFICATE_CHAIN_FOUND_NO_POE",
            SubIndication::RevokedNoPoe => "REVOKED_NO_POE",
            SubIndication::RevokedCaNoPoe => "REVOKED_CA_NO_POE",
            SubIndication::OutOfBoundsNotRevoked => "OUT_OF_BOUNDS_NOT_REVOKED",
            SubIndication::OutOfBoundsNoPoe => "OUT_OF_BOUNDS_NO_POE",
            SubIndication::RevocationOutOfBoundsNoPoe => "REVOCATION_OUT_OF_BOUNDS_NO_POE",
            SubIndication::CryptoConstraintsFailureNoPoe => "CRYPTO_CONSTRAINTS_FAILURE_NO_POE",
            SubIndication::NoPoe => "NO_POE",
            SubIndication::TryLater => "TRY_LATER",
            SubIndication::SignedDataNotFound => "SIGNED_DATA_NOT_FOUND",
            SubIndication::Custom(_) => "CUSTOM",
        }
    }

    /// The condition under which a rerun may differ (Table 7), or `None`
    /// where the table lists none.
    #[must_use]
    pub const fn retry(self) -> Option<Retry> {
        match self {
            SubIndication::ChainConstraintsFailure
            | SubIndication::CertificateChainGeneralFailure => Some(Retry::OtherChain),
            SubIndication::PolicyProcessingError => Some(Retry::PolicyFile),
            SubIndication::SignaturePolicyNotAvailable => Some(Retry::PolicyDocument),
            SubIndication::NoSigningCertificateFound => Some(Retry::SigningCertificate),
            SubIndication::NoCertificateChainFound => Some(Retry::AuthorityCertificates),
            SubIndication::RevokedNoPoe
            | SubIndication::RevokedCaNoPoe
            | SubIndication::OutOfBoundsNotRevoked
            | SubIndication::OutOfBoundsNoPoe
            | SubIndication::CryptoConstraintsFailureNoPoe
            | SubIndication::NoPoe => Some(Retry::ProofOfExistence),
            SubIndication::TryLater => Some(Retry::FresherRevocation),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
