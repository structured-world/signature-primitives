//! Table 6 and Table 7 of ETSI EN 319 102-1 V1.4.1, as values.

use super::*;

const ALL: [SubIndication; 26] = [
    SubIndication::FormatFailure,
    SubIndication::HashFailure,
    SubIndication::SigCryptoFailure,
    SubIndication::Revoked,
    SubIndication::Expired,
    SubIndication::NotYetValid,
    SubIndication::SigConstraintsFailure,
    SubIndication::ChainConstraintsFailure,
    SubIndication::CertificateChainGeneralFailure,
    SubIndication::CryptoConstraintsFailure,
    SubIndication::PolicyProcessingError,
    SubIndication::SignaturePolicyNotAvailable,
    SubIndication::TimestampOrderFailure,
    SubIndication::NoSigningCertificateFound,
    SubIndication::NoCertificateChainFound,
    SubIndication::NoCertificateChainFoundNoPoe,
    SubIndication::RevokedNoPoe,
    SubIndication::RevokedCaNoPoe,
    SubIndication::OutOfBoundsNotRevoked,
    SubIndication::OutOfBoundsNoPoe,
    SubIndication::RevocationOutOfBoundsNoPoe,
    SubIndication::CryptoConstraintsFailureNoPoe,
    SubIndication::NoPoe,
    SubIndication::TryLater,
    SubIndication::SignedDataNotFound,
    SubIndication::Custom(Custom::UnsupportedAlgorithm),
];

/// Exactly the six sub-indications Table 6 places under TOTAL-FAILED are
/// failures; every other one, `CUSTOM` included, is indeterminate, and none
/// belongs to TOTAL-PASSED.
#[test]
fn each_sub_indication_belongs_to_the_main_indication_table_6_gives_it() {
    let failed: alloc::vec::Vec<_> = ALL
        .iter()
        .filter(|sub| sub.indication() == Indication::TotalFailed)
        .map(|sub| sub.as_str())
        .collect();
    assert_eq!(
        failed,
        [
            "FORMAT_FAILURE",
            "HASH_FAILURE",
            "SIG_CRYPTO_FAILURE",
            "REVOKED",
            "EXPIRED",
            "NOT_YET_VALID"
        ]
    );
    assert!(
        ALL.iter()
            .all(|sub| sub.indication() != Indication::TotalPassed)
    );
}

/// The tokens are the standard's, unique, and the main indications are the
/// three of Table 5; nothing names a legal or qualified status.
#[test]
fn tokens_are_the_standards_and_name_no_legal_status() {
    let mut tokens: alloc::vec::Vec<_> = ALL.iter().map(|sub| sub.as_str()).collect();
    tokens.sort_unstable();
    tokens.dedup();
    assert_eq!(tokens.len(), ALL.len());
    assert_eq!(Indication::TotalPassed.as_str(), "TOTAL-PASSED");
    assert_eq!(Indication::TotalFailed.as_str(), "TOTAL-FAILED");
    assert_eq!(Indication::Indeterminate.as_str(), "INDETERMINATE");
    for token in tokens {
        assert!(!token.contains("QUALIFIED") && !token.contains("LEGAL"));
    }
}

/// Table 7 names a retry condition for exactly these sub-indications.
#[test]
fn retry_conditions_are_table_7s() {
    let retried: alloc::vec::Vec<_> = ALL
        .iter()
        .filter_map(|sub| sub.retry().map(|retry| (sub.as_str(), retry)))
        .collect();
    assert_eq!(
        retried,
        [
            ("CHAIN_CONSTRAINTS_FAILURE", Retry::OtherChain),
            ("CERTIFICATE_CHAIN_GENERAL_FAILURE", Retry::OtherChain),
            ("POLICY_PROCESSING_ERROR", Retry::PolicyFile),
            ("SIGNATURE_POLICY_NOT_AVAILABLE", Retry::PolicyDocument),
            ("NO_SIGNING_CERTIFICATE_FOUND", Retry::SigningCertificate),
            ("NO_CERTIFICATE_CHAIN_FOUND", Retry::AuthorityCertificates),
            ("REVOKED_NO_POE", Retry::ProofOfExistence),
            ("REVOKED_CA_NO_POE", Retry::ProofOfExistence),
            ("OUT_OF_BOUNDS_NOT_REVOKED", Retry::ProofOfExistence),
            ("OUT_OF_BOUNDS_NO_POE", Retry::ProofOfExistence),
            ("CRYPTO_CONSTRAINTS_FAILURE_NO_POE", Retry::ProofOfExistence),
            ("NO_POE", Retry::ProofOfExistence),
            ("TRY_LATER", Retry::FresherRevocation),
        ]
    );
}
