//! Format-owner authentication of an original protected credential.

use crate::pki::Authorities;

/// Completed format authentication, separate from application authorization.
/// This is the same contract for XML, CMS and other `AdES` credential carriers;
/// each carrier binds the result to its actual original payload and signer.
pub enum Authentication<'path, 'document, E> {
    /// The original credential format has no selected authentication handler.
    Unsupported,
    /// The selected handler completed and rejected the original credential.
    Rejected,
    /// Original signature/issuer authentication succeeded using these actual
    /// authority paths/effective keys. Asserted-role authorization, historical
    /// trust and revocation/freshness acceptance remain separate.
    Authenticated {
        /// Actual retained format receipt, not a trusted boolean.
        evidence: E,
        /// Complete authority inputs used by authentication. Empty Paths is
        /// insufficient evidence, never an implicit certificate-free result.
        authorities: Authorities<'path, 'document>,
    },
}
