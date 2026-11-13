//! OpenSSL traditional private-key import. All output storage belongs to the caller.
//!
//! Use a wiping buffer for decrypted or encoded keys. A successful CBC decrypt
//! checks padding only. For a recognized encrypted envelope, treat a subsequent
//! key parse failure as a protected-container failure and do not retry as plaintext.

mod envelope;
mod key;

pub use envelope::Envelope;
pub use key::{Key, KeyFamily};

use structured_asn1::memory::{MemoryError, Work};

/// A traditional private-key import failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input does not identify a traditional container.
    #[error("not a traditional private-key container")]
    NotTraditional,
    /// A recognized password envelope could not be opened.
    #[error("could not open traditional password envelope")]
    Protected,
    /// The traditional key is malformed or uses unsupported parameters.
    #[error("invalid traditional private key")]
    InvalidKey,
    /// A DSA component exceeds the configured or fixed-storage limit.
    #[error("DSA component exceeds its size limit")]
    ComponentLimit,
    /// The output slice cannot hold the planned DER.
    #[error("output requires {required} bytes")]
    OutputTooShort {
        /// Exact size of the encoded key.
        required: usize,
    },
    /// The supplied work account refused the operation.
    #[error(transparent)]
    Resource(#[from] MemoryError),
}

fn charge(work: &impl Work, bytes: usize) -> Result<(), Error> {
    let amount = u64::try_from(bytes).map_err(|_| MemoryError::WorkExceeded)?;
    work.charge_work(amount)?;
    Ok(())
}
