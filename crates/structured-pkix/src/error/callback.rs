//! Processing failures and the original error of an injected callback.

use core::fmt;

/// A callback-backed query that could not finish.
///
/// The wrapper allocates no storage. Any owned callback error data must retain
/// its own resource accounting until it is dropped.
#[derive(Debug)]
pub enum CallbackError<E> {
    /// Shared processing failed, including a located resource refusal.
    Processing(super::Error),
    /// The caller's callback failed, preserving its original cause.
    Callback(E),
}

impl<E> From<super::Error> for CallbackError<E> {
    fn from(error: super::Error) -> Self {
        Self::Processing(error)
    }
}

impl<E: fmt::Display> fmt::Display for CallbackError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Processing(error) => error.fmt(f),
            Self::Callback(error) => write!(f, "callback: {error}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for CallbackError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Processing(error) => Some(error),
            Self::Callback(error) => Some(error),
        }
    }
}

/// Result of shared processing that can invoke a fallible callback.
pub type CallbackResult<T, E> = core::result::Result<T, CallbackError<E>>;
