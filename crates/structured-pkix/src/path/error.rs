//! Failures of path processing and the caller's injected capabilities.

use core::fmt;

/// A path operation that could not finish, preserving the originating cause.
///
/// A callback may report policy, provider or resource failures in its own error
/// type. These are distinct from a completed signature check answering `No` or
/// `Unsupported`, or a recognizer answering `false`. This wrapper allocates no
/// storage; owned data inside a callback error remains the callback's accounting
/// responsibility.
#[derive(Debug)]
pub enum BuildError<V, R> {
    /// Shared processing failed, including a located resource refusal.
    Processing(crate::Error),
    /// The injected signature verifier failed to execute its check.
    Verification(V),
    /// The injected extension recognizer failed to execute its query.
    Recognition(R),
}

/// Result of path processing with the injected callbacks' original error types.
pub type BuildResult<T, V, R> = core::result::Result<T, BuildError<V, R>>;

impl<V, R> From<crate::Error> for BuildError<V, R> {
    fn from(error: crate::Error) -> Self {
        Self::Processing(error)
    }
}

impl<V, R> From<crate::error::CallbackError<R>> for BuildError<V, R> {
    fn from(error: crate::error::CallbackError<R>) -> Self {
        match error {
            crate::error::CallbackError::Processing(error) => Self::Processing(error),
            crate::error::CallbackError::Callback(error) => Self::Recognition(error),
        }
    }
}

impl<V: fmt::Display, R: fmt::Display> fmt::Display for BuildError<V, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Processing(error) => error.fmt(f),
            Self::Verification(error) => write!(f, "signature verifier: {error}"),
            Self::Recognition(error) => write!(f, "extension recognizer: {error}"),
        }
    }
}

impl<V: core::error::Error + 'static, R: core::error::Error + 'static> core::error::Error
    for BuildError<V, R>
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Processing(error) => Some(error),
            Self::Verification(error) => Some(error),
            Self::Recognition(error) => Some(error),
        }
    }
}
