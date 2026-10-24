//! RFC3161 checks consume the selected original member through one common pass.

use crate::{
    content::Content,
    error::Error as ArchiveError,
    zip::{MemberId, ReadFailure},
};
use structured_asn1::{Reader, memory::Execution, range::RangeSource};
use structured_cms::{
    provider::SignatureProvider,
    timestamp::{CheckContext, CheckedTimestamp, Token, TokenExtension},
};

/// Explicit check purpose; absence of live request fields never selects a
/// historical operation implicitly or relabels historical proof as freshness.
pub enum Context<'c, 'a, 'r> {
    /// Complete ordinary request/current-reference processing.
    Live(&'c CheckContext<'a, 'r>),
    /// Archived evidence; no live request, comparison instant or window allowed.
    Historical(&'c CheckContext<'a, 'r>),
}

/// Explicit covered input role. This does not assert that a source-produced
/// manifest is conforming, that its declared hashes match or that a TSA is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// Original data or ordinary assertion-manifest bytes.
    Data,
    /// Selected original archive-manifest bytes; coverage needs the graph proof.
    Archive,
}

/// Archive framing, actual payload and timestamp execution remain independent.
#[derive(Debug)]
pub enum Error<SE, PE, RE, D, G> {
    /// Source generation/current-source execution refused before checking.
    Archive(ArchiveError<SE>),
    /// The actual original member cannot be acquired completely.
    Payload(ReadFailure<SE, D, G>),
    /// Unchanged common check cause, including its independently retained map.
    Check(structured_cms::timestamp::CheckError<ReadFailure<SE, D, G>, PE, RE>),
}

/// One original token's actual input association and common execution answer.
/// This does not establish a trusted historical path or archive continuity.
pub struct Checked<'a, D, G> {
    token: MemberId<D, G>,
    input: MemberId<D, G>,
    inner: CheckedTimestamp<'a>,
}

impl<'a, D: Copy, G: Copy> Checked<'a, D, G> {
    /// Exact original time assertion, not a filename selected by success.
    #[must_use]
    pub fn token(&self) -> MemberId<D, G> {
        self.token
    }
    /// Exact complete original file/manifest consumed by the imprint check.
    #[must_use]
    pub fn input(&self) -> MemberId<D, G> {
        self.input
    }
    /// Every independent common timestamp answer, including negative outcomes.
    #[must_use]
    pub fn common(&self) -> &CheckedTimestamp<'a> {
        &self.inner
    }
    /// Transfers the original common answer without copying evidence/source maps.
    #[must_use]
    pub fn into_common(self) -> CheckedTimestamp<'a> {
        self.inner
    }
}

impl<'v, 's, S: RangeSource> Content<'v, 's, S> {
    /// Requires the actual carried token/source first, then invokes the shared
    /// full asynchronous timestamp validator on the sealed original payload.
    /// Candidate/key/time/extension recognition stay caller-provided contracts.
    #[expect(
        clippy::result_large_err,
        reason = "retain original timestamp diagnostic maps on refusal without a secondary allocation"
    )]
    pub async fn check_timestamp<'a, P, PE, RE>(
        &'a self,
        token: &'a Token<'a>,
        parent: &Reader<'a>,
        provider: &'a P,
        context: Context<'_, 'a, '_>,
        input: &impl crate::payload::Payload<'v, 's, S>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<
        Checked<'a, S::Document, S::Generation>,
        Error<S::Error, PE, RE, S::Document, S::Generation>,
    >
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let execution = parent.execution();
        self.require(token.message(), parent, &execution)
            .map_err(Error::Archive)?;
        if !core::ptr::eq(self.member().archive(), input.member().archive()) {
            return Err(Error::Archive(ArchiveError::Foreign {
                range: self.enclosure(),
            }));
        }
        let mut source = input.source(&execution).map_err(Error::Payload)?;
        let checked = match context {
            Context::Live(context) => {
                token
                    .check_async(provider, parent, context, &mut source, recognizes)
                    .await
            }
            Context::Historical(context) => {
                token
                    .check_historical_async(provider, parent, context, &mut source, recognizes)
                    .await
            }
        }
        .map_err(Error::Check)?;
        self.member()
            .archive()
            .admit(&execution, self.enclosure())
            .map_err(Error::Archive)?;
        Ok(Checked {
            token: self.member().id(),
            input: input.member().id(),
            inner: checked,
        })
    }
}
