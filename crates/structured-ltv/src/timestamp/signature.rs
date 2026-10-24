//! A signature timestamp's association with the signer's checked path.

use super::{Interval, Purpose, TemporalError, Verified};
use crate::pki::{SignerReceipt, TimestampPath};
use crate::source::{Query, ScopeError};
use structured_pkix::temporal::LeapTable;

#[derive(Clone, Copy)]
enum Input {
    SignatureValue,
    Existence,
}

/// A completed mathematical/static association, still requiring authenticated
/// TSA path/status and signer revocation/algorithm/policy processing.
pub struct SignatureTime<'receipt, S, N, D, G, I> {
    signer: &'receipt S,
    timestamp: &'receipt Verified<N, D, G, I>,
    generation: Interval,
}

impl<'receipt, S, N, D, G, I> SignatureTime<'receipt, S, N, D, G, I> {
    /// Same original selected signature/certificate and checked static path.
    #[must_use]
    pub fn signer(&self) -> &'receipt S {
        self.signer
    }
    /// Same complete token check over the selected original signature value.
    #[must_use]
    pub fn timestamp(&self) -> &'receipt Verified<N, D, G, I> {
        self.timestamp
    }
    /// Entire stated generation interval, never a bare claimed signing time.
    #[must_use]
    pub fn generation(&self) -> Interval {
        self.generation
    }
}

/// Missing association facts do not assert that a certificate has expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureTimeFailure {
    /// Selected key/certificate or an original path digest is not established.
    Certificate,
    /// Static path was not checked over the complete generation interval.
    Interval,
}

/// Original execution/context error, not a completed negative time claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureTimeError<N> {
    /// Original current-source/generation/resource refusal.
    Scope(ScopeError<N>),
    /// The receipt belongs to another selected signature or source generation.
    Foreign {
        /// Original timestamp property.
        property: N,
    },
    /// The timestamp covers another kind of input; it cannot replace a
    /// signature timestamp simply because it also covers some signature bytes.
    Purpose {
        /// Original timestamp property.
        property: N,
    },
    /// Full stated accuracy/UTC interval cannot be established.
    Time {
        /// Original timestamp property.
        property: N,
        /// Original UTC uncertainty or execution refusal.
        cause: TemporalError,
    },
}

/// Mathematical/static binding or explicit insufficient facts, not a B-T grade.
pub enum SignatureTimeBinding<'receipt, S, N, D, G, I> {
    /// Same selected signature, with full generation-time static path coverage.
    Bound(SignatureTime<'receipt, S, N, D, G, I>),
    /// Required certificate/interval facts have not been established.
    Unproven(SignatureTimeFailure),
}

/// Association result in the query's original identity domain.
pub type SignatureTimeResult<'receipt, S, Q, I> = Result<
    SignatureTimeBinding<
        'receipt,
        S,
        <Q as Query>::Id,
        <Q as Query>::Document,
        <Q as Query>::Generation,
        I,
    >,
    SignatureTimeError<<Q as Query>::Id>,
>;

/// Associate a complete original signature timestamp with the actual signing
/// certificate/path, preserving source generation and its full accuracy.
///
/// EN319132-1 V1.3.1 §§5.3/6.3(o) timestamp the original signature value and
/// require creation before signing-certificate expiry/revocation. A checked
/// path interval containing the entire generation interval supplies static
/// validity; revocation and TSA authority remain separate necessary facts.
/// Neither an archive timestamp nor a claimed signing time can substitute here.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn signature_time<'receipt, 'path, 'document, S, Q, I>(
    signer: &'receipt S,
    timestamp: &'receipt Verified<Q::Id, Q::Document, Q::Generation, I>,
    utc: &LeapTable<'_>,
    query: &Q,
) -> SignatureTimeResult<'receipt, S, Q, I>
where
    'document: 'path,
    S: SignerReceipt<
            'path,
            'document,
            Id = Q::Id,
            Document = Q::Document,
            Generation = Q::Generation,
        >,
    Q: Query,
{
    bind(signer, timestamp, query, Input::SignatureValue, || {
        timestamp.interval(utc, query.execution())
    })
}

/// Reuse the complete generation interval already established by the actual
/// checked TSA path for this SAME token receipt. This has the same
/// source/purpose/certificate/static interval semantics as [`signature_time`],
/// without repeating UTC lookup or arithmetic.
pub fn signature_time_path<'receipt, 'path, 'document, S, Q, I>(
    signer: &'receipt S,
    path: &'receipt TimestampPath<'_, '_, '_, Q::Id, Q::Document, Q::Generation, I>,
    query: &Q,
) -> SignatureTimeResult<'receipt, S, Q, I>
where
    'document: 'path,
    S: SignerReceipt<
            'path,
            'document,
            Id = Q::Id,
            Document = Q::Document,
            Generation = Q::Generation,
        >,
    Q: Query,
{
    bind(
        signer,
        path.actor().verified(),
        query,
        Input::SignatureValue,
        || Ok(path.generation()),
    )
}

/// Associates an actual checked signature OR archive input with the selected
/// signer's static path interval. A format must already have bound that input
/// to this signature; this does not turn an archive into a signature property.
/// EN319142-1 §6.3 permits a covering document timestamp to supply `PAdES` B-T.
/// Other formats retain their independent signature-property requirements.
/// <https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
pub fn existence_time_path<'receipt, 'path, 'document, S, Q, I>(
    signer: &'receipt S,
    path: &'receipt TimestampPath<'_, '_, '_, Q::Id, Q::Document, Q::Generation, I>,
    query: &Q,
) -> SignatureTimeResult<'receipt, S, Q, I>
where
    'document: 'path,
    S: SignerReceipt<
            'path,
            'document,
            Id = Q::Id,
            Document = Q::Document,
            Generation = Q::Generation,
        >,
    Q: Query,
{
    bind(
        signer,
        path.actor().verified(),
        query,
        Input::Existence,
        || Ok(path.generation()),
    )
}

fn bind<'receipt, 'path, 'document, S, Q, I>(
    signer: &'receipt S,
    timestamp: &'receipt Verified<Q::Id, Q::Document, Q::Generation, I>,
    query: &Q,
    input: Input,
    interval: impl FnOnce() -> Result<Interval, TemporalError>,
) -> SignatureTimeResult<'receipt, S, Q, I>
where
    'document: 'path,
    S: SignerReceipt<
            'path,
            'document,
            Id = Q::Id,
            Document = Q::Document,
            Generation = Q::Generation,
        >,
    Q: Query,
{
    let selected = signer.signature();
    let property = timestamp.property();
    if selected.snapshot != query.snapshot() || timestamp.token().snapshot != selected.snapshot {
        return Err(SignatureTimeError::Foreign { property });
    }
    if !query
        .equal(timestamp.signature(), selected.node)
        .map_err(|cause| {
            SignatureTimeError::Scope(ScopeError::Resource {
                node: property,
                cause,
            })
        })?
    {
        return Err(SignatureTimeError::Foreign { property });
    }
    query
        .admit(selected.node, 1)
        .map_err(SignatureTimeError::Scope)?;
    if timestamp.purpose() != Purpose::Signature
        && !(matches!(input, Input::Existence) && timestamp.purpose() == Purpose::Archive)
    {
        return Err(SignatureTimeError::Purpose { property });
    }
    let Some(path) = signer.path() else {
        return Ok(SignatureTimeBinding::Unproven(
            SignatureTimeFailure::Certificate,
        ));
    };
    let generation = interval().map_err(|cause| SignatureTimeError::Time { property, cause })?;
    query
        .admit(selected.node, 1)
        .map_err(SignatureTimeError::Scope)?;
    let checked = path.interval();
    if checked.from_instant() > generation.earliest || checked.to_instant() < generation.latest {
        return Ok(SignatureTimeBinding::Unproven(
            SignatureTimeFailure::Interval,
        ));
    }
    Ok(SignatureTimeBinding::Bound(SignatureTime {
        signer,
        timestamp,
        generation,
    }))
}
