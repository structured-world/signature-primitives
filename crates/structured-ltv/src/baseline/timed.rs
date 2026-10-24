//! Whole original TSA-path census and root signature-time static association.

use super::BasicStage;
use crate::pki::SignerReceipt;
use crate::source::{Query, ScopeError};
use crate::timestamp::{
    Purpose, SignatureTime, SignatureTimeBinding, SignatureTimeError, SignatureTimeFailure,
    TimestampPaths, TimestampScope, existence_time_path, signature_time_path,
};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

/// One actual root signature timestamp's complete static certificate binding.
/// Negative results do not disappear because a different timestamp succeeded.
pub enum SignatureTimeFact<'a, S, N, D, G, I> {
    /// Exact original signature input and full generation/static path interval.
    Bound(SignatureTime<'a, S, N, D, G, I>),
    /// Completed insufficient root certificate/interval fact, not source refusal.
    Unproven {
        /// Original root signature timestamp property.
        property: N,
        /// Exact completed negative cause.
        cause: SignatureTimeFailure,
    },
}

/// Whole original token/TSA path set plus every root signature-time association.
/// This does not assert pre-revocation chronology, current/historical status,
/// format material completeness, algorithm-obsolescence policy or caller trust.
/// In particular it is NOT an unconditional B-T acceptance verdict.
pub struct Timed<'a, 'certificate, 'document, B, S, N, D, G, I> {
    basic: &'a B,
    paths: &'a TimestampPaths<'a, 'certificate, 'document, N, D, G, I>,
    signatures: OwnedVec<SignatureTimeFact<'a, S, N, D, G, I>>,
    static_complete: bool,
}

impl<'a, 'c, 'd, B, S, N, D, G, I> Timed<'a, 'c, 'd, B, S, N, D, G, I> {
    /// Same original basic stage.
    #[must_use]
    pub fn basic(&self) -> &'a B {
        self.basic
    }
    /// Complete source-derived root AND nested-counter timestamp/TSA paths.
    #[must_use]
    pub fn paths(&self) -> &'a TimestampPaths<'a, 'c, 'd, N, D, G, I> {
        self.paths
    }
    /// Every original root signature timestamp, including negative associations.
    #[must_use]
    pub fn signatures(&self) -> &[SignatureTimeFact<'a, S, N, D, G, I>] {
        &self.signatures
    }
    /// At least one authorized root existence timestamp exists and every required timestamp's
    /// complete accuracy interval is covered by the actual static signer path.
    /// Counter/data/archive timestamps cannot substitute for this condition.
    #[must_use]
    pub fn all_static_time_requirements_met(&self) -> bool {
        self.static_complete
    }
}

/// Terminal original source/selection/query refusal; no partial timed report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeError<N> {
    /// Wrong scope, source or selected root/counter census.
    Foreign {
        /// Original selected signature.
        signature: N,
    },
    /// Original current-operation/source failure, including the complete
    /// counter-census membership query.
    Scope(ScopeError<N>),
    /// Original signature-time association processing failed.
    Signature(SignatureTimeError<N>),
    /// Work or retained report capacity was refused before use.
    Resource {
        /// Original selecting signature/property.
        node: N,
        /// Exact resource refusal.
        cause: MemoryError,
    },
}

/// Complete original static time facts in the query's identity domain.
pub type TimeResult<'a, 'c, 'd, B, S, Q, I> = Result<
    Timed<'a, 'c, 'd, B, S, <Q as Query>::Id, <Q as Query>::Document, <Q as Query>::Generation, I>,
    TimeError<<Q as Query>::Id>,
>;

/// Bind all-token TSA-path facts to the SAME root/counter source and every actual
/// root signature timestamp to the checked signer. Reuses previously established
/// complete generation intervals, not another UTC parse or certificate hash.
/// EN319132-1 §§5.3/6.3(n,o) distinguish the signature timestamp from other
/// kinds and require EACH such timestamp before expiration/revocation. This
/// establishes the static interval part; actual revocation facts stay explicit.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn timestamped<'a, 'c, 'd, 'path, 'document, B, Q, I>(
    basic: &'a B,
    paths: &'a TimestampPaths<'a, 'c, 'd, Q::Id, Q::Document, Q::Generation, I>,
    query: &Q,
) -> TimeResult<'a, 'c, 'd, B, B::Signer, Q, I>
where
    'document: 'path,
    B: BasicStage<'path, 'document, Id = Q::Id, Document = Q::Document, Generation = Q::Generation>,
    Q: Query,
{
    timed(basic, paths, None, query)
}

/// Same complete TSA/static core with one format-authorized archive input as
/// the fallback existence time when no root signature timestamp is written.
/// The format issuer supplies the original archive property, not the caller.
/// EN319142-1 §6.3 allows `PAdES` document timestamps for this purpose; default
/// XAdES/CAdES composition continues to require its signature timestamp kind.
/// <https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
pub fn timestamped_existence<'a, 'c, 'd, 'path, 'document, B, Q, I>(
    _issuer: I,
    basic: &'a B,
    paths: &'a TimestampPaths<'a, 'c, 'd, Q::Id, Q::Document, Q::Generation, I>,
    archive: Option<Q::Id>,
    query: &Q,
) -> TimeResult<'a, 'c, 'd, B, B::Signer, Q, I>
where
    'document: 'path,
    B: BasicStage<'path, 'document, Id = Q::Id, Document = Q::Document, Generation = Q::Generation>,
    Q: Query,
{
    timed(basic, paths, archive, query)
}

fn timed<'a, 'c, 'd, 'path, 'document, B, Q, I>(
    basic: &'a B,
    paths: &'a TimestampPaths<'a, 'c, 'd, Q::Id, Q::Document, Q::Generation, I>,
    archive: Option<Q::Id>,
    query: &Q,
) -> TimeResult<'a, 'c, 'd, B, B::Signer, Q, I>
where
    'document: 'path,
    B: BasicStage<'path, 'document, Id = Q::Id, Document = Q::Document, Generation = Q::Generation>,
    Q: Query,
{
    let selected = basic.signer().signature();
    let signature = selected.node;
    let required = paths.required();
    let resource = |cause| TimeError::Resource {
        node: signature,
        cause,
    };
    if !matches!(required.scope(), TimestampScope::All(_))
        || required.scope().location().snapshot != query.snapshot()
        || selected.snapshot != query.snapshot()
        || !query
            .equal(required.signature(), signature)
            .map_err(resource)?
        || !required
            .includes_counters(basic.counters(), query)
            .map_err(TimeError::Scope)?
    {
        return Err(TimeError::Foreign { signature });
    }
    query.admit(signature, 1).map_err(TimeError::Scope)?;
    let mut signature_written = false;
    if let Some(archive) = archive {
        let mut archive_written = false;
        for entry in required.entries() {
            query.admit(entry.property, 1).map_err(TimeError::Scope)?;
            if !query.equal(entry.signature, signature).map_err(resource)? {
                continue;
            }
            if entry.purpose == Purpose::Signature {
                signature_written = true;
            }
            if entry.purpose == Purpose::Archive
                && query.equal(entry.property, archive).map_err(resource)?
            {
                archive_written = true;
            }
        }
        if !archive_written {
            return Err(TimeError::Foreign { signature });
        }
    }
    let mut signatures = query.execution().vector();
    let mut static_complete = basic.all_requirements_met();
    for path in paths.paths() {
        query.execution().charge_work(1).map_err(resource)?;
        let verified = path.actor().verified();
        if verified.purpose() != Purpose::Signature && archive.is_none() {
            continue;
        }
        if !query
            .equal(verified.signature(), signature)
            .map_err(resource)?
        {
            continue;
        }
        let fallback = !signature_written
            && verified.purpose() == Purpose::Archive
            && match archive {
                Some(archive) => query
                    .equal(verified.property(), archive)
                    .map_err(resource)?,
                None => false,
            };
        if verified.purpose() != Purpose::Signature && !fallback {
            continue;
        }
        signatures.try_reserve(1).map_err(resource)?;
        let association = if fallback {
            existence_time_path(basic.signer(), path, query)
        } else {
            signature_time_path(basic.signer(), path, query)
        };
        let fact = match association.map_err(TimeError::Signature)? {
            SignatureTimeBinding::Bound(value) => SignatureTimeFact::Bound(value),
            SignatureTimeBinding::Unproven(cause) => {
                static_complete = false;
                SignatureTimeFact::Unproven {
                    property: verified.property(),
                    cause,
                }
            }
        };
        signatures.try_push(fact).map_err(resource)?;
    }
    if signatures.is_empty() {
        static_complete = false;
    }
    query.admit(signature, 1).map_err(TimeError::Scope)?;
    Ok(Timed {
        basic,
        paths,
        signatures: signatures.into_owned(),
        static_complete,
    })
}
