//! Independent generation/imprint facts, not a signature or trust proof.

use super::{Accuracy, HashAlgorithmReading, TokenInfo};
use crate::{Error, ErrorCode, Result};
use structured_asn1::{
    Oid, Reader, Span,
    memory::{OwnedVec, Work},
    value::OwnedOid,
};
use structured_pkix::temporal::Reading;

/// Independently retained written hash algorithm and logical digest bytes.
/// Parameter absence stays distinct from a written NULL; no re-encoding or
/// generic normalization substitutes for the selected provider's semantics.
#[derive(Debug)]
pub struct RetainedImprint {
    algorithm: OwnedOid,
    parameters: Option<OwnedVec<u8>>,
    hashed: OwnedVec<u8>,
}
impl RetainedImprint {
    /// Original validated identifier arcs, now independent of the source parser.
    #[must_use]
    pub fn algorithm(&self) -> Oid<'_> {
        self.algorithm.as_oid()
    }
    /// Whole original parameter TLV, without a fabricated absent/default value.
    #[must_use]
    pub fn parameters(&self) -> Option<&[u8]> {
        self.parameters.as_deref()
    }
    /// Complete logical hashedMessage octets, with no fragment headers.
    #[must_use]
    pub fn hashed(&self) -> &[u8] {
        &self.hashed
    }
}

/// A conforming token's declared generation/imprint projection.
///
/// This deliberately carries no successful signature/trust verdict. Callers
/// inspect and verify the token independently; only the complete timestamp
/// checker may turn positive checks into evidence. Every retained allocation
/// holds its charge after parser/token drop; no infallible deep Clone exists.
#[derive(Debug)]
pub struct RetainedFacts {
    imprint: RetainedImprint,
    policy: OwnedOid,
    serial: OwnedVec<u8>,
    nonce: Option<OwnedVec<u8>>,
    gen_time: Reading,
    accuracy: Option<Accuracy>,
    ordering: bool,
    source_span: Span,
}

impl TokenInfo<'_> {
    /// Retains this generation/imprint projection before the scoped source ends.
    ///
    /// A retained malformed token is not silently turned into conforming data.
    /// This projection refuses inspection faults; the original model and all
    /// diagnostics remain available on refusal. It copies only declared facts,
    /// not a certificate, source payload, provider state or a trust assertion.
    pub fn retain_facts(&self, parent: &Reader<'_>) -> Result<RetainedFacts> {
        self.imprint().require_session(parent)?;
        if self.has_faults() {
            return Err(Error::schema(
                ErrorCode::MalformedValue,
                "tstInfo",
                self.span().start,
            ));
        }
        let HashAlgorithmReading::Identifier(algorithm) = self.imprint().algorithm() else {
            return Err(Error::schema(
                ErrorCode::MalformedValue,
                "tstInfo.messageImprint",
                self.imprint().span().start,
            ));
        };
        let accuracy = self
            .accuracy()
            .map(super::AccuracyReading::deviation)
            .transpose()
            .map_err(|error| {
                Error::schema(
                    ErrorCode::MalformedValue,
                    "tstInfo.accuracy",
                    error.span.start,
                )
            })?;
        let work = parent.execution();
        work.charge_work(8)
            .map_err(|reason| Error::resource(reason, "tstInfo", self.span().start))?;
        let hash_algorithm =
            OwnedOid::from_oid_in(algorithm.algorithm(), &work).map_err(|reason| {
                Error::resource(
                    reason,
                    "tstInfo.messageImprint.hashAlgorithm",
                    algorithm.offset(),
                )
            })?;
        let parameters = algorithm
            .parameters()
            .map(|bytes| {
                retain(
                    bytes,
                    &work,
                    "tstInfo.messageImprint.hashAlgorithm.parameters",
                    algorithm.offset(),
                )
            })
            .transpose()?;
        let hashed = self
            .imprint()
            .hashed()
            .copy_in(
                parent,
                "tstInfo.messageImprint.hashedMessage",
                self.imprint().hashed().span().start,
            )?
            .into_owned();
        let policy = OwnedOid::from_oid_in(self.policy(), &work)
            .map_err(|reason| Error::resource(reason, "tstInfo.policy", self.span().start))?;
        let serial = retain(
            self.serial().element().contents(),
            &work,
            "tstInfo.serialNumber",
            self.serial().element().span().start,
        )?;
        let nonce = self
            .nonce()
            .map(|nonce| {
                retain(
                    nonce.element().contents(),
                    &work,
                    "tstInfo.nonce",
                    nonce.element().span().start,
                )
            })
            .transpose()?;
        Ok(RetainedFacts {
            imprint: RetainedImprint {
                algorithm: hash_algorithm,
                parameters,
                hashed,
            },
            policy,
            serial,
            nonce,
            gen_time: self.gen_time(),
            accuracy,
            ordering: self.ordering(),
            source_span: self.span(),
        })
    }
}

fn retain<W: Work>(bytes: &[u8], work: &W, field: &'static str, at: u64) -> Result<OwnedVec<u8>> {
    let mut owned = work.vector();
    owned
        .try_extend_from_slice(bytes)
        .map_err(|reason| Error::resource(reason, field, at))?;
    Ok(owned.into_owned())
}

impl RetainedFacts {
    /// Copies declared facts into independently charged current storage.
    /// Moving the owner needs no copy; a genuine deep copy admits new work and
    /// capacity before execution. Partial refusal leaves this source unchanged.
    pub fn try_copy_in<W: Work>(&self, work: &W) -> Result<Self> {
        work.charge_work(8)
            .map_err(|reason| Error::resource(reason, "tstInfo", self.source_span.start))?;
        let algorithm =
            OwnedOid::from_oid_in(self.imprint.algorithm(), work).map_err(|reason| {
                Error::resource(
                    reason,
                    "tstInfo.messageImprint.hashAlgorithm",
                    self.source_span.start,
                )
            })?;
        let parameters = self
            .imprint
            .parameters()
            .map(|bytes| {
                retain(
                    bytes,
                    work,
                    "tstInfo.messageImprint.hashAlgorithm.parameters",
                    self.source_span.start,
                )
            })
            .transpose()?;
        let hashed = retain(
            self.imprint.hashed(),
            work,
            "tstInfo.messageImprint.hashedMessage",
            self.source_span.start,
        )?;
        let policy = OwnedOid::from_oid_in(self.policy(), work)
            .map_err(|reason| Error::resource(reason, "tstInfo.policy", self.source_span.start))?;
        let serial = retain(
            self.serial(),
            work,
            "tstInfo.serialNumber",
            self.source_span.start,
        )?;
        let nonce = self
            .nonce()
            .map(|bytes| retain(bytes, work, "tstInfo.nonce", self.source_span.start))
            .transpose()?;
        Ok(Self {
            imprint: RetainedImprint {
                algorithm,
                parameters,
                hashed,
            },
            policy,
            serial,
            nonce,
            gen_time: self.gen_time,
            accuracy: self.accuracy,
            ordering: self.ordering,
            source_span: self.source_span,
        })
    }
    /// Declared complete imprint, requiring selected-provider resolution to use.
    #[must_use]
    pub fn imprint(&self) -> &RetainedImprint {
        &self.imprint
    }
    /// Original policy arcs; no product policy acceptance is implied.
    #[must_use]
    pub fn policy(&self) -> Oid<'_> {
        self.policy.as_oid()
    }
    /// Original serial INTEGER contents, never a narrowing numeric conversion.
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }
    /// Original nonce INTEGER contents when one was written.
    #[must_use]
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }
    /// Original common UTC reading, not a fabricated exact instant.
    #[must_use]
    pub fn gen_time(&self) -> Reading {
        self.gen_time
    }
    /// Complete Accuracy absence remains distinct from a present zero value.
    #[must_use]
    pub fn accuracy(&self) -> Option<Accuracy> {
        self.accuracy
    }
    /// Original ordering assertion, which does not establish chronology itself.
    #[must_use]
    pub fn ordering(&self) -> bool {
        self.ordering
    }
    /// Range in the original callback reader's coordinates. When logical, keep
    /// its supplied `SourceMap` separately; this is not a physical document span.
    #[must_use]
    pub fn source_span(&self) -> Span {
        self.source_span
    }
}
