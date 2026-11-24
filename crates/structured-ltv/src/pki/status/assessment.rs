//! Assessment of all supplied CRL and OCSP evidence for a checked path member.

use crate::pki::{CheckedPath, CrlAuthority, CrlBindingError, OcspBindingError, ResponderError};
use structured_asn1::{
    Oid, Span,
    memory::{MemoryError, OwnedVec},
};
use structured_pkix::{
    Certificate, Time,
    crl::{CertificateList, Reason, Reasons, ScopeFailure},
    ocsp::{self, BasicResponse},
    path::EffectiveKey,
    temporal::{Instant, LeapTable, Uncertainty},
};

mod decide;
mod evaluate;
pub use evaluate::assess;

/// Time bounds established for the signature by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    /// Exclusive lower bound, if a bound was established.
    pub lower: Option<Instant>,
    /// Inclusive upper bound.
    pub upper: Instant,
}

/// Caller-supplied time facts and freshness constraint for one assessment.
pub struct Query<'q> {
    /// Signature interval.
    pub interval: Interval,
    /// Time at which the assessment runs.
    pub now: Instant,
    /// Authenticated UTC correction facts.
    pub utc: &'q LeapTable<'q>,
    /// Override for the ETSI freshness window, in seconds. When absent the
    /// source must supply a usable `nextUpdate`.
    pub max_freshness_seconds: Option<u64>,
}

/// Caller-supplied OCSP authorization candidates for this target member.
#[derive(Clone, Copy)]
pub enum Responder<'p, 'a> {
    /// The actual issuer from the checked target path.
    Issuer,
    /// A responder explicitly configured by the caller for this target issuer.
    Configured {
        /// Certificate selected by the caller.
        certificate: &'a Certificate<'a>,
        /// Its effective verification key.
        key: EffectiveKey<'a>,
    },
    /// A candidate whose complete path has been checked by the caller.
    Delegate {
        /// Checked path ending in the responder certificate.
        path: &'p CheckedPath<'a>,
        /// Assessment of that responder at the response's production time,
        /// when its certificate has no noCheck exemption.
        revocation: Option<&'p Assessment<'p, 'a>>,
    },
}

/// An original caller-supplied artifact and its candidate authorization inputs.
#[derive(Clone, Copy)]
pub enum Source<'p, 'a> {
    /// A complete or delta CRL, with all candidate signing paths supplied.
    Crl {
        /// Original list.
        list: &'a CertificateList<'a>,
        /// Candidate authorities selected by the caller.
        authorities: &'p [CrlAuthority<'p, 'a>],
    },
    /// A `BasicOCSPResponse`, original request facts and authorization candidates.
    Ocsp {
        /// Original signed response.
        response: &'a BasicResponse<'a>,
        /// Original request nonce, when supplied.
        nonce: Option<ocsp::RequestNonce<'p>>,
        /// Expected exact signer selected by the caller, when supplied.
        intended_signer: Option<&'p Certificate<'a>>,
        /// Additional configured or delegated responders. The issuer is always
        /// tried; inclusion in the response does not authorize another signer.
        responders: &'p [Responder<'p, 'a>],
    },
}

/// Positions in the original source slice. A delta does not replace its base's
/// provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sources {
    /// Original complete CRL or OCSP response; the delta for a paired statement.
    pub primary: usize,
    /// Original complete CRL when a delta produced this statement.
    pub base: Option<usize>,
}

/// Why a candidate could not provide an authenticated usable statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unusable<'a> {
    /// No supplied candidate authenticated and bound the artifact.
    Authority,
    /// The CRL issuer or signature did not authenticate.
    CrlAuthentication(structured_pkix::crl::AuthenticationFailure),
    /// The OCSP signer identity or signature did not authenticate.
    OcspAuthentication(ocsp::SignatureFailure),
    /// The caller's signature verifier does not support this signature.
    UnsupportedSignature,
    /// The caller's digest provider does not support responder identification.
    UnsupportedResponderDigest,
    /// No compatible authorized base was supplied for this delta.
    DeltaWithoutBase,
    /// Conflicting entries for the target in a CRL.
    EntryConflict,
    /// The CRL violates RFC 5280 §5.2.5 at this original extension.
    NoncriticalIssuingDistributionPoint(Span),
    /// The source demands semantics this processor does not recognize.
    UnsupportedCritical {
        /// Identifier of the unhandled critical extension.
        kind: Oid<'a>,
        /// Original location of the extension.
        span: Span,
    },
    /// The original request's nonce did not bind.
    Nonce(ocsp::NonceBinding),
    /// The original request identified a different responder.
    UnexpectedSigner,
    /// No usable unique `CertID` matched this target.
    Lookup(LookupFailure),
    /// Delegation has no exemption or supplied positive responder assessment.
    ResponderRevocationUnchecked,
    /// The revocation data was issued outside its signing certificate validity.
    IssuedOutsideSignerValidity,
    /// The status or its signature was issued after assessment time.
    IssuedAfterNow,
    /// Silence after expiry is unsupported by retention evidence.
    IssuedAfterTargetExpiry,
}

/// What the bound source says, before it is joined with other sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finding<'a> {
    /// An OCSP responder asserted the serial was never issued.
    NotIssued,
    /// Absence or a positive OCSP answer for the specified reasons.
    NotRevoked(Reasons),
    /// Actual source entry or assertion.
    Revoked(Revoked),
    /// The source cannot say when a hold started or ended within these bounds.
    Suspended {
        /// Complete list that did not yet record the hold.
        after: Time,
        /// Delta list that recorded its release.
        released_by: Time,
    },
    /// An intermediate hold or revocation was removed after expiry.
    HeldOrRevoked {
        /// Complete list that did not yet record the entry.
        after: Time,
        /// Delta list that recorded its removal.
        removed_by: Time,
    },
    /// A responder does not know the status.
    Unknown,
    /// The CRL scope does not include the target.
    NotApplicable(ScopeFailure),
    /// The source did not yield a usable statement.
    Unusable(Unusable<'a>),
}

/// Reason an authenticated response did not identify one usable assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LookupFailure {
    /// No matching assertion.
    Missing,
    /// Multiple matching assertions.
    Ambiguous,
    /// The selected provider does not support the `CertID` hash.
    UnsupportedHash,
    /// The hash encoding contradicts its algorithm.
    MalformedHash,
}

impl Finding<'_> {
    fn knows(self) -> bool {
        !matches!(
            self,
            Self::Unknown | Self::NotApplicable(_) | Self::Unusable(_)
        )
    }
}

/// Source freshness under the caller's ETSI freshness constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The statement was issued within the applicable freshness window.
    Fresh,
    /// The statement was issued too early.
    Stale,
    /// Neither the source nor the caller supplied a maximum freshness.
    NoNextUpdate,
    /// The source's advertised window runs backward.
    ReversedUpdateInterval,
    /// UTC correction facts did not place an applicable label.
    Uncertain(Uncertainty),
}

/// A supplied artifact's original provenance and completed status facts.
#[derive(Debug, Clone, Copy)]
pub struct Statement<'a> {
    /// Positions in the original input.
    pub sources: Sources,
    /// Authenticated signer and, for OCSP, the selected original assertion.
    pub authentication: Option<Authentication<'a>>,
    /// Source's status information time (`thisUpdate`).
    pub issued: Time,
    /// Time when the signed source was released (`producedAt` for OCSP).
    pub released: Time,
    /// Advertised next update, when present.
    pub next_update: Option<Time>,
    /// Reasons for which the source is usable.
    pub reasons: Reasons,
    /// Original meaning or the reason the source could not be used.
    pub finding: Finding<'a>,
    /// Caller-selected freshness assessment.
    pub freshness: Freshness,
}

/// Provenance of an authenticated and bound revocation finding.
#[derive(Debug, Clone, Copy)]
pub enum Authentication<'a> {
    /// Original CRL signers under the caller's checked path or anchor.
    Crl {
        /// Signer of the primary CRL.
        signer: &'a Certificate<'a>,
        /// Signer of the complete list, when a delta was used.
        base_signer: Option<&'a Certificate<'a>>,
    },
    /// Original signed responder and its bound target assertion.
    Ocsp {
        /// Authenticated response signer.
        signer: &'a Certificate<'a>,
        /// Actual responder authorization branch.
        authority: ocsp::AuthoritySource,
        /// Original response entry bound by `CertID`.
        assertion: &'a ocsp::SingleResponse<'a>,
    },
}

impl Statement<'_> {
    fn knows(self) -> bool {
        self.finding.knows()
    }

    fn speaks(self) -> bool {
        self.knows() || matches!(self.finding, Finding::Unknown)
    }
}

/// Support for non-revocation after the signer's certificate expires
/// (EN 319 102-1 V1.4.1 §5.2.6.4 step 7, NOTE 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryEvidence {
    /// Neither form of support has been established.
    Unestablished,
    /// Usable, checked post-expiry status covers all revocation reasons.
    RetainedStatus,
    /// The caller authenticated an applicable CA assurance of
    /// non-revocation at the time of signing.
    CaAssuranceAtSigning,
}

/// Completed assessment of the original non-anchor path member.
pub struct Assessment<'p, 'a> {
    path: &'p CheckedPath<'a>,
    member: usize,
    interval: Interval,
    now: Instant,
    statements: OwnedVec<Statement<'a>>,
    status: Status,
    expiry_evidence: ExpiryEvidence,
}

impl<'p, 'a> Assessment<'p, 'a> {
    /// Original checked path.
    pub fn path(&self) -> &'p CheckedPath<'a> {
        self.path
    }

    /// Issuer-to-subject member ordinal.
    pub fn member(&self) -> usize {
        self.member
    }

    /// Result of joining the supplied statements.
    pub fn status(&self) -> Status {
        self.status
    }

    /// Whether post-expiry assertions decisively cover every reason.
    pub fn expiry_evidence(&self) -> ExpiryEvidence {
        self.expiry_evidence
    }

    /// Original findings, addressed by the indices in `Status`.
    pub fn statements(&self) -> &[Statement<'a>] {
        &self.statements
    }
}

/// Processing and capability failures are separate from completed findings.
#[derive(Debug)]
pub enum Error<V, D, R> {
    /// No such non-anchor member.
    Member,
    /// The exclusive lower bound or assessment time contradicts the interval.
    Interval,
    /// Accounted processing or allocation refusal.
    Resource(MemoryError),
    /// Located PKIX processing failure.
    Processing(structured_pkix::Error),
    /// Failure returned by the selected signature verifier.
    Verification(V),
    /// Failure returned by the selected digest provider.
    Digest(D),
    /// Failure returned by the delegate path extension recognizer.
    Recognition(R),
    /// Local bounds prevented a completed delegate path check.
    DelegateIncomplete(structured_pkix::path::Truncation),
    /// CRL association processing refusal.
    CrlBinding(CrlBindingError),
    /// OCSP target association processing refusal.
    OcspBinding(OcspBindingError),
    /// Delegated responder association processing refusal.
    Responder(ResponderError),
}

/// A recorded revocation, preserving the source date and optional reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revoked {
    /// The date recorded by the source.
    pub at: Time,
    /// The reason recorded by the source.
    pub reason: Option<Reason>,
}

impl Revoked {
    fn on_hold(self) -> bool {
        self.reason == Some(Reason::CertificateHold)
    }
}
/// A revocation's established relation to the signature interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// Before the earliest moment the signature could have been made.
    Before,
    /// Not proven after the signature, including an unknown lower bound.
    NotProvablyAfter,
}

/// What already authenticated evidence establishes across the interval.
/// Indices refer to the caller's statement catalogue, not a new common store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// An authenticated responder states the certificate was never issued.
    NotIssued {
        /// Deciding statement index.
        basis: usize,
    },
    /// Clear at the applicable time; a later recorded revocation stays visible.
    NotRevoked {
        /// Deciding statement index.
        basis: usize,
        /// A revocation after the interval or, for an applicable chain-model
        /// CA reason, after the subordinate was issued.
        later: Option<Revoked>,
    },
    /// A recorded revocation reaches the interval.
    Revoked {
        /// Deciding statement index.
        basis: usize,
        /// Source revocation facts.
        revoked: Revoked,
        /// Established temporal relation.
        when: When,
    },
    /// A recorded suspension reaches the interval.
    OnHold {
        /// Deciding statement index.
        basis: usize,
    },
    /// Held or revoked at an unknown moment, without evidence distinguishing them.
    HeldOrRevoked {
        /// Deciding statement index.
        basis: usize,
    },
    /// Evidence is not fresh enough under the caller's selected freshness policy.
    NotFresh {
        /// Deciding statement index.
        basis: usize,
    },
    /// Fresh evidence covers only some revocation reasons.
    PartialReasons {
        /// Deciding statement index.
        basis: usize,
        /// Reasons covered by the supplied deciding sources together.
        covered: Reasons,
    },
    /// A supplied responder does not know this certificate's status.
    Unknown {
        /// Deciding statement index.
        basis: usize,
    },
    /// Equally current evidence conflicts.
    Conflict {
        /// First conflicting statement index.
        first: usize,
        /// Second conflicting statement index.
        second: usize,
    },
    /// Supplied UTC facts cannot establish the temporal relation.
    Uncertain(Uncertainty),
    /// No supplied source states this certificate's status.
    NoEvidence,
}
