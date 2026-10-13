//! Certification paths: which sequences of certificates lead from a
//! certificate to an anchor the caller trusts, and what that costs.
//!
//! One signature can have several valid paths, and a report shows them,
//! because a cross-certified provider is recognized under one scheme by one
//! path and under another by another. That is not the same as enumerating
//! every path: a certificate set somebody else controls can hold a
//! combinatorial number of them, and a browser asked for all of them stops
//! answering. So the search is bounded in every direction it can grow, and
//! when a bound is reached the answer says so. Silence about truncation
//! would be a worse answer than the truncation.
//!
//! Where the bound is on how many paths are returned, which paths are kept
//! is not the order they were found in. A second path to the same anchor
//! naming the same policies tells a reader nothing the first did not; a path
//! to another anchor, or one naming other policies, is the whole reason
//! several paths are shown at all. So a path that differs in either is kept
//! ahead of a repeat of one already held.
//!
//! An anchor is an input, never a discovery (RFC 5280 6.1): a self-signed
//! certificate that happens to sit in the same pool is a certificate like
//! any other, and a path that ends at one the caller did not name ends
//! nowhere.

mod error;
mod name_space;
mod policy;
mod validation;

pub use error::{BuildError, BuildResult};
pub use validation::{
    ConstraintSource, EffectiveAnchor, NameConstraintFailure, Rejection, RejectionReason,
    Validation, ValidationBounds, ValidationContext, ValidationFacts, validate, validate_effective,
};

use crate::algorithm::AlgorithmIdentifier;
use crate::certificate::{Certificate, Validity};
use crate::error::Result;
use crate::extension::Recognizer;
use crate::key::PublicKeyInfo;
use crate::name::Name;
use structured_asn1::memory::{Memory, OwnedMap, OwnedVec};
use structured_asn1::{BitString, Oid};

/// What the caller trusts, as the trust context named it.
///
/// A name and a key, because that is what an anchor is: the certificate it
/// was published in, where there is one, is kept for the report and is not
/// what makes it an anchor. Two anchors with the same name and different
/// keys are two anchors, and a path is built to each.
#[derive(Debug, Clone, Copy)]
pub struct Anchor<'a> {
    name: &'a Name<'a>,
    key: PublicKeyInfo<'a>,
    certificate: Option<&'a Certificate<'a>>,
}

impl<'a> Anchor<'a> {
    /// An anchor the trust context supplies as a name and a key.
    #[must_use]
    pub fn new(name: &'a Name<'a>, key: PublicKeyInfo<'a>) -> Self {
        Self {
            name,
            key,
            certificate: None,
        }
    }

    /// An anchor the trust context supplies as a certificate, whose subject
    /// and key it is. The certificate is not part of any path built to it
    /// (RFC 5280 6.1), and is kept so a report can name where the anchor
    /// came from and so that what it says about the names below it is
    /// obeyed.
    #[must_use]
    pub fn from_certificate(certificate: &'a Certificate<'a>) -> Self {
        Self {
            name: certificate.tbs().subject(),
            key: certificate.tbs().public_key(),
            certificate: Some(certificate),
        }
    }

    /// The name a certificate issued under this anchor carries as its issuer.
    #[must_use]
    pub fn name(&self) -> &'a Name<'a> {
        self.name
    }

    /// The public key information, as encoded, which is what verifies the
    /// signature of the certificate below it.
    #[must_use]
    pub fn key(&self) -> PublicKeyInfo<'a> {
        self.key
    }

    /// The certificate the anchor was published in, where the trust context
    /// had one.
    #[must_use]
    pub fn certificate(&self) -> Option<&'a Certificate<'a>> {
        self.certificate
    }

    /// Whether two anchors are the same one: the same name and the same key,
    /// which is what an anchor is.
    fn same(self, other: Self, execution: &Memory) -> Result<bool> {
        execution
            .charge_work(self.key.as_bytes().len().max(other.key.as_bytes().len()) as u64)
            .map_err(|reason| self.name.resource(reason))?;
        if self.key.as_bytes() != other.key.as_bytes() {
            return Ok(false);
        }
        self.name.matches(other.name, execution)
    }
}

/// What a verifier says about one signature.
///
/// The third answer is the one that matters: an algorithm this build cannot
/// verify is not a signature that passed. Collapsing it into a no would say
/// the certificate is broken, and into a yes would say it is good; both are
/// claims nobody made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verified {
    /// The signature is the issuer's over these bytes.
    Yes,
    /// The signature is not.
    No,
    /// This build cannot answer: the algorithm, the key or the parameters
    /// are outside what it verifies.
    Unsupported,
}

/// The key a certificate's signature is checked with, and the parameters
/// that are in force for it.
///
/// "If the public key algorithm parameters are absent, the working public key
/// parameters are inherited" from the certificate above (RFC 5280 6.1.2 (c)
/// and 6.1.4 (e)). A key written without them is not a key anything can be
/// checked with on its own: the curve or the group it belongs to is written
/// once, in an authority above it, and every key below stands in that same
/// one. A verifier handed the encoding alone would have to answer that it
/// cannot say, and a valid path would go unreported.
///
/// Where the key carries its own parameters, those are the ones in force and
/// nothing is inherited. This is the ordinary case: a named curve, an RSA
/// modulus, an Edwards key.
#[derive(Debug, Clone, Copy)]
pub struct WorkingKey<'a> {
    key: PublicKeyInfo<'a>,
    /// Parameters whose algorithm compatibility was admitted and established
    /// during the transition. Getters never defer an untrusted OID comparison.
    inherited: Option<&'a [u8]>,
}

impl<'a> WorkingKey<'a> {
    /// A key that stands on its own, which is what a trust anchor's is: there
    /// is nothing above it to inherit from.
    #[must_use]
    pub fn standing(key: PublicKeyInfo<'a>) -> Self {
        Self {
            key,
            inherited: None,
        }
    }

    /// The key itself, as the certificate wrote it.
    #[must_use]
    pub fn key(self) -> PublicKeyInfo<'a> {
        self.key
    }

    /// The parameters in force: the key's own where it has them, and the ones
    /// carried down from above where it does not and belongs to the same
    /// algorithm, subject to its specific key profile. An absent PSS parameter
    /// field means unrestricted PSS usage and does not inherit restrictions
    /// (RFC4055 §3.3 case2).
    ///
    /// "If the certificate subjectPublicKey algorithm and the
    /// `working_public_key_algorithm` are different, set the
    /// `working_public_key_parameters` to null" (RFC 5280 6.1.4 (e)). Nothing
    /// is carried across a change of algorithm: a curve is not a modulus,
    /// and an authority on one algorithm certifying a key on another says
    /// nothing about how that key is written. Handing them over anyway gives
    /// a verifier a key described by parameters that are not its own, which
    /// it can only refuse.
    ///
    /// The generic RFC5280 transition treats explicit NULL and omitted
    /// parameters alike. A specific key profile may define absence differently,
    /// as PSS does. This projection does not validate algorithm-specific syntax:
    /// the provider also receives the original SPKI and must reject a spelling
    /// forbidden by its algorithm contract.
    ///
    /// `None` means no effective parameters were supplied or inherited. It
    /// does not itself prove that the key's encoding is valid for its algorithm.
    #[must_use]
    pub fn parameters(self) -> Option<&'a [u8]> {
        if !self.key.algorithm().has_no_parameters() {
            return self.key.algorithm().parameters();
        }
        self.inherited
    }

    /// Project the subject's effective key using the current parameter state.
    /// This is only the RFC 5280 §6.1.4(d)–(e) state transition: it does not
    /// authenticate the certificate, bind issuer names, or establish trust.
    /// <https://www.rfc-editor.org/rfc/rfc5280#section-6.1.4>
    ///
    /// A caller projecting a key from an already validated path starts at its
    /// anchor and visits the original certificates in issuer-to-subject order.
    /// Returned SPKI and parameters borrow those sources; no key catalogue,
    /// copy or repeated signature verification is needed. The current execution
    /// account pays for each transition and data-dependent OID comparison.
    ///
    /// # Panics
    /// Only if the internal unit-meter invariant is violated: that meter
    /// always admits local work and cannot produce a truncated transition.
    pub fn subject(self, certificate: &'a Certificate<'a>, execution: &Memory) -> Result<Self> {
        execution
            .charge_work(1)
            .map_err(|reason| certificate.tbs().subject().resource(reason))?;
        // The unit meter never returns local truncation; the same transition
        // core still enforces the shared execution domain before comparisons.
        self.below(certificate, execution, &mut ())
            .map(|key| key.expect("unit meter never truncates parameter projection"))
    }

    /// The working key one certificate further down: this certificate's own
    /// key, standing in the parameters in force where it wrote none.
    ///
    /// The algorithm those parameters belong to travels with them, since a
    /// key further down inherits only from a key of its own algorithm.
    fn below(
        self,
        certificate: &'a Certificate<'a>,
        execution: &Memory,
        meter: &mut impl Meter,
    ) -> Result<Option<Self>> {
        let key = certificate.tbs().public_key();
        let mut inherited = None;
        if key.algorithm().has_no_parameters()
            && let Some(parameters) = self.parameters()
        {
            let previous = self.key.algorithm().algorithm().as_bytes();
            let current = key.algorithm().algorithm().as_bytes();
            // RFC4055 §§3.1,3.3 case2 overrides generic parameter inheritance
            // for a PSS SPKI with absent parameters: no key restrictions.
            // https://www.rfc-editor.org/rfc/rfc4055#section-3.3
            // NULL is invalid PSS syntax (§3.1), not an inherited-parameter
            // placeholder. Keep it in the original SPKI and supply no parent
            // parameters that an adapter could use to repair its spelling.
            let pss = crate::oid::RSASSA_PSS.as_bytes();
            if current.len() == pss.len() {
                let reads = (pss.len() as u64) * 2;
                if !meter.spend(reads / cost::COMPARED)? {
                    return Ok(None);
                }
                execution
                    .charge_work(reads)
                    .map_err(|reason| certificate.tbs().subject().resource(reason))?;
                if current == pss {
                    return Ok(Some(Self {
                        key,
                        inherited: None,
                    }));
                }
            }
            if previous.len() == current.len() {
                if core::ptr::eq(previous, current) {
                    inherited = Some(parameters);
                } else {
                    let reads = (current.len() as u64).checked_mul(2).ok_or_else(|| {
                        certificate
                            .tbs()
                            .subject()
                            .resource(structured_asn1::memory::MemoryError::WorkExceeded)
                    })?;
                    if !meter.spend(reads / cost::COMPARED)? {
                        return Ok(None);
                    }
                    execution
                        .charge_work(reads)
                        .map_err(|reason| certificate.tbs().subject().resource(reason))?;
                    if previous == current {
                        inherited = Some(parameters);
                    }
                }
            }
        }
        Ok(Some(Self { key, inherited }))
    }
}

/// Who checks a signature.
///
/// Which algorithms may verify what belongs to the algorithm registry rather
/// than to this crate, so the check is asked for rather than performed here.
/// A caller that supplies no verifier gets no path: nothing else in a path
/// binds one certificate to the next.
pub trait Verify {
    /// The original policy, provider or resource failure of this implementation.
    type Error;

    /// Whether the signature over `signed` is the one the key in `key`
    /// makes under `algorithm`.
    ///
    /// The key arrives with the parameters in force rather than as the
    /// encoding alone, since a certificate may omit them and stand in the
    /// ones an authority above it wrote.
    ///
    /// A key may also be offered before those are known: while a path is
    /// being looked for, an authority is asked about with the key exactly as
    /// its certificate wrote it, because what it stands in is above and
    /// above has not been reached. An implementation that cannot judge a key
    /// without parameters it was not given answers `Unsupported` rather than
    /// `No`. The two are not interchangeable here: `No` prunes the branch,
    /// and a key that merely could not be judged yet is asked about again
    /// from the anchor down.
    fn verify(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        signed: &[u8],
        signature: BitString<'_>,
        execution: &Memory,
    ) -> core::result::Result<Verified, Self::Error>;
}

/// Nothing is verified, which is what a caller without a registry has.
impl Verify for () {
    type Error = core::convert::Infallible;
    fn verify(
        &self,
        _algorithm: &AlgorithmIdentifier<'_>,
        _key: WorkingKey<'_>,
        _signed: &[u8],
        _signature: BitString<'_>,
        _execution: &Memory,
    ) -> core::result::Result<Verified, Self::Error> {
        Ok(Verified::Unsupported)
    }
}

/// Whether the search has run out of time.
///
/// There is no clock here: this crate builds without an operating system, so
/// wall time is something the caller watches and this asks about. The work
/// bound below is the one that always applies, and this one narrows it where
/// the caller can measure.
pub trait Watch {
    /// Whether the time the caller allowed has passed.
    fn out_of_time(&self) -> bool;
}

/// No clock, so no deadline: the work bound is what stops the search.
impl Watch for () {
    fn out_of_time(&self) -> bool {
        false
    }
}

/// What charges work and says whether there is any left.
///
/// The search holds the meter, and the planes that work out policies and
/// names are given it rather than a copy of what it counts: a plane with its
/// own budget is a second bound the caller never set, and one with none
/// spends whatever a list somebody else wrote asks for. One trait rather
/// than the search itself, so those planes do not carry the verifier, the
/// clock and the recognizer through their signatures to reach the counter.
pub(crate) trait Meter {
    /// Charges work, and says whether there is any budget left. Both the
    /// work bound and the caller's clock are answered here, since running
    /// out of either stops the same search.
    fn spend(&mut self, work: u64) -> Result<bool>;
}

/// No meter, so no bound: for asking a plane what it works out rather than
/// what it spends, which is what the tests of one plane are about.
impl Meter for () {
    fn spend(&mut self, _work: u64) -> Result<bool> {
        Ok(true)
    }
}

/// How far the search may go before it stops and says so.
///
/// Every direction a search can grow has a number here, because a
/// certificate set somebody else controls grows in all of them: deeper
/// chains, wider fan-out at each step, more paths that differ in one
/// certificate, more policies in each certificate. The defaults are what a
/// browser can spend on a document somebody sent, not what a server can
/// spend on its own inventory.
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    /// How many certificates a path may hold, the anchor aside.
    pub depth: usize,
    /// How many times a certificate may be entered at some depth.
    pub visited: usize,
    /// How many candidate issuers may be considered in total.
    pub edges: usize,
    /// How much work the checks along the way may cost.
    pub work: u64,
    /// How many paths may be returned.
    pub paths: usize,
    /// How many graph nodes, retained parent edges and expected policy OIDs
    /// one path's policy processing may hold together. Scratch capacity is
    /// additionally admitted by the shared execution account.
    pub policies: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            depth: 12,
            visited: 4_096,
            edges: 16_384,
            work: 1_000_000,
            paths: 8,
            policies: 1_024,
        }
    }
}

/// Which bound stopped the search, where one did.
///
/// A report says which, because the answers differ: a search that ran out of
/// paths has more to show, and a search that ran out of depth was looking in
/// the wrong place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Truncation {
    /// A path reached the depth bound and was not followed further.
    Depth,
    /// The count of entered certificates reached its bound.
    Visited,
    /// The count of considered candidates reached its bound.
    Edges,
    /// The checks along the way cost what the caller allowed.
    Work,
    /// The caller's clock ran out.
    Time,
    /// More paths were found than the caller asked for, and one that was
    /// found is not among the ones returned.
    Paths,
    /// Working out what a path was issued under grew past what the caller
    /// allowed it to hold, so that path was not settled.
    Policies,
}

impl Truncation {
    /// Whether reaching this bound ends the whole search rather than one
    /// branch of it.
    ///
    /// The counts of work, time, entered certificates and considered
    /// candidates are spent once for the whole search, so reaching one
    /// leaves nothing further to look at. Depth, room for paths and the size
    /// of a policy tree are reached by one branch or one path, and the
    /// search goes on to the next.
    fn halts(self) -> bool {
        matches!(self, Self::Work | Self::Time | Self::Visited | Self::Edges)
    }
}

/// One certification path: the certificates from the target up, the anchor
/// they lead to, and what the authorities along it agreed the target was
/// issued under.
#[derive(Debug)]
pub struct Path<'a> {
    certificates: OwnedVec<&'a Certificate<'a>>,
    anchor: Anchor<'a>,
    policies: OwnedVec<Oid<'a>>,
}

impl<'a> Path<'a> {
    /// The certificates, the target first and the one the anchor issued
    /// last. The anchor's own certificate is not among them.
    #[must_use]
    pub fn certificates(&self) -> &[&'a Certificate<'a>] {
        &self.certificates
    }

    /// The anchor this path ends at.
    #[must_use]
    pub fn anchor(&self) -> Anchor<'a> {
        self.anchor
    }

    /// The policies every authority along the path agreed the target was
    /// issued under, narrowed to the ones the caller asked about.
    ///
    /// Empty says the path names no policy the caller asked about, which is
    /// a path only because nobody along it demanded that it name one.
    ///
    /// A set rather than a list, and returned in one order whatever order
    /// the certificates wrote it in, so that two paths naming one set are
    /// told apart by walking them once.
    #[must_use]
    pub fn policies(&self) -> &[Oid<'a>] {
        &self.policies
    }

    /// How many certificates the path holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Whether the path holds no certificates, which no path this builder
    /// returns does.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Whether two paths say the same thing: the same names carrying the
    /// same keys, up to the same anchor.
    ///
    /// Serial numbers and validity are not part of it, so an authority that
    /// re-issued its own certificate is one route rather than two. What
    /// makes a second path worth showing is that it goes somewhere else or
    /// says something else, and neither of those is a new serial number.
    fn same_route(
        &self,
        chain: &[&'a Certificate<'a>],
        anchor: Anchor<'a>,
        execution: &Memory,
    ) -> Result<bool> {
        if self.certificates.len() != chain.len() || !self.anchor.same(anchor, execution)? {
            return Ok(false);
        }
        for (ours, theirs) in self.certificates.iter().zip(chain) {
            execution
                .charge_work(
                    ours.tbs()
                        .public_key()
                        .as_bytes()
                        .len()
                        .max(theirs.tbs().public_key().as_bytes().len()) as u64,
                )
                .map_err(|reason| ours.tbs().subject().resource(reason))?;
            if ours.tbs().public_key().as_bytes() != theirs.tbs().public_key().as_bytes()
                || !ours
                    .tbs()
                    .subject()
                    .matches(theirs.tbs().subject(), execution)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether a path would tell a reader what this one already told them:
    /// the same anchor, and the same policies. What is worth keeping when
    /// there is room for fewer paths than were found is one of each of
    /// these, not the first ones found.
    /// Both sets arrive in one order, which is what makes this a walk down
    /// the two rather than a search of one for each member of the other:
    /// the second is the square of a count the caller's policy ceiling
    /// allows, and it is repeated against every path being held.
    fn same_meaning(
        &self,
        anchor: Anchor<'a>,
        policies: &[Oid<'a>],
        execution: &Memory,
    ) -> Result<bool> {
        if !self.anchor.same(anchor, execution)? || self.policies.len() != policies.len() {
            return Ok(false);
        }
        for (ours, theirs) in self.policies.iter().zip(policies) {
            execution
                .charge_work(ours.as_bytes().len().max(theirs.as_bytes().len()) as u64)
                .map_err(|reason| self.anchor.name.resource(reason))?;
            if ours != theirs {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// What the search found, and what it did not get to.
#[derive(Debug)]
pub struct Outcome<'a> {
    paths: OwnedVec<Path<'a>>,
    truncated: Option<Truncation>,
}

impl<'a> Outcome<'a> {
    fn empty(execution: &Memory) -> Self {
        Self {
            paths: execution.vector(),
            truncated: None,
        }
    }

    /// The paths, shortest first, and among paths of one length in the order
    /// the caller's inputs put them in.
    #[must_use]
    pub fn paths(&self) -> &[Path<'a>] {
        &self.paths
    }

    /// Which bound stopped the search, where one did. `None` says the search
    /// finished: every path there is, is here.
    #[must_use]
    pub fn truncated(&self) -> Option<Truncation> {
        self.truncated
    }

    /// Whether the search was stopped rather than finished, which a report
    /// must say rather than claim it enumerated everything.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated.is_some()
    }
}

/// The UTC-label interval the path is built for, retaining leap/fractional labels.
///
/// A signature is placed in an interval rather than at an instant, because
/// what a timestamp proves is an upper bound and the lower one is usually
/// unknown. A certificate takes part in a path only where it was valid
/// across the whole of it: resolving at one end would let a signature made
/// before a certificate existed pass on the strength of a later moment.
///
/// Ordinary whole-second constructors remain available. Use the `Instant`
/// constructors for fractional or inserted-second endpoints; caller-supplied
/// leap facts authenticate their occurrence separately from this comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    from: crate::temporal::Instant,
    to: crate::temporal::Instant,
}

impl Interval {
    /// The interval between two moments, whichever way round the caller
    /// hands them: an interval is a pair of bounds, not an ordering.
    #[must_use]
    pub fn between(first: i64, second: i64) -> Self {
        Self::between_instants(
            crate::temporal::Instant::whole(first),
            crate::temporal::Instant::whole(second),
        )
    }

    /// The interval that is one moment, which is what a caller has when the
    /// signing time is known exactly and nothing wider has to be covered.
    #[must_use]
    pub fn at(moment: i64) -> Self {
        Self::at_instant(crate::temporal::Instant::whole(moment))
    }

    /// The interval between two lossless labels, in either input order.
    #[must_use]
    pub fn between_instants(
        first: crate::temporal::Instant,
        second: crate::temporal::Instant,
    ) -> Self {
        Self {
            from: first.min(second),
            to: first.max(second),
        }
    }

    /// A point interval retaining the supplied leap flag and nanoseconds.
    #[must_use]
    pub fn at_instant(moment: crate::temporal::Instant) -> Self {
        Self {
            from: moment,
            to: moment,
        }
    }

    /// The earlier bound's lossy POSIX projection, without fractional precision.
    #[must_use]
    pub fn from(self) -> i64 {
        self.from.seconds()
    }

    /// The later bound's lossy POSIX projection, without fractional precision.
    #[must_use]
    pub fn to(self) -> i64 {
        self.to.seconds()
    }

    /// The earlier lossless UTC label.
    #[must_use]
    pub fn from_instant(self) -> crate::temporal::Instant {
        self.from
    }

    /// The later lossless UTC label.
    #[must_use]
    pub fn to_instant(self) -> crate::temporal::Instant {
        self.to
    }

    /// Whether a validity interval holds the whole of this one.
    fn inside(self, validity: Validity) -> bool {
        validity.not_before().instant() <= self.from && self.to <= validity.not_after().instant()
    }
}

/// What the caller was asking about, before any certificate was read.
///
/// The defaults are a validator with no policy of its own: it asks what the
/// authorities agreed on rather than whether they agreed on one thing, and
/// reads what the certificates say rather than overriding it. A caller with
/// a policy of its own says so here, and gets paths that satisfy it or none.
#[derive(Debug, Clone, Copy)]
pub struct Policy<'a> {
    /// The policies the caller is asking about. Empty asks about all of
    /// them, and a path then carries whatever its authorities agreed on.
    pub wanted: &'a [Oid<'a>],
    /// Whether every path must name a policy, rather than only those an
    /// authority along the way demanded it of.
    pub explicit: bool,
    /// Whether a policy one authority maps to another's is honoured.
    pub mapping: bool,
    /// Whether the identifier standing for any policy is read as the
    /// certificate meant it.
    pub any: bool,
}

impl Default for Policy<'_> {
    fn default() -> Self {
        Self {
            wanted: &[],
            explicit: false,
            mapping: true,
            any: true,
        }
    }
}

/// What the search charges for the checks it runs, so that a pool somebody
/// else controls cannot buy an unbounded amount of them. The numbers are
/// relative to each other rather than to any clock: a signature check is
/// what a path spends most of its budget on, and a name comparison is a
/// walk over two names.
mod cost {
    /// Reading an extension of a certificate the search is considering.
    pub(super) const EXTENSION: u64 = 8;
    /// Reaching for two names to compare them, before what they hold.
    pub(super) const NAME: u64 = 16;
    /// How many bytes of the two names one unit of work buys where they are
    /// compared. Comparing them reads both: the parts of a name holding
    /// several attributes are ordered against each other, and values that
    /// are not byte-identical are folded through to the end. What that
    /// costs is the size of what a pool somebody else wrote put there, so
    /// it is charged by that size rather than at a flat rate.
    pub(super) const COMPARED: u64 = 16;
    /// Asking the verifier about one signature.
    pub(super) const SIGNATURE: u64 = 1_024;
    /// Holding one certificate to the constraints above it.
    pub(super) const CHECK: u64 = 32;
    /// Looking at one entry of a list a document decides the length of: a
    /// policy a certificate names, a mapping it declares, a region an
    /// authority wrote, a node of the working out being indexed.
    ///
    /// Charged per entry rather than per list, because the length is what
    /// somebody else chose. What the entry holds is charged where it is
    /// read, which for most of these is a lookup in an index and nothing
    /// more.
    pub(super) const ENTRY: u64 = 4;
    /// How many bytes of a certificate one unit of work buys where the whole
    /// of it is read, which is where its identity is taken.
    pub(super) const HASHED: u64 = 64;
}

/// Everything the search asks of the caller: what is trusted, when, how far
/// to look, what is being asked about, and who answers the questions this
/// crate does not.
///
/// One value rather than a row of arguments, because these travel together:
/// a path built against other anchors, or for another interval, is another
/// question rather than the same one asked differently.
pub struct Context<'a, 'p, V: Verify, W: Watch, R: Recognizer> {
    /// The current operation's shared execution and storage domain.
    /// Retained certificate accounts never implicitly finance this search.
    pub execution: &'p Memory,
    /// The anchors a path may end at, in the order a report should prefer.
    pub anchors: &'p [Anchor<'a>],
    /// The interval the path is built for.
    pub interval: Interval,
    /// How far the search may go before it stops and says so.
    pub bounds: Bounds,
    /// What the caller is asking about the policies a path was issued under.
    pub policy: Policy<'a>,
    /// Who checks a signature.
    pub verifier: &'p V,
    /// Who says the time the caller allowed has passed.
    pub watch: &'p W,
    /// Which extensions a scheme understands beyond the ones this crate
    /// reads, since a critical extension nobody understood is a certificate
    /// no path goes through.
    pub recognizer: &'p R,
}

/// The state a search carries, so the bounds are counted in one place.
struct Search<'a, 'p, V: Verify, W: Watch, R: Recognizer> {
    execution: &'p Memory,
    /// The candidates as the caller supplied them, unread until a path
    /// needs one.
    supplied: &'p [&'a Certificate<'a>],
    /// The certificate the question is about, which is not a candidate
    /// issuer of itself.
    target: &'a Certificate<'a>,
    /// The candidates folded to one each, worked out the first time the
    /// search looks for an issuer.
    ///
    /// Not before then: a target an anchor issued is settled by the anchors
    /// alone, and reading a pool of certificates no path goes through would
    /// spend the budget that answer needs before the answer is reached. A
    /// document may carry any number of them, so that is a path a caller
    /// holds the whole of being reported as left out.
    pool: Option<OwnedVec<&'a Certificate<'a>>>,
    anchors: &'p [Anchor<'a>],
    interval: Interval,
    bounds: Bounds,
    policy: Policy<'a>,
    verifier: &'p V,
    watch: &'p W,
    recognizer: &'p R,
    visited: usize,
    edges: usize,
    spent: u64,
    /// The bound that ended the search, where one did.
    halted: Option<Truncation>,
    /// What a bound left out without ending the search.
    noted: Option<Truncation>,
    found: OwnedVec<Path<'a>>,
    /// What the verifier has already said, so that a subpath shared by many
    /// paths costs one check rather than one per path. Two certificates
    /// stand for one answer here by where their bytes are, since that is
    /// what was handed to the verifier; a second copy of one certificate is
    /// a second entry and not a wrong one.
    signatures: OwnedMap<(usize, usize, usize), Verified>,
    /// What each certificate says about itself, which does not depend on
    /// where in a path it sits. A cross-certified pool reaches the same
    /// certificate at many depths and on many chains, and reading its
    /// extensions again each time would charge a caller once per visit for
    /// an answer that cannot have changed.
    properties: OwnedMap<usize, Properties<'a>>,
}

/// What one certificate says about itself, worked out once.
#[derive(Debug, Clone, Copy)]
struct Properties<'a> {
    /// Common facts, or no facts when the local operation could not finish.
    facts: Option<validation::CertificateFacts<'a>>,
    /// Whether it can stand in a path at all: valid across the interval, and
    /// carrying no critical extension nobody understood.
    usable: bool,
    /// What it says about issuing certificates, or `None` where it says it
    /// issues none.
    issues: Option<crate::constraints::BasicConstraints>,
    /// Whether it is an anchor's own certificate: it carries the name and
    /// key of one, and signs itself. Both, because a certificate carrying an
    /// anchor's identity under somebody else's signature is a link to that
    /// anchor rather than the anchor.
    publishes_itself: bool,
}

impl<V: Verify, W: Watch, R: Recognizer> Meter for Search<'_, '_, V, W, R> {
    fn spend(&mut self, work: u64) -> Result<bool> {
        Self::spend(self, work)
    }
}

impl<'a, V: Verify, W: Watch, R: Recognizer> validation::Driver<'a, R> for Search<'a, '_, V, W, R> {
    type VerificationError = V::Error;

    fn verified(
        &mut self,
        certificate: &'a Certificate<'a>,
        key: WorkingKey<'a>,
    ) -> BuildResult<Option<Verified>, V::Error, R::Error> {
        Self::verified(self, certificate, key)
    }

    fn facts(
        &mut self,
        certificate: &'a Certificate<'a>,
        _settings: &validation::Settings<'a, '_, R>,
    ) -> BuildResult<Option<validation::CertificateFacts<'a>>, V::Error, R::Error> {
        Ok(properties(self, certificate)?.facts)
    }
}

impl<V: Verify, W: Watch, R: Recognizer> Search<'_, '_, V, W, R> {
    /// Charges work, and says whether the search may go on.
    fn spend(&mut self, work: u64) -> Result<bool> {
        debug_assert!(self.spent <= self.bounds.work);
        if work > self.bounds.work - self.spent {
            self.stop(Truncation::Work);
            return Ok(false);
        }
        self.execution
            .charge_work(work)
            .map_err(|reason| self.target.tbs().subject().resource(reason))?;
        self.spent += work;
        if self.watch.out_of_time() {
            self.stop(Truncation::Time);
            return Ok(false);
        }
        Ok(true)
    }

    /// Charges for comparing two names, by what comparing them reads.
    ///
    /// Before the comparison rather than after it: a bound that is charged
    /// once the work is done is a bound the last comparison was never held
    /// to, and a pool of long names is a set of last comparisons.
    fn spend_names(&mut self, left: &Name<'_>, right: &Name<'_>) -> Result<bool> {
        validation::spend_names(self, left, right)
    }

    /// Records which bound stopped the search, keeping the first one: it is
    /// the one that decided the answer.
    fn stop(&mut self, at: Truncation) {
        // Two kinds of bound, kept apart because they are two statements. A
        // bound that ends the whole search decides the answer and is what
        // the answer reports; one that ended a branch or left a path out is
        // worth saying only where nothing ended the search. Keeping one
        // field for both would let the first branch to run out of depth
        // swallow the count of certificates that later stopped everything,
        // and the search would carry on past a bound it had reached while
        // naming the wrong reason for what it did not do.
        let recorded = if at.halts() {
            &mut self.halted
        } else {
            &mut self.noted
        };
        if recorded.is_none() {
            *recorded = Some(at);
        }
    }

    /// Whether a bound has ended the search.
    ///
    /// Running out of room for paths is not one of them: what is worth
    /// keeping is decided when a path is settled rather than by which was
    /// found first, so a search that has filled its room keeps looking for
    /// something better to put in it, under the bounds that remain.
    fn stopped(&self) -> bool {
        self.halted.is_some()
    }

    /// What the answer says about being incomplete: the bound that ended the
    /// search where one did, and otherwise what was left out along the way.
    fn truncated(&self) -> Option<Truncation> {
        self.halted.or(self.noted)
    }

    /// Asks the verifier about one signature, or repeats what it said about
    /// the same one before. `None` says the budget ran out before it could
    /// be asked, which is not an answer about the signature.
    ///
    /// The charge is here rather than at the call sites, and only where the
    /// verifier is actually reached. Repeating what is already known costs a
    /// lookup, and charging a cryptographic check for it would undo what
    /// remembering the answer was for: a sub-path shared by many chains
    /// would spend the budget once per chain that walks it, and the search
    /// would stop before reaching paths it had already done the work for.
    fn verified(
        &mut self,
        certificate: &Certificate<'_>,
        key: WorkingKey<'_>,
    ) -> BuildResult<Option<Verified>, V::Error, R::Error> {
        // The parameters are part of what was asked, not only the key: one
        // key standing in two different sets of inherited parameters is two
        // questions, and answering the second from the first would carry an
        // answer across paths that do not share what the key stands in.
        let at = (
            certificate.signed_bytes().as_ptr() as usize,
            key.key().as_bytes().as_ptr() as usize,
            key.parameters().map_or(0, |held| held.as_ptr() as usize),
        );
        if let Some(answer) = self
            .signatures
            .get(&at, self.execution)
            .map_err(|reason| certificate.tbs().subject().resource(reason))?
        {
            return Ok(Some(*answer));
        }
        if !self.spend(cost::SIGNATURE)? {
            return Ok(None);
        }
        // Admit the cache allocation before invoking the external verifier.
        self.signatures
            .try_insert(at, Verified::Unsupported)
            .map_err(|reason| certificate.tbs().subject().resource(reason))?;
        let answer = self
            .verifier
            .verify(
                &certificate.signature_algorithm(),
                key,
                certificate.signed_bytes(),
                certificate.signature(),
                self.execution,
            )
            .map_err(BuildError::Verification)?;
        *self
            .signatures
            .get_mut(&at, self.execution)
            .map_err(|reason| certificate.tbs().subject().resource(reason))?
            .expect("the admitted signature cache entry") = answer;
        Ok(Some(answer))
    }
}

/// Admits anchor-folding work before mutation in both local and aggregate budgets.
fn spend_anchor(
    context: &Context<'_, '_, impl Verify, impl Watch, impl Recognizer>,
    spent: &mut u64,
    halted: &mut Option<Truncation>,
    origin: &Name<'_>,
    work: u64,
) -> Result<bool> {
    debug_assert!(*spent <= context.bounds.work);
    if work > context.bounds.work - *spent {
        *halted = Some(Truncation::Work);
        return Ok(false);
    }
    if context.watch.out_of_time() {
        *halted = Some(Truncation::Time);
        return Ok(false);
    }
    context
        .execution
        .charge_work(work)
        .map_err(|reason| origin.resource(reason))?;
    *spent += work;
    Ok(true)
}

/// The anchors a search will look at, with the repeats among the caller's
/// folded away, and what folding them spent.
///
/// Two anchors of one name and one key are one anchor, and the paths to them
/// are one path. A trust context assembled from several stores hands the same
/// root over more than once, and every copy would buy an edge and a name
/// comparison to settle a path that was already settled, so a bound would
/// report the answer as truncated over nothing that was left out.
///
/// Folded by what makes two anchors one, which is the same name and the same
/// key however the name was written, and the same certificate or none behind
/// both. Folding by the bytes of the name instead would leave one key under
/// two spellings as two anchors, and placed in front of a key that does
/// verify they can spend a tight bound before it is reached: the path that
/// exists is then not returned, which is a lost answer rather than a charge.
///
/// The keys are grouped first, because they are compared as bytes and a trust
/// store's are all different: an anchor is looked at once, and the comparison
/// that reads two names runs only where a key was supplied twice, which is
/// the case being folded. Comparing every pair would be the square of a count
/// for the sake of the pairs that cannot match.
fn fold_anchors<'a>(
    context: &Context<'a, '_, impl Verify, impl Watch, impl Recognizer>,
    spent: &mut u64,
    halted: &mut Option<Truncation>,
) -> Result<OwnedVec<Anchor<'a>>> {
    let mut keyed: OwnedMap<&[u8], OwnedVec<usize>> = context.execution.map();
    let mut anchors: OwnedVec<Anchor<'a>> = context.execution.vector();
    'anchors: for anchor in context.anchors {
        let key = anchor.key().as_bytes();
        if !spend_anchor(
            context,
            spent,
            halted,
            anchor.name(),
            cost::CHECK + key.len() as u64 / cost::HASHED,
        )? {
            break;
        }

        let fail = |reason| anchor.name().resource(reason);
        if keyed.get(&key, context.execution).map_err(fail)?.is_none() {
            keyed
                .try_insert(key, context.execution.vector())
                .map_err(fail)?;
        }
        let group = keyed
            .get_mut(&key, context.execution)
            .map_err(fail)?
            .expect("the group was inserted before lookup");
        for at in group.iter() {
            let theirs: &Name<'_> = anchors[*at].name();
            let bytes = (theirs.as_bytes().len() as u64)
                .checked_add(anchor.name().as_bytes().len() as u64)
                .ok_or_else(|| {
                    anchor
                        .name()
                        .resource(structured_asn1::memory::MemoryError::WorkExceeded)
                })?;
            if !spend_anchor(
                context,
                spent,
                halted,
                anchor.name(),
                cost::NAME + bytes / cost::COMPARED,
            )? {
                break 'anchors;
            }
            if !theirs.matches(anchor.name(), context.execution)? {
                continue;
            }

            // The names and the key agree, and one thing is left that tells
            // two such anchors apart: what each was published in. A trust
            // context that supplied the anchor as a constrained certificate
            // bound the names below it, and the same name and key supplied
            // without one bound nothing. They are two statements about one
            // key, and folding them would let the order of the caller's list
            // decide which constraint holds and so whether a path exists at
            // all.
            let held = anchors[*at].certificate();
            let bytes = published_bytes(held)
                .checked_add(published_bytes(anchor.certificate()))
                .ok_or_else(|| {
                    anchor
                        .name()
                        .resource(structured_asn1::memory::MemoryError::WorkExceeded)
                })?;
            if !spend_anchor(
                context,
                spent,
                halted,
                anchor.name(),
                cost::CHECK + bytes / cost::HASHED,
            )? {
                break 'anchors;
            }
            if published_alike(held, anchor.certificate(), context.execution)? {
                continue 'anchors;
            }
        }
        group.try_push(anchors.len()).map_err(fail)?;
        anchors.try_push(*anchor).map_err(fail)?;
    }
    Ok(anchors)
}

/// The candidates of a pool, each of them once and the target not among
/// them.
///
/// A pool that holds one certificate twice holds one certificate, and folding
/// the copies before the search rather than at each step is what makes that
/// true of what the search spends as well as of what it finds. A pool
/// somebody else wrote may repeat a certificate leading nowhere as often as
/// it likes, and charging every copy would let the copies spend the search
/// before the issuer that does lead somewhere is reached.
///
/// The folding is itself charged, because it is itself work somebody else
/// decides the size of: the identity of a certificate is its bytes, and there
/// may be any number of certificates of any length.
fn fold_pool<'a, V: Verify, W: Watch, R: Recognizer>(
    search: &mut Search<'a, '_, V, W, R>,
    pool: &[&'a Certificate<'a>],
    target: &'a Certificate<'a>,
) -> BuildResult<OwnedVec<&'a Certificate<'a>>, V::Error, R::Error> {
    let mut named: OwnedMap<usize, ()> = search.execution.map();
    let mut seen: OwnedMap<&[u8], ()> = search.execution.map();
    let mut unique = search.execution.vector();
    for candidate in pool {
        let bytes = candidate.as_bytes();

        // Looking at a candidate at all, which every one of them costs.
        if !search.spend(cost::CHECK)? {
            break;
        }

        // A pool that names one certificate over and over names it once,
        // and recognising that costs a pointer. Reading the whole encoding
        // is what telling a separately written copy from it costs, and
        // charging that for every repeat lets the repeats spend the search
        // before the issuer that does lead somewhere is reached.
        if named
            .try_insert(bytes.as_ptr() as usize, ())
            .map_err(|reason| candidate.tbs().subject().resource(reason))?
            .is_some()
        {
            continue;
        }
        if !search.spend(bytes.len() as u64 / cost::HASHED)? {
            break;
        }

        // The target is not a candidate issuer of itself, and a caller who
        // put it here was told that changes nothing. Leaving it among the
        // candidates makes that false of what the search spends: the cycle
        // check refuses it, but only after an edge and a name comparison
        // have been charged for it, so a bound tight enough to notice
        // reports the answer as truncated over a certificate that could
        // never have been followed.
        search
            .execution
            .charge_work(bytes.len().max(target.as_bytes().len()) as u64)
            .map_err(|reason| candidate.tbs().subject().resource(reason))?;
        if bytes != target.as_bytes()
            && seen
                .try_insert(bytes, ())
                .map_err(|reason| candidate.tbs().subject().resource(reason))?
                .is_none()
        {
            unique
                .try_push(*candidate)
                .map_err(|reason| candidate.tbs().subject().resource(reason))?;
        }
    }
    Ok(unique)
}

/// Builds the paths from one certificate to the anchors the caller trusts.
///
/// The pool is where issuers are looked for, and holding the target itself
/// changes nothing: a certificate never appears twice in one path
/// (RFC 5280 6.1), so it cannot be its own issuer.
///
/// # Errors
///
/// A spent budget, which says this run gave up rather than that the
/// certificates are wrong.
pub fn build<'a, V: Verify, W: Watch, R: Recognizer>(
    target: &'a Certificate<'a>,
    pool: &[&'a Certificate<'a>],
    context: &Context<'a, '_, V, W, R>,
) -> BuildResult<Outcome<'a>, V::Error, R::Error> {
    // A path ends at an anchor, so a caller who named none has asked a
    // question whose complete answer is no paths. Reading the pool to find
    // that out spends a budget on work that cannot change the answer, and a
    // bound reached while doing it would report the one conclusive answer
    // there is as though something had been left out, which reads to a
    // caller as worth asking again.
    if context.anchors.is_empty() {
        return Ok(Outcome::empty(context.execution));
    }

    // And a path is built for a moment. A target the caller's interval does
    // not hold is not one any path can end at, whatever the anchors and the
    // pool say, so folding them to find that out is the same spending on an
    // answer that cannot change. The question is asked again where every
    // certificate of a path is held to it, and asking it here first is what
    // keeps a bound from calling this conclusive answer a partial one.
    if !context.interval.inside(target.tbs().validity()) {
        return Ok(Outcome::empty(context.execution));
    }

    let mut spent = 0u64;
    let mut halted = None;
    let anchors = fold_anchors(context, &mut spent, &mut halted)?;
    if halted.is_some() {
        return Ok(Outcome {
            paths: context.execution.vector(),
            truncated: halted,
        });
    }

    let mut search = Search {
        execution: context.execution,
        supplied: pool,
        target,
        pool: None,
        anchors: &anchors,
        interval: context.interval,
        bounds: context.bounds,
        policy: context.policy,
        verifier: context.verifier,
        watch: context.watch,
        recognizer: context.recognizer,
        visited: 0,
        edges: 0,
        spent,
        halted,
        noted: None,
        found: context.execution.vector(),
        signatures: context.execution.map(),
        properties: context.execution.map(),
    };

    // The certificate an anchor was published in is not a step on a path to
    // that anchor: "when the trust anchor is provided in the form of a
    // self-signed certificate, this self-signed certificate is not included
    // as part of the prospective certification path" (RFC 5280 6.1). That
    // holds of the first position as much as of the rest, and the rest
    // already keep it. Settling such a target reports the anchor as issued
    // by itself, which is the anchor named twice rather than a chain of
    // authority, and it is what a caller asking about a root would read as
    // the root having been certified by somebody.
    //
    // A self-signed certificate can chain nowhere else, since the only name
    // that issued it is its own, so there is nothing further to look for
    // and the empty answer is the whole of it.
    let known = properties(&mut search, target)?;
    let mut chain = context.execution.vector();
    if known.usable && !known.publishes_itself {
        walk(&mut search, target, &mut chain)?;
    }

    // Shortest first: a longer path to the same place says the same thing
    // through more parties, and a reader reads the first one. Among paths
    // of one length the order is the one the caller's inputs put them in,
    // which is what makes the same inputs give the same answer twice.
    // Include the discovery position in the comparison so the allocation-free
    // heap sort preserves the documented order among equal-length paths.
    let mut ordered = context.execution.vector();
    let found = core::mem::replace(&mut search.found, context.execution.vector());
    for (position, path) in found.into_iter().enumerate() {
        ordered
            .try_push((position, path))
            .map_err(|reason| target.tbs().subject().resource(reason))?;
    }
    ordered
        .try_sort_unstable_by(|left, right| {
            Ok::<_, structured_asn1::memory::MemoryError>(
                (left.1.len(), left.0).cmp(&(right.1.len(), right.0)),
            )
        })
        .map_err(|error| target.tbs().subject().resource(error.into()))?;
    for (_, path) in ordered {
        search
            .found
            .try_push(path)
            .map_err(|reason| target.tbs().subject().resource(reason))?;
    }
    let truncated = search.truncated();
    Ok(Outcome {
        paths: search.found,
        truncated,
    })
}

/// Follows one certificate up: to every anchor that could have issued it,
/// and to every certificate in the pool that could have.
fn walk<'a, V: Verify, W: Watch, R: Recognizer>(
    search: &mut Search<'a, '_, V, W, R>,
    certificate: &'a Certificate<'a>,
    chain: &mut OwnedVec<&'a Certificate<'a>>,
) -> BuildResult<(), V::Error, R::Error> {
    // One candidate cursor per active certificate replaces recursive DFS.
    // Both stacks are admitted by the request domain before their growth.
    let mut cursors = search.execution.vector();
    let mut entering = certificate;
    'enter: loop {
        if search.stopped() {
            break;
        }
        if search.visited >= search.bounds.visited {
            search.stop(Truncation::Visited);
            break;
        }
        search.visited += 1;
        if !search.spend(cost::CHECK)? {
            break;
        }
        if chain.len() >= search.bounds.depth {
            search.stop(Truncation::Depth);
            break;
        }
        chain
            .try_push(entering)
            .map_err(|reason| entering.tbs().subject().resource(reason))?;
        cursors
            .try_push(0usize)
            .map_err(|reason| entering.tbs().subject().resource(reason))?;
        settle(search, entering, chain)?;

        loop {
            if search.stopped() {
                break 'enter;
            }
            let current = *chain.last().expect("the active DFS certificate");
            let cursor = cursors.last_mut().expect("its candidate cursor");
            if let Some(candidate) = next_issuer(
                search,
                current,
                chain,
                chain.len() >= search.bounds.depth,
                cursor,
            )? {
                entering = candidate;
                continue 'enter;
            }
            chain.pop();
            cursors.pop();
            if chain.is_empty() {
                break 'enter;
            }
        }
    }
    chain.clear();
    Ok(())
}

/// Ends the chain at every anchor that issued the certificate on top of it,
/// which is where a path becomes one.
fn settle<'a, V: Verify, W: Watch, R: Recognizer>(
    search: &mut Search<'a, '_, V, W, R>,
    certificate: &'a Certificate<'a>,
    chain: &[&'a Certificate<'a>],
) -> BuildResult<(), V::Error, R::Error> {
    for at in 0..search.anchors.len() {
        let anchor = search.anchors[at];
        if search.stopped() {
            break;
        }
        if search.edges >= search.bounds.edges {
            search.stop(Truncation::Edges);
            break;
        }
        search.edges += 1;
        if !search.spend_names(certificate.tbs().issuer(), anchor.name())? {
            break;
        }
        if !certificate
            .tbs()
            .issuer()
            .matches(anchor.name(), search.execution)?
        {
            continue;
        }
        // The signature is checked where the path is walked from the anchor
        // down, since that is where the parameters a key may stand in are
        // known. Nothing is lost by not asking here: this is the last edge
        // of the path, so the check is one step away either way.
        let Some(policies) = validate_candidate(search, chain, anchor)? else {
            continue;
        };
        keep(search, chain, anchor, policies)?;
    }
    Ok(())
}

/// Puts a settled path among the ones that will be returned, where there is
/// room for it or where what it says is not already there.
///
/// A repeat of a route already held is dropped and is not truncation: it is
/// the same path spelled through a re-issued certificate, and nothing was
/// lost by not showing it twice. Dropping a path that does say something
/// else is truncation, and so is making room for one by putting out a
/// repeat of something already shown.
/// The chain is held rather than copied until there is somewhere to put it:
/// a cross-certified pool settles the same route many times over, and a copy
/// made before the question is asked is a copy made for every one of them.
fn keep<'a, V: Verify, W: Watch, R: Recognizer>(
    search: &mut Search<'a, '_, V, W, R>,
    chain: &[&'a Certificate<'a>],
    anchor: Anchor<'a>,
    policies: OwnedVec<Oid<'a>>,
) -> BuildResult<(), V::Error, R::Error> {
    // Telling this path from the ones already held reads their names, the
    // keys under them and their policies again, once per path held, and how
    // long a name or a key encoding is is the pool's to decide. Both are
    // read from the front, so two of one length that part near the end are
    // read almost to the end. The charge is taken for the whole scan before
    // it runs.
    //
    // Obeyed where there is anything to compare against: a charge that the
    // budget cannot meet is the answer that this scan is not going to
    // happen, and running it anyway is the reading the charge exists to
    // stop. What is then not known is whether this route says what a held
    // one already says, so it is not shown, and the answer is marked
    // truncated by the charge that failed.
    //
    // Where nothing is held there is nothing to compare and no scan to
    // refuse. The first path a search settles is kept whatever the budget
    // says, since dropping it would lose an answer for work nobody was
    // going to do.
    let held = search.found.len() as u64;
    if held > 0 {
        if !search.spend(chain.len() as u64)? {
            return Ok(());
        }
        let overflow = || {
            anchor
                .name
                .resource(structured_asn1::memory::MemoryError::WorkExceeded)
        };
        let mut read = 0u64;
        for certificate in chain {
            let tbs = certificate.tbs();
            let bytes =
                tbs.subject().as_bytes().len() as u64 + tbs.public_key().as_bytes().len() as u64;
            read = read.checked_add(bytes).ok_or_else(overflow)?;
        }
        let each = (read / cost::COMPARED)
            .checked_add(cost::NAME)
            .and_then(|work| work.checked_add(policies.len() as u64))
            .ok_or_else(overflow)?;
        let work = each.checked_mul(held).ok_or_else(overflow)?;
        if !search.spend(work)? {
            return Ok(());
        }
    }

    // The same route saying the same thing. A re-issued certificate is one
    // route spelled twice, but an authority that re-issued under another
    // policy said something else through it, and that is precisely the
    // distinct outcome several paths exist to preserve: dropping it as a
    // repeat would throw away the answer while reporting nothing missing.
    for held in &search.found {
        if held.same_route(chain, anchor, search.execution)?
            && held.same_meaning(anchor, &policies, search.execution)?
        {
            return Ok(());
        }
    }
    if search.found.len() < search.bounds.paths {
        let mut certificates = search.execution.vector();
        certificates
            .try_extend_from_slice(chain)
            .map_err(|reason| anchor.name.resource(reason))?;
        search
            .found
            .try_push(Path {
                certificates,
                anchor,
                policies,
            })
            .map_err(|reason| anchor.name.resource(reason))?;
        return Ok(());
    }

    // No room. A path saying something none of the held ones say is worth
    // more than a second path saying what one of them already said, so it
    // takes the place of the last such repeat. Either way a path that was
    // found is not being returned, which the answer has to say.
    search.stop(Truncation::Paths);
    for held in &search.found {
        if held.same_meaning(anchor, &policies, search.execution)? {
            return Ok(());
        }
    }
    let mut repeat = None;
    for at in (0..search.found.len()).rev() {
        let candidate = &search.found[at];
        let mut count = 0;
        for held in &search.found {
            if held.same_meaning(candidate.anchor, &candidate.policies, search.execution)? {
                count += 1;
                if count > 1 {
                    break;
                }
            }
        }
        if count > 1 {
            repeat = Some(at);
            break;
        }
    }
    if let Some(at) = repeat {
        // The repeat is taken out and the new path put on the end, rather
        // than dropped into the slot the repeat held. Paths of one length
        // come back in the order the caller's inputs put them in, and the
        // sort that arranges them is by length alone: a path written into
        // an earlier slot would sit in front of paths found before it, and
        // nothing afterwards would move it back.
        let moves = core::mem::size_of_val(&search.found[at..]);
        search
            .execution
            .charge_work(moves as u64)
            .map_err(|reason| anchor.name.resource(reason))?;
        search.found[at..].rotate_left(1);
        search.found.pop();
        let mut certificates = search.execution.vector();
        certificates
            .try_extend_from_slice(chain)
            .map_err(|reason| anchor.name.resource(reason))?;
        search
            .found
            .try_push(Path {
                certificates,
                anchor,
                policies,
            })
            .map_err(|reason| anchor.name.resource(reason))?;
    }
    Ok(())
}

/// Follows the chain further up: to every certificate in the pool that could
/// have issued the one on top of it.
///
/// `deepest` says the chain has reached the length the caller allowed, so
/// that a candidate found here is one the depth bound refuses to step into
/// rather than one to walk. It is what turns the bound into a report: the
/// answer says it was reached where a candidate was there to be refused,
/// and says nothing where the chain had nowhere to go regardless.
fn next_issuer<'a, V: Verify, W: Watch, R: Recognizer>(
    search: &mut Search<'a, '_, V, W, R>,
    certificate: &'a Certificate<'a>,
    chain: &[&'a Certificate<'a>],
    deepest: bool,
    at: &mut usize,
) -> BuildResult<Option<&'a Certificate<'a>>, V::Error, R::Error> {
    // The candidates, folded the first time one is looked for. Every later
    // position reads the same folded list.
    if search.pool.is_none() {
        let supplied = search.supplied;
        let target = search.target;
        search.pool = Some(fold_pool(search, supplied, target)?);
    }
    // By position rather than by iterator: what follows this borrows the
    // search to walk further up, and a candidate is one shared reference,
    // so reading it out ends the borrow the loop would otherwise hold.
    while let Some(candidate) = search.pool.as_ref().and_then(|pool| pool.get(*at)).copied() {
        *at += 1;
        if search.stopped() {
            break;
        }
        if search.edges >= search.bounds.edges {
            search.stop(Truncation::Edges);
            break;
        }
        search.edges += 1;
        if !search.spend_names(certificate.tbs().issuer(), candidate.tbs().subject())? {
            break;
        }
        // A certificate appears once in a path (RFC 5280 6.1), which is
        // also what keeps a cycle from being followed round.
        //
        // Asked of where the certificate is rather than of what it holds.
        // The pool was folded before the search so that no two candidates
        // carry the same bytes, and the target was taken out of it, so two
        // certificates of one chain hold the same bytes exactly when they
        // are the same one. Comparing the encodings would read both from
        // end to end for an answer their addresses already give, and a pool
        // of long re-issued certificates that part only near the end makes
        // that a full scan per candidate per position of the chain, where
        // the charge just taken covers two names. It is the identity the
        // rest of the search already works by: what a certificate says
        // about itself is remembered under the same address.
        let mut repeated = false;
        for held in chain {
            search
                .execution
                .charge_work(1)
                .map_err(|reason| certificate.tbs().subject().resource(reason))?;
            if core::ptr::eq(held.as_bytes(), candidate.as_bytes()) {
                repeated = true;
                break;
            }
        }
        if repeated {
            continue;
        }
        if !certificate
            .tbs()
            .issuer()
            .matches(candidate.tbs().subject(), search.execution)?
        {
            continue;
        }
        // Everything cheap first, and the signature last: a candidate that
        // could not have issued anything, or was not valid when it would
        // have had to be, is refused for what it says rather than for what
        // its key does, and the check that costs the most is the one a
        // hostile pool would most like to buy in quantity.
        //
        // The certificate an anchor was published in is not a link in a path
        // to that anchor: "when the trust anchor is provided in the form of
        // a self-signed certificate, this self-signed certificate is not
        // included as part of the prospective certification path"
        // (RFC 5280 6.1). Walking into it would produce the path that was
        // already found, spelled one certificate longer.
        //
        // Self-signed is the whole of that rule, and names are not enough to
        // establish it. A provider recognized under two schemes has its
        // identity certified by both, and an authority rolling its key over
        // certifies the new key with the old one: the first carries the
        // anchor's name and key under somebody else's signature, the second
        // carries one name on both sides under the old key's. Both are
        // ordinary links, and skipping either would lose a whole route while
        // saying nothing about having lost it.
        let known = properties(search, candidate)?;
        if known.publishes_itself || !known.usable || known.issues.is_none() {
            continue;
        }
        if deepest {
            // A candidate that names itself the issuer and can issue is a
            // branch the depth bound is refusing, and refusing it is what
            // the answer has to say. Whether its signature would have held
            // is exactly what the search does not get to find out, so the
            // check is not spent on a candidate it will not follow. Once
            // one is refused the rest say the same thing, and the search
            // has other branches to spend its budget on.
            search.stop(Truncation::Depth);
            break;
        }
        // The key is asked about here, where the answer prunes the branch: a
        // candidate that did not sign this certificate is not walked into,
        // and a pool of such candidates costs one check each rather than a
        // subtree each.
        //
        // It is asked as the certificate wrote it, since what a key standing
        // in parameters written above stands in is exactly what this search
        // has not found yet. So only a definite no prunes. A registry that
        // cannot judge a key on those terms says that it cannot rather than
        // saying no, and the branch is walked so the question can be put
        // again from the anchor down, where the parameters in force are
        // known. Refusing on anything short of a no would lose whole routes.
        //
        // Asking only where the key carries its own parameters would prune
        // almost nothing: an algorithm that takes none writes a null, which
        // is written the same way as omitting them, so a pool of ordinary
        // wrong-key authorities would be walked in full and could spend the
        // whole budget before the one that signed this certificate is
        // reached. What tells the two apart is the registry's answer, and
        // the registry is who this asks.
        let key = WorkingKey::standing(candidate.tbs().public_key());
        let Some(answer) = search.verified(certificate, key)? else {
            break;
        };
        if answer == Verified::No {
            continue;
        }
        return Ok(Some(candidate));
    }
    Ok(None)
}

/// Whether two anchors were published the same way: in the same certificate,
/// or in none. It is the last thing that tells apart two anchors of one name
/// and one key, because the certificate an anchor was published in is what
/// says how the names below it are constrained.
fn published_alike(
    left: Option<&Certificate<'_>>,
    right: Option<&Certificate<'_>>,
    execution: &Memory,
) -> Result<bool> {
    match (left, right) {
        (None, None) => Ok(true),
        (Some(ours), Some(theirs)) => binds_alike(ours, theirs, execution),
        _ => Ok(false),
    }
}

/// Whether two certificates of one name and one key say the same thing about
/// the names below them.
///
/// By what is read rather than by every byte. An anchor's certificate is not
/// a link in any path: the one thing the search takes from it is what it
/// says about the space below, which is the regions it names, and nothing
/// else about it is consulted anywhere. A trust store holding a root
/// re-issued with a new serial, a new validity or a new signature holds one
/// statement of trust written twice, and keeping both makes the search try
/// each of them at every position where an anchor could end a path: a tight
/// bound on edges is then spent on copies, and a path through the one that
/// matches is lost.
///
/// The one extension compared is therefore the one enforced. Basic
/// constraints were compared here while an anchor's regions were honoured
/// only under an asserted authority bit; they are not read of an anchor any
/// more, and comparing them would split anchors that behave identically.
fn binds_alike(
    ours: &Certificate<'_>,
    theirs: &Certificate<'_>,
    execution: &Memory,
) -> Result<bool> {
    if same(ours, theirs) {
        return Ok(true);
    }
    let ours = ours
        .tbs()
        .extensions()
        .get(crate::oid::NAME_CONSTRAINTS, execution)?;
    let theirs = theirs
        .tbs()
        .extensions()
        .get(crate::oid::NAME_CONSTRAINTS, execution)?;
    Ok(match (ours, theirs) {
        (None, None) => true,
        (Some(ours), Some(theirs)) => {
            ours.is_critical() == theirs.is_critical() && ours.value() == theirs.value()
        }
        _ => false,
    })
}

/// How many times comparing a name may read it.
///
/// Once, where every part holds one attribute: the parts line up in the
/// order they were written and each pair is compared where it stands. A part
/// holding several is a set, whose order carries no meaning, so both sides
/// are put in order before they are lined up, and a sort of `n` reads its
/// input about `log2(n)` times over. The widest part decides it, since one
/// wide part is enough to pay for.
///
/// A document decides how many attributes a part holds, so this factor is
/// theirs to choose too: without it a name of one very wide part is charged
/// as though it were read straight through, and the sort runs to the end
/// with nothing left to stop it.
fn sorting_rounds(name: &Name<'_>) -> u64 {
    let widest = name
        .parts()
        .iter()
        .map(|part| part.attributes().len())
        .max()
        .unwrap_or(1)
        .max(1);
    u64::from(widest.ilog2()) + 1
}

/// How many bytes comparing an anchor's published certificate reads on its
/// side, which is none where it was published as a name and a key.
fn published_bytes(certificate: Option<&Certificate<'_>>) -> u64 {
    certificate.map_or(0, |certificate| certificate.as_bytes().len() as u64)
}

/// Whether two certificates are the same one: the bytes they arrived as. A
/// pool that holds one certificate twice holds one certificate.
fn same(left: &Certificate<'_>, right: &Certificate<'_>) -> bool {
    core::ptr::eq(left.as_bytes(), right.as_bytes()) || left.as_bytes() == right.as_bytes()
}

/// Whether a certificate is one an anchor was published in: the same name
/// and the same key, however the trust context supplied the anchor itself.
fn publishes_anchor<V: Verify, W: Watch, R: Recognizer>(
    search: &mut Search<'_, '_, V, W, R>,
    certificate: &Certificate<'_>,
) -> BuildResult<bool, V::Error, R::Error> {
    let anchors = search.anchors;
    for anchor in anchors {
        if !search.spend_names(certificate.tbs().subject(), anchor.name())? {
            break;
        }
        if !certificate
            .tbs()
            .subject()
            .matches(anchor.name(), search.execution)?
        {
            continue;
        }

        // The keys are compared byte for byte, and how long a key encoding
        // is is decided by whoever wrote the certificate. Two encodings of
        // one length that differ near the end are read to the end, and a
        // pool can hold a candidate for every anchor: charged at a flat
        // rate, one certificate and a handful of anchors buy the reading of
        // their product while the bound barely moves. The name comparison
        // above is charged by what it reads for the same reason, and this
        // is the other side of the same question.
        let key = certificate.tbs().public_key().as_bytes();
        let against = anchor.key().as_bytes();
        let read = (key.len() as u64 + against.len() as u64) / cost::COMPARED;
        if !search.spend(read)? {
            break;
        }
        if key == against {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What one certificate says about itself, read the first time it is seen
/// and repeated afterwards.
///
/// Every answer here is a property of the certificate and of the question
/// the caller asked, neither of which changes while a search runs, so the
/// second visit costs a lookup rather than the extensions again.
fn properties<'a, V: Verify, W: Watch, R: Recognizer>(
    search: &mut Search<'a, '_, V, W, R>,
    certificate: &'a Certificate<'a>,
) -> BuildResult<Properties<'a>, V::Error, R::Error> {
    let at = certificate.as_bytes().as_ptr() as usize;
    if let Some(known) = search
        .properties
        .get(&at, search.execution)
        .map_err(|reason| certificate.tbs().subject().resource(reason))?
    {
        return Ok(*known);
    }
    let settings = validation::Settings {
        execution: search.execution,
        interval: search.interval,
        policy: search.policy,
        policies: search.bounds.policies,
        recognizer: search.recognizer,
    };
    let facts = validation::certificate_facts(certificate, &settings, search)?;
    let usable = facts.is_some_and(|facts| facts.rejected.is_none());
    let self_issued = facts.is_some_and(|facts| facts.self_issued);
    let issuing = facts.and_then(|facts| {
        if facts.issuing.is_none() {
            facts.basic
        } else {
            None
        }
    });
    // Anchor publication identity is search metadata, not a certificate-path
    // acceptance rule. Ask the expensive self-signature only after cheap facts.
    let publishes_itself = usable
        && self_issued
        && publishes_anchor(search, certificate)?
        && search.verified(
            certificate,
            WorkingKey::standing(certificate.tbs().public_key()),
        )? == Some(Verified::Yes);
    let known = Properties {
        facts,
        usable,
        issues: issuing,
        publishes_itself,
    };
    search
        .properties
        .try_insert(at, known)
        .map_err(|reason| certificate.tbs().subject().resource(reason))?;
    Ok(known)
}

/// Whether the chain, read down from the anchor, is a path: every
/// certificate within the names the ones above it allowed, under a policy
/// they agreed on, and inside the depth they permitted (RFC 5280 6.1.3 and
/// 6.1.4).
///
/// The answer carries what the path was issued under, because that is not a
/// property of any one certificate: it is what is left after every authority
/// along the path has narrowed it.
///
/// The chain is held with the target first, so it is read backwards: the
/// certificate the anchor issued is where the path starts.
fn validate_candidate<'a, V: Verify, W: Watch, R: Recognizer>(
    search: &mut Search<'a, '_, V, W, R>,
    chain: &[&'a Certificate<'a>],
    anchor: Anchor<'a>,
) -> BuildResult<Option<OwnedVec<Oid<'a>>>, V::Error, R::Error> {
    let settings = validation::Settings {
        execution: search.execution,
        interval: search.interval,
        policy: search.policy,
        policies: search.bounds.policies,
        recognizer: search.recognizer,
    };
    // Every adjacent issuer and this terminal anchor were matched before
    // settle selected the chain. Preserve that construction witness rather
    // than normalizing all the same names a second time during processing.
    match validation::process(
        validation::Chain::Constructed(chain),
        anchor,
        &settings,
        search,
    )? {
        Validation::Accepted(facts) => Ok(Some(facts.into_policies())),
        Validation::Rejected(_) => Ok(None),
        Validation::Incomplete(reason) => {
            if !search.stopped() {
                search.stop(reason);
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests;
