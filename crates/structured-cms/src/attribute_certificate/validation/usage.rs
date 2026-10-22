//! Relying-party AC processing over authenticated issuance and original evidence.
//!
//! The protocol supplies authenticated participants and selected trust. This
//! module binds those inputs, enforces all known critical effects and records
//! usable attribute types. It does not authenticate a protocol, discover trust,
//! decrypt attributes, select freshness policy or grant application permission.
//! RFC5755 §§5–7: <https://www.rfc-editor.org/rfc/rfc5755#section-5>

use super::aa_path::validated::{ScopedVerifier, VerificationError};
use super::aa_path::{Issued, Permission};
use super::authentication::Authenticated;
use super::digest::BoundObject;
use super::{Check, HolderMethod, Rejection, charge};
use crate::attribute_certificate::controls::{self, AaControls};
use crate::attribute_certificate::{proxy, target};
use crate::{Error, Result};
use structured_asn1::Oid;
use structured_asn1::memory::{Execution, OwnedVec, Work};
use structured_pkix::Certificate;
use structured_pkix::extension::Recognizer;
use structured_pkix::general_name::GeneralName;
use structured_pkix::path::{self, EffectiveAnchor, Interval, Verify, Watch};
use structured_pkix::temporal::{LeapTable, Reading, Uncertainty};

mod status;
pub use status::{Evidence, NoStatus, Status};

/// One supplied holder PKC path, checked against its explicitly chosen anchor.
/// Protocol proof of possession and PKC revocation remain caller obligations.
#[derive(Debug)]
pub struct HolderPath<'p, 'a> {
    certificates: &'p [&'a Certificate<'a>],
    facts: path::ValidationFacts<'a>,
    anchor: EffectiveAnchor<'a>,
    interval: Interval,
}

/// The complete holder-path operation, without a usable partial key.
#[derive(Debug)]
pub enum HolderValidation<T, P> {
    /// Complete common PKIX validation.
    Accepted(T),
    /// Original common path rejection, including an empty supplied path.
    Rejected(P),
    /// Caller-selected processing bound prevented complete validation.
    Incomplete(path::Truncation),
}

/// Complete holder path result, retaining verifier and recognizer causes.
pub type HolderResult<'p, 'a, V, R> = core::result::Result<
    HolderValidation<HolderPath<'p, 'a>, path::Rejection<'a>>,
    HolderError<V, R>,
>;

/// Located processing and independent holder-path callback causes.
#[derive(Debug)]
pub enum HolderError<V, R> {
    /// Original shared processing/resource error.
    Processing(Error),
    /// Original selected verifier cause.
    Verification(V),
    /// Original extension recognizer cause.
    Recognition(R),
}

impl<'p, 'a> HolderPath<'p, 'a> {
    /// Original leaf-first path; its first element is the holder PKC.
    #[must_use]
    pub fn certificates(&self) -> &[&Certificate<'a>] {
        self.certificates
    }
    /// Actual effective key and independently owned policy facts.
    #[must_use]
    pub fn facts(&self) -> &path::ValidationFacts<'a> {
        &self.facts
    }
    /// Explicitly selected trust boundary, not a discovered self-signed root.
    #[must_use]
    pub fn anchor(&self) -> EffectiveAnchor<'a> {
        self.anchor
    }
    /// Complete interval checked by this original operation.
    #[must_use]
    pub fn interval(&self) -> Interval {
        self.interval
    }
    /// Validate a supplied holder path through the same PKIX core as AA paths.
    /// The anchor is outside the supplied prospective path. Every provider call
    /// receives the original signature ceiling as well as the current Work.
    pub fn validate<V, T, R, W>(
        certificates: &'p [&'a Certificate<'a>],
        anchor: EffectiveAnchor<'a>,
        context: &path::ValidationContext<'a, '_, V, T, R, W>,
    ) -> HolderResult<'p, 'a, <V as Verify<W>>::Error, R::Error>
    where
        W: Work,
        V: Verify<W>,
        for<'op> V: Verify<Execution<'op>, Error = <V as Verify<W>>::Error>,
        T: Watch,
        R: Recognizer<W>,
    {
        let verifier = ScopedVerifier(context.verifier);
        let scoped = path::ValidationContext {
            execution: context.execution,
            interval: context.interval,
            policy: context.policy,
            bounds: context.bounds,
            verifier: &verifier,
            watch: context.watch,
            recognizer: context.recognizer,
        };
        let checked =
            path::validate_effective(certificates, anchor, &scoped).map_err(
                |error| match error {
                    path::BuildError::Processing(e) => HolderError::Processing(Error::pkix(e)),
                    path::BuildError::Recognition(e) => HolderError::Recognition(e),
                    path::BuildError::Verification(VerificationError::Callback(e)) => {
                        HolderError::Verification(e)
                    }
                    path::BuildError::Verification(VerificationError::Processing(e)) => {
                        HolderError::Processing(e)
                    }
                },
            )?;
        Ok(match checked {
            path::Validation::Accepted(facts) => HolderValidation::Accepted(Self {
                certificates,
                facts,
                anchor,
                interval: context.interval,
            }),
            path::Validation::Rejected(error) => HolderValidation::Rejected(error),
            path::Validation::Incomplete(reason) => HolderValidation::Incomplete(reason),
        })
    }
}

/// Explicit caller-authenticated holder context. Selecting an alternative never
/// tries another written Holder identity as a fallback. Supplying this input
/// asserts that the protocol established the holder's possession/identity and,
/// for a certificate, its revocation status. The library checks the PKIX path.
#[derive(Debug)]
pub enum Holder<'r, 'p, 'a, 'c> {
    /// An authenticated PKC with a completed original path.
    Certificate {
        /// Original checked path whose first PKC authenticated the holder.
        path: &'r HolderPath<'p, 'a>,
        /// Explicit baseCertificateID or entityName interpretation.
        method: HolderMethod,
    },
    /// Already completed object-digest comparison for this AC. For a PKC object,
    /// its complete path is required; bare keys use the protocol's independent
    /// authentication scheme (RFC5755 §5(1), §7.3).
    Object {
        /// Original digest comparison, never just an asserted digest match.
        binding: &'r BoundObject<'r, 'c, 'a>,
        /// Required for certificate objects; optional for bare-key protocols.
        path: Option<&'r HolderPath<'p, 'a>>,
    },
}

/// Authenticated protocol identities for all proxy participants. The caller
/// supplies the trustworthy complete preceding-hop list, never an untrusted
/// list from the AC. A missing context cannot bypass a present `ProxyInfo`.
#[derive(Debug, Clone, Copy)]
pub struct Proxy<'n, 'a> {
    /// Holder or independently authenticated immediate proxy.
    pub sender: proxy::Sender<'a, 'n>,
    /// Every earlier proxy, in protocol order.
    pub intermediates: &'n [&'n [GeneralName<'a>]],
}

/// A completed negative or unproven use requirement. No variant is a resource
/// or callback failure; those remain terminal errors.
#[derive(Debug)]
pub enum Failure {
    /// Direct trust did not select the actual authenticated AA object.
    AuthorityTrust,
    /// Requested time is outside a checked issuance or holder-path interval.
    Interval,
    /// Supplied UTC facts cannot establish the requested precise label.
    Time(Uncertainty),
    /// Common Holder comparison refused, retaining its original source.
    Holder(Rejection),
    /// Object-digest facts refer to another original AC.
    HolderObject,
    /// A PKC digest object lacks its own path or names another path's PKC.
    HolderPath,
    /// Present targeting completed without a match or with unknown membership.
    Target(target::Decision),
    /// A present proxy restriction lacks complete authenticated participants.
    ProxyContext,
    /// Present proxy restriction did not establish a same-set match.
    Proxy(proxy::Decision),
    /// Original evidence does not establish status for this target/time/scheme.
    Status(Status),
}

/// Complete use outcome. Only Checked retains a usable attribute catalogue.
#[derive(Debug)]
pub enum Outcome<T> {
    /// All mechanism requirements completed relative to explicit trusted inputs.
    Checked(T),
    /// Completed negative or unproven requirement.
    Rejected(Failure),
}

/// Trusted group-membership query role, with the original target callback error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupRole {
    /// Current recipient's group membership for targetInformation.
    Target,
    /// Sender, recipient or original preceding proxy for `ProxyInfo`.
    Proxy(proxy::Subject),
}

/// All operation facts. No configuration discovery, clock, default status or
/// fallback holder method is inferred. Additional OCSP age/nonce/recipient and
/// responder-trust policy belongs to the caller before supplying evidence.
pub struct Context<'r, 'p, 'a, 'c, 'op, S: Evidence, W: Work> {
    /// Caller-authenticated holder, with any required checked certificate path.
    pub holder: Holder<'r, 'p, 'a, 'c>,
    /// Known identities of the current recipient, not AC-supplied claims.
    pub recipient: &'r [GeneralName<'a>],
    /// Complete authenticated proxy context when `ProxyInfo` is present.
    pub proxy: Option<Proxy<'r, 'a>>,
    /// Previously processed original status evidence or explicit `NoStatus`.
    /// The caller establishes trust/path/status of each signing authority,
    /// including the issuer/same-anchor facts required for indirect CRLs.
    pub status: &'r S,
    /// Exact evaluation label used by the status processor.
    pub now: Reading,
    /// Authenticated UTC coverage, including precise upward rounding facts.
    pub utc: &'op LeapTable<'op>,
    /// Current operation pays every new query, callback and retained result.
    pub execution: &'op W,
}

/// One original attribute's AA-control result. Excluded attributes must be
/// ignored for authorization, without suppressing unrelated permitted types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeUse {
    /// Original attribute ordinal, without sorting/deduplication or byte changes.
    pub index: usize,
    /// Complete applicable AA-control intersection for this actual type.
    pub permission: Permission,
}

/// Issuance and trust sources retained without cloning profile/path storage.
#[derive(Debug)]
pub enum Authority<'r, 'p, 'a, 'c> {
    /// The separately selected directly trusted AA is the authenticated AA.
    Direct(&'r Authenticated<'r, 'c, 'a>),
    /// Existing authenticated path and issuance, with its complete controls.
    Path(&'r Issued<'r, 'p, 'c, 'a>),
}
impl<'r, 'a, 'c> Authority<'r, '_, 'a, 'c> {
    fn facts(&self) -> &'r Authenticated<'r, 'c, 'a> {
        match self {
            Self::Direct(facts) => facts,
            Self::Path(issued) => issued.facts(),
        }
    }
    fn allows<W: Work>(
        &self,
        kind: Oid<'_>,
        controls: Option<&AaControls<'_>>,
        work: &W,
    ) -> Result<Permission> {
        match self {
            Self::Direct(facts) => {
                charge(
                    &work.execution_for(facts.certificate().parser),
                    1,
                    facts.certificate().element().span().start,
                )?;
                if let Some(control) = controls
                    && !control.allows(kind, work)?
                {
                    return Ok(Permission::Excluded {
                        certificate: 0,
                        source: control.element.span(),
                    });
                }
                Ok(Permission::Permitted)
            }
            Self::Path(issued) => issued.allows(kind, work),
        }
    }
}

/// Completed mechanism facts relative to the caller's authenticated context.
/// Original issuance/holder/status references remain required; only the new
/// eligibility catalogue is independently owned. This is not an application
/// authorization grant or proof that opaque callback/backend costs are bounded.
#[derive(Debug)]
pub struct Checked<'r, 'p, 'a, 'c, S> {
    authority: Authority<'r, 'p, 'a, 'c>,
    direct_controls: Option<AaControls<'a>>,
    holder: Holder<'r, 'p, 'a, 'c>,
    status: &'r S,
    now: Reading,
    target: Option<usize>,
    proxy: Option<usize>,
    attributes: OwnedVec<AttributeUse>,
}
impl<'r, 'p, 'a, 'c, S> Checked<'r, 'p, 'a, 'c, S> {
    /// Exact original AC whose complete use requirements produced this receipt.
    /// This does not authorize substitution of another equal-looking AC.
    #[must_use]
    pub fn certificate(&self) -> &'r crate::attribute_certificate::AttributeCertificate<'c> {
        self.authority.facts().certificate()
    }
    /// Original authenticated issuance and selected trust route.
    #[must_use]
    pub fn authority(&self) -> &Authority<'r, 'p, 'a, 'c> {
        &self.authority
    }
    /// Actual authenticated holder input, not another later certificate.
    #[must_use]
    pub fn holder(&self) -> &Holder<'r, 'p, 'a, 'c> {
        &self.holder
    }
    /// Original evidence whose association/time/status checks completed.
    #[must_use]
    pub fn status(&self) -> &'r S {
        self.status
    }
    /// Exact evaluation label, including subnanosecond precision.
    #[must_use]
    pub fn evaluated_at(&self) -> Reading {
        self.now
    }
    /// Original matching target ordinal; None means no targeting was written.
    #[must_use]
    pub fn target(&self) -> Option<usize> {
        self.target
    }
    /// Original common proxy-set ordinal; None means no `ProxyInfo` was written.
    #[must_use]
    pub fn proxy(&self) -> Option<usize> {
        self.proxy
    }
    /// Complete original attribute catalogue and per-type restriction results.
    /// Caller traversal/output must be admitted by its own operation.
    #[must_use]
    pub fn attributes(&self) -> &[AttributeUse] {
        &self.attributes
    }
    /// Apply the same authenticated controls to an actual caller-decrypted type.
    /// This does not prove decryption or `ACClearAttrs` issuer/serial binding.
    pub fn allows<W: Work>(&self, kind: Oid<'_>, work: &W) -> Result<Permission> {
        self.authority
            .allows(kind, self.direct_controls.as_ref(), work)
    }
}

/// Terminal source/current processing failure or original group callback cause.
#[derive(Debug)]
pub enum UseError<E> {
    /// Located source/query error, distinct from a completed unmet requirement.
    Processing(Error),
    /// Original membership callback cause and target range.
    Membership(target::CheckError<E>),
}
impl<E> From<Error> for UseError<E> {
    fn from(error: Error) -> Self {
        Self::Processing(error)
    }
}

/// Complete processing using an explicitly selected directly trusted AA.
/// Equal bytes from another untrusted object do not silently select trust.
pub fn direct<'r, 'p, 'a, 'c, S: Evidence, W: Work, E>(
    facts: &'r Authenticated<'r, 'c, 'a>,
    trusted_aa: &Certificate<'_>,
    context: Context<'r, 'p, 'a, 'c, '_, S, W>,
    membership: impl FnMut(
        GroupRole,
        &GeneralName<'c>,
        &Execution<'_>,
    ) -> core::result::Result<target::Membership, E>,
) -> core::result::Result<Outcome<Checked<'r, 'p, 'a, 'c, S>>, UseError<E>> {
    let work = facts.authority().execution_in(context.execution);
    charge(&work, 1, facts.authority().span().start)?;
    if !core::ptr::eq(facts.authority(), trusted_aa) {
        return Ok(Outcome::Rejected(Failure::AuthorityTrust));
    }
    // A directly trusted AA is a one-position restriction path: its control
    // is optional, but written exclusions still apply (RFC5755 §7.4).
    let controls = facts
        .authority()
        .tbs()
        .extensions()
        .get(controls::IDENTIFIER, &work)
        .map_err(Error::pkix)?
        .map(|extension| AaControls::read_extension(extension, &work))
        .transpose()?;
    check(Authority::Direct(facts), controls, context, membership)
}

/// Complete processing under one existing constrained, authenticated AA path.
/// Path and issuance signatures are not repeated by this composition.
pub fn issued<'r, 'p, 'a, 'c, S: Evidence, W: Work, E>(
    facts: &'r Issued<'r, 'p, 'c, 'a>,
    context: Context<'r, 'p, 'a, 'c, '_, S, W>,
    membership: impl FnMut(
        GroupRole,
        &GeneralName<'c>,
        &Execution<'_>,
    ) -> core::result::Result<target::Membership, E>,
) -> core::result::Result<Outcome<Checked<'r, 'p, 'a, 'c, S>>, UseError<E>> {
    check(Authority::Path(facts), None, context, membership)
}

fn holder_binding<W: Work>(
    ac: &crate::attribute_certificate::AttributeCertificate<'_>,
    holder: &Holder<'_, '_, '_, '_>,
    inside: impl Fn(Interval) -> bool,
    execution: &W,
) -> Result<Option<Failure>> {
    match holder {
        Holder::Certificate { path, method } => {
            if !inside(path.interval) {
                return Ok(Some(Failure::Interval));
            }
            if let Check::Rejected(reason) =
                ac.bind_holder(path.certificates[0], *method, execution)?
            {
                return Ok(Some(Failure::Holder(reason)));
            }
        }
        Holder::Object { binding, path } => {
            let original = binding.certificate();
            charge(
                &execution.execution_for(original.parser),
                1,
                original.element().span().start,
            )?;
            if !core::ptr::eq(binding.certificate(), ac) {
                return Ok(Some(Failure::HolderObject));
            }
            if let Some(path) = path
                && !inside(path.interval)
            {
                return Ok(Some(Failure::Interval));
            }
            match binding.object() {
                super::digest::Object::Certificate(certificate) => {
                    charge(
                        &certificate.execution_in(execution),
                        1,
                        certificate.span().start,
                    )?;
                    if let Some(path) = path {
                        let actual = path.certificates[0];
                        charge(&actual.execution_in(execution), 1, actual.span().start)?;
                    }
                    if !path.is_some_and(|path| core::ptr::eq(path.certificates[0], certificate)) {
                        return Ok(Some(Failure::HolderPath));
                    }
                }
                super::digest::Object::PublicKey(key) => {
                    charge(
                        &key.key().execution_in(execution),
                        1,
                        key.key().algorithm().offset(),
                    )?;
                    if let Some(path) = path {
                        let actual = path.facts.key;
                        charge(
                            &actual.key().execution_in(execution),
                            1,
                            actual.key().algorithm().offset(),
                        )?;
                        let parameters = match (actual.parameters(), key.parameters()) {
                            (None, None) => true,
                            (Some(left), Some(right)) => core::ptr::eq(left, right),
                            _ => false,
                        };
                        if !core::ptr::eq(actual.key().as_bytes(), key.key().as_bytes())
                            || !parameters
                        {
                            return Ok(Some(Failure::HolderPath));
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}

fn check<'r, 'p, 'a, 'c, S: Evidence, W: Work, E>(
    authority: Authority<'r, 'p, 'a, 'c>,
    direct_controls: Option<AaControls<'a>>,
    context: Context<'r, 'p, 'a, 'c, '_, S, W>,
    mut membership: impl FnMut(
        GroupRole,
        &GeneralName<'c>,
        &Execution<'_>,
    ) -> core::result::Result<target::Membership, E>,
) -> core::result::Result<Outcome<Checked<'r, 'p, 'a, 'c, S>>, UseError<E>> {
    let facts = authority.facts();
    let ac = facts.certificate();
    let execution = context.execution.execution_for(ac.parser);
    let at = ac.element().span().start;
    // LeapTable::shift performs three binary searches. As in the common
    // CRL update-window check, fund the actual table-dependent search bound
    // plus scalar arithmetic before validating/rounding the label.
    let searches = u64::from(usize::BITS - context.utc.transitions().len().leading_zeros() + 1);
    charge(&execution, 6 + 3 * searches + 64, at)?;
    let upper = match context.now.upper_bound(context.utc) {
        Ok(value) => value,
        Err(reason) => return Ok(Outcome::Rejected(Failure::Time(reason))),
    };
    let inside = |interval: Interval| {
        context.now.start() >= interval.from_instant() && upper <= interval.to_instant()
    };
    if !inside(facts.interval()) {
        return Ok(Outcome::Rejected(Failure::Interval));
    }
    if let Some(reason) = holder_binding(ac, &context.holder, inside, &execution)? {
        return Ok(Outcome::Rejected(reason));
    }
    let target = if let Some(targets) = facts.profile().targeting() {
        match targets
            .check(context.recipient, &execution, |name, work| {
                membership(GroupRole::Target, name, work)
            })
            .map_err(UseError::Membership)?
        {
            target::Decision::Matches { target } => Some(target),
            other => return Ok(Outcome::Rejected(Failure::Target(other))),
        }
    } else {
        None
    };
    let proxy = if let Some(proxies) = facts.profile().proxying() {
        let Some(proxy) = context.proxy else {
            return Ok(Outcome::Rejected(Failure::ProxyContext));
        };
        match proxies
            .check(
                proxy.sender,
                context.recipient,
                proxy.intermediates,
                &execution,
                |subject, name, work| membership(GroupRole::Proxy(subject), name, work),
            )
            .map_err(UseError::Membership)?
        {
            proxy::Decision::Matches { group } => Some(group),
            other => return Ok(Outcome::Rejected(Failure::Proxy(other))),
        }
    } else {
        None
    };
    let status = context
        .status
        .check(facts.profile(), context.now, &execution)?;
    if !matches!(status, Status::Good | Status::NoRevAvailable) {
        return Ok(Outcome::Rejected(Failure::Status(status)));
    }
    let mut attributes = execution.vector();
    let original = &ac.information().attributes;
    attributes
        .try_reserve(original.len())
        .map_err(|e| Error::resource(e, super::FIELD, at))?;
    for (index, attribute) in original.iter().enumerate() {
        charge(&execution, 1, attribute.element().span().start)?;
        let permission =
            authority.allows(attribute.kind(), direct_controls.as_ref(), &execution)?;
        attributes
            .try_push(AttributeUse { index, permission })
            .map_err(|e| Error::resource(e, super::FIELD, at))?;
    }
    Ok(Outcome::Checked(Checked {
        authority,
        direct_controls,
        holder: context.holder,
        status: context.status,
        now: context.now,
        target,
        proxy,
        attributes: attributes.into_owned(),
    }))
}
