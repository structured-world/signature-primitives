//! Accounted proxy-set checks (RFC5755 §7.2), separate from AC authentication.
//!
//! Sender/recipient/hop identities and the trustworthy complete forwarding path
//! come from the application protocol. This checks no signature or AA trust.

use super::target::{CheckError, Membership, TargetInformation};
use crate::{Error, Result};
use structured_asn1::memory::{Execution, Work};
use structured_asn1::{Element, Oid, Parser};
use structured_pkix::Extension;
use structured_pkix::general_name::GeneralName;

const FIELD: &str = "attributeCertificate.proxyInfo";
/// `id-pe-ac-proxying`, 1.3.6.1.5.5.7.1.10.
pub const IDENTIFIER: Oid<'static> = Oid::from_bytes(&[43, 6, 1, 5, 5, 7, 1, 10]);

/// Already-authenticated sender facts supplied by the caller, not this reader.
#[derive(Debug, Clone, Copy)]
pub enum Sender<'a, 'n> {
    /// Caller has established the sender matches the AC Holder.
    Holder,
    /// Sender is a proxy with these independently established identities.
    Proxy(&'n [GeneralName<'a>]),
}

/// Identity whose group membership the callback must establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// Authenticated immediate sender.
    Sender,
    /// Current verifier.
    Recipient,
    /// Earlier proxy on the trustworthy forwarding path, in supplied order.
    Intermediate(usize),
}

/// Complete proxy constraints, sharing the targeting decoder and original groups.
#[derive(Debug)]
pub struct ProxyInfo<'a> {
    parser: &'a Parser,
    targets: TargetInformation<'a>,
}

/// Completed proxy-set fact, never an application authorization verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Every required participant matched the same original proxy set.
    Matches {
        /// Original group ordinal, not an index into a merged union.
        group: usize,
    },
    /// Each group had a completed negative participant check.
    Differs,
    /// A group could qualify but at least one participant remained unknown.
    Unproven,
    /// `ProxyInfo` must be critical (RFC5755 §7.2).
    NonCritical,
    /// targetCert is forbidden anywhere, even after an otherwise matching set.
    ProhibitedTargetCertificate {
        /// Original flat target ordinal.
        target: usize,
    },
}

impl<'a> ProxyInfo<'a> {
    /// Reads the registered extension using the existing complete Target kernel.
    /// Late malformed or prohibited alternatives cannot disappear on early match.
    pub fn read<W: Work>(extension: &Extension<'a>, work: &W) -> Result<Self> {
        Ok(Self {
            parser: extension.parser(),
            targets: TargetInformation::read_as(extension, work, IDENTIFIER, FIELD)?,
        })
    }

    /// Original whole extension-value SEQUENCE.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.targets.element()
    }

    /// Original sets with flat target ranges. Proxy matching preserves these
    /// boundaries, unlike recipient-only targeting's union.
    #[must_use]
    pub fn groups(&self) -> &[super::target::Group<'a>] {
        self.targets.groups()
    }

    /// Original flat target catalogue; reading it is not a proxy check.
    #[must_use]
    pub fn targets(&self) -> &[super::target::Target<'a>] {
        self.targets.targets()
    }

    /// Original prohibited alternatives, retained for inspection.
    #[must_use]
    pub fn certificates(&self) -> &[super::target::TargetCertificate<'a>] {
        self.targets.certificates()
    }

    /// Written extension criticality, not inferred from its OID.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.targets.is_critical()
    }

    /// Checks RFC5755 §7.2's common-set rule for all supplied participants.
    /// The protocol must supply a trustworthy COMPLETE preceding-hop list;
    /// omitting a hop here cannot prove that it was allowed. Holder bypasses
    /// only the sender membership check, never recipient or earlier proxies.
    /// Unknown membership differs from a completed negative; processing and
    /// callback errors remain terminal, with their original causes.
    /// The membership callback must admit its own data-dependent work through
    /// the supplied execution. Its external side effects cannot be rolled back
    /// if a later participant or set refuses.
    pub fn check<W: Work, E>(
        &self,
        sender: Sender<'_, '_>,
        recipient: &[GeneralName<'_>],
        intermediates: &[&[GeneralName<'_>]],
        work: &W,
        mut membership: impl FnMut(
            Subject,
            &GeneralName<'a>,
            &Execution<'_>,
        ) -> core::result::Result<Membership, E>,
    ) -> core::result::Result<Decision, CheckError<E>> {
        let execution = work.execution_for(self.parser);
        let pay = |at| {
            execution
                .charge_work(1)
                .map_err(|e| CheckError::Processing(Error::resource(e, FIELD, at)))
        };
        pay(self.targets.element().span().start)?;
        if !self.targets.is_critical() {
            return Ok(Decision::NonCritical);
        }
        if let Some(entry) = self.targets.certificates().first() {
            return Ok(Decision::ProhibitedTargetCertificate {
                target: entry.target,
            });
        }
        let mut unknown = false;
        // RFC5755 §7.2 requires all proxies on the path to be members of
        // the SAME set. Never use TargetInformation::check's union here.
        // https://www.rfc-editor.org/rfc/rfc5755#section-7.2
        for (index, group) in self.targets.groups().iter().enumerate() {
            pay(group.element.span().start)?;
            let mut undecided = false;
            match self.matches(
                index,
                Subject::Recipient,
                recipient,
                &execution,
                &mut membership,
            )? {
                Membership::NotMember => continue,
                Membership::Unknown => undecided = true,
                Membership::Member => {}
            }
            if let Sender::Proxy(names) = sender {
                match self.matches(index, Subject::Sender, names, &execution, &mut membership)? {
                    Membership::NotMember => continue,
                    Membership::Unknown => undecided = true,
                    Membership::Member => {}
                }
            }
            let mut excluded = false;
            for (ordinal, names) in intermediates.iter().enumerate() {
                pay(group.element.span().start)?;
                match self.matches(
                    index,
                    Subject::Intermediate(ordinal),
                    names,
                    &execution,
                    &mut membership,
                )? {
                    Membership::NotMember => {
                        excluded = true;
                        break;
                    }
                    Membership::Unknown => undecided = true,
                    Membership::Member => {}
                }
            }
            if excluded {
                continue;
            }
            if !undecided {
                return Ok(Decision::Matches { group: index });
            }
            unknown = true;
        }
        Ok(if unknown {
            Decision::Unproven
        } else {
            Decision::Differs
        })
    }

    fn matches<E>(
        &self,
        group: usize,
        subject: Subject,
        names: &[GeneralName<'_>],
        execution: &Execution<'_>,
        membership: &mut impl FnMut(
            Subject,
            &GeneralName<'a>,
            &Execution<'_>,
        ) -> core::result::Result<Membership, E>,
    ) -> core::result::Result<Membership, CheckError<E>> {
        let mut unknown = false;
        for target in &self.targets.targets()[self.targets.groups()[group].targets.clone()] {
            match super::target::matches_target(
                target,
                names,
                execution,
                FIELD,
                &mut |name, work| membership(subject, name, work),
            )? {
                Membership::Member => return Ok(Membership::Member),
                Membership::Unknown => unknown = true,
                Membership::NotMember => {}
            }
        }
        Ok(if unknown {
            Membership::Unknown
        } else {
            Membership::NotMember
        })
    }
}
