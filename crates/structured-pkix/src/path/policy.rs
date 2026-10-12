//! Certification policies agreed along a path, using the RFC9618 policy graph.
//!
//! Each depth/OID has one node with all previous-depth parents. Policy mappings
//! change expected subject-domain names; settled output retains authority/user
//! OIDs. Qualifiers remain borrowed from their certificates rather than copied
//! into graph nodes. All graph, edge and scratch storage uses the operation account.

use crate::constraints::CertificateCount;
use structured_asn1::Oid;
use structured_asn1::memory::{MemoryError, OwnedVec};

mod graph;
#[cfg(test)]
use graph::Node;
pub(super) use graph::Processing;

const WORKED: u64 = super::cost::ENTRY;

fn identified(policy: Oid<'_>) -> u64 {
    policy.as_bytes().len() as u64 / super::cost::COMPARED
}

/// Policy processing exceeded a local bound or the shared resource account.
///
/// Attacker-controlled policies and mappings induce nodes, parent edges and
/// expected OIDs. A local refusal says processing did not finish; it is not a
/// policy rejection. Shared-resource errors retain their original location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Overflow {
    Limit,
    Resource(crate::Error),
}

impl From<crate::Error> for Overflow {
    fn from(error: crate::Error) -> Self {
        Self::Resource(error)
    }
}

fn resource(reason: MemoryError, offset: u64) -> Overflow {
    Overflow::Resource(crate::Error::resource(
        reason,
        "certificationPath.policies",
        offset,
    ))
}

/// What the caller decided before the path was walked (RFC 5280 6.1.1).
#[derive(Debug, Clone, Copy)]
pub(super) struct Initial {
    /// Whether a path must name a policy from the outset, rather than only
    /// where an authority along it demands one.
    pub(super) explicit_policy: bool,
    /// Whether policy mappings are honoured at all.
    pub(super) policy_mapping: bool,
    /// Whether the identifier standing for any policy is accepted at all.
    pub(super) any_policy: bool,
}

impl Default for Initial {
    /// What a validator with no policy of its own starts from: nothing is
    /// demanded, mappings are honoured, and the identifier standing for any
    /// policy is read as the certificate meant it.
    fn default() -> Self {
        Self {
            explicit_policy: false,
            policy_mapping: true,
            any_policy: true,
        }
    }
}

#[derive(Debug)]
pub(super) struct Settled<'a> {
    policies: OwnedVec<Oid<'a>>,
    satisfied: bool,
}

impl<'a> Settled<'a> {
    /// The policies every authority along the path agreed on.
    #[cfg(test)]
    pub(super) fn policies(&self) -> &[Oid<'a>] {
        &self.policies
    }

    /// Whether the path names a policy where one was demanded of it.
    pub(super) fn is_satisfied(&self) -> bool {
        self.satisfied
    }

    /// Transfers the final allocation and its existing charge to the report.
    pub(super) fn into_policies(self) -> OwnedVec<Oid<'a>> {
        self.policies
    }
}

/// Brings a counter forward, which is the only direction a certificate may
/// move one (RFC 5280 6.1.4 (i) and (j)).
fn narrow(counter: &mut u32, count: Option<CertificateCount>) {
    if let Some(count) = count.and_then(CertificateCount::certificates)
        && count < *counter
    {
        *counter = count;
    }
}

#[cfg(test)]
mod tests;
