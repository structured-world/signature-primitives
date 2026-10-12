//! Which policies a path was issued under, worked out along the path.
//!
//! A certificate policy is what an authority says a certificate was issued
//! for, and it means something only when every authority above the
//! certificate said the same thing, or said which of its own policies
//! stands for it. Working that out is a tree that grows down the path
//! (RFC 5280 6.1), and the answer at the end is the set of policies the
//! authorities agreed on, which is what tells a qualified certificate from
//! one that merely chains to the same root.
//!
//! Two things are deliberately not kept here. Policy qualifiers are text for
//! a person to read and a report reads them from the certificate that holds
//! them, so keeping a copy per node would be the same text stored as many
//! times as the tree is wide. And a node is never removed from the array it
//! lives in: it is marked as no longer part of the tree, because indices are
//! how a node names its parent and moving one would rewrite the others.

use super::Meter;
use crate::constraints::{CertificateCount, InhibitAnyPolicy, PolicyConstraints};
use crate::oid;
use crate::policy::{CertificatePolicies, PolicyMappings};
use structured_asn1::Oid;
use structured_asn1::memory::{Memory, MemoryError, OwnedMap, OwnedVec};

#[derive(PartialEq, Eq, Hash)]
struct Carried<'a>(usize, Oid<'a>);

impl structured_asn1::memory::HashWork for Carried<'_> {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        structured_asn1::memory::HashWork::hash_work(&self.1)?
            .checked_add(1)
            .ok_or(MemoryError::WorkExceeded)
    }
}

/// What looking at one entry of a list somebody else wrote costs: one node
/// of the tree, one policy a certificate names, one mapping it declares.
///
/// The same amount for each, because each is one lookup in an index built
/// for the purpose, and because what is being bounded is the length of a
/// list a document decides rather than the shape of any one entry.
const WORKED: u64 = super::cost::ENTRY;

/// What hashing or comparing one identifier reads, on top of looking at the
/// entry that carries it.
///
/// An index answers by hashing every byte of the identifier it is given, and
/// a comparison reads every byte of both sides. How many bytes an identifier
/// holds is the document's to decide, and a certificate may name identifiers
/// that add no node and reach no ceiling: the flat charge for the entry does
/// not cover reading them, and without this a set of very long identifiers
/// can be hashed over and over while the bound barely moves.
fn identified(policy: Oid<'_>) -> u64 {
    policy.as_bytes().len() as u64 / super::cost::COMPARED
}

/// The tree grew past what the caller allowed it to hold.
///
/// A certificate set somebody else controls decides how many policies each
/// of its certificates names, and the tree is as wide as their product. This
/// says the search declined to hold it, which is not a statement about the
/// path.
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

fn group<'a, T>(
    index: &mut OwnedMap<Oid<'a>, OwnedVec<T>>,
    key: Oid<'a>,
    value: T,
    execution: &Memory,
    offset: u64,
) -> Result<(), Overflow> {
    let fail = |reason| resource(reason, offset);
    if index.get(&key, execution).map_err(fail)?.is_none() {
        index.try_insert(key, execution.vector()).map_err(fail)?;
    }
    index
        .get_mut(&key, execution)
        .map_err(fail)?
        .expect("the admitted group")
        .try_push(value)
        .map_err(fail)
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

/// One node: a policy that is still agreed on at some depth, and what the
/// certificate below it may name to carry the agreement further down.
#[derive(Debug)]
struct Node<'a> {
    policy: Oid<'a>,
    /// What the certificate below may name to carry this policy further
    /// down, or empty for the usual case where that is the policy itself.
    ///
    /// Empty rather than a list holding one identifier, because a node is
    /// made per policy per certificate and a hostile certificate set decides
    /// how many that is: a list allocated for every one of them would be one
    /// allocation per node for a value that is already in the node.
    expected: OwnedVec<Oid<'a>>,
    parent: Option<usize>,
    depth: u32,
    children: u32,
    live: bool,
}

impl<'a> Node<'a> {
    /// How many identifiers it would accept.
    fn expects_count(&self) -> usize {
        self.expected.len().max(1)
    }

    /// One of them.
    fn expects_at(&self, at: usize) -> Oid<'a> {
        self.expected.get(at).copied().unwrap_or(self.policy)
    }
}

/// The policy state of one path, as it stands after some number of
/// certificates.
#[derive(Debug)]
pub(super) struct Processing<'a> {
    /// The nodes, or `None` where the tree was emptied, which is what the
    /// specification calls a null tree and is not the same as an empty one.
    nodes: Option<OwnedVec<Node<'a>>>,
    execution: Memory,
    offset: u64,
    /// How deep the tree is now, which is how many certificates have been
    /// processed.
    depth: u32,
    /// After how many more certificates a path must name a policy.
    explicit_policy: u32,
    /// After how many more certificates mappings stop being honoured.
    policy_mapping: u32,
    /// After how many more certificates the identifier standing for any
    /// policy stops being accepted.
    inhibit_any_policy: u32,
    /// How many identifiers the expectation sets hold, metered alongside the
    /// nodes because a mapping's expectations are held for as long as the
    /// tree is.
    expectations: usize,
    /// How much the tree and its expectations may hold between them.
    ceiling: usize,
}

impl<'a> Processing<'a> {
    /// The state before the first certificate: one node standing for any
    /// policy, and the three counters set past the end of the path unless
    /// the caller asked for them to bind from the start (RFC 5280 6.1.2).
    pub(super) fn new(
        length: u32,
        initial: Initial,
        ceiling: usize,
        execution: &Memory,
        offset: u64,
    ) -> Result<Self, Overflow> {
        // The node every path starts from is a node, and it is held for as
        // long as the working out is: a caller who allowed the tree nothing
        // has allowed it that too. Building it anyway would spend a slot the
        // bound does not have and answer as though the bound had been kept.
        if ceiling == 0 {
            return Err(Overflow::Limit);
        }

        // Past the end of the path is where a counter that never binds
        // sits: the path decrements it once per certificate and it is still
        // positive at the end.
        let never = length
            .checked_add(1)
            .ok_or_else(|| resource(MemoryError::CapacityOverflow, offset))?;
        let mut nodes = execution.vector();
        nodes
            .try_reserve_exact(1)
            .map_err(|reason| resource(reason, offset))?;
        nodes
            .try_push(Node {
                policy: oid::ANY_POLICY,
                expected: execution.vector(),
                parent: None,
                depth: 0,
                children: 0,
                live: true,
            })
            .map_err(|reason| resource(reason, offset))?;
        Ok(Self {
            nodes: Some(nodes),
            execution: execution.clone(),
            offset,
            depth: 0,
            explicit_policy: if initial.explicit_policy { 0 } else { never },
            policy_mapping: if initial.policy_mapping { never } else { 0 },
            inhibit_any_policy: if initial.any_policy { never } else { 0 },
            expectations: 0,
            ceiling,
        })
    }

    /// How many nodes were made, which is what the search charges the tree
    /// against its budget by.
    pub(super) fn nodes(&self) -> usize {
        self.nodes.as_ref().map_or(0, |nodes| nodes.len())
    }

    /// What one certificate says about policies (RFC 5280 6.1.3 (d) to (f)),
    /// answering whether the path still satisfies what is demanded of it.
    pub(super) fn present(
        &mut self,
        policies: Option<&CertificatePolicies<'a>>,
        self_issued: bool,
        last: bool,
        meter: &mut impl Meter,
    ) -> Result<bool, Overflow> {
        self.depth += 1;
        match policies {
            Some(policies) => self.grow(policies, self_issued, last, meter)?,
            // (e) A certificate that names no policy ends the agreement:
            // there is no policy every authority named.
            None => self.nodes = None,
        }
        // (f) A path that names no policy is a path only where nobody
        // demanded one.
        Ok(self.explicit_policy > 0 || self.nodes.is_some())
    }

    /// Grows the tree by one certificate's policies (RFC 5280 6.1.3 (d)).
    fn grow(
        &mut self,
        policies: &CertificatePolicies<'a>,
        self_issued: bool,
        last: bool,
        meter: &mut impl Meter,
    ) -> Result<(), Overflow> {
        let Some(nodes) = self.nodes.as_mut() else {
            return Ok(());
        };
        let depth = self.depth;
        let parents = depth - 1;
        let ceiling = self.ceiling;
        // What the expectation sets are holding while this certificate is
        // read. Nothing here adds to them or releases them: growing the
        // tree gives every new node an empty set, so the count is the same
        // at the end as at the start and is read once.
        let held = self.expectations;

        // Which nodes above expect which policy, indexed once. A certificate
        // may name any number of policies and the tree may hold any number
        // of nodes, and scanning every node for every policy is their
        // product: an extension that parses can then buy hundreds of
        // millions of comparisons while adding no node and reaching no
        // ceiling. Indexing makes it their sum.
        let fail = |reason| resource(reason, self.offset);
        let mut expecting: OwnedMap<Oid<'a>, OwnedVec<usize>> = self.execution.map();
        let mut anywhere = self.execution.vector();
        for at in 0..nodes.len() {
            if !meter.spend(WORKED)? {
                return Err(Overflow::Limit);
            }
            if !live_at(nodes, at, parents) {
                continue;
            }
            if nodes[at].policy == oid::ANY_POLICY {
                anywhere.try_push(at).map_err(fail)?;
            }
            for which in 0..nodes[at].expects_count() {
                let expected = nodes[at].expects_at(which);
                if !meter.spend(WORKED + identified(expected))? {
                    return Err(Overflow::Limit);
                }
                group(&mut expecting, expected, at, &self.execution, self.offset)?;
            }
        }

        // (1) Each named policy continues the agreement where the
        // certificate above expected it, and otherwise where the
        // certificate above accepted anything.
        let mut has_any = false;
        for named in policies.policies() {
            // Charged for looking at it, before it is hashed and looked up.
            // A certificate names as many policies as the encoding allows,
            // and one that matches nothing above adds no node: without this
            // the only thing counting is the ceiling on what the tree holds,
            // which such a list never reaches. The bound then says how large
            // the working out may be while saying nothing about how long
            // reading the list may take.
            if !meter.spend(WORKED)? {
                return Err(Overflow::Limit);
            }
            let policy = named.policy();
            if policy == oid::ANY_POLICY {
                has_any = true;
                continue;
            }
            // Charged before the index is asked, which hashes every byte of
            // it, and before every node it lands under is given a copy.
            if !meter.spend(identified(policy))? {
                return Err(Overflow::Limit);
            }
            match expecting.get(&policy, &self.execution).map_err(fail)? {
                Some(parents) => {
                    for at in parents.iter().copied() {
                        push(
                            nodes,
                            at,
                            policy,
                            self.execution.vector(),
                            depth,
                            (held, ceiling, self.offset),
                        )?;
                    }
                }
                None => {
                    for at in anywhere.iter().copied() {
                        push(
                            nodes,
                            at,
                            policy,
                            self.execution.vector(),
                            depth,
                            (held, ceiling, self.offset),
                        )?;
                    }
                }
            }
        }

        // (2) The identifier standing for any policy carries every policy
        // the certificate above expected, where it is still accepted. A
        // self-issued certificate that is not the last one is a key
        // rollover rather than a step down the chain of authority, so it
        // carries them whatever the counter says.
        if has_any && (self.inhibit_any_policy > 0 || (self_issued && !last)) {
            carry_any(
                nodes,
                depth,
                (held, ceiling, self.offset),
                &self.execution,
                meter,
            )?;
        }

        // (3) A node the certificate carried nothing down from is a policy
        // the agreement no longer holds, and so is an ancestor left with
        // nothing below it.
        prune(nodes, parents, meter)?;
        if !nodes[0].live {
            self.nodes = None;
        }
        Ok(())
    }

    /// What one certificate that is not the last says about policies below
    /// it (RFC 5280 6.1.4 (b) and (h) to (j)).
    pub(super) fn carry(
        &mut self,
        mappings: Option<&PolicyMappings<'a>>,
        constraints: Option<PolicyConstraints>,
        inhibit: Option<InhibitAnyPolicy>,
        self_issued: bool,
        meter: &mut impl Meter,
    ) -> Result<(), Overflow> {
        if let Some(mappings) = mappings {
            self.map(mappings, meter)?;
        }

        // (h) Every certificate issued to somebody else is a step down the
        // chain of authority, and each counter counts those steps. One
        // issued to the issuer's own name is a key rollover and is not a
        // step.
        if !self_issued {
            self.explicit_policy = self.explicit_policy.saturating_sub(1);
            self.policy_mapping = self.policy_mapping.saturating_sub(1);
            self.inhibit_any_policy = self.inhibit_any_policy.saturating_sub(1);
        }

        // (i) and (j) An authority may bring any of the three forward, and
        // may only ever bring it forward: a certificate cannot give a path
        // below it more room than it was given.
        if let Some(constraints) = constraints {
            narrow(
                &mut self.explicit_policy,
                constraints.require_explicit_policy(),
            );
            narrow(
                &mut self.policy_mapping,
                constraints.inhibit_policy_mapping(),
            );
        }
        if let Some(inhibit) = inhibit {
            narrow(&mut self.inhibit_any_policy, Some(inhibit.skip()));
        }
        Ok(())
    }

    /// Applies one certificate's mappings (RFC 5280 6.1.4 (b)).
    fn map(
        &mut self,
        mappings: &PolicyMappings<'a>,
        meter: &mut impl Meter,
    ) -> Result<(), Overflow> {
        // Nothing to map onto. A certificate above named no policy and ended
        // the agreement, and nothing below revives it, so this list will
        // never be read: metering it would refuse the path for room the
        // working out was never going to use, and call that truncation.
        if self.nodes.is_none() {
            return Ok(());
        }

        // (2) Mappings are no longer honoured, so the policy an issuer would
        // have mapped stops being agreed on here and nothing is carried down
        // under another name. Only the issuer names are read, so nothing is
        // expected afterwards and nothing is held against the ceiling:
        // charging the subject policies would measure room the working out
        // was never going to use, and a certificate naming enough mappings
        // would then discard a path whose other branches were never in
        // question.
        //
        // The issuers are gathered once and the nodes read once. One pass
        // per issuer would be their product, which a certificate that merely
        // parses can make as large as the tree the caller allowed.
        if self.policy_mapping == 0 {
            return self.unmap(mappings, meter);
        }

        self.remap(mappings, meter)
    }

    /// Applies the mappings of a certificate whose mappings are not honoured
    /// (RFC 5280 6.1.4 (b) (2)).
    fn unmap(
        &mut self,
        mappings: &PolicyMappings<'a>,
        meter: &mut impl Meter,
    ) -> Result<(), Overflow> {
        {
            let depth = self.depth;
            let Some(nodes) = self.nodes.as_mut() else {
                return Ok(());
            };
            // The nodes are indexed and the mappings read against them,
            // rather than the other way round. A certificate names as many
            // mappings as it likes, and what is kept here is bounded by
            // what the caller allowed the tree to hold: gathering the
            // issuers first would let an extension that merely parses buy
            // memory no bound of the caller's ever sees.
            let fail = |reason| resource(reason, self.offset);
            let mut standing: OwnedMap<Oid<'a>, OwnedVec<usize>> = self.execution.map();
            for at in 0..nodes.len() {
                if !meter.spend(WORKED)? {
                    return Err(Overflow::Limit);
                }
                if live_at(nodes, at, depth) {
                    if !meter.spend(identified(nodes[at].policy))? {
                        return Err(Overflow::Limit);
                    }
                    group(
                        &mut standing,
                        nodes[at].policy,
                        at,
                        &self.execution,
                        self.offset,
                    )?;
                }
            }

            // What goes is each node the issuer names and nothing else:
            // "delete each node of depth i in the valid_policy_tree where
            // ID-P is the valid_policy" (RFC 5280 6.1.4 (b) (2)). Removing
            // a node already takes any ancestor it was the last thing below,
            // and there is nothing to sweep at this depth: the certificate
            // below has not been read yet, so every node here is childless
            // and a sweep would take the policies nobody mapped with it.
            for mapping in mappings.mappings() {
                if !meter.spend(WORKED)? {
                    return Err(Overflow::Limit);
                }
                let issuer = mapping.issuer_domain();
                if issuer == oid::ANY_POLICY || mapping.subject_domain() == oid::ANY_POLICY {
                    continue;
                }
                // Taken out rather than read, so each issuer is answered
                // once. A certificate may name one issuer policy in as many
                // mappings as it likes, and the first of them has already
                // taken every node that policy stands at: reading the same
                // indices again for each repeat is the mapping count times
                // the tree's, which is work the ceiling on what the tree
                // holds does not bound.
                if !meter.spend(identified(issuer))? {
                    return Err(Overflow::Limit);
                }
                let Some(named) = standing.remove(&issuer, &self.execution).map_err(fail)? else {
                    continue;
                };
                for at in named {
                    if !meter.spend(WORKED)? {
                        return Err(Overflow::Limit);
                    }
                    kill(nodes, at, meter)?;
                }
            }
            if !nodes[0].live {
                self.nodes = None;
            }
        }
        Ok(())
    }

    /// Applies the mappings of a certificate whose mappings are honoured
    /// (RFC 5280 6.1.4 (b) (1)).
    fn remap(
        &mut self,
        mappings: &PolicyMappings<'a>,
        meter: &mut impl Meter,
    ) -> Result<(), Overflow> {
        // What the grouping itself will hold, metered before any of it is
        // built. Expectation sets live for as long as the tree does, so they
        // are bounded with it: an extension may name any number of subject
        // policies for one issuer, and a list that parses must not buy
        // memory the caller's bound never sees. The length of the list is
        // the ceiling on the entries it can produce.
        //
        // This pays for the grouping alone, and only while it is held: it is
        // dropped when the mappings have been applied, and the charge is
        // released with it. What the nodes keep is charged where each copy
        // is made, and what a copy replaces is released there, so the meter
        // counts what the tree holds rather than everything it ever held.
        // Counting for ever makes it drift above the truth, until a path
        // that fits is refused for room it is not using.
        let entries = mappings.mappings().len();
        debug_assert!(self.nodes() <= self.ceiling);
        if self.expectations > self.ceiling - self.nodes()
            || entries > self.ceiling - self.nodes() - self.expectations
        {
            return Err(Overflow::Limit);
        }
        self.expectations += entries;

        // Each issuer's subject policies, gathered in one pass and kept in
        // the order the certificate wrote them. Collecting them again per
        // mapping would read the whole list once for every entry in it,
        // which is work proportional to the square of a count the
        // certificate chooses.
        let fail = |reason| resource(reason, self.offset);
        let mut order = self.execution.vector();
        let mut grouped: OwnedMap<Oid<'a>, OwnedVec<Oid<'a>>> = self.execution.map();
        for mapping in mappings.mappings() {
            // Charged for looking at it, as everywhere a list a document
            // decides the length of is read. What this branch holds is
            // bounded by the ceiling above, but reading is not holding.
            if !meter.spend(WORKED)? {
                return Err(Overflow::Limit);
            }
            let issuer = mapping.issuer_domain();
            // The identifier standing for any policy is not a domain that
            // can be mapped (RFC 5280 4.2.1.5), and the reader of the
            // extension does not refuse it, so a mapping naming it is
            // ignored rather than honoured.
            if issuer == oid::ANY_POLICY || mapping.subject_domain() == oid::ANY_POLICY {
                continue;
            }
            let subject = mapping.subject_domain();
            if !meter.spend(identified(issuer) + identified(subject))? {
                return Err(Overflow::Limit);
            }
            if grouped
                .get(&issuer, &self.execution)
                .map_err(fail)?
                .is_none()
            {
                order.try_push(issuer).map_err(fail)?;
            }
            group(&mut grouped, issuer, subject, &self.execution, self.offset)?;
        }

        let Some(nodes) = self.nodes.as_mut() else {
            return Ok(());
        };
        let depth = self.depth;
        let ceiling = self.ceiling;

        // Which nodes stand at which policy, indexed once. A certificate
        // names as many issuers as it likes and the tree holds as many
        // nodes as the caller allowed: scanning the nodes for every issuer
        // is their product, and comparing two identifiers reads them, so an
        // extension that merely parses buys the reading of a set of long
        // identifiers over and over. Indexing makes it their sum.
        let Level { standing, anywhere } =
            level(nodes, depth, &self.execution, self.offset, meter)?;

        for issuer in order {
            if !meter.spend(identified(issuer))? {
                return Err(Overflow::Limit);
            }
            let subjects = grouped
                .remove(&issuer, &self.execution)
                .map_err(fail)?
                .expect("an issuer just grouped");

            // (1) The policy carries on below under the names the issuer
            // maps it to, replacing what the node expected rather than
            // adding to it.
            let mut matched = false;
            if let Some(indices) = standing.get(&issuer, &self.execution).map_err(fail)? {
                for at in indices.iter().copied() {
                    if !meter.spend(WORKED)? {
                        return Err(Overflow::Limit);
                    }
                    if live_at(nodes, at, depth) {
                        // Every copy is charged where it is made, and what it
                        // replaces is released there. One policy can stand under
                        // as many branches as the tree is wide, so paying for
                        // the list once while handing it to each of them would
                        // hold the tree's width for the price of one; and a
                        // vector that has been overwritten is no longer held.
                        debug_assert!(self.expectations >= nodes[at].expected.len());
                        let retained = self.expectations - nodes[at].expected.len();
                        if retained > ceiling - nodes.len()
                            || subjects.len() > ceiling - nodes.len() - retained
                        {
                            return Err(Overflow::Limit);
                        }
                        let copy = subjects.try_copy().map_err(fail)?;
                        nodes[at].expected = copy;
                        self.expectations = retained + subjects.len();
                        matched = true;
                    }
                }
            }
            if matched {
                continue;
            }
            for at in anywhere.iter().copied() {
                if live_at(nodes, at, depth) {
                    // A new node keeps its own copy, so it is charged too.
                    if self.expectations > ceiling - nodes.len()
                        || subjects.len() > ceiling - nodes.len() - self.expectations
                    {
                        return Err(Overflow::Limit);
                    }
                    let expectations = self.expectations + subjects.len();
                    push(
                        nodes,
                        at,
                        issuer,
                        subjects,
                        depth,
                        (expectations, ceiling, self.offset),
                    )?;
                    self.expectations = expectations;
                    break;
                }
            }
        }

        // The grouping has been applied and is going out of scope, so what
        // it was holding is released.
        debug_assert!(self.expectations >= entries);
        self.expectations -= entries;
        Ok(())
    }

    /// The policies the authorities along the path agreed on, once the last
    /// certificate has been processed (RFC 5280 6.1.5).
    ///
    /// `wanted` is the set the caller was asking about, empty meaning any:
    /// a report that asks about every policy gets every policy that was
    /// agreed on, and one asking about a particular policy gets it or
    /// nothing.
    pub(super) fn settle(
        mut self,
        constraints: Option<PolicyConstraints>,
        wanted: &'a [Oid<'a>],
        meter: &mut impl Meter,
    ) -> Result<Settled<'a>, Overflow> {
        // (a) The last certificate spends the counter, whoever it was issued
        // to: "If explicit_policy is not 0, decrement explicit_policy by 1"
        // (RFC 5280 6.1.5 (a)), with no condition on it. The exemption for a
        // certificate issued to its own issuer belongs to the step that
        // walks the path, where the same decrement is written "If
        // certificate i is not self-issued" (6.1.4 (h)). Carrying it here
        // too leaves the counter one above where the path left it, and a
        // target naming no policy is then accepted under an authority that
        // demanded one.
        self.explicit_policy = self.explicit_policy.saturating_sub(1);
        // (b) An authority that demands a policy from the certificate it
        // issues demands one of this path.
        if let Some(constraints) = constraints
            && constraints
                .require_explicit_policy()
                .is_some_and(CertificateCount::is_zero)
        {
            self.explicit_policy = 0;
        }

        // (g) What the caller asked about, met with what was agreed.
        let policies = self.intersect(wanted, meter)?;
        Ok(Settled {
            satisfied: self.explicit_policy > 0 || !policies.is_empty(),
            policies,
        })
    }

    /// The agreed policies at the end of the path, narrowed to the ones the
    /// caller asked about (RFC 5280 6.1.5 (g)).
    fn intersect(
        &mut self,
        wanted: &'a [Oid<'a>],
        meter: &mut impl Meter,
    ) -> Result<OwnedVec<Oid<'a>>, Overflow> {
        let depth = self.depth;
        let ceiling = self.ceiling;
        // As in growing the tree: putting the caller's own policies back
        // under the node standing for any policy adds nodes and no
        // expectations, so what the sets hold is read once.
        let held = self.expectations;
        // Read before anything is removed: narrowing the tree can take the
        // node standing for any policy away, and with it the parent the
        // caller's own policies have to be put back under.
        let terminal_any = self.any_policy_at(depth, meter)?;
        let anywhere = match (self.nodes.as_ref(), terminal_any) {
            (Some(nodes), Some(at)) => nodes[at].parent,
            _ => None,
        };
        let Some(nodes) = self.nodes.as_mut() else {
            return Ok(self.execution.vector());
        };

        // A caller asking about every policy is answered with the tree as
        // it stands, the identifier standing for any policy included: it is
        // what the authorities agreed, and reading it as a list of every
        // policy that exists is something no certificate said.
        //
        // Naming that identifier is the other way of writing the same
        // request, and the profile says so twice: it is what a caller "not
        // concerned about certificate policy" is told to send
        // (RFC 5280 6.1.1 (c)), and "if the valid_policy_tree is not NULL
        // and the user-initial-policy-set is any-policy, the intersection is
        // the entire valid_policy_tree" (6.1.5 (g) (ii)). Read as a set of
        // one instead, the narrowing below looks for a node already naming
        // it, finds the very node that stands for it, and then kills that
        // node without putting anything back, so a path naming exactly what
        // was asked for comes back naming nothing.
        let fail = |reason| resource(reason, self.offset);
        let mut requested: OwnedMap<Oid<'a>, ()> = self.execution.map();
        for policy in wanted {
            if !meter.spend(WORKED)? {
                return Err(Overflow::Limit);
            }
            requested.try_insert(*policy, ()).map_err(fail)?;
        }
        let unrestricted = wanted.is_empty()
            || requested
                .get(&oid::ANY_POLICY, &self.execution)
                .map_err(fail)?
                .is_some();
        if !unrestricted {
            // (1) and (2) What the caller's set is compared against is the
            // nodes whose parent stands for any policy, and not the nodes at
            // the end of the path. A node further down is what an authority
            // mapped its parent to: it carries the parent's meaning under
            // another name, so comparing the name at the end of a mapped
            // branch would answer a caller who enabled mappings that its own
            // policy was never met.
            for at in 0..nodes.len() {
                if !meter.spend(WORKED)? {
                    return Err(Overflow::Limit);
                }
                let Some(parent) = nodes[at].parent else {
                    continue;
                };
                if !nodes[at].live || nodes[parent].policy != oid::ANY_POLICY {
                    continue;
                }
                let policy = nodes[at].policy;
                if policy != oid::ANY_POLICY
                    && requested
                        .get(&policy, &self.execution)
                        .map_err(fail)?
                        .is_none()
                {
                    cut(nodes, at, meter)?;
                }
            }

            // (3) A policy the path carried only under the identifier
            // standing for any policy was agreed on, and is named here under
            // each name the caller asked about; then the node that stood for
            // all of them goes, having said what it had to say.
            if let (Some(parent), Some(any)) = (anywhere, terminal_any) {
                let mut standing: OwnedMap<Oid<'a>, ()> = self.execution.map();
                for node in nodes.iter() {
                    if !meter.spend(WORKED)? {
                        return Err(Overflow::Limit);
                    }
                    if node.live
                        && node
                            .parent
                            .is_some_and(|above| nodes[above].policy == oid::ANY_POLICY)
                    {
                        standing.try_insert(node.policy, ()).map_err(fail)?;
                    }
                }
                for policy in wanted {
                    if !meter.spend(WORKED)? {
                        return Err(Overflow::Limit);
                    }
                    let policy = *policy;
                    if standing.try_insert(policy, ()).map_err(fail)?.is_some() {
                        continue;
                    }
                    push(
                        nodes,
                        parent,
                        policy,
                        self.execution.vector(),
                        depth,
                        (held, ceiling, self.offset),
                    )?;
                }
                kill(nodes, any, meter)?;
            }
        }

        // (4) And what is left with nothing below it is no longer part of
        // the tree.
        prune(nodes, depth.saturating_sub(1), meter)?;
        if !nodes[0].live {
            self.nodes = None;
            return Ok(self.execution.vector());
        }

        terminal_policies(nodes, depth, &self.execution, self.offset, meter)
    }

    /// The node at the end of the path that stands for any policy, where
    /// there is one.
    fn any_policy_at(&self, depth: u32, meter: &mut impl Meter) -> Result<Option<usize>, Overflow> {
        if let Some(nodes) = self.nodes.as_ref() {
            for (at, node) in nodes.iter().enumerate() {
                if !meter.spend(WORKED)? {
                    return Err(Overflow::Limit);
                }
                if node.live && node.depth == depth && node.policy == oid::ANY_POLICY {
                    return Ok(Some(at));
                }
            }
        }
        Ok(None)
    }
}

fn carry_any<'a>(
    nodes: &mut OwnedVec<Node<'a>>,
    depth: u32,
    room: (usize, usize, u64),
    execution: &Memory,
    meter: &mut impl Meter,
) -> Result<(), Overflow> {
    let (held, ceiling, offset) = room;
    let parents = depth - 1;
    let fail = |reason| resource(reason, offset);
    // What each node already carries down, indexed once. A node
    // expects as many policies as a mapping left it, and the named
    // pass above has already given it a child for the ones this
    // certificate names: finding that out by scanning the tree for
    // every expectation is their product, and each step of it
    // compares two identifiers, which reads them. The index is kept
    // up to date as children are added, so an expectation named
    // twice still adds one node.
    let mut carried: OwnedMap<Carried<'a>, ()> = execution.map();
    for node in nodes.iter() {
        if !meter.spend(WORKED)? {
            return Err(Overflow::Limit);
        }
        if let Some(parent) = node.parent
            && node.live
        {
            if !meter.spend(identified(node.policy))? {
                return Err(Overflow::Limit);
            }
            carried
                .try_insert(Carried(parent, node.policy), ())
                .map_err(fail)?;
        }
    }

    for at in 0..nodes.len() {
        if !meter.spend(WORKED)? {
            return Err(Overflow::Limit);
        }
        if !live_at(nodes, at, parents) {
            continue;
        }
        for expected in 0..nodes[at].expects_count() {
            let policy = nodes[at].expects_at(expected);
            if !meter.spend(WORKED + identified(policy))? {
                return Err(Overflow::Limit);
            }
            if carried
                .try_insert(Carried(at, policy), ())
                .map_err(fail)?
                .is_some()
            {
                continue;
            }
            push(
                nodes,
                at,
                policy,
                execution.vector(),
                depth,
                (held, ceiling, offset),
            )?;
        }
    }

    Ok(())
}

fn terminal_policies<'a>(
    nodes: &[Node<'a>],
    depth: u32,
    execution: &Memory,
    offset: u64,
    meter: &mut impl Meter,
) -> Result<OwnedVec<Oid<'a>>, Overflow> {
    // One order for every set, rather than the one the certificates
    // happened to write. What a path was issued under is a set, and two
    // settled paths are compared by it: kept in the certificates' order,
    // that comparison has to search one set for each member of the
    // other, which is the square of a count the caller's ceiling allows
    // and which the search repeats against every path it is holding.
    // Ordered once, the comparison is a walk down both, and the same
    // ordering is what removes the repeats without searching either.
    let fail = |reason| resource(reason, offset);
    let mut policies = execution.vector();
    for node in nodes {
        if !meter.spend(WORKED)? {
            return Err(Overflow::Limit);
        }
        if node.live && node.depth == depth {
            policies.try_push(node.policy).map_err(fail)?;
        }
    }
    //
    // What that ordering reads is charged before it is read. An
    // identifier is compared byte for byte, two that share a long
    // prefix are read to where they part, and how long they are and how
    // many there are is decided by the certificates: the ordering is
    // about as many comparisons as the count times its logarithm, and a
    // route that settles again pays for it again. Charged by the count
    // alone, one set of long identifiers buys the whole of that while
    // the bound barely moves.
    execution.charge_work(policies.len() as u64).map_err(fail)?;
    let bytes = policies
        .iter()
        .map(|policy| policy.as_bytes().len() as u64)
        .try_fold(0u64, |sum, bytes| {
            sum.checked_add(bytes).ok_or(MemoryError::WorkExceeded)
        })
        .map_err(fail)?;
    let rounds = u64::from(policies.len().max(1).ilog2() + 1);
    let work = rounds
        .checked_mul(bytes)
        .ok_or_else(|| fail(MemoryError::WorkExceeded))?;
    if !meter.spend(work / super::cost::COMPARED)? {
        return Err(Overflow::Limit);
    }
    policies
        .try_sort_unstable_by(|left, right| {
            execution.charge_work(left.as_bytes().len().max(right.as_bytes().len()) as u64)?;
            Ok::<_, MemoryError>(left.as_bytes().cmp(right.as_bytes()))
        })
        .map_err(|error| fail(error.into()))?;
    let mut unique = 0;
    for at in 0..policies.len() {
        if unique > 0 {
            execution
                .charge_work(
                    policies[at]
                        .as_bytes()
                        .len()
                        .max(policies[unique - 1].as_bytes().len()) as u64,
                )
                .map_err(fail)?;
            if policies[at] == policies[unique - 1] {
                continue;
            }
        }
        execution
            .charge_work(core::mem::size_of::<Oid<'a>>() as u64)
            .map_err(fail)?;
        policies[unique] = policies[at];
        unique += 1;
    }
    while policies.len() > unique {
        execution.charge_work(1).map_err(fail)?;
        policies.pop();
    }
    Ok(policies)
}

struct Level<'a> {
    standing: OwnedMap<Oid<'a>, OwnedVec<usize>>,
    anywhere: OwnedVec<usize>,
}

fn level<'a>(
    nodes: &[Node<'a>],
    depth: u32,
    execution: &Memory,
    offset: u64,
    meter: &mut impl Meter,
) -> Result<Level<'a>, Overflow> {
    let fail = |reason| resource(reason, offset);
    let mut standing: OwnedMap<Oid<'a>, OwnedVec<usize>> = execution.map();
    let mut anywhere = execution.vector();
    for at in 0..nodes.len() {
        if !meter.spend(WORKED)? {
            return Err(Overflow::Limit);
        }
        if !live_at(nodes, at, depth) {
            continue;
        }
        if nodes[at].policy == oid::ANY_POLICY {
            anywhere.try_push(at).map_err(fail)?;
        }
        if !meter.spend(identified(nodes[at].policy))? {
            return Err(Overflow::Limit);
        }
        group(&mut standing, nodes[at].policy, at, execution, offset)?;
    }
    Ok(Level { standing, anywhere })
}

/// What the path was issued under, once every certificate has spoken.
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

/// Whether a node is part of the tree and sits at one depth.
fn live_at(nodes: &[Node<'_>], at: usize, depth: u32) -> bool {
    nodes[at].live && nodes[at].depth == depth
}

/// Adds a node below another one, refusing where the tree and what it is
/// holding are already as large as the caller allowed.
///
/// `held` is how many identifiers the expectation sets hold at this moment.
/// The ceiling is what the two may reach between them, so counting the nodes
/// alone would let a mapping's leftovers be spent twice: once when the
/// mapping was applied and again by every node grown afterwards, and the
/// path would settle as though the bound had been kept.
fn push<'a>(
    nodes: &mut OwnedVec<Node<'a>>,
    parent: usize,
    policy: Oid<'a>,
    expected: OwnedVec<Oid<'a>>,
    depth: u32,
    room: (usize, usize, u64),
) -> Result<(), Overflow> {
    let (held, ceiling, offset) = room;
    if held >= ceiling || nodes.len() >= ceiling - held {
        return Err(Overflow::Limit);
    }
    let children = nodes[parent]
        .children
        .checked_add(1)
        .ok_or_else(|| resource(MemoryError::CapacityOverflow, offset))?;
    nodes
        .try_push(Node {
            policy,
            expected,
            parent: Some(parent),
            depth,
            children: 0,
            live: true,
        })
        .map_err(|reason| resource(reason, offset))?;
    nodes[parent].children = children;
    Ok(())
}

/// Removes a node and, where that was the last thing below its parent, the
/// parent too, all the way up.
///
/// Upwards and iteratively: a node names its parent, so the walk is a chain
/// as long as the path and never a stack that grows with the tree.
fn kill(nodes: &mut [Node<'_>], at: usize, meter: &mut impl Meter) -> Result<(), Overflow> {
    let mut at = at;
    loop {
        if !meter.spend(WORKED)? {
            return Err(Overflow::Limit);
        }
        if !nodes[at].live {
            return Ok(());
        }
        nodes[at].live = false;
        let Some(parent) = nodes[at].parent else {
            return Ok(());
        };
        nodes[parent].children -= 1;
        if nodes[parent].children > 0 {
            return Ok(());
        }
        at = parent;
    }
}

/// Removes a node, everything below it, and any ancestor it was the last
/// thing below.
///
/// This is what deleting a node means where the specification says "delete
/// this node and all its children" (RFC 5280 6.1.5 (g) (iii) 2): a policy
/// the caller did not ask about takes the branch that carried it with it,
/// and leaving the branch behind would answer with a policy at the end of a
/// path whose agreement had just been removed.
///
/// Downwards by one forward sweep, because a parent is always written before
/// the children that name it; upwards by the same chain the removal below
/// walks. Neither recurses.
fn cut(nodes: &mut [Node<'_>], at: usize, meter: &mut impl Meter) -> Result<(), Overflow> {
    if !meter.spend(WORKED)? {
        return Err(Overflow::Limit);
    }
    if !nodes[at].live {
        return Ok(());
    }
    nodes[at].live = false;
    for below in at + 1..nodes.len() {
        if !meter.spend(WORKED)? {
            return Err(Overflow::Limit);
        }
        let orphaned = nodes[below].parent.is_some_and(|above| !nodes[above].live);
        if nodes[below].live && orphaned {
            nodes[below].live = false;
        }
    }

    let mut at = at;
    loop {
        if !meter.spend(WORKED)? {
            return Err(Overflow::Limit);
        }
        let Some(parent) = nodes[at].parent else {
            return Ok(());
        };
        nodes[parent].children -= 1;
        if nodes[parent].children > 0 || !nodes[parent].live {
            return Ok(());
        }
        nodes[parent].live = false;
        at = parent;
    }
}

/// Removes every node at or above `depth` that has nothing below it.
fn prune(nodes: &mut [Node<'_>], depth: u32, meter: &mut impl Meter) -> Result<(), Overflow> {
    for at in 0..nodes.len() {
        if !meter.spend(WORKED)? {
            return Err(Overflow::Limit);
        }
        if nodes[at].live && nodes[at].depth == depth && nodes[at].children == 0 {
            kill(nodes, at, meter)?;
        }
    }
    Ok(())
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
