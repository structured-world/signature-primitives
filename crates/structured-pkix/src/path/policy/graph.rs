//! RFC9618 policy graph. Qualifiers stay in certificates, not graph nodes.

use super::{Initial, Overflow, Settled, WORKED, identified, narrow, resource};
use crate::constraints::{CertificateCount, InhibitAnyPolicy, PolicyConstraints};
use crate::oid;
use crate::path::Meter;
use crate::policy::{CertificatePolicies, PolicyMappings};
use structured_asn1::Oid;
use structured_asn1::memory::{Memory, MemoryError, OwnedMap, OwnedVec, Work};

/// The usual single edge/index is inline; fan-in retains an accounted tail.
#[derive(Debug)]
struct Indices<E: Work = Memory> {
    first: Option<usize>,
    rest: OwnedVec<usize, E>,
}

impl<E: Work> Indices<E> {
    fn new(execution: &E) -> Self {
        Self {
            first: None,
            rest: execution.vector(),
        }
    }

    fn one(at: usize, execution: &E) -> Self {
        Self {
            first: Some(at),
            rest: execution.vector(),
        }
    }

    fn len(&self) -> usize {
        if self.first.is_some() {
            self.rest.len() + 1
        } else {
            0
        }
    }

    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.first.into_iter().chain(self.rest.iter().copied())
    }

    fn push(&mut self, at: usize) -> Result<(), MemoryError> {
        if self.first.is_none() {
            self.first = Some(at);
            Ok(())
        } else {
            self.rest.try_push(at)
        }
    }
}

#[derive(Debug)]
pub(super) struct Node<'a, E: Work = Memory> {
    pub(super) policy: Oid<'a>,
    pub(super) expected: OwnedVec<Oid<'a>, E>,
    parents: Indices<E>,
    pub(super) depth: u32,
    children: usize,
    pub(super) live: bool,
    /// Intrusive work list for iterative ancestor pruning; no scratch allocation.
    pending: Option<usize>,
}

#[cfg(test)]
impl<E: Work> Node<'_, E> {
    pub(super) fn parent_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.parents.iter()
    }
}

#[derive(Debug)]
pub(in crate::path) struct Processing<'a, E: Work = Memory> {
    pub(super) nodes: Option<OwnedVec<Node<'a, E>, E>>,
    execution: E,
    offset: u64,
    depth: u32,
    frontier: Indices<E>,
    explicit_policy: u32,
    policy_mapping: u32,
    inhibit_any_policy: u32,
    expectations: usize,
    edges: usize,
    ceiling: usize,
}

fn admit(meter: &mut impl Meter, entries: usize, offset: u64) -> Result<(), Overflow> {
    let count = u64::try_from(entries).map_err(|_| resource(MemoryError::WorkExceeded, offset))?;
    let work = count
        .checked_mul(WORKED)
        .ok_or_else(|| resource(MemoryError::WorkExceeded, offset))?;
    if !meter.spend(work)? {
        return Err(Overflow::Limit);
    }
    Ok(())
}

impl<'a, E: Work> Processing<'a, E> {
    pub(in crate::path) fn new(
        length: u32,
        initial: Initial,
        ceiling: usize,
        execution: &E,
        offset: u64,
    ) -> Result<Self, Overflow> {
        if ceiling == 0 {
            return Err(Overflow::Limit);
        }
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
                parents: Indices::new(execution),
                depth: 0,
                children: 0,
                live: true,
                pending: None,
            })
            .map_err(|reason| resource(reason, offset))?;
        Ok(Self {
            nodes: Some(nodes),
            execution: execution.clone(),
            offset,
            depth: 0,
            frontier: Indices::one(0, execution),
            explicit_policy: if initial.explicit_policy { 0 } else { never },
            policy_mapping: if initial.policy_mapping { never } else { 0 },
            inhibit_any_policy: if initial.any_policy { never } else { 0 },
            expectations: 0,
            edges: 0,
            ceiling,
        })
    }

    pub(in crate::path) fn nodes(&self) -> usize {
        self.nodes.as_ref().map_or(0, |nodes| nodes.len())
    }

    fn room(&self, additional: usize) -> Result<(), Overflow> {
        let used = self
            .nodes()
            .checked_add(self.expectations)
            .and_then(|used| used.checked_add(self.edges))
            .ok_or_else(|| resource(MemoryError::CapacityOverflow, self.offset))?;
        if used > self.ceiling || additional > self.ceiling - used {
            return Err(Overflow::Limit);
        }
        Ok(())
    }

    fn push(
        &mut self,
        policy: Oid<'a>,
        parents: Indices<E>,
        expected: OwnedVec<Oid<'a>, E>,
        meter: &mut impl Meter,
    ) -> Result<usize, Overflow> {
        let edges = parents.len();
        let extra = edges
            .checked_add(expected.len())
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| resource(MemoryError::CapacityOverflow, self.offset))?;
        self.room(extra)?;
        admit(meter, edges + 1, self.offset)?;
        let nodes = self.nodes.as_mut().expect("a live graph");
        for at in parents.iter() {
            debug_assert!(nodes[at].live && nodes[at].depth + 1 == self.depth);
            if nodes[at].children == usize::MAX {
                return Err(resource(MemoryError::CapacityOverflow, self.offset));
            }
        }
        let at = nodes.len();
        nodes
            .try_push(Node {
                policy,
                expected,
                parents,
                depth: self.depth,
                children: 0,
                live: true,
                pending: None,
            })
            .map_err(|reason| resource(reason, self.offset))?;
        let (ancestors, appended) = nodes.split_at_mut(at);
        for parent in appended[0].parents.iter() {
            ancestors[parent].children += 1;
        }
        self.edges += edges;
        self.expectations += nodes[at].expected.len();
        Ok(at)
    }

    pub(in crate::path) fn present(
        &mut self,
        policies: Option<&CertificatePolicies<'a>>,
        self_issued: bool,
        last: bool,
        meter: &mut impl Meter,
    ) -> Result<bool, Overflow> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| resource(MemoryError::CapacityOverflow, self.offset))?;
        match policies {
            Some(named) => self.grow(named, self_issued, last, meter)?,
            None => self.clear(),
        }
        Ok(self.explicit_policy > 0 || self.nodes.is_some())
    }

    fn clear(&mut self) {
        self.nodes = None;
        self.frontier = Indices::new(&self.execution);
        self.expectations = 0;
        self.edges = 0;
    }

    fn grow(
        &mut self,
        policies: &CertificatePolicies<'a>,
        self_issued: bool,
        last: bool,
        meter: &mut impl Meter,
    ) -> Result<(), Overflow> {
        if self.nodes.is_none() {
            return Ok(());
        }
        let offset = self.offset;
        let fail = |reason| resource(reason, offset);
        let mut expecting: OwnedMap<Oid<'a>, Indices<E>, E> = self.execution.map();
        let mut any = None;
        admit(meter, self.frontier.len(), self.offset)?;
        for at in self.frontier.iter() {
            let node = &self.nodes.as_ref().expect("a live graph")[at];
            if !node.live {
                continue;
            }
            if node.policy == oid::ANY_POLICY {
                any = Some(at);
            }
            let count = node.expected.len().max(1);
            admit(meter, count, self.offset)?;
            for which in 0..count {
                let expected = if node.expected.is_empty() {
                    node.policy
                } else {
                    node.expected[which]
                };
                if !meter.spend(identified(expected))? {
                    return Err(Overflow::Limit);
                }
                if let Some(group) = expecting
                    .get_mut(&expected, &self.execution)
                    .map_err(fail)?
                {
                    group.push(at).map_err(fail)?;
                } else {
                    expecting
                        .try_insert(expected, Indices::one(at, &self.execution))
                        .map_err(fail)?;
                }
            }
        }

        let mut next = Indices::new(&self.execution);
        let mut standing: OwnedMap<Oid<'a>, (), E> = self.execution.map();
        let mut has_any = false;
        for named in policies.policies() {
            admit(meter, 1, self.offset)?;
            let policy = named.policy();
            if policy == oid::ANY_POLICY {
                has_any = true;
                continue;
            }
            if standing.try_insert(policy, ()).map_err(fail)?.is_some() {
                continue;
            }
            let parents = expecting.remove(&policy, &self.execution).map_err(fail)?;
            let parents = match parents {
                Some(parents) => parents,
                None => match any {
                    Some(at) => Indices::one(at, &self.execution),
                    None => continue,
                },
            };
            let at = self.push(policy, parents, self.execution.vector(), meter)?;
            next.push(at).map_err(fail)?;
        }

        // RFC9618 §5.3(2): every missing expected policy gets one child with
        // all matching parents. Exact matches above consumed their groups.
        if has_any && (self.inhibit_any_policy > 0 || (self_issued && !last)) {
            let mut missing = self.execution.vector();
            for (policy, _) in expecting.try_iter(&self.execution).map_err(fail)? {
                admit(meter, 1, self.offset)?;
                missing.try_push(*policy).map_err(fail)?;
            }
            for policy in missing {
                admit(meter, 1, self.offset)?;
                let parents = expecting
                    .remove(&policy, &self.execution)
                    .map_err(fail)?
                    .expect("a recorded group");
                let at = self.push(policy, parents, self.execution.vector(), meter)?;
                next.push(at).map_err(fail)?;
            }
        }
        let previous = core::mem::replace(&mut self.frontier, next);
        admit(meter, previous.len(), self.offset)?;
        for at in previous.iter() {
            if self.nodes.as_ref().expect("a live graph")[at].live
                && self.nodes.as_ref().expect("a live graph")[at].children == 0
            {
                self.kill(at, meter)?;
            }
            // Previous expectations are no longer queried. Drop their actual
            // allocation now; clearing alone would retain its capacity charge.
            let node = &mut self.nodes.as_mut().expect("a live graph")[at];
            self.expectations -= node.expected.len();
            node.expected = self.execution.vector();
        }
        if !self.nodes.as_ref().expect("a graph before nulling")[0].live {
            self.clear();
        }
        Ok(())
    }

    /// Every dead ancestor enters this intrusive stack once. Shared descendants
    /// keep another parent's child count positive, so pruning cannot cut them.
    fn kill(&mut self, at: usize, meter: &mut impl Meter) -> Result<(), Overflow> {
        let nodes = self.nodes.as_mut().expect("a graph to prune");
        admit(meter, 1, self.offset)?;
        if !nodes[at].live {
            return Ok(());
        }
        debug_assert_eq!(nodes[at].children, 0);
        nodes[at].live = false;
        nodes[at].pending = None;
        let mut pending = Some(at);
        while let Some(at) = pending {
            admit(meter, nodes[at].parents.len() + 1, self.offset)?;
            pending = nodes[at].pending;
            let parents = core::mem::replace(&mut nodes[at].parents, Indices::new(&self.execution));
            self.edges -= parents.len();
            self.expectations -= nodes[at].expected.len();
            nodes[at].expected = self.execution.vector();
            for parent in parents.iter() {
                debug_assert!(nodes[parent].children > 0);
                nodes[parent].children -= 1;
                if nodes[parent].live && nodes[parent].children == 0 {
                    nodes[parent].live = false;
                    nodes[parent].pending = pending;
                    pending = Some(parent);
                }
            }
        }
        Ok(())
    }

    pub(in crate::path) fn carry(
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
        if !self_issued {
            if self.explicit_policy > 0 {
                self.explicit_policy -= 1;
            }
            if self.policy_mapping > 0 {
                self.policy_mapping -= 1;
            }
            if self.inhibit_any_policy > 0 {
                self.inhibit_any_policy -= 1;
            }
        }
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

    fn map(
        &mut self,
        mappings: &PolicyMappings<'a>,
        meter: &mut impl Meter,
    ) -> Result<(), Overflow> {
        if self.nodes.is_none() {
            return Ok(());
        }
        let offset = self.offset;
        let fail = |reason| resource(reason, offset);
        let mut standing: OwnedMap<Oid<'a>, usize, E> = self.execution.map();
        let mut any = None;
        admit(meter, self.frontier.len(), self.offset)?;
        for at in self.frontier.iter() {
            let node = &self.nodes.as_ref().expect("a live graph")[at];
            if !node.live {
                continue;
            }
            standing.try_insert(node.policy, at).map_err(fail)?;
            if node.policy == oid::ANY_POLICY {
                any = Some(at);
            }
        }
        if self.policy_mapping == 0 {
            for mapping in mappings.mappings() {
                admit(meter, 1, self.offset)?;
                if let Some(at) = standing
                    .remove(&mapping.issuer_domain(), &self.execution)
                    .map_err(fail)?
                {
                    self.kill(at, meter)?;
                }
            }
            if !self.nodes.as_ref().expect("a graph before nulling")[0].live {
                self.clear();
            }
            return Ok(());
        }

        // Group once and move each set into the unique issuer node. The public
        // PolicyMappings decoder has already rejected anyPolicy and deduplicated pairs.
        // Grouping is accounted scratch. Only expectations or nodes actually
        // attached below consume the retained graph ceiling.
        let mut grouped: OwnedMap<Oid<'a>, OwnedVec<Oid<'a>, E>, E> = self.execution.map();
        let mut order = self.execution.vector();
        for mapping in mappings.mappings() {
            admit(meter, 1, self.offset)?;
            let issuer = mapping.issuer_domain();
            if let Some(group) = grouped.get_mut(&issuer, &self.execution).map_err(fail)? {
                group.try_push(mapping.subject_domain()).map_err(fail)?;
            } else {
                let mut group = self.execution.vector();
                group.try_push(mapping.subject_domain()).map_err(fail)?;
                grouped.try_insert(issuer, group).map_err(fail)?;
                order.try_push(issuer).map_err(fail)?;
            }
        }
        for issuer in order {
            admit(meter, 1, self.offset)?;
            let subjects = grouped
                .remove(&issuer, &self.execution)
                .map_err(fail)?
                .expect("a recorded issuer");
            if let Some(at) = standing
                .get(&issuer, &self.execution)
                .map_err(fail)?
                .copied()
            {
                let node = &mut self.nodes.as_mut().expect("a live graph")[at];
                self.expectations -= node.expected.len();
                node.expected = self.execution.vector();
                self.room(subjects.len())?;
                self.expectations += subjects.len();
                self.nodes.as_mut().expect("a live graph")[at].expected = subjects;
            } else if let Some(any) = any {
                let previous = self.nodes.as_ref().expect("a live graph")[any]
                    .parents
                    .first
                    .expect("non-root anyPolicy has one parent");
                // RFC9618 §5.4(2): synthesis is under previous-depth anyPolicy.
                let at = self.push(
                    issuer,
                    Indices::one(previous, &self.execution),
                    subjects,
                    meter,
                )?;
                self.frontier.push(at).map_err(fail)?;
            }
        }
        Ok(())
    }

    pub(in crate::path) fn settle(
        mut self,
        constraints: Option<PolicyConstraints>,
        wanted: &'a [Oid<'a>],
        meter: &mut impl Meter,
    ) -> Result<Settled<'a>, Overflow> {
        if self.explicit_policy > 0 {
            self.explicit_policy -= 1;
        }
        if let Some(constraints) = constraints
            && constraints
                .require_explicit_policy()
                .is_some_and(CertificateCount::is_zero)
        {
            self.explicit_policy = 0;
        }
        let fail = |reason| resource(reason, self.offset);
        let mut output = self.execution.vector();
        if let Some(nodes) = &self.nodes {
            let mut authority: OwnedMap<Oid<'a>, (), E> = self.execution.map();
            for node in nodes {
                admit(meter, 1, self.offset)?;
                if !node.live || node.parents.len() != 1 {
                    continue;
                }
                let parent = node.parents.first.expect("a sole parent");
                // RFC9618 §5.5(4): surviving authority roots, plus terminal anyPolicy.
                if (node.policy != oid::ANY_POLICY && nodes[parent].policy == oid::ANY_POLICY)
                    || (node.policy == oid::ANY_POLICY && node.depth == self.depth)
                {
                    authority.try_insert(node.policy, ()).map_err(fail)?;
                }
            }
            let mut requested: OwnedMap<Oid<'a>, (), E> = self.execution.map();
            for policy in wanted {
                admit(meter, 1, self.offset)?;
                requested.try_insert(*policy, ()).map_err(fail)?;
            }
            let unrestricted = wanted.is_empty()
                || requested
                    .get(&oid::ANY_POLICY, &self.execution)
                    .map_err(fail)?
                    .is_some();
            if unrestricted {
                for (policy, ()) in authority.try_iter(&self.execution).map_err(fail)? {
                    admit(meter, 1, self.offset)?;
                    output.try_push(*policy).map_err(fail)?;
                }
            } else {
                let any = authority
                    .get(&oid::ANY_POLICY, &self.execution)
                    .map_err(fail)?
                    .is_some();
                for (policy, ()) in requested.try_iter(&self.execution).map_err(fail)? {
                    admit(meter, 1, self.offset)?;
                    if any
                        || authority
                            .get(policy, &self.execution)
                            .map_err(fail)?
                            .is_some()
                    {
                        output.try_push(*policy).map_err(fail)?;
                    }
                }
            }
        }
        output
            .try_sort_unstable_by(|left, right| {
                let bytes = left.as_bytes().len().min(right.as_bytes().len()) as u64;
                if !meter.spend(bytes / super::super::cost::COMPARED)? {
                    return Err(Overflow::Limit);
                }
                self.execution.charge_work(bytes).map_err(fail)?;
                Ok::<_, Overflow>(left.as_bytes().cmp(right.as_bytes()))
            })
            .map_err(|error| match error {
                structured_asn1::memory::SortError::Comparison(error) => error,
                structured_asn1::memory::SortError::Resource(reason) => fail(reason),
            })?;
        Ok(Settled {
            satisfied: self.explicit_policy > 0 || !output.is_empty(),
            policies: output.into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Certificate;
    use crate::fixtures::{CertificateParts, extension, oid as encoded_oid, seq};
    use alloc::vec::Vec;
    use structured_asn1::Parser;

    const GOLD: Oid<'static> = Oid::from_bytes(&[0x2a, 0x03, 0x04, 0x01]);
    const SILVER: Oid<'static> = Oid::from_bytes(&[0x2a, 0x03, 0x04, 0x02]);
    const BRONZE: Oid<'static> = Oid::from_bytes(&[0x2a, 0x03, 0x04, 0x03]);

    fn certificate(named: &[Oid<'static>], maps: &[(Oid<'static>, Oid<'static>)]) -> Vec<u8> {
        let named = seq(&named
            .iter()
            .map(|oid| seq(&[encoded_oid(*oid)]))
            .collect::<Vec<_>>());
        let mut extensions = alloc::vec![extension(oid::CERTIFICATE_POLICIES, false, &named)];
        if !maps.is_empty() {
            let maps = seq(&maps
                .iter()
                .map(|(issuer, subject)| seq(&[encoded_oid(*issuer), encoded_oid(*subject)]))
                .collect::<Vec<_>>());
            extensions.push(extension(oid::POLICY_MAPPINGS, true, &maps));
        }
        CertificateParts {
            extensions: Some(seq(&extensions)),
            ..CertificateParts::default()
        }
        .build()
    }

    fn process<'a>(certificates: &[Certificate<'a>], execution: &Memory) -> Processing<'a> {
        let initial = Initial {
            explicit_policy: false,
            policy_mapping: true,
            any_policy: true,
        };
        let mut graph = Processing::new(
            u32::try_from(certificates.len()).unwrap(),
            initial,
            1024,
            execution,
            719,
        )
        .unwrap();
        for (position, certificate) in certificates.iter().enumerate() {
            let extensions = certificate.tbs().extensions();
            let named = extensions.certificate_policies(execution).unwrap().unwrap();
            let last = position + 1 == certificates.len();
            assert!(graph.present(Some(&named), false, last, &mut ()).unwrap());
            if !last {
                let mappings = extensions.policy_mappings(execution).unwrap();
                graph
                    .carry(mappings.as_ref(), None, None, false, &mut ())
                    .unwrap();
            }
        }
        graph
    }

    #[test]
    fn unattached_mappings_do_not_spend_the_retained_graph_ceiling() {
        // With no issuer frontier node and no anyPolicy node, a mapping
        // retains nothing. Input/grouping scratch belongs to Memory, while
        // the local ceiling exactly holds root + Gold + its single edge;
        // the unchanged expected OID is the node's inline policy itself.
        let der = certificate(&[GOLD], &[(BRONZE, SILVER)]);
        let parser = Parser::der(crate::fixtures::memory());
        let certificate = Certificate::read(&parser, &der, 0).unwrap();
        let execution = crate::fixtures::memory();
        let extensions = certificate.tbs().extensions();
        let named = extensions
            .certificate_policies(&execution)
            .unwrap()
            .unwrap();
        let maps = extensions.policy_mappings(&execution).unwrap().unwrap();
        let mut graph = Processing::new(
            1,
            Initial {
                explicit_policy: false,
                policy_mapping: true,
                any_policy: true,
            },
            3,
            &execution,
            719,
        )
        .unwrap();
        assert!(graph.present(Some(&named), false, false, &mut ()).unwrap());
        assert_eq!(graph.nodes(), 2);
        graph
            .carry(Some(&maps), None, None, false, &mut ())
            .unwrap();
        assert_eq!(graph.nodes(), 2);
        assert_eq!(
            graph.settle(None, &[], &mut ()).unwrap().policies(),
            &[GOLD]
        );
        drop(named);
        drop(maps);
        assert_eq!(execution.used(), 0);
    }

    #[test]
    fn chained_mappings_return_the_authority_oid() {
        // RFC9618 §5.5: output is authority Gold, although the leaf calls it Bronze.
        let steps = [
            certificate(&[GOLD], &[(GOLD, SILVER)]),
            certificate(&[SILVER], &[(SILVER, BRONZE)]),
            certificate(&[BRONZE], &[]),
        ];
        let parser = Parser::der(crate::fixtures::memory());
        let read = steps
            .iter()
            .map(|der| Certificate::read(&parser, der, 0).unwrap())
            .collect::<Vec<_>>();
        let execution = crate::fixtures::memory();
        let graph = process(&read, &execution);
        let settled = graph.settle(None, &[GOLD], &mut ()).unwrap();
        assert!(settled.is_satisfied());
        assert_eq!(settled.policies(), &[GOLD]);
    }

    #[test]
    fn converging_mappings_share_one_child_and_preserve_both_authorities() {
        // Fan-in must retain two parents, not duplicate the same depth/OID node.
        let steps = [
            certificate(&[GOLD, SILVER], &[(GOLD, BRONZE), (SILVER, BRONZE)]),
            certificate(&[BRONZE], &[]),
        ];
        let parser = Parser::der(crate::fixtures::memory());
        let read = steps
            .iter()
            .map(|der| Certificate::read(&parser, der, 0).unwrap())
            .collect::<Vec<_>>();
        let execution = crate::fixtures::memory();
        let graph = process(&read, &execution);
        let nodes = graph.nodes.as_ref().unwrap();
        assert_eq!(graph.nodes(), 4);
        let leaf = nodes
            .iter()
            .find(|node| node.live && node.depth == 2)
            .unwrap();
        assert_eq!(leaf.policy, BRONZE);
        assert_eq!(leaf.parents.len(), 2);
        for parent in leaf.parents.iter() {
            assert_eq!(nodes[parent].depth, 1);
        }
        let settled = graph.settle(None, &[], &mut ()).unwrap();
        assert_eq!(settled.policies(), &[GOLD, SILVER]);
    }

    #[test]
    fn synthesized_mapping_uses_the_previous_any_policy_parent() {
        // RFC9618 §5.4 synthesis must never introduce a same-depth edge.
        let steps = [
            certificate(&[oid::ANY_POLICY], &[]),
            certificate(&[oid::ANY_POLICY], &[(GOLD, SILVER)]),
            certificate(&[SILVER], &[]),
        ];
        let parser = Parser::der(crate::fixtures::memory());
        let read = steps
            .iter()
            .map(|der| Certificate::read(&parser, der, 0).unwrap())
            .collect::<Vec<_>>();
        let execution = crate::fixtures::memory();
        let graph = process(&read, &execution);
        let nodes = graph.nodes.as_ref().unwrap();
        let synthesized = nodes
            .iter()
            .find(|node| node.live && node.policy == GOLD)
            .unwrap();
        assert_eq!(synthesized.parents.len(), 1);
        let parent = synthesized.parents.first.unwrap();
        assert_eq!(nodes[parent].depth + 1, synthesized.depth);
        assert_eq!(nodes[parent].policy, oid::ANY_POLICY);
        assert_eq!(
            graph.settle(None, &[GOLD], &mut ()).unwrap().policies(),
            &[GOLD]
        );
    }

    #[test]
    fn owned_output_retains_storage_after_the_graph_is_consumed() {
        // Scratch graph/index allocations drop, while the output's capacity remains charged.
        let steps = [certificate(&[GOLD], &[])];
        let parser = Parser::der(crate::fixtures::memory());
        let read = steps
            .iter()
            .map(|der| Certificate::read(&parser, der, 0).unwrap())
            .collect::<Vec<_>>();
        let execution = crate::fixtures::memory();
        let graph = process(&read, &execution);
        assert!(execution.used() > 0);
        let output = graph.settle(None, &[], &mut ()).unwrap().into_policies();
        assert_eq!(&*output, &[GOLD]);
        assert_eq!(
            execution.used(),
            output.capacity() * core::mem::size_of::<Oid<'_>>()
        );
        drop(output);
        assert_eq!(execution.used(), 0);
    }

    #[test]
    fn settlement_resource_refusal_keeps_the_processing_location() {
        // Exhaust the same operation domain immediately before settlement.
        // A resource error must retain its location and release all scratch.
        use alloc::sync::Arc;
        use structured_asn1::memory::MemoryAccount;
        const WORK: usize = 1_000_000;
        let steps = [certificate(&[GOLD], &[])];
        let parser = Parser::der(crate::fixtures::memory());
        let read = steps
            .iter()
            .map(|der| Certificate::read(&parser, der, 0).unwrap())
            .collect::<Vec<_>>();
        // Hash tables have independent seeds, so setup work cannot be
        // calibrated with a different graph's collision comparisons.
        let execution = Memory::new(Arc::new(MemoryAccount::new(1024 * 1024, WORK)));
        let graph = process(&read, &execution);
        execution
            .charge_work(u64::try_from(WORK - execution.work_used()).unwrap())
            .unwrap();
        assert_eq!(execution.work_used(), WORK);
        let error = graph.settle(None, &[], &mut ()).unwrap_err();
        let Overflow::Resource(error) = error else {
            panic!("shared exhaustion must remain a resource error")
        };
        assert_eq!(error.offset(), 719);
        assert_eq!(error.field(), "certificationPath.policies");
        assert!(error.is_limit());
        assert_eq!(execution.used(), 0);
    }

    #[test]
    fn repeated_fan_in_and_fan_out_grow_nodes_linearly() {
        // Two policies converge and then split at every level. A tree doubles
        // complete histories; RFC9618 retains one node per depth/OID instead.
        let mappings = [
            (GOLD, GOLD),
            (GOLD, SILVER),
            (SILVER, GOLD),
            (SILVER, SILVER),
        ];
        let steps = (0..24)
            .map(|_| certificate(&[GOLD, SILVER], &mappings))
            .collect::<Vec<_>>();
        let parser = Parser::der(crate::fixtures::memory());
        let read = steps
            .iter()
            .map(|der| Certificate::read(&parser, der, 0).unwrap())
            .collect::<Vec<_>>();
        let execution = crate::fixtures::memory();
        let graph = process(&read, &execution);
        assert_eq!(graph.nodes(), 1 + 2 * steps.len());
        let nodes = graph.nodes.as_ref().unwrap();
        for depth in 1..=24 {
            let level = nodes
                .iter()
                .filter(|node| node.live && node.depth == depth)
                .collect::<Vec<_>>();
            assert_eq!(level.len(), 2);
            for node in level {
                assert_eq!(node.parents.len(), if depth == 1 { 1 } else { 2 });
                for parent in node.parents.iter() {
                    assert_eq!(nodes[parent].depth + 1, depth);
                }
            }
        }
        assert_eq!(
            graph.settle(None, &[], &mut ()).unwrap().policies(),
            &[GOLD, SILVER]
        );
        assert_eq!(execution.used(), 0);
    }
}
