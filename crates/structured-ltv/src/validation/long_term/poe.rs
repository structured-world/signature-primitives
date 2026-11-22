use super::{Covered, Error, Hash, Horizon, Object, Proof};
use crate::validation::{Constraints, Material};
use structured_asn1::memory::{OwnedVec, Work};
use structured_pkix::temporal::Instant;

#[derive(Clone, Copy, Default)]
struct Entry {
    earliest: Option<Instant>,
    head: Option<usize>,
}

struct Node {
    at: Instant,
    next: Option<usize>,
}

pub(super) struct Proofs<W: Work> {
    entries: OwnedVec<Entry, W>,
    times: OwnedVec<Node, W>,
    now: Instant,
}

impl<W: Work> Proofs<W> {
    pub(super) fn new(count: usize, now: Instant, work: &W) -> Result<Self, Error> {
        work.charge_work(count as u64)?;
        let mut entries = work.vector();
        entries.try_reserve_exact(count)?;
        for _ in 0..count {
            entries.try_push(Entry::default())?;
        }
        Ok(Self {
            entries,
            times: work.vector(),
            now,
        })
    }

    pub(super) fn add(&mut self, proof: Proof, work: &W) -> Result<(), Error> {
        work.charge_work(4)?;
        if proof.at > self.now {
            return Err(Error::FutureTime(proof.at));
        }
        let slot = self
            .entries
            .get_mut(proof.object.0)
            .ok_or(Error::ForeignObject(proof.object))?;
        let next = self.times.len();
        self.times.try_push(Node {
            at: proof.at,
            next: slot.head,
        })?;
        slot.head = Some(next);
        slot.earliest = Some(slot.earliest.map_or(proof.at, |known| known.min(proof.at)));
        Ok(())
    }

    pub(super) fn earliest(&self, object: Object, work: &W) -> Result<Option<Instant>, Error> {
        work.charge_work(1)?;
        Ok(self
            .entries
            .get(object.0)
            .ok_or(Error::ForeignObject(object))?
            .earliest)
    }

    pub(super) fn by(&self, object: Object, horizon: Horizon, work: &W) -> Result<bool, Error> {
        Ok(self
            .earliest(object, work)?
            .is_some_and(|at| horizon.admits(at)))
    }

    pub(super) fn between(
        &self,
        object: Object,
        from: Instant,
        to: Horizon,
        work: &W,
    ) -> Result<bool, Error> {
        work.charge_work(1)?;
        let mut next = self
            .entries
            .get(object.0)
            .ok_or(Error::ForeignObject(object))?
            .head;
        while let Some(i) = next {
            work.charge_work(1)?;
            let node = &self.times[i];
            if from < node.at && to.admits(node.at) {
                return Ok(true);
            }
            next = node.next;
        }
        Ok(false)
    }

    pub(super) fn extract(
        &mut self,
        covered: &[Covered],
        at: Instant,
        constraints: &Constraints<'_>,
        work: &W,
    ) -> Result<(), Error> {
        // 5.6.2.3.4 step 4 precedes step 5. A reference must have an
        // independently known later proof within the hash's reliable period.
        for item in covered {
            work.charge_work(1)?;
            let Covered::Reference {
                digest,
                target,
                hash,
            } = *item
            else {
                continue;
            };
            if let Some(limit) = hash_limit(constraints, hash, self.now, work)?
                && limit.admits(at)
            {
                self.add(Proof { object: digest, at }, work)?;
                if self.between(target, at, limit, work)? {
                    self.add(Proof { object: target, at }, work)?;
                }
            }
        }
        for item in covered {
            work.charge_work(1)?;
            if let Covered::Direct(object) = *item {
                self.add(Proof { object, at }, work)?;
            }
        }
        Ok(())
    }
}

pub(super) fn hash_limit(
    constraints: &Constraints<'_>,
    hash: Hash,
    now: Instant,
    work: &impl Work,
) -> Result<Option<Horizon>, Error> {
    work.charge_work(constraints.hashes.len() as u64)?;
    let Some(rule) = constraints.hashes.iter().find(|rule| rule.hash == hash) else {
        return Ok(None);
    };
    Ok(Some(
        rule.until.map_or(Horizon::Through(now), Horizon::Before),
    ))
}

pub(super) struct Crypto<'a> {
    rules: &'a Constraints<'a>,
    cost: u64,
}

impl<'a> Crypto<'a> {
    pub(super) fn new(rules: &'a Constraints<'a>, work: &impl Work) -> Result<Self, Error> {
        Ok(Self {
            rules,
            cost: crate::validation::admission::material_cost(rules, work)?,
        })
    }

    pub(super) fn assess(
        &self,
        material: Material,
        at: Instant,
        lower: Option<Instant>,
        work: &impl Work,
    ) -> Result<Result<(), crate::validation::Unmet>, Error> {
        work.charge_work(self.cost)?;
        Ok(self.rules.assess(material, at, lower))
    }

    pub(super) fn sunset(
        &self,
        material: Material,
        work: &impl Work,
    ) -> Result<Result<Option<Instant>, crate::validation::Unmet>, Error> {
        work.charge_work(self.cost)?;
        Ok(self.rules.sunset(material))
    }
}
