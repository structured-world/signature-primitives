//! Bounded discovery before time, constraint or trust evaluation.

use super::{
    Anchor, Bounds, EffectiveKey, Meter, Truncation, Verified, Verify, cost, fold_pool_in,
};
use crate::{Certificate, Name};
use core::convert::Infallible;
use core::fmt;
use structured_asn1::memory::{Execution, MemoryError, OwnedVec, Work};

/// A prospective leaf-first chain ending at a caller-supplied anchor.
#[derive(Debug)]
pub struct Candidate<'a> {
    chain: OwnedVec<&'a Certificate<'a>>,
    anchor: Anchor<'a>,
}

impl<'a> Candidate<'a> {
    /// Original certificates, target first and anchor excluded.
    #[must_use]
    pub fn certificates(&self) -> &[&'a Certificate<'a>] {
        &self.chain
    }

    /// The original anchor offered by the caller.
    #[must_use]
    pub fn anchor(&self) -> Anchor<'a> {
        self.anchor
    }
}

/// Discovery stopped without a complete result.
#[derive(Debug)]
pub enum Error<V = Infallible> {
    /// A caller-selected search bound was reached.
    Limit(Truncation),
    /// Processing or original/current resource refusal.
    Processing(crate::Error),
    /// Original verifier execution failure.
    Verification(V),
}

impl<V> From<crate::Error> for Error<V> {
    fn from(error: crate::Error) -> Self {
        Self::Processing(error)
    }
}

impl<V: fmt::Display> fmt::Display for Error<V> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(limit) => write!(output, "prospective path search reached {limit:?}"),
            Self::Processing(error) => error.fmt(output),
            Self::Verification(error) => write!(output, "issuer signature verifier: {error}"),
        }
    }
}

impl<V: core::error::Error + 'static> core::error::Error for Error<V> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Limit(_) => None,
            Self::Processing(error) => Some(error),
            Self::Verification(error) => Some(error),
        }
    }
}

/// Enumerate prospective chains to the supplied anchors in input DFS order.
///
/// ETSI EN 319 102-1 V1.4.1 §5.2.6.4 step 2 and RFC 5280 §6.1(a)–(c)
/// precede validation of signatures, time, policies and other constraints.
/// The caller establishes anchor trust and chooses how to validate each
/// candidate. Exact repeated certificates are folded and never form cycles.
/// Any exhausted depth, edge, visit, work or output bound returns an error.
/// Policy-tree bounds apply in validation, outside this search.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf>
/// <https://www.rfc-editor.org/rfc/rfc5280#section-6.1>
pub fn enumerate<'a, W: Work>(
    target: &'a Certificate<'a>,
    pool: &[&'a Certificate<'a>],
    anchors: &[Anchor<'a>],
    bounds: Bounds,
    work: &W,
) -> Result<OwnedVec<Candidate<'a>>, Error> {
    let mut found = work.vector();
    if anchors.is_empty() {
        return Ok(found.into_owned());
    }
    walk(
        target,
        pool,
        bounds,
        work,
        |_, _| Ok(true),
        |event, chain, meter| {
            if event != Event::Enter {
                return Ok(());
            }
            let Some(last) = chain.last() else {
                return Ok(());
            };
            for &anchor in anchors {
                meter.edge()?;
                let source = anchor
                    .certificate()
                    .map(|published| published.signature_algorithm().source_parser());
                if !names(last, anchor.name(), source, meter)? {
                    continue;
                }
                if let Some(published) = anchor.certificate() {
                    let mut repeated = false;
                    for held in chain {
                        let bytes = published.as_bytes().len().max(held.as_bytes().len()) as u64;
                        meter.admit(cost::CHECK + bytes / cost::COMPARED)?;
                        work.charge_work_from(
                            [
                                published.signature_algorithm().source_parser(),
                                held.signature_algorithm().source_parser(),
                            ],
                            bytes,
                        )
                        .map_err(|cause| published.tbs().subject().resource(cause))?;
                        if super::same(held, published) {
                            repeated = true;
                            break;
                        }
                    }
                    if repeated {
                        continue;
                    }
                }
                if found.len() >= bounds.paths {
                    return Err(Error::Limit(Truncation::Paths));
                }
                meter.admit(chain.len() as u64)?;
                let mut retained = work.vector();
                retained
                    .try_extend_from_slice(chain)
                    .map_err(|cause| meter.resource(cause))?;
                found
                    .try_push(Candidate {
                        chain: retained.into_owned(),
                        anchor,
                    })
                    .map_err(|cause| meter.resource(cause))?;
            }
            Ok(())
        },
    )?;
    Ok(found.into_owned())
}

/// Enumerate original tips of name-linked branches with verified issuer edges.
///
/// An edge must verify with the issuer's standalone key. Missing inherited
/// parameters and unsupported algorithms establish no edge. A returned tip
/// identifies a certificate for the caller to consider as an anchor. No
/// certificate trust or time/constraint result is inferred.
pub fn verified_tops<'a, W: Work, V, VE>(
    target: &'a Certificate<'a>,
    pool: &[&'a Certificate<'a>],
    bounds: Bounds,
    work: &W,
    verifier: &V,
) -> Result<OwnedVec<&'a Certificate<'a>>, Error<VE>>
where
    V: for<'scope> Verify<Execution<'scope>, Error = VE>,
{
    let mut found = work.vector();
    let mut seen = work.map::<usize, ()>();
    walk(
        target,
        pool,
        bounds,
        work,
        |(subject, issuer), meter| {
            meter.admit(cost::SIGNATURE)?;
            let algorithm = subject.signature_algorithm();
            let key = issuer.tbs().public_key();
            // Admit dispatch jointly. The backend receives the subject scope;
            // the original key carries its own scope for deferred decoding.
            work.charge_work_from(
                [algorithm.source_parser(), key.algorithm().source_parser()],
                1,
            )
            .map_err(|cause| meter.resource(cause))?;
            let subject_work = subject.execution_in(work);
            verifier
                .verify(
                    &algorithm,
                    EffectiveKey::standing(key),
                    subject.signed_bytes(),
                    subject.signature_value(),
                    &subject_work,
                )
                .map(|answer| answer == Verified::Yes)
                .map_err(Error::Verification)
        },
        |event, chain, meter| {
            if event == Event::Tip
                && let Some(&top) = chain.last()
                && seen
                    .try_insert(top.as_bytes().as_ptr() as usize, ())
                    .map_err(|cause| meter.resource(cause))?
                    .is_none()
            {
                if found.len() >= bounds.paths {
                    return Err(Error::Limit(Truncation::Paths));
                }
                found.try_push(top).map_err(|cause| meter.resource(cause))?;
            }
            Ok(())
        },
    )?;
    Ok(found.into_owned())
}

#[derive(PartialEq, Eq)]
enum Event {
    Enter,
    Tip,
}

struct Budget<'a, 'w, W> {
    remaining: u64,
    edges: usize,
    visited: usize,
    source: &'a Name<'a>,
    work: &'w W,
}

impl<W: Work> Meter for Budget<'_, '_, W> {
    fn spend(&mut self, amount: u64) -> crate::Result<bool> {
        let Some(remaining) = self.remaining.checked_sub(amount) else {
            self.remaining = 0;
            return Ok(false);
        };
        self.work
            .charge_work(amount)
            .map_err(|cause| self.resource(cause))?;
        self.remaining = remaining;
        Ok(true)
    }
}

impl<W: Work> Budget<'_, '_, W> {
    fn resource(&self, cause: MemoryError) -> crate::Error {
        self.source.resource(cause)
    }

    fn admit<V>(&mut self, amount: u64) -> Result<(), Error<V>> {
        if !self.spend(amount)? {
            return Err(Error::Limit(Truncation::Work));
        }
        Ok(())
    }

    fn edge<V>(&mut self) -> Result<(), Error<V>> {
        self.edges = self
            .edges
            .checked_sub(1)
            .ok_or(Error::Limit(Truncation::Edges))?;
        self.admit(cost::CHECK)
    }
}

fn names<W: Work, V>(
    subject: &Certificate<'_>,
    issuer: &Name<'_>,
    issuer_source: Option<&structured_asn1::Parser>,
    meter: &mut Budget<'_, '_, W>,
) -> Result<bool, Error<V>> {
    let written = subject.tbs().issuer();
    if !super::validation::spend_names(meter, written, issuer)? {
        return Err(Error::Limit(Truncation::Work));
    }
    // Rebinding one execution twice would replace the first foreign parser.
    Ok(if let Some(issuer_source) = issuer_source {
        written.matches_between(
            issuer,
            (meter.work, subject.signature_algorithm().source_parser()),
            (meter.work, issuer_source),
        )?
    } else {
        written.matches(issuer, &subject.execution_in(meter.work))?
    })
}

struct Frame {
    next: usize,
    continued: bool,
}

fn walk<'a, W: Work, V>(
    target: &'a Certificate<'a>,
    pool: &[&'a Certificate<'a>],
    bounds: Bounds,
    work: &W,
    mut follows: impl FnMut(
        (&'a Certificate<'a>, &'a Certificate<'a>),
        &mut Budget<'a, '_, W>,
    ) -> Result<bool, Error<V>>,
    mut visit: impl FnMut(Event, &[&'a Certificate<'a>], &mut Budget<'a, '_, W>) -> Result<(), Error<V>>,
) -> Result<(), Error<V>> {
    let mut meter = Budget {
        remaining: bounds.work,
        edges: bounds.edges,
        visited: bounds.visited,
        source: target.tbs().subject(),
        work,
    };
    let mut exhausted = false;
    let pool = fold_pool_in(work, pool, target, |amount| {
        let paid = meter.spend(amount)?;
        exhausted = !paid;
        Ok(paid)
    })?;
    if exhausted {
        return Err(Error::Limit(Truncation::Work));
    }
    let mut chain = work.vector();
    let mut stack = work.vector::<Frame>();
    let mut entering = target;
    'enter: loop {
        if chain.len() >= bounds.depth {
            return Err(Error::Limit(Truncation::Depth));
        }
        meter.visited = meter
            .visited
            .checked_sub(1)
            .ok_or(Error::Limit(Truncation::Visited))?;
        meter.admit(cost::CHECK)?;
        chain
            .try_push(entering)
            .map_err(|cause| meter.resource(cause))?;
        stack
            .try_push(Frame {
                next: 0,
                continued: false,
            })
            .map_err(|cause| meter.resource(cause))?;
        visit(Event::Enter, &chain, &mut meter)?;
        while let Some(frame) = stack.last_mut() {
            let &subject = chain.last().expect("each cursor has a certificate");
            for &issuer in &pool[frame.next..] {
                frame.next += 1;
                meter.edge()?;
                meter.admit(chain.len() as u64)?;
                if chain.iter().any(|held| core::ptr::eq(*held, issuer)) {
                    continue;
                }
                if names(
                    subject,
                    issuer.tbs().subject(),
                    Some(issuer.signature_algorithm().source_parser()),
                    &mut meter,
                )? && follows((subject, issuer), &mut meter)?
                {
                    frame.continued = true;
                    entering = issuer;
                    continue 'enter;
                }
            }
            if !frame.continued {
                visit(Event::Tip, &chain, &mut meter)?;
            }
            stack.pop();
            chain.pop();
        }
        return Ok(());
    }
}
