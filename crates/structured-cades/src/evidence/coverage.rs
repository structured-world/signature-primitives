//! Whole-item coverage from the SAME executed source recipe and sealed record.
use super::record::{Checked, Verified};
use crate::{
    Cades, Error, ISSUER,
    material::Index,
    source::{DocumentId, Node},
    timestamp,
};
use structured_asn1::{
    Reader, Span,
    memory::{Memory, OwnedVec, SortError, Work},
};
use structured_ltv::{
    material::{Coverage, IndexError},
    source::{Scope, Source as _},
};
const FIELD: &str = "cades.evidence.coverage";
type Items<'m, 'd> = Coverage<Node, DocumentId<'m, 'd>, (), Memory, Cades>;

/// Source/query or original material-index refusal; never missing material.
#[derive(Debug)]
pub enum CoverageError {
    /// Original source, work or storage refusal.
    Processing(Error),
    /// Exact source-index refusal, including a fused traversal failure.
    Index(IndexError<Node>),
    /// A selected timestamp/index belongs to another sealed proof or source.
    Foreign {
        /// Actual selecting proof property.
        property: Node,
    },
}
/// Same original checked TSA with its own actual, source-derived coverage.
/// A later renewal covers the original input and earlier complete timestamps;
/// it does not claim coverage of its OWN carried certificates or future TSAs.
pub struct Archive<'view, 'prepared, 'm, 'd, 'path> {
    report: &'view Checked<'prepared, 'm, 'd, 'path>,
    timestamp: &'view timestamp::Checked<'m, 'd, 'path>,
    coverage: Items<'m, 'd>,
}
impl<'m, 'd, 'path> Archive<'_, '_, 'm, 'd, 'path> {
    /// Same complete checked timestamp, without rechecking mathematics.
    #[must_use]
    pub fn timestamp(&self) -> &timestamp::Checked<'m, 'd, 'path> {
        self.timestamp
    }
    /// Exact whole-item selection; successful evidence must still bind it.
    #[must_use]
    pub fn coverage(&self) -> &Items<'m, 'd> {
        &self.coverage
    }
    /// Full earlier TSA/counter census from this actual protected input.
    pub fn requirements(
        &self,
        operation: &Reader<'d>,
    ) -> Result<
        structured_ltv::timestamp::TimestampRequirements<Node, DocumentId<'m, 'd>, (), Cades>,
        timestamp::ArchiveScopeError,
    > {
        timestamp::requirements::derive(
            self.timestamp,
            &self.coverage,
            self.report.prepared,
            operation,
        )
    }
}
impl<'prepared, 'm, 'd, 'path> Verified<'_, 'prepared, 'm, 'd, 'path> {
    /// Bind one actual global timestamp ordinal to its executed recipe. The
    /// provided index is this preparation's existing whole material index;
    /// no material/certificate/status grammar is parsed again.
    pub fn archive<'view, W: Work>(
        &'view self,
        ordinal: usize,
        index: &Index<'_, 'm, 'd, W>,
        operation: &Reader<'d>,
    ) -> Result<Archive<'view, 'prepared, 'm, 'd, 'path>, CoverageError> {
        let report = self.report();
        let prepared = report.prepared;
        let property = report.required.property;
        let resource =
            |cause| CoverageError::Processing(Error::resource(cause, FIELD, property.span().start));
        prepared
            .document()
            .message()
            .require_session(operation, FIELD)
            .map_err(|cause| CoverageError::Processing(Error::Cms(cause)))?;
        let work = operation.execution();
        work.charge_work(3).map_err(resource)?;
        if !report.timestamps.contains(&ordinal)
            || index.snapshot() != prepared.document().snapshot()
            || index.signature() != Node::of(prepared.signer().span())
        {
            return Err(CoverageError::Foreign { property });
        }
        let entry = prepared
            .parsed
            .proofs
            .entries
            .get(report.proof)
            .ok_or(CoverageError::Foreign { property })?;
        if entry.required.property != property {
            return Err(CoverageError::Foreign { property });
        }
        let relative = ordinal - report.timestamps.start;
        let timestamp = &report.checks[report.checks.len() - 1 - relative];
        let actor = timestamp
            .actor()
            .ok_or(CoverageError::Foreign { property })?;
        let mut spans = work.vector();
        let base = report
            .covered
            .as_ref()
            .ok_or(CoverageError::Foreign { property })?;
        spans.try_extend_from_slice(base).map_err(resource)?;
        for previous in report.timestamps.start..ordinal {
            work.charge_work(1).map_err(resource)?;
            let value = prepared.timestamps()[previous]
                .value()
                .ok_or(CoverageError::Foreign { property })?;
            spans.try_push(value.span()).map_err(resource)?;
        }
        normalize(&mut spans, &work).map_err(resource)?;
        let document = prepared.document();
        let query = Scope::new(document, document.snapshot(), &work);
        let mut items = work.map();
        for occurrence in index
            .all_occurrences(&query)
            .map_err(CoverageError::Index)?
        {
            let occurrence = occurrence.map_err(CoverageError::Index)?;
            let node = occurrence.location().node;
            if selects(&spans, node.span(), &work).map_err(resource)? {
                items.try_insert(node, true).map_err(resource)?;
            }
        }
        for counter in prepared
            .counters()
            .iter()
            .chain(prepared.parallel_counters())
        {
            work.charge_work(1).map_err(resource)?;
            if selects(&spans, counter.node().span(), &work).map_err(resource)? {
                items.try_insert(counter.node(), true).map_err(resource)?;
            }
        }
        for entry in prepared.timestamps() {
            work.charge_work(1).map_err(resource)?;
            let node = entry
                .value()
                .map_or(entry.property(), |value| Node::of(value.span()));
            if node == actor.verified().token().node {
                continue;
            }
            if selects(&spans, node.span(), &work).map_err(resource)? {
                items.try_insert(node, true).map_err(resource)?;
            }
            if selects(&spans, entry.property().span(), &work).map_err(resource)? {
                items.try_insert(entry.property(), true).map_err(resource)?;
            }
        }
        let coverage = Coverage::for_token(
            ISSUER,
            document.snapshot(),
            report.required.signature,
            property,
            actor.verified().token().node,
            structured_ltv::timestamp::Purpose::Archive,
            items.into_owned(),
        );
        Ok(Archive {
            report,
            timestamp,
            coverage,
        })
    }
}
pub(super) fn normalize_owned<W: Work>(
    spans: OwnedVec<Span>,
    work: &W,
    at: u64,
) -> Result<OwnedVec<Span>, Error> {
    let mut spans = spans
        .with_execution(work)
        .map_err(|_| Error::Foreign { at })?;
    normalize(&mut spans, work).map_err(|cause| Error::resource(cause, FIELD, at))?;
    Ok(spans.into_owned())
}
fn normalize<W: Work>(
    spans: &mut OwnedVec<Span, W>,
    work: &W,
) -> Result<(), structured_asn1::memory::MemoryError> {
    spans
        .try_sort_unstable_by(|a, b| {
            work.charge_work(3)?;
            Ok::<_, structured_asn1::memory::MemoryError>(
                a.start.cmp(&b.start).then_with(|| b.length.cmp(&a.length)),
            )
        })
        .map_err(|cause| match cause {
            SortError::Resource(cause) | SortError::Comparison(cause) => cause,
        })?;
    let mut written = 0;
    for read in 0..spans.len() {
        work.charge_work(3)?;
        let current = spans[read];
        if written != 0 && current.start <= spans[written - 1].end() {
            let previous = &mut spans[written - 1];
            if current.end() > previous.end() {
                previous.length = current.end() - previous.start;
            }
        } else {
            spans[written] = current;
            written += 1;
        }
    }
    while spans.len() > written {
        work.charge_work(1)?;
        spans.pop();
    }
    Ok(())
}
pub(super) fn selects<W: Work>(
    spans: &[Span],
    node: Span,
    work: &W,
) -> Result<bool, structured_asn1::memory::MemoryError> {
    let mut low = 0;
    let mut high = spans.len();
    while low < high {
        work.charge_work(2)?;
        let middle = low + (high - low) / 2;
        if spans[middle].start <= node.start {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if low == 0 {
        return Ok(false);
    }
    work.charge_work(1)?;
    Ok(spans[low - 1].end() >= node.end())
}
