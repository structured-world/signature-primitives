//! Complete CMS and PDF timestamp inputs, including unsuccessful occurrences.

use super::{ISSUER, Node, Pades};
use crate::{
    basic::Basic,
    document::Document,
    error::{Error, ErrorKind},
    model::admit,
    range::RangeSource,
    signature::{Candidate, Coverage, Failure, Signature, SubFilter},
};
use structured_asn1::{
    Span,
    memory::{OwnedVec, Work},
};
use structured_ltv::{
    pki::CounterReceipts,
    source::Location as Original,
    timestamp::{CheckedActor, Purpose, RequiredToken, TimestampRequirements, TimestampScope},
};

/// Complete original timestamp census or the original PDF/source refusal.
pub type RequirementsRead<'a, 's, D, G, E> =
    Result<Requirements<'a, 's, D, G>, crate::error::ReadFailure<E>>;

/// The whole actual root/counter token census followed by every document
/// timestamp in the original document. Earlier DTS authorities remain
/// preceding-material obligations even when they cannot prove this root.
pub struct Requirements<'a, 's, D, G> {
    all: TimestampRequirements<Node, D, G, Pades>,
    pdf: OwnedVec<DocumentTimestamp<'a, 's, D, G>>,
    counters: OwnedVec<Node>,
    pub(super) root: Signature<'a, 's, D, G>,
    revision: Option<usize>,
    vri: OwnedVec<VriTimestamp>,
    total_pdf: usize,
}

/// One actual VRI TS occurrence in its historical DSS interpretation window.
#[derive(Debug, Clone, Copy)]
pub struct VriTimestamp {
    /// Original ordinal across all historical VRI timestamp occurrences.
    pub ordinal: usize,
    /// Historical DSS window, not the latest file revision.
    pub revision: usize,
    /// VRI dictionary ordinal in that same original Validation owner.
    pub vri: usize,
    /// TS stream ordinal in that Validation owner's retained item pool.
    pub item: usize,
}

/// One actual PDF timestamp candidate, including an unreadable source input.
pub enum DocumentTimestamp<'a, 's, D, G> {
    /// Original dictionary has readable exact ranges and Contents.
    Readable(Signature<'a, 's, D, G>),
    /// Original candidate has no usable replacement signature handle.
    Unreadable(&'a Failure),
}
impl<'a, 's, D: Copy + Eq, G: Copy + Eq> DocumentTimestamp<'a, 's, D, G> {
    /// Exact source dictionary, independently of readable required fields.
    #[must_use]
    pub fn location(&self) -> crate::source::Location {
        match self {
            Self::Readable(value) => value.location(),
            Self::Unreadable(value) => value.location,
        }
    }
    /// Actual signature handle only when its required fields were readable.
    #[must_use]
    pub fn signature(&self) -> Option<Signature<'a, 's, D, G>> {
        match self {
            Self::Readable(value) => Some(*value),
            Self::Unreadable(_) => None,
        }
    }
    /// Original required-value failure; never a successful timestamp absence.
    #[must_use]
    pub fn failure(&self) -> Option<&'a Failure> {
        match self {
            Self::Readable(_) => None,
            Self::Unreadable(value) => Some(value),
        }
    }
    pub(crate) fn token(&self) -> Node {
        match self {
            Self::Readable(value) => Node::of(value.contents()),
            Self::Unreadable(value) => match value.contents {
                Some(location) => Node::of(location),
                None => Node::missing_contents(value.location),
            },
        }
    }
}
impl<'a, 's, D: Copy + Eq, G: Copy + Eq> Requirements<'a, 's, D, G> {
    /// Actual original PDF signature from which this entire census was derived.
    #[must_use]
    pub fn signature(&self) -> Signature<'a, 's, D, G> {
        self.root
    }
    /// Entire original set accepted by the common all-token TSA path binder.
    #[must_use]
    pub fn all(&self) -> &TimestampRequirements<Node, D, G, Pades> {
        &self.all
    }
    /// Source-derived PDF timestamp dictionaries in physical source order.
    /// These are not selected by successful cryptographic checks.
    #[must_use]
    pub fn document_timestamps(&self) -> &[DocumentTimestamp<'a, 's, D, G>] {
        &self.pdf
    }

    /// Explicit historical assessment window, absent for the current census.
    /// The source ordinal remains its position in the complete original set.
    #[must_use]
    pub fn revision(&self) -> Option<usize> {
        self.revision
    }
    /// Every original VRI TS, including an unreadable carried token. The
    /// matching source model belongs to this exact historical owner.
    #[must_use]
    pub fn vri_timestamps(&self) -> &[VriTimestamp] {
        &self.vri
    }
    pub(crate) fn total_pdf(&self) -> usize {
        self.total_pdf
    }

    /// Derives the exact timestamp census visible at one original DTS revision.
    /// A malformed selected occurrence refuses this projection; it is never
    /// replaced with an earlier readable or successful occurrence. The caller
    /// retains this complete source census independently of the historical view.
    pub fn at_source_revision(&self, ordinal: usize, operation: &impl Work) -> crate::Result<Self> {
        let location = self.root.location();
        let work = self.root.owner().value.session.query(operation);
        admit(&work, location, 1)?;
        if self.revision.is_some() {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            });
        }
        let selected = self
            .pdf
            .get(ordinal)
            .and_then(DocumentTimestamp::signature)
            .ok_or(Error {
                kind: ErrorKind::Foreign,
                location,
            })?;
        let Coverage::Revision(revision) = selected.coverage() else {
            return Err(Error {
                kind: ErrorKind::Syntax(crate::error::Syntax::Container),
                location: selected.location(),
            });
        };
        if !matches!(self.root.coverage(), Coverage::Revision(root) if root <= revision) {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: selected.location(),
            });
        }
        let mut entries = work.vector();
        let mut pdf = work.vector();
        // The CMS source is immutable inside the selected root; the following
        // PDF entries preserve every occurrence, including unreadable siblings.
        let prefix = self.all.entries().len() - self.pdf.len() - self.vri.len();
        for entry in &self.all.entries()[..=prefix + ordinal] {
            admit(&work, location, 1)?;
            entries.try_push(*entry).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
        for original in &self.pdf[..=ordinal] {
            admit(&work, original.location(), 1)?;
            let original = match original {
                DocumentTimestamp::Readable(value) => DocumentTimestamp::Readable(*value),
                DocumentTimestamp::Unreadable(value) => DocumentTimestamp::Unreadable(value),
            };
            pdf.try_push(original).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
        let mut vri = work.vector();
        for (index, original) in self.vri.iter().enumerate() {
            admit(&work, location, 1)?;
            if original.revision > revision {
                continue;
            }
            entries
                .try_push(self.all.entries()[prefix + self.pdf.len() + index])
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
            vri.try_push(*original).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
        let mut counters = work.vector();
        let mut kept = work.vector();
        for counter in &self.counters {
            admit(&work, location, 1)?;
            counters.try_push(*counter).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
            kept.try_push(*counter).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
        let all = TimestampRequirements::with_counters(
            ISSUER,
            self.all.signature(),
            self.all.scope(),
            entries.into_owned(),
            counters.into_owned(),
            None,
        );
        Ok(Self {
            all,
            pdf: pdf.into_owned(),
            counters: kept.into_owned(),
            root: self.root,
            revision: Some(revision),
            vri: vri.into_owned(),
            total_pdf: self.total_pdf,
        })
    }

    pub(crate) fn first_existence_timestamp(
        &self,
        operation: &impl Work,
    ) -> crate::Result<Option<Node>> {
        let work = self.root.owner().value.session.query(operation);
        for original in &self.pdf {
            admit(&work, original.location(), 1)?;
            let Some(signature) = original.signature() else {
                continue;
            };
            if matches!(signature.coverage(), Coverage::Revision(_))
                && covers(signature, self.root.contents().enclosing(), &work)?
            {
                return Ok(Some(Node::of(signature.location())));
            }
        }
        Ok(None)
    }
    /// Complete earlier-token scope for one actual document timestamp.
    /// Its own and later tokens are excluded by exact original input ranges;
    /// no current-time success count or caller-provided mask selects actors.
    pub fn before_archive(
        &self,
        ordinal: usize,
        actor: &CheckedActor<'_, '_, Node, D, G, Pades>,
        operation: &impl Work,
    ) -> crate::Result<TimestampRequirements<Node, D, G, Pades>> {
        let at = self.archive(ordinal, actor, operation)?;
        let location = at.location();
        let work = self.root.owner().value.session.query(operation);
        let proof = actor.verified();
        let mut entries = work.vector();
        for entry in self.all.entries() {
            admit(&work, location, 1)?;
            if entry.token == proof.token().node {
                continue;
            }
            if covers_node(at, entry.token, &work)? {
                entries.try_push(*entry).map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
            }
        }
        let mut counters = work.vector();
        let mut included = work.vector();
        for &counter in &self.counters {
            admit(&work, location, 1)?;
            counters.try_push(counter).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
            included
                .try_push(covers(at, counter.span(), &work)?)
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
        }
        Ok(TimestampRequirements::with_counters(
            ISSUER,
            self.all.signature(),
            TimestampScope::BeforeArchive(Original {
                snapshot: proof.token().snapshot,
                node: proof.token().node,
            }),
            entries.into_owned(),
            counters.into_owned(),
            Some(included.into_owned()),
        ))
    }

    pub(super) fn archive(
        &self,
        ordinal: usize,
        actor: &CheckedActor<'_, '_, Node, D, G, Pades>,
        operation: &impl Work,
    ) -> crate::Result<Signature<'a, 's, D, G>> {
        let work = self.root.owner().value.session.query(operation);
        admit(&work, self.root.location(), 1)?;
        let at = self
            .pdf
            .get(ordinal)
            .and_then(DocumentTimestamp::signature)
            .ok_or(Error {
                kind: ErrorKind::Foreign,
                location: self.root.location(),
            })?;
        let proof = actor.verified();
        if proof.token().snapshot != self.root.owner().value.stamp.snapshot
            || proof.signature() != self.all.signature()
            || proof.property() != Node::of(at.location())
            || proof.token().node != Node::of(at.contents())
            || proof.purpose() != Purpose::Archive
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location: at.location(),
            });
        }
        Ok(at)
    }
}

pub(crate) fn covers_node<D: Copy + Eq, G: Copy + Eq>(
    signature: Signature<'_, '_, D, G>,
    node: Node,
    work: &impl Work,
) -> crate::Result<bool> {
    admit(work, signature.location(), 1)?;
    if let Some(material) = node.material_revision() {
        // EN319142-1 §§5.4.2/5.4.3 bind DSS interpretation and all its
        // references/decoding controls to the authenticated revision. A full
        // revision proof excludes only its own isolated Contents string, not
        // a DSS stream. Using only the stream body's old span could accept a
        // late xref/DSS/filter reassociation as already protected material.
        // https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf
        return Ok(
            matches!(signature.coverage(), Coverage::Revision(revision) if material <= revision),
        );
    }
    if node.is_missing_contents() {
        return Ok(false);
    }
    covers(signature, node.span(), work)
}

pub(crate) fn covers<D: Copy + Eq, G: Copy + Eq>(
    signature: Signature<'_, '_, D, G>,
    item: Span,
    work: &impl Work,
) -> crate::Result<bool> {
    for range in signature.ranges() {
        admit(work, signature.location(), 1)?;
        if range.start <= item.start
            && item.start - range.start <= range.length
            && item.length <= range.length - (item.start - range.start)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn document_timestamps<'a, 's, D: Copy + Eq, G: Copy + Eq, W: Work>(
    root: Signature<'a, 's, D, G>,
    mapping: crate::binding::Mapping<'_, '_, D, G>,
    entries: &mut OwnedVec<RequiredToken<Node>, W>,
    work: &W,
) -> crate::Result<OwnedVec<DocumentTimestamp<'a, 's, D, G>, W>> {
    let location = root.location();
    let mut pdf = work.vector();
    for index in 0..root.catalogue().candidates() {
        admit(work, location, 1)?;
        let timestamp = match root
            .catalogue()
            .candidate(index)
            .expect("bounded complete census")
        {
            Candidate::Readable(timestamp) => {
                if !timestamp.is_document_timestamp()
                    && timestamp.sub_filter() != Some(SubFilter::Rfc3161)
                {
                    continue;
                }
                DocumentTimestamp::Readable(timestamp)
            }
            Candidate::Unreadable(timestamp) => {
                if !timestamp.document_timestamp {
                    continue;
                }
                DocumentTimestamp::Unreadable(timestamp)
            }
        };
        let property = Node::of(timestamp.location());
        entries
            .try_push(RequiredToken {
                signature: mapping.root,
                property,
                token: timestamp.token(),
                purpose: Purpose::Archive,
            })
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: timestamp.location(),
            })?;
        let at = timestamp.location();
        pdf.try_push(timestamp).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location: at,
        })?;
    }
    Ok(pdf)
}

fn project_requirements<D: Copy, G: Copy, W: Work>(
    mapping: crate::binding::Mapping<'_, '_, D, G>,
    source: &[RequiredToken<structured_cades::source::Node>],
    entries: &mut OwnedVec<RequiredToken<Node>, W>,
    location: crate::source::Location,
    work: &impl Work,
) -> crate::Result<()> {
    for original in source {
        admit(work, location, 1)?;
        entries
            .try_push(RequiredToken {
                signature: mapping.node(original.signature),
                property: mapping.node(original.property),
                token: mapping.node(original.token),
                purpose: original.purpose,
            })
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
    }
    Ok(())
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// Derives all timestamp obligations from the sealed original preparation
    /// and the same complete physical signature census as its selected root.
    ///
    /// # Panics
    /// Panics if an internal candidate ordinal leaves the complete source census.
    pub fn timestamp_requirements<'a, 'r, 'v, 'p, 'm, 'd, 'path, W: Work>(
        &self,
        basic: &Basic<'r, 'v, 'p, 'm, 'd, 'a, 's, 'path, S::Document, S::Generation>,
        history: &crate::material::History<'_, 's, S::Document, S::Generation>,
        operation: &W,
    ) -> RequirementsRead<'a, 's, S::Document, S::Generation, S::Error> {
        let bound = basic.binding();
        let mapping = bound.mapping;
        let prepared = bound.prepared();
        let root = prepared.container.signature();
        let location = root.location();
        let work = self.session.query(operation);
        if mapping.snapshot != self.stamp.snapshot
            || !core::ptr::eq(root.owner().value.session, self.session)
            || history.root.location() != root.location()
            || history.root.owner().value.stamp != self.stamp
            || !core::ptr::eq(history.root.owner().value.session, self.session)
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        self.check(&work, location)?;
        let mut entries = work.vector();
        project_requirements(
            mapping,
            prepared.cms.timestamp_requirements().entries(),
            &mut entries,
            location,
            &work,
        )?;
        let pdf = document_timestamps(root, mapping, &mut entries, &work)?;
        let mut vri = work.vector();
        for window in history.revisions() {
            for (index, value) in window.vri().iter().enumerate() {
                admit(&work, value.location(), 1)?;
                let Some(item) = value.timestamp() else {
                    continue;
                };
                let property = Node::dss(value.location(), window.revision());
                let token = Node::dss(window.items()[item].location(), window.revision());
                entries
                    .try_push(RequiredToken {
                        signature: mapping.root,
                        property,
                        token,
                        purpose: Purpose::ValidationData,
                    })
                    .map_err(|cause| Error {
                        kind: ErrorKind::Resource(cause),
                        location: value.location(),
                    })?;
                vri.try_push(VriTimestamp {
                    ordinal: vri.len(),
                    revision: window.revision(),
                    vri: index,
                    item,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: value.location(),
                })?;
            }
        }
        let mut counters = work.vector();
        let mut kept = work.vector();
        for ordinal in 0..basic.counters().len() {
            admit(&work, location, 1)?;
            let node = basic.counters().counter(ordinal).signature;
            counters.try_push(node).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
            kept.try_push(node).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
        self.check(&work, location)?;
        let all = TimestampRequirements::with_counters(
            ISSUER,
            mapping.root,
            TimestampScope::All(Original {
                snapshot: mapping.snapshot,
                node: mapping.root,
            }),
            entries.into_owned(),
            counters.into_owned(),
            None,
        );
        let total_pdf = pdf.len();
        Ok(Requirements {
            all,
            pdf: pdf.into_owned(),
            counters: kept.into_owned(),
            root,
            revision: None,
            vri: vri.into_owned(),
            total_pdf,
        })
    }
}
