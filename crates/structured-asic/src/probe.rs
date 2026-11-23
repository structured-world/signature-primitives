//! Bounded physical-format evidence over an immutable original byte source.
//!
//! The probe runs before format verification. It reads no filesystem path or
//! external reference and never consumes filename or transport MIME metadata.

mod acquire;
mod framing;
mod package;
mod xml;

use crate::{Session, error};
use structured_asn1::{
    Span,
    memory::{MemoryError, OwnedText, OwnedVec, Work},
    range::{InputError, RangeSource, Stamp},
};

/// Physical format or package subtype. ZIP and a subtype may both be present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Format {
    /// Portable Document Format.
    Pdf,
    /// CMS `ContentInfo` with the `SignedData` content type.
    CmsSignedData,
    /// XML markup.
    Xml,
    /// ZIP or ZIP64.
    Zip,
    /// Associated Signature Container with subtype still to be established.
    Asic,
    /// Simple Associated Signature Container.
    AsicS,
    /// Extended Associated Signature Container.
    AsicE,
    /// `OpenDocument` package.
    Odf,
    /// Office Open XML package.
    Ooxml,
    /// Portable Network Graphics.
    Png,
    /// JPEG interchange codestream.
    Jpeg,
    /// Graphics Interchange Format, 1987 edition.
    Gif87a,
    /// Graphics Interchange Format, 1989 edition.
    Gif89a,
    /// Classic little-endian TIFF.
    TiffLittleEndian,
    /// Classic big-endian TIFF.
    TiffBigEndian,
    /// WebP in a RIFF container.
    WebP,
    /// Windows bitmap.
    Bmp,
}

impl Format {
    /// Stable machine-readable format or subtype code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::CmsSignedData => "cms-signed-data",
            Self::Xml => "xml",
            Self::Zip => "zip",
            Self::Asic => "asic",
            Self::AsicS => "asic-s",
            Self::AsicE => "asic-e",
            Self::Odf => "odf",
            Self::Ooxml => "ooxml",
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Gif87a => "gif87a",
            Self::Gif89a => "gif89a",
            Self::TiffLittleEndian => "tiff-le",
            Self::TiffBigEndian => "tiff-be",
            Self::WebP => "webp",
            Self::Bmp => "bmp",
        }
    }

    const fn is_zip(self) -> bool {
        matches!(
            self,
            Self::Zip | Self::Asic | Self::AsicS | Self::AsicE | Self::Odf | Self::Ooxml
        )
    }
}

/// Strength or negative result of one candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Finding {
    /// The format's bounded structural evidence was read.
    Framing,
    /// A marker was found and its structure was incomplete or outside the probe extent.
    Incomplete,
    /// The configured inspection extent left relevant original structure unread.
    Uninspected,
    /// The markers disagree or are malformed.
    Conflicting,
    /// Several original records compete for one format decision.
    Ambiguous,
    /// Recognized framing requires an unsupported encoding or capability.
    Unsupported,
}

/// One candidate with its primary original marker or member range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Candidate format or ZIP subtype.
    pub format: Format,
    /// Bounded finding, which does not claim complete format conformance.
    pub finding: Finding,
    /// Original physical range bearing this evidence.
    pub range: Span,
}

/// Effective namespace of the bounded root opening tag.
#[derive(Debug)]
pub enum Namespace {
    /// Unread declarations, DTD subsets or entities prevent an answer.
    Unknown,
    /// The unprefixed root has no namespace.
    None,
    /// The namespace established by the read opening tag.
    Uri(OwnedText),
}

/// Caller-selected acquisition and bounded inspection limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum number of requested bytes across all original range calls.
    pub bytes: u64,
    /// Maximum number of original range calls, including short reads.
    pub reads: u64,
    /// Maximum prefix examined for standalone formats, including the XML prologue.
    pub prefix: usize,
    /// Maximum PDF footer search length.
    pub pdf_suffix: usize,
    /// Maximum decoded bytes per selected ZIP metadata member.
    pub metadata: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 512 * 1024,
            reads: 4096,
            prefix: 4096,
            pdf_suffix: 4096,
            metadata: 32 * 1024,
        }
    }
}

/// A refusal produced by the bounded original-range adapter.
#[derive(Debug)]
pub enum Acquisition<E> {
    /// The original acquisition cause.
    Source(E),
    /// The cumulative requested-byte ceiling refused this read.
    Bytes,
    /// The cumulative read-count ceiling refused this read.
    Reads,
    /// The source changed before an original range could be dispatched.
    Changed,
}

/// Terminal processing error. Negative format findings stay in the report.
#[derive(Debug)]
pub enum Error<E> {
    /// Located source, snapshot or work failure.
    Input(InputError<Acquisition<E>>),
    /// Original ZIP processing or configured mechanism limit refusal.
    Zip(error::Error<Acquisition<E>>),
    /// Original memory or work refusal in a format probe.
    Resource {
        /// Range under inspection.
        range: Span,
        /// Original refusal.
        cause: MemoryError,
    },
}

/// Immutable source identity, candidates, and actual successful acquisitions.
#[derive(Debug)]
pub struct Report<D, G> {
    stamp: Stamp<D, G>,
    candidates: OwnedVec<Candidate>,
    ranges: OwnedVec<Span>,
    root_namespace: Option<Namespace>,
    ambiguous: bool,
}

impl<D: Copy, G: Copy> Report<D, G> {
    /// Original source identity, generation and length.
    #[must_use]
    pub fn stamp(&self) -> Stamp<D, G> {
        self.stamp
    }

    /// Candidates in discovery order. An empty list is unknown.
    #[must_use]
    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    /// Actual returned ranges in acquisition order, including repeated reads.
    #[must_use]
    pub fn ranges(&self) -> &[Span] {
        &self.ranges
    }

    /// Root namespace evidence, if the XML probe reached a root name.
    #[must_use]
    pub fn root_namespace(&self) -> Option<&Namespace> {
        self.root_namespace.as_ref()
    }

    /// More than one confirmed independent format or incompatible ZIP subtype.
    #[must_use]
    pub fn is_ambiguous(&self) -> bool {
        self.ambiguous
    }
}

/// Type-preserving result of a probe using a caller's range source.
pub type ResultOf<S> = Result<
    Report<<S as RangeSource>::Document, <S as RangeSource>::Generation>,
    Error<<S as RangeSource>::Error>,
>;

/// Detects every supported candidate visible within the configured inspection.
///
/// A framing finding does not imply successful parsing, signature validation,
/// or the absence of additional formats outside the inspected ranges. The `ASiC`
/// session provides original ceilings, including ZIP entry and decoded limits.
/// The supplied operation is charged cumulatively with the original source.
pub async fn read<S: RangeSource, W: Work>(
    source: &S,
    session: &Session,
    work: &W,
    limits: Limits,
) -> ResultOf<S> {
    let execution = session.query(work);
    let access = acquire::Source::new(source, limits, execution);
    let stamp = access.original_stamp();
    let count = stamp.length.min(limits.prefix as u64);
    let prefix_range = Span {
        start: 0,
        length: count,
    };
    let prefix = access.read(prefix_range, &execution).await?;
    let mut candidates = execution.vector();
    let mut root_namespace = None;
    charge(&execution, prefix_range, 8)?;
    if let Some(candidate) = framing::pdf(&access, &prefix, limits, &execution).await? {
        record(&mut candidates, candidate)?;
    }
    for candidate in framing::prefix(&prefix, stamp.length).into_iter().flatten() {
        record(&mut candidates, candidate)?;
    }
    if let Some((candidate, namespace)) = xml::probe(&prefix, &execution)? {
        root_namespace = namespace;
        record(&mut candidates, candidate)?;
    }
    package::probe(
        &access,
        session,
        &execution,
        limits,
        &prefix,
        &mut candidates,
    )
    .await?;
    access.check(Span {
        start: 0,
        length: 0,
    })?;
    execution
        .charge_work(candidates.len() as u64)
        .map_err(|cause| Error::Resource {
            range: prefix_range,
            cause,
        })?;
    let ambiguous = ambiguity(&candidates);
    Ok(Report {
        stamp,
        candidates: candidates.into_owned(),
        ranges: access.ranges(),
        root_namespace,
        ambiguous,
    })
}

fn ambiguity(candidates: &[Candidate]) -> bool {
    let mut standalone = 0_u32;
    let mut zip = 0_u32;
    for candidate in candidates {
        if candidate.finding == Finding::Ambiguous {
            return true;
        }
        if candidate.finding != Finding::Framing {
            continue;
        }
        let bit = 1 << candidate.format as u32;
        if candidate.format.is_zip() {
            zip |= bit;
        } else {
            standalone |= bit;
        }
    }
    if standalone.count_ones() + u32::from(zip != 0) > 1 {
        return true;
    }
    let asic_subtypes = (1 << Format::AsicS as u32) | (1 << Format::AsicE as u32);
    zip &= !(1 << Format::Zip as u32);
    if zip & asic_subtypes != 0 {
        zip &= !(1 << Format::Asic as u32);
    }
    zip.count_ones() > 1
}

fn charge<E>(work: &impl Work, range: Span, factor: u64) -> Result<(), Error<E>> {
    let cause = |cause| Error::Resource { range, cause };
    let cost = range
        .length
        .checked_mul(factor)
        .and_then(|cost| cost.checked_add(1))
        .ok_or_else(|| cause(MemoryError::WorkExceeded))?;
    work.charge_work(cost).map_err(cause)
}

fn record<E>(
    candidates: &mut OwnedVec<Candidate, impl Work>,
    candidate: Candidate,
) -> Result<(), Error<E>> {
    candidates
        .try_push(candidate)
        .map_err(|cause| Error::Resource {
            range: candidate.range,
            cause,
        })
}
