//! Immutable ZIP occurrences and bounded original-member acquisition.

use crate::{
    Session,
    error::{Error, resource},
};
use structured_asn1::{
    Span,
    memory::{OwnedVec, Work},
    range::{RangeSource, Stamp, Window},
};

mod directory;
mod framing;
mod stream;
pub use stream::{Acquisition, Integrity, ReadFailure, Source};

/// One original central-directory ordinal, bound to its immutable source view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberId<D, G> {
    stamp: Stamp<D, G>,
    ordinal: usize,
}
impl<D: Copy, G: Copy> MemberId<D, G> {
    /// Original central-directory position, never sorted-name position.
    #[must_use]
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    /// Original source identity, generation and exact length.
    #[must_use]
    pub fn stamp(&self) -> Stamp<D, G> {
        self.stamp
    }
}

/// A readable negative original fact. No invalid occurrence is filtered out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// Original name/comment is not UTF-8, as required by EN319162-1 §4.2.
    Utf8,
    /// A name is empty, absolute, or has a drive/device/backslash component.
    Name,
    /// Identical original names identify several member occurrences.
    DuplicateName,
    /// Local and central metadata do not describe the same member.
    LocalMismatch,
    /// A descriptor is missing or disagrees with the central entry.
    Descriptor,
    /// Original member enclosures overlap, including duplicate local offsets.
    Overlap,
    /// A local enclosure cannot be bounded before the central directory.
    LocalBounds,
    /// Stored compression has unequal compressed/uncompressed lengths.
    StoredLength,
    /// Entry uses encryption, independently of any claimed `ASiC` profile.
    Encrypted,
    /// This compression method is unavailable to the decoder.
    Compression,
    /// ISO21320 excludes the original flags/version needed for extraction.
    IsoProfile,
    /// A ZIP64 optional record is duplicate, missing or structurally invalid.
    Zip64,
    /// A Unicode path extra field disagrees with the original name.
    UnicodeName,
    /// A central-directory signature is outside the ISO21320 profile.
    DirectorySignature,
}

/// One original negative fact, retaining its exact physical location.
#[derive(Debug, Clone, Copy)]
pub struct Fault {
    /// Original member ordinal; None denotes archive-level metadata.
    pub member: Option<usize>,
    /// Original physical enclosure.
    pub range: Span,
    /// Independent negative fact.
    pub kind: FaultKind,
}

#[derive(Clone, Copy)]
struct Bytes {
    start: usize,
    length: usize,
}
impl Bytes {
    fn get(self, values: &[u8]) -> &[u8] {
        &values[self.start..self.start + self.length]
    }
}

struct Entry {
    central: Span,
    name_span: Span,
    extra: Span,
    comment: Span,
    name: Bytes,
    needed: u16,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: u64,
    decoded: u64,
    local: u64,
    local_extra: Option<Span>,
    data: Option<Span>,
    enclosure: Option<Span>,
    zip64: bool,
    readable: bool,
    disk: u32,
    unicode: Option<Span>,
    overlap: bool,
}

/// Complete original central-directory census. Names occupy one pooled buffer;
/// entry order is never replaced by a map's unique-name interpretation.
pub struct Archive<'s, S: RangeSource> {
    source: &'s S,
    session: &'s Session,
    stamp: Stamp<S::Document, S::Generation>,
    directory: Span,
    comment: Span,
    entries: OwnedVec<Entry>,
    names: OwnedVec<u8>,
    order: OwnedVec<usize>,
    faults: OwnedVec<Fault>,
}

/// A selected original occurrence; construction checks its immutable archive.
pub struct Member<'view, 'source, S: RangeSource> {
    archive: &'view Archive<'source, S>,
    ordinal: usize,
}

impl<'s, S: RangeSource> Archive<'s, S> {
    pub(crate) fn session(&self) -> &'s Session {
        self.session
    }
    /// Reads original ZIP/ZIP64 metadata under source AND current execution.
    /// No payload is inflated and no filesystem path is acquired.
    pub async fn read<W: Work>(
        source: &'s S,
        session: &'s Session,
        work: &W,
    ) -> Result<Self, Error<S::Error>> {
        directory::read(source, session, work).await
    }
    /// Immutable source metadata captured before directory acquisition.
    #[must_use]
    pub fn stamp(&self) -> Stamp<S::Document, S::Generation> {
        self.stamp
    }
    pub(crate) fn unchanged(&self) -> bool {
        self.source.stamp() == self.stamp
    }
    /// Number of original occurrences, including duplicates and invalid entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether the original directory contains no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Original archive comment bytes, distinct from a filename/MIME hint.
    #[must_use]
    pub fn comment_span(&self) -> Span {
        self.comment
    }
    /// Original directory enclosure.
    #[must_use]
    pub fn directory_span(&self) -> Span {
        self.directory
    }

    pub(crate) fn admit<W: Work>(&self, work: &W, range: Span) -> Result<(), Error<S::Error>> {
        self.session
            .query(work)
            .charge_work(1)
            .map_err(|cause| resource(range, cause))?;
        if self.source.stamp() != self.stamp {
            return Err(structured_asn1::range::InputError::Changed { range }.into());
        }
        Ok(())
    }

    /// Selects by original ordinal after current/source admission. No lookup
    /// chooses one copy of a duplicated name or drops malformed occurrences.
    pub fn member<W: Work>(
        &self,
        ordinal: usize,
        work: &W,
    ) -> Result<Option<Member<'_, 's, S>>, Error<S::Error>> {
        self.admit(work, self.directory)?;
        if ordinal >= self.entries.len() {
            return Ok(None);
        }
        Ok(Some(Member {
            archive: self,
            ordinal,
        }))
    }
    /// Selects an existing ID only within its exact original source view.
    pub fn original<W: Work>(
        &self,
        id: MemberId<S::Document, S::Generation>,
        work: &W,
    ) -> Result<Member<'_, 's, S>, Error<S::Error>> {
        self.admit(work, self.directory)?;
        if id.stamp != self.stamp || id.ordinal >= self.entries.len() {
            return Err(Error::Foreign {
                range: self.directory,
            });
        }
        Ok(Member {
            archive: self,
            ordinal: id.ordinal,
        })
    }
    /// Visits every negative fact in original discovery order under this query.
    /// Refusal is returned once and permanently fuses traversal.
    pub fn faults<'v, 'q, W: Work>(
        &'v self,
        work: &'q W,
    ) -> crate::error::SourceResult<
        impl Iterator<Item = Result<Fault, Error<S::Error>>> + use<'v, 'q, 's, S, W>,
        S,
    > {
        self.admit(work, self.directory)?;
        let mut at = 0;
        let mut refused = false;
        Ok(core::iter::from_fn(move || {
            if refused || at == self.faults.len() {
                return None;
            }
            if let Err(cause) = self.admit(work, self.directory) {
                refused = true;
                return Some(Err(cause));
            }
            let value = self.faults[at];
            at += 1;
            Some(Ok(value))
        }))
    }

    /// Exact original-name lookup. The result keeps the complete duplicate
    /// range; no Unicode/case normalization or filesystem interpretation occurs.
    pub fn find<W: Work>(
        &self,
        name: &[u8],
        work: &W,
    ) -> Result<Names<'_, 's, S>, Error<S::Error>> {
        self.admit(work, self.directory)?;
        let execution = self.session.query(work);
        let mut lo = 0;
        let mut hi = self.order.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let other = self.entries[self.order[mid]].name.get(&self.names);
            execution
                .charge_work(other.len().min(name.len()) as u64 + 1)
                .map_err(|cause| resource(self.directory, cause))?;
            if other < name {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let first = lo;
        hi = self.order.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let other = self.entries[self.order[mid]].name.get(&self.names);
            execution
                .charge_work(other.len().min(name.len()) as u64 + 1)
                .map_err(|cause| resource(self.directory, cause))?;
            if other <= name {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(Names {
            archive: self,
            first,
            end: lo,
        })
    }

    fn window<'q, W: Work>(
        &'q self,
        work: &'q W,
        bounds: Span,
    ) -> Result<Window<'q, S>, Error<S::Error>> {
        Ok(Window::new(
            self.source,
            self.stamp,
            bounds,
            self.session.query(work),
        )?)
    }
}

/// Complete exact-name candidate range, independent of whether a member is usable.
pub struct Names<'view, 'source, S: RangeSource> {
    archive: &'view Archive<'source, S>,
    first: usize,
    end: usize,
}
impl<'v, 's, S: RangeSource> Names<'v, 's, S> {
    /// Number of distinct original occurrences with this exact name.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.first
    }
    /// Whether no exact original name was present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.first == self.end
    }
    /// Retrieves one original candidate, never a normalized replacement.
    pub fn member<W: Work>(
        &self,
        ordinal: usize,
        work: &W,
    ) -> Result<Option<Member<'v, 's, S>>, Error<S::Error>> {
        self.archive.admit(work, self.archive.directory)?;
        if ordinal >= self.len() {
            return Ok(None);
        }
        Ok(Some(Member {
            archive: self.archive,
            ordinal: self.archive.order[self.first + ordinal],
        }))
    }
}

impl<S: RangeSource> Member<'_, '_, S> {
    fn entry(&self) -> &Entry {
        &self.archive.entries[self.ordinal]
    }
    /// Immutable identity of this original occurrence.
    #[must_use]
    pub fn id(&self) -> MemberId<S::Document, S::Generation> {
        MemberId {
            stamp: self.archive.stamp,
            ordinal: self.ordinal,
        }
    }
    /// Untouched original filename bytes, including invalid UTF-8.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.entry().name.get(&self.archive.names)
    }
    /// Original central-directory enclosure.
    #[must_use]
    pub fn central_span(&self) -> Span {
        self.entry().central
    }
    /// Original physical filename enclosure.
    #[must_use]
    pub fn name_span(&self) -> Span {
        self.entry().name_span
    }
    /// Original declared compression method.
    #[must_use]
    pub fn method(&self) -> u16 {
        self.entry().method
    }
    /// Original ZIP general-purpose flags.
    #[must_use]
    pub fn flags(&self) -> u16 {
        self.entry().flags
    }
    /// Original required extraction version.
    #[must_use]
    pub fn version_needed(&self) -> u16 {
        self.entry().needed
    }
    /// Original compressed payload extent, if it can be bounded unambiguously.
    #[must_use]
    pub fn data_span(&self) -> Option<Span> {
        self.entry().data
    }
    /// Original complete local record, including its actual descriptor.
    #[must_use]
    pub fn local_span(&self) -> Option<Span> {
        self.entry().enclosure
    }
    /// Original local-header extra fields, independently of central extras.
    #[must_use]
    pub fn local_extra_span(&self) -> Option<Span> {
        self.entry().local_extra
    }
    /// Declared decoded length. Successful acquisition independently checks it.
    #[must_use]
    pub fn decoded_length(&self) -> u64 {
        self.entry().decoded
    }
}

impl<'v, 's, S: RangeSource> Member<'v, 's, S> {
    pub(crate) fn archive(&self) -> &'v Archive<'s, S> {
        self.archive
    }
    pub(crate) fn session(&self) -> &'s Session {
        self.archive.session
    }
}
