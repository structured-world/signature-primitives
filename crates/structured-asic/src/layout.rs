//! Complete original member roles, without claiming cryptography from a name.

use crate::{
    error::{Error, resource},
    zip::{Archive, Member, MemberId},
};
use structured_asn1::{
    Span,
    memory::{OwnedVec, Work},
    range::RangeSource,
};

mod assess;
pub use assess::{Form, Inspection, Issue, Principal, Requirement, Rules, Strength};

/// Original filename role. A matching filename never proves readable content,
/// schema validity, signed coverage, a signature result or a baseline level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// An explicit ZIP directory occurrence, not an implied additional data file.
    Directory,
    /// The exact root-level `mimetype` member.
    Mimetype,
    /// A file outside the original root META-INF directory.
    Data,
    /// A potential `CAdES` file matching the normative naming pattern.
    Cades,
    /// A potential XML signature file, with its original parent context intact.
    Xades,
    /// A potential RFC3161 token file.
    Timestamp,
    /// A potential ASN.1 RFC4998 record file.
    Evidence,
    /// A named XMLERS record, retained even when its mechanism is unavailable.
    XmlEvidence,
    /// A potential ordinary `ASiCManifest`.
    Manifest,
    /// A potential `ASiCArchiveManifest`.
    ArchiveManifest,
    /// A potential `ASiCEvidenceRecordManifest`.
    EvidenceManifest,
    /// The original ODF package manifest.
    OdfManifest,
    /// The original OCF rootfile manifest.
    OcfContainer,
    /// Other application-specific metadata without reserved keywords.
    Application,
    /// Metadata with reserved naming that matches no supported format role.
    Reserved,
}

/// Independent original mimetype-header facts. Content and media-type binding
/// are checked against the actual acquired member, not these filenames.
#[derive(Debug, Clone, Copy)]
pub struct MimetypeHeader<D, G> {
    /// Exact original occurrence; duplicate names produce separate records.
    pub member: MemberId<D, G>,
    /// Actual physical local-record enclosure, if independently bounded.
    pub local: Option<Span>,
    flags: u8,
}
impl<D, G> MimetypeHeader<D, G> {
    /// It is physically first at original offset zero, regardless of CD order.
    #[must_use]
    pub fn first(&self) -> bool {
        self.flags & 1 != 0
    }
    /// Original compression method is STORED.
    #[must_use]
    pub fn stored(&self) -> bool {
        self.flags & 2 != 0
    }
    /// Original local header contains exactly zero extra bytes.
    #[must_use]
    pub fn no_extra(&self) -> bool {
        self.flags & 4 != 0
    }
    /// Original flags do not request ZIP encryption.
    #[must_use]
    pub fn unencrypted(&self) -> bool {
        self.flags & 8 != 0
    }
}

/// One paid original occurrence and its unchanged processing cause.
pub type OccurrenceResult<'v, 's, S> =
    crate::error::SourceResult<Option<(Member<'v, 's, S>, Role)>, S>;
type HeaderResult<S> = crate::error::SourceResult<
    MimetypeHeader<<S as RangeSource>::Document, <S as RangeSource>::Generation>,
    S,
>;

/// Retains every original member role in CD order, including duplicates,
/// reserved names and unreadable members. One pooled name buffer remains in
/// the archive; this catalogue stores only fixed-size classifications.
pub struct Census<'v, 's, S: RangeSource> {
    archive: &'v Archive<'s, S>,
    roles: OwnedVec<Role>,
    mimetypes: OwnedVec<MimetypeHeader<S::Document, S::Generation>>,
}

impl<'v, 's, S: RangeSource> Census<'v, 's, S> {
    /// Performs a paid metadata pass under both the source and current query.
    ///
    /// # Panics
    /// An internal catalogue invariant fails if a bounded original ordinal is absent.
    pub fn read<W: Work>(archive: &'v Archive<'s, S>, work: &W) -> Result<Self, Error<S::Error>> {
        archive.admit(work, archive.directory_span())?;
        let execution = archive.session().query(work);
        let mut roles = execution.vector();
        roles
            .try_reserve_exact(archive.len())
            .map_err(|cause| resource(archive.directory_span(), cause))?;
        let mut mimetypes = execution.vector();
        for ordinal in 0..archive.len() {
            let member = archive
                .member(ordinal, work)?
                .expect("bounded original ordinal");
            let execution = member.session().query(work);
            execution
                .charge_work(member.name().len() as u64 * 64 + 1)
                .map_err(|cause| resource(member.name_span(), cause))?;
            let role = classify(member.name());
            if role == Role::Mimetype {
                // EN319162-1 V1.1.1 A.1: local, not central, extra fields
                // determine the fixed physical MIME magic position.
                // https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf
                mimetypes
                    .try_push(MimetypeHeader {
                        member: member.id(),
                        local: member.local_span(),
                        flags: u8::from(member.local_span().is_some_and(|span| span.start == 0))
                            | (u8::from(member.method() == 0) << 1)
                            | (u8::from(
                                member
                                    .local_extra_span()
                                    .is_some_and(|span| span.length == 0),
                            ) << 2)
                            | (u8::from(member.flags() & 0x2041 == 0) << 3),
                    })
                    .map_err(|cause| resource(member.central_span(), cause))?;
            }
            roles
                .try_push(role)
                .map_err(|cause| resource(member.central_span(), cause))?;
        }
        archive.admit(work, archive.directory_span())?;
        Ok(Self {
            archive,
            roles: roles.into_owned(),
            mimetypes: mimetypes.into_owned(),
        })
    }
    /// The complete immutable ZIP occurrence census.
    #[must_use]
    pub fn archive(&self) -> &'v Archive<'s, S> {
        self.archive
    }
    /// Number of original members, never the number of unique names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roles.len()
    }
    /// Whether the original census is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }
    /// Selects one original occurrence and its paid role under this query.
    pub fn occurrence<W: Work>(&self, ordinal: usize, work: &W) -> OccurrenceResult<'v, 's, S> {
        let Some(member) = self.archive.member(ordinal, work)? else {
            return Ok(None);
        };
        Ok(Some((member, self.roles[ordinal])))
    }
    /// Complete mimetype occurrence traversal. Failure fuses this query, and
    /// an absent optional member never becomes a fabricated default media type.
    pub fn mimetypes<'q, W: Work>(
        &'q self,
        work: &'q W,
    ) -> impl Iterator<Item = HeaderResult<S>> + use<'q, 'v, 's, S, W> {
        let mut at = 0;
        let mut stopped = false;
        core::iter::from_fn(move || {
            if stopped || at == self.mimetypes.len() {
                return None;
            }
            if let Err(cause) = self.archive.admit(work, self.archive.directory_span()) {
                stopped = true;
                return Some(Err(cause));
            }
            let value = self.mimetypes[at];
            at += 1;
            Some(Ok(value))
        })
    }
}

fn classify(name: &[u8]) -> Role {
    if name.ends_with(b"/") {
        return Role::Directory;
    }
    if name == b"mimetype" {
        return Role::Mimetype;
    }
    let Some(relative) = name.strip_prefix(b"META-INF/") else {
        return Role::Data;
    };
    if relative == b"manifest.xml" {
        return Role::OdfManifest;
    }
    if relative == b"container.xml" {
        return Role::OcfContainer;
    }
    if relative.ends_with(b".xml") {
        // Annex A.7(2a) permits an arbitrary prefix when the previous latest
        // manifest is renamed: META-INF/*ASiCArchiveManifest*.xml.
        if contains(relative, b"ASiCArchiveManifest") {
            return Role::ArchiveManifest;
        }
        if relative.starts_with(b"ASiCEvidenceRecordManifest") {
            return Role::EvidenceManifest;
        }
        if relative.starts_with(b"ASiCManifest") {
            return Role::Manifest;
        }
        if contains(relative, b"evidencerecord") {
            return Role::XmlEvidence;
        }
        if contains(relative, b"signatures") {
            return Role::Xades;
        }
    }
    if relative.ends_with(b".p7s") && contains(relative, b"signature") {
        return Role::Cades;
    }
    if relative.ends_with(b".tst") && contains(relative, b"timestamp") {
        return Role::Timestamp;
    }
    if relative.ends_with(b".ers") && contains(relative, b"evidencerecord") {
        return Role::Evidence;
    }
    // EN319162-1 §4.4.3.2(5d) alone uses case-insensitive reserved words.
    // This rule must not case-fold actual member or signed reference identity.
    for word in [
        b"signature".as_slice(),
        b"timestamp",
        b"manifest",
        b"container.xml",
    ] {
        if relative
            .windows(word.len())
            .any(|part| part.eq_ignore_ascii_case(word))
        {
            return Role::Reserved;
        }
    }
    Role::Application
}

fn contains(name: &[u8], word: &[u8]) -> bool {
    name.windows(word.len()).any(|part| part == word)
}
