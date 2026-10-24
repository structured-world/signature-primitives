//! Source-produced ODF manifest and OCF rootfile associations.
//!
//! Format inventory is independent of `XMLDSig`, member digests and trust. ODF
//! full-path is a ZIP filename, not an URI to decode or normalize.

use crate::{
    error::Error as ArchiveError,
    zip::{Member, MemberId, Names},
};
use structured_asn1::{
    memory::{MemoryError, OwnedVec, Work},
    range::RangeSource,
};
use structured_cms::stream::{AsyncSource, Receiver, Refused};
use structured_xades::xml::{Access, AccessError, Name, Node, Snapshot, Xml};

/// ODF package manifest namespace, distinct from digital signatures.
pub const ODF: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

/// The selected original package inventory vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// ODF 1.2 manifest:file-entry and its exact ZIP filename.
    Odf,
    /// OCF container/rootfiles/rootfile and its full-path.
    Ocf,
}

/// Every readable negative or explicitly unassessed original instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// Wrong original root, child or non-whitespace character content.
    Structure,
    /// Required original attribute or rootfiles/entry is absent.
    Missing,
    /// Selected schema's version is absent or has a different value.
    Version,
    /// An entry selects no original member or several exact-name occurrences.
    Target,
    /// The same original member or package root is declared repeatedly.
    Duplicate,
    /// ODF forbids declaring mimetype or the manifest itself.
    Forbidden,
    /// An original non-META-INF file has no unique ODF declaration.
    Undeclared,
    /// An original media-type value is not complete MIME syntax.
    Media,
    /// Encryption or extension content is retained but not assessed here.
    Unassessed,
}

/// Located original package instruction or missing member obligation.
#[derive(Debug, Clone, Copy)]
pub struct Fault<N, D, G> {
    /// Actual original XML location, or root for an undeclared member.
    pub node: N,
    /// Actual ZIP occurrence when the obligation identifies one.
    pub member: Option<MemberId<D, G>>,
    /// Independent completed negative/unassessed fact.
    pub kind: FaultKind,
}

/// Original path projection without changing signed filename identity.
pub enum Target<'v, 's, S: RangeSource> {
    /// Required full-path was absent.
    Absent,
    /// ODF's exact "/" package declaration.
    Package,
    /// ODF directories need not have an explicit ZIP directory occurrence.
    Directory(OwnedVec<u8>),
    /// Every exact original candidate, including zero or multiple occurrences.
    Members(Names<'v, 's, S>),
}

/// Every original declaration, not just successful unique members.
pub struct Entry<'v, 's, N, S: RangeSource> {
    node: N,
    target: Target<'v, 's, S>,
    media: Option<OwnedVec<u8>>,
}
impl<'v, 's, N: Copy, S: RangeSource> Entry<'v, 's, N, S> {
    /// Actual original declaration location.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original path projection, without URI or Unicode normalization.
    #[must_use]
    pub fn target(&self) -> &Target<'v, 's, S> {
        &self.target
    }
    /// XML-normalized original media-type, preserving absent versus empty.
    #[must_use]
    pub fn media_type(&self) -> Option<&[u8]> {
        self.media.as_deref()
    }
}

/// Terminal source, owner or resource cause, never a readable format fault.
#[derive(Debug)]
pub enum Error<E, N, SE> {
    /// Original XML source/current operation refused.
    Xml(AccessError<E, N>),
    /// Original archive source/current operation refused.
    Archive(ArchiveError<SE>),
    /// Retained storage/lexical comparison refused before doing the work.
    Resource {
        /// Actual attempted original XML node.
        node: N,
        /// Original admission or allocation refusal.
        cause: MemoryError,
    },
}

/// Inventory derived only inside the actual member-producing XML scope.
/// This does not attest complete ODF encryption/extension semantics or signatures.
pub struct Reading<'v, 's, N, D, G, S: RangeSource> {
    source: Member<'v, 's, S>,
    snapshot: Snapshot<D, G>,
    root: N,
    format: Format,
    entries: OwnedVec<Entry<'v, 's, N, S>>,
    faults: OwnedVec<Fault<N, S::Document, S::Generation>>,
}
impl<'v, 's, N: Copy, D: Copy, G: Copy, S: RangeSource> Reading<'v, 's, N, D, G, S> {
    /// Actual complete member from which this XML inventory was produced.
    #[must_use]
    pub fn source(&self) -> &Member<'v, 's, S> {
        &self.source
    }
    /// Actual original XML source and generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Actual whole-document root, preserving its parent context.
    #[must_use]
    pub fn root(&self) -> N {
        self.root
    }
    /// Explicit selected inventory vocabulary.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }
    /// All original declarations in document order.
    #[must_use]
    pub fn entries(&self) -> &[Entry<'v, 's, N, S>] {
        &self.entries
    }
    /// All original negative/unassessed declarations and missing obligations.
    #[must_use]
    pub fn faults(&self) -> &[Fault<N, S::Document, S::Generation>] {
        &self.faults
    }

    /// ODF1.2 part3 §3.3 requires exact equality of the package root's media
    /// attribute with the complete mimetype member. MIME essence equality is
    /// insufficient. Duplicate roots/names remain unavailable, never selected.
    ///
    /// # Panics
    /// An internal immutable name-catalogue invariant fails if its unique
    /// candidate cannot be selected from that same catalogue.
    pub async fn check_root_media<W: Work>(
        &self,
        work: &W,
    ) -> Result<RootMedia, crate::zip::ReadFailure<S::Error, S::Document, S::Generation>> {
        let archive = self.source.archive();
        let execution = archive.session().query(work);
        let failure = |cause| crate::zip::ReadFailure::Processing {
            member: self.source.id(),
            cause,
        };
        archive
            .admit(&execution, self.source.central_span())
            .map_err(failure)?;
        if self.format != Format::Odf {
            return Ok(RootMedia::NotApplicable);
        }
        let names = archive.find(b"mimetype", &execution).map_err(failure)?;
        let mut root = None;
        for entry in &self.entries {
            execution.charge_work(1).map_err(|cause| {
                failure(crate::error::resource(self.source.central_span(), cause))
            })?;
            if matches!(entry.target, Target::Package) {
                if root.is_some() {
                    return Ok(RootMedia::Unavailable);
                }
                root = Some(entry);
            }
        }
        if names.is_empty() && root.is_none() {
            return Ok(RootMedia::Absent);
        }
        if names.len() != 1 {
            return Ok(RootMedia::Unavailable);
        }
        let Some(expected) = root.and_then(Entry::media_type) else {
            return Ok(RootMedia::Unavailable);
        };
        let member = names
            .member(0, &execution)
            .map_err(failure)?
            .expect("one exact original candidate");
        let mut source = member.source(&execution)?;
        let mut receiver = Compare {
            expected,
            at: 0,
            differs: false,
            work: &execution,
            refused: None,
        };
        let result = source.stream(&mut receiver, &execution).await;
        if let Some(cause) = receiver.refused {
            return Err(failure(crate::error::resource(
                member.central_span(),
                cause,
            )));
        }
        result?;
        archive
            .admit(&execution, self.source.central_span())
            .map_err(failure)?;
        Ok(if receiver.differs || receiver.at != expected.len() {
            RootMedia::Differs
        } else {
            RootMedia::Matches
        })
    }
}

/// Exact package media association, independently of container signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootMedia {
    /// This selected vocabulary has no ODF root/mimetype equality rule.
    NotApplicable,
    /// Neither optional package declaration nor mimetype is present.
    Absent,
    /// Missing/ambiguous input or media attribute prevents a unique comparison.
    Unavailable,
    /// Complete original CRC-checked member equals the original media attribute.
    Matches,
    /// Completed exact bytes or lengths differ.
    Differs,
}

struct Compare<'a, W: Work> {
    expected: &'a [u8],
    at: usize,
    differs: bool,
    work: &'a W,
    refused: Option<MemoryError>,
}
impl<W: Work> Receiver for Compare<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
        if self.refused.is_some() {
            return Err(Refused);
        }
        if let Err(cause) = self.work.charge_work(bytes.len() as u64) {
            self.refused = Some(cause);
            return Err(Refused);
        }
        if self.differs {
            return Ok(());
        }
        if bytes.len() > self.expected.len() - self.at {
            self.differs = true;
            return Ok(());
        }
        let end = self.at + bytes.len();
        if self.expected[self.at..end] != *bytes {
            self.differs = true;
        }
        self.at = end;
        Ok(())
    }
}

type ResultOf<T, X, S> =
    Result<T, Error<<X as Xml>::Error, <X as Xml>::Id, <S as RangeSource>::Error>>;

/// Complete source-produced package reading or original processing refusal.
pub type InspectionResult<'v, 's, X, S> = ResultOf<
    Reading<'v, 's, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, S>,
    X,
    S,
>;

#[expect(
    clippy::too_many_lines,
    reason = "ODF and OCF share one ordered inventory walk and duplicate map; splitting the closure would obscure which exact source declarations discharge the aggregate census"
)]
pub(crate) fn inspect<'v, 's, X: Xml, S: RangeSource, W: Work>(
    base: Member<'v, 's, S>,
    access: &Access<'_, X, W>,
    root: X::Id,
    format: Format,
) -> InspectionResult<'v, 's, X, S> {
    let work = access.execution();
    let archive = base.archive();
    archive
        .admit(work, base.central_span())
        .map_err(Error::Archive)?;
    let namespace = match format {
        Format::Odf => ODF,
        Format::Ocf => crate::xml::OCF,
    };
    let has_name = |node, local| {
        access
            .has_name(node, Name { namespace, local })
            .map_err(Error::Xml)
    };
    let mut faults = work.vector();
    let mut entries = work.vector();
    let refusal = |cause| Error::Resource { node: root, cause };
    let fault = |faults: &mut OwnedVec<_, _>, node, member, kind| {
        faults
            .try_push(Fault { node, member, kind })
            .map_err(refusal)
    };
    let root_name = match format {
        Format::Odf => "manifest",
        Format::Ocf => "container",
    };
    if !has_name(root, root_name)? {
        fault(&mut faults, root, None, FaultKind::Structure)?;
    }
    let version_namespace = if format == Format::Odf { ODF } else { "" };
    let valid = access
        .attribute(
            root,
            Name {
                namespace: version_namespace,
                local: "version",
            },
            |value| {
                let Some(value) = value else {
                    return Ok(false);
                };
                work.charge_work(value.len() as u64)?;
                Ok(value.trim_matches([' ', '\t', '\r', '\n'])
                    == if format == Format::Odf { "1.2" } else { "1.0" })
            },
        )
        .map_err(Error::Xml)?
        .map_err(refusal)?;
    if !valid {
        fault(&mut faults, root, None, FaultKind::Version)?;
    }
    let mut parents = work.vector();
    if format == Format::Ocf {
        let mut groups = 0usize;
        walk::<X, S, W>(access, root, |node, element| {
            if element && has_name(node, "rootfiles")? {
                groups += 1;
                parents.try_push(node).map_err(refusal)
            } else {
                fault(&mut faults, node, None, FaultKind::Structure)
            }
        })?;
        if groups != 1 {
            fault(
                &mut faults,
                root,
                None,
                if groups == 0 {
                    FaultKind::Missing
                } else {
                    FaultKind::Duplicate
                },
            )?;
        }
    } else {
        parents.try_push(root).map_err(refusal)?;
    }
    let mut declared = work.map();
    let mut package = false;
    for parent in parents {
        walk::<X, S, W>(access, parent, |node, element| {
            let entry_name = if format == Format::Odf {
                "file-entry"
            } else {
                "rootfile"
            };
            if !element || !has_name(node, entry_name)? {
                return fault(&mut faults, node, None, FaultKind::Structure);
            }
            let attr_namespace = if format == Format::Odf { ODF } else { "" };
            // ODF1.2 part3 §4.8.4 defines a ZIP filename, not an IRI. In
            // particular a percent sign is literal and must not be decoded.
            // https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html
            let target = access
                .attribute(
                    node,
                    Name {
                        namespace: attr_namespace,
                        local: "full-path",
                    },
                    |value| {
                        let Some(value) = value else {
                            return Ok(Target::Absent);
                        };
                        work.charge_work(value.len() as u64)
                            .map_err(|cause| Error::Resource { node, cause })?;
                        if value == "/" && format == Format::Odf {
                            return Ok(Target::Package);
                        }
                        if value.ends_with('/') && format == Format::Odf {
                            let mut path = work.vector();
                            path.try_extend_from_slice(value.as_bytes())
                                .map_err(|cause| Error::Resource { node, cause })?;
                            return Ok(Target::Directory(path.into_owned()));
                        }
                        archive
                            .find(value.as_bytes(), work)
                            .map(Target::Members)
                            .map_err(Error::Archive)
                    },
                )
                .map_err(Error::Xml)??;
            match &target {
                Target::Absent => fault(&mut faults, node, None, FaultKind::Missing)?,
                Target::Package => {
                    if package {
                        fault(&mut faults, node, None, FaultKind::Duplicate)?;
                    }
                    package = true;
                }
                Target::Members(names) => {
                    if names.len() != 1 {
                        fault(&mut faults, node, None, FaultKind::Target)?;
                    }
                    for ordinal in 0..names.len() {
                        let member = names
                            .member(ordinal, work)
                            .map_err(Error::Archive)?
                            .expect("exact-name candidate count bounds its ordinal");
                        if declared
                            .try_insert(member.id().ordinal(), ())
                            .map_err(refusal)?
                            .is_some()
                        {
                            fault(&mut faults, node, Some(member.id()), FaultKind::Duplicate)?;
                        }
                        if format == Format::Odf
                            && (member.name() == b"mimetype"
                                || member.name() == b"META-INF/manifest.xml")
                        {
                            fault(&mut faults, node, Some(member.id()), FaultKind::Forbidden)?;
                        }
                    }
                }
                Target::Directory(_) => {}
            }
            let media = access
                .attribute(
                    node,
                    Name {
                        namespace: attr_namespace,
                        local: "media-type",
                    },
                    |value| {
                        let Some(value) = value else {
                            return Ok(None);
                        };
                        let mut bytes = work.vector();
                        bytes.try_extend_from_slice(value.as_bytes())?;
                        Ok(Some(bytes.into_owned()))
                    },
                )
                .map_err(Error::Xml)?
                .map_err(refusal)?;
            match &media {
                None => fault(&mut faults, node, None, FaultKind::Missing)?,
                Some(bytes) if !bytes.is_empty() => {
                    let mut syntax = structured_cms::mime::Syntax::<true>::new();
                    let text = core::str::from_utf8(bytes).expect("XML attribute bytes are UTF-8");
                    syntax.feed(text, work).map_err(refusal)?;
                    if !syntax.complete() {
                        fault(&mut faults, node, None, FaultKind::Media)?;
                    }
                }
                Some(_) => {}
            }
            walk::<X, S, W>(access, node, |child, element| {
                fault(
                    &mut faults,
                    child,
                    None,
                    if element {
                        FaultKind::Unassessed
                    } else {
                        FaultKind::Structure
                    },
                )
            })?;
            entries
                .try_push(Entry {
                    node,
                    target,
                    media,
                })
                .map_err(refusal)
        })?;
    }
    if entries.is_empty() {
        fault(&mut faults, root, None, FaultKind::Missing)?;
    }
    if format == Format::Odf {
        // ODF1.2 part3 §3.2 excludes mimetype and META-INF, but every other
        // original file requires exactly one declaration. ZIP directory entries
        // represent folders rather than files and do not acquire that obligation.
        for ordinal in 0..archive.len() {
            let member = archive
                .member(ordinal, work)
                .map_err(Error::Archive)?
                .expect("archive length bounds member ordinal");
            let name = member.name();
            work.charge_work(name.len() as u64).map_err(refusal)?;
            if name == b"mimetype" {
                if !package {
                    fault(&mut faults, root, Some(member.id()), FaultKind::Missing)?;
                }
            } else if !name.starts_with(b"META-INF/")
                && !name.ends_with(b"/")
                && declared.get(&ordinal, work).map_err(refusal)?.is_none()
            {
                fault(&mut faults, root, Some(member.id()), FaultKind::Undeclared)?;
            }
        }
    }
    access.inspect(root, |_| ()).map_err(Error::Xml)?;
    archive
        .admit(work, base.central_span())
        .map_err(Error::Archive)?;
    Ok(Reading {
        source: base,
        snapshot: access.snapshot(),
        root,
        format,
        entries: entries.into_owned(),
        faults: faults.into_owned(),
    })
}

fn walk<X: Xml, S: RangeSource, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    mut visit: impl FnMut(X::Id, bool) -> ResultOf<(), X, S>,
) -> ResultOf<(), X, S> {
    let mut next = access.first_child(parent).map_err(Error::Xml)?;
    while let Some(node) = next {
        next = access.next_sibling(parent, node).map_err(Error::Xml)?;
        let kind = access
            .inspect(node, |value| match value {
                Node::Element(_) => Ok(Some(true)),
                Node::Other => Ok(None),
                Node::Text(text) => {
                    access.execution().charge_work(text.len() as u64)?;
                    Ok(
                        if text
                            .bytes()
                            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                        {
                            None
                        } else {
                            Some(false)
                        },
                    )
                }
            })
            .map_err(Error::Xml)?
            .map_err(|cause| Error::Resource { node, cause })?;
        if let Some(element) = kind {
            visit(node, element)?;
        }
    }
    Ok(())
}
