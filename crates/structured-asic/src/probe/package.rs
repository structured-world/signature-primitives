mod markup;

use super::{
    Acquisition, Candidate, Error, Finding, Format, Limits, acquire::Source, charge, record,
};
use crate::{
    Session,
    error::{Error as ZipError, Syntax},
    layout::{Role, classify},
    uri,
    zip::{Archive, FaultKind, Member, ReadFailure},
};
use structured_asn1::{
    Span,
    memory::{Execution, OwnedVec},
    range::RangeSource,
};

type ArchiveOf<'a, 's, S> = Archive<'a, Source<'s, S>>;
type MemberOf<'v, 'a, 's, S> = Member<'v, 'a, Source<'s, S>>;

pub(super) async fn probe<S: RangeSource>(
    source: &Source<'_, S>,
    session: &Session,
    work: &Execution<'_>,
    limits: Limits,
    prefix: &[u8],
    candidates: &mut OwnedVec<Candidate, Execution<'_>>,
) -> Result<(), Error<S::Error>> {
    let marker = [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]
        .iter()
        .any(|&magic| {
            prefix.starts_with(magic) || (prefix.len() >= 2 && magic.starts_with(prefix))
        });
    let length = source.original_stamp().length;
    if length < 4 {
        if marker {
            add(
                candidates,
                Format::Zip,
                Finding::Incomplete,
                Span {
                    start: 0,
                    length: prefix.len().min(4) as u64,
                },
            )?;
        }
        return Ok(());
    }
    source.check(Span {
        start: length,
        length: 0,
    })?;
    let archive = match Archive::read(source, session, work).await {
        Ok(archive) => archive,
        Err(ZipError::Syntax {
            range,
            kind: Syntax::End,
        }) if marker => {
            return add(
                candidates,
                Format::Zip,
                Finding::Incomplete,
                Span {
                    start: 0,
                    length: range.length.min(4),
                },
            );
        }
        Err(ZipError::Syntax {
            range,
            kind: Syntax::End,
        }) if range.length == length => return Ok(()),
        Err(ZipError::Syntax {
            range,
            kind: Syntax::AmbiguousDirectory,
        }) => {
            return add(
                candidates,
                Format::Zip,
                Finding::Ambiguous,
                observed(range, length),
            );
        }
        Err(ZipError::Syntax { range, .. }) => {
            let available = observed(range, length);
            let finding = if available.length < range.length && available.length != 0 {
                Finding::Incomplete
            } else {
                Finding::Conflicting
            };
            return add(candidates, Format::Zip, finding, available);
        }
        Err(ZipError::Unsupported { range, .. }) => {
            return add(
                candidates,
                Format::Zip,
                Finding::Unsupported,
                observed(range, length),
            );
        }
        Err(error) => return Err(zip(error)),
    };
    add(
        candidates,
        Format::Zip,
        Finding::Framing,
        Span {
            start: archive.comment_span().start - 22,
            length: 22,
        },
    )?;
    record_zip_faults(&archive, work, candidates)?;
    let asic_role = classify_members(&archive, work)?;
    let mime = mime(&archive, asic_role, limits, work, candidates).await?;
    odf(&archive, mime, limits, work, candidates).await?;
    office(&archive, limits, work, candidates).await
}

fn record_zip_faults<S: RangeSource>(
    archive: &ArchiveOf<'_, '_, S>,
    work: &Execution<'_>,
    candidates: &mut OwnedVec<Candidate, Execution<'_>>,
) -> Result<(), Error<S::Error>> {
    let length = archive.stamp().length;
    for fault in archive.faults(work).map_err(zip)? {
        let fault = fault.map_err(zip)?;
        let finding = match fault.kind {
            FaultKind::Encrypted | FaultKind::Compression => Finding::Unsupported,
            FaultKind::DuplicateName => Finding::Ambiguous,
            FaultKind::LocalMismatch
            | FaultKind::Descriptor
            | FaultKind::Overlap
            | FaultKind::LocalBounds
            | FaultKind::StoredLength
            | FaultKind::Zip64 => Finding::Conflicting,
            _ => continue,
        };
        add(
            candidates,
            Format::Zip,
            finding,
            observed(fault.range, length),
        )?;
    }
    Ok(())
}

fn observed(range: Span, total: u64) -> Span {
    // ZIP errors may locate the attempted record beyond EOF. Only its
    // available intersection is evidence from this immutable input.
    let start = range.start.min(total);
    Span {
        start,
        length: range.length.min(total - start),
    }
}

fn classify_members<S: RangeSource>(
    archive: &ArchiveOf<'_, '_, S>,
    work: &Execution<'_>,
) -> Result<Option<Span>, Error<S::Error>> {
    for index in 0..archive.len() {
        let Some(member) = archive.member(index, work).map_err(zip)? else {
            break;
        };
        let range = member.name_span();
        charge(work, range, 8)?;
        // Names are corroboration when a checked format marker exists.
        if member.data_span().is_some()
            && matches!(
                classify(member.name()),
                Role::Cades
                    | Role::Xades
                    | Role::Timestamp
                    | Role::Evidence
                    | Role::XmlEvidence
                    | Role::Manifest
                    | Role::ArchiveManifest
                    | Role::EvidenceManifest
            )
        {
            return Ok(Some(range));
        }
    }
    Ok(None)
}

enum Selected<M> {
    None,
    Duplicate,
    One(M),
}

fn unique<'v, 'a, 's, S: RangeSource>(
    archive: &'v ArchiveOf<'a, 's, S>,
    name: &[u8],
    format: Format,
    work: &Execution<'_>,
    candidates: &mut OwnedVec<Candidate, Execution<'_>>,
) -> Result<Selected<MemberOf<'v, 'a, 's, S>>, Error<S::Error>> {
    let names = archive.find(name, work).map_err(zip)?;
    match names.len() {
        0 => Ok(Selected::None),
        1 => Ok(names
            .member(0, work)
            .map_err(zip)?
            .map_or(Selected::None, Selected::One)),
        count => {
            for index in 0..count {
                if let Some(member) = names.member(index, work).map_err(zip)? {
                    add(candidates, format, Finding::Ambiguous, member.name_span())?;
                }
            }
            Ok(Selected::Duplicate)
        }
    }
}

async fn mime<S: RangeSource>(
    archive: &ArchiveOf<'_, '_, S>,
    roles: Option<Span>,
    limits: Limits,
    work: &Execution<'_>,
    candidates: &mut OwnedVec<Candidate, Execution<'_>>,
) -> Result<Option<(OdfType, Span)>, Error<S::Error>> {
    let kinds = archive.find(b"mimetype", work).map_err(zip)?;
    if kinds.len() != 1 {
        if let Some(range) = roles {
            add(candidates, Format::Asic, Finding::Incomplete, range)?;
        }
        // Each original conflicting mimetype is retained rather than selecting one.
        for index in 0..kinds.len() {
            if let Some(member) = kinds.member(index, work).map_err(zip)? {
                add(
                    candidates,
                    Format::Zip,
                    Finding::Ambiguous,
                    member.name_span(),
                )?;
            }
        }
        return Ok(None);
    }
    let Some(member) = kinds.member(0, work).map_err(zip)? else {
        return Ok(None);
    };
    let range = marker_span(&member);
    let raw = bytes(&member, Format::Asic, limits, work).await?;
    let raw = match raw {
        Read::Bytes(value) => value,
        Read::Finding(candidate) => {
            if roles.is_some() {
                record(candidates, candidate)?;
            }
            return Ok(None);
        }
    };
    charge(work, range_for_cost(range, raw.len()), 4)?;
    // EN 319 162-1 V1.1.1 §§4.3.3.1, 4.4.3.1 and A.1. Read
    // actual checked bytes; a filename or a MIME hint is no substitute.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf
    let asic = match raw.as_ref() {
        b"application/vnd.etsi.asic-s+zip" => Some(Format::AsicS),
        b"application/vnd.etsi.asic-e+zip" => Some(Format::AsicE),
        _ => None,
    };
    if let Some(format) = asic {
        add(
            candidates,
            format,
            if roles.is_some() {
                Finding::Framing
            } else {
                Finding::Incomplete
            },
            range,
        )?;
    } else if let Some(role) = roles {
        add(candidates, Format::Asic, Finding::Incomplete, role)?;
    }
    Ok(odf_type(raw.as_ref()).map(|kind| (kind, range)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OdfType {
    Text,
    TextTemplate,
    TextMaster,
    TextWeb,
    Spreadsheet,
    SpreadsheetTemplate,
    Presentation,
    PresentationTemplate,
    Graphics,
    GraphicsTemplate,
    Chart,
    ChartTemplate,
    Formula,
    FormulaTemplate,
    Image,
    ImageTemplate,
    Database,
}

fn odf_type(bytes: &[u8]) -> Option<OdfType> {
    let suffix = bytes.strip_prefix(b"application/vnd.oasis.opendocument.")?;
    Some(match suffix {
        b"text" => OdfType::Text,
        b"text-template" => OdfType::TextTemplate,
        b"text-master" => OdfType::TextMaster,
        b"text-web" => OdfType::TextWeb,
        b"spreadsheet" => OdfType::Spreadsheet,
        b"spreadsheet-template" => OdfType::SpreadsheetTemplate,
        b"presentation" => OdfType::Presentation,
        b"presentation-template" => OdfType::PresentationTemplate,
        b"graphics" => OdfType::Graphics,
        b"graphics-template" => OdfType::GraphicsTemplate,
        b"chart" => OdfType::Chart,
        b"chart-template" => OdfType::ChartTemplate,
        b"formula" => OdfType::Formula,
        b"formula-template" => OdfType::FormulaTemplate,
        b"image" => OdfType::Image,
        b"image-template" => OdfType::ImageTemplate,
        b"database" => OdfType::Database,
        _ => return None,
    })
}

async fn odf<S: RangeSource>(
    archive: &ArchiveOf<'_, '_, S>,
    mime: Option<(OdfType, Span)>,
    limits: Limits,
    work: &Execution<'_>,
    candidates: &mut OwnedVec<Candidate, Execution<'_>>,
) -> Result<(), Error<S::Error>> {
    let format = Format::Odf;
    let member = match unique(archive, b"META-INF/manifest.xml", format, work, candidates)? {
        Selected::One(member) => member,
        Selected::None => {
            if let Some((_, range)) = mime {
                add(candidates, format, Finding::Incomplete, range)?;
            }
            return Ok(());
        }
        Selected::Duplicate => return Ok(()),
    };
    // ODF 1.3 Part 2 §§3.2 and 4.2: namespace and the root file-entry's
    // media type are separate from the ZIP filename.
    // https://docs.oasis-open.org/office/OpenDocument/v1.3/os/part2-packages/OpenDocument-v1.3-os-part2-packages.html
    let range = marker_span(&member);
    let raw = match bytes(&member, format, limits, work).await? {
        Read::Bytes(raw) => raw,
        Read::Finding(candidate) => return record(candidates, candidate),
    };
    let Some(document) = markup::read(&raw, range, work)? else {
        return add(candidates, format, Finding::Incomplete, range);
    };
    let ns = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
    if !document.root("manifest", ns) {
        if mime.is_some() {
            add(candidates, format, Finding::Conflicting, range)?;
        }
        return Ok(());
    }
    let mut roots = document
        .entries("file-entry", ns)
        .filter(|node| document.attribute(node, "full-path", Some(ns)) == Some("/"));
    let Some(root) = roots.next() else {
        return add(candidates, format, Finding::Incomplete, range);
    };
    let media = document
        .attribute(root, "media-type", Some(ns))
        .and_then(|media| odf_type(media.as_bytes()));
    let finding = if roots.next().is_some() || mime.is_some_and(|(mime, _)| media != Some(mime)) {
        Finding::Conflicting
    } else if document.has_element("encryption-data", ns) {
        Finding::Unsupported
    } else if media.is_some() {
        Finding::Framing
    } else {
        Finding::Incomplete
    };
    add(candidates, format, finding, range)
}

async fn office<S: RangeSource>(
    archive: &ArchiveOf<'_, '_, S>,
    limits: Limits,
    work: &Execution<'_>,
    candidates: &mut OwnedVec<Candidate, Execution<'_>>,
) -> Result<(), Error<S::Error>> {
    let format = Format::Ooxml;
    let types = unique(archive, b"[Content_Types].xml", format, work, candidates)?;
    let rels = unique(archive, b"_rels/.rels", format, work, candidates)?;
    let (types, rels) = match (types, rels) {
        (Selected::One(types), Selected::One(rels)) => (types, rels),
        (Selected::One(member), Selected::None) | (Selected::None, Selected::One(member)) => {
            return add(candidates, format, Finding::Incomplete, member.name_span());
        }
        _ => return Ok(()),
    };
    let range = marker_span(&rels);
    let original_relationships = match bytes(&rels, format, limits, work).await? {
        Read::Bytes(raw) => raw,
        Read::Finding(candidate) => return record(candidates, candidate),
    };
    let Some(relationships) = markup::read(&original_relationships, range, work)? else {
        return add(candidates, format, Finding::Incomplete, range);
    };
    let selected = office_target(&relationships, work, range)?;
    let target = match selected {
        Ok(Some(target)) => target,
        Ok(None) => return Ok(()),
        Err(finding) => return add(candidates, format, finding, range),
    };
    match unique(archive, target.as_ref(), format, work, candidates)? {
        Selected::None => return add(candidates, format, Finding::Incomplete, range),
        Selected::Duplicate => return Ok(()),
        Selected::One(part) => {
            if let Err(error) = part.source(work) {
                return add(
                    candidates,
                    format,
                    member_failure(error)?,
                    marker_span(&part),
                );
            }
        }
    }
    let original_types = match bytes(&types, format, limits, work).await? {
        Read::Bytes(raw) => raw,
        Read::Finding(candidate) => return record(candidates, candidate),
    };
    let types_range = marker_span(&types);
    let Some(types) = markup::read(&original_types, types_range, work)? else {
        return add(candidates, format, Finding::Incomplete, types_range);
    };
    let finding = office_type(&types, target.as_ref(), work, types_range)?;
    add(candidates, format, finding, range)
}

const OPC_RELS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const OPC_TYPES: &str = "http://schemas.openxmlformats.org/package/2006/content-types";

fn office_target<'x, E>(
    document: &'x markup::Document<'_, '_>,
    work: &Execution<'_>,
    range: Span,
) -> Result<Result<Option<uri::MemberName<'x>>, Finding>, Error<E>> {
    // ECMA-376 Part 2, package relationships and internal part addressing.
    // https://dev.ecma-international.org/publications-and-standards/standards/ecma-376/
    if !document.root("Relationships", OPC_RELS) {
        return Ok(Err(Finding::Conflicting));
    }
    let mut matches = document.entries("Relationship", OPC_RELS).filter(|node| {
        matches!(
            document.attribute(node, "Type", None),
            Some(
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
                    | "http://purl.oclc.org/ooxml/officeDocument/relationships/officeDocument"
            )
        )
    });
    let Some(node) = matches.next() else {
        return Ok(Ok(None));
    };
    if matches.next().is_some() {
        return Ok(Err(Finding::Conflicting));
    }
    match document.attribute(node, "TargetMode", None) {
        Some("External") => return Ok(Err(Finding::Unsupported)),
        None | Some("Internal") => {}
        Some(_) => return Ok(Err(Finding::Conflicting)),
    }
    let Some(target) = document.attribute(node, "Target", None) else {
        return Ok(Err(Finding::Incomplete));
    };
    match uri::opc_root(target, true, work).map_err(|cause| Error::Resource { cause, range })? {
        Some(name) => Ok(Ok(Some(name))),
        None => Ok(Err(Finding::Conflicting)),
    }
}

fn office_type<E>(
    document: &markup::Document<'_, '_>,
    target: &[u8],
    work: &Execution<'_>,
    range: Span,
) -> Result<Finding, Error<E>> {
    if !document.root("Types", OPC_TYPES) {
        return Ok(Finding::Conflicting);
    }
    let mut specific = None;
    for node in document.entries("Override", OPC_TYPES) {
        let (Some(name), Some(media)) = (
            document.attribute(node, "PartName", None),
            document.attribute(node, "ContentType", None),
        ) else {
            continue;
        };
        if let Some(name) =
            uri::opc_root(name, false, work).map_err(|cause| Error::Resource { cause, range })?
        {
            let name = name.as_ref();
            charge(work, range_for_cost(range, name.len().min(target.len())), 1)?;
            if name == target && specific.replace(media).is_some() {
                return Ok(Finding::Conflicting);
            }
        }
    }
    if let Some(media) = specific {
        return Ok(office_media(media));
    }
    let Some(extension) = target.rsplit(|&byte| byte == b'/').next().and_then(|part| {
        part.iter()
            .rposition(|&byte| byte == b'.')
            .map(|dot| &part[dot + 1..])
    }) else {
        return Ok(Finding::Incomplete);
    };
    let mut default = None;
    for node in document.entries("Default", OPC_TYPES) {
        let Some(candidate) = document.attribute(node, "Extension", None) else {
            continue;
        };
        let Some(media) = document.attribute(node, "ContentType", None) else {
            continue;
        };
        charge(
            work,
            range_for_cost(range, extension.len().min(candidate.len())),
            1,
        )?;
        if extension.eq_ignore_ascii_case(candidate.as_bytes()) && default.replace(media).is_some()
        {
            return Ok(Finding::Conflicting);
        }
    }
    Ok(default.map_or(Finding::Incomplete, office_media))
}

fn office_media(media: &str) -> Finding {
    const OPEN: &str = "application/vnd.openxmlformats-officedocument.";
    const MS: &str = "application/vnd.ms-";
    let matches = if let Some(kind) = media.strip_prefix(OPEN) {
        matches!(
            kind,
            "wordprocessingml.document.main+xml"
                | "wordprocessingml.template.main+xml"
                | "spreadsheetml.sheet.main+xml"
                | "spreadsheetml.template.main+xml"
                | "presentationml.presentation.main+xml"
                | "presentationml.slideshow.main+xml"
                | "presentationml.template.main+xml"
        )
    } else if let Some(kind) = media.strip_prefix(MS) {
        matches!(
            kind,
            "word.document.macroEnabled.main+xml"
                | "word.template.macroEnabledTemplate.main+xml"
                | "excel.sheet.macroEnabled.main+xml"
                | "excel.template.macroEnabled.main+xml"
                | "powerpoint.presentation.macroEnabled.main+xml"
                | "powerpoint.slideshow.macroEnabled.main+xml"
                | "powerpoint.template.macroEnabled.main+xml"
        )
    } else {
        false
    };
    if matches {
        Finding::Framing
    } else {
        Finding::Unsupported
    }
}

enum Read {
    Bytes(OwnedVec<u8>),
    Finding(Candidate),
}

async fn bytes<S: RangeSource>(
    member: &MemberOf<'_, '_, '_, S>,
    format: Format,
    limits: Limits,
    work: &Execution<'_>,
) -> Result<Read, Error<S::Error>> {
    let range = marker_span(member);
    let finding = |finding| {
        Read::Finding(Candidate {
            format,
            finding,
            range,
        })
    };
    if member.flags() & 1 != 0 {
        return Ok(finding(Finding::Unsupported));
    }
    if member.decoded_length() > limits.metadata {
        return Ok(finding(Finding::Uninspected));
    }
    match member.read_bytes(work).await {
        Ok(bytes) => Ok(Read::Bytes(bytes)),
        Err(error) => Ok(finding(member_failure(error)?)),
    }
}

fn member_failure<E, D, G>(error: ReadFailure<Acquisition<E>, D, G>) -> Result<Finding, Error<E>> {
    match error {
        ReadFailure::Processing {
            cause: ZipError::Unsupported { .. },
            ..
        } => Ok(Finding::Unsupported),
        ReadFailure::Integrity { .. }
        | ReadFailure::Receiver(_)
        | ReadFailure::Processing {
            cause: ZipError::Syntax { .. },
            ..
        } => Ok(Finding::Conflicting),
        ReadFailure::Processing { cause, .. } => Err(zip(cause)),
    }
}

fn marker_span<S: RangeSource>(member: &Member<'_, '_, S>) -> Span {
    member.data_span().unwrap_or_else(|| member.name_span())
}

fn range_for_cost(range: Span, length: usize) -> Span {
    Span {
        start: range.start,
        length: length as u64,
    }
}

fn zip<E>(error: ZipError<Acquisition<E>>) -> Error<E> {
    match error {
        ZipError::Input(error) => Error::Input(error),
        error => Error::Zip(error),
    }
}

fn add<E>(
    output: &mut OwnedVec<Candidate, Execution<'_>>,
    format: Format,
    finding: Finding,
    range: Span,
) -> Result<(), Error<E>> {
    record(
        output,
        Candidate {
            format,
            finding,
            range,
        },
    )
}
