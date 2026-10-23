//! RFC4998 Appendix A: change only deleted ER attributes and containing lengths.

use super::{View, syntax};
use crate::{Error, Result, preservation::Kind};
use structured_asn1::{
    Element, Encoding, Parser, Reader,
    length::DerLength,
    memory::{OwnedVec, Work},
};
use structured_cms::{
    ErrorCode,
    attribute::{Attribute, Placement},
    content::ContentInfo,
    stream::{Receiver, Refused, Source},
};

const FIELD: &str = "cades.evidence.object";

enum Header<'d> {
    Original(&'d [u8]),
    Definite { tag: u8, length: DerLength },
}
struct Frame<'d> {
    header: Header<'d>,
    prefix: &'d [u8],
    suffix: &'d [u8],
    indefinite: bool,
    length: u64,
}
impl<'d> Frame<'d> {
    fn body(element: Element<'d>, tag: u8, length: u64) -> Result<Self> {
        let old = element.contents_span();
        let header_len = usize::try_from(old.start - element.span().start)
            .map_err(|_| syntax(ErrorCode::LengthOverflow, element.span()))?;
        let header = if element.is_indefinite() || length == old.length {
            Header::Original(&element.as_bytes()[..header_len])
        } else {
            Header::Definite {
                tag,
                length: DerLength::new(length),
            }
        };
        let header_length = match &header {
            Header::Original(bytes) => bytes.len() as u64,
            Header::Definite { length, .. } => 1 + length.as_bytes().len() as u64,
        };
        let total = header_length
            .checked_add(length)
            .and_then(|value| value.checked_add(if element.is_indefinite() { 2 } else { 0 }))
            .ok_or_else(|| syntax(ErrorCode::LengthOverflow, element.span()))?;
        Ok(Self {
            header,
            prefix: &[],
            suffix: &[],
            indefinite: element.is_indefinite(),
            length: total,
        })
    }
    fn around(element: Element<'d>, tag: u8, child: Element<'d>, replacement: u64) -> Result<Self> {
        let outer = element.contents_span();
        let inner = child.span();
        if inner.start < outer.start || inner.end() > outer.end() {
            return Err(Error::Foreign { at: inner.start });
        }
        let start = usize::try_from(inner.start - outer.start)
            .map_err(|_| syntax(ErrorCode::LengthOverflow, inner))?;
        let end = usize::try_from(inner.end() - outer.start)
            .map_err(|_| syntax(ErrorCode::LengthOverflow, inner))?;
        let prefix = &element.contents()[..start];
        let suffix = &element.contents()[end..];
        let length = (prefix.len() as u64)
            .checked_add(replacement)
            .and_then(|value| value.checked_add(suffix.len() as u64))
            .ok_or_else(|| syntax(ErrorCode::LengthOverflow, outer))?;
        let mut frame = Self::body(element, tag, length)?;
        frame.prefix = prefix;
        frame.suffix = suffix;
        Ok(frame)
    }
    fn begin<W: Work>(
        &self,
        out: &mut impl Receiver,
        work: &W,
    ) -> core::result::Result<(), ObjectError> {
        work.charge_work(1).map_err(ObjectError::Resource)?;
        match &self.header {
            Header::Original(bytes) => out.write(bytes).map_err(ObjectError::Receiver)?,
            Header::Definite { tag, length } => {
                out.write(&[*tag]).map_err(ObjectError::Receiver)?;
                out.write(length.as_bytes())
                    .map_err(ObjectError::Receiver)?;
            }
        }
        out.write(self.prefix).map_err(ObjectError::Receiver)
    }
    fn end<W: Work>(
        &self,
        out: &mut impl Receiver,
        work: &W,
    ) -> core::result::Result<(), ObjectError> {
        work.charge_work(1).map_err(ObjectError::Resource)?;
        out.write(self.suffix).map_err(ObjectError::Receiver)?;
        if self.indefinite {
            out.write(&[0, 0]).map_err(ObjectError::Receiver)?;
        }
        Ok(())
    }
}

fn enclosing_frames<'d>(
    message: &structured_cms::SignedData<'d>,
    content: &ContentInfo<'d>,
    envelope: Element<'d>,
    first: Element<'d>,
    signer: Frame<'d>,
) -> Result<[Frame<'d>; 5]> {
    let signer_set = Frame::around(message.signer_set_element(), 0x31, first, signer.length)?;
    let body = Frame::around(
        *content.content(),
        0x30,
        message.signer_set_element(),
        signer_set.length,
    )?;
    let explicit = Frame::around(
        content.content_wrapper(),
        0xa0,
        *content.content(),
        body.length,
    )?;
    let outer = Frame::around(envelope, 0x30, content.content_wrapper(), explicit.length)?;
    Ok([outer, explicit, body, signer_set, signer])
}

/// Actual source/dispatch refusal while streaming an original CMS projection.
#[derive(Debug)]
pub enum ObjectError {
    /// Current operation refused before a source-descriptor traversal.
    Resource(structured_asn1::memory::MemoryError),
    /// The common stream guard retains the original provider/sink cause.
    Receiver(Refused),
    /// Original snapshot source/depth/current-operation refusal.
    PriorProcessing(Error),
}

/// Refusal keeps current and previous document coordinates distinct.
#[derive(Debug)]
pub enum SnapshotError {
    /// Current final-message selection/placement/operation refusal.
    Current(Error),
    /// Actual previous source/query refusal, in that source's coordinates.
    Prior(Error),
    /// Unchanged fields or exact prior attributes differ between the sources.
    Changed {
        /// Current selecting proof.
        current: structured_asn1::Span,
        /// Actual earlier whole CMS input.
        prior: structured_asn1::Span,
    },
}
/// Exact earlier whole CMS coding, captured from its own existing parsed
/// message. It is not a caller-created sequence of bytes or a claimed date.
/// Binding checks every unchanged source field and prior attribute before any
/// hashing; original BER length forms can then be replayed without guessing.
pub struct CmsSnapshot<'a, 'd> {
    envelope: Element<'d>,
    message: &'a structured_cms::SignedData<'d>,
    frames: [Frame<'d>; 5],
    parser: &'d Parser,
    encoding: Encoding,
    depth: u32,
}
impl<'a, 'd> CmsSnapshot<'a, 'd> {
    /// Capture the actual full original container, without another CMS parse.
    pub fn capture(
        message: &'a structured_cms::SignedData<'d>,
        envelope: Element<'d>,
        operation: &Reader<'d>,
    ) -> Result<Self> {
        let content = container(message, envelope, operation)?;
        let first = message
            .signers()
            .first()
            .ok_or_else(|| syntax(ErrorCode::MissingField, envelope.span()))?;
        let signer = if let Some(unsigned) = first.unsigned_attributes() {
            Frame::around(
                *first.element(),
                0x30,
                *unsigned.element(),
                unsigned.element().as_bytes().len() as u64,
            )?
        } else {
            let mut frame = Frame::body(
                *first.element(),
                0x30,
                first.element().contents_span().length,
            )?;
            frame.prefix = first.element().contents();
            frame
        };
        let frames = enclosing_frames(message, &content, envelope, *first.element(), signer)?;
        Ok(Self {
            envelope,
            message,
            frames,
            parser: operation.parser(),
            encoding: operation.encoding(),
            depth: operation.depth(),
        })
    }
}
struct Original<'d> {
    element: Element<'d>,
    parser: &'d Parser,
    encoding: Encoding,
    depth: u32,
}

/// Closed whole-`ContentInfo` input for one original internal/external ER
/// attribute. Only self/later ER attributes and their containing lengths change.
/// Other fields, signature bytes and BER indefinite framing remain original.
pub struct CmsObject<'a, 'd> {
    frames: [Frame<'d>; 5],
    unsigned: Option<Frame<'d>>,
    attributes: &'a [Attribute<'d>],
    keep: OwnedVec<bool>,
    target: usize,
    original: Option<Original<'d>>,
}
impl<'d> CmsObject<'_, 'd> {
    /// Wire occurrence among the first signer's actual ER attributes. Full
    /// record closure still checks their proven chronology; SET order/`genTime`
    /// alone is never an authenticated ordering receipt.
    #[must_use]
    pub fn occurrence(&self) -> usize {
        self.target
    }
    pub(super) fn coverage(
        &self,
        view: &View<'_, '_, 'd>,
        operation: &Reader<'d>,
    ) -> Result<OwnedVec<structured_asn1::Span>> {
        let work = operation.execution();
        let mut ranges = work.vector();
        let message = view.prepared.document().message();
        let mut fields = message.fields_source().reader_in(&work)?;
        while let Some(element) = fields
            .next_element()
            .map_err(|cause| Error::encoding(cause, FIELD))?
        {
            if element.span() != message.signer_set_element().span() {
                ranges
                    .try_push(element.span())
                    .map_err(|cause| Error::resource(cause, FIELD, element.span().start))?;
            }
        }
        let first = message
            .signers()
            .first()
            .expect("CmsObject admitted first signer");
        let source = first.fields();
        ranges
            .try_push(structured_asn1::Span {
                start: source.identity[0].span().start,
                length: source.signature[1].span().end() - source.identity[0].span().start,
            })
            .map_err(|cause| Error::resource(cause, FIELD, first.span().start))?;
        for signer in message.signers().iter().skip(1) {
            ranges
                .try_push(signer.span())
                .map_err(|cause| Error::resource(cause, FIELD, signer.span().start))?;
        }
        for (ordinal, attribute) in self.attributes.iter().enumerate() {
            work.charge_work(1)
                .map_err(|cause| Error::resource(cause, FIELD, attribute.span().start))?;
            if self.keep[ordinal] {
                ranges
                    .try_push(attribute.span())
                    .map_err(|cause| Error::resource(cause, FIELD, attribute.span().start))?;
            }
        }
        Ok(ranges.into_owned())
    }
}
impl Source for CmsObject<'_, '_> {
    type Error = ObjectError;
    fn stream<W: Work>(
        &mut self,
        out: &mut impl Receiver,
        work: &W,
    ) -> core::result::Result<(), ObjectError> {
        if let Some(original) = &self.original {
            // Obtaining a borrowed source slice is constant work. The common
            // selected provider pays the actual byte scan during hashing.
            let origin = work
                .read_scoped_source(
                    original.parser,
                    original.element.as_bytes(),
                    original.element.span().start,
                    original.encoding,
                    original.depth,
                )
                .map_err(|cause| ObjectError::PriorProcessing(Error::encoding(cause, FIELD)))?;
            origin
                .charge(1)
                .map_err(|cause| ObjectError::PriorProcessing(Error::encoding(cause, FIELD)))?;
            return out
                .write(original.element.as_bytes())
                .map_err(ObjectError::Receiver);
        }
        for frame in &self.frames {
            frame.begin(out, work)?;
        }
        if let Some(unsigned) = &self.unsigned {
            unsigned.begin(out, work)?;
            for (index, attribute) in self.attributes.iter().enumerate() {
                work.charge_work(1).map_err(ObjectError::Resource)?;
                if self.keep[index] {
                    out.write(attribute.as_bytes())
                        .map_err(ObjectError::Receiver)?;
                }
            }
            unsigned.end(out, work)?;
        }
        for frame in self.frames.iter().rev() {
            frame.end(out, work)?;
        }
        Ok(())
    }
}
impl<'a, 'd> View<'a, '_, 'd> {
    /// Selects the actual full CMS object for RFC4998 Appendix A. The supplied
    /// `ContentInfo` must contain this SAME parsed `SignedData`, not equal bytes
    /// from another parser/model. No serialization or second CMS parse occurs.
    pub fn cms_object(
        &self,
        envelope: Element<'d>,
        operation: &Reader<'d>,
    ) -> Result<CmsObject<'a, 'd>> {
        let required = self.entry.required;
        let message = self.prepared.document().message();
        message.require_session(operation, FIELD)?;
        operation
            .charge(12)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        if required.placement != Placement::Unsigned
            || !matches!(
                required.kind,
                Kind::EvidenceRecordInternal | Kind::EvidenceRecordExternal
            )
        {
            return Err(Error::Foreign {
                at: required.property.span().start,
            });
        }
        let first = message
            .signers()
            .first()
            .ok_or_else(|| syntax(ErrorCode::MissingField, envelope.span()))?;
        if first.span() != required.signature.span() {
            return Err(Error::Foreign {
                at: required.signature.span().start,
            });
        }
        let content = container(message, envelope, operation)?;
        let unsigned = first
            .unsigned_attributes()
            .ok_or_else(|| syntax(ErrorCode::MissingField, first.span()))?;
        let work = operation.execution();
        let mut keep = work.vector();
        keep.try_reserve_exact(unsigned.items().len())
            .map_err(|cause| Error::resource(cause, FIELD, unsigned.element().span().start))?;
        let mut target = None;
        let mut occurrence = 0;
        let mut retained = 0u64;
        for attribute in unsigned.items() {
            work.charge_work(1 + attribute.kind().as_bytes().len().min(11) as u64)
                .map_err(|cause| Error::resource(cause, FIELD, attribute.span().start))?;
            let evidence = matches!(
                Kind::from_oid(attribute.kind()),
                Some(Kind::EvidenceRecordInternal | Kind::EvidenceRecordExternal)
            );
            if evidence && attribute.values().len() != 1 {
                return Err(syntax(ErrorCode::AttributeCardinality, attribute.span()));
            }
            if attribute.span() == required.property.span() {
                target = Some(occurrence);
            }
            let selected = !evidence || target.is_none();
            if selected {
                retained = retained
                    .checked_add(attribute.as_bytes().len() as u64)
                    .ok_or_else(|| syntax(ErrorCode::LengthOverflow, attribute.span()))?;
            }
            keep.try_push(selected)
                .map_err(|cause| Error::resource(cause, FIELD, attribute.span().start))?;
            if evidence {
                occurrence += 1;
            }
        }
        let target = target.ok_or(Error::Foreign {
            at: required.property.span().start,
        })?;
        let modified = if retained == 0 {
            None
        } else {
            Some(Frame::body(*unsigned.element(), 0xa1, retained)?)
        };
        let signer = Frame::around(
            *first.element(),
            0x30,
            *unsigned.element(),
            modified.as_ref().map_or(0, |frame| frame.length),
        )?;
        let frames = enclosing_frames(message, &content, envelope, *first.element(), signer)?;
        Ok(CmsObject {
            frames,
            unsigned: modified,
            attributes: unsigned.items(),
            keep: keep.into_owned(),
            target,
            original: None,
        })
    }
    /// Replay a genuine earlier whole CMS encoding. Only enclosing length
    /// spellings may differ from the final-message projection; all original
    /// signed fields, material, parallel signers and retained attributes must
    /// match exactly before a digest/provider/source callback is started.
    pub fn cms_object_snapshot(
        &self,
        envelope: Element<'d>,
        snapshot: &CmsSnapshot<'_, 'd>,
        operation: &Reader<'d>,
    ) -> core::result::Result<CmsObject<'a, 'd>, SnapshotError> {
        let mut selected = self
            .cms_object(envelope, operation)
            .map_err(SnapshotError::Current)?;
        let current = operation.execution();
        let origin = current
            .read_scoped_source(
                snapshot.parser,
                snapshot.envelope.as_bytes(),
                snapshot.envelope.span().start,
                snapshot.encoding,
                snapshot.depth,
            )
            .map_err(|cause| SnapshotError::Prior(Error::encoding(cause, FIELD)))?;
        let work = origin.execution();
        let current = self.required().property.span();
        let prior_span = snapshot.envelope.span();
        let changed = || SnapshotError::Changed {
            current,
            prior: prior_span,
        };
        let at = prior_span.start;
        for (actual, prior) in selected.frames.iter().zip(&snapshot.frames) {
            if !same(actual.prefix, prior.prefix, &work, at).map_err(SnapshotError::Prior)?
                || !same(actual.suffix, prior.suffix, &work, at).map_err(SnapshotError::Prior)?
            {
                return Err(changed());
            }
        }
        let prior = snapshot.message.signers()[0]
            .unsigned_attributes()
            .map_or(&[][..], |attributes| attributes.items());
        let mut next = 0;
        for (ordinal, attribute) in selected.attributes.iter().enumerate() {
            work.charge_work(1)
                .map_err(|cause| SnapshotError::Prior(Error::resource(cause, FIELD, at)))?;
            if !selected.keep[ordinal] {
                continue;
            }
            let previous = prior.get(next).ok_or_else(changed)?;
            if !same(attribute.as_bytes(), previous.as_bytes(), &work, at)
                .map_err(SnapshotError::Prior)?
            {
                return Err(changed());
            }
            next += 1;
        }
        if next != prior.len() {
            return Err(changed());
        }
        selected.original = Some(Original {
            element: snapshot.envelope,
            parser: snapshot.parser,
            encoding: snapshot.encoding,
            depth: snapshot.depth,
        });
        Ok(selected)
    }
}

fn same<W: Work>(left: &[u8], right: &[u8], work: &W, at: u64) -> Result<bool> {
    work.charge_work(1)
        .map_err(|cause| Error::resource(cause, FIELD, at))?;
    if left.len() != right.len() {
        return Ok(false);
    }
    work.charge_work(left.len() as u64)
        .map_err(|cause| Error::resource(cause, FIELD, at))?;
    Ok(left == right)
}
fn container<'d>(
    message: &structured_cms::SignedData<'d>,
    envelope: Element<'d>,
    operation: &Reader<'d>,
) -> Result<ContentInfo<'d>> {
    message.require_session(operation, FIELD)?;
    let (content, _) = ContentInfo::read_element(operation, &envelope)?;
    operation
        .charge(1 + content.kind().as_bytes().len() as u64)
        .map_err(|cause| Error::encoding(cause, FIELD))?;
    if content.kind() != structured_cms::oid::SIGNED_DATA {
        return Err(syntax(ErrorCode::UnexpectedContentType, envelope.span()));
    }
    if content.content().span() != message.span()
        || !core::ptr::eq(
            content.content().as_bytes().as_ptr(),
            message.as_bytes().as_ptr(),
        )
    {
        return Err(Error::Foreign {
            at: envelope.span().start,
        });
    }
    Ok(content)
}
