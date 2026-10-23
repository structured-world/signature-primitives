//! Schema-selected DER projections for archive inputs. Signed/content octets
//! are never silently replaced in an ordinary signature verification.
use crate::{
    Error, ErrorCode, Octets, Result,
    stream::{Receiver, Refused, Source},
};
use core::cmp::Ordering;
use structured_asn1::{
    Class, Element, Encoding, Span, Tag,
    length::DerLength,
    memory::{HashWork, MemoryError, OwnedMap, OwnedVec, SortError, Work},
    universal,
};
const FIELD: &str = "archive.der";

#[derive(Clone, Copy)]
pub(crate) enum Form {
    Set,
    Octets,
    Omit,
}
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Key(u64, u64);
impl From<Span> for Key {
    fn from(span: Span) -> Self {
        Self(span.start, span.length)
    }
}
impl HashWork for Key {
    fn hash_work(&self) -> core::result::Result<u64, MemoryError> {
        Ok(3)
    }
}
pub(crate) struct Rules<W: Work> {
    items: OwnedMap<Key, Form, W>,
}
impl<W: Work> Rules<W> {
    pub(crate) fn new(work: &W) -> Self {
        Self { items: work.map() }
    }
    pub(crate) fn insert(&mut self, span: Span, form: Form, _work: &W) -> Result<()> {
        self.items
            .try_insert(Key::from(span), form)
            .map(|_| ())
            .map_err(|cause| Error::resource(cause, FIELD, span.start))
    }
    pub(crate) fn algorithm(
        &mut self,
        identifier: structured_pkix::AlgorithmIdentifier<'_>,
        work: &W,
    ) -> Result<()> {
        let at = identifier.offset();
        work.charge_work(
            1 + identifier
                .algorithm()
                .as_bytes()
                .len()
                .min(structured_pkix::oid::RSASSA_PSS.as_bytes().len()) as u64,
        )
        .map_err(|cause| Error::resource(cause, FIELD, at))?;
        if identifier.algorithm() != structured_pkix::oid::RSASSA_PSS {
            return Ok(());
        }
        if let Some(parameters) =
            structured_pkix::algorithm::pss::read(identifier, work).map_err(Error::pkix)?
        {
            for element in parameters.written_defaults() {
                self.insert(element.span(), Form::Omit, work)?;
            }
        }
        Ok(())
    }
}
enum Body<'d> {
    Bytes(&'d [u8]),
    Byte(u8),
    Bits {
        prefix: &'d [u8],
        last: u8,
    },
    String(Octets<'d>),
    Segments {
        pieces: OwnedVec<&'d [u8]>,
        unused: u8,
        last: Option<u8>,
    },
    Children,
}
struct Node<'d> {
    tag: &'d [u8],
    primitive: Option<[u8; 1]>,
    length: DerLength,
    total: u64,
    body: Body<'d>,
    parent: Option<usize>,
    first: Option<usize>,
    next: Option<usize>,
}
/// Metadata-only encoding tree. Content payloads remain borrowed original
/// ranges, including constructed eContent; traversal AND drop are iterative.
pub(crate) struct Projection<'d> {
    nodes: OwnedVec<Node<'d>>,
}
struct Frame<'d, 'w> {
    reader: structured_asn1::ScopedReader<'d, 'w>,
    index: usize,
    last: Option<usize>,
    sort: bool,
    at: u64,
}
impl<'d> Projection<'d> {
    pub(crate) fn new(
        parent: &structured_asn1::ScopedReader<'d, '_>,
        element: Element<'d>,
        rules: &Rules<impl Work>,
    ) -> Result<Self> {
        let work = parent.execution();
        let mut nodes = work.vector();
        let mut frames = work.vector();
        let (node, entered) = make(parent, element, rules, None)?;
        nodes
            .try_push(node)
            .map_err(|cause| Error::resource(cause, FIELD, element.span().start))?;
        if let Some((reader, sort)) = entered {
            frames
                .try_push(Frame {
                    reader,
                    index: 0,
                    last: None,
                    sort,
                    at: element.span().start,
                })
                .map_err(|cause| Error::resource(cause, FIELD, element.span().start))?;
        }
        while let Some(frame) = frames.last_mut() {
            work.charge_work(1)
                .map_err(|cause| Error::resource(cause, FIELD, frame.at))?;
            if let Some(child) = frame
                .reader
                .next_element()
                .map_err(|cause| Error::encoding(cause, FIELD))?
            {
                if matches!(
                    rules
                        .items
                        .get(&Key::from(child.span()), &work)
                        .map_err(|cause| Error::resource(cause, FIELD, child.span().start))?,
                    Some(Form::Omit)
                ) {
                    continue;
                }
                let index = nodes.len();
                let (node, entered) = make(&frame.reader, child, rules, Some(frame.index))?;
                nodes
                    .try_push(node)
                    .map_err(|cause| Error::resource(cause, FIELD, child.span().start))?;
                if let Some(previous) = frame.last {
                    nodes[previous].next = Some(index);
                } else {
                    nodes[frame.index].first = Some(index);
                }
                frame.last = Some(index);
                if let Some((reader, sort)) = entered {
                    frames
                        .try_push(Frame {
                            reader,
                            index,
                            last: None,
                            sort,
                            at: child.span().start,
                        })
                        .map_err(|cause| Error::resource(cause, FIELD, child.span().start))?;
                }
            } else {
                let frame = frames.pop().expect("last frame exists");
                if frame.sort {
                    sort_children(&mut nodes, frame.index, &work, frame.at)?;
                }
                let mut length = 0u64;
                let mut next = nodes[frame.index].first;
                while let Some(index) = next {
                    work.charge_work(1)
                        .map_err(|cause| Error::resource(cause, FIELD, frame.at))?;
                    length = length
                        .checked_add(nodes[index].total)
                        .ok_or_else(|| Error::schema(ErrorCode::LengthOverflow, FIELD, frame.at))?;
                    next = nodes[index].next;
                }
                finish(&mut nodes[frame.index], length, frame.at)?;
            }
        }
        Ok(Self {
            nodes: nodes.into_owned(),
        })
    }
    pub(crate) fn len(&self) -> u64 {
        self.nodes[0].total
    }
    pub(crate) fn feed<W: Work, E>(
        &self,
        work: &W,
        mut write: impl FnMut(&[u8]) -> core::result::Result<(), E>,
    ) -> core::result::Result<(), FeedError<E>> {
        let mut cursor = Cursor::new(&self.nodes, 0);
        while let Some(bytes) = cursor.next(work).map_err(FeedError::Resource)? {
            write(bytes).map_err(FeedError::Callback)?;
        }
        Ok(())
    }
    pub(crate) fn write<W: Work>(
        &self,
        out: &mut impl Receiver,
        work: &W,
    ) -> core::result::Result<(), ProjectionError> {
        let mut cursor = Cursor::new(&self.nodes, 0);
        while let Some(bytes) = cursor.next(work).map_err(ProjectionError::Resource)? {
            out.write(bytes).map_err(ProjectionError::Receiver)?;
        }
        Ok(())
    }
}
fn finish(node: &mut Node<'_>, length: u64, at: u64) -> Result<()> {
    node.length = DerLength::new(length);
    let tag = if node.primitive.is_some() {
        1
    } else {
        node.tag.len() as u64
    };
    node.total = length
        .checked_add(node.length.as_bytes().len() as u64)
        .and_then(|value| value.checked_add(tag))
        .ok_or_else(|| Error::schema(ErrorCode::LengthOverflow, FIELD, at))?;
    Ok(())
}
fn identifier<'d>(
    element: Element<'d>,
    parent: &structured_asn1::ScopedReader<'_, '_>,
) -> Result<&'d [u8]> {
    // Header validity/minimal identifier spelling was already proved by the
    // parser. This locates the ORIGINAL identifier boundary, never decodes a
    // second ASN.1 grammar (wide opaque tags remain original).
    parent
        .charge(1)
        .map_err(|cause| Error::encoding(cause, FIELD))?;
    let bytes = element.as_bytes();
    if bytes[0] & 31 != 31 {
        return Ok(&bytes[..1]);
    }
    let mut end = 1;
    loop {
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        let byte = bytes[end];
        end += 1;
        if byte & 128 == 0 {
            return Ok(&bytes[..end]);
        }
    }
}
fn make<'d, 'w>(
    parent: &structured_asn1::ScopedReader<'d, 'w>,
    element: Element<'d>,
    rules: &Rules<impl Work>,
    owner: Option<usize>,
) -> Result<(
    Node<'d>,
    Option<(structured_asn1::ScopedReader<'d, 'w>, bool)>,
)> {
    let at = element.span().start;
    let tag = element.tag();
    let form = rules
        .items
        .get(&Key::from(element.span()), &parent.execution())
        .map_err(|cause| Error::resource(cause, FIELD, at))?
        .copied();
    let mut node = Node {
        tag: identifier(element, parent)?,
        primitive: None,
        length: DerLength::new(0),
        total: 0,
        body: Body::Children,
        parent: owner,
        first: None,
        next: None,
    };
    let string = matches!(form, Some(Form::Octets))
        || (tag.class() == Class::Universal
            && matches!(tag.number(), Some(4 | 12 | 18..=22 | 25..=28 | 30)));
    if string {
        let number = tag
            .number()
            .expect("known universal or implicit string tag");
        let octets = Octets::projection_string(
            parent,
            &element,
            number,
            tag.class() != Class::Universal,
            FIELD,
        )?;
        node.primitive = Some([node.tag[0] & !32]);
        let length = octets.len() as u64;
        node.body = Body::String(octets);
        finish(&mut node, length, at)?;
        return Ok((node, None));
    }
    if tag == Tag::constructed(universal::BIT_STRING) {
        return Ok((bit_node(parent, element, node)?, None));
    }
    if tag.is_constructed() {
        let reader = parent
            .enter(&element)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        if tag.class() == Class::Universal && !matches!(tag.number(), Some(8 | 11 | 16 | 17 | 29)) {
            // A known segmented BIT/time/other open encoding needs its own
            // canonical codec. Never mistake a constructed value for a
            // SEQUENCE, or turn unsupported projection into malformed input.
            structured_pkix::der::conforms(parent, &element, FIELD).map_err(Error::pkix)?;
            return Err(Error::schema(ErrorCode::UnsupportedEncoding, FIELD, at));
        }
        return Ok((
            node,
            Some((
                reader,
                matches!(form, Some(Form::Set)) || tag == Tag::constructed(universal::SET),
            )),
        ));
    }
    let mut length = element.contents().len() as u64;
    node.body = if tag == Tag::primitive(universal::BOOLEAN) {
        let value = parent
            .boolean(&element)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        length = 1;
        Body::Byte(if value { 255 } else { 0 })
    } else if tag == Tag::primitive(universal::BIT_STRING) {
        let bits = parent
            .bit_string(&element)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        if bits.unused_bits() != 0 {
            let contents = element.contents();
            Body::Bits {
                prefix: &contents[..contents.len() - 1],
                last: contents[contents.len() - 1] & (255 << bits.unused_bits()),
            }
        } else {
            Body::Bytes(element.contents())
        }
    } else {
        let strict = parent
            .reread(&element, Encoding::Der)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        if let Err(cause) = structured_pkix::der::conforms(&strict, &element, FIELD) {
            if cause.is_resource() {
                return Err(Error::pkix(cause));
            }
            structured_pkix::der::conforms(parent, &element, FIELD).map_err(Error::pkix)?;
            return Err(Error::schema(ErrorCode::UnsupportedEncoding, FIELD, at));
        }
        Body::Bytes(element.contents())
    };
    finish(&mut node, length, at)?;
    Ok((node, None))
}
fn bit_node<'d>(
    parent: &structured_asn1::ScopedReader<'d, '_>,
    element: Element<'d>,
    mut node: Node<'d>,
) -> Result<Node<'d>> {
    let at = element.span().start;
    let work = parent.execution();
    let mut pieces = work.vector();
    let mut unused = 0u8;
    let mut last = None;
    let mut length = 1u64;
    structured_pkix::der::bit_fragments(parent, &element, FIELD, |fragment, bits| {
        let bytes = bits.as_bytes();
        unused = bits.unused_bits();
        length = length.checked_add(bytes.len() as u64).ok_or_else(|| {
            structured_pkix::Error::new(
                structured_pkix::ErrorCode::MalformedValue,
                FIELD,
                fragment.span().start,
            )
        })?;
        let bytes = if unused == 0 {
            bytes
        } else {
            last = Some(bytes[bytes.len() - 1] & (255 << unused));
            &bytes[..bytes.len() - 1]
        };
        pieces
            .try_push(bytes)
            .map_err(|cause| structured_pkix::Error::resource(cause, FIELD, fragment.span().start))
    })
    .map_err(Error::pkix)?;
    node.primitive = Some([node.tag[0] & !32]);
    node.body = Body::Segments {
        pieces: pieces.into_owned(),
        unused,
        last,
    };
    finish(&mut node, length, at)?;
    Ok(node)
}

pub(crate) enum FeedError<E> {
    Resource(MemoryError),
    Callback(E),
}
/// Original projection traversal/receiver refusal, without fabricated offsets.
#[derive(Debug)]
pub enum ProjectionError {
    /// Current work refused before traversal.
    Resource(MemoryError),
    /// The driver retains the first receiver cause.
    Receiver(Refused),
}
struct Cursor<'n, 'd> {
    nodes: &'n [Node<'d>],
    root: usize,
    index: Option<usize>,
    phase: u8,
    piece: usize,
}
impl<'n, 'd> Cursor<'n, 'd> {
    fn new(nodes: &'n [Node<'d>], root: usize) -> Self {
        Self {
            nodes,
            root,
            index: Some(root),
            phase: 0,
            piece: 0,
        }
    }
    fn advance<W: Work>(
        &mut self,
        mut index: usize,
        work: &W,
    ) -> core::result::Result<(), MemoryError> {
        loop {
            work.charge_work(1)?;
            if index == self.root {
                self.index = None;
                return Ok(());
            }
            if let Some(next) = self.nodes[index].next {
                self.index = Some(next);
                self.phase = 0;
                self.piece = 0;
                return Ok(());
            }
            index = self.nodes[index].parent.expect("non-root projection child");
        }
    }
    fn next<W: Work>(&mut self, work: &W) -> core::result::Result<Option<&'n [u8]>, MemoryError> {
        while let Some(index) = self.index {
            work.charge_work(1)?;
            let node = &self.nodes[index];
            match self.phase {
                0 => {
                    self.phase = 1;
                    return Ok(Some(
                        node.primitive.as_ref().map_or(node.tag, |tag| &tag[..]),
                    ));
                }
                1 => {
                    self.phase = 2;
                    return Ok(Some(node.length.as_bytes()));
                }
                _ => match &node.body {
                    Body::Children => {
                        if let Some(child) = node.first {
                            self.index = Some(child);
                            self.phase = 0;
                            self.piece = 0;
                        } else {
                            self.advance(index, work)?;
                        }
                    }
                    Body::Bytes(bytes) => {
                        self.advance(index, work)?;
                        return Ok(Some(bytes));
                    }
                    Body::Byte(byte) => {
                        self.advance(index, work)?;
                        return Ok(Some(core::slice::from_ref(byte)));
                    }
                    Body::Bits { prefix, last } => {
                        if self.piece == 0 {
                            self.piece = 1;
                            return Ok(Some(prefix));
                        }
                        self.advance(index, work)?;
                        return Ok(Some(core::slice::from_ref(last)));
                    }
                    Body::Segments {
                        pieces,
                        unused,
                        last,
                    } => {
                        if self.piece == 0 {
                            self.piece = 1;
                            return Ok(Some(core::slice::from_ref(unused)));
                        }
                        if let Some(bytes) = pieces.get(self.piece - 1) {
                            self.piece += 1;
                            return Ok(Some(bytes));
                        }
                        self.advance(index, work)?;
                        if let Some(last) = last {
                            return Ok(Some(core::slice::from_ref(last)));
                        }
                    }
                    Body::String(value) => {
                        if let Some(piece) = value.pieces().get(self.piece) {
                            self.piece += 1;
                            return Ok(Some(piece.as_bytes()));
                        }
                        self.advance(index, work)?;
                    }
                },
            }
        }
        Ok(None)
    }
}
fn nonempty<'n, W: Work>(
    cursor: &mut Cursor<'n, '_>,
    work: &W,
) -> core::result::Result<Option<&'n [u8]>, MemoryError> {
    loop {
        match cursor.next(work)? {
            Some([]) => {}
            other => return Ok(other),
        }
    }
}
fn compare<W: Work>(
    nodes: &[Node<'_>],
    a: usize,
    b: usize,
    work: &W,
) -> core::result::Result<Ordering, MemoryError> {
    let mut left = Cursor::new(nodes, a);
    let mut right = Cursor::new(nodes, b);
    let mut a = &[][..];
    let mut b = &[][..];
    loop {
        if a.is_empty() {
            a = match nonempty(&mut left, work)? {
                Some(bytes) => bytes,
                None => {
                    return Ok(if b.is_empty() && nonempty(&mut right, work)?.is_none() {
                        Ordering::Equal
                    } else {
                        Ordering::Less
                    });
                }
            };
        }
        if b.is_empty() {
            b = match nonempty(&mut right, work)? {
                Some(bytes) => bytes,
                None => return Ok(Ordering::Greater),
            };
        }
        let length = a.len().min(b.len());
        work.charge_work(1 + length as u64)?;
        let order = a[..length].cmp(&b[..length]);
        if order != Ordering::Equal {
            return Ok(order);
        }
        a = &a[length..];
        b = &b[length..];
    }
}
fn sort_children<W: Work>(nodes: &mut [Node<'_>], parent: usize, work: &W, at: u64) -> Result<()> {
    let resource = |cause| Error::resource(cause, FIELD, at);
    let mut indices = work.vector();
    let mut next = nodes[parent].first;
    while let Some(index) = next {
        indices.try_push(index).map_err(resource)?;
        next = nodes[index].next;
    }
    indices
        .try_sort_unstable_by(|a, b| compare(nodes, *a, *b, work))
        .map_err(|cause| match cause {
            SortError::Resource(cause) | SortError::Comparison(cause) => resource(cause),
        })?;
    nodes[parent].first = indices.first().copied();
    for (ordinal, index) in indices.iter().enumerate() {
        work.charge_work(1).map_err(resource)?;
        nodes[*index].next = indices.get(ordinal + 1).copied();
    }
    Ok(())
}

/// Complete original `SignerInfo` fields projected to the DER inputs selected
/// by TS101733 §6.5.1. Payload strings remain original borrowed ranges.
pub struct DerFields<'d> {
    values: OwnedVec<Projection<'d>>,
}
impl Source for DerFields<'_> {
    type Error = ProjectionError;
    fn stream<W: Work>(
        &mut self,
        out: &mut impl Receiver,
        work: &W,
    ) -> core::result::Result<(), Self::Error> {
        for value in &self.values {
            work.charge_work(1).map_err(ProjectionError::Resource)?;
            value.write(out, work)?;
        }
        Ok(())
    }
}
impl<'d> crate::signer::Fields<'d> {
    /// DER version/SID/digestAlgorithm, with original field depth and execution.
    pub fn identity_der(
        &self,
        parent: &structured_asn1::ScopedReader<'d, '_>,
    ) -> Result<DerFields<'d>> {
        self.project(parent, &self.identity, self.identity[2])
    }
    /// DER signatureAlgorithm/signature; a constructed signature is flattened
    /// through the SAME OCTET STRING kernel, without joining its bytes.
    pub fn signature_der(
        &self,
        parent: &structured_asn1::ScopedReader<'d, '_>,
    ) -> Result<DerFields<'d>> {
        self.project(parent, &self.signature, self.signature[0])
    }
    fn project(
        &self,
        parent: &structured_asn1::ScopedReader<'d, '_>,
        elements: &[Element<'d>],
        algorithm: Element<'d>,
    ) -> Result<DerFields<'d>> {
        parent
            .charge(1)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        if !core::ptr::eq(self.parser, parent.parser()) || self.depth != parent.depth() {
            return Err(Error::schema(
                ErrorCode::InvalidLocation,
                FIELD,
                self.identity[0].span().start,
            ));
        }
        let work = parent.execution();
        let mut rules = Rules::new(&work);
        let identifier =
            structured_pkix::algorithm::read(parent, &algorithm, FIELD).map_err(Error::pkix)?;
        rules.algorithm(identifier, &work)?;
        if self.identity[1].tag().class() == Class::ContextSpecific {
            rules.insert(self.identity[1].span(), Form::Octets, &work)?;
        }
        let mut values = work.vector();
        values
            .try_reserve_exact(elements.len())
            .map_err(|cause| Error::resource(cause, FIELD, self.identity[0].span().start))?;
        for element in elements {
            values
                .try_push(Projection::new(parent, *element, &rules)?)
                .map_err(|cause| Error::resource(cause, FIELD, element.span().start))?;
        }
        Ok(DerFields {
            values: values.into_owned(),
        })
    }
}

#[cfg(test)]
mod tests;
