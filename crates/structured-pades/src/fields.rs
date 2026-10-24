//! Historical `AcroForm` field ownership, names and inherited signature types.

use crate::{
    document::{Document, Graph, GraphObject},
    error::{Error, ErrorKind, ReadFailure, Syntax},
    model::admit,
    range::RangeSource,
    source::Location,
};
use structured_asn1::memory::{HashWork, Memory, MemoryError, OwnedText, OwnedVec, Work};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Position {
    owner: usize,
    node: usize,
}
impl HashWork for Position {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(2)
    }
}

/// One actual field dictionary with its full, decoded original field name.
pub struct Field<'g, 's, D, G> {
    pub(crate) object: GraphObject<'g, 's, D, G>,
    pub(crate) name: OwnedText,
    pub(crate) signature: bool,
    pub(crate) parent: Option<usize>,
}

impl<'g, 's, D: Copy + Eq, G: Copy + Eq> Field<'g, 's, D, G> {
    /// Fully qualified original text name, not an object-number alias.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    /// Original field dictionary, resolved in the selected historical graph.
    #[must_use]
    pub fn object(&self) -> GraphObject<'g, 's, D, G> {
        self.object
    }
    /// Actual FT, inherited through the field tree as required by ISO32000.
    #[must_use]
    pub fn is_signature(&self) -> bool {
        self.signature
    }
    /// Owning parent field ordinal, independently of widget Parent backlinks.
    #[must_use]
    pub fn parent(&self) -> Option<usize> {
        self.parent
    }
}

/// The complete historical field tree. Cycles, shared children and duplicate
/// full field names refuse rather than selecting one original definition.
pub struct Fields<'g, 's, D, G> {
    pub(crate) graph: &'g Graph<'s, D, G>,
    pub(crate) values: OwnedVec<Field<'g, 's, D, G>, Memory>,
    index: OwnedVec<usize, Memory>,
}

impl<'g, 's, D: Copy + Eq, G: Copy + Eq> Fields<'g, 's, D, G> {
    /// Every original field dictionary, including nonterminal field groups.
    #[must_use]
    pub fn values(&self) -> &[Field<'g, 's, D, G>] {
        &self.values
    }

    /// Finds one actual full name through the paid sorted field index.
    pub fn get(&self, name: &str, operation: &impl Work) -> crate::Result<Option<usize>> {
        let work = self.graph.session.query(operation);
        let mut low = 0;
        let mut high = self.index.len();
        while low < high {
            let middle = low + (high - low) / 2;
            let field = &self.values[self.index[middle]];
            admit(
                &work,
                field.object.direct().location(),
                name.len().min(field.name.len()) as u64 + 1,
            )?;
            match field.name().cmp(name) {
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
                core::cmp::Ordering::Equal => return Ok(Some(self.index[middle])),
            }
        }
        Ok(None)
    }

    /// Effective V follows the original parent fields, preserving the actual
    /// value's source owner. An absent child V is not an empty replacement.
    pub fn value(
        &self,
        ordinal: usize,
        operation: &impl Work,
    ) -> crate::Result<Option<GraphObject<'g, 's, D, G>>> {
        self.inherited(ordinal, b"V", operation)
    }

    pub(crate) fn inherited(
        &self,
        ordinal: usize,
        key: &[u8],
        operation: &impl Work,
    ) -> crate::Result<Option<GraphObject<'g, 's, D, G>>> {
        let work = self.graph.session.query(operation);
        let mut next = Some(ordinal);
        while let Some(index) = next {
            let field = self.values.get(index).ok_or(Error {
                kind: ErrorKind::Foreign,
                location: self.graph.root().direct().location(),
            })?;
            admit(&work, field.object.direct().location(), 1)?;
            if let Some(value) = field.object.get(key, &work)?
                && value.direct().kind() != crate::object::Type::Null
            {
                return Ok(Some(value));
            }
            next = field.parent;
        }
        Ok(None)
    }

    /// Finds the original signature field whose V selects this exact dictionary.
    /// Equal CMS values cannot substitute another field or historical value.
    pub fn signature(
        &self,
        location: Location,
        operation: &impl Work,
    ) -> crate::Result<Option<usize>> {
        let mut result = None;
        for (ordinal, field) in self.values.iter().enumerate() {
            admit(operation, location, 1)?;
            if !field.signature {
                continue;
            }
            if field
                .object
                .get(b"V", operation)?
                .is_some_and(|value| value.direct().location() == location)
            {
                if result.is_some() {
                    return Err(Error {
                        kind: ErrorKind::Ambiguous(Syntax::Dictionary),
                        location,
                    });
                }
                result = Some(ordinal);
            }
        }
        Ok(result)
    }
}

struct Pending<'g, 's, D, G> {
    object: GraphObject<'g, 's, D, G>,
    parent: Option<usize>,
    signature: bool,
}

fn ordered<D: Copy + Eq, G: Copy + Eq, W: Work>(
    values: &[Field<'_, '_, D, G>],
    location: Location,
    work: &W,
) -> crate::Result<OwnedVec<usize, W>> {
    let mut ordered = work.vector();
    for (ordinal, field) in values.iter().enumerate() {
        admit(work, field.object.direct().location(), 1)?;
        if !field.name.is_empty() {
            ordered.try_push(ordinal).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
    }
    ordered
        .try_sort_unstable_by(|&a, &b| {
            let first = values[a].name();
            let second = values[b].name();
            admit(
                work,
                values[b].object.direct().location(),
                first.len().min(second.len()) as u64 + 1,
            )?;
            Ok::<_, Error>(first.cmp(second))
        })
        .map_err(|cause| match cause {
            structured_asn1::memory::SortError::Resource(cause) => Error {
                kind: ErrorKind::Resource(cause),
                location,
            },
            structured_asn1::memory::SortError::Comparison(cause) => cause,
        })?;
    for pair in ordered.windows(2) {
        admit(
            work,
            location,
            values[pair[0]].name.len().min(values[pair[1]].name.len()) as u64 + 1,
        )?;
        if values[pair[0]].name == values[pair[1]].name {
            return Err(Error {
                kind: ErrorKind::Ambiguous(Syntax::Dictionary),
                location: values[pair[1]].object.direct().location(),
            });
        }
    }
    Ok(ordered)
}

fn seed<'g, 's, D: Copy + Eq, G: Copy + Eq, W: Work>(
    graph: &'g Graph<'s, D, G>,
    pending: &mut OwnedVec<Pending<'g, 's, D, G>, W>,
    location: Location,
    work: &impl Work,
) -> crate::Result<()> {
    if let Some(form) = graph.root().get(b"AcroForm", work)?
        && let Some(roots) = form.get(b"Fields", work)?
    {
        let members = roots.members(work).ok_or(Error {
            kind: ErrorKind::Syntax(Syntax::Dictionary),
            location: roots.direct().location(),
        })?;
        for root in members {
            let object = root?.resolved(work)?.ok_or(Error {
                kind: ErrorKind::Syntax(Syntax::Dictionary),
                location,
            })?;
            pending
                .try_push(Pending {
                    object,
                    parent: None,
                    signature: false,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
        }
    }
    Ok(())
}

impl<'s, S: RangeSource> Document<'s, S> {
    async fn field_name<'g, W: Work>(
        &self,
        graph: &'g Graph<'s, S::Document, S::Generation>,
        object: GraphObject<'g, 's, S::Document, S::Generation>,
        parent_name: Option<&str>,
        work: &W,
    ) -> Result<OwnedText<W>, ReadFailure<S::Error>> {
        let location = object.direct().location();
        let mut name = if let Some(parent) = parent_name {
            OwnedText::try_from_str(parent, work).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?
        } else {
            OwnedText::try_from_str("", work).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?
        };
        if let Some(part) = object.get(b"T", work)? {
            let reading = graph.nodes[part.owner]
                .reading
                .as_ref()
                .expect("resolved field text owner");
            let bytes = self
                .string_in(
                    reading,
                    graph.decoded(part.owner),
                    part.node,
                    usize::MAX,
                    work,
                )
                .await?;
            let text = crate::text::read(&bytes, part.direct().location(), work)?;
            admit(work, part.direct().location(), text.len() as u64)?;
            if text.as_bytes().contains(&b'.') || text.is_empty() {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::String),
                    location: part.direct().location(),
                }
                .into());
            }
            if !name.is_empty() {
                name.try_push_str(".").map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
            }
            name.try_push_str(text.as_str()).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        }
        Ok(name)
    }

    async fn read_field<'g, W: Work>(
        &self,
        graph: &'g Graph<'s, S::Document, S::Generation>,
        item: &Pending<'g, 's, S::Document, S::Generation>,
        values: &[Field<'g, 's, S::Document, S::Generation>],
        work: &W,
    ) -> Result<Option<Field<'g, 's, S::Document, S::Generation>>, ReadFailure<S::Error>> {
        let object = item.object;
        let parent = item.parent;
        let inherited_signature = item.signature;
        let location = object.direct().location();
        if object.direct().kind() != crate::object::Type::Dictionary {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Dictionary),
                location,
            }
            .into());
        }
        if let Some(parent) = parent {
            let backlink = object.get(b"Parent", work)?.ok_or(Error {
                kind: ErrorKind::Syntax(Syntax::Dictionary),
                location,
            })?;
            let expected = values[parent].object;
            if backlink.direct().location() != expected.direct().location() {
                return Err(Error {
                    kind: ErrorKind::Ambiguous(Syntax::Dictionary),
                    location,
                }
                .into());
            }
        }
        let signature = match object.get(b"FT", work)? {
            Some(kind) => kind.direct().name_equals(b"Sig", work)?,
            None => inherited_signature,
        };
        let name = self
            .field_name(
                graph,
                object,
                parent.map(|ordinal| values[ordinal].name()),
                work,
            )
            .await?;
        // A pure widget child is not another field with the same name.
        let widget = object
            .get(b"Subtype", work)?
            .map(|value| value.direct().name_equals(b"Widget", work))
            .transpose()?
            .unwrap_or(false);
        if widget && object.get(b"T", work)?.is_none() && object.get(b"FT", work)?.is_none() {
            return Ok(None);
        }
        Ok(Some(Field {
            object,
            name: name.into_owned(),
            signature,
            parent,
        }))
    }

    /// Reads the actual `AcroForm` tree iteratively under current and original
    /// funding. PDF text-name decoding is shared with `FieldMDP` selections.
    ///
    /// # Panics
    /// Panics if a completed graph loses a resolved field-name owner.
    pub async fn fields<'g, W: Work>(
        &self,
        graph: &'g Graph<'s, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<Fields<'g, 's, S::Document, S::Generation>, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let location = graph.root().direct().location();
        if !core::ptr::eq(graph.session, self.session) || graph.stamp != self.stamp {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        self.check(&work, location)?;
        let mut values: OwnedVec<Field<'g, 's, S::Document, S::Generation>, _> = work.vector();
        let mut pending = work.vector();
        let mut seen = work.map();
        seed(graph, &mut pending, location, &work)?;
        let mut at = 0;
        while at < pending.len() {
            admit(&work, location, 1)?;
            let object = pending[at].object;
            let location = object.direct().location();
            let position = Position {
                owner: object.owner,
                node: object.node.0,
            };
            if seen
                .try_insert(position, ())
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?
                .is_some()
            {
                return Err(Error {
                    kind: ErrorKind::Ambiguous(Syntax::Cycle),
                    location,
                }
                .into());
            }
            let Some(field) = self.read_field(graph, &pending[at], &values, &work).await? else {
                at += 1;
                continue;
            };
            let signature = field.signature;
            let ordinal = values.len();
            if let Some(kids) = object.get(b"Kids", &work)? {
                let members = kids.members(&work).ok_or(Error {
                    kind: ErrorKind::Syntax(Syntax::Dictionary),
                    location: kids.direct().location(),
                })?;
                for child in members {
                    let child = child?.resolved(&work)?.ok_or(Error {
                        kind: ErrorKind::Syntax(Syntax::Dictionary),
                        location,
                    })?;
                    pending
                        .try_push(Pending {
                            object: child,
                            parent: Some(ordinal),
                            signature,
                        })
                        .map_err(|cause| Error {
                            kind: ErrorKind::Resource(cause),
                            location,
                        })?;
                }
            }
            values.try_push(field).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
            at += 1;
        }
        let ordered = ordered(&values, location, &work)?;
        self.check(&work, location)?;
        Ok(Fields {
            graph,
            values: values.into_owned(),
            index: ordered.into_owned(),
        })
    }
}
