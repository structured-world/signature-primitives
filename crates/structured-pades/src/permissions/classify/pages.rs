//! Page-tree topology and annotation changes use their actual field edges.

use super::{Outcome, Permission, appearance, signature, state, timestamp};
use crate::{
    document::{Document, GraphObject},
    error::{Error, ErrorKind, ReadFailure, Syntax},
    fields::Fields,
    model::admit,
    object::Type,
    range::RangeSource,
};
use structured_asn1::memory::{HashWork, Memory, MemoryError, OwnedMap, OwnedVec, Work};
mod templates;
pub(super) type Copies<W> = OwnedMap<(usize, usize, usize), (), W>;

struct FieldScope<'f, 'a, 's, D, G, W: Work> {
    before: &'f Fields<'a, 's, D, G>,
    after: &'f Fields<'a, 's, D, G>,
    fields: &'f OwnedMap<(usize, usize, usize), usize, W>,
}

#[derive(Hash, PartialEq, Eq)]
struct Identity(u64, u16);
impl HashWork for Identity {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(2)
    }
}

enum PageStep {
    Same,
    Template,
    Refused(Outcome),
}

struct Pair<'a, 's, D, G> {
    a: GraphObject<'a, 's, D, G>,
    b: GraphObject<'a, 's, D, G>,
    parent: Option<usize>,
    count: u64,
    branch: bool,
}

fn page_counts<D: Copy + Eq, G: Copy + Eq>(
    pending: &mut [Pair<'_, '_, D, G>],
    location: crate::source::Location,
    work: &impl Work,
) -> crate::Result<Outcome> {
    for at in (0..pending.len()).rev() {
        admit(work, location, 1)?;
        let count = pending[at].count;
        if pending[at].branch {
            for value in [pending[at].a, pending[at].b] {
                if value
                    .get(b"Count", work)?
                    .map(|value| value.direct().unsigned(work))
                    .transpose()?
                    != Some(count)
                {
                    return Ok(Outcome::Indeterminate);
                }
            }
        }
        if let Some(parent) = pending[at].parent {
            pending[parent].count = pending[parent].count.checked_add(count).ok_or(Error {
                kind: ErrorKind::Syntax(Syntax::Number),
                location,
            })?;
        }
    }
    Ok(Outcome::Permitted)
}

struct AnnotationIndex<W: Work> {
    lookup: OwnedMap<Identity, usize, W>,
    used: OwnedVec<bool, W>,
}

fn annotation_index<D: Copy + Eq, G: Copy + Eq, W: Work>(
    old: &[GraphObject<'_, '_, D, G>],
    location: crate::source::Location,
    work: &W,
) -> crate::Result<Option<AnnotationIndex<W>>> {
    let mut lookup = work.map();
    let mut used = work.vector();
    used.try_reserve_exact(old.len()).map_err(|cause| Error {
        kind: ErrorKind::Resource(cause),
        location,
    })?;
    for (ordinal, value) in old.iter().enumerate() {
        admit(work, value.direct().location(), 1)?;
        let identity = value.identity();
        if lookup
            .try_insert(Identity(identity.0, identity.1), ordinal)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?
            .is_some()
        {
            return Ok(None);
        }
        used.try_push(false).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
    }
    Ok(Some(AnnotationIndex { lookup, used }))
}

fn page_links<D: Copy + Eq, G: Copy + Eq, W: Work>(
    pending: &[Pair<'_, '_, D, G>],
    at: usize,
    seen: &mut OwnedMap<(usize, usize, usize), (), W>,
    work: &impl Work,
) -> crate::Result<bool> {
    let a = pending[at].a;
    let b = pending[at].b;
    for (side, value) in [(0, a), (1, b)] {
        if seen
            .try_insert((side, value.owner, value.node.0), ())
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: value.direct().location(),
            })?
            .is_some()
        {
            return Ok(false);
        }
    }
    if let Some(parent) = pending[at].parent {
        for (value, parent) in [(a, pending[parent].a), (b, pending[parent].b)] {
            if value
                .get(b"Parent", work)?
                .is_none_or(|value| value.direct().location() != parent.direct().location())
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

impl<S: RangeSource> Document<'_, S> {
    async fn page_children<'a, 's, W: Work>(
        &self,
        a: GraphObject<'a, 's, S::Document, S::Generation>,
        b: GraphObject<'a, 's, S::Document, S::Generation>,
        at: usize,
        pending: &mut OwnedVec<Pair<'a, 's, S::Document, S::Generation>, W>,
        location: crate::source::Location,
        work: &impl Work,
    ) -> Result<PageStep, ReadFailure<S::Error>> {
        if !self
            .same_dictionary_except(a, b, &[b"Parent", b"Kids", b"Count"], work)
            .await?
        {
            return Ok(PageStep::Refused(Outcome::Forbidden));
        }
        let (Some(first), Some(second)) = (a.get(b"Kids", work)?, b.get(b"Kids", work)?) else {
            return Ok(PageStep::Refused(Outcome::Indeterminate));
        };
        let first = array(first, work)?;
        let second = array(second, work)?;
        // Added/reordered pages require a proven original named-page
        // template relationship, never just a matching page count.
        if first.len() != second.len() {
            return Ok(PageStep::Template);
        }
        let mut changed = false;
        for (a, b) in first.into_iter().zip(second) {
            if a.identity() != b.identity() {
                changed = true;
                break;
            }
            pending
                .try_push(Pair {
                    a,
                    b,
                    parent: Some(at),
                    count: 0,
                    branch: false,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
        }
        if changed {
            return Ok(PageStep::Template);
        }
        Ok(PageStep::Same)
    }

    pub(super) async fn classify_pages<'a, 's>(
        &self,
        before: &Fields<'a, 's, S::Document, S::Generation>,
        after: &Fields<'a, 's, S::Document, S::Generation>,
        permission: Permission,
        copies: &mut Copies<impl Work>,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        let (Some(a), Some(b)) = (
            before.graph.root().get(b"Pages", work)?,
            after.graph.root().get(b"Pages", work)?,
        ) else {
            return Ok(Outcome::Indeterminate);
        };
        if self.same_graph_values(a, b, work).await? {
            return Ok(Outcome::Permitted);
        }
        let mut pending = work.vector();
        let mut seen = work.map();
        let location = b.direct().location();
        let mut fields = work.map();
        for (index, field) in after.values().iter().enumerate() {
            let object = field.object();
            fields
                .try_insert((object.owner, object.node.0, 0), index)
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: object.direct().location(),
                })?;
        }
        pending
            .try_push(Pair {
                a,
                b,
                parent: None,
                count: 0,
                branch: false,
            })
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        let mut at = 0;
        while at < pending.len() {
            admit(work, location, 1)?;
            let a = pending[at].a;
            let b = pending[at].b;
            if !page_links(&pending, at, &mut seen, work)? {
                return Ok(Outcome::Indeterminate);
            }
            let (Some(first), Some(second)) = (a.get(b"Type", work)?, b.get(b"Type", work)?) else {
                return Ok(Outcome::Indeterminate);
            };
            if first.direct().name_equals(b"Pages", work)?
                && second.direct().name_equals(b"Pages", work)?
            {
                pending[at].branch = true;
                match self
                    .page_children(a, b, at, &mut pending, location, work)
                    .await?
                {
                    PageStep::Same => {}
                    PageStep::Refused(outcome) => return Ok(outcome),
                    PageStep::Template => {
                        drop(pending);
                        drop(seen);
                        drop(fields);
                        return self
                            .classify_template_pages(before, after, permission, copies, work)
                            .await;
                    }
                }
            } else if first.direct().name_equals(b"Page", work)?
                && second.direct().name_equals(b"Page", work)?
            {
                if !self
                    .same_dictionary_except(a, b, &[b"Parent", b"Annots"], work)
                    .await?
                {
                    return Ok(Outcome::Forbidden);
                }
                let result = self
                    .classify_annotations(
                        a,
                        b,
                        &FieldScope {
                            before,
                            after,
                            fields: &fields,
                        },
                        permission,
                        work,
                    )
                    .await?;
                if result != Outcome::Permitted {
                    return Ok(result);
                }
                pending[at].count = 1;
            } else {
                return Ok(Outcome::Indeterminate);
            }
            at += 1;
        }
        page_counts(&mut pending, location, work).map_err(Into::into)
    }

    async fn classify_annotations<'a, 's>(
        &self,
        old_page: GraphObject<'a, 's, S::Document, S::Generation>,
        new_page: GraphObject<'a, 's, S::Document, S::Generation>,
        scope: &FieldScope<'_, 'a, 's, S::Document, S::Generation, impl Work>,
        permission: Permission,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        let a = old_page.get(b"Annots", work)?;
        let b = new_page.get(b"Annots", work)?;
        if self.same_optional(a, b, work).await? {
            return Ok(Outcome::Permitted);
        }
        let old = a.map(|value| array(value, work)).transpose()?;
        let new = b.map(|value| array(value, work)).transpose()?;
        let old = old.as_deref().unwrap_or(&[]);
        let new = new.as_deref().unwrap_or(&[]);
        let location = new_page.direct().location();
        let Some(AnnotationIndex { lookup, mut used }) = annotation_index(old, location, work)?
        else {
            return Ok(Outcome::Indeterminate);
        };
        let mut last = None;
        for &value in new {
            admit(work, value.direct().location(), 1)?;
            if let Some(page) = value.get(b"P", work)?
                && page.direct().location() != new_page.direct().location()
            {
                return Ok(Outcome::Indeterminate);
            }
            let Some(kind) = value.get(b"Subtype", work)? else {
                return Ok(Outcome::Indeterminate);
            };
            let widget = kind.direct().name_equals(b"Widget", work)?;
            let identity = value.identity();
            let previous = lookup
                .get(&Identity(identity.0, identity.1), work)
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?
                .copied();
            if let Some(index) = previous {
                if used[index] {
                    return Ok(Outcome::Indeterminate);
                }
                used[index] = true;
                if permission != Permission::Annotations && last.is_some_and(|last| index <= last) {
                    return Ok(Outcome::Forbidden);
                }
                last = Some(index);
                if self.same_graph_values(old[index], value, work).await? {
                    continue;
                }
            }
            if widget {
                let result = self
                    .widget_change(
                        previous.map(|index| old[index]),
                        value,
                        scope,
                        permission,
                        work,
                    )
                    .await?;
                if result != Outcome::Permitted {
                    return Ok(result);
                }
            } else {
                if permission != Permission::Annotations {
                    return Ok(Outcome::Forbidden);
                }
                if !known_annotation(value, work)? {
                    return Ok(Outcome::Indeterminate);
                }
            }
        }
        for (index, was_used) in used.iter().enumerate() {
            admit(work, location, 1)?;
            if *was_used {
                continue;
            }
            let widget = old[index]
                .get(b"Subtype", work)?
                .map(|value| value.direct().name_equals(b"Widget", work))
                .transpose()?
                .unwrap_or(false);
            if widget || permission != Permission::Annotations {
                return Ok(Outcome::Forbidden);
            }
            if !known_annotation(old[index], work)? {
                return Ok(Outcome::Indeterminate);
            }
        }
        Ok(Outcome::Permitted)
    }

    async fn widget_change<'a, 's>(
        &self,
        old: Option<GraphObject<'a, 's, S::Document, S::Generation>>,
        new: GraphObject<'a, 's, S::Document, S::Generation>,
        scope: &FieldScope<'_, 'a, 's, S::Document, S::Generation, impl Work>,
        permission: Permission,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        let FieldScope {
            before,
            after,
            fields,
        } = scope;
        let Some(field) = field(new, fields, work)? else {
            return Ok(Outcome::Indeterminate);
        };
        let current = &after.values()[field];
        let value = after.value(field, work)?;
        if let Some(old) = old {
            let omitted = if current.object().direct().location() == new.direct().location() {
                &[b"AP".as_slice(), b"AS", b"V", b"P", b"Parent"][..]
            } else {
                &[b"AP".as_slice(), b"AS", b"P", b"Parent"][..]
            };
            // ISO 32000-1, 12.7.4.5: Parent links a separate widget to its
            // field. Compare that binding, while the field owns value checks.
            if old.get(b"Parent", work)?.map(GraphObject::identity)
                != new.get(b"Parent", work)?.map(GraphObject::identity)
            {
                return Ok(Outcome::Forbidden);
            }
            if !self.same_dictionary_except(old, new, omitted, work).await? {
                return Ok(Outcome::Forbidden);
            }
            if old.get(b"P", work)?.map(GraphObject::identity)
                != new.get(b"P", work)?.map(GraphObject::identity)
            {
                return Ok(Outcome::Forbidden);
            }
            let Some(previous) = before.get(current.name(), work)? else {
                return Ok(Outcome::Indeterminate);
            };
            let old_value = before.value(previous, work)?;
            if self.same_optional(old_value, value, work).await? {
                return Ok(Outcome::Forbidden);
            }
        } else if !current.is_signature() || !signature(value, work)? {
            return Ok(Outcome::Forbidden);
        }
        if permission == Permission::NoChanges && !timestamp(value, work)? {
            return Ok(Outcome::Forbidden);
        }
        if !state(new.get(b"AS", work)?, value, work)? || !appearance(new.get(b"AP", work)?, work)?
        {
            return Ok(Outcome::Indeterminate);
        }
        Ok(Outcome::Permitted)
    }
}

fn array<'a, 's, D: Copy + Eq, G: Copy + Eq>(
    value: GraphObject<'a, 's, D, G>,
    work: &impl Work,
) -> crate::Result<OwnedVec<GraphObject<'a, 's, D, G>, Memory>> {
    let location = value.direct().location();
    if value.direct().kind() != Type::Array {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Dictionary),
            location,
        });
    }
    let mut output = work.vector();
    for member in value.members(work).expect("array") {
        let member = member?;
        if member.direct().reference().is_none() {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Object),
                location: member.direct().location(),
            });
        }
        let member = member.resolved(work)?.ok_or(Error {
            kind: ErrorKind::Syntax(Syntax::Object),
            location,
        })?;
        output.try_push(member).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
    }
    Ok(output.into_owned())
}

fn field<D: Copy + Eq, G: Copy + Eq>(
    widget: GraphObject<'_, '_, D, G>,
    fields: &OwnedMap<(usize, usize, usize), usize, impl Work>,
    work: &impl Work,
) -> crate::Result<Option<usize>> {
    let location = widget.direct().location();
    if let Some(&index) = fields
        .get(&(widget.owner, widget.node.0, 0), work)
        .map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?
    {
        return Ok(Some(index));
    }
    if let Some(parent) = widget.get(b"Parent", work)? {
        return fields
            .get(&(parent.owner, parent.node.0, 0), work)
            .map(Option::<&usize>::copied)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            });
    }
    Ok(None)
}

fn known_annotation<D: Copy + Eq, G: Copy + Eq>(
    value: GraphObject<'_, '_, D, G>,
    work: &impl Work,
) -> crate::Result<bool> {
    let Some(kind) = value.get(b"Subtype", work)? else {
        return Ok(false);
    };
    if let Some(ty) = value.get(b"Type", work)?
        && !ty.direct().name_equals(b"Annot", work)?
    {
        return Ok(false);
    }
    for name in [
        b"Text".as_slice(),
        b"Link",
        b"FreeText",
        b"Line",
        b"Square",
        b"Circle",
        b"Polygon",
        b"PolyLine",
        b"Highlight",
        b"Underline",
        b"Squiggly",
        b"StrikeOut",
        b"Stamp",
        b"Caret",
        b"Ink",
        b"Popup",
        b"FileAttachment",
        b"Sound",
        b"Movie",
        b"Screen",
        b"PrinterMark",
        b"TrapNet",
        b"Watermark",
        b"3D",
        b"Redact",
    ] {
        if kind.direct().name_equals(name, work)? {
            return Ok(true);
        }
    }
    Ok(false)
}
