//! Source-proven named page instantiation, with no label-only exemption.

use super::{Copies, FieldScope, Identity, array};
use crate::{
    arena::Kind,
    document::{Document, GraphObject},
    error::{Error, ErrorKind, ReadFailure, Syntax},
    fields::Fields,
    model::admit,
    object::Type,
    permissions::{Outcome, Permission},
    range::RangeSource,
};
use structured_asn1::memory::{OwnedVec, Work};
mod widgets;

struct Node<'a, 's, D, G> {
    value: GraphObject<'a, 's, D, G>,
    parent: Option<usize>,
    branch: bool,
    count: u64,
}
struct Pages<'a, 's, D, G> {
    nodes: OwnedVec<Node<'a, 's, D, G>>,
    leaves: OwnedVec<usize>,
}
struct Named<'a, 's, D, G> {
    key: OwnedVec<u8>,
    page: GraphObject<'a, 's, D, G>,
}
struct TemplateContext<'f, 'a, 's, D, G, W: Work> {
    templates: &'f [Named<'a, 's, D, G>],
    visible: &'f [Named<'a, 's, D, G>],
    old_leaves: &'f structured_asn1::memory::OwnedMap<Identity, usize, W>,
    old_fields: &'f structured_asn1::memory::OwnedMap<(usize, usize, usize), usize, W>,
    fields: FieldScope<'f, 'a, 's, D, G, W>,
    location: crate::source::Location,
}

enum Step<'a, 's, D, G> {
    Node(GraphObject<'a, 's, D, G>, bool),
    End(
        GraphObject<'a, 's, D, G>,
        usize,
        Option<GraphObject<'a, 's, D, G>>,
    ),
}

fn field_index<D: Copy + Eq, G: Copy + Eq, W: Work>(
    fields: &Fields<'_, '_, D, G>,
    location: crate::source::Location,
    work: &W,
) -> crate::Result<structured_asn1::memory::OwnedMap<(usize, usize, usize), usize, W>> {
    let mut output = work.map();
    for (ordinal, field) in fields.values().iter().enumerate() {
        let value = field.object();
        output
            .try_insert((value.owner, value.node.0, 0), ordinal)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
    }
    Ok(output)
}

type ComparedPages<'a, 's, D, G> = (
    Pages<'a, 's, D, G>,
    Pages<'a, 's, D, G>,
    crate::source::Location,
);

fn compared_pages<'a, 's, D: Copy + Eq, G: Copy + Eq>(
    before: &Fields<'a, 's, D, G>,
    after: &Fields<'a, 's, D, G>,
    work: &impl Work,
) -> crate::Result<Option<ComparedPages<'a, 's, D, G>>> {
    let (Some(a), Some(b)) = (
        before.graph.root().get(b"Pages", work)?,
        after.graph.root().get(b"Pages", work)?,
    ) else {
        return Ok(None);
    };
    let Some(old) = flatten(a, work)? else {
        return Ok(None);
    };
    let Some(new) = flatten(b, work)? else {
        return Ok(None);
    };
    Ok(Some((old, new, b.direct().location())))
}

fn leaf_index<D: Copy + Eq, G: Copy + Eq, W: Work>(
    pages: &Pages<'_, '_, D, G>,
    location: crate::source::Location,
    work: &W,
) -> crate::Result<structured_asn1::memory::OwnedMap<Identity, usize, W>> {
    let mut output = work.map();
    for (ordinal, &index) in pages.leaves.iter().enumerate() {
        let id = pages.nodes[index].value.identity();
        output
            .try_insert(Identity(id.0, id.1), ordinal)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
    }
    Ok(output)
}

impl<S: RangeSource> Document<'_, S> {
    async fn template_branches<'a, 's>(
        &self,
        old: &Pages<'a, 's, S::Document, S::Generation>,
        new: &Pages<'a, 's, S::Document, S::Generation>,
        location: crate::source::Location,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        let mut old_branches = work.map();
        let mut new_branches = work.map();
        let refusal = |cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        };
        for (ordinal, node) in old.nodes.iter().enumerate() {
            admit(work, location, 1)?;
            if node.branch {
                let id = node.value.identity();
                old_branches
                    .try_insert(Identity(id.0, id.1), ordinal)
                    .map_err(refusal)?;
            }
        }
        for node in &new.nodes {
            admit(work, location, 1)?;
            if !node.branch {
                continue;
            }
            let id = node.value.identity();
            let id = Identity(id.0, id.1);
            new_branches
                .try_insert(Identity(id.0, id.1), ())
                .map_err(refusal)?;
            if let Some(&ordinal) = old_branches.get(&id, work).map_err(refusal)? {
                if !self
                    .same_dictionary_except(
                        old.nodes[ordinal].value,
                        node.value,
                        &[b"Type", b"Parent", b"Kids", b"Count"],
                        work,
                    )
                    .await?
                {
                    return Ok(Outcome::Forbidden);
                }
            } else if !branch_metadata(node.value, work)? {
                return Ok(Outcome::Indeterminate);
            }
        }
        for node in &old.nodes {
            admit(work, location, 1)?;
            if !node.branch {
                continue;
            }
            let id = node.value.identity();
            if new_branches
                .get(&Identity(id.0, id.1), work)
                .map_err(refusal)?
                .is_none()
                && !branch_metadata(node.value, work)?
            {
                return Ok(Outcome::Indeterminate);
            }
        }
        Ok(Outcome::Permitted)
    }

    async fn instantiate_page<'a, 's>(
        &self,
        page: GraphObject<'a, 's, S::Document, S::Generation>,
        scope: &TemplateContext<'_, 'a, 's, S::Document, S::Generation, impl Work>,
        copies: &mut Copies<impl Work>,
        permission: Permission,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        let TemplateContext {
            templates,
            visible,
            old_leaves,
            old_fields,
            fields,
            location,
        } = scope;
        let location = *location;
        let refusal = |cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        };
        let Some(marker) = page.get(b"TemplateInstantiated", work)? else {
            return Ok(Outcome::Forbidden);
        };
        let reading = marker.graph.nodes[marker.owner]
            .reading
            .as_ref()
            .expect("resolved marker owner");
        let Kind::Name(name) = reading.value.arena.nodes[marker.node.0].kind else {
            return Ok(Outcome::Indeterminate);
        };
        let name = &reading.value.arena.names[name.start..name.start + name.length];
        let template = find(templates, name, work, location)?;
        let original_page = find(visible, name, work, location)?;
        let (prototype, hidden) = match (template, original_page) {
            (Some(value), None) => (value, true),
            (None, Some(value)) => (value, false),
            (None, None) => return Ok(Outcome::Forbidden),
            (Some(_), Some(_)) => return Ok(Outcome::Indeterminate),
        };
        let Some(kind) = prototype.get(b"Type", work)? else {
            return Ok(Outcome::Indeterminate);
        };
        if hidden {
            if !kind.direct().name_equals(b"Template", work)?
                || prototype.get(b"Parent", work)?.is_some()
                || prototype.get(b"B", work)?.is_some()
            {
                return Ok(Outcome::Indeterminate);
            }
        } else {
            let id = prototype.identity();
            if !kind.direct().name_equals(b"Page", work)?
                || old_leaves
                    .get(&Identity(id.0, id.1), work)
                    .map_err(refusal)?
                    .is_none()
            {
                return Ok(Outcome::Indeterminate);
            }
        }
        if !self
            .same_dictionary_except(
                prototype,
                page,
                &[b"Type", b"Parent", b"TemplateInstantiated", b"Annots"],
                work,
            )
            .await?
        {
            return Ok(Outcome::Forbidden);
        }
        let annotations = self
            .template_annotations(
                (prototype, page),
                fields,
                old_fields,
                copies,
                permission,
                work,
            )
            .await?;
        if annotations != Outcome::Permitted {
            return Ok(annotations);
        }
        Ok(Outcome::Permitted)
    }

    pub(super) async fn classify_template_pages<'a, 's>(
        &self,
        before: &Fields<'a, 's, S::Document, S::Generation>,
        after: &Fields<'a, 's, S::Document, S::Generation>,
        permission: Permission,
        copies: &mut Copies<impl Work>,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        // ISO32000-1 Table254 permits instantiation, not arbitrary page
        // insertion. Table30 identifies the original named page; §12.7.6
        // and Table36 provide the original Pages/Templates name-tree binding.
        // https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
        if permission == Permission::NoChanges {
            return Ok(Outcome::Forbidden);
        }
        let Some((old, new, location)) = compared_pages(before, after, work)? else {
            return Ok(Outcome::Indeterminate);
        };
        let Some(names) = before.graph.root().get(b"Names", work)? else {
            return Ok(Outcome::Forbidden);
        };
        let Some(templates) = self
            .named_pages(names.get(b"Templates", work)?, work)
            .await?
        else {
            return Ok(Outcome::Indeterminate);
        };
        let Some(visible) = self.named_pages(names.get(b"Pages", work)?, work).await? else {
            return Ok(Outcome::Indeterminate);
        };
        let refusal = |cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        };
        let fields = field_index(after, location, work)?;
        let old_fields = field_index(before, location, work)?;
        let old_leaves = leaf_index(&old, location, work)?;
        let branches = self.template_branches(&old, &new, location, work).await?;
        if branches != Outcome::Permitted {
            return Ok(branches);
        }
        let mut cursor = 0;
        for &index in &new.leaves {
            admit(work, location, 1)?;
            let page = new.nodes[index].value;
            let id = page.identity();
            if let Some(&ordinal) = old_leaves
                .get(&Identity(id.0, id.1), work)
                .map_err(refusal)?
            {
                if ordinal != cursor {
                    return Ok(Outcome::Forbidden);
                }
                let previous = old.nodes[old.leaves[ordinal]].value;
                if !self
                    .same_dictionary_except(previous, page, &[b"Parent", b"Annots"], work)
                    .await?
                {
                    return Ok(Outcome::Forbidden);
                }
                let result = self
                    .classify_annotations(
                        previous,
                        page,
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
                cursor += 1;
                continue;
            }
            let outcome = self
                .instantiate_page(
                    page,
                    &TemplateContext {
                        templates: &templates,
                        visible: &visible,
                        old_leaves: &old_leaves,
                        old_fields: &old_fields,
                        fields: FieldScope {
                            before,
                            after,
                            fields: &fields,
                        },
                        location,
                    },
                    copies,
                    permission,
                    work,
                )
                .await?;
            if outcome != Outcome::Permitted {
                return Ok(outcome);
            }
        }
        Ok(if cursor == old.leaves.len() {
            Outcome::Permitted
        } else {
            Outcome::Forbidden
        })
    }

    async fn named_limits<'a, 's>(
        &self,
        node: GraphObject<'a, 's, S::Document, S::Generation>,
        start: usize,
        limits: Option<GraphObject<'a, 's, S::Document, S::Generation>>,
        output: &[Named<'a, 's, S::Document, S::Generation>],
        work: &impl Work,
    ) -> Result<bool, ReadFailure<S::Error>> {
        if let Some(limits) = limits {
            let Some(mut limits) = limits.members(work) else {
                return Ok(false);
            };
            let (Some(low), Some(high), None) = (limits.next(), limits.next(), limits.next())
            else {
                return Ok(false);
            };
            let (low, high) = (low?.resolved(work)?, high?.resolved(work)?);
            let (Some(low), Some(high)) = (low, high) else {
                return Ok(false);
            };
            if start == output.len() {
                return Ok(false);
            }
            let low = self.name_key(low, work).await?;
            let high = self.name_key(high, work).await?;
            admit(
                work,
                node.direct().location(),
                (low.len() + high.len()) as u64,
            )?;
            if low != output[start].key || high != output.last().expect("nonempty subtree").key {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn named_pages<'a, 's>(
        &self,
        root: Option<GraphObject<'a, 's, S::Document, S::Generation>>,
        work: &impl Work,
    ) -> Result<Option<OwnedVec<Named<'a, 's, S::Document, S::Generation>>>, ReadFailure<S::Error>>
    {
        let mut output: OwnedVec<Named<'a, 's, S::Document, S::Generation>, _> = work.vector();
        let Some(root) = root else {
            return Ok(Some(output.into_owned()));
        };
        let location = root.direct().location();
        let failure = |cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        };
        let mut pending = work.vector();
        let mut seen = work.map();
        pending.try_push(Step::Node(root, true)).map_err(failure)?;
        while let Some(step) = pending.pop() {
            admit(work, location, 1)?;
            let (node, is_root) = match step {
                Step::End(node, start, limits) => {
                    if !self
                        .named_limits(node, start, limits, &output, work)
                        .await?
                    {
                        return Ok(None);
                    }
                    continue;
                }
                Step::Node(node, root) => (node, root),
            };
            if seen
                .try_insert((node.owner, node.node.0, 0), ())
                .map_err(failure)?
                .is_some()
            {
                return Ok(None);
            }
            let names = node.get(b"Names", work)?;
            let kids = node.get(b"Kids", work)?;
            let limits = node.get(b"Limits", work)?;
            if is_root == limits.is_some() {
                return Ok(None);
            }
            pending
                .try_push(Step::End(node, output.len(), limits))
                .map_err(failure)?;
            match (names, kids) {
                (Some(names), None) => {
                    let Some(mut members) = names.members(work) else {
                        return Ok(None);
                    };
                    while let Some(key) = members.next() {
                        let key = key?.resolved(work)?.ok_or(Error {
                            kind: ErrorKind::Syntax(Syntax::Object),
                            location,
                        })?;
                        let Some(page) = members.next() else {
                            return Ok(None);
                        };
                        let page = page?;
                        if page.direct().reference().is_none() {
                            return Ok(None);
                        }
                        let Some(page) = page.resolved(work)? else {
                            return Ok(None);
                        };
                        let key = self.name_key(key, work).await?;
                        if let Some(previous) = output.last() {
                            admit(
                                work,
                                page.direct().location(),
                                key.len().min(previous.key.len()) as u64 + 1,
                            )?;
                            if previous.key.as_ref() >= key.as_ref() {
                                return Ok(None);
                            }
                        }
                        output.try_push(Named { key, page }).map_err(failure)?;
                    }
                }
                (None, Some(kids)) => {
                    let kids = array(kids, work)?;
                    if kids.is_empty() {
                        return Ok(None);
                    }
                    for child in kids.into_iter().rev() {
                        pending
                            .try_push(Step::Node(child, false))
                            .map_err(failure)?;
                    }
                }
                _ => return Ok(None),
            }
        }
        Ok(Some(output.into_owned()))
    }

    async fn name_key(
        &self,
        value: GraphObject<'_, '_, S::Document, S::Generation>,
        work: &impl Work,
    ) -> Result<OwnedVec<u8>, ReadFailure<S::Error>> {
        if value.direct().kind() != Type::String {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::String),
                location: value.direct().location(),
            }
            .into());
        }
        let reading = value.graph.nodes[value.owner]
            .reading
            .as_ref()
            .expect("resolved original string owner");
        self.string_in(
            reading,
            value.graph.decoded(value.owner),
            value.node,
            usize::MAX,
            work,
        )
        .await
    }
}

fn find<'a, 's, D: Copy + Eq, G: Copy + Eq>(
    values: &[Named<'a, 's, D, G>],
    key: &[u8],
    work: &impl Work,
    location: crate::source::Location,
) -> crate::Result<Option<GraphObject<'a, 's, D, G>>> {
    let (mut low, mut high) = (0, values.len());
    while low < high {
        let middle = low + (high - low) / 2;
        admit(
            work,
            location,
            key.len().min(values[middle].key.len()) as u64 + 1,
        )?;
        match values[middle].key.as_ref().cmp(key) {
            core::cmp::Ordering::Less => low = middle + 1,
            core::cmp::Ordering::Greater => high = middle,
            core::cmp::Ordering::Equal => return Ok(Some(values[middle].page)),
        }
    }
    Ok(None)
}

fn flatten<'a, 's, D: Copy + Eq, G: Copy + Eq>(
    root: GraphObject<'a, 's, D, G>,
    work: &impl Work,
) -> crate::Result<Option<Pages<'a, 's, D, G>>> {
    let location = root.direct().location();
    let failure = |cause| Error {
        kind: ErrorKind::Resource(cause),
        location,
    };
    let mut nodes: OwnedVec<Node<'a, 's, D, G>, _> = work.vector();
    let mut leaves = work.vector();
    let mut pending = work.vector();
    let mut seen = work.map();
    pending.try_push((root, None::<usize>)).map_err(failure)?;
    while let Some((value, parent)) = pending.pop() {
        admit(work, value.direct().location(), 1)?;
        if seen
            .try_insert((value.owner, value.node.0, 0), ())
            .map_err(failure)?
            .is_some()
        {
            return Ok(None);
        }
        if let Some(parent) = parent {
            if value.get(b"Parent", work)?.is_none_or(|actual| {
                actual.direct().location() != nodes[parent].value.direct().location()
            }) {
                return Ok(None);
            }
        } else if value.get(b"Parent", work)?.is_some() {
            return Ok(None);
        }
        let Some(kind) = value.get(b"Type", work)? else {
            return Ok(None);
        };
        let branch = kind.direct().name_equals(b"Pages", work)?;
        if !branch && !kind.direct().name_equals(b"Page", work)? {
            return Ok(None);
        }
        let ordinal = nodes.len();
        nodes
            .try_push(Node {
                value,
                parent,
                branch,
                count: u64::from(!branch),
            })
            .map_err(failure)?;
        if branch {
            let Some(kids) = value.get(b"Kids", work)? else {
                return Ok(None);
            };
            let kids = array(kids, work)?;
            for child in kids.into_iter().rev() {
                pending.try_push((child, Some(ordinal))).map_err(failure)?;
            }
        } else {
            leaves.try_push(ordinal).map_err(failure)?;
        }
    }
    for index in (0..nodes.len()).rev() {
        admit(work, location, 1)?;
        let count = nodes[index].count;
        if nodes[index].branch
            && nodes[index]
                .value
                .get(b"Count", work)?
                .map(|value| value.direct().unsigned(work))
                .transpose()?
                != Some(count)
        {
            return Ok(None);
        }
        if let Some(parent) = nodes[index].parent {
            nodes[parent].count = nodes[parent].count.checked_add(count).ok_or(Error {
                kind: ErrorKind::Syntax(Syntax::Number),
                location,
            })?;
        }
    }
    Ok(Some(Pages {
        nodes: nodes.into_owned(),
        leaves: leaves.into_owned(),
    }))
}

fn branch_metadata<D: Copy + Eq, G: Copy + Eq>(
    value: GraphObject<'_, '_, D, G>,
    work: &impl Work,
) -> crate::Result<bool> {
    let Some(members) = value.members(work) else {
        return Ok(false);
    };
    let mut key = true;
    for member in members {
        let member = member?;
        if key
            && !member.direct().name_equals(b"Type", work)?
            && !member.direct().name_equals(b"Parent", work)?
            && !member.direct().name_equals(b"Kids", work)?
            && !member.direct().name_equals(b"Count", work)?
        {
            return Ok(false);
        }
        key = !key;
    }
    Ok(true)
}
