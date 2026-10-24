//! Actual template widget copies, including inherited field metadata.

use super::super::super::{appearance, form_value, signature, state};
use super::super::{Copies, FieldScope, array, field, known_annotation};
use crate::{
    document::{Document, GraphObject},
    error::{Error, ErrorKind, ReadFailure},
    model::admit,
    permissions::{Outcome, Permission},
    range::RangeSource,
};
use structured_asn1::memory::{OwnedMap, Work};

type PagePair<'a, 's, D, G> = (GraphObject<'a, 's, D, G>, GraphObject<'a, 's, D, G>);

impl<S: RangeSource> Document<'_, S> {
    pub(super) async fn template_annotations<'a, 's>(
        &self,
        (prototype, page): PagePair<'a, 's, S::Document, S::Generation>,
        scope: &FieldScope<'_, 'a, 's, S::Document, S::Generation, impl Work>,
        old_fields: &OwnedMap<(usize, usize, usize), usize, impl Work>,
        copies: &mut Copies<impl Work>,
        permission: Permission,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        let old = prototype
            .get(b"Annots", work)?
            .map(|value| array(value, work))
            .transpose()?;
        let new = page
            .get(b"Annots", work)?
            .map(|value| array(value, work))
            .transpose()?;
        let old = old.as_deref().unwrap_or(&[]);
        let new = new.as_deref().unwrap_or(&[]);
        let mut cursor = 0;
        for &annotation in new {
            admit(work, annotation.direct().location(), 1)?;
            if let Some(parent) = annotation.get(b"P", work)?
                && parent.direct().location() != page.direct().location()
            {
                return Ok(Outcome::Indeterminate);
            }
            let widget = is_widget(annotation, work)?;
            if permission == Permission::Annotations && !widget {
                if !known_annotation(annotation, work)? {
                    return Ok(Outcome::Indeterminate);
                }
                continue;
            }
            if permission == Permission::Annotations {
                while cursor < old.len() && !is_widget(old[cursor], work)? {
                    if !known_annotation(old[cursor], work)? {
                        return Ok(Outcome::Indeterminate);
                    }
                    cursor += 1;
                }
            }
            let Some(&original) = old.get(cursor) else {
                return Ok(Outcome::Forbidden);
            };
            cursor += 1;
            if is_widget(original, work)? != widget {
                return Ok(Outcome::Forbidden);
            }
            if let Some(parent) = original.get(b"P", work)?
                && parent.direct().location() != prototype.direct().location()
            {
                return Ok(Outcome::Indeterminate);
            }
            if widget {
                let result = self
                    .template_widget(original, annotation, scope, old_fields, copies, work)
                    .await?;
                if result != Outcome::Permitted {
                    return Ok(result);
                }
            } else if !self
                .same_dictionary_except(original, annotation, &[b"P"], work)
                .await?
            {
                return Ok(Outcome::Forbidden);
            }
        }
        for &original in &old[cursor..] {
            admit(work, original.direct().location(), 1)?;
            if permission != Permission::Annotations || is_widget(original, work)? {
                return Ok(Outcome::Forbidden);
            }
            if !known_annotation(original, work)? {
                return Ok(Outcome::Indeterminate);
            }
        }
        Ok(Outcome::Permitted)
    }

    async fn copy_ancestry(
        &self,
        first: usize,
        second: usize,
        scope: &FieldScope<'_, '_, '_, S::Document, S::Generation, impl Work>,
        copies: &mut Copies<impl Work>,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        let FieldScope {
            before,
            after,
            fields: _,
        } = scope;
        let mut old = Some(first);
        let mut new = Some(second);
        loop {
            let (Some(a), Some(b)) = (old, new) else {
                return Ok(if old.is_none() && new.is_none() {
                    Outcome::Permitted
                } else {
                    Outcome::Indeterminate
                });
            };
            let previous = &before.values()[a];
            let current = &after.values()[b];
            admit(work, current.object().direct().location(), 1)?;
            if a != first
                && !self
                    .same_dictionary_except(
                        previous.object(),
                        current.object(),
                        &[b"P", b"Parent", b"T", b"Kids"],
                        work,
                    )
                    .await?
            {
                return Ok(Outcome::Forbidden);
            }
            if before.get(current.name(), work)?.is_some() {
                return Ok(Outcome::Forbidden);
            }
            let object = current.object();
            copies
                .try_insert((object.owner, object.node.0, 0), ())
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: object.direct().location(),
                })?;
            old = previous.parent();
            new = current.parent();
            debug_assert!(
                old.is_none_or(|parent| parent < a) && new.is_none_or(|parent| parent < b)
            );
        }
    }

    async fn template_widget<'a, 's>(
        &self,
        original: GraphObject<'a, 's, S::Document, S::Generation>,
        instance: GraphObject<'a, 's, S::Document, S::Generation>,
        scope: &FieldScope<'_, 'a, 's, S::Document, S::Generation, impl Work>,
        old_fields: &OwnedMap<(usize, usize, usize), usize, impl Work>,
        copies: &mut Copies<impl Work>,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        let FieldScope {
            before,
            after,
            fields,
        } = scope;
        let (Some(first), Some(second)) = (
            field(original, old_fields, work)?,
            field(instance, fields, work)?,
        ) else {
            return Ok(Outcome::Indeterminate);
        };
        if before.values()[first].is_signature() != after.values()[second].is_signature() {
            return Ok(Outcome::Forbidden);
        }
        // Table254 and §12.7.6 permit the instantiation. Renaming must not
        // change inherited field actions, flags, formatting or other metadata.
        // ISO32000-1 §12.7.7.2/Table249 and AnnexJ describe renamed copies.
        // https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
        if !self
            .same_dictionary_except(
                original,
                instance,
                &[b"P", b"Parent", b"T", b"V", b"AP", b"AS", b"Kids"],
                work,
            )
            .await?
            || !self
                .same_dictionary_except(
                    before.values()[first].object(),
                    after.values()[second].object(),
                    &[b"P", b"Parent", b"T", b"V", b"AP", b"AS", b"Kids"],
                    work,
                )
                .await?
        {
            return Ok(Outcome::Forbidden);
        }
        let a = before.value(first, work)?;
        let b = after.value(second, work)?;
        let same = self.same_optional(a, b, work).await?;
        if !same {
            if before
                .inherited(first, b"Ff", work)?
                .map(|value| value.direct().unsigned(work))
                .transpose()?
                .unwrap_or(0)
                & 1
                != 0
            {
                return Ok(Outcome::Forbidden);
            }
            if before.values()[first].is_signature() {
                if a.is_some() || !signature(b, work)? {
                    return Ok(Outcome::Forbidden);
                }
            } else if !form_value(after.inherited(second, b"FT", work)?, b, work)? {
                return Ok(Outcome::Indeterminate);
            }
        }
        if !self
            .same_optional(original.get(b"AP", work)?, instance.get(b"AP", work)?, work)
            .await?
        {
            if same {
                return Ok(Outcome::Forbidden);
            }
            if !appearance(instance.get(b"AP", work)?, work)? {
                return Ok(Outcome::Indeterminate);
            }
        }
        if !state(instance.get(b"AS", work)?, b, work)? {
            return Ok(Outcome::Indeterminate);
        }
        self.copy_ancestry(first, second, scope, copies, work).await
    }
}

fn is_widget<D: Copy + Eq, G: Copy + Eq>(
    value: GraphObject<'_, '_, D, G>,
    work: &impl Work,
) -> crate::Result<bool> {
    value
        .get(b"Subtype", work)?
        .map(|value| value.direct().name_equals(b"Widget", work))
        .transpose()
        .map(|value| value.unwrap_or(false))
}
