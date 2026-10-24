//! Permission categories derive from actual graph edges, never object numbers.

use super::{AssessmentError, Outcome, Permission};
use crate::{
    document::{Document, GraphObject},
    error::{Error, ErrorKind, ReadFailure, Syntax},
    fields::Fields,
    model::admit,
    object::Type,
    range::RangeSource,
};
use structured_asn1::memory::Work;
mod pages;
#[cfg(test)]
mod tests;

enum FieldChange {
    Permitted(bool),
    Refused(Outcome),
}

impl<S: RangeSource> Document<'_, S> {
    async fn existing_field<'a, 's>(
        &self,
        before: &Fields<'a, 's, S::Document, S::Generation>,
        after: &Fields<'a, 's, S::Document, S::Generation>,
        (ordinal, index): (usize, usize),
        permission: Permission,
        work: &impl Work,
    ) -> Result<FieldChange, ReadFailure<S::Error>> {
        let field = &before.values()[ordinal];
        let mut added_signature = false;
        let current = &after.values()[index];
        if field.is_signature() != current.is_signature() {
            return Ok(FieldChange::Refused(Outcome::Forbidden));
        }
        if !self
            .same_dictionary_except(
                field.object(),
                current.object(),
                &[b"V", b"AP", b"AS", b"Kids", b"Parent", b"P"],
                work,
            )
            .await?
        {
            return Ok(FieldChange::Refused(Outcome::Forbidden));
        }
        if field.object().get(b"P", work)?.map(GraphObject::identity)
            != current.object().get(b"P", work)?.map(GraphObject::identity)
        {
            return Ok(FieldChange::Refused(Outcome::Forbidden));
        }
        if field.parent().map(|at| before.values()[at].name())
            != current.parent().map(|at| after.values()[at].name())
        {
            return Ok(FieldChange::Refused(Outcome::Forbidden));
        }
        let first = before.value(ordinal, work)?;
        let second = after.value(index, work)?;
        let same = self.same_optional(first, second, work).await?;
        if !same {
            if field.is_signature() {
                if first.is_some_and(|value| value.direct().kind() != Type::Null) {
                    return Ok(FieldChange::Refused(Outcome::Forbidden));
                }
                if !timestamp(second, work)? && permission == Permission::NoChanges {
                    return Ok(FieldChange::Refused(Outcome::Forbidden));
                }
                if !signature(second, work)? {
                    return Ok(FieldChange::Refused(Outcome::Indeterminate));
                }
                added_signature = true;
            } else {
                if permission == Permission::NoChanges {
                    return Ok(FieldChange::Refused(Outcome::Forbidden));
                }
                if before
                    .inherited(ordinal, b"Ff", work)?
                    .map(|value| value.direct().unsigned(work))
                    .transpose()?
                    .unwrap_or(0)
                    & 1
                    != 0
                {
                    return Ok(FieldChange::Refused(Outcome::Forbidden));
                }
                if !form_value(after.inherited(index, b"FT", work)?, second, work)? {
                    return Ok(FieldChange::Refused(Outcome::Indeterminate));
                }
            }
        }
        let first_ap = field.object().get(b"AP", work)?;
        let second_ap = current.object().get(b"AP", work)?;
        if !self.same_optional(first_ap, second_ap, work).await? {
            // Appearance updates require an actual permitted value change.
            // Graphics semantics not established here remain unavailable.
            if same {
                return Ok(FieldChange::Refused(Outcome::Forbidden));
            }
            if !appearance(second_ap, work)? {
                return Ok(FieldChange::Refused(Outcome::Indeterminate));
            }
        }
        let old_state = field.object().get(b"AS", work)?;
        let new_state = current.object().get(b"AS", work)?;
        if !self.same_optional(old_state, new_state, work).await?
            && (same || !state(new_state, second, work)?)
        {
            return Ok(FieldChange::Refused(Outcome::Indeterminate));
        }
        Ok(FieldChange::Permitted(added_signature))
    }

    async fn form_changes(
        &self,
        old: GraphObject<'_, '_, S::Document, S::Generation>,
        new: GraphObject<'_, '_, S::Document, S::Generation>,
        added_signature: bool,
        copied: bool,
        work: &impl Work,
    ) -> Result<Outcome, ReadFailure<S::Error>> {
        let first_form = old.get(b"AcroForm", work)?;
        let second_form = new.get(b"AcroForm", work)?;
        match (first_form, second_form) {
            (Some(a), Some(b)) => {
                if !self
                    .same_dictionary_except(a, b, &[b"Fields", b"SigFlags"], work)
                    .await?
                {
                    return Ok(Outcome::Indeterminate);
                }
                let first = flags(a, work)?;
                let second = flags(b, work)?;
                if first != second && (!added_signature || first & !second != 0 || second & !3 != 0)
                {
                    return Ok(Outcome::Forbidden);
                }
            }
            (None, None) => {}
            (None, Some(form)) if added_signature || copied => {
                let members = form.members(work).ok_or(Error {
                    kind: ErrorKind::Syntax(Syntax::Dictionary),
                    location: form.direct().location(),
                })?;
                let mut key = true;
                for member in members {
                    let member = member?;
                    if key
                        && !member.direct().name_equals(b"Fields", work)?
                        && !member.direct().name_equals(b"SigFlags", work)?
                    {
                        return Ok(Outcome::Indeterminate);
                    }
                    key = !key;
                }
            }
            _ => return Ok(Outcome::Forbidden),
        }
        Ok(Outcome::Permitted)
    }

    #[expect(
        clippy::result_large_err,
        reason = "validation-update interpretation retains the actual material error and its original encoded enclosure rather than flattening or boxing it"
    )]
    pub(super) async fn classify_changes<'a, 's>(
        &self,
        before: &Fields<'a, 's, S::Document, S::Generation>,
        after: &Fields<'a, 's, S::Document, S::Generation>,
        permission: Permission,
        work: &impl Work,
    ) -> Result<Outcome, AssessmentError<S::Error>> {
        // ISO32000-1 §12.8.2.2/Table254 and EN319142-1 §5.4.3.
        // Exemptions are attached to catalog/field edges. A shared appearance
        // or DSS object reached through page contents is still compared there.
        // https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf
        let old = before.graph.root();
        let new = after.graph.root();
        if !self
            .same_dictionary_except(old, new, &[b"DSS", b"AcroForm", b"Pages"], work)
            .await?
        {
            return Ok(Outcome::Forbidden);
        }
        let mut copies = work.map();
        let pages = self
            .classify_pages(before, after, permission, &mut copies, work)
            .await?;
        if pages != Outcome::Permitted {
            return Ok(pages);
        }

        let mut added_signature = false;
        for (ordinal, field) in before.values().iter().enumerate() {
            admit(work, field.object().direct().location(), 1)?;
            let Some(index) = after.get(field.name(), work)? else {
                return Ok(Outcome::Forbidden);
            };
            match self
                .existing_field(before, after, (ordinal, index), permission, work)
                .await?
            {
                FieldChange::Permitted(added) => {
                    if added {
                        added_signature = true;
                    }
                }
                FieldChange::Refused(outcome) => return Ok(outcome),
            }
        }
        for (ordinal, field) in after.values().iter().enumerate() {
            admit(work, field.object().direct().location(), 1)?;
            if before.get(field.name(), work)?.is_some() {
                continue;
            }
            let value = after.value(ordinal, work)?;
            let object = field.object();
            if copies
                .get(&(object.owner, object.node.0, 0), work)
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: object.direct().location(),
                })?
                .is_some()
            {
                if field.is_signature() && signature(value, work)? {
                    added_signature = true;
                }
                continue;
            }
            if !field.is_signature() || !signature(value, work)? {
                return Ok(Outcome::Forbidden);
            }
            if !timestamp(value, work)? && permission == Permission::NoChanges {
                return Ok(Outcome::Forbidden);
            }
            added_signature = true;
        }
        let form = self
            .form_changes(old, new, added_signature, !copies.is_empty(), work)
            .await?;
        if form != Outcome::Permitted {
            return Ok(form);
        }
        // DSS is a validation-update exemption, but all references and values
        // must still be a readable same-revision validation structure.
        let validation = self.validation(after.graph.revision(), work).await?;
        let parsed = validation.parse(work).map_err(AssessmentError::Material)?;
        if !parsed.all_values_readable() || !validation.all_vri_material_in_dss() {
            return Ok(Outcome::Indeterminate);
        }
        Ok(Outcome::Permitted)
    }

    async fn same_optional<'a, 's>(
        &self,
        a: Option<GraphObject<'a, 's, S::Document, S::Generation>>,
        b: Option<GraphObject<'a, 's, S::Document, S::Generation>>,
        work: &impl Work,
    ) -> Result<bool, ReadFailure<S::Error>> {
        match (a, b) {
            (Some(a), Some(b)) => self.same_graph_values(a, b, work).await,
            (None, None) => Ok(true),
            _ => Ok(false),
        }
    }
}

fn timestamp<D: Copy + Eq, G: Copy + Eq>(
    value: Option<GraphObject<'_, '_, D, G>>,
    work: &impl Work,
) -> crate::Result<bool> {
    let Some(value) = value else { return Ok(false) };
    if value.direct().kind() != Type::Dictionary {
        return Ok(false);
    }
    Ok(value
        .get(b"Type", work)?
        .is_some_and(|kind| kind.direct().kind() == Type::Name)
        && value
            .get(b"Type", work)?
            .expect("present Type")
            .direct()
            .name_equals(b"DocTimeStamp", work)?)
}

fn signature<D: Copy + Eq, G: Copy + Eq>(
    value: Option<GraphObject<'_, '_, D, G>>,
    work: &impl Work,
) -> crate::Result<bool> {
    let Some(value) = value else { return Ok(false) };
    if value.direct().kind() != Type::Dictionary {
        return Ok(false);
    }
    Ok(value
        .get(b"ByteRange", work)?
        .is_some_and(|value| value.direct().kind() == Type::Array)
        && value
            .get(b"Contents", work)?
            .is_some_and(|value| value.direct().kind() == Type::String))
}

fn flags<D: Copy + Eq, G: Copy + Eq>(
    form: GraphObject<'_, '_, D, G>,
    work: &impl Work,
) -> crate::Result<u64> {
    form.get(b"SigFlags", work)?
        .map(|value| value.direct().unsigned(work))
        .transpose()
        .map(|value| value.unwrap_or(0))
}

fn form_value<D: Copy + Eq, G: Copy + Eq>(
    kind: Option<GraphObject<'_, '_, D, G>>,
    value: Option<GraphObject<'_, '_, D, G>>,
    work: &impl Work,
) -> crate::Result<bool> {
    let Some(value) = value else { return Ok(true) };
    if value.direct().kind() == Type::Null {
        return Ok(true);
    }
    let Some(kind) = kind else { return Ok(false) };
    if kind.direct().name_equals(b"Tx", work)? {
        return Ok(value.direct().kind() == Type::String);
    }
    if kind.direct().name_equals(b"Btn", work)? {
        return Ok(value.direct().kind() == Type::Name);
    }
    if kind.direct().name_equals(b"Ch", work)? {
        if value.direct().kind() == Type::String {
            return Ok(true);
        }
        if value.direct().kind() != Type::Array {
            return Ok(false);
        }
        for entry in value.members(work).expect("array") {
            let Some(entry) = entry?.resolved(work)? else {
                return Ok(false);
            };
            if entry.direct().kind() != Type::String {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    Ok(false)
}

fn state<D: Copy + Eq, G: Copy + Eq>(
    state: Option<GraphObject<'_, '_, D, G>>,
    value: Option<GraphObject<'_, '_, D, G>>,
    work: &impl Work,
) -> crate::Result<bool> {
    let Some(state) = state else { return Ok(true) };
    if state.direct().kind() != Type::Name {
        return Ok(false);
    }
    if state.direct().name_equals(b"Off", work)? {
        return Ok(true);
    }
    let Some(value) = value else { return Ok(false) };
    let a = state.direct();
    let b = value.direct();
    if b.kind() != Type::Name {
        return Ok(false);
    }
    Ok(crate::dictionary::compare_names_between(
        &a.owner.arena,
        a.node,
        &b.owner.arena,
        b.node,
        work,
    )? == core::cmp::Ordering::Equal)
}

fn appearance<D: Copy + Eq, G: Copy + Eq>(
    value: Option<GraphObject<'_, '_, D, G>>,
    work: &impl Work,
) -> crate::Result<bool> {
    let Some(value) = value else { return Ok(true) };
    if value.direct().kind() != Type::Dictionary {
        return Ok(false);
    }
    for name in [b"N".as_slice(), b"R", b"D"] {
        let Some(entry) = value.get(name, work)? else {
            continue;
        };
        if entry.direct().kind() != Type::Dictionary {
            return Ok(false);
        }
        if entry.get(b"Subtype", work)?.is_some() {
            if !form(entry, work)? {
                return Ok(false);
            }
        } else {
            let mut members = entry.members(work).expect("appearance state dictionary");
            while let Some(key) = members.next() {
                if key?.direct().kind() != Type::Name {
                    return Ok(false);
                }
                let Some(value) = members.next() else {
                    return Ok(false);
                };
                let Some(value) = value?.resolved(work)? else {
                    return Ok(false);
                };
                if !form(value, work)? {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn form<D: Copy + Eq, G: Copy + Eq>(
    value: GraphObject<'_, '_, D, G>,
    work: &impl Work,
) -> crate::Result<bool> {
    if value.direct().kind() != Type::Dictionary {
        return Ok(false);
    }
    let reading = value.graph.nodes[value.owner]
        .reading
        .as_ref()
        .expect("graph owner");
    if value.node.0 != reading.value.root.0 || reading.stream.is_none() {
        return Ok(false);
    }
    let Some(kind) = value.get(b"Subtype", work)? else {
        return Ok(false);
    };
    kind.direct().name_equals(b"Form", work)
}
