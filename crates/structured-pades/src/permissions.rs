//! Original signed transforms and historical permission evaluation.

use crate::{
    arena::Kind,
    document::{Document, Graph},
    error::{Error, ErrorKind, ReadFailure, Syntax},
    fields::Fields,
    model::{admit, get, named, required},
    range::RangeSource,
    signature::{Coverage, Signature},
    source::Location,
};
use structured_asn1::memory::{Memory, OwnedText, OwnedVec, Work};
mod classify;
mod placement;

/// Structural acquisition and interpreted validation-material failures remain
/// separate phases. The PDF reader itself does not carry CMS parser state.
#[derive(Debug)]
pub enum AssessmentError<E> {
    /// Original PDF syntax, source, or execution cause.
    Pdf(ReadFailure<E>),
    /// Original interpreted material cause and its actual source enclosure.
    Material(crate::material::MaterialFailure),
}
impl<E> From<ReadFailure<E>> for AssessmentError<E> {
    fn from(cause: ReadFailure<E>) -> Self {
        Self::Pdf(cause)
    }
}
impl<E> From<Error> for AssessmentError<E> {
    fn from(cause: Error) -> Self {
        Self::Pdf(cause.into())
    }
}
impl<E> From<crate::range::InputError<E>> for AssessmentError<E> {
    fn from(cause: crate::range::InputError<E>) -> Self {
        Self::Pdf(cause.into())
    }
}
pub use placement::Placement;

/// Original `DocMDP` permission, including its normative default P=2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// No ordinary document modification; validation updates remain separate.
    NoChanges,
    /// Form filling, template instantiation and signing are permitted.
    FormFill,
    /// Form/signing permissions also permit annotation changes.
    Annotations,
}

/// Original `FieldMDP` field-selection operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Every original field is protected.
    All,
    /// Only the named fields and their descendants are protected.
    Include,
    /// Every field except the named fields and their descendants is protected.
    Exclude,
}

/// One original `FieldMDP` selection, without writable replacement field names.
pub struct Lock {
    action: Action,
    fields: OwnedVec<OwnedText, Memory>,
    location: Location,
}

impl Lock {
    /// Original selection operator.
    #[must_use]
    pub fn action(&self) -> Action {
        self.action
    }
    /// Original fully qualified text names, decoded without normalizing them.
    #[must_use]
    pub fn fields(&self) -> &[OwnedText] {
        &self.fields
    }
    /// Original transform-parameter dictionary.
    #[must_use]
    pub fn location(&self) -> Location {
        self.location
    }

    fn protects(&self, name: &str, work: &impl Work) -> crate::Result<bool> {
        if self.action == Action::All {
            return Ok(true);
        }
        let mut selected = false;
        for field in &self.fields {
            admit(work, self.location, name.len().min(field.len()) as u64 + 1)?;
            if name == field.as_str()
                || (name.starts_with(field.as_str())
                    && name.as_bytes().get(field.len()) == Some(&b'.'))
            {
                selected = true;
                break;
            }
        }
        Ok(if self.action == Action::Include {
            selected
        } else {
            !selected
        })
    }
}

/// Format-derived permissions from the ORIGINAL signed dictionary.
pub struct Transforms {
    permission: Option<Permission>,
    locks: OwnedVec<Lock, Memory>,
    unsupported: bool,
    location: Location,
}

impl Transforms {
    /// Original signature dictionary carrying these transform selections.
    #[must_use]
    pub fn location(&self) -> Location {
        self.location
    }

    /// The original `DocMDP` permission, if this is a certification signature.
    #[must_use]
    pub fn permission(&self) -> Option<Permission> {
        self.permission
    }
    /// Every original `FieldMDP` transform, without choosing a successful subset.
    #[must_use]
    pub fn locks(&self) -> &[Lock] {
        &self.locks
    }
    /// A different transform requires its own normative mechanism.
    #[must_use]
    pub fn has_unsupported_transform(&self) -> bool {
        self.unsupported
    }
}

/// Completed modification result, independent of signature arithmetic and trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// All actual observed changes satisfy the original transform permissions.
    Permitted,
    /// At least one source-derived change violates a selected permission.
    Forbidden,
    /// A change's required semantics are unavailable; no positive result.
    Indeterminate,
    /// No original `DocMDP` or `FieldMDP` restriction was supplied by this signature.
    Unstated,
}

/// One original changed indirect definition. Names are facts of the source,
/// never caller-supplied modification categories.
#[derive(Debug, Clone, Copy)]
pub struct Change {
    /// Original indirect object identity.
    pub identity: (u64, u16),
    /// Definition in the compared revision, or its prior definition on deletion.
    pub location: Location,
}

/// Complete historical structural comparison with its actual original rules.
/// A signature's byte-range math must be considered independently by callers.
pub struct Assessment {
    transforms: Transforms,
    changes: OwnedVec<Change, Memory>,
    outcome: Outcome,
    source_revision: usize,
    compared_revision: usize,
}

impl Assessment {
    /// Original signed transform selections used for this comparison.
    #[must_use]
    pub fn transforms(&self) -> &Transforms {
        &self.transforms
    }
    /// Every observed original indirect-object change, including indeterminate ones.
    #[must_use]
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }
    /// Completed normative answer, never a math or application trust verdict.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
    /// Exact signed and compared chronological revision ordinals.
    #[must_use]
    pub fn revisions(&self) -> (usize, usize) {
        (self.source_revision, self.compared_revision)
    }
}

fn reference_fields(
    arena: &crate::arena::Arena<impl Work>,
    reference: crate::arena::NodeId,
    work: &impl Work,
) -> crate::Result<(crate::arena::NodeId, Option<crate::arena::NodeId>)> {
    let at = arena.nodes[reference.0].location;
    let method = required(arena, reference, b"TransformMethod", work)?;
    let parameters = get(arena, reference, b"TransformParams", work)?;
    if let Some(kind) = get(arena, reference, b"Type", work)?
        && !named(arena, kind, b"SigRef", work)?
    {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Dictionary),
            location: at,
        });
    }
    if let Some(parameters) = parameters {
        if !matches!(arena.nodes[parameters.0].kind, Kind::Dictionary(_, _)) {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Dictionary),
                location: arena.nodes[parameters.0].location,
            });
        }
        for (key, expected) in [
            (b"Type".as_slice(), b"TransformParams".as_slice()),
            (b"V", b"1.2"),
        ] {
            if let Some(value) = get(arena, parameters, key, work)?
                && !named(arena, value, expected, work)?
            {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::Dictionary),
                    location: arena.nodes[value.0].location,
                });
            }
        }
    }
    Ok((method, parameters))
}

impl<'s, S: RangeSource> Document<'s, S> {
    async fn field_lock(
        &self,
        reading: &crate::document::Reading<'s, S::Document, S::Generation>,
        graph: &Graph<'s, S::Document, S::Generation>,
        reference: crate::arena::NodeId,
        parameters: Option<crate::arena::NodeId>,
        work: &impl Work,
    ) -> Result<Lock, ReadFailure<S::Error>> {
        let arena = &reading.value.arena;
        let at = arena.nodes[reference.0].location;
        let data = required(arena, reference, b"Data", work)?;
        let Kind::Reference { number, generation } = arena.nodes[data.0].kind else {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Dictionary),
                location: arena.nodes[data.0].location,
            }
            .into());
        };
        let catalog = self
            .object(graph.revision, number, generation, work)
            .await?;
        if catalog
            .as_ref()
            .is_none_or(|value| value.value.root().location() != graph.root().direct().location())
        {
            return Err(Error {
                kind: ErrorKind::Ambiguous(Syntax::Dictionary),
                location: arena.nodes[data.0].location,
            }
            .into());
        }
        let parameters = parameters.ok_or(Error {
            kind: ErrorKind::Syntax(Syntax::Dictionary),
            location: at,
        })?;
        let action = required(arena, parameters, b"Action", work)?;
        let action = if named(arena, action, b"All", work)? {
            Action::All
        } else if named(arena, action, b"Include", work)? {
            Action::Include
        } else if named(arena, action, b"Exclude", work)? {
            Action::Exclude
        } else {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Name),
                location: arena.nodes[action.0].location,
            }
            .into());
        };
        let mut names = work.vector();
        let fields = get(arena, parameters, b"Fields", work)?;
        if fields.is_none() && action != Action::All {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Dictionary),
                location: at,
            }
            .into());
        }
        if let Some(fields) = fields {
            let Kind::Array(children) = arena.nodes[fields.0].kind else {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::Dictionary),
                    location: arena.nodes[fields.0].location,
                }
                .into());
            };
            let mut next = children.first;
            while let Some(index) = next {
                admit(work, at, 1)?;
                let link = arena.links[index];
                next = link.next;
                let bytes = self.string(reading, link.value, usize::MAX, work).await?;
                let name = crate::text::read(&bytes, arena.nodes[link.value.0].location, work)?;
                names.try_push(name).map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: at,
                })?;
            }
        }
        Ok(Lock {
            action,
            fields: names.into_owned(),
            location: arena.nodes[parameters.0].location,
        })
    }

    /// Reads ISO32000-1 §12.8.2/Tables253,254,256 from the original signature.
    /// Parameters are direct signed objects; `FieldMDP` Data is the specified
    /// indirect catalog identity, not a caller-selected replacement graph.
    /// <https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf>
    pub async fn transforms<W: Work>(
        &self,
        signature: Signature<'_, 's, S::Document, S::Generation>,
        graph: &Graph<'s, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<Transforms, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let location = signature.location();
        if !core::ptr::eq(graph.session, self.session)
            || graph.stamp != self.stamp
            || signature.coverage() != Coverage::Revision(graph.revision)
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        self.check(&work, location)?;
        let reading = signature.owner();
        let arena = &reading.value.arena;
        let mut output = Transforms {
            permission: None,
            locks: work.vector().into_owned(),
            unsupported: false,
            location,
        };
        let mut locks = work.vector();
        if let Some(references) = get(arena, signature.node(), b"Reference", &work)? {
            let Kind::Array(children) = arena.nodes[references.0].kind else {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::Dictionary),
                    location: arena.nodes[references.0].location,
                }
                .into());
            };
            let mut next = children.first;
            while let Some(index) = next {
                admit(&work, location, 1)?;
                let link = arena.links[index];
                next = link.next;
                let reference = link.value;
                let at = arena.nodes[reference.0].location;
                let (method, parameters) = reference_fields(arena, reference, &work)?;
                if named(arena, method, b"DocMDP", &work)? {
                    if output.permission.is_some() {
                        return Err(Error {
                            kind: ErrorKind::Ambiguous(Syntax::Dictionary),
                            location: at,
                        }
                        .into());
                    }
                    // ISO32000-1 Table254 declares a number: integral real
                    // spellings are valid, fractional values cannot truncate.
                    let permission = parameters
                        .map(|node| get(arena, node, b"P", &work))
                        .transpose()?
                        .flatten()
                        .map(|node| crate::model::unsigned_number(arena, node, &work))
                        .transpose()?
                        .unwrap_or(2);
                    output.permission = Some(match permission {
                        1 => Permission::NoChanges,
                        2 => Permission::FormFill,
                        3 => Permission::Annotations,
                        _ => {
                            return Err(Error {
                                kind: ErrorKind::Syntax(Syntax::Number),
                                location: at,
                            }
                            .into());
                        }
                    });
                } else if named(arena, method, b"FieldMDP", &work)? {
                    let lock = self
                        .field_lock(reading, graph, reference, parameters, &work)
                        .await?;
                    locks.try_push(lock).map_err(|cause| Error {
                        kind: ErrorKind::Resource(cause),
                        location: at,
                    })?;
                } else {
                    output.unsupported = true;
                }
            }
        }
        output.locks = locks.into_owned();
        self.check(&work, location)?;
        Ok(output)
    }

    async fn locks_preserved<'g>(
        &self,
        before: &Fields<'g, 's, S::Document, S::Generation>,
        after: &Fields<'g, 's, S::Document, S::Generation>,
        transforms: &Transforms,
        work: &impl Work,
    ) -> Result<bool, ReadFailure<S::Error>> {
        let mut preserved = true;
        for (ordinal, field) in before.values().iter().enumerate() {
            let at = field.object.direct().location();
            let differs = if let Some(other) = after.get(field.name(), work)? {
                match (before.value(ordinal, work)?, after.value(other, work)?) {
                    (None, None) => false,
                    (Some(a), Some(b)) => !self.same_graph_values(a, b, work).await?,
                    _ => true,
                }
            } else {
                true
            };
            if differs {
                for lock in &transforms.locks {
                    admit(work, at, 1)?;
                    if lock.protects(field.name(), work)? {
                        preserved = false;
                    }
                }
            }
        }
        for (ordinal, field) in after.values().iter().enumerate() {
            admit(work, field.object().direct().location(), 1)?;
            if before.get(field.name(), work)?.is_some() || after.value(ordinal, work)?.is_none() {
                continue;
            }
            for lock in &transforms.locks {
                if lock.protects(field.name(), work)? {
                    preserved = false;
                }
            }
        }
        Ok(preserved)
    }

    async fn graph_changes<W: Work>(
        &self,
        first: &Graph<'s, S::Document, S::Generation>,
        second: &Graph<'s, S::Document, S::Generation>,
        location: Location,
        work: &W,
    ) -> Result<OwnedVec<Change, W>, ReadFailure<S::Error>> {
        let mut changes = work.vector();
        for (ordinal, node) in second.nodes.iter().enumerate() {
            admit(work, location, 1)?;
            let old = first
                .index
                .get(&node.key, work)
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?
                .copied();
            let different = match (
                old.and_then(|index| first.nodes[index].reading.as_ref()),
                node.reading.as_ref(),
            ) {
                (Some(a), Some(b)) => {
                    !self
                        .same_readings_in(
                            a,
                            first.decoded(old.expect("selected original node")),
                            b,
                            second.decoded(ordinal),
                            work,
                        )
                        .await?
                }
                (None, None) => false,
                _ => true,
            };
            if different {
                let at = node
                    .reading
                    .as_ref()
                    .map_or(location, |reading| reading.value.root().location());
                changes
                    .try_push(Change {
                        identity: (node.key.number, node.key.generation),
                        location: at,
                    })
                    .map_err(|cause| Error {
                        kind: ErrorKind::Resource(cause),
                        location: at,
                    })?;
            }
        }
        for node in &first.nodes {
            admit(work, location, 1)?;
            if second
                .index
                .get(&node.key, work)
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?
                .is_none()
            {
                let at = node
                    .reading
                    .as_ref()
                    .map_or(location, |reading| reading.value.root().location());
                changes
                    .try_push(Change {
                        identity: (node.key.number, node.key.generation),
                        location: at,
                    })
                    .map_err(|cause| Error {
                        kind: ErrorKind::Resource(cause),
                        location: at,
                    })?;
            }
        }
        Ok(changes)
    }

    /// Compares the complete actual historical catalog closures and every
    /// selected field value. Unavailable change semantics stay indeterminate;
    /// they cannot become permitted by an empty caller-supplied change list.
    ///
    /// # Panics
    /// Panics if an internally selected original graph node loses its owner.
    #[expect(
        clippy::result_large_err,
        reason = "structural and interpreted material failures retain separate typed causes and original locations without allocation on refusal"
    )]
    pub async fn inspect_permissions<W: Work>(
        &self,
        signature: Signature<'_, 's, S::Document, S::Generation>,
        before: &Fields<'_, 's, S::Document, S::Generation>,
        after: &Fields<'_, 's, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<Assessment, AssessmentError<S::Error>> {
        let work = self.session.query(operation);
        let location = signature.location();
        let first = before.graph;
        let second = after.graph;
        if second.revision < first.revision
            || second.stamp != first.stamp
            || !core::ptr::eq(second.session, self.session)
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        let transforms = self.transforms(signature, first, &work).await?;
        let placement = self.signature_placement(signature, first, before, &transforms, &work)?;
        let mut outcome = if transforms.unsupported {
            Outcome::Indeterminate
        } else if transforms.permission.is_none() && transforms.locks.is_empty() {
            Outcome::Unstated
        } else {
            Outcome::Permitted
        };
        if !self
            .locks_preserved(before, after, &transforms, &work)
            .await?
        {
            outcome = Outcome::Forbidden;
        }
        let mut changes = self.graph_changes(first, second, location, &work).await?;
        let mut unclassified = false;
        for definition in signature.catalogue().definitions() {
            admit(&work, definition.location, 1)?;
            if definition.revision <= first.revision
                || definition.revision > second.revision
                || definition.kind != crate::signature::DefinitionKind::Object
            {
                continue;
            }
            let key = crate::document::GraphKey {
                number: definition.identity.0,
                generation: definition.identity.1,
            };
            let current = second.index.get(&key, &work).map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: definition.location,
            })?;
            let selected = current.and_then(|&index| second.nodes[index].reading.as_ref());
            if selected
                .is_some_and(|reading| reading.value.root().location() == definition.location)
            {
                continue;
            }
            // Superseded intermediate and unindexed definitions remain facts.
            // Comparing only the final graph cannot authorize their semantics.
            unclassified = true;
            changes
                .try_push(Change {
                    identity: definition.identity,
                    location: definition.location,
                })
                .map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location: definition.location,
                })?;
        }
        if !changes.is_empty()
            && outcome != Outcome::Forbidden
            && let Some(permission) = transforms.permission
        {
            outcome = self
                .classify_changes(before, after, permission, &work)
                .await?;
        }
        if !placement.all_requirements_met() {
            outcome = Outcome::Forbidden;
        }
        if unclassified && outcome == Outcome::Permitted {
            outcome = Outcome::Indeterminate;
        }
        self.check(&work, location)?;
        Ok(Assessment {
            transforms,
            changes: changes.into_owned(),
            outcome,
            source_revision: first.revision,
            compared_revision: second.revision,
        })
    }

    /// ISO32000-1 §12.8.2.2.2 first requires the byte-range digest to be
    /// verified. This closed route accepts only this crate's actual range pass;
    /// failed arithmetic/input facts cannot produce a positive permission.
    /// Use inspection separately when reporting unauthenticated change facts.
    #[expect(
        clippy::result_large_err,
        reason = "authenticated assessment propagates unchanged source-qualified inspection failures without allocating an envelope"
    )]
    pub async fn permissions<W: Work>(
        &self,
        mathematical: &crate::basic::Mathematical<
            '_,
            '_,
            '_,
            '_,
            '_,
            's,
            S::Document,
            S::Generation,
        >,
        before: &Fields<'_, 's, S::Document, S::Generation>,
        after: &Fields<'_, 's, S::Document, S::Generation>,
        operation: &W,
    ) -> Result<Assessment, AssessmentError<S::Error>> {
        let mut assessment = self
            .inspect_permissions(mathematical.signature(), before, after, operation)
            .await?;
        if !mathematical.input_verified() && assessment.outcome == Outcome::Permitted {
            assessment.outcome = Outcome::Indeterminate;
        }
        Ok(assessment)
    }
}
