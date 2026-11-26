//! The original ETSI protected object group, replayed without materialization.

use super::{Member, Records};
use crate::{
    binding::Status,
    container::DS,
    reference::{Completeness, Parent, Replay, ReplayOutcome, VisitError},
    timestamp::{self, InputError, TimestampXml},
    xml::{Access, AccessError, Name, Snapshot, Xml},
};
use structured_asn1::memory::{OwnedVec, Work};
use structured_cms::stream::{Receiver, Source};

mod construct;
pub use construct::{InitialError, InitialImprint, InitialResult};

/// Refusal while selecting or replaying an original protection object.
#[derive(Debug)]
pub enum ObjectError<E, N> {
    /// Original XML access, shape, or resource refusal.
    Input(InputError<E, N>),
    /// Original reference processing did not establish a complete catalogue.
    Incomplete(Completeness<N>),
    /// A required original reference was not successfully authenticated.
    Reference {
        /// Original reference instruction.
        node: N,
        /// Its independent XML signature status.
        status: Status,
    },
    /// The requested original record was not found.
    Index(usize),
}

type ResultFor<T, X> = Result<T, ObjectError<<X as Xml>::Error, <X as Xml>::Id>>;

#[derive(Clone, Copy)]
enum Input<N> {
    Reference(N),
    Element(N),
}

/// One original protected member of an evidence record's data-object group.
pub struct Object<'a, X: TimestampXml> {
    xml: &'a X,
    context: Context<X>,
    input: Input<X::Id>,
}

struct Context<X: Xml> {
    snapshot: Snapshot<X::Document, X::Generation>,
    signature: X::Id,
    method: X::Id,
}

impl<X: Xml> Copy for Context<X> {}
impl<X: Xml> Clone for Context<X> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<X: TimestampXml> Object<'_, X> {
    /// Exact XML element or authenticated reference instruction being replayed.
    #[must_use]
    pub fn node(&self) -> X::Id {
        match self.input {
            Input::Reference(node) | Input::Element(node) => node,
        }
    }
}

impl<X: TimestampXml> Source for Object<'_, X> {
    type Error = ObjectError<X::Error, X::Id>;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        let Context {
            snapshot,
            signature,
            method,
        } = self.context;
        let node = self.node();
        let access = Access::new(self.xml, snapshot, work);
        let xml_error = |cause| ObjectError::Input(InputError::Access(cause));
        match self.input {
            Input::Element(_) => access
                .query(node, |xml, _, work| {
                    xml.canonicalize(snapshot, node, method, receiver, work)
                })
                .map_err(xml_error),
            Input::Reference(_) => {
                let outcome = access
                    .query(node, |xml, _, work| {
                        xml.replay_reference(
                            snapshot,
                            signature,
                            node,
                            Replay::Timestamp(method),
                            receiver,
                            work,
                        )
                    })
                    .map_err(xml_error)?;
                match outcome {
                    ReplayOutcome::Complete => Ok(()),
                    ReplayOutcome::Unavailable(cause) => {
                        Err(ObjectError::Input(InputError::Unavailable { node, cause }))
                    }
                }
            }
        }
    }
}

/// Exact complete group of streams for initial proof and tree renewal.
pub struct Objects<'a, X: TimestampXml> {
    items: OwnedVec<Object<'a, X>>,
}

impl<'a, X: TimestampXml> Objects<'a, X> {
    /// Borrow each member as one complete source for the common digest driver.
    pub fn sources(&mut self) -> &mut [Object<'a, X>] {
        &mut self.items
    }
}

impl<X: TimestampXml> Records<'_, X> {
    /// Build the original group shared by this member and every parallel sibling.
    /// The containing property and every later group are outside this input.
    pub fn objects<'a, W: Work>(
        &self,
        xml: &'a X,
        index: usize,
        work: &W,
    ) -> ResultFor<Objects<'a, X>, X> {
        let Member { group, .. } = *self.members.get(index).ok_or(ObjectError::Index(index))?;
        self.plan(xml, Some(self.groups[group].node), work)
    }

    /// Build the input before adding a new serial sealing property at the tail.
    /// Any newly incorporated timestamp validation data must already be present
    /// in this unpublished original generation.
    pub fn serial_objects<'a, W: Work>(
        &self,
        xml: &'a X,
        work: &W,
    ) -> ResultFor<Objects<'a, X>, X> {
        self.plan(xml, None, work)
    }

    fn plan<'a, W: Work>(
        &self,
        xml: &'a X,
        boundary: Option<X::Id>,
        work: &W,
    ) -> ResultFor<Objects<'a, X>, X> {
        let layout = self.bound.containers();
        let snapshot = layout.snapshot();
        let signature = layout.signature();
        let access = Access::new(xml, snapshot, work);
        let mut items = work.vector();
        let signed = timestamp::singleton(&access, signature, DS, "SignedInfo")
            .map_err(ObjectError::Input)?;
        let method = timestamp::singleton(&access, signed, DS, "CanonicalizationMethod")
            .map_err(ObjectError::Input)?;
        let context = Context {
            snapshot,
            signature,
            method,
        };
        let resource = |node, cause| ObjectError::Input(InputError::Resource { node, cause });
        let complete = access.query_fallible(signature, |owner, _, work| {
            owner.visit_authenticated_references(snapshot, signature, work, |descriptor| {
                let reference = descriptor.reference;
                if reference.status != Status::Valid {
                    return Err(ObjectError::Reference {
                        node: reference.node,
                        status: reference.status,
                    });
                }
                if matches!(descriptor.parent, Parent::Manifest(_))
                    && let Some(target) = reference.target
                    && access
                        .has_name(
                            target,
                            Name {
                                namespace: DS,
                                local: "Manifest",
                            },
                        )
                        .map_err(|cause| ObjectError::Input(InputError::Access(cause)))?
                {
                    return Ok(());
                }
                items
                    .try_push(Object {
                        xml,
                        context,
                        input: Input::Reference(reference.node),
                    })
                    .map_err(|cause| resource(reference.node, cause))
            })
        });
        check_catalogue(complete, resource)?;
        let mut element = |node| {
            items
                .try_push(Object {
                    xml,
                    context,
                    input: Input::Element(node),
                })
                .map_err(|cause| resource(node, cause))
        };
        element(signed)?;
        element(
            timestamp::singleton(&access, signature, DS, "SignatureValue")
                .map_err(ObjectError::Input)?,
        )?;
        if let Some(key) =
            timestamp::optional(&access, signature, DS, "KeyInfo").map_err(ObjectError::Input)?
        {
            element(key)?;
        }
        append_unsigned(&access, self.parent, boundary, &mut element)?;
        for child in access.children(signature) {
            let node = child.map_err(|cause| ObjectError::Input(InputError::Child(cause)))?;
            if access
                .has_name(
                    node,
                    Name {
                        namespace: DS,
                        local: "Object",
                    },
                )
                .map_err(|cause| ObjectError::Input(InputError::Access(cause)))?
                && !access
                    .equal_id(node, layout.object())
                    .map_err(|cause| resource(node, cause))?
            {
                element(node)?;
            }
        }
        Ok(Objects {
            items: items.into_owned(),
        })
    }
}

type Catalogue<E, N> = Result<Completeness<N>, AccessError<VisitError<E, ObjectError<E, N>>, N>>;

fn check_catalogue<E, N>(
    complete: Catalogue<E, N>,
    resource: impl FnOnce(N, structured_asn1::memory::MemoryError) -> ObjectError<E, N>,
) -> Result<(), ObjectError<E, N>> {
    match complete {
        Ok(Completeness::Complete) => {}
        Ok(other) => return Err(ObjectError::Incomplete(other)),
        Err(AccessError::Xml(VisitError::Visitor(cause))) => return Err(cause),
        Err(AccessError::Xml(VisitError::Processing(cause))) => {
            return Err(ObjectError::Input(InputError::Access(AccessError::Xml(
                cause,
            ))));
        }
        Err(AccessError::Changed { node }) => {
            return Err(ObjectError::Input(InputError::Access(
                AccessError::Changed { node },
            )));
        }
        Err(AccessError::Resource { node, cause }) => return Err(resource(node, cause)),
    }
    Ok(())
}

fn append_unsigned<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: Option<X::Id>,
    boundary: Option<X::Id>,
    mut append: impl FnMut(X::Id) -> ResultFor<(), X>,
) -> ResultFor<(), X> {
    // TS 119 132-3 §§5.1.1 and 5.2.2: earlier sealing groups are each one
    // object. All other properties are protected regardless of position.
    // https://www.etsi.org/deliver/etsi_ts/119100_119199/11913203/01.01.01_60/ts_11913203v010101p.pdf
    let mut before = boundary;
    let mut later_seals = false;
    if let Some(parent) = parent {
        for child in access.children(parent) {
            let node = child.map_err(|cause| ObjectError::Input(InputError::Child(cause)))?;
            if let Some(boundary) = before
                && access
                    .equal_id(node, boundary)
                    .map_err(|cause| ObjectError::Input(InputError::Resource { node, cause }))?
            {
                before = None;
                later_seals = true;
                continue;
            }
            if later_seals
                && access
                    .has_name(node, super::PROPERTY)
                    .map_err(|cause| ObjectError::Input(InputError::Access(cause)))?
            {
                continue;
            }
            append(node)?;
        }
    }
    match before {
        Some(node) => Err(ObjectError::Input(InputError::Foreign { node })),
        None => Ok(()),
    }
}
