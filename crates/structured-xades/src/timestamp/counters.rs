//! Timestamp inputs from the complete, original countersignature census.

use super::{Input, InputError, InputResult, Role, Stamp, TimestampXml};
use crate::xml::{Access, Snapshot, Xml};
use crate::{binding, container, pki::CounterPaths, properties};
use structured_asn1::memory::{OwnedVec, Work};

/// One child timestamp and its original input scope. Construction requires the
/// actual counter receipt; a root binding cannot stand in for this child.
pub struct CounterStamp<N, D, G> {
    layout: container::Containers<N, D, G>,
    stamp: Stamp<N, D, G>,
}

impl<N: Copy, D: Copy, G: Copy> CounterStamp<N, D, G> {
    /// Original property, including all of its encapsulated tokens.
    #[must_use]
    pub fn stamp(&self) -> &Stamp<N, D, G> {
        &self.stamp
    }

    /// Prepare the child's original `SignatureValue`, reference outputs or archive
    /// components through the SAME selector as the root. No signature is replayed.
    pub fn input<'xml, X: TimestampXml<Id = N, Document = D, Generation = G>, W: Work>(
        &self,
        xml: &'xml X,
        execution: &W,
    ) -> InputResult<Input<'xml, X>, X> {
        Input::prepare_in(xml, &self.layout, &self.stamp, execution)
    }
}

/// Complete child timestamp census, including nested children in counter order.
/// This is source selection, not positive timestamp or baseline evidence.
pub struct CounterTimestamps<N, D, G> {
    pub(super) snapshot: Snapshot<D, G>,
    pub(super) signature: N,
    pub(super) entries: OwnedVec<CounterStamp<N, D, G>>,
    pub(super) signatures: OwnedVec<N>,
}

impl<N, D, G> CounterTimestamps<N, D, G> {
    /// Every original child timestamp; failed/unreadable tokens remain obligations.
    #[must_use]
    pub fn entries(&self) -> &[CounterStamp<N, D, G>] {
        &self.entries
    }
}

/// Original child field, authenticated signed-property, or admission refusal.
#[derive(Debug)]
pub enum CounterTimestampError<E, N> {
    /// Current original source/input refusal.
    Input(InputError<E, N>),
    /// Original signed-property structural failure.
    Property(properties::Error<E, N>),
    /// Signed object timestamps lack whole original `SignedProperties` coverage.
    Binding(binding::BindingError<E, N>),
}

/// Complete child source census or the original field/binding/admission cause.
pub type CounterTimestampResult<X> = Result<
    CounterTimestamps<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
    CounterTimestampError<<X as Xml>::Error, <X as Xml>::Id>,
>;

/// Read all original child timestamp properties without imposing the root's
/// SigningTime/SigningCertificateV2/header requirements on a plain counter.
/// Signed object timestamps do require actual whole-property authentication;
/// unsigned timestamps need the actual checked child, direct layout and Target
/// association with that child; no signed-property reference is fabricated.
/// Partial output is dropped on any source, schema, binding or resource refusal.
pub fn counter_timestamps<X: binding::SignatureXml, W: Work>(
    access: &Access<'_, X, W>,
    counters: &CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
) -> CounterTimestampResult<X> {
    let root = counters.signature();
    if counters.snapshot() != access.snapshot() {
        return Err(CounterTimestampError::Input(InputError::Foreign {
            node: root,
        }));
    }
    let mut entries = access.execution().vector();
    let mut signatures = access.execution().vector();
    for index in 0..counters.actors().len() {
        pay(access, root)?;
        let actor = &counters.actors()[index];
        let signature = actor.signer().counter().original().child();
        pay(access, signature)?;
        signatures.try_push(signature).map_err(|cause| {
            CounterTimestampError::Input(InputError::Resource {
                node: signature,
                cause,
            })
        })?;
        let Some(layout) = actor.containers() else {
            continue;
        };
        let [parent, _] = crate::unsigned::containers(access, layout.unsigned())
            .map_err(CounterTimestampError::Property)?;
        if let Some(parent) = parent {
            let mut target_checked = false;
            for child in access.children(parent) {
                let node = child
                    .map_err(|cause| CounterTimestampError::Input(InputError::Child(cause)))?;
                if super::named(access, node, container::XADES, "SignatureTimeStamp")
                    .map_err(CounterTimestampError::Input)?
                    || super::named(access, node, super::XADES_141, "ArchiveTimeStamp")
                        .map_err(CounterTimestampError::Input)?
                    || super::named(access, node, super::XADES_141, "SigAndRefsTimeStampV2")
                        .map_err(CounterTimestampError::Input)?
                    || super::named(access, node, super::XADES_141, "RefsOnlyTimeStampV2")
                        .map_err(CounterTimestampError::Input)?
                {
                    if !target_checked {
                        binding::check_target(access, layout)
                            .map_err(CounterTimestampError::Binding)?;
                        target_checked = true;
                    }
                    let stamp = super::read_in(access, layout, node)
                        .map_err(CounterTimestampError::Input)?;
                    entries
                        .try_push(CounterStamp {
                            layout: *layout,
                            stamp,
                        })
                        .map_err(|cause| {
                            CounterTimestampError::Input(InputError::Resource { node, cause })
                        })?;
                }
            }
        }
        let (_, objects) =
            properties::sections(access, layout).map_err(CounterTimestampError::Property)?;
        if let Some(parent) = objects {
            let objects = properties::read_objects(access, parent)
                .map_err(CounterTimestampError::Property)?;
            let mut authenticated = false;
            for entry in objects.entries() {
                pay(access, entry.node)?;
                let role = match entry.role {
                    properties::DataObjectRole::AllTimestamp => Role::AllDataObjects,
                    properties::DataObjectRole::IndividualTimestamp => Role::IndividualDataObjects,
                    _ => continue,
                };
                if !authenticated {
                    binding::bind(access, layout).map_err(CounterTimestampError::Binding)?;
                    authenticated = true;
                }
                let stamp = super::read_object_fields(access, layout, &objects, entry.node, role)
                    .map_err(CounterTimestampError::Input)?;
                entries
                    .try_push(CounterStamp {
                        layout: *layout,
                        stamp,
                    })
                    .map_err(|cause| {
                        CounterTimestampError::Input(InputError::Resource {
                            node: entry.node,
                            cause,
                        })
                    })?;
            }
        }
    }
    pay(access, root)?;
    Ok(CounterTimestamps {
        snapshot: access.snapshot(),
        signature: root,
        entries: entries.into_owned(),
        signatures: signatures.into_owned(),
    })
}

fn pay<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> Result<(), CounterTimestampError<X::Error, X::Id>> {
    access
        .query(node, |_, _, work| Ok(work.charge_work(1)))
        .map_err(|cause| CounterTimestampError::Input(InputError::Access(cause)))?
        .map_err(|cause| CounterTimestampError::Input(InputError::Resource { node, cause }))
}
