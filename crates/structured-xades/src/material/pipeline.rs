//! One scoped decode/PKIX pass over the complete prepared material inventory.

use super::counters::collect_counters;
use super::{Cause, Entry, RetainError, Source, Value};
use crate::binary::{Located, Location, OwnedBinaryXml};
use crate::prepare::Prepared;
use crate::unsigned;
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::{
    Reader,
    memory::{HashWork, MemoryError, OwnedVec, Work},
};
use structured_pkix::ocsp::{BasicResponse, Response};

/// Original storage role, not authorization, freshness or a completeness claim.
#[derive(Debug, Clone, Copy)]
pub enum Placement<N> {
    /// Original selected `KeyInfo` certificate/CRL. The identity is its owning
    /// signature, matching archive coverage's original header component.
    KeyInfo(N),
    /// Ordinary signature/countersignature material property.
    Signature(N),
    /// Attribute-authority material property.
    Attribute(N),
    /// General `AnyValidationData` container.
    General(N),
    /// Timestamp-specific validation-data container; its URI is only a hint.
    Timestamp(N),
    /// Material carried in an actual CMS token, whose enclosing timestamp
    /// property and input role remain separate from mathematical evidence.
    TimestampToken {
        /// Original timestamp property.
        property: N,
        /// Original `EncapsulatedTimeStamp` element.
        token: N,
        /// Original timestamp input role.
        role: crate::timestamp::Role,
    },
}

/// Original retained material and the property role which actually contains it.
pub struct Retained<N, D, G> {
    placement: Placement<N>,
    source: Source<N, D, G>,
}

impl<N: Copy, D: Copy, G: Copy> Retained<N, D, G> {
    /// Actual original source placement.
    #[must_use]
    pub fn placement(&self) -> Placement<N> {
        self.placement
    }
    /// Retained original XML enclosure and decoded source, without another copy.
    #[must_use]
    pub fn source(&self) -> &Source<N, D, G> {
        &self.source
    }
}

/// Schema-open entry preserved separately from parsed X.509/CRL/OCSP values.
#[derive(Debug, Clone, Copy)]
pub struct Opaque<N, D, G> {
    /// Actual original source placement, never inferred from a material count.
    pub placement: Placement<N>,
    /// Original open-format member and its XML snapshot.
    pub location: Location<N, D, G>,
    /// Original other-certificate or other-status role.
    pub entry: Entry<N>,
}

/// Parsed basic response from one original whole OCSP envelope. Its signature,
/// authorization, freshness and status still require the common PKIX checks.
pub struct Basic<'source, N, D, G> {
    source_index: usize,
    location: Location<N, D, G>,
    response: BasicResponse<'source>,
}

impl<'source, N: Copy, D: Copy, G: Copy> Basic<'source, N, D, G> {
    /// Ordinal of the original whole response in the frozen sources/values set.
    #[must_use]
    pub fn source_index(&self) -> usize {
        self.source_index
    }
    /// Original XML enclosure; basic-response offsets remain decoded coordinates.
    #[must_use]
    pub fn location(&self) -> Location<N, D, G> {
        self.location
    }
    /// Shared original signed data, embedded certificates and status assertions.
    #[must_use]
    pub fn response(&self) -> &BasicResponse<'source> {
        &self.response
    }
}

/// Callback-local parsed set. All known values have been decoded and parsed
/// before the visitor runs; source and parsed arrays have identical index order.
/// Open formats are not silently counted as usable X.509/status material.
pub struct View<'source, N, D, G> {
    pub(super) snapshot: crate::xml::Snapshot<D, G>,
    pub(super) signature: N,
    pub(super) sources: &'source [Retained<N, D, G>],
    pub(super) values: &'source [Located<Value<'source>, N, D, G>],
    opaque: &'source [Opaque<N, D, G>],
    pub(super) basic: &'source [Basic<'source, N, D, G>],
}

impl<'source, N, D, G> View<'source, N, D, G> {
    /// Frozen original sources backing every parsed value.
    #[must_use]
    pub fn sources(&self) -> &'source [Retained<N, D, G>] {
        self.sources
    }
    /// Parsed known values, without authentication or status promotion.
    #[must_use]
    pub fn values(&self) -> &'source [Located<Value<'source>, N, D, G>] {
        self.values
    }
    /// Original schema-open formats requiring explicit recognition if needed.
    #[must_use]
    pub fn opaque(&self) -> &'source [Opaque<N, D, G>] {
        self.opaque
    }
    /// Every known basic-response payload, decoded once under the same current
    /// operation. Unknown types and protocol failures remain in `values()`;
    /// they are never silently promoted to signed basic responses.
    #[must_use]
    pub fn basic_responses(&self) -> &'source [Basic<'source, N, D, G>] {
        self.basic
    }
}

impl<N: Copy, D: Copy, G: Copy> View<'_, N, D, G> {
    /// Original immutable source generation of this complete parsed catalogue.
    #[must_use]
    pub fn snapshot(&self) -> crate::xml::Snapshot<D, G> {
        self.snapshot
    }

    /// Exact selected root whose original material was collected.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
}

/// Terminal pipeline refusal; no successfully parsed subset is returned.
#[derive(Debug)]
pub enum Error<E, VE, N, D, G> {
    /// XML source/generation/current-operation refusal.
    Access(AccessError<E, N>),
    /// Original header/material field grammar, source or resource cause.
    Property(crate::properties::Error<E, N>),
    /// Original general/timestamp validation-data field cause.
    Validation(crate::validation::Error<E, N>),
    /// Source retention failed before the exact value was available.
    Retain {
        /// Original XML enclosure.
        location: Location<N, D, G>,
        /// Unchanged source cause.
        cause: RetainError<E, N>,
    },
    /// Located original PKIX/schema/resource cause in decoded coordinates.
    Parse(Located<Cause, N, D, G>),
    /// Prepared catalogue does not belong to the expected original scope.
    Foreign {
        /// Original catalogue parent.
        node: N,
    },
    /// Metadata/source/parsed catalogue storage or traversal admission failed.
    Resource {
        /// Original enclosing node.
        node: N,
        /// Original resource cause.
        cause: MemoryError,
    },
    /// Exact visitor refusal; external visitor side effects are not rolled back.
    Visitor(VE),
}

/// Pipeline result with this owner's unchanged causes and source identity types.
pub type PipelineResult<T, X, VE> = Result<
    T,
    Error<<X as Xml>::Error, VE, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
>;

pub(super) type Record<X> = Retained<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
pub(super) type Open<X> = Opaque<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
type Basics<'source, X, W> =
    OwnedVec<Basic<'source, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>, W>;

/// Retains and parses every known original value once, then invokes a scoped
/// visitor over the finalized source/parsed catalogues. Partial preparation and
/// results are dropped on refusal. The visitor may retain accounted owned facts
/// or original XML identities, but cannot borrow these temporary source buffers.
/// Material availability/authentication/path/status/chronology and attained
/// levels remain separate: an OCSP failure envelope stays a failure value.
///
/// ```compile_fail
/// use structured_asn1::Reader;
/// use structured_xades::{binary::OwnedBinaryXml, material, prepare::Prepared};
/// fn escape<'a, X: OwnedBinaryXml>(
///     xml: &X, prepared: &Prepared<X>, operation: &Reader<'_>,
/// ) -> material::PipelineResult<&'a [u8], X, ()> {
///     material::with_values(xml, prepared, operation, |_, view| {
///         Ok(view.sources()[0].source().bytes())
///     })
/// }
/// ```
pub fn with_values<X: OwnedBinaryXml, R, VE>(
    xml: &X,
    prepared: &Prepared<X>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(
        &Reader<'source>,
        View<'source, X::Id, X::Document, X::Generation>,
    ) -> Result<R, VE>,
) -> PipelineResult<R, X, VE> {
    with_inputs(xml, prepared, None, operation, visitor)
}

/// Retain the root's prepared material AND every original counter's header and
/// unsigned material in one frozen source pool. Membership comes from the
/// complete actual counter/path receipt, not a caller-written child list.
/// Plain `XMLDSig` counters need no B-level properties or mandatory `KeyInfo`.
/// This does not process child timestamp tokens, authenticate material, or
/// assert a counter/root baseline level. Token-carried material remains a
/// separate source pool, consumed by the same original-artifact index.
///
/// ```compile_fail
/// use structured_asn1::Reader;
/// use structured_xades::{binary::OwnedBinaryXml, material, pki, prepare::Prepared};
/// fn escape<'a, X: OwnedBinaryXml>(
///     xml: &X, prepared: &Prepared<X>, operation: &Reader<'_>,
///     counters: &pki::CounterPaths<'_, '_, X::Id, X::Document, X::Generation>,
/// ) -> material::PipelineResult<&'a [u8], X, ()> {
///     material::with_counter_values(xml, prepared, counters, operation, |_, view| {
///         Ok(view.sources()[0].source().bytes())
///     })
/// }
/// ```
pub fn with_counter_values<X: OwnedBinaryXml, R, VE>(
    xml: &X,
    prepared: &Prepared<X>,
    counters: &CounterSources<'_, '_, X>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(
        &Reader<'source>,
        View<'source, X::Id, X::Document, X::Generation>,
    ) -> Result<R, VE>,
) -> PipelineResult<R, X, VE> {
    with_inputs(xml, prepared, Some(counters), operation, visitor)
}

pub(super) type CounterSources<'view, 'document, X> = crate::pki::CounterPaths<
    'view,
    'document,
    <X as Xml>::Id,
    <X as Xml>::Document,
    <X as Xml>::Generation,
>;

fn with_inputs<X: OwnedBinaryXml, R, VE>(
    xml: &X,
    prepared: &Prepared<X>,
    counters: Option<&CounterSources<'_, '_, X>>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(
        &Reader<'source>,
        View<'source, X::Id, X::Document, X::Generation>,
    ) -> Result<R, VE>,
) -> PipelineResult<R, X, VE> {
    let layout = prepared.bound().containers();
    let execution = operation.execution();
    let access = Access::new(xml, layout.snapshot(), &execution);
    admit(&access, layout.signature())?;
    if let Some(counters) = counters
        && (counters.snapshot() != layout.snapshot()
            || !access
                .equal_id(counters.signature(), layout.signature())
                .map_err(|cause| Error::Resource {
                    node: layout.signature(),
                    cause,
                })?)
    {
        return Err(Error::Foreign {
            node: counters.signature(),
        });
    }
    let mut sources = execution.vector();
    let mut opaque = execution.vector();
    collect_header(xml, &access, prepared.header(), operation, &mut sources)?;
    let parents = material_parents(&access, prepared)?;
    for index in 0..prepared.material().len() {
        admit(&access, layout.signature())?;
        let catalogue = &prepared.material()[index];
        let node = catalogue.parent();
        let placement = source_placement(parents, node, &execution)
            .map_err(|cause| Error::Resource { node, cause })?
            .ok_or(Error::Foreign { node })?;
        collect(
            xml,
            &access,
            catalogue,
            placement,
            operation,
            &mut sources,
            &mut opaque,
        )?;
    }
    for index in 0..prepared.validation().len() {
        admit(&access, layout.signature())?;
        let data = &prepared.validation()[index];
        if data.snapshot() != layout.snapshot()
            || !access
                .equal_id(data.signature(), layout.signature())
                .map_err(|cause| Error::Resource {
                    node: data.node(),
                    cause,
                })?
        {
            return Err(Error::Foreign { node: data.node() });
        }
        collect_validation(xml, &access, data, operation, &mut sources, &mut opaque)?;
    }
    if let Some(counters) = counters {
        collect_counters(xml, &access, counters, operation, &mut sources, &mut opaque)?;
    }
    let mut values = execution.vector();
    for index in 0..sources.len() {
        admit(&access, layout.signature())?;
        let source = &sources[index].source;
        let value = source.read_in(operation).map_err(Error::Parse)?;
        values.try_push(value).map_err(|cause| Error::Resource {
            node: source.location().node,
            cause,
        })?;
    }
    let basic = read_basics(&access, layout.signature(), &values, operation, &execution)?;
    admit(&access, layout.signature())?;
    let result = visitor(
        operation,
        View {
            snapshot: layout.snapshot(),
            signature: layout.signature(),
            sources: &sources,
            values: &values,
            opaque: &opaque,
            basic: &basic,
        },
    )
    .map_err(Error::Visitor)?;
    // A successful visitor result must not escape after a source generation
    // change. Returning Err drops that result and all temporary catalogues.
    admit(&access, layout.signature())?;
    Ok(result)
}

fn read_basics<'source, X: Xml, W: Work, VE>(
    access: &Access<'_, X, W>,
    signature: X::Id,
    values: &[crate::binary::LocatedValue<Value<'source>, X>],
    operation: &Reader<'source>,
    execution: &W,
) -> PipelineResult<Basics<'source, X, W>, X, VE> {
    let mut basic = execution.vector();
    let mut cursor = 0;
    while cursor < values.len() {
        admit(access, signature)?;
        let index = cursor;
        cursor += 1;
        let value = &values[index];
        let Value::Ocsp(Response::Successful(envelope)) = &value.value else {
            continue;
        };
        if let Some(response) = envelope.basic_in(operation).map_err(|cause| {
            Error::Parse(Located {
                location: value.location,
                value: Cause::Pki(cause),
            })
        })? {
            basic
                .try_push(Basic {
                    source_index: index,
                    location: value.location,
                    response,
                })
                .map_err(|cause| Error::Resource {
                    node: value.location.node,
                    cause,
                })?;
        }
    }
    Ok(basic)
}

fn collect_header<X: OwnedBinaryXml, W: Work, VE>(
    xml: &X,
    access: &Access<'_, X, W>,
    header: &crate::header::Reading<X>,
    operation: &Reader<'_>,
    sources: &mut OwnedVec<Record<X>, W>,
) -> PipelineResult<(), X, VE> {
    // XMLDSig1.1 §4.5.4 includes X509CRL in the SAME original X509Data. EN
    // 319132-1 §5.4.3(1-3) expressly permits status data already in KeyInfo;
    // losing these copies would incorrectly require a second incorporation.
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-X509Data
    collect_data(
        xml,
        access,
        header.signature(),
        header.x509_data(),
        operation,
        sources,
    )
}

pub(super) fn collect_data<X: OwnedBinaryXml, W: Work, VE>(
    xml: &X,
    access: &Access<'_, X, W>,
    signature: X::Id,
    data: X::Id,
    operation: &Reader<'_>,
    sources: &mut OwnedVec<Record<X>, W>,
) -> PipelineResult<(), X, VE> {
    crate::header::visit_values(access, data, |node, kind| {
        admit(access, signature)?;
        let location = Location {
            snapshot: access.snapshot(),
            node,
        };
        let schema = match kind {
            crate::header::ValueKind::Certificate => super::Kind::Certificate,
            crate::header::ValueKind::Crl => super::Kind::Crl,
        };
        let source = super::retain_expected(
            xml,
            location,
            schema,
            crate::container::DS,
            kind.local(),
            operation,
        )
        .map_err(|cause| Error::Retain { location, cause })?;
        sources
            .try_push(Retained {
                placement: Placement::KeyInfo(signature),
                source,
            })
            .map_err(|cause| Error::Resource { node, cause })?;
        Ok(())
    })
    .map_err(|cause| match cause {
        crate::reference::VisitError::Processing(cause) => Error::Property(cause),
        crate::reference::VisitError::Visitor(cause) => cause,
    })
}

fn material_parents<X: Xml, W: Work, VE>(
    access: &Access<'_, X, W>,
    prepared: &Prepared<X>,
) -> PipelineResult<[Option<X::Id>; 4], X, VE> {
    let mut parents = [None; 4];
    for index in 0..prepared.unsigned().entries().len() {
        admit(access, prepared.unsigned().signature())?;
        let entry = prepared.unsigned().entries()[index];
        let slot = match entry.role {
            unsigned::Role::Certificates => 0,
            unsigned::Role::Revocation => 1,
            unsigned::Role::AttributeCertificates => 2,
            unsigned::Role::AttributeRevocation => 3,
            _ => continue,
        };
        parents[slot] = Some(entry.node);
    }
    Ok(parents)
}

pub(super) fn collect<X: OwnedBinaryXml, W: Work, VE>(
    xml: &X,
    access: &Access<'_, X, W>,
    catalogue: &super::Catalogue<X::Id, X::Document, X::Generation>,
    placement: Placement<X::Id>,
    operation: &Reader<'_>,
    sources: &mut OwnedVec<Record<X>, W>,
    opaque: &mut OwnedVec<Open<X>, W>,
) -> PipelineResult<(), X, VE> {
    if catalogue.snapshot() != access.snapshot() {
        return Err(Error::Foreign {
            node: catalogue.parent(),
        });
    }
    for index in 0..catalogue.entries().len() {
        admit(access, catalogue.parent())?;
        let entry = catalogue.entries()[index];
        match entry {
            Entry::Encapsulated { node, kind } => {
                let location = Location {
                    snapshot: catalogue.snapshot(),
                    node,
                };
                let source = super::retain(xml, location, kind, operation)
                    .map_err(|cause| Error::Retain { location, cause })?;
                sources
                    .try_push(Retained { placement, source })
                    .map_err(|cause| Error::Resource { node, cause })?;
            }
            Entry::OtherCertificate { node } | Entry::OtherStatus { node } => {
                opaque
                    .try_push(Opaque {
                        placement,
                        location: Location {
                            snapshot: catalogue.snapshot(),
                            node,
                        },
                        entry,
                    })
                    .map_err(|cause| Error::Resource { node, cause })?;
            }
        }
    }
    Ok(())
}

pub(super) fn collect_validation<X: OwnedBinaryXml, W: Work, VE>(
    xml: &X,
    access: &Access<'_, X, W>,
    data: &crate::validation::Reading<X>,
    operation: &Reader<'_>,
    sources: &mut OwnedVec<Record<X>, W>,
    opaque: &mut OwnedVec<Open<X>, W>,
) -> PipelineResult<(), X, VE> {
    if data.snapshot() != access.snapshot() {
        return Err(Error::Foreign { node: data.node() });
    }
    let placement = match data.role() {
        crate::validation::Role::Any => Placement::General(data.node()),
        crate::validation::Role::Timestamp => Placement::Timestamp(data.node()),
    };
    for catalogue in [data.certificates(), data.revocations()]
        .into_iter()
        .flatten()
    {
        collect(
            xml, access, catalogue, placement, operation, sources, opaque,
        )?;
    }
    Ok(())
}

pub(super) fn admit<X: Xml, W: Work, VE>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> PipelineResult<(), X, VE> {
    access
        .query(node, |_, _, work| Ok(work.charge_work(1)))
        .map_err(Error::Access)?
        .map_err(|cause| Error::Resource { node, cause })
}

fn source_placement<N: Copy + HashWork, W: Work>(
    parents: [Option<N>; 4],
    node: N,
    work: &W,
) -> Result<Option<Placement<N>>, MemoryError> {
    for (index, parent) in parents.into_iter().enumerate() {
        if let Some(parent) = parent
            && crate::xml::equal_id(parent, node, work)?
        {
            return Ok(Some(if index < 2 {
                Placement::Signature(node)
            } else {
                Placement::Attribute(node)
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod placement_tests {
    use super::{Placement, source_placement};
    use alloc::sync::Arc;
    use structured_asn1::memory::{HashWork, Memory, MemoryAccount, MemoryError};

    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    struct Identity(u8, u64);
    impl HashWork for Identity {
        fn hash_work(&self) -> Result<u64, MemoryError> {
            Ok(self.1)
        }
    }

    #[test]
    fn placement_pays_the_retained_parent_operand_before_comparison() {
        // The untrusted retained parent has a larger scan bound than the
        // material node. Paying four node bounds cannot admit even one pair.
        let node = Identity(1, 1);
        let parent = Identity(2, 100);
        let short = Memory::new(Arc::new(MemoryAccount::new(0, 4)));
        assert!(matches!(
            source_placement([Some(parent), None, None, None], node, &short),
            Err(MemoryError::WorkExceeded)
        ));
        assert_eq!(short.work_remaining(), 4);
        let exact = Memory::new(Arc::new(MemoryAccount::new(0, 2)));
        assert!(matches!(
            source_placement([None, None, Some(node), None], node, &exact),
            Ok(Some(Placement::Attribute(_)))
        ));
        assert_eq!(exact.work_remaining(), 0);
    }
}
