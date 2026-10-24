//! Attached-schema child order and original attribute projections.

use super::{
    Boolean, Builder, DS, Error, Extension, Fault, FaultKind, Object, ResultOf, Slot, name, walk,
};
use structured_asn1::memory::Work;
use structured_xades::{
    attributes::{self, AttributeXml},
    reference::LexicalSource,
    scalar::{self, Datatype, ScalarXml},
    xml::{Access, Name},
};

pub(super) fn attributes<X: AttributeXml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    allowed: &[&str],
    output: &mut Builder<X::Id, W>,
) -> ResultOf<(), X> {
    attributes::visit(access, node, |attribute| {
        access
            .execution()
            .charge_work(attribute.namespace.len() as u64 + attribute.local.len() as u64 + 1)?;
        if attribute.namespace == "http://www.w3.org/2001/XMLSchema-instance" {
            output.faults.try_push(Fault {
                node,
                kind: FaultKind::InstanceUnassessed,
            })?;
            return Ok(());
        }
        if attribute.namespace.is_empty() {
            for local in allowed {
                access
                    .execution()
                    .charge_work(attribute.local.len().min(local.len()) as u64 + 1)?;
                if attribute.local == *local {
                    return Ok(());
                }
            }
        }
        output.faults.try_push(Fault {
            node,
            kind: FaultKind::Unexpected,
        })
    })
    .map_err(Error::Attributes)
}

pub(super) fn uri<X: ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    output: &mut Builder<X::Id, W>,
) -> ResultOf<(), X> {
    match scalar::check(
        access,
        node,
        LexicalSource::Attribute(Name {
            namespace: "",
            local: "URI",
        }),
        Datatype::AnyUri,
    ) {
        Ok(()) => Ok(()),
        Err(scalar::Error::Access(cause)) => Err(Error::Access(cause)),
        Err(scalar::Error::Value { fact, .. }) => output.fault(
            node,
            if fact == scalar::Fact::Absent {
                FaultKind::Missing
            } else {
                FaultKind::Scalar
            },
        ),
    }
}

pub(super) fn empty<X: AttributeXml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    output: &mut Builder<X::Id, W>,
) -> ResultOf<(), X> {
    walk(access, node, |child, element| {
        output.fault(
            child,
            if element {
                FaultKind::Unexpected
            } else {
                FaultKind::Text
            },
        )
    })
}

fn boolean<X: AttributeXml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    local: &'static str,
) -> ResultOf<Boolean, X> {
    access
        .attribute(
            node,
            Name {
                namespace: "",
                local,
            },
            |value| {
                let Some(value) = value else {
                    return Ok(Boolean::Absent);
                };
                access.execution().charge_work(value.len() as u64)?;
                // XSD1.0 part2 §§3.2.2,4.3.6 fixes whitespace=collapse. The only
                // valid nonempty values have no interior whitespace after collapse.
                // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#boolean
                let value = value.trim_matches([' ', '\t', '\r', '\n']);
                Ok(match value {
                    "true" | "1" => Boolean::Value(true),
                    "false" | "0" => Boolean::Value(false),
                    _ => Boolean::Malformed,
                })
            },
        )
        .map_err(Error::Access)?
        .map_err(|cause| Error::Resource { node, cause })
}

fn required<E, N: Copy, W: Work>(
    value: Boolean,
    node: N,
    output: &mut Builder<N, W>,
) -> Result<(), Error<E, N>> {
    match value {
        Boolean::Absent => output.fault(node, FaultKind::Missing),
        Boolean::Malformed => output.fault(node, FaultKind::Scalar),
        Boolean::Value(_) => Ok(()),
    }
}

pub(super) fn extensions<X: AttributeXml, W: Work>(
    access: &Access<'_, X, W>,
    owner: X::Id,
    node: X::Id,
    output: &mut Builder<X::Id, W>,
) -> ResultOf<(), X> {
    attributes(access, node, &[], output)?;
    let mut count = 0;
    walk(access, node, |child, element| {
        if !element {
            return output.fault(child, FaultKind::Text);
        }
        if !access
            .has_name(child, name("Extension"))
            .map_err(Error::Access)?
        {
            return output.fault(child, FaultKind::Unexpected);
        }
        attributes(access, child, &["Critical"], output)?;
        let critical = boolean(access, child, "Critical")?;
        required(critical, child, output)?;
        output
            .extensions
            .try_push(Extension {
                owner,
                node: child,
                critical,
            })
            .map_err(|cause| Error::Resource { node: child, cause })?;
        // ExtensionType is mixed/lax AnyType. Its XML-owned payload is not
        // recursively reinterpreted as ASiC or discarded by local-name matching.
        count += 1;
        Ok(())
    })?;
    if count == 0 {
        output.fault(node, FaultKind::Missing)?;
    }
    Ok(())
}

fn insert<E, N: Copy, W: Work>(
    slot: &mut Slot<N>,
    node: N,
    output: &mut Builder<N, W>,
) -> Result<(), Error<E, N>> {
    if matches!(slot, Slot::Absent) {
        *slot = Slot::One(node);
    } else {
        *slot = Slot::Ambiguous;
        output.fault(node, FaultKind::Duplicate)?;
    }
    Ok(())
}

pub(super) fn object<X: AttributeXml + ScalarXml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    output: &mut Builder<X::Id, W>,
) -> ResultOf<Object<X::Id>, X> {
    attributes(access, node, &["URI", "MimeType", "Rootfile"], output)?;
    uri(access, node, output)?;
    let rootfile = boolean(access, node, "Rootfile")?;
    if rootfile == Boolean::Malformed {
        output.fault(node, FaultKind::Scalar)?;
    }
    let mut value = Object {
        node,
        method: Slot::Absent,
        value: Slot::Absent,
        rootfile,
    };
    let mut stage = 0;
    let mut extension = false;
    walk(access, node, |child, element| {
        if !element {
            return output.fault(child, FaultKind::Text);
        }
        if access
            .has_name(
                child,
                Name {
                    namespace: DS,
                    local: "DigestMethod",
                },
            )
            .map_err(Error::Access)?
        {
            if stage != 0 {
                output.fault(child, FaultKind::Order)?;
            }
            insert(&mut value.method, child, output)?;
        } else if access
            .has_name(
                child,
                Name {
                    namespace: DS,
                    local: "DigestValue",
                },
            )
            .map_err(Error::Access)?
        {
            if stage > 1 || matches!(value.method, Slot::Absent) {
                output.fault(child, FaultKind::Order)?;
            }
            stage = stage.max(1);
            insert(&mut value.value, child, output)?;
        } else if access
            .has_name(child, name("DataObjectReferenceExtensions"))
            .map_err(Error::Access)?
        {
            if extension {
                output.fault(child, FaultKind::Duplicate)?;
            }
            if matches!(value.value, Slot::Absent) {
                output.fault(child, FaultKind::Order)?;
            }
            extension = true;
            stage = 2;
            extensions(access, node, child, output)?;
        } else {
            output.fault(child, FaultKind::Unexpected)?;
        }
        Ok(())
    })?;
    if matches!(value.method, Slot::Absent) || matches!(value.value, Slot::Absent) {
        output.fault(node, FaultKind::Missing)?;
    }
    Ok(value)
}
