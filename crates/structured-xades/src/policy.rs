//! Original signature-policy declarations, distinct from application policy.

use crate::container::{DS, XADES};
use crate::identifier;
use crate::properties::{self, Error, PropertyResult};
use crate::timestamp::XADES_141;
use crate::unsigned;
use crate::xml::{Access, AccessError, Name, Snapshot, Xml};
use structured_asn1::memory::{OwnedVec, Work};

mod syntax;
pub use syntax::{SyntaxError, SyntaxResult, check_qualifier_syntax};

/// Signed schema choice. Neither variant establishes policy acceptance.
#[derive(Debug)]
pub enum Declaration<N> {
    /// Original empty marker; its meaning must come from external context.
    Implied(N),
    /// Original explicit version identifier, hash and transforms/qualifiers.
    Explicit(Explicit<N>),
}

/// Source-bound declaration selected from the authenticated signed properties.
/// Public schema values alone cannot construct this original-source association.
pub struct Reading<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    declaration: Declaration<N>,
}

impl<N: Copy, D: Copy, G: Copy> Reading<N, D, G> {
    /// Exact original document and generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Exact selected signature covering this policy property.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original `SignaturePolicyIdentifier`.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original schema choice, before document/digest or application acceptance.
    #[must_use]
    pub fn declaration(&self) -> &Declaration<N> {
        &self.declaration
    }
}

/// Policy reading using this XML owner's original source identity types.
pub type Original<X> = Reading<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Original unsigned policy-document source, never an implicitly acquired file.
#[derive(Debug, Clone, Copy)]
pub enum StoredDocument<N> {
    /// Original base64-encoded policy document, before decoding/hash comparison.
    Embedded(N),
    /// Original local-store URI; this crate performs no file or network access.
    Local(N),
}

/// Source-bound original policy store permitted by an explicit signed hash.
/// Presence is not a successful document digest or application-policy decision.
pub struct Store<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    specification: identifier::Reading<N>,
    document: StoredDocument<N>,
}

impl<N: Copy, D: Copy, G: Copy> Store<N, D, G> {
    /// Exact original document identity/generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Selected signature whose signed policy hash must authenticate the content.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original unsigned `SignaturePolicyStore`.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original technical-specification identifier, before lexical validation.
    #[must_use]
    pub fn specification(&self) -> &identifier::Reading<N> {
        &self.specification
    }
    /// Original source choice; no acquisition or decoding has occurred.
    #[must_use]
    pub fn document(&self) -> StoredDocument<N> {
        self.document
    }
}

/// Policy store using this XML owner's original source identity types.
pub type OriginalStore<X> = Store<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Reads §5.2.10 and enforces §6.3(m) before source/decoder/provider execution.
/// Absent or implied signed policy cannot authorize an unsigned policy store.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read_store<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    inventory: &unsigned::Reading<X>,
    policy: Option<&Original<X>>,
) -> PropertyResult<Option<OriginalStore<X>>, X> {
    if access.snapshot() != inventory.snapshot() {
        return Err(Error::Access(AccessError::Changed {
            node: inventory.signature(),
        }));
    }
    access
        .query(inventory.signature(), |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    if let Some(policy) = policy
        && (policy.snapshot != inventory.snapshot()
            || !access
                .equal_id(policy.signature, inventory.signature())
                .map_err(|cause| Error::Resource {
                    node: policy.node,
                    cause,
                })?)
    {
        return Err(Error::Access(AccessError::Changed { node: policy.node }));
    }
    let mut store = None;
    for index in 0..inventory.entries().len() {
        access
            .query(inventory.signature(), |_, _, work| Ok(work.charge_work(1)))
            .map_err(Error::Access)?
            .map_err(|cause| Error::Resource {
                node: inventory.signature(),
                cause,
            })?;
        let entry = inventory.entries()[index];
        if entry.role == unsigned::Role::PolicyStore {
            store = Some(entry.node);
            break;
        }
    }
    let Some(node) = store else { return Ok(None) };
    if !matches!(
        policy.map(|value| &value.declaration),
        Some(Declaration::Explicit(_))
    ) {
        return Err(Error::Forbidden { node });
    }
    let mut fields = access.children(node);
    let spec = fields
        .next()
        .transpose()
        .map_err(Error::Child)?
        .ok_or(Error::Missing {
            parent: node,
            local: "SPDocSpecification",
        })?;
    if !named(access, spec, XADES_141, "SPDocSpecification")? {
        return Err(Error::Unexpected { node: spec });
    }
    let specification = read_specification(access, spec)?;
    let value = fields
        .next()
        .transpose()
        .map_err(Error::Child)?
        .ok_or(Error::Missing {
            parent: node,
            local: "SignaturePolicyDocument or SigPolDocLocalURI",
        })?;
    let document = if named(access, value, XADES_141, "SignaturePolicyDocument")? {
        StoredDocument::Embedded(value)
    } else if named(access, value, XADES_141, "SigPolDocLocalURI")? {
        StoredDocument::Local(value)
    } else {
        return Err(Error::Unexpected { node: value });
    };
    properties::simple_content(access, value)?;
    if let Some(extra) = fields.next() {
        return Err(Error::Unexpected {
            node: extra.map_err(Error::Child)?,
        });
    }
    Ok(Some(Store {
        snapshot: inventory.snapshot(),
        signature: inventory.signature(),
        node,
        specification,
        document,
    }))
}

/// An original qualifier, including schema-open extension payloads.
#[derive(Debug)]
pub struct Qualifier<N> {
    /// Original `SigPolicyQualifier` wrapper, whose `AnyType` content remains open.
    pub node: N,
    /// Every original direct `SPDocSpecification` in this schema-open wrapper.
    /// Presence is not selection of one technical specification or its meaning.
    pub specifications: OwnedVec<N>,
}

/// Explicit original policy declaration before content/hash or trust checks.
#[derive(Debug)]
pub struct Explicit<N> {
    /// Original `SignaturePolicyId`, not a fabricated Reference instruction.
    pub node: N,
    /// Original version identifier, before its XML-owned URI/OID lexical check.
    pub identifier: identifier::Reading<N>,
    /// Optional original `XMLDSig` transforms; no transform execution is inferred.
    pub transforms: Option<N>,
    /// Original selected digest method.
    pub method: N,
    /// Original base64 digest value, not yet decoded or compared.
    pub digest: N,
    /// Complete original qualifier catalogue in order.
    pub qualifiers: OwnedVec<Qualifier<N>>,
}

/// Reads the selected covered policy declaration without implicit acquisition.
/// EN319132-1 V1.3.1 §5.2.9 requires exactly one schema choice. A specification
/// transform requires `SPDocSpecification` before any transform/provider work.
/// This function does not identify an implied application policy, execute a
/// policy document or turn unsigned `PolicyStore` content into authenticated data.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signed: &properties::Reading<X>,
) -> PropertyResult<Option<Original<X>>, X> {
    if access.snapshot() != signed.snapshot() {
        return Err(Error::Access(AccessError::Changed {
            node: signed.parent(),
        }));
    }
    access
        .query(signed.parent(), |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    let Some(parent) = signed.policy() else {
        return Ok(None);
    };
    let mut children = access.children(parent);
    let node = children
        .next()
        .transpose()
        .map_err(Error::Child)?
        .ok_or(Error::Missing {
            parent,
            local: "SignaturePolicyId or SignaturePolicyImplied",
        })?;
    if let Some(extra) = children.next() {
        return Err(Error::Unexpected {
            node: extra.map_err(Error::Child)?,
        });
    }
    if named(access, node, XADES, "SignaturePolicyImplied")? {
        if let Some(extra) = access.children(node).next() {
            return Err(Error::Unexpected {
                node: extra.map_err(Error::Child)?,
            });
        }
        return Ok(Some(Reading {
            snapshot: signed.snapshot(),
            signature: signed.signature(),
            node: parent,
            declaration: Declaration::Implied(node),
        }));
    }
    if !named(access, node, XADES, "SignaturePolicyId")? {
        return Err(Error::Unexpected { node });
    }
    explicit(access, node).map(|value| {
        Some(Reading {
            snapshot: signed.snapshot(),
            signature: signed.signature(),
            node: parent,
            declaration: Declaration::Explicit(value),
        })
    })
}

fn explicit<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> PropertyResult<Explicit<X::Id>, X> {
    let mut fields = [None; 4];
    let mut previous = 0;
    for child in access.children(node) {
        let child = child.map_err(Error::Child)?;
        let mut selected = None;
        for (rank, (ns, local)) in [
            (XADES, "SigPolicyId"),
            (DS, "Transforms"),
            (XADES, "SigPolicyHash"),
            (XADES, "SigPolicyQualifiers"),
        ]
        .iter()
        .enumerate()
        {
            if named(access, child, ns, local)? {
                selected = Some(rank);
                break;
            }
        }
        let rank = selected.ok_or(Error::Unexpected { node: child })?;
        if fields[rank].is_some() {
            return Err(Error::Duplicate { node: child });
        }
        if rank < previous {
            return Err(Error::Order { node: child });
        }
        fields[rank] = Some(child);
        previous = rank;
    }
    let identifier = identifier::read(
        access,
        fields[0].ok_or(Error::Missing {
            parent: node,
            local: "SigPolicyId",
        })?,
    )?;
    let (method, digest) = properties::digest_value(
        access,
        fields[2].ok_or(Error::Missing {
            parent: node,
            local: "SigPolicyHash",
        })?,
    )?;
    let qualifiers = qualifiers(access, node, fields[3])?;
    if let Some(transforms) = fields[1] {
        check_transforms(access, transforms, &qualifiers)?;
    }
    Ok(Explicit {
        node,
        identifier,
        transforms: fields[1],
        method,
        digest,
        qualifiers,
    })
}

fn qualifiers<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    enclosure: X::Id,
    parent: Option<X::Id>,
) -> PropertyResult<OwnedVec<Qualifier<X::Id>>, X> {
    let mut output = access
        .query(enclosure, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    if let Some(parent) = parent {
        for child in access.children(parent) {
            let node = child.map_err(Error::Child)?;
            if !named(access, node, XADES, "SigPolicyQualifier")? {
                return Err(Error::Unexpected { node });
            }
            // AnyType may mix text and arbitrary elements. Inspect its direct
            // children without imposing an element-only content model.
            let mut specifications = access
                .query(node, |_, _, work| Ok(work.vector()))
                .map_err(Error::Access)?;
            let mut child = access.first_child(node).map_err(Error::Access)?;
            while let Some(value) = child {
                if named(access, value, XADES_141, "SPDocSpecification")? {
                    read_specification(access, value)?;
                    specifications
                        .try_push(value)
                        .map_err(|cause| Error::Resource { node: value, cause })?;
                } else if named(access, value, XADES, "SPURI")? {
                    properties::simple_content(access, value)?;
                } else if named(access, value, XADES, "SPUserNotice")? {
                    user_notice(access, value)?;
                }
                child = access.next_sibling(node, value).map_err(Error::Access)?;
            }
            output
                .try_push(Qualifier {
                    node,
                    specifications: specifications.into_owned(),
                })
                .map_err(|cause| Error::Resource { node, cause })?;
        }
        if output.is_empty() {
            return Err(Error::Missing {
                parent,
                local: "SigPolicyQualifier",
            });
        }
    }
    Ok(output.into_owned())
}

fn user_notice<X: Xml, W: Work>(access: &Access<'_, X, W>, parent: X::Id) -> PropertyResult<(), X> {
    user_notice_with(access, parent, |number| {
        properties::simple_content(access, number)
    })
}

// Both structural inspection and lexical qualification use this same grammar.
// Integer validity belongs to the XML owner's arbitrary-precision scalar kernel.
fn user_notice_with<X: Xml, W: Work, E: From<Error<X::Error, X::Id>>>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    mut integer: impl FnMut(X::Id) -> Result<(), E>,
) -> Result<(), E> {
    let mut notice = None;
    let mut text = None;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        if named(access, node, XADES, "NoticeRef")? {
            if notice.is_some() {
                return Err(Error::Duplicate { node }.into());
            }
            if text.is_some() {
                return Err(Error::Order { node }.into());
            }
            notice = Some(node);
            let mut fields = access.children(node);
            let organization =
                fields
                    .next()
                    .transpose()
                    .map_err(Error::Child)?
                    .ok_or(Error::Missing {
                        parent: node,
                        local: "Organization",
                    })?;
            if !named(access, organization, XADES, "Organization")? {
                return Err(Error::Unexpected { node: organization }.into());
            }
            properties::simple_content(access, organization)?;
            let numbers =
                fields
                    .next()
                    .transpose()
                    .map_err(Error::Child)?
                    .ok_or(Error::Missing {
                        parent: node,
                        local: "NoticeNumbers",
                    })?;
            if !named(access, numbers, XADES, "NoticeNumbers")? {
                return Err(Error::Unexpected { node: numbers }.into());
            }
            if let Some(extra) = fields.next() {
                return Err(Error::Unexpected {
                    node: extra.map_err(Error::Child)?,
                }
                .into());
            }
            for number in access.children(numbers) {
                let number = number.map_err(Error::Child)?;
                if !named(access, number, XADES, "int")? {
                    return Err(Error::Unexpected { node: number }.into());
                }
                integer(number)?;
            }
        } else if named(access, node, XADES, "ExplicitText")? {
            if text.is_some() {
                return Err(Error::Duplicate { node }.into());
            }
            properties::simple_content(access, node)?;
            text = Some(node);
        } else {
            return Err(Error::Unexpected { node }.into());
        }
    }
    Ok(())
}

fn check_transforms<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    qualifiers: &[Qualifier<X::Id>],
) -> PropertyResult<(), X> {
    let mut populated = false;
    let mut specification = None;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        if !named(access, node, DS, "Transform")? {
            return Err(Error::Unexpected { node });
        }
        let special = access.attribute(node, Name { namespace: "", local: "Algorithm" }, |value| {
            let Some(value) = value else { return Ok(None) };
            let value = access.trim_xml_whitespace(value)?;
            access.equal(value, "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification").map(Some)
        }).map_err(Error::Access)?.map_err(|cause| Error::Resource { node, cause })?;
        let Some(special) = special else {
            return Err(Error::Missing {
                parent: node,
                local: "Algorithm",
            });
        };
        if special {
            specification = Some(node);
        }
        populated = true;
    }
    if !populated {
        return Err(Error::Missing {
            parent,
            local: "Transform",
        });
    }
    if let Some(node) = specification {
        let mut index = 0;
        while index < qualifiers.len() {
            // Admit the next metadata access before selecting its slice item.
            access
                .query(node, |_, _, work| Ok(work.charge_work(1)))
                .map_err(Error::Access)?
                .map_err(|cause| Error::Resource { node, cause })?;
            if !qualifiers[index].specifications.is_empty() {
                return Ok(());
            }
            index += 1;
        }
        return Err(Error::Missing {
            parent: node,
            local: "SPDocSpecification",
        });
    }
    Ok(())
}

fn named<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> PropertyResult<bool, X> {
    access
        .has_name(node, Name { namespace, local })
        .map_err(Error::Access)
}

fn read_specification<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> PropertyResult<identifier::Reading<X::Id>, X> {
    let reading = identifier::read(access, node)?;
    if reading.qualifier == Some(identifier::Qualifier::Uri) {
        return Err(Error::Forbidden {
            node: reading.identifier,
        });
    }
    Ok(reading)
}
