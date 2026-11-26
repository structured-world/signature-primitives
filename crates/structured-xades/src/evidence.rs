//! ETSI TS 119 132-3 evidence records for direct incorporation.

use crate::{
    binding::Selected,
    container::{Layout, XADES},
    xml::{Access, AccessError, ChildError, Name, Snapshot, Xml},
};
use core::ops::Range;
use structured_asn1::memory::{MemoryError, OwnedVec, Work};

mod asn1;
mod objects;
pub mod xmlers;
pub use asn1::{Asn1, Asn1Error, Asn1ReadingError, Asn1Result, Asn1Verification};
pub use objects::{Object, ObjectError, Objects};

/// ETSI TS 119 132-3 §4.1 namespace for the sealing property and ASN.1 members.
pub const XADES_ERS: &str = "http://uri.etsi.org/19132/v1.1.1#";
/// RFC 6283 §2.1 namespace for XML evidence records.
pub const XML_ERS: &str = "urn:ietf:params:xml:ns:ers";

const PROPERTY: Name<'static> = Name {
    namespace: XADES_ERS,
    local: "SealingEvidenceRecords",
};
const ASN_MEMBER: Name<'static> = Name {
    namespace: XADES_ERS,
    local: "ASN1EvidenceRecord",
};
const XML_MEMBER: Name<'static> = Name {
    namespace: XML_ERS,
    local: "EvidenceRecord",
};

/// Original wire format of all members on one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// RFC 4998 binary EvidenceRecord carried as XML base64Binary.
    Asn1,
    /// RFC 6283 EvidenceRecord carried as original XML.
    Xml,
}

/// Original resource and structural results remain located.
#[derive(Debug)]
pub enum Error<E, N> {
    /// Original XML owner, generation, or Work refusal.
    Access(AccessError<E, N>),
    /// Original container traversal refusal.
    Child(ChildError<E, N>),
    /// Allocation or work refused before growth/traversal.
    Resource {
        /// Original enclosure.
        node: N,
        /// Unchanged resource cause.
        cause: MemoryError,
    },
    /// A property has no evidence record member.
    Empty(N),
    /// Unexpected element for this property.
    Unexpected(N),
    /// Formats are mixed in one property or signature.
    Mixed(N),
    /// The record ordinal was not obtained from the original catalogue.
    Index(usize),
    /// The selection is outside the original authenticated layout.
    Foreign(N),
}

/// Result in the original XML owner's identity and error types.
pub type ResultFor<T, X> = Result<T, Error<<X as Xml>::Error, <X as Xml>::Id>>;

/// One seal enclosing parallel records with the same protected input.
#[derive(Debug)]
pub struct Group<N> {
    node: N,
    members: Range<usize>,
}

impl<N: Copy> Group<N> {
    /// Exact original `SealingEvidenceRecords` element.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }

    /// Its parallel members in the catalogue's original order.
    #[must_use]
    pub fn members(&self) -> Range<usize> {
        self.members.clone()
    }
}

/// One original member of a sealing group.
#[derive(Debug, Clone, Copy)]
pub struct Member<N> {
    node: N,
    group: usize,
}

impl<N: Copy> Member<N> {
    /// Exact original ASN.1 enclosure or XML evidence record element.
    #[must_use]
    pub fn node(self) -> N {
        self.node
    }

    /// Original sealing property ordinal shared by parallel members.
    #[must_use]
    pub fn group(self) -> usize {
        self.group
    }
}

/// The complete sealing census for one authenticated direct signature.
pub struct Records<'a, X: Xml> {
    bound: &'a Selected<X>,
    parent: Option<X::Id>,
    format: Option<Format>,
    groups: OwnedVec<Group<X::Id>>,
    members: OwnedVec<Member<X::Id>>,
}

impl<X: Xml> Records<'_, X> {
    /// Actual original document and generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<X::Document, X::Generation> {
        self.bound.containers().snapshot()
    }

    /// The original signature enclosing every group.
    #[must_use]
    pub fn signature(&self) -> X::Id {
        self.bound.containers().signature()
    }

    /// Actual record format, absent only when the census is empty.
    #[must_use]
    pub fn format(&self) -> Option<Format> {
        self.format
    }

    /// Original groups in serial order.
    #[must_use]
    pub fn groups(&self) -> &[Group<X::Id>] {
        &self.groups
    }

    /// Original members in group order and then document order.
    #[must_use]
    pub fn members(&self) -> &[Member<X::Id>] {
        &self.members
    }
}

/// Inspect complete original group structure on the bound signature.
/// ETSI TS 119 132-3 §§5.1.1 and 5.2.1 treat members in a property as parallel
/// and require one wire format across all properties on the same signature.
/// <https://www.etsi.org/deliver/etsi_ts/119100_119199/11913203/01.01.01_60/ts_11913203v010101p.pdf>
pub fn read<'a, X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &'a Selected<X>,
) -> ResultFor<Records<'a, X>, X> {
    let layout = bound.containers();
    let parent = unsigned_parent(access, layout)?;
    let work = access.execution();
    let mut format = None;
    let mut groups = work.vector();
    let mut members = work.vector();
    if let Some(parent) = parent {
        for property in access.children(parent) {
            let node = property.map_err(Error::Child)?;
            if !access.has_name(node, PROPERTY).map_err(Error::Access)? {
                continue;
            }
            let first = members.len();
            for member in access.children(node) {
                let member = member.map_err(Error::Child)?;
                let actual = member_format(access, member)?;
                if let Some(expected) = format {
                    if expected != actual {
                        return Err(Error::Mixed(member));
                    }
                } else {
                    format = Some(actual);
                }
                members
                    .try_push(Member {
                        node: member,
                        group: groups.len(),
                    })
                    .map_err(|cause| Error::Resource {
                        node: member,
                        cause,
                    })?;
            }
            if members.len() == first {
                return Err(Error::Empty(node));
            }
            groups
                .try_push(Group {
                    node,
                    members: first..members.len(),
                })
                .map_err(|cause| Error::Resource { node, cause })?;
        }
    }
    Ok(Records {
        bound,
        parent,
        format,
        groups: groups.into_owned(),
        members: members.into_owned(),
    })
}

fn member_format<X: Xml, W: Work>(access: &Access<'_, X, W>, node: X::Id) -> ResultFor<Format, X> {
    if access.has_name(node, ASN_MEMBER).map_err(Error::Access)? {
        Ok(Format::Asn1)
    } else if access.has_name(node, XML_MEMBER).map_err(Error::Access)? {
        Ok(Format::Xml)
    } else {
        Err(Error::Unexpected(node))
    }
}

fn unsigned_parent<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    layout: &Layout<X>,
) -> ResultFor<Option<X::Id>, X> {
    let signature = layout.signature();
    if layout.snapshot() != access.snapshot() {
        return Err(Error::Foreign(signature));
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(Error::Access)?;
    let mut found = None;
    if let Some(unsigned) = layout.unsigned() {
        for child in access.children(unsigned) {
            let child = child.map_err(Error::Child)?;
            if access
                .has_name(
                    child,
                    Name {
                        namespace: XADES,
                        local: "UnsignedSignatureProperties",
                    },
                )
                .map_err(Error::Access)?
                && found.replace(child).is_some()
            {
                return Err(Error::Unexpected(child));
            }
        }
    }
    Ok(found)
}
