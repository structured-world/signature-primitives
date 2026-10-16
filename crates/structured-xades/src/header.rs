//! Baseline `XMLDSig` header requirements, separate from selected-key/path trust.

use crate::binary::{self, BinaryXml, Location};
use crate::binding::Bound;
use crate::container::DS;
use crate::properties::{Error, PropertyResult};
use crate::xml::{Access, AccessError, Name, Snapshot, Xml};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_pkix::Certificate;

/// Original mandatory header roles; presence alone is not certificate binding.
#[derive(Debug)]
pub struct Header<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    key_info: N,
    x509_data: N,
    method: N,
    certificates: OwnedVec<N>,
}

impl<N: Copy, D: Copy, G: Copy> Header<N, D, G> {
    /// Original XML identity and immutable generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Exact selected Signature.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original mandatory `KeyInfo`.
    #[must_use]
    pub fn key_info(&self) -> N {
        self.key_info
    }
    /// The one baseline `X509Data` container.
    #[must_use]
    pub fn x509_data(&self) -> N {
        self.x509_data
    }
    /// Original `SignedInfo` canonicalization method, retaining parameters.
    #[must_use]
    pub fn method(&self) -> N {
        self.method
    }
    /// Original certificate value nodes in source order.
    #[must_use]
    pub fn certificates(&self) -> &[N] {
        &self.certificates
    }
}

/// Header using the XML owner's original identity types.
pub type Reading<X> = Header<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// The two native value fields in XMLDSig1.1 `X509Data` (not draft extensions).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueKind {
    Certificate,
    Crl,
}
impl ValueKind {
    pub(crate) fn local(self) -> &'static str {
        match self {
            Self::Certificate => "X509Certificate",
            Self::Crl => "X509CRL",
        }
    }
}

// Shared with plain counters: discovery does not impose B-B KeyInfo/X509Data
// cardinalities or claim that these untrusted values authenticate the signer.
type ValueVisitResult<X, E> =
    Result<(), crate::reference::VisitError<Error<<X as Xml>::Error, <X as Xml>::Id>, E>>;

pub(crate) fn visit_values<X: Xml, W: Work, VE>(
    access: &Access<'_, X, W>,
    data: X::Id,
    mut visitor: impl FnMut(X::Id, ValueKind) -> Result<(), VE>,
) -> ValueVisitResult<X, VE> {
    use crate::reference::VisitError;
    for child in access.children(data) {
        let node = child.map_err(|cause| VisitError::Processing(Error::Child(cause)))?;
        for kind in [ValueKind::Certificate, ValueKind::Crl] {
            if access
                .has_name(
                    node,
                    Name {
                        namespace: DS,
                        local: kind.local(),
                    },
                )
                .map_err(|cause| VisitError::Processing(Error::Access(cause)))?
            {
                visitor(node, kind).map_err(VisitError::Visitor)?;
                break;
            }
        }
    }
    Ok(())
}

/// Reads mandatory header roles under the already selected authenticated source.
/// EN319132-1 §6.3 table2 requires one KeyInfo/X509Data and its requirement(a)
/// requires the signing certificate within `X509Certificate`; [`included`] checks
/// the latter against the actual candidate, rather than inferring it from count.
/// Requirement(d)'s six canonicalization identities are format constraints;
/// parameter validation and stricter compiled algorithm policy stay XML-owned.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    bound: &Bound<X::Id, X::Document, X::Generation>,
) -> PropertyResult<Reading<X>, X> {
    let layout = bound.containers();
    if access.snapshot() != layout.snapshot() {
        return Err(Error::Access(AccessError::Changed {
            node: layout.signature(),
        }));
    }
    let signature = layout.signature();
    let key_info = required(access, signature, "KeyInfo")?;
    let x509_data = required(access, key_info, "X509Data")?;
    let signed_info = required(access, signature, "SignedInfo")?;
    let method = required(access, signed_info, "CanonicalizationMethod")?;
    let allowed = access
        .attribute(
            method,
            Name {
                namespace: "",
                local: "Algorithm",
            },
            |value| {
                let Some(value) = value else {
                    return Ok(false);
                };
                let value = access.trim_xml_whitespace(value)?;
                for algorithm in [
                    "http://www.w3.org/2006/12/xml-c14n11",
                    "http://www.w3.org/2001/10/xml-exc-c14n#",
                    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                    "http://www.w3.org/2006/12/xml-c14n11#WithComments",
                    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
                    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
                ] {
                    if access.equal(value, algorithm)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            },
        )
        .map_err(Error::Access)?
        .map_err(|cause| Error::Resource {
            node: method,
            cause,
        })?;
    if !allowed {
        return Err(Error::Unexpected { node: method });
    }
    let mut certificates = access
        .query(x509_data, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    visit_values(access, x509_data, |node, kind| {
        if kind == ValueKind::Certificate {
            certificates
                .try_push(node)
                .map_err(|cause| Error::Resource { node, cause })?;
        }
        Ok(())
    })
    .map_err(|cause| match cause {
        crate::reference::VisitError::Processing(cause)
        | crate::reference::VisitError::Visitor(cause) => cause,
    })?;
    if certificates.is_empty() {
        return Err(Error::Missing {
            parent: x509_data,
            local: "X509Certificate",
        });
    }
    Ok(Header {
        snapshot: layout.snapshot(),
        signature,
        key_info,
        x509_data,
        method,
        certificates: certificates.into_owned(),
    })
}

fn required<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
    local: &'static str,
) -> PropertyResult<X::Id, X> {
    let mut found = None;
    for child in access.children(parent) {
        let node = child.map_err(Error::Child)?;
        if access
            .has_name(
                node,
                Name {
                    namespace: DS,
                    local,
                },
            )
            .map_err(Error::Access)?
        {
            if found.is_some() {
                return Err(Error::Duplicate { node });
            }
            found = Some(node);
        }
    }
    found.ok_or(Error::Missing { parent, local })
}

/// Original equality-scan admission refusal; never a certificate mismatch.
#[derive(Debug)]
pub struct InclusionError(pub MemoryError);

/// Original included-certificate location using the XML owner's identities.
pub type Inclusion<X> =
    Option<Location<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>>;

/// Finds the actual candidate's complete original DER in the selected `KeyInfo`.
/// No hash, re-encoding, key hint or certificate count substitutes for equality.
/// XML base64 decoding stays with the bounded XML owner. This checks presence,
/// not a path, revocation result, or association with the selected signature key.
pub fn included<X: BinaryXml, W: Work>(
    xml: &X,
    header: &Reading<X>,
    certificate: &Certificate<'_>,
    execution: &W,
) -> binary::BinaryResult<Inclusion<X>, X, InclusionError> {
    let access = Access::new(xml, header.snapshot, execution);
    for index in 0..header.certificates.len() {
        let location = Location {
            snapshot: header.snapshot,
            node: header.key_info,
        };
        access
            .query(header.key_info, |_, _, work| Ok(work.charge_work(1)))
            .map_err(|cause| binary::Error::Access { location, cause })?
            .map_err(|cause| binary::Error::Callback {
                location,
                cause: InclusionError(cause),
            })?;
        let location = Location {
            snapshot: header.snapshot,
            node: header.certificates[index],
        };
        let matches = binary::with_octets(xml, location, execution, |bytes| {
            if bytes.len() != certificate.as_bytes().len() {
                return Ok(false);
            }
            let length = u64::try_from(bytes.len())
                .map_err(|_| InclusionError(MemoryError::WorkExceeded))?;
            execution.charge_work(length).map_err(InclusionError)?;
            Ok(bytes == certificate.as_bytes())
        })?;
        if matches {
            return Ok(Some(location));
        }
    }
    Ok(None)
}
