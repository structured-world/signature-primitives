//! Original signing-certificate references, before digest/path validation.

use crate::binary::{self, BinaryXml, Location};
use crate::binding::{Bound, SignatureXml};
use crate::container::XADES;
use crate::properties::{Error, PropertyResult, Reading};
use crate::xml::{Access, AccessError, Name, Snapshot, Xml};
use structured_asn1::digest::{Digest, OnceError, Resolution, matches_once};
use structured_asn1::{
    Reader, Tag,
    memory::{MemoryError, OwnedVec, Work},
    universal,
};
use structured_cms::ess::IssuerSerialReading;
use structured_pkix::{Certificate, path::WorkingKey};

mod path;
pub use path::{
    CheckedPathCertificate, PathCheckResult, PathDigest, PathDigestResult, PathDigests, check_path,
    match_path,
};

/// Association with the key that actually verified the selected XML signature.
/// Trust and source association are independent: a caller-trusted key may still
/// lack a receipt linking it to a particular certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAssociation {
    /// The selected successful verification key belongs to this certificate.
    Same,
    /// Existing key evidence proves a different certificate/key association.
    Differs,
    /// Mathematical verification succeeded but no such association was retained.
    Unproven,
}

/// Read-only selected-key evidence from the XML owner, not a second verifier.
pub trait CertificateXml: SignatureXml {
    /// Reads the successful selected key/certificate association for this exact
    /// signature and source generation. `KeyInfo` presence, any valid signature,
    /// an issuer hint or caller trust alone must not produce `Same`. Missing
    /// association evidence is `Unproven`, not unsupported mathematics. Any
    /// fingerprint/key comparisons and lazy access are paid before execution.
    /// `key` is the actual expected effective key, including inherited path
    /// parameters. `Same` additionally requires the parameter semantics used
    /// by the original successful operation, not just a certificate fingerprint.
    /// Missing selected-key evidence is never repaired by invoking a resolver,
    /// constructing a standing key, re-encoding SPKI or repeating verification.
    fn key_association<W: Work>(
        &self,
        snapshot: Snapshot<Self::Document, Self::Generation>,
        signature: Self::Id,
        certificate: &Certificate<'_>,
        key: WorkingKey<'_>,
        execution: &W,
    ) -> Result<KeyAssociation, Self::Error>;
}

/// XML `DigestMethod` resolution of the selected provider, layered over its
/// [`Digest`] execution.
///
/// Resolution must enforce original method syntax/parameters and compiled XML
/// algorithm policy before hashing; no ASN.1 identifier is constructed from an
/// XML algorithm URI. Every callback admits its transitive CPU, allocation and
/// output capacity; this contract alone does not qualify an opaque backend's
/// accounting.
pub trait DigestProvider<'a, X: Xml>: Digest<'a> {
    /// Resolves the original method through the selected XML provider dispatcher.
    fn resolve<W: Work>(
        &self,
        access: &Access<'_, X, W>,
        method: X::Id,
    ) -> Result<Resolution<Self::Identity>, Self::Error>;

    /// O(1) metadata of the ACTUAL resolved native digest, independent of its
    /// URI spelling or output width. Resolution already performed any parsing;
    /// this lookup does not rescan parameters, allocate or select another engine.
    /// A signature suite without an external digest is `Intrinsic`, not a usable
    /// digest capability. The common baseline guard rejects it and MD5 before
    /// invoking hash primitives; compiled deployment acceptance stays in resolve.
    fn classify(&self, identity: &Self::Identity) -> crate::hashes::HashClass;
}

/// Completed digest agreement, separate from selected-key association/path trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    /// A syntactically identified algorithm is forbidden by the baseline format.
    ProhibitedAlgorithm,
    /// Full original certificate digest matches the signed reference.
    Matches,
    /// Completed digest comparison differs.
    Differs,
    /// Selected provider does not implement this XML digest identity.
    Unsupported,
    /// Original XML digest method violates its selected algorithm's syntax.
    MalformedMethod,
    /// Declared digest value has an impossible fixed width.
    MalformedValue,
}

/// Digest execution failure in the original XML method/value enclosure.
#[derive(Debug)]
pub enum DigestError<E> {
    /// Caller selected an ordinal outside the parsed reference catalogue.
    /// This is processing misuse, not malformed XML or resource exhaustion.
    ReferenceIndex {
        /// Requested catalogue ordinal.
        index: usize,
    },
    /// Original selected-provider/policy/resource cause.
    Provider(E),
    /// Common dispatch admission refused before provider execution.
    Resource(MemoryError),
    /// The provider's output contradicts its own identity's fixed width: a
    /// provider contract failure, never an ordinary mismatch.
    OutputWidth {
        /// Width promised by the resolved identity.
        expected: usize,
        /// Width actually returned.
        actual: usize,
    },
}

/// One original `Cert` entry in the signed `SigningCertificateV2` property.
/// The first entry identifies the signing certificate. Neither an optional URI
/// nor an issuer/serial hint substitutes for hashing the complete certificate.
#[derive(Debug, Clone, Copy)]
pub struct Reference<N> {
    node: N,
    method: N,
    digest: N,
    issuer: Option<N>,
}

impl<N: Copy> Reference<N> {
    /// Original `Cert` node; its optional URI is a caller-owned acquisition hint.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original ds:DigestMethod, including its algorithm URI and parameters.
    #[must_use]
    pub fn method(&self) -> N {
        self.method
    }
    /// Original ds:DigestValue, whose base64 decoding belongs to the XML owner.
    #[must_use]
    pub fn digest(&self) -> N {
        self.digest
    }
    /// Optional original base64 DER RFC5035 `IssuerSerial` hint.
    #[must_use]
    pub fn issuer_serial(&self) -> Option<N> {
        self.issuer
    }
}

/// The accounted original list, preserving the first-entry signing-key role.
/// Structural reading alone does not establish a certificate digest match,
/// signer-key association, validated path or attained baseline level.
pub struct References<N, D, G> {
    snapshot: Snapshot<D, G>,
    signature: N,
    node: N,
    entries: OwnedVec<Reference<N>>,
}

impl<N: Copy, D: Copy, G: Copy> References<N, D, G> {
    /// Exact original signed source generation.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<D, G> {
        self.snapshot
    }
    /// Exact selected signature that authenticates this certificate catalogue.
    #[must_use]
    pub fn signature(&self) -> N {
        self.signature
    }
    /// Original signed property container.
    #[must_use]
    pub fn node(&self) -> N {
        self.node
    }
    /// Original entries in their normative order; the list is nonempty.
    #[must_use]
    pub fn entries(&self) -> &[Reference<N>] {
        &self.entries
    }
}

/// Compares one original reference with a candidate's complete original encoding.
///
/// The caller must separately bind this candidate to the successfully selected
/// XML signature key. A digest match, URI or issuer hint does not establish that
/// association and does not produce baseline/path/trust evidence here.
pub fn compare<'p, X: BinaryXml, P: DigestProvider<'p, X>, W: Work>(
    xml: &X,
    reference: &Catalogue<X>,
    index: usize,
    certificate: &Certificate<'_>,
    provider: &'p P,
    execution: &W,
) -> binary::BinaryResult<Agreement, X, DigestError<P::Error>> {
    // An invalid ordinal is caller misuse, not malformed signed XML. Represent
    // the enclosure honestly without indexing or starting a provider operation.
    let Some(entry) = reference.entries.get(index) else {
        return Err(binary::Error::Callback {
            location: Location {
                snapshot: reference.snapshot,
                node: reference.node,
            },
            cause: DigestError::ReferenceIndex { index },
        });
    };
    let location = Location {
        snapshot: reference.snapshot,
        node: entry.method,
    };
    let access = Access::new(xml, reference.snapshot, execution);
    if let Some(answer) = preflight_method(&access, entry.method)
        .map_err(|cause| binary::Error::Access { location, cause })?
    {
        return Ok(answer);
    }
    binary::with_octets(
        xml,
        Location {
            snapshot: reference.snapshot,
            node: entry.digest,
        },
        execution,
        |expected| {
            Ok::<_, core::convert::Infallible>(compare_expected(
                &access,
                entry,
                certificate,
                provider,
                expected,
            ))
        },
    )
    .map_err(|error| error.map_callback(|never| match never {}))?
}

fn compare_expected<'p, X: Xml, P: DigestProvider<'p, X>, W: Work>(
    access: &Access<'_, X, W>,
    entry: &Reference<X::Id>,
    certificate: &Certificate<'_>,
    provider: &'p P,
    expected: &[u8],
) -> binary::BinaryResult<Agreement, X, DigestError<P::Error>> {
    let identity = match resolve_expected(access, entry, provider, expected)? {
        Expected::Ready(identity) => identity,
        Expected::Answer(answer) => return Ok(answer),
    };
    compare_resolved(access, entry, certificate, provider, &identity, expected)
}

pub(crate) enum Expected<I> {
    Ready(FormatDigest<I>),
    Answer(Agreement),
}

/// A resolved identity that passed the shared baseline digest-class gate.
/// Only `baseline_digest` constructs it; optimized paths cannot bypass the gate
/// merely by already possessing an opaque provider identity.
pub(crate) struct FormatDigest<I>(I);

impl<I> FormatDigest<I> {
    pub(crate) fn identity(&self) -> &I {
        &self.0
    }
}

pub(crate) fn baseline_digest<'p, X: Xml, P: DigestProvider<'p, X>>(
    identity: P::Identity,
    provider: &P,
) -> Expected<P::Identity> {
    match resolved_digest::<true, X, P>(identity, provider) {
        Ok(identity) => Expected::Ready(FormatDigest(identity)),
        Err(answer) => Expected::Answer(answer),
    }
}

pub(crate) fn resolved_digest<'p, const BASELINE: bool, X: Xml, P: DigestProvider<'p, X>>(
    identity: P::Identity,
    provider: &P,
) -> Result<P::Identity, Agreement> {
    // EN319132-1 V1.3.1 §6.2.1 prohibits the actual MD5 digest. URI aliases
    // cannot change that requirement. XMLDSig1.1 §4.4.3.5 selects a DIGEST
    // algorithm here, not an intrinsic signature suite with no external hash.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-DigestMethod
    match provider.classify(&identity) {
        crate::hashes::HashClass::Md5 if BASELINE => Err(Agreement::ProhibitedAlgorithm),
        crate::hashes::HashClass::Intrinsic => Err(Agreement::MalformedMethod),
        crate::hashes::HashClass::Md5 | crate::hashes::HashClass::OtherKnown => Ok(identity),
    }
}

fn resolve_expected<'p, X: Xml, P: DigestProvider<'p, X>, W: Work>(
    access: &Access<'_, X, W>,
    entry: &Reference<X::Id>,
    provider: &P,
    expected: &[u8],
) -> binary::BinaryResult<Expected<P::Identity>, X, DigestError<P::Error>> {
    let location = Location {
        snapshot: access.snapshot(),
        node: entry.method,
    };
    let resolved = access
        .query(entry.method, |_, _, _| {
            Ok(provider.resolve(access, entry.method))
        })
        .map_err(|cause| binary::Error::Access { location, cause })?
        .map_err(|cause| binary::Error::Callback {
            location,
            cause: DigestError::Provider(cause),
        })?;
    let identity = match resolved {
        Resolution::Supported(identity) => identity,
        Resolution::Unsupported => return Ok(Expected::Answer(Agreement::Unsupported)),
        Resolution::Malformed => return Ok(Expected::Answer(Agreement::MalformedMethod)),
    };
    let identity = match baseline_digest::<X, P>(identity, provider) {
        Expected::Ready(identity) => identity,
        answer @ Expected::Answer(_) => return Ok(answer),
    };
    if let Some(width) = provider.width(identity.identity())
        && expected.len() != width
    {
        return Ok(Expected::Answer(Agreement::MalformedValue));
    }
    Ok(Expected::Ready(identity))
}

fn compare_resolved<'p, X: Xml, P: DigestProvider<'p, X>, W: Work>(
    access: &Access<'_, X, W>,
    entry: &Reference<X::Id>,
    certificate: &Certificate<'_>,
    provider: &'p P,
    identity: &FormatDigest<P::Identity>,
    expected: &[u8],
) -> binary::BinaryResult<Agreement, X, DigestError<P::Error>> {
    let execution = access.execution();
    let location = Location {
        snapshot: access.snapshot(),
        node: entry.digest,
    };
    let check = || {
        execution.charge_work(1).map_err(DigestError::Resource)?;
        // One update over the whole original certificate; no re-encoding,
        // implicit acquisition or width-based algorithm inference.
        let answer = matches_once(
            provider,
            identity.identity(),
            certificate.as_bytes(),
            expected,
            execution,
        )
        .map_err(|error| match error {
            OnceError::Provider(cause) => DigestError::Provider(cause),
            OnceError::OutputWidth { expected, actual } => {
                DigestError::OutputWidth { expected, actual }
            }
        })?;
        Ok(match answer {
            Resolution::Supported(true) => Agreement::Matches,
            Resolution::Supported(false) => Agreement::Differs,
            Resolution::Unsupported => Agreement::Unsupported,
            Resolution::Malformed => Agreement::MalformedMethod,
        })
    };
    check().map_err(|cause| binary::Error::Callback { location, cause })
}

pub(crate) fn preflight_method<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> Result<Option<Agreement>, AccessError<X::Error, X::Id>> {
    access
        .attribute(
            node,
            Name {
                namespace: "",
                local: "Algorithm",
            },
            |value| {
                let Some(value) = value else {
                    return Ok(Some(Agreement::MalformedMethod));
                };
                let value = access.trim_xml_whitespace(value)?;
                // EN319132-1 §6.2.1 unconditionally excludes MD5. This format rule
                // cannot be relaxed by a general XML algorithm policy or provider.
                // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
                // The URI is RFC9231 §2.1.1's MD5 digest identifier.
                // https://www.rfc-editor.org/rfc/rfc9231.html#section-2.1.1
                if access.equal(value, "http://www.w3.org/2001/04/xmldsig-more#md5")? {
                    return Ok(Some(Agreement::ProhibitedAlgorithm));
                }
                Ok(None)
            },
        )?
        .map_err(|cause| AccessError::Resource { node, cause })
}

/// Certificate-reference catalogue using the XML owner's original identities.
pub type Catalogue<X> = References<<X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;

/// Completed selected-key and signed certificate-digest facts for this candidate.
/// Original borrowed sources remain attached, so facts for one certificate or
/// signature cannot silently become evidence for a different original object.
/// This is not a baseline-level assertion or path/revocation/trust verdict.
pub struct CheckedCertificate<'view, 'document, N, D, G> {
    reference: &'view References<N, D, G>,
    certificate: &'view Certificate<'document>,
    key: KeyAssociation,
    digest: Agreement,
}

impl<'view, 'document, N, D, G> CheckedCertificate<'view, 'document, N, D, G> {
    /// Actual candidate whose original bytes were compared.
    #[must_use]
    pub fn certificate(&self) -> &'view Certificate<'document> {
        self.certificate
    }
    /// Original signed reference catalogue and its selected signature/source.
    #[must_use]
    pub fn reference(&self) -> &'view References<N, D, G> {
        self.reference
    }
    /// Independent actual verification-key association.
    #[must_use]
    pub fn key(&self) -> KeyAssociation {
        self.key
    }
    /// Independent complete signed digest comparison.
    #[must_use]
    pub fn digest(&self) -> Agreement {
        self.digest
    }
    /// Both selected-key association and signed certificate digest are proven.
    /// Other property syntax and path/status/policy checks remain necessary.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.key == KeyAssociation::Same && self.digest == Agreement::Matches
    }
}

/// Checked facts indexed by original identities, independent of a scoped XML view.
pub type Checked<'view, 'document, X> = CheckedCertificate<
    'view,
    'document,
    <X as Xml>::Id,
    <X as Xml>::Document,
    <X as Xml>::Generation,
>;

/// Selected-certificate conformance/processing refusal, separate from key/digest mismatch.
#[derive(Debug)]
pub enum CheckError<E, PE, N, D, G> {
    /// Catalogue belongs to another selected signature or original generation.
    /// This is caller/source misuse, not a fault in the signed document.
    ForeignCatalogue {
        /// Requested selected signature.
        signature: N,
        /// Original supplied reference container.
        property: N,
    },
    /// Current baseline prohibits the optional general-schema Cert URI attribute.
    ForbiddenCertificateUri {
        /// Original Cert entry, with exact XML document/generation.
        location: Location<N, D, G>,
    },
    /// Original read-only selected-key access/refusal.
    Access(AccessError<E, N>),
    /// Original digest execution and binary/XML source enclosure.
    Digest(binary::Error<E, DigestError<PE>, N, D, G>),
}

/// Selected-certificate check result retaining both original borrowed operands.
pub type CheckResult<'v, 'd, X, PE> = CertificateResult<Checked<'v, 'd, X>, X, PE>;

/// Certificate binding result in the XML owner's original error/source domains.
pub type CertificateResult<T, X, PE> = Result<
    T,
    CheckError<<X as Xml>::Error, PE, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
>;

/// Scoped optional issuer-hint refusal; this hint never replaces digest binding.
#[derive(Debug)]
pub enum IssuerError<E> {
    /// Caller selected an ordinal outside the original certificate catalogue.
    ReferenceIndex {
        /// Requested catalogue ordinal.
        index: usize,
    },
    /// Original decoded ASN.1 source failure, including its resource class.
    Encoding(structured_asn1::Error),
    /// Original shared ESS schema/diagnostic-retention refusal.
    Reading(structured_cms::Error),
    /// The source contains bytes after the one required DER instance.
    Trailing {
        /// Original position in the decoded source, not XML bytes.
        offset: u64,
    },
    /// Original inspection callback refused.
    Callback(E),
}

/// Reads the original optional hint with the existing RFC5035 field kernel.
///
/// EN319132-1 §5.2.2 fixes this value to one DER `IssuerSerial`. The scoped
/// callback sees its original reading and every retained diagnostic. A hint's
/// readability or issuer agreement is not certificate digest/key/path evidence.
pub fn with_issuer_serial<X: BinaryXml, R, E>(
    xml: &X,
    reference: &Catalogue<X>,
    index: usize,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(IssuerSerialReading<'source>) -> Result<R, E>,
) -> binary::BinaryResult<Option<binary::LocatedValue<R, X>>, X, IssuerError<E>> {
    let location = Location {
        snapshot: reference.snapshot,
        node: reference.node,
    };
    let Some(entry) = reference.entries.get(index) else {
        return Err(binary::Error::Callback {
            location,
            cause: IssuerError::ReferenceIndex { index },
        });
    };
    let execution = operation.execution();
    Access::new(xml, reference.snapshot, &execution)
        .query(entry.node, |_, _, _| Ok(()))
        .map_err(|cause| binary::Error::Access { location, cause })?;
    let Some(node) = entry.issuer else {
        return Ok(None);
    };
    let location = Location {
        snapshot: reference.snapshot,
        node,
    };
    with_issuer_serial_at(xml, location, operation, visitor).map(Some)
}

pub(crate) fn with_issuer_serial_at<X: BinaryXml, R, E>(
    xml: &X,
    location: Location<X::Id, X::Document, X::Generation>,
    operation: &Reader<'_>,
    visitor: impl for<'source> FnOnce(IssuerSerialReading<'source>) -> Result<R, E>,
) -> binary::BinaryResult<binary::LocatedValue<R, X>, X, IssuerError<E>> {
    binary::with_der_reader(xml, location, operation, |reader| {
        let element = reader
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(IssuerError::Encoding)?;
        let reading = IssuerSerialReading::read(reader, &element, "xades.issuerSerialV2")
            .map_err(IssuerError::Reading)?;
        if !reader.is_empty() {
            return Err(IssuerError::Trailing {
                offset: reader.offset(),
            });
        }
        visitor(reading)
            .map(|value| binary::Located { location, value })
            .map_err(IssuerError::Callback)
    })
}

/// Checks the first signed reference against the actual selected candidate.
/// The first-entry role is defined by EN319132-1 §5.2.2. Additional entries stay
/// available in the original catalogue; they are not silently treated as trust.
/// Baseline reference conformance is checked before key/provider callbacks;
/// low-level [`read`] still supports inspection of the general reference schema.
pub fn check<
    'view,
    'document,
    'p,
    X: BinaryXml + CertificateXml,
    P: DigestProvider<'p, X>,
    W: Work,
>(
    xml: &X,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    reference: &'view Catalogue<X>,
    certificate: &'view Certificate<'document>,
    provider: &'p P,
    execution: &W,
) -> CheckResult<'view, 'document, X, P::Error> {
    let key = bind_key::<X, P::Error, W>(
        xml,
        bound,
        reference,
        certificate,
        WorkingKey::standing(certificate.tbs().public_key()),
        execution,
    )?;
    let digest =
        compare(xml, reference, 0, certificate, provider, execution).map_err(CheckError::Digest)?;
    Ok(CheckedCertificate {
        reference,
        certificate,
        key,
        digest,
    })
}

fn bind_key<X: CertificateXml, PE, W: Work>(
    xml: &X,
    bound: &Bound<X::Id, X::Document, X::Generation>,
    reference: &Catalogue<X>,
    certificate: &Certificate<'_>,
    key: WorkingKey<'_>,
    execution: &W,
) -> CertificateResult<KeyAssociation, X, PE> {
    let source = bound.containers();
    if reference.snapshot != source.snapshot() {
        return Err(CheckError::ForeignCatalogue {
            signature: source.signature(),
            property: reference.node,
        });
    }
    let access = Access::new(xml, source.snapshot(), execution);
    if !access
        .equal_id(reference.signature, source.signature())
        .map_err(|cause| {
            CheckError::Access(AccessError::Resource {
                node: reference.node,
                cause,
            })
        })?
    {
        return Err(CheckError::ForeignCatalogue {
            signature: source.signature(),
            property: reference.node,
        });
    }
    for index in 0..reference.entries.len() {
        access
            .query(reference.node, |_, _, work| Ok(work.charge_work(1)))
            .map_err(CheckError::Access)?
            .map_err(|cause| {
                CheckError::Access(AccessError::Resource {
                    node: reference.node,
                    cause,
                })
            })?;
        let entry = &reference.entries[index];
        let written = access
            .attribute(
                entry.node,
                Name {
                    namespace: "",
                    local: "URI",
                },
                |value| value.is_some(),
            )
            .map_err(CheckError::Access)?;
        // EN319132-1 V1.3.1 §6.3(i): a current-baseline generator shall not
        // write Cert/@URI, even though the general §5.2.2 schema allows it.
        // Preserve inspection separately, but do not run acceptance callbacks
        // before reporting this baseline conformance failure.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
        if written {
            return Err(CheckError::ForbiddenCertificateUri {
                location: Location {
                    snapshot: reference.snapshot,
                    node: entry.node,
                },
            });
        }
    }
    access
        .query(source.signature(), |xml, snapshot, work| {
            xml.key_association(snapshot, source.signature(), certificate, key, work)
        })
        .map_err(CheckError::Access)
}

/// Reads the signed certificate-reference schema without acquisition or hashing.
///
/// EN319132-1 V1.3.1 §5.2.2 and its versioned 1.3.2 schema define a nonempty
/// Cert list, each with `CertDigest` followed by optional `IssuerSerialV2`. The
/// digest consists of the original `DigestMethod` then `DigestValue`, exactly once.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn read<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    signed: &Reading<X>,
) -> PropertyResult<Catalogue<X>, X> {
    let node = signed.signing_certificate();
    if signed.snapshot() != access.snapshot() {
        return Err(Error::Access(AccessError::Changed { node }));
    }
    let mut entries = access
        .query(node, |_, _, work| Ok(work.vector()))
        .map_err(Error::Access)?;
    for child in access.children(node) {
        let child = child.map_err(Error::Child)?;
        expect_name(access, child, XADES, "Cert")?;
        let entry = read_entry(access, child)?;
        entries
            .try_push(entry)
            .map_err(|cause| Error::Resource { node: child, cause })?;
    }
    if entries.is_empty() {
        return Err(Error::Missing {
            parent: node,
            local: "Cert",
        });
    }
    Ok(References {
        snapshot: signed.snapshot(),
        signature: signed.signature(),
        node,
        entries: entries.into_owned(),
    })
}

pub(crate) fn read_entry<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
) -> PropertyResult<Reference<X::Id>, X> {
    let mut children = access.children(node);
    let digest = required(&mut children, node, "CertDigest")?;
    expect_name(access, digest, XADES, "CertDigest")?;
    let issuer = children.next().transpose().map_err(Error::Child)?;
    if let Some(issuer) = issuer {
        expect_name(access, issuer, XADES, "IssuerSerialV2")?;
    }
    if let Some(extra) = children.next() {
        return Err(Error::Unexpected {
            node: extra.map_err(Error::Child)?,
        });
    }
    let (method, value) = crate::properties::digest_value(access, digest)?;
    Ok(Reference {
        node,
        method,
        digest: value,
        issuer,
    })
}

fn required<X: Xml, W: Work>(
    children: &mut crate::xml::Children<'_, '_, X, W>,
    parent: X::Id,
    local: &'static str,
) -> PropertyResult<X::Id, X> {
    children
        .next()
        .transpose()
        .map_err(Error::Child)?
        .ok_or(Error::Missing { parent, local })
}

fn expect_name<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    node: X::Id,
    namespace: &str,
    local: &str,
) -> PropertyResult<(), X> {
    if !access
        .has_name(node, Name { namespace, local })
        .map_err(Error::Access)?
    {
        return Err(Error::Unexpected { node });
    }
    Ok(())
}
