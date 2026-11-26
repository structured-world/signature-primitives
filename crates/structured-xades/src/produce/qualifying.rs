//! Optional qualifying properties over the XML owner's staged signature.

use super::{Datatype, Emit, Error, Event, Value, Work, Writer, XADES, attr};
use crate::identifier::Qualifier;

/// The exact lexical metadata of the original target when it is a ds:Object.
#[derive(Clone, Copy, Debug, Default)]
pub struct ObjectMetadata<'a> {
    /// Written `MimeType` attribute.
    pub mime_type: Option<&'a str>,
    /// Written Encoding attribute.
    pub encoding: Option<&'a str>,
}

/// A schema-governed slot for an XML-owned fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragmentSlot {
    /// Contents of an `AnyType` wrapper, including any allowed attributes.
    AnyContent,
    /// A complete ds:Transforms element with its actual parameters.
    PolicyTransforms,
}

/// Owner capabilities for new properties in the same unpublished draft.
pub trait PropertyWriter: Writer {
    /// An original typed fragment handle, scoped to this draft.
    type Fragment;

    /// Resolve this fragment URI to the actual ds:Reference in the selected
    /// `SignedInfo` or a signed Manifest. Reject a `SignedProperties` reference,
    /// count lookup work, and reject stale or ambiguous identities.
    /// A present result without attributes also represents a non-ds:Object target.
    fn data_reference<W: Work>(
        &self,
        uri: &str,
        work: &W,
    ) -> Result<Option<ObjectMetadata<'_>>, Self::Error>;

    /// Write the exact admitted fragment in this slot with all XML policy,
    /// source-identity, and resource checks. The owner must keep the insertion
    /// point and reference plan fixed throughout one property write.
    fn fragment<W: Work>(
        &mut self,
        slot: FragmentSlot,
        fragment: &Self::Fragment,
        work: &W,
    ) -> Result<(), Self::Error>;

    /// Write lexical xsd:integer in the current element using the owner's
    /// scalar validation. Arbitrary width and sign are supported.
    fn integer<W: Work>(&mut self, lexical: &str, work: &W) -> Result<(), Self::Error>;
}

/// EN 319 132-1 §5.1.2 auxiliary object identifier.
#[derive(Clone, Copy, Debug)]
pub struct Identifier<'a> {
    /// Original lexical URI, with the exact OID representation when qualified.
    pub uri: &'a str,
    /// Schema qualifier for an OID carried by the URI.
    pub qualifier: Option<Qualifier>,
    /// Optional textual description.
    pub description: Option<&'a str>,
    /// URI references to documentation, in supplied order.
    pub documentation: &'a [&'a str],
}

impl Identifier<'_> {
    pub(super) fn write<B: Writer, W: Work>(
        self,
        namespace: &'static str,
        name: &'static str,
        emit: &mut Emit<'_, B, W>,
    ) -> Result<(), Error<B::Error>> {
        self.write_in(namespace, XADES, name, emit)
    }

    pub(super) fn write_in<B: Writer, W: Work>(
        self,
        namespace: &'static str,
        children: &'static str,
        name: &'static str,
        emit: &mut Emit<'_, B, W>,
    ) -> Result<(), Error<B::Error>> {
        if self.uri.is_empty() {
            return Err(Error::Value("identifier.uri"));
        }
        emit.begin(namespace, name)?;
        emit.begin(children, "Identifier")?;
        if let Some(qualifier) = self.qualifier {
            let lexical = match qualifier {
                Qualifier::Uri => "OIDAsURI",
                Qualifier::Urn => "OIDAsURN",
            };
            emit.event(Event::Attribute(
                attr("Qualifier"),
                Value {
                    lexical,
                    datatype: Datatype::String,
                },
            ))?;
        }
        emit.event(Event::Text(Value {
            lexical: self.uri,
            datatype: Datatype::AnyUri,
        }))?;
        emit.end()?;
        if let Some(description) = self.description {
            emit.text(children, "Description", description)?;
        }
        if !self.documentation.is_empty() {
            emit.begin(children, "DocumentationReferences")?;
            for uri in self.documentation {
                emit.scalar(children, "DocumentationReference", uri, Datatype::AnyUri)?;
            }
            emit.end()?;
        }
        emit.end()
    }
}

/// Complete `DataObjectFormat` for a staged signed-data reference.
#[derive(Clone, Copy, Debug)]
pub struct DataObjectFormat<'a> {
    /// URI addressing the ds:Reference instruction itself.
    pub reference: &'a str,
    /// Human-readable description.
    pub description: Option<&'a str>,
    /// Authoritative identifier of the object's type.
    pub identifier: Option<Identifier<'a>>,
    /// Media type. Required by the baseline profile.
    pub mime_type: Option<&'a str>,
    /// URI identifying the encoding.
    pub encoding: Option<&'a str>,
}

impl DataObjectFormat<'_> {
    /// Write this property into the staged `SignedDataObjectProperties`.
    ///
    /// EN 319 132-1 §5.2.4 requires at least a description, an identifier
    /// or a media type and exact matching to applicable ds:Object attributes.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write<B: PropertyWriter, W: Work>(
        self,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        if self.description.is_none() && self.identifier.is_none() && self.mime_type.is_none() {
            return Err(Error::Value("dataObjectFormat.description"));
        }
        if let Some(value) = self.mime_type {
            super::basic::check_mime(value, work)?;
        }
        let object = reference(writer, self.reference, work)?;
        for (written, original, field) in [
            (
                self.mime_type,
                object.mime_type,
                "dataObjectFormat.mimeType",
            ),
            (self.encoding, object.encoding, "dataObjectFormat.encoding"),
        ] {
            if let (Some(written), Some(original)) = (written, original) {
                work.charge_work(written.len() as u64)
                    .map_err(Error::Resource)?;
                if written != original {
                    return Err(Error::Value(field));
                }
            }
        }
        self.emit(&mut Emit { writer, work })
    }

    pub(super) fn emit<B: Writer, W: Work>(
        self,
        emit: &mut Emit<'_, B, W>,
    ) -> Result<(), Error<B::Error>> {
        self.emit_in(XADES, emit)
    }

    pub(super) fn emit_in<B: Writer, W: Work>(
        self,
        namespace: &'static str,
        emit: &mut Emit<'_, B, W>,
    ) -> Result<(), Error<B::Error>> {
        emit.begin(namespace, "DataObjectFormat")?;
        emit.attribute("ObjectReference", self.reference)?;
        if let Some(value) = self.description {
            emit.text(namespace, "Description", value)?;
        }
        if let Some(identifier) = self.identifier {
            identifier.write_in(namespace, namespace, "ObjectIdentifier", emit)?;
        }
        if let Some(value) = self.mime_type {
            emit.text(namespace, "MimeType", value)?;
        }
        if let Some(value) = self.encoding {
            emit.scalar(namespace, "Encoding", value, Datatype::AnyUri)?;
        }
        emit.end()
    }
}

/// Data objects qualified by one commitment.
#[derive(Clone, Copy, Debug)]
pub enum CommitmentScope<'a> {
    /// All signed data objects.
    All,
    /// Nonempty list of URIs addressing actual ds:Reference instructions.
    References(&'a [&'a str]),
}

/// One `CommitmentTypeIndication` and its optional XML-owned qualifiers.
pub struct Commitment<'a, F> {
    /// Identifier without an OID qualifier, as required by §5.2.3.
    pub identifier: Identifier<'a>,
    /// Selected signed objects.
    pub scope: CommitmentScope<'a>,
    /// `AnyType` contents, in order of emission.
    pub qualifiers: &'a [F],
}

impl<F> Commitment<'_, F> {
    /// Write into the staged `SignedDataObjectProperties`.
    ///
    /// EN 319 132-1 §5.2.3 requires either `AllSignedDataObjects` or a
    /// nonempty set of references, and an unqualified URI identifier.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write<B: PropertyWriter<Fragment = F>, W: Work>(
        &self,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        if self.identifier.qualifier.is_some() {
            return Err(Error::Value("commitment.identifier.qualifier"));
        }
        if let CommitmentScope::References(references) = self.scope {
            if references.is_empty() {
                return Err(Error::Value("commitment.references"));
            }
            for uri in references {
                reference(writer, uri, work)?;
            }
        }
        let mut emit = Emit { writer, work };
        emit.begin(XADES, "CommitmentTypeIndication")?;
        self.identifier
            .write(XADES, "CommitmentTypeId", &mut emit)?;
        match self.scope {
            CommitmentScope::All => {
                emit.begin(XADES, "AllSignedDataObjects")?;
                emit.end()?;
            }
            CommitmentScope::References(references) => {
                for uri in references {
                    emit.scalar(XADES, "ObjectReference", uri, Datatype::AnyUri)?;
                }
            }
        }
        values(
            &mut emit,
            "CommitmentTypeQualifiers",
            "CommitmentTypeQualifier",
            self.qualifiers,
        )?;
        emit.end()
    }
}

/// Recorded production location using the five ordered fields of §5.2.5.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionPlace<'a> {
    /// City.
    pub city: Option<&'a str>,
    /// Street address.
    pub street: Option<&'a str>,
    /// State or province.
    pub state_or_province: Option<&'a str>,
    /// Postal code.
    pub postal_code: Option<&'a str>,
    /// Country name.
    pub country: Option<&'a str>,
}

impl ProductionPlace<'_> {
    /// Write into the staged `SignedSignatureProperties`. An empty place is
    /// forbidden by EN 319 132-1 §5.2.5.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write<B: Writer, W: Work>(
        self,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        let fields = [
            ("City", self.city),
            ("StreetAddress", self.street),
            ("StateOrProvince", self.state_or_province),
            ("PostalCode", self.postal_code),
            ("CountryName", self.country),
        ];
        if fields.iter().all(|(_, value)| value.is_none()) {
            return Err(Error::Value("productionPlace"));
        }
        let mut emit = Emit { writer, work };
        emit.begin(XADES, "SignatureProductionPlaceV2")?;
        for (field, value) in fields {
            if let Some(value) = value {
                emit.text(XADES, field, value)?;
            }
        }
        emit.end()
    }
}

/// One of the two credential syntaxes permitted in `CertifiedRole`.
pub enum CertifiedRole<'a, F> {
    /// Complete original DER attribute certificate with its producing scope.
    X509(RoleCertificate<'a>),
    /// An external XML-owned credential syntax.
    Other(F),
}

/// An original whole DER X.509 attribute certificate suitable for encapsulation.
#[derive(Clone, Copy, Debug)]
pub struct RoleCertificate<'a> {
    bytes: &'a [u8],
    producer: structured_pkix::algorithm::Producer<'a>,
}

/// Original causes from admission of the attribute certificate and its DER spelling.
#[derive(Debug)]
pub enum RoleCertificateError {
    /// Attribute certificate grammar, with original location.
    Certificate(structured_cms::Error),
    /// Original DER header or work refusal.
    Encoding(structured_asn1::Error),
    /// Derivation of the complete DER encoding failed, preserving its original location.
    Der(structured_pkix::Error),
}

impl<'a> RoleCertificate<'a> {
    /// Admit the attribute certificate and its complete DER bytes under its
    /// producing reader. An implicitly tagged CMS certificate is a different
    /// spelling and must first be supplied as an original SEQUENCE.
    pub fn read(parent: &mut structured_asn1::Reader<'a>) -> Result<Self, RoleCertificateError> {
        use structured_asn1::{Encoding, Tag, universal};
        let certificate = structured_cms::attribute_certificate::AttributeCertificate::read(parent)
            .map_err(RoleCertificateError::Certificate)?;
        let element = certificate.element();
        let work = parent.execution();
        let mut reader = work
            .read_scoped_source(
                parent.parser(),
                element.as_bytes(),
                element.span().start,
                Encoding::Der,
                parent.depth(),
            )
            .map_err(RoleCertificateError::Encoding)?;
        let root = reader
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(RoleCertificateError::Encoding)?;
        structured_pkix::der::conforms(&reader, &root, "certifiedRole.attributeCertificate")
            .map_err(RoleCertificateError::Der)?;
        Ok(Self {
            bytes: element.as_bytes(),
            producer: certificate.signature_algorithm().execution_origin(),
        })
    }
}

/// `SignerRoleV2` with independent claim, credential, and assertion groups.
pub struct SignerRole<'a, F> {
    /// `AnyType` contents of the claimed roles.
    pub claimed: &'a [F],
    /// Certified role credentials.
    pub certified: &'a [CertifiedRole<'a, F>],
    /// `AnyType` contents of the third-party signed assertions.
    pub assertions: &'a [F],
}

impl<F> SignerRole<'_, F> {
    /// Write into `SignedSignatureProperties`. Groups appear in schema order
    /// and only when they have at least one member (EN 319 132-1 §5.2.6).
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write<B: PropertyWriter<Fragment = F>, W: Work>(
        &self,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        let mut emit = Emit { writer, work };
        emit.begin(XADES, "SignerRoleV2")?;
        values(&mut emit, "ClaimedRoles", "ClaimedRole", self.claimed)?;
        if !self.certified.is_empty() {
            emit.begin(XADES, "CertifiedRolesV2")?;
            for role in self.certified {
                emit.begin(XADES, "CertifiedRole")?;
                match role {
                    CertifiedRole::X509(certificate) => {
                        let scoped = certificate.producer.execution_in(work);
                        let mut emit = Emit {
                            writer: emit.writer,
                            work: &scoped,
                        };
                        emit.binary(XADES, "X509AttributeCertificate", certificate.bytes)?;
                    }
                    CertifiedRole::Other(value) => {
                        emit.begin(XADES, "OtherAttributeCertificate")?;
                        fragment(&mut emit, FragmentSlot::AnyContent, value)?;
                        emit.end()?;
                    }
                }
                emit.end()?;
            }
            emit.end()?;
        }
        values(
            &mut emit,
            "SignedAssertions",
            "SignedAssertion",
            self.assertions,
        )?;
        emit.end()
    }
}

fn reference<'a, B: PropertyWriter, W: Work>(
    writer: &'a B,
    uri: &str,
    work: &W,
) -> Result<ObjectMetadata<'a>, Error<B::Error>> {
    if uri.is_empty() {
        return Err(Error::Value("dataObject.reference"));
    }
    work.charge_work(1).map_err(Error::Resource)?;
    writer
        .data_reference(uri, work)
        .map_err(Error::Writer)?
        .ok_or(Error::Foreign)
}

pub(super) fn fragment<B: PropertyWriter, W: Work>(
    emit: &mut Emit<'_, B, W>,
    slot: FragmentSlot,
    value: &B::Fragment,
) -> Result<(), Error<B::Error>> {
    emit.work.charge_work(1).map_err(Error::Resource)?;
    emit.writer
        .fragment(slot, value, emit.work)
        .map_err(Error::Writer)
}

fn values<B: PropertyWriter, W: Work>(
    emit: &mut Emit<'_, B, W>,
    group: &'static str,
    item: &'static str,
    entries: &[B::Fragment],
) -> Result<(), Error<B::Error>> {
    if !entries.is_empty() {
        emit.begin(XADES, group)?;
        for entry in entries {
            emit.begin(XADES, item)?;
            fragment(emit, FragmentSlot::AnyContent, entry)?;
            emit.end()?;
        }
        emit.end()?;
    }
    Ok(())
}
