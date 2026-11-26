//! Baseline signed-property construction and `XMLDSig` reference instructions.

use super::{
    DS, DataObjectFormat, Datatype, Emit, Error, Event, PolicyWriter, ReferenceWriter,
    SignaturePolicy, Value, Work, Writer, XADES, references::write_issuer_serial,
};
use crate::legacy::Profile;
use structured_pkix::Certificate;

/// One original data-object reference and its required MIME description.
/// `CounterSignature` and `SignedProperties` references are represented separately.
#[derive(Debug, Clone, Copy)]
pub struct DataObject<'a> {
    /// Bare-name reference URI identifying the actual ds:Reference, not its target.
    pub reference: &'a str,
    /// RFC2045 media type of the signed data object.
    pub mime_type: &'a str,
}

/// The reference role the XML signer must install in `SignedInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceKind {
    /// `SignedProperties`, with the `XAdES` reference Type and full coverage.
    SignedProperties,
    /// Parent `SignatureValue`, with the `CountersignedSignature` Type.
    CounterSignature,
}
impl ReferenceKind {
    /// Required Type URI, independent of the XML prefix or ID spelling.
    #[must_use]
    pub const fn type_uri(self) -> &'static str {
        match self {
            Self::SignedProperties => crate::binding::SIGNED_PROPERTIES,
            Self::CounterSignature => "http://uri.etsi.org/01903#CountersignedSignature",
        }
    }
}

/// Explicit reference instructions, not evidence that a signature exists.
#[derive(Debug, Clone, Copy)]
pub struct BasicReferences<'a> {
    /// ID of the new `SignedProperties` to protect, without a leading '#'.
    pub signed_properties: &'a str,
    /// URI of the countersigned `SignatureValue`, absent for an ordinary signature.
    pub counter_signature: Option<&'a str>,
}

/// Minimal interoperable B-B property construction. Optional policy, role,
/// commitment and object timestamps remain composable in the XML draft, and
/// are checked by the existing complete preparation/field/level pipeline.
///
/// The signing certificate is actual parsed DER. `certificate_digest` is the
/// selected provider's digest of its COMPLETE bytes, not SPKI or signed bytes.
/// This input is not a certificate/digest binding receipt; existing certificate
/// checks must independently bind the final signed properties to the selected key.
pub struct Basic<'a, 'certificate> {
    /// URI targeting this Signature by its unique bare-name fragment.
    pub target: &'a str,
    /// ID assigned to the new `SignedProperties` element.
    pub signed_properties_id: &'a str,
    /// Claimed UTC XML Schema dateTime, validated by the XML writer.
    pub signing_time: &'a str,
    /// Actual whole signing certificate.
    pub certificate: &'a Certificate<'certificate>,
    /// XML digest-method URI selected by the native provider.
    pub certificate_digest_method: &'a str,
    /// Complete certificate digest computed by that provider.
    pub certificate_digest: &'a [u8],
    /// Signed data objects excluding `SignedProperties` and the counter target.
    pub objects: &'a [DataObject<'a>],
    /// Actual parent `SignatureValue` URI for a baseline countersignature.
    pub counter_signature: Option<&'a str>,
}

impl Basic<'_, '_> {
    /// Emit `QualifyingProperties` inside the owner's one new ds:Object.
    /// The owner must include `certificate` in KeyInfo/X509Data and install
    /// the returned `SignedInfo` instructions before `XMLDSig` signing.
    ///
    /// EN319132-1 §§4.4.2/5.2.2/5.2.7.2/6.3(a,h–l): direct incorporation,
    /// `SigningTime`, `SigningCertificateV2` without Cert URI/issuer hint, and one
    /// `DataObjectFormat` per ordinary object. A pure countersignature has none.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write<'a, B: Writer, W: Work>(
        &'a self,
        writer: &mut B,
        work: &W,
    ) -> Result<BasicReferences<'a>, Error<B::Error>> {
        self.write_with_properties(
            writer,
            work,
            |_, _| Ok(()),
            |writer, work| self.write_objects(XADES, &mut Emit { writer, work }),
            |_, _| Ok(()),
        )
    }

    /// Compose the mandatory signed properties with additional producers.
    /// The object callback controls all data-object properties and must write
    /// one baseline `DataObjectFormat` per ordinary reference in `self.objects`.
    /// A pure countersignature with no ordinary objects skips that callback.
    /// The unsigned callback owns the optional `UnsignedProperties` wrapper;
    /// no unsigned output is covered by the `SignedProperties` reference.
    pub fn write_with_properties<'a, B: Writer, W: Work>(
        &'a self,
        writer: &mut B,
        work: &W,
        signature: impl FnOnce(&mut B, &W) -> Result<(), Error<B::Error>>,
        objects: impl FnOnce(&mut B, &W) -> Result<(), Error<B::Error>>,
        unsigned: impl FnOnce(&mut B, &W) -> Result<(), Error<B::Error>>,
    ) -> Result<BasicReferences<'a>, Error<B::Error>> {
        self.validate(work)?;
        let mut emit = Emit { writer, work };
        self.begin(XADES, &mut emit)?;
        emit.begin(XADES, "SigningCertificateV2")?;
        self.write_certificate_digest(XADES, DS, &mut emit)?;
        emit.end()?;
        emit.end()?;
        signature(emit.writer, work)?;
        emit.end()?;
        if !self.objects.is_empty() {
            emit.begin(XADES, "SignedDataObjectProperties")?;
            objects(emit.writer, work)?;
            emit.end()?;
        }
        emit.end()?;
        unsigned(emit.writer, work)?;
        emit.end()?;
        Ok(self.references())
    }

    /// Emit the historical certificate and policy vocabulary explicitly.
    /// Install the returned reference using [`Profile::signed_properties_type`].
    /// The original certificate can be included through [`Self::write_key_info`].
    /// V1.1.1 requires a policy choice. Only the pre-EN profile requires
    /// MIME descriptions for every signed data object.
    pub fn write_historical<'a, B: ReferenceWriter + PolicyWriter, W: Work>(
        &'a self,
        profile: Profile,
        policy: Option<&SignaturePolicy<'_, B::Fragment>>,
        writer: &mut B,
        work: &W,
    ) -> Result<BasicReferences<'a>, Error<B::Error>> {
        self.validate(work)?;
        if profile == Profile::V111 && policy.is_none() {
            return Err(Error::Value("signaturePolicy.required"));
        }
        let namespace = profile.namespace();
        let mut emit = Emit { writer, work };
        self.begin(namespace, &mut emit)?;
        emit.begin(namespace, "SigningCertificate")?;
        self.write_certificate_digest(namespace, profile.digest_namespace(), &mut emit)?;
        let scoped = self.certificate.execution_in(work);
        write_issuer_serial(
            &mut Emit {
                writer: emit.writer,
                work: &scoped,
            },
            namespace,
            self.certificate,
        )?;
        emit.end()?;
        emit.end()?;
        if let Some(policy) = policy {
            policy.write_historical(profile, emit.writer, work)?;
        }
        emit.end()?;
        if !self.objects.is_empty() {
            emit.begin(namespace, "SignedDataObjectProperties")?;
            self.write_objects(namespace, &mut emit)?;
            emit.end()?;
        }
        emit.end()?;
        emit.end()?;
        Ok(self.references())
    }

    fn validate<E, W: Work>(&self, work: &W) -> Result<(), Error<E>> {
        work.charge_work(1).map_err(Error::Resource)?;
        if self.target.is_empty()
            || self.signed_properties_id.is_empty()
            || self.signing_time.is_empty()
            || self.certificate_digest_method.is_empty()
            || self.certificate_digest.is_empty()
        {
            return Err(Error::Value("basic.required"));
        }
        if self.counter_signature.is_none() && self.objects.is_empty() {
            return Err(Error::Value("basic.dataObjects"));
        }
        for object in self.objects {
            work.charge_work(1).map_err(Error::Resource)?;
            if object.reference.is_empty() {
                return Err(Error::Value("dataObject.reference"));
            }
            check_mime(object.mime_type, work)?;
        }
        Ok(())
    }

    fn references(&self) -> BasicReferences<'_> {
        BasicReferences {
            signed_properties: self.signed_properties_id,
            counter_signature: self.counter_signature,
        }
    }

    fn begin<B: Writer, W: Work>(
        &self,
        namespace: &'static str,
        emit: &mut Emit<'_, B, W>,
    ) -> Result<(), Error<B::Error>> {
        emit.begin(namespace, "QualifyingProperties")?;
        emit.attribute("Target", self.target)?;
        emit.begin(namespace, "SignedProperties")?;
        emit.attribute("Id", self.signed_properties_id)?;
        emit.begin(namespace, "SignedSignatureProperties")?;
        emit.begin(namespace, "SigningTime")?;
        emit.event(Event::Text(Value {
            lexical: self.signing_time,
            datatype: Datatype::ZonedDateTime,
        }))?;
        emit.end()
    }

    fn write_certificate_digest<B: Writer, W: Work>(
        &self,
        namespace: &'static str,
        digest_namespace: &'static str,
        emit: &mut Emit<'_, B, W>,
    ) -> Result<(), Error<B::Error>> {
        emit.begin(namespace, "Cert")?;
        emit.begin(namespace, "CertDigest")?;
        emit.digest_in(
            digest_namespace,
            self.certificate_digest_method,
            self.certificate_digest,
        )?;
        emit.end()
    }

    fn write_objects<B: Writer, W: Work>(
        &self,
        namespace: &'static str,
        emit: &mut Emit<'_, B, W>,
    ) -> Result<(), Error<B::Error>> {
        for object in self.objects {
            DataObjectFormat {
                reference: object.reference,
                description: None,
                identifier: None,
                mime_type: Some(object.mime_type),
                encoding: None,
            }
            .emit_in(namespace, emit)?;
        }
        Ok(())
    }

    /// Emit the mandatory original signing certificate in one `X509Data`,
    /// inside a new `KeyInfo`. No path discovery, key matching or trust is implied.
    pub fn write_key_info<B: Writer, W: Work>(
        &self,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        let scoped = self.certificate.execution_in(work);
        let mut emit = Emit {
            writer,
            work: &scoped,
        };
        emit.begin(DS, "KeyInfo")?;
        emit.begin(DS, "X509Data")?;
        emit.binary(DS, "X509Certificate", self.certificate.as_bytes())?;
        emit.end()?;
        emit.end()
    }
}

pub(super) fn check_mime<E, W: Work>(value: &str, work: &W) -> Result<(), Error<E>> {
    let mut mime = structured_cms::mime::Syntax::<true>::new();
    if !mime.feed(value, work).map_err(Error::Resource)? || !mime.complete() {
        return Err(Error::Value("dataObject.mimeType"));
    }
    Ok(())
}
