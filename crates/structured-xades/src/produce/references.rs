//! Complete certificate and revocation reference property construction.

use super::{DS, Emit, Error, Material, MaterialKind, Work, Writer, XADES, material};
use crate::{hashes::HashClass, timestamp::ReferenceSyntax};
use structured_asn1::{
    Integer,
    digest::{Digest, OnceError, Resolution, hash_once},
};
use structured_pkix::{
    Certificate, Name, Time,
    crl::CertificateList,
    ocsp::{BasicResponse, ResponderId, ResponseBytes},
};

/// Role of a preselected set of validation artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceRole {
    /// Material for the signature's certification and revocation paths.
    Signature,
    /// Material for attribute certificates or signed assertion paths.
    AttributeAuthority,
}

/// Render certificate metadata into the current text-only XML element.
/// The shared writer chooses every field and passes its parsed source value.
pub trait ReferenceWriter: Writer {
    /// Render the original distinguished name under `XMLDSig` naming rules.
    fn distinguished_name<W: Work>(&mut self, name: &Name<'_>, work: &W)
    -> Result<(), Self::Error>;
    /// Render the original ASN.1 integer as an XML Schema decimal integer.
    fn integer<W: Work>(&mut self, value: Integer<'_>, work: &W) -> Result<(), Self::Error>;
    /// Render the original absolute instant as an XML Schema dateTime.
    fn datetime<W: Work>(&mut self, value: Time, work: &W) -> Result<(), Self::Error>;
}

/// Borrowed original material and, for OCSP, its related parsed responder.
/// This proves enclosure identity but does not select a path or authenticate it.
pub struct ReferenceArtifact<'a, 'source> {
    material: Material<'a, 'source>,
    basic: Option<&'a BasicResponse<'source>>,
}

impl<'a, 'source> ReferenceArtifact<'a, 'source> {
    /// Complete original certificate used to validate the signer or credential.
    #[must_use]
    pub const fn certificate(certificate: &'a Certificate<'source>) -> Self {
        Self {
            material: Material::certificate(certificate),
            basic: None,
        }
    }

    /// Complete original CRL used to determine an applicable certificate status.
    #[must_use]
    pub const fn crl(crl: &'a CertificateList<'source>) -> Self {
        Self {
            material: Material::crl(crl),
            basic: None,
        }
    }

    /// Use the exact whole envelope containing this already parsed response.
    pub fn ocsp<E, W: Work>(
        envelope: &'a ResponseBytes<'source>,
        basic: &'a BasicResponse<'source>,
        work: &W,
    ) -> Result<Self, Error<E>> {
        Ok(Self {
            material: Material::ocsp(envelope, basic, work)?,
            basic: Some(basic),
        })
    }
}

/// A complete reference set selected under the validated paths and status facts.
/// Ordinary certificate entries exclude the signer's own certificate. The
/// caller provides actual material, including each complete or delta CRL used.
pub struct References<'a, 'source> {
    /// Original or V2 certificate-reference vocabulary.
    pub syntax: ReferenceSyntax,
    /// Certification purpose of the supplied original artifacts.
    pub role: ReferenceRole,
    /// Exact new XML digest URI selected by the caller.
    pub method: &'a str,
    /// Artifacts in first-use order. Entries retain their original execution.
    pub artifacts: &'a [ReferenceArtifact<'a, 'source>],
}

/// Failure to construct references, preserving unrelated callback causes.
#[derive(Debug)]
pub enum ReferenceError<E, P> {
    /// Original XML writing, source or resource refusal.
    Write(Error<E>),
    /// Original digest backend or output-width refusal.
    Digest(OnceError<P>),
    /// Resolved native method was unavailable or malformed.
    Method(Resolution<()>),
    /// The resolved identity has no permitted external digest in this format.
    Prohibited(HashClass),
    /// Original CRL extension processing refusal.
    Pki(structured_pkix::Error),
}

impl<E, P> From<Error<E>> for ReferenceError<E, P> {
    fn from(error: Error<E>) -> Self {
        Self::Write(error)
    }
}

impl References<'_, '_> {
    /// Emit each nonempty property and its groups. The selected provider
    /// resolves exactly the written URI once with the applicable digest
    /// policy. Each artifact is hashed once from its intact original bytes.
    ///
    /// TS 101 903 V1.4.2 §§7.2.2 and 7.4 and EN 319 132-1 Annex A
    /// prescribe the reference field order and whole-artifact digest input.
    /// <https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.02_60/ts_101903v010402p.pdf>
    pub fn write<'p, B: ReferenceWriter, P: Digest<'p>, W: Work>(
        &self,
        writer: &mut B,
        provider: &'p P,
        work: &W,
        resolve: impl FnOnce(&str, &W) -> Result<Resolution<(P::Identity, HashClass)>, P::Error>,
    ) -> Result<(), ReferenceError<B::Error, P::Error>> {
        if self.artifacts.is_empty() {
            return Ok(());
        }
        if self.method.is_empty() {
            return Err(Error::Value("reference.digestMethod").into());
        }
        work.charge_work(1).map_err(Error::Resource)?;
        let (identity, class) = resolved(
            resolve(self.method, work)
                .map_err(|cause| ReferenceError::Digest(OnceError::Provider(cause)))?,
        )?;
        if class == HashClass::Intrinsic
            || (self.syntax == ReferenceSyntax::V2 && class == HashClass::Md5)
        {
            return Err(ReferenceError::Prohibited(class));
        }
        let mut emit = Emit { writer, work };
        let attribute = self.role == ReferenceRole::AttributeAuthority;
        let cert = self.syntax.certificates(attribute);
        let names = [
            (MaterialKind::Certificate, cert.local, "CertRefs"),
            (MaterialKind::Crl, "CRLRefs", "CRLRef"),
            (MaterialKind::Ocsp, "OCSPRefs", "OCSPRef"),
        ];
        let mut revocations = false;
        for (kind, group, member) in names {
            let mut opened = false;
            for artifact in self.artifacts {
                work.charge_work(1).map_err(Error::Resource)?;
                if artifact.material.kind() != kind {
                    continue;
                }
                if !opened {
                    if kind == MaterialKind::Certificate {
                        emit.begin(cert.namespace, group)?;
                        emit.begin(cert.namespace, member)?;
                    } else {
                        if !revocations {
                            let local = if attribute {
                                "AttributeRevocationRefs"
                            } else {
                                "CompleteRevocationRefs"
                            };
                            emit.begin(XADES, local)?;
                            revocations = true;
                        }
                        emit.begin(XADES, group)?;
                    }
                    opened = true;
                }
                write_reference(
                    self.syntax,
                    artifact,
                    self.method,
                    provider,
                    &identity,
                    &mut emit,
                )?;
            }
            if opened {
                emit.end()?;
                if kind == MaterialKind::Certificate {
                    emit.end()?;
                }
            }
        }
        if revocations {
            emit.end()?;
        }
        Ok(())
    }
}

fn resolved<T, E, P>(value: Resolution<T>) -> Result<T, ReferenceError<E, P>> {
    match value {
        Resolution::Supported(value) => Ok(value),
        Resolution::Unsupported => Err(ReferenceError::Method(Resolution::Unsupported)),
        Resolution::Malformed => Err(ReferenceError::Method(Resolution::Malformed)),
    }
}

fn write_reference<'p, B: ReferenceWriter, P: Digest<'p>, W: Work>(
    syntax: ReferenceSyntax,
    artifact: &ReferenceArtifact<'_, '_>,
    method: &str,
    provider: &'p P,
    identity: &P::Identity,
    outer: &mut Emit<'_, B, W>,
) -> Result<(), ReferenceError<B::Error, P::Error>> {
    let material = &artifact.material;
    let work = material.execution_in(outer.work);
    work.charge_work(1).map_err(Error::Resource)?;
    let output = resolved(
        hash_once(provider, identity, material.bytes(), &work).map_err(ReferenceError::Digest)?,
    )?;
    let output = output.as_ref();
    if output.is_empty() {
        return Err(Error::Value("reference.digestValue").into());
    }
    let mut emit = Emit {
        writer: outer.writer,
        work: &work,
    };
    match material.value {
        material::Value::Certificate(cert) => {
            emit.begin(XADES, "Cert")?;
            write_digest(&mut emit, "CertDigest", method, output)?;
            if syntax == ReferenceSyntax::Original {
                write_issuer_serial(&mut emit, XADES, cert)?;
            }
        }
        material::Value::Crl(crl) => {
            emit.begin(XADES, "CRLRef")?;
            write_digest(&mut emit, "DigestAlgAndValue", method, output)?;
            emit.begin(XADES, "CRLIdentifier")?;
            text(&mut emit, XADES, "Issuer", |writer, work| {
                writer.distinguished_name(crl.tbs().issuer(), work)
            })?;
            text(&mut emit, XADES, "IssueTime", |writer, work| {
                writer.datetime(crl.tbs().this_update(), work)
            })?;
            if let Some(number) = crl.tbs().number(&work).map_err(ReferenceError::Pki)? {
                text(&mut emit, XADES, "Number", |writer, work| {
                    writer.integer(number, work)
                })?;
            }
            emit.end()?;
        }
        material::Value::Ocsp(_) => {
            let basic = artifact
                .basic
                .ok_or(Error::Value("reference.ocspEnvelope"))?;
            let scoped = basic.execution_in(&work);
            let mut emit = Emit {
                writer: emit.writer,
                work: &scoped,
            };
            emit.begin(XADES, "OCSPRef")?;
            emit.begin(XADES, "OCSPIdentifier")?;
            emit.begin(XADES, "ResponderID")?;
            match basic.responder() {
                ResponderId::Name(name) => text(&mut emit, XADES, "ByName", |writer, work| {
                    writer.distinguished_name(name, work)
                })?,
                ResponderId::KeyHash(hash) => {
                    // TS 101 903 V1.4.2 §7.4.2 and EN 319 132-1 A.1.2 use
                    // the complete DER byKey field. Its parsed SHA-1 is 20 bytes.
                    let mut field = [0; 24];
                    field[..4].copy_from_slice(&[0xa2, 22, 4, 20]);
                    scoped.charge_work(24).map_err(Error::Resource)?;
                    field[4..].copy_from_slice(hash);
                    emit.binary(XADES, "ByKey", &field)?;
                }
            }
            emit.end()?;
            text(&mut emit, XADES, "ProducedAt", |writer, work| {
                writer.datetime(basic.produced_at(), work)
            })?;
            emit.end()?;
            write_digest(&mut emit, "DigestAlgAndValue", method, output)?;
            emit.end()?;
            return Ok(());
        }
    }
    emit.end()?;
    Ok(())
}

pub(super) fn write_issuer_serial<B: ReferenceWriter, W: Work>(
    emit: &mut Emit<'_, B, W>,
    namespace: &'static str,
    cert: &Certificate<'_>,
) -> Result<(), Error<B::Error>> {
    emit.begin(namespace, "IssuerSerial")?;
    text(emit, DS, "X509IssuerName", |writer, work| {
        writer.distinguished_name(cert.tbs().issuer(), work)
    })?;
    text(emit, DS, "X509SerialNumber", |writer, work| {
        writer.integer(cert.tbs().serial(), work)
    })?;
    emit.end()
}

fn text<B: ReferenceWriter, W: Work>(
    emit: &mut Emit<'_, B, W>,
    namespace: &'static str,
    local: &'static str,
    render: impl FnOnce(&mut B, &W) -> Result<(), B::Error>,
) -> Result<(), Error<B::Error>> {
    emit.begin(namespace, local)?;
    emit.work.charge_work(1).map_err(Error::Resource)?;
    render(emit.writer, emit.work).map_err(Error::Writer)?;
    emit.end()
}

fn write_digest<B: Writer, W: Work>(
    emit: &mut Emit<'_, B, W>,
    local: &'static str,
    method: &str,
    digest: &[u8],
) -> Result<(), Error<B::Error>> {
    emit.begin(XADES, local)?;
    emit.digest(method, digest)?;
    emit.end()
}
