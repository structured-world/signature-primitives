//! Append missing whole validation artifacts through one general container.

use super::{Emit, Error, Work, Writer, XADES};
use crate::timestamp::XADES_141;
use structured_asn1::memory::{Execution, OwnedVec};
use structured_ltv::material::{ArtifactRef, Incorporation};
use structured_pkix::{
    Certificate,
    crl::CertificateList,
    ocsp::{BasicResponse, ResponseBytes},
};

/// Whole artifact encoding placed inside a newly constructed XML property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterialKind {
    /// Complete DER certificate.
    Certificate,
    /// Complete DER `CertificateList`, including a delta when actually used.
    Crl,
    /// Complete successful DER `OCSPResponse` envelope, not only its signed body.
    Ocsp,
}

enum Value<'a, 'source> {
    Certificate(&'a Certificate<'source>),
    Crl(&'a CertificateList<'source>),
    Ocsp(&'a ResponseBytes<'source>),
}

/// Whole original material with its actual producing execution capability.
/// Parsing or construction establishes no status, authority or trust.
pub struct Material<'a, 'source> {
    value: Value<'a, 'source>,
}
impl<'a, 'source> Material<'a, 'source> {
    /// Retain a borrowed original certificate, without copying its DER.
    #[must_use]
    pub const fn certificate(value: &'a Certificate<'source>) -> Self {
        Self {
            value: Value::Certificate(value),
        }
    }
    /// Retain a borrowed original complete or delta CRL.
    #[must_use]
    pub const fn crl(value: &'a CertificateList<'source>) -> Self {
        Self {
            value: Value::Crl(value),
        }
    }
    /// Bind the exact whole envelope to the actual required `BasicOCSPResponse`.
    /// A different envelope/body or unsupported response syntax cannot supply
    /// required material. No parse or signature verification is repeated.
    pub fn ocsp<E, W: Work>(
        value: &'a ResponseBytes<'source>,
        required: &BasicResponse<'_>,
        work: &W,
    ) -> Result<Self, Error<E>> {
        let original = required.signature_algorithm().execution_origin();
        let envelope = value.execution_origin();
        // A joint comparison must preserve both foreign producers as well as
        // every active current ceiling; sequential source rebinding replaces
        // the previous foreign source and cannot establish this invariant.
        original
            .charge_work_with(envelope, work, 20)
            .map_err(Error::Resource)?;
        if value.kind() != structured_pkix::oid::OCSP_BASIC {
            return Err(Error::Value("ocsp.responseType"));
        }
        let bytes = value.payload();
        let expected = required.as_bytes();
        if bytes.len() != expected.len() {
            return Err(Error::Value("ocsp.envelope"));
        }
        original
            .charge_work_with(envelope, work, bytes.len() as u64)
            .map_err(Error::Resource)?;
        if bytes != expected {
            return Err(Error::Value("ocsp.envelope"));
        }
        Ok(Self {
            value: Value::Ocsp(value),
        })
    }
    /// Original wire kind, without decoding or allocation.
    #[must_use]
    pub const fn kind(&self) -> MaterialKind {
        match self.value {
            Value::Certificate(_) => MaterialKind::Certificate,
            Value::Crl(_) => MaterialKind::Crl,
            Value::Ocsp(_) => MaterialKind::Ocsp,
        }
    }
    fn bytes(&self) -> &'source [u8] {
        match self.value {
            Value::Certificate(value) => value.as_bytes(),
            Value::Crl(value) => value.as_bytes(),
            Value::Ocsp(value) => value.as_bytes(),
        }
    }
    fn execution_in<'q, W: Work>(&self, work: &'q W) -> Execution<'q>
    where
        'source: 'q,
    {
        match self.value {
            Value::Certificate(value) => value.execution_in(work),
            Value::Crl(value) => value.execution_in(work),
            Value::Ocsp(value) => value.execution_in(work),
        }
    }
}

/// A complete missing-artifact plan derived from an existing shared census.
/// It owns only accounted handles, never copies DER or retains parser storage.
/// A material plan does not replace conditional placement, credential-specific
/// obligations, static/historical validity or the final B-LT/LTA assessment.
pub struct Materials<'a, 'source> {
    entries: OwnedVec<Material<'a, 'source>>,
}
impl<'a, 'source> Materials<'a, 'source> {
    /// Walk every missing original artifact from the complete incorporation
    /// report. The callback supplies an actual whole OCSP envelope when needed;
    /// its cause is preserved, and a partial plan is dropped on any refusal.
    ///
    /// Rebuild incorporation on the staged generation after writing. Using a
    /// successful subset or asserting completeness cannot satisfy that check.
    pub fn missing<N: Copy, D: Copy, G: Copy, P: Copy, E, W: Work>(
        required: &Incorporation<'a, 'source, N, D, G, P>,
        work: &W,
        mut envelope: impl FnMut(
            &'a BasicResponse<'source>,
            &Execution<'_>,
        ) -> Result<&'a ResponseBytes<'source>, E>,
    ) -> Result<Self, Error<E>> {
        let mut entries = work.vector();
        for entry in required.entries() {
            let artifact = entry.artifact();
            let scoped = artifact.execution_in(work);
            scoped.charge_work(1).map_err(Error::Resource)?;
            if entry.occurrence().is_some() {
                continue;
            }
            let material = match artifact {
                ArtifactRef::Certificate(value) => Material::certificate(value),
                ArtifactRef::Crl(value) => Material::crl(value),
                ArtifactRef::Ocsp(value) => {
                    let original = envelope(value, &scoped).map_err(Error::Writer)?;
                    Material::ocsp(original, value, &scoped)?
                }
            };
            entries.try_push(material).map_err(Error::Resource)?;
        }
        Ok(Self {
            entries: entries.into_owned(),
        })
    }
    /// Every missing artifact in first-encounter order, without filtering.
    #[must_use]
    pub fn entries(&self) -> &[Material<'a, 'source>] {
        &self.entries
    }

    /// Append a new `AnyValidationData` containing missing values only. The
    /// general container may hold root, counter, credential and TSA material,
    /// avoiding mutations of previously archived subtrees. Empty plans emit
    /// nothing, never an empty forbidden `AnyValidationData`.
    /// EN319132-1 §§5.4.6/6.3(x,cc) and §5.5.2.2 require staging missing
    /// validation data before acquiring the next archive timestamp.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
    pub fn write<B: Writer, W: Work>(
        &self,
        writer: &mut B,
        work: &W,
    ) -> Result<(), Error<B::Error>> {
        write_material(&self.entries, writer, work)
    }
}

/// Encode a supplied complete material set as one new general container.
/// This lower-level encoder establishes syntax, never census completeness.
pub fn write_material<B: Writer, W: Work>(
    entries: &[Material<'_, '_>],
    writer: &mut B,
    work: &W,
) -> Result<(), Error<B::Error>> {
    work.charge_work(1).map_err(Error::Resource)?;
    if entries.is_empty() {
        return Ok(());
    }
    let mut emit = Emit { writer, work };
    emit.begin(XADES_141, "AnyValidationData")?;
    let mut certificates = false;
    for value in entries {
        work.charge_work(1).map_err(Error::Resource)?;
        if value.kind() == MaterialKind::Certificate {
            certificates = true;
            break;
        }
    }
    if certificates {
        emit.begin(XADES, "CertificateValues")?;
        for value in entries {
            work.charge_work(1).map_err(Error::Resource)?;
            if value.kind() == MaterialKind::Certificate {
                write_one(value, &mut emit)?;
            }
        }
        emit.end()?;
    }
    let mut crls = false;
    let mut ocsps = false;
    for value in entries {
        work.charge_work(1).map_err(Error::Resource)?;
        match value.kind() {
            MaterialKind::Crl => crls = true,
            MaterialKind::Ocsp => ocsps = true,
            MaterialKind::Certificate => {}
        }
    }
    if crls || ocsps {
        emit.begin(XADES, "RevocationValues")?;
        for (kind, local) in [
            (MaterialKind::Crl, "CRLValues"),
            (MaterialKind::Ocsp, "OCSPValues"),
        ] {
            if (kind == MaterialKind::Crl && !crls) || (kind == MaterialKind::Ocsp && !ocsps) {
                continue;
            }
            emit.begin(XADES, local)?;
            for value in entries {
                work.charge_work(1).map_err(Error::Resource)?;
                if value.kind() == kind {
                    write_one(value, &mut emit)?;
                }
            }
            emit.end()?;
        }
        emit.end()?;
    }
    emit.end()
}
fn write_one<B: Writer, W: Work>(
    value: &Material<'_, '_>,
    emit: &mut Emit<'_, B, W>,
) -> Result<(), Error<B::Error>> {
    let scoped = value.execution_in(emit.work);
    let mut actual = Emit {
        writer: emit.writer,
        work: &scoped,
    };
    let local = match value.kind() {
        MaterialKind::Certificate => "EncapsulatedX509Certificate",
        MaterialKind::Crl => "EncapsulatedCRLValue",
        MaterialKind::Ocsp => "EncapsulatedOCSPValue",
    };
    actual.binary(XADES, local, value.bytes())
}
