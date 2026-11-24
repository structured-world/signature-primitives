use super::{Prepared, SignerCertificate};
use crate::binary::{self, BinaryXml, Location};
use crate::certificate::{self, Agreement, CertificateXml, DigestProvider, KeyAssociation};
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::memory::Work;
use structured_pkix::{Certificate, path::EffectiveKey};

/// Original V1 certificate identifications. Their issuer hint is an XML
/// `IssuerSerial` element, with issuer-name and serial-number children.
pub struct SigningReferences<X: Xml>(pub(super) certificate::Catalogue<X>);

impl<X: Xml> SigningReferences<X> {
    /// Originals in source order, without assigning the signer to ordinal zero.
    #[must_use]
    pub fn entries(&self) -> &[certificate::Reference<X::Id>] {
        self.0.entries()
    }
}

/// A candidate's association to the original signing-certificate protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateMatch<N> {
    /// A signed reference digest matched the complete candidate encoding.
    Digest(N),
    /// The authenticated `KeyInfo` contains the complete candidate encoding.
    Embedded(N),
    /// All inspected claims could be compared and none matched.
    Differs,
    /// One or more digest claims could not be evaluated.
    Unchecked,
}

/// Independent certificate and verified-key facts for a legacy candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerCheck<N> {
    /// Candidate's association to the actual selected XML verification key.
    pub key: KeyAssociation,
    /// How the original signature protected the candidate's encoding.
    pub certificate: CertificateMatch<N>,
}

/// Located XML, binary-value or digest processing failure.
#[derive(Debug)]
pub enum SignerError<E, P, N, D, G> {
    /// The original selected key query or XML source refused.
    Access(AccessError<E, N>),
    /// The original embedded certificate cannot be read or compared.
    Embedded(binary::Error<E, structured_asn1::memory::MemoryError, N, D, G>),
    /// Original certificate digest acquisition or verification failed.
    Digest(binary::Error<E, certificate::DigestError<P>, N, D, G>),
}

/// Signer check preserving the XML adapter and digest provider causes.
pub type SignerResult<X, P> = Result<
    SignerCheck<<X as Xml>::Id>,
    SignerError<<X as Xml>::Error, P, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
>;

/// Check coverage of the candidate certificate and its actual verification key.
///
/// TS 101 903 V1.2.2 §7.2.2 says the signing certificate is identified in the
/// sequence. The signer may match any entry. Trust and the consistency of XML
/// issuer-name and serial claims remain separate.
pub fn check_signer<'p, X: BinaryXml + CertificateXml, P: DigestProvider<'p, X>, W: Work>(
    xml: &X,
    prepared: &Prepared<X>,
    candidate: &Certificate<'_>,
    key: EffectiveKey<'_>,
    provider: &'p P,
    current: &W,
) -> SignerResult<X, P::Error> {
    let layout = prepared.bound.containers();
    let work = candidate.execution_in(current);
    let access = Access::new(xml, layout.snapshot(), &work);
    let key = access
        .query(layout.signature(), |xml, snapshot, work| {
            xml.key_association(snapshot, layout.signature(), candidate, key, work)
        })
        .map_err(SignerError::Access)?;
    let certificate = match &prepared.signer {
        SignerCertificate::References(reference) => {
            let mut result = CertificateMatch::Differs;
            for (index, entry) in reference.0.entries().iter().enumerate() {
                let answer = certificate::compare_in::<false, X, P, _>(
                    xml,
                    &reference.0,
                    index,
                    candidate,
                    provider,
                    &work,
                )
                .map_err(SignerError::Digest)?;
                match answer {
                    Agreement::Matches => {
                        result = CertificateMatch::Digest(entry.node());
                        break;
                    }
                    Agreement::Differs => {}
                    _ => result = CertificateMatch::Unchecked,
                }
            }
            result
        }
        SignerCertificate::KeyInfo { certificates, .. } => {
            let mut result = CertificateMatch::Differs;
            for &node in certificates {
                let equal = binary::with_octets(
                    xml,
                    Location {
                        snapshot: layout.snapshot(),
                        node,
                    },
                    &work,
                    |bytes| {
                        let candidate = candidate.as_bytes();
                        if bytes.len() != candidate.len() {
                            return Ok(false);
                        }
                        work.charge_work(bytes.len() as u64)?;
                        Ok(bytes == candidate)
                    },
                )
                .map_err(SignerError::Embedded)?;
                if equal {
                    result = CertificateMatch::Embedded(node);
                    break;
                }
            }
            result
        }
    };
    Ok(SignerCheck { key, certificate })
}
