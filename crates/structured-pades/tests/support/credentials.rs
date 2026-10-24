//! Empty original credential sources must never invoke a provider callback.

use core::convert::Infallible;
use structured_cades::{credential, material};

pub struct Empty;
impl<'p, 'd> credential::Provider<'p, 'd> for Empty {
    type Evidence = ();
    type Error = Infallible;
    fn authenticate(
        &self,
        _: credential::Context<'_, '_, 'd>,
    ) -> Result<structured_ltv::credential::Authentication<'p, 'd, ()>, Infallible> {
        panic!("an empty source cannot invoke authentication")
    }
}
impl material::credentials::Provider<()> for Empty {
    type Error = Infallible;
    fn visit<'m, 'd, V>(
        &self,
        _: &credential::Checked<'m, 'd, '_, ()>,
        _: &[material::Open<'d>],
        _: &structured_asn1::ScopedReader<'d, '_>,
        _: impl for<'value, 'source> FnMut(
            material::credentials::Need<'value, 'source, 'm, 'd>,
        ) -> Result<(), V>,
    ) -> Result<material::credentials::Completeness, material::credentials::VisitError<Infallible, V>>
    {
        panic!("an empty source cannot invoke dependency interpretation")
    }
}

/// A small independently signed assertion format used only by native tests.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Case {
    Absent,
    Valid,
    Invalid,
}

pub fn attributes(
    case: Case,
    key: &p256::ecdsa::SigningKey,
) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    use crate::crypto::{attribute, tlv};
    use p256::ecdsa::{Signature, signature::hazmat::PrehashSigner};
    use sha2::{Digest, Sha256};
    if case == Case::Absent {
        return alloc::vec::Vec::new();
    }
    let message = b"original PDF credential assertion";
    let signature: Signature = key.sign_prehash(&Sha256::digest(message)).unwrap();
    let body = [tlv(4, message), tlv(4, signature.to_der().as_bytes())].concat();
    let first = tlv(0x30, &[tlv(6, &[42, 3]), tlv(0x30, &body)].concat());
    let mut second = first.clone();
    if case == Case::Invalid {
        let at = second
            .windows(message.len())
            .position(|bytes| bytes == message)
            .unwrap();
        second[at] ^= 1;
    }
    let roles = tlv(0x30, &tlv(0xa2, &tlv(0x30, &[first, second].concat())));
    alloc::vec![attribute(
        structured_cms::oid::SIGNER_ATTRIBUTES_V2.as_bytes(),
        &roles
    )]
}

#[derive(Debug)]
pub enum Error {
    Source(structured_cades::Error),
    Malformed,
}
impl Error {
    fn asn(cause: structured_asn1::Error) -> Self {
        Self::Source(structured_cades::Error::Encoding {
            field: "assertion",
            cause,
        })
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Source(cause) => write!(output, "{cause:?}"),
            Self::Malformed => output.write_str("malformed assertion"),
        }
    }
}
pub struct Evidence<'p, 'd> {
    pub certificate: &'p structured_pkix::Certificate<'d>,
    pub message: &'d [u8],
}
pub struct Owner<'p, 'd> {
    pub certificate: &'p structured_pkix::Certificate<'d>,
    pub key: p256::ecdsa::VerifyingKey,
    pub authentications: core::cell::Cell<usize>,
    pub visits: core::cell::Cell<usize>,
}
impl<'p, 'd> credential::Provider<'p, 'd> for Owner<'p, 'd> {
    type Evidence = Evidence<'p, 'd>;
    type Error = Error;
    fn authenticate(
        &self,
        context: credential::Context<'_, '_, 'd>,
    ) -> Result<structured_ltv::credential::Authentication<'p, 'd, Self::Evidence>, Error> {
        use p256::ecdsa::{Signature, signature::hazmat::PrehashVerifier};
        use sha2::{Digest, Sha256};
        use structured_asn1::{Tag, universal};
        use structured_ltv::credential::Authentication;
        let value = context.value();
        context.operation().charge(3).map_err(Error::asn)?;
        if value.kind.is_none_or(|kind| kind.as_bytes() != [42, 3]) {
            return Ok(Authentication::Unsupported);
        }
        let source = value.value.ok_or(Error::Malformed)?;
        let work = context.operation().execution();
        let mut reader = source.reader_scoped_in(&work).map_err(Error::Source)?;
        let element = reader
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(Error::asn)?;
        let mut fields = reader.enter(&element).map_err(Error::asn)?;
        let message = fields
            .expect(Tag::primitive(universal::OCTET_STRING))
            .map_err(Error::asn)?;
        let signature = fields
            .expect(Tag::primitive(universal::OCTET_STRING))
            .map_err(Error::asn)?;
        if !reader.is_empty() || !fields.is_empty() {
            return Err(Error::Malformed);
        }
        // Fixed-width P-256 test oracle; all input scanning and arithmetic
        // admission precedes decoding the signature or hashing the message.
        fields
            .charge(100_000 + message.contents().len() as u64 + signature.contents().len() as u64)
            .map_err(Error::asn)?;
        self.authentications.set(self.authentications.get() + 1);
        let Ok(signature) = Signature::from_der(signature.contents()) else {
            return Ok(Authentication::Rejected);
        };
        if self
            .key
            .verify_prehash(&Sha256::digest(message.contents()), &signature)
            .is_err()
        {
            return Ok(Authentication::Rejected);
        }
        Ok(Authentication::Authenticated {
            evidence: Evidence {
                certificate: self.certificate,
                message: message.contents(),
            },
            authorities: structured_ltv::pki::Authorities::CertificateFree,
        })
    }
}
impl<'p, 'd> material::credentials::Provider<Evidence<'p, 'd>> for Owner<'p, 'd> {
    type Error = Error;
    fn visit<'m, 'doc, V>(
        &self,
        checked: &credential::Checked<'m, 'doc, '_, Evidence<'p, 'd>>,
        _: &[material::Open<'doc>],
        _: &structured_asn1::ScopedReader<'doc, '_>,
        mut visitor: impl for<'value, 'source> FnMut(
            material::credentials::Need<'value, 'source, 'm, 'doc>,
        ) -> Result<(), V>,
    ) -> Result<material::credentials::Completeness, material::credentials::VisitError<Error, V>>
    {
        let credential::Outcome::Authentication(
            structured_ltv::credential::Authentication::Authenticated { evidence, .. },
        ) = checked.outcome()
        else {
            panic!("only independently authenticated evidence reaches material interpretation")
        };
        assert_eq!(evidence.message, b"original PDF credential assertion");
        self.visits.set(self.visits.get() + 1);
        visitor(material::credentials::Need::Known(
            structured_ltv::material::ArtifactRef::Certificate(evidence.certificate),
        ))
        .map_err(material::credentials::VisitError::Visitor)?;
        Ok(material::credentials::Completeness::Complete)
    }
}
