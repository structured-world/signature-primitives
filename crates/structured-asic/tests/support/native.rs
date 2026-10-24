//! Trusted DEV fixture writer and real fixed-curve oracle, reused from the
//! existing CMS/LTV integration mechanisms. No production cost qualification.

use std::{vec, vec::Vec};

use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use sha2::{Digest, Sha256};
use std::{cell::Cell, cmp::Ordering, sync::Arc};
use structured_asn1::{
    Encoding, Reader,
    digest::Resolution,
    memory::{Memory, MemoryAccount, MemoryError, Work},
};
use structured_cms::{
    Octets, oid,
    provider::{Prehash, SignatureAnswer, SignatureMode, SignatureProvider},
};
use structured_pkix::{
    AlgorithmIdentifier,
    algorithm::digest::{Algorithm, AsnDigest},
    path::{Verified, Verify, WorkingKey},
};

pub const ECDSA: &[u8] = &[42, 134, 72, 206, 61, 4, 3, 2];
pub const CURVE: &[u8] = &[42, 134, 72, 206, 61, 3, 1, 7];

pub fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(8 << 20, 128 << 20)))
}
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if value.len() < 128 {
        result.push(u8::try_from(value.len()).unwrap());
    } else if let Ok(length) = u8::try_from(value.len()) {
        result.extend([0x81, length]);
    } else {
        result.push(0x82);
        result.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    }
    result.extend(value);
    result
}
pub fn name(common: &str) -> Vec<u8> {
    tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(
                0x30,
                &[
                    tlv(6, structured_pkix::oid::COMMON_NAME.as_bytes()),
                    tlv(12, common.as_bytes()),
                ]
                .concat(),
            ),
        ),
    )
}
pub fn certificate(
    subject: &str,
    issuer: &str,
    key: &SigningKey,
    signer: &SigningKey,
    tsa: bool,
) -> Vec<u8> {
    let algorithm = tlv(0x30, &tlv(6, ECDSA));
    let public = VerifyingKey::from(key).to_sec1_point(false);
    let mut bits = vec![0];
    bits.extend(public.as_bytes());
    let spki = tlv(
        0x30,
        &[
            tlv(
                0x30,
                &[
                    tlv(6, structured_pkix::oid::EC_PUBLIC_KEY.as_bytes()),
                    tlv(6, CURVE),
                ]
                .concat(),
            ),
            tlv(3, &bits),
        ]
        .concat(),
    );
    let mut tbs = vec![0xa0, 3, 2, 1, 2, 2, 1, 7];
    tbs.extend(&algorithm);
    tbs.extend(name(issuer));
    tbs.extend(tlv(
        0x30,
        &[tlv(23, b"250101000000Z"), tlv(23, b"300101000000Z")].concat(),
    ));
    tbs.extend(name(subject));
    tbs.extend(spki);
    let mut extensions = Vec::new();
    if subject == "Root" {
        extensions.extend(tlv(
            0x30,
            &[
                tlv(6, &[85, 29, 15]),
                vec![1, 1, 0xff],
                tlv(4, &[3, 2, 1, 6]),
            ]
            .concat(),
        ));
    }
    if tsa {
        let extension = tlv(
            0x30,
            &[
                tlv(6, &[85, 29, 37]),
                vec![1, 1, 0xff],
                tlv(4, &tlv(0x30, &tlv(6, &[43, 6, 1, 5, 5, 7, 3, 8]))),
            ]
            .concat(),
        );
        extensions.extend(extension);
    }
    if !extensions.is_empty() {
        tbs.extend(tlv(0xa3, &tlv(0x30, &extensions)));
    }
    let tbs = tlv(0x30, &tbs);
    let signature: Signature = signer.sign_prehash(&Sha256::digest(&tbs)).unwrap();
    let mut bits = vec![0];
    bits.extend(signature.to_der().as_bytes());
    tlv(0x30, &[tbs, algorithm, tlv(3, &bits)].concat())
}
pub fn attribute(kind: &[u8], value: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(6, kind), tlv(0x31, value)].concat())
}
pub fn signature_octets(encoded: &[u8]) -> Vec<u8> {
    let parser = structured_asn1::Parser::ber(memory());
    let mut reader = parser.read(encoded, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signer = structured_cms::signer::SignerInfo::read(&reader, &element).unwrap();
    signer
        .signature()
        .pieces()
        .iter()
        .flat_map(|piece| piece.as_bytes())
        .copied()
        .collect()
}
pub fn signer(
    content_type: Option<&[u8]>,
    content: &[u8],
    cert: &[u8],
    key: &SigningKey,
    extra_signed: &[Vec<u8>],
    unsigned: &[Vec<u8>],
) -> Vec<u8> {
    signer_digest(
        content_type,
        content,
        cert,
        key,
        extra_signed,
        unsigned,
        oid::SHA256.as_bytes(),
    )
}
pub fn signer_digest(
    content_type: Option<&[u8]>,
    content: &[u8],
    cert: &[u8],
    key: &SigningKey,
    extra_signed: &[Vec<u8>],
    unsigned: &[Vec<u8>],
    digest: &[u8],
) -> Vec<u8> {
    let mut attributes = vec![
        attribute(
            oid::MESSAGE_DIGEST.as_bytes(),
            &tlv(4, &Sha256::digest(content)),
        ),
        attribute(
            oid::SIGNING_CERTIFICATE_V2.as_bytes(),
            &tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &Sha256::digest(cert))))),
        ),
    ];
    if let Some(kind) = content_type {
        attributes.push(attribute(oid::CONTENT_TYPE.as_bytes(), &tlv(6, kind)));
    }
    attributes.extend_from_slice(extra_signed);
    attributes.sort();
    let set = tlv(0x31, &attributes.concat());
    let signature: Signature = key.sign_prehash(&Sha256::digest(&set)).unwrap();
    let mut fields = vec![2, 1, 1];
    fields.extend(tlv(0x30, &[name("Root"), vec![2, 1, 7]].concat()));
    fields.extend(tlv(0x30, &tlv(6, digest)));
    fields.extend(tlv(0xa0, &attributes.concat()));
    fields.extend(tlv(0x30, &tlv(6, ECDSA)));
    fields.extend(tlv(4, signature.to_der().as_bytes()));
    if !unsigned.is_empty() {
        let mut values = unsigned.to_vec();
        values.sort();
        fields.extend(tlv(0xa1, &values.concat()));
    }
    tlv(0x30, &fields)
}
pub fn message(
    kind: &[u8],
    content: Option<&[u8]>,
    certs: &[Vec<u8>],
    crls: &[Vec<u8>],
    signers: &[Vec<u8>],
) -> Vec<u8> {
    let mut body = vec![2, 1, if kind == oid::DATA.as_bytes() { 1 } else { 3 }];
    body.extend(tlv(0x31, &tlv(0x30, &tlv(6, oid::SHA256.as_bytes()))));
    let mut econtent = tlv(6, kind);
    if let Some(content) = content {
        econtent.extend(tlv(0xa0, &tlv(4, content)));
    }
    body.extend(tlv(0x30, &econtent));
    if !certs.is_empty() {
        let mut certs = certs.to_vec();
        certs.sort();
        body.extend(tlv(0xa0, &certs.concat()));
    }
    if !crls.is_empty() {
        let mut values = crls.to_vec();
        values.sort();
        body.extend(tlv(0xa1, &values.concat()));
    }
    let mut signers = signers.to_vec();
    signers.sort();
    body.extend(tlv(0x31, &signers.concat()));
    tlv(
        0x30,
        &[
            tlv(6, oid::SIGNED_DATA.as_bytes()),
            tlv(0xa0, &tlv(0x30, &body)),
        ]
        .concat(),
    )
}

#[derive(Debug)]
pub enum Fault {
    Resource(MemoryError),
    Pkix(structured_pkix::Error),
    WrongMode,
}
impl std::fmt::Display for Fault {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resource(cause) => cause.fmt(out),
            Self::Pkix(cause) => cause.fmt(out),
            Self::WrongMode => out.write_str("raw input was not selected"),
        }
    }
}
impl From<MemoryError> for Fault {
    fn from(cause: MemoryError) -> Self {
        Self::Resource(cause)
    }
}
pub struct Oracle {
    pub starts: Cell<usize>,
    pub signatures: Cell<usize>,
    pub objects: Cell<usize>,
    pub refuse_xml: bool,
}
impl Oracle {
    pub fn new() -> Self {
        Self {
            starts: Cell::new(0),
            signatures: Cell::new(0),
            objects: Cell::new(0),
            refuse_xml: false,
        }
    }
}
pub struct HashState {
    hash: Sha256,
    position: usize,
    object: bool,
}
impl<'a> structured_asn1::digest::Digest<'a> for Oracle {
    type Identity = ();
    type State = HashState;
    type Output = [u8; 32];
    type Error = Fault;
    fn width(&self, (): &()) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Fault> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&'a self, (): &(), work: &W) -> Result<Resolution<HashState>, Fault> {
        work.charge_work(64)?;
        self.starts.set(self.starts.get() + 1);
        Ok(Resolution::Supported(HashState {
            hash: Sha256::new(),
            position: 0,
            object: true,
        }))
    }
    fn update<W: Work>(&self, state: &mut HashState, bytes: &[u8], work: &W) -> Result<(), Fault> {
        work.charge_work(64 + bytes.len() as u64)?;
        if state.object {
            let remaining = &b"original object"[state.position..];
            if bytes.len() <= remaining.len() && bytes == &remaining[..bytes.len()] {
                state.position += bytes.len();
            } else {
                state.object = false;
            }
        }
        state.hash.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: HashState, work: &W) -> Result<[u8; 32], Fault> {
        work.charge_work(128)?;
        if state.object && state.position == b"original object".len() {
            self.objects.set(self.objects.get() + 1);
        }
        Ok(state.hash.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &[u8; 32],
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Fault> {
        work.charge_work(33)?;
        Ok(output == expected)
    }
}
impl AsnDigest<'_> for Oracle {
    fn identity(&self, algorithm: Algorithm) -> Option<()> {
        (algorithm == Algorithm::Sha256).then_some(())
    }
}
impl<'a> SignatureProvider<'a> for Oracle {
    type SignatureIdentity = ();
    type RawState = ();
    fn resolve_signature(
        &'a self,
        id: AlgorithmIdentifier<'a>,
        (): &(),
        key: WorkingKey<'a>,
        _: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<SignatureMode<()>>, Fault> {
        parent.charge(100).map_err(|cause| {
            Fault::Pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::Encoding(cause.code()),
                "oracle",
                cause.offset(),
            ))
        })?;
        if id.algorithm().as_bytes() != ECDSA {
            return Ok(Resolution::Unsupported);
        }
        if id.parameters().is_some() {
            return Ok(Resolution::Malformed);
        }
        let ec = structured_pkix::key::ec::read(key, &parent.execution()).map_err(Fault::Pkix)?;
        let structured_pkix::key::ec::Curve::Named(curve) = ec.curve() else {
            return Ok(Resolution::Unsupported);
        };
        if curve.as_bytes() != CURVE {
            return Ok(Resolution::Unsupported);
        }
        Ok(Resolution::Supported(SignatureMode::Prehashed(())))
    }
    fn compare_signature<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Fault> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start_raw<W: Work>(
        &'a self,
        (): &(),
        _: WorkingKey<'a>,
        _: &'a Octets<'a>,
        _: &W,
    ) -> Result<(), Fault> {
        Err(Fault::WrongMode)
    }
    fn update_raw<W: Work>(&self, (): &mut (), _: &[u8], _: &W) -> Result<(), Fault> {
        Err(Fault::WrongMode)
    }
    fn finish_raw<W: Work>(&self, (): (), _: &W) -> Result<SignatureAnswer, Fault> {
        Err(Fault::WrongMode)
    }
    fn verify_prehashed<W: Work>(
        &'a self,
        (): &(),
        key: WorkingKey<'a>,
        signature: &Octets<'a>,
        digest: Prehash<'_, '_, Self, ()>,
        work: &W,
    ) -> Result<SignatureAnswer, Fault> {
        work.charge_work(100_000 + signature.len() as u64)?;
        let mut bytes = [0; 72];
        if signature.len() > bytes.len() {
            return Ok(SignatureAnswer::Invalid);
        }
        let mut at = 0;
        for piece in signature.pieces() {
            work.charge_work(1 + piece.as_bytes().len() as u64)?;
            let end = at + piece.as_bytes().len();
            bytes[at..end].copy_from_slice(piece.as_bytes());
            at = end;
        }
        let Some(public) = key.key().key_octets() else {
            return Ok(SignatureAnswer::Invalid);
        };
        let Ok(public) = VerifyingKey::from_sec1_bytes(public) else {
            return Ok(SignatureAnswer::Invalid);
        };
        let Ok(signature) = Signature::from_der(&bytes[..at]) else {
            return Ok(SignatureAnswer::Invalid);
        };
        self.signatures.set(self.signatures.get() + 1);
        Ok(
            if public.verify_prehash(digest.as_bytes(), &signature).is_ok() {
                SignatureAnswer::Valid
            } else {
                SignatureAnswer::Invalid
            },
        )
    }
}
impl<W: Work> Verify<W> for Oracle {
    type Error = Fault;
    fn verify(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        signed: &[u8],
        signature: structured_pkix::signature::SignatureValue<'_>,
        work: &W,
    ) -> Result<Verified, Fault> {
        work.charge_work(100_000 + signed.len() as u64 + signature.as_bytes().len() as u64)?;
        if algorithm.algorithm().as_bytes() != ECDSA {
            return Ok(Verified::Unsupported);
        }
        let Some(public) = key.key().key_octets() else {
            return Ok(Verified::No);
        };
        let Ok(public) = VerifyingKey::from_sec1_bytes(public) else {
            return Ok(Verified::No);
        };
        let Ok(signature) = Signature::from_der(signature.as_bytes()) else {
            return Ok(Verified::No);
        };
        Ok(
            if public
                .verify_prehash(&Sha256::digest(signed), &signature)
                .is_ok()
            {
                Verified::Yes
            } else {
                Verified::No
            },
        )
    }
}
