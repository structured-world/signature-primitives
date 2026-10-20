//! Synthetic RFC3161 fixture with actual fixed-curve arithmetic, not a runtime
//! provider or independent XML canonicalization/conformance corpus.

use core::{cell::Cell, cmp::Ordering};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use sha2::{Digest, Sha256};
use structured_asn1::digest::Resolution;
use structured_asn1::{
    Encoding, Reader,
    memory::{MemoryError, Work},
};
use structured_cms::{
    Octets, oid,
    provider::{Prehash, SignatureAnswer, SignatureMode, SignatureProvider},
};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
use structured_pkix::{AlgorithmIdentifier, path::WorkingKey};

const SHA256: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];
const ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2];
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1];
const CURVE: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];

#[derive(Debug)]
pub enum Failure {
    Resource(MemoryError),
    Mode,
}

impl core::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Resource(cause) => cause.fmt(formatter),
            Self::Mode => formatter.write_str("fixture requires finalized SHA256 and P256"),
        }
    }
}

impl From<MemoryError> for Failure {
    fn from(value: MemoryError) -> Self {
        Self::Resource(value)
    }
}

pub struct Oracle {
    key: VerifyingKey,
    public: [u8; 65],
    pub verified: Cell<usize>,
}

impl<'a> structured_asn1::digest::Digest<'a> for Oracle {
    type Identity = ();
    type State = Sha256;
    type Output = [u8; 32];
    type Error = Failure;
    fn width(&self, (): &()) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&'a self, (): &(), work: &W) -> Result<Resolution<Sha256>, Failure> {
        work.charge_work(64)?;
        Ok(Resolution::Supported(Sha256::new()))
    }
    fn update<W: Work>(&self, state: &mut Sha256, bytes: &[u8], work: &W) -> Result<(), Failure> {
        work.charge_work(bytes.len() as u64 + 64)?;
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, work: &W) -> Result<[u8; 32], Failure> {
        work.charge_work(128)?;
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &[u8; 32],
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        work.charge_work(32)?;
        Ok(output.as_slice() == expected)
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
        algorithm: AlgorithmIdentifier<'a>,
        (): &(),
        key: WorkingKey<'a>,
        _encoding: Encoding,
        reader: &Reader<'a>,
    ) -> Result<Resolution<SignatureMode<()>>, Failure> {
        reader.execution().charge_work(200)?;
        if algorithm.algorithm().as_bytes() != ECDSA
            || key.key().algorithm().algorithm().as_bytes() != EC
        {
            return Ok(Resolution::Unsupported);
        }
        // Fixed DER fixture parameters, compared without a foreign-session read
        // or a replacement Parser. This is not a generic EC key decoder.
        if algorithm.parameters().is_some()
            || key.parameters() != Some(&[6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7][..])
            || key.key().key_octets() != Some(self.public.as_slice())
        {
            return Ok(Resolution::Malformed);
        }
        Ok(Resolution::Supported(SignatureMode::Prehashed(())))
    }
    fn compare_signature<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start_raw<W: Work>(
        &'a self,
        (): &(),
        _key: WorkingKey<'a>,
        _signature: &'a Octets<'a>,
        _work: &W,
    ) -> Result<(), Failure> {
        Err(Failure::Mode)
    }
    fn update_raw<W: Work>(&self, (): &mut (), _bytes: &[u8], _work: &W) -> Result<(), Failure> {
        Err(Failure::Mode)
    }
    fn finish_raw<W: Work>(&self, (): (), _work: &W) -> Result<SignatureAnswer, Failure> {
        Err(Failure::Mode)
    }
    fn verify_prehashed<W: Work>(
        &'a self,
        (): &(),
        _key: WorkingKey<'a>,
        signature: &Octets<'a>,
        digest: Prehash<'_, '_, Self, ()>,
        work: &W,
    ) -> Result<SignatureAnswer, Failure> {
        // Test-only conservative admission; no production cost-model claim.
        work.charge_work(100_000 + signature.len() as u64)?;
        let signature = Signature::from_der(signature.as_one().ok_or(Failure::Mode)?)
            .map_err(|_| Failure::Mode)?;
        self.verified.set(self.verified.get() + 1);
        Ok(
            if self
                .key
                .verify_prehash(digest.as_bytes(), &signature)
                .is_ok()
            {
                SignatureAnswer::Valid
            } else {
                SignatureAnswer::Invalid
            },
        )
    }
}

/// Synthetic DER framing shared by test-only timestamp/material builders.
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut value = vec![tag];
    if contents.len() < 128 {
        value.push(u8::try_from(contents.len()).unwrap());
    } else if let Ok(length) = u8::try_from(contents.len()) {
        value.extend([0x81, length]);
    } else {
        let length = u16::try_from(contents.len()).unwrap().to_be_bytes();
        value.extend([0x82, length[0], length[1]]);
    }
    value.extend(contents);
    value
}

/// Generates test data only; no production signing API is introduced.
pub fn fixture(covered: &[u8]) -> (Oracle, Vec<u8>, Vec<u8>) {
    fixture_carriage(covered, false, None, true, None)
}

/// Generates a token carrying its exact selected TSA certificate as well.
pub fn fixture_with_certificate(covered: &[u8]) -> (Oracle, Vec<u8>, Vec<u8>) {
    fixture_carriage(covered, true, None, true, None)
}

/// A real issuer-to-TSA chain, rather than treating a self-signed TSA as a path.
pub fn fixture_with_root(covered: &[u8]) -> (Oracle, Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let (provider, token, tsa) = fixture_carriage(covered, true, Some(&root), true, None);
    let root = certificate_bytes(
        &root,
        &root,
        b"Synthetic XAdES Root",
        b"Synthetic XAdES Root",
        true,
    );
    (provider, token, tsa, root)
}

/// The same signed certificate inputs without constructing an unused CMS token.
pub fn certificate_pair() -> (Vec<u8>, Vec<u8>) {
    let root = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let leaf = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    (
        certificate_bytes(
            &leaf,
            &root,
            b"Synthetic XAdES TSA",
            b"Synthetic XAdES Root",
            false,
        ),
        certificate_bytes(
            &root,
            &root,
            b"Synthetic XAdES Root",
            b"Synthetic XAdES Root",
            true,
        ),
    )
}

/// Genuine nonce-bound request/response with legally omitted accuracy.
pub fn fixture_unstated_accuracy(covered: &[u8]) -> (Oracle, Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let (provider, token, tsa) = fixture_carriage(covered, true, Some(&root), false, Some(7));
    let request = tlv(
        0x30,
        &[
            tlv(2, &[1]),
            message_imprint(covered),
            tlv(2, &[7]),
            tlv(1, &[0xff]),
        ]
        .concat(),
    );
    (provider, token, tsa, request)
}

fn message_imprint(covered: &[u8]) -> Vec<u8> {
    tlv(
        0x30,
        &[tlv(0x30, &tlv(6, SHA256)), tlv(4, &Sha256::digest(covered))].concat(),
    )
}

/// Same issuer name and serial but a different actual public key.
pub fn other_issuer() -> Vec<u8> {
    let key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    certificate_bytes(
        &key,
        &key,
        b"Synthetic XAdES Root",
        b"Synthetic XAdES Root",
        true,
    )
}

fn certificate_bytes(
    signing: &SigningKey,
    issuer: &SigningKey,
    subject: &[u8],
    issuer_name: &[u8],
    ca: bool,
) -> Vec<u8> {
    certificate_bytes_serial(
        signing,
        issuer,
        subject,
        issuer_name,
        ca,
        1,
        LeafPurpose::Timestamp,
    )
}

/// CRL signing key5 certified either by the target's root2 or unrelated root4.
/// Both paths and CRL signatures are mathematically valid; only root2 provides
/// the required same-anchor relation. The issuer certificate is not the anchor.
pub fn crl_authority(root_seed: u8) -> (Vec<u8>, Vec<u8>) {
    let (certificate, root) = crl_authority_parts(root_seed, true);
    (certificate, root.unwrap())
}

/// Same actual authority certificate when the original root already exists.
pub fn crl_authority_certificate(root_seed: u8) -> Vec<u8> {
    crl_authority_parts(root_seed, false).0
}

/// Reuse the original root2 bytes, generating an alternate root only when the
/// mismatch case actually needs it. Both are still parsed/verified normally.
pub fn crl_authority_with_root(
    root_seed: u8,
    original: &[u8],
) -> (Vec<u8>, std::borrow::Cow<'_, [u8]>) {
    if root_seed == 2 {
        return (
            crl_authority_certificate(root_seed),
            std::borrow::Cow::Borrowed(original),
        );
    }
    let (certificate, root) = crl_authority(root_seed);
    (certificate, std::borrow::Cow::Owned(root))
}

fn crl_authority_parts(root_seed: u8, include_root: bool) -> (Vec<u8>, Option<Vec<u8>>) {
    let root = SigningKey::from_bytes((&[root_seed; 32]).into()).unwrap();
    let signing = SigningKey::from_bytes((&[5; 32]).into()).unwrap();
    let root_name: &[u8] = if root_seed == 2 {
        b"Synthetic XAdES Root"
    } else {
        b"Other XAdES Root"
    };
    (
        certificate_bytes_serial(
            &signing,
            &root,
            b"Synthetic XAdES Root",
            root_name,
            true,
            9,
            LeafPurpose::Timestamp,
        ),
        if include_root {
            Some(certificate_bytes(&root, &root, root_name, root_name, true))
        } else {
            None
        },
    )
}

/// Direct OCSP delegate key5, with its actual issuing root and explicit purpose.
pub fn ocsp_delegate(root_seed: u8) -> (Vec<u8>, Vec<u8>) {
    ocsp_delegate_with_no_check(root_seed, false)
}

/// Same actual delegate with the common NULL-valued noCheck extension.
pub fn ocsp_delegate_no_check(root_seed: u8) -> (Vec<u8>, Vec<u8>) {
    ocsp_delegate_with_no_check(root_seed, true)
}

fn ocsp_delegate_with_no_check(root_seed: u8, no_check: bool) -> (Vec<u8>, Vec<u8>) {
    let root = SigningKey::from_bytes((&[root_seed; 32]).into()).unwrap();
    let signer = SigningKey::from_bytes((&[5; 32]).into()).unwrap();
    let name: &[u8] = if root_seed == 2 {
        b"Synthetic XAdES Root"
    } else {
        b"Other XAdES Root"
    };
    (
        certificate_bytes_serial(
            &signer,
            &root,
            b"Synthetic XAdES Root",
            name,
            false,
            9,
            LeafPurpose::Ocsp { no_check },
        ),
        certificate_bytes(&root, &root, name, name, true),
    )
}

#[derive(Clone, Copy)]
enum LeafPurpose {
    Timestamp,
    Ocsp { no_check: bool },
}

fn certificate_bytes_serial(
    signing: &SigningKey,
    issuer: &SigningKey,
    subject: &[u8],
    issuer_name: &[u8],
    ca: bool,
    serial: u8,
    purpose: LeafPurpose,
) -> Vec<u8> {
    let name = |value: &[u8]| {
        tlv(
            0x30,
            &tlv(
                0x31,
                &tlv(0x30, &[tlv(6, &[0x55, 4, 3]), tlv(12, value)].concat()),
            ),
        )
    };
    let public = VerifyingKey::from(signing).to_sec1_point(false);
    let signature_algorithm = tlv(0x30, &tlv(6, ECDSA));
    let mut validity = tlv(0x17, b"250101000000Z");
    validity.extend(tlv(0x17, b"300101000000Z"));
    let mut key_algorithm = tlv(6, EC);
    key_algorithm.extend(tlv(6, CURVE));
    let mut spki = tlv(0x30, &key_algorithm);
    let mut bits = vec![0];
    bits.extend(public.as_bytes());
    spki.extend(tlv(3, &bits));
    let mut identifier = tlv(6, structured_pkix::oid::SUBJECT_KEY_IDENTIFIER.as_bytes());
    identifier.extend(tlv(4, &tlv(4, &[7])));
    let mut extensions = tlv(0x30, &identifier);
    if ca {
        let mut basic = tlv(6, structured_pkix::oid::BASIC_CONSTRAINTS.as_bytes());
        basic.extend([1, 1, 0xff]);
        basic.extend(tlv(4, &[0x30, 3, 1, 1, 0xff]));
        extensions.extend(tlv(0x30, &basic));
        // RFC10007 §4 requires cRLSign on a version3 CRL issuer; this
        // fixture also permits its actual certificate and OCSP signing uses.
        extensions.extend(tlv(
            0x30,
            &[
                tlv(6, structured_pkix::oid::KEY_USAGE.as_bytes()),
                tlv(1, &[0xff]),
                tlv(4, &[3, 2, 1, 0x86]),
            ]
            .concat(),
        ));
    } else {
        let kind = match purpose {
            LeafPurpose::Timestamp => structured_pkix::oid::TIME_STAMPING,
            LeafPurpose::Ocsp { .. } => structured_pkix::oid::OCSP_SIGNING,
        };
        let mut eku = tlv(6, structured_pkix::oid::EXT_KEY_USAGE.as_bytes());
        eku.extend([1, 1, 0xff]);
        eku.extend(tlv(4, &tlv(0x30, &tlv(6, kind.as_bytes()))));
        extensions.extend(tlv(0x30, &eku));
        if matches!(purpose, LeafPurpose::Ocsp { no_check: true }) {
            extensions.extend(tlv(
                0x30,
                &[
                    tlv(6, structured_pkix::oid::OCSP_NO_CHECK.as_bytes()),
                    tlv(4, &[5, 0]),
                ]
                .concat(),
            ));
        }
    }
    let mut tbs = vec![0xa0, 3, 2, 1, 2, 2, 1, serial];
    tbs.extend(&signature_algorithm);
    tbs.extend(name(issuer_name));
    tbs.extend(tlv(0x30, &validity));
    tbs.extend(name(subject));
    tbs.extend(tlv(0x30, &spki));
    tbs.extend(tlv(0xa3, &tlv(0x30, &extensions)));
    let tbs = tlv(0x30, &tbs);
    let signature: Signature = issuer.sign_prehash(&Sha256::digest(&tbs)).unwrap();
    let mut certificate = tbs;
    certificate.extend(signature_algorithm);
    let mut bits = vec![0];
    bits.extend(signature.to_der().as_bytes());
    certificate.extend(tlv(3, &bits));
    tlv(0x30, &certificate)
}

/// Test-only fixed P256 issuer verification; no runtime backend/cost guarantee.
pub struct PathOracle {
    pub calls: Cell<usize>,
}

/// Empty complete/delta CRLs actually signed by `fixture_with_root`'s issuer.
pub fn crl_pair() -> (Vec<u8>, Vec<u8>) {
    crl_pair_for(2)
}

/// Same original CRL schema, signed by an explicit synthetic authority key.
pub fn crl_pair_for(seed: u8) -> (Vec<u8>, Vec<u8>) {
    crl_pair_scope(seed, [None, None], true)
}

/// Independent complete/delta pair using the same signed wire fixture kernel.
pub fn crl_pair_number(seed: u8, base: u8) -> (Vec<u8>, Vec<u8>) {
    let signed = crl_writer(seed);
    (
        signed(base, false, None, None),
        signed(base.checked_add(1).unwrap(), true, None, None),
    )
}

/// One original complete list without generating/signing an unused delta.
pub fn complete_crl_for(seed: u8) -> Vec<u8> {
    crl_writer(seed)(1, false, None, None)
}

/// Distinct actual complete CRL for an independently used credential CA path.
/// Reuses the same signed wire fixture; no private revocation evaluator.
pub fn complete_crl_number(seed: u8, number: u8) -> Vec<u8> {
    crl_writer(seed)(number, false, None, None)
}

/// Same complete-list kernel with one actual revoked serial and signed bytes.
pub fn revoking_crl_for(seed: u8, serial: u8) -> Vec<u8> {
    crl_writer(seed)(1, false, None, Some(serial))
}

/// Two separately signed complete CRLs whose reason partitions jointly cover
/// all eight reasons. Neither alone can establish complete absence.
pub fn crl_reason_partitions(seed: u8) -> (Vec<u8>, Vec<u8>) {
    crl_pair_scope(seed, [Some(&[3, 0x78]), Some(&[7, 7, 0x80])], false)
}

fn crl_pair_scope(seed: u8, reasons: [Option<&[u8]>; 2], delta: bool) -> (Vec<u8>, Vec<u8>) {
    let signed = crl_writer(seed);
    (
        signed(1, false, reasons[0], None),
        signed(if delta { 2 } else { 1 }, delta, reasons[1], None),
    )
}

fn crl_writer(seed: u8) -> impl Fn(u8, bool, Option<&[u8]>, Option<u8>) -> Vec<u8> {
    let root = SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
    let algorithm = tlv(0x30, &tlv(6, ECDSA));
    let name = tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(
                0x30,
                &[tlv(6, &[0x55, 4, 3]), tlv(12, b"Synthetic XAdES Root")].concat(),
            ),
        ),
    );
    move |number: u8, delta: bool, reasons: Option<&[u8]>, revoked: Option<u8>| {
        let mut fields = tlv(2, &[1]);
        fields.extend(&algorithm);
        fields.extend(&name);
        fields.extend(tlv(0x17, b"250101000000Z"));
        fields.extend(tlv(0x17, b"300101000000Z"));
        if let Some(serial) = revoked {
            fields.extend(tlv(
                0x30,
                &tlv(
                    0x30,
                    &[tlv(2, &[serial]), tlv(0x17, b"250101000000Z")].concat(),
                ),
            ));
        }
        let mut extensions = tlv(
            0x30,
            &[tlv(6, &[0x55, 0x1d, 0x14]), tlv(4, &tlv(2, &[number]))].concat(),
        );
        extensions.extend(tlv(
            0x30,
            &[
                tlv(6, &[0x55, 0x1d, 0x23]),
                tlv(4, &tlv(0x30, &tlv(0x80, &[7]))),
            ]
            .concat(),
        ));
        if let Some(reasons) = reasons {
            extensions.extend(tlv(
                0x30,
                &[
                    tlv(
                        6,
                        structured_pkix::oid::ISSUING_DISTRIBUTION_POINT.as_bytes(),
                    ),
                    tlv(1, &[0xff]),
                    tlv(4, &tlv(0x30, &tlv(0x83, reasons))),
                ]
                .concat(),
            ));
        }
        if delta {
            extensions.extend(tlv(
                0x30,
                &[
                    tlv(6, &[0x55, 0x1d, 0x1b]),
                    tlv(1, &[0xff]),
                    tlv(4, &tlv(2, &[number.checked_sub(1).unwrap()])),
                ]
                .concat(),
            ));
        }
        fields.extend(tlv(0xa0, &tlv(0x30, &extensions)));
        let tbs = tlv(0x30, &fields);
        let signature: Signature = root.sign_prehash(&Sha256::digest(&tbs)).unwrap();
        let mut bits = vec![0];
        bits.extend(signature.to_der().as_bytes());
        tlv(0x30, &[tbs, algorithm.clone(), tlv(3, &bits)].concat())
    }
}

/// Whole successful OCSP envelope, with real issuer signature and SHA256 `CertID`.
pub fn ocsp_response(issuer_seed: u8) -> Vec<u8> {
    ocsp_response_signed(issuer_seed, 2)
}

/// Same response schema and original `CertID`, signed by the selected authority.
pub fn ocsp_response_signed(issuer_seed: u8, signer_seed: u8) -> Vec<u8> {
    ocsp_response_value(issuer_seed, signer_seed, 1)
}

/// Same authenticated schema, identifying the supplied original certificate.
pub fn ocsp_response_for_serial(issuer_seed: u8, serial: u8) -> Vec<u8> {
    ocsp_response_value(issuer_seed, issuer_seed, serial)
}

fn ocsp_response_value(issuer_seed: u8, signer_seed: u8, serial: u8) -> Vec<u8> {
    let root = SigningKey::from_bytes((&[signer_seed; 32]).into()).unwrap();
    let name = tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(
                0x30,
                &[tlv(6, &[0x55, 4, 3]), tlv(12, b"Synthetic XAdES Root")].concat(),
            ),
        ),
    );
    let issuer = SigningKey::from_bytes((&[issuer_seed; 32]).into()).unwrap();
    let public = VerifyingKey::from(&issuer).to_sec1_point(false);
    let id = tlv(
        0x30,
        &[
            tlv(0x30, &tlv(6, SHA256)),
            tlv(4, &Sha256::digest(&name)),
            tlv(4, &Sha256::digest(public.as_bytes())),
            tlv(2, &[serial]),
        ]
        .concat(),
    );
    let single = tlv(
        0x30,
        &[
            id,
            tlv(0x80, &[]),
            tlv(0x18, b"20250101000000Z"),
            tlv(0xa0, &tlv(0x18, b"20300101000000Z")),
        ]
        .concat(),
    );
    let data = tlv(
        0x30,
        &[
            tlv(0xa1, &name),
            tlv(0x18, b"20260101000000Z"),
            tlv(0x30, &single),
        ]
        .concat(),
    );
    let signature: Signature = root.sign_prehash(&Sha256::digest(&data)).unwrap();
    let mut bits = vec![0];
    bits.extend(signature.to_der().as_bytes());
    let basic = tlv(
        0x30,
        &[data, tlv(0x30, &tlv(6, ECDSA)), tlv(3, &bits)].concat(),
    );
    tlv(
        0x30,
        &[
            tlv(10, &[0]),
            tlv(
                0xa0,
                &tlv(
                    0x30,
                    &[tlv(6, &[43, 6, 1, 5, 5, 7, 48, 1, 1]), tlv(4, &basic)].concat(),
                ),
            ),
        ]
        .concat(),
    )
}

// DEV-only fixed SHA256 provider, with no whole-input/output Vec.
impl structured_asn1::digest::Digest<'_> for PathOracle {
    type Identity = ();
    type State = Sha256;
    type Output = [u8; 32];
    type Error = MemoryError;
    fn width(&self, (): &()) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), _: &W) -> Result<Ordering, MemoryError> {
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), work: &W) -> Result<Resolution<Sha256>, MemoryError> {
        work.charge_work(128)?;
        Ok(Resolution::Supported(Sha256::new()))
    }
    fn update<W: Work>(
        &self,
        state: &mut Sha256,
        input: &[u8],
        work: &W,
    ) -> Result<(), MemoryError> {
        work.charge_work(input.len() as u64)?;
        state.update(input);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, _: &W) -> Result<[u8; 32], MemoryError> {
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &[u8; 32],
        expected: &[u8],
        work: &W,
    ) -> Result<bool, MemoryError> {
        work.charge_work(expected.len() as u64)?;
        Ok(output.as_slice() == expected)
    }
}

impl AsnDigest<'_> for PathOracle {
    fn identity(&self, algorithm: Algorithm) -> Option<()> {
        (algorithm == Algorithm::Sha256).then_some(())
    }
}

impl<W: Work> structured_pkix::path::Verify<W> for PathOracle {
    type Error = MemoryError;
    fn verify(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        signed: &[u8],
        signature: structured_pkix::signature::SignatureValue<'_>,
        work: &W,
    ) -> Result<structured_pkix::path::Verified, Self::Error> {
        use structured_pkix::path::Verified;
        work.charge_work(128 + signed.len() as u64 + signature.as_bytes().len() as u64)?;
        self.calls.set(self.calls.get() + 1);
        if algorithm.algorithm().as_bytes() != ECDSA {
            return Ok(Verified::Unsupported);
        }
        let Ok(key) = VerifyingKey::from_sec1_bytes(key.key().key().as_bytes()) else {
            return Ok(Verified::No);
        };
        let Ok(signature) = Signature::from_der(signature.as_bytes()) else {
            return Ok(Verified::No);
        };
        Ok(
            if key
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

fn fixture_carriage(
    covered: &[u8],
    include_certificate: bool,
    issuer: Option<&SigningKey>,
    accuracy: bool,
    nonce: Option<u8>,
) -> (Oracle, Vec<u8>, Vec<u8>) {
    fixture_imprint(
        &message_imprint(covered),
        include_certificate,
        issuer,
        accuracy,
        nonce,
        FixtureDigest::Allowed,
    )
}

/// A real SHA256/P256 CMS signature carrying the RFC1321 A.5 MD5("abc")
/// imprint. This tests baseline refusal before selected-provider resolution;
/// the SHA256-only oracle does not pretend to implement an MD5 provider.
pub fn fixture_md5_imprint() -> (Oracle, Vec<u8>, Vec<u8>) {
    let imprint = tlv(
        0x30,
        &[
            tlv(0x30, &tlv(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 2, 5])),
            tlv(
                4,
                &[
                    0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28,
                    0xe1, 0x7f, 0x72,
                ],
            ),
        ]
        .concat(),
    );
    fixture_imprint(&imprint, false, None, true, None, FixtureDigest::Allowed)
}

/// Signed ESS restrictions with a declared MD5 digest at the selected ordinal.
/// The later restriction is not skipped merely because the first signer hash
/// uses the allowed SHA256 default. No MD5 verification capability is claimed.
pub fn fixture_md5_ess(index: usize) -> (Oracle, Vec<u8>, Vec<u8>) {
    fixture_imprint(
        &message_imprint(b"abc"),
        false,
        None,
        true,
        None,
        FixtureDigest::EssMd5(index),
    )
}

/// MD5-declared signer for format preflight, not a valid MD5 arithmetic oracle.
/// The fixture's actual P256/SHA256 signing stays unchanged: the prohibited
/// declaration must refuse before attempting any provider interpretation.
pub fn fixture_md5_signer() -> (Oracle, Vec<u8>, Vec<u8>) {
    fixture_imprint(
        &message_imprint(b"abc"),
        false,
        None,
        true,
        None,
        FixtureDigest::SignerMd5,
    )
}

/// An unused advertisement is not a digest computation. All actual signer,
/// ESS and imprint hashes remain the same SHA256 identities and octets.
pub fn fixture_unused_md5(covered: &[u8]) -> (Oracle, Vec<u8>, Vec<u8>) {
    fixture_imprint(
        &message_imprint(covered),
        false,
        None,
        true,
        None,
        FixtureDigest::AdvertisedMd5,
    )
}

#[derive(Clone, Copy)]
enum FixtureDigest {
    Allowed,
    SignerMd5,
    EssMd5(usize),
    AdvertisedMd5,
}

fn signing_certificate_attribute(certificate: &[u8], digest: FixtureDigest) -> Vec<u8> {
    // RFC5035 ESSCertIDv2 has SHA256 DEFAULT; X.690 §11.5 omits it in DER.
    let cert_id = tlv(0x30, &tlv(4, &Sha256::digest(certificate)));
    let mut cert_ids = Vec::new();
    if let FixtureDigest::EssMd5(index) = digest {
        for _ in 0..index {
            cert_ids.extend(&cert_id);
        }
        cert_ids.extend(tlv(
            0x30,
            &[
                tlv(0x30, &tlv(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 2, 5])),
                tlv(4, &[0; 16]),
            ]
            .concat(),
        ));
    } else {
        cert_ids.extend(cert_id);
    }
    let mut attribute = tlv(6, oid::SIGNING_CERTIFICATE_V2.as_bytes());
    attribute.extend(tlv(0x31, &tlv(0x30, &tlv(0x30, &cert_ids))));
    attribute
}

fn fixture_imprint(
    imprint: &[u8],
    include_certificate: bool,
    issuer: Option<&SigningKey>,
    accuracy: bool,
    nonce: Option<u8>,
    digest: FixtureDigest,
) -> (Oracle, Vec<u8>, Vec<u8>) {
    let signing = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let key = VerifyingKey::from(&signing);
    let public: [u8; 65] = key.to_sec1_point(false).as_bytes().try_into().unwrap();
    let signature_algorithm = tlv(0x30, &tlv(6, ECDSA));
    let digest_algorithm = tlv(
        0x30,
        &tlv(
            6,
            if matches!(digest, FixtureDigest::SignerMd5) {
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 2, 5]
            } else {
                SHA256
            },
        ),
    );
    let certificate = match issuer {
        Some(root) => certificate_bytes(
            &signing,
            root,
            b"Synthetic XAdES TSA",
            b"Synthetic XAdES Root",
            false,
        ),
        None => certificate_bytes(
            &signing,
            &signing,
            b"Synthetic XAdES TSA",
            b"Synthetic XAdES TSA",
            false,
        ),
    };
    let mut info = vec![2, 1, 1, 6, 1, 43];
    info.extend(imprint);
    info.extend([2, 1, 7]);
    info.extend(tlv(0x18, b"20260101000000Z"));
    if accuracy {
        info.extend([0x30, 0]);
    }
    if let Some(value) = nonce {
        info.extend(tlv(2, &[value]));
    }
    let info = tlv(0x30, &info);
    let mut content_type = tlv(6, oid::CONTENT_TYPE.as_bytes());
    content_type.extend(tlv(0x31, &tlv(6, oid::TST_INFO.as_bytes())));
    let mut message_digest = tlv(6, oid::MESSAGE_DIGEST.as_bytes());
    message_digest.extend(tlv(0x31, &tlv(4, &Sha256::digest(&info))));
    let cert_attribute = signing_certificate_attribute(&certificate, digest);
    let mut attributes = [
        tlv(0x30, &content_type),
        tlv(0x30, &message_digest),
        tlv(0x30, &cert_attribute),
    ];
    attributes.sort();
    let mut attrs = tlv(0x31, &attributes.concat());
    let signature: Signature = signing.sign_prehash(&Sha256::digest(&attrs)).unwrap();
    attrs[0] = 0xa0;
    let mut signer = vec![2, 1, 3, 0x80, 1, 7];
    signer.extend(&digest_algorithm);
    signer.extend(attrs);
    signer.extend(signature_algorithm);
    signer.extend(tlv(4, signature.to_der().as_bytes()));
    let mut content = tlv(6, oid::TST_INFO.as_bytes());
    content.extend(tlv(0xa0, &tlv(4, &info)));
    let mut fields = vec![2, 1, 3];
    if matches!(digest, FixtureDigest::AdvertisedMd5) {
        // Fixed DER order: the shorter MD5 AlgorithmIdentifier sorts first.
        let mut advertised = tlv(0x30, &tlv(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 2, 5]));
        advertised.extend(&digest_algorithm);
        fields.extend(tlv(0x31, &advertised));
    } else {
        fields.extend(tlv(0x31, &digest_algorithm));
    }
    fields.extend(tlv(0x30, &content));
    if include_certificate {
        fields.extend(tlv(0xa0, &certificate));
    }
    fields.extend(tlv(0x31, &tlv(0x30, &signer)));
    let mut envelope = tlv(6, oid::SIGNED_DATA.as_bytes());
    envelope.extend(tlv(0xa0, &tlv(0x30, &fields)));
    (
        Oracle {
            key,
            public,
            verified: Cell::new(0),
        },
        tlv(0x30, &envelope),
        certificate,
    )
}
