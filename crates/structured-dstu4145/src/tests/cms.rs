//! Real hash/kernel composition through the existing selected CMS provider.

use super::accounting::{SIGNATURE_OID, fixture, memory, parser, read, tlv};
use crate::{
    Error,
    accounted::{Failure, HashState, Hashes, Identity, Key},
    gost::{DEFAULT_DKE, Dke},
    hash::{Hash, Output},
};
use core::{cell::Cell, cmp::Ordering, convert::Infallible};
use std::vec::Vec;
use structured_asn1::{
    Encoding, Oid, Reader,
    digest::{Digest, Resolution},
    memory::{MemoryError, Work},
};
use structured_cms::{
    Octets,
    binding::Scope,
    prepare::{self, Part, Preparation, PrepareError},
    provider::{
        Prehash, ProviderSession, SignatureAnswer, SignatureDigestError, SignatureMode,
        SignatureProvider,
    },
    signer::SignerInfo,
};
use structured_pkix::{
    AlgorithmIdentifier, PublicKeyInfo,
    algorithm::{
        digest::{self, Algorithm, AsnDigest},
        dstu4145::{self, Profile},
        signature,
    },
    path::WorkingKey,
};

struct Provider<'a> {
    keys: [(PublicKeyInfo<'a>, Key<'a>); 2],
    calls: Cell<usize>,
    starts: Cell<usize>,
    refuse_on: Cell<usize>,
}

impl<'a> Provider<'a> {
    fn selected<W: Work>(&self, key: WorkingKey<'a>, work: &W) -> Result<&Key<'a>, Failure> {
        key.key()
            .algorithm()
            .execution_origin()
            .charge_work_in(work, 2)
            .map_err(|reason| Failure::Resource {
                reason,
                at: key.key().algorithm().offset(),
            })?;
        for (original, prepared) in &self.keys {
            if core::ptr::eq(original.as_bytes(), key.key().as_bytes()) {
                return Ok(prepared);
            }
        }
        Err(Failure::Backend {
            reason: Error::InvalidKey,
            at: key.key().algorithm().offset(),
        })
    }
}

impl<'a> Digest<'a> for Provider<'a> {
    type Identity = Identity<'a>;
    type State = HashState<'a>;
    type Output = Output;
    type Error = Failure;
    fn width(&self, id: &Self::Identity) -> Option<usize> {
        Hashes.width(id)
    }
    fn compare<W: Work>(
        &self,
        a: &Self::Identity,
        b: &Self::Identity,
        w: &W,
    ) -> Result<Ordering, Failure> {
        Hashes.compare(a, b, w)
    }
    fn start<W: Work>(
        &'a self,
        id: &Self::Identity,
        w: &W,
    ) -> Result<Resolution<Self::State>, Failure> {
        self.starts.set(self.starts.get() + 1);
        Hashes.start(id, w)
    }
    fn update<W: Work>(&self, s: &mut Self::State, b: &[u8], w: &W) -> Result<(), Failure> {
        Hashes.update(s, b, w)
    }
    fn finish<W: Work>(&self, s: Self::State, w: &W) -> Result<Output, Failure> {
        Hashes.finish(s, w)
    }
    fn matches<W: Work>(
        &self,
        id: &Self::Identity,
        o: &Output,
        b: &[u8],
        w: &W,
    ) -> Result<bool, Failure> {
        Hashes.matches(id, o, b, w)
    }
}

impl<'a> AsnDigest<'a> for Provider<'a> {
    fn identity(&self, algorithm: Algorithm) -> Option<Identity<'a>> {
        // A bare GOST OID has no key-specific DKE. ESS/TSP need an explicitly
        // selected operation context, never the last signature's context.
        let bytes = match algorithm {
            Algorithm::Kupyna256 => 32,
            Algorithm::Kupyna384 => 48,
            Algorithm::Kupyna512 => 64,
            _ => return None,
        };
        Some(Identity::trusted(Hash::Kupyna(bytes)).unwrap())
    }
}

impl<'a> SignatureProvider<'a> for Provider<'a> {
    type SignatureIdentity = Profile;
    type RawState = Infallible;
    fn resolve_signature_digest(
        &'a self,
        id: AlgorithmIdentifier<'a>,
        key: WorkingKey<'a>,
        parent: &Reader<'a>,
    ) -> Result<Resolution<Identity<'a>>, SignatureDigestError<Failure>> {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        if self.refuse_on.get() == call {
            return Err(SignatureDigestError::Callback(Failure::Resource {
                reason: MemoryError::WorkExceeded,
                at: id.offset(),
            }));
        }
        match digest::algorithm(&id, &parent.execution()).map_err(SignatureDigestError::Encoding)? {
            Resolution::Supported(algorithm) => self
                .selected(key, &parent.execution())
                .and_then(|key| key.resolve_digest(algorithm, &parent.execution()))
                .map_err(SignatureDigestError::Callback),
            Resolution::Unsupported => Ok(Resolution::Unsupported),
            Resolution::Malformed => Ok(Resolution::Malformed),
        }
    }
    fn resolve_signature(
        &'a self,
        id: AlgorithmIdentifier<'a>,
        digest: &Identity<'a>,
        key: WorkingKey<'a>,
        _: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<SignatureMode<Profile>>, Failure> {
        let profile =
            signature::with_algorithm(id, &parent.execution(), |algorithm| match algorithm {
                Some(signature::Algorithm::Dstu4145(profile)) => Some(profile),
                _ => None,
            })
            .map_err(Failure::Encoding)?;
        let Some(profile) = profile else {
            return Ok(Resolution::Unsupported);
        };
        let prepared = self.selected(key, &parent.execution())?;
        let expected = prepared.digest_identity(profile, &parent.execution())?;
        if self.compare(&expected, digest, &parent.execution())? != Ordering::Equal {
            return Ok(Resolution::Malformed);
        }
        Ok(Resolution::Supported(SignatureMode::Prehashed(profile)))
    }
    fn compare_signature<W: Work>(
        &self,
        a: &Profile,
        b: &Profile,
        w: &W,
    ) -> Result<Ordering, Failure> {
        w.charge_work(3)
            .map_err(|reason| Failure::Resource { reason, at: 0 })?;
        Ok(a.digest()
            .cmp(&b.digest())
            .then(
                (a.basis() == dstu4145::Basis::OptimalNormal)
                    .cmp(&(b.basis() == dstu4145::Basis::OptimalNormal)),
            )
            .then(
                (a.byte_order() == dstu4145::ByteOrder::BigEndian)
                    .cmp(&(b.byte_order() == dstu4145::ByteOrder::BigEndian)),
            ))
    }
    fn start_raw<W: Work>(
        &'a self,
        _: &Profile,
        _: WorkingKey<'a>,
        _: &'a Octets<'a>,
        _: &W,
    ) -> Result<Infallible, Failure> {
        Err(Failure::Backend {
            reason: Error::UnsupportedDomain,
            at: 0,
        })
    }
    fn update_raw<W: Work>(&self, state: &mut Infallible, _: &[u8], _: &W) -> Result<(), Failure> {
        match *state {}
    }
    fn finish_raw<W: Work>(&self, state: Infallible, _: &W) -> Result<SignatureAnswer, Failure> {
        match state {}
    }
    fn verify_prehashed<W: Work>(
        &'a self,
        profile: &Profile,
        key: WorkingKey<'a>,
        signature: &Octets<'a>,
        hash: Prehash<'_, '_, Self, Identity<'a>>,
        w: &W,
    ) -> Result<SignatureAnswer, Failure> {
        assert!(hash.from_provider(self));
        let signature = signature.as_one().ok_or(Failure::Backend {
            reason: Error::InvalidEncoding,
            at: signature.span().start,
        })?;
        Ok(
            if self.selected(key, w)?.verify_prehash(
                *profile,
                *hash.identity(),
                hash.as_bytes(),
                signature,
                w,
            )? {
                SignatureAnswer::Valid
            } else {
                SignatureAnswer::Invalid
            },
        )
    }
}

fn attr(oid: Oid<'_>, value: &[u8]) -> Vec<u8> {
    let mut body = tlv(6, oid.as_bytes());
    body.extend(tlv(49, value));
    tlv(48, &body)
}

fn signer(protected: bool, malformed_signature: bool) -> Vec<u8> {
    let digest = tlv(48, &tlv(6, structured_pkix::oid::GOST34311.as_bytes()));
    let mut signature_algorithm = tlv(6, SIGNATURE_OID);
    if malformed_signature {
        // Two parameters violate AlgorithmIdentifier before any provider
        // interprets its one optional ANY as a particular signature profile.
        signature_algorithm.extend([5, 0, 5, 0]);
    }
    let signature_algorithm = tlv(48, &signature_algorithm);
    let mut body = std::vec![2, 1, 3, 0x80, 1, 7];
    body.extend(&digest);
    if protected {
        let mut protection = digest;
        protection.extend(tlv(0xa1, &tlv(6, SIGNATURE_OID)));
        let mut attributes = std::vec![
            attr(
                structured_cms::oid::CONTENT_TYPE,
                &tlv(6, structured_cms::oid::DATA.as_bytes())
            ),
            attr(structured_cms::oid::MESSAGE_DIGEST, &tlv(4, &[0; 32])),
            attr(
                structured_cms::oid::ALGORITHM_PROTECTION,
                &tlv(48, &protection)
            ),
        ];
        attributes.sort();
        body.extend(tlv(0xa0, &attributes.concat()));
    }
    body.extend(signature_algorithm);
    let mut signature = [0; 42];
    signature[0] = 2;
    signature[21] = 3;
    body.extend(tlv(4, &signature));
    tlv(48, &body)
}

struct Source {
    calls: usize,
}
impl structured_cms::stream::Source for Source {
    type Error = &'static str;
    fn stream<W: Work>(
        &mut self,
        sink: &mut impl structured_cms::stream::Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        work.charge_work(1).map_err(|_| "resource")?;
        self.calls += 1;
        sink.write(b"first").map_err(|_| "receiver")?;
        sink.write(b"second").map_err(|_| "receiver")
    }
}

/// One selected provider resolves the same GOST OID with two actual key DKEs,
/// fans out one payload pass, and deduplicates only the third equal identity.
/// The receipt is forwarded through ProviderSession without rehashing.
#[test]
fn mixed_key_dke_signers_share_one_source_pass() {
    let memory = memory();
    let parser = parser(memory.clone());
    let mut alternate = DEFAULT_DKE;
    alternate.swap(0, 1);
    let a = fixture(&DEFAULT_DKE);
    let b = fixture(&alternate);
    let da = Dke::new(&DEFAULT_DKE).unwrap();
    let db = Dke::new(&alternate).unwrap();
    let ka = read(&parser, &a, 100);
    let kb = read(&parser, &b, 1000);
    let provider = ProviderSession::new(Provider {
        keys: [
            (ka, Key::prepare(ka, &da, &memory).unwrap()),
            (kb, Key::prepare(kb, &db, &memory).unwrap()),
        ],
        calls: Cell::new(0),
        starts: Cell::new(0),
        refuse_on: Cell::new(0),
    });
    assert!(provider.identity(Algorithm::Gost34311).is_none());
    let encoded = signer(false, false);
    let mut reader = parser.read(&encoded, 2400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signer = SignerInfo::read(&reader, &element).unwrap();
    let mut requests = reader.execution().vector();
    for key in [ka, kb, ka] {
        let Preparation::Ready(ready) = prepare::resolve(
            &provider,
            &signer,
            WorkingKey::standing(key),
            &reader,
            Scope::Content(structured_cms::oid::DATA),
        )
        .unwrap() else {
            panic!("ready")
        };
        requests.try_push(ready).unwrap();
    }
    assert_eq!(provider.calls.get(), 3);
    assert_eq!(provider.starts.get(), 0);
    let batch = structured_cms::verify::Batch::prepare(
        &provider,
        requests.into_owned(),
        &reader.execution(),
        "signers",
        2400,
    )
    .unwrap();
    let mut source = Source { calls: 0 };
    let results = batch.run(&mut source, &reader.execution()).unwrap();
    assert_eq!(source.calls, 1);
    assert_eq!(provider.starts.get(), 2);
    assert_eq!(results.len(), 3);
    for result in &*results {
        assert_eq!(result.signature(), Some(SignatureAnswer::Invalid));
    }
    assert!(provider.identity(Algorithm::Gost34311).is_none());
}

/// Protected algorithms use the same key-bound hook. Its refusal remains a
/// located callback error, while malformed syntax permits no hook at all.
#[test]
fn protected_digest_hook_and_preflight_gates() {
    let memory = memory();
    let parser = parser(memory.clone());
    let raw = fixture(&DEFAULT_DKE);
    let dke = Dke::new(&DEFAULT_DKE).unwrap();
    let key = read(&parser, &raw, 100);
    let provider = ProviderSession::new(Provider {
        keys: [
            (key, Key::prepare(key, &dke, &memory).unwrap()),
            (key, Key::prepare(key, &dke, &memory).unwrap()),
        ],
        calls: Cell::new(0),
        starts: Cell::new(0),
        refuse_on: Cell::new(0),
    });
    for (protected, malformed, refusal) in [
        (true, false, 0),
        (true, false, 2),
        (false, true, 0),
        (false, false, 1),
    ] {
        provider.calls.set(0);
        provider.refuse_on.set(refusal);
        let raw = signer(protected, malformed);
        let mut reader = parser.read(&raw, 2400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let signer = SignerInfo::read(&reader, &element).unwrap();
        let result = prepare::resolve(
            &provider,
            &signer,
            WorkingKey::standing(key),
            &reader,
            Scope::Content(structured_cms::oid::DATA),
        );
        if malformed {
            assert!(matches!(result, Ok(Preparation::Malformed(_))));
            assert_eq!(provider.calls.get(), 0);
        } else if refusal != 0 {
            let expected = if protected {
                Part::ProtectedDigest
            } else {
                Part::Digest
            };
            assert!(
                matches!(result,Err(PrepareError::Callback{part,source:Failure::Resource{reason:MemoryError::WorkExceeded,..}}) if part==expected)
            );
            assert_eq!(provider.calls.get(), refusal);
        } else {
            assert!(matches!(result, Ok(Preparation::Ready(_))));
            assert_eq!(provider.calls.get(), 2);
        }
        assert_eq!(provider.starts.get(), 0);
    }
}
