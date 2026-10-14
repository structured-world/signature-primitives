//! Routing/lifetime tests with a synthetic digest, not a cryptographic oracle.

use super::{attribute, certificate, identity, issuer, memory, sequence, signer, tlv, value};
use core::{cell::Cell, cmp::Ordering};
use structured_asn1::memory::{MemoryError, Work};
use structured_asn1::{Encoding, Parser, Reader};
use structured_cms::ess::{Binding, BindingError, SigningAttributes};
use structured_cms::oid;
use structured_cms::provider::{
    DigestAlgorithm, DigestProvider, ImpliedDigest, Prehash, Resolution,
};

#[derive(Debug)]
enum Failure {
    Resource(MemoryError),
    Injected,
}
impl From<MemoryError> for Failure {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Hash {
    Sha1,
    Sha256,
}
struct Identity(Hash);
struct State {
    sum: u8,
    width: usize,
}
struct Output {
    bytes: [u8; 32],
    width: usize,
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.width]
    }
}
#[derive(Default)]
struct Provider {
    starts: Cell<usize>,
    updates: Cell<usize>,
    finishes: Cell<usize>,
    comparisons: Cell<usize>,
    refused: Cell<bool>,
    unsupported: Cell<bool>,
    malformed: Cell<bool>,
    last_input: Cell<*const u8>,
}

impl<'a> DigestProvider<'a> for Provider {
    type Error = Failure;
    type Identity = Identity;
    type State = State;
    type Output = Output;
    fn resolve_digest(
        &'a self,
        identifier: DigestAlgorithm<'a>,
        _: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<Identity>, Failure> {
        parent.execution().charge_work(1)?;
        if self.refused.get() {
            return Err(Failure::Injected);
        }
        if self.unsupported.get() {
            return Ok(Resolution::Unsupported);
        }
        if self.malformed.get() {
            return Ok(Resolution::Malformed);
        }
        let algorithm = match identifier {
            DigestAlgorithm::Implied {
                algorithm: ImpliedDigest::EssSha1,
                ..
            } => Hash::Sha1,
            DigestAlgorithm::Implied {
                algorithm: ImpliedDigest::EssV2Sha256,
                ..
            } => Hash::Sha256,
            DigestAlgorithm::Written(algorithm) => {
                parent
                    .execution()
                    .charge_work(algorithm.algorithm().as_bytes().len() as u64)?;
                if algorithm.algorithm() == oid::SHA1 {
                    Hash::Sha1
                } else if algorithm.algorithm() == oid::SHA256 {
                    Hash::Sha256
                } else {
                    return Ok(Resolution::Unsupported);
                }
            }
        };
        Ok(Resolution::Supported(Identity(algorithm)))
    }
    fn compare_digest<W: Work>(
        &self,
        left: &Identity,
        right: &Identity,
        execution: &W,
    ) -> Result<Ordering, Failure> {
        execution.charge_work(1)?;
        Ok(left.0.cmp(&right.0))
    }
    fn digest_width(&self, identity: &Identity) -> Option<usize> {
        Some(match identity.0 {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
        })
    }
    fn start_digest<W: Work>(
        &'a self,
        identity: &Identity,
        execution: &W,
    ) -> Result<State, Failure> {
        execution.charge_work(1)?;
        self.starts.set(self.starts.get() + 1);
        Ok(State {
            sum: 0,
            width: self.digest_width(identity).unwrap(),
        })
    }
    fn update_digest<W: Work>(
        &self,
        state: &mut State,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), Failure> {
        execution.charge_work(bytes.len() as u64)?;
        self.updates.set(self.updates.get() + 1);
        self.last_input.set(bytes.as_ptr());
        for byte in bytes {
            state.sum = state.sum.wrapping_add(*byte);
        }
        Ok(())
    }
    fn finish_digest<W: Work>(&self, state: State, execution: &W) -> Result<Output, Failure> {
        execution.charge_work(1)?;
        self.finishes.set(self.finishes.get() + 1);
        Ok(Output {
            bytes: [state.sum; 32],
            width: state.width,
        })
    }
    fn matches_digest<W: Work>(
        &self,
        digest: Prehash<'_, '_, Self, Identity>,
        expected: &[u8],
        execution: &W,
    ) -> Result<bool, Failure> {
        execution.charge_work(expected.len() as u64)?;
        self.comparisons.set(self.comparisons.get() + 1);
        Ok(digest.as_bytes() == expected)
    }
}

#[test]
fn first_identifiers_share_only_full_identity_and_whole_certificate_input() {
    // Equal resolved V1/V2 identities share one state/output; different hashes
    // remain two states fed from the same original certificate range once.
    let certificate_bytes = certificate("issuer", 7);
    let sum = certificate_bytes
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    for (same_identity, states) in [(true, 1), (false, 2)] {
        let v1 = attribute(
            oid::SIGNING_CERTIFICATE,
            &[value(&[identity(&[sum; 20])], None)],
        );
        let second = if same_identity {
            sequence(&[
                sequence(&[tlv(6, oid::SHA1.as_bytes())]),
                tlv(4, &[sum; 20]),
            ])
        } else {
            identity(&[sum; 32])
        };
        let v2 = attribute(oid::SIGNING_CERTIFICATE_V2, &[value(&[second], None)]);
        let encoded = signer(&[v1, v2], &[]);
        let storage = memory(1_000_000, 1_000_000);
        let parser = Parser::ber(storage.clone());
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let signer = structured_cms::signer::SignerInfo::read(&parent, &element).unwrap();
        let attributes = SigningAttributes::read(&signer, &parent).unwrap();
        let certificate =
            structured_pkix::Certificate::read(&parser, &certificate_bytes, 900).unwrap();
        let provider = Provider::default();
        let held = storage.used();
        let bindings = attributes
            .bind_certificate(&provider, &certificate, &parent)
            .unwrap();
        assert_eq!(bindings.v1, Some(Binding::Matches));
        assert_eq!(bindings.v2, Some(Binding::Matches));
        assert_eq!(provider.starts.get(), states);
        assert_eq!(provider.updates.get(), states);
        assert_eq!(provider.finishes.get(), states);
        assert_eq!(provider.comparisons.get(), 2);
        assert_eq!(provider.last_input.get(), certificate.as_bytes().as_ptr());
        assert_eq!(storage.used(), held);
    }
}

#[test]
fn malformed_width_and_unsupported_do_not_start_a_hash_or_read_certificate_bytes() {
    // Impossible declarations and resolver semantic answers precede all state
    // and source side effects. Original callback refusal stays an Error.
    let certificate_bytes = certificate("issuer", 7);
    let encoded = signer(
        &[attribute(
            oid::SIGNING_CERTIFICATE,
            &[value(&[identity(&[7])], None)],
        )],
        &[],
    );
    let parser = Parser::ber(memory(1_000_000, 1_000_000));
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = structured_cms::signer::SignerInfo::read(&parent, &element).unwrap();
    let attributes = SigningAttributes::read(&signer, &parent).unwrap();
    let certificate = structured_pkix::Certificate::read(&parser, &certificate_bytes, 900).unwrap();
    let provider = Provider::default();
    assert_eq!(
        attributes
            .bind_certificate(&provider, &certificate, &parent)
            .unwrap()
            .v1,
        Some(Binding::MalformedHash)
    );
    provider.unsupported.set(true);
    assert_eq!(
        attributes
            .bind_certificate(&provider, &certificate, &parent)
            .unwrap()
            .v1,
        Some(Binding::Unsupported)
    );
    provider.unsupported.set(false);
    provider.malformed.set(true);
    assert_eq!(
        attributes
            .bind_certificate(&provider, &certificate, &parent)
            .unwrap()
            .v1,
        Some(Binding::MalformedAlgorithm)
    );
    provider.malformed.set(false);
    provider.refused.set(true);
    assert!(matches!(
        attributes.bind_certificate(&provider, &certificate, &parent),
        Err(BindingError::Callback {
            source: Failure::Injected,
            ..
        })
    ));
    assert_eq!(provider.starts.get(), 0);
    assert_eq!(provider.updates.get(), 0);
    assert_eq!(provider.finishes.get(), 0);
    assert!(provider.last_input.get().is_null());
}

#[test]
fn new_local_refusal_is_neither_hash_mismatch_nor_unsupported() {
    // Current query admission governs actual resolver work, while retained
    // source capacity stays on its original account and no state is started.
    let certificate_bytes = certificate("issuer", 7);
    let encoded = signer(
        &[attribute(
            oid::SIGNING_CERTIFICATE,
            &[value(&[identity(&[7; 20])], None)],
        )],
        &[],
    );
    let storage = memory(1_000_000, 1_000_000);
    let parser = Parser::ber(storage.clone());
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = structured_cms::signer::SignerInfo::read(&parent, &element).unwrap();
    let attributes = SigningAttributes::read(&signer, &parent).unwrap();
    let certificate = structured_pkix::Certificate::read(&parser, &certificate_bytes, 900).unwrap();
    let held = storage.used();
    let old_work = storage.work_used();
    let current = memory(1_000_000, 1_000_000);
    let limited = Parser::new(
        Encoding::Ber,
        structured_asn1::Limits {
            max_work: 1,
            ..structured_asn1::Limits::default()
        },
        current.clone(),
    );
    let query = limited.read(&[], 1400).unwrap();
    let provider = Provider::default();
    let Err(BindingError::Callback {
        source: Failure::Resource(MemoryError::WorkExceeded),
        field,
        span,
    }) = attributes.bind_certificate(&provider, &certificate, &query)
    else {
        panic!("resolver local refusal hidden")
    };
    assert_eq!(field, "signerInfo.signedAttrs.signingCertificate");
    assert_eq!(span, attributes.v1().unwrap().signer().element().span());
    assert_eq!(provider.starts.get(), 0);
    assert_eq!(current.used(), 0);
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), old_work);
}

#[test]
fn hash_issuer_and_unreadable_results_remain_independent_of_profile_faults() {
    // A complete hash does not turn an unreadable issuer into absence. A
    // changed serial/name is distinct from a changed hash; current shared
    // Name semantics supply case folding, not a private ESS comparer.
    let certificate_bytes = certificate(" STRASSE ", 7);
    let sum = certificate_bytes
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
    for (hash, issuer_value, expected, faults) in [
        (sum, issuer("Straße"), Binding::Matches, 0),
        (sum, issuer("different"), Binding::IssuerDiffers, 0),
        (sum, tlv(5, &[]), Binding::IssuerUnreadable, 1),
        (
            sum.wrapping_add(1),
            issuer("Straße"),
            Binding::HashDiffers,
            0,
        ),
    ] {
        let id = sequence(&[tlv(4, &[hash; 20]), issuer_value]);
        let encoded = signer(
            &[attribute(oid::SIGNING_CERTIFICATE, &[value(&[id], None)])],
            &[],
        );
        let storage = memory(1_000_000, 1_000_000);
        let parser = Parser::ber(storage.clone());
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let signer = structured_cms::signer::SignerInfo::read(&parent, &element).unwrap();
        let attributes = SigningAttributes::read(&signer, &parent).unwrap();
        assert_eq!(attributes.v1().unwrap().faults().len(), faults);
        let certificate =
            structured_pkix::Certificate::read(&parser, &certificate_bytes, 900).unwrap();
        let held = storage.used();
        let provider = Provider::default();
        let result = attributes
            .bind_certificate(&provider, &certificate, &parent)
            .unwrap();
        assert_eq!(result.v1, Some(expected));
        assert!(result.v2.is_none());
        assert_eq!(attributes.v1().unwrap().faults().len(), faults);
        assert_eq!(provider.starts.get(), 1);
        assert_eq!(provider.updates.get(), 1);
        assert_eq!(storage.used(), held);
    }
}
