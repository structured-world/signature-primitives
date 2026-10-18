//! Routing/lifetime tests with a synthetic digest, not a cryptographic oracle.

use super::{attribute, certificate, identity, issuer, memory, sequence, signer, tlv, value};
use core::{cell::Cell, cmp::Ordering};
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{MemoryError, Work};
use structured_asn1::{Encoding, Parser};
use structured_cms::ess::{Binding, BindingError, SigningAttributes};
use structured_cms::oid;
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

#[derive(Debug)]
enum Failure {
    /// The provider's own admission refused; no test inspects which ceiling.
    Resource,
    Injected,
}
impl From<MemoryError> for Failure {
    fn from(_: MemoryError) -> Self {
        Self::Resource
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
    last_input: Cell<*const u8>,
}

impl Digest<'_> for Provider {
    type Identity = Identity;
    type State = State;
    type Output = Output;
    type Error = Failure;
    fn compare<W: Work>(
        &self,
        left: &Identity,
        right: &Identity,
        execution: &W,
    ) -> Result<Ordering, Failure> {
        execution.charge_work(1)?;
        Ok(left.0.cmp(&right.0))
    }
    fn width(&self, identity: &Identity) -> Option<usize> {
        Some(match identity.0 {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
        })
    }
    fn start<W: Work>(
        &self,
        identity: &Identity,
        execution: &W,
    ) -> Result<Resolution<State>, Failure> {
        execution.charge_work(1)?;
        self.starts.set(self.starts.get() + 1);
        Ok(Resolution::Supported(State {
            sum: 0,
            width: self.width(identity).unwrap(),
        }))
    }
    fn update<W: Work>(
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
    fn finish<W: Work>(&self, state: State, execution: &W) -> Result<Output, Failure> {
        execution.charge_work(1)?;
        self.finishes.set(self.finishes.get() + 1);
        Ok(Output {
            bytes: [state.sum; 32],
            width: state.width,
        })
    }
    fn matches<W: Work>(
        &self,
        _: &Identity,
        output: &Output,
        expected: &[u8],
        execution: &W,
    ) -> Result<bool, Failure> {
        execution.charge_work(expected.len() as u64)?;
        if self.refused.get() {
            return Err(Failure::Injected);
        }
        self.comparisons.set(self.comparisons.get() + 1);
        Ok(output.as_ref() == expected)
    }
}

impl AsnDigest<'_> for Provider {
    fn identity(&self, algorithm: Algorithm) -> Option<Identity> {
        if self.unsupported.get() {
            return None;
        }
        match algorithm {
            Algorithm::Sha1 => Some(Identity(Hash::Sha1)),
            Algorithm::Sha256 => Some(Identity(Hash::Sha256)),
            _ => None,
        }
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
    assert_eq!(provider.starts.get(), 0);
    assert_eq!(provider.updates.get(), 0);
    assert_eq!(provider.finishes.get(), 0);
    assert!(provider.last_input.get().is_null());
}

#[test]
fn written_hash_parameters_its_algorithm_does_not_take_are_malformed_before_hashing() {
    // A V2 identifier writing an INTEGER beside SHA-256 is a malformed
    // algorithm (RFC 5754 §2 allows only absent or NULL), never a mismatch or
    // an unsupported mechanism, and no state starts.
    let certificate_bytes = certificate("issuer", 7);
    let written = sequence(&[
        sequence(&[tlv(6, oid::SHA256.as_bytes()), tlv(2, &[1])]),
        tlv(4, &[7; 32]),
    ]);
    let encoded = signer(
        &[attribute(
            oid::SIGNING_CERTIFICATE_V2,
            &[value(&[written], None)],
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
            .v2,
        Some(Binding::MalformedAlgorithm)
    );
    assert_eq!(provider.starts.get(), 0);
}

#[test]
fn comparison_refusal_stays_a_callback_error_not_a_mismatch() {
    // The provider's own comparison fails after hashing; its cause is kept.
    let certificate_bytes = certificate("issuer", 7);
    let encoded = signer(
        &[attribute(
            oid::SIGNING_CERTIFICATE,
            &[value(&[identity(&[7; 20])], None)],
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
    provider.refused.set(true);
    assert!(matches!(
        attributes.bind_certificate(&provider, &certificate, &parent),
        Err(BindingError::Callback {
            source: Failure::Injected,
            ..
        })
    ));
    assert_eq!(provider.comparisons.get(), 0);
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
    let result = attributes.bind_certificate(&provider, &certificate, &query);
    let Err(BindingError::Processing(error)) = result else {
        panic!("local refusal hidden: {result:?}")
    };
    assert!(error.is_resource());
    assert_eq!(error.field(), "signerInfo.signedAttrs.signingCertificate");
    assert_eq!(
        error.offset(),
        attributes.v1().unwrap().signer().element().span().start
    );
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
