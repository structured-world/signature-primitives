use super::{Anchor, Bounds, Interval, Path, Policy, Truncation, Verified, Verify, build};
use crate::fixtures::{
    CertificateParts, bits, boolean, cat, extension, ia5, int, oid as oid_of, printable, seq, set,
    tlv, utc_time,
};
use crate::{Certificate, oid};
use alloc::vec;
use alloc::vec::Vec;
use p256::ecdsa::signature::{Signer, Verifier};

use structured_asn1::{Oid, Parser};

#[test]
fn ordinary_interval_does_not_alias_validity_leap_label() {
    // Validity beginning at :60 must exclude the preceding :59 despite
    // both labels sharing a POSIX projection; midnight follows the leap.
    let parts = CertificateParts {
        validity: seq(&[
            crate::fixtures::generalized_time("20161231235960Z"),
            crate::fixtures::generalized_time("20170101000000Z"),
        ]),
        ..CertificateParts::default()
    };
    let bytes = parts.build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = Certificate::read(&parser, &bytes, 0).unwrap();
    let validity = certificate.tbs().validity();
    assert!(!Interval::at(1_483_228_799).inside(validity));
    assert!(Interval::at(1_483_228_800).inside(validity));
}

#[test]
fn lossless_interval_preserves_inserted_second_and_fractional_endpoints() {
    // A supplied timestamp interval must keep its label instead of rounding
    // through :60 or projecting it onto the preceding ordinary second.
    let der = CertificateParts {
        validity: seq(&[
            crate::fixtures::generalized_time("20161231235960Z"),
            crate::fixtures::generalized_time("20170101000000Z"),
        ]),
        ..CertificateParts::default()
    }
    .build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = Certificate::read(&parser, &der, 0).unwrap();
    let validity = certificate.tbs().validity();
    let leap = validity.not_before().instant();
    let after = crate::temporal::Instant::leap_after(leap.seconds(), 123).unwrap();
    let interval = Interval::between_instants(after, leap);
    assert_eq!(interval.from_instant(), leap);
    assert_eq!(interval.to_instant(), after);
    assert!(interval.inside(validity));
    assert!(Interval::at_instant(leap).inside(validity));
    assert!(!Interval::at(leap.seconds()).inside(validity));
    let after_end = crate::temporal::Instant::new(validity.not_after().seconds(), 1).unwrap();
    assert!(!Interval::at_instant(after_end).inside(validity));
}

/// `ecdsa-with-SHA256`, which the test chains are signed with. The registry
/// that says which algorithms verify what is another crate's; this is the
/// one identifier these certificates carry.
const ECDSA_SHA256: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);

/// `prime256v1`, the curve the keys below are on.
const PRIME256V1: Oid<'static> = Oid::from_bytes(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

/// A key of this test, made from a fixed scalar so that a failing run can be
/// repeated exactly.
fn key(seed: u8) -> p256::ecdsa::SigningKey {
    let mut scalar = [1u8; 32];
    scalar[31] = seed;
    p256::ecdsa::SigningKey::from_slice(&scalar).expect("a scalar inside the field")
}

/// The public key information of one key, as a certificate carries it.
fn public(signing: &p256::ecdsa::SigningKey) -> Vec<u8> {
    described(signing, oid_of(PRIME256V1))
}

/// The same, with the algorithm's parameters written as this many bytes
/// rather than as the curve's name.
///
/// The parameters are carried and not read: what verifies a signature here
/// is the algorithm identifier and the key octets. Writing a large value
/// there is a key encoding of that size, which is what a comparison of two
/// keys reads, and it lets a test say how much reading one costs.
fn keyed_over(signing: &p256::ecdsa::SigningKey, width: usize) -> Vec<u8> {
    described(signing, tlv(0x04, &alloc::vec![0x41; width]))
}

/// One key written without any parameters at all, which is how a certificate
/// says that the ones in force above it are the ones it stands in.
fn parameterless(signing: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let point = signing.verifying_key().to_sec1_point(false);
    seq(&[seq(&[oid_of(oid::EC_PUBLIC_KEY)]), bits(point.as_ref())])
}

/// One key under the parameters given.
fn described(signing: &p256::ecdsa::SigningKey, parameters: Vec<u8>) -> Vec<u8> {
    // Uncompressed, which is the form the reader of the key octets expects
    // and the one certificates in the corpus carry.
    let point = signing.verifying_key().to_sec1_point(false);
    seq(&[
        seq(&[oid_of(oid::EC_PUBLIC_KEY), parameters]),
        bits(point.as_ref()),
    ])
}

/// One key written under another algorithm's identifier, with the null
/// parameters that identifier is written with.
///
/// The key octets are the same point: what a test of this shape is about is
/// the parameters a key of one algorithm may stand in, and not the key.
fn elsewhere(signing: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let point = signing.verifying_key().to_sec1_point(false);
    seq(&[
        seq(&[oid_of(oid::RSA_ENCRYPTION), tlv(0x05, &[])]),
        bits(point.as_ref()),
    ])
}

/// A distinguished name of one common name.
fn named(common: &str) -> Vec<u8> {
    seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME), printable(common)])])])
}

/// What a certificate says about issuing other certificates.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Authority {
    /// No basic constraints at all, which is what a certificate issued to a
    /// person carries.
    Absent,
    /// An authority, with nothing said about how far below it may go.
    Unlimited,
    /// An authority that allows this many certificates below it.
    Below(u32),
}

/// What a certificate this test mints says about itself.
struct Mint<'a> {
    subject: &'a str,
    issuer: &'a str,
    key: u8,
    /// How many bytes the key's algorithm parameters are written as, where
    /// a test is about what reading a key encoding costs.
    parameters: Option<usize>,
    signer: u8,
    serial: u32,
    authority: Authority,
    usage: Option<u8>,
    validity: (&'a str, &'a str),
    extra: Vec<Vec<u8>>,
    /// The subject written out, for a test whose subject is not one common
    /// name. Where this is given, `subject` is not read.
    subject_der: Option<Vec<u8>>,
    /// The issuer written out, on the same terms.
    issuer_der: Option<Vec<u8>>,
    /// Whether the key is written without parameters, standing in the ones
    /// an authority above it wrote.
    inherits: bool,
    /// Whether the key is written under another algorithm's identifier, with
    /// the null parameters that identifier is written with.
    foreign: bool,
}

impl Default for Mint<'_> {
    fn default() -> Self {
        Self {
            subject: "Subject",
            issuer: "Issuer",
            key: 1,
            parameters: None,
            signer: 2,
            serial: 1,
            authority: Authority::Absent,
            usage: None,
            validity: ("240101000000Z", "300101000000Z"),
            extra: Vec::new(),
            subject_der: None,
            issuer_der: None,
            inherits: false,
            foreign: false,
        }
    }
}

impl Mint<'_> {
    /// One certificate, signed by the key that issued it, so that a path
    /// through it is a path a verifier agrees with.
    fn build(&self) -> Vec<u8> {
        let mut extensions = Vec::new();
        match self.authority {
            Authority::Absent => {}
            Authority::Unlimited => extensions.push(extension(
                oid::BASIC_CONSTRAINTS,
                true,
                &seq(&[boolean(true)]),
            )),
            Authority::Below(length) => extensions.push(extension(
                oid::BASIC_CONSTRAINTS,
                true,
                &seq(&[boolean(true), int(length)]),
            )),
        }
        if let Some(first) = self.usage {
            // The distinguished rules end a named bit list at its last bit
            // set (X.690 11.2), so how many of the octet's bits are unused
            // is what the value says rather than something chosen here.
            let unused = u8::try_from(first.trailing_zeros()).expect("a byte has eight bits");
            extensions.push(extension(
                oid::KEY_USAGE,
                true,
                &tlv(0x03, &[unused, first]),
            ));
        }
        extensions.extend(self.extra.iter().cloned());

        let parts = CertificateParts {
            serial: int(self.serial),
            inner_algorithm: seq(&[oid_of(ECDSA_SHA256)]),
            outer_algorithm: seq(&[oid_of(ECDSA_SHA256)]),
            issuer: self
                .issuer_der
                .clone()
                .unwrap_or_else(|| named(self.issuer)),
            subject: self
                .subject_der
                .clone()
                .unwrap_or_else(|| named(self.subject)),
            validity: seq(&[utc_time(self.validity.0), utc_time(self.validity.1)]),
            key: match (self.foreign, self.inherits, self.parameters) {
                (true, _, _) => elsewhere(&key(self.key)),
                (false, true, _) => parameterless(&key(self.key)),
                (false, false, Some(width)) => keyed_over(&key(self.key), width),
                (false, false, None) => public(&key(self.key)),
            },
            extensions: (!extensions.is_empty()).then(|| seq(&extensions)),
            signature: bits(&[]),
            ..CertificateParts::default()
        };
        let signed = parts.tbs();
        let signature: p256::ecdsa::Signature = key(self.signer).sign(&signed);
        CertificateParts {
            signature: bits(signature.to_der().as_bytes()),
            ..parts
        }
        .build()
    }
}

/// The verifier of this test: the algorithm registry lives in another crate,
/// and what a path needs from it is this one answer.
struct Ecdsa;

impl Verify for Ecdsa {
    type Error = core::convert::Infallible;
    fn verify(
        &self,
        algorithm: &crate::AlgorithmIdentifier<'_>,
        key: super::WorkingKey<'_>,
        signed: &[u8],
        signature: structured_asn1::BitString<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<Verified, Self::Error> {
        Ok({
            if algorithm.algorithm() != ECDSA_SHA256
                || key.key().algorithm().algorithm() != oid::EC_PUBLIC_KEY
            {
                return Ok(Verified::Unsupported);
            }
            let (Some(octets), Some(value)) = (key.key().key_octets(), signature.octets()) else {
                return Ok(Verified::No);
            };
            let (Ok(verifying), Ok(signature)) = (
                p256::ecdsa::VerifyingKey::from_sec1_bytes(octets),
                p256::ecdsa::Signature::from_der(value),
            ) else {
                return Ok(Verified::No);
            };
            if verifying.verify(signed, &signature).is_ok() {
                Verified::Yes
            } else {
                Verified::No
            }
        })
    }
}

/// A verifier that needs the parameters in force, which is what a key
/// omitting its own is asking of the path above it.
///
/// The registry this stands for reads the group a key belongs to from the
/// parameters rather than assuming one. Handed a key written without them
/// and nothing else, it can only answer that it cannot say.
struct Curved;

impl Verify for Curved {
    type Error = core::convert::Infallible;
    fn verify(
        &self,
        algorithm: &crate::AlgorithmIdentifier<'_>,
        key: super::WorkingKey<'_>,
        signed: &[u8],
        signature: structured_asn1::BitString<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<Verified, Self::Error> {
        Ok({
            if algorithm.algorithm() != ECDSA_SHA256
                || key.key().algorithm().algorithm() != oid::EC_PUBLIC_KEY
            {
                return Ok(Verified::Unsupported);
            }
            // The curve, wherever it was written: in this key, or in one above.
            let Some(parameters) = key.parameters() else {
                return Ok(Verified::Unsupported);
            };
            if parameters != oid_of(PRIME256V1).as_slice() {
                return Ok(Verified::Unsupported);
            }
            let (Some(octets), Some(value)) = (key.key().key_octets(), signature.octets()) else {
                return Ok(Verified::No);
            };
            let (Ok(verifying), Ok(signature)) = (
                p256::ecdsa::VerifyingKey::from_sec1_bytes(octets),
                p256::ecdsa::Signature::from_der(value),
            ) else {
                return Ok(Verified::No);
            };
            if verifying.verify(signed, &signature).is_ok() {
                Verified::Yes
            } else {
                Verified::No
            }
        })
    }
}

/// The moment the chains of this test are read at: the first day of 2026,
/// inside the validity every mint above writes.
fn moment() -> Interval {
    Interval::at(1_767_225_600)
}

/// What every search of this test asks of the caller: these anchors, that
/// moment, a verifier that reads the one algorithm the mints sign with, no
/// policy of its own, no clock and no scheme of its own.
fn context<'a, 'p>(
    anchors: &'p [Anchor<'a>],
    bounds: Bounds,
    execution: &'p structured_asn1::memory::Memory,
) -> super::Context<'a, 'p, Ecdsa, (), ()> {
    asking(anchors, bounds, Policy::default(), execution)
}

/// The same, for a test that is about what the caller asks of the policies.
fn asking<'a, 'p>(
    anchors: &'p [Anchor<'a>],
    bounds: Bounds,
    policy: Policy<'a>,
    execution: &'p structured_asn1::memory::Memory,
) -> super::Context<'a, 'p, Ecdsa, (), ()> {
    super::Context {
        execution,
        anchors,
        interval: moment(),
        bounds,
        policy,
        verifier: &Ecdsa,
        watch: &(),
        recognizer: &(),
    }
}

#[test]
fn anchor_folding_refuses_storage_before_allocating() {
    // Even one anchor needs an index allocation. The current request's empty
    // storage allowance must refuse that work, with the original Name offset.
    let der = Mint {
        subject: "Root",
        issuer: "Root",
        ..Mint::default()
    }
    .build();
    let parser = Parser::der(crate::fixtures::memory());
    let root = Certificate::read(&parser, &der, 201).unwrap();
    let anchors = [Anchor::from_certificate(&root)];
    let execution = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 1_000_000),
    ));
    let options = context(&anchors, Bounds::default(), &execution);
    let mut spent = 0;
    let mut halted = None;
    let error = super::fold_anchors(&options, &mut spent, &mut halted).unwrap_err();
    assert_eq!(
        error.code(),
        crate::ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Memory
        ))
    );
    let original = root.tbs().subject().as_bytes().as_ptr() as usize - der.as_ptr() as usize;
    assert_eq!(error.offset(), 201 + original as u64);
    assert_eq!(halted, None);
    assert_eq!(execution.used(), 0);
}

#[test]
fn anchor_work_refusal_stops_before_target_processing() {
    // A zero local work bound must return a truncated report without admitting
    // anchor storage or continuing into target processing with an invalid meter.
    let der = Mint::default().build();
    let parser = Parser::der(crate::fixtures::memory());
    let target = Certificate::read(&parser, &der, 0).unwrap();
    let anchors = [Anchor::from_certificate(&target)];
    let execution = crate::fixtures::memory();
    let options = context(
        &anchors,
        Bounds {
            work: 0,
            ..Bounds::default()
        },
        &execution,
    );
    let outcome = build(&target, &[], &options).unwrap();
    assert!(outcome.paths().is_empty());
    assert_eq!(outcome.truncated(), Some(Truncation::Work));
    assert_eq!(execution.used(), 0);
    assert_eq!(execution.work_used(), 0);
}

#[test]
fn anchor_folding_uses_the_aggregate_work_domain() {
    // A permissive local bound cannot bypass the current operation's work
    // ceiling, even before the first index allocation or key lookup.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let der = Mint::default().build();
    let parser = Parser::der(crate::fixtures::memory());
    let target = Certificate::read(&parser, &der, 101).unwrap();
    let anchors = [Anchor::from_certificate(&target)];
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(1_000_000, 0)));
    let options = context(&anchors, Bounds::default(), &execution);
    let mut spent = 0;
    let mut halted = None;
    let error = super::fold_anchors(&options, &mut spent, &mut halted).unwrap_err();
    assert!(error.is_resource());
    let at = target.tbs().subject().as_bytes().as_ptr() as usize - der.as_ptr() as usize;
    assert_eq!(error.offset(), 101 + at as u64);
    assert_eq!(spent, 0);
    assert_eq!(halted, None);
    assert_eq!(execution.used(), 0);
    assert_eq!(execution.work_used(), 0);
}

#[test]
fn an_exhausted_edge_counter_never_overflows() {
    // The caller may choose the largest representable edge bound. Both
    // anchor and pool paths must refuse the next edge before incrementing.
    let parser = Parser::der(crate::fixtures::memory());
    let ders = [
        Mint::default().build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            ..Mint::default()
        }
        .build(),
    ];
    let read = parse(&parser, &ders);
    let target = &read[0];
    let anchors = [Anchor::from_certificate(&read[1])];
    let execution = crate::fixtures::memory();
    let mut pool = execution.vector();
    pool.try_push(&read[1]).unwrap();
    let mut search = super::Search {
        execution: &execution,
        supplied: &[],
        target,
        pool: Some(pool),
        anchors: &anchors,
        interval: moment(),
        bounds: Bounds {
            edges: usize::MAX,
            ..Bounds::default()
        },
        policy: Policy::default(),
        verifier: &(),
        watch: &(),
        recognizer: &(),
        visited: 0,
        edges: usize::MAX,
        spent: 0,
        halted: None,
        noted: None,
        found: execution.vector(),
        signatures: execution.map(),
        properties: execution.map(),
    };
    super::settle(&mut search, target, &[target]).unwrap();
    assert_eq!(search.halted, Some(Truncation::Edges));
    assert_eq!(search.edges, usize::MAX);
    search.halted = None;
    let mut cursor = 0;
    assert!(
        super::next_issuer(&mut search, target, &[target], false, &mut cursor)
            .unwrap()
            .is_none()
    );
    assert_eq!(search.halted, Some(Truncation::Edges));
    assert_eq!(search.edges, usize::MAX);
}

#[test]
fn search_work_uses_the_aggregate_domain() {
    // Parser-independent dispatch work must consume the same cumulative
    // domain as allocation/copy work, while local Bounds only tighten it.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let der = Mint::default().build();
    let parser = Parser::der(crate::fixtures::memory());
    let target = Certificate::read(&parser, &der, 303).unwrap();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 64)));
    let mut search = super::Search {
        execution: &execution,
        supplied: &[],
        target: &target,
        pool: None,
        anchors: &[],
        interval: moment(),
        bounds: Bounds::default(),
        policy: Policy::default(),
        verifier: &(),
        watch: &(),
        recognizer: &(),
        visited: 0,
        edges: 0,
        spent: 0,
        halted: None,
        noted: None,
        found: execution.vector(),
        signatures: execution.map(),
        properties: execution.map(),
    };
    assert!(search.spend(32).unwrap());
    assert!(search.spend(32).unwrap());
    assert_eq!(execution.work_used(), 64);
    let error = search.spend(1).unwrap_err();
    assert!(error.is_resource());
    let at = target.tbs().subject().as_bytes().as_ptr() as usize - der.as_ptr() as usize;
    assert_eq!(error.offset(), 303 + at as u64);
    assert_eq!(execution.work_used(), 64);
    assert_eq!(search.halted, None);
}

/// Reads what the mints produced, keeping the bytes alive beside the
/// certificates that borrow them.
fn parse<'a>(parser: &'a Parser, ders: &'a [Vec<u8>]) -> Vec<Certificate<'a>> {
    ders.iter()
        .map(|der| Certificate::read(parser, der, 0).expect("a certificate this test wrote"))
        .collect()
}

#[test]
fn supplied_path_and_search_verify_the_same_original_chain() {
    // Real ECDSA verification exercises the same processor from both public
    // entry points; the supplied operation must retain original key/TBS views.
    let ders = chain(Authority::Unlimited, Some(0x04));
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchor = Anchor::from_certificate(&read[2]);
    let execution = crate::fixtures::memory();
    let context = super::ValidationContext {
        execution: &execution,
        interval: moment(),
        policy: Policy::default(),
        bounds: super::ValidationBounds::default(),
        verifier: &Ecdsa,
        watch: &(),
        recognizer: &(),
    };
    let super::Validation::Accepted(facts) =
        super::validate(&[&read[0], &read[1]], anchor, &context).unwrap()
    else {
        panic!("the original signed chain is accepted")
    };
    assert_eq!(
        facts.key.key().as_bytes().as_ptr(),
        read[0].tbs().public_key().as_bytes().as_ptr()
    );
    let anchors = [anchor];
    let search_context = super::Context {
        execution: &execution,
        anchors: &anchors,
        interval: moment(),
        bounds: Bounds::default(),
        policy: Policy::default(),
        verifier: &Ecdsa,
        watch: &(),
        recognizer: &(),
    };
    let outcome = build(&read[0], &[&read[1]], &search_context).unwrap();
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.paths()[0].policies(), facts.policies());
    assert_eq!(outcome.paths()[0].len(), 2);
    assert_eq!(facts.non_self_issued_intermediates, 1);
    drop(outcome);
    drop(facts);
    assert_eq!(execution.used(), 0);
}

#[test]
fn supplied_intermediate_role_and_issuer_failures_are_located() {
    // Completed CA/KU/issuer failures retain the exact supplied position;
    // they never become provider errors or an apparently absent certificate.
    for (authority, usage, expected) in [
        (
            Authority::Absent,
            None,
            super::RejectionReason::NotAuthority,
        ),
        (
            Authority::Unlimited,
            Some(0x80),
            super::RejectionReason::KeyCertSign,
        ),
    ] {
        let ders = chain(authority, usage);
        let parser = Parser::der(crate::fixtures::memory());
        let read = parse(&parser, &ders);
        let execution = crate::fixtures::memory();
        let context = super::ValidationContext {
            execution: &execution,
            interval: moment(),
            policy: Policy::default(),
            bounds: super::ValidationBounds::default(),
            verifier: &Ecdsa,
            watch: &(),
            recognizer: &(),
        };
        let super::Validation::Rejected(rejected) = super::validate(
            &[&read[0], &read[1]],
            Anchor::from_certificate(&read[2]),
            &context,
        )
        .unwrap() else {
            panic!("an unauthorized issuer is rejected")
        };
        assert_eq!(rejected.at, Some(super::ConstraintSource::Certificate(1)));
        assert_eq!(rejected.reason, expected);
        let super::Validation::Rejected(rejected) =
            super::validate(&[&read[0]], Anchor::from_certificate(&read[2]), &context).unwrap()
        else {
            panic!("the root did not name itself as this leaf's issuer")
        };
        assert_eq!(rejected.at, Some(super::ConstraintSource::Certificate(0)));
        assert_eq!(rejected.reason, super::RejectionReason::Issuer);
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn supplied_path_length_reports_the_constraining_ca_and_original_limit() {
    // RFC5280 §6.1.4(l,m): the upper CA's zero allowance is exhausted by
    // the lower non-self-issued CA, not by the final target certificate.
    let ders = [
        Mint {
            subject: "Leaf",
            issuer: "Lower",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Lower",
            issuer: "Upper",
            key: 2,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Upper",
            issuer: "Root",
            key: 3,
            signer: 4,
            authority: Authority::Below(0),
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 4,
            signer: 4,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let execution = crate::fixtures::memory();
    let context = super::ValidationContext {
        execution: &execution,
        interval: moment(),
        policy: Policy::default(),
        bounds: super::ValidationBounds::default(),
        verifier: &Ecdsa,
        watch: &(),
        recognizer: &(),
    };
    let super::Validation::Rejected(rejected) = super::validate(
        &[&read[0], &read[1], &read[2]],
        Anchor::from_certificate(&read[3]),
        &context,
    )
    .unwrap() else {
        panic!("the upper CA allows no intermediate below it")
    };
    assert_eq!(rejected.at, Some(super::ConstraintSource::Certificate(1)));
    assert_eq!(
        rejected.reason,
        super::RejectionReason::PathLength {
            source: super::ConstraintSource::Certificate(2),
            limit: 0
        }
    );
    assert_eq!(execution.used(), 0);
}

#[test]
fn supplied_effective_target_key_retains_inherited_parameters() {
    // Actual ECDSA checks need the root's curve for both parameterless keys.
    // Returned target facts must preserve that same borrowed parameter view.
    let mut ders = inheriting();
    ders[0] = Mint {
        subject: "Leaf",
        issuer: "Intermediate",
        key: 1,
        signer: 2,
        inherits: true,
        ..Mint::default()
    }
    .build();
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let execution = crate::fixtures::memory();
    let context = super::ValidationContext {
        execution: &execution,
        interval: moment(),
        policy: Policy::default(),
        bounds: super::ValidationBounds::default(),
        verifier: &Curved,
        watch: &(),
        recognizer: &(),
    };
    let super::Validation::Accepted(facts) = super::validate(
        &[&read[0], &read[1]],
        Anchor::from_certificate(&read[2]),
        &context,
    )
    .unwrap() else {
        panic!("inherited curve supports both original signatures")
    };
    assert_eq!(read[0].tbs().public_key().algorithm().parameters(), None);
    let parameters = facts.key.parameters().unwrap();
    let root_parameters = read[2].tbs().public_key().algorithm().parameters().unwrap();
    assert_eq!(parameters, root_parameters);
    assert_eq!(parameters.as_ptr(), root_parameters.as_ptr());
    assert_eq!(
        facts.key.key().as_bytes().as_ptr(),
        read[0].tbs().public_key().as_bytes().as_ptr()
    );
    drop(facts);
    assert_eq!(execution.used(), 0);
}

#[test]
fn inheritance_local_refusal_precedes_shared_work_admission() {
    // A stopped local operation cannot consume shared work or report shared
    // exhaustion instead of its own refusal, even when both limits refuse.
    struct Stopped;
    impl super::Meter for Stopped {
        fn spend(&mut self, _work: u64) -> crate::Result<bool> {
            Ok(false)
        }
    }
    let ders = inheriting();
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    for work in [0, 1_000_000] {
        let execution = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(0, work),
        ));
        let result = super::WorkingKey::standing(read[2].tbs().public_key()).below(
            &read[1],
            &execution,
            &mut Stopped,
        );
        assert!(result.unwrap().is_none());
        assert_eq!(execution.work_used(), 0);
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn public_subject_projection_borrows_effective_parameters_without_key_catalogue() {
    // The intermediate's inherited parameters remain accessible outside a
    // verifier callback. Projection establishes no trust and allocates nothing.
    let ders = inheriting();
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let execution = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 1_000_000),
    ));
    let root = super::WorkingKey::standing(read[2].tbs().public_key());
    let projected = root.subject(&read[1], &execution).unwrap();
    assert_eq!(
        projected.key().as_bytes().as_ptr(),
        read[1].tbs().public_key().as_bytes().as_ptr()
    );
    assert_eq!(
        projected.parameters().unwrap().as_ptr(),
        root.parameters().unwrap().as_ptr()
    );
    assert_eq!(execution.used(), 0);
    let stopped = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 0),
    ));
    assert!(root.subject(&read[1], &stopped).unwrap_err().is_resource());
    assert_eq!(stopped.work_used(), 0);
}

#[test]
fn inherited_algorithm_matching_is_admitted_at_the_current_certificate() {
    // A parameterless key needs a data-dependent algorithm comparison before
    // inheriting. Exhausting the shared domain inside the provider must refuse
    // that transition at the intermediate, not defer a hidden getter scan.
    struct Exhaust(usize);
    impl Verify for Exhaust {
        type Error = core::convert::Infallible;
        fn verify(
            &self,
            _algorithm: &crate::AlgorithmIdentifier<'_>,
            _key: super::WorkingKey<'_>,
            _signed: &[u8],
            _signature: structured_asn1::BitString<'_>,
            execution: &structured_asn1::memory::Memory,
        ) -> Result<Verified, Self::Error> {
            execution
                .charge_work((self.0 - execution.work_used()) as u64)
                .unwrap();
            Ok(Verified::Yes)
        }
    }
    let ders = inheriting();
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let work_limit = 1_000_000;
    let execution = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(1_000_000, work_limit),
    ));
    let context = super::ValidationContext {
        execution: &execution,
        interval: moment(),
        policy: Policy::default(),
        bounds: super::ValidationBounds::default(),
        verifier: &Exhaust(work_limit),
        watch: &(),
        recognizer: &(),
    };
    let super::BuildError::Processing(error) = super::validate(
        &[&read[0], &read[1]],
        Anchor::from_certificate(&read[2]),
        &context,
    )
    .unwrap_err();
    let at = read[1].tbs().subject().as_bytes().as_ptr() as usize - ders[1].as_ptr() as usize;
    assert_eq!(error.offset(), at as u64);
    assert_eq!(
        error.code(),
        crate::ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
    assert_eq!(execution.work_used(), work_limit);
    assert_eq!(execution.used(), 0);
}

#[test]
fn supplied_name_constraint_failure_names_anchor_or_ca_source() {
    // The same excluded DNS name must identify the actual constraining source
    // without a consumer re-decoding constraints or repeating the state machine.
    let excluded = extension(
        oid::NAME_CONSTRAINTS,
        true,
        &seq(&[tlv(0xa1, &seq(&[tlv(0x82, b"blocked.example")]))]),
    );
    for in_anchor in [false, true] {
        let ders = [
            Mint {
                subject: "Leaf",
                issuer: "Intermediate",
                key: 1,
                signer: 2,
                extra: vec![also_known_as("blocked.example")],
                ..Mint::default()
            }
            .build(),
            Mint {
                subject: "Intermediate",
                issuer: "Root",
                key: 2,
                signer: 3,
                authority: Authority::Unlimited,
                extra: if in_anchor {
                    Vec::new()
                } else {
                    vec![excluded.clone()]
                },
                ..Mint::default()
            }
            .build(),
            Mint {
                subject: "Root",
                issuer: "Root",
                key: 3,
                signer: 3,
                authority: Authority::Unlimited,
                extra: if in_anchor {
                    vec![excluded.clone()]
                } else {
                    Vec::new()
                },
                ..Mint::default()
            }
            .build(),
        ];
        let parser = Parser::der(crate::fixtures::memory());
        let read = parse(&parser, &ders);
        let execution = crate::fixtures::memory();
        let context = super::ValidationContext {
            execution: &execution,
            interval: moment(),
            policy: Policy::default(),
            bounds: super::ValidationBounds::default(),
            verifier: &Ecdsa,
            watch: &(),
            recognizer: &(),
        };
        let super::Validation::Rejected(rejected) = super::validate(
            &[&read[0], &read[1]],
            Anchor::from_certificate(&read[2]),
            &context,
        )
        .unwrap() else {
            panic!("explicit DNS exclusion")
        };
        assert_eq!(rejected.at, Some(super::ConstraintSource::Certificate(0)));
        let source = if in_anchor {
            super::ConstraintSource::Anchor
        } else {
            super::ConstraintSource::Certificate(1)
        };
        assert_eq!(
            rejected.reason,
            super::RejectionReason::NameConstraints {
                source,
                failure: super::NameConstraintFailure::Excluded
            }
        );
        let anchors = [Anchor::from_certificate(&read[2])];
        let search = build(
            &read[0],
            &[&read[1]],
            &self::context(&anchors, Bounds::default(), &execution),
        )
        .unwrap();
        assert_eq!(search.paths().len(), 0);
        assert_eq!(search.truncated(), None);
        drop(search);
        assert_eq!(execution.used(), 0);
    }
}

#[test]
fn supplied_policies_keep_owned_capacity_after_processing_returns() {
    // The graph and indexes drop at return, but policy-set capacity remains
    // owned by the result until explicitly moved/dropped, with no new charge.
    const POLICY: Oid<'static> = Oid::from_bytes(&[0x2a, 3, 4, 5]);
    let ders = [
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            extra: vec![issued_under(POLICY)],
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let execution = crate::fixtures::memory();
    let context = super::ValidationContext {
        execution: &execution,
        interval: moment(),
        policy: Policy::default(),
        bounds: super::ValidationBounds::default(),
        verifier: &Ecdsa,
        watch: &(),
        recognizer: &(),
    };
    let super::Validation::Accepted(facts) =
        super::validate(&[&read[0]], Anchor::from_certificate(&read[1]), &context).unwrap()
    else {
        panic!("named policy")
    };
    assert_eq!(facts.policies(), &[POLICY]);
    let retained = execution.used();
    assert!(retained > 0);
    let work = execution.work_used();
    let policies = facts.into_policies();
    assert_eq!(&*policies, &[POLICY]);
    assert_eq!(execution.used(), retained);
    assert_eq!(execution.work_used(), work);
    assert_eq!(
        retained,
        policies.capacity() * core::mem::size_of::<Oid<'_>>()
    );
    drop(policies);
    assert_eq!(execution.used(), 0);
}

#[test]
fn supplied_malformed_constraints_keep_original_decode_location() {
    // Relevant malformed data is a located semantic refusal, distinct from
    // resource exhaustion. It must not disappear as an absent extension.
    let ders = [
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            extra: vec![extension(oid::NAME_CONSTRAINTS, true, &tlv(0x01, &[0xff]))],
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let execution = crate::fixtures::memory();
    let expected = read[0]
        .tbs()
        .extensions()
        .name_constraints(&execution)
        .unwrap_err();
    let context = super::ValidationContext {
        execution: &execution,
        interval: moment(),
        policy: Policy::default(),
        bounds: super::ValidationBounds::default(),
        verifier: &Ecdsa,
        watch: &(),
        recognizer: &(),
    };
    let super::Validation::Rejected(rejected) =
        super::validate(&[&read[0]], Anchor::from_certificate(&read[1]), &context).unwrap()
    else {
        panic!("malformed constraints")
    };
    assert_eq!(rejected.at, Some(super::ConstraintSource::Certificate(0)));
    assert_eq!(
        rejected.reason,
        super::RejectionReason::MalformedExtension {
            extension: oid::NAME_CONSTRAINTS,
            code: expected.code(),
            field: expected.field(),
            offset: expected.offset()
        }
    );
    assert_eq!(execution.used(), 0);
}

#[test]
fn a_chain_to_an_anchor_the_caller_named_is_a_path() {
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let (leaf, intermediate, root) = (&read[0], &read[1], &read[2]);

    let anchors = alloc::vec![Anchor::from_certificate(root)];
    let pool = alloc::vec![intermediate, root];
    let outcome = build(
        leaf,
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.paths().len(), 1);
    assert!(!outcome.is_truncated());
    let path: &Path<'_> = &outcome.paths()[0];
    // The anchor's own certificate is not part of the path (RFC 5280 6.1).
    assert_eq!(path.len(), 2);
    assert!(core::ptr::eq(path.certificates()[0], leaf));
    assert!(core::ptr::eq(path.certificates()[1], intermediate));
    assert!(path.anchor().certificate().is_some());
}

#[test]
fn returned_paths_retain_their_storage_charge() {
    // Search scratch storage may be released on return, but the path and its
    // certificate references remain charged until the caller drops the report.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = [Anchor::from_certificate(&read[1])];
    let execution = crate::fixtures::memory();
    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, Bounds::default(), &execution),
    )
    .unwrap();
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.paths()[0].certificates().len(), 1);
    assert!(
        execution.used()
            >= core::mem::size_of::<Path<'_>>() + core::mem::size_of::<&Certificate<'_>>()
    );
    drop(outcome);
    assert_eq!(execution.used(), 0);
}

#[test]
fn a_verifier_failure_preserves_the_provider_cause() {
    // A failed provider call is neither an invalid signature nor an unsupported
    // algorithm. It must abort build with its exact cause and current domain.
    struct Refusing<'a>(&'a structured_asn1::memory::Memory);
    impl Verify for Refusing<'_> {
        type Error = &'static str;
        fn verify(
            &self,
            _: &crate::AlgorithmIdentifier<'_>,
            _: super::WorkingKey<'_>,
            _: &[u8],
            _: structured_asn1::BitString<'_>,
            execution: &structured_asn1::memory::Memory,
        ) -> core::result::Result<Verified, Self::Error> {
            assert!(execution.same_account(self.0));
            Err("provider execution failed")
        }
    }
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = [Anchor::from_certificate(&read[1])];
    let execution = crate::fixtures::memory();
    let options = super::Context {
        execution: &execution,
        anchors: &anchors,
        interval: moment(),
        bounds: Bounds::default(),
        policy: Policy::default(),
        verifier: &Refusing(&execution),
        watch: &(),
        recognizer: &(),
    };
    let error = build(&read[0], &[], &options).unwrap_err();
    assert!(matches!(
        error,
        super::BuildError::Verification("provider execution failed")
    ));
    assert_eq!(execution.used(), 0);
}

#[test]
fn a_recognizer_failure_preserves_the_policy_cause() {
    // Refusal to execute the scheme's query must not become an unknown critical
    // extension, which would return a conclusive report containing no path.
    struct Refusing<'a>(&'a structured_asn1::memory::Memory);
    impl crate::extension::Recognizer for Refusing<'_> {
        type Error = &'static str;
        fn recognizes(
            &self,
            _: Oid<'_>,
            execution: &structured_asn1::memory::Memory,
        ) -> core::result::Result<bool, Self::Error> {
            assert!(execution.same_account(self.0));
            Err("scheme policy refused")
        }
    }
    let unknown = Oid::from_bytes(&[0x2b, 6, 1, 4, 1, 127]);
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            extra: alloc::vec![extension(unknown, true, &seq(&[]))],
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = [Anchor::from_certificate(&read[1])];
    let execution = crate::fixtures::memory();
    let options = super::Context {
        execution: &execution,
        anchors: &anchors,
        interval: moment(),
        bounds: Bounds::default(),
        policy: Policy::default(),
        verifier: &Ecdsa,
        watch: &(),
        recognizer: &Refusing(&execution),
    };
    let error = build(&read[0], &[], &options).unwrap_err();
    assert!(matches!(
        error,
        super::BuildError::Recognition("scheme policy refused")
    ));
    assert_eq!(execution.used(), 0);
}

#[test]
fn iterative_search_keeps_a_deep_chain_in_order() {
    // A caller may widen the depth bound. Traversal must use accounted heap
    // frames and still return every certificate in target-to-anchor order.
    const DEPTH: usize = 128;
    let names: Vec<_> = (0..=DEPTH)
        .map(|at| alloc::format!("Authority {at:04}"))
        .collect();
    let ders: Vec<_> = (0..=DEPTH)
        .map(|at| {
            Mint {
                subject: &names[at],
                issuer: &names[(at + 1).min(DEPTH)],
                key: 1,
                signer: 1,
                authority: Authority::Unlimited,
                ..Mint::default()
            }
            .build()
        })
        .collect();
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let pool: Vec<_> = read[1..DEPTH].iter().collect();
    let anchors = [Anchor::from_certificate(&read[DEPTH])];
    let execution = crate::fixtures::memory();
    let bounds = Bounds {
        depth: DEPTH,
        edges: DEPTH * DEPTH + DEPTH,
        work: 10_000_000,
        ..Bounds::default()
    };
    let outcome = build(&read[0], &pool, &context(&anchors, bounds, &execution)).unwrap();
    assert_eq!(outcome.truncated(), None);
    assert_eq!(outcome.paths().len(), 1);
    let certificates = outcome.paths()[0].certificates();
    assert_eq!(certificates.len(), DEPTH);
    for (actual, expected) in certificates.iter().zip(&read[..DEPTH]) {
        assert!(core::ptr::eq(*actual, expected));
    }
    drop(outcome);
    assert_eq!(execution.used(), 0);
}

#[test]
fn a_root_the_caller_did_not_name_ends_nothing() {
    // A self-signed certificate in the pool is a certificate like any other.
    // Reaching one proves nothing about trust, and the trust context is what
    // says which keys a path may end at.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let pool = alloc::vec![&read[1]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&[], Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert!(outcome.paths().is_empty());
}

/// A leaf, an intermediate and a root, which is the shape most of the tests
/// below vary one thing in.
fn chain(intermediate: Authority, usage: Option<u8>) -> Vec<Vec<u8>> {
    alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            authority: intermediate,
            usage,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ]
}

#[test]
fn an_issuer_that_does_not_say_it_issues_certificates_is_not_one() {
    // A certificate that carries no basic constraints, or carries them
    // without the authority bit, has not been given the right to issue what
    // sits below it (RFC 5280 6.1.4 (k)).
    for authority in [Authority::Absent, Authority::Below(0)] {
        let ders = chain(authority, None);
        let parser = Parser::der(crate::fixtures::memory());
        let read = parse(&parser, &ders);
        let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
        let pool = alloc::vec![&read[1]];

        let outcome = build(
            &read[0],
            &pool,
            &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
        )
        .expect("a budget this test does not spend");
        if authority == Authority::Absent {
            assert!(outcome.paths().is_empty());
        } else {
            // Below(0) is an authority that allows nothing under it, which
            // is the next test's subject: here it is only not Absent.
            assert!(outcome.paths().is_empty() || outcome.paths().len() == 1);
        }
    }
}

#[test]
fn an_authority_that_allows_nothing_below_it_ends_the_path_there() {
    // A path length of zero says no certificate may sit between this
    // authority and the one it issued (RFC 5280 6.1.4 (m)), so a leaf under
    // an intermediate under it is one certificate too many.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Middle",
            key: 1,
            signer: 4,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Middle",
            issuer: "Intermediate",
            key: 4,
            signer: 2,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            authority: Authority::Below(0),
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[3])];
    let pool = alloc::vec![&read[1], &read[2]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert!(outcome.paths().is_empty());

    // The same chain without that limit is a path, so what refused it above
    // is the limit and not the shape.
    let ders = alloc::vec![
        ders[0].clone(),
        ders[1].clone(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            authority: Authority::Below(1),
            ..Mint::default()
        }
        .build(),
        ders[3].clone(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[3])];
    let pool = alloc::vec![&read[1], &read[2]];
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
}

#[test]
fn an_issuer_whose_key_is_not_for_signing_certificates_is_not_one() {
    // Where a certificate says what its key is for, signing certificates has
    // to be among it (RFC 5280 6.1.4 (n)). The first bit of the key usage is
    // the digital signature; the sixth is signing certificates.
    let signing_only = chain(Authority::Unlimited, Some(0b1000_0000));
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &signing_only);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert!(outcome.paths().is_empty());

    let allowed = chain(Authority::Unlimited, Some(0b0000_0100));
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &allowed);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
}

/// The key of the authority sitting at one place in the cross-certified set
/// below, which has to be distinct everywhere: two authorities holding one
/// key are one authority, and the paths through them are one path.
fn cross_key(level: usize, at: u8) -> u8 {
    10 + u8::try_from(level).expect("a level of this test") * 8 + at
}

/// A pool where the authorities at each level all share one name and hold
/// different keys, and each of them was certified by every authority at the
/// level above.
///
/// That is what a cross-certified set is, and why it grows a combinatorial
/// number of paths out of a few certificates: the certificate the level
/// below chose fixes which key is looked for next, and that key was
/// certified as many times as there are authorities above it. Every path
/// here goes through different keys, so none of them is another one spelled
/// differently.
fn cross_certified(levels: usize, width: u8) -> Vec<Vec<u8>> {
    /// The names of the levels, which is what a set of certificates
    /// cross-certifying each other shares.
    const NAMES: [&str; 4] = ["Level0", "Level1", "Level2", "Level3"];

    let mut ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: NAMES[0],
            key: 1,
            signer: cross_key(0, 0),
            ..Mint::default()
        }
        .build(),
    ];
    let mut serial = 1;
    for level in 0..levels {
        let top = level + 1 == levels;
        for mine in 0..width {
            // At the top the only issuer is the anchor, so the loop over
            // parents is one step: a second certificate would differ from
            // the first in nothing but its serial number.
            let parents = if top { 1 } else { width };
            for parent in 0..parents {
                serial += 1;
                ders.push(
                    Mint {
                        subject: NAMES[level],
                        issuer: if top { "Root" } else { NAMES[level + 1] },
                        key: cross_key(level, mine),
                        signer: if top {
                            99
                        } else {
                            cross_key(level + 1, parent)
                        },
                        serial,
                        authority: Authority::Unlimited,
                        ..Mint::default()
                    }
                    .build(),
                );
            }
        }
    }
    ders.push(
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 99,
            signer: 99,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    );
    ders
}

#[test]
fn a_search_that_reached_a_bound_says_which_one() {
    // Every bound is one a certificate set somebody else controls can push
    // the search into, and a report that did not say which was reached
    // would read as "these are all the paths there are".
    let ders = cross_certified(3, 3);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();

    for (bounds, expected) in [
        (
            Bounds {
                paths: 2,
                ..Bounds::default()
            },
            Truncation::Paths,
        ),
        (
            Bounds {
                depth: 2,
                ..Bounds::default()
            },
            Truncation::Depth,
        ),
        (
            Bounds {
                visited: 3,
                ..Bounds::default()
            },
            Truncation::Visited,
        ),
        (
            Bounds {
                edges: 4,
                ..Bounds::default()
            },
            Truncation::Edges,
        ),
        (
            Bounds {
                work: 2_048,
                ..Bounds::default()
            },
            Truncation::Work,
        ),
    ] {
        let outcome = build(
            &read[0],
            &pool,
            &context(&anchors, bounds, &crate::fixtures::memory()),
        )
        .expect("a bound is an answer, not an error");
        assert_eq!(outcome.truncated(), Some(expected), "{bounds:?}");
        assert!(outcome.paths().len() <= bounds.paths);
    }
}

/// A clock that has already run out, which is what a caller hands the search
/// when the person is waiting.
struct Passed;

impl super::Watch for Passed {
    fn out_of_time(&self) -> bool {
        true
    }
}

#[test]
fn a_clock_the_caller_watches_stops_the_search() {
    // There is no clock in this crate, so the bound that measures wall time
    // is the caller's to answer. A search that stops on it says so, and says
    // it was time rather than work.
    let ders = chain(Authority::Unlimited, None);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];
    let outcome = build(
        &read[0],
        &pool,
        &super::Context {
            execution: &crate::fixtures::memory(),
            anchors: &anchors,
            interval: moment(),
            bounds: Bounds::default(),
            policy: Policy::default(),
            verifier: &Ecdsa,
            watch: &Passed,
            recognizer: &(),
        },
    )
    .expect("a clock is an answer, not an error");

    assert_eq!(outcome.truncated(), Some(Truncation::Time));
    assert!(outcome.paths().is_empty());
}

/// How a path can be written down so that two runs can be compared: the
/// serial numbers along it, and the key of the anchor it ends at.
fn spelled(outcome: &super::Outcome<'_>) -> Vec<(Vec<Vec<u8>>, Vec<u8>)> {
    outcome
        .paths()
        .iter()
        .map(|path| {
            (
                path.certificates()
                    .iter()
                    .map(|certificate| certificate.tbs().serial().as_bytes().to_vec())
                    .collect(),
                path.anchor().key().as_bytes().to_vec(),
            )
        })
        .collect()
}

#[test]
fn every_route_a_cross_certified_set_offers_is_shown() {
    // Each authority above the leaf was certified by every authority above
    // it, so there are as many routes as there are ways of choosing one at
    // each level. All of them are real paths, and a report that showed one
    // would be hiding the schemes the others go through.
    let ders = cross_certified(2, 3);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 3);
    assert_eq!(outcome.truncated(), None);
    for path in outcome.paths() {
        assert_eq!(path.len(), 3);
    }
    // Three routes, and no two of them the same one twice: the authority
    // just below the leaf is the same one on all of them, and the one above
    // it holds a different key on each.
    let mut keys: Vec<Vec<u8>> = outcome
        .paths()
        .iter()
        .map(|path| {
            path.certificates()[2]
                .tbs()
                .public_key()
                .as_bytes()
                .to_vec()
        })
        .collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), 3);
}

#[test]
fn an_authority_that_reissued_its_own_certificate_is_one_route() {
    // A rollover leaves two certificates naming the same authority and the
    // same key, and every path through one of them says exactly what the
    // path through the other says. Showing both would tell a reader there
    // are two ways to the anchor when there is one.
    let leaf = Mint {
        subject: "Leaf",
        issuer: "Intermediate",
        key: 1,
        signer: 2,
        ..Mint::default()
    }
    .build();
    let older = Mint {
        subject: "Intermediate",
        issuer: "Root",
        key: 2,
        signer: 3,
        serial: 1,
        authority: Authority::Unlimited,
        validity: ("240101000000Z", "290101000000Z"),
        ..Mint::default()
    }
    .build();
    let newer = Mint {
        subject: "Intermediate",
        issuer: "Root",
        key: 2,
        signer: 3,
        serial: 2,
        authority: Authority::Unlimited,
        validity: ("240102000000Z", "300101000000Z"),
        ..Mint::default()
    }
    .build();
    let root = Mint {
        subject: "Root",
        issuer: "Root",
        key: 3,
        signer: 3,
        authority: Authority::Unlimited,
        ..Mint::default()
    }
    .build();

    let ders = alloc::vec![leaf, older, newer, root];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[3])];
    let pool = alloc::vec![&read[1], &read[2]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
    // Nothing was dropped for want of room: the second spelling was never a
    // second path.
    assert_eq!(outcome.truncated(), None);
}

/// A leaf under one authority whose certificate two different roots issued,
/// which is the shape of a provider recognized under two schemes.
fn recognized_twice() -> Vec<Vec<u8>> {
    alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "RootOne",
            key: 2,
            signer: 3,
            serial: 1,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "RootTwo",
            key: 2,
            signer: 4,
            serial: 2,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "RootOne",
            issuer: "RootOne",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "RootTwo",
            issuer: "RootTwo",
            key: 4,
            signer: 4,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ]
}

#[test]
fn a_path_to_each_anchor_the_caller_named_is_shown() {
    // The same authority, certified by two roots. Which of them a reader
    // cares about depends on the scheme they are asking under, so both are
    // answers and neither replaces the other.
    let ders = recognized_twice();
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![
        Anchor::from_certificate(&read[3]),
        Anchor::from_certificate(&read[4]),
    ];
    let pool = alloc::vec![&read[1], &read[2]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 2);
    let mut anchors: Vec<Vec<u8>> = outcome
        .paths()
        .iter()
        .map(|path| path.anchor().key().as_bytes().to_vec())
        .collect();
    anchors.sort_unstable();
    anchors.dedup();
    assert_eq!(anchors.len(), 2);
}

#[test]
fn a_path_that_says_something_else_takes_the_place_of_a_repeat() {
    // Three routes to one anchor and one to another, with room for two.
    // What is worth keeping is one of each, and the search finds the three
    // repeats first: keeping what arrived first would answer with two paths
    // to one anchor and never mention the other scheme at all.
    let mut ders = cross_certified(2, 3);
    let root = ders.pop().expect("the root");
    ders.push(
        // A second anchor, which certified the last of the authorities
        // above the leaf. The route to it is found after the room is full.
        Mint {
            subject: "Level1",
            issuer: "RootTwo",
            key: cross_key(1, 2),
            signer: 98,
            serial: 100,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    );
    let anchor_ders = alloc::vec![
        root,
        Mint {
            subject: "RootTwo",
            issuer: "RootTwo",
            key: 98,
            signer: 98,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let roots = parse(&parser, &anchor_ders);
    let anchors = alloc::vec![
        Anchor::from_certificate(&roots[0]),
        Anchor::from_certificate(&roots[1]),
    ];
    let pool: Vec<&Certificate<'_>> = read[1..].iter().collect();

    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                paths: 2,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.paths().len(), 2);
    assert_eq!(outcome.truncated(), Some(Truncation::Paths));
    let mut keys: Vec<Vec<u8>> = outcome
        .paths()
        .iter()
        .map(|path| path.anchor().key().as_bytes().to_vec())
        .collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), 2, "one path to each anchor, not two to one");
}

#[test]
fn two_certificates_that_issued_each_other_do_not_send_the_search_round() {
    // A pair of authorities each holding the other's certificate is a cycle,
    // and following it would never end. A certificate appears once in a
    // path (RFC 5280 6.1), which is what stops it.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "One",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "One",
            issuer: "Two",
            key: 2,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Two",
            issuer: "One",
            key: 3,
            signer: 2,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let pool = alloc::vec![&read[1], &read[2]];

    // Nothing the caller named, so the cycle leads nowhere and the search
    // ends rather than turning.
    let outcome = build(
        &read[0],
        &pool,
        &context(&[], Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert!(outcome.paths().is_empty());
    assert_eq!(outcome.truncated(), None);

    // The same cycle with one of the two named as an anchor is a path, and
    // still one: the way round is not a second one.
    let anchors = alloc::vec![Anchor::new(
        read[2].tbs().subject(),
        read[2].tbs().public_key()
    )];
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
}

#[test]
fn a_rollover_link_between_two_keys_of_one_name_is_a_path() {
    // An authority rolling its key over certifies the new key with the old
    // one, and both keys are anchors while the change is in flight. That
    // certificate names itself as its own issuer without being self-signed,
    // and it is the only route from the new key to the old anchor: skipping
    // every certificate whose names match loses it.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Authority",
            key: 1,
            signer: 5,
            ..Mint::default()
        }
        .build(),
        // The new key, certified by the old one. Self-issued by name, and
        // signed by somebody else.
        Mint {
            subject: "Authority",
            issuer: "Authority",
            key: 5,
            signer: 6,
            serial: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        // The old key's own certificate, which is the anchor.
        Mint {
            subject: "Authority",
            issuer: "Authority",
            key: 6,
            signer: 6,
            serial: 4,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    // Both keys are trusted, which is what a rollover means.
    let anchors = alloc::vec![
        Anchor::from_certificate(&read[1]),
        Anchor::from_certificate(&read[2]),
    ];
    let pool = alloc::vec![&read[1], &read[2]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");

    // Straight to the new key, and through the rollover link to the old one.
    assert_eq!(outcome.paths().len(), 2);
    let mut lengths: Vec<usize> = outcome.paths().iter().map(Path::len).collect();
    lengths.sort_unstable();
    assert_eq!(lengths, alloc::vec![1, 2]);

    // RFC 5280 §6.1.4(l): the self-issued rollover consumes no intermediate
    // allowance. Expose the count for caller-owned anchor constraints too.
    let execution = crate::fixtures::memory();
    let validation = super::ValidationContext {
        execution: &execution,
        interval: moment(),
        policy: Policy::default(),
        bounds: super::ValidationBounds::default(),
        verifier: &Ecdsa,
        watch: &(),
        recognizer: &(),
    };
    let super::Validation::Accepted(facts) =
        super::validate(&[&read[0], &read[1]], anchors[1], &validation).unwrap()
    else {
        panic!("the rollover is accepted against the old anchor")
    };
    assert_eq!(facts.non_self_issued_intermediates, 0);
}

#[test]
fn a_pool_holding_one_certificate_twice_spends_for_one() {
    // Repeating a certificate does not make it two, and a pool somebody else
    // wrote may repeat one that leads nowhere as many times as it likes. If
    // each copy is charged, the copies spend the search before the issuer
    // that does lead somewhere is reached.
    let ders = chain(Authority::Unlimited, None);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];

    // The one intermediate, written out several times over, and a bound with
    // room for a couple of candidates.
    let pool = alloc::vec![&read[1], &read[1], &read[1], &read[1], &read[1]];
    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                edges: 4,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn a_pool_built_to_explode_answers_inside_its_bounds() {
    // Four levels of four cross-certified authorities offer more routes
    // than a browser will ever be asked to show. What matters is that the
    // search ends, holds no more than the caller allowed, and says that
    // what it holds is not all there was.
    let ders = cross_certified(4, 4);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();

    let bounds = Bounds::default();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, bounds, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    assert!(outcome.paths().len() <= bounds.paths);
    assert!(outcome.is_truncated());
    for path in outcome.paths() {
        assert_eq!(path.len(), 5);
    }
}

#[test]
fn a_budget_that_runs_out_leaves_behind_what_it_had_found() {
    // Running out is not a verdict about the certificates: the paths that
    // were settled before the budget went are still paths, and the answer
    // is those plus the fact that there may be more.
    let ders = cross_certified(3, 3);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();

    // Enough for the first route and its checks, and not enough for all
    // nine of them.
    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                work: 12_000,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a spent budget is an answer, not an error");

    assert!(!outcome.paths().is_empty(), "what was found is still shown");
    assert_eq!(outcome.truncated(), Some(Truncation::Work));

    // And the whole search, for comparison, finds more than that.
    let whole = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert!(whole.paths().len() > outcome.paths().len());
}

#[test]
fn the_same_pool_gives_the_same_paths_twice() {
    // Nothing in the search depends on anything but the certificates, their
    // order and the caller's question. A report made today has to be the
    // report made again tomorrow.
    let ders = cross_certified(3, 3);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();

    let first = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    let second = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(spelled(&first), spelled(&second));
}

/// The chain of the name-constraint tests: a leaf under an authority that
/// carries the given constraints, under a root that carries its own.
fn constrained(intermediate: Option<Vec<u8>>, root: Option<Vec<u8>>) -> Vec<Vec<u8>> {
    alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            authority: Authority::Unlimited,
            extra: intermediate.into_iter().collect(),
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            extra: root.into_iter().collect(),
            ..Mint::default()
        }
        .build(),
    ]
}

/// A name-constraints extension permitting one domain and nothing else.
///
/// A domain rather than a directory subtree, because the authorities of
/// these chains carry no domain name of their own: a directory region would
/// hold every certificate below it to a subtree of the leaf's own name,
/// which is not what the test is about.
fn permitting(domain: &str) -> Vec<u8> {
    extension(
        oid::NAME_CONSTRAINTS,
        true,
        &seq(&[tlv(0xa0, &seq(&[tlv(0x82, domain.as_bytes())]))]),
    )
}

/// A subject alternative name of one domain name.
fn also_known_as(host: &str) -> Vec<u8> {
    extension(
        oid::SUBJECT_ALT_NAME,
        false,
        &seq(&[tlv(0x82, host.as_bytes())]),
    )
}

/// How many paths the constrained chain offers, where the leaf is known by
/// one host name.
fn paths_under(intermediate: Option<Vec<u8>>, root: Option<Vec<u8>>, host: &str) -> usize {
    let mut ders = constrained(intermediate, root);
    ders[0] = Mint {
        subject: "Leaf",
        issuer: "Intermediate",
        key: 1,
        signer: 2,
        extra: alloc::vec![also_known_as(host)],
        ..Mint::default()
    }
    .build();

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];
    build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend")
    .paths()
    .len()
}

#[test]
fn a_name_outside_what_its_authority_allowed_is_not_a_path() {
    // The authority said what it may certify. A certificate naming
    // something else was not certified by it in any sense a path can
    // report (RFC 5280 6.1.3 (b)).
    let permitted = Some(permitting("example.com"));
    assert_eq!(paths_under(permitted.clone(), None, "host.example.com"), 1);
    assert_eq!(paths_under(permitted, None, "host.evil.net"), 0);
}

#[test]
fn what_the_anchor_allows_binds_the_path_below_it() {
    // A trust context that published a constrained root published the
    // constraint with it. The anchor's own certificate is not a step in the
    // path, and what it says about the names below it is still what it
    // says.
    let permitted = Some(permitting("example.com"));
    assert_eq!(paths_under(None, permitted.clone(), "host.example.com"), 1);
    assert_eq!(paths_under(None, permitted, "host.evil.net"), 0);
}

/// A policy of these tests, which is an identifier no profile gives a
/// meaning to: what matters is that a path carries it.
const HOUSE_POLICY: Oid<'static> = Oid::from_bytes(&[0x2a, 0x03, 0x04, 0x01]);

/// Another, for the tests that are about telling two apart.
const OTHER_POLICY: Oid<'static> = Oid::from_bytes(&[0x2a, 0x03, 0x04, 0x02]);

/// A certificate policies extension naming one policy.
fn issued_under(policy: Oid<'_>) -> Vec<u8> {
    extension(
        oid::CERTIFICATE_POLICIES,
        false,
        &seq(&[seq(&[oid_of(policy)])]),
    )
}

/// A policy constraints extension demanding that the path name a policy
/// from the next certificate down.
fn demanding_a_policy() -> Vec<u8> {
    extension(oid::POLICY_CONSTRAINTS, true, &seq(&[tlv(0x80, &[0x00])]))
}

/// The chain of the policy tests: a leaf and an authority each carrying
/// whatever the test gives them.
fn under_policies(leaf: Vec<Vec<u8>>, intermediate: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            extra: leaf,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            authority: Authority::Unlimited,
            extra: intermediate,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ]
}

#[test]
fn the_policy_the_authorities_agreed_on_travels_with_the_path() {
    // What a certificate was issued under is not a property of the
    // certificate: it is what is left after every authority above it has
    // said whether it agrees.
    let ders = under_policies(
        alloc::vec![issued_under(HOUSE_POLICY)],
        alloc::vec![issued_under(HOUSE_POLICY)],
    );
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.paths()[0].policies(), &[HOUSE_POLICY]);
}

#[test]
fn an_authority_that_demands_a_policy_is_not_answered_by_a_path_without_one() {
    // The demand is written into a certificate, and a path that does not
    // meet it is not a path (RFC 5280 6.1.4 (i) and 6.1.5).
    let ders = under_policies(alloc::vec![], alloc::vec![demanding_a_policy()]);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert!(outcome.paths().is_empty());

    // The same chain whose leaf names a policy the authority also names is
    // a path, so what refused it above was the demand and not the shape.
    let ders = under_policies(
        alloc::vec![issued_under(HOUSE_POLICY)],
        alloc::vec![issued_under(HOUSE_POLICY), demanding_a_policy()],
    );
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
}

#[test]
fn a_caller_that_demands_a_policy_gets_no_path_from_certificates_naming_none() {
    // The same demand, made by the caller rather than by a certificate.
    let ders = under_policies(alloc::vec![], alloc::vec![]);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];

    let demanding = Policy {
        explicit: true,
        ..Policy::default()
    };
    let outcome = build(
        &read[0],
        &pool,
        &asking(
            &anchors,
            Bounds::default(),
            demanding,
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");
    assert!(outcome.paths().is_empty());

    // And with nothing demanded, the same certificates are a path that
    // names no policy.
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.paths()[0].policies(), []);
}

#[test]
fn a_policy_bound_of_nothing_leaves_no_room_to_work_a_path_out() {
    // A caller allowing the working out nothing at all has not asked for a
    // path settled without it. Building the node every path starts from
    // anyway spends a slot the bound does not have, and the answer comes
    // back as though the bound had been obeyed.
    let ders = chain(Authority::Unlimited, None);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];

    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                policies: 0,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a bound is an answer, not an error");
    assert!(outcome.paths().is_empty());
    assert_eq!(outcome.truncated(), Some(Truncation::Policies));
}

#[test]
fn a_bound_that_ends_the_search_is_the_one_the_answer_names() {
    // Some bounds end a branch and some end the search. A branch that could
    // not go deeper is worth saying, but it must not stand in for the bound
    // that actually stopped everything: a report naming the depth while the
    // search ran on past the count of certificates the caller allowed says
    // both the wrong reason and the wrong amount of work.
    let ders = cross_certified(3, 3);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();

    // Deep enough that a branch reaches the depth bound early, and a count
    // of entered certificates that the search passes shortly after.
    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                depth: 2,
                visited: 3,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a bound is an answer, not an error");

    assert_eq!(outcome.truncated(), Some(Truncation::Visited));
}

#[test]
fn a_depth_of_none_leaves_no_path_to_return() {
    // A caller that allows no certificates has asked for no path. Settling
    // the target first and marking the depth afterwards returns one anyway,
    // which is a path outside the bound reported as though the bound held.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];

    let outcome = build(
        &read[0],
        &[],
        &context(
            &anchors,
            Bounds {
                depth: 0,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a bound is an answer, not an error");
    assert!(outcome.paths().is_empty());
    assert_eq!(outcome.truncated(), Some(Truncation::Depth));

    // One certificate of room is enough for it, so what refused it above was
    // the bound and not the chain.
    let outcome = build(
        &read[0],
        &[],
        &context(
            &anchors,
            Bounds {
                depth: 1,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
}

#[test]
fn an_anchors_own_identity_cross_signed_by_another_is_still_a_link() {
    // A provider recognized under two schemes has its identity certified by
    // both. The certificate that publishes one anchor is not a step in a
    // path to that anchor, but the same identity cross-signed by the other
    // anchor is an ordinary intermediate: skipping every certificate that
    // shares an anchor's name and key loses the whole second scheme, and
    // says nothing about having lost it.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Provider",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        // The provider's own self-signed identity, which is anchor one.
        Mint {
            subject: "Provider",
            issuer: "Provider",
            key: 2,
            signer: 2,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        // The same identity, certified by the other scheme's root.
        Mint {
            subject: "Provider",
            issuer: "Other",
            key: 2,
            signer: 4,
            serial: 7,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Other",
            issuer: "Other",
            key: 4,
            signer: 4,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![
        Anchor::from_certificate(&read[1]),
        Anchor::from_certificate(&read[3]),
    ];
    let pool = alloc::vec![&read[1], &read[2]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");

    // One path straight to the provider's own anchor, and one through its
    // cross-certificate to the other scheme's.
    assert_eq!(outcome.paths().len(), 2);
    let mut anchors: Vec<Vec<u8>> = outcome
        .paths()
        .iter()
        .map(|path| path.anchor().key().as_bytes().to_vec())
        .collect();
    anchors.sort_unstable();
    anchors.dedup();
    assert_eq!(anchors.len(), 2);
}

#[test]
fn one_identity_issued_under_two_policies_is_two_answers() {
    // The same authority, re-issued with a different policy, is the same
    // route and not the same answer. Dropping the second as a repeat throws
    // away exactly the distinct policy outcome that showing several paths
    // exists to preserve, and says nothing about having thrown it away.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            extra: alloc::vec![issued_under(oid::ANY_POLICY)],
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            serial: 1,
            authority: Authority::Unlimited,
            extra: alloc::vec![issued_under(HOUSE_POLICY)],
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            serial: 2,
            authority: Authority::Unlimited,
            extra: alloc::vec![issued_under(OTHER_POLICY)],
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[3])];
    let pool = alloc::vec![&read[1], &read[2]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.paths().len(), 2);
    let mut policies: Vec<Vec<u8>> = outcome
        .paths()
        .iter()
        .flat_map(super::Path::policies)
        .map(|policy| policy.as_bytes().to_vec())
        .collect();
    policies.sort_unstable();
    assert_eq!(
        policies,
        alloc::vec![
            HOUSE_POLICY.as_bytes().to_vec(),
            OTHER_POLICY.as_bytes().to_vec()
        ]
    );
}

#[test]
fn a_policy_restriction_that_cannot_be_read_is_not_one_that_is_absent() {
    // A policy extension that is present and does not parse says something
    // this run could not read. Reading it as absent lets a certificate into
    // a path without the restriction it carries, which is the one reading
    // that is certainly wrong. It is not marked critical here, so nothing
    // else refuses it.
    let malformed = extension(
        oid::POLICY_CONSTRAINTS,
        false,
        &cat(&[seq(&[tlv(0x80, &[0x00])]), vec![0x00]]),
    );
    let ders = under_policies(alloc::vec![], alloc::vec![malformed]);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];

    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert!(outcome.paths().is_empty());

    // The same chain whose restriction reads is a path, so what refused it
    // above was the unreadable value and not the shape.
    let ders = under_policies(
        alloc::vec![],
        alloc::vec![extension(
            oid::POLICY_CONSTRAINTS,
            false,
            &seq(&[tlv(0x80, &[0x05])]),
        )],
    );
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
}

#[test]
fn a_depth_bound_nothing_could_have_gone_past_is_not_truncation() {
    // Reaching the depth bound is only worth reporting where the bound is
    // what stopped the search from going further. A target issued directly
    // by an anchor, with nothing in the pool, has nowhere further to go at
    // any depth: an answer that returns the one path there is and calls
    // itself truncated tells a reader to go looking for paths that do not
    // exist, and does it on every ordinary single-certificate check.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];

    let outcome = build(
        &read[0],
        &[],
        &context(
            &anchors,
            Bounds {
                depth: 1,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn a_path_that_takes_a_repeats_place_still_lands_in_the_order_it_was_found() {
    // Paths of one length are returned in the order the caller's inputs put
    // them in, which is what a reader relies on to know that reading the
    // first is reading the one the caller preferred. When the room is full
    // and a path saying something new arrives, it takes the place of a
    // repeat: putting it into that slot puts it in front of paths that were
    // found earlier, and the sort is by length alone and cannot repair it.
    //
    // Four routes of one length: two to the first anchor, saying the same
    // thing through different authorities, and one each to the second and
    // the third.
    let mut ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Mid",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
    ];
    for upper in [31, 32, 33, 34] {
        ders.push(
            Mint {
                subject: "Mid",
                issuer: "Up",
                key: 2,
                signer: upper,
                authority: Authority::Unlimited,
                serial: u32::from(upper),
                ..Mint::default()
            }
            .build(),
        );
    }
    for (upper, root, signer) in [
        (31, "RootA", 41),
        (32, "RootA", 41),
        (33, "RootB", 42),
        (34, "RootC", 43),
    ] {
        ders.push(
            Mint {
                subject: "Up",
                issuer: root,
                key: upper,
                signer,
                authority: Authority::Unlimited,
                serial: u32::from(upper),
                ..Mint::default()
            }
            .build(),
        );
    }
    let roots: Vec<Vec<u8>> = [("RootA", 41), ("RootB", 42), ("RootC", 43)]
        .into_iter()
        .map(|(name, key)| {
            Mint {
                subject: name,
                issuer: name,
                key,
                signer: key,
                authority: Authority::Unlimited,
                ..Mint::default()
            }
            .build()
        })
        .collect();

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let read_roots = parse(&parser, &roots);
    let anchors: Vec<Anchor<'_>> = read_roots.iter().map(Anchor::from_certificate).collect();
    let pool: Vec<&Certificate<'_>> = read[1..].iter().collect();

    // Room for three, so the fourth route arrives with none and takes the
    // place of the second route to the first anchor.
    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                paths: 3,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.truncated(), Some(Truncation::Paths));
    let order: Vec<Vec<u8>> = outcome
        .paths()
        .iter()
        .map(|path| {
            path.certificates()
                .last()
                .expect("a path holds certificates")
                .tbs()
                .serial()
                .as_bytes()
                .to_vec()
        })
        .collect();
    assert_eq!(
        order,
        alloc::vec![alloc::vec![31], alloc::vec![33], alloc::vec![34]]
    );
}

/// The chain of the name-cost test: a leaf under one authority, beside
/// decoys whose names are as long and differ only at the end, so that every
/// candidate edge compares two names all the way through.
fn under_names_of(width: usize) -> Vec<Vec<u8>> {
    let base = "A".repeat(width);
    let mut ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: &base,
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: &base,
            issuer: "Root",
            key: 2,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    // The decoys differ from the authority's name only in a last letter, so
    // that comparing one against the leaf's issuer folds both values all the
    // way through rather than parting at the first character.
    for decoy in 0..20u8 {
        let mut name = base.clone();
        name.push(char::from(b'B' + decoy));
        ders.push(
            Mint {
                subject: &name,
                issuer: "Nowhere",
                key: 4,
                signer: 4,
                serial: u32::from(decoy) + 2,
                authority: Authority::Unlimited,
                ..Mint::default()
            }
            .build(),
        );
    }
    ders.push(
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    );
    ders
}

#[test]
fn comparing_two_long_names_costs_what_comparing_them_costs() {
    // Two names are compared at every candidate edge, and comparing them
    // reads both: the parts are ordered against each other where one holds
    // several attributes, and the values are folded through to the end
    // where they are not byte-identical. A pool somebody else wrote decides
    // how long those names are, so charging a fixed amount for the
    // comparison lets a set of long names buy work and allocations the work
    // bound never sees, however tight the caller set it.
    //
    // One shape, twice: the same leaf, authority and twenty decoys, once
    // with short names and once with names of two thousand characters that
    // differ only at the end. The budget is comfortable for the first.
    let budget = Bounds {
        work: 12_000,
        ..Bounds::default()
    };

    let short = under_names_of(4);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &short);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a budget this shape does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);

    let long = under_names_of(2_000);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &long);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    assert_eq!(outcome.truncated(), Some(Truncation::Work));
}

#[test]
fn a_pool_that_holds_the_target_spends_nothing_on_it() {
    // Holding the target in the pool changes nothing: a certificate appears
    // once in a path, so it can never be its own issuer. Leaving it among
    // the candidates makes that promise false of what the search spends,
    // and a bound tight enough to notice reports the answer as truncated
    // over a candidate that could never have been followed.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];
    let bounds = Bounds {
        edges: 1,
        ..Bounds::default()
    };

    // One edge is exactly the anchor this target chains to, and an empty
    // pool spends nothing further.
    let empty = build(
        &read[0],
        &[],
        &context(&anchors, bounds, &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(empty.paths().len(), 1);
    assert_eq!(empty.truncated(), None);

    // The same question, asked with the target among the candidates, is the
    // same question and has to have the same answer.
    let pool = alloc::vec![&read[0]];
    let held = build(
        &read[0],
        &pool,
        &context(&anchors, bounds, &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(held.paths().len(), 1);
    assert_eq!(held.truncated(), None);
}

/// A name-constraints extension permitting these locations by host, in the
/// order written, so that a name matching the last is compared against all
/// of them.
fn permitting_locations(hosts: &[&str]) -> Vec<u8> {
    let subtrees: Vec<Vec<u8>> = hosts
        .iter()
        .map(|host| seq(&[tlv(0x86, host.as_bytes())]))
        .collect();
    extension(
        oid::NAME_CONSTRAINTS,
        true,
        &seq(&[tlv(0xa0, &cat(&subtrees))]),
    )
}

/// A subject alternative name of one location.
fn located_at(location: &str) -> Vec<u8> {
    extension(
        oid::SUBJECT_ALT_NAME,
        false,
        &seq(&[tlv(0x86, location.as_bytes())]),
    )
}

/// The constrained chain, where the leaf is known by one location whose
/// authority carries this much user information in front of the host.
fn located_under(width: usize) -> Vec<Vec<u8>> {
    let hosts: Vec<alloc::string::String> = (0..16u8)
        .map(|which| alloc::format!("h{which}.example.com"))
        .chain(core::iter::once(alloc::string::String::from(
            "host.example.com",
        )))
        .collect();
    let borrowed: Vec<&str> = hosts.iter().map(alloc::string::String::as_str).collect();
    let mut ders = constrained(Some(permitting_locations(&borrowed)), None);
    let location = alloc::format!("https://{}@host.example.com/", "a".repeat(width));
    ders[0] = Mint {
        subject: "Leaf",
        issuer: "Intermediate",
        key: 1,
        signer: 2,
        extra: alloc::vec![located_at(&location)],
        ..Mint::default()
    }
    .build();
    ders
}

#[test]
fn reading_a_location_out_of_a_long_authority_costs_what_it_reads() {
    // Finding where a location's host begins reads the authority from the
    // front, once for the name however many regions it is then compared
    // against. How long that authority is is a certificate's to decide, so
    // reading it has to cost what reading it costs: charged a fixed amount,
    // one certificate buys the whole scan while the bound barely moves.
    //
    // One shape twice, seventeen regions each, with the matching one last
    // so that all of them are compared. The budget is comfortable for the
    // short authority.
    let budget = Bounds {
        work: 20_000,
        ..Bounds::default()
    };

    let short = located_under(4);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &short);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a budget this shape does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);

    let long = located_under(400_000);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &long);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    assert_eq!(outcome.truncated(), Some(Truncation::Work));
}

#[test]
fn a_search_with_no_anchor_answers_without_spending_anything() {
    // A path ends at an anchor the caller trusts, so a caller who named
    // none has asked a question whose complete answer is no paths. Reading
    // the pool to find that out spends a budget on work that cannot change
    // the answer, and a bound reached while doing it reports the one
    // conclusive answer there is as though something had been left out.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let pool: Vec<&Certificate<'_>> = read[1..].iter().collect();

    // A budget too small to read even one candidate, which is what makes
    // the difference visible: reading the pool at all reports Work.
    let outcome = build(
        &read[0],
        &pool,
        &context(
            &[],
            Bounds {
                work: 1,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("no anchor is an answer, not an error");

    assert!(outcome.paths().is_empty());
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn an_anchor_the_caller_named_twice_is_one_anchor() {
    // Two anchors with the same name and the same key are one anchor, and
    // the paths to them are one path. A trust context assembled from
    // several stores hands the same root over more than once, and charging
    // an edge for each copy spends the search on candidates that were
    // already settled, so a bound reports the answer as truncated over
    // nothing that was left out.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let bounds = Bounds {
        edges: 1,
        ..Bounds::default()
    };

    // One edge is exactly the one anchor this target chains to.
    let once = alloc::vec![Anchor::from_certificate(&read[1])];
    let outcome = build(
        &read[0],
        &[],
        &context(&once, bounds, &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);

    // The same anchor named twice is the same question and has to have the
    // same answer.
    let twice = alloc::vec![
        Anchor::from_certificate(&read[1]),
        Anchor::from_certificate(&read[1]),
    ];
    let outcome = build(
        &read[0],
        &[],
        &context(&twice, bounds, &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn an_anchors_own_certificate_is_not_a_path_to_that_anchor() {
    // "When the trust anchor is provided in the form of a self-signed
    // certificate, this self-signed certificate is not included as part of
    // the prospective certification path" (RFC 5280 6.1). Asked about that
    // certificate itself, the search settled it against the anchor it
    // publishes and answered with a path of one certificate: the anchor,
    // reported as issued by itself. That is the anchor named twice rather
    // than a chain of authority, and it is the same rule already kept for
    // every other position in a path.
    let ders = alloc::vec![
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[0])];

    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");

    assert!(outcome.paths().is_empty());
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn anchors_of_one_name_spelled_two_ways_are_one_anchor() {
    // Two stores can supply one key under a name written two ways, and a
    // distinguished name is compared by what it says rather than by how it
    // was encoded. Folding them by their bytes leaves both, and each then
    // costs an edge: placed in front of a different key that does verify,
    // they can spend a tight bound before it is reached and the path that
    // exists is not returned.
    //
    // Supplied as names and keys rather than as certificates, so that the
    // spelling is the only thing that differs between the two: anchors
    // published in different certificates are not one anchor whatever their
    // names say, since each certificate constrains the names below it.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 4,
            ..Mint::default()
        }
        .build(),
        // One key under two spellings of one name.
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "ROOT",
            issuer: "ROOT",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        // The key the leaf was actually signed with, named last.
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 4,
            signer: 4,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![
        Anchor::new(read[1].tbs().subject(), read[1].tbs().public_key()),
        Anchor::new(read[2].tbs().subject(), read[2].tbs().public_key()),
        Anchor::new(read[3].tbs().subject(), read[3].tbs().public_key()),
    ];

    // Room for two candidate anchors: the folded pair counts as one, and the
    // key that verifies is the second.
    let outcome = build(
        &read[0],
        &[],
        &context(
            &anchors,
            Bounds {
                edges: 2,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);
}

/// A chain whose leaf carries names of this width on both sides, which is
/// what the comparison that asks whether it issued itself reads.
fn issued_to_names_of(width: usize) -> Vec<Vec<u8>> {
    let base = "A".repeat(width);
    alloc::vec![
        Mint {
            subject: &base,
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ]
}

#[test]
fn asking_whether_a_certificate_issued_itself_costs_what_it_reads() {
    // Whether a certificate names itself as its own issuer is two names
    // compared, and comparing them reads both. A document decides how long
    // those names are, so asking the question for nothing lets one
    // certificate buy the ordering and folding of two names the bound never
    // sees, and asks it after the caller's stopping condition has already
    // been reached.
    //
    // One shape twice, with a budget comfortable for the short names.
    let budget = Bounds {
        work: 3_000,
        ..Bounds::default()
    };

    let short = issued_to_names_of(4);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &short);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];
    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a budget this shape does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);

    // One required comparison alone exceeds the budget. This does not rely
    // on repeating an anchor-identity comparison for a non-self-issued target.
    let long = issued_to_names_of(100_000);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &long);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];
    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    assert_eq!(outcome.truncated(), Some(Truncation::Work));
}

#[test]
fn anchors_of_one_key_published_differently_are_not_one_anchor() {
    // An anchor supplied as a certificate binds the names below it to what
    // that certificate constrains; the same name and key supplied without
    // one binds nothing. They are the same key and two statements of trust,
    // so folding them by name and key alone keeps whichever came first and
    // lets the order of the caller's list decide whether a path exists.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            extra: alloc::vec![also_known_as("host.other.test")],
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            extra: alloc::vec![permitting("example.com")],
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);

    // The same key, once as the constrained certificate it was published in
    // and once as a bare name and key.
    let published = Anchor::from_certificate(&read[1]);
    let bare = Anchor::new(read[1].tbs().subject(), read[1].tbs().public_key());

    // The leaf is known by a host outside what the certificate permits, so
    // the bare anchor admits it and the published one does not. Either way
    // round, the caller trusts that key without a constraint, and the path
    // exists.
    let first = alloc::vec![published, bare];
    let outcome = build(
        &read[0],
        &[],
        &context(&first, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1, "constrained named first");

    let second = alloc::vec![bare, published];
    let outcome = build(
        &read[0],
        &[],
        &context(&second, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1, "bare named first");
}

#[test]
fn a_target_the_interval_does_not_hold_answers_without_reading_the_inputs() {
    // A path is built for a moment, and a target the caller's interval does
    // not hold is not one any path can end at, whatever the pool or the
    // anchors say. Folding those inputs to find that out spends a budget on
    // work that cannot change the answer, and a bound reached while doing
    // it reports the one conclusive answer there is as though something had
    // been left out.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            validity: ("200101000000Z", "210101000000Z"),
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];
    let pool: Vec<&Certificate<'_>> = read[1..].iter().collect();

    // A budget too small to fold even one input, which is what makes the
    // difference visible: reading them at all reports Work.
    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                work: 1,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("an expired target is an answer, not an error");

    assert!(outcome.paths().is_empty());
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn a_target_claiming_to_be_an_authority_and_naming_nobody_is_not_a_path() {
    // "If the subject is a CA ... then the subject field MUST be populated
    // with a non-empty distinguished name matching the contents of the
    // issuer field ... in all certificates issued by the subject CA"
    // (RFC 5280 4.1.2.6). A certificate may carry its identity in the
    // alternative names and leave the subject empty, but not while claiming
    // to be an authority: there is then no name for anything below it to be
    // issued under.
    //
    // The certificates a path is built through are held to what they say
    // about issuing. The one the question is about is not, because it need
    // not be an authority at all, so this went unasked of it and a target
    // that claimed to be one with no name was returned as a path.
    let parts = CertificateParts {
        serial: int(1),
        inner_algorithm: seq(&[oid_of(ECDSA_SHA256)]),
        outer_algorithm: seq(&[oid_of(ECDSA_SHA256)]),
        issuer: named("Root"),
        subject: seq(&[]),
        validity: seq(&[utc_time("240101000000Z"), utc_time("300101000000Z")]),
        key: public(&key(1)),
        extensions: Some(seq(&[
            extension(oid::BASIC_CONSTRAINTS, true, &seq(&[boolean(true)])),
            // Critical, which is what the profile asks of a certificate
            // carrying its identity here rather than in the subject.
            extension(
                oid::SUBJECT_ALT_NAME,
                true,
                &seq(&[tlv(0x82, b"host.example.com")]),
            ),
        ])),
        signature: bits(&[]),
        ..CertificateParts::default()
    };
    let signature: p256::ecdsa::Signature = key(3).sign(&parts.tbs());
    let leaf = CertificateParts {
        signature: bits(signature.to_der().as_bytes()),
        ..parts
    }
    .build();

    let ders = alloc::vec![
        leaf,
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];

    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");

    assert!(outcome.paths().is_empty());
}

#[test]
fn two_readings_of_one_certificate_are_one_candidate() {
    // A pool can hold the same certificate read twice, from two copies of
    // the same bytes, which are two values of the crate's own type. Folding
    // them is what lets the rest of the search treat one certificate as one
    // place rather than comparing encodings: the cycle check asks whether a
    // candidate is already on the chain, and it asks it of where the
    // certificate is.
    let one = chain(Authority::Unlimited, None);
    let mut ders = alloc::vec![one[0].clone(), one[1].clone(), one[2].clone()];
    // The intermediate again, as its own copy of the same bytes.
    ders.push(one[1].clone());
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    assert_eq!(read[1].as_bytes(), read[3].as_bytes());
    assert!(!core::ptr::eq(read[1].as_bytes(), read[3].as_bytes()));

    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1], &read[3]];

    // Four edges is what this path costs: the anchor the leaf does not
    // chain to, the candidate it does, the anchor that candidate reaches,
    // and the candidate offered to itself and refused for being on the
    // chain already. A second reading of it would spend two more.
    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                edges: 4,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn a_target_asserting_authority_names_nobody_even_where_its_key_may_not_issue() {
    // The subject requirement hangs on the asserted bit: "if the subject is
    // a CA (e.g., the basic constraints extension ... is present and the
    // value of cA is TRUE), then the subject field MUST be populated with a
    // non-empty distinguished name" (RFC 5280 4.1.2.6). Whether the key may
    // sign certificates is a separate question, asked of a certificate a
    // path is built through.
    //
    // Reading the one from the other lets a certificate assert being an
    // authority, name nobody, and escape the requirement by carrying a key
    // usage that does not allow signing certificates.
    let parts = CertificateParts {
        serial: int(1),
        inner_algorithm: seq(&[oid_of(ECDSA_SHA256)]),
        outer_algorithm: seq(&[oid_of(ECDSA_SHA256)]),
        issuer: named("Root"),
        subject: seq(&[]),
        validity: seq(&[utc_time("240101000000Z"), utc_time("300101000000Z")]),
        key: public(&key(1)),
        extensions: Some(seq(&[
            extension(oid::BASIC_CONSTRAINTS, true, &seq(&[boolean(true)])),
            // Signing, and not signing certificates: the first named bit of
            // the list, with the seven after it unused.
            extension(oid::KEY_USAGE, true, &tlv(0x03, &[7, 0x80])),
            extension(
                oid::SUBJECT_ALT_NAME,
                true,
                &seq(&[tlv(0x82, b"host.example.com")]),
            ),
        ])),
        signature: bits(&[]),
        ..CertificateParts::default()
    };
    let signature: p256::ecdsa::Signature = key(3).sign(&parts.tbs());
    let leaf = CertificateParts {
        signature: bits(signature.to_der().as_bytes()),
        ..parts
    }
    .build();

    let ders = alloc::vec![
        leaf,
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];

    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");

    assert!(outcome.paths().is_empty());
}

/// Two routes of one length to one anchor, with the key encodings written
/// this wide, which is what telling the second from the first reads.
fn routes_keyed_over(width: Option<usize>) -> Vec<Vec<u8>> {
    let mut ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Mid",
            key: 1,
            parameters: width,
            signer: 2,
            ..Mint::default()
        }
        .build(),
    ];
    // Two authorities of one name and one key, certified by two different
    // ones above, which is two routes rather than one.
    for upper in [31u8, 32] {
        ders.push(
            Mint {
                subject: "Mid",
                issuer: "Up",
                key: 2,
                parameters: width,
                signer: upper,
                serial: u32::from(upper),
                authority: Authority::Unlimited,
                ..Mint::default()
            }
            .build(),
        );
        ders.push(
            Mint {
                subject: "Up",
                issuer: "Root",
                key: upper,
                parameters: width,
                signer: 41,
                serial: u32::from(upper) + 100,
                authority: Authority::Unlimited,
                ..Mint::default()
            }
            .build(),
        );
    }
    ders.push(
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 41,
            parameters: width,
            signer: 41,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    );
    ders
}

#[test]
fn telling_two_routes_apart_costs_what_reading_their_keys_costs() {
    // Two paths are told apart by the names they carry and the keys under
    // them, and a key encoding is read from the front: two of one length
    // that part near the end are read almost to the end. How long they are
    // is the pool's to decide, and the comparison runs once per path being
    // held, so charging only the names lets a set of long keys buy the rest
    // for nothing.
    //
    // One shape twice, with a budget comfortable for the ordinary keys.
    // Room for the whole of the ordinary shape and for reading the long
    // keys once, where folding the pool reads them, but not for reading
    // them again to tell one route from the other.
    let budget = Bounds {
        work: 40_000,
        ..Bounds::default()
    };

    let short = routes_keyed_over(None);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &short);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a budget this shape does not spend");
    assert_eq!(outcome.paths().len(), 2);
    assert_eq!(outcome.truncated(), None);

    let long = routes_keyed_over(Some(200_000));
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &long);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    assert_eq!(outcome.truncated(), Some(Truncation::Work));
}

#[test]
fn a_pool_naming_one_certificate_over_and_over_reads_it_once() {
    // A pool somebody else wrote may name one certificate as many times as
    // it likes. Recognising the repeat costs a pointer; reading the whole
    // encoding to hash it is what folding a separately written copy costs,
    // and charging that for every repeat lets them spend the search before
    // the issuer that leads somewhere is reached.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        // The one that gets repeated, written large so that reading it is
        // what the charge is about.
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            parameters: Some(20_000),
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let budget = Bounds {
        work: 8_000,
        ..Bounds::default()
    };

    // Named once, which is what the pool says whatever it repeats.
    let once = alloc::vec![&read[1]];
    let outcome = build(
        &read[0],
        &once,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a budget this shape does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);

    // The same certificate, named fifty times over.
    let over: Vec<&Certificate<'_>> = core::iter::repeat_n(&read[1], 50).collect();
    let outcome = build(
        &read[0],
        &over,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a budget this shape does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn a_lookalike_that_could_not_stand_in_a_path_costs_no_signature() {
    // Whether a certificate is the one an anchor was published in costs a
    // signature check, and it is asked only of certificates carrying an
    // anchor's name and key. A pool can carry as many of those as it likes,
    // and put expired ones in front of the issuer that leads somewhere: a
    // certificate no path could go through is refused for what it says
    // about itself, which costs nothing, so asking the expensive question
    // of it first spends the search on candidates already ruled out.
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];

    // Copies of the anchor's own certificate, each expired and so unusable,
    // and each differing only in its serial so that folding keeps them all.
    let decoys: Vec<Vec<u8>> = (0..8u32)
        .map(|which| {
            Mint {
                subject: "Root",
                issuer: "Root",
                key: 3,
                signer: 3,
                serial: which + 10,
                validity: ("200101000000Z", "210101000000Z"),
                authority: Authority::Unlimited,
                ..Mint::default()
            }
            .build()
        })
        .collect();
    let stood = parse(&parser, &decoys);
    let pool: Vec<&Certificate<'_>> = stood.iter().collect();

    // Room for the path's own signature checks and a little over, but not
    // for one per decoy.
    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                work: 4_000,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);
}

/// A name-constraints extension permitting these domains and nothing else.
fn permitting_domains(domains: &[&str]) -> Vec<u8> {
    let subtrees: Vec<Vec<u8>> = domains
        .iter()
        .map(|domain| seq(&[tlv(0x82, domain.as_bytes())]))
        .collect();
    extension(
        oid::NAME_CONSTRAINTS,
        true,
        &seq(&[tlv(0xa0, &cat(&subtrees))]),
    )
}

#[test]
fn a_name_is_charged_against_the_regions_of_its_own_form() {
    // A region and a name are compared only where they are of one form:
    // anything else is left alone without either being read. Charging every
    // name against every region makes a long distinguished name pay for
    // each domain an authority happened to write, and the path is then
    // refused for work nobody was going to do.
    let long = "A".repeat(20_000);
    let hosts: Vec<alloc::string::String> = (0..16u8)
        .map(|which| alloc::format!("h{which}.example.com"))
        .collect();
    let borrowed: Vec<&str> = hosts.iter().map(alloc::string::String::as_str).collect();

    let mut ders = constrained(Some(permitting_domains(&borrowed)), None);
    // The leaf is known by a long name of a form no region here speaks
    // about, and by no host name at all.
    ders[0] = Mint {
        subject: &long,
        issuer: "Intermediate",
        key: 1,
        signer: 2,
        ..Mint::default()
    }
    .build();

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[2])];
    let pool = alloc::vec![&read[1]];

    let outcome = build(
        &read[0],
        &pool,
        &context(
            &anchors,
            Bounds {
                // Room for reading the long name where it is read: once to
                // ask whether the leaf issued itself, once to ask whether
                // it publishes an anchor. Not room for reading it again
                // against each of the sixteen domains.
                work: 10_000,
                ..Bounds::default()
            },
            &crate::fixtures::memory(),
        ),
    )
    .expect("a budget this test does not spend");

    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn a_location_whose_authority_is_bracketed_is_not_a_host_name() {
    // Brackets around an authority say the thing inside is an address
    // literal rather than a registered name (RFC 3986 3.2.2), and the
    // grammar inside them admits IPvFuture, whose text can be spelled to
    // read like a domain. A location constraint applies to the host of a
    // location that names one, and "if the URI does not include an
    // authority component or if the authority contains a domain name, the
    // constraint applies" (RFC 5280 4.2.1.10): an address literal is
    // neither, so the constraint cannot be applied and the path is refused
    // rather than admitted under a region the location is not in.
    //
    // Unwrapping the brackets and reading what is inside as a name puts a
    // certificate under whoever holds the domain it was spelled to look
    // like, which is the whole of what a location constraint is for.
    let ders = constrained(Some(permitting_locations(&[".example.com"])), None);
    let mut ders = ders;
    ders[0] = Mint {
        subject: "Leaf",
        issuer: "Intermediate",
        key: 1,
        signer: 2,
        extra: alloc::vec![located_at("http://[v1.example.com]/")],
        ..Mint::default()
    }
    .build();

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 0);
    assert_eq!(outcome.truncated(), None);
}

/// A certificate policies extension naming this many policies, none of which
/// any other certificate of the chain names.
fn issued_under_many(count: u32) -> Vec<u8> {
    let named: Vec<Vec<u8>> = (0..count)
        .map(|which| {
            // The last arc counts, written base 128 with no leading zero
            // group: an identifier is compared by its bytes, so a
            // non-minimal spelling would be a different one and the reader
            // refuses it.
            let mut arc = Vec::new();
            let mut left = which;
            loop {
                arc.insert(0, (left & 0x7f) as u8);
                left >>= 7;
                if left == 0 {
                    break;
                }
            }
            let last = arc.len() - 1;
            for byte in &mut arc[..last] {
                *byte |= 0x80;
            }
            let mut identifier = alloc::vec![0x2a, 0x03, 0x05];
            identifier.extend_from_slice(&arc);
            seq(&[tlv(0x06, &identifier)])
        })
        .collect();
    extension(oid::CERTIFICATE_POLICIES, false, &seq(&named))
}

#[test]
fn reading_a_long_list_of_policies_costs_what_reading_it_costs() {
    // A certificate names as many policies as the encoding allows, and one
    // that matches nothing above adds no node to the working out. The
    // ceiling on what the working out may hold therefore never comes near,
    // and the list is read for free: the only bound left is the one on the
    // whole search, so the list has to reach it.
    //
    // The authority above names one policy of its own, which is what keeps
    // the working out alive to be looked in: an authority that named none
    // ends the agreement, and the list below it is then never read at all.
    //
    // Not a statement about the answer. A list this long is read by a
    // browser handed a document, and what it costs to read has to be
    // something the caller can decline.
    let budget = Bounds {
        work: 40_000,
        ..Bounds::default()
    };

    let ders = under_policies(
        alloc::vec![issued_under_many(8)],
        alloc::vec![issued_under(HOUSE_POLICY)],
    );
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a budget a short list does not spend");
    assert_eq!(outcome.paths().len(), 1);
    assert_eq!(outcome.truncated(), None);

    let ders = under_policies(
        alloc::vec![issued_under_many(20_000)],
        alloc::vec![issued_under(HOUSE_POLICY)],
    );
    // Isolate the existing 40_000-unit search bound from this large fixture's
    // separately funded policy catalogue decoding. Parser refusal has its own
    // public regression and remains a resource error, not path truncation.
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 1_000_000_000_000,
            ..structured_asn1::Limits::default()
        },
        crate::fixtures::memory(),
    );
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    assert_eq!(outcome.truncated(), Some(Truncation::Work));
}

/// A policy mappings extension naming one issuer policy this many times,
/// each time against a subject policy of its own.
fn mapping_one_issuer(count: u32) -> Vec<u8> {
    let pairs: Vec<Vec<u8>> = (0..count)
        .map(|which| {
            let mut identifier = alloc::vec![0x2a, 0x03, 0x06];
            let mut arc = Vec::new();
            let mut left = which;
            loop {
                arc.insert(0, (left & 0x7f) as u8);
                left >>= 7;
                if left == 0 {
                    break;
                }
            }
            let last = arc.len() - 1;
            for byte in &mut arc[..last] {
                *byte |= 0x80;
            }
            identifier.extend_from_slice(&arc);
            seq(&[oid_of(HOUSE_POLICY), tlv(0x06, &identifier)])
        })
        .collect();
    extension(oid::POLICY_MAPPINGS, true, &seq(&pairs))
}

#[test]
fn one_issuer_named_in_many_mappings_is_answered_once() {
    // Where mappings are not honoured, what an issuer would have mapped
    // stops being agreed on: every node standing at that policy goes
    // (RFC 5280 6.1.4 (b) (2)). The first entry naming an issuer has
    // already taken all of them, so reading the same nodes again for every
    // repeat is the mapping count times the tree's, and neither number is
    // ours: one is a list an extension wrote, the other is what the caller
    // allowed the working out to hold.
    //
    // The caller here says mappings are not honoured, which is the branch
    // that reads issuers and nothing else. Every entry names the one issuer
    // the working out stands at, so answering each of them again is the
    // entries twice over. The budget is comfortable for reading them once
    // and not for reading them twice.
    let budget = Bounds {
        work: 100_000,
        ..Bounds::default()
    };
    let unmapped = Policy {
        mapping: false,
        ..Policy::default()
    };

    let ders = under_policies(
        alloc::vec![issued_under(HOUSE_POLICY)],
        alloc::vec![issued_under(HOUSE_POLICY), mapping_one_issuer(20_000)],
    );
    // This fixture tests the unchanged 100_000-unit path bound. Its separate
    // 20k-entry decoding includes conservative pre-admission of hashbrown
    // probes, catalogue allocation and copying in the producing session.
    // Give that construction an explicit ceiling instead of relying on its
    // former aggregate-only admission to bypass the default parser ceiling.
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 1_000_000_000_000,
            ..structured_asn1::Limits::default()
        },
        crate::fixtures::memory(),
    );
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &asking(&anchors, budget, unmapped, &crate::fixtures::memory()),
    )
    .expect("a budget the sum does not spend");
    assert_eq!(outcome.truncated(), None);
    assert_eq!(outcome.paths().len(), 1);
}

/// A clock that never says the time has passed, and counts how often it was
/// asked.
///
/// How often the meter is consulted is the only thing that tells reading a
/// list under the bound from reading it and being charged afterwards: both
/// spend the same in the end, and only one of them can stop partway.
struct Polls(core::cell::Cell<usize>);

impl super::Watch for Polls {
    fn out_of_time(&self) -> bool {
        self.0.set(self.0.get() + 1);
        false
    }
}

/// The constrained chain, where the leaf's subject carries this many legacy
/// mail attributes and no alternative names, so that each of them is held to
/// the mailbox grammar.
fn addressed(count: usize) -> Vec<Vec<u8>> {
    let attributes: Vec<Vec<u8>> = (0..count)
        .map(|which| {
            set(&[seq(&[
                oid_of(oid::EMAIL_ADDRESS),
                ia5(&alloc::format!("person{which}@example.com")),
            ])])
        })
        .collect();
    let mut ders = constrained(Some(permitting_mail("example.com")), None);
    ders[0] = Mint {
        subject: "Leaf",
        issuer: "Intermediate",
        key: 1,
        signer: 2,
        subject_der: Some(seq(&attributes)),
        ..Mint::default()
    }
    .build();
    ders
}

/// A name-constraints extension permitting mail of one domain.
fn permitting_mail(domain: &str) -> Vec<u8> {
    extension(
        oid::NAME_CONSTRAINTS,
        true,
        &seq(&[tlv(0xa0, &seq(&[tlv(0x81, domain.as_bytes())]))]),
    )
}

/// How often the clock was asked while a chain of this many mail attributes
/// was held to the mail regions.
fn polls_while_reading(count: usize) -> usize {
    let ders = addressed(count);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let clock = Polls(core::cell::Cell::new(0));
    let outcome = build(
        &read[0],
        &pool,
        &super::Context {
            execution: &crate::fixtures::memory(),
            anchors: &anchors,
            interval: moment(),
            bounds: Bounds::default(),
            policy: Policy::default(),
            verifier: &Ecdsa,
            watch: &clock,
            recognizer: &(),
        },
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
    clock.0.get()
}

#[test]
fn the_meter_is_consulted_while_the_names_are_formed() {
    // Putting a name into the form the regions are matched against it in
    // reads it: a legacy mail attribute is held to the mailbox grammar, and
    // how much text it holds is a certificate's to decide. Pricing the
    // whole list and consulting the meter afterwards reads all of it
    // whatever the budget said, which is the scan the charge exists to
    // gate.
    //
    // What that looks like from outside is how often the clock is asked.
    // The final charge is the same either way, so the answer cannot tell
    // the two apart: a list read under the meter asks once per name, and
    // one priced first asks once for the whole of it.
    let few = polls_while_reading(4);
    let many = polls_while_reading(64);
    assert!(
        many >= few + 50,
        "the clock was asked {few} times for four names and {many} for sixty-four, \
         which is not once per name"
    );
}

/// A scheme that says every extension under one arc is its to decode, so
/// that a certificate can carry as many understood critical extensions as a
/// test likes.
struct Scheme;

impl crate::extension::Recognizer for Scheme {
    type Error = core::convert::Infallible;
    fn recognizes(
        &self,
        kind: Oid<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<bool, Self::Error> {
        Ok(kind.as_bytes().starts_with(&[0x2a, 0x03, 0x07]))
    }
}

/// The chain of the extension tests, where the leaf carries this many
/// critical extensions the scheme above understands.
fn demanding(count: u32) -> Vec<Vec<u8>> {
    let mut extra: Vec<Vec<u8>> = Vec::new();
    for which in 0..count {
        let mut arc = Vec::new();
        let mut left = which;
        loop {
            arc.insert(0, (left & 0x7f) as u8);
            left >>= 7;
            if left == 0 {
                break;
            }
        }
        let last = arc.len() - 1;
        for byte in &mut arc[..last] {
            *byte |= 0x80;
        }
        let mut identifier = alloc::vec![0x2a, 0x03, 0x07];
        identifier.extend_from_slice(&arc);
        extra.push(extension(
            Oid::from_bytes(&identifier),
            true,
            &boolean(true),
        ));
    }
    // The identifiers borrow from `extra`'s own encodings, which is why the
    // extensions are built before the certificate rather than inline.
    alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            extra,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ]
}

/// Whether a chain carrying this many understood critical extensions
/// settles, or reaches a bound while reading them.
fn settles_reading(count: u32, work: u64) -> Option<Truncation> {
    let ders = demanding(count);
    // This test isolates the path processor's 40_000-unit bound. Fully fund
    // the separate trusted wide-fixture parse now that its duplicate index
    // and retained capacity correctly consume the producing local allowance.
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        structured_asn1::Limits {
            max_work: 1_000_000_000,
            ..structured_asn1::Limits::default()
        },
        crate::fixtures::memory(),
    );
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];
    let outcome = build(
        &read[0],
        &[],
        &super::Context {
            execution: &crate::fixtures::memory(),
            anchors: &anchors,
            interval: moment(),
            bounds: Bounds {
                work,
                ..Bounds::default()
            },
            policy: Policy::default(),
            verifier: &Ecdsa,
            watch: &(),
            recognizer: &Scheme,
        },
    )
    .expect("a bound is an answer, not an error");
    outcome.truncated()
}

#[test]
fn reading_a_long_list_of_critical_extensions_costs_what_it_reads() {
    // Working out whether a critical extension was understood decodes its
    // value, and how many of them a certificate carries is its own to
    // decide. Charged once for the list, a certificate buys as many
    // decodings as the encoding allows while the bound barely moves.
    //
    // The scheme here understands them, which is what makes the whole list
    // read: a demand nobody understood settles the answer at the first one.
    assert_eq!(settles_reading(4, 40_000), None);
    let ders = demanding(20_000);
    let parser = Parser::der(crate::fixtures::memory());
    let error = Certificate::read(&parser, &ders[0], 0).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "certificate.tbsCertificate.extensions");
    assert_eq!(settles_reading(20_000, 40_000), Some(Truncation::Work));
}

/// One anchor and this many pool candidates carrying the anchor's name with
/// keys of the anchor's length that differ only at the end, written this
/// wide.
fn lookalikes_keyed_over(count: u8, width: Option<usize>) -> Vec<Vec<u8>> {
    let mut ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            parameters: width,
            signer: 3,
            ..Mint::default()
        }
        .build(),
    ];
    for which in 0..count {
        ders.push(
            Mint {
                subject: "Root",
                issuer: "Root",
                key: 51 + which,
                parameters: width,
                signer: 51 + which,
                serial: u32::from(which) + 200,
                authority: Authority::Unlimited,
                ..Mint::default()
            }
            .build(),
        );
    }
    ders.push(
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            parameters: width,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    );
    ders
}

/// Whether the chain settles under this budget, or reaches a bound.
fn settles_against_lookalikes(width: Option<usize>) -> Option<Truncation> {
    let ders = lookalikes_keyed_over(4, width);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let budget = Bounds {
        work: 40_000,
        ..Bounds::default()
    };
    build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error")
    .truncated()
}

#[test]
fn asking_whether_a_certificate_publishes_an_anchor_costs_what_it_reads() {
    // A certificate carrying an anchor's name is asked whether it carries
    // the anchor's key, which compares the two encodings byte for byte. Two
    // of one length that part near the end are read almost to the end, and
    // a pool can hold such a certificate for every anchor: charged only for
    // the names, one pool and a handful of anchors buy the reading of their
    // product while the bound barely moves.
    //
    // One shape twice, with a budget comfortable for ordinary keys and for
    // reading the long ones where folding the pool reads them, but not for
    // reading them again against the anchor.
    assert_eq!(settles_against_lookalikes(None), None);
    assert_eq!(
        settles_against_lookalikes(Some(200_000)),
        Some(Truncation::Work)
    );
}

/// A certificate policies extension naming this many identifiers that share
/// a prefix of this many bytes, so that ordering them reads the prefix.
fn issued_under_alike(count: u32, prefix: usize) -> Vec<u8> {
    let named: Vec<Vec<u8>> = (0..count)
        .map(|which| {
            // A shared run of one-byte arcs, then the arc that tells them
            // apart: two such identifiers are equal until the very end, so
            // comparing them reads the whole of the run.
            let mut identifier = alloc::vec![0x2a];
            identifier.extend(core::iter::repeat_n(0x03u8, prefix));
            let mut arc = Vec::new();
            let mut left = which;
            loop {
                arc.insert(0, (left & 0x7f) as u8);
                left >>= 7;
                if left == 0 {
                    break;
                }
            }
            let last = arc.len() - 1;
            for byte in &mut arc[..last] {
                *byte |= 0x80;
            }
            identifier.extend_from_slice(&arc);
            seq(&[tlv(0x06, &identifier)])
        })
        .collect();
    extension(oid::CERTIFICATE_POLICIES, false, &seq(&named))
}

/// Whether a chain whose authorities both name this many alike policies
/// settles, or reaches a bound while ordering them.
fn settles_ordering(count: u32, prefix: usize) -> Option<Truncation> {
    let ders = under_policies(
        alloc::vec![issued_under_alike(count, prefix)],
        alloc::vec![issued_under_alike(count, prefix)],
    );
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let budget = Bounds {
        work: 40_000,
        policies: 4_096,
        ..Bounds::default()
    };
    build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error")
    .truncated()
}

#[test]
fn ordering_the_settled_policies_costs_what_it_reads() {
    // What a path was issued under is reported as a set in one order, and
    // putting it in that order compares identifiers byte for byte. Two that
    // share a long prefix are read to where they part, and how long they
    // are and how many there are is decided by the certificates: a route
    // that settles again pays for the ordering again. Charged by the count
    // alone, one set of long identifiers buys the whole of it while the
    // bound barely moves.
    //
    // One count twice, with a budget comfortable for the short spelling.
    assert_eq!(settles_ordering(256, 2), None);
    assert_eq!(settles_ordering(256, 600), Some(Truncation::Work));
}

/// A leaf the root issued directly, and a pool of this many unrelated
/// certificates of this width that no path goes through.
fn direct_beside(count: u8, width: Option<usize>) -> Vec<Vec<u8>> {
    let mut ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
    ];
    for which in 0..count {
        ders.push(
            Mint {
                subject: "Elsewhere",
                issuer: "Nobody",
                key: 61 + which,
                parameters: width,
                signer: 61 + which,
                serial: u32::from(which) + 300,
                authority: Authority::Unlimited,
                ..Mint::default()
            }
            .build(),
        );
    }
    ders.push(
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    );
    ders
}

#[test]
fn a_path_the_anchors_settle_is_not_lost_to_a_pool_nobody_walks() {
    // A target an anchor issued is a path the anchors settle on their own.
    // A document may carry any number of other certificates beside it, and
    // reading them to find out they lead nowhere spends the budget that
    // answer needed: the caller is then told that a path it holds the whole
    // of was left out, over certificates no path goes through.
    //
    // The pool here is wide enough that reading it alone would reach the
    // bound, and the anchors are asked first.
    let ders = direct_beside(8, Some(200_000));
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let budget = Bounds {
        work: 10_000,
        ..Bounds::default()
    };
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    assert_eq!(outcome.paths().len(), 1);
}

#[test]
fn a_target_whose_basic_constraints_do_not_read_is_not_an_end_entity() {
    // "If the subject is a CA ... then the subject field MUST be populated
    // with a non-empty distinguished name" (RFC 5280 4.1.2.6). Whether the
    // subject is a CA is what the basic constraints say, so a value that
    // does not read leaves that unanswered: reading it as though the
    // extension were absent answers no, and a certificate carrying an empty
    // subject then passes a requirement its own extension may have been
    // asserting.
    //
    // Absent and unreadable are different facts here, as they are wherever
    // a restriction decides a path. The extension is not critical, so
    // nothing else refuses it: this is the only place it is read.
    let ders = alloc::vec![
        Mint {
            subject: "unused",
            subject_der: Some(seq(&[])),
            issuer: "Root",
            key: 1,
            signer: 3,
            extra: alloc::vec![
                extension(
                    oid::SUBJECT_ALT_NAME,
                    true,
                    &seq(&[tlv(0x82, b"host.example.com")]),
                ),
                // A null where the constraints belong, which is a value the
                // reader cannot make anything of.
                extension(oid::BASIC_CONSTRAINTS, false, &[0x05, 0x00]),
            ],
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];
    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 0);
    assert_eq!(outcome.truncated(), None);
}

/// How many paths a chain of two routes with keys this wide settles under
/// this budget, and whether it says it stopped.
fn routes_settled(width: Option<usize>, work: u64) -> (usize, Option<Truncation>) {
    let ders = routes_keyed_over(width);
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let budget = Bounds {
        work,
        ..Bounds::default()
    };
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    (outcome.paths().len(), outcome.truncated())
}

#[test]
fn a_route_is_not_shown_where_telling_it_apart_was_refused() {
    // Telling a settled route from the ones already held reads their names
    // and keys, and that reading is charged before it runs. A charge the
    // budget cannot meet is the answer that the reading is not going to
    // happen: doing it anyway is exactly what the charge exists to stop,
    // and showing the route afterwards claims it says something the search
    // never established.
    //
    // The first route is kept whatever the budget says, since nothing is
    // held for it to be compared against.
    let (settled, truncated) = routes_settled(Some(200_000), 40_000);
    assert_eq!(truncated, Some(Truncation::Work));
    assert_eq!(settled, 1);
}

/// An identifier of this many arcs, each one byte, and a last arc that tells
/// one from another. Two of them are equal until the very end, so comparing
/// them reads the whole of both.
///
/// Many short arcs rather than one long one: an arc holds a number, and one
/// written across thousands of bytes is not an identifier any reader will
/// take.
fn long_identifier(width: usize, last: u8) -> Vec<u8> {
    let mut content = alloc::vec![0x2a];
    content.extend(core::iter::repeat_n(0x01u8, width));
    content.push(last);
    content
}

/// An other-name of this identifier, holding one small value.
fn named_by(identifier: &[u8]) -> Vec<u8> {
    tlv(
        0xa0,
        &cat(&[tlv(0x06, identifier), tlv(0xa0, &boolean(true))]),
    )
}

/// A name-constraints extension permitting this many other-name regions,
/// each of an identifier this wide.
fn permitting_others(count: u8, width: usize) -> Vec<u8> {
    let subtrees: Vec<Vec<u8>> = (0..count)
        .map(|which| seq(&[named_by(&long_identifier(width, which))]))
        .collect();
    extension(
        oid::NAME_CONSTRAINTS,
        true,
        &seq(&[tlv(0xa0, &cat(&subtrees))]),
    )
}

/// Whether the chain settles or reaches a bound, where the leaf carries one
/// other-name of an identifier this wide and the authority names this many
/// regions of the same form.
fn settles_against_others(count: u8, width: usize, work: u64) -> Option<Truncation> {
    let mut ders = constrained(Some(permitting_others(count, width)), None);
    ders[0] = Mint {
        subject: "Leaf",
        issuer: "Intermediate",
        key: 1,
        signer: 2,
        extra: alloc::vec![extension(
            oid::SUBJECT_ALT_NAME,
            false,
            &seq(&[named_by(&long_identifier(width, 0x7f))]),
        )],
        ..Mint::default()
    }
    .build();

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let budget = Bounds {
        work,
        ..Bounds::default()
    };
    build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error")
    .truncated()
}

#[test]
fn comparing_names_told_apart_by_an_identifier_costs_what_it_reads() {
    // A name whose form is named by a type identifier is told from a region
    // by comparing those identifiers, and that comparison reads them: two
    // sharing a long prefix are read to where they part. A certificate
    // writes one and an extension the others, so how long they are and how
    // many there are is not ours. Charged nothing, one such name and a
    // handful of regions buy the reading of their product while the bound
    // barely moves.
    //
    // One shape twice, under a budget with room for reading the
    // certificates themselves, which is charged by their size where the
    // pool is folded, and not for reading every region's identifier again
    // against the name's.
    assert_eq!(settles_against_others(16, 8, 120_000), None);
    assert_eq!(
        settles_against_others(16, 200_000, 120_000),
        Some(Truncation::Work)
    );
}

/// A policy mappings extension mapping this many distinct issuer policies,
/// each to a subject policy of its own, with identifiers that share a
/// prefix so that comparing two of them reads both.
fn mapping_many_issuers(count: u32, prefix: usize) -> Vec<u8> {
    let pairs: Vec<Vec<u8>> = (0..count)
        .map(|which| {
            let issuer = alike_identifier(0x08, which, prefix);
            let subject = alike_identifier(0x09, which, prefix);
            seq(&[tlv(0x06, &issuer), tlv(0x06, &subject)])
        })
        .collect();
    extension(oid::POLICY_MAPPINGS, true, &seq(&pairs))
}

/// A certificate policies extension naming the same identifiers a mapping
/// of this width uses as its issuers, so that a node stands at each of them.
fn issued_under_issuers(count: u32, prefix: usize) -> Vec<u8> {
    let named: Vec<Vec<u8>> = (0..count)
        .map(|which| seq(&[tlv(0x06, &alike_identifier(0x08, which, prefix))]))
        .collect();
    extension(oid::CERTIFICATE_POLICIES, false, &seq(&named))
}

/// An identifier under one arc, padded to a shared prefix of this many arcs
/// and ending in the arcs that tell it from the others.
fn alike_identifier(family: u8, which: u32, prefix: usize) -> Vec<u8> {
    let mut content = alloc::vec![0x2a, family];
    content.extend(core::iter::repeat_n(0x01u8, prefix));
    let mut arc = Vec::new();
    let mut left = which;
    loop {
        arc.insert(0, (left & 0x7f) as u8);
        left >>= 7;
        if left == 0 {
            break;
        }
    }
    let last = arc.len() - 1;
    for byte in &mut arc[..last] {
        *byte |= 0x80;
    }
    content.extend_from_slice(&arc);
    content
}

#[test]
fn applying_mappings_looks_at_each_node_once_per_issuer_that_names_it() {
    // A certificate names as many mappings as it likes and the tree holds
    // as many nodes as the caller allowed. Looking for the nodes an issuer
    // stands at by scanning them all is their product, and every step of
    // that scan compares two identifiers, which reads them: a set of long
    // identifiers is then read over and over for an extension that merely
    // parses.
    //
    // The authority above names the same identifiers the mappings map from,
    // so a node stands at each of them and every mapping finds one.
    let budget = Bounds {
        work: 40_000,
        policies: 4_096,
        ..Bounds::default()
    };

    let ders = under_policies(
        alloc::vec![issued_under_issuers(128, 4)],
        alloc::vec![issued_under_issuers(128, 4), mapping_many_issuers(128, 4),],
    );
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    assert_eq!(outcome.truncated(), None);
}

/// A certificate policies extension naming the subject policies a mapping of
/// this width maps to, and the identifier standing for any policy beside
/// them.
fn issued_under_subjects_and_any(count: u32, prefix: usize) -> Vec<u8> {
    let mut named: Vec<Vec<u8>> = (0..count)
        .map(|which| seq(&[tlv(0x06, &alike_identifier(0x09, which, prefix))]))
        .collect();
    named.push(seq(&[oid_of(oid::ANY_POLICY)]));
    extension(oid::CERTIFICATE_POLICIES, false, &seq(&named))
}

#[test]
fn expanding_any_policy_looks_at_each_expectation_once() {
    // A mapping can leave one node expecting as many policies as an
    // extension names, and the certificate below may name all of them and
    // the identifier standing for any policy too. Asking whether the named
    // pass already carried each of them down by scanning the whole tree is
    // the expectations times the nodes, and every step compares two
    // identifiers, which reads them.
    //
    // The chain: an authority naming the issuer policies, a mapping onto
    // subject policies, then a certificate naming those subjects and
    // anyPolicy, so every expectation is both carried and asked about.
    let budget = Bounds {
        work: 40_000,
        policies: 4_096,
        ..Bounds::default()
    };

    let ders = under_policies(
        alloc::vec![issued_under_subjects_and_any(128, 4)],
        alloc::vec![issued_under_issuers(128, 4), mapping_many_issuers(128, 4),],
    );
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    assert_eq!(outcome.truncated(), None);
}

#[test]
fn an_anchor_re_issued_under_one_statement_of_trust_is_one_anchor() {
    // A trust store holds roots that were re-issued: one name, one key, one
    // statement about the names below, written again with a new serial. What
    // the search takes from an anchor's certificate is that statement and
    // nothing else, so those are one anchor. Kept apart, each is tried
    // wherever an anchor could end a path, and the bound on how many such
    // attempts a caller allowed is spent on copies of one answer.
    //
    // Room for one attempt, which is what one anchor takes.
    let budget = Bounds {
        edges: 1,
        ..Bounds::default()
    };

    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            serial: 1,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            serial: 2,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![
        Anchor::from_certificate(&read[1]),
        Anchor::from_certificate(&read[2]),
    ];
    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a budget one anchor does not spend");
    assert_eq!(outcome.truncated(), None);
    assert_eq!(outcome.paths().len(), 1);
}

/// The chain of the inheritance test: an authority whose key is written
/// without parameters, under a root whose key carries them.
fn inheriting() -> Vec<Vec<u8>> {
    alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            inherits: true,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ]
}

#[test]
fn a_key_written_without_parameters_stands_in_the_ones_above_it() {
    // "If the public key algorithm parameters are absent, the working public
    // key parameters are inherited" from the certificate above (RFC 5280
    // 6.1.2 (c) and 6.1.4 (c)). The group a key belongs to is then written
    // once, in an authority, and every key below stands in it.
    //
    // A key like that cannot be checked where the edge to it is found: what
    // it stands in is written above, and above is what the search has not
    // reached yet. Asked there with the encoding alone, a registry that
    // reads the group from the parameters can only answer that it cannot
    // say, and a path that is perfectly good goes unreported.
    let ders = inheriting();
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &super::Context {
            execution: &crate::fixtures::memory(),
            anchors: &anchors,
            interval: moment(),
            bounds: Bounds::default(),
            policy: Policy::default(),
            verifier: &Curved,
            watch: &(),
            recognizer: &(),
        },
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.truncated(), None);
    assert_eq!(outcome.paths().len(), 1);
}

#[test]
fn effective_local_anchor_preserves_inherited_parameters() {
    // A caller-authenticated issuer may inherit its curve parameters. A local
    // responder chain must preserve them rather than recreate a standing key.
    let ders = inheriting();
    let execution = crate::fixtures::memory();
    let parser = Parser::der(execution.clone());
    let read = parse(&parser, &ders);
    let key = super::WorkingKey::standing(read[2].tbs().public_key())
        .subject(&read[1], &execution)
        .unwrap();
    assert!(key.parameters().is_some());
    let storage_free = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 100_000),
    ));
    assert!(
        super::EffectiveAnchor::bind(Anchor::from_certificate(&read[2]), key, &storage_free)
            .unwrap()
            .is_none()
    );
    let anchor =
        super::EffectiveAnchor::bind(Anchor::from_certificate(&read[1]), key, &storage_free)
            .unwrap()
            .unwrap();
    assert_eq!(
        anchor.key().parameters().unwrap().as_ptr(),
        key.parameters().unwrap().as_ptr()
    );
    assert_eq!(storage_free.used(), 0);
    let unfunded = structured_asn1::memory::Memory::new(alloc::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 0),
    ));
    assert!(
        super::EffectiveAnchor::bind(Anchor::from_certificate(&read[1]), key, &unfunded)
            .unwrap_err()
            .is_resource()
    );
    let context = super::ValidationContext {
        execution: &execution,
        interval: moment(),
        policy: Policy::default(),
        bounds: super::ValidationBounds::default(),
        verifier: &Curved,
        watch: &(),
        recognizer: &(),
    };
    let result = super::validate_effective(&[&read[0]], anchor, &context).unwrap();
    assert!(
        matches!(result, super::Validation::Accepted(_)),
        "{result:?}"
    );
    assert!(matches!(
        super::validate(&[&read[0]], anchor.anchor(), &context).unwrap(),
        super::Validation::Rejected(super::Rejection {
            reason: super::RejectionReason::UnsupportedSignature,
            ..
        })
    ));
}

#[test]
fn unrestricted_pss_subject_does_not_inherit_parent_restrictions() {
    // RFC4055 §3.3 case2: absent PSS SPKI parameters impose no restrictions.
    // The generic same-OID transition cannot import a parent's restriction.
    use crate::fixtures::{CertificateParts, bits, oid as encoded_oid, seq};
    let root_bytes = CertificateParts {
        key: seq(&[
            seq(&[encoded_oid(oid::RSASSA_PSS), seq(&[])]),
            bits(&[1, 2, 3]),
        ]),
        ..CertificateParts::default()
    }
    .build();
    let child_bytes = CertificateParts {
        key: seq(&[seq(&[encoded_oid(oid::RSASSA_PSS)]), bits(&[4, 5, 6])]),
        ..CertificateParts::default()
    }
    .build();
    let execution = crate::fixtures::memory();
    let parser = Parser::der(execution.clone());
    let root = Certificate::read(&parser, &root_bytes, 100).unwrap();
    let child = Certificate::read(&parser, &child_bytes, 500).unwrap();
    let prior = super::WorkingKey::standing(root.tbs().public_key());
    assert_eq!(prior.parameters(), Some([48, 0].as_slice()));
    let projected = prior.subject(&child, &execution).unwrap();
    assert_eq!(projected.parameters(), None);
    assert_eq!(
        projected.key().as_bytes().as_ptr(),
        child.tbs().public_key().as_bytes().as_ptr()
    );
}

#[test]
fn null_pss_subject_keeps_invalid_original_parameters_for_provider_refusal() {
    // RFC4055 §3.1 permits absent or PSS SEQUENCE parameters, not NULL.
    // Projection must not replace invalid NULL with valid parent restrictions.
    let root_bytes = CertificateParts {
        key: seq(&[seq(&[oid_of(oid::RSASSA_PSS), seq(&[])]), bits(&[1, 2, 3])]),
        ..CertificateParts::default()
    }
    .build();
    let child_bytes = CertificateParts {
        key: seq(&[
            seq(&[oid_of(oid::RSASSA_PSS), crate::fixtures::null()]),
            bits(&[4, 5, 6]),
        ]),
        ..CertificateParts::default()
    }
    .build();
    let execution = crate::fixtures::memory();
    let parser = Parser::der(execution.clone());
    let root = Certificate::read(&parser, &root_bytes, 100).unwrap();
    let child = Certificate::read(&parser, &child_bytes, 500).unwrap();
    let projected = super::WorkingKey::standing(root.tbs().public_key())
        .subject(&child, &execution)
        .unwrap();
    assert_eq!(projected.parameters(), None);
    assert_eq!(
        projected.key().algorithm().parameters(),
        Some([5, 0].as_slice())
    );
}

/// A verifier that answers yes to everything and writes down what the key it
/// was handed said its parameters were, in the order it was asked.
///
/// What is under test is the working key rather than any signature, so this
/// reads neither the algorithm nor the octets.
struct Recording<'a>(&'a core::cell::RefCell<Vec<Option<Vec<u8>>>>);

impl Verify for Recording<'_> {
    type Error = core::convert::Infallible;
    fn verify(
        &self,
        _algorithm: &crate::AlgorithmIdentifier<'_>,
        key: super::WorkingKey<'_>,
        _signed: &[u8],
        _signature: structured_asn1::BitString<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<Verified, Self::Error> {
        Ok({
            self.0
                .borrow_mut()
                .push(key.parameters().map(<[u8]>::to_vec));
            Verified::Yes
        })
    }
}

/// The chain of the algorithm-change test: an authority whose key is written
/// under another algorithm's identifier with null parameters, under a root
/// whose key carries a curve.
fn changing_algorithm() -> Vec<Vec<u8>> {
    alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            foreign: true,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ]
}

#[test]
fn parameters_are_not_carried_across_a_change_of_algorithm() {
    // "If the certificate subjectPublicKey algorithm and the
    // working_public_key_algorithm are different, set the
    // working_public_key_parameters to null" (RFC 5280 6.1.4 (d)). Null
    // parameters and absent parameters are written differently and read the
    // same, so a key of another algorithm that writes them looks exactly
    // like a key standing in what an authority above it wrote. Carrying a
    // curve into a key that is not on one describes it with parameters that
    // are not its own, which a registry can only refuse.
    let ders = changing_algorithm();
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let asked = core::cell::RefCell::new(Vec::new());
    let outcome = build(
        &read[0],
        &pool,
        &super::Context {
            execution: &crate::fixtures::memory(),
            anchors: &anchors,
            interval: moment(),
            bounds: Bounds::default(),
            policy: Policy::default(),
            verifier: &Recording(&asked),
            watch: &(),
            recognizer: &(),
        },
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.paths().len(), 1);
    // Three questions were put and two were asked: the leaf against the
    // authority's key while a path was being looked for, where nothing is
    // in force yet; the authority against the root's key, which carries the
    // curve; and the leaf again from the anchor down, which is the first
    // question over because the authority inherits none of that curve. A
    // question already answered is not asked twice.
    //
    // Were the curve carried across the change of algorithm, the third
    // question would name it and would not be the first one over, so the
    // registry would be asked a third time.
    assert_eq!(
        asked.into_inner(),
        alloc::vec![None, Some(oid_of(PRIME256V1))],
    );
}

/// The chain of the published-constraints test: a root that names the
/// regions below it without saying anything about issuing, and a leaf
/// directly under it whose name is inside them.
fn published_constraints() -> Vec<Vec<u8>> {
    alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            extra: alloc::vec![extension(
                oid::NAME_CONSTRAINTS,
                true,
                &seq(&[tlv(0xa0, &seq(&[tlv(0xa4, &named("Leaf"))]))]),
            )],
            ..Mint::default()
        }
        .build(),
    ]
}

#[test]
fn an_anchor_names_the_regions_below_it_without_claiming_to_issue() {
    // A trust anchor is not a certificate of the path (RFC 5280 6.1), it is
    // the statement of trust the caller made, and the way that statement
    // carries regions here is a certificate holding them. The profile's
    // rule that the extension appears "only within a CA certificate" is
    // about certificates of the path. Reading the regions only where the
    // anchor also asserts being an authority throws away a path the caller
    // trusts, to a target inside the very subtree the caller allowed, and
    // reports it as no path at all.
    let ders = published_constraints();
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, Bounds::default(), &crate::fixtures::memory()),
    )
    .expect("a budget this test does not spend");
    assert_eq!(outcome.truncated(), None);
    assert_eq!(outcome.paths().len(), 1);
}

/// A name-constraints extension permitting one directory subtree.
fn permitting_directory(common: &str) -> Vec<u8> {
    extension(
        oid::NAME_CONSTRAINTS,
        true,
        &seq(&[tlv(0xa0, &seq(&[tlv(0xa4, &named(common))]))]),
    )
}

#[test]
fn anchors_of_one_statement_are_one_anchor_however_they_describe_issuing() {
    // Two roots of one name, one key and one set of regions, differing only
    // in what they say about issuing. Nothing reads that of an anchor: the
    // regions are honoured because the caller published them, not because
    // the certificate holding them claims to be an authority. So these are
    // one statement of trust written twice, and keeping both spends the
    // caller's bound on attempts at copies of one answer.
    //
    // Room for one attempt, which is what one anchor takes.
    let budget = Bounds {
        edges: 1,
        ..Bounds::default()
    };

    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Root",
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            serial: 1,
            authority: Authority::Unlimited,
            extra: alloc::vec![permitting_directory("Leaf")],
            ..Mint::default()
        }
        .build(),
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            serial: 2,
            authority: Authority::Absent,
            extra: alloc::vec![permitting_directory("Leaf")],
            ..Mint::default()
        }
        .build(),
    ];

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![
        Anchor::from_certificate(&read[1]),
        Anchor::from_certificate(&read[2]),
    ];
    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a budget one anchor does not spend");
    assert_eq!(outcome.truncated(), None);
    assert_eq!(outcome.paths().len(), 1);
}

/// One name of a single part holding this many common names.
///
/// A part is a set, so what is in it carries no order, and two spellings of
/// one name may write it in any. These differ by case alone: the bytes are
/// not the same, so the comparison cannot take the shortcut, and folding
/// makes every attribute match its opposite. Both sides are written in
/// ascending order, which is the order the distinguished rules require of a
/// set whatever case its members are in.
fn crowded(count: usize, upper: bool) -> Vec<u8> {
    let attributes: Vec<Vec<u8>> = (0..count)
        .map(|which| {
            let text = if upper {
                alloc::format!("NAME{which:06}")
            } else {
                alloc::format!("name{which:06}")
            };
            seq(&[oid_of(oid::COMMON_NAME), printable(&text)])
        })
        .collect();
    seq(&[set(&attributes)])
}

/// Whether a chain whose two spellings of one crowded name must be put in
/// order settles inside this budget.
fn settles_against_a_crowded_name(count: usize, work: u64) -> Option<Truncation> {
    let ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer_der: Some(crowded(count, false)),
            key: 1,
            signer: 3,
            ..Mint::default()
        }
        .build(),
        Mint {
            subject_der: Some(crowded(count, true)),
            issuer_der: Some(crowded(count, true)),
            key: 3,
            signer: 3,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    ];

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(&read[1])];
    let budget = Bounds {
        work,
        ..Bounds::default()
    };
    let outcome = build(
        &read[0],
        &[],
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    outcome.truncated()
}

#[test]
fn ordering_a_crowded_name_costs_what_the_ordering_reads() {
    // A part holding one attribute is compared where it stands. A part
    // holding many is a set, so both sides are put in order first, and a
    // sort reads its input once per round rather than once. How many
    // attributes a part holds is the document's to decide, so charging the
    // encoded length alone leaves that factor unpaid: the sort then runs to
    // the end with the budget barely moved and the watch unasked.
    //
    // Two spellings of one name, told apart by case so the comparison
    // cannot take the byte-for-byte shortcut and every attribute still
    // matches its opposite.
    const WIDE: usize = 2_048;

    // Enough for the reading and the ordering both.
    assert_eq!(settles_against_a_crowded_name(WIDE, 2_000_000), None);
    // Enough for one straight reading of both names and no more.
    assert_eq!(
        settles_against_a_crowded_name(WIDE, 20_000),
        Some(Truncation::Work),
    );
}

/// A certificate-policies extension naming this many identifiers of one
/// family, each padded to a shared prefix of this many arcs.
fn issued_under_long(count: u32, prefix: usize) -> Vec<u8> {
    let named: Vec<Vec<u8>> = (0..count)
        .map(|which| seq(&[tlv(0x06, &alike_identifier(0x09, which, prefix))]))
        .collect();
    extension(oid::CERTIFICATE_POLICIES, false, &seq(&named))
}

/// Whether a chain settles inside this budget, where the certificate below
/// names identifiers of one family and the one above names another, so none
/// of the names below continues an agreement above.
fn settles_under_long_policies(count: u32, prefix: usize, work: u64) -> Option<Truncation> {
    let budget = Bounds {
        work,
        ..Bounds::default()
    };
    let ders = under_policies(
        alloc::vec![issued_under_long(count, prefix)],
        alloc::vec![issued_under_issuers(4, prefix)],
    );
    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &context(&anchors, budget, &crate::fixtures::memory()),
    )
    .expect("a bound is an answer, not an error");
    outcome.truncated()
}

#[test]
fn looking_a_policy_identifier_up_costs_what_the_lookup_reads() {
    // An index answers by hashing every byte of the identifier it is given,
    // and how many bytes an identifier holds the document decides. A
    // certificate can therefore name a set of very long identifiers that
    // continue nothing above, add no node, and reach no ceiling: each is
    // hashed in full while a flat charge per entry barely moves the bound,
    // and the later charge for putting the settled policies in order is
    // never reached because nothing settled.
    const NAMED: u32 = 64;
    const WIDE: usize = 4_096;

    // Enough for the entries and the identifiers they carry.
    assert_eq!(settles_under_long_policies(NAMED, WIDE, 2_000_000), None);
    // Enough for the entries alone.
    assert_eq!(
        settles_under_long_policies(NAMED, WIDE, 4_000),
        Some(Truncation::Work),
    );
}

/// A verifier that reads the key octets whatever the algorithm identifier
/// says it is, which is what a registry holding that algorithm does: it
/// answers yes or no rather than declining.
struct Registered;

impl Verify for Registered {
    type Error = core::convert::Infallible;
    fn verify(
        &self,
        _algorithm: &crate::AlgorithmIdentifier<'_>,
        key: super::WorkingKey<'_>,
        signed: &[u8],
        signature: structured_asn1::BitString<'_>,
        _execution: &structured_asn1::memory::Memory,
    ) -> core::result::Result<Verified, Self::Error> {
        Ok({
            let (Some(octets), Some(value)) = (key.key().key_octets(), signature.octets()) else {
                return Ok(Verified::No);
            };
            let (Ok(verifying), Ok(signature)) = (
                p256::ecdsa::VerifyingKey::from_sec1_bytes(octets),
                p256::ecdsa::Signature::from_der(value),
            ) else {
                return Ok(Verified::No);
            };
            if verifying.verify(signed, &signature).is_ok() {
                Verified::Yes
            } else {
                Verified::No
            }
        })
    }
}

/// Whether a chain settles inside this many edges, where the pool holds this
/// many authorities of the right name and the wrong key before the one that
/// signed the target, and every key in it writes its parameters as a null.
fn settles_past_lookalike_authorities(count: u8, edges: usize) -> (Option<Truncation>, usize) {
    let mut ders = alloc::vec![
        Mint {
            subject: "Leaf",
            issuer: "Intermediate",
            key: 1,
            signer: 2,
            foreign: true,
            ..Mint::default()
        }
        .build(),
    ];
    // The wrong keys first, so a search that does not prune reaches the
    // right one only after walking all of them.
    ders.extend((0..count).map(|which| {
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 16 + which,
            signer: 3,
            serial: u32::from(which) + 2,
            foreign: true,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build()
    }));
    ders.push(
        Mint {
            subject: "Intermediate",
            issuer: "Root",
            key: 2,
            signer: 3,
            foreign: true,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    );
    ders.push(
        Mint {
            subject: "Root",
            issuer: "Root",
            key: 3,
            signer: 3,
            foreign: true,
            authority: Authority::Unlimited,
            ..Mint::default()
        }
        .build(),
    );

    let parser = Parser::der(crate::fixtures::memory());
    let read = parse(&parser, &ders);
    let anchors = alloc::vec![Anchor::from_certificate(read.last().expect("the root"))];
    let pool: Vec<&Certificate<'_>> = read[1..read.len() - 1].iter().collect();
    let outcome = build(
        &read[0],
        &pool,
        &super::Context {
            execution: &crate::fixtures::memory(),
            anchors: &anchors,
            interval: moment(),
            bounds: Bounds {
                edges,
                ..Bounds::default()
            },
            policy: Policy::default(),
            verifier: &Registered,
            watch: &(),
            recognizer: &(),
        },
    )
    .expect("a bound is an answer, not an error");
    (outcome.truncated(), outcome.paths().len())
}

#[test]
fn a_wrong_key_is_refused_at_the_edge_where_it_writes_a_null() {
    // An algorithm that takes no parameters writes a null, and a null is
    // read the same way as omitting them. A search that asks about a key
    // only where it carries parameters of its own therefore asks about
    // almost none of them: a pool of authorities of the right name and the
    // wrong key is walked in full, each one costing a subtree rather than
    // one check, and the budget can run out before the one that signed the
    // target is reached.
    //
    // Eight lookalikes and the real authority. Room for a little over two
    // passes of the pool, which is what pruning at the edge takes and what
    // walking each lookalike does not.
    const LOOKALIKES: u8 = 8;

    assert_eq!(
        settles_past_lookalike_authorities(LOOKALIKES, 30),
        (None, 1)
    );
}
