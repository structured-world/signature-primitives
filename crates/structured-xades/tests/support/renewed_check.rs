//! DEV-only SHA oracle; synthetic XML framing is not real C14N qualification.

use super::{Cause, DS, Tree, XADES_141, element, funded, renewed_tree};
use core::{cell::Cell, cmp::Ordering};
use sha2::{Digest as _, Sha256};
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{MemoryError, Work};
use structured_xades::{
    binding::{self, Coverage, Reference, Status},
    certificate::DigestProvider,
    container,
    reference::{Completeness, ObjectLocation},
    renewed::{self, PairOutcome, State},
    unsigned,
    xml::{Access, AccessError, Name, Xml},
};

const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const SHA256_ALIAS: &str = "urn:fixture:sha256-alias";
const SHA512_256: &str = "urn:fixture:sha512-256";
const MD5_ALIAS: &str = "urn:fixture:md5-alias";
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Identity {
    Sha256,
    Sha384,
    Sha512_256,
    Md5,
}
#[derive(Debug)]
enum Failure {
    Access(AccessError<Cause, usize>),
    Resource(MemoryError),
    Refused,
}
impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Access(cause) => write!(f, "{cause:?}"),
            Self::Resource(cause) => cause.fmt(f),
            Self::Refused => f.write_str("digest callback refused update"),
        }
    }
}
#[derive(Default)]
struct Oracle<'a> {
    mutate_start: Option<&'a Cell<u8>>,
    resolved: Cell<usize>,
    started: Cell<usize>,
    finished: Cell<usize>,
    refuse_update: bool,
    refuse_start: Option<usize>,
}
impl DigestProvider<'_, Tree> for Oracle<'_> {
    fn classify(&self, identity: &Identity) -> structured_xades::hashes::HashClass {
        // Executable oracle identities are SHA2 variants. The MD5 identity is
        // classification-only: every primitive below refuses if it is reached.
        match identity {
            Identity::Sha256 | Identity::Sha384 | Identity::Sha512_256 => {
                structured_xades::hashes::HashClass::OtherKnown
            }
            Identity::Md5 => structured_xades::hashes::HashClass::Md5,
        }
    }
    fn resolve<W: Work>(
        &self,
        access: &Access<'_, Tree, W>,
        method: usize,
    ) -> Result<Resolution<Identity>, Failure> {
        self.resolved.set(self.resolved.get() + 1);
        access
            .attribute(
                method,
                Name {
                    namespace: "",
                    local: "Algorithm",
                },
                |value| {
                    let Some(value) = value else {
                        return Ok(Resolution::Malformed);
                    };
                    access
                        .execution()
                        .charge_work(value.len() as u64)
                        .map_err(Failure::Resource)?;
                    Ok(match value {
                        SHA256 | SHA256_ALIAS => Resolution::Supported(Identity::Sha256),
                        SHA384 => Resolution::Supported(Identity::Sha384),
                        SHA512_256 => Resolution::Supported(Identity::Sha512_256),
                        MD5_ALIAS => Resolution::Supported(Identity::Md5),
                        _ => Resolution::Unsupported,
                    })
                },
            )
            .map_err(Failure::Access)?
    }
}
impl Digest<'_> for Oracle<'_> {
    type Identity = Identity;
    // Only SHA-256 streams; the other identities answer `Unsupported` at start.
    type State = Sha256;
    type Output = [u8; 32];
    type Error = Failure;
    fn width(&self, identity: &Identity) -> Option<usize> {
        Some(match identity {
            Identity::Sha256 | Identity::Sha512_256 => 32,
            Identity::Sha384 => 48,
            Identity::Md5 => 16,
        })
    }
    fn compare<W: Work>(
        &self,
        left: &Identity,
        right: &Identity,
        work: &W,
    ) -> Result<Ordering, Failure> {
        assert!(
            *left != Identity::Md5 && *right != Identity::Md5,
            "prohibited identity must not reach renewed identity comparison"
        );
        work.charge_work(1).map_err(Failure::Resource)?;
        Ok(left.cmp(right))
    }
    fn start<W: Work>(&self, identity: &Identity, work: &W) -> Result<Resolution<Sha256>, Failure> {
        assert_ne!(
            *identity,
            Identity::Md5,
            "prohibited streaming MD5 must not start"
        );
        work.charge_work(64).map_err(Failure::Resource)?;
        self.started.set(self.started.get() + 1);
        if self.refuse_start == Some(self.started.get()) {
            return Err(Failure::Refused);
        }
        if let Some(generation) = self.mutate_start {
            generation.set(generation.get() + 1);
            return Ok(Resolution::Unsupported);
        }
        Ok(if *identity == Identity::Sha256 {
            Resolution::Supported(Sha256::new())
        } else {
            Resolution::Unsupported
        })
    }
    fn update<W: Work>(&self, state: &mut Sha256, bytes: &[u8], work: &W) -> Result<(), Failure> {
        work.charge_work(bytes.len() as u64 + 64)
            .map_err(Failure::Resource)?;
        if self.refuse_update {
            return Err(Failure::Refused);
        }
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, work: &W) -> Result<[u8; 32], Failure> {
        work.charge_work(64).map_err(Failure::Resource)?;
        self.finished.set(self.finished.get() + 1);
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        _: &Identity,
        output: &[u8; 32],
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        work.charge_work(32).map_err(Failure::Resource)?;
        Ok(output == expected)
    }
}

struct Fixture {
    xml: Tree,
    node: usize,
    method: usize,
    digest: usize,
    object: usize,
    reference: usize,
    instruction: usize,
    old: usize,
}
fn fixture() -> Fixture {
    let (mut xml, node, method, digest, object, reference) = renewed_tree();
    xml.digest_algorithm = Some(SHA256);
    let object_container = xml.nodes.len();
    xml.nodes.push(element(Some(0), DS, "Object"));
    let manifest = xml.nodes.len();
    xml.nodes
        .push(element(Some(object_container), DS, "Manifest"));
    let instruction = xml.nodes.len();
    xml.nodes.push(element(Some(manifest), DS, "Reference"));
    let old = xml.nodes.len();
    xml.nodes
        .push(element(Some(instruction), DS, "DigestMethod"));
    xml.digest_algorithms.push((old, SHA384));
    xml.references[0].target = Some(manifest);
    xml.references[0].coverage = Coverage::ElementContent;
    xml.references.push(Reference {
        node: instruction,
        target: None,
        kind: None,
        status: Status::Valid,
        coverage: Coverage::Transformed,
    });
    xml.reference_locations
        .push((instruction, ObjectLocation::Detached));
    let canonical = [
        b'E',
        u8::try_from(instruction).unwrap(),
        b'M',
        u8::try_from(method).unwrap(),
    ];
    xml.binary_routes
        .push((reference, Sha256::digest(canonical).to_vec()));
    xml.binary_routes
        .push((object, Sha256::digest([b'D', 2]).to_vec()));
    Fixture {
        xml,
        node,
        method,
        digest,
        object,
        reference,
        instruction,
        old,
    }
}
fn reading(xml: &Tree, work: &structured_asn1::memory::Memory) -> renewed::Reading<Tree> {
    let access = Access::new(xml, xml.snapshot(), work);
    let containers = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &containers).unwrap();
    let inventory = unsigned::read(&access, &bound, unsigned::Requirements::Timestamped).unwrap();
    let index = inventory
        .entries()
        .iter()
        .position(|entry| entry.role == unsigned::Role::RenewedDigests)
        .unwrap();
    renewed::read(&access, &inventory, index).unwrap()
}

fn append_renewal(f: &mut Fixture, differs: bool) -> usize {
    // Trusted synthetic framing: every property has its OWN original method
    // node and thus its own canonical Reference projection in this XML oracle.
    let node = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(7), XADES_141, "RenewedDigestsV2"));
    let method = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(node), DS, "CanonicalizationMethod"));
    f.xml.nodes.push(element(Some(node), DS, "DigestMethod"));
    let pair = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(node), XADES_141, "RecomputedDigestValue"));
    let object = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(pair), XADES_141, "NewSDODigestValue"));
    let reference = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(pair), XADES_141, "OriginalRefDigest"));
    let mut expected = Sha256::digest([b'D', 2]).to_vec();
    if differs {
        expected[0] ^= 1;
    }
    f.xml.binary_routes.push((object, expected));
    f.xml.binary_routes.push((
        reference,
        Sha256::digest([
            b'E',
            u8::try_from(f.instruction).unwrap(),
            b'M',
            u8::try_from(method).unwrap(),
        ])
        .to_vec(),
    ));
    node
}

fn prepared_fixture() -> Fixture {
    // The low-level renewal fixture intentionally never reads the root header.
    // Full preparation also needs its genuine C14N method and a format for the
    // detached Manifest child; neither requirement may be bypassed here.
    let mut f = fixture();
    let method = f
        .xml
        .nodes
        .iter()
        .position(|node| {
            node.parent == Some(9)
                && matches!(
                    node.value,
                    super::Node::Element(Name {
                        namespace: DS,
                        local: "CanonicalizationMethod"
                    })
                )
        })
        .unwrap();
    f.xml
        .digest_algorithms
        .push((method, "http://www.w3.org/2006/12/xml-c14n11"));
    let objects = f
        .xml
        .nodes
        .iter()
        .position(|node| {
            matches!(
                node.value,
                super::Node::Element(Name {
                    namespace: super::XADES,
                    local: "SignedDataObjectProperties"
                })
            )
        })
        .unwrap();
    let format = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(objects), super::XADES, "DataObjectFormat"));
    f.xml.mime(format);
    let ordinal = f
        .xml
        .references
        .iter()
        .position(|reference| reference.node == f.instruction)
        .unwrap();
    f.xml.include_routes.push((
        format,
        ordinal,
        structured_xades::reference::Boolean::Absent,
    ));
    f
}

#[test]
fn complete_renewal_processing_keeps_a_negative_middle_property_and_checks_the_last() {
    // A caller-selected successful subset must not stand for all original
    // properties. The middle mismatch is retained; the last property still
    // executes exactly once, with every retained byte charged to CURRENT work.
    for differs in [false, true] {
        let mut f = prepared_fixture();
        let nodes = [
            f.node,
            append_renewal(&mut f, differs),
            append_renewal(&mut f, false),
        ];
        let original = funded();
        let prepared = structured_xades::prepare::prepare(
            &Access::new(&f.xml, f.xml.snapshot(), &original),
            0,
            unsigned::Requirements::Timestamped,
            None,
        )
        .unwrap();
        let held = original.used();
        let paid = original.work_used();
        let query = funded();
        let provider = Oracle::default();
        let result = renewed::check_prepared(&f.xml, &prepared, &provider, &query).unwrap();
        assert!(core::ptr::eq(result.prepared(), &raw const prepared));
        assert_eq!(result.reports().len(), 3);
        for (index, report) in result.reports().iter().enumerate() {
            assert_eq!(report.property(), nodes[index]);
            assert_eq!(report.state(), State::Processed);
            assert_eq!(report.pairs().len(), 1);
            if differs && index == 1 {
                assert!(matches!(report.pairs()[0].outcome, PairOutcome::Differs));
            } else {
                assert!(matches!(report.pairs()[0].outcome, PairOutcome::Matches));
            }
        }
        assert_eq!(result.all_written_renewals_agree(), !differs);
        assert_eq!(provider.started.get(), 6);
        assert_eq!(provider.finished.get(), 6);
        assert_eq!(original.used(), held);
        assert_eq!(original.work_used(), paid);
        assert!(query.used() > 0);
        drop(result);
        assert_eq!(query.used(), 0);
    }
}

#[test]
fn complete_renewal_processing_releases_prior_reports_on_a_late_provider_refusal() {
    // The first property's successful report cannot escape when a later
    // property refuses. The opaque original provider cause stays terminal.
    let mut f = prepared_fixture();
    append_renewal(&mut f, false);
    let original = funded();
    let prepared = structured_xades::prepare::prepare(
        &Access::new(&f.xml, f.xml.snapshot(), &original),
        0,
        unsigned::Requirements::Timestamped,
        None,
    )
    .unwrap();
    let held = original.used();
    let query = funded();
    let provider = Oracle {
        refuse_start: Some(3),
        ..Oracle::default()
    };
    assert!(matches!(
        renewed::check_prepared(&f.xml, &prepared, &provider, &query),
        Err(renewed::CheckError::Digest {
            cause: structured_xades::digest::Error::Provider(Failure::Refused),
            ..
        })
    ));
    assert_eq!(provider.started.get(), 3);
    assert_eq!(provider.finished.get(), 2);
    assert_eq!(query.used(), 0);
    assert_eq!(original.used(), held);
}

#[test]
fn complete_renewal_processing_requires_new_admission_before_provider_dispatch() {
    // Retained preparation does not fund a fresh full-root query. Refusal
    // occurs before hashing, and neither account retains partial output.
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};
    let f = prepared_fixture();
    let original = funded();
    let prepared = structured_xades::prepare::prepare(
        &Access::new(&f.xml, f.xml.snapshot(), &original),
        0,
        unsigned::Requirements::Timestamped,
        None,
    )
    .unwrap();
    let held = original.used();
    for (capacity, work) in [(0, 1_000_000), (65_536, 0)] {
        let query = Memory::new(Arc::new(MemoryAccount::new(capacity, work)));
        let provider = Oracle::default();
        let Err(error) = renewed::check_prepared(&f.xml, &prepared, &provider, &query) else {
            panic!("unfunded full census cannot succeed");
        };
        if capacity == 0 {
            assert!(matches!(
                error,
                renewed::CheckError::Resource {
                    node: 0,
                    cause: MemoryError::LimitExceeded,
                }
            ));
        } else {
            assert!(matches!(
                error,
                renewed::CheckError::Access(AccessError::Resource {
                    node: 0,
                    cause: MemoryError::WorkExceeded,
                })
            ));
        }
        assert_eq!(provider.started.get(), 0);
        assert_eq!(f.xml.streamed.get(), 0);
        assert_eq!(query.used(), 0);
        assert_eq!(original.used(), held);
    }
}

#[test]
fn empty_renewal_census_is_not_a_longevity_claim_and_still_checks_the_live_source() {
    // No written renewal is a vacuous comparison result, never proof that
    // renewal was unnecessary. Even this empty path must reject a stale source.
    let xml = super::preparation_tree();
    let original = funded();
    let prepared = structured_xades::prepare::prepare(
        &Access::new(&xml, xml.snapshot(), &original),
        0,
        unsigned::Requirements::Timestamped,
        None,
    )
    .unwrap();
    let query = funded();
    let provider = Oracle::default();
    let empty = renewed::check_prepared(&xml, &prepared, &provider, &query).unwrap();
    assert!(empty.reports().is_empty());
    assert!(empty.all_written_renewals_agree());
    assert!(core::ptr::eq(empty.prepared(), &raw const prepared));
    assert_eq!(query.used(), 0);
    assert_eq!(provider.started.get(), 0);
    drop(empty);
    xml.generation.set(xml.generation.get() + 1);
    assert!(matches!(
        renewed::check_prepared(&xml, &prepared, &provider, &query),
        Err(renewed::CheckError::Access(AccessError::Changed {
            node: 0
        }))
    ));
    assert_eq!(query.used(), 0);
    assert_eq!(provider.started.get(), 0);
}

#[test]
fn complete_renewal_reports_outlive_scoped_execution_and_keep_its_storage_account() {
    // Return transfers the scoped vector's SAME retained account. A parser's
    // local ceiling still applies before allocation/callback, and dropping it
    // never refunds the live returned reports or charges the preparation owner.
    use structured_asn1::{Encoding, Limits, Parser};
    let f = prepared_fixture();
    let original = funded();
    let prepared = structured_xades::prepare::prepare(
        &Access::new(&f.xml, f.xml.snapshot(), &original),
        0,
        unsigned::Requirements::Timestamped,
        None,
    )
    .unwrap();
    let held = original.used();
    let query = funded();
    let provider = Oracle::default();
    let denied = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        query.clone(),
    );
    let operation = denied.read(&[], 900).unwrap();
    assert!(matches!(
        renewed::check_prepared(&f.xml, &prepared, &provider, &operation.execution()),
        Err(renewed::CheckError::Access(AccessError::Resource {
            node: 0,
            cause: MemoryError::WorkExceeded,
        }))
    ));
    assert_eq!(provider.started.get(), 0);
    assert_eq!(query.used(), 0);
    let retained = {
        let parser = Parser::der(query.clone());
        let operation = parser.read(&[], 900).unwrap();
        renewed::check_prepared(&f.xml, &prepared, &provider, &operation.execution()).unwrap()
    };
    assert!(retained.all_written_renewals_agree());
    assert_eq!(retained.reports().len(), 1);
    assert!(query.used() > 0);
    assert_eq!(original.used(), held);
    drop(retained);
    assert_eq!(query.used(), 0);
    assert_eq!(original.used(), held);
}

#[test]
fn renewal_rejects_new_md5_alias_before_canonicalization_or_object_replay() {
    // A known MD5 identity remains forbidden despite a noncanonical wire URI.
    // Neither an intentionally impossible width nor stale old-target facts may
    // turn the format ban into another digest path or permit primitive effects.
    let mut f = fixture();
    f.xml.digest_algorithms.push((f.digest, MD5_ALIAS));
    let work = funded();
    let reading = reading(&f.xml, &work);
    let provider = Oracle::default();
    let result = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
    assert_eq!(
        result.state(),
        State::Algorithm(structured_xades::certificate::Agreement::ProhibitedAlgorithm)
    );
    assert!(result.pairs().is_empty());
    assert!(!result.agrees());
    assert_eq!(provider.resolved.get(), 1);
    assert_eq!(provider.started.get(), 0);
    assert_eq!(f.xml.streamed.get(), 0);
}

#[test]
fn renewal_preserves_prohibited_old_digest_identity_without_reading_the_object() {
    // Canonicalizing the authenticated instruction with the permitted NEW
    // digest is distinct from accepting its old MD5 identity. Keep the exact
    // per-pair failure and original target status; never replay the payload.
    let mut f = fixture();
    f.xml.digest_algorithms[0] = (f.old, MD5_ALIAS);
    let work = funded();
    let reading = reading(&f.xml, &work);
    let provider = Oracle::default();
    let result = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
    assert_eq!(result.state(), State::Processed);
    assert_eq!(result.pairs().len(), 1);
    assert!(matches!(
        result.pairs()[0].outcome,
        PairOutcome::Algorithm(structured_xades::certificate::Agreement::ProhibitedAlgorithm)
    ));
    assert_eq!(result.pairs()[0].reference, Some(f.instruction));
    assert_eq!(result.pairs()[0].old_target_status, Some(Status::Valid));
    assert!(!result.agrees());
    assert_eq!(provider.resolved.get(), 2);
    assert_eq!(provider.started.get(), 1);
    assert_eq!(provider.finished.get(), 1);
    assert_eq!(f.xml.streamed.get(), 1);
}

#[test]
fn renewal_hashes_original_instruction_and_ordinary_object_output_with_distinct_algorithms() {
    // Hash both actual roles with the new identity, but compare it against the
    // original Reference's old identity before replaying the detached object.
    let f = fixture();
    let work = funded();
    let reading = reading(&f.xml, &work);
    let held = work.used();
    let provider = Oracle::default();
    let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
    assert_eq!(report.property(), f.node);
    assert_eq!(report.state(), State::Processed);
    assert!(report.agrees());
    assert_eq!(report.pairs().len(), 1);
    assert_eq!(report.pairs()[0].reference, Some(f.instruction));
    assert!(matches!(report.pairs()[0].outcome, PairOutcome::Matches));
    assert_eq!(provider.started.get(), 2);
    assert_eq!(provider.finished.get(), 2);
    assert_eq!(f.xml.streamed.get(), 2);
    drop(report);
    assert_eq!(work.used(), held);
}

#[test]
fn renewal_same_algorithm_is_not_silently_accepted_or_replayed() {
    // Equal resolved identities reject renewal even if all written values match.
    for written in [SHA256, SHA256_ALIAS] {
        let mut f = fixture();
        f.xml.digest_algorithms[0] = (f.old, written);
        let work = funded();
        let reading = reading(&f.xml, &work);
        let provider = Oracle::default();
        let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
        assert!(!report.agrees());
        assert!(matches!(
            report.pairs()[0].outcome,
            PairOutcome::SameAlgorithm
        ));
        assert_eq!(provider.started.get(), 1);
        assert_eq!(f.xml.streamed.get(), 1);
    }
}

#[test]
fn renewal_different_algorithms_with_equal_output_width_are_not_same_identity() {
    // SHA-512/256 and SHA-256 both produce 32 bytes. Full resolved identity,
    // rather than URI inequality or output length, must decide renewal.
    let mut f = fixture();
    f.xml.digest_algorithms[0] = (f.old, SHA512_256);
    let work = funded();
    let reading = reading(&f.xml, &work);
    let provider = Oracle::default();
    let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
    assert!(report.agrees());
    assert!(matches!(report.pairs()[0].outcome, PairOutcome::Matches));
    assert_eq!(provider.started.get(), 2);
    assert_eq!(provider.finished.get(), 2);
}

#[test]
fn renewal_retained_report_keeps_only_its_accounted_diagnostics_after_all_scopes_drop() {
    // Scoped Work and original XML/provider/parser models must not be pinned
    // by the returned independent report; its own capacity charge still lives.
    let work = funded();
    let report = {
        let f = fixture();
        let original = reading(&f.xml, &work);
        let parser = structured_asn1::Parser::der(work.clone());
        let reader = parser.read(&[], 900).unwrap();
        let execution = reader.execution();
        renewed::check(&f.xml, &original, &Oracle::default(), &execution).unwrap()
    };
    assert!(report.agrees());
    assert_eq!(report.snapshot().document, 9);
    assert_eq!(report.signature(), 0);
    assert!(work.used() > 0);
    assert_eq!(report.pairs().len(), 1);
    drop(report);
    assert_eq!(work.used(), 0);
}

#[test]
fn renewal_unavailable_explicit_object_continues_to_the_next_pair() {
    // §5.5.3 step3/6: preserve the original absent-source cause, then process
    // the next pair rather than returning early or inventing an empty digest.
    let mut f = fixture();
    f.xml.unavailable_reference = Some(f.instruction);
    // The signed parent authenticates the instruction, independently of the
    // old target digest result. Legacy XML reports missing bytes as Invalid.
    f.xml.references[2].status = Status::Invalid;
    let pair = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(f.node), XADES_141, "RecomputedDigestValue"));
    let object = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(pair), XADES_141, "NewSDODigestValue"));
    let reference = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(pair), XADES_141, "OriginalRefDigest"));
    let manifest = f.xml.nodes[f.instruction].parent.unwrap();
    let instruction = f.xml.nodes.len();
    f.xml.nodes.push(element(Some(manifest), DS, "Reference"));
    let old = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(instruction), DS, "DigestMethod"));
    f.xml.digest_algorithms.push((old, SHA384));
    f.xml.references.push(Reference {
        node: instruction,
        target: None,
        kind: None,
        status: Status::Valid,
        coverage: Coverage::Transformed,
    });
    f.xml
        .reference_locations
        .push((instruction, ObjectLocation::Detached));
    f.xml.binary_routes.push((
        reference,
        Sha256::digest([
            b'E',
            u8::try_from(instruction).unwrap(),
            b'M',
            u8::try_from(f.method).unwrap(),
        ])
        .to_vec(),
    ));
    f.xml
        .binary_routes
        .push((object, Sha256::digest([b'D', 3]).to_vec()));
    let work = funded();
    let reading = reading(&f.xml, &work);
    let provider = Oracle::default();
    let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
    assert_eq!(report.pairs().len(), 2);
    assert!(!report.agrees());
    assert!(matches!(
        report.pairs()[0].outcome,
        PairOutcome::Unavailable(Cause::Unavailable)
    ));
    assert_eq!(report.pairs()[0].old_target_status, Some(Status::Invalid));
    assert!(matches!(report.pairs()[1].outcome, PairOutcome::Matches));
    assert_eq!(provider.started.get(), 4);
    assert_eq!(provider.finished.get(), 3);
}

#[test]
fn renewal_wrong_declared_width_prevents_all_canonicalization_and_payload_work() {
    // Width is known after resolution and must be checked before input work;
    // no candidate hash is useful if the only declared pair is malformed.
    let mut f = fixture();
    f.xml.binary_routes[0].1 = vec![0; 31];
    let work = funded();
    let reading = reading(&f.xml, &work);
    let provider = Oracle::default();
    let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
    assert!(matches!(
        report.pairs()[0].outcome,
        PairOutcome::Algorithm(structured_xades::certificate::Agreement::MalformedValue)
    ));
    assert_eq!(provider.started.get(), 0);
    assert_eq!(f.xml.streamed.get(), 0);
}

#[test]
fn renewal_object_width_and_lexical_refusal_precede_source_and_resolver_effects() {
    // Both declared values are preflighted. Lexical refusal is located at the
    // original value and occurs before even the first provider resolution.
    let mut f = fixture();
    f.xml
        .binary_routes
        .iter_mut()
        .find(|route| route.0 == f.object)
        .unwrap()
        .1 = vec![0; 31];
    let work = funded();
    let reading = reading(&f.xml, &work);
    let provider = Oracle::default();
    let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
    assert!(matches!(
        report.pairs()[0].outcome,
        PairOutcome::Algorithm(structured_xades::certificate::Agreement::MalformedValue)
    ));
    assert_eq!(provider.started.get(), 0);
    assert_eq!(f.xml.streamed.get(), 0);
    drop(report);
    f.xml.decoding = super::Decoding::Refuse;
    let provider = Oracle::default();
    assert!(
        matches!(renewed::check(&f.xml,&reading,&provider,&work),Err(renewed::CheckError::Binary(structured_xades::binary::Error::Access {location,..})) if location.node==f.reference)
    );
    assert_eq!(provider.resolved.get(), 0);
    assert_eq!(provider.started.get(), 0);
}

#[test]
fn renewal_mismatch_and_missing_instruction_keep_their_distinct_completed_results() {
    // A wrong object hash is not a missing reference. Neither outcome may be
    // presented as a successful renewal or a processing/resource failure.
    for reference in [true, false] {
        let mut f = fixture();
        let node = if reference { f.reference } else { f.object };
        f.xml
            .binary_routes
            .iter_mut()
            .find(|route| route.0 == node)
            .unwrap()
            .1 = vec![0; 32];
        let work = funded();
        let reading = reading(&f.xml, &work);
        let provider = Oracle::default();
        let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
        assert_eq!(report.state(), State::Processed);
        assert!(!report.agrees());
        if reference {
            assert!(matches!(
                report.pairs()[0].outcome,
                PairOutcome::MissingReference
            ));
            assert_eq!(report.pairs()[0].reference, None);
        } else {
            assert!(matches!(report.pairs()[0].outcome, PairOutcome::Differs));
            assert_eq!(report.pairs()[0].reference, Some(f.instruction));
        }
        assert_eq!(provider.started.get(), if reference { 1 } else { 2 });
    }
}

#[test]
fn renewal_identical_canonical_instructions_are_ambiguous_before_object_replay() {
    // Distinct References can have identical canonical encodings (e.g. neither
    // has an Id). A digest lookup must never silently select the first.
    let mut f = fixture();
    let manifest = f.xml.nodes[f.instruction].parent.unwrap();
    let duplicate = f.xml.nodes.len();
    f.xml.nodes.push(element(Some(manifest), DS, "Reference"));
    let method = f.xml.nodes.len();
    f.xml
        .nodes
        .push(element(Some(duplicate), DS, "DigestMethod"));
    f.xml.digest_algorithms.push((method, SHA384));
    f.xml.references.push(Reference {
        node: duplicate,
        target: None,
        kind: None,
        status: Status::Valid,
        coverage: Coverage::Transformed,
    });
    f.xml
        .reference_locations
        .push((duplicate, ObjectLocation::Detached));
    f.xml.canonical_routes.push((
        duplicate,
        vec![
            b'E',
            u8::try_from(f.instruction).unwrap(),
            b'M',
            u8::try_from(f.method).unwrap(),
        ],
    ));
    let work = funded();
    let reading = reading(&f.xml, &work);
    let provider = Oracle::default();
    let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
    assert!(matches!(
        report.pairs()[0].outcome,
        PairOutcome::AmbiguousReference
    ));
    assert!(!report.agrees());
    assert_eq!(provider.started.get(), 2);
    assert_eq!(f.xml.streamed.get(), 2);
}

#[test]
fn renewal_prohibits_md5_before_any_provider_or_source_effect() {
    // Baseline §6.2.1's MD5 prohibition is independent of provider support.
    let mut f = fixture();
    f.xml
        .digest_algorithms
        .push((f.digest, "http://www.w3.org/2001/04/xmldsig-more#md5"));
    let work = funded();
    let reading = reading(&f.xml, &work);
    let provider = Oracle::default();
    let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
    assert_eq!(
        report.state(),
        State::Algorithm(structured_xades::certificate::Agreement::ProhibitedAlgorithm)
    );
    assert_eq!(provider.resolved.get(), 0);
    assert_eq!(f.xml.streamed.get(), 0);
}

#[test]
fn renewal_unsupported_streaming_cannot_return_a_successful_report_after_source_mutation() {
    // Even an early semantic capability answer must retain the same source
    // boundary; a provider call cannot leave a stale-source report behind.
    let f = fixture();
    let work = funded();
    let reading = reading(&f.xml, &work);
    let provider = Oracle {
        mutate_start: Some(&f.xml.generation),
        ..Oracle::default()
    };
    assert!(matches!(
        renewed::check(&f.xml, &reading, &provider, &work),
        Err(renewed::CheckError::Access(AccessError::Changed { .. }))
    ));
    assert_eq!(f.xml.streamed.get(), 0);
}

#[test]
fn renewal_scratch_capacity_and_current_work_refusals_drop_every_partial_copy() {
    // Declared digest copies/catalogues belong to this operation, not the
    // retained original parse account. Even a partial successful copy rolls back.
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};
    let f = fixture();
    let original = funded();
    let reading = reading(&f.xml, &original);
    let held = original.used();
    for capacity in [0, 64] {
        let work = Memory::new(Arc::new(MemoryAccount::new(capacity, 1_048_576)));
        let provider = Oracle::default();
        let Err(error) = renewed::check(&f.xml, &reading, &provider, &work) else {
            panic!("unfunded scratch cannot succeed")
        };
        assert!(matches!(
            error,
            renewed::CheckError::Resource { .. } | renewed::CheckError::Binary(_)
        ));
        assert_eq!(provider.started.get(), 0);
        assert_eq!(f.xml.streamed.get(), 0);
        assert_eq!(work.used(), 0);
        assert_eq!(original.used(), held);
    }
    let work = Memory::new(Arc::new(MemoryAccount::new(1_048_576, 0)));
    assert!(matches!(
        renewed::check(&f.xml, &reading, &Oracle::default(), &work),
        Err(renewed::CheckError::Access(AccessError::Resource { .. }))
    ));
    assert_eq!(work.used(), 0);
    assert_eq!(original.used(), held);
}

#[test]
fn renewal_incomplete_and_ignored_receiver_refusal_never_finish_or_become_mismatch() {
    // The same sticky stream kernel must retain the first opaque cause and
    // abandon state on incomplete input, regardless of XML owner behaviour.
    for refusal in [false, true] {
        let mut f = fixture();
        f.xml.incomplete = !refusal;
        f.xml.ignore_refusal = refusal;
        let work = funded();
        let reading = reading(&f.xml, &work);
        let held = work.used();
        let provider = Oracle {
            refuse_update: refusal,
            ..Oracle::default()
        };
        let Err(error) = renewed::check(&f.xml, &reading, &provider, &work) else {
            panic!("refused stream cannot yield a normal report")
        };
        if refusal {
            assert!(matches!(
                error,
                renewed::CheckError::Digest {
                    cause: structured_xades::digest::Error::Provider(Failure::Refused),
                    ..
                }
            ));
        } else {
            assert!(matches!(
                error,
                renewed::CheckError::Digest {
                    cause: structured_xades::digest::Error::Source(renewed::SourceError::Access(
                        AccessError::Xml(Cause::Incomplete)
                    )),
                    ..
                }
            ));
        }
        assert_eq!(provider.started.get(), 1);
        assert_eq!(provider.finished.get(), 0);
        assert_eq!(work.used(), held);
    }
}

#[test]
fn renewal_never_promotes_same_document_or_unprocessed_manifest_catalogues() {
    // Proven detached provenance, not target=None/URI spelling, is required.
    for location in [ObjectLocation::SameDocument, ObjectLocation::Unknown] {
        let mut f = fixture();
        f.xml.reference_locations[0].1 = location;
        let work = funded();
        let reading = reading(&f.xml, &work);
        let provider = Oracle::default();
        let report = renewed::check(&f.xml, &reading, &provider, &work).unwrap();
        assert_eq!(
            report.state(),
            if location == ObjectLocation::Unknown {
                State::UnclassifiedManifest
            } else {
                State::NoDetachedManifest
            }
        );
        assert!(!report.agrees());
        assert_eq!(provider.started.get(), 0);
    }
    let mut f = fixture();
    f.xml.reference_completeness = Completeness::Unchecked(f.instruction);
    let work = funded();
    let reading = reading(&f.xml, &work);
    assert!(
        matches!(renewed::check(&f.xml,&reading,&Oracle::default(),&work),Err(renewed::CheckError::Incomplete(Completeness::Unchecked(node))) if node==f.instruction)
    );
}
