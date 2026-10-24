//! Test-only SHA256 oracle for stream/identity/error control, not production
//! XML provider or transitive backend accounting qualification.

#[path = "async_digest.rs"]
mod asynchronous;
#[path = "finished_digest.rs"]
mod finished;
#[path = "reference_digests.rs"]
mod reference_digests;

use super::{Tree, certificate_tree, funded};
use core::{cell::Cell, cmp::Ordering};
use sha2::{Digest as _, Sha256};
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{MemoryError, Work};
use structured_cms::stream::{Receiver, Refused, Source};
use structured_xades::{
    binary,
    certificate::{Agreement, DigestProvider},
    digest,
    pki::participants,
    xml::{Access, AccessError, Name, Xml},
};

const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

#[derive(Clone, Copy)]
enum Mode {
    Ready,
    Unsupported,
    RefuseUpdate,
    ShortOutput,
}
#[derive(Debug)]
enum Failure {
    Access(AccessError<super::Cause, usize>),
    Resource(MemoryError),
    Refused,
}
impl core::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Access(cause) => write!(formatter, "XML access: {cause:?}"),
            Self::Resource(cause) => cause.fmt(formatter),
            Self::Refused => formatter.write_str("selected provider refused update"),
        }
    }
}

struct Oracle {
    mode: Mode,
    started: Cell<usize>,
    updated: Cell<usize>,
    finished: Cell<usize>,
    resolved: Cell<usize>,
}
impl Oracle {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            started: Cell::new(0),
            updated: Cell::new(0),
            finished: Cell::new(0),
            resolved: Cell::new(0),
        }
    }
}
enum Output {
    Full([u8; 32]),
    Short([u8; 31]),
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Full(value) => value,
            Self::Short(value) => value,
        }
    }
}

impl DigestProvider<'_, Tree> for Oracle {
    fn classify(&self, (): &()) -> structured_xades::hashes::HashClass {
        // This oracle's only resolved native digest is SHA256.
        structured_xades::hashes::HashClass::OtherKnown
    }
    fn resolve<W: Work>(
        &self,
        access: &Access<'_, Tree, W>,
        method: usize,
    ) -> Result<Resolution<()>, Failure> {
        self.resolved.set(self.resolved.get() + 1);
        let available = access
            .attribute(
                method,
                Name {
                    namespace: "",
                    local: "Algorithm",
                },
                |value| {
                    let Some(value) = value else {
                        return Ok(false);
                    };
                    if value.len() != SHA256.len() {
                        return Ok(false);
                    }
                    access.execution().charge_work(value.len() as u64)?;
                    Ok(value == SHA256)
                },
            )
            .map_err(Failure::Access)?
            .map_err(Failure::Resource)?;
        Ok(if available {
            Resolution::Supported(())
        } else {
            Resolution::Unsupported
        })
    }
}

pub(super) fn with_checked_path(
    check: impl FnOnce(
        &structured_ltv::pki::CheckedPath<'_>,
        &[u8],
        &[u8],
        &structured_asn1::memory::Memory,
    ),
) {
    with_checked_path_at(1_767_225_600, check);
}

#[test]
fn basic_assembly_links_original_facts_and_preserves_inclusion_digest_and_hint_failures() {
    // Public assembly must use the actual selected certificate and original
    // KeyInfo, preserve readable hint faults and never repeat certificate hashes
    // or root scalar processing just to combine already checked receipts.
    use structured_xades::{baseline, certificate, hashes, prepare, properties, unsigned};
    with_checked_path(|path, leaf, root, memory| {
        for mode in 0..9 {
            let mut xml = super::attribute_checks::fixture();
            xml.date_time = properties::DateTimeFact::Valid {
                timezone_minutes: Some(0),
            };
            xml.key_association = certificate::KeyAssociation::Same;
            basic_binary_routes(&mut xml, leaf, root, mode);
            xml.hash_completeness = hashes::HashCompleteness::Complete;
            xml.hash_uses.push(hashes::HashUse {
                signature: 0,
                origin: hashes::HashOrigin::SignatureMessage {
                    instruction: 0,
                    method: None,
                },
                state: hashes::HashUseState::Complete(hashes::HashClass::OtherKnown),
            });
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let fields = prepare::check_fields(&prepared, &access).unwrap();
            let counters =
                structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
                    Ok::<_, ()>(path)
                })
                .unwrap();
            let hashes::ParticipantBinding::Bound(hashes) =
                hashes::check_participants(&prepared, &counters, &access).unwrap()
            else {
                panic!("root has a complete actual hash projection")
            };
            let provider = Oracle::new(Mode::Ready);
            let selected = certificate::check_path(
                &xml,
                prepared.bound(),
                prepared.certificates(),
                path,
                &provider,
                memory,
            )
            .unwrap();
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            if mode == 8 {
                // EN319132-1 §5.2.2 Note2: the signed digest binds the actual
                // certificate even when a well-formed retrieval hint differs.
                // Confirm this is a real mismatch, not an accidentally matching
                // fixture; malformed DER remains covered by modes3/4/6.
                let hint = certificate::with_issuer_serial(
                    &xml,
                    prepared.certificates(),
                    0,
                    &operation,
                    |reading| {
                        reading.matches_certificate(selected.selected().certificate(), &operation)
                    },
                )
                .unwrap()
                .unwrap();
                assert_eq!(hint.value, structured_cms::ess::IssuerAgreement::Differs);
                assert!(selected.is_bound());
            }
            let scalar_calls = xml.scalar_calls.get();
            let held = memory.used();
            let input = baseline::BasicInput {
                fields: &fields,
                hashes: &hashes,
                certificate: &selected,
                counters: &counters,
            };
            let checked = baseline::basic(input, &xml, &operation).unwrap();
            assert_eq!(prepared.requirements(), unsigned::Requirements::Basic);
            assert!(core::ptr::eq(checked.inputs().fields, &raw const fields));
            assert_eq!(
                checked.all_root_requirements_met(),
                matches!(mode, 0 | 5 | 7 | 8)
            );
            assert_eq!(checked.included().is_some(), mode != 1);
            assert_eq!(checked.inputs().certificate.is_bound(), mode != 2);
            assert_basic_hints(&checked, &prepared, mode);
            // The B-B level carries the same negative stage outcome; it is
            // never reported as met when any root condition failed.
            let level = baseline::assess(baseline::Evidence::basic(&checked)).unwrap();
            assert_eq!(level.requested(), unsigned::Requirements::Basic);
            assert_eq!(
                level.all_requirements_met(),
                checked.all_root_requirements_met()
            );
            // The selected certificate was hashed exactly once, by check_path.
            assert_eq!((provider.started.get(), provider.finished.get()), (1, 1));
            assert_eq!(xml.scalar_calls.get(), scalar_calls);
            assert_eq!(xml.date_time_calls.get(), 1);
            assert_eq!(xml.streamed.get(), 0);
            // The report owns diagnostic charges, not this parsing scope.
            drop(operation);
            drop(parser);
            if matches!(mode, 3 | 4 | 6) {
                assert_eq!(checked.hints()[0].faults()[0].offset(), 2);
                assert!(memory.used() > held);
            }
            if mode == 4 {
                assert_basic_hint_cutoff(input, &xml);
            }
            drop(checked);
            assert_eq!(memory.used(), held);
        }
    });
}

fn assert_basic_hints(
    checked: &structured_xades::baseline::Basic<'_, '_, '_, '_, usize, u8, u8>,
    prepared: &structured_xades::prepare::Prepared<Tree>,
    mode: u8,
) {
    use structured_xades::baseline::HintSource;
    if matches!(mode, 3 | 4 | 6) {
        assert_eq!(checked.hints().len(), 1);
        let hint = &checked.hints()[0];
        assert_eq!(hint.faults().len(), 1);
        assert_eq!(
            hint.faults()[0].code(),
            structured_cms::ErrorCode::AttributeSyntax
        );
        assert_eq!(hint.faults()[0].offset(), 2);
        assert_eq!(hint.faults()[0].field(), "xades.issuerSerialV2");
        assert_eq!(
            hint.source(),
            if mode == 3 {
                HintSource::Protected(0)
            } else {
                HintSource::ValidationReference {
                    property: 0,
                    entry: 0,
                }
            }
        );
    } else if mode == 5 || mode == 7 || mode == 8 {
        assert_eq!(checked.hints().len(), 1);
        assert!(checked.hints()[0].faults().is_empty());
        if mode == 8 {
            assert_eq!(checked.hints()[0].source(), HintSource::Protected(0));
        }
    } else {
        assert!(checked.hints().is_empty());
    }
    if (4..8).contains(&mode) {
        let references = &prepared.validation_references()[0];
        assert_eq!(
            references.role(),
            if mode >= 6 {
                structured_xades::unsigned::Role::AttributeCertificateReferences
            } else {
                structured_xades::unsigned::Role::CertificateReferences
            }
        );
        let structured_xades::validation::ReferenceIdentifier::Certificate { issuer_serial } =
            references.entries()[0].identifier()
        else {
            panic!("original unsigned hint")
        };
        assert_eq!(checked.hints()[0].location().node, issuer_serial);
        assert_eq!(
            checked.hints()[0].source(),
            HintSource::ValidationReference {
                property: 0,
                entry: 0
            }
        );
    }
}

fn assert_basic_hint_cutoff(
    input: structured_xades::baseline::BasicInput<'_, '_, '_, '_, usize, u8, u8>,
    xml: &Tree,
) {
    // Refuse the LAST source guard after a complete malformed-hint report was
    // retained. Rollback must release both report capacity and nested faults.
    use std::sync::Arc;
    use structured_asn1::{
        Encoding, Limits, Parser,
        memory::{Memory, MemoryAccount},
    };
    use structured_xades::baseline::{self, BasicError};
    let measured = funded();
    let parser = Parser::der(measured.clone());
    let reader = parser.read(&[], 900).unwrap();
    let report = baseline::basic(input, xml, &reader).unwrap();
    assert!(!report.all_root_requirements_met());
    assert_eq!(report.hints().len(), 1);
    let needed = measured.work_used();
    drop(report);
    assert_eq!(measured.used(), 0);
    for aggregate in [false, true] {
        for exact in [false, true] {
            let limit = needed - usize::from(!exact);
            let memory = Memory::new(Arc::new(MemoryAccount::new(
                1 << 20,
                if aggregate { limit } else { 1 << 28 },
            )));
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: if aggregate { 1 << 28 } else { limit as u64 },
                    ..Limits::default()
                },
                memory.clone(),
            );
            let reader = parser.read(&[], 900).unwrap();
            let result = baseline::basic(input, xml, &reader);
            if exact {
                assert!(!result.unwrap().all_root_requirements_met());
            } else {
                assert!(matches!(
                    result,
                    Err(BasicError::Access(AccessError::Resource {
                        cause: MemoryError::WorkExceeded,
                        ..
                    }))
                ));
            }
            assert_eq!(memory.used(), 0);
        }
    }
}

pub(super) fn basic_binary_routes(xml: &mut Tree, leaf: &[u8], root: &[u8], mode: u8) {
    // All values are original source fixtures. No output assertions are changed
    // to accommodate a malformed hint; its shared readable fault is required.
    let find = |xml: &Tree, namespace, local| {
        xml.nodes.iter().position(|node|matches!(node.value,super::Node::Element(name) if name.namespace==namespace&&name.local==local)).unwrap()
    };
    let issuer = find(xml, super::XADES, "IssuerSerialV2");
    if mode == 3 {
        xml.binary_routes
            .push((issuer, vec![0x30, 5, 0x30, 0, 2, 1, 7]));
    } else if mode == 8 {
        xml.binary_routes.push((
            issuer,
            vec![
                0x30, 21, 0x30, 16, 0xa4, 14, 0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c,
                1, b'z', 2, 1, 9,
            ],
        ));
    } else {
        xml.nodes[issuer].parent = None;
    }
    let method = find(xml, super::DS, "DigestMethod");
    let digest = find(xml, super::DS, "DigestValue");
    let certificate = find(xml, super::DS, "X509Certificate");
    xml.digest_algorithms.push((method, SHA256));
    let digest_bytes = if mode == 2 {
        Sha256::digest(root)
    } else {
        Sha256::digest(leaf)
    };
    xml.binary_routes.push((digest, digest_bytes.to_vec()));
    xml.binary_routes
        .push((certificate, if mode == 1 { root } else { leaf }.to_vec()));
    if (4..8).contains(&mode) {
        // Annex A.1.1 imports 5.2.2's one DER IssuerSerial even for an
        // unsigned hint. Base64 readability alone must not hide its faults.
        let mut add = |parent, namespace, local| {
            let node = xml.nodes.len();
            xml.nodes
                .push(super::element(Some(parent), namespace, local));
            node
        };
        if mode >= 6 {
            // Actual original role metadata enables the attribute-reference
            // property. This is not a forged authenticated-credential receipt.
            let role = add(4, super::XADES, "SignerRoleV2");
            let assertions = add(role, super::XADES, "SignedAssertions");
            add(assertions, super::XADES, "SignedAssertion");
        }
        let references = add(
            7,
            super::XADES_141,
            if mode >= 6 {
                "AttributeCertificateRefsV2"
            } else {
                "CompleteCertificateRefsV2"
            },
        );
        let list = add(references, super::XADES_141, "CertRefs");
        let cert = add(list, super::XADES, "Cert");
        let digest = add(cert, super::XADES, "CertDigest");
        let method = add(digest, super::DS, "DigestMethod");
        let value = add(digest, super::DS, "DigestValue");
        let hint = add(cert, super::XADES, "IssuerSerialV2");
        xml.digest_algorithms.push((method, SHA256));
        xml.binary_routes
            .push((value, Sha256::digest(root).to_vec()));
        xml.binary_routes.push((
            hint,
            if mode == 4 || mode == 6 {
                vec![0x30, 5, 0x30, 0, 2, 1, 7]
            } else {
                vec![
                    0x30, 21, 0x30, 16, 0xa4, 14, 0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3,
                    0x0c, 1, b'a', 2, 1, 1,
                ]
            },
        ));
    }
}

pub(super) fn checked_certificate<'a, 'd>(
    xml: &Tree,
    prepared: &'a structured_xades::prepare::Prepared<Tree>,
    path: &'a structured_ltv::pki::CheckedPath<'d>,
    memory: &structured_asn1::memory::Memory,
) -> structured_xades::certificate::CheckedPathCertificate<'a, 'd, usize, u8, u8> {
    // Same actual digest/key/path helper, exposed only within this test binary.
    structured_xades::certificate::check_path(
        xml,
        prepared.bound(),
        prepared.certificates(),
        path,
        &Oracle::new(Mode::Ready),
        memory,
    )
    .unwrap()
}

fn with_checked_path_at(
    instant: i64,
    check: impl FnOnce(
        &structured_ltv::pki::CheckedPath<'_>,
        &[u8],
        &[u8],
        &structured_asn1::memory::Memory,
    ),
) {
    use structured_pkix::path::{Anchor, Interval, ValidationBounds, ValidationContext};
    let (leaf_bytes, root_bytes) = super::timestamp_oracle::certificate_pair();
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let leaf = structured_pkix::Certificate::read(&parser, &leaf_bytes, 400).unwrap();
    let root = structured_pkix::Certificate::read(&parser, &root_bytes, 1200).unwrap();
    let verifier = super::timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let context = ValidationContext {
        execution: &memory,
        interval: Interval::at(instant),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    let structured_ltv::pki::PathOutcome::Accepted(path) =
        structured_ltv::pki::check_path(&[&leaf], Anchor::from_certificate(&root), &context)
            .unwrap()
    else {
        panic!("real issuer path")
    };
    check(&path, &leaf_bytes, &root_bytes, &memory);
    assert_eq!(verifier.calls.get(), 1);
}

fn certificate_path_tree(first: Vec<u8>, second: Vec<u8>) -> Tree {
    let (mut xml, [property, _, _, _, value, issuer]) = certificate_tree();
    xml.nodes[issuer].parent = None;
    xml.binary_routes.push((value, first));
    let cert = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(property), super::XADES, "Cert"));
    let digest = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(cert), super::XADES, "CertDigest"));
    xml.nodes
        .push(super::element(Some(digest), super::DS, "DigestMethod"));
    let value = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(digest), super::DS, "DigestValue"));
    xml.binary_routes.push((value, second));
    xml.digest_algorithm = Some(SHA256);
    xml
}

#[test]
fn signed_certificate_path_digests_keep_first_target_role_and_resolve_each_once() {
    // A root hash is allowed later but cannot replace the first signing-cert
    // hash. The actual checked chain is retained; no path verification repeats.
    use structured_ltv::material::PathCertificate;
    use structured_xades::certificate;
    with_checked_path(|path, leaf, root, memory| {
        for first in [leaf, root] {
            let xml = certificate_path_tree(
                Sha256::digest(first).to_vec(),
                Sha256::digest(root).to_vec(),
            );
            let signed = super::signed_roles(&xml, memory).unwrap();
            let access = Access::new(&xml, xml.snapshot(), memory);
            let references = certificate::read(&access, &signed).unwrap();
            let provider = Oracle::new(Mode::Ready);
            let held = memory.used();
            let report =
                certificate::match_path(&xml, &references, path, &provider, memory).unwrap();
            assert!(core::ptr::eq(report.path(), path));
            assert!(core::ptr::eq(report.references(), &raw const references));
            assert_eq!(report.entries().len(), 2);
            assert_eq!(report.all_match(), core::ptr::eq(first, leaf));
            assert_eq!(
                report.entries()[0].certificate,
                if core::ptr::eq(first, leaf) {
                    Some(PathCertificate::Member(0))
                } else {
                    None
                }
            );
            assert_eq!(
                report.entries()[1].certificate,
                Some(PathCertificate::Anchor)
            );
            assert_eq!(provider.resolved.get(), 2);
            assert_eq!(provider.started.get(), 3);
            drop(report);
            assert_eq!(memory.used(), held);
        }
    });
}

#[test]
fn path_digest_width_and_storage_refusals_precede_candidate_hashing() {
    // Impossible declared width is separate from mismatch; report allocation
    // refusal runs no resolver/hash and never returns a successful partial set.
    use structured_xades::certificate;
    with_checked_path(|path, leaf, _, memory| {
        let xml = certificate_path_tree(Sha256::digest(leaf).to_vec(), vec![0; 31]);
        let signed = super::signed_roles(&xml, memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), memory);
        let references = certificate::read(&access, &signed).unwrap();
        let provider = Oracle::new(Mode::Ready);
        let report = certificate::match_path(&xml, &references, path, &provider, memory).unwrap();
        assert_eq!(report.entries()[0].agreement, Agreement::Matches);
        assert_eq!(report.entries()[1].agreement, Agreement::MalformedValue);
        assert!(!report.all_match());
        assert_eq!(provider.resolved.get(), 2);
        assert_eq!(provider.started.get(), 1);
        let denied = structured_asn1::memory::Memory::new(std::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(0, 1 << 24),
        ));
        let provider = Oracle::new(Mode::Ready);
        assert!(matches!(
            certificate::match_path(&xml, &references, path, &provider, &denied),
            Err(binary::Error::Callback {
                cause: certificate::DigestError::Resource(_),
                ..
            })
        ));
        assert_eq!(provider.resolved.get(), 0);
        assert_eq!(provider.started.get(), 0);
        assert_eq!(denied.used(), 0);
    });
}

#[test]
fn selected_certificate_path_binding_reuses_first_digest_without_promoting_unproven_keys() {
    // The selected-key receipt and path restrictions share their first hash;
    // correct digests alone cannot turn an unproven XML key into a binding.
    use structured_xades::{binding, certificate, container};
    with_checked_path(|path, leaf, root, memory| {
        for association in [
            certificate::KeyAssociation::Same,
            certificate::KeyAssociation::Unproven,
        ] {
            let mut xml =
                certificate_path_tree(Sha256::digest(leaf).to_vec(), Sha256::digest(root).to_vec());
            xml.key_association = association;
            let signed = super::signed_roles(&xml, memory).unwrap();
            let access = Access::new(&xml, xml.snapshot(), memory);
            let references = certificate::read(&access, &signed).unwrap();
            let layout = container::locate(&access, 0).unwrap();
            let bound = binding::bind(&access, &layout).unwrap();
            let provider = Oracle::new(Mode::Ready);
            let checked =
                certificate::check_path(&xml, &bound, &references, path, &provider, memory)
                    .unwrap();
            assert_eq!(
                checked.is_bound(),
                association == certificate::KeyAssociation::Same
            );
            assert_eq!(checked.selected().key(), association);
            // Association must receive this actual checked path's key and
            // original parameter view, not a reconstructed certificate key.
            assert_eq!(
                xml.key_projection.get(),
                Some(super::KeyProjection::of(path.facts().key))
            );
            assert_eq!(checked.selected().digest(), Agreement::Matches);
            assert!(checked.digests().all_match());
            assert!(core::ptr::eq(
                checked.selected().certificate(),
                path.members()[0].certificate()
            ));
            assert_eq!(provider.resolved.get(), 2);
            assert_eq!(provider.started.get(), 3);
        }
    });
}

#[test]
fn plain_counter_path_binding_uses_actual_selected_key_without_inventing_properties() {
    // Plain XMLDSig counters have no XAdES signing-certificate property. Their
    // actual selected-key receipt must still bind every actor's material path.
    use structured_xades::{binding, certificate, container, counter, pki};
    with_checked_path(|path, _, _, memory| {
        for association in [
            certificate::KeyAssociation::Same,
            certificate::KeyAssociation::Differs,
            certificate::KeyAssociation::Unproven,
        ] {
            let mut xml = Tree::normal();
            let (child, _, _) = super::append_nested_counter(&mut xml, 7, 12, false);
            xml.key_association = association;
            let access = Access::new(&xml, xml.snapshot(), memory);
            let layout = container::locate(&access, 0).unwrap();
            let root = binding::bind(&access, &layout).unwrap();
            let properties = xml.nodes[child].parent.unwrap();
            let original = counter::read(&access, &root, properties).unwrap();
            let checked = counter::bind(&access, original).unwrap();
            let capacity = memory.used();
            let result = pki::bind_counter(path, &checked, &access).unwrap();
            match (association, result) {
                (certificate::KeyAssociation::Same, pki::CounterBinding::Bound(bound)) => {
                    assert!(core::ptr::eq(bound.path(), path));
                    assert_eq!(bound.counter().reference(), checked.reference());
                    assert_eq!(bound.counter().ordinal(), checked.ordinal());
                    assert_eq!(bound.counter().original().child(), child);
                }
                (certificate::KeyAssociation::Differs, pki::CounterBinding::Differs)
                | (certificate::KeyAssociation::Unproven, pki::CounterBinding::Unproven) => {}
                _ => panic!("selected-key cause must remain distinct"),
            }
            assert_eq!(memory.used(), capacity);
            // Retain the scalar source receipt beyond the movable walk frame;
            // only the independently checked certificate path stays borrowed.
            let retained = counter::walk(&access, &root, |checked, _| {
                pki::bind_counter(path, checked, &access)
            })
            .unwrap();
            assert_eq!(retained.len(), 1);
            if let pki::CounterBinding::Bound(bound) = &retained[0] {
                assert_eq!(bound.counter().original().child(), child);
            }
            drop(retained);
            assert_eq!(memory.used(), capacity);
            assert_eq!(
                xml.key_projection.get(),
                Some(super::KeyProjection::of(path.facts().key))
            );
            xml.key_projection.set(None);
            let empty = structured_asn1::memory::Memory::new(super::Arc::new(
                structured_asn1::memory::MemoryAccount::new(0, 0),
            ));
            let refused = Access::new(&xml, xml.snapshot(), &empty);
            assert!(matches!(
                pki::bind_counter(path, &checked, &refused),
                Err(AccessError::Resource { .. })
            ));
            assert_eq!(xml.key_projection.get(), None);
            let mut stale = xml.snapshot();
            stale.generation += 1;
            let stale = Access::new(&xml, stale, memory);
            assert!(matches!(
                pki::bind_counter(path, &checked, &stale),
                Err(AccessError::Changed { .. })
            ));
            assert_eq!(xml.key_projection.get(), None);
        }
    });
}

fn counter_material_tree(leaf: &[u8], root: &[u8], broken: bool) -> (Tree, Vec<usize>) {
    // Synthetic XML projection only. Actual common path/key receipts select
    // both counters; retained material itself remains untrusted until checked.
    let mut xml = super::preparation_tree();
    xml.binary = leaf.to_vec();
    xml.key_association = structured_xades::certificate::KeyAssociation::Same;
    let (first, value, parent) = super::append_nested_counter(&mut xml, 7, 12, true);
    let (second, _, _) = super::append_nested_counter(&mut xml, parent.unwrap(), value, false);
    let mut expected = Vec::new();
    for (signature, certificates) in [(first, &[leaf, root][..]), (second, &[root][..])] {
        let key_info = xml.nodes.len();
        xml.nodes
            .push(super::element(Some(signature), super::DS, "KeyInfo"));
        for certificate in certificates {
            let data = xml.nodes.len();
            xml.nodes
                .push(super::element(Some(key_info), super::DS, "X509Data"));
            expected.push(counter_material_value(
                &mut xml,
                data,
                super::DS,
                "X509Certificate",
                certificate.to_vec(),
            ));
        }
    }
    let last_header = expected.pop().unwrap();
    let parent = parent.unwrap();
    let revocation = xml.nodes.len();
    xml.nodes.push(super::element(
        Some(parent),
        super::XADES,
        "RevocationValues",
    ));
    let values = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(revocation), super::XADES, "CRLValues"));
    expected.push(counter_material_value(
        &mut xml,
        values,
        super::XADES,
        "EncapsulatedCRLValue",
        if broken {
            Vec::new()
        } else {
            super::readable_crl_fixture(b"260101000000Z")
        },
    ));
    let general = xml.nodes.len();
    xml.nodes.push(super::element(
        Some(parent),
        super::XADES_141,
        "AnyValidationData",
    ));
    let certificates = xml.nodes.len();
    xml.nodes.push(super::element(
        Some(general),
        super::XADES,
        "CertificateValues",
    ));
    expected.push(counter_material_value(
        &mut xml,
        certificates,
        super::XADES,
        "EncapsulatedX509Certificate",
        root.to_vec(),
    ));
    let revocation = xml.nodes.len();
    xml.nodes.push(super::element(
        Some(general),
        super::XADES,
        "RevocationValues",
    ));
    let values = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(revocation), super::XADES, "CRLValues"));
    expected.push(counter_material_value(
        &mut xml,
        values,
        super::XADES,
        "EncapsulatedCRLValue",
        super::readable_crl_fixture(b"270101000000Z"),
    ));
    expected.push(last_header);
    (xml, expected)
}

fn counter_material_value(
    xml: &mut Tree,
    parent: usize,
    namespace: &'static str,
    local: &'static str,
    bytes: Vec<u8>,
) -> usize {
    let node = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(parent), namespace, local));
    xml.binary_routes.push((node, bytes));
    node
}

#[test]
fn nested_counter_timestamps_keep_own_inputs_and_archive_precedence() {
    // A root archive covers an earlier counter's entire subtree, including a
    // grandchild timestamp. A later sibling counter is not its antecedent.
    // All-token LT must nevertheless retain that later token as an obligation.
    use structured_xades::{prepare, timestamp, unsigned};
    with_checked_path(|path, leaf, _, memory| {
        let mut xml = super::preparation_tree();
        xml.binary = leaf.to_vec();
        xml.key_association = structured_xades::certificate::KeyAssociation::Same;
        let (first, first_value, first_parent) =
            super::append_nested_counter(&mut xml, 7, 12, true);
        let (grandchild, grand_value, grand_parent) =
            super::append_nested_counter(&mut xml, first_parent.unwrap(), first_value, true);
        let (first_stamp, first_tokens) = super::append_timestamp(
            &mut xml,
            first_parent.unwrap(),
            timestamp::Role::Signature,
            1,
        );
        let (grand_stamp, grand_tokens) = super::append_timestamp(
            &mut xml,
            grand_parent.unwrap(),
            timestamp::Role::Signature,
            1,
        );
        let (archive, _) = super::append_timestamp(&mut xml, 7, timestamp::Role::Archive, 1);
        let (later, later_value, later_parent) =
            super::append_nested_counter(&mut xml, 7, 12, true);
        let (later_stamp, later_tokens) = super::append_timestamp(
            &mut xml,
            later_parent.unwrap(),
            timestamp::Role::Signature,
            1,
        );
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        let before = memory.used();
        let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
        assert_eq!(stamps.entries().len(), 3);
        for (entry, (property, value)) in stamps.entries().iter().zip([
            (first_stamp, first_value),
            (grand_stamp, grand_value),
            (later_stamp, later_value),
        ]) {
            assert_eq!(entry.stamp().node(), property);
            let input = entry.input(&xml, memory).unwrap();
            let coverage = input.element_coverage(memory).unwrap();
            assert!(coverage.selects(value, &access).unwrap());
            assert!(!coverage.selects(12, &access).unwrap());
        }
        let all = timestamp::requirements_with_counters(
            &access,
            &prepared,
            &stamps,
            timestamp::TimestampSelection::All,
        )
        .unwrap();
        assert_eq!(all.entries().len(), 5);
        for (entry, (owner, property, token)) in all.entries()[2..].iter().zip([
            (first, first_stamp, first_tokens[0]),
            (grandchild, grand_stamp, grand_tokens[0]),
            (later, later_stamp, later_tokens[0]),
        ]) {
            assert_eq!(
                (entry.signature, entry.property, entry.token),
                (owner, property, token)
            );
        }
        let at = prepared
            .timestamps()
            .iter()
            .position(|entry| entry.node() == archive)
            .unwrap();
        let prior = timestamp::requirements_with_counters(
            &access,
            &prepared,
            &stamps,
            timestamp::TimestampSelection::BeforeArchive(at),
        )
        .unwrap();
        assert_eq!(prior.entries().len(), 3);
        assert_eq!(prior.entries()[1].token, first_tokens[0]);
        assert_eq!(prior.entries()[2].token, grand_tokens[0]);
        assert!(matches!(
            all.bind_paths(&[], &access).unwrap(),
            structured_ltv::timestamp::TimestampPathBinding::Unproven(
                structured_ltv::timestamp::TimestampPathFailure::Count
            )
        ));
        drop(prior);
        drop(all);
        drop(stamps);
        assert_eq!(memory.used(), before);
    });
}

#[test]
fn complete_counter_material_pool_keeps_nested_and_plain_child_sources() {
    // Two X509Data in an XAdES counter and one in its plain XMLDSig child:
    // neither child needs the root's SigningCertificateV2/SigningTime/KeyInfo
    // cardinality. All six child values share ONE frozen original source pool.
    use structured_xades::{material, prepare, unsigned};
    with_checked_path(|path, leaf, root, memory| {
        for broken in [false, true] {
            let (xml, expected) = counter_material_tree(leaf, root, broken);
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters =
                structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
                    Ok::<_, ()>(path)
                })
                .unwrap();
            assert_eq!(counters.actors().len(), 2);
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            let before = memory.used();
            let calls = Cell::new(0);
            let result =
                material::with_counter_values(&xml, &prepared, &counters, &operation, |_, view| {
                    calls.set(calls.get() + 1);
                    assert_eq!(view.sources().len(), 7);
                    assert_eq!(view.values().len(), 7);
                    for ((source, value), expected) in view.sources()[1..]
                        .iter()
                        .zip(&view.values()[1..])
                        .zip(&expected)
                    {
                        assert_eq!(source.source().location().node, *expected);
                        assert_eq!(value.location.node, *expected);
                        let bytes = match &value.value {
                            material::Value::Certificate(value) => value.as_bytes(),
                            material::Value::Crl(value) => value.as_bytes(),
                            material::Value::Ocsp(_) => panic!("no fabricated status format"),
                        };
                        assert_eq!(bytes.as_ptr(), source.source().bytes().as_ptr());
                        assert_eq!(bytes, source.source().bytes());
                    }
                    Ok::<_, ()>(())
                });
            if broken {
                assert!(
                    matches!(result,Err(material::PipelineError::Parse(binary::Located{
                    location,value:material::Cause::Empty{..}})) if location.node==expected[2])
                );
                assert_eq!(calls.get(), 0);
            } else {
                result.unwrap();
                assert_eq!(calls.get(), 1);
            }
            assert_eq!(memory.used(), before);
        }
    });
}

#[test]
fn nested_counter_token_pool_preserves_each_source_and_drops_partial_decode() {
    // Token parsing is shared, but every token keeps its own child signature,
    // property and source bytes. A broken last token cannot yield a prefix or
    // run a visitor with missing TSA material; all temporary capacity releases.
    use structured_xades::{prepare, timestamp, unsigned};
    with_checked_path(|path, _, _, memory| {
        let (_, token, _, _) = super::timestamp_oracle::fixture_with_root(b"inspection only");
        for broken in [false, true] {
            let mut xml = super::preparation_tree();
            xml.binary = token.clone();
            xml.key_association = structured_xades::certificate::KeyAssociation::Same;
            let (first, value, parent) = super::append_nested_counter(&mut xml, 7, 12, true);
            let (second, _, nested) =
                super::append_nested_counter(&mut xml, parent.unwrap(), value, true);
            let (first_stamp, first_tokens) =
                super::append_timestamp(&mut xml, parent.unwrap(), timestamp::Role::Signature, 1);
            let (second_stamp, second_tokens) =
                super::append_timestamp(&mut xml, nested.unwrap(), timestamp::Role::Archive, 2);
            if broken {
                xml.binary_routes.push((second_tokens[1], Vec::new()));
            }
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters =
                structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
                    Ok::<_, ()>(path)
                })
                .unwrap();
            let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            let before = memory.used();
            let calls = Cell::new(0);
            let result =
                timestamp::with_counter_tokens(&xml, &prepared, &stamps, &operation, |_, view| {
                    calls.set(calls.get() + 1);
                    assert_eq!(view.sources().len(), 4);
                    assert_eq!(view.readings().len(), 4);
                    for (source, (owner, property, node)) in view.sources()[1..].iter().zip([
                        (first, first_stamp, first_tokens[0]),
                        (second, second_stamp, second_tokens[0]),
                        (second, second_stamp, second_tokens[1]),
                    ]) {
                        assert_eq!(
                            (
                                source.signature(),
                                source.property(),
                                source.location().node
                            ),
                            (owner, property, node)
                        );
                        assert_eq!(source.bytes(), token);
                    }
                    Ok::<_, ()>(())
                });
            if broken {
                assert!(
                    matches!(result, Err(timestamp::TokenPipelineError::Token {location,..}) if location.node == second_tokens[1])
                );
                assert_eq!(calls.get(), 0);
            } else {
                result.unwrap();
                assert_eq!(calls.get(), 1);
            }
            assert_eq!(memory.used(), before);
        }
    });
}

#[test]
fn nested_signature_timestamp_math_binds_child_signature_value() {
    // Real TSP signature/hash checks over synthetic XML framing. A token over
    // the root value must not establish a timestamp for a nested child value.
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    use structured_xades::{prepare, timestamp, unsigned};
    for (wrong_value, pooled) in [(false, false), (true, false), (false, true), (true, true)] {
        with_checked_path(|path, _, _, memory| {
            let mut xml = super::preparation_tree();
            xml.key_association = structured_xades::certificate::KeyAssociation::Same;
            let (_, value, parent) = super::append_nested_counter(&mut xml, 7, 12, true);
            let (child, own_value, parent) =
                super::append_nested_counter(&mut xml, parent.unwrap(), value, true);
            let (property, tokens) =
                super::append_timestamp(&mut xml, parent.unwrap(), timestamp::Role::Signature, 1);
            let method = property + 1; // fixture appends the original method immediately after property
            let covered = if wrong_value { 12 } else { own_value };
            let bytes = [
                b'E',
                u8::try_from(covered).unwrap(),
                b'M',
                u8::try_from(method).unwrap(),
            ];
            let (provider, token, tsa, _) = super::timestamp_oracle::fixture_with_root(&bytes);
            xml.binary = token;
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters =
                structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
                    Ok::<_, ()>(path)
                })
                .unwrap();
            let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            let certificate = structured_pkix::Certificate::read(&parser, &tsa, 400).unwrap();
            let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
            let context = structured_cms::timestamp::CheckContext {
                certificate: &certificate,
                certificate_parent: &operation,
                key: WorkingKey::standing(certificate.tbs().public_key()),
                requested: None,
                utc: &utc,
                reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
                window: None,
            };
            let check = timestamp::Check {
                xml: &xml,
                provider: &provider,
                context: &context,
            };
            let actor = if pooled {
                timestamp::with_counter_tokens(
                    &xml,
                    &prepared,
                    &stamps,
                    &operation,
                    |query, view| {
                        assert!(matches!(
                            check.retain_counter_from(
                                &stamps.entries()[0],
                                view.entry(0).unwrap(),
                                query,
                                |_, _| Ok::<_, ()>(false)
                            ),
                            Err(timestamp::CheckError::Input(
                                timestamp::InputError::Foreign { .. }
                            ))
                        ));
                        assert_eq!(provider.verified.get(), 0);
                        xml.decoded_pointer.set(0);
                        let result = check
                            .retain_counter_from(
                                &stamps.entries()[0],
                                view.entry(1).unwrap(),
                                query,
                                |_, _| Ok::<_, ()>(false),
                            )
                            .unwrap();
                        assert_eq!(xml.decoded_pointer.get(), 0); // no second binary decoding
                        Ok::<_, ()>(result)
                    },
                )
                .unwrap()
            } else {
                check
                    .retain_counter_actor(&stamps.entries()[0], 0, &operation, |_, _| {
                        Ok::<_, ()>(false)
                    })
                    .unwrap()
            };
            assert_counter_actor(actor, wrong_value, (child, property, tokens[0]));
            assert_eq!(provider.verified.get(), 1);
        });
    }
}

fn assert_counter_actor(
    actor: Option<structured_xades::timestamp::TimestampActor<'_, '_, Tree>>,
    wrong_value: bool,
    expected: (usize, usize, usize),
) {
    if wrong_value {
        assert!(actor.is_none());
    } else {
        let actor = actor.unwrap();
        let evidence = actor.verified();
        assert_eq!(
            (
                evidence.signature(),
                evidence.property(),
                evidence.token().node
            ),
            expected
        );
    }
}

#[test]
fn unsigned_counter_timestamp_cannot_borrow_another_signatures_qualifying_target() {
    // EN319132-1 4.3.1 binds even UNSIGNED properties to their corresponding
    // Signature via Target. An actual checked counter and valid token framing
    // cannot substitute this association; no child B-B header is required.
    use structured_xades::{binding, container, prepare, timestamp, unsigned};
    with_checked_path(|path, _, _, memory| {
        let mut xml = super::preparation_tree();
        xml.key_association = structured_xades::certificate::KeyAssociation::Same;
        let (child, _, parent) = super::append_nested_counter(&mut xml, 7, 12, true);
        super::append_timestamp(&mut xml, parent.unwrap(), timestamp::Role::Signature, 1);
        let layout = container::locate(&Access::new(&xml, xml.snapshot(), memory), child).unwrap();
        xml.target_routes
            .push((layout.qualifying(), super::Target::LocalBareName(0)));
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        let held = memory.used();
        let Err(cause) = timestamp::counter_timestamps(&access, &counters) else {
            panic!("accepted a child timestamp whose Target selects the root signature");
        };
        assert!(matches!(cause,
            timestamp::CounterTimestampError::Binding(binding::BindingError::Target { node })
                if node == layout.qualifying()));
        assert_eq!(memory.used(), held);
        assert_eq!(xml.streamed.get(), 0);
    });
}

#[test]
fn signed_counter_timestamps_require_whole_properties_but_not_child_baseline() {
    // A signed-object timestamp cannot be read as authenticated using only the
    // counter's parent-Value reference. No fabricated SigningTime/cert property
    // is required once the actual SignedProperties reference succeeds.
    use structured_xades::{binding, container, prepare, timestamp, unsigned};
    with_checked_path(|path, _, _, memory| {
        for coverage in [
            None,
            Some(super::Coverage::Transformed),
            Some(super::Coverage::ElementContent),
        ] {
            let mut xml = super::preparation_tree();
            xml.key_association = structured_xades::certificate::KeyAssociation::Same;
            let (child, _, _) = super::append_nested_counter(&mut xml, 7, 12, true);
            let layout =
                container::locate(&Access::new(&xml, xml.snapshot(), memory), child).unwrap();
            let objects = xml.nodes.len();
            xml.nodes.push(super::element(
                Some(layout.signed()),
                super::XADES,
                "SignedDataObjectProperties",
            ));
            let (property, _) =
                super::append_timestamp(&mut xml, objects, timestamp::Role::AllDataObjects, 1);
            let mut reference = None;
            if let Some(coverage) = coverage {
                let evidence = xml.nested_counters.last_mut().unwrap();
                let info = xml.nodes[evidence.references[0].node].parent.unwrap();
                let node = xml.nodes.len();
                xml.nodes
                    .push(super::element(Some(info), super::DS, "Reference"));
                reference = Some(node);
                evidence.references.push(super::Reference {
                    node,
                    target: Some(layout.signed()),
                    kind: Some(super::SIGNED_PROPERTIES),
                    status: super::Status::Valid,
                    coverage,
                });
            }
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters =
                structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
                    Ok::<_, ()>(path)
                })
                .unwrap();
            let before = memory.used();
            let result = timestamp::counter_timestamps(&access, &counters);
            match coverage {
                None => assert!(
                    matches!(result, Err(timestamp::CounterTimestampError::Binding(binding::BindingError::References {node})) if node==child)
                ),
                Some(super::Coverage::Transformed) => assert!(
                    matches!(result, Err(timestamp::CounterTimestampError::Binding(binding::BindingError::Reference {node})) if Some(node)==reference)
                ),
                Some(super::Coverage::ElementContent) => {
                    let reading = result.unwrap();
                    assert_eq!(reading.entries().len(), 1);
                    assert_eq!(reading.entries()[0].stamp().node(), property);
                    assert_eq!(
                        reading.entries()[0].stamp().role(),
                        timestamp::Role::AllDataObjects
                    );
                }
            }
            assert_eq!(memory.used(), before);
        }
    });
}

#[test]
fn counter_timestamp_source_guards_precede_decoding_and_refusals_release_capacity() {
    // Equal ordinals/accounts are not original document identity. A foreign
    // child pool is rejected before decoding any root token; zero current work
    // and storage never produce an empty successful timestamp census.
    use structured_xades::{prepare, timestamp, unsigned};
    with_checked_path(|path, _, _, memory| {
        let mut xml = super::preparation_tree();
        xml.key_association = structured_xades::certificate::KeyAssociation::Same;
        let (_, _, parent) = super::append_nested_counter(&mut xml, 7, 12, true);
        super::append_timestamp(&mut xml, parent.unwrap(), timestamp::Role::Signature, 1);
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
        let mut foreign = super::preparation_tree();
        foreign.document = xml.document + 1;
        let selected = prepare::prepare(
            &Access::new(&foreign, foreign.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        assert!(matches!(
            timestamp::with_counter_tokens(
                &foreign,
                &selected,
                &stamps,
                &operation,
                |_, _| -> Result<(), ()> { panic!("foreign pool") }
            ),
            Err(timestamp::TokenPipelineError::Foreign { node: 0 })
        ));
        assert_eq!(foreign.decoded_pointer.get(), 0);
        let held = memory.used();
        for (capacity, work) in [(0, 100_000), (100_000, 0)] {
            let denied = structured_asn1::memory::Memory::new(std::sync::Arc::new(
                structured_asn1::memory::MemoryAccount::new(capacity, work),
            ));
            let denied = Access::new(&xml, xml.snapshot(), &denied);
            assert!(matches!(
                timestamp::counter_timestamps(&denied, &counters),
                Err(timestamp::CounterTimestampError::Input(
                    timestamp::InputError::Access(AccessError::Resource { .. })
                        | timestamp::InputError::Resource { .. }
                ))
            ));
            assert_eq!(memory.used(), held);
        }
    });
}

#[test]
fn counter_material_refusals_preserve_original_cause_and_release_all_sources() {
    // New current-operation admission is required even for retained counter
    // receipts. Zero memory/work cannot become an empty successful catalogue.
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
    use structured_xades::{material, prepare, unsigned};
    with_checked_path(|path, leaf, root, memory| {
        let (xml, _) = counter_material_tree(leaf, root, false);
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        let held = memory.used();
        for (storage, work) in [(0, 1_000_000), (65_536, 0)] {
            let current = Memory::new(super::Arc::new(MemoryAccount::new(storage, work)));
            let parser = structured_asn1::Parser::der(current.clone());
            let operation = parser.read(&[], 900).unwrap();
            let result = material::with_counter_values(
                &xml,
                &prepared,
                &counters,
                &operation,
                |_, _| -> Result<(), ()> {
                    panic!("refused before any successful material callback")
                },
            );
            if work == 0 {
                assert!(matches!(
                    result,
                    Err(material::PipelineError::Access(AccessError::Resource {
                        cause: MemoryError::WorkExceeded,
                        ..
                    }))
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(material::PipelineError::Retain {
                        cause: material::RetainError::Access(AccessError::Xml(
                            super::Cause::Resource(MemoryError::LimitExceeded)
                        )),
                        ..
                    } | material::PipelineError::Resource {
                        cause: MemoryError::LimitExceeded,
                        ..
                    })
                ));
            }
            assert_eq!(current.used(), 0);
            assert_eq!(memory.used(), held);
        }
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let original = "original visitor refusal";
        let result =
            material::with_counter_values(&xml, &prepared, &counters, &operation, |_, _| {
                xml.generation.set(xml.generation.get() + 1);
                Err::<(), _>(original)
            });
        assert!(matches!(result,Err(material::PipelineError::Visitor(cause)) if cause==original));
        assert_eq!(memory.used(), held);
    });
}

#[test]
fn foreign_counter_source_is_rejected_before_root_decoding() {
    // Same scalar node ordinals/path/account are not document identity. The
    // source guard must run before retaining even the first root certificate.
    use structured_xades::{material, prepare, unsigned};
    with_checked_path(|path, leaf, root, memory| {
        let (xml, _) = counter_material_tree(leaf, root, false);
        let (mut foreign, _) = counter_material_tree(leaf, root, false);
        foreign.document = xml.document + 1;
        let access = Access::new(&xml, xml.snapshot(), memory);
        let foreign_access = Access::new(&foreign, foreign.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let selected =
            prepare::prepare(&foreign_access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters =
            structured_xades::pki::bind_counters(selected.bound(), &foreign_access, |_, _| {
                Ok::<_, ()>(path)
            })
            .unwrap();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let held = memory.used();
        assert_eq!(xml.decoded_pointer.get(), 0);
        let result =
            material::with_counter_values(&xml, &prepared, &counters, &operation, |_, _| {
                Ok::<_, ()>(())
            });
        assert!(matches!(
            result,
            Err(material::PipelineError::Foreign { node: 0 })
        ));
        assert_eq!(xml.decoded_pointer.get(), 0);
        assert_eq!(memory.used(), held);
    });
}

#[test]
fn plain_counter_without_key_info_does_not_acquire_root_header_requirements() {
    // XMLDSig1.1 KeyInfo is optional. The actual successful external key/path
    // remains explicit; missing child data is NOT a fabricated incorporated
    // certificate and must later remain missing in material availability.
    use structured_xades::{material, prepare, unsigned};
    with_checked_path(|path, leaf, root, memory| {
        let (mut xml, mut expected) = counter_material_tree(leaf, root, false);
        let child = xml.nested_counters[1].child;
        let key_info = xml.element_child(child, super::DS, "KeyInfo");
        xml.nodes[key_info].parent = None;
        expected.pop();
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
            Ok::<_, ()>(path)
        })
        .unwrap();
        assert_eq!(counters.actors().len(), 2);
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let held = memory.used();
        material::with_counter_values(&xml,&prepared,&counters,&operation,|_,view| {
            assert_eq!(view.sources().len(),6);
            for (source,node) in view.sources()[1..].iter().zip(&expected) {
                assert_eq!(source.source().location().node,*node);
                assert!(!matches!(source.placement(),material::Placement::KeyInfo(signature) if signature==child));
            }
            Ok::<_,()>(())
        }).unwrap();
        assert_eq!(memory.used(), held);
    });
}

#[test]
fn complete_counter_paths_require_every_original_actor_and_drop_late_failure() {
    // A caller cannot form the complete set by omitting the later counter
    // whose path is missing. The original walk, not supplied successes, counts.
    use structured_xades::{binding, certificate, container, counter, pki};
    with_checked_path(|path, _, _, memory| {
        for missing in [false, true] {
            let mut xml = Tree::normal();
            let (first, _, _) = super::append_nested_counter(&mut xml, 7, 12, false);
            let (second, _, _) = super::append_nested_counter(&mut xml, 7, 12, false);
            xml.key_association = certificate::KeyAssociation::Same;
            let access = Access::new(&xml, xml.snapshot(), memory);
            let layout = container::locate(&access, 0).unwrap();
            let root = binding::bind(&access, &layout).unwrap();
            let capacity = memory.used();
            let calls = Cell::new(0);
            let result = structured_xades::pki::bind_counters(&root, &access, |counter, work| {
                work.charge_work(1).unwrap();
                calls.set(calls.get() + 1);
                if missing && counter.original().child() == second {
                    return Err("no checked path for second counter");
                }
                Ok(path)
            });
            assert_eq!(calls.get(), 2);
            if missing {
                assert!(matches!(result, Err(counter::WalkError::Visitor(
                    pki::CounterSelectionError::Selection { signature, cause: "no checked path for second counter" }
                )) if signature == second));
            } else {
                let result = result.unwrap();
                assert_eq!(result.snapshot(), xml.snapshot());
                assert_eq!(result.signature(), 0);
                assert_eq!(result.actors().len(), 2);
                assert_eq!(
                    result.actors()[0].signer().counter().original().child(),
                    first
                );
                assert_eq!(
                    result.actors()[1].signer().counter().original().child(),
                    second
                );
                assert!(core::ptr::eq(result.actors()[0].signer().path(), path));
                assert!(memory.used() > capacity);
                drop(result);
            }
            assert_eq!(memory.used(), capacity);
        }
    });
}

pub(super) fn append_assertion(xml: &mut Tree, parent: usize) -> (usize, usize) {
    let property = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(parent), super::XADES, "SignerRoleV2"));
    let assertions = xml.nodes.len();
    xml.nodes.push(super::element(
        Some(property),
        super::XADES,
        "SignedAssertions",
    ));
    let assertion = xml.nodes.len();
    xml.nodes.push(super::element(
        Some(assertions),
        super::XADES,
        "SignedAssertion",
    ));
    (property, assertion)
}

pub(super) fn append_counter_credentials(
    xml: &mut Tree,
    memory: &structured_asn1::memory::Memory,
    coverage: super::Coverage,
) -> (usize, usize, usize, usize) {
    let (child, _, _) = super::append_nested_counter(xml, 7, 12, true);
    let layout = {
        let access = Access::new(xml, xml.snapshot(), memory);
        structured_xades::container::locate(&access, child).unwrap()
    };
    let signature_properties = xml
        .nodes
        .iter()
        .position(|node| {
            node.parent == Some(layout.signed())
                && matches!(
                    node.value,
                    structured_xades::xml::Node::Element(Name {
                        namespace: super::XADES,
                        local: "SignedSignatureProperties"
                    })
                )
        })
        .unwrap();
    let (property, assertion) = append_assertion(xml, signature_properties);
    let evidence = xml.nested_counters.last_mut().unwrap();
    let info = xml.nodes[evidence.references[0].node].parent.unwrap();
    let reference = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(info), super::DS, "Reference"));
    evidence.references.push(super::Reference {
        node: reference,
        target: Some(layout.signed()),
        kind: Some(super::SIGNED_PROPERTIES),
        status: super::Status::Valid,
        coverage,
    });
    (child, property, assertion, reference)
}

#[test]
fn counter_credentials_require_original_property_coverage_without_child_baseline_requirements() {
    // A counter can carry credentials without claiming B-B itself. Its role
    // source must nevertheless be authenticated; missing root-only fields are
    // not a reason to discard those credential participants.
    use structured_xades::{binding, certificate, container, counter, pki, role};
    with_checked_path(|path, _, _, memory| {
        for coverage in [
            super::Coverage::ElementContent,
            super::Coverage::Transformed,
        ] {
            let mut xml = Tree::normal();
            let (child, property, assertion, reference) =
                append_counter_credentials(&mut xml, memory, coverage);
            xml.key_association = certificate::KeyAssociation::Same;
            let access = Access::new(&xml, xml.snapshot(), memory);
            let layout = container::locate(&access, 0).unwrap();
            let root = binding::bind(&access, &layout).unwrap();
            let before = memory.used();
            let selections = Cell::new(0);
            let result = structured_xades::pki::bind_counters(&root, &access, |_, _| {
                selections.set(selections.get() + 1);
                Ok::<_, ()>(path)
            });
            if coverage == super::Coverage::Transformed {
                assert!(matches!(result, Err(counter::WalkError::Visitor(
                    pki::CounterSelectionError::Binding(super::BindingError::Reference { node })
                )) if node == reference));
                assert_eq!(selections.get(), 0);
            } else {
                let checked = result.unwrap();
                let roles = checked.actors()[0].roles().unwrap();
                assert_eq!(roles.signature(), child);
                assert_eq!(roles.node(), property);
                assert_eq!(roles.entries().len(), 1);
                assert_eq!(roles.entries()[0].node, assertion);
                assert_eq!(roles.entries()[0].kind, role::Kind::Assertion);
                assert_eq!(selections.get(), 1);
                drop(checked);
            }
            assert_eq!(memory.used(), before);
        }
    });
}

struct CredentialAuthorities<'path, 'document> {
    paths: &'path [&'path structured_ltv::pki::CheckedPath<'document>],
    anchor: &'path structured_pkix::path::EffectiveAnchor<'document>,
}

impl<'path, 'document> structured_xades::credential::Provider<'path, 'document, Tree>
    for CredentialAuthorities<'path, 'document>
{
    type Evidence = usize;
    type Error = MemoryError;
    fn authenticate<W: Work>(
        &self,
        access: &Access<'_, Tree, W>,
        source: structured_xades::credential::Credential<usize, u8, u8>,
    ) -> Result<structured_xades::credential::Authentication<'path, 'document, usize>, MemoryError>
    {
        // Metadata-only authority/source oracle, not credential mathematics.
        use structured_ltv::pki::Authorities;
        use structured_xades::credential::Authentication;
        access.execution().charge_work(1)?;
        let authorities = if source.signature() == 0 {
            Authorities::Paths(self.paths)
        } else {
            Authorities::DirectAnchor(self.anchor)
        };
        Ok(Authentication::Authenticated {
            evidence: source.entry().node,
            authorities,
        })
    }
}

fn participant_tree(
    leaf: &[u8],
    memory: &structured_asn1::memory::Memory,
) -> (Tree, usize, usize, usize, usize) {
    let mut xml = super::preparation_tree();
    let find = |xml: &Tree, namespace, local| {
        xml.nodes.iter().position(|node|
        matches!(node.value, structured_xades::xml::Node::Element(name) if name.namespace == namespace && name.local == local)
    ).unwrap()
    };
    let issuer = find(&xml, super::XADES, "IssuerSerialV2");
    xml.nodes[issuer].parent = None;
    let method = find(&xml, super::DS, "DigestMethod");
    xml.digest_algorithms.push((method, SHA256));
    let value = find(&xml, super::DS, "DigestValue");
    xml.binary_routes
        .push((value, Sha256::digest(leaf).to_vec()));
    let certificate = find(&xml, super::DS, "X509Certificate");
    xml.binary_routes.push((certificate, leaf.to_vec()));
    // No earlier timestamp in this source-census case. This archive's own token
    // is intentionally excluded; its mathematical check is a separate stage.
    xml.nodes[8].parent = None;
    let (archive, _) =
        super::append_timestamp(&mut xml, 7, structured_xades::timestamp::Role::Archive, 1);
    let (_, root_credential) = append_assertion(&mut xml, 4);
    let (child, _, child_credential, _) =
        append_counter_credentials(&mut xml, memory, super::Coverage::ElementContent);
    xml.key_association = structured_xades::certificate::KeyAssociation::Same;
    (xml, child, root_credential, child_credential, archive)
}

fn participant_tree_before_archive(
    leaf: &[u8],
    memory: &structured_asn1::memory::Memory,
) -> (Tree, usize, usize, usize, usize) {
    let (mut xml, child, root_credential, child_credential, archive) =
        participant_tree(leaf, memory);
    // This separate source has its complete counter/credential BEFORE its
    // selected archive. Preserve the base fixture's later-counter regression.
    xml.nodes[archive].parent = None;
    let (archive, _) =
        super::append_timestamp(&mut xml, 7, structured_xades::timestamp::Role::Archive, 1);
    (xml, child, root_credential, child_credential, archive)
}

#[test]
fn present_validation_containers_require_their_actual_signer_copies() {
    // EN5.4.2/3 permit the root's KeyInfo alternative; 5.4.4/5 do NOT
    // permit another container to replace the credential signer's mandatory
    // copy. General availability and mandatory placement are separate facts.
    // Both original complete and delta CRLs must participate, not just one.
    use structured_ltv::{pki, timestamp::TimestampPathBinding};
    use structured_xades::{material, pki::bind_counters, prepare, timestamp, unsigned};
    for mode in 0..8 {
        with_checked_path(|path, leaf, root, memory| {
            let (mut xml, _, _, _, archive) = participant_tree(leaf, memory);
            xml.nodes[archive].parent = None;
            conditional_material_tree(&mut xml, mode, leaf, root);
            let child_material = conditional_counter_values(&mut xml, mode, root, leaf, memory);
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters = bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path));
            let counters = counters.unwrap();
            let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
            let all = timestamp::requirements_with_counters(
                &access,
                &prepared,
                &stamps,
                timestamp::TimestampSelection::All,
            )
            .unwrap();
            let TimestampPathBinding::Bound(all) = all.bind_paths(&[], &access).unwrap() else {
                panic!("no original timestamps");
            };
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            with_prepared_participants(
                &xml,
                &prepared,
                path,
                path.anchor(),
                &all,
                memory,
                |participants| {
                    with_original_delta_statuses(path, memory, |inputs| {
                        let roots = [inputs; 3];
                        let nodes = [pki::AuthorityNode {
                            statuses: inputs,
                            responders: &[],
                        }];
                        let closed = participants
                            .close_statuses(&roots, &nodes, &access)
                            .unwrap();
                        material::with_counter_values(
                            &xml,
                            &prepared,
                            &counters,
                            &operation,
                            |query, view| {
                                let work = query.execution();
                                let access = Access::new(&xml, xml.snapshot(), &work);
                                let index = material::index(&view, &access).unwrap();
                                assert_presence(&closed, &index, &access, mode);
                                let before = memory.used();
                                let result = material::conditional_placement(
                                    &prepared, &closed, &counters, &index, &access,
                                )
                                .unwrap();
                                assert_conditional_findings(
                                    &result,
                                    mode,
                                    &xml,
                                    child_material,
                                    root,
                                    leaf,
                                );
                                let report_capacity = memory.used() - before;
                                let conditional_count = result.findings().len();
                                drop(result);
                                assert_eq!(memory.used(), before);
                                assert_whole_material_checks(
                                    &prepared,
                                    &closed,
                                    &counters,
                                    &index,
                                    &access,
                                    &xml,
                                    (mode, conditional_count),
                                );
                                if mode == 1 {
                                    assert_conditional_refusals(
                                        &prepared,
                                        &closed,
                                        &counters,
                                        &index,
                                        &access,
                                        &xml,
                                        report_capacity,
                                    );
                                }
                                Ok::<_, ()>(())
                            },
                        )
                        .unwrap();
                    });
                },
            );
        });
    }
}

fn assert_whole_material_checks<W: Work, Q: Work>(
    prepared: &structured_xades::prepare::Prepared<Tree>,
    closed: &structured_ltv::pki::ParticipantClosure<
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    counters: &structured_xades::pki::CounterPaths<'_, '_, usize, u8, u8>,
    index: &structured_xades::material::Index<'_, usize, u8, u8, W>,
    access: &Access<'_, Tree, Q>,
    xml: &Tree,
    expected: (u8, usize),
) {
    // General presence must not hide wrong placement in the composed route.
    use structured_xades::material;
    let (mode, conditional_count) = expected;
    let before = access.execution().memory().used();
    let checked = material::check_participants(prepared, closed, counters, index, access).unwrap();
    assert_eq!(checked.presence().all_present(), mode != 2);
    assert_eq!(checked.conditional().findings().len(), conditional_count);
    assert!(checked.exclusive().findings().is_empty());
    assert!(checked.timestamps().findings().is_empty());
    assert!(core::ptr::eq(checked.timestamps().inputs(), closed));
    assert_eq!(
        checked.all_x509_requirements_met(),
        matches!(mode, 0 | 3 | 5 | 7)
    );
    drop(checked);
    assert_eq!(access.execution().memory().used(), before);
    if mode == 1 {
        let denied = super::Memory::new(super::Arc::new(super::MemoryAccount::new(0, 0)));
        let current = Access::new(xml, access.snapshot(), &denied);
        assert!(matches!(
            material::check_participants(prepared, closed, counters, index, &current),
            Err(material::CheckError::Conditional(
                material::ConditionalError::Index(structured_ltv::material::IndexError::Resource {
                    cause: MemoryError::WorkExceeded,
                    ..
                })
            ))
        ));
        assert_eq!(denied.used(), 0);
        assert_eq!(access.execution().memory().used(), before);
    }
}

fn assert_presence<W: Work, Q: Work>(
    closed: &structured_ltv::pki::ParticipantClosure<
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    index: &structured_xades::material::Index<'_, usize, u8, u8, W>,
    access: &Access<'_, Tree, Q>,
    mode: u8,
) {
    let purposes = structured_ltv::pki::authority_uses(closed, access).unwrap();
    let artifacts = structured_ltv::material::artifact_uses(&purposes, access).unwrap();
    let presence = structured_ltv::material::incorporation(&artifacts, index, access).unwrap();
    assert_eq!(presence.all_present(), mode != 2);
}

fn assert_conditional_refusals<W: Work, Q: Work>(
    prepared: &structured_xades::prepare::Prepared<Tree>,
    closed: &structured_ltv::pki::ParticipantClosure<
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    counters: &structured_xades::pki::CounterPaths<'_, '_, usize, u8, u8>,
    index: &structured_xades::material::Index<'_, usize, u8, u8, W>,
    access: &Access<'_, Tree, Q>,
    xml: &Tree,
    report_capacity: usize,
) {
    // Both indexing and output retention need current capacity. No prefix of
    // findings or an empty successful result may escape; sources stay intact.
    use structured_asn1::memory::{Memory, MemoryAccount};
    use structured_xades::material;
    assert!(report_capacity > 0);
    let before = access.execution().memory().used();
    for (capacity, fuel) in [
        (0, 1_000_000),
        (report_capacity - 1, 1_000_000),
        (65_536, 0),
    ] {
        let denied = Memory::new(super::Arc::new(MemoryAccount::new(capacity, fuel)));
        let current = Access::new(xml, xml.snapshot(), &denied);
        assert!(matches!(
            material::conditional_placement(prepared, closed, counters, index, &current),
            Err(material::ConditionalError::Index(
                structured_ltv::material::IndexError::Resource { .. }
                    | structured_ltv::material::IndexError::Scope(
                        structured_ltv::source::ScopeError::Resource { .. },
                    )
            ))
        ));
        assert_eq!(denied.used(), 0);
        assert_eq!(access.execution().memory().used(), before);
    }
    let foreign = Access::new(
        xml,
        structured_xades::xml::Snapshot {
            document: xml.document + 1,
            generation: xml.generation.get(),
        },
        access.execution(),
    );
    assert!(matches!(
        material::conditional_placement(prepared, closed, counters, index, &foreign),
        Err(material::ConditionalError::Index(
            structured_ltv::material::IndexError::Foreign { signature: 0 }
        ))
    ));
    assert_eq!(access.execution().memory().used(), before);
    assert_conditional_late_work(prepared, closed, counters, index, access, xml);
    with_checked_path(|other, _, _, _| {
        // A separately valid path receipt for the same counter/key cannot be
        // substituted after the participant/status closure chose its path.
        let substituted = structured_xades::pki::bind_counters(prepared.bound(), access, |_, _| {
            Ok::<_, ()>(other)
        })
        .unwrap();
        let held = access.execution().memory().used();
        assert!(matches!(
            material::conditional_placement(prepared, closed, &substituted, index, access),
            Err(material::ConditionalError::Index(
                structured_ltv::material::IndexError::Foreign { signature: 0 }
            ))
        ));
        assert_eq!(access.execution().memory().used(), held);
    });
}

fn assert_conditional_late_work<W: Work, Q: Work>(
    prepared: &structured_xades::prepare::Prepared<Tree>,
    closed: &structured_ltv::pki::ParticipantClosure<
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    counters: &structured_xades::pki::CounterPaths<'_, '_, usize, u8, u8>,
    index: &structured_xades::material::Index<'_, usize, u8, u8, W>,
    original: &Access<'_, Tree, Q>,
    xml: &Tree,
) {
    // Exhaust exactly at the FINAL identity guard, after all findings have
    // been built. The failed query must release output and owner-index scratch;
    // a different current account must not spend the source/storage account.
    use structured_asn1::memory::{HashWork, Memory, MemoryAccount};
    use structured_xades::material;
    let held = original.execution().memory().used();
    let source_work = original.execution().memory().work_used();
    let admitted = Memory::new(super::Arc::new(MemoryAccount::new(1 << 20, 1_000_000)));
    let observed = super::query_boundary::Boundary::observe(xml);
    let current = Access::new(&observed, original.snapshot(), &admitted);
    let report =
        material::conditional_placement(prepared, closed, counters, index, &current).unwrap();
    assert_eq!(report.findings().len(), 6);
    let final_query = observed.calls();
    drop(report);
    assert_eq!(admitted.used(), 0);
    let signature = prepared.bound().containers().signature();
    let last_identity = usize::try_from(2 * signature.hash_work().unwrap()).unwrap();
    assert!(last_identity > 0);
    let denied = Memory::new(super::Arc::new(MemoryAccount::new(1 << 20, 1_000_000)));
    let boundary =
        super::query_boundary::Boundary::exhaust(xml, final_query, &denied, last_identity - 1);
    let current = Access::new(&boundary, original.snapshot(), &denied);
    assert!(matches!(
        material::conditional_placement(prepared, closed, counters, index, &current),
        Err(material::ConditionalError::Index(
            structured_ltv::material::IndexError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            }
        ))
    ));
    assert_eq!(boundary.calls(), final_query);
    assert!(boundary.held().unwrap() > 0);
    assert_eq!(denied.work_remaining(), last_identity - 1);
    assert_eq!(denied.used(), 0);
    assert_eq!(original.execution().memory().used(), held);
    assert_eq!(original.execution().memory().work_used(), source_work);
}

fn conditional_counter_values(
    xml: &mut Tree,
    mode: u8,
    root: &[u8],
    leaf: &[u8],
    memory: &structured_asn1::memory::Memory,
) -> Option<(usize, usize)> {
    if mode < 4 {
        return None;
    }
    let certificates: &[&[u8]] = match mode {
        5 => &[root],
        7 => &[root, leaf],
        _ => &[],
    };
    Some(append_counter_values(
        xml,
        if mode < 6 {
            "AttrAuthoritiesCertValues"
        } else {
            "CertificateValues"
        },
        certificates,
        memory,
    ))
}

fn append_counter_values(
    xml: &mut Tree,
    local: &'static str,
    certificates: &[&[u8]],
    memory: &structured_asn1::memory::Memory,
) -> (usize, usize) {
    // A root copy must not satisfy the child's present but empty container.
    // Its credential uses a direct anchor; its ordinary signer uses the full
    // checked path. The two roles must retain their distinct copy obligations.
    let child = xml.nested_counters[0].child;
    let layout = {
        let access = Access::new(xml, xml.snapshot(), memory);
        structured_xades::container::locate(&access, child).unwrap()
    };
    let unsigned = if let Some(node) = layout.unsigned() {
        node
    } else {
        let node = xml.nodes.len();
        xml.nodes.push(super::element(
            Some(layout.qualifying()),
            super::XADES,
            "UnsignedProperties",
        ));
        node
    };
    let parent = xml
        .nodes
        .iter()
        .position(|node| {
            node.parent == Some(unsigned)
                && matches!(
                    node.value,
                    structured_xades::xml::Node::Element(Name {
                        namespace: super::XADES,
                        local: "UnsignedSignatureProperties"
                    })
                )
        })
        .unwrap_or_else(|| {
            let node = xml.nodes.len();
            xml.nodes.push(super::element(
                Some(unsigned),
                super::XADES,
                "UnsignedSignatureProperties",
            ));
            node
        });
    let property = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(parent), super::XADES, local));
    for certificate in certificates {
        let node = xml.nodes.len();
        xml.nodes.push(super::element(
            Some(property),
            super::XADES,
            "EncapsulatedX509Certificate",
        ));
        xml.binary_routes.push((node, certificate.to_vec()));
    }
    (child, property)
}

fn conditional_material_tree(xml: &mut Tree, mode: u8, leaf: &[u8], root: &[u8]) {
    if mode != 3 {
        for (local, certificate) in [
            ("CertificateValues", root),
            ("AttrAuthoritiesCertValues", leaf),
        ] {
            let property = xml.nodes.len();
            xml.nodes.push(super::element(Some(7), super::XADES, local));
            if mode == 0 || mode >= 4 {
                let value = xml.nodes.len();
                xml.nodes.push(super::element(
                    Some(property),
                    super::XADES,
                    "EncapsulatedX509Certificate",
                ));
                xml.binary_routes.push((value, certificate.to_vec()));
            }
        }
        for local in ["RevocationValues", "AttributeRevocationValues"] {
            let property = xml.nodes.len();
            if mode == 0 || mode >= 4 {
                assert!(super::append_crl_pair(xml, false).is_none());
                xml.nodes[property].value = structured_xades::xml::Node::Element(Name {
                    namespace: super::XADES,
                    local,
                });
            } else {
                xml.nodes.push(super::element(Some(7), super::XADES, local));
            }
        }
    }
    if mode == 1 || mode == 3 {
        let general = xml.nodes.len();
        xml.nodes.push(super::element(
            Some(7),
            super::XADES_141,
            "AnyValidationData",
        ));
        let certificates = xml.nodes.len();
        xml.nodes.push(super::element(
            Some(general),
            super::XADES,
            "CertificateValues",
        ));
        for certificate in [root, leaf] {
            let value = xml.nodes.len();
            xml.nodes.push(super::element(
                Some(certificates),
                super::XADES,
                "EncapsulatedX509Certificate",
            ));
            xml.binary_routes.push((value, certificate.to_vec()));
        }
        let revocations = xml.nodes.len();
        assert!(super::append_crl_pair(xml, false).is_none());
        xml.nodes[revocations].parent = Some(general);
    }
}

fn assert_conditional_findings(
    result: &structured_xades::material::ConditionalPlacement<'_, '_, usize, u8, u8>,
    mode: u8,
    xml: &Tree,
    child_material: Option<(usize, usize)>,
    root: &[u8],
    leaf: &[u8],
) {
    use structured_ltv::pki;
    use structured_xades::material;
    assert_eq!(result.snapshot(), xml.snapshot());
    assert_eq!(result.signature(), 0);
    assert_eq!(
        result.findings().len(),
        if mode == 1 || mode == 2 {
            6
        } else if mode == 6 {
            2
        } else {
            usize::from(mode == 4)
        }
    );
    if mode == 1 || mode == 2 {
        let mut missing = 0;
        let mut elsewhere = 0;
        let mut statuses = 0;
        for finding in result.findings() {
            match finding.cause {
                material::ConditionalFailure::Missing => missing += 1,
                material::ConditionalFailure::Elsewhere => elsewhere += 1,
            }
            if matches!(
                finding.artifact,
                structured_ltv::material::ArtifactRef::Crl(_)
            ) {
                statuses += 1;
            }
            assert!(matches!(
                finding.participant,
                pki::Participant::Signer(0) | pki::Participant::Credential { signature: 0, .. }
            ));
        }
        assert_eq!(
            (missing, elsewhere, statuses),
            if mode == 1 { (0, 6, 4) } else { (5, 1, 4) }
        );
    }
    if mode == 4 {
        let (owner, property) = child_material.unwrap();
        let finding = &result.findings()[0];
        assert_eq!(finding.property, property);
        assert!(
            matches!(finding.participant, pki::Participant::Credential { signature, .. } if signature == owner)
        );
        assert!(
            matches!(finding.artifact, structured_ltv::material::ArtifactRef::Certificate(certificate) if certificate.as_bytes() == root)
        );
        assert_eq!(finding.cause, material::ConditionalFailure::Elsewhere);
    }
    if mode == 6 {
        // Root KeyInfo holds the same leaf and root CertificateValues holds
        // the same anchor. Neither is this child's own KeyInfo/property.
        let (owner, property) = child_material.unwrap();
        for finding in result.findings() {
            assert_eq!(finding.property, property);
            assert!(
                matches!(finding.participant, pki::Participant::Counter { signature, .. } if signature == owner)
            );
            assert_eq!(finding.cause, material::ConditionalFailure::Elsewhere);
        }
        assert!(
            matches!(result.findings()[0].artifact, structured_ltv::material::ArtifactRef::Certificate(certificate) if certificate.as_bytes() == root)
        );
        assert!(
            matches!(result.findings()[1].artifact, structured_ltv::material::ArtifactRef::Certificate(certificate) if certificate.as_bytes() == leaf)
        );
    }
}

fn participant_archive_tree(
    leaf: &[u8],
    root: &[u8],
    memory: &structured_asn1::memory::Memory,
    late_anchor: bool,
    general: bool,
    extra_archive: bool,
) -> (Tree, usize, super::timestamp_oracle::Oracle, Vec<u8>) {
    // Real TSP math over synthetic XML framing. No real C14N claim.
    struct Collected(Vec<u8>);
    impl Receiver for Collected {
        fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
            self.0.extend(bytes);
            Ok(())
        }
    }
    let (mut xml, _, _, _, old_archive) = participant_tree(leaf, memory);
    xml.nodes[old_archive].parent = None;
    xml.nodes[8].parent = Some(7);
    // A structurally archival source also carries its genuine earlier signature
    // timestamp. Distinct token nodes retain distinct original payloads.
    let (prior_node, prior_method) = {
        use structured_xades::{binding, container, timestamp};
        let access = Access::new(&xml, xml.snapshot(), memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp = timestamp::read(&access, &bound, 8).unwrap();
        (stamp.tokens()[0], u8::try_from(stamp.method()).unwrap())
    };
    let (_, prior, _, _) =
        super::timestamp_oracle::fixture_with_root(&[b'E', 12, b'M', prior_method]);
    xml.binary_routes.push((prior_node, prior));
    assert!(super::append_crl_pair(&mut xml, false).is_none());
    let add_anchor = |xml: &mut Tree| {
        let property = xml.nodes.len();
        xml.nodes
            .push(super::element(Some(7), super::XADES, "CertificateValues"));
        let value = xml.nodes.len();
        xml.nodes.push(super::element(
            Some(property),
            super::XADES,
            "EncapsulatedX509Certificate",
        ));
        xml.binary_routes.push((value, root.to_vec()));
    };
    if !late_anchor {
        add_anchor(&mut xml);
    }
    if general {
        // Additional exact copies in the prescribed general container. Keep
        // its CertificateValues-before-RevocationValues schema order.
        let general_node = xml.nodes.len();
        xml.nodes.push(super::element(
            Some(7),
            super::XADES_141,
            "AnyValidationData",
        ));
        let certificates = xml.nodes.len();
        xml.nodes.push(super::element(
            Some(general_node),
            super::XADES,
            "CertificateValues",
        ));
        for certificate in [leaf, root] {
            let value = xml.nodes.len();
            xml.nodes.push(super::element(
                Some(certificates),
                super::XADES,
                "EncapsulatedX509Certificate",
            ));
            xml.binary_routes.push((value, certificate.to_vec()));
        }
        let revocation = xml.nodes.len();
        assert!(super::append_crl_pair(&mut xml, false).is_none());
        xml.nodes[revocation].parent = Some(general_node);
    }
    let (archive, _) =
        super::append_timestamp(&mut xml, 7, structured_xades::timestamp::Role::Archive, 1);
    if late_anchor {
        add_anchor(&mut xml);
    }
    let bytes = {
        use structured_xades::{binding, container, timestamp};
        let access = Access::new(&xml, xml.snapshot(), memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp = timestamp::read(&access, &bound, archive).unwrap();
        let mut input = timestamp::Input::prepare(&xml, &bound, &stamp, memory).unwrap();
        let mut output = Collected(Vec::new());
        Source::stream(&mut input, &mut output, memory).unwrap();
        output.0
    };
    let (provider, token, tsa, _) = super::timestamp_oracle::fixture_with_root(&bytes);
    xml.binary = token;
    if extra_archive {
        // Later augmentation preserves the first archive's actual input. Its
        // unassessed material must still prevent a complete archive census.
        super::append_timestamp(&mut xml, 7, structured_xades::timestamp::Role::Archive, 1);
    }
    (xml, archive, provider, tsa)
}

pub(super) fn with_original_delta_statuses(
    path: &structured_ltv::pki::CheckedPath<'_>,
    memory: &structured_asn1::memory::Memory,
    check: impl FnOnce(&structured_ltv::pki::PathStatuses<'_, '_, '_>),
) {
    // Fixture setup uses the existing shared CRL pipeline, not written Good flags.
    use structured_ltv::pki;
    use structured_pkix::{
        crl,
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    let (base_bytes, delta_bytes) = super::timestamp_oracle::crl_pair();
    let parser = structured_asn1::Parser::der(memory.clone());
    let base = crl::CertificateList::read(&parser, &base_bytes, 5000).unwrap();
    let delta = crl::CertificateList::read(&parser, &delta_bytes, 6000).unwrap();
    let issuer = path.anchor().certificate().unwrap();
    let verifier = super::timestamp_oracle::PathOracle {
        calls: Cell::new(0),
    };
    let key = WorkingKey::standing(issuer.tbs().public_key());
    let crl::Authentication::Authenticated(base) =
        base.authenticate(issuer, key, &verifier, memory).unwrap()
    else {
        panic!("actual complete CRL signature")
    };
    let crl::Authentication::Authenticated(delta) =
        delta.authenticate(issuer, key, &verifier, memory).unwrap()
    else {
        panic!("actual delta CRL signature")
    };
    let crl::DeltaBinding::Bound(pair) = base.bind_delta(&delta, memory).unwrap() else {
        panic!("same actual issuer/scope")
    };
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let evaluation = crl::Evaluation {
        now: Instant::new(1_767_225_600, 0).unwrap().into(),
        utc: &utc,
        execution: memory,
        origin: crl::SourceOrigin::Cached,
    };
    let crl::DeltaEvidence::Facts(facts) = pair
        .evaluate(path.members()[0].certificate(), &evaluation)
        .unwrap()
    else {
        panic!("applicable original CRLs")
    };
    let coverage = crl::Coverage::new(facts.absence().unwrap(), memory).unwrap();
    let authorities = [pki::CrlAuthorities::Delta {
        base: pki::CrlAuthority::Anchor,
        delta: pki::CrlAuthority::Anchor,
    }];
    let pki::CrlCoverageBinding::Bound(bound) = path
        .bind_crl_coverage(0, &coverage, &authorities, &utc, memory)
        .unwrap()
    else {
        panic!("same actual status target/authorities")
    };
    let entries = [pki::MemberStatus::Crl(&bound)];
    let census = path
        .status_census(evaluation.now, &entries, memory)
        .unwrap();
    check(&census);
    assert_eq!(verifier.calls.get(), 2);
}

fn with_prepared_participants<'document>(
    xml: &Tree,
    prepared: &structured_xades::prepare::Prepared<Tree>,
    path: &structured_ltv::pki::CheckedPath<'document>,
    credential_anchor: structured_pkix::path::Anchor<'document>,
    prior: &structured_ltv::timestamp::TimestampPaths<
        '_,
        '_,
        'document,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    memory: &structured_asn1::memory::Memory,
    check: impl FnOnce(
        &structured_ltv::pki::ParticipantRequirements<
            '_,
            'document,
            usize,
            u8,
            u8,
            structured_xades::Xades,
        >,
    ),
) {
    with_prepared_inputs(
        xml,
        prepared,
        path,
        credential_anchor,
        prior,
        memory,
        |participants, _| check(participants),
    );
}

fn with_prepared_inputs<'document>(
    xml: &Tree,
    prepared: &structured_xades::prepare::Prepared<Tree>,
    path: &structured_ltv::pki::CheckedPath<'document>,
    credential_anchor: structured_pkix::path::Anchor<'document>,
    prior: &structured_ltv::timestamp::TimestampPaths<
        '_,
        '_,
        'document,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    memory: &structured_asn1::memory::Memory,
    check: impl FnOnce(
        &structured_ltv::pki::ParticipantRequirements<
            '_,
            'document,
            usize,
            u8,
            u8,
            structured_xades::Xades,
        >,
        &structured_xades::credential::ParticipantCredentials<'_, 'document, usize, usize, u8, u8>,
    ),
) {
    use structured_pkix::path::WorkingKey;
    use structured_xades::{certificate, credential};
    let access = Access::new(xml, xml.snapshot(), memory);
    let digest = Oracle::new(Mode::Ready);
    let signer = certificate::check_path(
        xml,
        prepared.bound(),
        prepared.certificates(),
        path,
        &digest,
        memory,
    )
    .unwrap();
    let counters =
        structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path))
            .unwrap();
    let anchor = structured_pkix::path::EffectiveAnchor::bind(
        credential_anchor,
        WorkingKey::standing(credential_anchor.key()),
        memory,
    )
    .unwrap()
    .unwrap();
    let paths = [path];
    let credentials = credential::check_participants(
        prepared,
        &counters,
        &CredentialAuthorities {
            paths: &paths,
            anchor: &anchor,
        },
        &access,
    )
    .unwrap();
    let participants = participants(&signer, &counters, &credentials, prior, &access).unwrap();
    check(&participants, &credentials);
}

#[test]
fn exclusive_credential_ca_rejects_ordinary_copies_but_not_shared_or_attribute_copies() {
    // Genuine certificates/path signatures, metadata credential owner. This
    // isolates the EN5.4.2(5) rule, not SAML authentication or a full B level.
    use structured_ltv::pki;
    use structured_pkix::path::Anchor;
    use structured_xades::{material, prepare, timestamp, unsigned};
    for (shared, attribute) in [(false, false), (false, true), (true, false)] {
        with_checked_path(|path, leaf, _, memory| {
            let (mut xml, _, _, _, archive) = participant_tree(leaf, memory);
            xml.nodes[archive].parent = None;
            let other_bytes = super::timestamp_oracle::other_issuer();
            let parser = structured_asn1::Parser::der(memory.clone());
            let other = structured_pkix::Certificate::read(&parser, &other_bytes, 2400).unwrap();
            let anchor = if shared {
                path.anchor()
            } else {
                Anchor::from_certificate(&other)
            };
            let certificate = anchor.certificate().unwrap();
            let property = xml.nodes.len();
            xml.nodes.push(super::element(
                Some(7),
                super::XADES,
                if attribute {
                    "AttrAuthoritiesCertValues"
                } else {
                    "CertificateValues"
                },
            ));
            let value = xml.nodes.len();
            xml.nodes.push(super::element(
                Some(property),
                super::XADES,
                "EncapsulatedX509Certificate",
            ));
            xml.binary_routes
                .push((value, certificate.as_bytes().to_vec()));
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters =
                structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| {
                    Ok::<_, ()>(path)
                })
                .unwrap();
            let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
            let all = timestamp::requirements_with_counters(
                &access,
                &prepared,
                &stamps,
                timestamp::TimestampSelection::All,
            )
            .unwrap();
            assert!(all.entries().is_empty());
            let structured_ltv::timestamp::TimestampPathBinding::Bound(all) =
                all.bind_paths(&[], &access).unwrap()
            else {
                panic!("complete original zero-token set")
            };
            let operation = parser.read(&[], 900).unwrap();
            with_prepared_participants(
                &xml,
                &prepared,
                path,
                anchor,
                &all,
                memory,
                |participants| {
                    with_original_delta_statuses(path, memory, |inputs| {
                        let roots = [inputs; 3];
                        let nodes = [pki::AuthorityNode {
                            statuses: inputs,
                            responders: &[],
                        }];
                        let closed = participants
                            .close_statuses(&roots, &nodes, &access)
                            .unwrap();
                        material::with_values(&xml, &prepared, &operation, |query, view| {
                            let work = query.execution();
                            let access = Access::new(&xml, xml.snapshot(), &work);
                            let index = material::index(&view, &access).unwrap();
                            assert_exclusive_material(
                                &closed,
                                &index,
                                &access,
                                value,
                                certificate,
                                !shared && !attribute,
                                &xml,
                            );
                            Ok::<_, ()>(())
                        })
                        .unwrap();
                    });
                },
            );
        });
    }
}

fn assert_exclusive_material<W: Work, Q: Work>(
    closed: &structured_ltv::pki::ParticipantClosure<
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    index: &structured_xades::material::Index<'_, usize, u8, u8, W>,
    access: &Access<'_, Tree, Q>,
    value: usize,
    certificate: &structured_pkix::Certificate<'_>,
    forbidden: bool,
    xml: &Tree,
) {
    use structured_asn1::memory::{Memory, MemoryAccount};
    use structured_ltv::pki;
    use structured_xades::material;
    let before = access.execution().memory().used();
    let uses = pki::authority_uses(closed, access).unwrap();
    let artifacts = structured_ltv::material::artifact_uses(&uses, access).unwrap();
    assert_incorporated_inputs(&artifacts, index, access, xml, false);
    let retained = access.execution().memory().used();
    let checked = material::exclusivity(&artifacts, index, access).unwrap();
    if forbidden {
        assert_eq!(checked.findings().len(), 1);
        let finding = &checked.findings()[0];
        assert_eq!(finding.kind(), material::ExclusiveFindingKind::ForbiddenCa);
        assert_eq!(finding.certificate().as_bytes(), certificate.as_bytes());
        assert_eq!(finding.occurrence().location().node, value);
        assert!(matches!(
            finding.artifact(),
            structured_ltv::material::ArtifactRef::Certificate(_)
        ));
    } else {
        assert!(checked.findings().is_empty());
    }
    let output_capacity = access.execution().memory().used() - retained;
    drop(checked);
    assert_eq!(access.execution().memory().used(), retained);
    if forbidden {
        // Capacity for the final output alone is not credit for its temporary
        // CA cache. A refusal drops both rather than publishing a partial report.
        assert!(output_capacity > 0);
        let limited = Memory::new(std::sync::Arc::new(MemoryAccount::new(
            output_capacity,
            1 << 24,
        )));
        let limited_access = Access::new(xml, access.snapshot(), &limited);
        assert!(matches!(
            material::exclusivity(&artifacts, index, &limited_access),
            Err(material::ExclusivityError::Resource {
                cause: MemoryError::LimitExceeded,
                ..
            })
        ));
        assert_eq!(limited.used(), 0);
        assert_eq!(access.execution().memory().used(), retained);
    }
    let denied = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 0)));
    let denied_access = Access::new(xml, access.snapshot(), &denied);
    assert!(matches!(
        material::exclusivity(&artifacts, index, &denied_access),
        Err(material::ExclusivityError::Index(
            structured_ltv::material::IndexError::Scope(
                structured_ltv::source::ScopeError::Resource { .. },
            )
        ))
    ));
    drop(artifacts);
    drop(uses);
    assert_eq!(access.execution().memory().used(), before);
}

#[test]
fn participant_archive_material_keeps_direct_anchor_coverage_and_late_refusal() {
    // Actual CRL pair, root/counter/credential paths and TSP math are composed
    // without treating metadata XML/credential oracles as B-LTA qualification.
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    use structured_xades::{prepare, timestamp, unsigned};
    for (late_anchor, general, extra) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        with_checked_path(|path, leaf, root, _| {
            let memory = &participant_material_memory();
            let (xml, archive, provider, tsa_bytes) =
                participant_archive_tree(leaf, root, memory, late_anchor, general, extra);
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
            let at = prepared
                .timestamps()
                .iter()
                .position(|stamp| stamp.node() == archive)
                .unwrap();
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            let tsa = structured_pkix::Certificate::read(&parser, &tsa_bytes, 400).unwrap();
            let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
            let context = structured_cms::timestamp::CheckContext {
                certificate: &tsa,
                certificate_parent: &operation,
                key: WorkingKey::standing(tsa.tbs().public_key()),
                requested: None,
                utc: &utc,
                reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
                window: None,
            };
            let check = timestamp::Check {
                xml: &xml,
                provider: &provider,
                context: &context,
            };
            let prior_actor = check
                .retain_actor(
                    prepared.bound(),
                    &prepared.timestamps()[0],
                    0,
                    &operation,
                    |_, _| Ok::<_, ()>(false),
                )
                .unwrap()
                .unwrap();
            let prior_path = checked_timestamp_path(path, &prior_actor, &utc, memory);
            let selection = timestamp::TimestampSelection::BeforeArchive(at);
            let required = participant_timestamp_requirements(&access, &prepared, path, selection);
            let prior_paths = [&prior_path];
            let structured_ltv::timestamp::TimestampPathBinding::Bound(prior) =
                required.bind_paths(&prior_paths, &access).unwrap()
            else {
                panic!("complete original earlier-token set")
            };
            let stamp = &prepared.timestamps()[at];
            let archive_actor = check
                .retain_actor(prepared.bound(), stamp, 0, &operation, |_, _| {
                    Ok::<_, ()>(false)
                })
                .unwrap()
                .unwrap();
            let evidence = archive_actor.verified();
            let archive_path = checked_timestamp_path(path, &archive_actor, &utc, memory);
            let coverage = timestamp::Input::prepare(&xml, prepared.bound(), stamp, memory)
                .unwrap()
                .element_coverage(memory)
                .unwrap();
            let material = ArchiveMaterialCheck {
                xml: &xml,
                prepared: &prepared,
                operation: &operation,
                coverage: &coverage,
                evidence,
                early: !late_anchor,
                general,
            };
            with_prepared_inputs(
                &xml,
                &prepared,
                path,
                path.anchor(),
                &prior,
                memory,
                |participants, credentials| {
                    material.before(participants, path, credentials);
                },
            );
            if !extra {
                material.all(path, &prior_path, &archive_path);
            }
            assert_eq!(provider.verified.get(), 2);
        });
    }
}

struct ArchiveMaterialCheck<'case, 'source, C: Work> {
    xml: &'case Tree,
    prepared: &'case structured_xades::prepare::Prepared<Tree>,
    operation: &'case structured_asn1::Reader<'source>,
    coverage: &'case structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &'case structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    early: bool,
    general: bool,
}

fn checked_timestamp_path<'v, 'c, 'd>(
    path: &'v structured_ltv::pki::CheckedPath<'d>,
    actor: &'v structured_xades::timestamp::TimestampActor<'c, 'd, Tree>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    memory: &structured_asn1::memory::Memory,
) -> structured_ltv::pki::TimestampPath<'v, 'c, 'd, usize, u8, u8, structured_xades::Xades> {
    // Every fixture token must bind its actual TSA key and complete generation
    // interval. A rejected binding never supplies an archive material actor.
    let structured_ltv::pki::TimestampBinding::Bound(path) =
        path.bind_timestamp(actor, utc, memory).unwrap()
    else {
        panic!("actual TSA key and full generation interval must bind")
    };
    path
}

struct ArchiveFormat<'a, 'd> {
    certificate: &'a structured_pkix::Certificate<'d>,
    calls: Cell<usize>,
}
impl structured_xades::material::credentials::Provider<Tree, usize> for ArchiveFormat<'_, '_> {
    type Error = MemoryError;
    fn visit<VE, W: Work>(
        &self,
        _: &structured_xades::credential::Checked<'_, '_, usize, usize, u8, u8>,
        _: &[structured_xades::material::Opaque<usize, u8, u8>],
        access: &Access<'_, Tree, W>,
        mut visitor: impl for<'v, 'd> FnMut(
            structured_xades::material::credentials::Need<'v, 'd, usize, u8, u8>,
        ) -> Result<(), VE>,
    ) -> Result<
        structured_xades::material::credentials::Completeness,
        structured_xades::reference::VisitError<MemoryError, VE>,
    > {
        // Format metadata oracle: exact required original bytes before THIS
        // archive. The corresponding X.509 authority check cannot replace it.
        use structured_xades::{material, reference::VisitError};
        access
            .execution()
            .charge_work(1)
            .map_err(VisitError::Processing)?;
        self.calls.set(self.calls.get() + 1);
        visitor(material::credentials::Need::Known(
            structured_ltv::material::ArtifactRef::Certificate(self.certificate),
        ))
        .map_err(VisitError::Visitor)?;
        Ok(material::credentials::Completeness::Complete)
    }
}

fn participant_timestamp_requirements<W: Work>(
    access: &Access<'_, Tree, W>,
    prepared: &structured_xades::prepare::Prepared<Tree>,
    path: &structured_ltv::pki::CheckedPath<'_>,
    selection: structured_xades::timestamp::TimestampSelection,
) -> structured_ltv::timestamp::TimestampRequirements<usize, u8, u8, structured_xades::Xades> {
    // Retained requirements own scalar source identities, never borrows into
    // temporary path/counter catalogues. Actual key receipts are still required.
    use structured_xades::timestamp;
    let counters =
        structured_xades::pki::bind_counters(prepared.bound(), access, |_, _| Ok::<_, ()>(path))
            .unwrap();
    let stamps = timestamp::counter_timestamps(access, &counters).unwrap();
    timestamp::requirements_with_counters(access, prepared, &stamps, selection).unwrap()
}

fn assert_archive_census_refusal(
    xml: &Tree,
    prepared: &structured_xades::prepare::Prepared<Tree>,
    stamps: &structured_xades::timestamp::CounterTimestamps<usize, u8, u8>,
    selection: structured_xades::timestamp::TimestampSelection,
    memory: &super::Memory,
) {
    use structured_xades::timestamp;
    // Deriving the archive actor mask is current-query work/storage, not
    // credit from the already retained complete counter catalogue.
    // A fresh map uses a fresh randomized hasher: equality-candidate work can
    // differ, so another map's measured cost minus one is NOT an exact boundary.
    // Exercise the deterministic dispatch boundary, preserving its exact cause.
    let denied = super::Memory::new(super::Arc::new(
        structured_asn1::memory::MemoryAccount::new(65_536, 0),
    ));
    let held = memory.used();
    let result = timestamp::requirements_with_counters(
        &Access::new(xml, xml.snapshot(), &denied),
        prepared,
        stamps,
        selection,
    );
    let Err(cause) = result else {
        panic!("zero-work query consumed a retained counter census");
    };
    assert!(
        matches!(
            cause,
            timestamp::RequirementError::Input(timestamp::InputError::Resource {
                node: 0,
                cause: MemoryError::WorkExceeded,
            })
        ),
        "unexpected refusal: {cause:?}"
    );
    assert_eq!(denied.used(), 0);
    assert_eq!(memory.used(), held);
}

#[test]
fn whole_participant_census_refuses_root_only_timestamp_requirements() {
    // An empty root antecedent list cannot prove that incorporated counters
    // have no timestamp obligations. Even this zero-child-token fixture needs
    // the complete source census; no caller-written successful subset is used.
    use structured_ltv::{pki, timestamp::TimestampPathBinding};
    use structured_pkix::path::{EffectiveAnchor, WorkingKey};
    use structured_xades::{
        certificate, credential, pki::bind_counters, prepare, timestamp, unsigned,
    };
    with_checked_path(|path, leaf, _, memory| {
        let (xml, _, _, _, archive) = participant_tree(leaf, memory);
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let counters = bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path)).unwrap();
        let anchor = EffectiveAnchor::bind(
            path.anchor(),
            WorkingKey::standing(path.anchor().key()),
            memory,
        )
        .unwrap()
        .unwrap();
        let paths = [path];
        let credentials = credential::check_participants(
            &prepared,
            &counters,
            &CredentialAuthorities {
                paths: &paths,
                anchor: &anchor,
            },
            &access,
        )
        .unwrap();
        let signer = certificate::check_path(
            &xml,
            prepared.bound(),
            prepared.certificates(),
            path,
            &Oracle::new(Mode::Ready),
            memory,
        )
        .unwrap();
        let at = prepared
            .timestamps()
            .iter()
            .position(|stamp| stamp.node() == archive)
            .unwrap();
        let selection = timestamp::TimestampSelection::BeforeArchive(at);
        let partial = timestamp::requirements(&access, &prepared, selection).unwrap();
        assert!(partial.entries().is_empty());
        let TimestampPathBinding::Bound(partial) = partial.bind_paths(&[], &access).unwrap() else {
            panic!("root source has no earlier tokens")
        };
        assert!(matches!(
            participants(&signer, &counters, &credentials, &partial, &access),
            Err(pki::ParticipantError::CounterTimestamps)
        ));
        let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
        let complete =
            timestamp::requirements_with_counters(&access, &prepared, &stamps, selection).unwrap();
        assert_archive_census_refusal(&xml, &prepared, &stamps, selection, memory);
        let TimestampPathBinding::Bound(complete) = complete.bind_paths(&[], &access).unwrap()
        else {
            panic!("all child sources really have no earlier tokens")
        };
        let report = participants(&signer, &counters, &credentials, &complete, &access).unwrap();
        assert_participant_origins(
            &counters,
            &prepared,
            path,
            &xml,
            memory,
            |candidate, query| {
                report.require_inputs(&signer, candidate, &credentials, &complete, query)
            },
        );
        assert_eq!(report.entries().len(), 2);
        // EN6.3(aa) applies BEFORE this archive was generated. participant_tree
        // puts its child CounterSignature AFTER that archive; 5.5.2.1 note4
        // explicitly permits this augmentation. Neither the later child nor
        // its later credential can become an earlier archive obligation.
        let root = prepared.bound().containers().signature();
        assert!(
            report
                .entries()
                .iter()
                .all(|entry| match entry.participant() {
                    pki::Participant::Signer(signature)
                    | pki::Participant::Credential { signature, .. } => signature == root,
                    _ => false,
                })
        );
        // Whole-signature LT must ALSO include the archive's own token. An
        // empty success list cannot prove that full scope, even if the earlier
        // archive's empty token requirement was successfully bound above.
        let all = timestamp::requirements_with_counters(
            &access,
            &prepared,
            &stamps,
            timestamp::TimestampSelection::All,
        )
        .unwrap();
        assert_eq!(all.entries().len(), 1);
        assert!(matches!(
            all.bind_paths(&[], &access).unwrap(),
            structured_ltv::timestamp::TimestampPathBinding::Unproven(
                structured_ltv::timestamp::TimestampPathFailure::Count
            )
        ));
    });
}

fn assert_participant_origins(
    counters: &structured_xades::pki::CounterPaths<'_, '_, usize, u8, u8>,
    prepared: &structured_xades::prepare::Prepared<Tree>,
    path: &structured_ltv::pki::CheckedPath<'_>,
    xml: &Tree,
    memory: &structured_asn1::memory::Memory,
    check: impl Fn(
        &structured_xades::pki::CounterPaths<'_, '_, usize, u8, u8>,
        &Access<'_, Tree, structured_asn1::memory::Memory>,
    ) -> Result<(), structured_ltv::pki::ParticipantError<usize>>,
) {
    // Identical document/node IDs are insufficient: a separately collected
    // catalogue could carry different selected paths or authentication inputs.
    use structured_ltv::pki;
    let access = Access::new(xml, xml.snapshot(), memory);
    check(counters, &access).unwrap();
    let other =
        structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path))
            .unwrap();
    assert!(matches!(
        check(&other, &access),
        Err(pki::ParticipantError::Foreign { signature: 0 })
    ));
    let denied = structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(65_536, 0),
    ));
    let denied_access = Access::new(xml, access.snapshot(), &denied);
    assert!(matches!(
        check(counters, &denied_access),
        Err(pki::ParticipantError::Scope(
            structured_ltv::source::ScopeError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            }
        ))
    ));
}

impl<C: Work> ArchiveMaterialCheck<'_, '_, C> {
    fn all<'document>(
        &self,
        path: &structured_ltv::pki::CheckedPath<'document>,
        prior: &structured_ltv::pki::TimestampPath<
            '_,
            '_,
            'document,
            usize,
            u8,
            u8,
            structured_xades::Xades,
        >,
        archive: &structured_ltv::pki::TimestampPath<
            '_,
            '_,
            'document,
            usize,
            u8,
            u8,
            structured_xades::Xades,
        >,
    ) {
        use structured_xades::timestamp;
        let memory = self.operation.memory();
        let access = Access::new(self.xml, self.xml.snapshot(), memory);
        let counters =
            structured_xades::pki::bind_counters(self.prepared.bound(), &access, |_, _| {
                Ok::<_, ()>(path)
            })
            .unwrap();
        let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
        let required = timestamp::requirements_with_counters(
            &access,
            self.prepared,
            &stamps,
            timestamp::TimestampSelection::All,
        )
        .unwrap();
        let paths = [prior, archive];
        let structured_ltv::timestamp::TimestampPathBinding::Bound(all) =
            required.bind_paths(&paths, &access).unwrap()
        else {
            panic!("every original token has its actual TSA path")
        };
        with_prepared_participants(
            self.xml,
            self.prepared,
            path,
            path.anchor(),
            &all,
            memory,
            |participants| {
                assert_all_participant_scope(self.xml, participants, path, memory, |closed| {
                    self.reject_all(closed, &counters);
                });
            },
        );
    }

    fn before<'document>(
        &self,
        participants: &structured_ltv::pki::ParticipantRequirements<
            '_,
            'document,
            usize,
            u8,
            u8,
            structured_xades::Xades,
        >,
        path: &structured_ltv::pki::CheckedPath<'document>,
        credentials: &structured_xades::credential::ParticipantCredentials<
            '_,
            'document,
            usize,
            usize,
            u8,
            u8,
        >,
    ) {
        use structured_ltv::pki;
        use structured_xades::{material, timestamp};
        let memory = self.operation.memory();
        let access = Access::new(self.xml, self.xml.snapshot(), memory);
        let counters =
            structured_xades::pki::bind_counters(self.prepared.bound(), &access, |_, _| {
                Ok::<_, ()>(path)
            })
            .unwrap();
        let ordinal = self
            .prepared
            .timestamps()
            .iter()
            .position(|stamp| stamp.node() == self.evidence.property())
            .unwrap();
        let required = participant_timestamp_requirements(
            &access,
            self.prepared,
            path,
            timestamp::TimestampSelection::BeforeArchive(ordinal),
        );
        let format = ArchiveFormat {
            certificate: path.anchor().certificate().unwrap(),
            calls: Cell::new(0),
        };
        with_original_delta_statuses(path, memory, |inputs| {
            let nodes = [pki::AuthorityNode {
                statuses: inputs,
                responders: &[],
            }];
            let roots = [inputs; 4];
            let closed = participants
                .close_statuses(&roots, &nodes, &access)
                .unwrap();
            material::with_values(self.xml, self.prepared, self.operation, |query, view| {
                let work = query.execution();
                let access = Access::new(self.xml, self.xml.snapshot(), &work);
                let index = material::index(&view, &access).unwrap();
                assert_participant_archive_material(
                    &closed,
                    &index,
                    self.coverage,
                    self.evidence,
                    &access,
                    self.xml,
                    self.early,
                );
                let report = material::credentials::check(
                    credentials,
                    &counters,
                    &required,
                    &index,
                    &material::credentials::Scope::before_archive(self.coverage, self.evidence),
                    &format,
                    &access,
                )
                .unwrap();
                assert_format_archive(&report, &format, self.early);
                let x509 = structured_ltv::material::archived_participants(
                    &closed,
                    &index,
                    self.coverage,
                    self.evidence,
                    &access,
                )
                .unwrap();
                assert_archive_pair(&x509, &report, &access, self.xml, self.early, self.prepared);
                Ok::<_, ()>(())
            })
            .unwrap();
        });
    }

    fn reject_all(
        &self,
        closed: &structured_ltv::pki::ParticipantClosure<
            '_,
            '_,
            '_,
            '_,
            usize,
            u8,
            u8,
            structured_xades::Xades,
        >,
        counters: &structured_xades::pki::CounterPaths<'_, '_, usize, u8, u8>,
    ) {
        // Whole-LT scope cannot be substituted for the exact antecedents of
        // this archive, even when every same certificate is available/covered.
        use structured_xades::material;
        material::with_values(self.xml, self.prepared, self.operation, |query, view| {
            let work = query.execution();
            let access = Access::new(self.xml, self.xml.snapshot(), &work);
            let index = material::index(&view, &access).unwrap();
            let before = work.memory().used();
            // The composed LT check must visit the same six original actors,
            // including BOTH real TSA paths. Ordinary incorporated copies alone
            // remain negative; the prescribed general pool satisfies placement.
            // Neither route repeats the two timestamp signatures or CRL math.
            let combined =
                material::check_participants(self.prepared, closed, counters, &index, &access)
                    .unwrap();
            assert!(core::ptr::eq(combined.timestamps().inputs(), closed));
            assert!(combined.presence().all_present());
            assert!(combined.conditional().findings().is_empty());
            assert!(combined.exclusive().findings().is_empty());
            assert_eq!(
                combined.timestamps().findings().len(),
                if self.general { 0 } else { 8 }
            );
            assert_eq!(combined.all_x509_requirements_met(), self.general);
            drop(combined);
            assert_eq!(work.memory().used(), before);
            assert_timestamp_placement(closed, &index, &access, self.xml, self.general);
            let uses = structured_ltv::pki::authority_uses(closed, &access).unwrap();
            let artifacts = structured_ltv::material::artifact_uses(&uses, &access).unwrap();
            assert_incorporated_inputs(&artifacts, &index, &access, self.xml, true);
            let placement = material::exclusivity(&artifacts, &index, &access).unwrap();
            assert_eq!(
                placement.signature(),
                self.prepared.bound().containers().signature()
            );
            assert_eq!(placement.snapshot(), self.xml.snapshot());
            assert!(placement.findings().is_empty());
            drop(placement);
            drop(artifacts);
            drop(uses);
            assert_eq!(work.memory().used(), before);
            assert!(
                matches!(structured_ltv::material::archived_participants(closed, &index,
                self.coverage, self.evidence, &access),
                Err(structured_ltv::material::ParticipantArchiveError::Foreign { expected, actual })
                if expected == self.prepared.bound().containers().signature()
                    && actual == self.evidence.property())
            );
            assert_eq!(work.memory().used(), before);
            Ok::<_, ()>(())
        })
        .unwrap();
    }
}

fn assert_format_archive(
    report: &structured_xades::material::credentials::Report<'_, '_, '_, usize, usize, u8, u8>,
    format: &ArchiveFormat<'_, '_>,
    early: bool,
) {
    // Format completeness and original coverage are independent: understood
    // material added later retains an exact Uncovered finding.
    use structured_xades::material;
    assert_eq!(report.entries().len(), 2);
    assert_eq!(format.calls.get(), 2);
    assert_eq!(report.all_requirements_met(), early);
    for entry in report.entries() {
        assert_eq!(
            entry.completeness(),
            material::credentials::Completeness::Complete
        );
        if early {
            assert_eq!(entry.findings(), []);
        } else {
            assert_eq!(
                entry.findings(),
                &[material::credentials::Finding {
                    dependency: 0,
                    cause: material::credentials::Missing::Uncovered
                }]
            );
        }
    }
}

fn assert_archive_pair<W: Work>(
    x509: &structured_ltv::material::ParticipantMaterial<
        '_,
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::material::Placement<usize>,
        structured_xades::Xades,
    >,
    format: &structured_xades::material::credentials::Report<'_, '_, '_, usize, usize, u8, u8>,
    access: &Access<'_, Tree, W>,
    xml: &Tree,
    covered: bool,
    prepared: &structured_xades::prepare::Prepared<Tree>,
) {
    // Joined material must retain both complete reports and exact original
    // credential identity, without reauthentication, copying or query credit.
    use structured_ltv::{baseline, pki};
    let held = access.execution().memory().used();
    let combined = baseline::archive_material(x509, format, access).unwrap();
    assert_eq!(combined.all_material_covered(), covered);
    assert!(core::ptr::eq(combined.x509(), x509));
    assert!(core::ptr::eq(combined.credentials(), format));
    let reports = [&combined];
    let mut archives = prepared
        .timestamps()
        .iter()
        .filter(|stamp| stamp.role() == structured_xades::timestamp::Role::Archive);
    assert_eq!(
        archives.next().unwrap().node(),
        x509.inputs().requirements().scope().location().node
    );
    let second = archives
        .next()
        .map(structured_xades::timestamp::Stamp::node);
    assert!(archives.next().is_none());
    if let Some(second) = second {
        assert!(matches!(baseline::archives(prepared,&reports,access),
            Err(baseline::ArchiveCensusError::Missing {property}) if property==second));
    } else {
        let census = baseline::archives(prepared, &reports, access).unwrap();
        assert!(core::ptr::eq(census.census(), prepared));
        assert_eq!(census.reports().len(), 1);
        assert_eq!(census.all_archive_material_covered(), covered);
    }
    assert!(matches!(baseline::archives(prepared,&reports[..0],access),
        Err(baseline::ArchiveCensusError::Missing {property}) if property==x509.inputs().requirements().scope().location().node));
    let duplicates = [&combined, &combined];
    if let Some(second) = second {
        assert!(matches!(baseline::archives(prepared, &duplicates, access),
            Err(baseline::ArchiveCensusError::Foreign {node}) if node==second));
    } else {
        assert!(matches!(
            baseline::archives(prepared, &duplicates, access),
            Err(baseline::ArchiveCensusError::Extra)
        ));
    }
    assert_eq!(access.execution().memory().used(), held);
    let denied = structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(65_536, 0),
    ));
    let query = Access::new(xml, xml.snapshot(), &denied);
    assert!(matches!(
        baseline::archive_material(x509, format, &query),
        Err(pki::ParticipantError::Scope(
            structured_ltv::source::ScopeError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            }
        ))
    ));
    assert_eq!(denied.used(), 0);
    assert!(matches!(
        baseline::archives(prepared, &reports, &query),
        Err(baseline::ArchiveCensusError::Scope(
            structured_ltv::source::ScopeError::Resource {
                cause: MemoryError::WorkExceeded,
                ..
            }
        ))
    ));
}

fn assert_incorporated_inputs<W: Work, Q: Work>(
    uses: &structured_ltv::material::ArtifactUses<
        '_,
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    index: &structured_xades::material::Index<'_, usize, u8, u8, W>,
    access: &Access<'_, Tree, Q>,
    xml: &Tree,
    present: bool,
) {
    // The full archive fixture incorporates all four actual inputs. The
    // exclusivity fixture has certificate copies but neither contributing CRL;
    // successful authentication/acquisition alone must not become incorporation.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let before = access.execution().memory().used();
    let report = structured_ltv::material::incorporation(uses, index, access).unwrap();
    assert_eq!(report.snapshot(), xml.snapshot());
    assert_eq!(report.signature(), 0);
    assert_eq!(report.all_present(), present);
    let mut statuses = 0;
    for entry in report.entries() {
        if let structured_ltv::material::ArtifactRef::Crl(_) = entry.artifact() {
            statuses += 1;
            assert_eq!(entry.occurrence().is_some(), present);
        }
        if present {
            assert!(entry.occurrence().is_some());
        }
    }
    assert_eq!(statuses, 2);
    drop(report);
    assert_eq!(access.execution().memory().used(), before);
    let denied = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1 << 24)));
    let denied_access = Access::new(xml, access.snapshot(), &denied);
    assert!(matches!(
        structured_ltv::material::incorporation(uses, index, &denied_access),
        Err(structured_ltv::material::IncorporationError::Index(
            structured_ltv::material::IndexError::Resource {
                cause: MemoryError::LimitExceeded,
                ..
            }
        ))
    ));
    assert_eq!(denied.used(), 0);
    assert_eq!(access.execution().memory().used(), before);
    let foreign = Access::new(
        xml,
        structured_xades::xml::Snapshot {
            document: xml.document + 1,
            generation: xml.generation.get(),
        },
        access.execution(),
    );
    assert!(matches!(
        structured_ltv::material::incorporation(uses, index, &foreign),
        Err(structured_ltv::material::IncorporationError::Index(
            structured_ltv::material::IndexError::Foreign { signature: 0 }
        ))
    ));
}

fn assert_timestamp_placement<W: Work, Q: Work>(
    closed: &structured_ltv::pki::ParticipantClosure<
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    index: &structured_xades::material::Index<'_, usize, u8, u8, W>,
    access: &Access<'_, Tree, Q>,
    xml: &Tree,
    general: bool,
) {
    // This XML-only pool has all four exact artifacts in ordinary containers.
    // They cover archive input but cannot satisfy §6.3(x) for EITHER real TSA.
    use structured_ltv::pki;
    use structured_xades::material;
    let before = access.execution().memory().used();
    let checked = material::timestamp_placement(closed, index, access).unwrap();
    assert!(std::ptr::eq(checked.inputs(), closed));
    assert_eq!(checked.snapshot(), xml.snapshot());
    assert_eq!(checked.findings().len(), if general { 0 } else { 8 });
    for entry in closed.requirements().entries() {
        if let pki::Participant::Timestamp { property, token } = entry.participant() {
            assert_eq!(
                checked
                    .findings()
                    .iter()
                    .filter(|finding| finding.property == property && finding.token == token)
                    .count(),
                if general { 0 } else { 4 }
            );
        }
    }
    assert!(
        checked.findings().iter().all(|finding| finding.cause
            == material::TimestampPlacementFailure::OutsideTimestampContainers)
    );
    drop(checked);
    assert_eq!(access.execution().memory().used(), before);
    for (storage, work) in [(0, 1_000_000), (65_536, 0)] {
        let denied = structured_asn1::memory::Memory::new(std::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(storage, work),
        ));
        let denied_access = Access::new(xml, xml.snapshot(), &denied);
        let refusal = material::timestamp_placement(closed, index, &denied_access);
        if work == 0 {
            assert!(matches!(
                refusal,
                Err(material::TimestampPlacementError::Index(
                    structured_ltv::material::IndexError::Scope(
                        structured_ltv::source::ScopeError::Resource {
                            cause: MemoryError::WorkExceeded,
                            ..
                        }
                    )
                ))
            ));
        } else {
            assert!(matches!(
                refusal,
                Err(material::TimestampPlacementError::Index(
                    structured_ltv::material::IndexError::Resource {
                        cause: MemoryError::LimitExceeded,
                        ..
                    }
                ))
            ));
        }
        assert_eq!(denied.used(), 0);
        assert_eq!(access.execution().memory().used(), before);
    }
}

fn assert_all_participant_scope<'document>(
    xml: &Tree,
    participants: &structured_ltv::pki::ParticipantRequirements<
        '_,
        'document,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    path: &structured_ltv::pki::CheckedPath<'document>,
    memory: &structured_asn1::memory::Memory,
    check: impl FnOnce(
        &structured_ltv::pki::ParticipantClosure<
            '_,
            '_,
            '_,
            '_,
            usize,
            u8,
            u8,
            structured_xades::Xades,
        >,
    ),
) {
    // Same actor collector, but LT includes the archive TSA too. The roots
    // come from those original actors; no caller-written count proves coverage.
    use structured_ltv::pki;
    assert_eq!(
        participants.scope(),
        structured_ltv::timestamp::TimestampScope::All(binary::Location {
            snapshot: xml.snapshot(),
            node: participants.signature()
        })
    );
    assert_eq!(participants.entries().len(), 6);
    assert_eq!(
        participants
            .entries()
            .iter()
            .filter(|entry| matches!(entry.participant(), pki::Participant::Timestamp { .. }))
            .count(),
        2
    );
    with_original_delta_statuses(path, memory, |inputs| {
        let nodes = [pki::AuthorityNode {
            statuses: inputs,
            responders: &[],
        }];
        let roots = [inputs; 5];
        let access = Access::new(xml, xml.snapshot(), memory);
        let closed = participants
            .close_statuses(&roots, &nodes, &access)
            .unwrap();
        let uses = pki::authority_uses(&closed, &access).unwrap();
        assert_participant_artifact_uses(&uses, &access, xml);
        assert_eq!(uses.inputs().requirements().scope(), participants.scope());
        assert_individual_root_attribution(closed.authorities(), memory);
        check(&closed);
    });
}

fn assert_individual_root_attribution(
    closure: &structured_ltv::pki::AuthorityClosure<'_, '_, '_>,
    original: &structured_asn1::memory::Memory,
) {
    // Two real TSA actors and the ordinary actors deliberately share this
    // cyclic CRL-authority graph. Aggregate purpose bits must not erase which
    // original actor needs the data; one visit per root/node, no crypto replay.
    use structured_ltv::pki::{AuthorityClosureError, AuthorityVisitError};
    assert_eq!(closure.nodes().len(), 1);
    let before = original.used();
    let mut visited = [0usize; 5];
    closure
        .visit_roots(original, |root, node| {
            assert!(std::ptr::eq(node.statuses, closure.roots()[root]));
            visited[root] += 1;
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(visited, [1; 5]);
    assert_eq!(original.used(), before);
    let mut calls = 0;
    let result = closure.visit_roots(original, |_, _| {
        calls += 1;
        Err("original visitor refusal")
    });
    assert!(matches!(
        result,
        Err(AuthorityVisitError::Visitor("original visitor refusal"))
    ));
    assert_eq!(calls, 1);
    assert_eq!(original.used(), before);
    for (storage, work) in [(0, 100_000), (65_536, 0)] {
        let denied = structured_asn1::memory::Memory::new(std::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(storage, work),
        ));
        let result = closure.visit_roots(&denied, |_, _| {
            panic!("refusal must precede first actor callback")
        });
        assert!(matches!(
            result,
            Err(AuthorityVisitError::<()>::Processing(
                AuthorityClosureError::Resource(_)
            ))
        ));
        assert_eq!(denied.used(), 0);
        assert_eq!(original.used(), before);
    }
}

fn participant_material_memory() -> structured_asn1::memory::Memory {
    // Two real tokens, credential/path censuses and CRL/material checks share
    // this operation. Keep the storage ceiling; explicitly fund combined work.
    structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(65_536, 2_000_000),
    ))
}

fn assert_participant_archive_material<W: Work, Q: Work, C: Work>(
    closed: &structured_ltv::pki::ParticipantClosure<
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    index: &structured_xades::material::Index<'_, usize, u8, u8, W>,
    coverage: &structured_ltv::material::Coverage<usize, u8, u8, C, structured_xades::Xades>,
    evidence: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    access: &Access<'_, Tree, Q>,
    xml: &Tree,
    early: bool,
) {
    use structured_asn1::memory::{Memory, MemoryAccount};
    use structured_xades::material::{self, Archived};
    let memory = access.execution().memory();
    let before = memory.used();
    let uses = structured_ltv::pki::authority_uses(closed, access).unwrap();
    assert_eq!(uses.entries().len(), 1);
    assert!(uses.entries()[0].uses().signature());
    assert!(uses.entries()[0].uses().credential());
    assert!(uses.entries()[0].uses().timestamp());
    assert_participant_artifact_uses(&uses, access, xml);
    let artifacts = structured_ltv::material::artifact_uses(&uses, access).unwrap();
    assert!(matches!(material::exclusivity(&artifacts, index, access),
        Err(material::ExclusivityError::Scope { node }) if node == closed.requirements().scope().location().node));
    assert!(matches!(
        structured_ltv::material::incorporation(&artifacts, index, access),
        Err(structured_ltv::material::IncorporationError::Scope)
    ));
    drop(artifacts);
    drop(uses);
    let report =
        structured_ltv::material::archived_participants(closed, index, coverage, evidence, access)
            .unwrap();
    assert!(core::ptr::eq(report.inputs(), closed));
    assert_eq!(report.all_x509_artifacts_covered(), early);
    assert_eq!(report.authorities().paths().len(), 1);
    assert_eq!(report.authorities().paths()[0].statuses().len(), 1);
    assert_eq!(report.anchors().len(), 1);
    let anchor = &report.anchors()[0];
    assert_eq!(
        anchor.participant(),
        closed.requirements().entries()[3].participant()
    );
    if early {
        assert!(matches!(anchor.certificate(), Some(Archived::Present(_))));
    } else {
        assert!(matches!(anchor.certificate(), Some(Archived::Uncovered)));
    }
    drop(report);
    assert_eq!(memory.used(), before);
    // Admit exactly the reached paths; refuse subsequent anchor-report capacity.
    let paths = structured_ltv::material::status::archived_authorities(
        closed.authorities(),
        index,
        coverage,
        evidence,
        access,
    )
    .unwrap();
    let capacity = memory.used() - before;
    drop(paths);
    assert_eq!(memory.used(), before);
    let limited = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, 1 << 26)));
    let limited_access = Access::new(xml, access.snapshot(), &limited);
    assert!(matches!(
        structured_ltv::material::archived_participants(
            closed,
            index,
            coverage,
            evidence,
            &limited_access
        ),
        Err(
            structured_ltv::material::ParticipantArchiveError::Resource {
                cause: MemoryError::LimitExceeded,
                ..
            }
        )
    ));
    assert_eq!(limited.used(), 0);
    assert_eq!(memory.used(), before);
    let denied = super::memory(0);
    let denied = Access::new(xml, access.snapshot(), &denied);
    assert!(matches!(
        structured_ltv::material::archived_participants(closed, index, coverage, evidence, &denied),
        Err(structured_ltv::material::ParticipantArchiveError::Material(
            structured_ltv::material::ArchiveError::Index(
                structured_ltv::material::IndexError::Scope(
                    structured_ltv::source::ScopeError::Resource { .. },
                )
            )
        ))
    ));
    let foreign = Access::new(
        xml,
        structured_xades::xml::Snapshot {
            document: xml.document + 1,
            generation: xml.generation.get(),
        },
        access.execution(),
    );
    assert!(
        matches!(structured_ltv::material::archived_participants(closed,index,coverage,evidence,&foreign),
        Err(structured_ltv::material::ParticipantArchiveError::Foreign {expected,actual}) if expected==closed.requirements().scope().location().node && actual==evidence.property())
    );
    assert_eq!(memory.used(), before);
}

fn assert_participant_artifact_uses<W: Work>(
    uses: &structured_ltv::pki::AuthorityUses<
        '_,
        '_,
        '_,
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    access: &Access<'_, Tree, W>,
    xml: &Tree,
) {
    // One shared root/leaf and actual complete+delta CRLs: identity is original
    // DER, not every path/status occurrence. All three real actor uses survive.
    use structured_asn1::memory::{Memory, MemoryAccount};
    use structured_ltv::pki;
    let memory = access.execution().memory();
    let before = memory.used();
    let artifacts = structured_ltv::material::artifact_uses(uses, access).unwrap();
    assert!(core::ptr::eq(artifacts.inputs(), uses.inputs()));
    assert_eq!(artifacts.entries().len(), 4);
    let mut certificates = 0;
    let mut crls = 0;
    for entry in artifacts.entries() {
        assert!(entry.uses().signature());
        assert!(entry.uses().credential());
        assert!(entry.uses().timestamp());
        match entry.artifact() {
            structured_ltv::material::ArtifactRef::Certificate(_) => certificates += 1,
            structured_ltv::material::ArtifactRef::Crl(_) => crls += 1,
            structured_ltv::material::ArtifactRef::Ocsp(_) => {
                panic!("actual source uses only CRLs")
            }
        }
    }
    assert_eq!((certificates, crls), (2, 2));
    drop(artifacts);
    assert_eq!(memory.used(), before);
    // Current operation pays even though roles/storage came from another one.
    let limited = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1 << 26)));
    let limited_access = Access::new(xml, access.snapshot(), &limited);
    assert!(matches!(
        structured_ltv::material::artifact_uses(uses, &limited_access),
        Err(pki::UsesError::Closure(
            pki::AuthorityClosureError::Resource(MemoryError::LimitExceeded)
        ))
    ));
    assert_eq!(limited.used(), 0);
    let denied = super::memory(0);
    let denied_access = Access::new(xml, access.snapshot(), &denied);
    assert!(matches!(
        structured_ltv::material::artifact_uses(uses, &denied_access),
        Err(pki::UsesError::Scope(
            structured_ltv::source::ScopeError::Resource { .. }
        ))
    ));
    let foreign = Access::new(
        xml,
        structured_xades::xml::Snapshot {
            document: xml.document + 1,
            generation: xml.generation.get(),
        },
        access.execution(),
    );
    assert!(matches!(
        structured_ltv::material::artifact_uses(uses, &foreign),
        Err(pki::UsesError::Foreign)
    ));
    assert_eq!(memory.used(), before);
}

pub(super) fn assert_participant_status_closure<'document>(
    path: &structured_ltv::pki::CheckedPath<'document>,
    inputs: &structured_ltv::pki::PathStatuses<'_, '_, 'document>,
) {
    let nodes = [structured_ltv::pki::AuthorityNode {
        statuses: inputs,
        responders: &[],
    }];
    assert_participant_nodes(path, inputs, &nodes);
}

pub(super) fn assert_participant_nodes<'document>(
    path: &structured_ltv::pki::CheckedPath<'document>,
    inputs: &structured_ltv::pki::PathStatuses<'_, '_, 'document>,
    nodes: &[structured_ltv::pki::AuthorityNode<'_, '_, 'document>],
) {
    // Real original CRL census from the enclosing archive test is required for
    // EVERY path actor, even when signer/counter/credential share that path.
    // Anchor-only credential material must not become an extra status root.
    use structured_ltv::pki;
    use structured_xades::{certificate, credential, prepare, timestamp, unsigned};
    // Independent source-query scenario: do not spend the enclosing archive
    // fixture's remaining operation budget on this additional XML document.
    let memory = &funded();
    let leaf = path.members().last().unwrap().certificate().as_bytes();
    let (mut xml, _, _, _, archive) = participant_tree(leaf, memory);
    // This helper checks WHOLE participant/status closure, not an earlier
    // archive. Its unused synthetic archive must not introduce a TSA obligation
    // or hide the later counter that the assertions below deliberately require.
    xml.nodes[archive].parent = None;
    let access = Access::new(&xml, xml.snapshot(), memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
    let digest = Oracle::new(Mode::Ready);
    let signer = certificate::check_path(
        &xml,
        prepared.bound(),
        prepared.certificates(),
        path,
        &digest,
        memory,
    )
    .unwrap();
    let counters =
        structured_xades::pki::bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path))
            .unwrap();
    let anchor = path.anchor();
    let anchor = structured_pkix::path::EffectiveAnchor::bind(
        anchor,
        structured_pkix::path::WorkingKey::standing(anchor.key()),
        memory,
    )
    .unwrap()
    .unwrap();
    let paths = [path];
    let credentials = credential::check_participants(
        &prepared,
        &counters,
        &CredentialAuthorities {
            paths: &paths,
            anchor: &anchor,
        },
        &access,
    )
    .unwrap();
    let selection = timestamp::TimestampSelection::All;
    let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
    let required =
        timestamp::requirements_with_counters(&access, &prepared, &stamps, selection).unwrap();
    let structured_ltv::timestamp::TimestampPathBinding::Bound(prior) =
        required.bind_paths(&[], &access).unwrap()
    else {
        panic!("complete empty earlier-token set")
    };
    let participants = participants(&signer, &counters, &credentials, &prior, &access).unwrap();
    let roots = [inputs; 3];
    let before = memory.used();
    let closed = participants.close_statuses(&roots, nodes, &access).unwrap();
    assert!(core::ptr::eq(
        closed.requirements(),
        &raw const participants
    ));
    assert_eq!(closed.authorities().roots().len(), 3);
    assert_eq!(closed.authorities().nodes().len(), nodes.len());
    assert!(core::ptr::eq(
        closed.authorities().nodes()[0].statuses,
        inputs
    ));
    let uses = pki::authority_uses(&closed, &access).unwrap();
    assert!(core::ptr::eq(uses.inputs(), &raw const closed));
    assert_eq!(uses.entries().len(), nodes.len());
    for (actual, expected) in uses.entries().iter().zip(nodes) {
        assert!(core::ptr::eq(actual.node(), expected));
        assert!(actual.uses().signature());
        assert!(actual.uses().credential());
        assert!(!actual.uses().timestamp());
    }
    drop(uses);
    drop(closed);
    assert_eq!(memory.used(), before);
    assert!(matches!(
        participants.close_statuses(&roots[..2], nodes, &access),
        Err(pki::ParticipantClosureError::Count)
    ));
    let extra = [inputs; 4];
    assert!(matches!(
        participants.close_statuses(&extra, nodes, &access),
        Err(pki::ParticipantClosureError::Count)
    ));
    assert!(matches!(
        participants.close_statuses(&roots, &[], &access),
        Err(pki::ParticipantClosureError::Authority(
            pki::AuthorityClosureError::MissingPath { .. }
        ))
    ));
    let denied = super::memory(0);
    let denied = Access::new(&xml, xml.snapshot(), &denied);
    assert!(matches!(
        participants.close_statuses(&roots, nodes, &denied),
        Err(pki::ParticipantClosureError::Scope(
            structured_ltv::source::ScopeError::Resource { .. }
        ))
    ));
    assert_eq!(memory.used(), before);
}

#[test]
fn archive_participant_requirements_derive_signer_counters_credentials_and_direct_anchor() {
    // Exact source actors determine X509 material inputs, not a success-list or
    // a count of carried values. This is NOT a positive B-LTA/real-C14N oracle.
    use structured_ltv::{pki, source::ScopeError, timestamp::TimestampPathBinding};
    use structured_xades::{
        certificate, credential, pki::bind_counters, prepare, timestamp, unsigned,
    };
    with_checked_path(|path, leaf, _, memory| {
        let (xml, child, root_credential, child_credential, archive) =
            participant_tree_before_archive(leaf, memory);
        let access = Access::new(&xml, xml.snapshot(), memory);
        let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
        let digest = Oracle::new(Mode::Ready);
        let signer = certificate::check_path(
            &xml,
            prepared.bound(),
            prepared.certificates(),
            path,
            &digest,
            memory,
        )
        .unwrap();
        assert!(signer.is_bound());
        let counters = bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path)).unwrap();
        let anchor = path.anchor();
        let key = structured_pkix::path::WorkingKey::standing(anchor.key());
        let anchor = structured_pkix::path::EffectiveAnchor::bind(anchor, key, memory)
            .unwrap()
            .unwrap();
        let paths = [path];
        let provider = CredentialAuthorities {
            paths: &paths,
            anchor: &anchor,
        };
        let credentials =
            credential::check_participants(&prepared, &counters, &provider, &access).unwrap();
        let at = prepared
            .timestamps()
            .iter()
            .position(|stamp| stamp.node() == archive)
            .unwrap();
        let required = participant_timestamp_requirements(
            &access,
            &prepared,
            path,
            timestamp::TimestampSelection::BeforeArchive(at),
        );
        assert!(required.entries().is_empty());
        let TimestampPathBinding::Bound(prior) = required.bind_paths(&[], &access).unwrap() else {
            panic!("complete empty antecedent set")
        };
        let before = memory.used();
        let census = participants(&signer, &counters, &credentials, &prior, &access).unwrap();
        assert!(
            matches!(census.scope(), structured_ltv::timestamp::TimestampScope::BeforeArchive(location) if location.node == archive)
        );
        assert_eq!(census.signature(), 0);
        let expected = [
            pki::Participant::Signer(0),
            pki::Participant::Counter {
                signature: child,
                property: xml.nodes[child].parent.unwrap(),
            },
            pki::Participant::Credential {
                signature: 0,
                node: root_credential,
                authority: 0,
            },
            pki::Participant::Credential {
                signature: child,
                node: child_credential,
                authority: 0,
            },
        ];
        assert_eq!(census.entries().len(), expected.len());
        for (index, entry) in census.entries().iter().enumerate() {
            assert_eq!(entry.participant(), expected[index]);
            if index == 3 {
                let pki::ParticipantAuthority::Anchor(actual) = entry.authority() else {
                    panic!("direct anchor")
                };
                assert!(core::ptr::eq(actual, &raw const anchor));
            } else {
                let pki::ParticipantAuthority::Path(actual) = entry.authority() else {
                    panic!("original checked path")
                };
                assert!(core::ptr::eq(actual, path));
            }
        }
        drop(census);
        assert_eq!(memory.used(), before);
        let denied = super::memory(0);
        let denied = Access::new(&xml, xml.snapshot(), &denied);
        assert!(matches!(
            participants(&signer, &counters, &credentials, &prior, &denied),
            Err(pki::ParticipantError::Scope(ScopeError::Resource { .. }))
        ));
        assert_eq!(memory.used(), before);
    });
}

fn assert_earlier_actor_census(
    participants: &structured_ltv::pki::ParticipantRequirements<
        '_,
        '_,
        usize,
        u8,
        u8,
        structured_xades::Xades,
    >,
    path: &structured_ltv::pki::TimestampPath<'_, '_, '_, usize, u8, u8, structured_xades::Xades>,
    expected: structured_ltv::timestamp::RequiredToken<usize>,
    archive: usize,
    provider: &super::timestamp_oracle::Oracle,
) {
    use structured_ltv::pki;
    assert_eq!(participants.entries().len(), 5);
    let entry = &participants.entries()[4];
    assert_eq!(
        entry.participant(),
        pki::Participant::Timestamp {
            property: expected.property,
            token: expected.token,
        }
    );
    let pki::ParticipantAuthority::Path(actual) = entry.authority() else {
        panic!("original checked TSA path")
    };
    assert!(core::ptr::eq(actual, path.path()));
    assert!(
        matches!(participants.scope(), structured_ltv::timestamp::TimestampScope::BeforeArchive(location) if location.node == archive)
    );
    assert_eq!(provider.verified.get(), 1);
}

fn prior_participant_tree(
    leaf: &[u8],
    memory: &structured_asn1::memory::Memory,
) -> (
    Tree,
    structured_xades::prepare::Prepared<Tree>,
    usize,
    super::timestamp_oracle::Oracle,
    Vec<u8>,
) {
    use structured_xades::{prepare, timestamp, unsigned};
    let (mut xml, _, _, _, archive) = participant_tree_before_archive(leaf, memory);
    xml.nodes[8].parent = Some(7);
    super::append_timestamp(&mut xml, 7, timestamp::Role::Archive, 1);
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), memory),
        0,
        unsigned::Requirements::Archival,
        None,
    )
    .unwrap();
    let method = u8::try_from(prepared.timestamps()[0].method()).unwrap();
    let (provider, token, tsa, _) =
        super::timestamp_oracle::fixture_with_root(&[b'E', 12, b'M', method]);
    xml.binary = token;
    (xml, prepared, archive, provider, tsa)
}

#[test]
fn archive_participants_require_the_actual_earlier_tsa_and_exclude_own_and_later_tokens() {
    // Real TSP mathematics supplies only its original earlier actor. Synthetic
    // XML framing is not a C14N or complete B-LTA interoperability oracle.
    use structured_ltv::pki;
    use structured_ltv::timestamp::{TimestampPathBinding, TimestampPathFailure};
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    use structured_xades::{certificate, credential, pki::bind_counters, timestamp};
    with_checked_path(|path, leaf, _, memory| {
        let (xml, prepared, archive, provider, tsa_bytes) = prior_participant_tree(leaf, memory);
        let stamp = &prepared.timestamps()[0];
        assert_eq!(stamp.node(), 8);
        let access = Access::new(&xml, xml.snapshot(), memory);
        let digest = Oracle::new(Mode::Ready);
        let signer = certificate::check_path(
            &xml,
            prepared.bound(),
            prepared.certificates(),
            path,
            &digest,
            memory,
        )
        .unwrap();
        let counters = bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path)).unwrap();
        let anchor = path.anchor();
        let anchor = structured_pkix::path::EffectiveAnchor::bind(
            anchor,
            WorkingKey::standing(anchor.key()),
            memory,
        )
        .unwrap()
        .unwrap();
        let paths = [path];
        let credentials = credential::check_participants(
            &prepared,
            &counters,
            &CredentialAuthorities {
                paths: &paths,
                anchor: &anchor,
            },
            &access,
        )
        .unwrap();
        let parser = structured_asn1::Parser::der(memory.clone());
        let parent = parser.read(&[], 900).unwrap();
        let tsa = structured_pkix::Certificate::read(&parser, &tsa_bytes, 400).unwrap();
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = structured_cms::timestamp::CheckContext {
            certificate: &tsa,
            certificate_parent: &parent,
            key: WorkingKey::standing(tsa.tbs().public_key()),
            requested: None,
            utc: &utc,
            reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
            window: None,
        };
        let actor = timestamp::Check {
            xml: &xml,
            provider: &provider,
            context: &context,
        }
        .retain_actor(prepared.bound(), stamp, 0, &parent, |_, _| {
            Ok::<_, ()>(false)
        })
        .unwrap()
        .expect("actual original signature timestamp");
        let pki::TimestampBinding::Bound(tsa_path) =
            path.bind_timestamp(&actor, &utc, memory).unwrap()
        else {
            panic!("actual TSA key and complete generation interval")
        };
        let at = prepared
            .timestamps()
            .iter()
            .position(|stamp| stamp.node() == archive)
            .unwrap();
        let required = participant_timestamp_requirements(
            &access,
            &prepared,
            path,
            timestamp::TimestampSelection::BeforeArchive(at),
        );
        assert_eq!(required.entries().len(), 1);
        let expected = required.entries()[0];
        assert_eq!(expected.property, 8);
        assert!(matches!(
            required.bind_paths(&[], &access).unwrap(),
            TimestampPathBinding::Unproven(TimestampPathFailure::Count)
        ));
        let supplied = [&tsa_path];
        let TimestampPathBinding::Bound(prior) = required.bind_paths(&supplied, &access).unwrap()
        else {
            panic!("complete original earlier TSA set")
        };
        let before = memory.used();
        let participants = participants(&signer, &counters, &credentials, &prior, &access).unwrap();
        assert_earlier_actor_census(&participants, &tsa_path, expected, archive, &provider);
        drop(participants);
        assert_eq!(memory.used(), before);
    });
}

fn inheritance_certificate(parameters: bool) -> Vec<u8> {
    // Metadata-only DSA fixture: tiny parameters deliberately provide no
    // cryptographic security. Reuse the existing DER fixture writer.
    use super::timestamp_oracle::tlv;
    let algorithm = tlv(0x30, &tlv(6, &[0x2a, 0x86, 0x48, 0xce, 0x38, 4, 3]));
    let name = tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(
                0x30,
                &[tlv(6, &[0x55, 4, 3]), tlv(12, b"Inheritance")].concat(),
            ),
        ),
    );
    let mut key_algorithm = tlv(6, &[0x2a, 0x86, 0x48, 0xce, 0x38, 4, 1]);
    if parameters {
        key_algorithm.extend(tlv(
            0x30,
            &[tlv(2, &[23]), tlv(2, &[11]), tlv(2, &[2])].concat(),
        ));
    }
    let key = tlv(
        0x30,
        &[tlv(0x30, &key_algorithm), tlv(3, &[0, 2, 1, 4])].concat(),
    );
    let validity = tlv(
        0x30,
        &[tlv(0x17, b"250101000000Z"), tlv(0x17, b"300101000000Z")].concat(),
    );
    let tbs = tlv(
        0x30,
        &[
            tlv(2, &[1]),
            algorithm.clone(),
            name.clone(),
            validity,
            name,
            key,
        ]
        .concat(),
    );
    tlv(0x30, &[tbs, algorithm, tlv(3, &[0, 1])].concat())
}

struct MetadataSignature;

impl<W: Work> structured_pkix::path::Verify<W> for MetadataSignature {
    type Error = MemoryError;

    fn verify(
        &self,
        _algorithm: &structured_pkix::AlgorithmIdentifier<'_>,
        _key: structured_pkix::path::WorkingKey<'_>,
        signed: &[u8],
        signature: structured_pkix::signature::SignatureValue<'_>,
        work: &W,
    ) -> Result<structured_pkix::path::Verified, MemoryError> {
        // This oracle isolates parameter propagation, NEVER DSA arithmetic.
        work.charge_work((signed.len() + signature.as_bytes().len()) as u64)?;
        Ok(structured_pkix::path::Verified::Yes)
    }
}

#[test]
fn selected_key_binding_receives_inherited_original_parameters() {
    // A standing leaf has no parameters; the checked path's effective key
    // does. Reconstructing standing here would lose the selected-key contract.
    use structured_ltv::pki;
    use structured_pkix::path::{
        Anchor, Interval, ValidationBounds, ValidationContext, WorkingKey,
    };
    use structured_xades::{binding, certificate, container};
    let leaf_bytes = inheritance_certificate(false);
    let root_bytes = inheritance_certificate(true);
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let leaf = structured_pkix::Certificate::read(&parser, &leaf_bytes, 400).unwrap();
    let root = structured_pkix::Certificate::read(&parser, &root_bytes, 1200).unwrap();
    assert_eq!(
        WorkingKey::standing(leaf.tbs().public_key()).parameters(),
        None
    );
    let context = ValidationContext {
        execution: &memory,
        interval: Interval::at(1_767_225_600),
        policy: structured_pkix::path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &MetadataSignature,
        watch: &(),
        recognizer: &(),
    };
    let pki::PathOutcome::Accepted(path) =
        pki::check_path(&[&leaf], Anchor::from_certificate(&root), &context).unwrap()
    else {
        panic!("metadata-only path oracle")
    };
    let inherited = path.facts().key.parameters().unwrap();
    let original = root.tbs().public_key().algorithm().parameters().unwrap();
    assert_eq!(inherited, original);
    assert_eq!(inherited.as_ptr(), original.as_ptr());
    let mut xml = certificate_path_tree(
        Sha256::digest(&leaf_bytes).to_vec(),
        Sha256::digest(&root_bytes).to_vec(),
    );
    xml.key_association = certificate::KeyAssociation::Same;
    let signed = super::signed_roles(&xml, &memory).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let references = certificate::read(&access, &signed).unwrap();
    let layout = container::locate(&access, 0).unwrap();
    let bound = binding::bind(&access, &layout).unwrap();
    let provider = Oracle::new(Mode::Ready);
    let checked =
        certificate::check_path(&xml, &bound, &references, &path, &provider, &memory).unwrap();
    assert!(checked.is_bound());
    assert_eq!(
        xml.key_projection.get(),
        Some(super::KeyProjection::of(path.facts().key))
    );
    assert_ne!(
        xml.key_projection.get(),
        Some(super::KeyProjection::of(WorkingKey::standing(
            leaf.tbs().public_key()
        )))
    );
}

fn timestamped_certificate_tree(
    role: structured_xades::timestamp::Role,
    leaf: &[u8],
    root: &[u8],
    memory: &structured_asn1::memory::Memory,
    accuracy: bool,
) -> (
    Tree,
    usize,
    super::timestamp_oracle::Oracle,
    Vec<u8>,
    Option<Vec<u8>>,
) {
    // Trusted fixture generation uses synthetic XML framing, not an actual
    // C14N interoperability oracle. The resulting TSP signatures/hashes are real.
    use structured_xades::{binding, container, timestamp};
    struct Collected(Vec<u8>);
    impl Receiver for Collected {
        fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
            self.0.extend(bytes);
            Ok(())
        }
    }
    let mut xml =
        certificate_path_tree(Sha256::digest(leaf).to_vec(), Sha256::digest(root).to_vec());
    let node = if role == timestamp::Role::Signature {
        8
    } else {
        let node = xml.nodes.len();
        xml.nodes.push(super::element(
            Some(7),
            timestamp::XADES_141,
            "ArchiveTimeStamp",
        ));
        node
    };
    let method = xml.nodes.len();
    xml.nodes.push(super::element(
        Some(node),
        super::DS,
        "CanonicalizationMethod",
    ));
    xml.nodes.push(super::element(
        Some(node),
        super::XADES,
        "EncapsulatedTimeStamp",
    ));
    xml.digest_algorithms
        .push((method, "http://www.w3.org/2006/12/xml-c14n11"));
    let bytes = {
        let access = Access::new(&xml, xml.snapshot(), memory);
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let stamp = timestamp::read(&access, &bound, node).unwrap();
        let mut input = timestamp::Input::prepare(&xml, &bound, &stamp, memory).unwrap();
        let mut collected = Collected(Vec::new());
        Source::stream(&mut input, &mut collected, memory).unwrap();
        collected.0
    };
    let (provider, token, tsa, request) = if accuracy {
        let (provider, token, tsa, _) = super::timestamp_oracle::fixture_with_root(&bytes);
        (provider, token, tsa, None)
    } else {
        let (provider, token, tsa, request) =
            super::timestamp_oracle::fixture_unstated_accuracy(&bytes);
        (provider, token, tsa, Some(request))
    };
    xml.binary = token;
    (xml, node, provider, tsa, request)
}

#[test]
fn signature_time_binding_keeps_role_source_key_and_full_static_interval() {
    // Real timestamp math cannot replace a different selected source/role,
    // an unproven XML key, or a path checked only at another instant.
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    use structured_xades::{binding, certificate, container, timestamp};
    for (at, role, association) in [
        (
            1_767_225_600,
            timestamp::Role::Signature,
            certificate::KeyAssociation::Same,
        ),
        (
            1_767_225_601,
            timestamp::Role::Signature,
            certificate::KeyAssociation::Same,
        ),
        (
            1_767_225_600,
            timestamp::Role::Signature,
            certificate::KeyAssociation::Unproven,
        ),
        (
            1_767_225_600,
            timestamp::Role::Archive,
            certificate::KeyAssociation::Same,
        ),
    ] {
        with_checked_path_at(at, |path, leaf, root, memory| {
            let (mut xml, node, provider, tsa, _) =
                timestamped_certificate_tree(role, leaf, root, memory, true);
            xml.key_association = association;
            let signed = super::signed_roles(&xml, memory).unwrap();
            let access = Access::new(&xml, xml.snapshot(), memory);
            let references = certificate::read(&access, &signed).unwrap();
            let layout = container::locate(&access, 0).unwrap();
            let bound = binding::bind(&access, &layout).unwrap();
            let digest = Oracle::new(Mode::Ready);
            let selected =
                certificate::check_path(&xml, &bound, &references, path, &digest, memory).unwrap();
            let stamp = timestamp::read(&access, &bound, node).unwrap();
            let parser = structured_asn1::Parser::der(memory.clone());
            let parent = parser.read(&[], 900).unwrap();
            let tsa = structured_pkix::Certificate::read(&parser, &tsa, 400).unwrap();
            let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
            let context = structured_cms::timestamp::CheckContext {
                certificate: &tsa,
                certificate_parent: &parent,
                key: WorkingKey::standing(tsa.tbs().public_key()),
                requested: None,
                utc: &utc,
                reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
                window: None,
            };
            let check = timestamp::Check {
                xml: &xml,
                provider: &provider,
                context: &context,
            };
            let actor = check
                .retain_actor(&bound, &stamp, 0, &parent, |_, _| Ok::<_, ()>(false))
                .unwrap()
                .unwrap();
            assert_cached_signature_time(&selected, path, &actor, &utc, &access, &xml);
            assert_signature_time(
                &selected,
                actor.verified(),
                &utc,
                &access,
                at,
                association,
                &xml,
            );
            assert_eq!(provider.verified.get(), 1);
        });
    }
}

fn assert_cached_signature_time(
    selected: &structured_xades::certificate::CheckedPathCertificate<'_, '_, usize, u8, u8>,
    path: &structured_ltv::pki::CheckedPath<'_>,
    actor: &structured_xades::timestamp::TimestampActor<'_, '_, Tree>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    access: &Access<'_, Tree, structured_asn1::memory::Memory>,
    xml: &Tree,
) {
    // A previously established full TSA interval must give the same static
    // association as original UTC evaluation. It must not widen role/key
    // acceptance or turn an inadmissible current query into a cached success.
    use structured_ltv::pki;
    use structured_ltv::source::ScopeError;
    use structured_ltv::timestamp::{
        SignatureTimeBinding, SignatureTimeError, signature_time, signature_time_path,
    };
    let pki::TimestampBinding::Bound(timestamp) =
        path.bind_timestamp(actor, utc, access.execution()).unwrap()
    else {
        return; // A path outside the complete interval cannot create a receipt.
    };
    // Cached generation is not credit for current signature identity work.
    // Refusal precedes the first XML query and keeps the unspent short budget.
    let short = structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 1),
    ));
    let lower = Access::new(xml, access.snapshot(), &short);
    assert!(matches!(signature_time_path(selected, &timestamp, &lower),
        Err(SignatureTimeError::Scope(
            ScopeError::Resource {node, cause:structured_asn1::memory::MemoryError::WorkExceeded}
        )) if node == actor.verified().property()));
    assert_eq!(short.work_remaining(), 1);
    match (
        signature_time(selected, actor.verified(), utc, access),
        signature_time_path(selected, &timestamp, access),
    ) {
        (Ok(SignatureTimeBinding::Bound(original)), Ok(SignatureTimeBinding::Bound(cached))) => {
            assert_eq!(original.generation(), cached.generation());
            assert!(core::ptr::eq(cached.timestamp(), actor.verified()));
            assert!(core::ptr::eq(cached.signer(), selected));
        }
        (Ok(SignatureTimeBinding::Unproven(a)), Ok(SignatureTimeBinding::Unproven(b))) => {
            assert_eq!(a, b);
        }
        (
            Err(SignatureTimeError::Purpose { property: a }),
            Err(SignatureTimeError::Purpose { property: b }),
        ) => {
            assert_eq!(a, b);
        }
        _ => panic!("original and cached generation binding differ"),
    }
}

#[test]
fn nonce_freshness_cannot_supply_an_unstated_signature_time_accuracy() {
    // A real live nonce can establish freshness and mathematical token facts,
    // but it cannot invent the endpoint needed for certificate-time coverage.
    use structured_cms::timestamp::{BoundUncertainty, CheckContext, Request, Requested};
    use structured_pkix::{path::WorkingKey, temporal::LeapTable};
    use structured_xades::{binding, certificate, container, timestamp};
    with_checked_path(|path, leaf, root, memory| {
        let (mut xml, node, provider, tsa, request) =
            timestamped_certificate_tree(timestamp::Role::Signature, leaf, root, memory, false);
        xml.key_association = certificate::KeyAssociation::Same;
        let signed = super::signed_roles(&xml, memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), memory);
        let references = certificate::read(&access, &signed).unwrap();
        let layout = container::locate(&access, 0).unwrap();
        let bound = binding::bind(&access, &layout).unwrap();
        let digest = Oracle::new(Mode::Ready);
        let selected =
            certificate::check_path(&xml, &bound, &references, path, &digest, memory).unwrap();
        let stamp = timestamp::read(&access, &bound, node).unwrap();
        let parser = structured_asn1::Parser::der(memory.clone());
        let parent = parser.read(&[], 900).unwrap();
        let tsa = structured_pkix::Certificate::read(&parser, &tsa, 400).unwrap();
        let bytes = request.unwrap();
        let mut original = parser.read(&bytes, 3000).unwrap();
        let element = original.next_element().unwrap().unwrap();
        let request = Request::read(&original, &element).unwrap();
        assert!(original.is_empty());
        let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = CheckContext {
            certificate: &tsa,
            certificate_parent: &parent,
            key: WorkingKey::standing(tsa.tbs().public_key()),
            requested: Some(Requested {
                request: &request,
                parent: &original,
            }),
            utc: &utc,
            reference: None,
            window: None,
        };
        let check = timestamp::Check {
            xml: &xml,
            provider: &provider,
            context: &context,
        };
        let verified = check
            .retain(&bound, &stamp, 0, &parent, |_, _| Ok::<_, ()>(false))
            .unwrap()
            .expect("valid requested nonce and original mathematical coverage");
        assert!(
            matches!(structured_ltv::timestamp::signature_time(&selected,&verified,&utc,&access),Err(structured_ltv::timestamp::SignatureTimeError::Time {property,cause:structured_ltv::timestamp::TemporalError::Uncertain(BoundUncertainty::AccuracyUnstated)}) if property==node)
        );
        assert_eq!(provider.verified.get(), 1);
    });
}

fn assert_signature_time(
    selected: &structured_xades::certificate::CheckedPathCertificate<'_, '_, usize, u8, u8>,
    verified: &structured_ltv::timestamp::Verified<usize, u8, u8, structured_xades::Xades>,
    utc: &structured_pkix::temporal::LeapTable<'_>,
    access: &Access<'_, Tree, structured_asn1::memory::Memory>,
    at: i64,
    association: structured_xades::certificate::KeyAssociation,
    xml: &Tree,
) {
    use structured_ltv::source::ScopeError;
    use structured_ltv::timestamp::{
        Purpose, SignatureTimeBinding, SignatureTimeError, SignatureTimeFailure, signature_time,
    };
    use structured_xades::certificate;
    let result = signature_time(selected, verified, utc, access);
    if verified.purpose() != Purpose::Signature {
        assert!(matches!(result, Err(SignatureTimeError::Purpose { .. })));
    } else if association != certificate::KeyAssociation::Same {
        assert!(matches!(
            result.unwrap(),
            SignatureTimeBinding::Unproven(SignatureTimeFailure::Certificate)
        ));
    } else if at != 1_767_225_600 {
        assert!(matches!(
            result.unwrap(),
            SignatureTimeBinding::Unproven(SignatureTimeFailure::Interval)
        ));
    } else {
        let SignatureTimeBinding::Bound(link) = result.unwrap() else {
            panic!("same signature at its actual generation")
        };
        assert!(core::ptr::eq(link.signer(), selected));
        assert!(core::ptr::eq(link.timestamp(), verified));
        assert_eq!(link.generation().earliest.seconds(), 1_767_225_600);
        assert_eq!(link.generation().earliest, link.generation().latest);
    }
    let denied = structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 0),
    ));
    let denied_access = Access::new(xml, xml.snapshot(), &denied);
    assert!(matches!(
        signature_time(selected, verified, utc, &denied_access),
        Err(SignatureTimeError::Scope(ScopeError::Resource { .. }))
    ));
    let foreign = Access::new(
        xml,
        structured_xades::xml::Snapshot {
            document: xml.document + 1,
            generation: xml.generation.get(),
        },
        access.execution(),
    );
    assert!(matches!(
        signature_time(selected, verified, utc, &foreign),
        Err(SignatureTimeError::Foreign { .. })
    ));
    xml.generation.set(xml.generation.get() + 1);
    assert!(matches!(
        signature_time(selected, verified, utc, access),
        Err(SignatureTimeError::Scope(ScopeError::Changed { .. }))
    ));
}
impl Digest<'_> for Oracle {
    type Identity = ();
    type State = Sha256;
    type Output = Output;
    type Error = Failure;
    fn width(&self, (): &()) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1).map_err(Failure::Resource)?;
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), work: &W) -> Result<Resolution<Sha256>, Failure> {
        work.charge_work(64).map_err(Failure::Resource)?;
        self.started.set(self.started.get() + 1);
        Ok(if matches!(self.mode, Mode::Unsupported) {
            Resolution::Unsupported
        } else {
            Resolution::Supported(Sha256::new())
        })
    }
    fn update<W: Work>(&self, state: &mut Sha256, bytes: &[u8], work: &W) -> Result<(), Failure> {
        work.charge_work(bytes.len() as u64 + 64)
            .map_err(Failure::Resource)?;
        self.updated.set(self.updated.get() + 1);
        if matches!(self.mode, Mode::RefuseUpdate) {
            return Err(Failure::Refused);
        }
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, work: &W) -> Result<Output, Failure> {
        work.charge_work(128).map_err(Failure::Resource)?;
        self.finished.set(self.finished.get() + 1);
        let value: [u8; 32] = state.finalize().into();
        Ok(if matches!(self.mode, Mode::ShortOutput) {
            Output::Short(value[..31].try_into().unwrap())
        } else {
            Output::Full(value)
        })
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        work.charge_work(64).map_err(Failure::Resource)?;
        Ok(output.as_ref() == expected)
    }
}

#[derive(Debug)]
enum SourceFailure {
    Resource(MemoryError),
    Receiver(Refused),
    Incomplete,
}
impl core::fmt::Display for SourceFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Resource(cause) => cause.fmt(formatter),
            Self::Receiver(Refused) => formatter.write_str("receiver refused chunk"),
            Self::Incomplete => formatter.write_str("source did not reach EOF"),
        }
    }
}
struct Tracked {
    calls: usize,
    incomplete: bool,
    ignore_refusal: bool,
}
impl Tracked {
    fn new() -> Self {
        Self {
            calls: 0,
            incomplete: false,
            ignore_refusal: false,
        }
    }
}
impl Source for Tracked {
    type Error = SourceFailure;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), SourceFailure> {
        self.calls += 1;
        for bytes in [b"ab".as_slice(), b"c".as_slice()] {
            work.charge_work(1).map_err(SourceFailure::Resource)?;
            let result = receiver.write(bytes);
            if !self.ignore_refusal {
                result.map_err(SourceFailure::Receiver)?;
            }
        }
        if self.incomplete {
            return Err(SourceFailure::Incomplete);
        }
        Ok(())
    }
}
fn fixture() -> (Tree, digest::Reference<usize, u8, u8>) {
    let (mut xml, [_, _, _, method, value, _]) = certificate_tree();
    xml.digest_algorithm = Some(SHA256);
    xml.binary = Sha256::digest(b"abc").to_vec();
    let reference = digest::Reference {
        snapshot: xml.snapshot(),
        method,
        value,
    };
    (xml, reference)
}

#[test]
fn streaming_digest_checks_complete_original_chunks_without_one_shot_collection() {
    // Real SHA256 across two chunks detects incorrect chunk order/input. Only
    // complete EOF permits finish; the contract has no one-shot fallback.
    for agrees in [false, true] {
        let (mut xml, reference) = fixture();
        if !agrees {
            xml.binary[0] ^= 1;
        }
        let work = funded();
        let provider = Oracle::new(Mode::Ready);
        let mut source = Tracked::new();
        let result = digest::check(&xml, reference, &mut source, &provider, &work).unwrap();
        assert_eq!(
            result,
            if agrees {
                Agreement::Matches
            } else {
                Agreement::Differs
            }
        );
        assert_eq!(source.calls, 1);
        assert_eq!(provider.started.get(), 1);
        assert_eq!(provider.updated.get(), 2);
        assert_eq!(provider.finished.get(), 1);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn declared_digest_decoding_refusal_precedes_algorithm_resolver_side_effects() {
    // The XML lexical owner must finish its declared-value validation before
    // algorithm callbacks can observe the request. No state or content starts.
    let (mut xml, reference) = fixture();
    xml.decoding = super::Decoding::Refuse;
    let work = funded();
    let provider = Oracle::new(Mode::Ready);
    let mut source = Tracked::new();
    let result = digest::check(&xml, reference, &mut source, &provider, &work);
    assert!(matches!(
        result,
        Err(binary::Error::Access {
            cause: AccessError::Xml(super::Cause::Source),
            ..
        })
    ));
    assert_eq!(provider.resolved.get(), 0);
    assert_eq!(provider.started.get(), 0);
    assert_eq!(source.calls, 0);
    assert_eq!(work.used(), 0);
}

#[test]
fn certificate_declared_digest_uses_the_same_decode_before_resolve_boundary() {
    // The contiguous certificate route must enforce the same source/lexical
    // boundary as the streaming route, not resolve before its value can be read.
    let (mut xml, _) = fixture();
    xml.decoding = super::Decoding::Refuse;
    let work = funded();
    let bytes = super::candidate_certificate();
    let parser = structured_asn1::Parser::der(work.clone());
    let candidate = structured_pkix::Certificate::read(&parser, &bytes, 0).unwrap();
    let signed = super::signed_roles(&xml, &work).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &work);
    let references = structured_xades::certificate::read(&access, &signed).unwrap();
    let provider = Oracle::new(Mode::Ready);
    let result =
        structured_xades::certificate::compare(&xml, &references, 0, &candidate, &provider, &work);
    assert!(matches!(
        result,
        Err(binary::Error::Access {
            cause: AccessError::Xml(super::Cause::Source),
            ..
        })
    ));
    assert_eq!(provider.resolved.get(), 0);
    assert_eq!(provider.started.get(), 0);
}

#[test]
fn streaming_digest_preflights_format_and_capability_before_reading_source() {
    // Bad declared widths, format-prohibited algorithms, absent/unknown methods
    // and an unavailable streaming capability never trigger content acquisition.
    for case in 0..5 {
        let (mut xml, reference) = fixture();
        let mut mode = Mode::Ready;
        let expected = match case {
            0 => {
                xml.binary.pop();
                Agreement::MalformedValue
            }
            1 => {
                xml.digest_algorithm = Some("http://www.w3.org/2001/04/xmldsig-more#md5");
                Agreement::ProhibitedAlgorithm
            }
            2 => {
                xml.digest_algorithm = None;
                Agreement::MalformedMethod
            }
            3 => {
                xml.digest_algorithm = Some("urn:unknown");
                Agreement::Unsupported
            }
            _ => {
                mode = Mode::Unsupported;
                Agreement::Unsupported
            }
        };
        let work = funded();
        let provider = Oracle::new(mode);
        let mut source = Tracked::new();
        assert_eq!(
            digest::check(&xml, reference, &mut source, &provider, &work).unwrap(),
            expected
        );
        assert_eq!(source.calls, 0);
        assert_eq!(provider.started.get(), usize::from(case == 4));
        assert_eq!(provider.finished.get(), 0);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn streaming_digest_keeps_incomplete_and_sticky_provider_refusal_out_of_normal_mismatch() {
    // A source ignoring receiver refusal cannot cause another update or finish;
    // an incomplete source cannot hash a prefix and report ordinary agreement.
    for refuses in [false, true] {
        let (xml, reference) = fixture();
        let work = funded();
        let provider = Oracle::new(if refuses {
            Mode::RefuseUpdate
        } else {
            Mode::Ready
        });
        let mut source = Tracked::new();
        source.ignore_refusal = refuses;
        source.incomplete = !refuses;
        let error = digest::check(&xml, reference, &mut source, &provider, &work).unwrap_err();
        if refuses {
            assert!(matches!(
                error,
                binary::Error::Callback {
                    cause: digest::Error::Provider(Failure::Refused),
                    ..
                }
            ));
            assert_eq!(provider.updated.get(), 1);
        } else {
            assert!(matches!(
                error,
                binary::Error::Callback {
                    cause: digest::Error::Source(SourceFailure::Incomplete),
                    ..
                }
            ));
            assert_eq!(provider.updated.get(), 2);
        }
        assert_eq!(provider.finished.get(), 0);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn streaming_digest_wrong_backend_width_is_processing_failure_with_original_xml_enclosure() {
    // A broken provider output is neither a malformed declared digest nor a
    // cryptographic mismatch, and cannot lose the original node/generation.
    let (xml, reference) = fixture();
    let work = funded();
    let provider = Oracle::new(Mode::ShortOutput);
    let mut source = Tracked::new();
    let error = digest::check(&xml, reference, &mut source, &provider, &work).unwrap_err();
    assert!(
        matches!(error,binary::Error::Callback {location,cause:digest::Error::OutputWidth {expected:32,actual:31}} if location.node==reference.value && location.snapshot==reference.snapshot)
    );
    assert_eq!(source.calls, 1);
    assert_eq!(provider.finished.get(), 1);
    assert_eq!(work.used(), 0);
}
