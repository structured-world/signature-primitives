//! Credential source/retention oracle, NOT attribute-certificate/SAML mathematics.

use super::{Tree, role_tree, signed_roles, xml_digest};
use core::cell::Cell;
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_ltv::pki::{Authorities, CheckedPath};
use structured_xades::{
    credential, role,
    xml::{Access, AccessError, Xml},
};

#[derive(Clone, Copy)]
enum Mode {
    Ready,
    Unsupported,
    Rejected,
    NoAuthorities,
    CapacityRefusal,
    DirectAnchor,
    CertificateFree,
}

struct Provider<'path, 'document> {
    paths: &'path [&'path CheckedPath<'document>],
    anchor: &'path structured_pkix::path::EffectiveAnchor<'document>,
    calls: Cell<usize>,
    mode: Mode,
    signatures: Signatures,
}

#[derive(Clone, Copy)]
enum Signatures {
    One(usize),
    RootAndCounter(usize, usize),
}

#[derive(Clone, Copy)]
enum MaterialMode {
    Ready,
    Missing,
    Unsupported,
    Refusal,
    Open,
    OpenMissing,
    SwallowedForeign,
}

struct Materials<'a, 'document> {
    certificate: &'a structured_pkix::Certificate<'document>,
    calls: Cell<usize>,
    mode: MaterialMode,
}

impl structured_xades::material::credentials::Provider<Tree, OwnedVec<u8>> for Materials<'_, '_> {
    type Error = MemoryError;

    fn visit<VE, W: Work>(
        &self,
        credential: &credential::Checked<'_, '_, OwnedVec<u8>, usize, u8, u8>,
        open: &[structured_xades::material::Opaque<usize, u8, u8>],
        access: &Access<'_, Tree, W>,
        mut visitor: impl for<'value, 'document> FnMut(
            structured_xades::material::credentials::Need<'value, 'document, usize, u8, u8>,
        ) -> Result<(), VE>,
    ) -> Result<
        structured_xades::material::credentials::Completeness,
        structured_xades::reference::VisitError<MemoryError, VE>,
    > {
        // Format metadata oracle only: the authentication receipt is reused,
        // not a second SAML/AC parser or signature/authentication implementation.
        use structured_xades::{
            material::credentials::{Completeness, Need},
            reference::VisitError,
        };
        access
            .execution()
            .charge_work(1)
            .map_err(VisitError::Processing)?;
        assert_eq!(credential.source().snapshot(), access.snapshot());
        self.calls.set(self.calls.get() + 1);
        if self.calls.get() == 2 {
            match self.mode {
                MaterialMode::Missing => {
                    visitor(Need::Missing).map_err(VisitError::Visitor)?;
                    return Ok(Completeness::Complete);
                }
                MaterialMode::Unsupported => return Ok(Completeness::Unsupported),
                MaterialMode::Refusal => {
                    return Err(VisitError::Processing(MemoryError::WorkExceeded));
                }
                MaterialMode::Open | MaterialMode::OpenMissing | MaterialMode::SwallowedForeign => {
                    let mut location = open[0].location;
                    if matches!(self.mode, MaterialMode::OpenMissing) {
                        location.node = usize::MAX;
                    }
                    if matches!(self.mode, MaterialMode::SwallowedForeign) {
                        location.snapshot.document += 1;
                        assert!(visitor(Need::Open(location)).is_err());
                        // First visitor refusal must survive a handler that
                        // swallows it and returns a different provider cause.
                        return Err(VisitError::Processing(MemoryError::WorkExceeded));
                    }
                    visitor(Need::Open(location)).map_err(VisitError::Visitor)?;
                    return Ok(Completeness::Complete);
                }
                MaterialMode::Ready => (),
            }
            assert!(matches!(
                credential.authorities(),
                Authorities::CertificateFree
            ));
        }
        visitor(Need::Known(
            structured_ltv::material::ArtifactRef::Certificate(self.certificate),
        ))
        .map_err(VisitError::Visitor)?;
        Ok(Completeness::Complete)
    }
}

#[test]
fn format_material_checks_every_original_credential_even_without_x509_authorities() {
    // All scope uses the complete root/counter census. CertificateFree must
    // still reach the format handler; late absence/unsupported is not success
    // and late provider failure releases all earlier admitted findings.
    use structured_xades::{material, pki, prepare, timestamp, unsigned};
    xml_digest::with_checked_path(|path, leaf, _, memory| {
        let paths = [path];
        let anchor = path.anchor();
        let key = structured_pkix::path::WorkingKey::standing(anchor.key());
        let anchor = structured_pkix::path::EffectiveAnchor::bind(anchor, key, memory)
            .unwrap()
            .unwrap();
        for mode in [
            MaterialMode::Ready,
            MaterialMode::Missing,
            MaterialMode::Unsupported,
            MaterialMode::Refusal,
            MaterialMode::Open,
            MaterialMode::OpenMissing,
            MaterialMode::SwallowedForeign,
        ] {
            let (xml, root_credential, child, child_credential) = material_tree(leaf, memory);
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters =
                pki::bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path)).unwrap();
            let authentication = Provider {
                paths: &paths,
                anchor: &anchor,
                calls: Cell::new(0),
                mode: Mode::CertificateFree,
                signatures: Signatures::RootAndCounter(0, child),
            };
            let credentials =
                credential::check_participants(&prepared, &counters, &authentication, &access)
                    .unwrap();
            let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
            let required = timestamp::requirements_with_counters(
                &access,
                &prepared,
                &stamps,
                timestamp::TimestampSelection::All,
            )
            .unwrap();
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            let materials = Materials {
                certificate: path.members().last().unwrap().certificate(),
                calls: Cell::new(0),
                mode,
            };
            let held = memory.used();
            let report = material::with_counter_values(
                &xml,
                &prepared,
                &counters,
                &operation,
                |query, view| {
                    let work = query.execution();
                    let current = Access::new(&xml, xml.snapshot(), &work);
                    let index = material::index(&view, &current).unwrap();
                    if matches!(mode, MaterialMode::Ready) {
                        assert_material_admission(
                            &xml,
                            &credentials,
                            &counters,
                            &required,
                            &index,
                            &materials,
                        );
                    }
                    Ok::<_, ()>(material::credentials::check(
                        &credentials,
                        &counters,
                        &required,
                        &index,
                        &material::credentials::Scope::whole(),
                        &materials,
                        &current,
                    ))
                },
            )
            .unwrap();
            assert_eq!(materials.calls.get(), 2);
            assert_eq!(authentication.calls.get(), 2);
            assert_material_report(
                report,
                mode,
                &credentials,
                (root_credential, child_credential),
                required.scope(),
            );
            assert_eq!(memory.used(), held);
        }
    });
}

fn material_tree(
    leaf: &[u8],
    memory: &structured_asn1::memory::Memory,
) -> (Tree, usize, usize, usize) {
    // Original root/counter credentials and one opaque original material member;
    // this is trusted fixture framing, not a second XML or credential parser.
    let mut xml = super::preparation_tree();
    xml.binary = leaf.to_vec();
    let (_, root_credential) = xml_digest::append_assertion(&mut xml, 4);
    let (child, _, child_credential, _) =
        xml_digest::append_counter_credentials(&mut xml, memory, super::Coverage::ElementContent);
    xml.key_association = structured_xades::certificate::KeyAssociation::Same;
    let values = xml.nodes.len();
    xml.nodes
        .push(super::element(Some(7), super::XADES, "CertificateValues"));
    xml.nodes.push(super::element(
        Some(values),
        super::XADES,
        "OtherCertificate",
    ));
    (xml, root_credential, child, child_credential)
}

type MaterialReport<'a, 'p, 'd> =
    structured_xades::material::credentials::Report<'a, 'p, 'd, OwnedVec<u8>, usize, u8, u8>;
type MaterialResult<'a, 'p, 'd> = Result<
    MaterialReport<'a, 'p, 'd>,
    structured_xades::material::credentials::Error<super::Cause, MemoryError, usize>,
>;

fn assert_material_admission<W: Work>(
    xml: &Tree,
    credentials: &credential::ParticipantCredentials<'_, '_, OwnedVec<u8>, usize, u8, u8>,
    counters: &structured_xades::pki::CounterPaths<'_, '_, usize, u8, u8>,
    required: &structured_ltv::timestamp::TimestampRequirements<usize, u8, u8>,
    index: &structured_xades::material::Index<'_, usize, u8, u8, W>,
    provider: &Materials<'_, '_>,
) {
    // Retained authentication/catalogue storage never prepays a fresh query.
    // Neither denial may dispatch the format callback or retain partial output.
    use structured_asn1::memory::{Memory, MemoryAccount};
    use structured_xades::material;
    let calls = provider.calls.get();
    let held = credentials.root().unwrap().entries()[0]
        .evidence()
        .memory()
        .used();
    for (capacity, work) in [(0, 1_000_000), (65_536, 0)] {
        let current = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, work)));
        let query = Access::new(xml, xml.snapshot(), &current);
        let result = material::credentials::check(
            credentials,
            counters,
            required,
            index,
            &material::credentials::Scope::whole(),
            provider,
            &query,
        );
        if work == 0 {
            assert!(matches!(
                result,
                Err(material::credentials::Error::Index(
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
                result,
                Err(material::credentials::Error::Resource {
                    cause: MemoryError::LimitExceeded,
                    ..
                })
            ));
        }
        assert_eq!(current.used(), 0);
        assert_eq!(provider.calls.get(), calls);
        assert_eq!(
            credentials.root().unwrap().entries()[0]
                .evidence()
                .memory()
                .used(),
            held
        );
    }
}

fn assert_material_report(
    report: MaterialResult<'_, '_, '_>,
    mode: MaterialMode,
    credentials: &credential::ParticipantCredentials<'_, '_, OwnedVec<u8>, usize, u8, u8>,
    nodes: (usize, usize),
    scope: structured_ltv::timestamp::TimestampScope<usize, u8, u8>,
) {
    use structured_xades::material;
    if matches!(mode, MaterialMode::Refusal) {
        assert!(
            matches!(report,Err(material::credentials::Error::Provider{node,cause:MemoryError::WorkExceeded}) if node==nodes.1)
        );
    } else if matches!(mode, MaterialMode::SwallowedForeign) {
        assert!(matches!(
            report,
            Err(material::credentials::Error::Foreign { .. })
        ));
    } else {
        let report = report.unwrap();
        assert!(core::ptr::eq(report.credentials(), credentials));
        assert_eq!(report.snapshot(), credentials.snapshot());
        assert_eq!(report.scope(), scope);
        assert_eq!(report.entries().len(), 2);
        assert_eq!(report.entries()[0].source().entry().node, nodes.0);
        assert_eq!(report.entries()[1].source().entry().node, nodes.1);
        assert_eq!(
            report.all_requirements_met(),
            matches!(mode, MaterialMode::Ready | MaterialMode::Open)
        );
        let last = &report.entries()[1];
        if matches!(mode, MaterialMode::Missing | MaterialMode::OpenMissing) {
            assert_eq!(
                last.findings(),
                &[material::credentials::Finding {
                    dependency: 0,
                    cause: material::credentials::Missing::Absent
                }]
            );
            assert_eq!(
                last.completeness(),
                material::credentials::Completeness::Complete
            );
        } else {
            assert_eq!(last.findings(), []);
        }
        if matches!(mode, MaterialMode::Unsupported) {
            assert_eq!(
                last.completeness(),
                material::credentials::Completeness::Unsupported
            );
        }
    }
}

impl<'path, 'document> credential::Provider<'path, 'document, Tree> for Provider<'path, 'document> {
    type Evidence = OwnedVec<u8>;
    type Error = MemoryError;

    fn authenticate<W: Work>(
        &self,
        access: &Access<'_, Tree, W>,
        source: credential::Credential<usize, u8, u8>,
    ) -> Result<credential::Authentication<'path, 'document, Self::Evidence>, MemoryError> {
        // Explicit metadata oracle: source and admitted retained evidence only.
        // A production provider must actually verify the selected format.
        let work = access.execution();
        work.charge_work(1)?;
        self.calls.set(self.calls.get() + 1);
        assert_eq!(source.snapshot(), access.snapshot());
        match self.signatures {
            Signatures::One(expected) => assert_eq!(source.signature(), expected),
            Signatures::RootAndCounter(root, child) => {
                assert!(source.signature() == root || source.signature() == child);
            }
        }
        assert_ne!(source.entry().kind, role::Kind::Claimed);
        let mut evidence = work.vector();
        if self.calls.get() == 2 {
            match self.mode {
                Mode::Unsupported => return Ok(credential::Authentication::Unsupported),
                Mode::Rejected => return Ok(credential::Authentication::Rejected),
                Mode::NoAuthorities => {
                    return Ok(credential::Authentication::Authenticated {
                        evidence: evidence.into_owned(),
                        authorities: Authorities::Paths(&[]),
                    });
                }
                Mode::CapacityRefusal => evidence.try_reserve_exact(1_000_000)?,
                Mode::DirectAnchor => {
                    return Ok(credential::Authentication::Authenticated {
                        evidence: evidence.into_owned(),
                        authorities: Authorities::DirectAnchor(self.anchor),
                    });
                }
                Mode::CertificateFree => {
                    return Ok(credential::Authentication::Authenticated {
                        evidence: evidence.into_owned(),
                        authorities: Authorities::CertificateFree,
                    });
                }
                Mode::Ready => (),
            }
        }
        evidence.try_extend_from_slice(b"retained original credential receipt")?;
        Ok(credential::Authentication::Authenticated {
            evidence: evidence.into_owned(),
            authorities: Authorities::Paths(self.paths),
        })
    }
}

#[test]
fn every_original_credential_is_checked_and_late_refusal_drops_retained_prefix() {
    // A successful earlier certificate cannot hide a later unsupported/rejected
    // assertion. Claimed roles never invoke this independent issuer provider.
    xml_digest::with_checked_path(|path, _, _, memory| {
        let paths = [path];
        let anchor = path.anchor();
        let key = structured_pkix::path::WorkingKey::standing(anchor.key());
        let anchor = structured_pkix::path::EffectiveAnchor::bind(anchor, key, memory)
            .unwrap()
            .unwrap();
        for mode in [
            Mode::Ready,
            Mode::Unsupported,
            Mode::Rejected,
            Mode::NoAuthorities,
            Mode::CapacityRefusal,
            Mode::DirectAnchor,
            Mode::CertificateFree,
        ] {
            let (xml, _, _, _) = role_tree();
            let signed = signed_roles(&xml, memory).unwrap();
            let access = Access::new(&xml, xml.snapshot(), memory);
            let roles = role::read(&access, &signed).unwrap().unwrap();
            let before = memory.used();
            let provider = Provider {
                paths: &paths,
                anchor: &anchor,
                calls: Cell::new(0),
                mode,
                signatures: Signatures::One(0),
            };
            let result = credential::check(&roles, &provider, &access);
            assert_eq!(provider.calls.get(), 2);
            match mode {
                Mode::Ready => {
                    let checked = result.unwrap();
                    assert_eq!(checked.snapshot(), xml.snapshot());
                    assert_eq!(checked.signature(), 0);
                    assert_eq!(checked.entries().len(), 2);
                    for (entry, source) in checked.entries().iter().zip(&roles.entries()[1..]) {
                        assert_eq!(entry.source().entry().node, source.node);
                        assert_eq!(entry.source().entry().kind, source.kind);
                        assert_eq!(
                            &entry.evidence()[..],
                            b"retained original credential receipt"
                        );
                        let Authorities::Paths(paths) = entry.authorities() else {
                            panic!("actual checked paths")
                        };
                        assert!(core::ptr::eq(paths[0], path));
                    }
                    assert!(memory.used() > before);
                    drop(checked);
                }
                Mode::Unsupported => assert!(
                    matches!(result, Err(credential::Error::Unsupported { node }) if node == roles.entries()[2].node)
                ),
                Mode::Rejected => assert!(
                    matches!(result, Err(credential::Error::Rejected { node }) if node == roles.entries()[2].node)
                ),
                Mode::NoAuthorities => assert!(
                    matches!(result, Err(credential::Error::MissingAuthorities { node }) if node == roles.entries()[2].node)
                ),
                Mode::CapacityRefusal => assert!(
                    matches!(result, Err(credential::Error::Provider { node, cause: MemoryError::LimitExceeded }) if node == roles.entries()[2].node)
                ),
                Mode::DirectAnchor => {
                    let result = result.unwrap();
                    let Authorities::DirectAnchor(anchor) = result.entries()[1].authorities()
                    else {
                        panic!("actual original direct anchor")
                    };
                    assert!(core::ptr::eq(
                        anchor.anchor().certificate().unwrap(),
                        path.anchor().certificate().unwrap()
                    ));
                    drop(result);
                }
                Mode::CertificateFree => {
                    let result = result.unwrap();
                    assert!(matches!(
                        result.entries()[1].authorities(),
                        Authorities::CertificateFree
                    ));
                    drop(result);
                }
            }
            assert_eq!(memory.used(), before);
        }
    });
}

#[test]
fn foreign_or_unfunded_credential_source_refuses_before_provider_dispatch() {
    // Old role metadata is not permission to bypass a current source or budget.
    xml_digest::with_checked_path(|path, _, _, memory| {
        let paths = [path];
        let anchor = path.anchor();
        let key = structured_pkix::path::WorkingKey::standing(anchor.key());
        let anchor = structured_pkix::path::EffectiveAnchor::bind(anchor, key, memory)
            .unwrap()
            .unwrap();
        let provider = Provider {
            paths: &paths,
            anchor: &anchor,
            calls: Cell::new(0),
            mode: Mode::Ready,
            signatures: Signatures::One(0),
        };
        let (xml, _, _, _) = role_tree();
        let signed = signed_roles(&xml, memory).unwrap();
        let access = Access::new(&xml, xml.snapshot(), memory);
        let roles = role::read(&access, &signed).unwrap().unwrap();
        let mut foreign = xml.snapshot();
        foreign.document += 1;
        let foreign = Access::new(&xml, foreign, memory);
        assert!(matches!(
            credential::check(&roles, &provider, &foreign),
            Err(credential::Error::Access(AccessError::Changed { .. }))
        ));
        let denied = super::memory(0);
        let denied = Access::new(&xml, xml.snapshot(), &denied);
        assert!(matches!(
            credential::check(&roles, &provider, &denied),
            Err(credential::Error::Access(AccessError::Resource { .. }))
        ));
        assert_eq!(provider.calls.get(), 0);
    });
}

#[test]
fn credential_facts_retain_their_own_capacity_after_xml_roles_and_provider_drop() {
    // Retained source identities/evidence must not pin a temporary XML view,
    // its role catalogue or provider, and must keep storage charged until drop.
    xml_digest::with_checked_path(|path, _, _, path_memory| {
        let paths = [path];
        let anchor = path.anchor();
        let key = structured_pkix::path::WorkingKey::standing(anchor.key());
        let anchor = structured_pkix::path::EffectiveAnchor::bind(anchor, key, path_memory)
            .unwrap()
            .unwrap();
        let (checked, account, expected) = {
            let account =
                super::Arc::new(structured_asn1::memory::MemoryAccount::new(65_536, 300_000));
            let memory = structured_asn1::memory::Memory::new(account.clone());
            let (xml, _, _, _) = role_tree();
            let signed = signed_roles(&xml, &memory).unwrap();
            let access = Access::new(&xml, xml.snapshot(), &memory);
            let roles = role::read(&access, &signed).unwrap().unwrap();
            let expected = [roles.entries()[1].node, roles.entries()[2].node];
            let provider = Provider {
                paths: &paths,
                anchor: &anchor,
                calls: Cell::new(0),
                mode: Mode::Ready,
                signatures: Signatures::One(0),
            };
            (
                credential::check(&roles, &provider, &access).unwrap(),
                account,
                expected,
            )
        };
        let observer = structured_asn1::memory::Memory::new(account);
        assert!(observer.used() > 0);
        assert_eq!(checked.entries()[0].source().entry().node, expected[0]);
        assert_eq!(checked.entries()[1].source().entry().node, expected[1]);
        assert_eq!(
            &checked.entries()[1].evidence()[..],
            b"retained original credential receipt"
        );
        drop(checked);
        assert_eq!(observer.used(), 0);
    });
}

#[test]
fn root_and_counter_credentials_form_one_source_derived_set_without_partial_groups() {
    // A successfully authenticated root credential cannot hide a later counter
    // credential. The complete original counter set determines the second group.
    use structured_xades::{binding, certificate, container, pki, prepare, unsigned};
    xml_digest::with_checked_path(|path, _, _, memory| {
        let paths = [path];
        let anchor = path.anchor();
        let key = structured_pkix::path::WorkingKey::standing(anchor.key());
        let anchor = structured_pkix::path::EffectiveAnchor::bind(anchor, key, memory)
            .unwrap()
            .unwrap();
        for mode in [Mode::Ready, Mode::Unsupported] {
            let mut xml = super::preparation_tree();
            let (_, root_assertion) = xml_digest::append_assertion(&mut xml, 4);
            let (child, _, child_assertion, _) = xml_digest::append_counter_credentials(
                &mut xml,
                memory,
                super::Coverage::ElementContent,
            );
            xml.key_association = certificate::KeyAssociation::Same;
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters =
                pki::bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path)).unwrap();
            let provider = Provider {
                paths: &paths,
                anchor: &anchor,
                calls: Cell::new(0),
                mode,
                signatures: Signatures::RootAndCounter(0, child),
            };
            let before = memory.used();
            let result = credential::check_participants(&prepared, &counters, &provider, &access);
            assert_eq!(provider.calls.get(), 2);
            if matches!(mode, Mode::Unsupported) {
                assert!(
                    matches!(result, Err(credential::Error::Unsupported { node }) if node == child_assertion)
                );
            } else {
                let result = result.unwrap();
                assert_eq!(result.snapshot(), xml.snapshot());
                assert_eq!(result.signature(), 0);
                assert_eq!(
                    result.root().unwrap().entries()[0].source().entry().node,
                    root_assertion
                );
                assert_eq!(result.counters().len(), 1);
                let counter = &result.counters()[0];
                assert_eq!(counter.source().original().child(), child);
                assert_eq!(counter.credentials().signature(), child);
                assert_eq!(
                    counter.credentials().entries()[0].source().entry().node,
                    child_assertion
                );
                drop(result);
            }
            assert_eq!(memory.used(), before);
            let layout = container::locate(&access, child).unwrap();
            let child_bound = binding::bind(&access, &layout).unwrap();
            let foreign =
                pki::bind_counters(&child_bound, &access, |_, _| Ok::<_, ()>(path)).unwrap();
            assert!(matches!(
                credential::check_participants(&prepared, &foreign, &provider, &access),
                Err(credential::Error::Foreign { signature: 0 })
            ));
            assert_eq!(provider.calls.get(), 2);
        }
    });
}
