//! Real SHA256 over original whole referenced artifacts, not authority facts.

#[path = "reference_crl_value.rs"]
mod crl_value;
#[path = "reference_ocsp_value.rs"]
mod ocsp_value;
#[path = "reference_status_roles.rs"]
mod status_roles;

use super::super::{DS, XADES, XADES_141, element, material, prepare, unsigned};
use super::*;
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
use structured_xades::validation::{ReferenceDigest, compare_reference_digest};

fn add(xml: &mut Tree, parent: usize, namespace: &'static str, local: &'static str) -> usize {
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(parent), namespace, local));
    node
}

fn fixture(kind: material::Kind, bytes: Vec<u8>, with_digest: bool) -> (Tree, usize) {
    let mut xml = super::super::attribute_checks::fixture();
    let entry = match kind {
        material::Kind::Certificate => {
            let refs = add(&mut xml, 7, XADES_141, "CompleteCertificateRefsV2");
            let list = add(&mut xml, refs, XADES_141, "CertRefs");
            add(&mut xml, list, XADES, "Cert")
        }
        material::Kind::Crl | material::Kind::Ocsp => {
            let refs = add(&mut xml, 7, XADES, "CompleteRevocationRefs");
            let list = add(
                &mut xml,
                refs,
                XADES,
                if kind == material::Kind::Crl {
                    "CRLRefs"
                } else {
                    "OCSPRefs"
                },
            );
            let entry = add(
                &mut xml,
                list,
                XADES,
                if kind == material::Kind::Crl {
                    "CRLRef"
                } else {
                    "OCSPRef"
                },
            );
            if kind == material::Kind::Ocsp {
                let id = add(&mut xml, entry, XADES, "OCSPIdentifier");
                let responder = add(&mut xml, id, XADES, "ResponderID");
                add(&mut xml, responder, XADES, "ByKey");
                add(&mut xml, id, XADES, "ProducedAt");
            }
            entry
        }
    };
    if with_digest {
        let digest = add(
            &mut xml,
            entry,
            XADES,
            if kind == material::Kind::Certificate {
                "CertDigest"
            } else {
                "DigestAlgAndValue"
            },
        );
        let method = add(&mut xml, digest, DS, "DigestMethod");
        xml.digest_algorithms.push((method, SHA256));
        let value = add(&mut xml, digest, DS, "DigestValue");
        xml.binary_routes
            .push((value, Sha256::digest(&bytes).to_vec()));
    }
    let container = add(
        &mut xml,
        7,
        XADES,
        if kind == material::Kind::Certificate {
            "CertificateValues"
        } else {
            "RevocationValues"
        },
    );
    let parent = if kind == material::Kind::Certificate {
        container
    } else {
        add(
            &mut xml,
            container,
            XADES,
            if kind == material::Kind::Crl {
                "CRLValues"
            } else {
                "OCSPValues"
            },
        )
    };
    let source = add(
        &mut xml,
        parent,
        XADES,
        match kind {
            material::Kind::Certificate => "EncapsulatedX509Certificate",
            material::Kind::Crl => "EncapsulatedCRLValue",
            material::Kind::Ocsp => "EncapsulatedOCSPValue",
        },
    );
    xml.binary_routes.push((source, bytes));
    (xml, source)
}

fn add_certificate_reference(xml: &mut Tree, list: usize, bytes: &[u8]) -> usize {
    let entry = add(xml, list, XADES, "Cert");
    let digest = add(xml, entry, XADES, "CertDigest");
    let method = add(xml, digest, DS, "DigestMethod");
    xml.digest_algorithms.push((method, SHA256));
    let value = add(xml, digest, DS, "DigestValue");
    xml.binary_routes
        .push((value, Sha256::digest(bytes).to_vec()));
    value
}

fn header_certificate(xml: &mut Tree, bytes: &[u8]) {
    // The full material pipeline includes the original KeyInfo as well as
    // CertificateValues; direct retained-source tests did not parse that pool.
    let info = xml.element_child(0, DS, "KeyInfo");
    let data = xml.element_child(info, DS, "X509Data");
    let node = xml.element_child(data, DS, "X509Certificate");
    xml.binary_routes.push((node, bytes.to_vec()));
}

const DOMAIN_SHA256: &str = "urn:fixture:sha256-with-domain";
const DOMAIN: &[u8] = b"test domain";

struct CatalogueOracle {
    inner: Oracle,
    fail_method: Option<usize>,
    held_on_failure: Cell<usize>,
}

impl DigestProvider<'_, Tree> for CatalogueOracle {
    fn classify(&self, _: &bool) -> structured_xades::hashes::HashClass {
        structured_xades::hashes::HashClass::OtherKnown
    }
    fn resolve<W: Work>(
        &self,
        access: &Access<'_, Tree, W>,
        method: usize,
    ) -> Result<Resolution<bool>, Failure> {
        self.inner.resolved.set(self.inner.resolved.get() + 1);
        if self.fail_method == Some(method) {
            self.held_on_failure.set(access.execution().memory().used());
            return Err(Failure::Refused);
        }
        access
            .attribute(
                method,
                Name {
                    namespace: "",
                    local: "Algorithm",
                },
                |uri| {
                    let Some(uri) = uri else {
                        return Ok(Resolution::Malformed);
                    };
                    access.execution().charge_work(uri.len() as u64)?;
                    Ok(if uri == SHA256 {
                        Resolution::Supported(false)
                    } else if uri == DOMAIN_SHA256 {
                        Resolution::Supported(true)
                    } else {
                        Resolution::Unsupported
                    })
                },
            )
            .map_err(Failure::Access)?
            .map_err(Failure::Resource)
    }
}

impl Digest<'_> for CatalogueOracle {
    type Identity = bool;
    type State = Sha256;
    type Output = Output;
    type Error = Failure;
    fn width(&self, _: &bool) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, left: &bool, right: &bool, work: &W) -> Result<Ordering, Failure> {
        work.charge_work(1).map_err(Failure::Resource)?;
        Ok(left.cmp(right))
    }
    fn start<W: Work>(&self, domain: &bool, work: &W) -> Result<Resolution<Sha256>, Failure> {
        let mut state = self.inner.start(&(), work)?;
        if let Resolution::Supported(state) = &mut state
            && *domain
        {
            self.inner.update(state, DOMAIN, work)?;
        }
        Ok(state)
    }
    fn update<W: Work>(&self, state: &mut Sha256, bytes: &[u8], work: &W) -> Result<(), Failure> {
        self.inner.update(state, bytes, work)
    }
    fn finish<W: Work>(&self, state: Sha256, work: &W) -> Result<Output, Failure> {
        self.inner.finish(state, work)
    }
    fn matches<W: Work>(
        &self,
        _: &bool,
        output: &Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Failure> {
        self.inner.matches(&(), output, expected, work)
    }
}

#[test]
fn reference_catalogue_does_not_deduplicate_same_width_different_identities() {
    // Two selected identities have the same width but different input domains.
    // Width-based caching would use the first output and reject the second row.
    use structured_xades::validation::compare_reference_catalogues;
    with_checked_path(|_, leaf, _, memory| {
        let (mut xml, _) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
        header_certificate(&mut xml, leaf);
        let refs = xml.element_child(7, XADES_141, "CompleteCertificateRefsV2");
        let list = xml.element_child(refs, XADES_141, "CertRefs");
        let value = add_certificate_reference(&mut xml, list, leaf);
        xml.digest_algorithms.last_mut().unwrap().1 = DOMAIN_SHA256;
        let mut state = Sha256::new();
        state.update(DOMAIN);
        state.update(leaf);
        xml.binary_routes
            .iter_mut()
            .find(|item| item.0 == value)
            .unwrap()
            .1 = state.finalize().to_vec();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let provider = CatalogueOracle {
            inner: Oracle::new(Mode::Ready),
            fail_method: None,
            held_on_failure: Cell::new(0),
        };
        material::with_values(&xml, &prepared, &operation, |_, view| {
            let work = funded();
            let report =
                compare_reference_catalogues(&xml, &prepared, &view, &provider, &work).unwrap();
            assert_eq!(report.rows().len(), 2);
            for row in 0..2 {
                let pairs = report.comparisons(row).unwrap();
                assert_eq!(pairs.len(), 2);
                for pair in pairs {
                    assert_eq!(pair.agreement(), Agreement::Matches);
                }
            }
            assert_eq!(
                (provider.inner.started.get(), provider.inner.finished.get()),
                (2, 2)
            );
            drop(report);
            assert_eq!(work.used(), 0);
            Ok::<_, ()>(())
        })
        .unwrap();
    });
}

#[test]
fn reference_catalogue_late_provider_refusal_drops_complete_prior_row() {
    // The second method fails only after the first reference's full candidate
    // set and finished memo exist. Neither a prefix report nor cache escapes.
    use structured_xades::validation::compare_reference_catalogues;
    with_checked_path(|_, leaf, _, memory| {
        let (mut xml, _) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
        header_certificate(&mut xml, leaf);
        let refs = xml.element_child(7, XADES_141, "CompleteCertificateRefsV2");
        let list = xml.element_child(refs, XADES_141, "CertRefs");
        add_certificate_reference(&mut xml, list, leaf);
        let method = xml.digest_algorithms.last().unwrap().0;
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let provider = CatalogueOracle {
            inner: Oracle::new(Mode::Ready),
            fail_method: Some(method),
            held_on_failure: Cell::new(0),
        };
        material::with_values(&xml, &prepared, &operation, |_, view| {
            let work = funded();
            assert!(matches!(
                compare_reference_catalogues(&xml, &prepared, &view, &provider, &work),
                Err(binary::Error::Callback {
                    cause: structured_xades::validation::ReferenceDigestError::Digest(
                        digest::Error::Provider(Failure::Refused)
                    ),
                    ..
                })
            ));
            assert_eq!(
                (provider.inner.started.get(), provider.inner.finished.get()),
                (1, 1)
            );
            assert!(provider.held_on_failure.get() > 0);
            assert_eq!(work.used(), 0);
            Ok::<_, ()>(())
        })
        .unwrap();
    });
}

fn complete_catalogue_fixture(leaf: &[u8], root: &[u8]) -> Tree {
    let (mut xml, source) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
    header_certificate(&mut xml, leaf);
    let parent = xml.nodes[source].parent.unwrap();
    for bytes in [root, leaf] {
        let node = add(&mut xml, parent, XADES, "EncapsulatedX509Certificate");
        xml.binary_routes.push((node, bytes.to_vec()));
    }
    let refs = xml.element_child(7, XADES_141, "CompleteCertificateRefsV2");
    let list = xml.element_child(refs, XADES_141, "CertRefs");
    add_certificate_reference(&mut xml, list, root);
    let value = add_certificate_reference(&mut xml, list, leaf);
    xml.binary_routes
        .iter_mut()
        .find(|item| item.0 == value)
        .unwrap()
        .1[0] ^= 1;
    let attribute = add(&mut xml, 7, XADES_141, "AttributeCertificateRefsV2");
    let attribute_list = add(&mut xml, attribute, XADES_141, "CertRefs");
    add_certificate_reference(&mut xml, attribute_list, leaf);
    // Attribute references are permitted only when a protected credential
    // exists. Its syntax is enough for this digest-only relation test;
    // this deliberately does not assert credential authentication.
    let role = add(&mut xml, 4, XADES, "SignerRoleV2");
    let assertions = add(&mut xml, role, XADES, "SignedAssertions");
    add(&mut xml, assertions, XADES, "SignedAssertion");
    xml
}

#[test]
fn complete_reference_digest_catalogue_retains_all_pairs_and_reuses_finished_outputs() {
    // Repeated declarations are not repeated source hashing. Every original
    // source (including a duplicate encoding) retains its own ordinal; a first
    // positive result cannot hide another mismatch or another positive copy.
    use structured_xades::validation::{ReferenceSearch, compare_reference_catalogues};
    with_checked_path(|_, leaf, root, memory| {
        let xml = complete_catalogue_fixture(leaf, root);
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let provider = Oracle::new(Mode::Ready);
        material::with_values(&xml, &prepared, &operation, |current, view| {
            let account = funded();
            let paid = memory.work_used();
            let held = memory.used();
            let report =
                compare_reference_catalogues(&xml, &prepared, &view, &provider, &account).unwrap();
            assert_eq!(report.rows().len(), 4);
            assert_eq!(report.sources().len(), 4);
            for row in report.rows() {
                assert_eq!(row.search(), ReferenceSearch::Compared);
            }
            assert_eq!(
                (report.rows()[3].property(), report.rows()[3].entry()),
                (1, 0)
            );
            for (row, expected) in [
                [
                    Agreement::Matches,
                    Agreement::Matches,
                    Agreement::Differs,
                    Agreement::Matches,
                ],
                [
                    Agreement::Differs,
                    Agreement::Differs,
                    Agreement::Matches,
                    Agreement::Differs,
                ],
                [
                    Agreement::Differs,
                    Agreement::Differs,
                    Agreement::Differs,
                    Agreement::Differs,
                ],
                [
                    Agreement::Matches,
                    Agreement::Matches,
                    Agreement::Differs,
                    Agreement::Matches,
                ],
            ]
            .iter()
            .enumerate()
            {
                let compared = report.comparisons(row).unwrap();
                assert_eq!(compared.len(), 4);
                for (ordinal, (actual, expected)) in compared.iter().zip(expected).enumerate() {
                    assert_eq!(actual.source(), Some(ordinal));
                    assert_eq!(actual.agreement(), *expected);
                }
            }
            assert!(report.comparisons(4).is_none());
            assert_eq!(
                (
                    provider.resolved.get(),
                    provider.started.get(),
                    provider.finished.get()
                ),
                (4, 2, 2)
            );
            assert!(account.used() > 0);
            assert_eq!((memory.work_used(), memory.used()), (paid, held));
            drop(report);
            assert_eq!(account.used(), 0);
            let _ = current;
            Ok::<_, ()>(())
        })
        .unwrap();
    });
}

#[test]
fn reference_catalogue_refusal_drops_every_partial_cache_and_report() {
    // An already parsed pool is not allocation/work credit for a new query;
    // failed hashing after a complete earlier row never returns that row alone.
    use structured_xades::validation::compare_reference_catalogues;
    with_checked_path(|_, leaf, root, memory| {
        let (mut xml, source) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
        header_certificate(&mut xml, leaf);
        let parent = xml.nodes[source].parent.unwrap();
        let next = add(&mut xml, parent, XADES, "EncapsulatedX509Certificate");
        xml.binary_routes.push((next, root.to_vec()));
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        material::with_values(&xml, &prepared, &operation, |_, view| {
            let held = memory.used();
            let paid = memory.work_used();
            let denied = structured_asn1::memory::Memory::new(std::sync::Arc::new(
                structured_asn1::memory::MemoryAccount::new(0, 1_000_000),
            ));
            let provider = Oracle::new(Mode::Ready);
            assert!(
                compare_reference_catalogues(&xml, &prepared, &view, &provider, &denied).is_err()
            );
            assert_eq!(provider.started.get(), 0);
            assert_eq!(denied.used(), 0);
            let account = funded();
            let provider = Oracle::new(Mode::RefuseUpdate);
            assert!(matches!(
                compare_reference_catalogues(&xml, &prepared, &view, &provider, &account),
                Err(binary::Error::Callback {
                    cause: structured_xades::validation::ReferenceDigestError::Digest(
                        digest::Error::Provider(Failure::Refused)
                    ),
                    ..
                })
            ));
            assert_eq!(account.used(), 0);
            assert_eq!((memory.work_used(), memory.used()), (paid, held));
            Ok::<_, ()>(())
        })
        .unwrap();
    });
}

#[test]
fn reference_catalogues_reject_foreign_pool_and_current_local_refusal_before_hashing() {
    // Identical phase-local node ordinals do not make two documents the same
    // source. A retained source's old account also cannot pay a current query.
    use structured_xades::validation::{ReferenceDigestError, compare_reference_catalogues};
    with_checked_path(|_, leaf, _, memory| {
        let (mut xml, _) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
        header_certificate(&mut xml, leaf);
        let (mut other, _) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
        other.document += 1;
        header_certificate(&mut other, leaf);
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let foreign = prepare::prepare(
            &Access::new(&other, other.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        material::with_values(&xml, &prepared, &operation, |_, view| {
            let provider = Oracle::new(Mode::Ready);
            let account = funded();
            assert!(matches!(
                compare_reference_catalogues(&other, &foreign, &view, &provider, &account),
                Err(binary::Error::Callback {
                    cause: ReferenceDigestError::Foreign,
                    ..
                })
            ));
            assert_eq!(account.used(), 0);
            let denied = structured_asn1::Parser::new(
                structured_asn1::Encoding::Der,
                structured_asn1::Limits {
                    max_work: 0,
                    ..Default::default()
                },
                account.clone(),
            );
            let query = denied.read(&[], 0).unwrap();
            assert!(matches!(
                compare_reference_catalogues(&xml, &prepared, &view, &provider, &query.execution()),
                Err(binary::Error::Access {
                    cause: AccessError::Resource { .. },
                    ..
                })
            ));
            assert_eq!((provider.resolved.get(), provider.started.get()), (0, 0));
            assert_eq!(account.used(), 0);
            Ok::<_, ()>(())
        })
        .unwrap();
    });
}

#[test]
fn reference_catalogues_keep_unavailable_outcomes_and_do_not_start_invalid_widths() {
    // Method/declared-value checks precede memo construction and source I/O.
    // A streaming-unsupported result remains explicit for EVERY original copy.
    use structured_xades::validation::{ReferenceSearch, compare_reference_catalogues};
    with_checked_path(|_, leaf, _, memory| {
        for mode in 0..3 {
            let (mut xml, _) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
            header_certificate(&mut xml, leaf);
            let refs = xml.element_child(7, XADES_141, "CompleteCertificateRefsV2");
            let list = xml.element_child(refs, XADES_141, "CertRefs");
            let entry = xml.element_child(list, XADES, "Cert");
            let digest = xml.element_child(entry, XADES, "CertDigest");
            let value = xml.element_child(digest, DS, "DigestValue");
            if mode == 0 {
                xml.binary_routes
                    .iter_mut()
                    .find(|item| item.0 == value)
                    .unwrap()
                    .1
                    .pop();
            }
            if mode == 1 {
                xml.digest_algorithms.last_mut().unwrap().1 = "urn:fixture:unsupported";
            }
            let provider = Oracle::new(if mode == 2 {
                Mode::Unsupported
            } else {
                Mode::Ready
            });
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            let prepared = prepare::prepare(
                &Access::new(&xml, xml.snapshot(), memory),
                0,
                unsigned::Requirements::Basic,
                None,
            )
            .unwrap();
            material::with_values(&xml, &prepared, &operation, |_, view| {
                let account = funded();
                let report =
                    compare_reference_catalogues(&xml, &prepared, &view, &provider, &account)
                        .unwrap();
                if mode == 2 {
                    assert_eq!(report.rows()[0].search(), ReferenceSearch::Compared);
                    assert_eq!(report.comparisons(0).unwrap().len(), 2);
                    for pair in report.comparisons(0).unwrap() {
                        assert_eq!(pair.agreement(), Agreement::Unsupported);
                    }
                    assert_eq!((provider.started.get(), provider.finished.get()), (1, 0));
                } else {
                    assert_eq!(
                        report.rows()[0].search(),
                        ReferenceSearch::Unavailable(if mode == 0 {
                            Agreement::MalformedValue
                        } else {
                            Agreement::Unsupported
                        })
                    );
                    assert!(report.comparisons(0).unwrap().is_empty());
                    assert_eq!(provider.started.get(), 0);
                }
                drop(report);
                assert_eq!(account.used(), 0);
                Ok::<_, ()>(())
            })
            .unwrap();
        }
    });
}

#[test]
fn reference_catalogues_include_certificates_inside_original_ocsp_envelopes() {
    // Complete material includes responder certificates carried inside a basic
    // response. They must retain enclosure+embedded ordinal and hash their own
    // certificate DER, without hashing the entire OCSP envelope as a certificate.
    use structured_xades::validation::compare_reference_catalogues;
    with_checked_path(|_, leaf, root, memory| {
        let (mut xml, source) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
        header_certificate(&mut xml, root);
        xml.binary_routes
            .iter_mut()
            .find(|route| route.0 == source)
            .unwrap()
            .1 = root.to_vec();
        let values = add(&mut xml, 7, XADES, "RevocationValues");
        let list = add(&mut xml, values, XADES, "OCSPValues");
        let ocsp = add(&mut xml, list, XADES, "EncapsulatedOCSPValue");
        xml.binary_routes
            .push((ocsp, super::super::ocsp_material_with_certificate(leaf)));
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        material::with_values(&xml, &prepared, &operation, |_, view| {
            let account = funded();
            let provider = Oracle::new(Mode::Ready);
            let report =
                compare_reference_catalogues(&xml, &prepared, &view, &provider, &account).unwrap();
            let pairs = report.comparisons(0).unwrap();
            assert_eq!(pairs.len(), 3);
            assert_eq!(pairs[0].agreement(), Agreement::Differs);
            assert_eq!(pairs[1].agreement(), Agreement::Differs);
            assert_eq!(pairs[2].agreement(), Agreement::Matches);
            assert_eq!(pairs[2].source(), Some(2));
            assert_eq!(pairs[2].embedded_certificate(), Some(0));
            assert_eq!((provider.started.get(), provider.finished.get()), (2, 2));
            drop(report);
            assert_eq!(account.used(), 0);
            Ok::<_, ()>(())
        })
        .unwrap();
    });
}

struct KeyDigest<'key> {
    key: &'key [u8],
    resolves: Cell<usize>,
    hashes: Cell<usize>,
    supported: bool,
    fail: bool,
}

// Control callbacks: forwarding/charging/error oracle, not SHA-1 math.
impl Digest<'_> for KeyDigest<'_> {
    type Identity = ();
    type State = ();
    type Output = [u8; 20];
    type Error = MemoryError;
    fn width(&self, (): &()) -> Option<usize> {
        Some(20)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), _: &W) -> Result<Ordering, MemoryError> {
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), _: &W) -> Result<Resolution<()>, MemoryError> {
        Ok(Resolution::Supported(()))
    }
    fn update<W: Work>(&self, (): &mut (), input: &[u8], work: &W) -> Result<(), MemoryError> {
        work.charge_work(input.len() as u64)?;
        self.hashes.set(self.hashes.get() + 1);
        if self.fail {
            return Err(MemoryError::WorkExceeded);
        }
        assert_eq!(input.as_ptr(), self.key.as_ptr());
        assert_eq!(input, self.key);
        Ok(())
    }
    fn finish<W: Work>(&self, (): (), _: &W) -> Result<[u8; 20], MemoryError> {
        Ok([0; 20])
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        _: &[u8; 20],
        expected: &[u8],
        work: &W,
    ) -> Result<bool, MemoryError> {
        work.charge_work(expected.len() as u64)?;
        Ok(expected == [0x33; 20])
    }
}

impl AsnDigest<'_> for KeyDigest<'_> {
    fn identity(&self, algorithm: Algorithm) -> Option<()> {
        self.resolves.set(self.resolves.get() + 1);
        assert_eq!(algorithm, Algorithm::Sha1);
        self.supported.then_some(())
    }
}

fn with_authenticated_ocsp(
    check: impl FnOnce(
        structured_pkix::ocsp::SignedResponse<'_, '_>,
        &structured_pkix::ocsp::ResponseBytes<'_>,
        &structured_asn1::Reader<'_>,
        &super::super::timestamp_oracle::PathOracle,
        &structured_asn1::memory::Memory,
        &[u8],
    ),
) {
    use structured_pkix::ocsp::{Response, SignatureAuthentication};
    with_checked_path(|_, _, root, memory| {
        let bytes = super::super::timestamp_oracle::ocsp_response(2);
        let parser = structured_asn1::Parser::der(memory.clone());
        let certificate = structured_pkix::Certificate::read(&parser, root, 100).unwrap();
        let Response::Successful(response) = Response::read(&parser, &bytes, 400).unwrap() else {
            panic!("successful envelope")
        };
        let original = parser.read(&[], 900).unwrap();
        let basic = response.basic_in(&original).unwrap().unwrap();
        let verifier = super::super::timestamp_oracle::PathOracle {
            calls: Cell::new(0),
        };
        let SignatureAuthentication::Signed(signed) = basic
            .authenticate_signature(
                &certificate,
                structured_pkix::path::WorkingKey::standing(certificate.tbs().public_key()),
                &verifier,
                &verifier,
                &original.execution(),
            )
            .unwrap()
        else {
            panic!("actual signed response")
        };
        assert_eq!(verifier.calls.get(), 1);
        check(signed, &response, &original, &verifier, memory, &bytes);
    });
}

fn ocsp_reference_fixture(
    bytes: &[u8],
    memory: &structured_asn1::memory::Memory,
) -> (Tree, prepare::Prepared<Tree>) {
    ocsp_reference_fixture_with_digest(bytes, memory, true)
}

fn ocsp_reference_fixture_with_digest(
    bytes: &[u8],
    memory: &structured_asn1::memory::Memory,
    with_digest: bool,
) -> (Tree, prepare::Prepared<Tree>) {
    // Original XML selectors shared by the association and refusal regressions.
    use structured_xades::{
        properties::{CalendarFact, CalendarValue},
        validation::{ReferenceIdentifier, ResponderIdentifier},
    };
    let (mut xml, _) = fixture(material::Kind::Ocsp, bytes.to_vec(), with_digest);
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), memory),
        0,
        unsigned::Requirements::Basic,
        None,
    )
    .unwrap();
    let refs = &prepared.validation_references()[0];
    let ReferenceIdentifier::Ocsp {
        responder: ResponderIdentifier::Key(key),
        time,
        ..
    } = refs.entries()[0].identifier()
    else {
        panic!("original OCSP selector")
    };
    let mut by_key = vec![0xa2, 22, 4, 20];
    by_key.extend([0x33; 20]);
    xml.binary_routes.push((key, by_key));
    xml.calendar_routes.push((
        time,
        CalendarFact::Value(CalendarValue {
            negative_year: false,
            year_digits: "2026",
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            fraction_digits: None,
            timezone_minutes: Some(0),
        }),
    ));
    (xml, prepared)
}

#[test]
fn ocsp_reference_keeps_whole_digest_and_identifier_on_one_authenticated_body() {
    // A valid response A identifier must never be joined to an envelope B
    // digest. A same-width mutation keeps B structurally readable while its
    // signature is not authenticated. A's signature never runs a second time.
    use structured_pkix::ocsp::{ResponderMatch, Response};
    use structured_xades::validation::{self, OcspReferenceInput, ReferenceIdentifier};
    with_authenticated_ocsp(|signed, envelope, operation, verifier, memory, bytes| {
        let (xml, prepared) = ocsp_reference_fixture(bytes, memory);
        let refs = &prepared.validation_references()[0];
        let ReferenceIdentifier::Ocsp { node, .. } = refs.entries()[0].identifier() else {
            panic!("original OCSP selector")
        };
        let keys = KeyDigest {
            key: signed.signer().tbs().public_key().key().as_bytes(),
            resolves: Cell::new(0),
            hashes: Cell::new(0),
            supported: true,
            fail: false,
        };
        let provider = Oracle::new(Mode::Ready);
        let held = memory.used();
        let result = validation::check_ocsp_envelope_reference(
            &xml,
            refs,
            0,
            OcspReferenceInput { envelope, signed },
            &keys,
            &provider,
            operation,
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.identity().location.node, node);
        assert_eq!(
            result.identity().value.responder(),
            Some(ResponderMatch::Matches)
        );
        assert_eq!(
            result.identity().value.produced_at(),
            validation::ReferenceTime::Matches
        );
        assert_eq!(
            result.digest(),
            Some(ReferenceDigest::Compared(Agreement::Matches))
        );
        assert_eq!((keys.resolves.get(), keys.hashes.get()), (1, 1));
        assert_eq!((provider.started.get(), provider.finished.get()), (1, 1));
        let mut other_bytes = bytes.to_vec();
        let time_at = other_bytes
            .windows(15)
            .position(|value| value == b"20260101000000Z")
            .unwrap();
        other_bytes[time_at + 13] = b'1';
        let other_parser = structured_asn1::Parser::der(memory.clone());
        let Response::Successful(other) =
            Response::read(&other_parser, &other_bytes, 2200).unwrap()
        else {
            panic!("other actual envelope")
        };
        assert_eq!(envelope.payload().len(), other.payload().len());
        assert_ne!(envelope.payload(), other.payload());
        let result = validation::check_ocsp_envelope_reference(
            &xml,
            refs,
            0,
            OcspReferenceInput {
                envelope: &other,
                signed,
            },
            &keys,
            &provider,
            operation,
        );
        assert!(
            matches!(result, Err(validation::OcspEnvelopeError::InputMismatch { node: actual }) if actual == node)
        );
        assert_eq!((keys.resolves.get(), keys.hashes.get()), (1, 1));
        assert_eq!((provider.started.get(), provider.finished.get()), (1, 1));
        assert_eq!(verifier.calls.get(), 1);
        drop(other);
        assert_eq!(memory.used(), held);
    });
}

#[test]
fn ocsp_envelope_relation_and_mandatory_time_refuse_before_provider_effects() {
    // Even an authenticated body gives no credit to a new local or aggregate
    // query. The exact body scan is admitted before comparison; malformed time
    // retains facts but cannot start either digest provider.
    use structured_asn1::{
        Encoding, Limits, Parser,
        memory::{Memory, MemoryAccount},
    };
    use structured_xades::{
        properties::CalendarFact,
        validation::{
            self, OcspEnvelopeError, OcspReferenceInput, ReferenceIdentifier, ReferenceTime,
        },
    };
    with_authenticated_ocsp(|signed, envelope, original, verifier, memory, bytes| {
        let (mut xml, prepared) = ocsp_reference_fixture(bytes, memory);
        let refs = &prepared.validation_references()[0];
        let ReferenceIdentifier::Ocsp { node, .. } = refs.entries()[0].identifier() else {
            panic!("OCSP input")
        };
        let keys = KeyDigest {
            key: signed.signer().tbs().public_key().key().as_bytes(),
            resolves: Cell::new(0),
            hashes: Cell::new(0),
            supported: true,
            fail: false,
        };
        let provider = Oracle::new(Mode::Ready);
        let held = memory.used();
        let actual = OcspReferenceInput { envelope, signed };
        let limit = u64::try_from(envelope.payload().len()).unwrap() + 10;
        for local in [false, true] {
            let query_memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(
                0,
                if local {
                    1 << 20
                } else {
                    usize::try_from(limit).unwrap()
                },
            )));
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: if local { limit } else { 1 << 20 },
                    ..Default::default()
                },
                query_memory.clone(),
            );
            let query = parser.read(&[], 990).unwrap();
            assert!(
                matches!(validation::check_ocsp_envelope_reference(&xml, refs, 0, actual, &keys, &provider, &query), Err(OcspEnvelopeError::Resource { node: at, cause: MemoryError::WorkExceeded }) if at == node)
            );
            assert_eq!(query_memory.used(), 0);
            assert_eq!(
                (
                    keys.resolves.get(),
                    keys.hashes.get(),
                    provider.resolved.get(),
                    provider.started.get()
                ),
                (0, 0, 0, 0)
            );
        }
        for (fact, expected) in [
            (CalendarFact::Malformed, ReferenceTime::Malformed),
            (CalendarFact::Unsupported, ReferenceTime::Unsupported),
        ] {
            xml.calendar_routes[0].1 = fact;
            let report = validation::check_ocsp_envelope_reference(
                &xml, refs, 0, actual, &keys, &provider, original,
            )
            .unwrap()
            .unwrap();
            assert_eq!(report.identity().value.produced_at(), expected);
            assert_eq!(report.identity().value.responder(), None);
            assert_eq!(report.digest(), None);
            assert_eq!(
                (
                    keys.resolves.get(),
                    keys.hashes.get(),
                    provider.resolved.get(),
                    provider.started.get()
                ),
                (0, 0, 0, 0)
            );
        }
        assert_eq!(verifier.calls.get(), 1);
        assert_eq!(memory.used(), held);
    });
}

#[test]
fn ocsp_envelope_cannot_relabel_an_opaque_response_type_as_signed_basic() {
    // An unknown responseType keeps opaque bytes even when those bytes equal
    // an authenticated BasicOCSPResponse. The OID is part of the binding, not
    // inferred from successful payload parsing or a coincidental byte match.
    use structured_pkix::{ocsp::Response, oid};
    use structured_xades::validation::{
        self, OcspEnvelopeError, OcspReferenceInput, ReferenceIdentifier,
    };
    with_authenticated_ocsp(|signed, original, operation, verifier, memory, bytes| {
        let (xml, prepared) = ocsp_reference_fixture(bytes, memory);
        let refs = &prepared.validation_references()[0];
        let ReferenceIdentifier::Ocsp { node, .. } = refs.entries()[0].identifier() else {
            panic!("OCSP input")
        };
        let mut relabeled = bytes.to_vec();
        let kind = oid::OCSP_BASIC.as_bytes();
        let at = relabeled
            .windows(kind.len())
            .position(|value| value == kind)
            .unwrap();
        relabeled[at + kind.len() - 1] = 2;
        let parser = structured_asn1::Parser::der(memory.clone());
        let Response::Successful(envelope) = Response::read(&parser, &relabeled, 2200).unwrap()
        else {
            panic!("readable opaque envelope")
        };
        assert_ne!(envelope.kind(), oid::OCSP_BASIC);
        assert_eq!(envelope.payload(), original.payload());
        let keys = KeyDigest {
            key: signed.signer().tbs().public_key().key().as_bytes(),
            resolves: Cell::new(0),
            hashes: Cell::new(0),
            supported: true,
            fail: false,
        };
        let provider = Oracle::new(Mode::Ready);
        assert!(
            matches!(validation::check_ocsp_envelope_reference(&xml, refs, 0, OcspReferenceInput { envelope: &envelope, signed }, &keys, &provider, operation), Err(OcspEnvelopeError::InputMismatch { node: at }) if at == node)
        );
        assert_eq!(
            (
                keys.resolves.get(),
                keys.hashes.get(),
                provider.resolved.get(),
                provider.started.get()
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(verifier.calls.get(), 1);
    });
}

#[test]
fn ocsp_identifier_composes_actual_signer_and_response_time_without_reverification() {
    // Real P256 authenticates the original response once. XML ByKey may
    // identify that signer even when ResponseData uses ByName; the callback
    // below is only a controlled SHA1-key query. A late refusal returns no prefix.
    use structured_pkix::ocsp::ResponderMatch;
    use structured_xades::{
        properties::{CalendarFact, CalendarValue},
        validation::{
            OcspReferenceError, ReferenceIdentifier, ReferenceTime, ResponderIdentifier,
            check_ocsp_reference,
        },
    };
    with_authenticated_ocsp(|signed, _, original, verifier, memory, bytes| {
        let certificate = signed.signer();
        let (mut xml, _) = fixture(material::Kind::Ocsp, bytes.to_vec(), false);
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let refs = &prepared.validation_references()[0];
        let ReferenceIdentifier::Ocsp {
            node,
            responder: ResponderIdentifier::Key(key),
            time,
        } = refs.entries()[0].identifier()
        else {
            panic!("OCSP ref")
        };
        let mut by_key = vec![0xa2, 22, 4, 20];
        by_key.extend([0x33; 20]);
        xml.binary_routes.push((key, by_key));
        let calendar = CalendarValue {
            negative_year: false,
            year_digits: "2026",
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            fraction_digits: None,
            timezone_minutes: Some(0),
        };
        xml.calendar_routes
            .push((time, CalendarFact::Value(calendar)));
        let mut digest = KeyDigest {
            key: certificate.tbs().public_key().key().as_bytes(),
            resolves: Cell::new(0),
            hashes: Cell::new(0),
            supported: true,
            fail: false,
        };
        let held = memory.used();
        let result = check_ocsp_reference(&xml, refs, 0, signed, &digest, original)
            .unwrap()
            .unwrap();
        assert_eq!(result.location.node, node);
        assert_eq!(result.value.responder(), Some(ResponderMatch::Matches));
        assert_eq!(result.value.produced_at(), ReferenceTime::Matches);
        assert_eq!(verifier.calls.get(), 1);
        xml.calendar_routes[0].1 = CalendarFact::Value(CalendarValue {
            second: 1,
            ..calendar
        });
        let result = check_ocsp_reference(&xml, refs, 0, signed, &digest, original)
            .unwrap()
            .unwrap();
        assert_eq!(result.value.responder(), Some(ResponderMatch::Matches));
        assert_eq!(result.value.produced_at(), ReferenceTime::Differs);
        digest.supported = false;
        let result = check_ocsp_reference(&xml, refs, 0, signed, &digest, original)
            .unwrap()
            .unwrap();
        assert_eq!(
            result.value.responder(),
            Some(ResponderMatch::UnsupportedHash)
        );
        assert_eq!(result.value.produced_at(), ReferenceTime::Differs);
        digest.supported = true;
        assert_ocsp_name_identity(signed, original, &digest, memory, bytes, calendar);
        xml.calendar_routes.clear();
        let hashes = digest.hashes.get();
        assert!(matches!(
            check_ocsp_reference(&xml, refs, 0, signed, &digest, original),
            Err(OcspReferenceError::Time(_))
        ));
        assert_eq!(digest.hashes.get(), hashes);
        assert_eq!(memory.used(), held);
        assert_eq!(verifier.calls.get(), 1);
        let zero = structured_asn1::memory::Memory::new(std::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(1 << 20, 0),
        ));
        let limited = structured_asn1::Parser::der(zero.clone());
        let query = limited.read(&[], 990).unwrap();
        let hashes = digest.hashes.get();
        assert!(matches!(
            check_ocsp_reference(&xml, refs, 0, signed, &digest, &query),
            Err(OcspReferenceError::Access(_))
        ));
        assert_eq!(digest.hashes.get(), hashes);
        assert_eq!(zero.used(), 0);
    });
}

fn assert_ocsp_name_identity(
    signed: structured_pkix::ocsp::SignedResponse<'_, '_>,
    original: &structured_asn1::Reader<'_>,
    digest: &KeyDigest<'_>,
    memory: &structured_asn1::memory::Memory,
    bytes: &[u8],
    calendar: structured_xades::properties::CalendarValue<'static>,
) {
    use structured_pkix::ocsp::ResponderMatch;
    use structured_xades::{
        properties::CalendarFact,
        validation::{ReferenceIdentifier, ReferenceTime, check_ocsp_reference},
    };
    // No key hash or response signature may be performed for ByName.
    let (mut named, _) = fixture(material::Kind::Ocsp, bytes.to_vec(), false);
    let selector = named
        .nodes
        .iter()
        .position(|entry| {
            matches!(
                entry.value,
                super::super::Node::Element(Name {
                    namespace: XADES,
                    local: "ByKey"
                })
            )
        })
        .unwrap();
    named.nodes[selector].value = super::super::Node::Element(Name {
        namespace: XADES,
        local: "ByName",
    });
    let named_prepared = prepare::prepare(
        &Access::new(&named, named.snapshot(), memory),
        0,
        unsigned::Requirements::Basic,
        None,
    )
    .unwrap();
    let named_refs = &named_prepared.validation_references()[0];
    let ReferenceIdentifier::Ocsp {
        time: named_time, ..
    } = named_refs.entries()[0].identifier()
    else {
        panic!("OCSP name reference")
    };
    named
        .calendar_routes
        .push((named_time, CalendarFact::Value(calendar)));
    named
        .text_routes
        .push((selector, "CN=synthetic xades root"));
    let hashes = digest.hashes.get();
    for (text, expected) in [
        ("CN=synthetic xades root", ResponderMatch::Matches),
        ("CN=Another Responder", ResponderMatch::Differs),
    ] {
        named.text_routes[0].1 = text;
        let result = check_ocsp_reference(&named, named_refs, 0, signed, digest, original)
            .unwrap()
            .unwrap();
        assert_eq!(result.value.responder(), Some(expected));
        assert_eq!(result.value.produced_at(), ReferenceTime::Matches);
    }
    assert_eq!(digest.hashes.get(), hashes);
}

#[test]
fn ocsp_identifier_time_preflight_refuses_before_key_provider() {
    // A known malformed/unavailable mandatory time must be reported before
    // digest resolution or hashing, even if the original key selector is valid.
    use structured_xades::{
        properties::CalendarFact,
        validation::{
            ReferenceIdentifier, ReferenceTime, ResponderIdentifier, check_ocsp_reference,
        },
    };
    with_authenticated_ocsp(|signed, _, original, _, memory, _| {
        let (mut xml, _) = fixture(material::Kind::Ocsp, Vec::new(), false);
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let refs = &prepared.validation_references()[0];
        let ReferenceIdentifier::Ocsp {
            responder: ResponderIdentifier::Key(key),
            time,
            ..
        } = refs.entries()[0].identifier()
        else {
            panic!("original OCSP fields")
        };
        let mut bytes = vec![0xa2, 22, 4, 20];
        bytes.extend([0x33; 20]);
        xml.binary_routes.push((key, bytes));
        xml.calendar_routes.push((time, CalendarFact::Malformed));
        let digest = KeyDigest {
            key: signed.signer().tbs().public_key().key().as_bytes(),
            resolves: Cell::new(0),
            hashes: Cell::new(0),
            supported: true,
            fail: false,
        };
        for (fact, expected) in [
            (CalendarFact::Malformed, ReferenceTime::Malformed),
            (CalendarFact::Unsupported, ReferenceTime::Unsupported),
        ] {
            xml.calendar_routes[0].1 = fact;
            let result = check_ocsp_reference(&xml, refs, 0, signed, &digest, original)
                .unwrap()
                .unwrap();
            assert_eq!(result.value.produced_at(), expected);
            assert_eq!(result.value.responder(), None);
            assert_eq!(digest.resolves.get(), 0);
            assert_eq!(digest.hashes.get(), 0);
        }
    });
}

#[test]
fn reference_by_key_binds_actual_certificate_and_preserves_scoped_provider_failure() {
    // The original DER hint is decoded once, then the SAME OCSP identity core
    // receives original subjectPublicKey bits. No signature verifier runs.
    use structured_pkix::{error::CallbackError, ocsp::ResponderMatch};
    use structured_xades::validation::{
        ReferenceIdentifier, ResponderIdentifier, ResponderKeyError, matches_reference_key,
    };
    with_checked_path(|_, leaf, _, memory| {
        let (mut xml, _) = fixture(material::Kind::Ocsp, vec![0x30, 0], false);
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let refs = &prepared.validation_references()[0];
        let ReferenceIdentifier::Ocsp {
            responder: ResponderIdentifier::Key(node),
            ..
        } = refs.entries()[0].identifier()
        else {
            panic!("original byKey")
        };
        let mut bytes = vec![0xa2, 22, 4, 20];
        bytes.extend([0x33; 20]);
        xml.binary_routes.push((node, bytes));
        let parser = structured_asn1::Parser::der(memory.clone());
        let certificate = structured_pkix::Certificate::read(&parser, leaf, 100).unwrap();
        let query = parser.read(&[], 900).unwrap();
        let mut digest = KeyDigest {
            key: certificate.tbs().public_key().key().as_bytes(),
            resolves: Cell::new(0),
            hashes: Cell::new(0),
            supported: true,
            fail: false,
        };
        let held = memory.used();
        let answer = matches_reference_key(&xml, refs, 0, &certificate, &digest, &query)
            .unwrap()
            .unwrap();
        assert_eq!(answer.location.node, node);
        assert_eq!(answer.value, ResponderMatch::Matches);
        xml.binary_routes.last_mut().unwrap().1[4] ^= 1;
        assert_eq!(
            matches_reference_key(&xml, refs, 0, &certificate, &digest, &query)
                .unwrap()
                .unwrap()
                .value,
            ResponderMatch::Differs
        );
        digest.supported = false;
        assert_eq!(
            matches_reference_key(&xml, refs, 0, &certificate, &digest, &query)
                .unwrap()
                .unwrap()
                .value,
            ResponderMatch::UnsupportedHash
        );
        assert_eq!(digest.hashes.get(), 2);
        digest.supported = true;
        digest.fail = true;
        assert!(
            matches!(matches_reference_key(&xml,refs,0,&certificate,&digest,&query),Err(binary::Error::Callback {location,cause:ResponderKeyError::Callback(CallbackError::Callback(MemoryError::WorkExceeded))}) if location.node==node)
        );
        assert_eq!(memory.used(), held);
    });
}

#[test]
fn certificate_references_classify_actual_exclusive_credential_ca_once() {
    // Real checked paths and a complete actor/status closure distinguish a
    // credential-only CA from one also serving the selected signature. The
    // credential test owner supplies metadata, not SAML authentication.
    use structured_pkix::path::Anchor;
    use structured_xades::{pki, timestamp};
    for shared in [false, true] {
        with_checked_path(|path, leaf, _, storage| {
            let (mut xml, _, _, _, archive) = super::participant_tree(leaf, storage);
            xml.nodes[archive].parent = None;
            let bytes = super::super::timestamp_oracle::other_issuer();
            let parser = structured_asn1::Parser::der(storage.clone());
            let other = structured_pkix::Certificate::read(&parser, &bytes, 2400).unwrap();
            let anchor = if shared {
                path.anchor()
            } else {
                Anchor::from_certificate(&other)
            };
            let certificate = anchor.certificate().unwrap();
            let refs = add(&mut xml, 7, XADES_141, "CompleteCertificateRefsV2");
            let list = add(&mut xml, refs, XADES_141, "CertRefs");
            add_certificate_reference(&mut xml, list, certificate.as_bytes());
            add_certificate_reference(&mut xml, list, certificate.as_bytes());
            let access = Access::new(&xml, xml.snapshot(), storage);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters =
                pki::bind_counters(prepared.bound(), &access, |_, _| Ok::<_, ()>(path)).unwrap();
            let stamps = timestamp::counter_timestamps(&access, &counters).unwrap();
            let all = timestamp::requirements_with_counters(
                &access,
                &prepared,
                &stamps,
                timestamp::TimestampSelection::All,
            )
            .unwrap();
            let timestamp::TimestampPathBinding::Bound(all) = all.bind_paths(&[], &access).unwrap()
            else {
                panic!("complete zero-token scope")
            };
            super::with_prepared_participants(
                &xml,
                &prepared,
                path,
                anchor,
                &all,
                storage,
                |participants| {
                    super::with_original_delta_statuses(path, storage, |statuses| {
                        let roots = [statuses; 3];
                        let nodes = [pki::AuthorityNode {
                            statuses,
                            responders: &[],
                        }];
                        let closed = participants
                            .close_statuses(&roots, &nodes, &access)
                            .unwrap();
                        let uses = pki::authority_uses(&closed, &access).unwrap();
                        let artifacts = material::artifact_uses(&uses, &access).unwrap();
                        assert_certificate_role_comparisons(
                            &xml,
                            &prepared,
                            &artifacts,
                            certificate,
                            shared,
                            storage,
                        );
                        assert_certificate_role_refusals(&xml, &prepared, &artifacts, storage);
                        if !shared {
                            assert_certificate_role_provider_refusal(
                                &xml, &prepared, &artifacts, storage,
                            );
                        }
                    });
                },
            );
        });
    }
}

fn assert_certificate_role_comparisons(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    artifacts: &material::ArtifactUses<'_, '_, '_, '_, '_, usize, u8, u8>,
    certificate: &structured_pkix::Certificate<'_>,
    shared: bool,
    storage: &structured_asn1::memory::Memory,
) {
    // An unsupported streaming capability is a per-candidate result after
    // algorithm resolution, never a completed mismatch. Repeated references
    // reuse that result just as they reuse a finished supported digest.
    use structured_xades::validation;
    let held = storage.used();
    let paid = storage.work_used();
    for mode in [Mode::Ready, Mode::Unsupported] {
        let query = funded();
        let provider = Oracle::new(mode);
        let report = validation::check_certificate_reference_roles(
            xml, prepared, artifacts, &provider, &query,
        )
        .unwrap();
        assert_eq!(report.rows().len(), 2);
        let unsupported = matches!(mode, Mode::Unsupported);
        for row in 0..2 {
            assert_eq!(report.rows()[row].property(), 0);
            assert_eq!(report.rows()[row].entry(), row);
            assert_eq!(
                report.rows()[row].search(),
                validation::ReferenceSearch::Compared
            );
            let compared = report.comparisons(row).unwrap();
            if shared {
                assert!(compared.is_empty());
            } else {
                assert_eq!(compared.len(), 1);
                assert_eq!(
                    compared[0].kind(),
                    material::ExclusiveFindingKind::ForbiddenCa
                );
                assert_eq!(
                    compared[0].agreement(),
                    if unsupported {
                        Agreement::Unsupported
                    } else {
                        Agreement::Matches
                    }
                );
                assert!(core::ptr::eq(compared[0].certificate(), certificate));
            }
        }
        let starts = usize::from(!shared);
        assert_eq!(provider.started.get(), starts);
        assert_eq!(
            provider.finished.get(),
            usize::from(!shared && !unsupported)
        );
        assert!(core::ptr::eq(report.prepared(), prepared));
        drop(report);
        assert_eq!(query.used(), 0);
        assert_eq!(storage.used(), held);
        assert_eq!(storage.work_used(), paid);
    }
}

fn assert_certificate_role_refusals(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    artifacts: &material::ArtifactUses<'_, '_, '_, '_, '_, usize, u8, u8>,
    storage: &structured_asn1::memory::Memory,
) {
    // A later query receives no credit from retained actor/CA catalogues.
    // Zero work/capacity refuses before provider side effects; no prefix leaks.
    use structured_asn1::memory::{Memory, MemoryAccount};
    use structured_xades::validation;
    let held = storage.used();
    let paid = storage.work_used();
    for (capacity, work) in [(0, 1 << 24), (1 << 24, 0)] {
        let query = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, work)));
        let provider = Oracle::new(Mode::Ready);
        let result = validation::check_certificate_reference_roles(
            xml, prepared, artifacts, &provider, &query,
        );
        if work == 0 {
            assert!(matches!(
                result,
                Err(binary::Error::Access {
                    cause: AccessError::Resource {
                        cause: MemoryError::WorkExceeded,
                        ..
                    },
                    ..
                })
            ));
        } else {
            // This XML fixture decodes the original DigestValue into current
            // admitted storage. Its refusal precedes the first CA query.
            let value = prepared.validation_references()[0].entries()[0]
                .digest()
                .unwrap()
                .1;
            assert!(matches!(result, Err(binary::Error::Access {
                location,
                cause: AccessError::Xml(super::super::Cause::Resource(MemoryError::LimitExceeded)),
            }) if location.node == value));
        }
        assert_eq!(provider.started.get(), 0);
        assert_eq!(query.used(), 0);
        assert_eq!(storage.used(), held);
        assert_eq!(storage.work_used(), paid);
    }
}

fn assert_certificate_role_provider_refusal(
    xml: &Tree,
    prepared: &prepare::Prepared<Tree>,
    artifacts: &material::ArtifactUses<'_, '_, '_, '_, '_, usize, u8, u8>,
    storage: &structured_asn1::memory::Memory,
) {
    // A refusal after CA decoding and stream start retains the actual provider
    // cause at DigestValue and releases every temporary classification/report.
    use structured_xades::validation::{self, CertificateRoleError};
    let held = storage.used();
    let paid = storage.work_used();
    let query = funded();
    let provider = Oracle::new(Mode::RefuseUpdate);
    let value = prepared.validation_references()[0].entries()[0]
        .digest()
        .unwrap()
        .1;
    let result =
        validation::check_certificate_reference_roles(xml, prepared, artifacts, &provider, &query);
    assert!(
        matches!(result, Err(binary::Error::Callback { location, cause: CertificateRoleError::Digest(digest::Error::Provider(Failure::Refused)) }) if location.node == value)
    );
    assert_eq!(provider.started.get(), 1);
    assert_eq!(provider.finished.get(), 0);
    assert_eq!(query.used(), 0);
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), paid);
}

#[test]
fn absent_complete_references_require_no_path_scan_or_query_storage() {
    // Absence of this optional property still checks the live source twice,
    // but does not allocate or hash/index certificates from an unrelated path.
    use structured_xades::{certificate, validation::check_root_certificate_references};
    with_checked_path(|path, leaf, root, storage| {
        let mut xml = super::super::attribute_checks::fixture();
        xml.key_association = certificate::KeyAssociation::Same;
        super::basic_binary_routes(&mut xml, leaf, root, 0);
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), storage),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let selected = super::checked_certificate(&xml, &prepared, path, storage);
        for limit in [1, 2] {
            let query = structured_asn1::memory::Memory::new(std::sync::Arc::new(
                structured_asn1::memory::MemoryAccount::new(0, limit),
            ));
            let provider = Oracle::new(Mode::Ready);
            let result =
                check_root_certificate_references(&xml, &prepared, &selected, &provider, &query);
            if limit == 2 {
                let report = result.unwrap();
                assert!(report.rows().is_empty());
                assert!(report.root_path_rules_met());
            } else {
                assert!(matches!(
                    result,
                    Err(binary::Error::Access {
                        cause: AccessError::Resource {
                            cause: MemoryError::WorkExceeded,
                            ..
                        },
                        ..
                    })
                ));
            }
            assert_eq!(query.used(), 0);
            assert_eq!(provider.started.get(), 0);
        }
    });
}

#[test]
fn root_reference_method_preflight_does_not_scan_or_index_path_bytes() {
    // Known prohibited MD5 needs only original method/report metadata. Building
    // a hash index over all path DER first would already spend at least those
    // bytes' hash-work, even though no candidate may be processed at all.
    use structured_xades::{
        certificate,
        validation::{ReferenceSearch, check_root_certificate_references},
    };
    with_checked_path(|path, leaf, root, storage| {
        let (mut xml, _) = fixture(material::Kind::Certificate, root.to_vec(), true);
        xml.key_association = certificate::KeyAssociation::Same;
        super::basic_binary_routes(&mut xml, leaf, root, 0);
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), storage),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let selected = super::checked_certificate(&xml, &prepared, path, storage);
        let method = prepared.validation_references()[0].entries()[0]
            .digest()
            .unwrap()
            .0;
        xml.digest_algorithms
            .iter_mut()
            .find(|route| route.0 == method)
            .unwrap()
            .1 = "http://www.w3.org/2001/04/xmldsig-more#md5";
        let provider = Oracle::new(Mode::Ready);
        let query = funded();
        let report =
            check_root_certificate_references(&xml, &prepared, &selected, &provider, &query)
                .unwrap();
        assert_eq!(
            report.rows()[0].search(),
            ReferenceSearch::Unavailable(Agreement::ProhibitedAlgorithm)
        );
        assert_eq!(report.comparisons(0).unwrap(), []);
        assert!(!report.root_path_rules_met());
        assert_eq!(provider.started.get(), 0);
        assert!(
            query.work_used() < leaf.len() + root.len(),
            "path bytes were indexed before method preflight"
        );
        drop(report);
        assert_eq!(query.used(), 0);
    });
}

#[test]
fn root_certificate_references_cover_actual_anchor_and_exclude_signer_with_one_memo() {
    // Unsigned complete references must cover the actual checked CA path but
    // must NOT reference the root signature's signing certificate. Equal DER
    // refs share finalized hashes, not caller-written coverage booleans.
    use structured_xades::{certificate, validation::check_root_certificate_references};
    with_checked_path(|path, leaf, root, storage| {
        for (values, mode, expected) in [
            (vec![root], Mode::Ready, true),
            (vec![root, root], Mode::Ready, true),
            (vec![leaf], Mode::Ready, false),
            (vec![root, leaf], Mode::Ready, false),
            (vec![root], Mode::Unsupported, false),
        ] {
            let (mut xml, _) = fixture(material::Kind::Certificate, values[0].to_vec(), true);
            xml.key_association = certificate::KeyAssociation::Same;
            super::basic_binary_routes(&mut xml, leaf, root, 0);
            let refs = xml.element_child(7, XADES_141, "CompleteCertificateRefsV2");
            let list = xml.element_child(refs, XADES_141, "CertRefs");
            for value in &values[1..] {
                add_certificate_reference(&mut xml, list, value);
            }
            let prepared = prepare::prepare(
                &Access::new(&xml, xml.snapshot(), storage),
                0,
                unsigned::Requirements::Basic,
                None,
            )
            .unwrap();
            let selected = super::checked_certificate(&xml, &prepared, path, storage);
            assert!(selected.is_bound());
            let provider = Oracle::new(mode);
            let query = funded();
            let held = storage.used();
            let spent = storage.work_used();
            let report =
                check_root_certificate_references(&xml, &prepared, &selected, &provider, &query)
                    .unwrap();
            assert_eq!(report.root_path_rules_met(), expected);
            assert_eq!(report.rows().len(), values.len());
            assert!(core::ptr::eq(report.path(), path));
            assert_eq!(
                report.candidate(0).unwrap().0,
                material::PathCertificate::Anchor
            );
            assert_eq!(
                report.candidate(1).unwrap().0,
                material::PathCertificate::Member(0)
            );
            assert!(report.candidate(2).is_none());
            if matches!(mode, Mode::Ready) {
                assert_eq!((provider.started.get(), provider.finished.get()), (2, 2));
                for (row, value) in values.iter().enumerate() {
                    assert_eq!(
                        report.comparisons(row).unwrap(),
                        if *value == root {
                            &[Agreement::Matches, Agreement::Differs]
                        } else {
                            &[Agreement::Differs, Agreement::Matches]
                        }
                    );
                }
            }
            assert_eq!(storage.used(), held);
            assert_eq!(storage.work_used(), spent);
            assert!(query.used() > 0);
            drop(report);
            assert_eq!(query.used(), 0);
        }
    });
}

#[test]
fn conditional_reference_presence_requires_complete_token_pool_and_keeps_missing_facts() {
    // CertificateValues activates Annex A inclusion. An acquired value or
    // incomplete token search cannot manufacture either presence or absence.
    // Completed wrong digest is a missing-copy fact, not a processing refusal.
    use structured_xades::{
        pki, timestamp,
        validation::{
            ReferencePresenceError, ReferencePresenceFailure, compare_reference_catalogues,
            compare_reference_catalogues_with_tokens, reference_presence,
        },
    };
    with_checked_path(|_, leaf, _, memory| {
        for (differs, mode, expected) in [
            (false, Mode::Ready, None),
            (true, Mode::Ready, Some(ReferencePresenceFailure::Missing)),
            (
                false,
                Mode::Unsupported,
                Some(ReferencePresenceFailure::Unavailable(
                    Agreement::Unsupported,
                )),
            ),
        ] {
            let (_, token, _, _) = super::super::timestamp_oracle::fixture_with_root(b"covered");
            let (mut xml, _) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
            header_certificate(&mut xml, leaf);
            let encoded = xml
                .nodes
                .iter()
                .position(|entry| {
                    matches!(
                        entry.value,
                        super::super::Node::Element(Name {
                            namespace: XADES,
                            local: "EncapsulatedTimeStamp"
                        })
                    )
                })
                .unwrap();
            xml.binary_routes.push((encoded, token));
            let access = Access::new(&xml, xml.snapshot(), memory);
            let prepared =
                prepare::prepare(&access, 0, unsigned::Requirements::Basic, None).unwrap();
            let counters = pki::bind_counters::<Tree, _, ()>(prepared.bound(), &access, |_, _| {
                panic!("no counter")
            })
            .unwrap();
            let required =
                timestamp::requirements(&access, &prepared, timestamp::TimestampSelection::All)
                    .unwrap();
            if differs {
                let value = prepared.validation_references()[0].entries()[0]
                    .digest()
                    .unwrap()
                    .1;
                xml.binary_routes
                    .iter_mut()
                    .find(|route| route.0 == value)
                    .unwrap()
                    .1[0] ^= 1;
            }
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            material::with_values(&xml, &prepared, &operation, |_, view| {
                timestamp::with_tokens(&xml, &prepared, &operation, |_, tokens| {
                    let carried = tokens.material_in(&operation).unwrap();
                    let provider = Oracle::new(mode);
                    let report = compare_reference_catalogues_with_tokens(
                        &xml,
                        &prepared,
                        &view,
                        &carried,
                        &provider,
                        &operation.execution(),
                    )
                    .unwrap();
                    let access = Access::new(&xml, xml.snapshot(), memory);
                    let held = memory.used();
                    let presence =
                        reference_presence(&report, &required, &counters, &access).unwrap();
                    assert_eq!(presence.rows().len(), 1);
                    assert!(presence.rows()[0].required());
                    assert_eq!(presence.rows()[0].failure(), expected);
                    assert_eq!(presence.all_required_present(), expected.is_none());
                    drop(presence);
                    assert_eq!(memory.used(), held);
                    assert_reference_presence_refusal(&report, &required, &counters, &xml);
                    let xml_only =
                        compare_reference_catalogues(&xml, &prepared, &view, &provider, memory)
                            .unwrap();
                    assert!(matches!(
                        reference_presence(&xml_only, &required, &counters, &access),
                        Err(ReferencePresenceError::Scope)
                    ));
                    Ok::<_, ()>(())
                })
                .unwrap();
                Ok::<_, ()>(())
            })
            .unwrap();
        }
    });
}

fn assert_reference_presence_refusal(
    report: &structured_xades::validation::ReferenceDigests<'_, '_, usize, u8, u8>,
    required: &structured_xades::timestamp::TimestampRequirements<usize, u8, u8>,
    counters: &structured_xades::pki::CounterPaths<'_, '_, usize, u8, u8>,
    xml: &Tree,
) {
    use structured_xades::validation::{ReferencePresenceError, reference_presence};
    let zero = structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 1 << 20),
    ));
    assert!(matches!(
        reference_presence(
            report,
            required,
            counters,
            &Access::new(xml, xml.snapshot(), &zero)
        ),
        Err(ReferencePresenceError::Resource(MemoryError::LimitExceeded))
    ));
    assert_eq!(zero.used(), 0);
    let zero = structured_asn1::memory::Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(1 << 20, 0),
    ));
    assert!(matches!(
        reference_presence(
            report,
            required,
            counters,
            &Access::new(xml, xml.snapshot(), &zero)
        ),
        Err(ReferencePresenceError::Access(AccessError::Resource {
            cause: MemoryError::WorkExceeded,
            ..
        }))
    ));
    assert_eq!(zero.used(), 0);
}

#[test]
fn reference_catalogue_rejects_foreign_token_pool_before_allocation_or_provider() {
    // Equal phase-local node/choice ordinals never join distinct documents.
    // Zero storage proves the foreign-pool guard precedes candidate/catalogue
    // growth; source refusal is not a successful empty token search.
    use structured_xades::{
        timestamp,
        validation::{ReferenceDigestError, compare_reference_catalogues_with_tokens},
    };
    with_checked_path(|_, leaf, _, memory| {
        let (_, token, _, _) = super::super::timestamp_oracle::fixture_with_root(b"covered");
        let (mut xml, _) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
        header_certificate(&mut xml, leaf);
        let (mut other, _) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
        other.document += 1;
        let encoded = other
            .nodes
            .iter()
            .position(|entry| {
                matches!(
                    entry.value,
                    super::super::Node::Element(Name {
                        namespace: XADES,
                        local: "EncapsulatedTimeStamp"
                    })
                )
            })
            .unwrap();
        other.binary_routes.push((encoded, token));
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let foreign = prepare::prepare(
            &Access::new(&other, other.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        material::with_values(&xml, &prepared, &operation, |_, view| {
            timestamp::with_tokens(&other, &foreign, &operation, |_, tokens| {
                let carried = tokens.material_in(&operation).unwrap();
                let provider = Oracle::new(Mode::Ready);
                let zero = structured_asn1::memory::Memory::new(std::sync::Arc::new(
                    structured_asn1::memory::MemoryAccount::new(0, 1 << 20),
                ));
                assert!(matches!(
                    compare_reference_catalogues_with_tokens(
                        &xml, &prepared, &view, &carried, &provider, &zero
                    ),
                    Err(binary::Error::Callback {
                        cause: ReferenceDigestError::Foreign,
                        ..
                    })
                ));
                assert_eq!(provider.started.get(), 0);
                assert_eq!(provider.finished.get(), 0);
                assert_eq!(zero.used(), 0);
                Ok::<_, ()>(())
            })
            .unwrap();
            Ok::<_, ()>(())
        })
        .unwrap();
    });
}

#[test]
fn reference_catalogues_include_token_certificates_crls_and_whole_ocsp_once() {
    // Inspection token metadata is not timestamp evidence. The comparison
    // must nevertheless search both original pools, hash WHOLE OCSP DER, keep
    // all duplicate certificate locations and finalize each exact value once.
    use structured_xades::{timestamp, validation::compare_reference_catalogues_with_tokens};
    with_checked_path(|_, leaf, _, memory| {
        let crl = super::super::readable_crl_fixture(b"260101000000Z");
        let ocsp = super::super::ocsp_material_with_certificate(leaf);
        let mut choices = crl.clone();
        choices.extend(super::super::carried_ocsp_choice(&ocsp));
        let token = super::super::inspection_token_with_carriage(&choices, leaf, 5);
        let (mut xml, _) = fixture(material::Kind::Certificate, leaf.to_vec(), true);
        header_certificate(&mut xml, leaf);
        let encoded = xml
            .nodes
            .iter()
            .position(|entry| {
                matches!(
                    entry.value,
                    super::super::Node::Element(Name {
                        namespace: XADES,
                        local: "EncapsulatedTimeStamp"
                    })
                )
            })
            .unwrap();
        xml.binary_routes.push((encoded, token));
        let refs = add(&mut xml, 7, XADES, "CompleteRevocationRefs");
        for (group, member, bytes) in [
            ("CRLRefs", "CRLRef", crl.as_slice()),
            ("OCSPRefs", "OCSPRef", ocsp.as_slice()),
        ] {
            let group_node = add(&mut xml, refs, XADES, group);
            let entry = add(&mut xml, group_node, XADES, member);
            if member == "OCSPRef" {
                let id = add(&mut xml, entry, XADES, "OCSPIdentifier");
                let responder = add(&mut xml, id, XADES, "ResponderID");
                add(&mut xml, responder, XADES, "ByKey");
                add(&mut xml, id, XADES, "ProducedAt");
            }
            let pair = add(&mut xml, entry, XADES, "DigestAlgAndValue");
            let method = add(&mut xml, pair, DS, "DigestMethod");
            xml.digest_algorithms.push((method, SHA256));
            let value = add(&mut xml, pair, DS, "DigestValue");
            xml.binary_routes
                .push((value, Sha256::digest(bytes).to_vec()));
        }
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), memory),
            0,
            unsigned::Requirements::Basic,
            None,
        )
        .unwrap();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        material::with_values(&xml, &prepared, &operation, |_, view| {
            timestamp::with_tokens(&xml, &prepared, &operation, |_, tokens| {
                let carried = tokens.material_in(&operation).unwrap();
                assert_eq!(carried.responses()[0].value.as_bytes(), ocsp);
                assert_ne!(
                    carried.responses()[0].value.as_bytes(),
                    carried.basic_responses()[0].value.as_bytes()
                );
                let provider = Oracle::new(Mode::Ready);
                let held = memory.used();
                let report = compare_reference_catalogues_with_tokens(
                    &xml,
                    &prepared,
                    &view,
                    &carried,
                    &provider,
                    &operation.execution(),
                )
                .unwrap();
                assert_token_reference_origins(&report);
                assert_eq!((provider.started.get(), provider.finished.get()), (3, 3));
                drop(report);
                assert_eq!(memory.used(), held);
                Ok::<_, ()>(())
            })
            .unwrap();
            Ok::<_, ()>(())
        })
        .unwrap();
    });
}

fn assert_token_reference_origins(
    report: &structured_xades::validation::ReferenceDigests<'_, '_, usize, u8, u8>,
) {
    use structured_xades::{material::ArtifactSource, timestamp::CarriedOrigin};
    assert_eq!(report.tokens().unwrap().len(), 1);
    assert_eq!(report.rows().len(), 3);
    let certificates = report.comparisons(0).unwrap();
    assert_eq!(certificates.len(), 4);
    assert!(
        certificates
            .iter()
            .all(|value| value.agreement() == Agreement::Matches)
    );
    assert_eq!(
        certificates[2].origin(),
        ArtifactSource::TokenCertificate {
            token: 0,
            certificate: 0
        }
    );
    assert_eq!(
        certificates[3].origin(),
        ArtifactSource::TokenRevocation(CarriedOrigin {
            token: 0,
            choice: 1
        })
    );
    assert_eq!(certificates[3].embedded_certificate(), Some(0));
    assert_eq!(certificates[2].source(), None);
    for (row, choice) in [(1, 0), (2, 1)] {
        let values = report.comparisons(row).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(
            values[0].origin(),
            ArtifactSource::TokenRevocation(CarriedOrigin { token: 0, choice })
        );
        assert_eq!(values[0].agreement(), Agreement::Matches);
    }
}

#[test]
fn external_path_artifacts_use_current_digest_kernel_without_fake_xml_sources() {
    // Optional references can identify an acquired anchor/list before a copy
    // is incorporated. Current queries hash original DER directly, preserving
    // the earlier parser's account and without constructing a material node.
    use structured_xades::validation::{ReferenceTarget, compare_reference_target};
    with_checked_path(|_, leaf, root, storage| {
        let origin = structured_asn1::Parser::der(storage.clone());
        let certificate = structured_pkix::Certificate::read(&origin, leaf, 100).unwrap();
        let other = structured_pkix::Certificate::read(&origin, root, 500).unwrap();
        let crl_bytes = super::super::readable_crl_fixture(b"260101000000Z");
        let crl = structured_pkix::crl::CertificateList::read(&origin, &crl_bytes, 700).unwrap();
        let ocsp_bytes = super::super::ocsp_material_with_certificate(leaf);
        let structured_pkix::ocsp::Response::Successful(response) =
            structured_pkix::ocsp::Response::read(&origin, &ocsp_bytes, 800).unwrap()
        else {
            panic!("successful envelope")
        };
        for kind in [
            material::Kind::Certificate,
            material::Kind::Crl,
            material::Kind::Ocsp,
        ] {
            let bytes = match kind {
                material::Kind::Certificate => leaf,
                material::Kind::Crl => crl_bytes.as_slice(),
                material::Kind::Ocsp => ocsp_bytes.as_slice(),
            };
            let (mut xml, source_node) = fixture(kind, bytes.to_vec(), true);
            // Remove the encapsulated payload route entirely: only original
            // DigestValue bytes remain. The queried target is the actual path input.
            xml.binary_routes.retain(|route| route.0 != source_node);
            let prepared = prepare::prepare(
                &Access::new(&xml, xml.snapshot(), storage),
                0,
                unsigned::Requirements::Basic,
                None,
            )
            .unwrap();
            let refs = &prepared.validation_references()[0];
            let query = funded();
            let parser = structured_asn1::Parser::der(query.clone());
            let operation = parser.read(&[], 900).unwrap();
            let provider = Oracle::new(Mode::Ready);
            let held = storage.used();
            let spent = storage.work_used();
            let target = match kind {
                material::Kind::Certificate => ReferenceTarget::Certificate(&certificate),
                material::Kind::Crl => ReferenceTarget::Crl(&crl),
                material::Kind::Ocsp => ReferenceTarget::Ocsp(&response),
            };
            assert_eq!(
                compare_reference_target(&xml, refs, 0, target, &provider, &operation.execution())
                    .unwrap(),
                ReferenceDigest::Compared(Agreement::Matches)
            );
            assert_eq!(storage.used(), held);
            assert_eq!(storage.work_used(), spent);
            assert_eq!(query.used(), 0);
            assert_eq!((provider.started.get(), provider.finished.get()), (1, 1));
            if kind == material::Kind::Certificate {
                assert_eq!(
                    compare_reference_target(
                        &xml,
                        refs,
                        0,
                        ReferenceTarget::Certificate(&other),
                        &provider,
                        &operation.execution()
                    )
                    .unwrap(),
                    ReferenceDigest::Compared(Agreement::Differs)
                );
                let starts = provider.started.get();
                assert_eq!(
                    compare_reference_target(
                        &xml,
                        refs,
                        0,
                        ReferenceTarget::Crl(&crl),
                        &provider,
                        &operation.execution()
                    )
                    .unwrap(),
                    ReferenceDigest::DifferentKind
                );
                assert_eq!(provider.started.get(), starts);
            }
        }
    });
}

#[test]
fn reference_digests_compare_whole_certificate_crl_and_ocsp_envelope_without_reencoding() {
    // Whole OCSPResponse bytes deliberately differ from BasicOCSPResponse.
    // All three comparisons reuse the actual shared SHA256 streaming driver.
    with_checked_path(|_, leaf, _, memory| {
        let ocsp = super::super::ocsp_material_with_certificate(leaf);
        for (kind, bytes) in [
            (material::Kind::Certificate, leaf.to_vec()),
            (
                material::Kind::Crl,
                super::super::readable_crl_fixture(b"260101000000Z"),
            ),
            (material::Kind::Ocsp, ocsp),
        ] {
            let (mut xml, node) = fixture(kind, bytes, true);
            let parser = structured_asn1::Parser::der(memory.clone());
            let operation = parser.read(&[], 900).unwrap();
            let source = material::retain(
                &xml,
                binary::Location {
                    snapshot: xml.snapshot(),
                    node,
                },
                kind,
                &operation,
            )
            .unwrap();
            // Successful PKIX structural decoding is independent of the digest.
            source.read_in(&operation).unwrap();
            let prepared = prepare::prepare(
                &Access::new(&xml, xml.snapshot(), memory),
                0,
                unsigned::Requirements::Basic,
                None,
            )
            .unwrap();
            let references = &prepared.validation_references()[0];
            let provider = Oracle::new(Mode::Ready);
            assert_eq!(
                compare_reference_digest(&xml, references, 0, &source, &provider, memory).unwrap(),
                ReferenceDigest::Compared(Agreement::Matches)
            );
            assert_eq!((provider.started.get(), provider.finished.get()), (1, 1));
            let value = references.entries()[0].digest().unwrap().1;
            xml.binary_routes
                .iter_mut()
                .find(|route| route.0 == value)
                .unwrap()
                .1[0] ^= 1;
            assert_eq!(
                compare_reference_digest(&xml, references, 0, &source, &provider, memory).unwrap(),
                ReferenceDigest::Compared(Agreement::Differs)
            );
        }
    });
}

#[test]
fn identifier_only_reference_never_fabricates_a_digest_match_or_provider_call() {
    // RFC/Annex A permits OCSPIdentifier without DigestAlgAndValue. Absence
    // is an outstanding identifier obligation, not a successful empty digest.
    let (xml, node) = fixture(material::Kind::Ocsp, vec![0x30, 0], false);
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let source = material::retain(
        &xml,
        binary::Location {
            snapshot: xml.snapshot(),
            node,
        },
        material::Kind::Ocsp,
        &operation,
    )
    .unwrap();
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), &memory),
        0,
        unsigned::Requirements::Basic,
        None,
    )
    .unwrap();
    let provider = Oracle::new(Mode::Ready);
    assert_eq!(
        compare_reference_digest(
            &xml,
            &prepared.validation_references()[0],
            0,
            &source,
            &provider,
            &memory
        )
        .unwrap(),
        ReferenceDigest::IdentifierOnly
    );
    assert_eq!((provider.resolved.get(), provider.started.get()), (0, 0));
}

#[test]
fn reference_digest_refusals_preserve_current_budget_cause_and_release_scratch() {
    // A retained original source gives no credit to a new query. Late provider
    // failure remains terminal at the original DigestValue, never Differs.
    use structured_xades::validation::ReferenceDigestError;
    let (xml, node) = fixture(material::Kind::Certificate, vec![0x30, 0], true);
    let original = funded();
    let parser = structured_asn1::Parser::der(original.clone());
    let operation = parser.read(&[], 900).unwrap();
    let source = material::retain(
        &xml,
        binary::Location {
            snapshot: xml.snapshot(),
            node,
        },
        material::Kind::Certificate,
        &operation,
    )
    .unwrap();
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), &original),
        0,
        unsigned::Requirements::Basic,
        None,
    )
    .unwrap();
    let references = &prepared.validation_references()[0];
    let value = references.entries()[0].digest().unwrap().1;
    let held = original.used();
    let paid = original.work_used();
    for (capacity, work) in [(0, 100_000), (100_000, 0)] {
        let query = structured_asn1::memory::Memory::new(std::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(capacity, work),
        ));
        let provider = Oracle::new(Mode::Ready);
        assert!(matches!(
            compare_reference_digest(&xml, references, 0, &source, &provider, &query),
            Err(binary::Error::Access { .. })
        ));
        assert_eq!(provider.started.get(), 0);
        assert_eq!(query.used(), 0);
        assert_eq!(original.used(), held);
        assert_eq!(original.work_used(), paid);
    }
    let query = funded();
    let provider = Oracle::new(Mode::RefuseUpdate);
    assert!(
        matches!(compare_reference_digest(&xml,references,0,&source,&provider,&query), Err(binary::Error::Callback {location, cause: ReferenceDigestError::Digest(digest::Error::Provider(Failure::Refused))}) if location.node == value)
    );
    assert_eq!((provider.started.get(), provider.finished.get()), (1, 0));
    assert_eq!(query.used(), 0);
    assert_eq!(original.used(), held);
    assert_eq!(original.work_used(), paid);
}

#[test]
fn reference_digest_rejects_foreign_material_and_invalid_ordinals_before_provider_work() {
    // Same account and identical original octets do not identify the same XML
    // source. A nonexistent ordinal is caller misuse, not malformed XML.
    use structured_xades::validation::ReferenceDigestError;
    let (xml, _) = fixture(material::Kind::Certificate, vec![0x30, 0], true);
    let (mut other, node) = fixture(material::Kind::Certificate, vec![0x30, 0], true);
    other.document = xml.document + 1;
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let source = material::retain(
        &other,
        binary::Location {
            snapshot: other.snapshot(),
            node,
        },
        material::Kind::Certificate,
        &operation,
    )
    .unwrap();
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), &memory),
        0,
        unsigned::Requirements::Basic,
        None,
    )
    .unwrap();
    let references = &prepared.validation_references()[0];
    let provider = Oracle::new(Mode::Ready);
    assert!(matches!(
        compare_reference_digest(&xml, references, 0, &source, &provider, &memory),
        Err(binary::Error::Callback {
            cause: ReferenceDigestError::Foreign,
            ..
        })
    ));
    let prepared_other = prepare::prepare(
        &Access::new(&other, other.snapshot(), &memory),
        0,
        unsigned::Requirements::Basic,
        None,
    )
    .unwrap();
    let absent = prepared_other.validation_references()[0].entries().len();
    assert!(
        matches!(compare_reference_digest(&other,&prepared_other.validation_references()[0],absent,&source,&provider,&memory), Err(binary::Error::Callback {cause: ReferenceDigestError::Index {index},..}) if index == absent)
    );
    assert_eq!((provider.resolved.get(), provider.started.get()), (0, 0));
}
