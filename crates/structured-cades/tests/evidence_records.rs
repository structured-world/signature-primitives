//! Real CMS/TSA signatures drive initial ERS and BOTH renewal mechanisms.

#[path = "support/crl.rs"]
mod crl_fixture;
mod support;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use std::{cell::Cell, convert::Infallible};
use structured_asn1::{Parser, Reader, memory::Work};
use structured_cms::{
    evidence::{
        ArchiveTimeStamp, EvidenceRecord, Membership,
        verify::{Authorities, Decision, Selection},
    },
    oid,
    stream::{Receiver, Refused, Source},
};
use structured_pkix::{
    Certificate,
    path::WorkingKey,
    temporal::{Instant, LeapTable},
};
use support::{Oracle, certificate, memory, message, signer, tlv};

fn token(input: &[u8], cert: &[u8], root: &[u8], key: &SigningKey, second: u8) -> Vec<u8> {
    let mut time = *b"20260101000100Z";
    time[12] = b'0' + second / 10;
    time[13] = b'0' + second % 10;
    token_at(input, cert, root, key, &time, true, false)
}
fn token_at(
    input: &[u8],
    cert: &[u8],
    root: &[u8],
    key: &SigningKey,
    time: &[u8],
    accuracy: bool,
    ordering: bool,
) -> Vec<u8> {
    let mut unique = Sha256::new();
    unique.update(input);
    unique.update(time);
    let mut serial = unique.finalize()[..8].to_vec();
    serial[0] = (serial[0] & 0x7f) | 1;
    let mut fields = [
        vec![2, 1, 1],
        tlv(6, &[42, 3]),
        tlv(
            0x30,
            &[
                tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
                tlv(4, &Sha256::digest(input)),
            ]
            .concat(),
        ),
        tlv(2, &serial),
        tlv(24, time),
    ]
    .concat();
    if accuracy {
        fields.extend(tlv(0x30, &[]));
    }
    if ordering {
        fields.extend(tlv(1, &[255]));
    }
    let info = tlv(0x30, &fields);
    let signed = signer(Some(oid::TST_INFO.as_bytes()), &info, cert, key, &[], &[]);
    assert_ne!(support::signature_octets(&signed), [] as [u8; 0]);
    message(
        oid::TST_INFO.as_bytes(),
        Some(&info),
        &[root.to_vec(), cert.to_vec()],
        &[],
        &[signed],
    )
}

#[test]
fn same_tsa_ordering_assertion_uses_exact_fraction_without_fabricating_accuracy() {
    // RFC3161 §2.4.2 permits same-TSA ordering independently of accuracy.
    // Distinct subnanosecond digits must not collapse to the same rounded label.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let tsa = certificate("TSA", "Root", &tsa_key, &root_key, true);
    for (left, right, ordered, positive) in [
        (
            b"20260101000100.0000000001Z".as_slice(),
            b"20260101000100.0000000002Z".as_slice(),
            true,
            true,
        ),
        (
            b"20260101000100.0000000002Z".as_slice(),
            b"20260101000100.0000000001Z".as_slice(),
            true,
            false,
        ),
        (
            b"20260101000100.0000000001Z".as_slice(),
            b"20260101000100.0000000002Z".as_slice(),
            false,
            false,
        ),
    ] {
        let first = token_at(b"data", &tsa, &root, &tsa_key, left, false, ordered);
        let second = token_at(&first, &tsa, &root, &tsa_key, right, false, ordered);
        let encoded = record(&[tlv(0x30, &[stamp(&first), stamp(&second)].concat())]);
        let parser = Parser::ber(memory());
        let mut parent = parser.read(&encoded, 700).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let parsed = EvidenceRecord::read(&parent, &element).unwrap();
        let cert_parser = Parser::der(memory());
        let cert = Certificate::read(&cert_parser, &tsa, 0).unwrap();
        let cert_parent = cert_parser.read(&[], 0).unwrap();
        let authority = Authority {
            certificate: &cert,
            parent: &cert_parent,
        };
        let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
        let mut sources = [Object {
            bytes: b"data",
            passes: Cell::new(0),
        }];
        let provider = Oracle::new();
        let report = parsed
            .verify(
                &provider,
                &parent,
                &authority,
                &utc,
                Instant::new(1_767_312_000, 0).unwrap(),
                &mut sources,
                Membership::Object,
                |_, _, _| Ok::<_, Infallible>(true),
                |_, _| Ok::<_, Infallible>(Decision::Valid),
            )
            .unwrap();
        assert_eq!(
            report.verified().is_some(),
            positive,
            "ordering={:?}; timeliness={:?}; evidence={:?}",
            report.ordering(),
            report
                .checks()
                .map(|check| check.timestamp().timeliness)
                .collect::<Vec<_>>(),
            report
                .checks()
                .map(|check| check.timestamp().evidence().is_some())
                .collect::<Vec<_>>()
        );
        assert_eq!(sources[0].passes.get(), 1);
        assert_eq!(provider.signatures.get(), 2);
    }
}
fn stamp(token: &[u8]) -> Vec<u8> {
    tlv(0x30, token)
}
fn record(chains: &[Vec<u8>]) -> Vec<u8> {
    tlv(
        0x30,
        &[
            vec![2, 1, 1],
            tlv(0x30, &tlv(0x30, &tlv(6, oid::SHA256.as_bytes()))),
            tlv(0x30, &chains.concat()),
        ]
        .concat(),
    )
}

#[test]
fn poe_extras_keep_original_models_placements_and_disjoint_material_slots() {
    // Extra material remains an untrusted individual artifact, not a fake root
    // CHOICE, TSA carrier or whole-PoE coverage claim. Exact duplicate copies
    // retain BOTH original locations without reparsing certificates.
    use structured_cades::material::{Placement, Pool};
    use structured_ltv::{
        material::ArtifactSource,
        source::{Scope, Source as _},
    };
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let leaf = certificate("Leaf", "Root", &key, &root_key, false);
    let crl = crl_fixture::crl(&root_key);
    let value = tlv(
        0x30,
        &[
            tlv(24, b"20260101000200Z"),
            tlv(0xa0, &leaf),
            tlv(0xa1, &crl),
        ]
        .concat(),
    );
    let attr = support::attribute(&[4, 0, 0x8d, 0x45, 2, 2], &value);
    let signed = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &leaf,
        &key,
        &[],
        &[attr],
    );
    let bytes = message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[root, leaf.clone()],
        &[crl],
        &[signed],
    );
    let parser = Parser::ber(memory());
    let message = structured_cms::SignedData::read(&parser, &bytes, 700).unwrap();
    let parent = parser.read(&[], 700).unwrap();
    let document = structured_cades::source::Document::new(&message, &parent).unwrap();
    let prepared = structured_cades::prepare::Preparation::read(
        &document,
        &message.signers()[0],
        structured_cades::Level::Basic,
        &parent,
    )
    .unwrap();
    let view = prepared.evidence(0, &parent).unwrap().unwrap();
    let poe = view.poe().unwrap();
    assert!(poe.proof().is_none());
    let extra = &poe.certificates().unwrap().certificates()[0];
    let pool = Pool::read(&prepared, &parent).unwrap();
    assert_eq!(pool.crls(), 2);
    let work = parent.execution();
    let query = Scope::new(&document, document.snapshot(), &work);
    let index = pool.index(&query).unwrap();
    let copies = index
        .certificate(extra, &query)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(copies.len(), 2);
    assert!(
        copies
            .iter()
            .any(|copy| matches!(copy.placement(), Placement::RootCertificate(_)))
    );
    let incorporated = copies
        .iter()
        .find(|copy| matches!(copy.placement(), Placement::PoeCertificate(_)))
        .unwrap();
    assert_eq!(incorporated.location().node.span(), extra.span());
    assert_ne!(incorporated.location().node.span(), poe.element().span());
    assert!(
        matches!(incorporated.source(),ArtifactSource::Material(ordinal) if ordinal>=message.certificate_choices().len()+message.revocations().len())
    );
    let stored_crl = pool.crl(1, &work).unwrap().unwrap();
    let copies = index
        .crl(stored_crl, &query)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(copies.len(), 2);
    assert!(
        copies
            .iter()
            .any(|copy| matches!(copy.placement(), Placement::RootRevocation(_)))
    );
    assert!(
        copies
            .iter()
            .any(|copy| matches!(copy.placement(), Placement::PoeRevocation(_)))
    );
    assert!(pool.open().is_empty());
    assert_eq!(
        prepared.timestamps().len(),
        0,
        "extra material alone cannot invent a proof/TSA"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "One live source/receipt graph exercises sequential PoE, ERS, snapshot, external and counter transitions without recreating or cloning qualified facts."
)]
fn internal_record_reuses_checked_paths_and_exact_tokens_without_rechecking_crypto() {
    // Whole-CMS AppendixA binding must issue actors from the SAME successful
    // ERS checks, with signed ESS restrictions on the actual checked TSA path.
    use structured_ltv::pki::{self, CheckedPath, PathOutcome};
    use structured_pkix::path::{self, Anchor, Interval, ValidationBounds, ValidationContext};
    struct Paths<'p, 'd> {
        path: &'p CheckedPath<'d>,
        parent: &'p Reader<'d>,
        selections: Cell<usize>,
    }
    impl<'d> structured_cades::evidence::Authorities<'d> for Paths<'_, 'd> {
        type Error = Infallible;
        fn select<'p, W: Work>(
            &'p self,
            _: usize,
            _: &structured_cms::timestamp::Token<'d>,
            _: &W,
        ) -> Result<structured_cades::evidence::Authority<'p, 'd>, Infallible>
        where
            'd: 'p,
        {
            self.selections.set(self.selections.get() + 1);
            Ok(structured_cades::evidence::Authority {
                path: self.path,
                certificate_parent: self.parent,
            })
        }
    }
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let leaf = certificate("Leaf", "Root", &key, &root_key, false);
    let tsa = certificate("TSA", "Root", &tsa_key, &root_key, true);
    let plain = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &leaf,
        &key,
        &[],
        &[],
    );
    let original = message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[root.clone(), leaf.clone()],
        &[],
        std::slice::from_ref(&plain),
    );
    let first = token(&original, &tsa, &root, &tsa_key, 0);
    let second = token(&first, &tsa, &root, &tsa_key, 10);
    let evidence = record(&[tlv(0x30, &[stamp(&first), stamp(&second)].concat())]);
    let attribute = support::attribute(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 49], &evidence);
    let augmented = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &leaf,
        &key,
        &[],
        &[attribute],
    );
    let bytes = message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[root.clone(), leaf.clone()],
        &[],
        &[augmented],
    );
    let parser = Parser::ber(memory());
    let message = structured_cms::SignedData::read(&parser, &bytes, 700).unwrap();
    let mut parent = parser.read(&bytes, 700).unwrap();
    let envelope = parent.next_element().unwrap().unwrap();
    let document = structured_cades::source::Document::new(&message, &parent).unwrap();
    let prepared = structured_cades::prepare::Preparation::read(
        &document,
        &message.signers()[0],
        structured_cades::Level::Basic,
        &parent,
    )
    .unwrap();
    let view = prepared.evidence(0, &parent).unwrap().unwrap();
    let cert_parser = Parser::der(memory());
    let root_cert = Certificate::read(&cert_parser, &root, 0).unwrap();
    let tsa_cert = Certificate::read(&cert_parser, &tsa, 500).unwrap();
    let cert_parent = cert_parser.read(&[], 0).unwrap();
    let path_work = cert_parent.execution();
    let path_verifier = Oracle::new();
    let context = ValidationContext {
        execution: &path_work,
        interval: Interval::at(tsa_cert.tbs().validity().not_before().seconds()),
        policy: path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &path_verifier,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(path) =
        pki::check_path(&[&tsa_cert], Anchor::from_certificate(&root_cert), &context).unwrap()
    else {
        panic!("real P256 TSA path");
    };
    let authorities = Paths {
        path: &path,
        parent: &cert_parent,
        selections: Cell::new(0),
    };
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    for decision in [Decision::Valid, Decision::Unknown, Decision::Invalid] {
        let provider = Oracle::new();
        let checked = view
            .check_internal(
                envelope,
                &provider,
                &parent,
                &authorities,
                &utc,
                Instant::new(1_767_312_000, 0).unwrap(),
                |_, _, _| Ok::<_, Infallible>(true),
                |_, _| Ok::<_, Infallible>(decision),
            )
            .unwrap();
        assert_eq!(checked.verified().is_some(), decision == Decision::Valid);
        assert_eq!(checked.checks().len(), 2);
        assert!(checked.checks().all(|check| check.actor().is_some()));
        assert_eq!(
            provider.signatures.get(),
            2,
            "actor creation must not recheck the TSA signature"
        );
        if let Some(receipt) = checked.verified() {
            assert_eq!(receipt.timestamps(), 0..2);
            assert_eq!(receipt.required().property, view.required().property);
            assert!(std::ptr::eq(receipt.prepared(), &raw const prepared));
            let pool = structured_cades::material::Pool::read(&prepared, &parent).unwrap();
            let work = parent.execution();
            let query = structured_ltv::source::Scope::new(
                &document,
                structured_ltv::source::Source::snapshot(&document),
                &work,
            );
            let index = pool.index(&query).unwrap();
            for ordinal in receipt.timestamps() {
                let archive = receipt.archive(ordinal, &index, &parent).unwrap();
                let actor = archive.timestamp().actor().unwrap();
                for occurrence in index.all_occurrences(&query).unwrap() {
                    let occurrence = occurrence.unwrap();
                    let expected = match occurrence.placement() {
                        structured_cades::material::Placement::RootCertificate(_) => true,
                        structured_cades::material::Placement::TokenCertificate {
                            token, ..
                        } => token < ordinal,
                        other => panic!("unexpected placement {other:?}"),
                    };
                    assert_eq!(
                        archive
                            .coverage()
                            .covers(actor.verified(), occurrence.location().node, &query)
                            .unwrap(),
                        expected,
                        "ordinal={ordinal}, copy={:?}",
                        occurrence.placement()
                    );
                }
                let requirements = archive.requirements(&parent).unwrap();
                // An ERS attribute contains several distinct TSAs. Material
                // scopes must identify THIS token, so an older empty-credential
                // report cannot replace a later token's different census.
                assert_eq!(
                    requirements.scope().location().node,
                    actor.verified().token().node
                );
                assert_eq!(requirements.entries().len(), ordinal);
                assert!(pool.index_for_archive((&archive).into(), &query).is_ok());
            }
        }
    }
    // Both PoE alternatives use the same eight-component input and the SAME
    // path/profile/common check. ERS renewals cover original preceding token
    // bytes; PoE metadata date is intentionally different from genTime.
    let parsed_plain = Parser::ber(memory());
    let mut original_signer = parsed_plain.read(&plain, 0).unwrap();
    let plain_element = original_signer.next_element().unwrap().unwrap();
    let plain_model =
        structured_cms::signer::SignerInfo::read(&original_signer, &plain_element).unwrap();
    let mut material_hashes = [
        Sha256::digest(&root).to_vec(),
        Sha256::digest(&leaf).to_vec(),
    ];
    material_hashes.sort();
    let identity = [
        vec![2, 1, 1],
        tlv(0x30, &[support::name("Root"), vec![2, 1, 7]].concat()),
        tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
    ]
    .concat();
    let signature = [
        tlv(0x30, &tlv(6, support::ECDSA)),
        tlv(4, &support::signature_octets(&plain)),
    ]
    .concat();
    let empty = Sha256::digest([]).to_vec();
    let eight = [
        Sha256::digest(tlv(6, oid::DATA.as_bytes())).to_vec(),
        Sha256::digest(b"payload").to_vec(),
        Sha256::digest(material_hashes.concat()).to_vec(),
        empty.clone(),
        Sha256::digest(identity).to_vec(),
        Sha256::digest(
            plain_model
                .signed_attributes()
                .unwrap()
                .signed_bytes()
                .unwrap()
                .concat(),
        )
        .to_vec(),
        Sha256::digest(signature).to_vec(),
        empty,
    ]
    .concat();
    for record_proof in [false, true] {
        let mut proof_eight = eight.clone();
        if !record_proof {
            let mut hashes = [
                Sha256::digest(&root).to_vec(),
                Sha256::digest(&leaf).to_vec(),
                Sha256::digest(&leaf).to_vec(),
            ];
            hashes.sort();
            proof_eight[2 * 32..3 * 32].copy_from_slice(&Sha256::digest(hashes.concat()));
        }
        let first = token(&proof_eight, &tsa, &root, &tsa_key, 0);
        let proof = if record_proof {
            let second = token(&first, &tsa, &root, &tsa_key, 10);
            tlv(
                0xa1,
                &record(&[tlv(0x30, &[stamp(&first), stamp(&second)].concat())]),
            )
        } else {
            tlv(0xa0, &first)
        };
        let extras = if record_proof {
            Vec::new()
        } else {
            tlv(0xa0, &leaf)
        };
        let poe = tlv(0x30, &[tlv(24, b"20260101000200Z"), proof, extras].concat());
        let attribute = support::attribute(&[4, 0, 0x8d, 0x45, 2, 2], &poe);
        let augmented = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &leaf,
            &key,
            &[],
            &[attribute],
        );
        let bytes = support::message(
            oid::DATA.as_bytes(),
            Some(b"payload"),
            &[root.clone(), leaf.clone()],
            &[],
            &[augmented],
        );
        let parser = Parser::ber(memory());
        let message = structured_cms::SignedData::read(&parser, &bytes, 700).unwrap();
        let parent = parser.read(&[], 700).unwrap();
        let document = structured_cades::source::Document::new(&message, &parent).unwrap();
        let prepared = structured_cades::prepare::Preparation::read(
            &document,
            &message.signers()[0],
            structured_cades::Level::Basic,
            &parent,
        )
        .unwrap();
        let view = prepared.evidence(0, &parent).unwrap().unwrap();
        for decision in [Decision::Valid, Decision::Unknown, Decision::Invalid] {
            let provider = Oracle::new();
            let checked = view
                .check_poe(
                    &provider,
                    &parent,
                    &authorities,
                    &utc,
                    Instant::new(1_767_312_000, 0).unwrap(),
                    None::<&mut structured_cades::timestamp::NoDetached>,
                    |_, _, _| Ok::<_, Infallible>(true),
                    |_, _| Ok::<_, Infallible>(decision),
                )
                .unwrap();
            assert_eq!(
                checked.verified().is_some(),
                decision == Decision::Valid,
                "record={record_proof}"
            );
            assert_eq!(checked.checks().len(), if record_proof { 2 } else { 1 });
            assert!(checked.checks().all(|check| check.actor().is_some()));
            assert_eq!(
                provider.signatures.get(),
                if record_proof { 2 } else { 1 },
                "one signature check per actual TSA"
            );
            let calls = Cell::new(0);
            let closed = structured_cades::evidence::close_preservation(
                &prepared,
                &[&checked],
                &parent,
                &utc,
                Instant::new(1_767_312_000, 0).unwrap(),
                |history, _| {
                    assert!(history.following.is_none());
                    calls.set(calls.get() + 1);
                    Ok::<_, Infallible>(Decision::Valid)
                },
            );
            assert_eq!(closed.is_ok(), decision == Decision::Valid);
            assert_eq!(calls.get(), usize::from(decision == Decision::Valid));
            if let Ok(closed) = closed {
                assert!(
                    closed
                        .contains(&view.required(), &parent.execution())
                        .unwrap()
                );
            }
            if let Some(receipt) = checked.verified() {
                let pool = structured_cades::material::Pool::read(&prepared, &parent).unwrap();
                let work = parent.execution();
                let query = structured_ltv::source::Scope::new(
                    &document,
                    structured_ltv::source::Source::snapshot(&document),
                    &work,
                );
                let index = pool.index(&query).unwrap();
                for ordinal in receipt.timestamps() {
                    let archive = receipt.archive(ordinal, &index, &parent).unwrap();
                    let actor = archive.timestamp().actor().unwrap();
                    for occurrence in index.all_occurrences(&query).unwrap() {
                        let occurrence = occurrence.unwrap();
                        let expected = match occurrence.placement() {
                            structured_cades::material::Placement::RootCertificate(_)
                            | structured_cades::material::Placement::PoeCertificate(_) => true,
                            structured_cades::material::Placement::TokenCertificate {
                                token,
                                ..
                            } => token < ordinal,
                            other => panic!("unexpected placement {other:?}"),
                        };
                        assert_eq!(
                            archive
                                .coverage()
                                .covers(actor.verified(), occurrence.location().node, &query)
                                .unwrap(),
                            expected,
                            "record={record_proof}, ordinal={ordinal}, copy={:?}",
                            occurrence.placement()
                        );
                    }
                    assert_eq!(
                        archive.requirements(&parent).unwrap().entries().len(),
                        ordinal
                    );
                    assert!(pool.index_for_archive((&archive).into(), &query).is_ok());
                }
            }
        }
    }
    // Full PoE closure is independent of wire SET ordering. The later proof
    // protects the WHOLE earlier attribute in Hu, and historical callbacks run
    // reverse chronologically with that actual authenticated following proof.
    let old_token = token(&eight, &tsa, &root, &tsa_key, 0);
    let old_attr = support::attribute(
        &[4, 0, 0x8d, 0x45, 2, 2],
        &tlv(
            0x30,
            &[tlv(24, b"20260101000200Z"), tlv(0xa0, &old_token)].concat(),
        ),
    );
    let mut next_eight = eight[..7 * 32].to_vec();
    next_eight.extend(Sha256::digest(Sha256::digest(&old_attr)));
    let next_token = token(&next_eight, &tsa, &root, &tsa_key, 20);
    let next_attr = support::attribute(
        &[4, 0, 0x8d, 0x45, 2, 2],
        &tlv(
            0x30,
            &[tlv(24, b"20260101000300Z"), tlv(0xa0, &next_token)].concat(),
        ),
    );
    let augmented = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &leaf,
        &key,
        &[],
        &[next_attr, old_attr],
    );
    let poe_bytes = support::message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[root.clone(), leaf.clone()],
        &[],
        &[augmented],
    );
    let poe_parser = Parser::ber(memory());
    let poe_message = structured_cms::SignedData::read(&poe_parser, &poe_bytes, 700).unwrap();
    let poe_parent = poe_parser.read(&[], 700).unwrap();
    let poe_document = structured_cades::source::Document::new(&poe_message, &poe_parent).unwrap();
    let poe_prepared = structured_cades::prepare::Preparation::read(
        &poe_document,
        &poe_message.signers()[0],
        structured_cades::Level::Basic,
        &poe_parent,
    )
    .unwrap();
    let provider = Oracle::new();
    let mut checked = Vec::new();
    for ordinal in 0..poe_prepared.evidence_records() {
        checked.push(
            poe_prepared
                .evidence(ordinal, &poe_parent)
                .unwrap()
                .unwrap()
                .check_poe(
                    &provider,
                    &poe_parent,
                    &authorities,
                    &utc,
                    Instant::new(1_767_312_000, 0).unwrap(),
                    None::<&mut structured_cades::timestamp::NoDetached>,
                    |_, _, _| Ok::<_, Infallible>(true),
                    |_, _| Ok::<_, Infallible>(Decision::Valid),
                )
                .unwrap(),
        );
    }
    assert_eq!(provider.signatures.get(), 2);
    let calls = Cell::new(0);
    let reference = Instant::new(1_767_312_000, 0).unwrap();
    let close = |proofs: &[&structured_cades::evidence::RecordChecked<'_, '_, '_, '_>]| {
        structured_cades::evidence::close_preservation(
            &poe_prepared,
            proofs,
            &poe_parent,
            &utc,
            reference,
            |history, _| {
                assert_eq!(history.following.is_some(), calls.get() == 1);
                calls.set(calls.get() + 1);
                Ok::<_, Infallible>(Decision::Valid)
            },
        )
        .map(|closed| closed.records().len())
    };
    assert!(
        close(&[&checked[0]]).is_err(),
        "a successful prefix cannot erase another PoE"
    );
    assert_eq!(
        calls.get(),
        0,
        "the complete census precedes historical callbacks"
    );
    let count = close(&[&checked[1], &checked[0]]).unwrap();
    assert_eq!(count, 2);
    assert_eq!(calls.get(), 2);
    assert_eq!(
        provider.signatures.get(),
        2,
        "closure does not replay cryptography"
    );
    // An AnnexB ERS appended AFTER a legacy PoE is first authenticated over
    // that entire PoE. Only its sealed coverage authorizes excluding the new
    // ERS attribute when replaying the older Hu (EN319122-1 §5.5.3).
    let old_token = token(&eight, &tsa, &root, &tsa_key, 0);
    let old_attr = support::attribute(
        &[4, 0, 0x8d, 0x45, 2, 2],
        &tlv(
            0x30,
            &[tlv(24, b"20260101000200Z"), tlv(0xa0, &old_token)].concat(),
        ),
    );
    let before_signer = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &leaf,
        &key,
        &[],
        std::slice::from_ref(&old_attr),
    );
    let before = support::message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[root.clone(), leaf.clone()],
        &[],
        &[before_signer],
    );
    let next_token = token(&before, &tsa, &root, &tsa_key, 20);
    let next_record = record(&[tlv(0x30, &stamp(&next_token))]);
    let next_attr = support::attribute(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 49], &next_record);
    let final_signer = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &leaf,
        &key,
        &[],
        &[old_attr, next_attr],
    );
    let mixed_bytes = support::message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[root.clone(), leaf.clone()],
        &[],
        &[final_signer],
    );
    let mixed_parser = Parser::ber(memory());
    let mixed_message = structured_cms::SignedData::read(&mixed_parser, &mixed_bytes, 700).unwrap();
    let mut mixed_parent = mixed_parser.read(&mixed_bytes, 700).unwrap();
    let mixed_envelope = mixed_parent.next_element().unwrap().unwrap();
    let mixed_document =
        structured_cades::source::Document::new(&mixed_message, &mixed_parent).unwrap();
    let mixed_prepared = structured_cades::prepare::Preparation::read(
        &mixed_document,
        &mixed_message.signers()[0],
        structured_cades::Level::Basic,
        &mixed_parent,
    )
    .unwrap();
    let mut old_view = None;
    let mut next_view = None;
    for ordinal in 0..mixed_prepared.evidence_records() {
        let view = mixed_prepared
            .evidence(ordinal, &mixed_parent)
            .unwrap()
            .unwrap();
        if view.poe().is_some() {
            old_view = Some(view);
        } else {
            next_view = Some(view);
        }
    }
    let old_view = old_view.unwrap();
    let next_view = next_view.unwrap();
    let provider = Oracle::new();
    let newer = next_view
        .check_internal(
            mixed_envelope,
            &provider,
            &mixed_parent,
            &authorities,
            &utc,
            reference,
            |_, _, _| Ok::<_, Infallible>(true),
            |_, _| Ok::<_, Infallible>(Decision::Valid),
        )
        .unwrap();
    let newer_receipt = newer.verified().unwrap();
    let pool = structured_cades::material::Pool::read(&mixed_prepared, &mixed_parent).unwrap();
    let work = mixed_parent.execution();
    let query = structured_ltv::source::Scope::new(
        &mixed_document,
        structured_ltv::source::Source::snapshot(&mixed_document),
        &work,
    );
    let index = pool.index(&query).unwrap();
    let archive = newer_receipt
        .archive(newer_receipt.timestamps().start, &index, &mixed_parent)
        .unwrap();
    let later = structured_cades::timestamp::historical::Later::record(&archive).unwrap();
    let older = old_view
        .check_poe_with_later(
            &provider,
            &mixed_parent,
            &authorities,
            &utc,
            reference,
            None::<&mut structured_cades::timestamp::NoDetached>,
            &[later],
            |_, _, _| Ok::<_, Infallible>(true),
            |_, _| Ok::<_, Infallible>(Decision::Valid),
        )
        .unwrap();
    assert!(older.verified().is_some());
    assert_eq!(provider.signatures.get(), 2);
    let calls = Cell::new(0);
    let closed = structured_cades::evidence::close_preservation(
        &mixed_prepared,
        &[&older, &newer],
        &mixed_parent,
        &utc,
        reference,
        |history, _| {
            assert_eq!(history.following.is_some(), calls.get() == 1);
            calls.set(calls.get() + 1);
            Ok::<_, Infallible>(Decision::Valid)
        },
    )
    .unwrap();
    assert_eq!(closed.records().len(), 2);
    assert_eq!(
        closed.records()[0].verified().unwrap().required().kind,
        structured_cades::preservation::Kind::LongTermValidation
    );
    // Retained receipts do not prepay a new operation. Both storage and work
    // refusal must be terminal before history, release partial output, and
    // leave the original source/receipt allocations unchanged.
    let retained = mixed_parent.memory().used();
    for (capacity, allowance) in [(0, 1_000_000), (1_000_000, 0)] {
        let query_memory = structured_asn1::memory::Memory::new(std::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(capacity, allowance),
        ));
        let query = mixed_parser
            .read(&mixed_bytes, 700)
            .unwrap()
            .with_execution(&query_memory);
        let histories = Cell::new(0);
        let failure = structured_cades::evidence::close_preservation(
            &mixed_prepared,
            &[&older, &newer],
            &query,
            &utc,
            reference,
            |_, _| {
                histories.set(histories.get() + 1);
                Ok::<_, Infallible>(Decision::Valid)
            },
        )
        .err()
        .expect("current operation must fund closure");
        let structured_cades::evidence::ClosureError::Processing(cause) = failure else {
            panic!("resource refusal cannot become an unproven or partial result");
        };
        assert!(cause.is_terminal());
        assert!(cause.offset() >= 700);
        assert_eq!(histories.get(), 0);
        assert_eq!(query_memory.used(), 0);
        assert_eq!(mixed_parent.memory().used(), retained);
        assert!(older.verified().is_some());
        assert!(newer.verified().is_some());
    }
    // A previous ContentInfo may have used genuine indefinite BER framing
    // which is no longer recoverable from the final definite container. A
    // source-bound snapshot preserves it, while altered signed fields refuse
    // BEFORE discovery or any provider/source callbacks.
    let prior_parser = Parser::ber(memory());
    let mut prior_reader = prior_parser.read(&original, 23).unwrap();
    let original_element = prior_reader.next_element().unwrap().unwrap();
    let prior_bytes = [
        vec![0x30, 0x80],
        original_element.contents().to_vec(),
        vec![0, 0],
    ]
    .concat();
    let prior_model = structured_cms::SignedData::read(&prior_parser, &prior_bytes, 23).unwrap();
    let mut prior_reader = prior_parser.read(&prior_bytes, 23).unwrap();
    let prior_envelope = prior_reader.next_element().unwrap().unwrap();
    let snapshot = structured_cades::evidence::CmsSnapshot::capture(
        &prior_model,
        prior_envelope,
        &prior_reader,
    )
    .unwrap();
    let proof = token(&prior_bytes, &tsa, &root, &tsa_key, 0);
    let evidence = record(&[tlv(0x30, &stamp(&proof))]);
    let attribute = support::attribute(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 49], &evidence);
    let augmented = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &leaf,
        &key,
        &[],
        std::slice::from_ref(&attribute),
    );
    let snapshot_bytes = support::message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[root.clone(), leaf.clone()],
        &[],
        &[augmented],
    );
    let snapshot_parser = Parser::ber(memory());
    let snapshot_message =
        structured_cms::SignedData::read(&snapshot_parser, &snapshot_bytes, 700).unwrap();
    let mut snapshot_parent = snapshot_parser.read(&snapshot_bytes, 700).unwrap();
    let snapshot_envelope = snapshot_parent.next_element().unwrap().unwrap();
    let snapshot_document =
        structured_cades::source::Document::new(&snapshot_message, &snapshot_parent).unwrap();
    let snapshot_prepared = structured_cades::prepare::Preparation::read(
        &snapshot_document,
        &snapshot_message.signers()[0],
        structured_cades::Level::Basic,
        &snapshot_parent,
    )
    .unwrap();
    let view = snapshot_prepared
        .evidence(0, &snapshot_parent)
        .unwrap()
        .unwrap();
    let provider = Oracle::new();
    let checked = view
        .check_internal_snapshot(
            snapshot_envelope,
            &snapshot,
            &provider,
            &snapshot_parent,
            &authorities,
            &utc,
            reference,
            |_, _, _| Ok::<_, Infallible>(true),
            |_, _| Ok::<_, Infallible>(Decision::Valid),
        )
        .unwrap();
    assert!(checked.verified().is_some());
    assert_eq!(provider.signatures.get(), 1);
    let changed = signer(
        Some(oid::DATA.as_bytes()),
        b"changed",
        &leaf,
        &key,
        &[],
        &[attribute],
    );
    let changed_bytes = support::message(
        oid::DATA.as_bytes(),
        Some(b"changed"),
        &[root.clone(), leaf.clone()],
        &[],
        &[changed],
    );
    let changed_parser = Parser::ber(memory());
    let changed_message =
        structured_cms::SignedData::read(&changed_parser, &changed_bytes, 700).unwrap();
    let mut changed_parent = changed_parser.read(&changed_bytes, 700).unwrap();
    let changed_envelope = changed_parent.next_element().unwrap().unwrap();
    let changed_document =
        structured_cades::source::Document::new(&changed_message, &changed_parent).unwrap();
    let changed_prepared = structured_cades::prepare::Preparation::read(
        &changed_document,
        &changed_message.signers()[0],
        structured_cades::Level::Basic,
        &changed_parent,
    )
    .unwrap();
    let changed_view = changed_prepared
        .evidence(0, &changed_parent)
        .unwrap()
        .unwrap();
    let selections = authorities.selections.get();
    let provider = Oracle::new();
    assert!(
        changed_view
            .check_internal_snapshot(
                changed_envelope,
                &snapshot,
                &provider,
                &changed_parent,
                &authorities,
                &utc,
                reference,
                |_, _, _| Ok::<_, Infallible>(true),
                |_, _| Ok::<_, Infallible>(Decision::Valid)
            )
            .is_err()
    );
    assert_eq!(authorities.selections.get(), selections);
    assert_eq!(provider.signatures.get(), 0);
    // RFC4998 AppendixA external selection protects exactly TWO objects:
    // original detached ContentInfo and the actual separate content. Their
    // sorted full hashes are one document group; payload is streamed once.
    let external_before = support::message(
        oid::DATA.as_bytes(),
        None,
        &[root.clone(), leaf.clone()],
        &[],
        std::slice::from_ref(&plain),
    );
    let mut members = [
        Sha256::digest(&external_before).to_vec(),
        Sha256::digest(b"payload").to_vec(),
    ];
    members.sort();
    let external_token = token(&members.concat(), &tsa, &root, &tsa_key, 0);
    let hashes = members
        .iter()
        .map(|hash| tlv(4, hash))
        .collect::<Vec<_>>()
        .concat();
    let external_stamp = tlv(
        0x30,
        &[tlv(0xa2, &tlv(0x30, &hashes)), external_token].concat(),
    );
    let external_record = record(&[tlv(0x30, &external_stamp)]);
    let external_attribute = support::attribute(
        &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 50],
        &external_record,
    );
    let external_signer = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &leaf,
        &key,
        &[],
        &[external_attribute],
    );
    let external_bytes = support::message(
        oid::DATA.as_bytes(),
        None,
        &[root.clone(), leaf.clone()],
        &[],
        &[external_signer],
    );
    let external_parser = Parser::ber(memory());
    let external_message =
        structured_cms::SignedData::read(&external_parser, &external_bytes, 700).unwrap();
    let mut external_parent = external_parser.read(&external_bytes, 700).unwrap();
    let external_envelope = external_parent.next_element().unwrap().unwrap();
    let external_document =
        structured_cades::source::Document::new(&external_message, &external_parent).unwrap();
    let external_prepared = structured_cades::prepare::Preparation::read(
        &external_document,
        &external_message.signers()[0],
        structured_cades::Level::Basic,
        &external_parent,
    )
    .unwrap();
    let external_view = external_prepared
        .evidence(0, &external_parent)
        .unwrap()
        .unwrap();
    let external_provider = Oracle::new();
    let mut payload = Object {
        bytes: b"payload",
        passes: Cell::new(0),
    };
    let external_checked = external_view
        .check_external(
            external_envelope,
            &mut payload,
            &external_provider,
            &external_parent,
            &authorities,
            &utc,
            reference,
            |_, _, _| Ok::<_, Infallible>(true),
            |_, _| Ok::<_, Infallible>(Decision::Valid),
        )
        .unwrap();
    assert!(external_checked.verified().is_some());
    assert_eq!(payload.passes.get(), 1);
    assert_eq!(external_provider.signatures.get(), 1);

    // A counter's PoE Hm covers its ORIGINAL PARENT signature, not root
    // payload or the child's signature/TLV. The same saved counter schema and
    // source context drive Hv/Hs/Ht without re-parsing a moved walk frame.
    let parent_signature = support::signature_octets(&plain);
    let child = signer(None, &parent_signature, &leaf, &key, &[], &[]);
    let child_parser = Parser::ber(memory());
    let mut child_parent = child_parser.read(&child, 0).unwrap();
    let child_element = child_parent.next_element().unwrap().unwrap();
    let child_model =
        structured_cms::signer::SignerInfo::read(&child_parent, &child_element).unwrap();
    let child_signature = [
        tlv(0x30, &tlv(6, support::ECDSA)),
        tlv(4, &support::signature_octets(&child)),
    ]
    .concat();
    let mut child_eight = eight.clone();
    child_eight[32..2 * 32].copy_from_slice(&Sha256::digest(&parent_signature));
    child_eight[5 * 32..6 * 32].copy_from_slice(&Sha256::digest(
        child_model
            .signed_attributes()
            .unwrap()
            .signed_bytes()
            .unwrap()
            .concat(),
    ));
    child_eight[6 * 32..7 * 32].copy_from_slice(&Sha256::digest(child_signature));
    let child_token = token(&child_eight, &tsa, &root, &tsa_key, 0);
    let child_poe = support::attribute(
        &[4, 0, 0x8d, 0x45, 2, 2],
        &tlv(
            0x30,
            &[tlv(24, b"20260101000200Z"), tlv(0xa0, &child_token)].concat(),
        ),
    );
    let child_augmented = signer(None, &parent_signature, &leaf, &key, &[], &[child_poe]);
    let counter_attribute = support::attribute(oid::COUNTERSIGNATURE.as_bytes(), &child_augmented);
    for altered in [false, true] {
        let payload = if altered {
            b"changed".as_slice()
        } else {
            b"payload".as_slice()
        };
        let root_signer = signer(
            Some(oid::DATA.as_bytes()),
            payload,
            &leaf,
            &key,
            &[],
            std::slice::from_ref(&counter_attribute),
        );
        let counter_bytes = support::message(
            oid::DATA.as_bytes(),
            Some(payload),
            &[root.clone(), leaf.clone()],
            &[],
            &[root_signer],
        );
        let counter_parser = Parser::ber(memory());
        let counter_message =
            structured_cms::SignedData::read(&counter_parser, &counter_bytes, 700).unwrap();
        let counter_parent = counter_parser.read(&[], 700).unwrap();
        let counter_document =
            structured_cades::source::Document::new(&counter_message, &counter_parent).unwrap();
        let counter_prepared = structured_cades::prepare::Preparation::read(
            &counter_document,
            &counter_message.signers()[0],
            structured_cades::Level::Basic,
            &counter_parent,
        )
        .unwrap();
        assert_eq!(counter_prepared.counters().len(), 1);
        assert_eq!(counter_prepared.evidence_records(), 1);
        let counter_view = counter_prepared
            .evidence(0, &counter_parent)
            .unwrap()
            .unwrap();
        let provider = Oracle::new();
        let checked = counter_view
            .check_poe(
                &provider,
                &counter_parent,
                &authorities,
                &utc,
                reference,
                None::<&mut structured_cades::timestamp::NoDetached>,
                |_, _, _| Ok::<_, Infallible>(true),
                |_, _| Ok::<_, Infallible>(Decision::Valid),
            )
            .unwrap();
        assert_eq!(checked.verified().is_some(), !altered);
        if let Some(receipt) = checked.verified() {
            assert_eq!(
                receipt.required().signature,
                counter_prepared.counters()[0].node()
            );
        }
    }
    // A two-object EXTERNAL record without a reduced tree is structurally
    // impossible. No caller path discovery or detached source may run first.
    let external = support::attribute(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 50], &evidence);
    let signed = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &leaf,
        &key,
        &[],
        &[external],
    );
    let external_bytes = support::message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[root.clone(), leaf],
        &[],
        &[signed],
    );
    let external_parser = Parser::ber(memory());
    let external_message =
        structured_cms::SignedData::read(&external_parser, &external_bytes, 700).unwrap();
    let mut external_parent = external_parser.read(&external_bytes, 700).unwrap();
    let envelope = external_parent.next_element().unwrap().unwrap();
    let external_document =
        structured_cades::source::Document::new(&external_message, &external_parent).unwrap();
    let external_prepared = structured_cades::prepare::Preparation::read(
        &external_document,
        &external_message.signers()[0],
        structured_cades::Level::Basic,
        &external_parent,
    )
    .unwrap();
    let external_view = external_prepared
        .evidence(0, &external_parent)
        .unwrap()
        .unwrap();
    let calls = authorities.selections.get();
    let provider = Oracle::new();
    let mut detached = Object {
        bytes: b"payload",
        passes: Cell::new(0),
    };
    assert!(
        external_view
            .check_external(
                envelope,
                &mut detached,
                &provider,
                &external_parent,
                &authorities,
                &utc,
                Instant::new(1_767_312_000, 0).unwrap(),
                |_, _, _| Ok::<_, Infallible>(true),
                |_, _| Ok::<_, Infallible>(Decision::Valid)
            )
            .is_err()
    );
    assert_eq!(
        authorities.selections.get(),
        calls,
        "membership syntax precedes caller path discovery"
    );
    assert_eq!(detached.passes.get(), 0);
    assert_eq!(provider.signatures.get(), 0);
}
struct Authority<'a> {
    certificate: &'a Certificate<'a>,
    parent: &'a Reader<'a>,
}
impl<'d> Authorities<'d> for Authority<'_> {
    type Error = Infallible;
    fn select<'a, W: Work>(
        &'a self,
        _: usize,
        _: &'a ArchiveTimeStamp<'d>,
        _: &W,
    ) -> Result<Selection<'a>, Infallible>
    where
        'd: 'a,
    {
        Ok(Selection {
            certificate: self.certificate,
            certificate_parent: self.parent,
            key: WorkingKey::standing(self.certificate.tbs().public_key()),
        })
    }
}
struct Object<'a> {
    bytes: &'a [u8],
    passes: Cell<usize>,
}
impl Source for Object<'_> {
    type Error = Refused;
    fn stream<W: Work>(&mut self, out: &mut impl Receiver, work: &W) -> Result<(), Refused> {
        work.charge_work(1).map_err(|_| Refused)?;
        self.passes.set(self.passes.get() + 1);
        out.write(self.bytes)
    }
}

#[test]
fn native_initial_timestamp_renewal_and_hash_tree_renewal_validate_every_token_once() {
    // Real signatures/ESS/exclusive TSA EKU are checked by the existing common
    // token kernel. Historical Valid below is explicit trusted fixture input,
    // not an implementation claim that mathematical checks establish status.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let tsa = certificate("TSA", "Root", &tsa_key, &root_key, true);
    let data = b"original object";
    let first = token(data, &tsa, &root, &tsa_key, 0);
    let renewed = token(&first, &tsa, &root, &tsa_key, 10);
    let chain = tlv(0x30, &[stamp(&first), stamp(&renewed)].concat());
    let prior = tlv(0x30, &chain);
    let input = [
        Sha256::digest(data).as_slice(),
        Sha256::digest(&prior).as_slice(),
    ]
    .concat();
    let hash_renewed = token(&input, &tsa, &root, &tsa_key, 20);
    // RFC4998 §5.2 hashes DER previous chains even when carried in BER.
    let chain_parser = Parser::ber(memory());
    let mut chain_reader = chain_parser.read(&chain, 0).unwrap();
    let chain_element = chain_reader.next_element().unwrap().unwrap();
    let ber_chain = [&[0x30, 0x80][..], chain_element.contents(), &[0, 0]].concat();
    let encoded = record(&[ber_chain, tlv(0x30, &stamp(&hash_renewed))]);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&encoded, 900).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let cert_parser = Parser::der(memory());
    let cert = Certificate::read(&cert_parser, &tsa, 100).unwrap();
    let cert_parent = cert_parser.read(&[], 100).unwrap();
    let authority = Authority {
        certificate: &cert,
        parent: &cert_parent,
    };
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    let now = Instant::new(1_767_312_000, 0).unwrap();
    for answer in [Decision::Valid, Decision::Unknown, Decision::Invalid] {
        let provider = Oracle::new();
        let mut sources = [Object {
            bytes: data,
            passes: Cell::new(0),
        }];
        let calls = Cell::new(0);
        let report = parsed
            .verify(
                &provider,
                &parent,
                &authority,
                &utc,
                now,
                &mut sources,
                Membership::Object,
                |_, _, _| Ok::<_, Infallible>(true),
                |facts, work| {
                    work.charge_work(1).unwrap();
                    assert_eq!(facts.index, 2 - calls.get());
                    assert_eq!(
                        facts.current.imprint,
                        structured_cms::timestamp::ImprintAgreement::Matches
                    );
                    assert!(facts.current.evidence().is_some());
                    if facts.index < 2 {
                        assert!(facts.following.is_some());
                    }
                    if facts.index < 2 {
                        assert!(facts.following_chain.is_some());
                    }
                    calls.set(calls.get() + 1);
                    Ok::<_, Infallible>(answer)
                },
            )
            .unwrap();
        assert_eq!(sources[0].passes.get(), 1);
        assert_eq!(calls.get(), 3);
        assert_eq!(provider.signatures.get(), 3);
        assert_eq!(
            report
                .checks()
                .map(structured_cms::evidence::verify::Checked::index)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(report.verified().is_some(), answer == Decision::Valid);
    }
}

#[test]
fn altered_renewal_prefix_and_unsorted_pair_alternative_cannot_produce_evidence() {
    // Each negative still has genuine valid timestamp signatures: only the
    // normative source input is changed. No permissive hash-recipe fallback.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let tsa = certificate("TSA", "Root", &tsa_key, &root_key, true);
    let first = token(b"data", &tsa, &root, &tsa_key, 0);
    let old = tlv(0x30, &stamp(&first));
    let data_hash = Sha256::digest(b"data");
    let prior_hash = Sha256::digest(tlv(0x30, &old));
    // Reverse the required numbered-step concatenation (not selected by width).
    let wrong = [prior_hash.as_slice(), data_hash.as_slice()].concat();
    let next = token(&wrong, &tsa, &root, &tsa_key, 10);
    let encoded = record(&[old, tlv(0x30, &stamp(&next))]);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&encoded, 0).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let cert_parser = Parser::der(memory());
    let cert = Certificate::read(&cert_parser, &tsa, 0).unwrap();
    let cert_parent = cert_parser.read(&[], 0).unwrap();
    let authority = Authority {
        certificate: &cert,
        parent: &cert_parent,
    };
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    let mut sources = [Object {
        bytes: b"data",
        passes: Cell::new(0),
    }];
    let provider = Oracle::new();
    let report = parsed
        .verify(
            &provider,
            &parent,
            &authority,
            &utc,
            Instant::new(1_767_312_000, 0).unwrap(),
            &mut sources,
            Membership::Object,
            |_, _, _| Ok::<_, Infallible>(true),
            |_, _| Ok::<_, Infallible>(Decision::Valid),
        )
        .unwrap();
    assert!(report.verified().is_none());
    assert_eq!(
        report.checks().last().unwrap().timestamp().imprint,
        structured_cms::timestamp::ImprintAgreement::Differs
    );
    assert_eq!(sources[0].passes.get(), 1);
}

#[test]
fn profile_refusal_precedes_object_io_and_retains_its_original_cause() {
    // Even a valid signed token must not acquire external content before the
    // selected CAdES profile has admitted that SAME original ESS/TSTInfo view.
    let key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let tsa = certificate("TSA", "Root", &key, &root_key, true);
    let encoded = record(&[tlv(0x30, &stamp(&token(b"data", &tsa, &root, &key, 0)))]);
    let parser = Parser::ber(memory());
    let mut parent = parser.read(&encoded, 900).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let parsed = EvidenceRecord::read(&parent, &element).unwrap();
    let cert_parser = Parser::der(memory());
    let cert = Certificate::read(&cert_parser, &tsa, 0).unwrap();
    let cert_parent = cert_parser.read(&[], 0).unwrap();
    let authority = Authority {
        certificate: &cert,
        parent: &cert_parent,
    };
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    let mut sources = [Object {
        bytes: b"data",
        passes: Cell::new(0),
    }];
    let provider = Oracle::new();
    let refused = parsed.verify_with_profile(
        &provider,
        &parent,
        &authority,
        &utc,
        Instant::new(1_767_312_000, 0).unwrap(),
        &mut sources,
        Membership::Object,
        |_, _, _| Ok::<_, Infallible>(true),
        |_, _| panic!("historical validation follows profile admission"),
        |index, input| {
            assert_eq!(index, 0);
            let structured_cms::evidence::TimeStamp::Rfc3161(original) =
                parsed.timestamps()[0].timestamp()
            else {
                panic!("the original fixture is an RFC3161 token");
            };
            assert!(std::ptr::eq(input.token, original));
            Err(structured_cms::timestamp::ProfileFailure {
                source: structured_cms::timestamp::ProfileSource::Information,
                cause: "selected profile",
            })
        },
    );
    let refused = refused.err().expect("the profile refusal is terminal");
    assert!(matches!(refused,structured_cms::evidence::verify::VerificationError::<_,_,_,_,Infallible,_>::Timestamp{index:0,cause:structured_cms::timestamp::ProfileCheckError::Profile{source:structured_cms::timestamp::ProfileFailure{cause:"selected profile",..},..}}));
    assert_eq!(sources[0].passes.get(), 0);
    assert_eq!(provider.signatures.get(), 0);
}

#[test]
fn cades_census_and_material_reuse_every_original_ers_envelope() {
    // Internal, external and PoE-carried records must expose every renewal
    // TSA, reusing the first-read Token rather than creating a parallel cache.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let leaf = certificate("Leaf", "Root", &key, &root_key, false);
    let tsa = certificate("TSA", "Root", &tsa_key, &root_key, true);
    let first = token(b"original input", &tsa, &root, &tsa_key, 0);
    let second = token(&first, &tsa, &root, &tsa_key, 10);
    let third = token(&second, &tsa, &root, &tsa_key, 20);
    let evidence = record(&[tlv(
        0x30,
        &[stamp(&first), stamp(&second), stamp(&third)].concat(),
    )]);
    for kind in [49, 50, 0] {
        let oid = if kind == 0 {
            vec![4, 0, 0x8d, 0x45, 2, 2]
        } else {
            vec![42, 134, 72, 134, 247, 13, 1, 9, 16, 2, kind]
        };
        let value = if kind == 0 {
            tlv(
                0x30,
                &[tlv(24, b"20260101000200Z"), tlv(0xa1, &evidence)].concat(),
            )
        } else {
            evidence.clone()
        };
        let signed = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &leaf,
            &key,
            &[],
            &[support::attribute(&oid, &value)],
        );
        let encoded = message(
            oid::DATA.as_bytes(),
            Some(b"payload"),
            &[root.clone(), leaf.clone()],
            &[],
            &[signed],
        );
        let parser = Parser::ber(memory());
        let message = structured_cms::SignedData::read(&parser, &encoded, 700).unwrap();
        let parent = parser.read(&[], 700).unwrap();
        let document = structured_cades::source::Document::new(&message, &parent).unwrap();
        let prepared = structured_cades::prepare::Preparation::read(
            &document,
            &message.signers()[0],
            structured_cades::Level::Basic,
            &parent,
        )
        .unwrap();
        assert_eq!(prepared.evidence_records(), 1);
        assert!(prepared.evidence_faults().is_empty());
        assert_eq!(prepared.timestamps().len(), 3);
        let view = prepared.evidence(0, &parent).unwrap().unwrap();
        assert_eq!(view.timestamps(), 0..3);
        let record = view.record().unwrap();
        let pool = structured_cades::material::Pool::read(&prepared, &parent).unwrap();
        assert!(pool.token_faults().is_empty());
        for ordinal in view.timestamps() {
            let structured_cms::evidence::TimeStamp::Rfc3161(original) =
                record.timestamps()[ordinal].timestamp()
            else {
                panic!("native TSA fixture");
            };
            assert!(std::ptr::eq(
                pool.token(ordinal, &parent.execution()).unwrap().unwrap(),
                original
            ));
            pool.with_token(ordinal, &parent, |context| {
                assert!(std::ptr::eq(context.token(), original));
                assert!(context.token().message().span().start > 700);
                Ok::<_, Infallible>(())
            })
            .unwrap();
        }
    }
}

#[test]
fn poe_date_and_extra_sets_without_a_proof_remain_distinct_from_success() {
    // TS101733 §6.5.1 permits the unfinished value and empty extra sets. Their
    // context tags must not be mistaken for explicit timestamp/ERS wrappers.
    let encoded = tlv(
        0x30,
        &[tlv(24, b"20260101000100Z"), tlv(0xa0, &[]), tlv(0xa1, &[])].concat(),
    );
    let parser = Parser::der(memory());
    let mut parent = parser.read(&encoded, 700).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let value = structured_cades::evidence::LongTermValidation::read(&parent, &element).unwrap();
    assert!(value.proof().is_none());
    assert!(value.certificates().unwrap().choices().is_empty());
    assert!(value.revocations().unwrap().values().is_empty());
    assert_eq!(value.element().as_bytes(), encoded);
    assert!(value.date_element().span().start > 700);
    assert_eq!(value.reader_in(&parent).unwrap().depth(), parent.depth());
}

#[test]
fn internal_object_removes_only_self_and_later_records_and_adapts_parent_lengths() {
    struct Capture(Vec<u8>);
    impl Receiver for Capture {
        fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }
    // Independent trusted fixture construction gives byte-exact expectations.
    // Preserve another unsigned attribute, a second signer and original BER
    // indefinite framing; do not hash only SignedData or reserialize the CMS.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let leaf = certificate("Leaf", "Root", &key, &root_key, false);
    let tsa = certificate("TSA", "Root", &tsa_key, &root_key, true);
    let ers = record(&[tlv(
        0x30,
        &stamp(&token(b"object", &tsa, &root, &tsa_key, 0)),
    )]);
    let er_oid = [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 49];
    let other = support::attribute(&[42, 9], &tlv(4, b"untouched"));
    for ber in [false, true] {
        let original = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &leaf,
            &key,
            &[],
            std::slice::from_ref(&other),
        );
        let final_signer = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &leaf,
            &key,
            &[],
            &[other.clone(), support::attribute(&er_oid, &ers)],
        );
        let wrap = |bytes: Vec<u8>| {
            if !ber {
                return bytes;
            }
            let parser = Parser::ber(memory());
            let mut reader = parser.read(&bytes, 0).unwrap();
            let value = reader.next_element().unwrap().unwrap();
            [vec![0x30, 0x80], value.contents().to_vec(), vec![0, 0]].concat()
        };
        let original = wrap(original);
        let final_signer = wrap(final_signer);
        let expected = wrap(message(
            oid::DATA.as_bytes(),
            Some(b"payload"),
            &[root.clone(), leaf.clone()],
            &[],
            &[original],
        ));
        let encoded = wrap(message(
            oid::DATA.as_bytes(),
            Some(b"payload"),
            &[root.clone(), leaf.clone()],
            &[],
            &[final_signer],
        ));
        let parser = Parser::ber(memory());
        let parsed = structured_cms::SignedData::read(&parser, &encoded, 700).unwrap();
        let mut parent = parser.read(&encoded, 700).unwrap();
        let envelope = parent.next_element().unwrap().unwrap();
        let document = structured_cades::source::Document::new(&parsed, &parent).unwrap();
        let prepared = structured_cades::prepare::Preparation::read(
            &document,
            &parsed.signers()[0],
            structured_cades::Level::Basic,
            &parent,
        )
        .unwrap();
        let view = prepared.evidence(0, &parent).unwrap().unwrap();
        let mut input = view.cms_object(envelope, &parent).unwrap();
        let mut capture = Capture(Vec::new());
        input.stream(&mut capture, &parent.execution()).unwrap();
        assert_eq!(input.occurrence(), 0);
        assert_eq!(capture.0, expected);
        // Equal copied bytes in a different parser are not this source.
        let other_parser = Parser::ber(memory());
        let mut other = other_parser.read(&encoded, 700).unwrap();
        let same_bytes = other.next_element().unwrap().unwrap();
        assert!(view.cms_object(same_bytes, &other).is_err());
    }
}
