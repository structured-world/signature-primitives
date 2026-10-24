//! Real timestamp arithmetic, original signature input, and source-bound stages.
#[path = "support/crl.rs"]
mod crl_fixture;
mod support;

use crl_fixture::crl;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use std::{cell::Cell, convert::Infallible};
use structured_asn1::{Parser, memory::Work};
use structured_cades::{
    Level, baseline, basic, counters, credential, material, prepare::Preparation, source::Document,
};
use structured_cms::{
    SignedData,
    binding::Scope,
    oid, prepare,
    verify::{ContentMode, DocumentBatch},
};
use structured_ltv::{
    credential::Authentication,
    pki::{self, PathOutcome, TimestampBinding},
    source::{Scope as QueryScope, Source},
    timestamp::TimestampPathBinding,
};
use structured_pkix::{
    path::{self, Anchor, Interval, ValidationBounds, ValidationContext},
    temporal::LeapTable,
};
use support::{Oracle, attribute, certificate, memory, message, signature_octets, signer, tlv};

struct EmptyCredentials(Cell<usize>);
impl<'p, 'd> credential::Provider<'p, 'd> for EmptyCredentials {
    type Evidence = ();
    type Error = Infallible;
    fn authenticate(
        &self,
        _: credential::Context<'_, '_, 'd>,
    ) -> Result<Authentication<'p, 'd, ()>, Infallible> {
        self.0.set(self.0.get() + 1);
        Ok(Authentication::Unsupported)
    }
}
impl material::credentials::Provider<()> for EmptyCredentials {
    type Error = Infallible;
    fn visit<'m, 'd, V>(
        &self,
        _: &credential::Checked<'m, 'd, '_, ()>,
        _: &[material::Open<'d>],
        _: &structured_asn1::ScopedReader<'d, '_>,
        _: impl for<'value, 'source> FnMut(
            material::credentials::Need<'value, 'source, 'm, 'd>,
        ) -> Result<(), V>,
    ) -> Result<material::credentials::Completeness, material::credentials::VisitError<Infallible, V>>
    {
        panic!("a source without credentials cannot invoke a format handler")
    }
}

struct RecordAuthority<'p, 'd> {
    path: &'p pki::CheckedPath<'d>,
    parent: &'p structured_asn1::Reader<'d>,
}
impl<'d> structured_cades::evidence::Authorities<'d> for RecordAuthority<'_, 'd> {
    type Error = Infallible;
    fn select<'p, W: Work>(
        &'p self,
        _: usize,
        _: &structured_cms::timestamp::Token<'d>,
        work: &W,
    ) -> Result<structured_cades::evidence::Authority<'p, 'd>, Infallible>
    where
        'd: 'p,
    {
        let _ = work;
        Ok(structured_cades::evidence::Authority {
            path: self.path,
            certificate_parent: self.parent,
        })
    }
}

fn token(
    input: &[u8],
    cert: &[u8],
    root: &[u8],
    key: &SigningKey,
    accuracy: bool,
    index: Option<&[u8]>,
) -> Vec<u8> {
    token_digest(
        input,
        cert,
        root,
        key,
        accuracy,
        index.map(|bytes| (bytes, false)),
        oid::SHA256.as_bytes(),
    )
}
fn token_digest(
    input: &[u8],
    cert: &[u8],
    root: &[u8],
    key: &SigningKey,
    accuracy: bool,
    index: Option<(&[u8], bool)>,
    digest: &[u8],
) -> Vec<u8> {
    let imprint = tlv(
        0x30,
        &[
            tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
            tlv(4, &Sha256::digest(input)),
        ]
        .concat(),
    );
    let mut fields = [
        vec![2, 1, 1],
        tlv(6, &[42, 3]),
        imprint,
        vec![2, 1, 9],
        tlv(24, b"20260101000100Z"),
    ]
    .concat();
    if accuracy {
        fields.extend(tlv(0x30, &[]));
    }
    let info = tlv(0x30, &fields);
    let unsigned: Vec<_> = index
        .into_iter()
        .map(|(bytes, _)| attribute(oid::ATS_HASH_INDEX_V3.as_bytes(), bytes))
        .collect();
    let signed: Vec<_> = index
        .filter(|(_, misplaced)| *misplaced)
        .map(|(bytes, _)| attribute(oid::ATS_HASH_INDEX_V3.as_bytes(), bytes))
        .into_iter()
        .collect();
    let signature = support::signer_digest(
        Some(oid::TST_INFO.as_bytes()),
        &info,
        cert,
        key,
        &signed,
        &unsigned,
        digest,
    );
    message(
        oid::TST_INFO.as_bytes(),
        Some(&info),
        &[root.to_vec(), cert.to_vec()],
        &[],
        &[signature],
    )
}

fn archive_token(
    before: &[u8],
    cert: &[u8],
    root: &[u8],
    key: &SigningKey,
    misplaced: bool,
) -> Vec<u8> {
    // Trusted DER fixture writer follows EN319122-1 §§5.5.2–5.5.3.
    // The existing CMS index/range core is separately checked against the DSS
    // compatibility corpus; here real token crypto tests the complete wiring.
    let parser = Parser::ber(memory());
    let message = SignedData::read(&parser, before, 0).unwrap();
    let mut fields = tlv(0x30, &tlv(6, oid::SHA256.as_bytes()));
    let cert_hashes: Vec<_> = message
        .certificates()
        .iter()
        .map(|cert| tlv(4, &Sha256::digest(cert.as_bytes())))
        .collect();
    let rev_hashes: Vec<_> = message
        .revocations()
        .iter()
        .map(|rev| tlv(4, &Sha256::digest(rev.as_bytes())))
        .collect();
    let mut attribute_hashes = Vec::new();
    for attribute in message.signers()[0].unsigned_attributes().unwrap().items() {
        for value in attribute.values() {
            let mut digest = Sha256::new();
            digest.update(tlv(6, attribute.kind().as_bytes()));
            digest.update(value.as_bytes());
            attribute_hashes.push(tlv(4, &digest.finalize()));
        }
    }
    for hashes in [&cert_hashes, &rev_hashes, &attribute_hashes] {
        fields.extend(tlv(0x30, &hashes.concat()));
    }
    let index = tlv(0x30, &fields);
    let mut reader = parser.read(&index, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let parsed = structured_cms::archive::HashIndex::read(&reader, &element).unwrap();
    let hash = Sha256::digest(b"sample");
    let ranges =
        structured_cms::archive::imprint_input(&message, &message.signers()[0], &parsed, &hash)
            .unwrap();
    let mut input = Vec::new();
    for range in ranges {
        input.extend(range);
    }
    token_digest(
        &input,
        cert,
        root,
        key,
        true,
        Some((&index, misplaced)),
        oid::SHA256.as_bytes(),
    )
}

// Trusted DER fixture writers provide complete certificate/CRL references.
fn reference_material(certificate: &[u8], crl: &[u8]) -> [Vec<u8>; 2] {
    let hash = |value: &[u8]| {
        tlv(
            0x30,
            &[
                tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
                tlv(4, &Sha256::digest(value)),
            ]
            .concat(),
        )
    };
    [
        attribute(
            &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 21],
            &tlv(0x30, &tlv(0x30, &hash(certificate))),
        ),
        attribute(
            &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 22],
            &tlv(
                0x30,
                &tlv(
                    0x30,
                    &tlv(0xa0, &tlv(0x30, &tlv(0x30, &tlv(0x30, &hash(crl))))),
                ),
            ),
        ),
    ]
}

// The trusted fixture's own definite header is excluded by AnnexA.1.5 inputs.
fn attribute_body(original: &[u8]) -> &[u8] {
    let width = if original[1] < 128 {
        0
    } else {
        usize::from(original[1] & 0x7f)
    };
    &original[2 + width..]
}

// Change only the outer Attribute header; all original token bytes stay exact.
fn ber_wrapper(original: &[u8], indefinite: bool) -> Vec<u8> {
    let width = if original[1] < 128 {
        0
    } else {
        usize::from(original[1] & 0x7f)
    };
    let mut changed = if indefinite {
        vec![0x30, 0x80]
    } else {
        let mut header = vec![0x30, 0x80 | u8::try_from(width + 1).unwrap(), 0];
        if width == 0 {
            header.push(original[1]);
        } else {
            header.extend(&original[2..2 + width]);
        }
        header
    };
    changed.extend(&original[2 + width..]);
    if indefinite {
        changed.extend([0, 0]);
    }
    changed
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one source-bound real-crypto scenario keeps the live receipt graph and each successive level's negative assertions visible together"
)]
#[expect(
    clippy::result_large_err,
    reason = "the token visitor returns the real mapped refusal unchanged; the test must exercise the same nonallocating error path"
)]
fn actual_signature_timestamp_and_complete_bt_cannot_use_wrong_input_or_unknown_accuracy() {
    // This is real ECDSA/SHA-256 on both CMS signatures and certificates.
    // A valid TSA signature alone cannot establish input or full time bounds.
    for mode in 0..18 {
        let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
        let signer_key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
        let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
        let root_bytes = certificate("Root", "Root", &root_key, &root_key, false);
        let leaf_bytes = certificate("Signer", "Root", &signer_key, &root_key, false);
        let tsa_bytes = certificate("TSA", "Root", &tsa_key, &root_key, true);
        let mut signed = vec![
            attribute(oid::SIGNING_TIME.as_bytes(), &tlv(23, b"260101000000Z")),
            attribute(
                oid::MIME_TYPE.as_bytes(),
                &tlv(12, b"application/octet-stream"),
            ),
        ];
        if mode == 8 {
            // A root content timestamp is signed before the signature timestamp
            // and ATSv3. The archive imprint includes these exact signedAttrs.
            let content = token(b"sample", &tsa_bytes, &root_bytes, &tsa_key, true, None);
            signed.push(attribute(oid::CONTENT_TIMESTAMP.as_bytes(), &content));
        }
        let provisional = signer(
            Some(oid::DATA.as_bytes()),
            b"sample",
            &leaf_bytes,
            &signer_key,
            &signed,
            &[],
        );
        let mut covered = signature_octets(&provisional);
        if mode == 1 {
            covered[0] ^= 1;
        }
        let timestamp = if mode == 5 {
            token_digest(
                &covered,
                &tsa_bytes,
                &root_bytes,
                &tsa_key,
                true,
                None,
                &[42, 134, 72, 134, 247, 13, 2, 5],
            )
        } else {
            token(&covered, &tsa_bytes, &root_bytes, &tsa_key, mode != 2, None)
        };
        let crls = [crl(&root_key)];
        let mut unsigned = vec![attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &timestamp)];
        if matches!(mode, 9 | 10) {
            unsigned[0] = ber_wrapper(&unsigned[0], mode == 9);
        }

        if (11..=13).contains(&mode) {
            let references = reference_material(&root_bytes, &crls[0]);
            let suffix = if mode == 11 { 25 } else { 26 };
            let mut input = Vec::new();
            if suffix == 25 {
                input.extend(&covered);
                input.extend(attribute_body(&unsigned[0]));
            }
            for reference in &references {
                input.extend(attribute_body(reference));
            }
            unsigned.extend(references);
            let stamped = token(&input, &tsa_bytes, &root_bytes, &tsa_key, true, None);
            unsigned.push(attribute(
                &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, suffix],
                &stamped,
            ));
        }
        if mode == 6 || mode == 13 {
            // EN319122-1 §5.5.3: a new valid ATSv3 cannot erase an older
            // original preservation obligation or manufacture its actors.
            unsigned.push(attribute(
                &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 48],
                &timestamp,
            ));
        }
        // B-LT requires the TSA certificate in the root certificate set.
        // Archive augmentation may reuse its actual copy in the timestamp.
        let certs = if matches!(mode, 14 | 15) {
            vec![root_bytes.clone(), leaf_bytes.clone()]
        } else {
            vec![root_bytes.clone(), leaf_bytes.clone(), tsa_bytes.clone()]
        };
        if matches!(mode, 4 | 6..=8 | 15 | 17) {
            let before_signer = signer(
                Some(oid::DATA.as_bytes()),
                b"sample",
                &leaf_bytes,
                &signer_key,
                &signed,
                &unsigned,
            );
            let before = message(
                oid::DATA.as_bytes(),
                Some(b"sample"),
                &certs,
                &crls,
                &[before_signer],
            );
            let archive = archive_token(&before, &tsa_bytes, &root_bytes, &tsa_key, mode == 7);
            unsigned.push(attribute(oid::ARCHIVE_TIMESTAMP_V3.as_bytes(), &archive));
        }
        if matches!(mode, 16 | 17) {
            let before_signer = signer(
                Some(oid::DATA.as_bytes()),
                b"sample",
                &leaf_bytes,
                &signer_key,
                &signed,
                &unsigned,
            );
            let before = message(
                oid::DATA.as_bytes(),
                Some(b"sample"),
                &certs,
                &crls,
                &[before_signer],
            );
            let stamped = token(&before, &tsa_bytes, &root_bytes, &tsa_key, true, None);
            let record = tlv(
                0x30,
                &[
                    vec![2, 1, 1],
                    tlv(0x30, &tlv(0x30, &tlv(6, oid::SHA256.as_bytes()))),
                    tlv(0x30, &tlv(0x30, &tlv(0x30, &stamped))),
                ]
                .concat(),
            );
            unsigned.push(attribute(
                &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 49],
                &record,
            ));
        }
        let signature = signer(
            Some(oid::DATA.as_bytes()),
            b"sample",
            &leaf_bytes,
            &signer_key,
            &signed,
            &unsigned,
        );
        let bytes = message(
            oid::DATA.as_bytes(),
            Some(b"sample"),
            &certs,
            &crls,
            &[signature],
        );
        let parser = Parser::ber(memory());
        let message = SignedData::read(&parser, &bytes, 400).unwrap();
        let parent = parser.read(&[], 0).unwrap();
        let work = parent.execution();
        let root = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == root_bytes)
            .unwrap();
        let leaf = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == leaf_bytes)
            .unwrap();
        let external_tsa = if matches!(mode, 14 | 15) {
            Some(structured_pkix::Certificate::read(&parser, &tsa_bytes, 0).unwrap())
        } else {
            None
        };
        let tsa = match &external_tsa {
            Some(tsa) => tsa,
            None => message
                .certificates()
                .iter()
                .find(|value| value.as_bytes() == tsa_bytes)
                .unwrap(),
        };
        let oracle = Oracle::new();
        let interval = Interval::between(
            leaf.tbs().validity().not_before().seconds(),
            leaf.tbs().validity().not_after().seconds(),
        );
        let utc = LeapTable::new(interval.from(), interval.to(), &[]).unwrap();
        let context = ValidationContext {
            execution: &work,
            interval,
            policy: path::Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let PathOutcome::Accepted(path) =
            pki::check_path(&[leaf], Anchor::from_certificate(root), &context).unwrap()
        else {
            panic!("real signer path");
        };
        let PathOutcome::Accepted(tsa_path) =
            pki::check_path(&[tsa], Anchor::from_certificate(root), &context).unwrap()
        else {
            panic!("real TSA path");
        };
        let selected = &message.signers()[0];
        let prepare::Preparation::Ready(plan) = prepare::resolve(
            &oracle,
            selected,
            path.members().last().unwrap().key(),
            &parent,
            Scope::Content(oid::DATA),
        )
        .unwrap() else {
            panic!("real CMS plan");
        };
        let mut requests = work.vector();
        requests.try_push(plan).unwrap();
        let checks = DocumentBatch::prepare(
            &oracle,
            &message,
            requests.into_owned(),
            ContentMode::Carried,
            &parent,
        )
        .unwrap()
        .run_carried()
        .unwrap();
        let document = Document::new(&message, &parent).unwrap();
        let level = match mode {
            3 | 14 | 16 => Level::LongTerm,
            4 | 6..=8 | 15 | 17 => Level::Archival,
            _ => Level::Timestamped,
        };
        let started = std::time::Instant::now();
        let prepared = Preparation::read(&document, selected, level, &parent).unwrap();
        assert_eq!(
            prepared.all_format_requirements_met(),
            !matches!(mode, 5 | 7 | 9 | 10),
            "{:?}",
            prepared.findings()
        );
        if mode == 5 {
            // The timestamp's actual MD5 imprint violates §6.2.1 at
            // preparation, independently of its later mathematical refusal.
            assert!(
                prepared
                    .findings()
                    .iter()
                    .any(|finding| matches!(finding.rule, structured_cades::prepare::Rule::Md5))
            );
        }
        let binding = basic::bind(
            &prepared,
            &checks,
            &checks.checks()[0],
            leaf,
            Some(&path),
            &oracle,
            &parent,
        )
        .unwrap();
        assert!(binding.is_bound());
        if matches!(mode, 9 | 10) {
            // Table1(l) requires DER for baseline conformance. This is NOT a
            // generic CMS decoding or signature-math prohibition: the real
            // token, root signature and imprint must still independently check.
            assert!(binding.mathematical());
            let pool = material::Pool::read(&prepared, &parent).unwrap();
            let time = structured_cades::timestamp::CheckTime {
                utc: &utc,
                reference: Some(interval.to_instant()),
            };
            let answer = pool
                .with_token(0, &parent, |selected| {
                    selected.check_signature(&oracle, &tsa_path, &parent, &time, |_, _| {
                        Ok::<_, Infallible>(true)
                    })
                })
                .unwrap();
            assert!(answer.actor().is_some());
            assert!(pool.token_faults().is_empty());
            let [fault] = prepared.properties().faults() else {
                panic!("one original wrapper finding")
            };
            assert_eq!(fault.attribute, oid::SIGNATURE_TIMESTAMP);
            let structured_cades::Error::Encoding { cause, .. } = &fault.cause else {
                panic!("original DER cause")
            };
            assert_eq!(
                cause.code(),
                if mode == 9 {
                    structured_asn1::ErrorCode::IndefiniteLengthNotAllowed
                } else {
                    structured_asn1::ErrorCode::LengthNotMinimal
                }
            );
            assert_eq!(
                cause.offset(),
                prepared.timestamps()[0].property().span().start + 1
            );
            continue;
        }

        if mode == 7 {
            let counter_checks = counters::bind(&prepared, &parent, |context| {
                context.check(&oracle, leaf, &path)
            })
            .unwrap();
            let handler = EmptyCredentials(Cell::new(0));
            assert!(matches!(
                credential::check(
                    &prepared,
                    &binding,
                    &counter_checks.paths().unwrap(),
                    &handler,
                    &parent
                ),
                Err(credential::CheckError::Nonconforming { .. })
            ));
            let pool = material::Pool::read(&prepared, &parent).unwrap();
            let time = structured_cades::timestamp::CheckTime {
                utc: &utc,
                reference: Some(interval.to_instant()),
            };
            let ordinal = prepared
                .timestamps()
                .iter()
                .position(|entry| entry.purpose() == structured_ltv::timestamp::Purpose::Archive)
                .unwrap();
            let result = pool.with_token(ordinal, &parent, |selected| {
                selected.check_archive_carried(&oracle, &tsa_path, &parent, &time, |_, _| {
                    Ok::<_, Infallible>(true)
                })
            });
            // A genuine token signature and a valid unsigned index cannot
            // hide a second, prohibited signed hash-index occurrence.
            let Err(structured_cades::timestamp::VisitError::Callback(
                structured_cades::timestamp::ArchiveCheckError::Timestamp(
                    structured_cades::timestamp::CheckError::Check(
                        structured_cms::timestamp::ProfileCheckError::Profile { source, .. },
                    ),
                ),
            )) = result
            else {
                panic!("signed hash-index must refuse the archive profile")
            };
            assert_eq!(
                source.source,
                structured_cms::timestamp::ProfileSource::Envelope
            );
            let structured_cades::timestamp::ProfileError::Cades(cause) = source.cause else {
                panic!("original CAdES placement cause must survive")
            };
            assert_eq!(cause.code(), structured_cms::ErrorCode::AttributePlacement);
            continue;
        }

        if mode == 5 {
            // The preparation-stage prohibition now prevents a credential
            // receipt too; keep the independent timestamp preflight assertion.
            let counter_checks = counters::bind(&prepared, &parent, |context| {
                context.check(&oracle, leaf, &path)
            })
            .unwrap();
            let handler = EmptyCredentials(Cell::new(0));
            assert!(matches!(
                credential::check(
                    &prepared,
                    &binding,
                    &counter_checks.paths().unwrap(),
                    &handler,
                    &parent
                ),
                Err(credential::CheckError::Nonconforming { .. })
            ));
            let pool = material::Pool::read(&prepared, &parent).unwrap();
            let time = structured_cades::timestamp::CheckTime {
                utc: &utc,
                reference: Some(interval.to_instant()),
            };
            let starts = oracle.starts.get();
            let answer = pool.with_token(0, &parent, |selected| {
                selected.check_signature(&oracle, &tsa_path, &parent, &time, |_, _| {
                    Ok::<_, Infallible>(true)
                })
            });
            assert!(
                matches!(
                    answer,
                    Err(structured_cades::timestamp::VisitError::Callback(
                        structured_cades::timestamp::CheckError::ForbiddenDigest { .. }
                    ))
                ),
                "MD5 is a format violation, not a provider's Unsupported mechanism"
            );
            assert_eq!(
                oracle.starts.get(),
                starts,
                "format prohibition precedes provider side effects"
            );
            continue;
        }

        let counter_checks = counters::bind(&prepared, &parent, |context| {
            context.check(&oracle, leaf, &path)
        })
        .unwrap();
        let counter_paths = counter_checks.paths().unwrap();
        let handler = EmptyCredentials(Cell::new(0));
        let credentials =
            credential::check(&prepared, &binding, &counter_paths, &handler, &parent).unwrap();
        let credentials = credentials.complete().unwrap();
        let basic = basic::basic(&binding, counter_paths, &parent).unwrap();
        let pool = material::Pool::read(&prepared, &parent).unwrap();
        eprintln!(
            "prepare+pool mode={mode} input_bytes={} elapsed_us={} retained_bytes={}",
            bytes.len(),
            started.elapsed().as_micros(),
            work.memory().used()
        );
        let record_authority = RecordAuthority {
            path: &tsa_path,
            parent: &parent,
        };
        let record_checked = if matches!(mode, 16 | 17) {
            let mut source = parser.read(&bytes, 400).unwrap();
            let envelope = source.next_element().unwrap().unwrap();
            let selected = prepared.evidence(0, &parent).unwrap().unwrap();
            Some(
                selected
                    .check_internal(
                        envelope,
                        &oracle,
                        &parent,
                        &record_authority,
                        &utc,
                        interval.to_instant(),
                        |_, _, _| Ok::<_, Infallible>(true),
                        |_, _| {
                            Ok::<_, Infallible>(structured_cms::evidence::verify::Decision::Valid)
                        },
                    )
                    .unwrap(),
            )
        } else {
            None
        };
        let preservation = record_checked.as_ref().map(|record| {
            structured_cades::evidence::close_preservation(
                &prepared,
                &[record],
                &parent,
                &utc,
                interval.to_instant(),
                |_, _| Ok::<_, Infallible>(structured_cms::evidence::verify::Decision::Valid),
            )
            .unwrap()
        });
        let time = structured_cades::timestamp::CheckTime {
            utc: &utc,
            reference: Some(interval.to_instant()),
        };
        let signature_ordinal = prepared
            .timestamps()
            .iter()
            .position(|entry| entry.purpose() == structured_ltv::timestamp::Purpose::Signature)
            .unwrap();
        let answer = pool.with_token(signature_ordinal, &parent, |selected| {
            selected.check_signature(&oracle, &tsa_path, &parent, &time, |_, _| {
                Ok::<_, Infallible>(true)
            })
        });
        let answer = answer.unwrap();
        let content_answer = if mode == 8 {
            let ordinal = prepared
                .timestamps()
                .iter()
                .position(|entry| entry.purpose() == structured_ltv::timestamp::Purpose::Content)
                .unwrap();
            Some(
                pool.with_token(ordinal, &parent, |selected| {
                    selected.check_content(&oracle, &tsa_path, &parent, &time, |_, _| {
                        Ok::<_, Infallible>(true)
                    })
                })
                .unwrap(),
            )
        } else {
            None
        };
        let archive = if matches!(mode, 4 | 6..=8 | 15 | 17) {
            let ordinal = prepared
                .timestamps()
                .iter()
                .position(|entry| entry.purpose() == structured_ltv::timestamp::Purpose::Archive)
                .unwrap();
            let result = pool.with_token(ordinal, &parent, |selected| {
                selected.check_archive_carried(&oracle, &tsa_path, &parent, &time, |_, _| {
                    Ok::<_, Infallible>(true)
                })
            });
            Some(result.unwrap())
        } else {
            None
        };
        let reference = if (11..=13).contains(&mode) {
            let ordinal = prepared
                .timestamps()
                .iter()
                .position(|entry| {
                    entry.purpose() == structured_ltv::timestamp::Purpose::ValidationData
                })
                .unwrap();
            let mut input = structured_cades::timestamp::references::ReferenceInput::new(
                &prepared, ordinal, &parent,
            )
            .unwrap();
            Some(
                pool.with_token(ordinal, &parent, |selected| {
                    selected.check_references(
                        &oracle,
                        &tsa_path,
                        &parent,
                        &time,
                        &mut input,
                        |_, _| Ok::<_, Infallible>(true),
                    )
                })
                .unwrap(),
            )
        } else {
            None
        };
        let query = QueryScope::new(&document, document.snapshot(), &work);
        if mode == 0 || mode >= 3 {
            assert!(
                answer.actor().is_some(),
                "signature={:?} identifier={:?} bindings={:?} authority={:?} imprint={:?} accuracy={:?} restrictions={:?}",
                answer.signature,
                answer.identifier,
                answer.bindings,
                answer.authority,
                answer.imprint,
                answer.accuracy,
                answer.restrictions
            );
            let actor = answer.actor().unwrap();
            let TimestampBinding::Bound(tsa_receipt) =
                tsa_path.bind_timestamp(actor, &utc, &work).unwrap()
            else {
                panic!("full generation interval covered by actual TSA path");
            };
            let archive_path = archive.as_ref().map(|archive| {
                let actor = archive
                    .timestamp()
                    .actor()
                    .expect("actual original archive imprint and TSA signature must hold");
                let TimestampBinding::Bound(path) =
                    tsa_path.bind_timestamp(actor, &utc, &work).unwrap()
                else {
                    panic!("actual archive TSA path");
                };
                path
            });
            let content_path = content_answer.as_ref().map(|answer| {
                let TimestampBinding::Bound(path) = tsa_path
                    .bind_timestamp(answer.actor().unwrap(), &utc, &work)
                    .unwrap()
                else {
                    panic!("actual content TSA path");
                };
                path
            });
            let reference_path = reference.as_ref().map(|answer| {
                let TimestampBinding::Bound(path) = tsa_path
                    .bind_timestamp(
                        answer
                            .timestamp()
                            .actor()
                            .expect("actual reference input and complete TSA proof"),
                        &utc,
                        &work,
                    )
                    .unwrap()
                else {
                    panic!("actual reference TSA path")
                };
                path
            });
            let record_path = record_checked.as_ref().map(|record| {
                let check = record.checks().next().unwrap();
                let TimestampBinding::Bound(path) = tsa_path
                    .bind_timestamp(check.actor().unwrap(), &utc, &work)
                    .unwrap()
                else {
                    panic!("original ERS TSA path");
                };
                path
            });
            let paths: Vec<_> = prepared
                .timestamps()
                .iter()
                .filter(|entry| {
                    !(matches!(mode, 6 | 13)
                        && matches!(
                            entry.preservation_kind(),
                            Some(
                                structured_cades::preservation::Kind::ArchiveV1
                                    | structured_cades::preservation::Kind::ArchiveV2
                            )
                        ))
                })
                .map(|entry| match entry.purpose() {
                    structured_ltv::timestamp::Purpose::Signature => &tsa_receipt,
                    structured_ltv::timestamp::Purpose::Content => content_path.as_ref().unwrap(),
                    structured_ltv::timestamp::Purpose::Archive => {
                        if entry.preservation_kind()
                            == Some(structured_cades::preservation::Kind::EvidenceRecordInternal)
                        {
                            record_path.as_ref().unwrap()
                        } else {
                            archive_path.as_ref().unwrap()
                        }
                    }
                    structured_ltv::timestamp::Purpose::ValidationData => {
                        reference_path.as_ref().unwrap()
                    }
                })
                .collect();
            if matches!(mode, 6 | 13) {
                // This old value deliberately reuses a signature-timestamp
                // token: valid TSA math, but the WRONG archive input. A modern
                // receipt cannot replace its distinct original obligation.
                let ordinal = prepared
                    .timestamps()
                    .iter()
                    .position(|entry| {
                        entry.preservation_kind()
                            == Some(structured_cades::preservation::Kind::ArchiveV2)
                    })
                    .unwrap();
                let later: Vec<_> = archive
                    .as_ref()
                    .and_then(structured_cades::timestamp::historical::Later::modern)
                    .into_iter()
                    .collect();
                let mut input = structured_cades::timestamp::historical::HistoricalInput::<
                    structured_cades::timestamp::NoDetached,
                >::project(
                    &prepared,
                    ordinal,
                    structured_cades::timestamp::historical::Edition::Rfc5126,
                    &[],
                    &later,
                    &parent,
                    None,
                )
                .unwrap();
                let historical = pool
                    .with_token(ordinal, &parent, |context| {
                        context.check_historical(
                            &oracle,
                            &tsa_path,
                            &parent,
                            &time,
                            &mut input,
                            |_, _| Ok::<_, Infallible>(true),
                        )
                    })
                    .unwrap();
                assert_eq!(
                    historical.timestamp().imprint,
                    structured_cms::timestamp::ImprintAgreement::Differs
                );
                assert!(historical.timestamp().actor().is_none());
                assert_eq!(
                    paths.len() + 1,
                    prepared.timestamp_requirements().entries().len()
                );
                assert!(matches!(
                    prepared
                        .timestamp_requirements()
                        .bind_paths(&paths, &query)
                        .unwrap(),
                    TimestampPathBinding::Unproven(
                        structured_ltv::timestamp::TimestampPathFailure::Count
                    )
                ));
                continue;
            }
            let TimestampPathBinding::Bound(paths) = prepared
                .timestamp_requirements()
                .bind_paths(&paths, &query)
                .unwrap()
            else {
                panic!("complete original token census");
            };
            let timed = baseline::timestamped(&basic, &paths, &query).unwrap();
            assert!(timed.all_static_time_requirements_met());
            if (11..=12).contains(&mode) {
                // AnnexA reference timestamps remain advisory at B-T, while
                // their actual TSA proofs now join the complete actor census.
                // A distinct old archive still needs its OWN proof above.
                let assessed = baseline::assess(baseline::Evidence::timestamped(&timed), &parent);
                assert!(assessed.unwrap().all_requirements_met());
            }
            let ordinary = structured_cades::participants::participants(
                basic.binding(),
                basic.counter_paths(),
                &credentials,
                &paths,
                &query,
            );
            let required = if let Some(preservation) = &preservation {
                assert!(
                    ordinary.is_err(),
                    "an ordinary successful TSA cannot erase the legacy input obligation"
                );
                structured_cades::participants::participants_preserved(
                    basic.binding(),
                    basic.counter_paths(),
                    &credentials,
                    &paths,
                    preservation,
                    &query,
                )
            } else {
                ordinary
            };
            if (11..=12).contains(&mode) {
                let required = required.unwrap();
                assert_eq!(
                    required.entries().len(),
                    3,
                    "actual signer, signature TSA and reference TSA"
                );
                assert!(
                    matches!(
                        prepared
                            .timestamp_requirements()
                            .bind_paths(&[&tsa_receipt], &query)
                            .unwrap(),
                        TimestampPathBinding::Unproven(
                            structured_ltv::timestamp::TimestampPathFailure::Count
                        )
                    ),
                    "the signature TSA cannot replace the reference TSA"
                );
                continue;
            }
            let required = required.unwrap();
            assert_eq!(
                required.entries().len(),
                1 + prepared.timestamps().len(),
                "actual signer and EVERY original TSA, not a supplied successful subset"
            );
            if mode == 0 {
                let assessment =
                    baseline::assess(baseline::Evidence::timestamped(&timed), &parent).unwrap();
                assert!(assessment.all_requirements_met());
            } else {
                // Authenticate an ACTUAL complete CRL, evaluate each target,
                // bind its real authority, and close every original actor.
                let crl = pool.crl(0, &work).unwrap().unwrap();
                let structured_pkix::crl::Authentication::Authenticated(authenticated) = crl
                    .authenticate(
                        root,
                        structured_pkix::path::WorkingKey::standing(root.tbs().public_key()),
                        &oracle,
                        &work,
                    )
                    .unwrap()
                else {
                    panic!("actual ECDSA CRL authentication");
                };
                let at = crl.tbs().this_update().instant().into();
                let evaluation = structured_pkix::crl::Evaluation {
                    now: at,
                    utc: &utc,
                    execution: &work,
                    origin: structured_pkix::crl::SourceOrigin::Cached,
                };
                let structured_pkix::crl::CompleteEvidence::Facts(signer_status) =
                    authenticated.evaluate(leaf, &evaluation).unwrap()
                else {
                    panic!("actual applicable signer CRL");
                };
                let structured_pkix::crl::CompleteEvidence::Facts(tsa_status) =
                    authenticated.evaluate(tsa, &evaluation).unwrap()
                else {
                    panic!("actual applicable TSA CRL");
                };
                assert!(signer_status.absence().is_some() && tsa_status.absence().is_some());
                let authorities = pki::CrlAuthorities::Complete(pki::CrlAuthority::Anchor);
                let pki::CrlReadingBinding::Bound(signer_status) = path
                    .bind_crl_reading(
                        0,
                        pki::CrlReading::Complete(&signer_status),
                        authorities,
                        &utc,
                        &work,
                    )
                    .unwrap()
                else {
                    panic!("actual signer status authority");
                };
                let pki::CrlReadingBinding::Bound(tsa_status) = tsa_path
                    .bind_crl_reading(
                        0,
                        pki::CrlReading::Complete(&tsa_status),
                        authorities,
                        &utc,
                        &work,
                    )
                    .unwrap()
                else {
                    panic!("actual TSA status authority");
                };
                let signer_entries = [pki::MemberStatus::CrlReading(&signer_status)];
                let tsa_entries = [pki::MemberStatus::CrlReading(&tsa_status)];
                let signer_statuses = path.status_census(at, &signer_entries, &work).unwrap();
                let tsa_statuses = tsa_path.status_census(at, &tsa_entries, &work).unwrap();
                let mut status_roots = vec![&tsa_statuses; required.entries().len()];
                status_roots[0] = &signer_statuses;
                let supplied = [
                    pki::AuthorityNode {
                        statuses: &signer_statuses,
                        responders: &[],
                    },
                    pki::AuthorityNode {
                        statuses: &tsa_statuses,
                        responders: &[],
                    },
                ];
                let inputs = required
                    .close_statuses(&status_roots, &supplied, &query)
                    .unwrap();
                let index = pool.index(&query).unwrap();
                let x509 = if let Some(preservation) = &preservation {
                    material::check_participants_preserved(
                        &prepared,
                        &pool,
                        &inputs,
                        &index,
                        preservation,
                        &query,
                    )
                    .unwrap()
                } else {
                    material::check_participants(&prepared, &pool, &inputs, &index, &query).unwrap()
                };
                assert_eq!(
                    x509.all_x509_requirements_met(),
                    mode != 14,
                    "{:?}",
                    x509.findings()
                );
                if mode == 14 {
                    assert!(
                        x509.presence().all_present(),
                        "the token copy is present but misplaced for B-LT"
                    );
                    assert!(
                        x509.findings()
                            .iter()
                            .any(|finding| matches!(finding, material::Finding::Placement { .. }))
                    );
                }
                let whole_credentials = material::credentials::check(
                    &credentials,
                    basic.counter_paths(),
                    prepared.timestamp_requirements(),
                    &index,
                    &material::credentials::Scope::whole(),
                    &handler,
                    &parent,
                )
                .unwrap();
                assert!(whole_credentials.all_requirements_met());
                let long = baseline::long_term(&timed, &x509, &whole_credentials, &query).unwrap();
                assert_eq!(long.all_material_requirements_met(), mode != 14);
                if mode == 14 {
                    let assessment =
                        baseline::assess(baseline::Evidence::LongTerm(&long), &parent).unwrap();
                    assert!(!assessment.all_requirements_met());
                    continue;
                }
                if let Some(archive) = &archive {
                    let earlier = archive.requirements(&prepared, &parent).unwrap();
                    assert_eq!(
                        earlier.entries().len(),
                        if mode == 8 { 2 } else { 1 },
                        "signed content timestamp must enter; own TSA must not"
                    );
                    if mode == 8 {
                        assert!(matches!(
                            earlier.bind_paths(&[&tsa_receipt], &query).unwrap(),
                            TimestampPathBinding::Unproven(
                                structured_ltv::timestamp::TimestampPathFailure::Count
                            )
                        ));
                    }
                    let earlier_paths: Vec<_> = earlier
                        .entries()
                        .iter()
                        .map(|entry| match entry.purpose {
                            structured_ltv::timestamp::Purpose::Content => {
                                content_path.as_ref().unwrap()
                            }
                            structured_ltv::timestamp::Purpose::Signature => &tsa_receipt,
                            _ => panic!("unexpected preceding fixture role"),
                        })
                        .collect();
                    let TimestampPathBinding::Bound(earlier_paths) =
                        earlier.bind_paths(&earlier_paths, &query).unwrap()
                    else {
                        panic!("actual covered preceding token");
                    };
                    let earlier_actors = if let Some(preservation) = &preservation {
                        structured_cades::participants::participants_preserved(
                            basic.binding(),
                            basic.counter_paths(),
                            &credentials,
                            &earlier_paths,
                            preservation,
                            &query,
                        )
                        .unwrap()
                    } else {
                        structured_cades::participants::participants(
                            basic.binding(),
                            basic.counter_paths(),
                            &credentials,
                            &earlier_paths,
                            &query,
                        )
                        .unwrap()
                    };
                    assert_eq!(
                        earlier_actors.entries().len(),
                        if mode == 8 { 3 } else { 2 },
                        "root and EVERY preceding TSA, including signed content"
                    );
                    let mut earlier_roots = vec![&tsa_statuses; earlier_actors.entries().len()];
                    earlier_roots[0] = &signer_statuses;
                    let earlier_inputs = earlier_actors
                        .close_statuses(&earlier_roots, &supplied, &query)
                        .unwrap();
                    let x509 = structured_ltv::material::archived_participants(
                        &earlier_inputs,
                        &index,
                        archive.coverage(),
                        archive.timestamp().actor().unwrap().verified(),
                        &query,
                    )
                    .unwrap();
                    assert!(x509.all_x509_artifacts_covered());
                    let archive_credentials = material::credentials::check(
                        &credentials,
                        basic.counter_paths(),
                        &earlier,
                        &index,
                        &material::credentials::Scope::before_archive(archive),
                        &handler,
                        &parent,
                    )
                    .unwrap();
                    let archive_material =
                        baseline::archive_material(&x509, &archive_credentials, &query).unwrap();
                    // A later ERS has its OWN archive/material obligation.
                    // The old modern receipt cannot stand in for that input,
                    // nor can it erase the later TSA from the full census.
                    let record_receipt = record_checked
                        .as_ref()
                        .and_then(structured_cades::evidence::RecordChecked::verified);
                    let record_archive = record_receipt.as_ref().map(|receipt| {
                        receipt
                            .archive(receipt.timestamps().start, &index, &parent)
                            .unwrap()
                    });
                    let record_earlier = record_archive
                        .as_ref()
                        .map(|archive| archive.requirements(&parent).unwrap());
                    let record_path_refs: Vec<_> = record_earlier
                        .as_ref()
                        .map(|earlier| {
                            earlier
                                .entries()
                                .iter()
                                .map(|entry| match entry.purpose {
                                    structured_ltv::timestamp::Purpose::Signature => &tsa_receipt,
                                    structured_ltv::timestamp::Purpose::Archive => {
                                        archive_path.as_ref().unwrap()
                                    }
                                    other => panic!("unexpected preceding ERS role {other:?}"),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let record_bound = record_earlier.as_ref().map(|earlier| {
                        assert_eq!(
                            earlier.entries().len(),
                            2,
                            "the later ERS covers signature TSA AND actual modern archive TSA"
                        );
                        let TimestampPathBinding::Bound(paths) =
                            earlier.bind_paths(&record_path_refs, &query).unwrap()
                        else {
                            panic!("complete ERS preceding TSA census");
                        };
                        paths
                    });
                    let record_actors = record_bound.as_ref().map(|paths| {
                        structured_cades::participants::participants_preserved(
                            basic.binding(),
                            basic.counter_paths(),
                            &credentials,
                            paths,
                            preservation.as_ref().unwrap(),
                            &query,
                        )
                        .unwrap()
                    });
                    let record_roots = record_actors.as_ref().map(|actors| {
                        let mut roots = vec![&tsa_statuses; actors.entries().len()];
                        roots[0] = &signer_statuses;
                        roots
                    });
                    let record_inputs =
                        record_actors
                            .as_ref()
                            .zip(record_roots.as_ref())
                            .map(|(actors, roots)| {
                                actors.close_statuses(roots, &supplied, &query).unwrap()
                            });
                    let record_x509 = record_inputs.as_ref().zip(record_archive.as_ref()).map(
                        |(inputs, archive)| {
                            structured_ltv::material::archived_participants(
                                inputs,
                                &index,
                                archive.coverage(),
                                archive.timestamp().actor().unwrap().verified(),
                                &query,
                            )
                            .unwrap()
                        },
                    );
                    let record_credentials = record_archive
                        .as_ref()
                        .zip(record_earlier.as_ref())
                        .map(|(archive, earlier)| {
                            material::credentials::check(
                                &credentials,
                                basic.counter_paths(),
                                earlier,
                                &index,
                                &material::credentials::Scope::before_archive(archive),
                                &handler,
                                &parent,
                            )
                            .unwrap()
                        });
                    let record_material = record_x509
                        .as_ref()
                        .zip(record_credentials.as_ref())
                        .map(|(x509, credentials)| {
                            baseline::archive_material(x509, credentials, &query).unwrap()
                        });
                    let mut reports = vec![&archive_material];
                    if let Some(record) = &record_material {
                        reports.push(record);
                    }
                    let archives = baseline::archives(&prepared, &reports, &query).unwrap();
                    let evidence = baseline::Evidence::Archival {
                        long_term: &long,
                        archives: &archives,
                    };
                    let assessment = if let Some(preservation) = &preservation {
                        baseline::assess_preserved(evidence, preservation, &parent).unwrap()
                    } else {
                        baseline::assess(evidence, &parent).unwrap()
                    };
                    assert!(assessment.all_requirements_met());
                } else {
                    let ordinary = baseline::assess(baseline::Evidence::LongTerm(&long), &parent);
                    let assessment = if let Some(preservation) = &preservation {
                        assert!(
                            matches!(
                                ordinary,
                                Err(baseline::LevelError::UnavailablePreservation {
                                    kind:
                                        structured_cades::preservation::Kind::EvidenceRecordInternal,
                                    ..
                                })
                            ),
                            "math alone cannot close a source preservation obligation"
                        );
                        baseline::assess_preserved(
                            baseline::Evidence::LongTerm(&long),
                            preservation,
                            &parent,
                        )
                        .unwrap()
                    } else {
                        ordinary.unwrap()
                    };
                    assert!(assessment.all_requirements_met());
                }
            }
        } else {
            assert!(
                answer.actor().is_none(),
                "wrong original input or unknown accuracy cannot issue a complete actor"
            );
            let TimestampPathBinding::Unproven(_) = prepared
                .timestamp_requirements()
                .bind_paths(&[], &query)
                .unwrap()
            else {
                panic!("dropping a failed original token cannot produce complete paths");
            };
        }
        assert_eq!(handler.0.get(), 0);
    }
}
