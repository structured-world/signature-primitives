//! Independent normative byte assembly and real SHA256 over historical inputs.
mod support;

#[path = "historical_inputs/references.rs"]
mod references;

use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use std::{cell::Cell, convert::Infallible};
use structured_asn1::{
    Parser,
    memory::{MemoryError, Work},
};
use structured_cades::{
    Level,
    prepare::Preparation,
    source::Document,
    timestamp::{
        self, NoDetached,
        historical::{
            Edition, Framing, HistoricalInput, OriginalSnapshot, SelectionError, Variant,
        },
    },
};
use structured_cms::{
    SignedData, oid,
    stream::{Receiver, Refused, Source},
    timestamp::ImprintAgreement,
};
use support::{Oracle, attribute, certificate, memory, message, signer, tlv};

const ARCHIVE_V1: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 27];
const ARCHIVE_V2: &[u8] = &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 48];

struct Fixture {
    root: Vec<u8>,
    certificate: Vec<u8>,
    tsa: Vec<u8>,
    signer: SigningKey,
    tsa_key: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let root_key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let signer = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let tsa_key = SigningKey::from_bytes((&[3u8; 32]).into()).unwrap();
        Self {
            root: certificate("Root", "Root", &root_key, &root_key, false),
            certificate: certificate("Signer", "Root", &signer, &root_key, false),
            tsa: certificate("TSA", "Root", &tsa_key, &root_key, true),
            signer,
            tsa_key,
        }
    }
    fn message(&self, unsigned: &[Vec<u8>], detached: bool, indefinite: bool) -> Vec<u8> {
        let mut signature = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &self.certificate,
            &self.signer,
            &[attribute(
                oid::SIGNING_TIME.as_bytes(),
                &tlv(0x17, b"260101000000Z"),
            )],
            unsigned,
        );
        if indefinite {
            let parser = Parser::ber(memory());
            let mut reader = parser.read(&signature, 0).unwrap();
            let element = reader.next_element().unwrap().unwrap();
            let parsed = structured_cms::signer::SignerInfo::read(&reader, &element).unwrap();
            let mut fields = parsed.signed_fields().to_vec();
            fields.extend([0xa1, 0x80]);
            fields.extend(parsed.unsigned_attributes().unwrap().element().contents());
            fields.extend([0, 0]);
            drop(parsed);
            drop(reader);
            signature = tlv(0x30, &fields);
        }
        message(
            oid::DATA.as_bytes(),
            if detached { None } else { Some(b"payload") },
            &[self.root.clone(), self.certificate.clone()],
            &[],
            &[signature],
        )
    }
    fn token(&self, covered: &[u8]) -> Vec<u8> {
        self.token_with_unsigned(covered, &[])
    }
    fn token_with_unsigned(&self, covered: &[u8], unsigned: &[Vec<u8>]) -> Vec<u8> {
        let imprint = tlv(
            0x30,
            &[
                tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
                tlv(4, &Sha256::digest(covered)),
            ]
            .concat(),
        );
        let info = tlv(
            0x30,
            &[
                vec![2, 1, 1],
                tlv(6, &[42, 3]),
                imprint,
                vec![2, 1, 9],
                tlv(24, b"20260101000100Z"),
                tlv(0x30, &[]),
            ]
            .concat(),
        );
        let signature = signer(
            Some(oid::TST_INFO.as_bytes()),
            &info,
            &self.tsa,
            &self.tsa_key,
            &[],
            unsigned,
        );
        message(
            oid::TST_INFO.as_bytes(),
            Some(&info),
            &[self.root.clone(), self.tsa.clone()],
            &[],
            &[signature],
        )
    }

    fn parallel_message(&self, archive: Option<&[u8]>, changed_parent: bool) -> Vec<u8> {
        let selected = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &self.certificate,
            &self.signer,
            &[],
            &[],
        );
        let original_parent = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &self.certificate,
            &self.signer,
            &[attribute(&[42, 3], &tlv(4, b"second root"))],
            &[],
        );
        let parent_signature = support::signature_octets(&original_parent);
        let child = signer(
            None,
            &parent_signature,
            &self.certificate,
            &self.signer,
            &[],
            &archive
                .map(|token| vec![attribute(ARCHIVE_V2, token)])
                .unwrap_or_default(),
        );
        let parent = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &self.certificate,
            &self.signer,
            &[attribute(
                &[42, 3],
                &tlv(
                    4,
                    if changed_parent {
                        b"another root"
                    } else {
                        b"second root"
                    },
                ),
            )],
            &[attribute(oid::COUNTERSIGNATURE.as_bytes(), &child)],
        );
        message(
            oid::DATA.as_bytes(),
            Some(b"payload"),
            &[self.root.clone(), self.certificate.clone()],
            &[],
            &[selected, parent],
        )
    }
}

#[test]
fn historical_tsa_legacy_values_keep_cardinality_faults() {
    // Registered validation-values cardinality belongs to the shared schema,
    // including inside a TSA signer. An empty/multivalued attribute cannot
    // become a clean optional property merely because no value is inspected.
    let fixture = Fixture::new();
    for last in [23, 24] {
        for count in [0, 2] {
            let mut kind = vec![42, 134, 72, 134, 247, 13, 1, 9, 16, 2];
            kind.push(last);
            let values = tlv(0x30, &[]).repeat(count);
            let malformed = tlv(0x30, &[tlv(6, &kind), tlv(0x31, &values)].concat());
            let token = fixture.token_with_unsigned(b"covered", &[malformed]);
            let bytes = fixture.message(&[attribute(ARCHIVE_V2, &token)], false, false);
            let parser = Parser::ber(memory());
            let data = SignedData::read(&parser, &bytes, 900).unwrap();
            let operation = parser.read(&[], 900).unwrap();
            let document = Document::new(&data, &operation).unwrap();
            let prepared =
                Preparation::read(&document, &data.signers()[0], Level::Basic, &operation).unwrap();
            timestamp::with_token(&prepared, 0, &operation, |context| {
                let faults = context.properties().unwrap().faults();
                assert_eq!(
                    faults.len(),
                    1,
                    "TSA values count {count}, OID suffix {last}"
                );
                assert!(matches!(
                    faults[0].cause,
                    structured_cades::Error::Syntax {
                        code: structured_cms::ErrorCode::AttributeCardinality,
                        ..
                    }
                ));
                assert_eq!(faults[0].cause.field(), Some("cades.legacy.values"));
                let attribute = &context
                    .token()
                    .signer()
                    .unsigned_attributes()
                    .unwrap()
                    .items()[0];
                assert_eq!(faults[0].cause.offset(), attribute.span().start);
                Ok::<_, Infallible>(())
            })
            .unwrap();
        }
    }
}

fn expected(before: &[u8], edition: Edition, headered: bool) -> Vec<u8> {
    // Trusted DEV oracle assembles the specification directly. It does not
    // call the production historical recipe or its projection helpers.
    let parser = Parser::ber(memory());
    let original = SignedData::read(&parser, before, 0).unwrap();
    let signer = &original.signers()[0];
    let mut bytes = Vec::new();
    if edition == Edition::Rfc3126 {
        if let Some(content) = original.content().content() {
            for part in content.pieces() {
                bytes.extend(part.as_bytes());
            }
        }
        if let Some(attributes) = signer.signed_attributes() {
            bytes.extend(attributes.element().contents());
        }
        bytes.extend(support::signature_octets(signer.as_bytes()));
        for last in [14, 21, 22, 23, 24, 25, 26, 27] {
            for attribute in signer.unsigned_attributes().unwrap().items() {
                if attribute.kind().as_bytes() == [42, 134, 72, 134, 247, 13, 1, 9, 16, 2, last] {
                    bytes.extend(attribute.element().contents());
                }
            }
        }
    } else {
        bytes.extend(original.encap_content_encoding());
        if edition == Edition::Rfc5126 && original.content().is_detached() {
            bytes.extend(b"payload");
        }
        if let Some(value) = original.certificate_encoding() {
            bytes.extend(value);
        }
        if let Some(value) = original.revocation_encoding() {
            bytes.extend(value);
        }
        bytes.extend(signer.signed_fields());
        if let Some(unsigned) = signer.unsigned_attributes() {
            bytes.extend(if headered {
                unsigned.element().as_bytes()
            } else {
                unsigned.element().contents()
            });
        }
    }
    bytes
}

#[derive(Debug)]
enum SourceFailure {
    Resource(MemoryError),
    Receiver(Refused),
}
impl std::fmt::Display for SourceFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resource(cause) => write!(out, "{cause}"),
            Self::Receiver(_) => out.write_str("receiver refused"),
        }
    }
}
struct Bytes<'a> {
    bytes: &'a [u8],
    passes: &'a Cell<usize>,
}
impl Source for Bytes<'_> {
    type Error = SourceFailure;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        work.charge_work(1).map_err(SourceFailure::Resource)?;
        self.passes.set(self.passes.get() + 1);
        for chunk in self.bytes.chunks(2) {
            work.charge_work(1).map_err(SourceFailure::Resource)?;
            receiver.write(chunk).map_err(SourceFailure::Receiver)?;
        }
        Ok(())
    }
}

#[test]
#[expect(
    clippy::result_large_err,
    reason = "exercise the real carried-information refusal without allocating a boxed replacement"
)]
fn v2_both_framings_share_one_detached_payload_pass() {
    // Both normative alternatives must finish from a single source pass. An
    // omitted detached source refuses BEFORE starting either provider state.
    let fixture = Fixture::new();
    for headered in [false, true] {
        let ordinary = attribute(&[42, 3], &tlv(4, b"opaque"));
        let before = fixture.message(std::slice::from_ref(&ordinary), true, false);
        let token = fixture.token(&expected(&before, Edition::Rfc5126, headered));
        let after = fixture.message(&[ordinary, attribute(ARCHIVE_V2, &token)], true, false);
        let account = memory();
        {
            let parser = Parser::ber(account.clone());
            let original = SignedData::read(&parser, &after, 900).unwrap();
            let operation = parser.read(&[], 900).unwrap();
            let document = Document::new(&original, &operation).unwrap();
            let prepared =
                Preparation::read(&document, &original.signers()[0], Level::Basic, &operation)
                    .unwrap();
            assert_eq!(prepared.timestamps().len(), 1);
            assert!(matches!(
                HistoricalInput::<NoDetached>::project(
                    &prepared,
                    0,
                    Edition::Rfc5126,
                    &[],
                    &[],
                    &operation,
                    None
                ),
                Err(SelectionError::MissingDetached)
            ));
            let passes = Cell::new(0);
            let mut source = Bytes {
                bytes: b"payload",
                passes: &passes,
            };
            let mut input = HistoricalInput::project(
                &prepared,
                0,
                Edition::Rfc5126,
                &[],
                &[],
                &operation,
                Some(&mut source),
            )
            .unwrap();
            let provider = Oracle::new();
            let agreement = timestamp::with_token(&prepared, 0, &operation, |context| {
                context
                    .token()
                    .with_info(context.reader(), |info, reader, _| {
                        Ok::<_, Infallible>(
                            info.imprint()
                                .check_input(&provider, reader, &mut input)
                                .unwrap(),
                        )
                    })
            })
            .unwrap();
            assert_eq!(agreement, ImprintAgreement::Matches);
            assert_eq!(passes.get(), 1);
            assert_eq!(provider.starts.get(), 2);
            assert_eq!(
                input.matched_variant(),
                Some(if headered {
                    Variant::UnsignedField
                } else {
                    Variant::UnsignedContents
                })
            );
        }
        assert_eq!(account.used(), 0);
    }
}

#[test]
#[expect(
    clippy::result_large_err,
    reason = "compare both original and projected paths through the actual source-map error contract"
)]
fn original_snapshot_retains_ber_wrapper_which_projection_cannot_recover() {
    // A final DER wrapper does NOT reveal the previous indefinite BER field.
    // Only the explicitly bound original snapshot can recover these bytes.
    let fixture = Fixture::new();
    let ordinary = attribute(&[42, 3], &tlv(4, b"opaque"));
    let before = fixture.message(std::slice::from_ref(&ordinary), false, true);
    let token = fixture.token(&expected(&before, Edition::Rfc5126, true));
    let after = fixture.message(&[ordinary, attribute(ARCHIVE_V2, &token)], false, false);
    let account = memory();
    {
        let old_parser = Parser::ber(account.clone());
        let old_message = SignedData::read(&old_parser, &before, 100).unwrap();
        let old_reader = old_parser.read(&[], 100).unwrap();
        let old_document = Document::new(&old_message, &old_reader).unwrap();
        let old_prepared = Preparation::read(
            &old_document,
            &old_message.signers()[0],
            Level::Basic,
            &old_reader,
        )
        .unwrap();
        let old_owner = old_document.signer(&old_message.signers()[0]).unwrap().node;
        let snapshot = OriginalSnapshot::capture(&old_prepared, old_owner, &old_reader).unwrap();
        let parser = Parser::ber(account.clone());
        let message = SignedData::read(&parser, &after, 900).unwrap();
        let reader = parser.read(&[], 900).unwrap();
        let document = Document::new(&message, &reader).unwrap();
        let prepared =
            Preparation::read(&document, &message.signers()[0], Level::Basic, &reader).unwrap();
        let provider = Oracle::new();
        let mut projection = HistoricalInput::<NoDetached>::project(
            &prepared,
            0,
            Edition::Rfc5126,
            &[],
            &[],
            &reader,
            None,
        )
        .unwrap();
        let projected = timestamp::with_token(&prepared, 0, &reader, |context| {
            context
                .token()
                .with_info(context.reader(), |info, source, _| {
                    Ok::<_, Infallible>(
                        info.imprint()
                            .check_input(&provider, source, &mut projection)
                            .unwrap(),
                    )
                })
        })
        .unwrap();
        assert_eq!(projected, ImprintAgreement::Differs);
        assert_eq!(projection.framing(), Framing::CanonicalDefiniteProjection);
        let mut input = HistoricalInput::<NoDetached>::from_snapshot(
            &prepared,
            0,
            Edition::Rfc5126,
            &snapshot,
            &[],
            &reader,
            None,
        )
        .unwrap();
        let actual = timestamp::with_token(&prepared, 0, &reader, |context| {
            context
                .token()
                .with_info(context.reader(), |info, source, _| {
                    Ok::<_, Infallible>(
                        info.imprint()
                            .check_input(&provider, source, &mut input)
                            .unwrap(),
                    )
                })
        })
        .unwrap();
        assert_eq!(actual, ImprintAgreement::Matches);
        assert_eq!(input.framing(), Framing::OriginalSnapshot);
        assert_eq!(input.matched_variant(), Some(Variant::UnsignedField));
    }
    assert_eq!(account.used(), 0);
}

#[test]
#[expect(
    clippy::result_large_err,
    reason = "the edition test retains the common inspection refusal rather than manufacturing a smaller test interface"
)]
fn v1_editions_are_explicit_and_early_contents_keep_normative_order() {
    // The same OID covers two distinct historical contracts. Neither uses
    // the V2 detached-byte rule or silently adds unknown early attributes.
    let fixture = Fixture::new();
    let legacy = [
        attribute(
            &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 23],
            &tlv(0x30, &fixture.certificate),
        ),
        attribute(
            &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 24],
            &tlv(0x30, &[]),
        ),
        attribute(&[42, 3], &tlv(4, b"opaque")),
    ];
    for edition in [Edition::Rfc3126, Edition::Ts101733V151] {
        for detached in [false, true] {
            let before = fixture.message(&legacy, detached, false);
            let token = fixture.token(&expected(&before, edition, true));
            let mut unsigned = legacy.to_vec();
            unsigned.push(attribute(ARCHIVE_V1, &token));
            let bytes = fixture.message(&unsigned, detached, false);
            let parser = Parser::ber(memory());
            let message = SignedData::read(&parser, &bytes, 900).unwrap();
            let reader = parser.read(&[], 900).unwrap();
            let document = Document::new(&message, &reader).unwrap();
            let prepared =
                Preparation::read(&document, &message.signers()[0], Level::Basic, &reader).unwrap();
            assert!(matches!(
                HistoricalInput::<NoDetached>::project(
                    &prepared,
                    0,
                    Edition::Rfc5126,
                    &[],
                    &[],
                    &reader,
                    None
                ),
                Err(SelectionError::WrongEdition)
            ));
            let mut input = HistoricalInput::<NoDetached>::project(
                &prepared,
                0,
                edition,
                &[],
                &[],
                &reader,
                None,
            )
            .unwrap();
            let provider = Oracle::new();
            let actual = timestamp::with_token(&prepared, 0, &reader, |context| {
                context
                    .token()
                    .with_info(context.reader(), |info, source, _| {
                        Ok::<_, Infallible>(
                            info.imprint()
                                .check_input(&provider, source, &mut input)
                                .unwrap(),
                        )
                    })
            })
            .unwrap();
            assert_eq!(
                actual,
                ImprintAgreement::Matches,
                "{edition:?}, detached={detached}"
            );
            assert_eq!(provider.starts.get(), 1);
        }
    }
}

#[test]
#[expect(
    clippy::result_large_err,
    reason = "assert the exact modern-dispatch refusal and independently qualify the genuine historical TSA receipt"
)]
#[expect(
    clippy::too_many_lines,
    reason = "verify each historical edition's complete native TSA/ESS/key/path receipt alongside rejection by the modern dispatcher"
)]
fn legacy_token_cannot_enter_the_modern_archive_dispatcher() {
    // A purpose alone is insufficient: an old attribute could carry an ATSv3
    // index. Dispatch must reject the WRONG format before even looking it up.
    for edition in [Edition::Rfc3126, Edition::Ts101733V151, Edition::Rfc5126] {
        let fixture = Fixture::new();
        // Later editions hash the complete countersignature attribute. Its
        // nested TSA must therefore remain an earlier validation obligation;
        // RFC3126's fixed category recipe does not include countersignatures.
        let nested = fixture.token(b"nested signature");
        let counter = signer(
            None,
            b"parent signature",
            &fixture.certificate,
            &fixture.signer,
            &[],
            &[attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &nested)],
        );
        let mut unsigned = vec![
            attribute(oid::COUNTERSIGNATURE.as_bytes(), &counter),
            attribute(&[42, 3], &tlv(4, b"opaque")),
            attribute(
                &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 23],
                &tlv(0x30, &fixture.certificate),
            ),
            attribute(
                &[42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 24],
                &tlv(0x30, &[]),
            ),
        ];
        let before = fixture.message(&unsigned, false, false);
        let token = fixture.token(&expected(&before, edition, true));
        unsigned.push(attribute(
            if edition == Edition::Rfc5126 {
                ARCHIVE_V2
            } else {
                ARCHIVE_V1
            },
            &token,
        ));
        let bytes = fixture.message(&unsigned, false, false);
        let parser = Parser::ber(memory());
        let message = SignedData::read(&parser, &bytes, 900).unwrap();
        let operation = parser.read(&[], 900).unwrap();
        let work = operation.execution();
        let root = message
            .certificates()
            .iter()
            .find(|certificate| certificate.as_bytes() == fixture.root)
            .unwrap();
        let tsa = structured_pkix::Certificate::read(&parser, &fixture.tsa, 50000).unwrap();
        let oracle = Oracle::new();
        let interval = structured_pkix::path::Interval::between(
            tsa.tbs().validity().not_before().seconds(),
            tsa.tbs().validity().not_after().seconds(),
        );
        let utc =
            structured_pkix::temporal::LeapTable::new(interval.from(), interval.to(), &[]).unwrap();
        let context = structured_pkix::path::ValidationContext {
            execution: &work,
            interval,
            policy: structured_pkix::path::Policy::default(),
            bounds: structured_pkix::path::ValidationBounds::default(),
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let structured_ltv::pki::PathOutcome::Accepted(path) = structured_ltv::pki::check_path(
            &[&tsa],
            structured_pkix::path::Anchor::from_certificate(root),
            &context,
        )
        .unwrap() else {
            panic!("real TSA path");
        };
        let document = Document::new(&message, &operation).unwrap();
        let prepared =
            Preparation::read(&document, &message.signers()[0], Level::Basic, &operation).unwrap();
        let ordinal = prepared
            .timestamps()
            .iter()
            .position(|entry| entry.value().is_some_and(|value| value.as_bytes() == token))
            .unwrap();
        let time = timestamp::CheckTime {
            utc: &utc,
            reference: Some(interval.to_instant()),
        };
        let starts = oracle.starts.get();
        let result = timestamp::with_token(&prepared, ordinal, &operation, |context| {
            context.check_archive_carried(&oracle, &path, &operation, &time, |_, _| {
                Ok::<_, Infallible>(true)
            })
        });
        assert!(
            matches!(
                result,
                Err(timestamp::VisitError::Callback(
                    timestamp::ArchiveCheckError::Before(timestamp::ArchiveError::Processing(
                        structured_cades::Error::Foreign { .. }
                    ))
                ))
            ),
            "wrong format dispatch"
        );
        assert_eq!(oracle.starts.get(), starts);
        let mut input = HistoricalInput::<NoDetached>::project(
            &prepared,
            ordinal,
            edition,
            &[],
            &[],
            &operation,
            None,
        )
        .unwrap();
        let checked = timestamp::with_token(&prepared, ordinal, &operation, |context| {
            context.check_historical(&oracle, &path, &operation, &time, &mut input, |_, _| {
                Ok::<_, Infallible>(true)
            })
        })
        .unwrap();
        assert!(
            checked.timestamp().actor().is_some(),
            "real signature, ESS, selected TSA key, path and imprint"
        );
        assert_eq!(checked.timestamp().imprint, ImprintAgreement::Matches);
        assert_eq!(
            checked.matched_variant(),
            Some(if edition == Edition::Rfc3126 {
                Variant::ListedContents
            } else {
                Variant::UnsignedField
            })
        );
        let required = checked.requirements(&prepared, &operation).unwrap();
        assert_eq!(
            required.entries().len(),
            usize::from(edition != Edition::Rfc3126),
            "exclude the archive's own TSA, retain every covered nested TSA"
        );
        if let Some(entry) = required.entries().first() {
            let nested = prepared
                .timestamps()
                .iter()
                .find(|entry| {
                    entry
                        .value()
                        .is_some_and(|value| value.as_bytes() == nested)
                })
                .unwrap();
            assert_eq!(entry.signature, nested.owner());
            assert_eq!(entry.property, nested.property());
        }
    }
}

#[test]
fn signed_historical_attribute_keeps_its_source_but_fails_placement() {
    // RFC5126 §6.4.1 defines an UNSIGNED attribute. An otherwise readable
    // token under signedAttrs is a located format failure, not a valid input.
    let fixture = Fixture::new();
    let token = fixture.token(b"unrelated timestamp input");
    let encoded_signer = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &fixture.certificate,
        &fixture.signer,
        &[attribute(ARCHIVE_V2, &token)],
        &[],
    );
    let bytes = message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[fixture.root.clone(), fixture.certificate.clone()],
        &[],
        &[encoded_signer],
    );
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 900).unwrap();
    let reader = parser.read(&[], 900).unwrap();
    let document = Document::new(&data, &reader).unwrap();
    let prepared = Preparation::read(&document, &data.signers()[0], Level::Basic, &reader).unwrap();
    assert_eq!(prepared.preservation().len(), 1);
    assert_eq!(prepared.timestamps().len(), 1);
    assert!(
        prepared.findings().iter().any(|finding| matches!(
            finding.rule,
            structured_cades::prepare::Rule::Schema {
                code: structured_cms::ErrorCode::AttributePlacement,
                ..
            }
        )),
        "historical signed placement"
    );
    assert!(matches!(
        HistoricalInput::<NoDetached>::project(
            &prepared,
            0,
            Edition::Rfc5126,
            &[],
            &[],
            &reader,
            None
        ),
        Err(SelectionError::WrongOccurrence)
    ));
}

#[test]
#[expect(
    clippy::result_large_err,
    reason = "preserve the original carried-information source map while checking the counter's actual parent binding"
)]
#[expect(
    clippy::too_many_lines,
    reason = "qualify the actual parallel counter's archive with its complete native TSA path and unchanged-parent refusal"
)]
fn other_root_counter_keeps_original_fields_and_parent_binding() {
    // The selected root has NO counters. A parallel root's child is still an
    // archive participant after its walking frame has been dropped. Moving
    // the same child under a changed parent must not reuse an old snapshot.
    let fixture = Fixture::new();
    let before = fixture.parallel_message(None, false);
    let old_parser = Parser::ber(memory());
    let old_data = SignedData::read(&old_parser, &before, 100).unwrap();
    let old_reader = old_parser.read(&[], 100).unwrap();
    let old_document = Document::new(&old_data, &old_reader).unwrap();
    let selected = old_data
        .signers()
        .iter()
        .find(|signer| signer.unsigned_attributes().is_none())
        .unwrap();
    let parent = old_data
        .signers()
        .iter()
        .find(|signer| signer.unsigned_attributes().is_some())
        .unwrap();
    let child = parent
        .countersignatures_in(&old_reader)
        .next()
        .unwrap()
        .unwrap();
    let mut covered = old_data.encap_content_encoding().to_vec();
    covered.extend(old_data.certificate_encoding().unwrap());
    covered.extend(child.signed_fields());
    let token = fixture.token(&covered);
    let old_prepared =
        Preparation::read(&old_document, selected, Level::Basic, &old_reader).unwrap();
    assert!(old_prepared.counters().is_empty());
    assert_eq!(old_prepared.parallel_counters().len(), 1);
    let snapshot = OriginalSnapshot::capture(
        &old_prepared,
        old_prepared.parallel_counters()[0].node(),
        &old_reader,
    )
    .unwrap();
    for changed_parent in [false, true] {
        let bytes = fixture.parallel_message(Some(&token), changed_parent);
        let parser = Parser::ber(memory());
        let data = SignedData::read(&parser, &bytes, 900).unwrap();
        let reader = parser.read(&[], 900).unwrap();
        let document = Document::new(&data, &reader).unwrap();
        let selected = data
            .signers()
            .iter()
            .find(|signer| signer.unsigned_attributes().is_none())
            .unwrap();
        let prepared = Preparation::read(&document, selected, Level::Basic, &reader).unwrap();
        assert!(prepared.counters().is_empty());
        assert_eq!(prepared.parallel_counters().len(), 1);
        assert_eq!(prepared.timestamps().len(), 1);
        let owner = prepared.parallel_counters()[0].node();
        assert_eq!(prepared.timestamps()[0].owner(), owner);
        let input = HistoricalInput::<NoDetached>::from_snapshot(
            &prepared,
            0,
            Edition::Rfc5126,
            &snapshot,
            &[],
            &reader,
            None,
        );
        if changed_parent {
            assert!(matches!(input, Err(SelectionError::PriorNotPreserved)));
        } else {
            let oracle = Oracle::new();
            let tsa = structured_pkix::Certificate::read(&parser, &fixture.tsa, 50000).unwrap();
            let root = data
                .certificates()
                .iter()
                .find(|value| value.as_bytes() == fixture.root)
                .unwrap();
            let interval = structured_pkix::path::Interval::between(
                tsa.tbs().validity().not_before().seconds(),
                tsa.tbs().validity().not_after().seconds(),
            );
            let utc =
                structured_pkix::temporal::LeapTable::new(interval.from(), interval.to(), &[])
                    .unwrap();
            let work = reader.execution();
            let validation = structured_pkix::path::ValidationContext {
                execution: &work,
                interval,
                policy: structured_pkix::path::Policy::default(),
                bounds: structured_pkix::path::ValidationBounds::default(),
                verifier: &oracle,
                watch: &(),
                recognizer: &(),
            };
            let structured_ltv::pki::PathOutcome::Accepted(path) = structured_ltv::pki::check_path(
                &[&tsa],
                structured_pkix::path::Anchor::from_certificate(root),
                &validation,
            )
            .unwrap() else {
                panic!("real TSA path")
            };
            let time = timestamp::CheckTime {
                utc: &utc,
                reference: Some(interval.to_instant()),
            };
            let mut input = input.unwrap();
            let checked = timestamp::with_token(&prepared, 0, &reader, |context| {
                context.check_historical(&oracle, &path, &reader, &time, &mut input, |_, _| {
                    Ok::<_, Infallible>(true)
                })
            })
            .unwrap();
            assert!(checked.timestamp().actor().is_some());
            assert_eq!(checked.timestamp().imprint, ImprintAgreement::Matches);
            // The verified archive belongs to this parallel counter, not the
            // selected root. Its own preceding census must still be usable.
            let required = checked.requirements(&prepared, &reader).unwrap();
            assert_eq!(required.signature(), owner);
            assert!(required.entries().is_empty());
            let pool = structured_cades::material::Pool::read(&prepared, &reader).unwrap();
            let query = structured_ltv::source::Scope::new(
                &document,
                structured_ltv::source::Source::snapshot(&document),
                &work,
            );
            let index = pool.index_for_archive((&checked).into(), &query).unwrap();
            assert!(
                matches!(
                    index
                        .archived(
                            structured_ltv::material::ArtifactRef::Certificate(root),
                            checked.coverage(),
                            checked.timestamp().actor().unwrap().verified(),
                            &query,
                        )
                        .unwrap(),
                    structured_ltv::material::Archived::Present(_)
                ),
                "the counter archive hashes the actual global certificate field"
            );
            let refused = structured_asn1::memory::Memory::new(std::sync::Arc::new(
                structured_asn1::memory::MemoryAccount::new(1 << 20, 0),
            ));
            let limited = structured_ltv::source::Scope::new(
                &document,
                structured_ltv::source::Source::snapshot(&document),
                &refused,
            );
            assert!(matches!(
                pool.index_for_archive((&checked).into(), &limited),
                Err(structured_cades::material::ArchiveIndexError::Coverage(
                    structured_ltv::material::CoverageError::Scope(
                        structured_ltv::source::ScopeError::Resource { .. }
                    )
                ))
            ));
            assert_eq!(refused.used(), 0);
            let foreign = structured_ltv::source::Scope::new(
                &old_document,
                structured_ltv::source::Source::snapshot(&old_document),
                &refused,
            );
            assert!(matches!(
                pool.index_for_archive((&checked).into(), &foreign),
                Err(structured_cades::material::ArchiveIndexError::Index(
                    structured_ltv::material::IndexError::Foreign { .. }
                ))
            ));
            assert_eq!(refused.used(), 0);
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one adversarial two-receipt transaction must show actual signatures, later coverage, resource refusal and material-scope isolation together"
)]
#[expect(
    clippy::result_large_err,
    reason = "both real timestamp checks keep the original unboxed processing/provider failure shape"
)]
fn later_receipt_covers_earlier_value_in_same_archive_attribute() {
    // Both tokens deliberately have the SAME genTime. Only completed input
    // coverage may justify excluding the later token from the earlier input.
    // A shared attribute ID must not erase the OTHER earlier TSA participant.
    use timestamp::historical::Later;
    let fixture = Fixture::new();
    let ordinary = attribute(&[42, 3], &tlv(4, b"opaque"));
    let before = fixture.message(std::slice::from_ref(&ordinary), false, false);
    let first = fixture.token(&expected(&before, Edition::Rfc5126, true));
    let intermediate = fixture.message(
        &[ordinary.clone(), attribute(ARCHIVE_V2, &first)],
        false,
        false,
    );
    let second = fixture.token(&expected(&intermediate, Edition::Rfc5126, true));
    let bytes = fixture.message(
        &[
            ordinary.clone(),
            attribute(ARCHIVE_V2, &[first.clone(), second.clone()].concat()),
        ],
        false,
        false,
    );
    let parser = Parser::ber(memory());
    let message = SignedData::read(&parser, &bytes, 900).unwrap();
    let operation = parser.read(&[], 900).unwrap();
    let work = operation.execution();
    let root = message
        .certificates()
        .iter()
        .find(|certificate| certificate.as_bytes() == fixture.root)
        .unwrap();
    let tsa = structured_pkix::Certificate::read(&parser, &fixture.tsa, 50000).unwrap();
    let oracle = Oracle::new();
    let interval = structured_pkix::path::Interval::between(
        tsa.tbs().validity().not_before().seconds(),
        tsa.tbs().validity().not_after().seconds(),
    );
    let utc =
        structured_pkix::temporal::LeapTable::new(interval.from(), interval.to(), &[]).unwrap();
    let validation = structured_pkix::path::ValidationContext {
        execution: &work,
        interval,
        policy: structured_pkix::path::Policy::default(),
        bounds: structured_pkix::path::ValidationBounds::default(),
        verifier: &oracle,
        watch: &(),
        recognizer: &(),
    };
    let structured_ltv::pki::PathOutcome::Accepted(path) = structured_ltv::pki::check_path(
        &[&tsa],
        structured_pkix::path::Anchor::from_certificate(root),
        &validation,
    )
    .unwrap() else {
        panic!("real TSA path")
    };
    let document = Document::new(&message, &operation).unwrap();
    let prepared =
        Preparation::read(&document, &message.signers()[0], Level::Basic, &operation).unwrap();
    let a = prepared
        .timestamps()
        .iter()
        .position(|entry| entry.value().unwrap().as_bytes() == first)
        .unwrap();
    let b = prepared
        .timestamps()
        .iter()
        .position(|entry| entry.value().unwrap().as_bytes() == second)
        .unwrap();
    assert_eq!(
        prepared.timestamps()[a].property(),
        prepared.timestamps()[b].property()
    );
    let starts = oracle.starts.get();
    assert!(matches!(
        HistoricalInput::<NoDetached>::project(
            &prepared,
            a,
            Edition::Rfc5126,
            &[],
            &[],
            &operation,
            None
        ),
        Err(SelectionError::UnprovenLater { .. })
    ));
    assert_eq!(oracle.starts.get(), starts);
    let time = timestamp::CheckTime {
        utc: &utc,
        reference: Some(interval.to_instant()),
    };
    let mut input = HistoricalInput::<NoDetached>::project(
        &prepared,
        b,
        Edition::Rfc5126,
        &[a],
        &[],
        &operation,
        None,
    )
    .unwrap();
    let checked = timestamp::with_token(&prepared, b, &operation, |context| {
        context.check_historical(&oracle, &path, &operation, &time, &mut input, |_, _| {
            Ok::<_, Infallible>(true)
        })
    })
    .unwrap();
    assert!(checked.timestamp().actor().is_some());
    assert_eq!(checked.timestamp().imprint, ImprintAgreement::Matches);
    assert_eq!(
        checked
            .requirements(&prepared, &operation)
            .unwrap()
            .entries()
            .len(),
        1
    );
    let proof = Later::historical(&checked).unwrap();
    for allowance in 0..128 {
        let current = structured_asn1::memory::Memory::new(std::sync::Arc::new(
            structured_asn1::memory::MemoryAccount::new(1 << 20, allowance),
        ));
        let query = parser.read(&[], 900).unwrap().with_execution(&current);
        let result = HistoricalInput::<NoDetached>::project(
            &prepared,
            a,
            Edition::Rfc5126,
            &[],
            &[Later::historical(&checked).unwrap()],
            &query,
            None,
        );
        assert!(
            !matches!(result, Err(SelectionError::WrongOccurrence)),
            "resource refusal became a wrong occurrence at allowance {allowance}"
        );
        drop(result);
        assert_eq!(current.used(), 0);
    }
    let mut input = HistoricalInput::<NoDetached>::project(
        &prepared,
        a,
        Edition::Rfc5126,
        &[],
        &[proof],
        &operation,
        None,
    )
    .unwrap();
    let earlier = timestamp::with_token(&prepared, a, &operation, |context| {
        context.check_historical(&oracle, &path, &operation, &time, &mut input, |_, _| {
            Ok::<_, Infallible>(true)
        })
    })
    .unwrap();
    assert_eq!(earlier.timestamp().imprint, ImprintAgreement::Matches);
    assert!(earlier.timestamp().actor().is_some());
    assert_ne!(
        earlier
            .requirements(&prepared, &operation)
            .unwrap()
            .scope()
            .location()
            .node,
        checked
            .requirements(&prepared, &operation)
            .unwrap()
            .scope()
            .location()
            .node,
        "member-specific inputs must not share a validation-material scope"
    );
    let query = structured_ltv::source::Scope::new(
        &document,
        structured_ltv::source::Source::snapshot(&document),
        &work,
    );
    let earlier_value = earlier.timestamp().actor().unwrap().verified().token().node;
    assert!(
        matches!(
            checked.coverage().covers(
                earlier.timestamp().actor().unwrap().verified(),
                earlier_value,
                &query
            ),
            Err(structured_ltv::material::CoverageError::Foreign { .. })
        ),
        "two token values sharing an attribute must not substitute their coverage receipts"
    );
    assert_credential_scope(&prepared, &operation, &fixture, &oracle, &earlier, &checked);

    // A separately carried earlier archive can retain its original VALUE
    // while its whole Attribute wrapper changes. The snapshot hashes the
    // genuine old BER; it must not grant coverage of the new DER wrapper.
    let minimal = attribute(ARCHIVE_V2, &first);
    let mut ber = vec![0x30, 0x80];
    {
        let mut fields = parser.read(&minimal, 90000).unwrap();
        ber.extend(fields.next_element().unwrap().unwrap().contents());
    }
    ber.extend([0, 0]);
    let before = fixture.message(&[ordinary.clone(), ber], false, false);
    let next = fixture.token(&expected(&before, Edition::Rfc5126, true));
    let after = fixture.message(
        &[ordinary, minimal, attribute(ARCHIVE_V2, &next)],
        false,
        false,
    );
    let old_message = SignedData::read(&parser, &before, 200_000).unwrap();
    let old_reader = parser.read(&[], 200_000).unwrap();
    let old_document = Document::new(&old_message, &old_reader).unwrap();
    let old = Preparation::read(
        &old_document,
        &old_message.signers()[0],
        Level::Basic,
        &old_reader,
    )
    .unwrap();
    let snapshot = OriginalSnapshot::capture(
        &old,
        old_document.signer(&old_message.signers()[0]).unwrap().node,
        &old_reader,
    )
    .unwrap();
    let message = SignedData::read(&parser, &after, 300_000).unwrap();
    let reader = parser.read(&[], 300_000).unwrap();
    let document = Document::new(&message, &reader).unwrap();
    let prepared =
        Preparation::read(&document, &message.signers()[0], Level::Basic, &reader).unwrap();
    let a = prepared
        .timestamps()
        .iter()
        .position(|entry| entry.value().unwrap().as_bytes() == first)
        .unwrap();
    let b = prepared
        .timestamps()
        .iter()
        .position(|entry| entry.value().unwrap().as_bytes() == next)
        .unwrap();
    let mut input = HistoricalInput::<NoDetached>::from_snapshot(
        &prepared,
        b,
        Edition::Rfc5126,
        &snapshot,
        &[],
        &reader,
        None,
    )
    .unwrap();
    let checked = timestamp::with_token(&prepared, b, &reader, |context| {
        context.check_historical(&oracle, &path, &operation, &time, &mut input, |_, _| {
            Ok::<_, Infallible>(true)
        })
    })
    .unwrap();
    let verified = checked.timestamp().actor().unwrap().verified();
    let work = reader.execution();
    let query = structured_ltv::source::Scope::new(
        &document,
        structured_ltv::source::Source::snapshot(&document),
        &work,
    );
    assert!(
        checked
            .coverage()
            .covers(
                verified,
                prepared.timestamp_requirements().entries()[a].token,
                &query
            )
            .unwrap()
    );
    assert!(
        !checked
            .coverage()
            .covers(verified, prepared.timestamps()[a].property(), &query)
            .unwrap(),
        "an original archive value cannot authenticate its changed enclosing wrapper"
    );
}

/// Exercise the EXISTING credential-material route with historical receipts,
/// an actually authenticated root, and a truly empty format-credential census.
#[expect(
    clippy::too_many_lines,
    reason = "qualify the historical material route with the complete real root path/CMS/credential transaction and its sibling negative"
)]
fn assert_credential_scope<'m, 'd>(
    prepared: &Preparation<'m, 'd>,
    operation: &structured_asn1::Reader<'d>,
    fixture: &Fixture,
    oracle: &Oracle,
    earlier: &timestamp::historical::HistoricalChecked<'m, 'd, '_>,
    later: &timestamp::historical::HistoricalChecked<'m, 'd, '_>,
) {
    use structured_cades::{basic, counters, credential, material};
    let message = prepared.document().message();
    let leaf = message
        .certificates()
        .iter()
        .find(|value| value.as_bytes() == fixture.certificate)
        .unwrap();
    let root = message
        .certificates()
        .iter()
        .find(|value| value.as_bytes() == fixture.root)
        .unwrap();
    let interval = structured_pkix::path::Interval::between(
        leaf.tbs().validity().not_before().seconds(),
        leaf.tbs().validity().not_after().seconds(),
    );
    let work = operation.execution();
    let validation = structured_pkix::path::ValidationContext {
        execution: &work,
        interval,
        policy: structured_pkix::path::Policy::default(),
        bounds: structured_pkix::path::ValidationBounds::default(),
        verifier: oracle,
        watch: &(),
        recognizer: &(),
    };
    let structured_ltv::pki::PathOutcome::Accepted(path) = structured_ltv::pki::check_path(
        &[leaf],
        structured_pkix::path::Anchor::from_certificate(root),
        &validation,
    )
    .unwrap() else {
        panic!("real signer path")
    };
    let structured_cms::prepare::Preparation::Ready(plan) = structured_cms::prepare::resolve(
        oracle,
        prepared.signer(),
        path.members().last().unwrap().key(),
        operation,
        structured_cms::binding::Scope::Content(oid::DATA),
    )
    .unwrap() else {
        panic!("real root plan")
    };
    let mut plans = work.vector();
    plans.try_push(plan).unwrap();
    let checks = structured_cms::verify::DocumentBatch::prepare(
        oracle,
        message,
        plans.into_owned(),
        structured_cms::verify::ContentMode::Carried,
        operation,
    )
    .unwrap()
    .run_carried()
    .unwrap();
    let binding = basic::bind(
        prepared,
        &checks,
        &checks.checks()[0],
        leaf,
        Some(&path),
        oracle,
        operation,
    )
    .unwrap();
    assert!(binding.is_bound());
    let counter_checks = counters::bind(prepared, operation, |context| {
        context.check(oracle, leaf, &path)
    })
    .unwrap();
    let counters = counter_checks.paths().unwrap();
    let credentials =
        credential::check(prepared, &binding, &counters, &NoCredentials, operation).unwrap();
    let complete = credentials.complete().unwrap();
    let pool = material::Pool::read(prepared, operation).unwrap();
    let query = structured_ltv::source::Scope::new(
        prepared.document(),
        structured_ltv::source::Source::snapshot(prepared.document()),
        &work,
    );
    let index = pool.index(&query).unwrap();
    let required = earlier.requirements(prepared, operation).unwrap();
    let report = material::credentials::check(
        &complete,
        &counters,
        &required,
        &index,
        &material::credentials::Scope::before_archive(earlier),
        &NoCredentials,
        operation,
    )
    .unwrap();
    assert!(report.all_requirements_met());
    assert!(
        matches!(
            material::credentials::check(
                &complete,
                &counters,
                &required,
                &index,
                &material::credentials::Scope::before_archive(later),
                &NoCredentials,
                operation
            ),
            Err(material::credentials::Error::Foreign { .. })
        ),
        "a valid sibling cannot supply this input's credential-material scope"
    );
}

struct NoCredentials;
impl<'p, 'd> structured_cades::credential::Provider<'p, 'd> for NoCredentials {
    type Evidence = ();
    type Error = Infallible;
    fn authenticate(
        &self,
        _: structured_cades::credential::Context<'_, '_, 'd>,
    ) -> Result<structured_ltv::credential::Authentication<'p, 'd, ()>, Infallible> {
        panic!("the source has no format credentials")
    }
}
impl structured_cades::material::credentials::Provider<()> for NoCredentials {
    type Error = Infallible;
    fn visit<'m, 'd, V>(
        &self,
        _: &structured_cades::credential::Checked<'m, 'd, '_, ()>,
        _: &[structured_cades::material::Open<'d>],
        _: &structured_asn1::ScopedReader<'d, '_>,
        _: impl for<'v, 's> FnMut(
            structured_cades::material::credentials::Need<'v, 's, 'm, 'd>,
        ) -> Result<(), V>,
    ) -> Result<
        structured_cades::material::credentials::Completeness,
        structured_cades::material::credentials::VisitError<Infallible, V>,
    > {
        panic!("the empty census cannot invoke a dependency handler")
    }
}

#[test]
fn historical_recipe_checks_current_capacity_work_and_original_session() {
    // A cached/prepared document is not credit for a NEW recipe's storage or
    // work. Refusal releases partial descriptors; same account is not proof
    // of the same producing parser.
    use std::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};
    let fixture = Fixture::new();
    let before = fixture.message(&[], false, false);
    let token = fixture.token(&expected(&before, Edition::Rfc5126, true));
    let bytes = fixture.message(&[attribute(ARCHIVE_V2, &token)], false, false);
    let parser = Parser::ber(memory());
    let message = SignedData::read(&parser, &bytes, 900).unwrap();
    let reader = parser.read(&[], 900).unwrap();
    let document = Document::new(&message, &reader).unwrap();
    let prepared =
        Preparation::read(&document, &message.signers()[0], Level::Basic, &reader).unwrap();
    for (capacity, work) in [(0, 1_000_000), (1_000_000, 0)] {
        let current = Memory::new(Arc::new(MemoryAccount::new(capacity, work)));
        let operation = parser.read(&[], 900).unwrap().with_execution(&current);
        assert!(matches!(
            HistoricalInput::<NoDetached>::project(
                &prepared,
                0,
                Edition::Rfc5126,
                &[],
                &[],
                &operation,
                None
            ),
            Err(SelectionError::Processing(_))
        ));
        assert_eq!(current.used(), 0, "no successful partial catalogue");
    }
    let foreign = Parser::ber(parser.memory().clone());
    let foreign = foreign.read(&[], 900).unwrap();
    assert!(matches!(
        HistoricalInput::<NoDetached>::project(
            &prepared,
            0,
            Edition::Rfc5126,
            &[],
            &[],
            &foreign,
            None
        ),
        Err(SelectionError::Processing(_))
    ));
}

#[test]
fn snapshot_binding_retains_its_original_local_ceiling() {
    // Even a generous NEW operation must not bypass an exhausted original
    // snapshot's local ceiling. The refusal retains the PRIOR source role.
    let fixture = Fixture::new();
    let before = fixture.message(&[], false, false);
    let token = fixture.token(&expected(&before, Edition::Rfc5126, true));
    let bytes = fixture.message(&[attribute(ARCHIVE_V2, &token)], false, false);
    let old_account = memory();
    let old_limits = structured_asn1::Limits {
        max_work: 1_000_000,
        ..structured_asn1::Limits::default()
    };
    let old_parser = Parser::new(
        structured_asn1::Encoding::Ber,
        old_limits,
        old_account.clone(),
    );
    let old_data = SignedData::read(&old_parser, &before, 100).unwrap();
    let old_reader = old_parser.read(&[], 100).unwrap();
    let old_document = Document::new(&old_data, &old_reader).unwrap();
    let old_prepared = Preparation::read(
        &old_document,
        &old_data.signers()[0],
        Level::Basic,
        &old_reader,
    )
    .unwrap();
    let snapshot = OriginalSnapshot::capture(
        &old_prepared,
        old_document.signer(&old_data.signers()[0]).unwrap().node,
        &old_reader,
    )
    .unwrap();
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 900).unwrap();
    let reader = parser.read(&[], 900).unwrap();
    let document = Document::new(&data, &reader).unwrap();
    let prepared = Preparation::read(&document, &data.signers()[0], Level::Basic, &reader).unwrap();
    old_reader
        .execution()
        .charge_work(old_limits.max_work - old_account.work_used() as u64)
        .unwrap();
    let held = reader.memory().used();
    assert!(matches!(
        HistoricalInput::<NoDetached>::from_snapshot(
            &prepared,
            0,
            Edition::Rfc5126,
            &snapshot,
            &[],
            &reader,
            None
        ),
        Err(SelectionError::PriorProcessing(_))
    ));
    assert_eq!(reader.memory().used(), held);
}

#[test]
fn unreadable_parallel_counter_is_a_preservation_source_finding() {
    // An unreadable parallel counter can hide historical properties. Keep
    // the selected root's independent B-B facts, but never claim that the
    // complete historical source/authority census succeeded without a cause.
    let fixture = Fixture::new();
    let token = fixture.token(b"source inspection does not assert an imprint");
    let selected = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &fixture.certificate,
        &fixture.signer,
        &[attribute(
            oid::SIGNING_TIME.as_bytes(),
            &tlv(23, b"260101000000Z"),
        )],
        &[attribute(ARCHIVE_V2, &token)],
    );
    let parallel = signer(
        Some(oid::DATA.as_bytes()),
        b"payload",
        &fixture.certificate,
        &fixture.signer,
        &[attribute(&[42, 3], &tlv(4, b"parallel root"))],
        &[attribute(oid::COUNTERSIGNATURE.as_bytes(), &tlv(4, &[]))],
    );
    let bytes = message(
        oid::DATA.as_bytes(),
        Some(b"payload"),
        &[fixture.root.clone(), fixture.certificate.clone()],
        &[],
        &[selected, parallel],
    );
    let parser = Parser::ber(memory());
    let data = SignedData::read(&parser, &bytes, 900).unwrap();
    let reader = parser.read(&[], 900).unwrap();
    let document = Document::new(&data, &reader).unwrap();
    let selected = data
        .signers()
        .iter()
        .find(|signer| {
            signer
                .unsigned_attributes()
                .unwrap()
                .items()
                .iter()
                .any(|attribute| attribute.kind().as_bytes() == ARCHIVE_V2)
        })
        .unwrap();
    let prepared = Preparation::read(&document, selected, Level::Basic, &reader).unwrap();
    let counter = &prepared.parallel_counters()[0];
    assert!(counter.malformed().is_some());
    assert!(prepared.basic_format_requirements_met());
    assert!(
        prepared
            .preservation_findings()
            .iter()
            .any(|finding| finding.location.node == counter.node()
                && finding.severity == structured_cades::prepare::Severity::Required)
    );
}
