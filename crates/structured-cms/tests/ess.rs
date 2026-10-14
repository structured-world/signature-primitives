//! ESS schema defaults, retained restrictions, faults and producing ceilings.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_cms::ess::{
    CertificateReading, IssuerAgreement, IssuerReading, SigningAttributes, SigningCertificate,
    Version,
};
use structured_cms::provider::{DigestAlgorithm, ImpliedDigest};
use structured_cms::{ErrorCode, oid};

#[path = "ess/binding.rs"]
mod binding;

fn memory(storage: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(storage, work)))
}
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if contents.len() < 128 {
        bytes.push(u8::try_from(contents.len()).unwrap());
    } else {
        bytes.extend_from_slice(&[0x81, u8::try_from(contents.len()).unwrap()]);
    }
    bytes.extend_from_slice(contents);
    bytes
}
fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn identity(hash: &[u8]) -> Vec<u8> {
    sequence(&[tlv(4, hash)])
}
fn value(identifiers: &[Vec<u8>], policies: Option<Vec<u8>>) -> Vec<u8> {
    let mut fields = vec![sequence(identifiers)];
    if let Some(policies) = policies {
        fields.push(policies);
    }
    sequence(&fields)
}
fn issuer(text: &str) -> Vec<u8> {
    let name = sequence(&[tlv(
        0x31,
        &sequence(&[tlv(6, &[0x55, 4, 3]), tlv(12, text.as_bytes())]),
    )]);
    sequence(&[sequence(&[tlv(0xa4, &name)]), tlv(2, &[7])])
}

fn certificate(text: &str, serial: u8) -> Vec<u8> {
    // Independent certificate source for ESS query funding tests; no crypto
    // result is inferred from this synthetic key/signature spelling.
    let algorithm = sequence(&[tlv(6, &[42])]);
    let name = sequence(&[tlv(
        0x31,
        &sequence(&[tlv(6, &[0x55, 4, 3]), tlv(12, text.as_bytes())]),
    )]);
    let tbs = sequence(&[
        tlv(2, &[serial]),
        algorithm.clone(),
        name.clone(),
        sequence(&[tlv(23, b"240101000000Z"), tlv(23, b"300101000000Z")]),
        name,
        sequence(&[algorithm.clone(), tlv(3, &[0, 1])]),
    ]);
    sequence(&[tbs, algorithm, tlv(3, &[0, 1])])
}

#[test]
fn omitted_algorithms_have_explicit_distinct_schema_identity_and_original_hash() {
    // No encoded algorithm exists in V1 or omitted V2. Their identities must
    // not be guessed from hash width or fabricated parameter/DER bytes.
    for (version, implied, length) in [
        (Version::V1, ImpliedDigest::EssSha1, 20),
        (Version::V2, ImpliedDigest::EssV2Sha256, 32),
    ] {
        let encoded = value(
            &[identity(&vec![7; length]), identity(&vec![8; length])],
            None,
        );
        let memory = memory(1_000_000, 1_000_000);
        let parser = Parser::der(memory.clone());
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let read = SigningCertificate::read(&parent, &element, version).unwrap();
        assert_eq!(read.version(), version);
        assert!(read.faults().is_empty());
        assert_eq!(read.identifiers().len(), 2);
        assert!(matches!(
            read.certificates(),
            [CertificateReading::Read(0), CertificateReading::Read(1)]
        ));
        let DigestAlgorithm::Implied {
            algorithm,
            field,
            span,
        } = read.signer().digest_algorithm()
        else {
            panic!("invented written algorithm")
        };
        assert_eq!(algorithm, implied);
        assert!(field.ends_with(if version == Version::V1 {
            ".signingCertificate"
        } else {
            ".signingCertificateV2"
        }));
        assert_eq!(span, read.signer().element().span());
        assert_eq!(read.signer().hashed().as_one().unwrap(), vec![7; length]);
        let at = usize::try_from(read.signer().hashed().pieces()[0].span().start - 400).unwrap();
        assert_eq!(
            read.signer().hashed().as_one().unwrap().as_ptr(),
            encoded[at..].as_ptr()
        );
        assert!(matches!(
            read.signer().issuer_serial(),
            IssuerReading::Absent
        ));
        drop(parent);
        assert!(memory.used() > 0);
        drop(read);
        assert_eq!(memory.used(), 0);
    }
}

#[test]
fn written_parameters_are_preserved_and_only_exact_default_is_default_written() {
    // NULL is not the ASN.1 absent-parameter default. Unknown written
    // algorithms remain written and must reach the selected resolver.
    for (kind, parameters, default_written) in [
        (oid::SHA256.as_bytes(), None, true),
        (oid::SHA256.as_bytes(), Some(vec![5, 0]), false),
        (&[42][..], None, false),
    ] {
        let mut algorithm = vec![tlv(6, kind)];
        if let Some(parameters) = &parameters {
            algorithm.push(parameters.clone());
        }
        let certificate = sequence(&[sequence(&algorithm), tlv(4, &[7; 32])]);
        let encoded = value(&[certificate], None);
        let parser = Parser::der(memory(1_000_000, 1_000_000));
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let read = SigningCertificate::read(&parent, &element, Version::V2).unwrap();
        let DigestAlgorithm::Written(algorithm) = read.signer().digest_algorithm() else {
            panic!("written algorithm became implied")
        };
        assert_eq!(algorithm.algorithm().as_bytes(), kind);
        assert_eq!(algorithm.parameters(), parameters.as_deref());
        assert_eq!(read.faults().len(), usize::from(default_written));
        if default_written {
            assert_eq!(read.faults()[0].code(), ErrorCode::DefaultWritten);
            assert_eq!(read.faults()[0].offset(), algorithm.offset());
        }
    }
}

#[test]
fn only_bare_default_has_one_recovery_and_still_retains_a_fault() {
    // Recovery cannot reinterpret another bare OID as the default or infer
    // it from the accompanying 32-byte hash. The exact bare default is faulty.
    for (kind, readable) in [(oid::SHA256.as_bytes(), true), (&[42][..], false)] {
        let encoded = value(&[sequence(&[tlv(6, kind), tlv(4, &[7; 32])])], None);
        let parser = Parser::ber(memory(1_000_000, 1_000_000));
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        match SigningCertificate::read(&parent, &element, Version::V2) {
            Ok(read) => {
                assert!(readable);
                assert!(matches!(
                    read.signer().digest_algorithm(),
                    DigestAlgorithm::Implied {
                        algorithm: ImpliedDigest::EssV2Sha256,
                        ..
                    }
                ));
                assert_eq!(read.faults().len(), 1);
                assert_eq!(read.faults()[0].code(), ErrorCode::AttributeSyntax);
            }
            Err(error) => {
                assert!(!readable);
                assert_eq!(error.code(), ErrorCode::AttributeSyntax);
            }
        }
    }
}

#[test]
fn malformed_later_restriction_and_written_unreadable_issuer_are_not_discarded() {
    // The first hash remains readable, but unreadable optional issuer/later
    // path restrictions retain their original bytes, cardinality and faults.
    let first = sequence(&[tlv(4, &[7; 20]), tlv(5, &[])]);
    let encoded = value(&[first, tlv(5, &[]), identity(&[8; 20])], None);
    let memory = memory(1_000_000, 1_000_000);
    let parser = Parser::der(memory.clone());
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let read = SigningCertificate::read(&parent, &element, Version::V1).unwrap();
    assert_eq!(read.faults().len(), 2);
    assert_eq!(read.identifiers().len(), 2);
    let [
        CertificateReading::Read(0),
        CertificateReading::Unreadable(extra),
        CertificateReading::Read(1),
    ] = read.certificates()
    else {
        panic!("restriction catalogue changed")
    };
    assert_eq!(extra.as_bytes(), [5, 0]);
    let IssuerReading::Unreadable(issuer) = read.signer().issuer_serial() else {
        panic!("written issuer became absent")
    };
    assert_eq!(issuer.as_bytes(), [5, 0]);
    assert_eq!(read.faults()[0].offset(), issuer.span().start);
    assert_eq!(read.faults()[1].offset(), extra.span().start);
    let held = memory.used();
    assert!(held > 0);
    drop(read);
    assert_eq!(memory.used(), 0);
}

#[test]
fn directory_issuer_uses_common_name_reading_and_non_directory_is_a_fault() {
    // ESS for a public-key certificate permits only its directoryName;
    // another readable GeneralName cannot become an absent issuerSerial.
    for (issuer_value, conforming) in [
        (issuer("Straße"), true),
        (
            sequence(&[sequence(&[tlv(0x82, b"example.com")]), tlv(2, &[7])]),
            false,
        ),
    ] {
        let encoded = value(&[sequence(&[tlv(4, &[7; 20]), issuer_value])], None);
        let parser = Parser::der(memory(1_000_000, 1_000_000));
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let read = SigningCertificate::read(&parent, &element, Version::V1).unwrap();
        let IssuerReading::Present(issuer) = read.signer().issuer_serial() else {
            panic!("readable issuer lost")
        };
        assert_eq!(issuer.names().len(), 1);
        assert_eq!(issuer.serial().as_u64(), Some(7));
        assert_eq!(read.faults().len(), usize::from(!conforming));
    }
}

#[test]
fn known_policy_qualifiers_use_shared_syntax_and_unknown_values_are_preserved() {
    // A recognized OID selects syntax, while an unknown qualifier remains
    // opaque. The first certificate cannot erase malformed later policies.
    for (kind, qualifier, malformed) in [
        (
            structured_pkix::oid::CPS_QUALIFIER.as_bytes(),
            tlv(2, &[1]),
            true,
        ),
        (
            structured_pkix::oid::CPS_QUALIFIER.as_bytes(),
            tlv(22, b"https://example.com/policy"),
            false,
        ),
        (
            structured_pkix::oid::USER_NOTICE_QUALIFIER.as_bytes(),
            sequence(&[]),
            false,
        ),
        (&[42][..], tlv(2, &[1]), false),
    ] {
        let policy = sequence(&[
            tlv(6, &[43]),
            sequence(&[sequence(&[tlv(6, kind), qualifier])]),
        ]);
        let encoded = value(&[identity(&[7; 20])], Some(sequence(&[policy])));
        let parser = Parser::der(memory(1_000_000, 1_000_000));
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let read = SigningCertificate::read(&parent, &element, Version::V1).unwrap();
        assert!(read.policies().is_some());
        assert_eq!(read.faults().len(), usize::from(malformed));
        assert_eq!(read.signer().hashed().as_one(), Some(&[7; 20][..]));
    }
}

#[test]
fn complete_nested_work_and_storage_refusals_never_become_recoverable_faults() {
    // Baseline measures real total producing work, not a guessed conservative
    // charge. One unit less must fail before success; partial catalogues drop.
    let encoded = value(
        &[
            sequence(&[tlv(4, &[7; 20]), issuer("Straße")]),
            identity(&[8; 20]),
        ],
        None,
    );
    let baseline = memory(1_000_000, 1_000_000);
    let parser = Parser::der(baseline.clone());
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let read = SigningCertificate::read(&parent, &element, Version::V1).unwrap();
    let total = u64::try_from(baseline.work_used()).unwrap();
    drop(read);
    assert_eq!(baseline.used(), 0);
    let current = memory(1_000_000, 1_000_000);
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: total - 1,
            ..Limits::default()
        },
        current.clone(),
    );
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let error = SigningCertificate::read(&parent, &element, Version::V1).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(current.used(), 0);
    for ceiling in [0, 64, 256, 512, 1024] {
        let current = memory(ceiling, 1_000_000);
        let parser = Parser::der(current.clone());
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        match SigningCertificate::read(&parent, &element, Version::V1) {
            Ok(read) => drop(read),
            Err(error) => assert!(error.is_resource()),
        }
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn issuer_comparison_uses_current_scope_and_foreign_certificate_storage_stays_put() {
    // Full folding/NFKC is common Name semantics, not a private ESS matcher.
    // The certificate's retained account cannot fund a later token query.
    let token_account = memory(1_000_000, 1_000_000);
    let parser = Parser::der(token_account.clone());
    let encoded = value(&[sequence(&[tlv(4, &[7; 20]), issuer("Straße")])], None);
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let read = SigningCertificate::read(&parent, &element, Version::V1).unwrap();
    let certificate_account = memory(1_000_000, 1_000_000);
    let certificate_parser = Parser::der(certificate_account.clone());
    let certificate_bytes = certificate(" STRASSE ", 7);
    let certificate =
        structured_pkix::Certificate::read(&certificate_parser, &certificate_bytes, 900).unwrap();
    let held = certificate_account.used();
    let original_work = certificate_account.work_used();
    let current = memory(1_000_000, 1_000_000);
    let query = parent.with_execution(&current);
    assert_eq!(
        read.signer().matches_issuer(&certificate, &query).unwrap(),
        IssuerAgreement::Matches
    );
    assert_eq!(current.used(), 0);
    assert!(current.work_used() > 0);
    assert_eq!(certificate_account.used(), held);
    assert_eq!(certificate_account.work_used(), original_work);
    let exhausted = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = exhausted.read(&[], 1200).unwrap();
    let error = read
        .signer()
        .matches_issuer(&certificate, &query)
        .unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.offset(), read.signer().element().span().start);
    assert_eq!(error.field(), "signerInfo.signedAttrs.signingCertificate");
    assert_eq!(current.used(), 0);
    assert_eq!(certificate_account.work_used(), original_work);
}

fn attribute(kind: structured_asn1::Oid<'_>, values: &[Vec<u8>]) -> Vec<u8> {
    let mut values = values.to_vec();
    values.sort();
    sequence(&[tlv(6, kind.as_bytes()), tlv(0x31, &values.concat())])
}

fn signer(signed: &[Vec<u8>], unsigned: &[Vec<u8>]) -> Vec<u8> {
    // Trusted fixture generation, outside the admitted reader/check operation.
    let mut signed = signed.to_vec();
    let mut unsigned = unsigned.to_vec();
    signed.sort();
    unsigned.sort();
    let mut inside = vec![2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42];
    if !signed.is_empty() {
        inside.extend(tlv(0xa0, &signed.concat()));
    }
    inside.extend_from_slice(&[0x30, 3, 6, 1, 43, 4, 1, 7]);
    if !unsigned.is_empty() {
        inside.extend(tlv(0xa1, &unsigned.concat()));
    }
    tlv(0x30, &inside)
}

#[test]
fn signed_versions_preserve_independent_signer_and_later_path_restrictions() {
    // Both attributes can be present and must retain their own restrictions;
    // a conflicting certificate hash is not resolved by choosing one version.
    let first = value(&[identity(&[7; 20]), identity(&[8; 20])], None);
    let second = value(&[identity(&[9; 32]), identity(&[10; 32])], None);
    let encoded = signer(
        &[
            attribute(oid::SIGNING_CERTIFICATE, &[first]),
            attribute(oid::SIGNING_CERTIFICATE_V2, &[second]),
        ],
        &[],
    );
    let storage = memory(1_000_000, 1_000_000);
    let parser = Parser::ber(storage.clone());
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = structured_cms::signer::SignerInfo::read(&parent, &element).unwrap();
    let source_capacity = storage.used();
    let read = SigningAttributes::read(&signer, &parent).unwrap();
    assert!(read.signed_attributes_present());
    assert!(read.faults().is_empty());
    let v1 = read.v1().unwrap();
    let v2 = read.v2().unwrap();
    assert_eq!(v1.certificates().len(), 2);
    assert_eq!(v2.certificates().len(), 2);
    assert_eq!(v1.signer().hashed().as_one(), Some(&[7; 20][..]));
    assert_eq!(v2.signer().hashed().as_one(), Some(&[9; 32][..]));
    assert_eq!(v1.identifiers()[1].hashed().as_one(), Some(&[8; 20][..]));
    assert_eq!(v2.identifiers()[1].hashed().as_one(), Some(&[10; 32][..]));
    assert!(storage.used() > source_capacity);
    drop(read);
    assert_eq!(storage.used(), source_capacity);
}

#[test]
fn unsigned_ess_is_a_placement_fault_and_not_a_signed_binding() {
    // No signed attributes and signed attributes without ESS are distinct;
    // unsigned ESS can supply neither a signer binding nor path restrictions.
    let ess = attribute(
        oid::SIGNING_CERTIFICATE,
        &[value(&[identity(&[7; 20])], None)],
    );
    let encoded = signer(&[], &[ess]);
    let parser = Parser::ber(memory(1_000_000, 1_000_000));
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = structured_cms::signer::SignerInfo::read(&parent, &element).unwrap();
    let read = SigningAttributes::read(&signer, &parent).unwrap();
    assert!(!read.signed_attributes_present());
    assert!(read.v1().is_none());
    assert!(read.v2().is_none());
    assert_eq!(read.faults().len(), 1);
    assert_eq!(read.faults()[0].code(), ErrorCode::AttributePlacement);
    assert_eq!(
        read.faults()[0].field(),
        "signerInfo.unsignedAttrs.signingCertificate"
    );
    assert_eq!(
        read.faults()[0].offset(),
        signer.unsigned_attributes().unwrap().items()[0]
            .span()
            .start
    );
}

#[test]
fn identical_ess_repetition_retains_one_value_and_fault_but_conflicts_refuse() {
    // One identical reading can remain for diagnostics, but MUST cardinality
    // faults are not erased; a different hash cannot be chosen arbitrarily.
    let first = value(&[identity(&[7; 20])], None);
    let changed = value(&[identity(&[8; 20])], None);
    for (signed, readable, faults) in [
        (
            vec![attribute(
                oid::SIGNING_CERTIFICATE,
                &[first.clone(), first.clone()],
            )],
            true,
            1,
        ),
        (
            vec![
                attribute(oid::SIGNING_CERTIFICATE, core::slice::from_ref(&first)),
                attribute(oid::SIGNING_CERTIFICATE, core::slice::from_ref(&first)),
            ],
            true,
            1,
        ),
        (
            vec![attribute(
                oid::SIGNING_CERTIFICATE,
                &[first.clone(), changed],
            )],
            false,
            0,
        ),
    ] {
        let encoded = signer(&signed, &[]);
        let storage = memory(1_000_000, 1_000_000);
        let parser = Parser::ber(storage.clone());
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let signer = structured_cms::signer::SignerInfo::read(&parent, &element).unwrap();
        let held = storage.used();
        match SigningAttributes::read(&signer, &parent) {
            Ok(read) => {
                assert!(readable);
                assert_eq!(read.faults().len(), faults);
                assert_eq!(read.faults()[0].code(), ErrorCode::AttributeCardinality);
                assert_eq!(
                    read.v1().unwrap().signer().hashed().as_one(),
                    Some(&[7; 20][..])
                );
                drop(read);
            }
            Err(error) => {
                assert!(!readable);
                assert_eq!(error.code(), ErrorCode::AttributeCardinality);
            }
        }
        assert_eq!(storage.used(), held);
    }
}

#[test]
fn v2_sha1_does_not_waive_the_mandatory_v1_attribute() {
    // RFC5035 section2 mandates V1 when SHA-1 is selected. Readability of
    // V2 cannot erase the missing companion, and unsigned V1 is no companion.
    let v1 = attribute(
        oid::SIGNING_CERTIFICATE,
        &[value(&[identity(&[7; 20])], None)],
    );
    let algorithm = sequence(&[tlv(6, &[0x2b, 0x0e, 3, 2, 26])]);
    let v2 = attribute(
        oid::SIGNING_CERTIFICATE_V2,
        &[value(&[sequence(&[algorithm, tlv(4, &[7; 20])])], None)],
    );
    for (signed, unsigned, missing, placement) in [
        (vec![v2.clone()], vec![], true, false),
        (vec![v2.clone()], vec![v1.clone()], true, true),
        (vec![v1, v2], vec![], false, false),
    ] {
        let encoded = signer(&signed, &unsigned);
        let parser = Parser::ber(memory(1_000_000, 1_000_000));
        let mut parent = parser.read(&encoded, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let signer = structured_cms::signer::SignerInfo::read(&parent, &element).unwrap();
        let read = SigningAttributes::read(&signer, &parent).unwrap();
        assert!(read.v2().is_some());
        let mut missing_count = 0;
        let mut placement_count = 0;
        for fault in read.faults() {
            match fault.code() {
                ErrorCode::MissingField => {
                    missing_count += 1;
                    assert_eq!(fault.field(), "signerInfo.signedAttrs.signingCertificate");
                    assert_eq!(
                        fault.offset(),
                        read.v2().unwrap().signer().element().span().start
                    );
                }
                ErrorCode::AttributePlacement => placement_count += 1,
                _ => panic!("unexpected schema fault"),
            }
        }
        assert_eq!(missing_count, usize::from(missing));
        assert_eq!(placement_count, usize::from(placement));
    }
}

#[test]
fn later_sha1_restriction_also_retains_the_missing_v1_compatibility_fault() {
    // Each ESSCertIDv2 selects its own hash. A SHA-256 first identifier does
    // not erase the section2 requirement for a later SHA-1 identification.
    let later = sequence(&[sequence(&[tlv(6, oid::SHA1.as_bytes())]), tlv(4, &[8; 20])]);
    let v2 = attribute(
        oid::SIGNING_CERTIFICATE_V2,
        &[value(&[identity(&[7; 32]), later], None)],
    );
    let encoded = signer(&[v2], &[]);
    let parser = Parser::ber(memory(1_000_000, 1_000_000));
    let mut parent = parser.read(&encoded, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let signer = structured_cms::signer::SignerInfo::read(&parent, &element).unwrap();
    let read = SigningAttributes::read(&signer, &parent).unwrap();
    assert!(read.v1().is_none());
    let v2 = read.v2().unwrap();
    assert_eq!(v2.identifiers().len(), 2);
    assert_eq!(read.faults().len(), 1);
    assert_eq!(read.faults()[0].code(), ErrorCode::MissingField);
    assert_eq!(
        read.faults()[0].offset(),
        v2.identifiers()[1].element().span().start
    );
    assert_eq!(v2.signer().hashed().as_one(), Some(&[7; 32][..]));
}

#[test]
fn absent_ess_does_not_hide_a_foreign_producing_reader() {
    // Even absence cannot authorize a different local budget. Caller misuse
    // must terminate before scanning/retaining placement or recovery faults.
    let memory = memory(65536, 65536);
    let parser = Parser::ber(memory.clone());
    let foreign = Parser::ber(memory.clone());
    let encoded = [
        0x30, 19, 2, 1, 3, 0x80, 1, 7, 0x30, 3, 6, 1, 42, 0x30, 3, 6, 1, 43, 4, 1, 8,
    ];
    let mut reader = parser.read(&encoded, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signer = structured_cms::signer::SignerInfo::read(&reader, &element).unwrap();
    let other = foreign.read(&[], 0).unwrap();
    let work = memory.work_used();
    let error = SigningAttributes::read(&signer, &other).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
    assert!(error.is_terminal());
    assert!(!error.is_resource());
    assert_eq!(memory.work_used(), work);
}
