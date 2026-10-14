use super::{QualifiedType, RetentionPeriod};
use crate::Certificate;
use crate::error::ErrorCode;
use crate::fixtures::{
    CertificateParts, extension, extension_error, int, oid as oid_of, printable, seq,
    with_extension,
};
use crate::oid;
use structured_asn1::Parser;

#[test]
fn lazy_qualified_types_keep_the_current_account_after_parser_release() {
    // Decoding a retained statement pays B, not source account A. The
    // owned enum result survives the parser and keeps only its own capacity.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let original = crate::fixtures::memory();
    let execution = crate::fixtures::memory();
    let value = seq(&[seq(&[oid_of(oid::QC_TYPE), seq(&[oid_of(oid::QCT_ESEAL)])])]);
    let der = seq(&[extension(oid::QC_STATEMENTS, false, &value)]);
    let types = {
        let parser = Parser::der(original.clone());
        let mut reader = parser.read(&der, 601).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let list = crate::extension::read(&reader, &element, "test").unwrap();
        let statements = list.qc_statements(&original).unwrap().unwrap();
        let before = original.work_used();
        let held = original.used();
        let exhausted = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 0)));
        assert!(statements.types(&exhausted).unwrap_err().is_resource());
        let types = statements.types(&execution).unwrap();
        assert_eq!(original.work_used(), before);
        assert_eq!(original.used(), held);
        types
    };
    assert_eq!(&*types, &[QualifiedType::ElectronicSeal]);
    assert!(types.memory().same_account(&execution));
    assert_eq!(original.used(), 0);
    assert_eq!(
        execution.used(),
        types.capacity() * core::mem::size_of::<QualifiedType>()
    );
    drop(types);
    assert_eq!(execution.used(), 0);
}

#[test]
fn lazy_qc_statement_keeps_its_document_depth() {
    // Isolate each lazy information path with a tighter parser, so a
    // successful initial DER walk cannot hide a later depth reset.
    let value = seq(&[
        seq(&[oid_of(oid::QC_RETENTION_PERIOD), int(10)]),
        seq(&[oid_of(oid::QC_TYPE), seq(&[oid_of(oid::QCT_ESEAL)])]),
        seq(&[
            oid_of(oid::PKIX_QC_SYNTAX_V2),
            seq(&[oid_of(oid::SEMANTICS_LEGAL_PERSON)]),
        ]),
    ]);
    with_extension(extension(oid::QC_STATEMENTS, true, &value), |list| {
        let limited = Parser::new(
            structured_asn1::Encoding::Der,
            structured_asn1::Limits {
                max_depth: 0,
                ..structured_asn1::Limits::default()
            },
            list.iter(list.memory())
                .next()
                .unwrap()
                .unwrap()
                .parser()
                .memory()
                .clone(),
        );
        let mut statements = list.qc_statements(list.memory()).unwrap().unwrap();
        statements.parser = &limited;
        let expected = ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Depth,
        ));
        assert_eq!(
            statements
                .retention_period(statements.memory())
                .unwrap_err()
                .code(),
            expected
        );
        assert_eq!(
            statements.types(statements.memory()).unwrap_err().code(),
            expected
        );
        assert_eq!(
            statements
                .semantics(statements.memory())
                .unwrap_err()
                .code(),
            expected
        );
        let statement = statements
            .get(oid::QC_TYPE, statements.memory())
            .unwrap()
            .unwrap();
        let error = statements
            .payload_sequence(&statement, statements.memory())
            .unwrap_err();
        assert_eq!(error.code(), expected);
        assert_eq!(error.offset(), statement.at);
    });
}

#[test]
fn the_claims_a_qualified_certificate_makes_are_read_as_claims() {
    let value = seq(&[
        seq(&[oid_of(oid::QC_COMPLIANCE)]),
        seq(&[oid_of(oid::QC_SSCD)]),
        seq(&[oid_of(oid::QC_TYPE), seq(&[oid_of(oid::QCT_ESEAL)])]),
    ]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();

        // Claims by the issuer, not findings. Whether the certificate is
        // qualified is decided by the trusted list, against the service that
        // issued it, at the moment in question.
        assert!(statements.claims_compliance(statements.memory()).unwrap());
        assert!(
            statements
                .claims_qualified_device(statements.memory())
                .unwrap()
        );
        assert_eq!(
            statements.types(statements.memory()).unwrap(),
            [QualifiedType::ElectronicSeal]
        );
    });
}

#[test]
fn a_seal_is_not_a_signature() {
    // A seal is made by a legal person and a signature by a natural one, and
    // collapsing the two would put an organization's name on a person's act.
    let value = seq(&[seq(&[oid_of(oid::QC_TYPE), seq(&[oid_of(oid::QCT_ESIGN)])])]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(
            statements.types(statements.memory()).unwrap(),
            [QualifiedType::ElectronicSignature]
        );
        // Naming a type is not claiming compliance, and a report that
        // inferred one from the other would say the issuer claimed something
        // it did not.
        assert!(!statements.claims_compliance(statements.memory()).unwrap());
    });
}

#[test]
fn a_kind_this_crate_does_not_know_is_skipped_and_stays_visible() {
    let unknown = structured_asn1::Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x06, 0x09]);
    let value = seq(&[seq(&[
        oid_of(oid::QC_TYPE),
        seq(&[oid_of(unknown), oid_of(oid::QCT_WEB)]),
    ])]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(
            statements.types(statements.memory()).unwrap(),
            [QualifiedType::WebsiteAuthentication]
        );
        // The statement it was written in is still there, so a scheme that
        // knows the kind can read it.
        assert!(
            statements
                .get(oid::QC_TYPE, statements.memory())
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn statements_this_crate_does_not_read_are_preserved() {
    // A limit on the value of transactions, which the product may show and
    // this layer does not interpret.
    let limit = seq(&[printable("UAH"), int(1000), int(0)]);
    let value = seq(&[seq(&[oid_of(oid::QC_LIMIT_VALUE), limit.clone()])]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        let kept = statements
            .get(oid::QC_LIMIT_VALUE, statements.memory())
            .unwrap()
            .unwrap();
        assert_eq!(kept.info(), Some(&limit[..]));
    });
}

#[test]
fn how_long_the_issuer_keeps_its_records_is_read() {
    let value = seq(&[seq(&[oid_of(oid::QC_RETENTION_PERIOD), int(10)])]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(
            statements.retention_period(statements.memory()).unwrap(),
            Some(RetentionPeriod::Years(10))
        );
    });
}

#[test]
fn how_the_subjects_identifiers_are_to_be_read_is_reported() {
    // Says whether an organization identifier belongs to an organization or to
    // a person, and getting it wrong turns one into the other.
    let information = seq(&[oid_of(oid::SEMANTICS_LEGAL_PERSON)]);
    let value = seq(&[seq(&[oid_of(oid::PKIX_QC_SYNTAX_V2), information])]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(
            statements.semantics(statements.memory()).unwrap(),
            Some(oid::SEMANTICS_LEGAL_PERSON)
        );
    });
}

#[test]
fn two_syntax_statements_that_disagree_are_not_resolved_by_choosing_one() {
    // Both versions may appear, each saying which profile the certificate
    // claims conformance with (RFC 3739 3.2.6), and each may carry a
    // semantics identifier. Two that differ say the subject's identifiers
    // are to be read two ways: answering with either turns a person into an
    // organization or the reverse, in a report somebody acts on.
    let natural = seq(&[oid_of(oid::SEMANTICS_NATURAL_PERSON)]);
    let legal = seq(&[oid_of(oid::SEMANTICS_LEGAL_PERSON)]);
    let value = seq(&[
        seq(&[oid_of(oid::PKIX_QC_SYNTAX_V1), natural]),
        seq(&[oid_of(oid::PKIX_QC_SYNTAX_V2), legal]),
    ]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(
            statements
                .semantics(statements.memory())
                .unwrap_err()
                .code(),
            ErrorCode::MalformedValue
        );
    });

    // Critical, the contradiction blocks rather than clearing on each
    // statement read by itself.
    let value = seq(&[
        seq(&[
            oid_of(oid::PKIX_QC_SYNTAX_V1),
            seq(&[oid_of(oid::SEMANTICS_NATURAL_PERSON)]),
        ]),
        seq(&[
            oid_of(oid::PKIX_QC_SYNTAX_V2),
            seq(&[oid_of(oid::SEMANTICS_LEGAL_PERSON)]),
        ]),
    ]);
    let der = crate::fixtures::seq(&[extension(oid::QC_STATEMENTS, true, &value)]);
    let parser = structured_asn1::Parser::der(crate::fixtures::memory());
    let mut reader = parser.read(&der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let list = crate::extension::read(&reader, &element, "test").unwrap();
    assert_eq!(
        list.unhandled_critical(&(), parser.memory()).unwrap().len(),
        1
    );

    // The same identifier written in both is one answer, not two.
    let value = seq(&[
        seq(&[
            oid_of(oid::PKIX_QC_SYNTAX_V1),
            seq(&[oid_of(oid::SEMANTICS_LEGAL_PERSON)]),
        ]),
        seq(&[
            oid_of(oid::PKIX_QC_SYNTAX_V2),
            seq(&[oid_of(oid::SEMANTICS_LEGAL_PERSON)]),
        ]),
    ]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(
            statements.semantics(statements.memory()).unwrap(),
            Some(oid::SEMANTICS_LEGAL_PERSON)
        );
    });

    // And one statement carrying an identifier beside one that carries none
    // is still that one identifier.
    let value = seq(&[
        seq(&[oid_of(oid::PKIX_QC_SYNTAX_V1)]),
        seq(&[
            oid_of(oid::PKIX_QC_SYNTAX_V2),
            seq(&[oid_of(oid::SEMANTICS_NATURAL_PERSON)]),
        ]),
    ]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(
            statements.semantics(statements.memory()).unwrap(),
            Some(oid::SEMANTICS_NATURAL_PERSON)
        );
    });
}

#[test]
fn absent_statements_answer_absent_rather_than_guessing() {
    let value = seq(&[seq(&[oid_of(oid::QC_COMPLIANCE)])]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(statements.types(statements.memory()).unwrap(), []);
        assert_eq!(
            statements.retention_period(statements.memory()).unwrap(),
            None
        );
        assert_eq!(statements.semantics(statements.memory()).unwrap(), None);
        assert!(
            !statements
                .claims_qualified_device(statements.memory())
                .unwrap()
        );
    });
}

#[test]
fn one_statement_written_twice_is_refused() {
    // Which of them the issuer claimed would have no answer.
    let value = seq(&[
        seq(&[oid_of(oid::QC_TYPE), seq(&[oid_of(oid::QCT_ESIGN)])]),
        seq(&[oid_of(oid::QC_TYPE), seq(&[oid_of(oid::QCT_ESEAL)])]),
    ]);
    let error = extension_error!(extension(oid::QC_STATEMENTS, false, &value), qc_statements);

    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.field(), "extensions.qcStatements");
}

#[test]
fn a_statement_list_that_is_misshapen_is_refused() {
    // A member that is not a statement at all. Empty is a separate question
    // and a valid list: see the test above it.
    let value = seq(&[int(1)]);
    let error = extension_error!(extension(oid::QC_STATEMENTS, false, &value), qc_statements);
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn a_retention_period_that_is_not_a_count_of_years_is_refused() {
    let value = seq(&[seq(&[oid_of(oid::QC_RETENTION_PERIOD), printable("ten")])]);
    let error = with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        statements
            .retention_period(statements.memory())
            .unwrap_err()
    });

    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn a_statement_with_bytes_after_its_information_is_refused_where_it_is_read() {
    use crate::fixtures::{cat, null};
    // The information is one value. A kind statement written as a sequence
    // plus a trailing NULL is refused when the statement list is read, which
    // is what lets the decoders above re-parse the information without each
    // repeating the check, and what keeps a malformed statement from driving
    // the signature-versus-seal classification.
    let value = seq(&[seq(&[
        oid_of(oid::QC_TYPE),
        cat(&[seq(&[oid_of(oid::QCT_ESIGN)]), null()]),
    ])]);
    let error = extension_error!(extension(oid::QC_STATEMENTS, false, &value), qc_statements);

    assert_eq!(error.code(), ErrorCode::TrailingData);
}

#[test]
fn semantics_information_that_is_not_shaped_like_it_is_refused() {
    use crate::fixtures::null;
    // After the identifier the only thing the structure may hold is the list
    // of registration authorities. A NULL there is a value the schema does
    // not have, and it must not ride along under a classification that
    // decides person versus organization.
    let information = seq(&[oid_of(oid::SEMANTICS_NATURAL_PERSON), null()]);
    let value = seq(&[seq(&[oid_of(oid::PKIX_QC_SYNTAX_V2), information])]);
    let error = with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        statements.semantics(statements.memory()).unwrap_err()
    });
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // The genuine optional list of authorities is read and exhaustion is
    // required after it.
    let authorities = seq(&[crate::fixtures::implicit(6, b"https://ra.example.ua")]);
    let information = seq(&[oid_of(oid::SEMANTICS_LEGAL_PERSON), authorities]);
    let value = seq(&[seq(&[oid_of(oid::PKIX_QC_SYNTAX_V2), information])]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(
            statements.semantics(statements.memory()).unwrap(),
            Some(oid::SEMANTICS_LEGAL_PERSON)
        );
    });
}

#[test]
fn information_on_a_statement_that_defines_none_is_refused() {
    use crate::fixtures::null;
    // The compliance and qualified-device statements are bare claims: their
    // identifiers define no information value. One carrying a value is
    // malformed statement data, not a stronger claim.
    for bare in [oid::QC_COMPLIANCE, oid::QC_SSCD] {
        let value = seq(&[seq(&[oid_of(bare), null()])]);
        let error = extension_error!(extension(oid::QC_STATEMENTS, false, &value), qc_statements);

        assert_eq!(error.code(), ErrorCode::MalformedValue);
        assert_eq!(error.field(), "extensions.qcStatements");
    }
}

#[test]
fn a_statement_error_points_into_the_document_not_into_its_own_slice() {
    // The kind statement's information must be a sequence; an integer there
    // fails. The error's offset is documented as counted in the whole
    // document, and re-parsing the information from zero would point every
    // such error at the front of the certificate instead of at the statement.
    // Built by hand rather than through the helper because the assertion
    // searches the encoded bytes themselves for the statement's position.
    let value = seq(&[seq(&[oid_of(oid::QC_TYPE), int(0x2a)])]);
    let der = CertificateParts {
        extensions: Some(seq(&[extension(oid::QC_STATEMENTS, false, &value)])),
        ..CertificateParts::default()
    }
    .build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = Certificate::read(&parser, &der, 0).unwrap();
    let statements = certificate
        .tbs()
        .extensions()
        .qc_statements(certificate.tbs().extensions().memory())
        .unwrap()
        .unwrap();

    let error = statements.types(statements.memory()).unwrap_err();
    let position = der
        .windows(3)
        .position(|window| window == [0x02, 0x01, 0x2a])
        .unwrap() as u64;
    assert_eq!(error.offset(), position);
}

#[test]
fn an_identical_statement_repeated_is_folded_rather_than_refused() {
    // QCStatements is a SEQUENCE OF with no uniqueness constraint, so a
    // statement repeated with the same information, here the payload-free
    // compliance claim, says one thing twice. Refusing it would block an
    // otherwise valid critical extension; only the same kind with different
    // information leaves the claim unanswerable.
    let value = seq(&[
        seq(&[oid_of(oid::QC_COMPLIANCE)]),
        seq(&[oid_of(oid::QC_COMPLIANCE)]),
    ]);
    with_extension(extension(oid::QC_STATEMENTS, false, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert!(statements.claims_compliance(statements.memory()).unwrap());
        // Folded, not duplicated: one statement survives.
        assert_eq!(statements.statements().len(), 1);
    });
}

#[test]
fn an_empty_statement_list_claims_nothing_and_is_read() {
    // QCStatements is a SEQUENCE OF with no minimum size (RFC 3739 3.2.6),
    // so an empty one is inside the schema: it makes no qualified claim,
    // which is a thing a reader can say, unlike the lists whose schema does
    // fix a minimum and where empty is malformed.
    with_extension(extension(oid::QC_STATEMENTS, true, &seq(&[])), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert!(statements.statements().is_empty());
        assert!(!statements.claims_compliance(statements.memory()).unwrap());
        assert!(
            !statements
                .claims_qualified_device(statements.memory())
                .unwrap()
        );
        assert_eq!(statements.types(statements.memory()).unwrap(), []);
    });
}

#[test]
fn a_constructed_primitive_statement_payload_is_refused() {
    // DER writes every universal type in the primitive form, the containers
    // aside (X.690 10.2): a constructed UTF8String is a second spelling of
    // one value, and preserving it would let a scheme that recognizes the
    // statement clear a payload that is not valid DER.
    use crate::fixtures::{tlv, utf8};
    let scheme = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x07, 0x01]);
    let value = seq(&[seq(&[oid_of(scheme), tlv(0x2c, &utf8("x"))])]);
    let error = extension_error!(extension(oid::QC_STATEMENTS, true, &value), qc_statements);
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // The same rule one level down. A check at the root alone would pass a
    // payload whose own tag is a container, which DER does write
    // constructed, while the string inside it is written the way DER does
    // not: the scheme still clears a critical extension on a value that is
    // a second spelling.
    let value = seq(&[seq(&[
        oid_of(scheme),
        seq(&[int(1), tlv(0x2c, &utf8("x"))]),
    ])]);
    let error = extension_error!(extension(oid::QC_STATEMENTS, true, &value), qc_statements);
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );

    // A container payload stays readable: a SEQUENCE is constructed by
    // definition.
    let value = seq(&[seq(&[oid_of(scheme), seq(&[int(1)])])]);
    with_extension(extension(oid::QC_STATEMENTS, true, &value), |list| {
        assert!(list.qc_statements(list.memory()).unwrap().is_some());
    });
}

#[test]
fn a_retention_period_past_any_interval_is_read_as_one() {
    use crate::fixtures::tlv;
    // QcEuRetentionPeriod is a bare INTEGER (ETSI TS 101 862, annex B), so a
    // period wider than the counter is inside the schema: it says the issuer
    // keeps the material longer than any interval anyone will ask about, not
    // that the statement is malformed.
    let huge = tlv(0x02, &[0x01, 0x00, 0x00, 0x00, 0x00]);
    let value = seq(&[seq(&[oid_of(oid::QC_RETENTION_PERIOD), huge])]);
    with_extension(extension(oid::QC_STATEMENTS, true, &value), |list| {
        let statements = list.qc_statements(list.memory()).unwrap().unwrap();
        assert_eq!(
            statements.retention_period(statements.memory()).unwrap(),
            Some(RetentionPeriod::BeyondAnyInterval)
        );
        assert_eq!(
            statements
                .retention_period(statements.memory())
                .unwrap()
                .and_then(RetentionPeriod::years),
            None
        );
        // Understood, so a critical list carrying it does not block.
        assert_eq!(
            list.unhandled_critical(
                &(),
                list.iter(list.memory())
                    .next()
                    .unwrap()
                    .unwrap()
                    .parser()
                    .memory()
            )
            .unwrap()
            .len(),
            0
        );
    });
}

#[test]
fn the_repeated_payload_comparison_is_charged_to_the_work_budget() {
    use crate::fixtures::octets;
    // Folding a repeat compares the two payloads byte by byte, and statement
    // information is opaque with no local ceiling: two large repeats sharing
    // a prefix cost that length, and a caller bounding work must see it.
    let scheme = structured_asn1::Oid::from_bytes(&[0x2a, 0x86, 0x24, 0x07, 0x01]);
    let payload = octets(&alloc::vec![0xaa; 50_000]);
    let value = seq(&[
        seq(&[oid_of(scheme), payload.clone()]),
        seq(&[oid_of(scheme), payload]),
    ]);
    let der = seq(&[extension(oid::QC_STATEMENTS, true, &value)]);

    let limits = structured_asn1::Limits {
        max_work: 8192,
        ..structured_asn1::Limits::default()
    };
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        limits,
        crate::fixtures::memory(),
    );
    let mut reader = parser.read(&der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let extensions = crate::extension::read(&reader, &element, "test").unwrap();
    let error = extensions.qc_statements(extensions.memory()).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Work
        ))
    );
}
