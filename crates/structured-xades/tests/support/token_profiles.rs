use super::*;

pub(super) fn indefinite_outer(der: &[u8]) -> Vec<u8> {
    let parser = structured_asn1::Parser::der(funded());
    let mut reader = parser.read(der, 0).unwrap();
    let element = reader
        .expect(structured_asn1::Tag::constructed(16))
        .unwrap();
    [b"\x30\x80".as_slice(), element.contents(), &[0, 0]].concat()
}

#[test]
fn cms_profile_admits_ber_without_rewriting_the_xml_encoding() {
    // RFC5652 permits BER around the unchanged signed contents. An absent
    // unsigned XML Encoding declaration must remain visible independently.
    let (mut xml, _, _) = token_pipeline_tree();
    xml.binary = indefinite_outer(&inspection_token());
    let expected = xml.binary.clone();
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let access = Access::new(&xml, xml.snapshot(), &memory);
    let prepared = prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
    let held = memory.used();
    timestamp::with_tokens(&xml, &prepared, &operation, timestamp::TokenProfile::Cms, |_, view| {
        assert_eq!(view.sources().len(), 2);
        for source in view.sources() {
            assert_eq!(source.bytes(), expected);
            assert_eq!(source.declaration(), binary::EncodingDeclaration::Absent);
            assert!(matches!(source.encoding_conformance(), timestamp::EncodingConformance::Mismatch(cause)
                if cause.code() == structured_cms::ErrorCode::Encoding(structured_asn1::ErrorCode::IndefiniteLengthNotAllowed)
                    && cause.offset() == 1));
        }
        Ok::<_, ()>(())
    })
    .unwrap();
    assert_eq!(xml.binary_encoding, None);
    assert_eq!(memory.used(), held);
}

#[test]
fn declaration_and_profile_matrix_keeps_cer_unchecked_and_etsi_strict() {
    // Admission and declaration are independent. Unsupported codecs and unknown
    // URIs refuse before source decoding in both explicit caller profiles.
    use binary::{EncodingDeclaration, PkiEncoding};
    use timestamp::TokenProfile;
    for profile in [TokenProfile::Cms, TokenProfile::Etsi] {
        for (uri, declaration) in [
            (None, Some(EncodingDeclaration::Absent)),
            (
                Some("http://uri.etsi.org/01903/v1.2.2#DER"),
                Some(EncodingDeclaration::Explicit(PkiEncoding::Der)),
            ),
            (
                Some("http://uri.etsi.org/01903/v1.2.2#BER"),
                Some(EncodingDeclaration::Explicit(PkiEncoding::Ber)),
            ),
            (
                Some("http://uri.etsi.org/01903/v1.2.2#CER"),
                Some(EncodingDeclaration::Explicit(PkiEncoding::Cer)),
            ),
            (
                Some("http://uri.etsi.org/01903/v1.2.2#PER"),
                Some(EncodingDeclaration::Explicit(PkiEncoding::Per)),
            ),
            (
                Some("http://uri.etsi.org/01903/v1.2.2#XER"),
                Some(EncodingDeclaration::Explicit(PkiEncoding::Xer)),
            ),
            (Some("urn:unknown-encoding"), None),
        ] {
            for ber in [false, true] {
                let (mut xml, _, _) = token_pipeline_tree();
                xml.binary_encoding = uri;
                let der = inspection_token();
                xml.binary = if ber { indefinite_outer(&der) } else { der };
                let memory = funded();
                let parser = structured_asn1::Parser::der(memory.clone());
                let operation = parser.read(&[], 900).unwrap();
                let access = Access::new(&xml, xml.snapshot(), &memory);
                let prepared =
                    prepare::prepare(&access, 0, unsigned::Requirements::Archival, None).unwrap();
                let held = memory.used();
                let mut calls = 0;
                let result =
                    timestamp::with_tokens(&xml, &prepared, &operation, profile, |_, view| {
                        calls += 1;
                        let expected = declaration.unwrap();
                        for (source, reading) in view.sources().iter().zip(view.readings()) {
                            assert_eq!(source.declaration(), expected);
                            assert_eq!(
                                reading.reader().encoding(),
                                if profile == TokenProfile::Etsi
                                    && expected.encoding() == PkiEncoding::Der
                                {
                                    structured_asn1::Encoding::Der
                                } else {
                                    structured_asn1::Encoding::Ber
                                }
                            );
                            assert_declaration_result(source, profile, expected.encoding(), ber);
                        }
                        Ok::<_, ()>(())
                    });
                let encoding = declaration.map(EncodingDeclaration::encoding);
                match encoding {
                    None => assert!(matches!(
                        &result,
                        Err(timestamp::TokenPipelineError::Encoding(
                            binary::Error::UnknownEncoding { .. }
                        ))
                    )),
                    Some(PkiEncoding::Per | PkiEncoding::Xer) => assert!(
                        matches!(&result, Err(timestamp::TokenPipelineError::Encoding(binary::Error::UnsupportedEncoding { encoding: actual, .. })) if Some(*actual) == encoding)
                    ),
                    Some(PkiEncoding::Cer) if profile == TokenProfile::Etsi => assert!(matches!(
                        &result,
                        Err(timestamp::TokenPipelineError::Encoding(
                            binary::Error::UnsupportedEncoding {
                                encoding: PkiEncoding::Cer,
                                ..
                            }
                        ))
                    )),
                    Some(PkiEncoding::Der) if ber && profile == TokenProfile::Etsi => assert!(
                        matches!(&result, Err(timestamp::TokenPipelineError::Token { cause, .. }) if cause.code() == structured_cms::ErrorCode::Encoding(structured_asn1::ErrorCode::IndefiniteLengthNotAllowed))
                    ),
                    _ => {
                        assert!(result.is_ok());
                        assert_eq!(calls, 1);
                    }
                }
                if matches!(&result, Err(timestamp::TokenPipelineError::Encoding(_))) {
                    assert_eq!(xml.decoded_pointer.get(), 0);
                }
                if result.is_err() {
                    assert_eq!(calls, 0);
                }
                drop(result);
                assert_eq!(memory.used(), held);
                assert_eq!(xml.binary_encoding, uri);
            }
        }
    }
}

fn assert_declaration_result(
    source: &timestamp::TokenSource<usize, u8, u8>,
    profile: timestamp::TokenProfile,
    encoding: binary::PkiEncoding,
    ber: bool,
) {
    use binary::PkiEncoding;
    use timestamp::{EncodingConformance, TokenProfile};
    match source.encoding_conformance() {
        EncodingConformance::Matches => assert!(!ber || encoding == PkiEncoding::Ber),
        EncodingConformance::Mismatch(cause) => {
            assert!(ber && encoding == PkiEncoding::Der);
            assert!(!cause.is_terminal());
        }
        EncodingConformance::Unchecked(PkiEncoding::Cer) => assert_eq!(profile, TokenProfile::Cms),
        EncodingConformance::Unchecked(other) => panic!("unexpected unchecked codec {other:?}"),
    }
}

#[test]
fn cms_profile_keeps_unsorted_implicit_certificate_sets_and_carried_identity() {
    // Definite lengths alone do not prove DER: CMS CertificateSet has an
    // IMPLICIT context tag. The existing strict schema kernel finds its order.
    let (a, b) = timestamp_oracle::certificate_pair();
    let certificates = if a > b {
        [&a[..], &b[..]].concat()
    } else {
        [&b[..], &a[..]].concat()
    };
    let (mut xml, _, _) = token_pipeline_tree();
    xml.binary = inspection_token_with_carriage(&[], &certificates, 3);
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), &memory),
        0,
        unsigned::Requirements::Archival,
        None,
    )
    .unwrap();
    timestamp::with_tokens(&xml, &prepared, &operation, timestamp::TokenProfile::Cms, |query, view| {
        for (source, reading) in view.sources().iter().zip(view.readings()) {
            assert!(matches!(source.encoding_conformance(), timestamp::EncodingConformance::Mismatch(cause)
                if cause.code() == structured_cms::ErrorCode::SetOrder && cause.field() == "signedData.certificates"));
            let certs = reading.token().message().certificates();
            assert_eq!(certs.len(), 2);
            assert_eq!([certs[0].as_bytes(), certs[1].as_bytes()].concat(), certificates);
            let base = source.bytes().as_ptr() as usize;
            for cert in certs {
                assert_eq!(cert.as_bytes().as_ptr() as usize, base + usize::try_from(cert.span().start).unwrap());
            }
        }
        assert!(view.material_in(query).unwrap().crls().is_empty());
        Ok::<_, ()>(())
    }).unwrap();
    assert!(
        matches!(timestamp::with_tokens(&xml, &prepared, &operation, timestamp::TokenProfile::Etsi, |_, _| Ok::<_, ()>(())),
        Err(timestamp::TokenPipelineError::Token { cause, .. }) if cause.code() == structured_cms::ErrorCode::SetOrder)
    );
}

fn replace_at(der: &[u8], path: &[usize], replacement: &impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    // Trusted synthetic fixtures have fixed shallow paths; preserve every
    // unselected original TLV, including the actual signed-attribute octets.
    if path.is_empty() {
        return replacement(der);
    }
    let parser = structured_asn1::Parser::der(funded());
    let mut root = parser.read(der, 0).unwrap();
    let element = root.next_element().unwrap().unwrap();
    let mut children = root.enter(&element).unwrap();
    let mut contents = Vec::new();
    let mut index = 0;
    while let Some(child) = children.next_element().unwrap() {
        if index == path[0] {
            contents.extend(replace_at(child.as_bytes(), &path[1..], replacement));
        } else {
            contents.extend(child.as_bytes());
        }
        index += 1;
    }
    assert!(path[0] < index);
    timestamp_oracle::tlv(der[0], &contents)
}

#[test]
fn cms_envelope_does_not_relax_signed_attributes_or_inner_tstinfo_der() {
    // Changing only BER container spelling cannot make non-DER signedAttrs
    // readable or a non-DER TSTInfo a usable proof. No math callback may run.
    let (provider, original, certificate_bytes) = timestamp_oracle::fixture(b"covered");
    for attributes in [false, true] {
        let changed = if attributes {
            replace_at(&original, &[1, 0, 3, 0, 3], &|bytes| {
                let mut encoded = indefinite_outer(&timestamp_oracle::tlv(0x30, &{
                    let parser = structured_asn1::Parser::der(funded());
                    let mut reader = parser.read(bytes, 0).unwrap();
                    reader.next_element().unwrap().unwrap().contents().to_vec()
                }));
                encoded[0] = 0xa0;
                encoded
            })
        } else {
            replace_at(&original, &[1, 0, 2, 1, 0], &|octets| {
                let parser = structured_asn1::Parser::der(funded());
                let mut reader = parser.read(octets, 0).unwrap();
                let element = reader.next_element().unwrap().unwrap();
                timestamp_oracle::tlv(4, &indefinite_outer(element.contents()))
            })
        };
        let (mut xml, _, _) = token_pipeline_tree();
        xml.binary = indefinite_outer(&changed);
        let memory = funded();
        let parser = structured_asn1::Parser::der(memory.clone());
        let operation = parser.read(&[], 900).unwrap();
        let certificate =
            structured_pkix::Certificate::read(&parser, &certificate_bytes, 400).unwrap();
        let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = CheckContext {
            certificate: &certificate,
            certificate_parent: &operation,
            key: structured_pkix::path::WorkingKey::standing(certificate.tbs().public_key()),
            requested: None,
            utc: &utc,
            reference: None,
            window: None,
            policy_accuracy: None,
        };
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), &memory),
            0,
            unsigned::Requirements::Archival,
            None,
        )
        .unwrap();
        let mut calls = 0;
        let result = timestamp::with_tokens(
            &xml,
            &prepared,
            &operation,
            timestamp::TokenProfile::Cms,
            |_, view| {
                calls += 1;
                assert!(!attributes);
                for reading in view.readings() {
                    reading
                        .token()
                        .with_info(reading.reader(), |info, _, _| {
                            assert!(info.faults().iter().any(|cause| cause.code()
                                == structured_cms::ErrorCode::Encoding(
                                    structured_asn1::ErrorCode::IndefiniteLengthNotAllowed
                                )));
                            Ok::<_, ()>(())
                        })
                        .unwrap();
                    let mut input = [b"covered".as_slice()];
                    let result = reading.token().check(
                        &provider,
                        reading.reader(),
                        &context,
                        &mut input,
                        |_, _| Ok::<_, ()>(false),
                    );
                    assert!(matches!(
                        result,
                        Err(structured_cms::timestamp::CheckError::Information(
                            structured_cms::content_source::ContentError::Callback {
                                source: structured_cms::timestamp::InfoError::Callback(
                                    structured_cms::timestamp::InfoCheckError::Nonconforming { .. }
                                ),
                                ..
                            }
                        ))
                    ));
                }
                Ok::<_, ()>(())
            },
        );
        if attributes {
            assert!(
                matches!(result, Err(timestamp::TokenPipelineError::Token { cause, .. }) if cause.code() == structured_cms::ErrorCode::Encoding(structured_asn1::ErrorCode::IndefiniteLengthNotAllowed))
            );
            assert_eq!(calls, 0);
        } else {
            result.unwrap();
            assert_eq!(calls, 1);
        }
        assert_eq!(provider.verified.get(), 0);
    }
}

#[test]
fn declaration_probe_preserves_producing_and_current_resource_refusals() {
    // A broader current account cannot fund a source-local zero ceiling; nor
    // may a failed strict probe become a harmless declaration mismatch.
    for producing in [false, true] {
        let (mut xml, first, _) = token_pipeline_tree();
        xml.binary = inspection_token();
        let source_memory = funded();
        if producing {
            *xml.binary_parser.borrow_mut() = Some(structured_asn1::Parser::new(
                structured_asn1::Encoding::Ber,
                structured_asn1::Limits {
                    max_work: 0,
                    ..Default::default()
                },
                source_memory.clone(),
            ));
        }
        let memory = funded();
        let prepared = prepare::prepare(
            &Access::new(&xml, xml.snapshot(), &memory),
            0,
            unsigned::Requirements::Archival,
            None,
        )
        .unwrap();
        let parser = structured_asn1::Parser::new(
            structured_asn1::Encoding::Der,
            structured_asn1::Limits {
                max_work: if producing { 1_000_000 } else { 0 },
                ..Default::default()
            },
            memory.clone(),
        );
        let operation = parser.read(&[], 900).unwrap();
        let held = memory.used();
        let result = timestamp::with_tokens(
            &xml,
            &prepared,
            &operation,
            timestamp::TokenProfile::Cms,
            |_, _| -> Result<(), ()> { panic!("terminal refusal must precede the visitor") },
        );
        match &result {
            Err(timestamp::TokenPipelineError::Access(AccessError::Resource { .. })) => {
                assert!(!producing);
            }
            Err(timestamp::TokenPipelineError::Reader { location, cause }) => {
                assert_eq!(location.node, first);
                assert!(cause.is_resource());
            }
            Err(timestamp::TokenPipelineError::Token { location, cause }) => {
                assert_eq!(location.node, first);
                assert!(cause.is_resource());
            }
            _ => panic!("resource refusal changed class"),
        }
        drop(result);
        assert_eq!(memory.used(), held);
        assert_eq!(source_memory.used(), 0);
    }
}

#[test]
fn ber_token_keeps_actual_signature_carried_material_and_archive_input() {
    // A real P256/ESS/imprint check over the same XML input must survive only
    // the outer BER spelling. Neither validation material nor coverage is rebuilt.
    use structured_pkix::{
        path::WorkingKey,
        temporal::{Instant, LeapTable},
    };
    let mut xml = preparation_tree();
    let method = xml.element_child(8, DS, "CanonicalizationMethod");
    let token_node = xml.element_child(8, XADES, "EncapsulatedTimeStamp");
    let value = xml.element_child(0, DS, "SignatureValue");
    let expected = [
        b'E',
        u8::try_from(value).unwrap(),
        b'M',
        u8::try_from(method).unwrap(),
    ];
    let (provider, der, certificate_bytes) = timestamp_oracle::fixture_with_certificate(&expected);
    xml.binary = indefinite_outer(&der);
    let original = xml.binary.clone();
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let certificate = structured_pkix::Certificate::read(&parser, &certificate_bytes, 400).unwrap();
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let context = CheckContext {
        certificate: &certificate,
        certificate_parent: &operation,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: None,
        utc: &utc,
        reference: Some(Instant::new(1_800_000_000, 0).unwrap()),
        window: None,
        policy_accuracy: None,
    };
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), &memory),
        0,
        unsigned::Requirements::Timestamped,
        None,
    )
    .unwrap();
    let held = memory.used();
    timestamp::with_tokens(
        &xml,
        &prepared,
        &operation,
        timestamp::TokenProfile::Cms,
        |query, view| {
            let source = &view.sources()[0];
            let reading = &view.readings()[0];
            assert_eq!(source.location().node, token_node);
            assert_eq!(source.bytes(), original);
            assert_eq!(
                reading.token().message().certificates()[0].as_bytes(),
                certificate_bytes
            );
            let material = view.material_in(query).unwrap();
            assert!(material.crls().is_empty());
            let mut input = Input::prepare(
                &xml,
                prepared.bound(),
                &prepared.timestamps()[0],
                &reading.reader().execution(),
            )
            .unwrap();
            let checked = reading
                .token()
                .check(&provider, reading.reader(), &context, &mut input, |_, _| {
                    Ok::<_, ()>(false)
                })
                .unwrap();
            assert!(checked.into_evidence().is_some());
            assert_eq!(provider.verified.get(), 1);
            assert_eq!(source.bytes(), original);
            Ok::<_, ()>(())
        },
    )
    .unwrap();
    assert_eq!(memory.used(), held);
    assert_eq!(xml.binary, original);
    assert_eq!(xml.binary_encoding, None);
}

#[test]
fn ber_carried_status_and_archive_selection_keep_original_ranges() {
    // The common archive input driver sees the same original XML nodes before
    // and after BER token inspection. Carried status models borrow those tokens.
    let (crl, _) = timestamp_oracle::crl_pair();
    let response = timestamp_oracle::ocsp_response(2);
    let choices = [&crl[..], &carried_ocsp_choice(&response)].concat();
    let (mut xml, first, second) = token_pipeline_tree();
    xml.binary = indefinite_outer(&inspection_token_with_choices(&choices, 5));
    let original = xml.binary.clone();
    let memory = funded();
    let parser = structured_asn1::Parser::der(memory.clone());
    let operation = parser.read(&[], 900).unwrap();
    let prepared = prepare::prepare(
        &Access::new(&xml, xml.snapshot(), &memory),
        0,
        unsigned::Requirements::Archival,
        None,
    )
    .unwrap();
    let capture = || {
        let mut input =
            Input::prepare(&xml, prepared.bound(), &prepared.timestamps()[1], &memory).unwrap();
        let mut sink = Collect::new(&memory);
        stream::run(&mut input, &mut sink, &memory, "logical.archive.input", 0).unwrap();
        sink
    };
    let before = capture();
    let held = memory.used();
    timestamp::with_tokens(
        &xml,
        &prepared,
        &operation,
        timestamp::TokenProfile::Cms,
        |query, view| {
            assert_eq!(view.sources()[0].location().node, first);
            assert_eq!(view.sources()[1].location().node, second);
            let material = view.material_in(query).unwrap();
            assert_eq!(material.crls().len(), 2);
            assert_eq!(material.responses().len(), 2);
            for index in 0..2 {
                let source = &view.sources()[index];
                assert_eq!(source.bytes(), original);
                let list = &material.crls()[index].value;
                assert_eq!(list.as_bytes(), crl);
                assert_eq!(
                    list.as_bytes().as_ptr() as usize,
                    source.bytes().as_ptr() as usize + usize::try_from(list.span().start).unwrap()
                );
                assert_eq!(material.responses()[index].value.as_bytes(), response);
            }
            let during = capture();
            assert_eq!(during.bytes(), before.bytes());
            Ok::<_, ()>(())
        },
    )
    .unwrap();
    assert_eq!(memory.used(), held);
    assert_eq!(capture().bytes(), before.bytes());
    assert_eq!(xml.binary, original);
    assert_eq!(xml.snapshot(), prepared.bound().containers().snapshot());
}
