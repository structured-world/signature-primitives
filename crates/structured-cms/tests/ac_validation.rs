//! Original AC profile, explicit PKC bindings and complete AA-path restrictions.
#[path = "ac_validation/authentication.rs"]
mod authentication;
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Limits, Oid, Parser};
use structured_cms::attribute_certificate::AttributeCertificate;
use structured_cms::attribute_certificate::controls;
use structured_cms::attribute_certificate::validation::{
    self, Check, HolderMethod, Reason, Revocation,
    aa_path::{AaPath, Permission},
};
use structured_pkix::{Certificate, oid};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(u8::try_from(body.len()).unwrap());
    } else if body.len() < 256 {
        out.extend([129, u8::try_from(body.len()).unwrap()]);
    } else {
        out.extend([
            130,
            u8::try_from(body.len() >> 8).unwrap(),
            u8::try_from(body.len() & 255).unwrap(),
        ]);
    }
    out.extend(body);
    out
}
fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(48, &parts.concat())
}
fn alg() -> Vec<u8> {
    seq(&[&[6, 1, 42]])
}
fn name(text: &[u8]) -> Vec<u8> {
    seq(&[&tlv(
        49,
        &seq(&[&tlv(6, oid::COMMON_NAME.as_bytes()), &tlv(12, text)]),
    )])
}
fn directory(text: &[u8]) -> Vec<u8> {
    tlv(164, &name(text))
}
fn issuer(text: &[u8]) -> Vec<u8> {
    tlv(160, &seq(&[&directory(text)]))
}
fn entity(tag: u8, text: &[u8]) -> Vec<u8> {
    seq(&[&tlv(161, &tlv(tag, text))])
}
fn base(text: &[u8], serial: &[u8], uid: &[u8]) -> Vec<u8> {
    seq(&[&tlv(
        160,
        &[seq(&[&directory(text)]), tlv(2, serial), uid.to_vec()].concat(),
    )])
}
fn validity() -> Vec<u8> {
    seq(&[&tlv(24, b"20251021000000Z"), &tlv(24, b"20271021000000Z")])
}
fn attrs() -> Vec<u8> {
    seq(&[&seq(&[&[6, 1, 42], &[49, 2, 5, 0]])])
}
fn ac_fields(holder: &[u8], issuer: &[u8], serial: &[u8], times: &[u8], tail: &[u8]) -> Vec<u8> {
    let info = seq(&[
        &[2, 1, 1],
        holder,
        issuer,
        &alg(),
        &tlv(2, serial),
        times,
        &attrs(),
        tail,
    ]);
    seq(&[&info, &alg(), &[3, 2, 0, 9]])
}
fn ac_bytes(holder: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
    ac_fields(
        holder,
        &issuer(b"Authority"),
        &[5],
        &validity(),
        &if extensions.is_empty() {
            vec![]
        } else {
            seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>())
        },
    )
}
fn ext(kind: Oid<'_>, value: &[u8], critical: bool) -> Vec<u8> {
    seq(&[
        &tlv(6, kind.as_bytes()),
        if critical { &[1, 1, 255] } else { &[] },
        &tlv(4, value),
    ])
}
fn pkc(
    issuer: &[u8],
    subject: &[u8],
    serial: &[u8],
    uids: &[u8],
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let extensions = if extensions.is_empty() {
        vec![]
    } else {
        tlv(
            163,
            &seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>()),
        )
    };
    let tbs = seq(&[
        &[160, 3, 2, 1, 2],
        &tlv(2, serial),
        &alg(),
        &name(issuer),
        &validity(),
        &name(subject),
        &seq(&[&alg(), &[3, 2, 0, 9]]),
        uids,
        &extensions,
    ]);
    seq(&[&tbs, &alg(), &[3, 2, 0, 9]])
}
fn read_ac<'a>(parser: &'a Parser, bytes: &'a [u8]) -> AttributeCertificate<'a> {
    AttributeCertificate::read(&mut parser.read(bytes, 700).unwrap()).unwrap()
}
fn read_pkc<'a>(parser: &'a Parser, bytes: &'a [u8]) -> Certificate<'a> {
    Certificate::read(parser, bytes, 2000).unwrap()
}
fn accepted<T: core::fmt::Debug>(check: Check<T>) -> T {
    match check {
        Check::Accepted(value) => value,
        other @ Check::Rejected(_) => panic!("{other:?}"),
    }
}
fn rejected<T: core::fmt::Debug>(check: Check<T>, reason: Reason) -> Option<structured_asn1::Span> {
    match check {
        Check::Rejected(value) => {
            assert_eq!(value.reason, reason);
            value.source
        }
        other @ Check::Accepted(_) => panic!("{other:?}"),
    }
}
fn profile_reason(bytes: &[u8], reason: Reason) {
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let ac = read_ac(&p, bytes);
    assert!(rejected(ac.profile(p.memory()).unwrap(), reason).is_some());
}
fn access(method: Oid<'_>, uri: &[u8]) -> Vec<u8> {
    seq(&[&seq(&[&tlv(6, method.as_bytes()), &tlv(134, uri)])])
}
fn distribution(tag: u8, value: &[u8]) -> Vec<u8> {
    seq(&[&seq(&[&tlv(160, &tlv(160, &tlv(tag, value)))])])
}

#[test]
fn static_profile_preserves_original_inputs_and_independent_obligations() {
    // Static success is neither signature math nor targeting/revocation success.
    let target = ext(
        structured_cms::attribute_certificate::target::IDENTIFIER,
        &seq(&[&seq(&[&tlv(160, &tlv(130, b"service.test"))])]),
        true,
    );
    let bytes = ac_bytes(
        &entity(130, b"holder.test"),
        &[
            ext(validation::AUDIT_IDENTITY, &tlv(4, b"opaque"), true),
            target,
            ext(validation::NO_REV_AVAILABLE, &[5, 0], false),
            ext(Oid::from_bytes(&[42, 7]), &[0xff], false),
        ],
    );
    let mem = memory(1 << 20, 1 << 24);
    let p = Parser::der(mem.clone());
    let ac = read_ac(&p, &bytes);
    let signed = ac.signed_bytes();
    let query = memory(1 << 20, 1 << 24);
    let facts = accepted(ac.profile(&query).unwrap());
    assert!(core::ptr::eq(facts.certificate(), &raw const ac));
    assert_eq!(facts.certificate().signed_bytes().as_ptr(), signed.as_ptr());
    let audit = facts.audit_identity().unwrap();
    assert_eq!(audit, b"opaque");
    assert!((bytes.as_ptr_range()).contains(&audit.as_ptr()));
    assert!(facts.targeting().is_some());
    assert!(facts.proxying().is_none());
    assert_eq!(facts.revocation(), Revocation::NoRevAvailable);
    assert_eq!(facts.holder_alternatives(), 1);
    assert!(query.used() > 0);
    drop(facts);
    assert_eq!(query.used(), 0);
    drop(ac);
    assert_eq!(mem.used(), 0);
}

#[test]
fn issuer_serial_validity_and_object_digest_profile_are_separate_from_readability() {
    // Every readable out-of-profile form survives inspection but cannot pass profile.
    let holder = entity(130, b"h.test");
    for serial in [vec![0], vec![255], vec![1; 21]] {
        profile_reason(
            &ac_fields(&holder, &issuer(b"Authority"), &serial, &validity(), &[]),
            Reason::Serial,
        );
    }
    let reversed = seq(&[&tlv(24, b"20271021000000Z"), &tlv(24, b"20251021000000Z")]);
    profile_reason(
        &ac_fields(&holder, &issuer(b"Authority"), &[5], &reversed, &[]),
        Reason::Validity,
    );
    for bad in [
        seq(&[&directory(b"Authority")]),
        tlv(160, &seq(&[&tlv(130, b"aa.test")])),
        tlv(160, &seq(&[&directory(b"Authority"), &directory(b"Other")])),
    ] {
        profile_reason(
            &ac_fields(&holder, &bad, &[5], &validity(), &[]),
            Reason::IssuerForm,
        );
    }
    for (kind, other) in [(2, false), (0, true)] {
        let digest = tlv(
            162,
            &[
                vec![10, 1, kind],
                if other { vec![6, 1, 42] } else { vec![] },
                alg(),
                vec![3, 2, 0, 9],
            ]
            .concat(),
        );
        profile_reason(&ac_bytes(&seq(&[&digest]), &[]), Reason::ObjectDigest);
    }
    let bytes = ac_fields(&holder, &issuer(b"Authority"), &[1; 20], &validity(), &[]);
    let p = Parser::der(memory(1 << 20, 1 << 24));
    accepted(read_ac(&p, &bytes).profile(p.memory()).unwrap());
}

#[test]
fn every_recognized_extension_enforces_its_own_criticality() {
    // Sharing a PKIX extension reader must not import PKC criticality policy into AC.
    let target = structured_cms::attribute_certificate::target::IDENTIFIER;
    let proxy = structured_cms::attribute_certificate::proxy::IDENTIFIER;
    for (kind, correct) in [
        (validation::AUDIT_IDENTITY, true),
        (target, true),
        (proxy, true),
        (oid::AUTHORITY_KEY_IDENTIFIER, false),
        (oid::AUTHORITY_INFO_ACCESS, false),
        (oid::CRL_DISTRIBUTION_POINTS, false),
        (validation::NO_REV_AVAILABLE, false),
    ] {
        profile_reason(
            &ac_bytes(&entity(130, b"h.test"), &[ext(kind, &[5, 0], !correct)]),
            Reason::Criticality,
        );
    }
    profile_reason(
        &ac_bytes(
            &entity(130, b"h.test"),
            &[ext(Oid::from_bytes(&[42, 7]), &[5, 0], true)],
        ),
        Reason::UnknownCritical,
    );
}

#[test]
fn audit_identity_and_no_revocation_validate_complete_value_grammar() {
    // NULL syntax and audit-length violations cannot become exemptions or identities.
    for value in [vec![], vec![1; 21]] {
        profile_reason(
            &ac_bytes(
                &entity(130, b"h.test"),
                &[ext(validation::AUDIT_IDENTITY, &tlv(4, &value), true)],
            ),
            Reason::AuditIdentity,
        );
    }
    for (kind, values, critical) in [
        (
            validation::AUDIT_IDENTITY,
            vec![vec![5, 0], vec![4, 1, 9, 5, 0]],
            true,
        ),
        (
            validation::NO_REV_AVAILABLE,
            vec![vec![5, 1, 0], vec![5, 0, 5, 0], vec![4, 0]],
            false,
        ),
    ] {
        for value in values {
            let bytes = ac_bytes(&entity(130, b"h.test"), &[ext(kind, &value, critical)]);
            let p = Parser::der(memory(1 << 20, 1 << 24));
            let ac = read_ac(&p, &bytes);
            assert!(ac.profile(p.memory()).is_err());
        }
    }
}

#[test]
fn access_and_distribution_profiles_reuse_complete_shared_readers() {
    // Profile URI restrictions and single fullName are stricter than generic PKIX syntax.
    for uri in [b"http://ocsp.test".as_slice(), b"HTTP://ocsp.test"] {
        let bytes = ac_bytes(
            &entity(130, b"h.test"),
            &[
                ext(
                    oid::AUTHORITY_KEY_IDENTIFIER,
                    &seq(&[&tlv(128, &[9])]),
                    false,
                ),
                ext(oid::AUTHORITY_INFO_ACCESS, &access(oid::OCSP, uri), false),
            ],
        );
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let ac = read_ac(&p, &bytes);
        let facts = accepted(ac.profile(p.memory()).unwrap());
        assert_eq!(facts.authority_key().unwrap().key_id(), Some(&[9][..]));
        assert_eq!(facts.access().unwrap().descriptions().len(), 1);
        assert_eq!(facts.revocation(), Revocation::Required);
    }
    for uri in [b"https://ocsp.test".as_slice(), b"ldap://ocsp.test"] {
        profile_reason(
            &ac_bytes(
                &entity(130, b"h.test"),
                &[ext(
                    oid::AUTHORITY_INFO_ACCESS,
                    &access(oid::OCSP, uri),
                    false,
                )],
            ),
            Reason::OcspLocation,
        );
    }
    for uri in [
        b"http://crl.test/a".as_slice(),
        b"ldap://directory.test/cn=CA?certificateRevocationList;binary",
    ] {
        let bytes = ac_bytes(
            &entity(130, b"h.test"),
            &[ext(
                oid::CRL_DISTRIBUTION_POINTS,
                &distribution(134, uri),
                false,
            )],
        );
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let ac = read_ac(&p, &bytes);
        let check = ac
            .profile(p.memory())
            .unwrap_or_else(|e| panic!("URI {:?}: {e:?}", std::str::from_utf8(uri)));
        assert!(accepted(check).distribution().is_some());
    }
    for value in [
        distribution(130, b"crl.test"),
        distribution(134, b"https://crl.test/a"),
        seq(&[
            &distribution(134, b"http://crl.test/a")[2..],
            &distribution(134, b"http://crl.test/b")[2..],
        ]),
    ] {
        profile_reason(
            &ac_bytes(
                &entity(130, b"h.test"),
                &[ext(oid::CRL_DISTRIBUTION_POINTS, &value, false)],
            ),
            Reason::DistributionPoint,
        );
    }
    profile_reason(
        &ac_bytes(
            &entity(130, b"h.test"),
            &[ext(
                oid::AUTHORITY_KEY_IDENTIFIER,
                &seq(&[&tlv(161, &directory(b"Authority")), &tlv(130, &[1])]),
                false,
            )],
        ),
        Reason::AuthorityKeyIdentifier,
    );
}

#[test]
fn ldap_distribution_point_may_omit_server_when_it_carries_dn_and_crl_attribute() {
    // RFC5280 §4.2.1.13 incorporates LDAP URLs; the server is optional (RFC4516 §2).
    let bytes = ac_bytes(
        &entity(130, b"h.test"),
        &[ext(
            oid::CRL_DISTRIBUTION_POINTS,
            &distribution(134, b"ldap:///cn=CA?certificateRevocationList;binary"),
            false,
        )],
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    assert!(
        accepted(read_ac(&p, &bytes).profile(p.memory()).unwrap())
            .distribution()
            .is_some()
    );
}

#[test]
fn authority_content_commitment_is_a_signature_use() {
    // RFC5755 §4.5 permits signature uses, including RFC5280 contentCommitment.
    let bytes = ac_bytes(&entity(130, b"h.test"), &[]);
    let cert_bytes = pkc(
        b"Root",
        b"Authority",
        &[1],
        &[],
        &[ext(oid::KEY_USAGE, &[3, 2, 6, 64], true)],
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let cp = Parser::der(memory(1 << 20, 1 << 24));
    accepted(
        read_ac(&p, &bytes)
            .bind_authority(&read_pkc(&cp, &cert_bytes), p.memory())
            .unwrap(),
    );
}

#[test]
fn no_revocation_conflicts_are_order_independent_but_ca_issuers_is_not_ocsp() {
    // AIA is a revocation pointer only for OCSP; no pointer absence means exemption.
    let no = ext(validation::NO_REV_AVAILABLE, &[5, 0], false);
    for pointer in [
        ext(
            oid::AUTHORITY_INFO_ACCESS,
            &access(oid::OCSP, b"http://ocsp.test"),
            false,
        ),
        ext(
            oid::CRL_DISTRIBUTION_POINTS,
            &distribution(134, b"http://crl.test"),
            false,
        ),
    ] {
        for extensions in [
            vec![no.clone(), pointer.clone()],
            vec![pointer.clone(), no.clone()],
        ] {
            profile_reason(
                &ac_bytes(&entity(130, b"h.test"), &extensions),
                Reason::RevocationConflict,
            );
        }
    }
    let bytes = ac_bytes(
        &entity(130, b"h.test"),
        &[
            no,
            ext(
                oid::AUTHORITY_INFO_ACCESS,
                &access(oid::CA_ISSUERS, b"http://ca.test"),
                false,
            ),
        ],
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    assert_eq!(
        accepted(read_ac(&p, &bytes).profile(p.memory()).unwrap()).revocation(),
        Revocation::NoRevAvailable
    );
}

#[test]
fn holder_base_binding_uses_full_serial_semantic_dn_and_optional_uid() {
    // No u64 projection or raw DN comparison may collapse or reject a true identity.
    let serial = [1; 15];
    let bytes = ac_bytes(&base(b"  AUTHORITY ", &serial, &[3, 2, 0, 9]), &[]);
    let cert_bytes = pkc(b"Authority", b"Holder", &serial, &[129, 2, 0, 9], &[]);
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let cp = Parser::der(memory(1 << 20, 1 << 24));
    let ac = read_ac(&p, &bytes);
    let cert = read_pkc(&cp, &cert_bytes);
    accepted(ac.profile(p.memory()).unwrap());
    accepted(
        ac.bind_holder(&cert, HolderMethod::BaseCertificate, p.memory())
            .unwrap(),
    );
    for (serial, uid, reason) in [
        ([2; 15], vec![129, 2, 0, 9], Reason::HolderCertificate),
        ([1; 15], vec![], Reason::HolderUniqueId),
        ([1; 15], vec![129, 2, 0, 8], Reason::HolderUniqueId),
    ] {
        let bytes = pkc(b"Authority", b"Holder", &serial, &uid, &[]);
        let other = read_pkc(&cp, &bytes);
        rejected(
            ac.bind_holder(&other, HolderMethod::BaseCertificate, p.memory())
                .unwrap(),
            reason,
        );
    }
}

#[test]
fn holder_entity_binding_checks_subject_and_san_without_choosing_another_method() {
    // Explicit method selection prevents a mismatching baseID hiding behind matching SAN.
    let h = seq(&[
        &base(b"Wrong", &[7], &[])[2..],
        &tlv(161, &tlv(130, b"HOLDER.TEST")),
    ]);
    let bytes = ac_bytes(&h, &[]);
    let cert_bytes = pkc(
        b"Authority",
        b"Holder",
        &[7],
        &[],
        &[ext(
            oid::SUBJECT_ALT_NAME,
            &seq(&[&tlv(130, b"holder.test")]),
            false,
        )],
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let cp = Parser::der(memory(1 << 20, 1 << 24));
    let ac = read_ac(&p, &bytes);
    let cert = read_pkc(&cp, &cert_bytes);
    assert_eq!(
        accepted(ac.profile(p.memory()).unwrap()).holder_alternatives(),
        2
    );
    rejected(
        ac.bind_holder(&cert, HolderMethod::BaseCertificate, p.memory())
            .unwrap(),
        Reason::HolderCertificate,
    );
    accepted(
        ac.bind_holder(&cert, HolderMethod::EntityName, p.memory())
            .unwrap(),
    );
    let bytes = ac_bytes(&seq(&[&tlv(161, &directory(b"  HOLDER "))]), &[]);
    let ac = read_ac(&p, &bytes);
    accepted(
        ac.bind_holder(&cert, HolderMethod::EntityName, p.memory())
            .unwrap(),
    );
    rejected(
        ac.bind_holder(&cert, HolderMethod::BaseCertificate, p.memory())
            .unwrap(),
        Reason::HolderAbsent,
    );
    let bytes = ac_bytes(&entity(130, b"other.test"), &[]);
    rejected(
        read_ac(&p, &bytes)
            .bind_holder(&cert, HolderMethod::EntityName, p.memory())
            .unwrap(),
        Reason::HolderName,
    );
}

#[test]
fn authority_binding_checks_own_uid_digital_signature_and_non_ca() {
    // Authority UID means its subject UID, not the UID of its certificate issuer.
    let bytes = ac_fields(
        &entity(130, b"h.test"),
        &issuer(b"AUTHORITY"),
        &[5],
        &validity(),
        &[3, 2, 0, 9],
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let ac = read_ac(&p, &bytes);
    let cp = Parser::der(memory(1 << 20, 1 << 24));
    for (name, uid, extensions, expected) in [
        (
            b"Authority".as_slice(),
            vec![129, 2, 0, 8, 130, 2, 0, 9],
            vec![],
            None,
        ),
        (
            b"Other",
            vec![130, 2, 0, 9],
            vec![],
            Some(Reason::AuthorityName),
        ),
        (
            b"Authority",
            vec![129, 2, 0, 9],
            vec![],
            Some(Reason::AuthorityUniqueId),
        ),
        (
            b"Authority",
            vec![130, 2, 0, 9],
            vec![ext(oid::BASIC_CONSTRAINTS, &[48, 3, 1, 1, 255], true)],
            Some(Reason::AuthorityIsCa),
        ),
        (
            b"Authority",
            vec![130, 2, 0, 9],
            vec![ext(oid::KEY_USAGE, &[3, 2, 5, 32], true)],
            Some(Reason::AuthorityUsage),
        ),
        (
            b"Authority",
            vec![130, 2, 0, 9],
            vec![ext(oid::KEY_USAGE, &[3, 2, 7, 128], true)],
            None,
        ),
    ] {
        let bytes = pkc(b"Root", name, &[1], &uid, &extensions);
        let cert = read_pkc(&cp, &bytes);
        let answer = ac.bind_authority(&cert, p.memory()).unwrap();
        if let Some(reason) = expected {
            rejected(answer, reason);
        } else {
            accepted(answer);
        }
    }
}

fn control(bound: Option<u8>, permitted: &[u8], excluded: &[u8], unspecified: bool) -> Vec<u8> {
    ext(
        controls::IDENTIFIER,
        &seq(&[
            &bound.map(|n| vec![2, 1, n]).unwrap_or_default(),
            &if permitted.is_empty() {
                vec![]
            } else {
                tlv(160, &tlv(6, permitted))
            },
            &if excluded.is_empty() {
                vec![]
            } else {
                tlv(161, &tlv(6, excluded))
            },
            if unspecified { &[] } else { &[1, 1, 0] },
        ]),
        false,
    )
}

#[test]
fn aa_path_collects_every_control_and_intersects_without_discarding_attributes() {
    // A lower allow cannot override a higher exclude, and exact denial source is retained.
    let bytes = [
        pkc(
            b"Intermediate",
            b"Authority",
            &[1],
            &[],
            &[control(None, &[42], &[], false)],
        ),
        pkc(
            b"Root",
            b"Intermediate",
            &[2],
            &[],
            &[control(Some(0), &[], &[42], true)],
        ),
        pkc(
            b"Root",
            b"Root",
            &[3],
            &[],
            &[control(Some(1), &[], &[], true)],
        ),
    ];
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let query = memory(1 << 20, 1 << 24);
    let path = accepted(AaPath::read(&refs, &query).unwrap());
    assert_eq!(path.certificates().len(), 3);
    assert!(matches!(
        path.allows(Oid::from_bytes(&[42]), &query).unwrap(),
        Permission::Excluded { certificate: 1, .. }
    ));
    assert!(matches!(
        path.allows(Oid::from_bytes(&[43]), &query).unwrap(),
        Permission::Excluded { certificate: 0, .. }
    ));
    assert!(query.used() > 0);
    drop(path);
    assert_eq!(query.used(), 0);
}

#[test]
fn aa_controls_require_complete_path_presence_and_actual_non_self_issued_distance() {
    // The chosen AA CA is optional, every lower PKC mandatory; pathLen zero skips self-issued.
    let p = Parser::der(memory(1 << 20, 1 << 26));
    let empty: [&Certificate<'_>; 0] = [];
    assert_eq!(
        rejected(AaPath::read(&empty, p.memory()).unwrap(), Reason::EmptyPath),
        None
    );
    for self_issued in [false, true] {
        let bytes = [
            pkc(
                b"Intermediate",
                b"Authority",
                &[1],
                &[],
                &[control(None, &[], &[], true)],
            ),
            pkc(
                if self_issued {
                    b"Intermediate"
                } else {
                    b"Root"
                },
                b"Intermediate",
                &[2],
                &[],
                &[control(None, &[], &[], true)],
            ),
            pkc(
                b"Root",
                b"Root",
                &[3],
                &[],
                &[control(Some(0), &[], &[], true)],
            ),
        ];
        let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
        let refs = certs.iter().collect::<Vec<_>>();
        let answer = AaPath::read(&refs, p.memory()).unwrap();
        if self_issued {
            accepted(answer);
        } else {
            rejected(answer, Reason::ControlDistance);
        }
    }
    let bytes = [
        pkc(b"Root", b"Authority", &[1], &[], &[]),
        pkc(b"Root", b"Root", &[2], &[], &[]),
    ];
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    assert_eq!(
        rejected(
            AaPath::read(&refs, p.memory()).unwrap(),
            Reason::MissingControls
        ),
        Some(certs[0].span())
    );
    let path = accepted(AaPath::read(&refs[1..], p.memory()).unwrap());
    assert_eq!(
        path.allows(Oid::from_bytes(&[42]), p.memory()).unwrap(),
        Permission::Permitted
    );
}

#[test]
fn deferred_profile_and_bindings_charge_current_execution_and_release_failures() {
    // Short current queries cannot borrow old parse funding, and failed scratch is released.
    let bytes = ac_bytes(
        &entity(130, b"h.test"),
        &[ext(
            oid::AUTHORITY_INFO_ACCESS,
            &access(oid::OCSP, b"http://ocsp.test"),
            false,
        )],
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let ac = read_ac(&p, &bytes);
    let cert_bytes = pkc(b"Root", b"Authority", &[1], &[], &[]);
    let cp = Parser::der(memory(1 << 20, 1 << 24));
    let cert = read_pkc(&cp, &cert_bytes);
    let zero = memory(1 << 20, 0);
    assert!(ac.profile(&zero).unwrap_err().is_terminal());
    assert!(
        ac.bind_holder(&cert, HolderMethod::EntityName, &zero)
            .unwrap_err()
            .is_terminal()
    );
    assert!(ac.bind_authority(&cert, &zero).unwrap_err().is_terminal());
    let no_capacity = memory(0, 1 << 24);
    assert!(ac.profile(&no_capacity).unwrap_err().is_terminal());
    assert_eq!(no_capacity.used(), 0);
    let q = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let query = q.read(&[], 900).unwrap();
    assert!(ac.profile(&query.execution()).unwrap_err().is_terminal());
}

#[test]
fn aa_path_cannot_bypass_an_exhausted_certificate_source() {
    // Retained scalar/catalogue queries still obey the producing PKC ceiling.
    let bytes = pkc(b"Root", b"Root", &[1], &[], &[]);
    let baseline = memory(1 << 20, 1 << 24);
    let bp = Parser::der(baseline.clone());
    drop(read_pkc(&bp, &bytes));
    let source = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_work: baseline.work_used() as u64,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let certificate = read_pkc(&source, &bytes);
    let query = memory(1 << 20, 1 << 24);
    assert!(
        AaPath::read(&[&certificate], &query)
            .unwrap_err()
            .is_terminal()
    );
}

#[test]
fn targeting_and_proxying_preflight_forbidden_certificates_and_keep_effects_visible() {
    // A matching early name cannot hide a later forbidden targetCert in any set.
    let good = seq(&[&tlv(160, &tlv(130, b"recipient.test"))]);
    let forbidden = tlv(162, &seq(&[&seq(&[&directory(b"Authority")]), &[2, 1, 7]]));
    for kind in [
        structured_cms::attribute_certificate::target::IDENTIFIER,
        structured_cms::attribute_certificate::proxy::IDENTIFIER,
    ] {
        profile_reason(
            &ac_bytes(
                &entity(130, b"h.test"),
                &[ext(kind, &seq(&[&good, &seq(&[&forbidden])]), true)],
            ),
            Reason::TargetCertificate,
        );
        let bytes = ac_bytes(&entity(130, b"h.test"), &[ext(kind, &seq(&[&good]), true)]);
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let ac = read_ac(&p, &bytes);
        let facts = accepted(ac.profile(p.memory()).unwrap());
        assert_eq!(
            facts.targeting().is_some(),
            kind == structured_cms::attribute_certificate::target::IDENTIFIER
        );
        assert_eq!(
            facts.proxying().is_some(),
            kind == structured_cms::attribute_certificate::proxy::IDENTIFIER
        );
    }
}

#[test]
fn malformed_san_and_late_critical_refusal_never_become_positive_prefixes() {
    // A required SAN cannot turn malformed syntax into an absent-name mismatch.
    let bytes = ac_bytes(&entity(130, b"holder.test"), &[]);
    let cert_bytes = pkc(
        b"Root",
        b"Holder",
        &[1],
        &[],
        &[ext(oid::SUBJECT_ALT_NAME, &[5, 0], false)],
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let cp = Parser::der(memory(1 << 20, 1 << 24));
    assert!(
        read_ac(&p, &bytes)
            .bind_holder(
                &read_pkc(&cp, &cert_bytes),
                HolderMethod::EntityName,
                p.memory()
            )
            .is_err()
    );
    let bytes = ac_bytes(
        &entity(130, b"h.test"),
        &[
            ext(
                structured_cms::attribute_certificate::target::IDENTIFIER,
                &seq(&[&seq(&[&tlv(160, &tlv(130, b"recipient.test"))])]),
                true,
            ),
            ext(Oid::from_bytes(&[42, 99]), &[5, 0], true),
        ],
    );
    let ac = read_ac(&p, &bytes);
    let query = memory(1 << 20, 1 << 24);
    rejected(ac.profile(&query).unwrap(), Reason::UnknownCritical);
    assert_eq!(query.used(), 0);
}

#[test]
fn profile_deferred_reads_obey_query_depth_and_original_source_work() {
    // Neither a new query account nor an existing catalogue grants parse work credit.
    let bytes = ac_bytes(
        &entity(130, b"h.test"),
        &[ext(
            oid::AUTHORITY_INFO_ACCESS,
            &access(oid::OCSP, b"http://ocsp.test"),
            false,
        )],
    );
    let baseline = memory(1 << 20, 1 << 24);
    let bp = Parser::der(baseline.clone());
    drop(read_ac(&bp, &bytes));
    let p = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_work: baseline.work_used() as u64,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let ac = read_ac(&p, &bytes);
    assert!(
        ac.profile(&memory(1 << 20, 1 << 24))
            .unwrap_err()
            .is_terminal()
    );
    let ac = read_ac(&bp, &bytes);
    let query_parser = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let query = query_parser.read(&[], 999).unwrap();
    assert!(ac.profile(&query.execution()).unwrap_err().is_terminal());
}

#[test]
fn aa_path_failure_rolls_back_catalogues_and_retained_queries_use_new_work() {
    // Partial controls release on missing upper control; retained checks pay a new request.
    let bytes = [
        pkc(
            b"Intermediate",
            b"Authority",
            &[1],
            &[],
            &[control(None, &[42], &[], false)],
        ),
        pkc(b"Root", b"Intermediate", &[2], &[], &[]),
        pkc(b"Root", b"Root", &[3], &[], &[]),
    ];
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let query = memory(1 << 20, 1 << 24);
    rejected(
        AaPath::read(&refs, &query).unwrap(),
        Reason::MissingControls,
    );
    assert_eq!(query.used(), 0);
    assert!(
        AaPath::read(&refs, &memory(0, 1 << 24))
            .unwrap_err()
            .is_terminal()
    );
    let short = [&certs[0], &certs[2]];
    let path = accepted(AaPath::read(&short, &query).unwrap());
    let current = memory(0, 1000);
    assert_eq!(
        path.allows(Oid::from_bytes(&[42]), &current).unwrap(),
        Permission::Permitted
    );
    current
        .charge_work(current.work_remaining() as u64)
        .unwrap();
    assert!(
        path.allows(Oid::from_bytes(&[42]), &current)
            .unwrap_err()
            .is_terminal()
    );
    drop(path);
    assert_eq!(query.used(), 0);
}

#[test]
fn authority_uid_presence_and_opaque_audit_borrow_are_exact() {
    // A PKC subject UID requires an AC issuer UID; audit bytes need no copy/allocation.
    let bytes = ac_bytes(
        &entity(130, b"h.test"),
        &[ext(validation::AUDIT_IDENTITY, &tlv(4, b"identity"), true)],
    );
    let cert_bytes = pkc(b"Root", b"Authority", &[1], &[130, 2, 0, 9], &[]);
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let cp = Parser::der(memory(1 << 20, 1 << 24));
    let ac = read_ac(&p, &bytes);
    rejected(
        ac.bind_authority(&read_pkc(&cp, &cert_bytes), p.memory())
            .unwrap(),
        Reason::AuthorityUniqueId,
    );
    let query = memory(0, 1 << 24);
    assert_eq!(
        accepted(ac.profile(&query).unwrap()).audit_identity(),
        Some(b"identity".as_slice())
    );
    assert_eq!(query.used(), 0);
}

#[test]
fn holder_subject_identity_does_not_materialize_unneeded_san() {
    // RFC5755 §4.2.2 permits subject OR SAN identity. A subject match needs no SAN catalogue.
    let bytes = ac_bytes(&seq(&[&tlv(161, &directory(b"Holder"))]), &[]);
    let names = (0..64)
        .map(|n| tlv(130, format!("name{n}.test").as_bytes()))
        .collect::<Vec<_>>();
    let cert_bytes = pkc(
        b"Root",
        b"Holder",
        &[1],
        &[],
        &[ext(
            oid::SUBJECT_ALT_NAME,
            &seq(&names.iter().map(Vec::as_slice).collect::<Vec<_>>()),
            false,
        )],
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let cp = Parser::der(memory(1 << 20, 1 << 24));
    let ac = read_ac(&p, &bytes);
    let cert = read_pkc(&cp, &cert_bytes);
    let query = memory(0, 1 << 24);
    accepted(
        ac.bind_holder(&cert, HolderMethod::EntityName, &query)
            .unwrap(),
    );
    assert_eq!(query.used(), 0);
}

#[test]
fn foreign_certificate_name_comparison_preserves_its_remaining_source_work() {
    // Funding metadata alone must not exempt the following foreign DN scan.
    let bytes = ac_bytes(&seq(&[&tlv(161, &directory(b"Authority"))]), &[]);
    let cert_bytes = pkc(b"Root", b"Authority", &[1], &[], &[]);
    let baseline = memory(1 << 20, 1 << 24);
    let bp = Parser::der(baseline.clone());
    drop(read_pkc(&bp, &cert_bytes));
    for authority in [false, true] {
        let source = Parser::new(
            structured_asn1::Encoding::Der,
            Limits {
                max_work: baseline.work_used() as u64 + 1,
                ..Limits::default()
            },
            memory(1 << 20, 1 << 24),
        );
        let cert = read_pkc(&source, &cert_bytes);
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let ac = read_ac(&p, &bytes);
        let query = memory(1 << 20, 1 << 24);
        let answer = if authority {
            ac.bind_authority(&cert, &query)
        } else {
            ac.bind_holder(&cert, HolderMethod::EntityName, &query)
        };
        assert!(answer.unwrap_err().is_terminal());
        assert_eq!(query.used(), 0);
    }
}

fn forbidden_names() -> [Vec<u8>; 3] {
    [
        tlv(136, &[42]),
        tlv(163, &[48, 0]),
        tlv(165, &tlv(161, &tlv(12, b"Party"))),
    ]
}

#[test]
fn static_profile_rejects_all_forbidden_holder_name_forms_even_after_allowed_name() {
    // RFC5755 §4.2 forbids these valid ASN.1 alternatives, not their inspection.
    for forbidden in forbidden_names() {
        for prefix in [vec![], directory(b"Holder")] {
            let bytes = ac_bytes(
                &seq(&[&tlv(161, &[prefix, forbidden.clone()].concat())]),
                &[],
            );
            let p = Parser::der(memory(1 << 20, 1 << 24));
            let ac = read_ac(&p, &bytes);
            assert!(
                !ac.information()
                    .holder
                    .entity_names
                    .as_ref()
                    .unwrap()
                    .is_empty()
            );
            rejected(ac.profile(p.memory()).unwrap(), Reason::NameForm);
        }
    }
}

#[test]
fn entity_binding_never_matches_a_forbidden_form_or_skips_a_late_forbidden_name() {
    // Matching SAN bytes, or an earlier matching subject, cannot legalize an AC name.
    for forbidden in forbidden_names() {
        for prefix in [vec![], directory(b"Holder")] {
            let bytes = ac_bytes(
                &seq(&[&tlv(161, &[prefix, forbidden.clone()].concat())]),
                &[],
            );
            let cert_bytes = pkc(
                b"Root",
                b"Holder",
                &[1],
                &[],
                &[ext(oid::SUBJECT_ALT_NAME, &seq(&[&forbidden]), false)],
            );
            let p = Parser::der(memory(1 << 20, 1 << 24));
            let cp = Parser::der(memory(1 << 20, 1 << 24));
            let ac = read_ac(&p, &bytes);
            let cert = read_pkc(&cp, &cert_bytes);
            rejected(
                ac.bind_holder(&cert, HolderMethod::EntityName, p.memory())
                    .unwrap(),
                Reason::NameForm,
            );
        }
    }
}

#[test]
fn profile_name_prohibition_reaches_all_decoded_extension_names() {
    // The same rule applies to extension names, not only Holder.entityName.
    for forbidden in forbidden_names() {
        let targets = seq(&[&seq(&[
            &tlv(160, &tlv(130, b"good.test")),
            &tlv(160, &forbidden),
        ])]);
        for extension in [
            ext(
                structured_cms::attribute_certificate::target::IDENTIFIER,
                &targets,
                true,
            ),
            ext(
                structured_cms::attribute_certificate::proxy::IDENTIFIER,
                &targets,
                true,
            ),
            ext(
                oid::AUTHORITY_KEY_IDENTIFIER,
                &seq(&[
                    &tlv(128, &[9]),
                    &tlv(161, &[directory(b"Authority"), forbidden.clone()].concat()),
                    &tlv(130, &[1]),
                ]),
                false,
            ),
            ext(
                oid::AUTHORITY_INFO_ACCESS,
                &seq(&[&seq(&[&tlv(6, &[42]), &forbidden])]),
                false,
            ),
        ] {
            let bytes = ac_bytes(&entity(130, b"holder.test"), &[extension]);
            let p = Parser::der(memory(1 << 20, 1 << 24));
            rejected(
                read_ac(&p, &bytes).profile(p.memory()).unwrap(),
                Reason::NameForm,
            );
        }
    }
}

#[test]
fn required_name_forms_and_standard_other_name_remain_profile_inputs() {
    // The profile excludes exactly its forbidden choices, not the four MUST or SRV SHOULD forms.
    let names = [
        tlv(130, b"holder.test"),
        directory(b"Holder"),
        tlv(134, b"http://holder.test"),
        tlv(135, &[192, 0, 2, 1]),
        tlv(
            160,
            &[
                tlv(6, &[43, 6, 1, 5, 5, 7, 8, 7]),
                tlv(160, &tlv(22, b"_ldap.example.com")),
            ]
            .concat(),
        ),
    ];
    let bytes = ac_bytes(&seq(&[&tlv(161, &names.concat())]), &[]);
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let ac = read_ac(&p, &bytes);
    let query = memory(0, 1 << 24);
    assert_eq!(
        accepted(ac.profile(&query).unwrap()).holder_alternatives(),
        1
    );
    assert_eq!(query.used(), 0);
}

#[test]
fn complete_name_type_scan_is_funded_before_a_late_forbidden_alternative() {
    // A long prefix costs Work; exhaustion cannot become a free semantic refusal.
    let ordinary = ac_bytes(&entity(130, b"holder.test"), &[]);
    let names = [tlv(130, b"holder.test").repeat(100), tlv(136, &[42])].concat();
    let bytes = ac_bytes(&seq(&[&tlv(161, &names)]), &[]);
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let baseline = memory(0, 1 << 24);
    accepted(read_ac(&p, &ordinary).profile(&baseline).unwrap());
    let query = memory(0, baseline.work_used() + 10);
    let ac = read_ac(&p, &bytes);
    assert!(ac.profile(&query).unwrap_err().is_terminal());
    assert_eq!(query.used(), 0);
}
