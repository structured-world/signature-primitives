//! End-to-end original path, CRL and OCSP revocation assessment.

mod support;

use core::{cell::Cell, cmp::Ordering};
use p256::ecdsa::SigningKey;
use sha2::{Digest as _, Sha256};
use structured_asn1::{
    Oid, Parser,
    digest::{Digest, Resolution},
    memory::{MemoryError, Work},
};
use structured_ltv::pki::{
    self, CrlAuthority, PathOutcome,
    status::{self, Finding, Interval, Query, Source, Status, Unusable, When},
};
use structured_pkix::{
    Certificate,
    algorithm::digest::{Algorithm, AsnDigest},
    crl::{CertificateList, Reason},
    ocsp::{self, BasicResponse},
    oid,
    path::{self, Anchor, ValidationBounds, ValidationContext},
    temporal::{Instant, LeapTable, Uncertainty},
};
use support::certificate_with_expiry;
use support::{Oracle, certificate, certificate_with_extensions, memory, name, signed, tlv};

const ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];

#[derive(Clone, Copy)]
struct List<'a> {
    number: u8,
    issued: &'a str,
    next: &'a str,
    entry: Option<(&'a str, u8)>,
    base: Option<u8>,
    partition: bool,
}

impl List<'_> {
    const fn empty() -> Self {
        Self {
            number: 1,
            issued: "250104000000Z",
            next: "250109000000Z",
            entry: None,
            base: None,
            partition: false,
        }
    }

    fn sign(self, key: &SigningKey) -> Vec<u8> {
        let mut extensions = ext(oid::CRL_NUMBER, false, &tlv(2, &[self.number]));
        if let Some(base) = self.base {
            extensions.extend(ext(oid::DELTA_CRL_INDICATOR, true, &tlv(2, &[base])));
            extensions.extend(ext(
                oid::AUTHORITY_KEY_IDENTIFIER,
                false,
                &tlv(0x30, &tlv(0x80, b"key")),
            ));
        } else {
            extensions.extend(ext(
                oid::AUTHORITY_KEY_IDENTIFIER,
                false,
                &tlv(0x30, &tlv(0x80, b"key")),
            ));
        }
        if self.partition {
            // onlySomeReasons = keyCompromise.
            extensions.extend(ext(
                oid::ISSUING_DISTRIBUTION_POINT,
                true,
                &tlv(0x30, &tlv(0x83, &[6, 0x40])),
            ));
        }
        let mut fields = [
            tlv(2, &[1]),
            tlv(0x30, &tlv(6, ECDSA)),
            name("Root"),
            tlv(0x17, self.issued.as_bytes()),
            tlv(0x17, self.next.as_bytes()),
        ]
        .concat();
        if let Some((at, reason)) = self.entry {
            fields.extend(tlv(
                0x30,
                &tlv(
                    0x30,
                    &[
                        tlv(2, &[7]),
                        tlv(0x17, at.as_bytes()),
                        tlv(0x30, &ext(oid::CRL_REASON, false, &tlv(10, &[reason]))),
                    ]
                    .concat(),
                ),
            ));
        }
        fields.extend(tlv(0xa0, &tlv(0x30, &extensions)));
        signed(tlv(0x30, &fields), key)
    }
}

fn ext(oid: Oid<'_>, critical: bool, content: &[u8]) -> Vec<u8> {
    let mut value = tlv(6, oid.as_bytes());
    if critical {
        value.extend(tlv(1, &[0xff]));
    }
    value.extend(tlv(4, content));
    tlv(0x30, &value)
}

fn signed_response(
    key: &SigningKey,
    signer_name: &str,
    signer: &SigningKey,
    status: &[u8],
    serial: u8,
    extended: bool,
) -> Vec<u8> {
    let certificate_id = tlv(
        0x30,
        &[
            tlv(0x30, &tlv(6, SHA256)),
            tlv(4, &Sha256::digest(name("Root"))),
            tlv(
                4,
                &Sha256::digest(key.verifying_key().to_sec1_point(false).as_bytes()),
            ),
            tlv(2, &[serial]),
        ]
        .concat(),
    );
    let single = tlv(
        0x30,
        &[
            certificate_id,
            status.to_vec(),
            tlv(0x18, b"20250104000000Z"),
            tlv(0xa0, &tlv(0x18, b"20250109000000Z")),
        ]
        .concat(),
    );
    let mut body = [
        tlv(0xa1, &name(signer_name)),
        tlv(0x18, b"20250104010000Z"),
        tlv(0x30, &single),
    ]
    .concat();
    if extended {
        body.extend(tlv(
            0xa1,
            &tlv(0x30, &ext(oid::OCSP_EXTENDED_REVOKE, false, &tlv(5, &[]))),
        ));
    }
    tlv(
        0x30,
        &[
            tlv(10, &[0]),
            tlv(
                0xa0,
                &tlv(
                    0x30,
                    &[
                        tlv(6, oid::OCSP_BASIC.as_bytes()),
                        tlv(4, &signed(tlv(0x30, &body), signer)),
                    ]
                    .concat(),
                ),
            ),
        ]
        .concat(),
    )
}

fn basic<'a>(parser: &'a Parser, der: &'a [u8]) -> BasicResponse<'a> {
    let ocsp::Response::Successful(response) = ocsp::Response::read(parser, der, 900).unwrap()
    else {
        panic!("expected a successful response envelope")
    };
    response.into_basic(parser.memory()).unwrap().unwrap()
}

struct Hash;
impl Digest<'_> for Hash {
    type Identity = ();
    type State = Sha256;
    type Output = [u8; 32];
    type Error = MemoryError;

    fn width(&self, (): &()) -> Option<usize> {
        Some(32)
    }
    fn compare<W: Work>(&self, (): &(), (): &(), work: &W) -> Result<Ordering, MemoryError> {
        work.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&self, (): &(), work: &W) -> Result<Resolution<Sha256>, MemoryError> {
        work.charge_work(1)?;
        Ok(Resolution::Supported(Sha256::new()))
    }
    fn update<W: Work>(
        &self,
        state: &mut Sha256,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), MemoryError> {
        work.charge_work(u64::try_from(bytes.len()).unwrap())?;
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Sha256, work: &W) -> Result<[u8; 32], MemoryError> {
        work.charge_work(1)?;
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        (): &(),
        output: &[u8; 32],
        expected: &[u8],
        work: &W,
    ) -> Result<bool, MemoryError> {
        work.charge_work(32)?;
        Ok(output.as_slice() == expected)
    }
}

impl AsnDigest<'_> for Hash {
    fn identity(&self, algorithm: Algorithm) -> Option<()> {
        (algorithm == Algorithm::Sha256).then_some(())
    }
}

fn at(day: i64) -> Instant {
    Instant::new(1_735_689_600 + (day - 1) * 86_400, 0).unwrap()
}

fn query<'q>(utc: &'q LeapTable<'q>) -> Query<'q> {
    Query {
        interval: Interval {
            lower: Some(at(3)),
            upper: at(5),
        },
        now: at(10),
        utc,
        max_freshness_seconds: None,
    }
}

fn keys() -> (SigningKey, SigningKey) {
    (
        SigningKey::from_bytes((&[1; 32]).into()).unwrap(),
        SigningKey::from_bytes((&[2; 32]).into()).unwrap(),
    )
}

fn certificates(root: &SigningKey, leaf: &SigningKey) -> (Vec<u8>, Vec<u8>) {
    (
        certificate_with_extensions(
            "Root",
            "Root",
            root,
            root,
            &ext(oid::KEY_USAGE, true, &tlv(3, &[1, 0x82])),
        ),
        certificate("Leaf", "Root", leaf, root),
    )
}

fn context<'a, 'q, E: Work>(
    execution: &'q E,
    verifier: &'q Oracle,
) -> ValidationContext<'a, 'q, Oracle, (), (), E> {
    ValidationContext {
        execution,
        interval: path::Interval::at(at(5).seconds()),
        policy: path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier,
        watch: &(),
        recognizer: &(),
    }
}

fn checked<'a, E: Work>(
    root: &'a Certificate<'a>,
    leaf: &'a Certificate<'a>,
    context: &ValidationContext<'a, '_, Oracle, (), (), E>,
) -> pki::CheckedPath<'a> {
    let PathOutcome::Accepted(path) =
        pki::check_path(&[leaf], Anchor::from_certificate(root), context).unwrap()
    else {
        panic!("test path is statically valid")
    };
    path
}

fn crl<'a>(list: &'a CertificateList<'a>) -> Source<'a, 'a> {
    Source::Crl {
        list,
        authorities: &[CrlAuthority::Anchor],
    }
}

#[test]
fn complete_lists_produce_clear_revoked_hold_stale_and_partial() {
    // These are signed source facts on the selected original member, not
    // synthetic statements injected into the join.
    let (root_key, leaf_key) = keys();
    let (root_der, leaf_der) = certificates(&root_key, &leaf_key);
    let account = memory(1 << 20);
    let parser = Parser::der(account.clone());
    let root = Certificate::read(&parser, &root_der, 1).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 500).unwrap();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    let context = context(&account, &oracle);
    let path = checked(&root, &leaf, &context);
    let utc = LeapTable::new(at(1).seconds() - 1, at(11).seconds(), &[]).unwrap();
    let query = query(&utc);
    let empty = List::empty();
    let lists = [
        empty,
        List {
            entry: Some(("250102000000Z", 1)),
            ..empty
        },
        List {
            entry: Some(("250104000000Z", 1)),
            ..empty
        },
        List {
            entry: Some(("250106000000Z", 1)),
            ..empty
        },
        List {
            entry: Some(("250104000000Z", 6)),
            ..empty
        },
        List {
            next: "250105000000Z",
            ..empty
        },
        List {
            partition: true,
            ..empty
        },
    ];
    for (index, list) in lists.iter().enumerate() {
        let der = list.sign(&root_key);
        let list = CertificateList::read(&parser, &der, 1000).unwrap();
        let sources = [crl(&list)];
        let outcome = status::assess(&path, 0, &sources, &query, &context, &oracle, &Hash).unwrap();
        assert_eq!(outcome.member(), 0);
        assert_eq!(outcome.statements()[0].sources.primary, 0);
        match (index, outcome.status()) {
            (
                0,
                Status::NotRevoked {
                    basis: 0,
                    later: None,
                },
            )
            | (4, Status::OnHold { basis: 0 })
            | (5, Status::NotFresh { basis: 0 }) => {}
            (
                1,
                Status::Revoked {
                    basis: 0,
                    revoked,
                    when: When::Before,
                },
            ) => assert_eq!(revoked.at.instant(), at(2)),
            (
                2,
                Status::Revoked {
                    basis: 0,
                    revoked,
                    when: When::NotProvablyAfter,
                },
            ) => assert_eq!(revoked.reason, Some(Reason::KeyCompromise)),
            (
                3,
                Status::NotRevoked {
                    basis: 0,
                    later: Some(revoked),
                },
            ) => assert_eq!(revoked.at.instant(), at(6)),
            (6, Status::PartialReasons { basis: 0, covered }) => assert_eq!(covered.bits(), 2),
            mismatch => panic!("unexpected assessment: {mismatch:?}"),
        }
    }
    let narrow = LeapTable::new(at(4).seconds() + 1, at(11).seconds(), &[]).unwrap();
    let outside = Query {
        utc: &narrow,
        ..query
    };
    let der = empty.sign(&root_key);
    let list = CertificateList::read(&parser, &der, 2000).unwrap();
    let result =
        status::assess(&path, 0, &[crl(&list)], &outside, &context, &oracle, &Hash).unwrap();
    assert_eq!(
        result.status(),
        Status::Uncertain(Uncertainty::OutsideCoverage)
    );
}

#[test]
fn mixed_sources_keep_conflict_never_issued_and_authentication_failures() {
    // Good and revoked answers with equal issuance conflict, an extended
    // never-issued answer remains distinct, and a forged signature cannot speak.
    let (root_key, leaf_key) = keys();
    let (root_der, leaf_der) = certificates(&root_key, &leaf_key);
    let account = memory(1 << 20);
    let parser = Parser::der(account.clone());
    let root = Certificate::read(&parser, &root_der, 1).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 500).unwrap();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    let context = context(&account, &oracle);
    let path = checked(&root, &leaf, &context);
    let utc = LeapTable::new(at(1).seconds() - 1, at(11).seconds(), &[]).unwrap();
    let query = query(&utc);
    let good = signed_response(&root_key, "Root", &root_key, &tlv(0x80, &[]), 7, false);
    let unknown = signed_response(&root_key, "Root", &root_key, &tlv(0x82, &[]), 7, false);
    let revoked = signed_response(
        &root_key,
        "Root",
        &root_key,
        &tlv(
            0xa1,
            &[tlv(0x18, b"20250102000000Z"), tlv(0xa0, &tlv(10, &[1]))].concat(),
        ),
        7,
        false,
    );
    let never = signed_response(
        &root_key,
        "Root",
        &root_key,
        &tlv(
            0xa1,
            &[tlv(0x18, b"19700101000000Z"), tlv(0xa0, &tlv(10, &[6]))].concat(),
        ),
        7,
        true,
    );
    let forged = signed_response(&root_key, "Root", &leaf_key, &tlv(0x80, &[]), 7, false);
    let other = signed_response(&root_key, "Root", &root_key, &tlv(0x80, &[]), 9, false);
    let artifacts = [&good, &unknown, &revoked, &never, &forged, &other];
    let decoded = artifacts.map(|bytes| basic(&parser, bytes));
    let [good, unknown, revoked, never, forged, other] =
        decoded.each_ref().map(|response| Source::Ocsp {
            response,
            nonce: None,
            intended_signer: None,
            responders: &[],
        });
    let result = status::assess(
        &path,
        0,
        &[unknown, forged, other],
        &query,
        &context,
        &oracle,
        &Hash,
    )
    .unwrap();
    assert_eq!(result.status(), Status::Unknown { basis: 0 });
    assert!(matches!(
        result.statements()[1].finding,
        Finding::Unusable(Unusable::OcspAuthentication(
            ocsp::SignatureFailure::Signature
        ))
    ));
    assert!(matches!(
        result.statements()[2].finding,
        Finding::Unusable(Unusable::Lookup(status::LookupFailure::Missing))
    ));
    let result = status::assess(&path, 0, &[never], &query, &context, &oracle, &Hash).unwrap();
    assert_eq!(result.status(), Status::NotIssued { basis: 0 });
    let empty_der = List::empty().sign(&root_key);
    let empty = CertificateList::read(&parser, &empty_der, 4000).unwrap();
    let result = status::assess(
        &path,
        0,
        &[crl(&empty), good, revoked],
        &query,
        &context,
        &oracle,
        &Hash,
    )
    .unwrap();
    let Status::Conflict { first, second } = result.status() else {
        panic!("the OCSP assertions disagree");
    };
    assert_eq!(result.statements()[first].sources.primary, 1);
    assert_eq!(result.statements()[second].sources.primary, 2);
    assert_eq!(
        status::assess(&path, 0, &[], &query, &context, &oracle, &Hash)
            .unwrap()
            .status(),
        Status::NoEvidence
    );
}

#[test]
fn delta_release_does_not_erase_an_overlapping_hold_or_claim_an_expired_serial() {
    // RFC 5280 §§5.2.4, 5.3.1: a removal bounds the release. An intermediate
    // entry removed after expiry can also have been a permanent revocation.
    let (root_key, leaf_key) = keys();
    let (root_der, _) = certificates(&root_key, &leaf_key);
    let target_der =
        certificate_with_expiry("Leaf", "Root", &leaf_key, &root_key, &[], b"250106000000Z");
    let account = memory(1 << 20);
    let parser = Parser::der(account.clone());
    let root = Certificate::read(&parser, &root_der, 1).unwrap();
    let target = Certificate::read(&parser, &target_der, 500).unwrap();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    let context = context(&account, &oracle);
    let path = checked(&root, &target, &context);
    let utc = LeapTable::new(at(1).seconds() - 1, at(11).seconds(), &[]).unwrap();
    let historical = query(&utc);
    let base = List::empty();
    let hold = List {
        entry: Some(("250102000000Z", 6)),
        ..base
    };
    let released = List {
        number: 2,
        base: Some(1),
        issued: "250105000000Z",
        entry: Some(("250105000000Z", 8)),
        ..base
    };
    let expired = List {
        issued: "250107000000Z",
        ..released
    };
    let same_time = List {
        issued: base.issued,
        entry: Some(("250102000000Z", 1)),
        ..released
    };
    let values = [base, hold, released, expired, same_time].map(|list| list.sign(&root_key));
    let [base, hold, released, expired, same_time] = values
        .each_ref()
        .map(|bytes| CertificateList::read(&parser, bytes, 2000).unwrap());
    let related = [crl(&released), crl(&hold)];
    let outcome =
        status::assess(&path, 0, &related, &historical, &context, &oracle, &Hash).unwrap();
    assert!(matches!(outcome.status(), Status::OnHold { .. }));
    assert!(
        outcome
            .statements()
            .iter()
            .any(|value| value.sources.primary == 0 && value.sources.base == Some(1))
    );

    let after = Query {
        interval: Interval {
            lower: Some(at(5)),
            upper: at(6),
        },
        ..historical
    };
    let outcome = status::assess(&path, 0, &related, &after, &context, &oracle, &Hash).unwrap();
    let Status::NotRevoked { basis, later: None } = outcome.status() else {
        panic!("hold released before this signature");
    };
    assert_eq!(outcome.statements()[basis].sources.primary, 0);

    let outcome = status::assess(
        &path,
        0,
        &[crl(&base), crl(&expired)],
        &historical,
        &context,
        &oracle,
        &Hash,
    )
    .unwrap();
    assert!(matches!(outcome.status(), Status::HeldOrRevoked { .. }));

    // A delta with the same timestamp and a strictly higher CRL number
    // updates its own base. That base's omission cannot conflict with it.
    let outcome = status::assess(
        &path,
        0,
        &[crl(&base), crl(&same_time)],
        &historical,
        &context,
        &oracle,
        &Hash,
    )
    .unwrap();
    assert!(matches!(outcome.status(), Status::Revoked { .. }));

    let outcome = status::assess(
        &path,
        0,
        &[crl(&expired)],
        &historical,
        &context,
        &oracle,
        &Hash,
    )
    .unwrap();
    assert_eq!(outcome.status(), Status::NoEvidence);
    assert!(matches!(
        outcome.statements()[0].finding,
        Finding::Unusable(Unusable::DeltaWithoutBase)
    ));
}

#[test]
fn delegated_responder_needs_explicit_authority_and_responder_status() {
    // An authenticated response by another key may be authorized by local
    // configuration or by original direct delegation plus responder status.
    let (root_key, leaf_key) = keys();
    let (root_der, target_der) = certificates(&root_key, &leaf_key);
    let signer = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let responder_der = certificate_with_extensions(
        "Responder",
        "Root",
        &signer,
        &root_key,
        &ext(
            oid::EXT_KEY_USAGE,
            false,
            &tlv(0x30, &tlv(6, oid::OCSP_SIGNING.as_bytes())),
        ),
    );
    let response_der = signed_response(&root_key, "Responder", &signer, &tlv(0x80, &[]), 7, false);
    let clear_der = List::empty().sign(&root_key);
    let account = memory(1 << 20);
    let parser = Parser::der(account.clone());
    let root = Certificate::read(&parser, &root_der, 1).unwrap();
    let target = Certificate::read(&parser, &target_der, 500).unwrap();
    let signer = Certificate::read(&parser, &responder_der, 1000).unwrap();
    let response = basic(&parser, &response_der);
    let list = CertificateList::read(&parser, &clear_der, 2000).unwrap();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    let context = context(&account, &oracle);
    let path = checked(&root, &target, &context);
    let production = response.produced_at().instant();
    let responder_context = ValidationContext {
        interval: path::Interval::at_instant(production),
        ..context
    };
    let responder_path = checked(&root, &signer, &responder_context);
    let utc = LeapTable::new(at(1).seconds() - 1, at(11).seconds(), &[]).unwrap();
    let query = query(&utc);
    let produced = Query {
        interval: Interval {
            lower: None,
            upper: production,
        },
        ..query
    };
    let assessment = status::assess(
        &responder_path,
        0,
        &[crl(&list)],
        &produced,
        &context,
        &oracle,
        &Hash,
    )
    .unwrap();
    assert!(matches!(assessment.status(), Status::NotRevoked { .. }));
    let assess = |responders| {
        status::assess(
            &path,
            0,
            &[Source::Ocsp {
                response: &response,
                nonce: None,
                intended_signer: Some(&signer),
                responders,
            }],
            &query,
            &context,
            &oracle,
            &Hash,
        )
        .unwrap()
    };
    assert_eq!(assess(&[]).status(), Status::NoEvidence);
    let unresolved = [status::Responder::Delegate {
        path: &responder_path,
        revocation: None,
    }];
    let outcome = assess(&unresolved);
    assert!(matches!(
        outcome.statements()[0].finding,
        Finding::Unusable(Unusable::ResponderRevocationUnchecked)
    ));
    let delegate = [status::Responder::Delegate {
        path: &responder_path,
        revocation: Some(&assessment),
    }];
    assert!(matches!(
        assess(&delegate).status(),
        Status::NotRevoked { .. }
    ));
    let local = [status::Responder::Configured {
        certificate: &signer,
        key: path::EffectiveKey::standing(signer.tbs().public_key()),
    }];
    assert!(matches!(assess(&local).status(), Status::NotRevoked { .. }));
}

#[test]
fn producing_work_is_enforced_before_the_signature_provider_runs() {
    // New current work cannot reset the original CRL parser's ceiling.
    let (root_key, leaf_key) = keys();
    let (root_der, leaf_der) = certificates(&root_key, &leaf_key);
    let der = List::empty().sign(&root_key);
    let account = memory(1 << 20);
    let parser = Parser::der(account.clone());
    let root = Certificate::read(&parser, &root_der, 1).unwrap();
    let leaf = Certificate::read(&parser, &leaf_der, 500).unwrap();
    let producing = Parser::der(memory(1 << 20));
    let list = CertificateList::read(&producing, &der, 1100).unwrap();
    let original = list.execution_in(producing.memory());
    original
        .charge_work(original.work_remaining() as u64)
        .unwrap();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    let context = context(&account, &oracle);
    let path = checked(&root, &leaf, &context);
    let calls = oracle.calls.get();
    let utc = LeapTable::new(at(1).seconds() - 1, at(11).seconds(), &[]).unwrap();
    let result = status::assess(
        &path,
        0,
        &[crl(&list)],
        &query(&utc),
        &context,
        &oracle,
        &Hash,
    );
    assert!(matches!(
        result,
        Err(status::Error::Resource(MemoryError::WorkExceeded))
    ));
    assert_eq!(oracle.calls.get(), calls);
}
