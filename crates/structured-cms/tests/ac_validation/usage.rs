//! Public relying-party composition with real Ed25519 issuance and PKIX paths.
#[path = "encrypted.rs"]
mod encrypted;
use super::*;
use structured_asn1::memory::Execution;
use structured_cms::attribute_certificate::validation::{
    self,
    usage::{Failure, Outcome},
};
use structured_cms::attribute_certificate::validation::{HolderMethod, usage::*};
use structured_cms::attribute_certificate::{proxy, target};
use structured_pkix::Certificate;
use structured_pkix::general_name::GeneralName;
use structured_pkix::path::{Anchor, EffectiveAnchor};
use structured_pkix::temporal::{LeapTable, Reading};

fn holder_bytes(subject: &[u8]) -> Vec<u8> {
    certificate(
        subject,
        b"Root",
        9,
        &SigningKey::from_bytes(&[4; 32]),
        &SigningKey::from_bytes(&[3; 32]),
        false,
        &[],
    )
}
fn holder_path<'p, 'a>(
    references: &'p [&'a Certificate<'a>],
    root: &'a Certificate<'a>,
    crypto: &Crypto,
    work: &Memory,
) -> HolderPath<'p, 'a> {
    let anchor = Anchor::from_certificate(root);
    let anchor = EffectiveAnchor::bind(anchor, WorkingKey::standing(anchor.key()), work)
        .unwrap()
        .unwrap();
    let HolderValidation::Accepted(path) =
        HolderPath::validate(references, anchor, &context(work, crypto, &())).unwrap()
    else {
        panic!("holder path")
    };
    path
}
fn use_ac(extensions: &[Vec<u8>]) -> Vec<u8> {
    use_ac_with(&entity(164, &name(b"Holder")), extensions)
}
fn use_ac_with(holder: &[u8], extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut extensions = extensions.to_vec();
    extensions.push(ext(
        oid::AUTHORITY_KEY_IDENTIFIER,
        &[48, 3, 128, 1, 1],
        false,
    ));
    let information = seq(&[
        &[2, 1, 1],
        holder,
        &issuer(b"Authority"),
        &ed(),
        &[2, 1, 5],
        &validity(),
        &seq(&[
            &seq(&[&[6, 1, 42], &[49, 2, 5, 0]]),
            &seq(&[&[6, 1, 43], &[49, 2, 5, 0]]),
        ]),
        &seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>()),
    ]);
    signed(&information, &SigningKey::from_bytes(&[1; 32]))
}

impl structured_asn1::digest::Digest<'_> for Crypto {
    type Identity = structured_pkix::algorithm::digest::Algorithm;
    type State = sha2::Sha256;
    type Output = [u8; 32];
    type Error = Cause;
    fn width(&self, algorithm: &Self::Identity) -> Option<usize> {
        Some(algorithm.width())
    }
    fn compare<W: Work>(
        &self,
        left: &Self::Identity,
        right: &Self::Identity,
        work: &W,
    ) -> Result<core::cmp::Ordering, Cause> {
        work.charge_work(1)?;
        Ok(left.cmp(right))
    }
    fn start<W: Work>(
        &self,
        algorithm: &Self::Identity,
        work: &W,
    ) -> Result<Resolution<Self::State>, Cause> {
        use sha2::Digest as _;
        work.charge_work(1)?;
        assert_eq!(
            *algorithm,
            structured_pkix::algorithm::digest::Algorithm::Sha256
        );
        Ok(Resolution::Supported(sha2::Sha256::new()))
    }
    fn update<W: Work>(
        &self,
        state: &mut Self::State,
        bytes: &[u8],
        work: &W,
    ) -> Result<(), Cause> {
        use sha2::Digest as _;
        work.charge_work(bytes.len() as u64)?;
        state.update(bytes);
        Ok(())
    }
    fn finish<W: Work>(&self, state: Self::State, work: &W) -> Result<Self::Output, Cause> {
        use sha2::Digest as _;
        work.charge_work(32)?;
        Ok(state.finalize().into())
    }
    fn matches<W: Work>(
        &self,
        _: &Self::Identity,
        output: &Self::Output,
        expected: &[u8],
        work: &W,
    ) -> Result<bool, Cause> {
        work.charge_work(32)?;
        Ok(output.as_slice() == expected)
    }
}
impl structured_pkix::algorithm::digest::AsnDigest<'_> for Crypto {
    fn identity(&self, a: structured_pkix::algorithm::digest::Algorithm) -> Option<Self::Identity> {
        (a == structured_pkix::algorithm::digest::Algorithm::Sha256).then_some(a)
    }
}
impl structured_cms::attribute_certificate::validation::digest::ObjectDigestProvider<'_>
    for Crypto
{
    fn validate_public_key<W: Work>(
        &self,
        key: WorkingKey<'_>,
        work: &W,
    ) -> Result<Resolution<()>, Cause> {
        structured_pkix::key::rfc8410::read(key.key(), work)?;
        Ok(Resolution::Supported(()))
    }
}

#[test]
fn object_digest_receipts_bind_the_same_ac_and_require_paths_for_certificate_objects() {
    // A genuine digest receipt cannot be transplanted to another AC or another PKC path.
    use sha2::Digest as _;
    use structured_cms::attribute_certificate::validation::digest::{Binding, Object};
    for public_key in [false, true] {
        let (chain, _) = fixture(Change::None);
        let hb = holder_bytes(b"Holder");
        let other_hb = holder_bytes(b"Other");
        let p = Parser::der(generous());
        let aa = read_pkc(&p, &chain[0]);
        let root = read_pkc(&p, &chain[2]);
        let holder = read_pkc(&p, &hb);
        let other_holder = read_pkc(&p, &other_hb);
        let hash = sha2::Sha256::digest(if public_key {
            holder.tbs().public_key().as_bytes()
        } else {
            holder.as_bytes()
        });
        let digest = tlv(
            162,
            &[
                tlv(10, &[u8::from(!public_key)]),
                seq(&[&tlv(6, oid::SHA256.as_bytes())]),
                tlv(3, &[&[0][..], hash.as_slice()].concat()),
            ]
            .concat(),
        );
        let ab = use_ac_with(&seq(&[&digest]), &[no_rev()]);
        let ac = read_ac(&p, &ab);
        let other_ac = read_ac(&p, &ab);
        let work = generous();
        let crypto = Crypto::new();
        let references = [&holder];
        let other_references = [&other_holder];
        let path = holder_path(&references, &root, &crypto, &work);
        let other_path = holder_path(&other_references, &root, &crypto, &work);
        let object = if public_key {
            Object::PublicKey(path.facts().key)
        } else {
            Object::Certificate(&holder)
        };
        let Binding::Bound(binding) = ac.bind_holder_digest(object, &crypto, &work).unwrap() else {
            panic!("digest")
        };
        let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
        for case in 0..4 {
            let original = if case == 3 { &other_ac } else { &ac };
            let super::Outcome::Authenticated(facts) = original
                .authenticate(
                    &aa,
                    WorkingKey::standing(aa.tbs().public_key()),
                    path.interval(),
                    &crypto,
                    &work,
                )
                .unwrap()
            else {
                panic!()
            };
            let calls = crypto.calls.get();
            let out = direct(
                &facts,
                &aa,
                Context {
                    holder: Holder::Object {
                        binding: &binding,
                        path: match case {
                            0 | 3 => Some(&path),
                            1 => None,
                            _ => Some(&other_path),
                        },
                    },
                    recipient: &[],
                    proxy: None,
                    status: &NoStatus,
                    now: path.interval().from_instant().into(),
                    utc: &utc,
                    execution: &work,
                },
                no_groups,
            )
            .unwrap();
            assert_eq!(crypto.calls.get(), calls);
            match out {
                Outcome::Checked(_) => assert!(case == 0 || (case == 1 && public_key)),
                Outcome::Rejected(Failure::HolderPath) => {
                    assert!(case == 2 || (case == 1 && !public_key));
                }
                Outcome::Rejected(Failure::HolderObject) => assert_eq!(case, 3),
                other @ Outcome::Rejected(_) => panic!("key={public_key} case={case}: {other:?}"),
            }
        }
    }
}

#[test]
fn holder_paths_preserve_incomplete_negative_and_callback_outcomes() {
    // No successful holder capability escapes a truncated/invalid path or opaque provider failure.
    let (chain, _) = fixture(Change::None);
    let hb = holder_bytes(b"Holder");
    let p = Parser::der(generous());
    let root = read_pkc(&p, &chain[2]);
    let holder = read_pkc(&p, &hb);
    let q = generous();
    let c = Crypto::new();
    let refs = [&holder];
    let anchor = Anchor::from_certificate(&root);
    let anchor = EffectiveAnchor::bind(anchor, WorkingKey::standing(anchor.key()), &q)
        .unwrap()
        .unwrap();
    let mut ctx = context(&q, &c, &());
    ctx.bounds.depth = 0;
    assert!(matches!(
        HolderPath::validate(&refs, anchor, &ctx).unwrap(),
        HolderValidation::Incomplete(path::Truncation::Depth)
    ));
    ctx.bounds.depth = 10;
    assert!(matches!(
        HolderPath::validate(&[], anchor, &ctx).unwrap(),
        HolderValidation::Rejected(_)
    ));
    c.fail.set(true);
    assert!(matches!(
        HolderPath::validate(&refs, anchor, &ctx),
        Err(HolderError::Verification(Cause::Marker))
    ));
    c.fail.set(false);
    c.unsupported.set(true);
    assert!(matches!(
        HolderPath::validate(&refs, anchor, &ctx).unwrap(),
        HolderValidation::Rejected(_)
    ));
}

#[test]
fn object_certificate_receipt_metadata_keeps_its_original_source_ceiling() {
    // Even an O(1) identity shortcut must admit the original certificate's
    // metadata before combining retained facts into a fresh successful result.
    use sha2::Digest as _;
    use structured_cms::attribute_certificate::validation::digest::{Binding, Object};
    let (chain, _) = fixture(Change::None);
    let hb = holder_bytes(b"Holder");
    let p = Parser::der(generous());
    let hp = Parser::der(generous());
    let holder = read_pkc(&hp, &hb);
    let aa = read_pkc(&p, &chain[0]);
    let root = read_pkc(&p, &chain[2]);
    let hash = sha2::Sha256::digest(holder.as_bytes());
    let holder_field = seq(&[&tlv(
        162,
        &[
            vec![10, 1, 1],
            seq(&[&tlv(6, oid::SHA256.as_bytes())]),
            tlv(3, &[&[0][..], hash.as_slice()].concat()),
        ]
        .concat(),
    )]);
    let ab = use_ac_with(&holder_field, &[no_rev()]);
    let ac = read_ac(&p, &ab);
    let work = generous();
    let crypto = Crypto::new();
    let refs = [&holder];
    let path = holder_path(&refs, &root, &crypto, &work);
    let Binding::Bound(binding) = ac
        .bind_holder_digest(Object::Certificate(&holder), &crypto, &work)
        .unwrap()
    else {
        panic!()
    };
    let super::Outcome::Authenticated(facts) = ac
        .authenticate(
            &aa,
            WorkingKey::standing(aa.tbs().public_key()),
            path.interval(),
            &crypto,
            &work,
        )
        .unwrap()
    else {
        panic!()
    };
    let source_reader = hp.read(&[], 0).unwrap();
    let source = source_reader.execution();
    source.charge_work(source.work_remaining() as u64).unwrap();
    let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
    let result = direct(
        &facts,
        &aa,
        Context {
            holder: Holder::Object {
                binding: &binding,
                path: Some(&path),
            },
            recipient: &[],
            proxy: None,
            status: &NoStatus,
            now: path.interval().from_instant().into(),
            utc: &utc,
            execution: &work,
        },
        no_groups,
    );
    assert!(matches!(result,Err(UseError::Processing(error))if error.is_resource()));
}

#[test]
fn membership_errors_and_unknown_answers_never_mint_checked_use() {
    // Unknown is unproven; callback errors retain their exact original cause/range.
    let (chain, _) = fixture(Change::None);
    let hb = holder_bytes(b"Holder");
    let groups = ext(
        target::IDENTIFIER,
        &seq(&[&seq(&[&tlv(161, &tlv(130, b"group.test"))])]),
        true,
    );
    let ab = use_ac(&[no_rev(), groups]);
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &chain[0]);
    let root = read_pkc(&p, &chain[2]);
    let holder = read_pkc(&p, &hb);
    let ac = read_ac(&p, &ab);
    let w = generous();
    let crypto = Crypto::new();
    let refs = [&holder];
    let path = holder_path(&refs, &root, &crypto, &w);
    let super::Outcome::Authenticated(facts) = ac
        .authenticate(
            &aa,
            WorkingKey::standing(aa.tbs().public_key()),
            path.interval(),
            &crypto,
            &w,
        )
        .unwrap()
    else {
        panic!()
    };
    let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
    for error in [false, true] {
        let out = direct(
            &facts,
            &aa,
            Context {
                holder: Holder::Certificate {
                    path: &path,
                    method: HolderMethod::EntityName,
                },
                recipient: &[],
                proxy: None,
                status: &NoStatus,
                now: path.interval().from_instant().into(),
                utc: &utc,
                execution: &w,
            },
            |role, _, work| {
                assert_eq!(role, GroupRole::Target);
                work.charge_work(1).unwrap();
                if error {
                    Err(731u32)
                } else {
                    Ok(target::Membership::Unknown)
                }
            },
        );
        if error {
            assert!(
                matches!(out,Err(UseError::Membership(target::CheckError::Callback{source:731,target}))if target.length>0)
            );
        } else {
            assert!(matches!(
                out.unwrap(),
                Outcome::Rejected(Failure::Target(target::Decision::Unproven))
            ));
        }
    }
}
fn no_rev() -> Vec<u8> {
    ext(validation::NO_REV_AVAILABLE, &[5, 0], false)
}

fn ocsp_bytes(nonce: Option<&[u8]>) -> Vec<u8> {
    use sha2::Digest as _;
    let key = SigningKey::from_bytes(&[1; 32]);
    let id = seq(&[
        &seq(&[&tlv(6, oid::SHA256.as_bytes())]),
        &tlv(4, &sha2::Sha256::digest(name(b"Authority"))),
        &tlv(4, &sha2::Sha256::digest(key.verifying_key().to_bytes())),
        &[2, 1, 5],
    ]);
    let time = tlv(24, b"20261021000000Z");
    let single = seq(&[
        &id,
        &[128, 0],
        &time,
        &tlv(160, &tlv(24, b"20261022000000Z")),
    ]);
    let extensions = nonce
        .map(|value| tlv(161, &seq(&[&ext(oid::OCSP_NONCE, &tlv(4, value), false)])))
        .unwrap_or_default();
    let info = seq(&[
        &tlv(161, &name(b"Authority")),
        &time,
        &seq(&[&single]),
        &extensions,
    ]);
    signed(&info, &key)
}

fn status_authority<'r, 'a>(
    response: &'r structured_pkix::ocsp::BasicResponse<'a>,
    aa: &'r Certificate<'a>,
    crypto: &Crypto,
    work: &Memory,
) -> structured_pkix::ocsp::ScopedResponse<'r, 'a> {
    use structured_pkix::ocsp;
    let key = WorkingKey::standing(aa.tbs().public_key());
    let ocsp::SignatureAuthentication::Signed(signed) = response
        .authenticate_signature(aa, key, crypto, crypto, work)
        .unwrap()
    else {
        panic!()
    };
    let ocsp::AuthorityBinding::Bound(scoped) = signed.bind_issuer(aa, key, work).unwrap() else {
        panic!()
    };
    scoped
}

#[test]
fn full_use_consumes_actual_ocsp_binding_without_rehash_and_refuses_bad_nonce() {
    // Real response/AC/path signatures are verified once; the final composition
    // retains the exact target/time receipt and actual sent nonce relationship.
    use structured_pkix::ocsp;
    let (chain, _) = fixture(Change::None);
    let hb = holder_bytes(b"Holder");
    let ab = use_ac(&[]);
    let rb = ocsp_bytes(Some(&[9; 32]));
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &chain[0]);
    let root = read_pkc(&p, &chain[2]);
    let holder = read_pkc(&p, &hb);
    let ac = read_ac(&p, &ab);
    let work = generous();
    let crypto = Crypto::new();
    let mut reader = p.read(&rb, 3000).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let response = ocsp::BasicResponse::read_element(&reader, &element).unwrap();
    let now = response.responses()[0].this_update().instant();
    let mut ctx = context(&work, &crypto, &());
    ctx.interval = Interval::at_instant(now);
    let anchor = Anchor::from_certificate(&root);
    let anchor = EffectiveAnchor::bind(anchor, WorkingKey::standing(anchor.key()), &work)
        .unwrap()
        .unwrap();
    let refs = [&holder];
    let HolderValidation::Accepted(path) = HolderPath::validate(&refs, anchor, &ctx).unwrap()
    else {
        panic!()
    };
    let super::Outcome::Authenticated(facts) = ac
        .authenticate(
            &aa,
            WorkingKey::standing(aa.tbs().public_key()),
            ctx.interval,
            &crypto,
            &work,
        )
        .unwrap()
    else {
        panic!()
    };
    let scoped = status_authority(&response, &aa, &crypto, &work);
    let utc = LeapTable::new(now.seconds() - 100_000, now.seconds() + 200_000, &[]).unwrap();
    for nonce in [[9; 32], [8; 32]] {
        let request = ocsp::Request {
            target: facts.profile(),
            nonce: Some(ocsp::RequestNonce::from_sent(&nonce).unwrap()),
            intended_signer: Some(&aa),
        };
        let time = ocsp::Evaluation {
            now: now.into(),
            utc: &utc,
            execution: &work,
        };
        let reading = scoped
            .evaluate_with_target(&request, &time, &crypto)
            .unwrap();
        let evidence = reading.evidence().unwrap();
        let calls = crypto.calls.get();
        let used = work.used();
        let result = direct(
            &facts,
            &aa,
            Context {
                holder: Holder::Certificate {
                    path: &path,
                    method: HolderMethod::EntityName,
                },
                recipient: &[],
                proxy: None,
                status: &evidence,
                now: time.now,
                utc: &utc,
                execution: &work,
            },
            no_groups,
        )
        .unwrap();
        assert_eq!(crypto.calls.get(), calls);
        if nonce[0] == 9 {
            let checked = accepted_use(result);
            assert_eq!(checked.status().evaluated_at(), time.now);
            drop(checked);
        } else {
            assert!(matches!(
                result,
                Outcome::Rejected(Failure::Status(Status::Nonce(ocsp::NonceBinding::Differs)))
            ));
        }
        assert_eq!(work.used(), used);
    }
}
fn targets(names: &[&[u8]], kind: Oid<'_>) -> Vec<u8> {
    ext(
        kind,
        &seq(&[&seq(&names
            .iter()
            .map(|name| tlv(160, &tlv(130, name)))
            .collect::<Vec<_>>()
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>())]),
        true,
    )
}
fn no_groups(
    _: GroupRole,
    _: &GeneralName<'_>,
    work: &Execution<'_>,
) -> Result<target::Membership, u32> {
    work.charge_work(1).map_err(|_| 731u32)?;
    Ok(target::Membership::NotMember)
}
fn accepted_use<T: core::fmt::Debug>(answer: Outcome<T>) -> T {
    match answer {
        Outcome::Checked(value) => value,
        other @ Outcome::Rejected(_) => panic!("{other:?}"),
    }
}

#[test]
fn direct_trust_and_holder_path_produce_original_complete_use_facts() {
    // Actual signed issuance, holder PKIX path and exact trust; no signature is repeated by use.
    let (chain, _) = fixture(Change::Exclude(0));
    let holder_bytes = holder_bytes(b"Holder");
    let ac_bytes = use_ac(&[no_rev()]);
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &chain[0]);
    let root = read_pkc(&p, &chain[2]);
    let holder = read_pkc(&p, &holder_bytes);
    let ac = read_ac(&p, &ac_bytes);
    let crypto = Crypto::new();
    let work = generous();
    let references = [&holder];
    let path = holder_path(&references, &root, &crypto, &work);
    assert_eq!(path.certificates().len(), 1);
    assert_eq!(
        path.facts().key.key().as_bytes(),
        holder.tbs().public_key().as_bytes()
    );
    assert!(core::ptr::eq(
        path.anchor().anchor().certificate().unwrap(),
        &raw const root
    ));
    let super::Outcome::Authenticated(facts) = ac
        .authenticate(
            &aa,
            WorkingKey::standing(aa.tbs().public_key()),
            path.interval(),
            &crypto,
            &work,
        )
        .unwrap()
    else {
        panic!("issuance")
    };
    assert_eq!(crypto.calls.get(), 2);
    let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
    let now = Reading::from(path.interval().from_instant());
    let checked = accepted_use(
        direct(
            &facts,
            &aa,
            Context {
                holder: Holder::Certificate {
                    path: &path,
                    method: HolderMethod::EntityName,
                },
                recipient: &[],
                proxy: None,
                status: &NoStatus,
                now,
                utc: &utc,
                execution: &work,
            },
            no_groups,
        )
        .unwrap(),
    );
    assert_eq!(crypto.calls.get(), 2);
    assert_eq!(checked.evaluated_at(), now);
    assert_eq!(checked.target(), None);
    assert_eq!(checked.proxy(), None);
    assert!(matches!(
        checked.attributes()[0].permission,
        Permission::Excluded { certificate: 0, .. }
    ));
    assert_eq!(
        checked.attributes()[1],
        AttributeUse {
            index: 1,
            permission: Permission::Permitted
        }
    );
    assert!(
        matches!(checked.authority(), Authority::Direct(actual) if core::ptr::eq(*actual, &raw const facts))
    );
    assert!(
        matches!(checked.holder(), Holder::Certificate { path: actual, .. } if core::ptr::eq(*actual, &raw const path))
    );
    assert!(core::ptr::eq(checked.status(), &NoStatus));
    let held = work.used();
    assert!(held > 0);
    drop(checked);
    assert!(work.used() < held);
}

#[test]
fn use_refuses_wrong_direct_trust_holder_time_and_missing_status() {
    // Completed adverse requirements cannot be replaced by successful signature math.
    for case in 0..6 {
        let (chain, _) = fixture(Change::None);
        let hb = holder_bytes(if case == 1 { b"Other" } else { b"Holder" });
        let ab = use_ac(&if case == 3 { vec![] } else { vec![no_rev()] });
        let p = Parser::der(generous());
        let aa = read_pkc(&p, &chain[0]);
        let root = read_pkc(&p, &chain[2]);
        let other_aa = read_pkc(&p, &chain[0]);
        let holder = read_pkc(&p, &hb);
        let ac = read_ac(&p, &ab);
        let work = generous();
        let crypto = Crypto::new();
        let refs = [&holder];
        let path = holder_path(&refs, &root, &crypto, &work);
        let super::Outcome::Authenticated(facts) = ac
            .authenticate(
                &aa,
                WorkingKey::standing(aa.tbs().public_key()),
                Interval::between(1_789_000_000, 1_791_000_000),
                &crypto,
                &work,
            )
            .unwrap()
        else {
            panic!()
        };
        let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
        let now = if case == 2 {
            Interval::at(1_792_000_000)
        } else if case == 4 {
            Interval::at(1_790_000_001)
        } else {
            path.interval()
        }
        .from_instant()
        .into();
        let result = direct(
            &facts,
            if case == 0 { &other_aa } else { &aa },
            Context {
                holder: Holder::Certificate {
                    path: &path,
                    method: if case == 5 {
                        HolderMethod::BaseCertificate
                    } else {
                        HolderMethod::EntityName
                    },
                },
                recipient: &[],
                proxy: None,
                status: &NoStatus,
                now,
                utc: &utc,
                execution: &work,
            },
            no_groups,
        )
        .unwrap();
        assert!(match result {
            Outcome::Rejected(Failure::AuthorityTrust) => case == 0,
            Outcome::Rejected(Failure::Holder(_)) => case == 1 || case == 5,
            Outcome::Rejected(Failure::Interval) => case == 2 || case == 4,
            Outcome::Rejected(Failure::Status(Status::Missing)) => case == 3,
            other => panic!("case {case}: {other:?}"),
        });
    }
}

#[test]
fn target_and_proxy_constraints_run_for_every_required_protocol_participant() {
    // Recipient targeting uses union; proxying requires the same set for all participants.
    for case in 0..5 {
        let (chain, _) = fixture(Change::None);
        let hb = holder_bytes(b"Holder");
        let ab = use_ac(&[
            no_rev(),
            targets(&[b"recipient.test"], target::IDENTIFIER),
            targets(
                &[b"recipient.test", b"proxy.test", b"previous.test"],
                proxy::IDENTIFIER,
            ),
        ]);
        let p = Parser::der(generous());
        let aa = read_pkc(&p, &chain[0]);
        let root = read_pkc(&p, &chain[2]);
        let holder = read_pkc(&p, &hb);
        let ac = read_ac(&p, &ab);
        let w = generous();
        let crypto = Crypto::new();
        let refs = [&holder];
        let path = holder_path(&refs, &root, &crypto, &w);
        let super::Outcome::Authenticated(facts) = ac
            .authenticate(
                &aa,
                WorkingKey::standing(aa.tbs().public_key()),
                path.interval(),
                &crypto,
                &w,
            )
            .unwrap()
        else {
            panic!()
        };
        let recipient = [GeneralName::Dns(if case == 1 {
            "other.test"
        } else {
            "recipient.test"
        })];
        let sender = [GeneralName::Dns(if case == 3 {
            "other.test"
        } else {
            "proxy.test"
        })];
        let prior = [GeneralName::Dns(if case == 4 {
            "other.test"
        } else {
            "previous.test"
        })];
        let hops = [prior.as_slice()];
        let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
        let out = direct(
            &facts,
            &aa,
            Context {
                holder: Holder::Certificate {
                    path: &path,
                    method: HolderMethod::EntityName,
                },
                recipient: &recipient,
                proxy: if case == 2 {
                    None
                } else {
                    Some(Proxy {
                        sender: proxy::Sender::Proxy(&sender),
                        intermediates: &hops,
                    })
                },
                status: &NoStatus,
                now: path.interval().from_instant().into(),
                utc: &utc,
                execution: &w,
            },
            no_groups,
        )
        .unwrap();
        match out {
            Outcome::Checked(checked) => {
                assert_eq!(case, 0);
                assert_eq!(checked.target(), Some(0));
                assert_eq!(checked.proxy(), Some(0));
            }
            Outcome::Rejected(Failure::Target(target::Decision::Differs)) => assert_eq!(case, 1),
            Outcome::Rejected(Failure::ProxyContext) => assert_eq!(case, 2),
            Outcome::Rejected(Failure::Proxy(proxy::Decision::Differs)) => {
                assert!(case == 3 || case == 4);
            }
            other @ Outcome::Rejected(_) => panic!("case {case}: {other:?}"),
        }
    }
}

#[test]
fn authenticated_aa_path_intersects_all_original_attribute_types_without_reverification() {
    // Excluded first attribute remains inspectable; an unrelated second attribute survives.
    let (chain, _) = fixture(Change::Exclude(1));
    let hb = holder_bytes(b"Holder");
    let ab = use_ac(&[no_rev()]);
    let p = Parser::der(generous());
    let certs = chain.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let holder = read_pkc(&p, &hb);
    let ac = read_ac(&p, &ab);
    let q = generous();
    let crypto = Crypto::new();
    let aa_path =
        super::accepted(aa_path::validate(&refs, &certs[2], &context(&q, &crypto, &())).unwrap());
    let super::Outcome::Authenticated(facts) = aa_path.authenticate(&ac, &crypto, &q).unwrap()
    else {
        panic!()
    };
    let holder_refs = [&holder];
    let path = holder_path(&holder_refs, &certs[2], &crypto, &q);
    let calls = crypto.calls.get();
    let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
    let operation = generous();
    let reader_parser = Parser::der(operation.clone());
    let reader = reader_parser.read(&[], 5000).unwrap();
    let work = reader.execution();
    let checked = accepted_use(
        issued(
            &facts,
            Context {
                holder: Holder::Certificate {
                    path: &path,
                    method: HolderMethod::EntityName,
                },
                recipient: &[],
                proxy: None,
                status: &NoStatus,
                now: path.interval().from_instant().into(),
                utc: &utc,
                execution: &work,
            },
            no_groups,
        )
        .unwrap(),
    );
    assert_eq!(crypto.calls.get(), calls);
    assert_eq!(checked.attributes().len(), 2);
    assert!(matches!(
        checked.attributes()[0].permission,
        Permission::Excluded { certificate: 1, .. }
    ));
    assert_eq!(checked.attributes()[1].permission, Permission::Permitted);
    assert_eq!(
        checked.allows(Oid::from_bytes(&[43]), &work).unwrap(),
        Permission::Permitted
    );
    drop(reader);
    drop(reader_parser);
    assert!(operation.used() > 0);
    assert_eq!(checked.attributes().len(), 2);
    drop(checked);
    assert_eq!(operation.used(), 0);
}

#[test]
fn zero_work_and_capacity_cannot_return_successful_partial_catalogues() {
    // Complete use refuses before callbacks/copies; result storage rolls back on failure.
    let (chain, _) = fixture(Change::None);
    let hb = holder_bytes(b"Holder");
    let ab = use_ac(&[no_rev()]);
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &chain[0]);
    let root = read_pkc(&p, &chain[2]);
    let holder = read_pkc(&p, &hb);
    let ac = read_ac(&p, &ab);
    let q = generous();
    let c = Crypto::new();
    let refs = [&holder];
    let path = holder_path(&refs, &root, &c, &q);
    let super::Outcome::Authenticated(facts) = ac
        .authenticate(
            &aa,
            WorkingKey::standing(aa.tbs().public_key()),
            path.interval(),
            &c,
            &q,
        )
        .unwrap()
    else {
        panic!()
    };
    let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
    for w in [memory(1 << 20, 0), memory(0, 1 << 20)] {
        let result = direct(
            &facts,
            &aa,
            Context {
                holder: Holder::Certificate {
                    path: &path,
                    method: HolderMethod::EntityName,
                },
                recipient: &[],
                proxy: None,
                status: &NoStatus,
                now: path.interval().from_instant().into(),
                utc: &utc,
                execution: &w,
            },
            no_groups,
        );
        assert!(matches!(result,Err(UseError::Processing(e))if e.is_resource()));
        assert_eq!(w.used(), 0);
    }
}

#[test]
fn exact_current_work_succeeds_and_one_unit_less_rolls_back() {
    // An execution's already-admitted work is neither refunded nor reused as
    // credit by a later operation; the complete cost has an exact boundary.
    let (chain, _) = fixture(Change::None);
    let hb = holder_bytes(b"Holder");
    let ab = use_ac(&[no_rev()]);
    let p = Parser::der(generous());
    let aa = read_pkc(&p, &chain[0]);
    let root = read_pkc(&p, &chain[2]);
    let holder = read_pkc(&p, &hb);
    let ac = read_ac(&p, &ab);
    let crypto = Crypto::new();
    let setup = generous();
    let refs = [&holder];
    let path = holder_path(&refs, &root, &crypto, &setup);
    let super::Outcome::Authenticated(facts) = ac
        .authenticate(
            &aa,
            WorkingKey::standing(aa.tbs().public_key()),
            path.interval(),
            &crypto,
            &setup,
        )
        .unwrap()
    else {
        panic!()
    };
    let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
    let run = |work: &Memory| {
        direct(
            &facts,
            &aa,
            Context {
                holder: Holder::Certificate {
                    path: &path,
                    method: HolderMethod::EntityName,
                },
                recipient: &[],
                proxy: None,
                status: &NoStatus,
                now: path.interval().from_instant().into(),
                utc: &utc,
                execution: work,
            },
            no_groups,
        )
    };
    let measure = generous();
    drop(accepted_use(run(&measure).unwrap()));
    let cost = measure.work_used();
    assert!(cost > 0);
    assert_eq!(measure.used(), 0);
    let exact = memory(1 << 20, cost);
    drop(accepted_use(run(&exact).unwrap()));
    assert_eq!(exact.work_used(), cost);
    assert_eq!(exact.used(), 0);
    let short = memory(1 << 20, cost - 1);
    let error = run(&short).unwrap_err();
    assert!(matches!(error,UseError::Processing(error)if error.is_resource()));
    assert_eq!(short.used(), 0);
}
