//! Native signed AA chains, complete constraints and original/caller resource boundaries.
#[path = "usage.rs"]
mod usage;
use super::{
    attrs, control, entity, ext, issuer, memory, name, read_ac, read_pkc, seq, tlv, validity,
};
use core::cell::Cell;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{Memory, MemoryError, Work};
use structured_asn1::{Limits, Oid, Parser};
use structured_cms::attribute_certificate::validation::Reason;
use structured_cms::attribute_certificate::validation::aa_path::{
    self, PathCheck, PathError, Permission, ValidatedPath,
};
use structured_cms::attribute_certificate::validation::authentication::{
    AlgorithmAgreement, AuthenticationError, Failure, Outcome,
};
use structured_pkix::extension::Recognizer;
use structured_pkix::path::{self, Interval, ValidationContext, Verified, Verify, WorkingKey};
use structured_pkix::signature::SignatureValue;
use structured_pkix::{AlgorithmIdentifier, oid};

fn generous() -> Memory {
    memory(1 << 22, 1 << 30)
}
fn ed() -> Vec<u8> {
    seq(&[&tlv(6, oid::ED25519.as_bytes())])
}
fn signed(info: &[u8], key: &SigningKey) -> Vec<u8> {
    seq(&[
        info,
        &ed(),
        &tlv(3, &[&[0][..], &key.sign(info).to_bytes()].concat()),
    ])
}
fn certificate(
    subject: &[u8],
    issuer: &[u8],
    number: u8,
    key: &SigningKey,
    parent: &SigningKey,
    ca: bool,
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let mut extensions = extensions.to_vec();
    if ca {
        extensions.push(ext(oid::BASIC_CONSTRAINTS, &[48, 3, 1, 1, 255], true));
        extensions.push(ext(oid::KEY_USAGE, &[3, 2, 2, 4], true));
    } else {
        extensions.push(ext(oid::KEY_USAGE, &[3, 2, 7, 128], true));
    }
    let key = seq(&[
        &ed(),
        &tlv(3, &[&[0][..], &key.verifying_key().to_bytes()].concat()),
    ]);
    let info = seq(&[
        &[160, 3, 2, 1, 2],
        &[2, 1, number],
        &ed(),
        &name(issuer),
        &validity(),
        &name(subject),
        &key,
        &tlv(
            163,
            &seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>()),
        ),
    ]);
    signed(&info, parent)
}
fn ac(key: &SigningKey, authority: &[u8]) -> Vec<u8> {
    let info = seq(&[
        &[2, 1, 1],
        &entity(130, b"holder.test"),
        &issuer(authority),
        &ed(),
        &[2, 1, 5],
        &validity(),
        &attrs(),
        &seq(&[&ext(
            oid::AUTHORITY_KEY_IDENTIFIER,
            &[48, 3, 128, 1, 1],
            false,
        )]),
    ]);
    signed(&info, key)
}
fn critical(mut value: Vec<u8>) -> Vec<u8> {
    // Helpers emit noncritical extension SEQUENCE; build the same control with TRUE.
    let p = Parser::der(generous());
    let mut r = p.read(&value, 0).unwrap();
    let e = r.next_element().unwrap().unwrap();
    let mut r = r.enter(&e).unwrap();
    let oid = r.next_element().unwrap().unwrap();
    let data = r.next_element().unwrap().unwrap();
    let out = seq(&[oid.as_bytes(), &[1, 1, 255], data.as_bytes()]);
    value.clear();
    out
}
#[derive(Clone, Copy)]
enum Change {
    None,
    Missing(usize),
    Malformed(usize),
    Exclude(usize),
    Distance,
    NonCa,
    WrongIssuer,
    BadSignature,
    Unknown,
    Expired,
}
fn fixture(change: Change) -> (Vec<Vec<u8>>, Vec<u8>) {
    let keys = [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    ];
    let mut controls: [Vec<Vec<u8>>; 3] =
        core::array::from_fn(|_| vec![critical(control(None, &[], &[], true))]);
    match change {
        Change::Missing(i) => controls[i].clear(),
        Change::Malformed(i) => {
            controls[i] = vec![ext(
                structured_cms::attribute_certificate::controls::IDENTIFIER,
                &[5, 0],
                true,
            )];
        }
        Change::Exclude(i) => controls[i] = vec![critical(control(None, &[], &[42], true))],
        Change::Distance => controls[2] = vec![control(Some(0), &[], &[], true)],
        Change::Unknown => controls[0].push(ext(Oid::from_bytes(&[42, 3]), &[5, 0], true)),
        _ => {}
    }
    let aa = certificate(
        b"Authority",
        if matches!(change, Change::WrongIssuer) {
            b"Wrong"
        } else {
            b"Intermediate"
        },
        1,
        &keys[0],
        if matches!(change, Change::BadSignature) {
            &keys[2]
        } else {
            &keys[1]
        },
        false,
        &controls[0],
    );
    let mut mid = certificate(
        b"Intermediate",
        b"Root",
        2,
        &keys[1],
        &keys[2],
        !matches!(change, Change::NonCa),
        &controls[1],
    );
    if matches!(change, Change::Expired) {
        // Change an original validity digit; signature validity is independently checked later.
        let at = mid.windows(4).position(|s| s == b"2027").unwrap();
        mid[at + 3] = b'5';
    }
    let root = certificate(b"Root", b"Root", 3, &keys[2], &keys[2], true, &controls[2]);
    (vec![aa, mid, root], ac(&keys[0], b"Authority"))
}
#[derive(Debug)]
enum Cause {
    Resource(MemoryError),
    Pkix(structured_pkix::Error),
    Marker,
}
impl core::fmt::Display for Cause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Resource(e) => write!(f, "{e}"),
            Self::Pkix(e) => write!(f, "{e}"),
            Self::Marker => f.write_str("provider marker"),
        }
    }
}
impl From<MemoryError> for Cause {
    fn from(e: MemoryError) -> Self {
        Self::Resource(e)
    }
}
impl From<structured_pkix::Error> for Cause {
    fn from(e: structured_pkix::Error) -> Self {
        Self::Pkix(e)
    }
}
struct Crypto {
    calls: Cell<usize>,
    fail: Cell<bool>,
    unsupported: Cell<bool>,
}
impl Crypto {
    fn new() -> Self {
        Self {
            calls: Cell::new(0),
            fail: Cell::new(false),
            unsupported: Cell::new(false),
        }
    }
}
impl<W: Work> Verify<W> for Crypto {
    type Error = Cause;
    fn verify(
        &self,
        algorithm: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        bytes: &[u8],
        signature: SignatureValue<'_>,
        work: &W,
    ) -> Result<Verified, Cause> {
        self.calls.set(self.calls.get() + 1);
        if self.fail.get() {
            return Err(Cause::Marker);
        }
        if self.unsupported.get() {
            return Ok(Verified::Unsupported);
        }
        work.charge_work(bytes.len() as u64 + 128)?;
        assert_eq!(algorithm.algorithm(), oid::ED25519);
        let raw = structured_pkix::key::rfc8410::read(key.key(), work)?;
        let key = VerifyingKey::from_bytes(raw.as_bytes().try_into().unwrap()).unwrap();
        let sig = Signature::from_slice(signature.octets().unwrap()).unwrap();
        Ok(if key.verify_strict(bytes, &sig).is_ok() {
            Verified::Yes
        } else {
            Verified::No
        })
    }
}
impl AlgorithmAgreement for Crypto {
    type Error = Cause;
    fn algorithms<W: Work>(
        &self,
        a: AlgorithmIdentifier<'_>,
        b: AlgorithmIdentifier<'_>,
        work: &W,
    ) -> Result<Resolution<bool>, Cause> {
        work.charge_work(32)?;
        Ok(Resolution::Supported(
            a.algorithm() == b.algorithm()
                && a.algorithm() == oid::ED25519
                && a.parameters().is_none()
                && b.parameters().is_none(),
        ))
    }
}
fn context<'a, 'p, R: Recognizer<Memory>>(
    work: &'p Memory,
    verifier: &'p Crypto,
    recognizer: &'p R,
) -> ValidationContext<'a, 'p, Crypto, (), R> {
    ValidationContext {
        execution: work,
        interval: Interval::at(1_790_000_000),
        policy: path::Policy::default(),
        bounds: path::ValidationBounds::default(),
        verifier,
        watch: &(),
        recognizer,
    }
}
fn accepted<'p, 'a>(
    answer: PathCheck<ValidatedPath<'p, 'a>, path::Rejection<'a>>,
) -> ValidatedPath<'p, 'a> {
    match answer {
        PathCheck::Accepted(p) => p,
        other => panic!("{other:?}"),
    }
}
#[test]
fn native_chain_and_ac_share_actual_key_interval_and_complete_constraints() {
    // Root is explicit trust input, not a third path signature; AC verification happens once.
    for deny in [None, Some(0), Some(1), Some(2)] {
        let (bytes, ac_bytes) = fixture(deny.map_or(Change::None, Change::Exclude));
        let p = Parser::der(generous());
        let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
        let refs = certs.iter().collect::<Vec<_>>();
        let cert = read_ac(&p, &ac_bytes);
        let crypto = Crypto::new();
        let query = generous();
        let path =
            accepted(aa_path::validate(&refs, &certs[2], &context(&query, &crypto, &())).unwrap());
        assert_eq!(crypto.calls.get(), 2);
        assert_eq!(path.certificates().len(), 3);
        assert!(core::ptr::eq(
            path.anchor().anchor().certificate().unwrap(),
            &raw const certs[2]
        ));
        assert_eq!(
            path.facts().key.key().as_bytes(),
            certs[0].tbs().public_key().as_bytes()
        );
        let Outcome::Authenticated(issued) = path.authenticate(&cert, &crypto, &query).unwrap()
        else {
            panic!("AC refused")
        };
        assert_eq!(crypto.calls.get(), 3);
        assert_eq!(issued.facts().interval(), path.interval());
        assert!(core::ptr::eq(issued.facts().certificate(), &raw const cert));
        let result = issued.allows(Oid::from_bytes(&[42]), &query).unwrap();
        if let Some(position) = deny {
            assert!(matches!(result,Permission::Excluded{certificate,..} if certificate==position));
        } else {
            assert_eq!(result, Permission::Permitted);
        }
        // A different/decrypted type is not discarded with an excluded cleartext one.
        assert_eq!(
            issued.allows(Oid::from_bytes(&[43]), &query).unwrap(),
            Permission::Permitted
        );
        assert_eq!(cert.information().attributes.len(), 1);
    }
}
#[test]
fn controls_census_finishes_before_any_signature_callback() {
    // Missing, malformed or too-distant controls never produce a path prefix/key.
    for change in [
        Change::Missing(0),
        Change::Missing(1),
        Change::Malformed(0),
        Change::Malformed(1),
        Change::Malformed(2),
        Change::Distance,
    ] {
        let (bytes, _) = fixture(change);
        let p = Parser::der(generous());
        let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
        let refs = certs.iter().collect::<Vec<_>>();
        let q = generous();
        let v = Crypto::new();
        let result = aa_path::validate(&refs, &certs[2], &context(&q, &v, &()));
        match change {
            Change::Missing(_) => assert!(
                matches!(result,Ok(PathCheck::Controls(r)) if r.reason==Reason::MissingControls)
            ),
            Change::Distance => assert!(
                matches!(result,Ok(PathCheck::Controls(r)) if r.reason==Reason::ControlDistance)
            ),
            _ => assert!(matches!(result, Err(PathError::Processing(_)))),
        }
        assert_eq!(v.calls.get(), 0);
        assert_eq!(q.used(), 0);
    }
}
#[test]
fn optional_anchor_control_and_explicit_boundary_are_not_inferred_from_pool() {
    // Only the caller-selected terminal position is optional; one issuer is direct trust, not an AA-CA path.
    let (bytes, _) = fixture(Change::Missing(2));
    let p = Parser::der(generous());
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let q = generous();
    let v = Crypto::new();
    let c = context(&q, &v, &());
    assert!(matches!(
        aa_path::validate(&[], &certs[2], &c).unwrap(),
        PathCheck::MissingAaCa
    ));
    assert!(matches!(
        aa_path::validate(&refs[..1], &certs[2], &c).unwrap(),
        PathCheck::MissingAaCa
    ));
    assert_eq!(v.calls.get(), 0);
    assert!(matches!(
        aa_path::validate(&refs, &certs[1], &c).unwrap(),
        PathCheck::TrustBoundary
    ));
    assert_eq!(v.calls.get(), 0);
    let _path = accepted(aa_path::validate(&refs, &certs[2], &c).unwrap());
    assert_eq!(v.calls.get(), 2);
}
#[test]
fn common_pkix_refusals_remain_typed_and_located() {
    // AAControls recognition must not bypass CA/KU, issuer, validity, signatures or critical demands.
    for (change, reason) in [
        (Change::NonCa, path::RejectionReason::NotAuthority),
        (Change::WrongIssuer, path::RejectionReason::Issuer),
        (Change::BadSignature, path::RejectionReason::Signature),
        (
            Change::Unknown,
            path::RejectionReason::CriticalExtension(Oid::from_bytes(&[42, 3])),
        ),
        (Change::Expired, path::RejectionReason::Validity),
    ] {
        let (bytes, _) = fixture(change);
        let p = Parser::der(generous());
        let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
        let refs = certs.iter().collect::<Vec<_>>();
        let q = generous();
        let v = Crypto::new();
        let result = aa_path::validate(&refs, &certs[2], &context(&q, &v, &())).unwrap();
        assert!(
            matches!(result,PathCheck::Path(ref r) if r.reason==reason),
            "{result:?}"
        );
        assert_eq!(q.used(), 0);
    }
}
#[test]
fn path_bounds_policy_and_provider_errors_cannot_return_usable_key() {
    // Local incomplete and callback failure are different from semantic rejection; all release storage.
    let (bytes, _) = fixture(Change::None);
    let p = Parser::der(generous());
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let q = generous();
    let v = Crypto::new();
    let mut c = context(&q, &v, &());
    c.bounds.depth = 1;
    assert!(matches!(
        aa_path::validate(&refs, &certs[2], &c).unwrap(),
        PathCheck::Incomplete(path::Truncation::Depth)
    ));
    assert_eq!(v.calls.get(), 0);
    c.bounds.depth = 8;
    c.bounds.work = 0;
    assert!(matches!(
        aa_path::validate(&refs, &certs[2], &c).unwrap(),
        PathCheck::Incomplete(path::Truncation::Work)
    ));
    c.bounds = path::ValidationBounds::default();
    c.policy.explicit = true;
    assert!(
        matches!(aa_path::validate(&refs,&certs[2],&c).unwrap(),PathCheck::Path(rejection) if rejection.reason==path::RejectionReason::Policies)
    );
    c.policy.explicit = false;
    v.fail.set(true);
    assert!(matches!(
        aa_path::validate(&refs, &certs[2], &c),
        Err(PathError::Verification(Cause::Marker))
    ));
    v.fail.set(false);
    v.unsupported.set(true);
    assert!(
        matches!(aa_path::validate(&refs,&certs[2],&c).unwrap(),PathCheck::Path(rejection) if rejection.reason==path::RejectionReason::UnsupportedSignature)
    );
    assert_eq!(q.used(), 0);
}
struct Recognition {
    fail: bool,
    calls: Cell<usize>,
}
impl Recognizer for Recognition {
    type Error = &'static str;
    fn recognizes(&self, kind: Oid<'_>, work: &Memory) -> Result<bool, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        work.charge_work(1).map_err(|_| "work")?;
        if self.fail {
            Err("original recognition cause")
        } else {
            Ok(kind == Oid::from_bytes(&[42, 3]))
        }
    }
}
#[test]
fn additional_critical_recognizer_is_forwarded_without_erasing_original_cause() {
    // The narrow control adapter recognizes only AAControls and preserves other scheme callbacks.
    let (bytes, _) = fixture(Change::Unknown);
    let p = Parser::der(generous());
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    for fail in [true, false] {
        let q = generous();
        let v = Crypto::new();
        let r = Recognition {
            fail,
            calls: Cell::new(0),
        };
        let result = aa_path::validate(&refs, &certs[2], &context(&q, &v, &r));
        if fail {
            assert!(matches!(
                result,
                Err(PathError::Recognition("original recognition cause"))
            ));
        } else {
            let _ = accepted(result.unwrap());
        }
        assert_eq!(r.calls.get(), 1);
        assert_eq!(q.used(), 0);
    }
}
#[test]
fn ac_failure_and_mismatched_anchor_key_do_not_inherit_path_success() {
    // A checked path is bound to its AA; it cannot authenticate another issuer or repaired signature.
    let (bytes, _) = fixture(Change::None);
    let p = Parser::der(generous());
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let q = generous();
    let v = Crypto::new();
    let c = context(&q, &v, &());
    assert!(matches!(
        aa_path::validate_with_key(
            &refs,
            &certs[2],
            WorkingKey::standing(certs[0].tbs().public_key()),
            &c
        )
        .unwrap(),
        PathCheck::AnchorKey
    ));
    assert_eq!(v.calls.get(), 0);
    let path = accepted(aa_path::validate(&refs, &certs[2], &c).unwrap());
    for authority in [b"Wrong".as_slice(), b"Authority".as_slice()] {
        let data = ac(&SigningKey::from_bytes(&[99; 32]), authority);
        let ac = read_ac(&p, &data);
        let result = path.authenticate(&ac, &v, &q).unwrap();
        if authority == b"Wrong" {
            assert!(
                matches!(result,Outcome::Rejected(rejection) if matches!(rejection.reason,Failure::Authority(_)))
            );
        } else {
            assert!(
                matches!(result,Outcome::Rejected(rejection) if rejection.reason==Failure::Signature)
            );
        }
    }
    v.fail.set(true);
    let data = ac(&SigningKey::from_bytes(&[1; 32]), b"Authority");
    let ac = read_ac(&p, &data);
    assert!(matches!(
        path.authenticate(&ac, &v, &q),
        Err(AuthenticationError::Callback {
            source: Cause::Marker,
            ..
        })
    ));
}
#[test]
fn retained_path_preserves_storage_and_uses_new_operation_for_every_query() {
    // Query lifetime ends independently; later source/control work and all final drops remain accounted.
    let (bytes, data) = fixture(Change::Exclude(2));
    let p = Parser::der(generous());
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let ac = read_ac(&p, &data);
    let v = Crypto::new();
    let owner = generous();
    let path = {
        let c = context(&owner, &v, &());
        accepted(aa_path::validate(&refs, &certs[2], &c).unwrap())
    };
    assert!(owner.used() > 0);
    let fresh = generous();
    let Outcome::Authenticated(issued) = path.authenticate(&ac, &v, &fresh).unwrap() else {
        panic!("refused")
    };
    assert!(matches!(
        issued.allows(Oid::from_bytes(&[42]), &fresh).unwrap(),
        Permission::Excluded { certificate: 2, .. }
    ));
    let none = memory(1 << 20, 0);
    assert!(issued.allows(Oid::from_bytes(&[42]), &none).is_err());
    drop(issued);
    assert_eq!(fresh.used(), 0);
    drop(path);
    assert_eq!(owner.used(), 0);
}
#[test]
fn current_storage_and_work_refusal_release_every_partial_catalogue() {
    // Every refusal leaves zero retained capacity and cannot yield a successful prefix census.
    let (bytes, _) = fixture(Change::Exclude(2));
    let p = Parser::der(generous());
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    for (capacity, work) in [
        (0, 1 << 24),
        (64, 1 << 24),
        (1 << 20, 0),
        (1 << 20, 32),
        (1 << 20, 200),
    ] {
        let q = memory(capacity, work);
        let v = Crypto::new();
        assert!(matches!(
            aa_path::validate(&refs, &certs[2], &context(&q, &v, &())),
            Err(PathError::Processing(_))
        ));
        assert_eq!(q.used(), 0);
    }
}
#[test]
fn exhausted_original_certificate_cannot_be_replaced_by_fresh_query_account() {
    // Original source-local ceiling applies even while current account has ample resources.
    let (bytes, _) = fixture(Change::None);
    for exhausted in 0..3 {
        let accounts = [generous(), generous(), generous()];
        let parsers = accounts
            .iter()
            .map(|m| {
                Parser::new(
                    structured_asn1::Encoding::Der,
                    Limits {
                        max_work: 200_000,
                        ..Limits::default()
                    },
                    m.clone(),
                )
            })
            .collect::<Vec<_>>();
        let certs = bytes
            .iter()
            .zip(&parsers)
            .map(|(b, p)| read_pkc(p, b))
            .collect::<Vec<_>>();
        let refs = certs.iter().collect::<Vec<_>>();
        let p = &parsers[exhausted];
        let reader = p.read(&[], 9000).unwrap();
        let e = reader.execution();
        // Spend original local ceiling, retaining one unit for metadata shortcuts.
        let used = accounts[exhausted].work_used();
        e.charge_work(200_000 - used as u64 - 1).unwrap();
        let q = generous();
        let v = Crypto::new();
        assert!(matches!(
            aa_path::validate(&refs, &certs[2], &context(&q, &v, &())),
            Err(PathError::Processing(_))
        ));
        assert_eq!(q.used(), 0);
        assert_eq!(v.calls.get(), 0);
    }
}

#[test]
fn anchor_mismatch_cannot_hide_exhausted_original_supplied_key() {
    // Source refusal must precede a semantic mismatch, even when no later controls are read.
    let (bytes, _) = fixture(Change::None);
    let p = Parser::der(generous());
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let source = generous();
    let source_parser = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_work: 200_000,
            ..Limits::default()
        },
        source.clone(),
    );
    let foreign = read_pkc(&source_parser, &bytes[0]);
    let reader = source_parser.read(&[], 9000).unwrap();
    let execution = reader.execution();
    execution
        .charge_work(200_000 - source.work_used() as u64)
        .unwrap();
    let q = generous();
    let v = Crypto::new();
    let result = aa_path::validate_with_key(
        &refs,
        &certs[2],
        WorkingKey::standing(foreign.tbs().public_key()),
        &context(&q, &v, &()),
    );
    assert!(
        matches!(result, Err(PathError::Processing(_))),
        "{result:?}"
    );
    assert_eq!(v.calls.get(), 0);
    assert_eq!(q.used(), 0);
}

struct Inherited {
    calls: Cell<usize>,
    parameters: Cell<*const u8>,
}
impl<W: Work> Verify<W> for Inherited {
    type Error = Cause;
    fn verify(
        &self,
        _: &AlgorithmIdentifier<'_>,
        key: WorkingKey<'_>,
        _: &[u8],
        _: SignatureValue<'_>,
        work: &W,
    ) -> Result<Verified, Cause> {
        // Plumbing oracle only: group arithmetic is deliberately not asserted by this test.
        let decoded = structured_pkix::key::dsa::read(key, work)?;
        assert!(decoded.parameters().is_some());
        self.parameters.set(key.parameters().unwrap().as_ptr());
        self.calls.set(self.calls.get() + 1);
        Ok(Verified::Yes)
    }
}
impl AlgorithmAgreement for Inherited {
    type Error = Cause;
    fn algorithms<W: Work>(
        &self,
        a: AlgorithmIdentifier<'_>,
        b: AlgorithmIdentifier<'_>,
        work: &W,
    ) -> Result<Resolution<bool>, Cause> {
        work.charge_work(32)?;
        Ok(Resolution::Supported(a.algorithm() == b.algorithm()))
    }
}
fn dsa_certificate(subject: &[u8], issuer: &[u8], parameters: &[u8], ca: bool) -> Vec<u8> {
    let dsa = Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]);
    let algorithm = seq(&[&tlv(6, dsa.as_bytes()), parameters]);
    let spki = seq(&[&algorithm, &[3, 4, 0, 2, 1, 4]]);
    let mut extensions = vec![control(None, &[], &[], true)];
    if ca {
        extensions.push(ext(oid::BASIC_CONSTRAINTS, &[48, 3, 1, 1, 255], true));
    }
    let info = seq(&[
        &[160, 3, 2, 1, 2],
        &[2, 1, 7],
        &ed(),
        &name(issuer),
        &validity(),
        &name(subject),
        &spki,
        &tlv(
            163,
            &seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>()),
        ),
    ]);
    signed(&info, &SigningKey::from_bytes(&[1; 32]))
}
#[test]
fn inherited_anchor_parameters_survive_complete_path_and_ac_composition() {
    // The effective AA CA key may inherit from a distinct original source. No fabricated SPKI repairs it.
    let params = seq(&[&[2, 1, 23], &[2, 1, 11], &[2, 1, 2]]);
    let ancestor_bytes = dsa_certificate(b"Ancestor", b"Ancestor", &params, true);
    let root_bytes = dsa_certificate(b"Root", b"Ancestor", &[], true);
    let aa_bytes = dsa_certificate(b"Authority", b"Root", &[], false);
    let p = Parser::der(generous());
    let source = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_work: 200_000,
            ..Limits::default()
        },
        generous(),
    );
    let ancestor = read_pkc(&source, &ancestor_bytes);
    let root = read_pkc(&p, &root_bytes);
    let aa = read_pkc(&p, &aa_bytes);
    let q = generous();
    let effective = WorkingKey::standing(ancestor.tbs().public_key())
        .subject(&root, &q)
        .unwrap();
    let path_certificates = [&aa, &root];
    let v = Inherited {
        calls: Cell::new(0),
        parameters: Cell::new(core::ptr::null()),
    };
    let c = ValidationContext {
        execution: &q,
        interval: Interval::at(1_790_000_000),
        policy: path::Policy::default(),
        bounds: path::ValidationBounds::default(),
        verifier: &v,
        watch: &(),
        recognizer: &(),
    };
    let path =
        accepted(aa_path::validate_with_key(&path_certificates, &root, effective, &c).unwrap());
    let original = ancestor
        .tbs()
        .public_key()
        .algorithm()
        .parameters()
        .unwrap()
        .as_ptr();
    assert_eq!(path.facts().key.parameters().unwrap().as_ptr(), original);
    assert_eq!(path.anchor().key().parameters().unwrap().as_ptr(), original);
    assert_eq!(v.parameters.get(), original);
    assert_eq!(v.calls.get(), 1);
    let data = ac(&SigningKey::from_bytes(&[1; 32]), b"Authority");
    let cert = read_ac(&p, &data);
    let Outcome::Authenticated(issued) = path.authenticate(&cert, &v, &q).unwrap() else {
        panic!("plumbing refused")
    };
    assert_eq!(
        issued.facts().key().parameters().unwrap().as_ptr(),
        original
    );
    assert_eq!(v.calls.get(), 2);
    assert_eq!(v.parameters.get(), original);
    // The third source's local refusal still reaches the same retained key on later verification.
    let reader = source.read(&[], 9000).unwrap();
    let execution = reader.execution();
    execution
        .charge_work(execution.work_remaining() as u64)
        .unwrap();
    let fresh = generous();
    assert!(
        matches!(path.authenticate(&cert, &v, &fresh), Err(AuthenticationError::Callback {source:Cause::Pkix(error),..}) if error.is_resource())
    );
    assert_eq!(fresh.used(), 0);
}

struct Expensive;
impl<W: Work> Verify<W> for Expensive {
    type Error = MemoryError;
    fn verify(
        &self,
        _: &AlgorithmIdentifier<'_>,
        _: WorkingKey<'_>,
        _: &[u8],
        _: SignatureValue<'_>,
        work: &W,
    ) -> Result<Verified, MemoryError> {
        // A correctly accounted provider must see the producing certificate's ceiling too.
        work.charge_work(300_000)?;
        Ok(Verified::Yes)
    }
}
#[test]
fn path_signature_callback_cannot_escape_the_original_signed_source() {
    // The fresh operation has ample work; only the original certificate forbids this math cost.
    let (bytes, _) = fixture(Change::None);
    let p = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_work: 200_000,
            ..Limits::default()
        },
        generous(),
    );
    let certs = bytes.iter().map(|b| read_pkc(&p, b)).collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let query = generous();
    let c = ValidationContext {
        execution: &query,
        interval: Interval::at(1_790_000_000),
        policy: path::Policy::default(),
        bounds: path::ValidationBounds::default(),
        verifier: &Expensive,
        watch: &(),
        recognizer: &(),
    };
    let result = aa_path::validate(&refs, &certs[2], &c);
    assert!(
        matches!(
            result,
            Err(PathError::Verification(MemoryError::WorkExceeded))
        ),
        "{result:?}"
    );
    assert_eq!(query.used(), 0);
}

#[test]
fn issuer_mismatch_after_control_census_still_funds_original_names() {
    // A completed negative issuer comparison is work too: stopping before callbacks is insufficient.
    let (bytes, _) = fixture(Change::WrongIssuer);
    let bytes = [&bytes[0], &bytes[2]];
    let baseline = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_work: 200_000,
            ..Limits::default()
        },
        generous(),
    );
    let certs = bytes
        .iter()
        .map(|b| read_pkc(&baseline, b))
        .collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let query = generous();
    let _ = path::EffectiveAnchor::bind(
        path::Anchor::from_certificate(&certs[1]),
        WorkingKey::standing(certs[1].tbs().public_key()),
        &query,
    )
    .unwrap();
    let _ = super::accepted(super::AaPath::read(&refs, &query).unwrap());
    let reader = baseline.read(&[], 9000).unwrap();
    let exact = 200_000 - reader.execution().work_remaining() as u64;
    let parser = Parser::new(
        structured_asn1::Encoding::Der,
        Limits {
            max_work: exact,
            ..Limits::default()
        },
        generous(),
    );
    let certs = bytes
        .iter()
        .map(|b| read_pkc(&parser, b))
        .collect::<Vec<_>>();
    let refs = certs.iter().collect::<Vec<_>>();
    let verifier = Crypto::new();
    let fresh = generous();
    let result = aa_path::validate(&refs, &certs[1], &context(&fresh, &verifier, &()));
    assert!(
        matches!(result,Err(PathError::Processing(ref error)) if error.is_resource()),
        "{result:?}"
    );
    assert_eq!(verifier.calls.get(), 0);
    assert_eq!(fresh.used(), 0);
}
