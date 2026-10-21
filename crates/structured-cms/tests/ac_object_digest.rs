//! Complete object-binding paths, using independent SHA-256 and synthetic DER.
use core::{
    cell::{Cell, RefCell},
    cmp::Ordering,
};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, OwnedVec, Work};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_cms::attribute_certificate::AttributeCertificate;
use structured_cms::attribute_certificate::validation::digest::{
    Binding, BindingError, BoundObject, Capability, Failure, Object, ObjectDigestProvider, Phase,
};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
use structured_pkix::key::effective::{EffectiveSpki, Part, VisitError};
use structured_pkix::path::WorkingKey;
use structured_pkix::{Certificate, PublicKeyInfo, oid};

fn memory(cap: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(cap, work)))
}
fn generous() -> Memory {
    memory(1 << 20, 1 << 25)
}
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(u8::try_from(value.len()).unwrap());
    } else {
        let len = value.len().to_be_bytes();
        let first = len.iter().position(|&b| b != 0).unwrap();
        out.push(128 | u8::try_from(len.len() - first).unwrap());
        out.extend(&len[first..]);
    }
    out.extend(value);
    out
}
fn seq(values: &[&[u8]]) -> Vec<u8> {
    tlv(48, &values.concat())
}
fn algorithm(kind: Oid<'_>, params: &[u8]) -> Vec<u8> {
    seq(&[&tlv(6, kind.as_bytes()), params])
}
fn unknown_alg() -> Vec<u8> {
    seq(&[&[6, 1, 42]])
}
fn spki(kind: Oid<'_>, params: &[u8], key: &[u8]) -> Vec<u8> {
    seq(&[&algorithm(kind, params), &tlv(3, &[&[0][..], key].concat())])
}
fn name(value: &[u8]) -> Vec<u8> {
    seq(&[&tlv(49, &seq(&[&[6, 3, 85, 4, 3], &tlv(12, value)]))])
}
fn cert(spki: &[u8], signature: u8) -> Vec<u8> {
    let tbs = seq(&[
        &[160, 3, 2, 1, 2],
        &[2, 1, 1],
        &unknown_alg(),
        &name(b"Issuer"),
        &seq(&[&tlv(23, b"260101000000Z"), &tlv(23, b"270101000000Z")]),
        &name(b"Holder"),
        spki,
    ]);
    seq(&[&tbs, &unknown_alg(), &[3, 2, 0, signature]])
}
fn ac(holder: &[u8]) -> Vec<u8> {
    let issuer = tlv(160, &seq(&[&tlv(164, &name(b"Authority"))]));
    let info = seq(&[
        &[2, 1, 1],
        holder,
        &issuer,
        &unknown_alg(),
        &[2, 1, 1],
        &seq(&[&tlv(24, b"20260101000000Z"), &tlv(24, b"20270101000000Z")]),
        &seq(&[&seq(&[&[6, 1, 42], &[49, 2, 5, 0]])]),
    ]);
    seq(&[&info, &unknown_alg(), &[3, 2, 0, 9]])
}
fn holder(object: u8, other: &[u8], alg: &[u8], padding: u8, hash: &[u8]) -> Vec<u8> {
    seq(&[&tlv(
        162,
        &[
            &[10, 1, object][..],
            other,
            alg,
            &tlv(3, &[&[padding][..], hash].concat()),
        ]
        .concat(),
    )])
}
fn assertion(object: u8, expected: &[u8]) -> Vec<u8> {
    ac(&holder(
        object,
        &[],
        &algorithm(oid::SHA256, &[]),
        0,
        expected,
    ))
}
fn read_ac<'a>(p: &'a Parser, b: &'a [u8]) -> AttributeCertificate<'a> {
    AttributeCertificate::read(&mut p.read(b, 700).unwrap()).unwrap()
}
fn read_key<'a>(p: &'a Parser, b: &'a [u8]) -> WorkingKey<'a> {
    let mut r = p.read(b, 400).unwrap();
    let e = r.next_element().unwrap().unwrap();
    WorkingKey::standing(PublicKeyInfo::read_element(&r, &e, "key").unwrap())
}
fn collect(key: WorkingKey<'_>, work: &impl Work) -> Vec<u8> {
    let der = EffectiveSpki::read(key, work).unwrap();
    assert!(core::ptr::eq(
        der.key().key().as_bytes().as_ptr(),
        key.key().as_bytes().as_ptr()
    ));
    let mut bytes = Vec::new();
    der.visit(work, |_, part, w| {
        w.charge_work(part.len() as u64)?;
        bytes.extend(part);
        Ok::<_, MemoryError>(())
    })
    .unwrap();
    assert_eq!(der.encoded_len(), bytes.len() as u64);
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    KeyError,
    StartError,
    UpdateError,
    LateUpdateError,
    FinishError,
    CompareError,
    KeyUnsupported,
    KeyMalformed,
    StartUnsupported,
    StartMalformed,
    NoHash,
    IdentityWidth,
    OutputWidth,
    NoWidth,
}
#[derive(Debug)]
enum Cause {
    Resource(MemoryError),
    Marker(Fault),
    Key(structured_pkix::Error),
}
impl From<MemoryError> for Cause {
    fn from(e: MemoryError) -> Self {
        Self::Resource(e)
    }
}
struct Live<'a>(&'a Cell<usize>);
impl Drop for Live<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}
struct State<'a> {
    hash: Sha256,
    live: Live<'a>,
    storage: OwnedVec<u8>,
}
struct Output {
    bytes: [u8; 32],
    len: usize,
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
struct Oracle {
    fault: Fault,
    calls: RefCell<Vec<&'static str>>,
    live: Cell<usize>,
    updates: Cell<usize>,
    allocate: bool,
}
impl Oracle {
    fn new(fault: Fault) -> Self {
        Self {
            fault,
            calls: RefCell::new(vec![]),
            live: Cell::new(0),
            updates: Cell::new(0),
            allocate: false,
        }
    }
    fn call(&self, name: &'static str, fault: Fault, w: &impl Work) -> Result<(), Cause> {
        w.charge_work(1)?;
        self.calls.borrow_mut().push(name);
        if self.fault == fault {
            Err(Cause::Marker(fault))
        } else {
            Ok(())
        }
    }
}
impl<'a> Digest<'a> for Oracle {
    type Identity = ();
    type State = State<'a>;
    type Output = Output;
    type Error = Cause;
    fn width(&self, (): &()) -> Option<usize> {
        match self.fault {
            Fault::IdentityWidth => Some(31),
            Fault::NoWidth => None,
            _ => Some(32),
        }
    }
    fn compare<W: Work>(&self, (): &(), (): &(), w: &W) -> Result<Ordering, Cause> {
        w.charge_work(1)?;
        Ok(Ordering::Equal)
    }
    fn start<W: Work>(&'a self, (): &(), w: &W) -> Result<Resolution<State<'a>>, Cause> {
        self.call("start", Fault::StartError, w)?;
        match self.fault {
            Fault::StartUnsupported => return Ok(Resolution::Unsupported),
            Fault::StartMalformed => return Ok(Resolution::Malformed),
            _ => {}
        }
        let mut storage = w.vector();
        if self.allocate {
            storage.try_extend_from_slice(&[0; 8])?;
        }
        self.live.set(self.live.get() + 1);
        Ok(Resolution::Supported(State {
            hash: Sha256::new(),
            live: Live(&self.live),
            storage: storage.into_owned(),
        }))
    }
    fn update<W: Work>(&self, s: &mut State<'a>, b: &[u8], w: &W) -> Result<(), Cause> {
        w.charge_work(b.len() as u64)?;
        self.call("update", Fault::UpdateError, w)?;
        self.updates.set(self.updates.get() + 1);
        if self.fault == Fault::LateUpdateError && self.updates.get() == 7 {
            return Err(Cause::Marker(Fault::LateUpdateError));
        }
        s.hash.update(b);
        Ok(())
    }
    fn finish<W: Work>(&self, s: State<'a>, w: &W) -> Result<Output, Cause> {
        self.call("finish", Fault::FinishError, w)?;
        let bytes = s.hash.finalize().into();
        drop(s.live);
        drop(s.storage);
        Ok(Output {
            bytes,
            len: if self.fault == Fault::OutputWidth {
                31
            } else {
                32
            },
        })
    }
    fn matches<W: Work>(&self, (): &(), o: &Output, b: &[u8], w: &W) -> Result<bool, Cause> {
        w.charge_work(b.len() as u64)?;
        self.call("compare", Fault::CompareError, w)?;
        Ok(o.as_ref() == b)
    }
}
impl AsnDigest<'_> for Oracle {
    fn identity(&self, a: Algorithm) -> Option<()> {
        self.calls.borrow_mut().push("identity");
        if self.fault == Fault::NoHash || a != Algorithm::Sha256 {
            None
        } else {
            Some(())
        }
    }
}
impl ObjectDigestProvider<'_> for Oracle {
    fn validate_public_key<W: Work>(
        &self,
        key: WorkingKey<'_>,
        w: &W,
    ) -> Result<Resolution<()>, Cause> {
        self.call("key", Fault::KeyError, w)?;
        w.charge_work(key.key().algorithm().algorithm().as_bytes().len() as u64 + 1)?;
        // This oracle checks framing/DSA structure, not key mathematics or policy.
        if key.key().algorithm().algorithm().as_bytes() == [42, 134, 72, 206, 56, 4, 1] {
            let parsed = structured_pkix::key::dsa::read(key, w).map_err(Cause::Key)?;
            if parsed.parameters().is_none() {
                return Ok(Resolution::Malformed);
            }
        }
        Ok(match self.fault {
            Fault::KeyUnsupported => Resolution::Unsupported,
            Fault::KeyMalformed => Resolution::Malformed,
            _ => Resolution::Supported(()),
        })
    }
}
fn bound<'r, 'a, 's>(outcome: Binding<'r, 'a, 's>) -> BoundObject<'r, 'a, 's> {
    match outcome {
        Binding::Bound(receipt) => receipt,
        other => panic!("{other:?}"),
    }
}
fn rejected(outcome: &Binding<'_, '_, '_>, expected: Failure) {
    assert!(
        matches!(outcome, Binding::Rejected(f) if *f == expected),
        "{outcome:?}"
    );
}

#[test]
fn whole_certificate_hash_includes_signature_and_receipt_binds_original_objects() {
    // Replacing only signature bytes changes the entire-certificate object.
    let p = Parser::der(generous());
    let cp = Parser::der(generous());
    let key = spki(
        oid::RSA_ENCRYPTION,
        &[5, 0],
        &seq(&[&[2, 1, 3], &[2, 1, 3]]),
    );
    let bytes = cert(&key, 9);
    let changed = cert(&key, 8);
    let expected = Sha256::digest(&bytes);
    let ac_bytes = assertion(1, &expected);
    let ac = read_ac(&p, &ac_bytes);
    let certificate = Certificate::read(&cp, &bytes, 2000).unwrap();
    let other = Certificate::read(&cp, &changed, 4000).unwrap();
    let provider = Oracle::new(Fault::None);
    let result = ac
        .bind_holder_digest(Object::Certificate(&certificate), &provider, p.memory())
        .unwrap();
    if let Binding::Bound(receipt) = result {
        assert!(core::ptr::eq(receipt.certificate(), &raw const ac));
        assert!(
            matches!(receipt.object(),Object::Certificate(c) if core::ptr::eq(c,&raw const certificate))
        );
    } else {
        panic!("{result:?}");
    }
    rejected(
        &ac.bind_holder_digest(Object::Certificate(&other), &provider, p.memory())
            .unwrap(),
        Failure::Differs,
    );
    assert!(!provider.calls.borrow().contains(&"key"));
}

#[test]
fn standalone_key_hash_covers_algorithm_parameters_and_key_bits() {
    // No certificate is needed, and hashing key bits alone is insufficient.
    let p = Parser::der(generous());
    let kp = Parser::der(generous());
    let bytes = spki(
        oid::RSA_ENCRYPTION,
        &[5, 0],
        &seq(&[&[2, 1, 3], &[2, 1, 3]]),
    );
    let key = read_key(&kp, &bytes);
    let hash = Sha256::digest(&bytes);
    let encoded = assertion(0, &hash);
    let ac = read_ac(&p, &encoded);
    let provider = Oracle::new(Fault::None);
    bound(
        ac.bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
            .unwrap(),
    );
    let wrong = assertion(0, &Sha256::digest(key.key().key().as_bytes()));
    let wrong = read_ac(&p, &wrong);
    rejected(
        &wrong
            .bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
            .unwrap(),
        Failure::Differs,
    );
    assert_eq!(provider.live.get(), 0);
}

#[test]
fn inherited_dsa_parameters_are_included_in_the_hash_not_the_original_spki() {
    // RFC5755§7.3's mandatory inheritance branch, omitted by the donor TODO.
    let dsa = Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]);
    let params = seq(&[&[2, 1, 23], &[2, 1, 11], &[2, 1, 2]]);
    let authority_bytes = spki(dsa, &params, &[2, 1, 8]);
    let subject_spki = spki(dsa, &[], &[2, 1, 4]);
    let subject_bytes = cert(&subject_spki, 9);
    let effective = spki(dsa, &params, &[2, 1, 4]);
    let p = Parser::der(generous());
    let kp = Parser::der(generous());
    let cp = Parser::der(generous());
    let subject = Certificate::read(&cp, &subject_bytes, 2000).unwrap();
    let key = read_key(&kp, &authority_bytes)
        .subject(&subject, p.memory())
        .unwrap();
    assert!(key.key().algorithm().parameters().is_none());
    assert_eq!(collect(key, p.memory()), effective);
    let provider = Oracle::new(Fault::None);
    let bytes = assertion(0, &Sha256::digest(&effective));
    let ac = read_ac(&p, &bytes);
    bound(
        ac.bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
            .unwrap(),
    );
    let wrong = assertion(0, &Sha256::digest(&subject_spki));
    let wrong = read_ac(&p, &wrong);
    rejected(
        &wrong
            .bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
            .unwrap(),
        Failure::Differs,
    );
}

#[test]
fn rfc3279_key_representations_stream_the_entire_der_and_remain_borrowed() {
    // RSA, DSA, DH, KEA, and both EC point forms use the same framing core.
    let dsa = Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]);
    let dh = Oid::from_bytes(&[42, 134, 72, 206, 62, 2, 1]);
    let kea = Oid::from_bytes(&[96, 134, 72, 1, 101, 2, 1, 1, 22]);
    let ec = Oid::from_bytes(&[42, 134, 72, 206, 61, 2, 1]);
    let params = seq(&[&[2, 1, 23], &[2, 1, 11], &[2, 1, 2]]);
    let curve = tlv(6, &[42, 134, 72, 206, 61, 3, 1, 7]);
    let cases = [
        spki(
            oid::RSA_ENCRYPTION,
            &[5, 0],
            &seq(&[&[2, 1, 3], &[2, 1, 3]]),
        ),
        spki(dsa, &params, &[2, 1, 4]),
        spki(
            dh,
            &seq(&[
                &[2, 1, 23],
                &[2, 1, 2],
                &[2, 1, 11],
                &[2, 1, 2],
                &seq(&[&[3, 2, 0, 128], &[2, 1, 1]]),
            ]),
            &[2, 1, 4],
        ),
        spki(kea, &tlv(4, &[9; 10]), &[1; 128]),
        spki(ec, &curve, &[&[4][..], &[1; 32], &[2; 32]].concat()),
        spki(ec, &curve, &[&[2][..], &[1; 32]].concat()),
    ];
    for bytes in cases {
        let p = Parser::der(generous());
        let key = read_key(&p, &bytes);
        let work = memory(0, 1 << 20);
        let encoded = EffectiveSpki::read(key, &work).unwrap();
        let mut collected: Vec<u8> = Vec::with_capacity(bytes.len());
        encoded
            .visit(&work, |part, data, w| {
                w.charge_work(data.len() as u64)?;
                if part == Part::PublicKey {
                    assert_eq!(data.as_ptr(), key.key().key().as_bytes().as_ptr());
                }
                collected.extend(data);
                Ok::<_, MemoryError>(())
            })
            .unwrap();
        assert_eq!(collected, bytes);
        assert_eq!(work.used(), 0);
        let ac_bytes = assertion(0, &Sha256::digest(&bytes));
        let ac = read_ac(&p, &ac_bytes);
        bound(
            ac.bind_holder_digest(
                Object::PublicKey(key),
                &Oracle::new(Fault::None),
                p.memory(),
            )
            .unwrap(),
        );
    }
}

#[test]
fn every_der_length_boundary_matches_independent_fixture_encoding() {
    // Header carry at 127/128 and 255/256 must include the unused-bits octet.
    for size in [
        0, 1, 110, 111, 112, 126, 127, 128, 129, 254, 255, 256, 257, 65535, 65536,
    ] {
        let bytes = spki(Oid::from_bytes(&[42]), &[], &vec![9; size]);
        let p = Parser::der(generous());
        let key = read_key(&p, &bytes);
        assert_eq!(collect(key, &generous()), bytes);
    }
}

#[test]
fn written_null_is_not_silently_dropped_and_absence_is_not_invented_null() {
    // The generic stream preserves meaning; the provider separately accepts the algorithm spelling.
    for params in [&[][..], &[5, 0][..]] {
        let bytes = spki(oid::RSA_ENCRYPTION, params, &[1, 2, 3]);
        let p = Parser::der(generous());
        let key = read_key(&p, &bytes);
        assert_eq!(collect(key, p.memory()), bytes);
    }
}

#[test]
fn ber_outer_framing_is_canonical_but_non_der_parameters_are_not_repaired() {
    // New headers are deliberate DER input framing, not normalization of opaque params.
    let der = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1, 2, 3]);
    let ber = [&[48, 129, der[1]][..], &der[2..]].concat();
    let p = Parser::ber(generous());
    let key = read_key(&p, &ber);
    assert_eq!(collect(key, p.memory()), der);
    let bad = spki(oid::RSA_ENCRYPTION, &[5, 129, 0], &[1, 2, 3]);
    let key = read_key(&p, &bad);
    assert!(EffectiveSpki::read(key, p.memory()).is_err());
}

#[test]
fn ber_parameter_der_check_admits_scratch_and_preserves_original_depth() {
    // A retained BER value must not gain default depth or unaccounted DER-walk storage.
    let params = seq(&[&seq(&[&seq(&[&[2, 1, 1]])])]);
    let kb = spki(oid::RSA_ENCRYPTION, &params, &[1]);
    let p = Parser::ber(generous());
    let key = read_key(&p, &kb);
    let query = memory(0, 100_000);
    let error = EffectiveSpki::read(key, &query).unwrap_err();
    assert!(error.is_resource());
    assert!(error.offset() >= 400);
    assert_eq!(query.used(), 0);

    let mut exact_depth = None;
    for depth in 2..10 {
        let p = Parser::new(
            Encoding::Ber,
            Limits {
                max_depth: depth,
                ..Limits::default()
            },
            generous(),
        );
        let mut reader = p.read(&kb, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        if let Ok(info) = PublicKeyInfo::read_element(&reader, &element, "key") {
            // The smallest depth that admits the original parse must admit this same walk.
            assert!(EffectiveSpki::read(WorkingKey::standing(info), &generous()).is_ok());
            exact_depth = Some(depth);
            break;
        }
    }
    assert!(exact_depth.is_some());
}

#[test]
fn padded_public_key_bits_refuse_before_emitting_any_part() {
    // BIT STRING inspection does not imply a whole-octet key representation.
    let bytes = seq(&[&unknown_alg(), &[3, 2, 1, 2]]);
    let p = Parser::der(generous());
    let key = read_key(&p, &bytes);
    assert!(EffectiveSpki::read(key, p.memory()).is_err());
}

#[test]
fn explicit_object_selection_and_absence_never_fall_back_to_other_holder_alternatives() {
    // An entityName cannot replace a missing/different explicitly selected object assertion.
    let p = Parser::der(generous());
    let cp = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let key = read_key(&cp, &kb);
    let cb = cert(&kb, 9);
    let c = Certificate::read(&cp, &cb, 2000).unwrap();
    let provider = Oracle::new(Fault::None);
    let absent = ac(&seq(&[&tlv(161, &tlv(130, b"holder.test"))]));
    rejected(
        &read_ac(&p, &absent)
            .bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
            .unwrap(),
        Failure::Absent,
    );
    let bytes = assertion(1, &[0; 32]);
    rejected(
        &read_ac(&p, &bytes)
            .bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
            .unwrap(),
        Failure::ObjectType,
    );
    let bytes = assertion(0, &[0; 32]);
    rejected(
        &read_ac(&p, &bytes)
            .bind_holder_digest(Object::Certificate(&c), &provider, p.memory())
            .unwrap(),
        Failure::ObjectType,
    );
    assert!(provider.calls.borrow().is_empty());
}

#[test]
fn forbidden_object_type_and_other_type_identifier_precede_all_provider_work() {
    // The ASN.1 third choice remains readable but cannot identify a profile object.
    let p = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let key = read_key(&p, &kb);
    for (kind, other) in [(2, vec![]), (0, tlv(6, &[42])), (1, tlv(6, &[42]))] {
        let bytes = ac(&holder(
            kind,
            &other,
            &algorithm(oid::SHA256, &[]),
            0,
            &[0; 32],
        ));
        let ac = read_ac(&p, &bytes);
        let provider = Oracle::new(Fault::None);
        rejected(
            &ac.bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
                .unwrap(),
            Failure::OtherObject,
        );
        assert!(provider.calls.borrow().is_empty());
    }
}

#[test]
fn invalid_digest_width_padding_and_parameters_are_gated_before_identity_or_state() {
    // Distinct malformed assertions cannot hash data, regardless of later provider answers.
    let p = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let key = read_key(&p, &kb);
    let cases = [
        (algorithm(oid::SHA256, &[]), 0, vec![0; 31], Failure::Hash),
        (algorithm(oid::SHA256, &[]), 1, vec![0; 32], Failure::Hash),
        (
            algorithm(oid::SHA256, &[4, 0]),
            0,
            vec![0; 32],
            Failure::Algorithm,
        ),
        (
            algorithm(Oid::from_bytes(&[96, 134, 72, 1, 101, 3, 4, 2, 8]), &[5, 0]),
            0,
            vec![0; 32],
            Failure::Algorithm,
        ),
    ];
    for (alg, padding, hash, reason) in cases {
        let bytes = ac(&holder(0, &[], &alg, padding, &hash));
        let ac = read_ac(&p, &bytes);
        let provider = Oracle::new(Fault::None);
        rejected(
            &ac.bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
                .unwrap(),
            reason,
        );
        assert!(provider.calls.borrow().is_empty());
    }
}

#[test]
fn unsupported_digest_key_and_start_are_not_negative_comparisons() {
    // Unavailable capability must not be conflated with a completed wrong hash.
    let p = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let key = read_key(&p, &kb);
    let bytes = assertion(0, &[0; 32]);
    let ac = read_ac(&p, &bytes);
    for (fault, capability) in [
        (Fault::NoHash, Capability::Digest),
        (Fault::KeyUnsupported, Capability::Key),
        (Fault::StartUnsupported, Capability::Digest),
    ] {
        let provider = Oracle::new(fault);
        assert!(
            matches!(ac.bind_holder_digest(Object::PublicKey(key),&provider,p.memory()).unwrap(),Binding::Unsupported(c) if c==capability)
        );
        assert!(!provider.calls.borrow().contains(&"update"));
        assert_eq!(provider.live.get(), 0);
    }
    let unknown = self::ac(&holder(0, &[], &unknown_alg(), 0, &[0; 32]));
    let provider = Oracle::new(Fault::None);
    assert!(matches!(
        read_ac(&p, &unknown)
            .bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
            .unwrap(),
        Binding::Unsupported(Capability::Digest)
    ));
    assert!(provider.calls.borrow().is_empty());
}

#[test]
fn key_and_start_malformed_answers_remain_distinct_from_unknown_capability() {
    // Both gates can refuse semantically before any input reaches the hash.
    let p = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let key = read_key(&p, &kb);
    let bytes = assertion(0, &[0; 32]);
    let ac = read_ac(&p, &bytes);
    for (fault, reason) in [
        (Fault::KeyMalformed, Failure::KeyEncoding),
        (Fault::StartMalformed, Failure::Algorithm),
    ] {
        let provider = Oracle::new(fault);
        rejected(
            &ac.bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
                .unwrap(),
            reason,
        );
        assert!(!provider.calls.borrow().contains(&"update"));
    }
}

#[test]
fn provider_width_contract_failure_never_becomes_document_hash_mismatch() {
    // Both advertised identity and actual output are checked against the written algorithm.
    let p = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let key = read_key(&p, &kb);
    let bytes = assertion(0, &Sha256::digest(&kb));
    let ac = read_ac(&p, &bytes);
    for fault in [Fault::IdentityWidth, Fault::OutputWidth] {
        let provider = Oracle::new(fault);
        assert!(matches!(
            ac.bind_holder_digest(Object::PublicKey(key), &provider, p.memory()),
            Err(BindingError::OutputWidth {
                expected: 32,
                actual: 31
            })
        ));
        assert!(!provider.calls.borrow().contains(&"compare"));
        assert_eq!(provider.live.get(), 0);
    }
    bound(
        ac.bind_holder_digest(
            Object::PublicKey(key),
            &Oracle::new(Fault::NoWidth),
            p.memory(),
        )
        .unwrap(),
    );
}

#[test]
fn every_provider_failure_preserves_cause_and_releases_state_storage() {
    // No resource/provider failure can escape as a partial positive or Differs.
    let p = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let key = read_key(&p, &kb);
    let bytes = assertion(0, &Sha256::digest(&kb));
    let ac = read_ac(&p, &bytes);
    for (fault, phase) in [
        (Fault::KeyError, Phase::KeyEncoding),
        (Fault::StartError, Phase::Start),
        (Fault::FinishError, Phase::Finish),
        (Fault::CompareError, Phase::Comparison),
    ] {
        let mut provider = Oracle::new(fault);
        provider.allocate = true;
        let query = generous();
        assert!(
            matches!(ac.bind_holder_digest(Object::PublicKey(key),&provider,&query),Err(BindingError::Callback{phase:p,source:Cause::Marker(f)}) if p==phase && f==fault)
        );
        assert_eq!(provider.live.get(), 0);
        assert_eq!(query.used(), 0);
    }
    let mut provider = Oracle::new(Fault::UpdateError);
    provider.allocate = true;
    let query = generous();
    assert!(matches!(
        ac.bind_holder_digest(Object::PublicKey(key), &provider, &query),
        Err(BindingError::KeyInput(VisitError::Callback {
            source: Cause::Marker(Fault::UpdateError),
            ..
        }))
    ));
    assert_eq!(provider.live.get(), 0);
    assert_eq!(query.used(), 0);
}

#[test]
fn final_key_fragment_failure_discards_all_prior_hash_progress() {
    // Six accepted chunks cannot yield a positive when the actual key payload fails.
    let p = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let key = read_key(&p, &kb);
    let bytes = assertion(0, &Sha256::digest(&kb));
    let ac = read_ac(&p, &bytes);
    let mut provider = Oracle::new(Fault::LateUpdateError);
    provider.allocate = true;
    let query = generous();
    assert!(matches!(
        ac.bind_holder_digest(Object::PublicKey(key), &provider, &query),
        Err(BindingError::KeyInput(VisitError::Callback {
            part: Part::PublicKey,
            context,
            source: Cause::Marker(Fault::LateUpdateError),
        })) if context.start >= 400 && context.length == 1
    ));
    assert_eq!(provider.updates.get(), 7);
    assert!(!provider.calls.borrow().contains(&"finish"));
    assert!(!provider.calls.borrow().contains(&"compare"));
    assert_eq!(provider.live.get(), 0);
    assert_eq!(query.used(), 0);
}

#[test]
fn whole_certificate_provider_input_failure_has_its_own_phase() {
    // Certificate bytes are one complete input, not synthesized SPKI chunks.
    let p = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let cb = cert(&kb, 9);
    let c = Certificate::read(&p, &cb, 2000).unwrap();
    let bytes = assertion(1, &Sha256::digest(&cb));
    let ac = read_ac(&p, &bytes);
    let provider = Oracle::new(Fault::UpdateError);
    assert!(matches!(
        ac.bind_holder_digest(Object::Certificate(&c), &provider, p.memory()),
        Err(BindingError::Callback {
            phase: Phase::CertificateInput,
            source: Cause::Marker(Fault::UpdateError)
        })
    ));
    assert_eq!(provider.live.get(), 0);
}

#[test]
fn state_allocation_refusal_is_typed_and_rolls_back_without_live_state() {
    // The oracle uses the real scoped allocator so capacity refusal is exercised transitively.
    let p = Parser::der(generous());
    let kb = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let key = read_key(&p, &kb);
    let bytes = assertion(0, &[0; 32]);
    let ac = read_ac(&p, &bytes);
    let mut provider = Oracle::new(Fault::None);
    provider.allocate = true;
    let query = memory(7, 1 << 20);
    assert!(matches!(
        ac.bind_holder_digest(Object::PublicKey(key), &provider, &query),
        Err(BindingError::Callback {
            phase: Phase::Start,
            source: Cause::Resource(_)
        })
    ));
    assert_eq!(query.used(), 0);
    assert_eq!(provider.live.get(), 0);
}

#[test]
fn unbound_dsa_parameters_cannot_be_hash_accepted_by_the_encoding_gate() {
    // Omitted DSA parameters without an effective inherited source cannot identify a full key.
    let p = Parser::der(generous());
    let kb = spki(
        Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]),
        &[],
        &[2, 1, 4],
    );
    let key = read_key(&p, &kb);
    let bytes = assertion(0, &Sha256::digest(&kb));
    let ac = read_ac(&p, &bytes);
    let provider = Oracle::new(Fault::None);
    rejected(
        &ac.bind_holder_digest(Object::PublicKey(key), &provider, p.memory())
            .unwrap(),
        Failure::KeyEncoding,
    );
    assert!(!provider.calls.borrow().contains(&"start"));
}

#[test]
fn invalid_written_dsa_null_is_not_repaired_by_general_parameter_inheritance() {
    // Algorithm-specific reader refusal retains its own location/cause, without a hash state.
    let p = Parser::der(generous());
    let kb = spki(
        Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]),
        &[5, 0],
        &[2, 1, 4],
    );
    let key = read_key(&p, &kb);
    let bytes = assertion(0, &[0; 32]);
    let ac = read_ac(&p, &bytes);
    let provider = Oracle::new(Fault::None);
    assert!(
        matches!(ac.bind_holder_digest(Object::PublicKey(key),&provider,p.memory()),Err(BindingError::Callback{phase:Phase::KeyEncoding,source:Cause::Key(error)}) if error.offset()>=400)
    );
    assert!(!provider.calls.borrow().contains(&"start"));
}

#[test]
fn exact_current_query_ceiling_survives_all_foreign_source_switches() {
    // AC, subject key and inherited parameters are three sources; one current operation pays all.
    let dsa = Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]);
    let params = seq(&[&[2, 1, 23], &[2, 1, 11], &[2, 1, 2]]);
    let authority = spki(dsa, &params, &[2, 1, 8]);
    let subject_spki = spki(dsa, &[], &[2, 1, 4]);
    let subject_bytes = cert(&subject_spki, 9);
    let expected = spki(dsa, &params, &[2, 1, 4]);
    let p = Parser::der(generous());
    let kp = Parser::der(generous());
    let cp = Parser::der(generous());
    let subject = Certificate::read(&cp, &subject_bytes, 2000).unwrap();
    let key = read_key(&kp, &authority)
        .subject(&subject, p.memory())
        .unwrap();
    let bytes = assertion(0, &Sha256::digest(&expected));
    let ac = read_ac(&p, &bytes);
    let baseline = memory(1 << 20, 1 << 25);
    let provider = Oracle::new(Fault::None);
    bound(
        ac.bind_holder_digest(Object::PublicKey(key), &provider, &baseline)
            .unwrap(),
    );
    let cost = baseline.work_used();
    for limit in [0, 4, 64, cost - 1, cost] {
        let root = Parser::new(
            Encoding::Der,
            Limits {
                max_work: limit as u64,
                ..Limits::default()
            },
            generous(),
        );
        let reader = root.read(&[], 9000).unwrap();
        let work = reader.execution();
        let provider = Oracle::new(Fault::None);
        let result = ac.bind_holder_digest(Object::PublicKey(key), &provider, &work);
        if limit == cost {
            bound(result.unwrap());
        } else {
            assert!(result.is_err(), "limit={limit}, {result:?}");
        }
        assert_eq!(provider.live.get(), 0);
        assert_eq!(root.memory().used(), 0);
    }
}

#[test]
fn original_key_ceiling_funds_the_key_validation_callback() {
    // Framing may consume the last source unit; the provider must not then use only AC work.
    let bytes = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]);
    let observed = generous();
    let baseline = Parser::der(observed.clone());
    let _ = read_key(&baseline, &bytes);
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: observed.work_used() as u64 + 64,
            ..Limits::default()
        },
        generous(),
    );
    let key = read_key(&source, &bytes);
    let p = Parser::der(generous());
    let encoded = assertion(0, &[0; 32]);
    let ac = read_ac(&p, &encoded);
    let provider = Oracle::new(Fault::None);
    assert!(matches!(
        ac.bind_holder_digest(Object::PublicKey(key), &provider, p.memory()),
        Err(BindingError::Callback {
            phase: Phase::KeyEncoding,
            source: Cause::Resource(MemoryError::WorkExceeded)
        })
    ));
    assert!(!provider.calls.borrow().contains(&"start"));
}

#[test]
fn inherited_parameter_chunk_retains_its_own_source_ceiling() {
    // A separately retained DER view still pays the parameter donor on a later visit.
    let dsa = Oid::from_bytes(&[42, 134, 72, 206, 56, 4, 1]);
    let params = seq(&[&[2, 1, 23], &[2, 1, 11], &[2, 1, 2]]);
    let authority = spki(dsa, &params, &[2, 1, 8]);
    let subject_bytes = cert(&spki(dsa, &[], &[2, 1, 4]), 9);
    let observed = generous();
    let p = Parser::der(observed.clone());
    let _ = read_key(&p, &authority);
    let source = Parser::new(
        Encoding::Der,
        Limits {
            max_work: observed.work_used() as u64 + 1,
            ..Limits::default()
        },
        generous(),
    );
    let cp = Parser::der(generous());
    let c = Certificate::read(&cp, &subject_bytes, 2000).unwrap();
    let query = generous();
    let key = read_key(&source, &authority).subject(&c, &query).unwrap();
    let encoded = EffectiveSpki::read(key, &query).unwrap();
    let mut visited = vec![];
    let result = encoded.visit(&query, |part, data, w| {
        visited.push(part);
        w.charge_work(data.len() as u64)
    });
    assert!(matches!(
        result,
        Err(VisitError::Callback {
            part: Part::Parameters,
            source: MemoryError::WorkExceeded,
            context,
        }) if context.start >= 400 && context.end() <= 400 + authority.len() as u64
    ));
    assert!(!visited.contains(&Part::PublicKey));
}

#[test]
fn retained_stream_visits_use_new_work_and_stop_after_a_visitor_failure() {
    // Prepared views keep no operation borrow, charge a later query, and never continue after refusal.
    let bytes = spki(oid::RSA_ENCRYPTION, &[5, 0], &[1, 2, 3]);
    let p = Parser::der(generous());
    let key = read_key(&p, &bytes);
    let encoded = {
        let initial = generous();
        EffectiveSpki::read(key, &initial).unwrap()
    };
    let denied = memory(0, 0);
    let calls = Cell::new(0);
    assert!(matches!(
        encoded.visit(&denied, |_, _, _| {
            calls.set(calls.get() + 1);
            Ok::<_, ()>(())
        }),
        Err(VisitError::Processing { .. })
    ));
    assert_eq!(calls.get(), 0);
    let work = memory(0, 1 << 20);
    let error = encoded
        .visit(&work, |part, _, _| {
            calls.set(calls.get() + 1);
            if part == Part::Algorithm {
                Err(17)
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert!(matches!(
        error,
        VisitError::Callback {
            part: Part::Algorithm,
            source: 17,
            ..
        }
    ));
    assert_eq!(calls.get(), 4);
    assert_eq!(work.used(), 0);
}

#[test]
fn whole_certificate_input_obeys_its_original_cumulative_ceiling() {
    // Already parsed DER cannot be hashed for free under an unrelated current account.
    let cb = cert(&spki(oid::RSA_ENCRYPTION, &[5, 0], &[1]), 9);
    let observed = generous();
    let p = Parser::der(observed.clone());
    let _ = Certificate::read(&p, &cb, 2000).unwrap();
    let cp = Parser::new(
        Encoding::Der,
        Limits {
            max_work: observed.work_used() as u64 + 1,
            ..Limits::default()
        },
        generous(),
    );
    let c = Certificate::read(&cp, &cb, 2000).unwrap();
    let ap = Parser::der(generous());
    let ab = assertion(1, &Sha256::digest(&cb));
    let ac = read_ac(&ap, &ab);
    let provider = Oracle::new(Fault::None);
    assert!(matches!(
        ac.bind_holder_digest(Object::Certificate(&c), &provider, ap.memory()),
        Err(BindingError::Callback {
            phase: Phase::CertificateInput,
            source: Cause::Resource(MemoryError::WorkExceeded)
        })
    ));
    assert_eq!(provider.live.get(), 0);
}
