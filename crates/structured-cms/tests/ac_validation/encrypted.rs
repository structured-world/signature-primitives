//! Native Ed25519 AC + AES-KW/AES-CBC, original use receipts and scoped outputs.
use super::*;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use aes_kw::KeyInit;
use structured_asn1::memory::OwnedVec;
use structured_asn1::{Encoding, Reader};
use structured_cms::attribute_certificate::encrypted::{
    self, Attempt, Bound, DecryptError, Encrypted, Outcome as Decrypted, Rejection,
};
use structured_cms::enveloped::{EnvelopedData, Recipient};

const AES_CBC: Oid<'static> = Oid::from_bytes(&[96, 134, 72, 1, 101, 3, 4, 1, 2]);
const AES_KW: Oid<'static> = Oid::from_bytes(&[96, 134, 72, 1, 101, 3, 4, 1, 5]);
const KEK: [u8; 16] = [9; 16];
const CEK: [u8; 16] = [5; 16];
const IV: [u8; 16] = [7; 16];
fn attr(kind: &[u8]) -> Vec<u8> {
    seq(&[&tlv(6, kind), &[49, 2, 5, 0]])
}
fn clear(authority: &[u8], serial: &[u8], attrs: &[Vec<u8>]) -> Vec<u8> {
    seq(&[
        &tlv(164, &name(authority)),
        &tlv(2, serial),
        &seq(&attrs.iter().map(Vec::as_slice).collect::<Vec<_>>()),
    ])
}
fn envelope(plain: &[u8]) -> Vec<u8> {
    let mut buf = vec![0; (plain.len() / 16 + 1) * 16];
    buf[..plain.len()].copy_from_slice(plain);
    let cipher = cbc::Encryptor::<aes::Aes128>::new(&CEK.into(), &IV.into())
        .encrypt_padded::<Pkcs7>(&mut buf, plain.len())
        .unwrap();
    let kw = aes_kw::KwAes128::new(&KEK.into());
    let mut wrapped = [0; 24];
    kw.wrap_key(&CEK, &mut wrapped).unwrap();
    let kek = tlv(
        162,
        &[
            &[2, 1, 4][..],
            &seq(&[&[4, 1, 1]]),
            &seq(&[&tlv(6, AES_KW.as_bytes())]),
            &tlv(4, &wrapped),
        ]
        .concat(),
    );
    let data = seq(&[
        &[2, 1, 2],
        &tlv(49, &kek),
        &seq(&[
            &tlv(6, encrypted::CONTENT_TYPE.as_bytes()),
            &seq(&[&tlv(6, AES_CBC.as_bytes()), &tlv(4, &IV)]),
            &tlv(128, cipher),
        ]),
    ]);
    seq(&[
        &tlv(6, structured_cms::enveloped::IDENTIFIER.as_bytes()),
        &tlv(160, &data),
    ])
}
fn ac_envelopes(values: &[Vec<u8>]) -> Vec<u8> {
    let mut values = values.to_vec();
    values.sort();
    let enc = seq(&[
        &tlv(6, encrypted::IDENTIFIER.as_bytes()),
        &tlv(49, &values.concat()),
    ]);
    let information = seq(&[
        &[2, 1, 1],
        &entity(164, &name(b"Holder")),
        &issuer(b"Authority"),
        &ed(),
        &[2, 1, 5],
        &validity(),
        &seq(&[&enc, &attr(&[43])]),
        &seq(&[
            &no_rev(),
            &ext(oid::AUTHORITY_KEY_IDENTIFIER, &[48, 3, 128, 1, 1], false),
        ]),
    ]);
    signed(&information, &SigningKey::from_bytes(&[1; 32]))
}
macro_rules! setup {
    ($envs:expr,$ac:ident,$reader:ident,$checked:ident,$work:ident,$crypto:ident) => {
        let bytes = ac_envelopes($envs);
        let (chain, _) = fixture(Change::Exclude(0));
        let hb = holder_bytes(b"Holder");
        let $work = generous();
        let p = Parser::der($work.clone());
        let aa = read_pkc(&p, &chain[0]);
        let root = read_pkc(&p, &chain[2]);
        let holder = read_pkc(&p, &hb);
        let $ac = read_ac(&p, &bytes);
        let $reader = p.read(&bytes, $ac.element().span().start).unwrap();
        let $crypto = Crypto::new();
        let refs = [&holder];
        let path = holder_path(&refs, &root, &$crypto, &$work);
        let super::super::Outcome::Authenticated(facts) = $ac
            .authenticate(
                &aa,
                WorkingKey::standing(aa.tbs().public_key()),
                path.interval(),
                &$crypto,
                &$work,
            )
            .unwrap()
        else {
            panic!("native issuance")
        };
        let utc = LeapTable::new(1_780_000_000, 1_800_000_000, &[]).unwrap();
        let Outcome::Checked($checked) = direct(
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
                execution: &$work,
            },
            no_groups,
        )
        .unwrap() else {
            panic!("checked use")
        };
    };
}
#[derive(Debug)]
enum NativeError {
    Resource(MemoryError),
    Cms(structured_cms::Error),
    Pkix(structured_pkix::Error),
    Encoding(structured_asn1::Error),
}
impl From<MemoryError> for NativeError {
    fn from(e: MemoryError) -> Self {
        Self::Resource(e)
    }
}
impl From<structured_cms::Error> for NativeError {
    fn from(e: structured_cms::Error) -> Self {
        Self::Cms(e)
    }
}
impl From<structured_pkix::Error> for NativeError {
    fn from(e: structured_pkix::Error) -> Self {
        Self::Pkix(e)
    }
}
impl From<structured_asn1::Error> for NativeError {
    fn from(e: structured_asn1::Error) -> Self {
        Self::Encoding(e)
    }
}
impl core::fmt::Display for NativeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Resource(e) => write!(f, "{e}"),
            Self::Cms(e) => write!(f, "{e}"),
            Self::Pkix(e) => write!(f, "{e}"),
            Self::Encoding(e) => write!(f, "{e}"),
        }
    }
}
fn native(
    envelope: &EnvelopedData<'_>,
    work: &Execution<'_>,
    parent: &Reader<'_>,
) -> Result<Attempt<OwnedVec<u8>>, NativeError> {
    // Test-only provider: fixed supported mechanisms and caller-owned KEK.
    // Actual key unwrap and in-place content decryption use RustCrypto's
    // stack-only engines, with accounted ciphertext/output and prior work.
    work.charge_work(10)?;
    if envelope.content.algorithm.algorithm() != AES_CBC {
        return Ok(Attempt::Unsupported);
    }
    let mut key = None;
    for recipient in &envelope.recipients {
        work.charge_work(1)?;
        if let Recipient::Kek {
            identifier,
            algorithm,
            encrypted,
        } = recipient
        {
            work.charge_work(10)?;
            if identifier.identifier().as_one() != Some(&[1]) || algorithm.algorithm() != AES_KW {
                continue;
            }
            let Some(wrapped) = encrypted.as_one() else {
                return Ok(Attempt::Unsupported);
            };
            if wrapped.len() != 24 {
                return Ok(Attempt::Rejected);
            }
            work.charge_work(256)?;
            let mut cek = [0; 16];
            if aes_kw::KwAes128::new(&KEK.into())
                .unwrap_key(wrapped, &mut cek)
                .is_err()
            {
                return Ok(Attempt::Rejected);
            }
            key = Some(cek);
            break;
        }
    }
    let Some(key) = key else {
        return Ok(Attempt::NotRecipient);
    };
    let mut params = envelope
        .content
        .algorithm
        .parameters_reader_in(parent, "test.cbc.iv")?
        .unwrap();
    let value = params.expect(structured_asn1::Tag::primitive(4))?;
    let Ok(iv) = <&[u8; 16]>::try_from(value.contents()) else {
        return Ok(Attempt::Rejected);
    };
    let Some(cipher) = envelope.content.ciphertext.as_ref() else {
        return Ok(Attempt::Rejected);
    };
    let mut bytes = cipher.copy_in(parent, "test.cbc.ciphertext", cipher.span().start)?;
    // Bound per-block decryption/padding before the actual cipher call.
    work.charge_work(bytes.len() as u64 * 32 + 64)?;
    let length = match cbc::Decryptor::<aes::Aes128>::new(&key.into(), &(*iv).into())
        .decrypt_padded::<Pkcs7>(&mut bytes)
    {
        Ok(output) => output.len(),
        Err(_) => return Ok(Attempt::Rejected),
    };
    while bytes.len() > length {
        bytes.pop();
    }
    Ok(Attempt::Decrypted(bytes))
}
fn retain(bound: &Bound<'_>, work: &Execution<'_>) -> Result<OwnedVec<u8>, MemoryError> {
    let mut out = work.vector();
    for value in bound.attributes() {
        work.charge_work(1)?;
        out.try_push(u8::from(value.permission == Permission::Permitted))?;
    }
    Ok(out.into_owned())
}

#[test]
fn native_signed_ac_kw_cbc_binding_controls_and_multiple_recipient_sets() {
    // Real signature, actual PKIX holder path, key unwrap and padded AES-CBC
    // produce source-bound attributes; no signature or status hash is repeated.
    let plain = clear(
        b" authority ",
        &[5],
        &[attr(&[42]), attr(&[43]), attr(&[43])],
    );
    let values = [envelope(&plain), envelope(&plain)];
    setup!(&values, ac, reader, checked, work, crypto);
    let encrypted = Encrypted::read(&ac, &reader).unwrap().unwrap();
    assert_eq!(encrypted.envelopes().len(), 2);
    let calls = crypto.calls.get();
    let baseline = work.used();
    let out = encrypted
        .decrypt_all(&checked, &reader, |e, w| native(e, w, &reader), retain)
        .unwrap();
    assert_eq!(crypto.calls.get(), calls);
    for value in &out {
        let Decrypted::Processed(value) = value else {
            panic!("bound plaintext")
        };
        assert_eq!(&**value, &[0, 1, 1]);
    }
    assert!(work.used() > baseline);
    drop(out);
    assert_eq!(work.used(), baseline);
}
#[test]
fn ciphertext_stealing_serial_issuer_and_original_receipt_refuse() {
    // Same valid decryption cannot be moved to another AA/serial/AC object.
    for (name, serial, expected) in [
        (b"Other".as_slice(), &[5][..], Rejection::Issuer),
        (b"Authority".as_slice(), &[6][..], Rejection::Serial),
    ] {
        let values = [envelope(&clear(name, serial, &[attr(&[42])]))];
        setup!(&values, ac, reader, checked, work, crypto);
        let encrypted = Encrypted::read(&ac, &reader).unwrap().unwrap();
        let seen = Cell::new(0);
        let out = encrypted
            .decrypt_all(
                &checked,
                &reader,
                |e, w| native(e, w, &reader),
                |_, _| {
                    seen.set(seen.get() + 1);
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
        assert!(matches!(out[0],Decrypted::Rejected(reason) if reason==expected));
        assert_eq!(seen.get(), 0);
        let other_parser = Parser::der(generous());
        let other = read_ac(&other_parser, ac.element().as_bytes());
        let other_reader = other_parser.read(ac.element().as_bytes(), 900).unwrap();
        let other_encrypted = Encrypted::read(&other, &other_reader).unwrap().unwrap();
        let result = other_encrypted.decrypt_all(
            &checked,
            &other_reader,
            |_, _| panic!("foreign receipt must preflight"),
            |_, _| Ok::<_, ()>(()),
        );
        assert!(matches!(result,Err(DecryptError::<(),()>::Processing(e)) if e.is_terminal()));
    }
}
#[test]
fn malformed_plaintext_is_logical_and_callbacks_keep_original_causes() {
    // Broken DER or a trailing logical value never reaches a bound visitor.
    let mut plain = clear(b"Authority", &[5], &[attr(&[43])]);
    plain.extend([5, 0]);
    let values = [envelope(&plain)];
    setup!(&values, ac, reader, checked, work, crypto);
    let encrypted = Encrypted::read(&ac, &reader).unwrap().unwrap();
    let result = encrypted.decrypt_all(&checked, &reader, |e, w| native(e, w, &reader), retain);
    let Err(DecryptError::Plaintext { cause, source }) = result else {
        panic!("plaintext coordinates")
    };
    assert_eq!(cause.code(), structured_cms::ErrorCode::TrailingData);
    assert_eq!(cause.offset(), u64::try_from(plain.len() - 2).unwrap());
    assert_eq!(source.value, 0);
    assert_eq!(source.envelope, encrypted.envelopes()[0].element().span());
    let result = encrypted.decrypt_all(&checked, &reader, |_, _| Err(731u16), retain);
    assert!(matches!(
        result,
        Err(DecryptError::Provider { cause: 731, .. })
    ));
    let plain = clear(b"Authority", &[5], &[attr(&[43])]);
    let result = encrypted.decrypt_all(
        &checked,
        &reader,
        |_, w| {
            let mut b = w.vector();
            b.try_extend_from_slice(&plain)?;
            Ok::<_, MemoryError>(Attempt::Decrypted(b.into_owned()))
        },
        |_, _| Err::<(), _>(947u16),
    );
    assert!(matches!(
        result,
        Err(DecryptError::Visitor { cause: 947, .. })
    ));
}
#[test]
fn unavailable_keys_and_foreign_output_accounts_do_not_create_plaintext_receipts() {
    // A backend capability/key failure is not an empty successful attribute set.
    let values = [envelope(&clear(b"Authority", &[5], &[]))];
    setup!(&values, ac, reader, checked, work, crypto);
    let encrypted = Encrypted::read(&ac, &reader).unwrap().unwrap();
    for case in 0..3 {
        let result = encrypted.decrypt_all(
            &checked,
            &reader,
            |_, _| {
                Ok::<_, ()>(match case {
                    0 => Attempt::NotRecipient,
                    1 => Attempt::Unsupported,
                    _ => Attempt::Rejected,
                })
            },
            |_, _| -> Result<(), ()> { panic!("no plaintext") },
        );
        let result: OwnedVec<Decrypted<()>> = result.unwrap();
        assert!(matches!(
            (case, &result[0]),
            (0, Decrypted::NotRecipient)
                | (1, Decrypted::Unsupported)
                | (2, Decrypted::Rejected(Rejection::Decryption))
        ));
    }
    let foreign = generous();
    let result = encrypted.decrypt_all(
        &checked,
        &reader,
        |_, _| Ok::<_, ()>(Attempt::Decrypted(foreign.vector())),
        |_, _| Ok::<_, ()>(()),
    );
    assert!(matches!(result,Err(DecryptError::Processing(e)) if e.is_terminal()));
}
#[test]
fn exact_current_budgets_rollback_and_retention_after_plaintext_drop() {
    // Successful output owns only retained data; exact work succeeds, one less
    // refuses, zero capacity never reaches provider, and every late error frees
    // all prior value results rather than returning a successful prefix.
    let plain = clear(b"Authority", &[5], &[attr(&[43])]);
    let values = [envelope(&plain), envelope(&plain)];
    setup!(&values, ac, reader, checked, work, crypto);
    let encrypted = Encrypted::read(&ac, &reader).unwrap().unwrap();
    let account = generous();
    let query = reader
        .parser()
        .read_as(ac.element().as_bytes(), 900, Encoding::Der)
        .unwrap()
        .with_execution(&account);
    let out = encrypted
        .decrypt_all(&checked, &query, |e, w| native(e, w, &query), retain)
        .unwrap();
    let exact = account.work_used();
    assert!(account.used() > 0);
    drop(query);
    for value in &out {
        let Decrypted::Processed(value) = value else {
            panic!()
        };
        assert_eq!(&**value, &[1]);
    }
    drop(out);
    assert_eq!(account.used(), 0);
    for limit in [exact, exact - 1] {
        let account = memory(1 << 22, limit);
        let query = reader
            .parser()
            .read_as(ac.element().as_bytes(), 900, Encoding::Der)
            .unwrap()
            .with_execution(&account);
        let out = encrypted.decrypt_all(&checked, &query, |e, w| native(e, w, &query), retain);
        assert_eq!(out.is_ok(), limit == exact);
        drop(out);
        assert_eq!(account.used(), 0);
    }
    let account = memory(0, 1 << 28);
    let query = reader
        .parser()
        .read_as(ac.element().as_bytes(), 900, Encoding::Der)
        .unwrap()
        .with_execution(&account);
    let out = encrypted.decrypt_all(
        &checked,
        &query,
        |_, _| panic!("zero report capacity"),
        retain,
    );
    assert!(matches!(out,Err(DecryptError::<(),MemoryError>::Processing(e)) if e.is_resource()));
    let baseline = work.used();
    let count = Cell::new(0);
    let out = encrypted.decrypt_all(
        &checked,
        &reader,
        |e, w| native(e, w, &reader),
        |b, w| {
            count.set(count.get() + 1);
            if count.get() == 2 {
                Err(MemoryError::WorkExceeded)
            } else {
                retain(b, w)
            }
        },
    );
    assert!(matches!(
        out,
        Err(DecryptError::Visitor {
            cause: MemoryError::WorkExceeded,
            ..
        })
    ));
    assert_eq!(work.used(), baseline);
}

#[test]
fn current_local_ceiling_and_original_source_are_not_reset_by_decryption() {
    // A broad new account must not widen a current query's local ceiling or
    // erase work already spent by the original AC parser before decryption.
    let plain = clear(b"Authority", &[5], &[attr(&[43])]);
    let values = [envelope(&plain)];
    setup!(&values, ac, reader, checked, work, crypto);
    let encrypted = Encrypted::read(&ac, &reader).unwrap().unwrap();
    let account = generous();
    let operation = Parser::der(account.clone());
    let q = operation.read(&[], 0).unwrap();
    let before = account.work_used();
    let query = reader
        .parser()
        .read_query_in(
            &q,
            ac.element().as_bytes(),
            ac.element().span().start,
            Encoding::Der,
            0,
        )
        .unwrap();
    let output = encrypted
        .decrypt_all(&checked, &query, |e, w| native(e, w, &query), retain)
        .unwrap();
    let exact = account.work_used() - before;
    drop(output);
    assert_eq!(account.used(), 0);
    for ceiling in [0, exact, exact - 1] {
        let account = generous();
        let op = Parser::new(
            Encoding::Der,
            Limits {
                max_work: ceiling as u64,
                ..Limits::default()
            },
            account.clone(),
        );
        let root = op.read(&[], 0).unwrap();
        let query = reader.parser().read_query_in(
            &root,
            ac.element().as_bytes(),
            ac.element().span().start,
            Encoding::Der,
            0,
        );
        if ceiling == 0 {
            assert!(query.unwrap_err().is_resource());
            assert_eq!(account.used(), 0);
            continue;
        }
        let query = query.unwrap();
        let output = encrypted.decrypt_all(&checked, &query, |e, w| native(e, w, &query), retain);
        assert_eq!(output.is_ok(), ceiling == exact);
        drop(output);
        assert_eq!(account.used(), 0);
    }
    let source = reader.execution();
    source.charge_work(source.work_remaining() as u64).unwrap();
    let fresh = generous();
    let current = reader.parser().read(&[], 0).unwrap().with_execution(&fresh);
    let result = encrypted.decrypt_all(
        &checked,
        &current,
        |_, _| panic!("exhausted original source"),
        retain,
    );
    assert!(matches!(result,Err(DecryptError::<(),MemoryError>::Processing(e)) if e.is_resource()));
    assert_eq!(fresh.used(), 0);
}
#[test]
fn decrypted_nesting_keeps_ciphertext_depth_and_returns_no_partial_output() {
    // Decryption creates logical bytes, not a fresh default-depth ASN.1 domain.
    let plain = clear(b"Authority", &[5], &[attr(&[43])]);
    let values = [envelope(&plain)];
    setup!(&values, ac, reader, checked, work, crypto);
    let encrypted = Encrypted::read(&ac, &reader).unwrap().unwrap();
    let account = generous();
    let current = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 0,
            ..Limits::default()
        },
        account.clone(),
    );
    let query = current.read(&[], 0).unwrap();
    let query = reader
        .parser()
        .read_query_in(
            &query,
            ac.element().as_bytes(),
            ac.element().span().start,
            Encoding::Der,
            0,
        )
        .unwrap();
    let result = encrypted.decrypt_all(
        &checked,
        &query,
        |_, w| {
            let mut out = w.vector();
            out.try_extend_from_slice(&plain)?;
            Ok::<_, MemoryError>(Attempt::Decrypted(out.into_owned()))
        },
        |_, _| -> Result<(), ()> { panic!("unfunded nested decoder") },
    );
    assert!(matches!(result,Err(DecryptError::Plaintext{cause,..}) if cause.is_resource()));
    assert_eq!(account.used(), 0);
}
#[test]
fn decrypted_receipt_outputs_survive_every_temporary_parser_and_model() {
    // Only explicitly retained owned results leave the callback and retain
    // their capacity after plaintext, AC models, receipts and parsers drop.
    let (output, account) = {
        let values = [envelope(&clear(b"Authority", &[5], &[attr(&[43])]))];
        setup!(&values, ac, reader, checked, work, crypto);
        let encrypted = Encrypted::read(&ac, &reader).unwrap().unwrap();
        let output = encrypted
            .decrypt_all(&checked, &reader, |e, w| native(e, w, &reader), retain)
            .unwrap();
        (output, work.clone())
    };
    assert!(account.used() > 0);
    let Decrypted::Processed(value) = &output[0] else {
        panic!()
    };
    assert_eq!(&**value, &[1]);
    drop(output);
    assert_eq!(account.used(), 0);
}
#[test]
fn complete_encrypted_value_preflight_and_plaintext_der_are_mandatory() {
    // No valid prefix escapes if a later ContentInfo is malformed; decoded
    // nonminimal serials and hostile opaque-value depth cannot become facts.
    let good = envelope(&clear(b"Authority", &[5], &[attr(&[43])]));
    let bad = seq(&[&tlv(6, &[42, 3]), &tlv(160, &[5, 0])]);
    let values = [good, bad];
    setup!(&values, ac, reader, checked, work, crypto);
    let before = work.used();
    assert!(Encrypted::read(&ac, &reader).is_err());
    assert_eq!(work.used(), before);
    assert!(core::ptr::eq(
        checked.certificate(),
        core::ptr::from_ref(&ac)
    ));
    for plain in [clear(b"Authority", &[0, 5], &[attr(&[43])]), {
        let mut deep = vec![5, 0];
        for _ in 0..=Limits::default().max_depth {
            deep = seq(&[&deep]);
        }
        clear(b"Authority", &[5], &[seq(&[&[6, 1, 43], &tlv(49, &deep)])])
    }] {
        let values = [envelope(&plain)];
        setup!(&values, ac, reader, checked, work, crypto);
        let encrypted = Encrypted::read(&ac, &reader).unwrap().unwrap();
        let before = work.used();
        let result = encrypted.decrypt_all(
            &checked,
            &reader,
            |e, w| native(e, w, &reader),
            |_, _| -> Result<(), ()> { panic!("malformed plaintext") },
        );
        assert!(matches!(result, Err(DecryptError::Plaintext { .. })));
        // The located error may itself retain accounted diagnostic capacity.
        drop(result);
        assert_eq!(work.used(), before);
    }
}
