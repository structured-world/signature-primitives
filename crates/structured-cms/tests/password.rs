//! OpenSSL interoperability, admission, and cleanup for password containers.
#![cfg(feature = "password-protection")]

use std::sync::Arc;
use structured_asn1::{
    Parser, Reader,
    memory::{Memory, MemoryAccount, MemoryError},
};
use structured_cms::personal::{
    self, Backend, Bag, Decision, Integrity, Pfx, Plaintext, PrivateKey, Safe, ShroudedKey, Source,
    password::{Authentication, Cost, Decryption, Error, Password},
};

const CLEAR: &[u8] = include_bytes!("fixtures/password/plain.der");
const PBKDF2: &[u8] = include_bytes!("fixtures/password/pbkdf2.der");
const SCRYPT: &[u8] = include_bytes!("fixtures/password/scrypt.der");
const PASSWORD: Password<'static> = Password::Octets(b"fixture");
const LEGACY: Password<'static> = Password::Legacy(b"\0f\0i\0x\0t\0u\0r\0e\0\0");

fn memory(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, work)))
}

fn scratch(base: Cost, extra: Cost) -> Vec<u8> {
    vec![0xa5; base.scratch + extra.scratch]
}

#[test]
fn encrypted_pkcs8_matches_openssl() {
    // Multi-lane scrypt exercises reuse of V/T and the last PBKDF2 pass.
    for input in [PBKDF2, SCRYPT] {
        let parser = Parser::der(memory(1 << 27));
        let mut query = parser.read(input, 0).unwrap();
        let element = query.next_element().unwrap().unwrap();
        let key = ShroudedKey::read(&query, &element).unwrap();
        let plan = Decryption::key(&key, &query).unwrap();
        let base = plan.cost().unwrap();
        let mut scratch = scratch(base, plan.password_cost(PASSWORD).unwrap());
        if input == SCRYPT {
            assert_eq!(base.scratch, 128 * 2 * (16 + 2 + 1));
        }
        let mut output = vec![0xa5; base.output + 1];
        let count = plan
            .decrypt(PASSWORD, &mut output, &mut scratch, &query)
            .unwrap();
        assert_eq!(&output[..count], CLEAR);
        assert!(output[count..base.output].iter().all(|&byte| byte == 0));
        assert_eq!(output[base.output], 0xa5);
        assert!(scratch.iter().all(|&byte| byte == 0));
    }
}

#[test]
fn refusals_precede_mutation_and_wrong_password_wipes() {
    // Refused work and short scratch do not write into either buffer.
    let parser = Parser::der(memory(1 << 27));
    let mut query = parser.read(SCRYPT, 0).unwrap();
    let element = query.next_element().unwrap().unwrap();
    let key = ShroudedKey::read(&query, &element).unwrap();
    let plan = Decryption::key(&key, &query).unwrap();
    let base = plan.cost().unwrap();
    let mut scratch = scratch(base, plan.password_cost(PASSWORD).unwrap());
    let mut output = vec![0xa5; base.output];
    assert!(matches!(
        plan.decrypt(PASSWORD, &mut output, &mut [], &query),
        Err(Error::Buffer)
    ));
    let refused = query.with_execution(&memory(0));
    assert!(matches!(
        plan.decrypt(PASSWORD, &mut output, &mut scratch, &refused),
        Err(Error::Resource(MemoryError::WorkExceeded))
    ));
    assert!(output.iter().chain(&scratch).all(|&byte| byte == 0xa5));
    assert!(matches!(
        plan.decrypt(
            Password::Octets(b"wrong"),
            &mut output,
            &mut scratch,
            &refused.with_execution(&memory(1 << 27))
        ),
        Err(Error::Rejected)
    ));
    assert!(output.iter().chain(&scratch).all(|&byte| byte == 0));
}

struct Consumer(Option<Plaintext>);

fn password(legacy: bool) -> Password<'static> {
    if legacy { LEGACY } else { PASSWORD }
}

fn decrypt(plan: &Decryption<'_, '_>, query: &Reader<'_>) -> Result<Plaintext, Error> {
    let password = password(plan.uses_legacy_password());
    let mut workspace = scratch(plan.cost()?, plan.password_cost(password)?);
    let result = plan.decrypt_owned(password, &mut workspace, query);
    assert!(workspace.iter().all(|&byte| byte == 0));
    result
}

impl Backend for Consumer {
    type Error = Error;

    fn authenticate(
        &mut self,
        integrity: &Integrity<'_>,
        query: &Reader<'_>,
    ) -> Result<Decision, Error> {
        let plan = Authentication::prepare(integrity, query)?.unwrap();
        let password = password(plan.uses_legacy_password());
        let mut workspace = scratch(plan.cost()?, plan.password_cost(password)?);
        plan.verify(password, &mut workspace, query)?;
        assert!(workspace.iter().all(|&byte| byte == 0));
        Ok(Decision::Accept)
    }

    fn decrypt_safe(
        &mut self,
        safe: &Safe<'_>,
        query: &Reader<'_>,
        _: &Source<'_>,
    ) -> Result<Plaintext, Error> {
        let Safe::Encrypted(safe) = safe else {
            return Err(Error::Unsupported);
        };
        decrypt(&Decryption::safe(safe, query)?, query)
    }

    fn decrypt_key(
        &mut self,
        key: &ShroudedKey<'_>,
        query: &Reader<'_>,
        _: &Source<'_>,
    ) -> Result<Plaintext, Error> {
        decrypt(&Decryption::key(key, query)?, query)
    }

    fn bag(&mut self, _: &Bag<'_>, _: &Reader<'_>, _: &Source<'_>) -> Result<(), Error> {
        Ok(())
    }

    fn key(&mut self, _: &PrivateKey<'_>, _: &Reader<'_>, _: &Source<'_>) -> Result<(), Error> {
        Ok(())
    }

    fn retain_key(&mut self, plaintext: Plaintext) -> Result<(), Error> {
        self.0 = Some(plaintext);
        Ok(())
    }
}

#[test]
fn pfx_authenticates_and_imports_both_privacy_layers() {
    // Full import uses the same engine for a safe and a shrouded key.
    for input in [
        include_bytes!("fixtures/password/legacy-mac.p12").as_slice(),
        include_bytes!("fixtures/password/pbmac1.p12").as_slice(),
        include_bytes!("fixtures/password/legacy-pbe.p12").as_slice(),
    ] {
        let parser = Parser::ber(memory(1 << 27));
        let mut query = parser.read(input, 0).unwrap();
        let pfx = Pfx::read(&mut query).unwrap();
        let plan = Authentication::prepare(pfx.integrity(), &query)
            .unwrap()
            .unwrap();
        let wrong = if plan.uses_legacy_password() {
            Password::Legacy(b"\0x\0\0")
        } else {
            Password::Octets(b"wrong")
        };
        let mut workspace = scratch(plan.cost().unwrap(), plan.password_cost(wrong).unwrap());
        assert!(matches!(
            plan.verify(wrong, &mut workspace, &query),
            Err(Error::Rejected)
        ));
        assert!(workspace.iter().all(|&byte| byte == 0));
        let mut consumer = Consumer(None);
        personal::process(&pfx, &query, &mut consumer).unwrap();
        assert_eq!(consumer.0.unwrap().as_bytes(), CLEAR);
    }
}
