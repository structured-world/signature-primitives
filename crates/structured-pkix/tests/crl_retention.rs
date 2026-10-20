//! X.509 `expiredCertsOnCRL`: the time from which a CRL keeps expired certificates.

use std::sync::Arc;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_pkix::crl::{CertificateList, EntryLookup};

const EXPIRED: [u8; 3] = [0x55, 0x1d, 0x3c];

fn memory(work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(128 * 1024, work)))
}
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if contents.len() < 128 {
        result.push(u8::try_from(contents.len()).unwrap());
    } else {
        result.extend_from_slice(&[0x81, u8::try_from(contents.len()).unwrap()]);
    }
    result.extend_from_slice(contents);
    result
}
fn algorithm() -> Vec<u8> {
    tlv(48, &[6, 3, 0x2a, 3, 4])
}
fn issuer() -> Vec<u8> {
    tlv(48, &tlv(49, &tlv(48, &[6, 3, 0x55, 4, 3, 12, 1, b'A'])))
}
fn date() -> Vec<u8> {
    tlv(23, b"261012120000Z")
}
fn crl(signed: &[u8]) -> Vec<u8> {
    tlv(48, &[signed, &algorithm(), &[3, 2, 0, 0xab]].concat())
}
fn extension(kind: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let flag: &[u8] = if critical { &[1, 1, 0xff] } else { &[] };
    tlv(48, &[&tlv(6, kind)[..], flag, &tlv(4, value)].concat())
}
fn list(extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut tbs = vec![2, 1, 1];
    tbs.extend(algorithm());
    tbs.extend(issuer());
    tbs.extend(date());
    if !extensions.is_empty() {
        tbs.extend(tlv(0xa0, &tlv(48, &extensions.concat())));
    }
    crl(&tlv(48, &tbs))
}
fn issuer_certificate() -> Vec<u8> {
    let mut signed = vec![2, 1, 1];
    signed.extend(algorithm());
    signed.extend(issuer());
    signed.extend(tlv(48, &[date(), date()].concat()));
    signed.extend(issuer());
    signed.extend(tlv(48, &[algorithm(), tlv(3, &[0, 7])].concat()));
    crl(&tlv(48, &signed))
}

struct SignatureYes;
impl structured_pkix::path::Verify for SignatureYes {
    type Error = std::convert::Infallible;
    fn verify(
        &self,
        _: &structured_pkix::AlgorithmIdentifier<'_>,
        _: structured_pkix::path::WorkingKey<'_>,
        _: &[u8],
        _: structured_asn1::BitString<'_>,
        _: &Memory,
    ) -> Result<structured_pkix::path::Verified, Self::Error> {
        Ok(structured_pkix::path::Verified::Yes)
    }
}

fn lookup(
    parsed: &CertificateList<'_>,
    issuer: &structured_pkix::Certificate<'_>,
    execution: &Memory,
) -> structured_pkix::Result<bool> {
    let structured_pkix::crl::Authentication::Authenticated(proof) = parsed
        .authenticate(
            issuer,
            structured_pkix::path::WorkingKey::standing(issuer.tbs().public_key()),
            &SignatureYes,
            execution,
        )
        .unwrap()
    else {
        panic!("fixture authority refused")
    };
    proof
        .entry(issuer, execution)
        .map(|found| matches!(found, EntryLookup::Absent))
}

#[test]
fn expired_certs_on_crl_is_read_and_understood_by_lookup() {
    // X.509 defines the value as GeneralizedTime; the lookup understands it
    // rather than ignoring it, and its absence stays absent.
    let execution = memory(1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = issuer_certificate();
    let issuer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let bytes = list(&[extension(&EXPIRED, false, &tlv(24, b"20190101000000Z"))]);
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    let time = parsed
        .tbs()
        .expired_certs_on_crl(&execution)
        .unwrap()
        .unwrap();
    assert_eq!(time.start().seconds(), 1_546_300_800);
    assert!(lookup(&parsed, &issuer, &execution).unwrap());
    let bytes = list(&[]);
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    assert!(
        parsed
            .tbs()
            .expired_certs_on_crl(&execution)
            .unwrap()
            .is_none()
    );
}

#[test]
fn expired_certs_on_crl_accepts_der_fractional_seconds() {
    // X.509 ExpiredCertsOnCRL is bare GeneralizedTime. Both the accessor
    // and authenticated entry lookup must accept a canonical DER fraction.
    let execution = memory(1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = issuer_certificate();
    let issuer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    for (label, nanos, remainder) in [
        (&b"20190101000000.5Z"[..], 500_000_000, false),
        (&b"20190101000000.123456789Z"[..], 123_456_789, false),
        (&b"20190101000000.0000000001Z"[..], 0, true),
        (&b"20190101000000.9999999999Z"[..], 999_999_999, true),
    ] {
        let bytes = list(&[extension(&EXPIRED, false, &tlv(24, label))]);
        let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
        let time = parsed
            .tbs()
            .expired_certs_on_crl(&execution)
            .unwrap()
            .unwrap();
        assert_eq!(time.start().seconds(), 1_546_300_800);
        assert_eq!(time.start().nanos(), nanos);
        assert_eq!(time.has_subnanosecond_remainder(), remainder);
        assert!(lookup(&parsed, &issuer, &execution).unwrap());
    }
}

#[test]
fn malformed_expired_certs_on_crl_is_a_located_fault_in_both_readings() {
    // UTCTime, a second value and an impossible calendar are not one
    // GeneralizedTime; neither the accessor nor the lookup may ignore them.
    let execution = memory(1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = issuer_certificate();
    let issuer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    for value in [
        tlv(23, b"190101000000Z"),
        [tlv(24, b"20190101000000Z"), vec![5, 0]].concat(),
        tlv(24, b"20191301000000Z"),
        tlv(24, b"20190101000000.0Z"),
        tlv(24, b"20190101000000.50Z"),
        tlv(24, b"20190101000000,5Z"),
        tlv(24, b"20190101000000.5+0000"),
    ] {
        let flagged = extension(&EXPIRED, false, &value);
        let bytes = list(std::slice::from_ref(&flagged));
        let at = 600
            + u64::try_from(
                bytes
                    .windows(flagged.len())
                    .position(|window| window == flagged)
                    .unwrap(),
            )
            .unwrap();
        let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
        let error = parsed.tbs().expired_certs_on_crl(&execution).unwrap_err();
        assert!(!error.is_resource(), "{error:?}");
        assert!(error.offset() >= at, "{error:?}");
        let again = lookup(&parsed, &issuer, &execution).unwrap_err();
        assert_eq!(again.code(), error.code());
    }
}

#[test]
fn critical_expired_certs_on_crl_is_a_located_fault_in_both_readings() {
    // X.509 makes the extension always non-critical: a critical one is a
    // malformed list, never retention coverage for an expired certificate.
    let execution = memory(1_000_000);
    let parser = Parser::der(execution.clone());
    let issuer_bytes = issuer_certificate();
    let issuer = structured_pkix::Certificate::read(&parser, &issuer_bytes, 100).unwrap();
    let flagged = extension(&EXPIRED, true, &tlv(24, b"20190101000000Z"));
    let bytes = list(std::slice::from_ref(&flagged));
    let at = 600
        + u64::try_from(
            bytes
                .windows(flagged.len())
                .position(|window| window == flagged)
                .unwrap(),
        )
        .unwrap();
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    let error = parsed.tbs().expired_certs_on_crl(&execution).unwrap_err();
    assert_eq!(error.code(), structured_pkix::ErrorCode::MalformedValue);
    assert_eq!(error.offset(), at);
    let again = lookup(&parsed, &issuer, &execution).unwrap_err();
    assert_eq!(again.code(), structured_pkix::ErrorCode::MalformedValue);
    assert_eq!(again.offset(), at);
}

#[test]
fn expired_certs_on_crl_reading_charges_the_current_execution() {
    // A spent ceiling is a resource refusal, never an absent extension.
    let execution = memory(1_000_000);
    let parser = Parser::der(execution.clone());
    let bytes = list(&[extension(&EXPIRED, false, &tlv(24, b"20190101000000Z"))]);
    let parsed = CertificateList::read(&parser, &bytes, 600).unwrap();
    let error = parsed.tbs().expired_certs_on_crl(&memory(0)).unwrap_err();
    assert!(error.is_resource(), "{error:?}");
}
