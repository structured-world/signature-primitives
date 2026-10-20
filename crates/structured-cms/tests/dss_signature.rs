//! Public RFC 6979 P-256 scalars through common CMS source/DER boundaries.
//! The fixed-curve engine and its cost allowance are test-only, not a backend
//! qualification or a production signature-policy decision.

use core::cell::Cell;
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, Work};
use structured_asn1::{Encoding, Integer, Parser};
use structured_cms::Octets;
use structured_cms::content_source::ContentError;
use structured_pkix::signature::DssValue;
use structured_pkix::{Error, ErrorCode};

#[derive(Debug)]
enum Failure {
    Pkix(Error),
    Cms(structured_cms::Error),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Pkix(error)
    }
}

impl From<structured_cms::Error> for Failure {
    fn from(error: structured_cms::Error) -> Self {
        Self::Cms(error)
    }
}

impl core::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pkix(error) => error.fmt(formatter),
            Self::Cms(error) => error.fmt(formatter),
        }
    }
}

fn memory(bytes: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(bytes, 1_000_000)))
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut bytes = [0; N];
    for (target, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |value| match value {
            b'0'..=b'9' => value - b'0',
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("invalid public vector"),
        };
        *target = digit(pair[0]) * 16 + digit(pair[1]);
    }
    bytes
}

fn vector() -> (VerifyingKey, [u8; 32], Vec<u8>) {
    // RFC 6979 Appendix A.2.5: P-256, SHA-256, message "sample".
    // https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5
    let mut public = [0; 65];
    public[0] = 4;
    public[1..33].copy_from_slice(&hex::<32>(
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
    ));
    public[33..].copy_from_slice(&hex::<32>(
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
    ));
    let hash = hex("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF");
    let mut signature = vec![0x30, 0x46, 2, 0x21, 0];
    signature.extend_from_slice(&hex::<32>(
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
    ));
    signature.extend_from_slice(&[2, 0x21, 0]);
    signature.extend_from_slice(&hex::<32>(
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ));
    (
        VerifyingKey::from_sec1_bytes(&public).unwrap(),
        hash,
        signature,
    )
}

fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() < 128);
    let mut output = vec![tag, u8::try_from(bytes.len()).unwrap()];
    output.extend_from_slice(bytes);
    output
}

fn carried(bytes: &[u8], segmented: bool) -> Vec<u8> {
    if !segmented {
        return tlv(4, bytes);
    }
    let middle = bytes.len() / 2;
    let mut pieces = tlv(4, &bytes[..middle]);
    pieces.extend(tlv(4, &bytes[middle..]));
    tlv(0x24, &pieces)
}

fn scalar(integer: Integer<'_>, work: &impl Work, at: u64) -> Result<Option<[u8; 32]>, Error> {
    let refuse = |reason| Error::resource(reason, "signatureValue", at);
    work.charge_work(1).map_err(refuse)?;
    if integer.is_negative() {
        return Ok(None);
    }
    let bytes = match integer.as_bytes() {
        [0, rest @ ..] => rest,
        all => all,
    };
    if bytes.len() > 32 {
        return Ok(None);
    }
    work.charge_work(32 + bytes.len() as u64).map_err(refuse)?;
    let mut result = [0; 32];
    result[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(Some(result))
}

#[test]
fn public_signature_verifies_from_scalars_without_another_der_decoder() {
    // The common reader supplies r/s to the selected backend, including high-S
    // and required sign pads. Joined temporary bytes cannot escape the callback.
    // Changed content still fails the actual signature arithmetic.
    let (key, hash, signature) = vector();
    for segmented in [false, true] {
        let memory = memory(16384);
        let parser = Parser::ber(memory.clone());
        let bytes = carried(&signature, segmented);
        let mut reader = parser.read(&bytes, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let octets = Octets::read(&reader, &element, "signatureValue").unwrap();
        let held = memory.used();
        for changed in [false, true] {
            let mut hash = hash;
            if changed {
                hash[0] ^= 1;
            }
            let verified = octets
                .with_nested_reader(
                    &reader,
                    Encoding::Der,
                    "signatureValue",
                    |input, context| {
                        let value = DssValue::read(input, "signatureValue")?;
                        let work = input.execution();
                        let ranges = context.project_span(value.r_span(), &work)?;
                        assert_eq!(ranges.len(), if segmented { 2 } else { 1 });
                        assert_eq!(
                            ranges.iter().map(|span| span.length).sum::<u64>(),
                            value.r_span().length
                        );
                        let r = scalar(value.r(), &work, value.r_span().start)?.unwrap();
                        let s = scalar(value.s(), &work, value.s_span().start)?.unwrap();
                        work.charge_work(100_000).map_err(|reason| {
                            Error::resource(reason, "signatureValue", value.element().span().start)
                        })?;
                        let signature = Signature::from_scalars(r, s).unwrap();
                        Ok::<_, Failure>(key.verify_prehash(&hash, &signature).is_ok())
                    },
                )
                .unwrap();
            assert_eq!(verified, !changed);
            assert_eq!(memory.used(), held);
        }
    }
}

#[test]
fn syntactically_readable_invalid_scalars_never_become_a_valid_signature() {
    // Decoding INTEGERs is not acceptance. The backend rejects zero, a
    // negative number, and a positive number outside this curve's order.
    for bytes in [
        &b"\x30\x06\x02\x01\x00\x02\x01\x01"[..],
        &b"\x30\x06\x02\x01\xff\x02\x01\x01"[..],
    ] {
        let parser = Parser::der(memory(16));
        let mut reader = parser.read(bytes, 400).unwrap();
        let value = DssValue::read(&mut reader, "signatureValue").unwrap();
        let work = reader.execution();
        let r = scalar(value.r(), &work, value.r_span().start).unwrap();
        let s = scalar(value.s(), &work, value.s_span().start).unwrap();
        assert!(match (r, s) {
            (Some(r), Some(s)) => Signature::from_scalars(r, s).is_err(),
            _ => true,
        });
    }
    let (_, _, mut bytes) = vector();
    bytes[5..37].fill(0xff);
    let parser = Parser::der(memory(16));
    let mut reader = parser.read(&bytes, 400).unwrap();
    let value = DssValue::read(&mut reader, "signatureValue").unwrap();
    let work = reader.execution();
    let r = scalar(value.r(), &work, value.r_span().start)
        .unwrap()
        .unwrap();
    let s = scalar(value.s(), &work, value.s_span().start)
        .unwrap()
        .unwrap();
    assert!(Signature::from_scalars(r, s).is_err());
}

#[test]
fn a_segmented_signature_error_retains_its_physical_source_after_the_join_drops() {
    // A bad second tag is found in joined logical bytes; its retained map
    // must identify the original octet after the buffer and parsers drop.
    let (_, _, mut signature) = vector();
    signature[37] = 5;
    for segmented in [false, true] {
        let memory = memory(16384);
        let parser = Parser::ber(memory.clone());
        let bytes = carried(&signature, segmented);
        let mut reader = parser.read(&bytes, 400).unwrap();
        let element = reader.next_element().unwrap().unwrap();
        let octets = Octets::read(&reader, &element, "signatureValue").unwrap();
        let error = octets
            .with_nested_reader(&reader, Encoding::Der, "signatureValue", |input, _| {
                DssValue::read(input, "signatureValue").map(|_| ())
            })
            .unwrap_err();
        let ContentError::Callback { source, context } = &error else {
            panic!("expected located schema cause");
        };
        assert_eq!(
            source.code(),
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
        );
        drop(octets);
        drop(reader);
        drop(parser);
        assert_eq!(memory.used() > 0, segmented);
        let current = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
        assert_eq!(
            context.project_offset(source.offset(), &current).unwrap(),
            if segmented { 443 } else { 439 }
        );
        drop(error);
        assert_eq!(memory.used(), 0);
        assert_eq!(current.used(), 0);
    }
}

#[test]
fn a_segmented_query_refuses_current_storage_before_entering_the_callback() {
    // Retained fragment metadata in the old account does not fund a new
    // request's map/join allocation. Refusal must not invoke the backend.
    let (_, _, signature) = vector();
    let old = memory(16384);
    let parser = Parser::ber(old.clone());
    let bytes = carried(&signature, true);
    let mut reader = parser.read(&bytes, 400).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let octets = Octets::read(&reader, &element, "signatureValue").unwrap();
    let held = old.used();
    let current = memory(0);
    let query = reader.with_execution(&current);
    let calls = Cell::new(0);
    let result = octets.with_nested_reader(&query, Encoding::Der, "signatureValue", |_, _| {
        calls.set(calls.get() + 1);
        Ok::<_, Error>(())
    });
    assert!(matches!(result, Err(ContentError::Processing(error)) if error.is_resource()));
    assert_eq!(calls.get(), 0);
    assert_eq!(current.used(), 0);
    assert_eq!(old.used(), held);
}
