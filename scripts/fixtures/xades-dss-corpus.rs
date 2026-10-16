//! Public DSS corpus decoded by shared code and independent XML/CMS oracles.
//! XML signature/archive coverage and trust are not fabricated by this harness.

use std::{path::PathBuf, sync::Arc};
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_cms::timestamp::Token;

#[path = "../../crates/structured-xades/tests/containers.rs"]
mod common_inputs;

#[test]
fn independent_timestamp_and_archive_inputs_match_the_signed_imprints() {
    // Actual C14N/reference octets from the independent fixture drive the SAME
    // common Input used by all other timestamp and archive routes.
    let directory = PathBuf::from(std::env::var_os("XADES_DSS_CORPUS").unwrap());
    common_inputs::independent_corpus::check(&directory);
}

#[test]
fn independent_signature_and_archive_tokens_preserve_original_readings() {
    // The SHA256-pinned upstream XML has a signature timestamp and an archive
    // timestamp. OpenSSL independently verifies each CMS signature/eContent;
    // fixed expected imprints below come from its RFC3161 decoder.
    let directory = PathBuf::from(std::env::var_os("XADES_DSS_CORPUS").unwrap());
    let expected = [
        "b3d8aeb10b119f6513ca9c67b65e6ebe915034e3b0aec8a0c89dc42f17ec3bf7",
        "b49d025c7282021bfc5566a5325ef05abafce46fa810862a6fad5b0c0219c9bf",
    ];
    for (ordinal, imprint) in expected.iter().enumerate() {
        let original = std::fs::read(directory.join(format!("token-{ordinal}.der"))).unwrap();
        let extracted = std::fs::read(directory.join(format!("tstinfo-{ordinal}.der"))).unwrap();
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 24, 1 << 28)));
        let parser = Parser::ber(memory.clone());
        let token = Token::read(&parser, &original, 400).unwrap();
        assert!(token.faults().is_empty(), "{:?}", token.faults());
        let operation = parser.read(&[], 900).unwrap();
        assert_eq!(
            token.message().content().content().unwrap().as_one(),
            Some(extracted.as_slice())
        );
        token
            .with_info(&operation, |info, _, _| {
                assert!(!info.has_faults(), "{:?}", info.faults());
                assert_eq!(info.policy().as_bytes(), &[0x2a, 3, 4]);
                assert_eq!(info.imprint().hashed().len(), 32);
                let actual = info.imprint().hashed().as_one().unwrap();
                for (byte, hex) in actual.iter().zip(imprint.as_bytes().chunks_exact(2)) {
                    assert_eq!(
                        *byte,
                        u8::from_str_radix(std::str::from_utf8(hex).unwrap(), 16).unwrap()
                    );
                }
                assert!(info.accuracy().is_none());
                assert!(info.nonce().is_none());
                assert!(!info.ordering());
                assert!(!info.gen_time().has_subnanosecond_remainder());
                Ok::<_, ()>(())
            })
            .unwrap();
        drop(token);
        assert_eq!(memory.used(), 0);
    }
}
