//! Common policy URI grammar and current execution qualification.

use std::sync::Arc;
use structured_asn1::{
    Encoding, Limits, Parser,
    memory::{Memory, MemoryAccount, MemoryError},
};

#[test]
fn generic_uri_syntax_keeps_cps_rules_and_admits_its_whole_scan() {
    // RFC3986 URI syntax must not inherit certificate-name host restrictions.
    // Each call pays before examining text, even when the URI is malformed.
    for (uri, expected) in [
        ("file:///policy", true),
        ("urn:example:policy", true),
        ("https://local_host/policy#part", true),
        ("https://example/%G0", false),
        ("relative/policy", false),
        ("https://example/has space", false),
    ] {
        let cost = uri.len() * 12 + 1;
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, cost)));
        assert_eq!(
            structured_pkix::general_name::uri_syntax(uri, &memory).unwrap(),
            expected
        );
        assert_eq!(memory.work_used(), cost);
        assert_eq!(memory.used(), 0);
        assert_eq!(
            structured_pkix::general_name::uri_syntax(uri, &memory),
            Err(MemoryError::WorkExceeded)
        );
    }
}

#[test]
fn policy_uri_query_preserves_the_producing_local_ceiling() {
    // A large shared account cannot bypass the active producing ceiling.
    let memory = Memory::new(Arc::new(MemoryAccount::new(0, 10000)));
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 8,
            ..Limits::default()
        },
        memory.clone(),
    );
    let reader = parser.read(&[], 900).unwrap();
    assert_eq!(
        structured_pkix::general_name::uri_syntax("urn:policy", &reader.execution()),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(memory.used(), 0);
}
