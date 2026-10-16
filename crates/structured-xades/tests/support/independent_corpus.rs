//! Independent C14N outputs exercising the actual common timestamp stream.

use super::*;
use std::path::Path;

/// Called by the pinned external corpus runner, not a fabricated XML verifier.
/// Native source lookup/C14N budgeting still needs its separate XML adapter gate.
///
/// # Panics
/// Fails the qualification if an oracle file is missing or common input bytes
/// differ from the independently verified timestamp/archive imprint.
pub fn check(directory: &Path) {
    // The test double owns only the fixed original geometry and oracle bytes.
    // libxml2 supplies real C14N; xmlsec/OpenSSL separately verified XML/CMS
    // math. Common Input must select ALL nine archive pieces in exact order.
    let mut xml = Tree::normal();
    let certificates = append(&mut xml, 7, XADES, "CertificateValues");
    let revocations = append(&mut xml, 7, XADES, "RevocationValues");
    let archive = append(&mut xml, 7, XADES_141, "ArchiveTimeStamp");
    append(&mut xml, archive, DS, "CanonicalizationMethod");
    append(&mut xml, archive, XADES, "EncapsulatedTimeStamp");
    let object = append(&mut xml, 0, DS, "Object");
    append(&mut xml, 8, DS, "CanonicalizationMethod");
    append(&mut xml, 8, XADES, "EncapsulatedTimeStamp");
    for (ordinal, node) in [9, 12, 13, 8, certificates, revocations, object]
        .iter()
        .enumerate()
    {
        xml.canonical_routes.push((
            *node,
            std::fs::read(directory.join(format!("part-{}.bin", ordinal + 2))).unwrap(),
        ));
    }
    for (ordinal, node) in [10, 11].iter().enumerate() {
        xml.reference_routes.push((
            *node,
            std::fs::read(directory.join(format!("part-{ordinal}.bin"))).unwrap(),
        ));
    }
    compare(&xml, 8, directory, "signature-input.bin", 0);
    compare(&xml, archive, directory, "archive-input.bin", 1);
}

fn append(xml: &mut Tree, parent: usize, namespace: &'static str, local: &'static str) -> usize {
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(parent), namespace, local));
    node
}

fn compare(xml: &Tree, node: usize, directory: &Path, expected: &str, token: usize) {
    use sha2::{Digest, Sha256};
    // Check exact bytes BEFORE their digest: omitting an apparently redundant
    // final ds:Object must not pass merely because all references were verified.
    let memory = funded();
    let access = Access::new(xml, xml.snapshot(), &memory);
    let bound = binding::bind(&access, &container::locate(&access, 0).unwrap()).unwrap();
    let stamp = timestamp::read(&access, &bound, node).unwrap();
    let mut input = Input::prepare(xml, &bound, &stamp, &memory).unwrap();
    let mut sink = Collect::new(&memory);
    stream::run(
        &mut input,
        &mut sink,
        &memory,
        "independent.timestamp.input",
        0,
    )
    .unwrap();
    assert_eq!(
        sink.bytes(),
        std::fs::read(directory.join(expected)).unwrap()
    );
    let source = std::fs::read(directory.join(format!("token-{token}.der"))).unwrap();
    let parser = structured_asn1::Parser::ber(memory.clone());
    let actual = structured_cms::timestamp::Token::read(&parser, &source, 400).unwrap();
    let operation = parser.read(&[], 900).unwrap();
    actual
        .with_info(&operation, |info, _, _| {
            assert!(!info.has_faults());
            assert_eq!(
                Sha256::digest(sink.bytes()).as_slice(),
                info.imprint().hashed().as_one().unwrap()
            );
            Ok::<_, ()>(())
        })
        .unwrap();
}
