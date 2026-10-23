//! Independent eight-hash byte oracle: no writable proof or digest constructor.
#[path = "../../../tests/support/mod.rs"]
mod support;
use alloc::{vec, vec::Vec};
use core::{cell::Cell, convert::Infallible};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use structured_asn1::{Parser, memory::Work};
use structured_cms::{
    oid,
    stream::{Receiver, Refused, Source},
};
use structured_pkix::{algorithm::digest::Algorithm, temporal::LeapTable};
use support::*;

struct Detached<'a> {
    bytes: &'a [u8],
    passes: Cell<usize>,
}
impl Source for Detached<'_> {
    type Error = Infallible;
    fn stream<W: Work>(&mut self, receiver: &mut impl Receiver, _: &W) -> Result<(), Self::Error> {
        self.passes.set(self.passes.get() + 1);
        receiver.write(self.bytes).unwrap();
        Ok(())
    }
}
struct Output(Vec<u8>);
impl Receiver for Output {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Refused> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}
fn tree(items: &[Vec<u8>]) -> Vec<u8> {
    let mut hashes = items
        .iter()
        .map(|value| Sha256::digest(value).to_vec())
        .collect::<Vec<_>>();
    hashes.sort();
    Sha256::digest(hashes.concat()).to_vec()
}

fn ber_signer(encoded: &[u8]) -> Vec<u8> {
    let parser = Parser::ber(memory());
    let mut reader = parser.read(encoded, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    let signer = structured_cms::signer::SignerInfo::read(&reader, &element).unwrap();
    let fields = signer.fields();
    let sid = [&[0x30, 0x80][..], fields.identity[1].contents(), &[0, 0]].concat();
    let signature = signature_octets(encoded);
    let split = signature.len() / 2;
    let signature = tlv(
        0x24,
        &[tlv(4, &signature[..split]), tlv(4, &signature[split..])].concat(),
    );
    tlv(
        0x30,
        &[
            &[2, 0x81, 1, 1][..],
            &sid,
            fields.identity[2].as_bytes(),
            signer.signed_attributes().unwrap().element().as_bytes(),
            fields.signature[0].as_bytes(),
            &signature,
            signer.unsigned_attributes().unwrap().element().as_bytes(),
        ]
        .concat(),
    )
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "The independent complete byte oracle keeps all eight components and both carried/detached sources visible together."
)]
fn eight_hashes_bind_full_fields_duplicate_material_and_date_selected_unsigned_attributes() {
    // TS101733 §6.5.1: Hu selection is exact unsigned poeDate, not SET
    // encoding order. Duplicate material is a multiset; d* has eight digests
    // and is NOT itself hashed until the actual timestamp/ERS driver does so.
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let leaf = certificate("Leaf", "Root", &key, &root_key, false);
    let kind = &[4, 0, 0x8d, 0x45, 2, 2];
    let older = attribute(kind, &tlv(0x30, &tlv(24, b"20260101000100.0000000001Z")));
    let current = attribute(
        kind,
        &tlv(
            0x30,
            &[tlv(24, b"20260101000100.0000000002Z"), tlv(0xa0, &leaf)].concat(),
        ),
    );
    let later = attribute(kind, &tlv(0x30, &tlv(24, b"20260101000100.0000000003Z")));
    let original_unknown = attribute(&[42, 3, 4], &tlv(4, b"original opaque fact"));
    // §6.5.1 hashes Hu as stored, including a legal BER length spelling.
    let unknown = [
        &[0x30, 0x81, original_unknown[1]][..],
        &original_unknown[2..],
    ]
    .concat();
    for carried in [true, false] {
        let encoded = signer(
            Some(oid::DATA.as_bytes()),
            b"payload",
            &leaf,
            &key,
            &[],
            &[
                current.clone(),
                later.clone(),
                older.clone(),
                unknown.clone(),
            ],
        );
        let encoded = ber_signer(&encoded);
        let bytes = message(
            oid::DATA.as_bytes(),
            if carried { Some(b"payload") } else { None },
            &[root.clone(), leaf.clone()],
            &[],
            &[encoded],
        );
        let parser = Parser::ber(memory());
        let message = structured_cms::SignedData::read(&parser, &bytes, 700).unwrap();
        let parent = parser.read(&[], 700).unwrap();
        let document = crate::source::Document::new(&message, &parent).unwrap();
        let prepared = crate::prepare::Preparation::read(
            &document,
            &message.signers()[0],
            crate::Level::Basic,
            &parent,
        )
        .unwrap();
        let mut chosen = None;
        for ordinal in 0..prepared.evidence_records() {
            let view = prepared.evidence(ordinal, &parent).unwrap().unwrap();
            if view.poe().unwrap().certificates().is_some() {
                chosen = Some(view);
                break;
            }
        }
        let view = chosen.unwrap();
        let provider = Oracle::new();
        let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
        let mut detached = Detached {
            bytes: b"payload",
            passes: Cell::new(0),
        };
        let completed = view
            .components(
                &provider,
                &[Algorithm::Sha256],
                &parent,
                Some(&mut detached),
                &utc,
                &parent.execution(),
            )
            .unwrap();
        let mut output = Output(Vec::new());
        completed
            .stream::<_, Infallible>(0, &provider, &(), &mut output, &parent.execution())
            .unwrap();
        let signer = &message.signers()[0];
        let protected = signer.signed_attributes().unwrap().signed_bytes().unwrap();
        let identity = [
            vec![2, 1, 1],
            tlv(0x30, &[name("Root"), vec![2, 1, 7]].concat()),
            tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
        ]
        .concat();
        assert_ne!(signature_octets(signer.as_bytes()), [] as [u8; 0]);
        let signature = [
            tlv(0x30, &tlv(6, ECDSA)),
            tlv(
                4,
                &signer
                    .signature()
                    .pieces()
                    .iter()
                    .flat_map(|piece| piece.as_bytes())
                    .copied()
                    .collect::<Vec<_>>(),
            ),
        ]
        .concat();
        let expected = [
            Sha256::digest(tlv(6, oid::DATA.as_bytes())).to_vec(),
            Sha256::digest(b"payload").to_vec(),
            tree(&[root.clone(), leaf.clone(), leaf.clone()]),
            tree(&[]),
            Sha256::digest(identity).to_vec(),
            Sha256::digest(protected.concat()).to_vec(),
            Sha256::digest(signature).to_vec(),
            tree(&[older.clone(), unknown.clone()]),
        ]
        .concat();
        assert_eq!(output.0, expected);
        assert_eq!(output.0.len(), 8 * 32);
        assert_eq!(detached.passes.get(), usize::from(!carried));
        assert_eq!(
            provider.signatures.get(),
            0,
            "source derivation never authenticates a token"
        );
    }
}

#[test]
fn missing_signed_attributes_do_not_invent_an_empty_hs_preimage() {
    // TS101733 §6.5.1 defines Hs over the ORIGINAL signedAttrs encoding.
    // An absent field supplies no such bytes. It must not become H(empty),
    // and failure must precede detached acquisition or provider state creation.
    let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let root = certificate("Root", "Root", &root_key, &root_key, false);
    let leaf = certificate("Leaf", "Root", &key, &root_key, false);
    let poe = attribute(
        &[4, 0, 0x8d, 0x45, 2, 2],
        &tlv(0x30, &tlv(24, b"20260101000100Z")),
    );
    let signed = tlv(
        0x30,
        &[
            vec![2, 1, 1],
            tlv(0x30, &[name("Root"), vec![2, 1, 7]].concat()),
            tlv(0x30, &tlv(6, oid::SHA256.as_bytes())),
            tlv(0x30, &tlv(6, ECDSA)),
            vec![4, 1, 7],
            tlv(0xa1, &poe),
        ]
        .concat(),
    );
    let bytes = message(oid::DATA.as_bytes(), None, &[root, leaf], &[], &[signed]);
    let parser = Parser::ber(memory());
    let message = structured_cms::SignedData::read(&parser, &bytes, 700).unwrap();
    let parent = parser.read(&[], 700).unwrap();
    let document = crate::source::Document::new(&message, &parent).unwrap();
    let prepared = crate::prepare::Preparation::read(
        &document,
        &message.signers()[0],
        crate::Level::Basic,
        &parent,
    )
    .unwrap();
    let view = prepared.evidence(0, &parent).unwrap().unwrap();
    let provider = Oracle::new();
    let mut detached = Detached {
        bytes: b"payload",
        passes: Cell::new(0),
    };
    let utc = LeapTable::new(1_735_689_600, 1_893_456_000, &[]).unwrap();
    let result = view.components(
        &provider,
        &[Algorithm::Sha256],
        &parent,
        Some(&mut detached),
        &utc,
        &parent.execution(),
    );
    assert!(
        matches!(result, Err(super::InputError::MissingSignedAttributes)),
        "no original signedAttrs means no Hs input"
    );
    assert_eq!(provider.starts.get(), 0);
    assert_eq!(detached.passes.get(), 0);
}
