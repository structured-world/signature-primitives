//! The `archive-time-stamp-v3` attribute and the `ats-hash-index-v3` inside
//! its token: one value each (EN 319 122-1 §§5.5.2-5.5.3).

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser, Reader};
use structured_cms::archive::{HashIndex, token_reader};
use structured_cms::timestamp::Token;
use structured_cms::{ErrorCode, SignedData, oid};

const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1_048_576, 1_048_576)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut encoded = vec![tag];
    let length = contents.len();
    if length < 0x80 {
        encoded.push(u8::try_from(length).unwrap());
    } else if length < 0x100 {
        encoded.extend([0x81, u8::try_from(length).unwrap()]);
    } else {
        encoded.push(0x82);
        encoded.extend(u16::try_from(length).unwrap().to_be_bytes());
    }
    encoded.extend_from_slice(contents);
    encoded
}

fn attribute(kind: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &[tlv(6, kind), tlv(0x31, &values.concat())].concat())
}

fn index() -> Vec<u8> {
    let fields = [
        tlv(0x30, &tlv(6, SHA256_OID)),
        tlv(0x30, &tlv(4, &[7; 32])),
        tlv(0x30, &[]),
        tlv(0x30, &[]),
    ];
    tlv(0x30, &fields.concat())
}

/// A `ContentInfo` carrying `SignedData` of `kind` whose one signer has `unsigned`.
fn signed(kind: &[u8], content: Option<&[u8]>, unsigned: &[Vec<u8>]) -> Vec<u8> {
    let mut fields = vec![2, 1, 3, 0x80, 1, 7];
    fields.extend(tlv(0x30, &tlv(6, oid::SHA256.as_bytes())));
    fields.extend(tlv(0x30, &tlv(6, &[0x2b, 0x65, 0x70])));
    fields.extend(tlv(4, &[8]));
    if !unsigned.is_empty() {
        fields.extend(tlv(0xa1, &unsigned.concat()));
    }
    let mut encapsulated = tlv(6, kind);
    if let Some(content) = content {
        encapsulated.extend(tlv(0xa0, &tlv(4, content)));
    }
    let mut inside = vec![2, 1, 3, 0x31, 0];
    inside.extend(tlv(0x30, &encapsulated));
    inside.extend(tlv(0x31, &tlv(0x30, &fields)));
    let envelope = [
        tlv(6, oid::SIGNED_DATA.as_bytes()),
        tlv(0xa0, &tlv(0x30, &inside)),
    ]
    .concat();
    tlv(0x30, &envelope)
}

fn token(unsigned: &[Vec<u8>]) -> Vec<u8> {
    // TSTInfo contents are not inspected when reading the index.
    signed(oid::TST_INFO.as_bytes(), Some(&[0x30, 0]), unsigned)
}

fn index_of(unsigned: &[Vec<u8>]) -> structured_cms::Result<Vec<u8>> {
    let encoded = token(unsigned);
    let parser = Parser::ber(memory());
    let token = Token::read(&parser, &encoded, 0).unwrap();
    let operation = parser.read(&[], 0).unwrap();
    HashIndex::of_token(&token, &operation).map(|index| index.as_bytes().to_vec())
}

#[test]
fn the_single_index_value_is_read_as_written() {
    let value = index();
    let found = index_of(&[attribute(
        oid::ATS_HASH_INDEX_V3.as_bytes(),
        std::slice::from_ref(&value),
    )]);
    assert_eq!(found.unwrap(), value);
}

#[test]
fn a_token_without_its_v3_index_is_refused() {
    // §5.5.3: the token shall carry a single ats-hash-index-v3; the TS 101 733
    // index (0.4.0.1733.2.5) has other hashing rules and is not substituted.
    assert_eq!(index_of(&[]).unwrap_err().code(), ErrorCode::MissingField);
    let superseded = attribute(&[4, 0, 0x8d, 0x45, 2, 5], &[index()]);
    assert_eq!(
        index_of(&[superseded]).unwrap_err().code(),
        ErrorCode::MissingField
    );
}

#[test]
fn a_repeated_index_attribute_or_value_is_refused() {
    // §5.5.2 "exactly one component of AttributeValue type"; §5.5.3 "a single
    // ats-hash-index-v3 attribute".
    let one = attribute(oid::ATS_HASH_INDEX_V3.as_bytes(), &[index()]);
    assert_eq!(
        index_of(&[one.clone(), one]).unwrap_err().code(),
        ErrorCode::DuplicateAttribute
    );
    let two = attribute(oid::ATS_HASH_INDEX_V3.as_bytes(), &[index(), index()]);
    assert_eq!(
        index_of(&[two]).unwrap_err().code(),
        ErrorCode::AttributeCardinality
    );
}

#[test]
fn a_foreign_token_is_refused_before_its_attributes_are_searched() {
    // Without an index, a search under another parser's reader would answer
    // MissingField; the session refusal must come first.
    let encoded = token(&[]);
    let parser = Parser::ber(memory());
    let token = Token::read(&parser, &encoded, 0).unwrap();
    let foreign = Parser::ber(memory());
    let other = foreign.read(&[], 0).unwrap();
    assert_eq!(
        HashIndex::of_token(&token, &other).unwrap_err().code(),
        ErrorCode::Pkix(structured_pkix::ErrorCode::ForeignReader)
    );
}

// Enters every constructed element, so it fails exactly when some element
// lies deeper than the reader's depth ceiling allows.
fn walk(reader: &mut Reader<'_>) -> bool {
    loop {
        match reader.next_element() {
            Ok(None) => return true,
            Ok(Some(element)) if element.tag().is_constructed() => {
                let Ok(mut inside) = reader.enter(&element) else {
                    return false;
                };
                if !walk(&mut inside) {
                    return false;
                }
            }
            Ok(Some(_)) => {}
            Err(_) => return false,
        }
    }
}

#[test]
fn the_index_is_read_at_its_original_depth() {
    // An index whose algorithm parameters nest deeply exceeds the depth
    // ceiling where it is written; rereading it from a shallow query must not
    // reset that budget.
    let mut parameters = tlv(5, &[]);
    for _ in 0..8 {
        parameters = tlv(0x30, &parameters);
    }
    let fields = [
        tlv(0x30, &[tlv(6, SHA256_OID), parameters].concat()),
        tlv(0x30, &[]),
        tlv(0x30, &[]),
        tlv(0x30, &[]),
    ];
    let value = tlv(0x30, &fields.concat());
    let encoded = token(&[attribute(oid::ATS_HASH_INDEX_V3.as_bytes(), &[value])]);
    let mut exercised = false;
    for max_depth in 1..40 {
        let limits = Limits {
            max_depth,
            ..Limits::default()
        };
        let whole = Parser::new(Encoding::Ber, limits, memory());
        let in_place = walk(&mut whole.read(&encoded, 0).unwrap());
        let parser = Parser::new(Encoding::Ber, limits, memory());
        let Ok(token) = Token::read(&parser, &encoded, 0) else {
            continue;
        };
        let query = parser.read(&[], 0).unwrap();
        let read = HashIndex::of_token(&token, &query);
        if !in_place {
            exercised = true;
            assert!(read.is_err(), "depth {max_depth} reset for the index");
        }
    }
    assert!(exercised, "no ceiling admitted the token but not the index");
}

#[test]
fn the_whole_index_attribute_must_be_der() {
    // §5.5.2 "The ats-hash-index-v3 attribute shall be DER encoded": a DER
    // value inside a non-minimal attrValues length is still refused.
    let value = index();
    let mut values = vec![0x31, 0x81, u8::try_from(value.len()).unwrap()];
    values.extend(&value);
    let lax = tlv(
        0x30,
        &[tlv(6, oid::ATS_HASH_INDEX_V3.as_bytes()), values].concat(),
    );
    assert!(index_of(&[lax]).is_err());
    let mut kind = vec![
        6,
        0x81,
        u8::try_from(oid::ATS_HASH_INDEX_V3.as_bytes().len()).unwrap(),
    ];
    kind.extend(oid::ATS_HASH_INDEX_V3.as_bytes());
    let lax_kind = tlv(0x30, &[kind, tlv(0x31, &value)].concat());
    assert!(index_of(&[lax_kind]).is_err());
}

#[test]
fn the_archive_attribute_yields_its_one_token() {
    // §5.5.3 "exactly one component of AttributeValue type".
    let inner = token(&[attribute(oid::ATS_HASH_INDEX_V3.as_bytes(), &[index()])]);
    for (values, expected) in [
        (vec![inner.clone()], None),
        (
            vec![inner.clone(), inner.clone()],
            Some(ErrorCode::AttributeCardinality),
        ),
        (vec![], Some(ErrorCode::AttributeCardinality)),
    ] {
        let unsigned = [attribute(oid::ARCHIVE_TIMESTAMP_V3.as_bytes(), &values)];
        let encoded = signed(oid::DATA.as_bytes(), None, &unsigned);
        let parser = Parser::ber(memory());
        let value = SignedData::read(&parser, &encoded, 0).unwrap();
        let query = parser.read(&[], 0).unwrap();
        let attribute = &value.signers()[0].unsigned_attributes().unwrap().items()[0];
        match (token_reader(attribute, &query), expected) {
            (Ok(mut reader), None) => {
                let token = Token::read_from(&mut reader).unwrap();
                assert!(HashIndex::of_token(&token, &reader).is_ok());
            }
            (Err(error), Some(code)) => assert_eq!(error.code(), code),
            (other, expected) => panic!("{expected:?} expected, got {:?}", other.err()),
        }
    }
    // Another attribute type is not read as an archive time-stamp.
    let unsigned = [attribute(oid::SIGNATURE_TIMESTAMP.as_bytes(), &[inner])];
    let encoded = signed(oid::DATA.as_bytes(), None, &unsigned);
    let parser = Parser::ber(memory());
    let value = SignedData::read(&parser, &encoded, 0).unwrap();
    let query = parser.read(&[], 0).unwrap();
    let attribute = &value.signers()[0].unsigned_attributes().unwrap().items()[0];
    assert_eq!(
        token_reader(attribute, &query).unwrap_err().code(),
        ErrorCode::AttributeSyntax
    );
}
