//! The published CMS HMAC path re-exports the foundation types.
#![cfg(feature = "hmac")]

#[test]
fn cms_hmac_types_are_shared() {
    let algorithm: structured_cms::hmac::Algorithm = structured_asn1::hmac::Algorithm::Sha256;
    let mac: Result<structured_asn1::hmac::Mac, structured_asn1::hmac::Error> =
        structured_cms::hmac::Mac::begin(algorithm, b"key");
    let tag: structured_cms::hmac::Tag = mac.unwrap().finalize();
    assert_eq!(tag.as_bytes().len(), 32);
}
