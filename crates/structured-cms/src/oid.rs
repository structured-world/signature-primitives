//! CMS identifiers used by the protocol's schema and attribute rules.

use structured_asn1::Oid;

/// Arbitrary octets, `id-data` (RFC5652 §4).
pub const DATA: Oid<'static> = Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1]);
/// CMS `SignedData` (RFC5652 §5).
pub const SIGNED_DATA: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2]);
/// Signed content-type attribute (RFC5652 §11.1).
pub const CONTENT_TYPE: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 3]);
/// Signed message-digest attribute (RFC5652 §11.2).
pub const MESSAGE_DIGEST: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 4]);
/// Signed signing-time attribute (RFC5652 §11.3).
pub const SIGNING_TIME: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 5]);
/// Unsigned countersignature attribute (RFC5652 §11.4).
pub const COUNTERSIGNATURE: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 6]);
/// Signed algorithm protection attribute (RFC6211 §2).
pub const ALGORITHM_PROTECTION: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 52]);

/// ESS signing-certificate V1 (RFC5035 §5).
pub const SIGNING_CERTIFICATE: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 12]);
/// ESS signing-certificate V2 (RFC5035 §3).
pub const SIGNING_CERTIFICATE_V2: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 47]);
/// Exact ASN.1 SHA-256 default identity in `ESSCertIDv2` (RFC5035 §4).
pub const SHA256: Oid<'static> = Oid::from_bytes(&[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1]);
/// SHA-1 identifies the ESS V1 compatibility requirement (RFC5035 §2),
/// not a cryptographic backend or a policy permission to accept that hash.
pub const SHA1: Oid<'static> = Oid::from_bytes(&[0x2b, 0x0e, 3, 2, 26]);
/// Encapsulated timestamp information, `id-ct-TSTInfo` (RFC3161 §2.4.2).
pub const TST_INFO: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 1, 4]);
/// Whole OCSP response in CMS `OtherRevocationInfoFormat` (RFC5940 §3).
pub const OCSP_RESPONSE: Oid<'static> = Oid::from_bytes(&[0x2b, 6, 1, 5, 5, 7, 16, 2]);
/// Signed ESS content-hints (RFC2634 §2.9; EN 319 122-1 §5.2.4.1).
pub const CONTENT_HINTS: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 4]);
/// Signed ESS content-identifier (RFC2634 §2.7; EN 319 122-1 §5.2.12).
pub const CONTENT_IDENTIFIER: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 7]);
/// Signed ESS content-reference (RFC2634 §2.11; EN 319 122-1 §5.2.11).
pub const CONTENT_REFERENCE: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 10]);
/// Unsigned `signature-time-stamp` (EN 319 122-1 §5.3).
pub const SIGNATURE_TIMESTAMP: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 14]);
/// Signed `signature-policy-identifier` (EN 319 122-1 §5.2.9.1).
pub const SIGNATURE_POLICY_IDENTIFIER: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 15]);
/// Signed `commitment-type-indication` (EN 319 122-1 §5.2.3).
pub const COMMITMENT_TYPE_INDICATION: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 16]);
/// Signed `signer-location` (EN 319 122-1 §5.2.5).
pub const SIGNER_LOCATION: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 17]);
/// Signed `content-time-stamp` (EN 319 122-1 §5.2.8).
pub const CONTENT_TIMESTAMP: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 2, 20]);
/// Signed `mime-type`, `0.4.0.1733.2.1` (EN 319 122-1 §5.2.4.2).
pub const MIME_TYPE: Oid<'static> = Oid::from_bytes(&[4, 0, 0x8d, 0x45, 2, 1]);
/// Signed `signer-attributes-v2`, `0.4.0.19122.1.1` (EN 319 122-1 §5.2.6.1).
pub const SIGNER_ATTRIBUTES_V2: Oid<'static> = Oid::from_bytes(&[4, 0, 0x81, 0x95, 0x32, 1, 1]);
/// `claimed-SAML-assertion`, `0.4.0.19122.1.2`, carried only inside
/// `signer-attributes-v2` (EN 319 122-1 §5.2.6.2).
pub const CLAIMED_SAML_ASSERTION: Oid<'static> = Oid::from_bytes(&[4, 0, 0x81, 0x95, 0x32, 1, 2]);
/// Unsigned `signature-policy-store`, `0.4.0.19122.1.3` (EN 319 122-1 §5.2.10).
pub const SIGNATURE_POLICY_STORE: Oid<'static> = Oid::from_bytes(&[4, 0, 0x81, 0x95, 0x32, 1, 3]);
/// Unsigned `ats-hash-index-v3`, `0.4.0.19122.1.5` (EN 319 122-1 §5.5.2).
pub const ATS_HASH_INDEX_V3: Oid<'static> = Oid::from_bytes(&[4, 0, 0x81, 0x95, 0x32, 1, 5]);
/// Unsigned `archive-time-stamp-v3`, `0.4.0.1733.2.4` (EN 319 122-1 §5.5.3).
pub const ARCHIVE_TIMESTAMP_V3: Oid<'static> = Oid::from_bytes(&[4, 0, 0x8d, 0x45, 2, 4]);
