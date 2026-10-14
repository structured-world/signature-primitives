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
