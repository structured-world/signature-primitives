//! The object identifiers this crate names.
//!
//! Written as the bytes they are encoded with, because that is what a
//! document carries and what identity is compared on. A test renders every
//! one of them back to the dotted form in its documentation, so a mistyped
//! byte is caught here rather than in a certificate that quietly fails to
//! match the extension it is.

use structured_asn1::Oid;

// Attribute types that appear in a distinguished name.

/// `2.5.4.3`, the common name.
pub const COMMON_NAME: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x03]);

/// `2.5.4.4`, a surname.
pub const SURNAME: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x04]);

/// `2.5.4.5`, a serial number carried as a name attribute, which is not the certificate's serial number.
pub const SERIAL_NUMBER: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x05]);

/// `2.5.4.6`, a country, as a two-letter code.
pub const COUNTRY: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x06]);

/// `2.5.4.7`, a locality.
pub const LOCALITY: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x07]);

/// `2.5.4.8`, a state or province.
pub const STATE_OR_PROVINCE: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x08]);

/// `2.5.4.9`, a street address.
pub const STREET_ADDRESS: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x09]);

/// `2.5.4.10`, an organization.
pub const ORGANIZATION: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x0a]);

/// `2.5.4.11`, an organizational unit.
pub const ORGANIZATIONAL_UNIT: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x0b]);

/// `2.5.4.12`, a title.
pub const TITLE: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x0c]);

/// `2.5.4.42`, a given name.
pub const GIVEN_NAME: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x2a]);

/// `2.5.4.43`, initials.
pub const INITIALS: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x2b]);

/// `2.5.4.44`, a generation qualifier.
pub const GENERATION_QUALIFIER: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x2c]);

/// `2.5.4.46`, a qualifier that tells two otherwise equal names apart.
pub const DN_QUALIFIER: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x2e]);

/// `2.5.4.65`, a pseudonym.
pub const PSEUDONYM: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x41]);

/// `2.5.4.97`, the organization identifier a qualified certificate carries, which is how a legal entity is identified rather than described.
pub const ORGANIZATION_IDENTIFIER: Oid<'static> = Oid::from_bytes(&[0x55, 0x04, 0x61]);

/// `1.2.840.113549.1.9.1`, an electronic mail address, deprecated in favour of the subject alternative name.
pub const EMAIL_ADDRESS: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01]);

/// `0.9.2342.19200300.100.1.25`, one component of a domain name.
pub const DOMAIN_COMPONENT: Oid<'static> =
    Oid::from_bytes(&[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19]);

/// `0.9.2342.19200300.100.1.1`, a user identifier.
pub const USER_ID: Oid<'static> =
    Oid::from_bytes(&[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01]);

// Extensions, by the identifier that appears in the certificate.

/// `2.5.29.9`, attributes of the subject that are not part of its name.
pub const SUBJECT_DIRECTORY_ATTRIBUTES: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x09]);

/// `2.5.29.14`, an identifier for the subject's public key.
pub const SUBJECT_KEY_IDENTIFIER: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x0e]);

/// `2.5.29.15`, what the key may be used for.
pub const KEY_USAGE: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x0f]);

/// `2.5.29.16`, when the private key may be used, which is not when the certificate is valid.
pub const PRIVATE_KEY_USAGE_PERIOD: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x10]);

/// `2.5.29.17`, further names for the subject.
pub const SUBJECT_ALT_NAME: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x11]);

/// `2.5.29.18`, further names for the issuer.
pub const ISSUER_ALT_NAME: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x12]);

/// `2.5.29.19`, whether this is a certification authority, and how deep a path below it may go.
pub const BASIC_CONSTRAINTS: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x13]);

/// `2.5.29.30`, the name space a certification authority may certify within.
pub const NAME_CONSTRAINTS: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x1e]);

/// `2.5.29.31`, where revocation lists are published.
pub const CRL_DISTRIBUTION_POINTS: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x1f]);

/// Monotonic CRL number, RFC 5280 §5.2.3.
pub const CRL_NUMBER: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x14]);
/// CRL entry revocation reason, RFC 5280 §5.3.1.
pub const CRL_REASON: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x15]);
/// CRL entry invalidity date, RFC 5280 §5.3.2.
pub const INVALIDITY_DATE: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x18]);
/// Delta CRL base number, RFC 5280 §5.2.4.
pub const DELTA_CRL_INDICATOR: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x1b]);
/// CRL distribution point and scope, RFC 5280 §5.2.5.
pub const ISSUING_DISTRIBUTION_POINT: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x1c]);
/// Indirect CRL entry issuer, RFC 5280 §5.3.3.
pub const CERTIFICATE_ISSUER: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x1d]);

/// `2.5.29.32`, the policies this certificate was issued under.
pub const CERTIFICATE_POLICIES: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x20]);

/// `2.5.29.33`, policies of one domain treated as equivalent to policies of another.
pub const POLICY_MAPPINGS: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x21]);

/// `2.5.29.35`, an identifier for the key that signed this certificate.
pub const AUTHORITY_KEY_IDENTIFIER: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x23]);

/// `2.5.29.36`, limits on policy processing below this certificate.
pub const POLICY_CONSTRAINTS: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x24]);

/// `2.5.29.37`, further purposes the key may be used for.
pub const EXT_KEY_USAGE: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x25]);

/// `2.5.29.46`, where the delta revocation list is published.
pub const FRESHEST_CRL: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x2e]);

/// `2.5.29.54`, how far down the path the any-policy identifier stops being accepted.
pub const INHIBIT_ANY_POLICY: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x36]);

/// `1.3.6.1.5.5.7.1.1`, where the issuer's certificate and status service are published.
pub const AUTHORITY_INFO_ACCESS: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]);

/// `1.3.6.1.5.5.7.1.11`, where services belonging to the subject are published.
pub const SUBJECT_INFO_ACCESS: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0b]);

/// `1.3.6.1.5.5.7.1.3`, statements about the certificate as a qualified certificate.
pub const QC_STATEMENTS: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x03]);

// Access methods, naming what sits at a location an access description points to.

/// `1.3.6.1.5.5.7.48.1`, a status service.
pub const OCSP: Oid<'static> = Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]);

/// Mandatory basic OCSP response syntax (RFC6960 §4.2.1).
pub const OCSP_BASIC: Oid<'static> = Oid::from_bytes(&[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1]);

/// Request/response nonce (RFC9654 §2.1).
pub const OCSP_NONCE: Oid<'static> = Oid::from_bytes(&[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 2]);

/// Responder certificate revocation exemption (RFC6960 §4.2.2.2.1).
pub const OCSP_NO_CHECK: Oid<'static> = Oid::from_bytes(&[0x2b, 6, 1, 5, 5, 7, 0x30, 1, 5]);

/// `1.3.6.1.5.5.7.48.2`, the issuer's own certificate.
pub const CA_ISSUERS: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]);

/// `1.3.6.1.5.5.7.48.3`, a timestamping service.
pub const TIME_STAMPING_ACCESS: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x03]);

/// `1.3.6.1.5.5.7.48.5`, a repository of certificates.
pub const CA_REPOSITORY: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x05]);

// Extended key usages.

/// `2.5.29.37.0`, any purpose.
pub const ANY_EXTENDED_KEY_USAGE: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x25, 0x00]);

/// `1.3.6.1.5.5.7.3.1`, authenticating a server.
pub const SERVER_AUTH: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]);

/// `1.3.6.1.5.5.7.3.2`, authenticating a client.
pub const CLIENT_AUTH: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]);

/// `1.3.6.1.5.5.7.3.3`, signing code.
pub const CODE_SIGNING: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03]);

/// `1.3.6.1.5.5.7.3.4`, protecting electronic mail.
pub const EMAIL_PROTECTION: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04]);

/// `1.3.6.1.5.5.7.3.8`, signing timestamps.
pub const TIME_STAMPING: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08]);

/// `1.3.6.1.5.5.7.3.9`, signing status responses.
pub const OCSP_SIGNING: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09]);

// Policies and their qualifiers.

/// `2.5.29.32.0`, the policy that stands for any of them.
pub const ANY_POLICY: Oid<'static> = Oid::from_bytes(&[0x55, 0x1d, 0x20, 0x00]);

/// `1.3.6.1.5.5.7.2.1`, a pointer to the practice statement, which is a location and is never fetched here.
pub const CPS_QUALIFIER: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01]);

/// `1.3.6.1.5.5.7.2.2`, a notice meant to be shown to a person.
pub const USER_NOTICE_QUALIFIER: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02]);

// Qualified certificate statements, as ETSI EN 319 412-5 defines them.

/// `0.4.0.1862.1.1`, the certificate is claimed to be a qualified certificate under the Regulation.
pub const QC_COMPLIANCE: Oid<'static> = Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x01]);

/// `0.4.0.1862.1.2`, a limit on the value of transactions the certificate may be used for.
pub const QC_LIMIT_VALUE: Oid<'static> = Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x02]);

/// `0.4.0.1862.1.3`, how long the issuer keeps the material needed to check this certificate.
pub const QC_RETENTION_PERIOD: Oid<'static> =
    Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x03]);

/// `0.4.0.1862.1.4`, the private key is held in a qualified signature creation device.
pub const QC_SSCD: Oid<'static> = Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x04]);

/// `0.4.0.1862.1.5`, where the disclosure statements are published.
pub const QC_PDS: Oid<'static> = Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x05]);

/// `0.4.0.1862.1.6`, which kind of qualified certificate this is.
pub const QC_TYPE: Oid<'static> = Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x06]);

/// `0.4.0.1862.1.7`, the national legislation the certificate is qualified under.
pub const QC_CC_LEGISLATION: Oid<'static> = Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x07]);

/// `0.4.0.1862.1.6.1`, a certificate for an electronic signature, made by a natural person.
pub const QCT_ESIGN: Oid<'static> = Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x06, 0x01]);

/// `0.4.0.1862.1.6.2`, a certificate for an electronic seal, made by a legal person.
pub const QCT_ESEAL: Oid<'static> = Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x06, 0x02]);

/// `0.4.0.1862.1.6.3`, a certificate for website authentication.
pub const QCT_WEB: Oid<'static> = Oid::from_bytes(&[0x04, 0x00, 0x8e, 0x46, 0x01, 0x06, 0x03]);

/// `1.3.6.1.5.5.7.11.1`, the first version of the statement carrying semantics for the subject's identifiers.
pub const PKIX_QC_SYNTAX_V1: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0b, 0x01]);

/// `1.3.6.1.5.5.7.11.2`, the second version of that statement.
pub const PKIX_QC_SYNTAX_V2: Oid<'static> =
    Oid::from_bytes(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0b, 0x02]);

/// `0.4.0.194121.1.1`, the subject's identifiers are read as those of a natural person.
pub const SEMANTICS_NATURAL_PERSON: Oid<'static> =
    Oid::from_bytes(&[0x04, 0x00, 0x8b, 0xec, 0x49, 0x01, 0x01]);

/// `0.4.0.194121.1.2`, the subject's identifiers are read as those of a legal person.
pub const SEMANTICS_LEGAL_PERSON: Oid<'static> =
    Oid::from_bytes(&[0x04, 0x00, 0x8b, 0xec, 0x49, 0x01, 0x02]);

// Public key algorithms, as far as saying what kind of key a certificate carries. What may be verified with one, and how, belongs to the algorithm registry rather than here.

/// `1.2.840.113549.1.1.1`, an RSA key.
pub const RSA_ENCRYPTION: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);

/// `1.2.840.113549.1.1.10`, an RSA key restricted to the probabilistic signature scheme.
pub const RSASSA_PSS: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a]);

/// `1.2.840.10045.2.1`, a key on an elliptic curve named by the parameters.
pub const EC_PUBLIC_KEY: Oid<'static> =
    Oid::from_bytes(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);

/// `1.3.101.112`, an Ed25519 key.
pub const ED25519: Oid<'static> = Oid::from_bytes(&[0x2b, 0x65, 0x70]);

/// `1.3.101.113`, an Ed448 key.
pub const ED448: Oid<'static> = Oid::from_bytes(&[0x2b, 0x65, 0x71]);

#[cfg(test)]
mod tests;
