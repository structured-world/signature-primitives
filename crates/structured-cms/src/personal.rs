//! Provider-neutral personal key containers (RFC7292 / RFC5958).
//!
//! Reading is inspection, never authentication or permission to use a key.
//! [`process()`] authenticates the complete original safe before extraction;
//! passwords, cryptographic engines, key selection and trust remain explicit
//! caller contracts. Private-key values are borrowed, not decoded by a backend.
//! No type containing private plaintext implements `Debug` or allocating Clone.

use crate::{ContentInfo, Error, ErrorCode, Octets, Result, SignedData};
use crate::{attribute::Attribute, enveloped::EncodedValue, signer::required};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Integer, Oid, Reader, Tag, universal};
use structured_pkix::AlgorithmIdentifier;

mod process;
pub mod protection;
pub use process::{
    Backend, Cause, Decision, Failure, Fragments, Origin, Plaintext, Source, legacy_password,
    process,
};

const FIELD: &str = "personal";
const DATA: Oid<'static> = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 7, 1]);
const SIGNED: Oid<'static> = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 7, 2]);
const ENCRYPTED: Oid<'static> = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 7, 6]);

/// Original PFX integrity mode. Absence of a MAC is not authenticated data.
#[expect(
    clippy::large_enum_variant,
    reason = "one PFX mode lives inline; boxing would add allocation and indirection to every inspected container"
)]
pub enum Integrity<'a> {
    /// Password integrity over the exact logical `AuthenticatedSafe` octets.
    Password {
        /// BER `AuthenticatedSafe` encoding, excluding OCTET STRING headers.
        safe: Octets<'a>,
        /// Optional original MAC; None remains unauthenticated inspection.
        mac: Option<MacData<'a>>,
    },
    /// Public-key integrity. The existing CMS processor owns signature rules.
    Signed(SignedData<'a>),
}

/// Original PFX v3. Parsing does not invoke passwords or provider operations.
pub struct Pfx<'a> {
    integrity: Integrity<'a>,
    original: EncodedValue<'a>,
}
impl<'a> Pfx<'a> {
    /// Reads one complete BER/DER PFX at the producing source position.
    pub fn read(parent: &mut Reader<'a>) -> Result<Self> {
        let element = required(parent, FIELD)?;
        let value = Self::read_element(parent, &element)?;
        end(parent)?;
        Ok(value)
    }
    /// Reads an embedded original PFX, without rejecting enclosing siblings.
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut inside = sequence(parent, element)?;
        let version = number(&mut inside)?;
        if version.as_u64() != Some(3) {
            return Err(invalid(ErrorCode::UnsupportedVersion, element));
        }
        let envelope = required(&mut inside, FIELD)?;
        let (info, reader) = ContentInfo::read_element(&inside, &envelope)?;
        let mac = inside
            .next_element()
            .map_err(encoding)?
            .map(|value| MacData::read(&inside, &value))
            .transpose()?;
        end(&inside)?;
        let integrity = if equal_oid(&inside, info.kind(), DATA)? {
            Integrity::Password {
                safe: Octets::read(&reader, info.content(), FIELD)?,
                mac,
            }
        } else if equal_oid(&inside, info.kind(), SIGNED)? {
            // RFC7292 §4: MacData occurs ONLY in password integrity mode.
            // https://www.rfc-editor.org/rfc/rfc7292#section-4
            if mac.is_some() {
                return Err(invalid(ErrorCode::FieldOrder, element));
            }
            let signed = SignedData::read_element(&reader, info.content())?;
            if !equal_oid(&reader, signed.content().kind(), DATA)? {
                return Err(invalid(ErrorCode::UnexpectedContentType, info.content()));
            }
            if signed.content().content().is_none() {
                return Err(invalid(ErrorCode::DetachedContent, info.content()));
            }
            Integrity::Signed(signed)
        } else {
            return Err(invalid(ErrorCode::UnexpectedContentType, &envelope));
        };
        Ok(Self {
            integrity,
            original: EncodedValue::new(parent, *element),
        })
    }
    /// Whole original PFX and its lazy original/current reader boundary.
    #[must_use]
    pub fn original(&self) -> &EncodedValue<'a> {
        &self.original
    }
    /// Original immutable integrity mode and its exact protected data.
    #[must_use]
    pub fn integrity(&self) -> &Integrity<'a> {
        &self.integrity
    }
    pub(crate) fn safe(&self) -> &Octets<'a> {
        match &self.integrity {
            Integrity::Password { safe, .. } => safe,
            Integrity::Signed(signed) => signed.content().content().expect("checked attached PFX"),
        }
    }
}

/// Original `MacData`, including ignored legacy fields in PBMAC1 mode.
pub struct MacData<'a> {
    /// Original digest/MAC algorithm; PBMAC1 is distinguished explicitly.
    pub algorithm: AlgorithmIdentifier<'a>,
    /// Encoded expected MAC octets.
    pub digest: Octets<'a>,
    /// Original legacy salt. RFC9879 §4 requires ignoring it for PBMAC1.
    pub salt: Octets<'a>,
    /// Original legacy iteration count. None denotes schema DEFAULT 1.
    /// In PBMAC1 mode this field is ignored, not used as a KDF limit/input.
    pub iterations: Option<Integer<'a>>,
    /// Validated PBMAC1 parameters, or None for the legacy MAC scheme.
    pub pbmac1: Option<protection::Pair<'a>>,
}
impl<'a> MacData<'a> {
    /// Reads `MacData` and RFC9879 mandatory PBMAC1 parameter constraints.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut inside = sequence(parent, element)?;
        let digest_info = required(&mut inside, FIELD)?;
        let mut digest_info = sequence(&inside, &digest_info)?;
        let algorithm = algorithm(&mut digest_info)?;
        let value = required(&mut digest_info, FIELD)?;
        let digest = Octets::read(&digest_info, &value, FIELD)?;
        end(&digest_info)?;
        let value = required(&mut inside, FIELD)?;
        let salt = Octets::read(&inside, &value, FIELD)?;
        let iterations = if inside.is_empty() {
            None
        } else {
            Some(number(&mut inside)?)
        };
        end(&inside)?;
        // RFC9879 §4 ignores this field for MAC computation, not for DER
        // encoding. X.690 §11.5 still omits the schema DEFAULT in either mode.
        if let Some(rounds) = iterations {
            default_one(parent, rounds, element)?;
        }
        let pbmac1 = if equal_oid(parent, algorithm.algorithm(), protection::PBMAC1)? {
            let pair = protection::Pair::read(algorithm, parent)?;
            if let Some(width) = protection::hmac_width(pair.scheme, parent)?
                && digest.len() != width
            {
                return Err(invalid(ErrorCode::DigestWidth, element));
            }
            if let Some(kdf) = pair.pbkdf2.as_ref()
                && kdf.key_length.is_none()
            {
                return Err(invalid(ErrorCode::MissingField, element));
            }
            Some(pair)
        } else {
            match structured_pkix::algorithm::digest::algorithm(&algorithm, &parent.execution())
                .map_err(Error::pkix)?
            {
                structured_asn1::digest::Resolution::Supported(hash)
                    if digest.len() != hash.width() =>
                {
                    return Err(invalid(ErrorCode::DigestWidth, element));
                }
                structured_asn1::digest::Resolution::Malformed => {
                    return Err(invalid(ErrorCode::AlgorithmSyntax, element));
                }
                _ => {}
            }
            if let Some(rounds) = iterations {
                positive(rounds, element)?;
            }
            None
        };
        Ok(Self {
            algorithm,
            digest,
            salt,
            iterations,
            pbmac1,
        })
    }
}

/// One protected `AuthenticatedSafe` member. Unrecognized content stays explicit.
pub enum Safe<'a> {
    /// Unencrypted `SafeContents` BER encoding, including its SEQUENCE TLV.
    Data(Octets<'a>),
    /// Password-encrypted `SafeContents`.
    Encrypted(EncryptedData<'a>),
    /// Public-key encrypted `SafeContents`, reusing all common recipient types.
    Enveloped(crate::enveloped::EnvelopedData<'a>),
    /// An open content type without a schema owned by this format.
    Other {
        /// Original content type.
        kind: Oid<'a>,
        /// Original inner value and producing context.
        value: EncodedValue<'a>,
    },
}
impl<'a> Safe<'a> {
    /// Reads one original `ContentInfo` member; no cryptography is performed.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let (info, reader) = ContentInfo::read_element(parent, element)?;
        if equal_oid(parent, info.kind(), DATA)? {
            Ok(Self::Data(Octets::read(&reader, info.content(), FIELD)?))
        } else if equal_oid(parent, info.kind(), ENCRYPTED)? {
            Ok(Self::Encrypted(EncryptedData::read(
                &reader,
                info.content(),
            )?))
        } else if equal_oid(parent, info.kind(), crate::enveloped::IDENTIFIER)? {
            Ok(Self::Enveloped(
                crate::enveloped::EnvelopedData::read_element(&reader, info.content())?,
            ))
        } else {
            Ok(Self::Other {
                kind: info.kind(),
                value: EncodedValue::new(&reader, *info.content()),
            })
        }
    }
}

/// CMS `EncryptedData`, RFC5652 §8, used by PKCS#12 password privacy.
pub struct EncryptedData<'a> {
    /// Original content algorithm and attached/detached encrypted octets.
    pub content: crate::enveloped::EncryptedContent<'a>,
    /// Every original unprotected attribute, not authenticated bag metadata.
    pub attributes: Option<OwnedVec<Attribute<'a>>>,
    /// Parsed password-protection parameters, prepared once before callbacks.
    pub protection: protection::Protection<'a>,
}
impl<'a> EncryptedData<'a> {
    /// Reads a complete original `EncryptedData` SEQUENCE and version rule.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut inside = sequence(parent, element)?;
        let version = number(&mut inside)?;
        let info = required(&mut inside, FIELD)?;
        let content = crate::enveloped::encrypted_content(&inside, &info)?;
        let attributes = inside
            .next_element()
            .map_err(encoding)?
            .map(|set| attributes(&inside, &set, Tag::context(true, 1)))
            .transpose()?;
        end(&inside)?;
        if version.as_u64() != Some(if attributes.is_some() { 2 } else { 0 }) {
            return Err(invalid(ErrorCode::VersionMismatch, element));
        }
        if attributes.as_ref().is_some_and(|a| a.is_empty()) {
            return Err(invalid(ErrorCode::EmptyAttributes, element));
        }
        let protection = protection::Protection::read(content.algorithm, parent)?;
        Ok(Self {
            content,
            attributes,
            protection,
        })
    }
}

/// RFC5958 `OneAsymmetricKey` / PKCS#8 `PrivateKeyInfo`.
pub struct PrivateKey<'a> {
    /// Zero is v1; one is v2. Validated against public-key presence.
    pub version: u64,
    /// Original algorithm, not a key/backend selection.
    pub algorithm: AlgorithmIdentifier<'a>,
    /// Original secret key contents. Borrowed, including BER fragments.
    pub secret: Octets<'a>,
    /// Original optional key attributes, distinct from bag attributes.
    pub attributes: Option<OwnedVec<Attribute<'a>>>,
    /// Validated original IMPLICIT BIT STRING, including BER segmentation.
    pub public_key: Option<EncodedValue<'a>>,
}
impl<'a> PrivateKey<'a> {
    /// Reads the original key container without normalizing or copying secrets.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut inside = sequence(parent, element)?;
        let version = number(&mut inside)?
            .as_u64()
            .ok_or_else(|| invalid(ErrorCode::ValueTooLarge, element))?;
        let algorithm = algorithm(&mut inside)?;
        let value = required(&mut inside, FIELD)?;
        let secret = Octets::read(&inside, &value, FIELD)?;
        let mut next = inside.next_element().map_err(encoding)?;
        let attributes = if let Some(set) = next.filter(|v| v.tag() == Tag::context(true, 0)) {
            let attributes = attributes(&inside, &set, Tag::context(true, 0))?;
            next = inside.next_element().map_err(encoding)?;
            Some(attributes)
        } else {
            None
        };
        let public_key = if let Some(bits) = next {
            if bits.tag() != Tag::context(false, 1) && bits.tag() != Tag::context(true, 1) {
                return Err(invalid(ErrorCode::UnexpectedTag, &bits));
            }
            structured_pkix::der::implicit_bit_string(&inside, &bits, FIELD)
                .map_err(Error::pkix)?;
            Some(EncodedValue::new(&inside, bits))
        } else {
            None
        };
        end(&inside)?;
        if version != u64::from(public_key.is_some()) {
            return Err(invalid(ErrorCode::VersionMismatch, element));
        }
        Ok(Self {
            version,
            algorithm,
            secret,
            attributes,
            public_key,
        })
    }
}

/// `EncryptedPrivateKeyInfo`, with original protection parameters/ciphertext.
pub struct ShroudedKey<'a> {
    /// Original protection algorithm.
    pub algorithm: AlgorithmIdentifier<'a>,
    /// Original encrypted private-key contents.
    pub encrypted: Octets<'a>,
    /// Structural password-protection interpretation; unknown remains open.
    pub protection: protection::Protection<'a>,
}
impl<'a> ShroudedKey<'a> {
    /// Reads the whole original encrypted key, without KDF/decryption work.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut inside = sequence(parent, element)?;
        let algorithm = algorithm(&mut inside)?;
        let value = required(&mut inside, FIELD)?;
        let encrypted = Octets::read(&inside, &value, FIELD)?;
        end(&inside)?;
        let protection = protection::Protection::read(algorithm, parent)?;
        Ok(Self {
            algorithm,
            encrypted,
            protection,
        })
    }
}

/// A typed original bag value, including open types and nested bags.
#[expect(
    clippy::large_enum_variant,
    reason = "one bag is decoded/visited at a time; inline protection facts avoid an extra heap owner per shrouded key"
)]
pub enum BagValue<'a> {
    /// Plain PKCS#8 key.
    Key(PrivateKey<'a>),
    /// Shrouded PKCS#8 key.
    Shrouded(ShroudedKey<'a>),
    /// X.509 certificate bytes (not implicitly parsed/authenticated).
    Certificate(Octets<'a>),
    /// SDSI base64 certificate text with shared IA5 syntax validation.
    Sdsi(Octets<'a>),
    /// X.509 CRL bytes (not implicitly authenticated).
    Crl(Octets<'a>),
    /// A registered or unknown secret value.
    Secret {
        /// Original secret-type OID.
        kind: Oid<'a>,
        /// Whole original open value.
        value: EncodedValue<'a>,
    },
    /// An open bag/certificate/CRL type, without guessed normalization.
    Other {
        /// Original type OID.
        kind: Oid<'a>,
        /// Whole original open value.
        value: EncodedValue<'a>,
    },
    /// Nested `SafeContents`, visited iteratively by the processor.
    Contents(EncodedValue<'a>),
}
/// `SafeBag` with original identity/attributes and decoded value.
pub struct Bag<'a> {
    /// Original bag identifier, including unknown extensions.
    pub kind: Oid<'a>,
    /// Original whole bag encoding and producing context.
    pub original: EncodedValue<'a>,
    /// Parsed original value, never a product-selected key.
    pub value: BagValue<'a>,
    /// Optional original attributes, including repeated/empty unknown values.
    pub attributes: Option<OwnedVec<Attribute<'a>>>,
}
impl<'a> Bag<'a> {
    /// Reads one complete original `SafeBag`. All six standard alternatives use
    /// the existing shared field kernels, not a second BER grammar.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let mut inside = sequence(parent, element)?;
        let kind = inside.read_oid().map_err(encoding)?;
        let wrapper = inside.expect(Tag::context(true, 0)).map_err(encoding)?;
        let mut explicit = inside.enter(&wrapper).map_err(encoding)?;
        let value = required(&mut explicit, FIELD)?;
        end(&explicit)?;
        let attributes = inside
            .next_element()
            .map_err(encoding)?
            .map(|set| attributes(&inside, &set, Tag::constructed(universal::SET)))
            .transpose()?;
        end(&inside)?;
        // RFC7292 §4.2: BAG-TYPE is extensible. Unknown does not mean KeyBag.
        let value = if bag_id(parent, kind, 1)? {
            BagValue::Key(PrivateKey::read(&explicit, &value)?)
        } else if bag_id(parent, kind, 2)? {
            BagValue::Shrouded(ShroudedKey::read(&explicit, &value)?)
        } else if bag_id(parent, kind, 6)? {
            tag(&value, Tag::constructed(universal::SEQUENCE))?;
            BagValue::Contents(EncodedValue::new(&explicit, value))
        } else if bag_id(parent, kind, 3)? || bag_id(parent, kind, 4)? || bag_id(parent, kind, 5)? {
            let mut typed = sequence(&explicit, &value)?;
            let inner_kind = typed.read_oid().map_err(encoding)?;
            let wrapper = typed.expect(Tag::context(true, 0)).map_err(encoding)?;
            let mut inner = typed.enter(&wrapper).map_err(encoding)?;
            let content = required(&mut inner, FIELD)?;
            end(&inner)?;
            end(&typed)?;
            let certificate = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 22, 1]);
            let sdsi = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 22, 2]);
            let crl = Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 9, 23, 1]);
            if bag_id(parent, kind, 5)? {
                structured_pkix::der::conforms(&inner, &content, FIELD).map_err(Error::pkix)?;
                BagValue::Secret {
                    kind: inner_kind,
                    value: EncodedValue::new(&inner, content),
                }
            } else if bag_id(parent, kind, 3)? && equal_oid(parent, inner_kind, certificate)? {
                BagValue::Certificate(Octets::read(&inner, &content, FIELD)?)
            } else if bag_id(parent, kind, 3)? && equal_oid(parent, inner_kind, sdsi)? {
                BagValue::Sdsi(Octets::read_ia5(&inner, &content, FIELD)?)
            } else if bag_id(parent, kind, 4)? && equal_oid(parent, inner_kind, crl)? {
                BagValue::Crl(Octets::read(&inner, &content, FIELD)?)
            } else {
                structured_pkix::der::conforms(&inner, &content, FIELD).map_err(Error::pkix)?;
                BagValue::Other {
                    kind: inner_kind,
                    value: EncodedValue::new(&inner, content),
                }
            }
        } else {
            structured_pkix::der::conforms(&explicit, &value, FIELD).map_err(Error::pkix)?;
            BagValue::Other {
                kind,
                value: EncodedValue::new(&explicit, value),
            }
        };
        Ok(Self {
            kind,
            original: EncodedValue::new(parent, *element),
            value,
            attributes,
        })
    }
}

fn bag_id(parent: &Reader<'_>, oid: Oid<'_>, last: u8) -> Result<bool> {
    equal_oid(
        parent,
        oid,
        Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 1, 12, 10, 1, last]),
    )
}
pub(super) fn equal_oid(parent: &Reader<'_>, left: Oid<'_>, right: Oid<'_>) -> Result<bool> {
    parent.charge(1).map_err(encoding)?;
    if left.as_bytes().len() != right.as_bytes().len() {
        return Ok(false);
    }
    parent
        .charge(left.as_bytes().len() as u64)
        .map_err(encoding)?;
    Ok(left == right)
}
fn attributes<'a>(
    parent: &Reader<'a>,
    set: &Element<'a>,
    expected: Tag,
) -> Result<OwnedVec<Attribute<'a>>> {
    tag(set, expected)?;
    let mut inside = parent.enter(set).map_err(encoding)?;
    let execution = parent.execution();
    let mut out = execution.vector();
    let mut previous = None;
    while let Some(value) = inside.next_element().map_err(encoding)? {
        if inside.encoding().is_der() {
            if let Some(bytes) = previous
                && !structured_pkix::der::set_ordered(&inside, bytes, &value, FIELD)
                    .map_err(Error::pkix)?
            {
                return Err(invalid(ErrorCode::SetOrder, &value));
            }
            previous = Some(value.as_bytes());
        }
        let attribute = Attribute::read(&inside, &value, FIELD)?;
        // DER values were already walked by Attribute::read. BER inspection
        // must reopen the saved value context: the list cursor is two levels
        // above attrValues and would grant nested values those levels for free.
        if !inside.encoding().is_der() {
            for (ordinal, item) in attribute.values().iter().enumerate() {
                let reader = attribute
                    .value_reader_in(ordinal, &inside, FIELD)?
                    .expect("ordinal comes from this attribute's original values");
                structured_pkix::der::conforms(&reader, item, FIELD).map_err(Error::pkix)?;
            }
        }
        out.try_push(attribute)
            .map_err(|e| Error::resource(e, FIELD, value.span().start))?;
    }
    Ok(out.into_owned())
}
pub(super) fn sequence<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<Reader<'a>> {
    tag(element, Tag::constructed(universal::SEQUENCE))?;
    parent.enter(element).map_err(encoding)
}
pub(super) fn tag(element: &Element<'_>, expected: Tag) -> Result<()> {
    if element.tag() != expected {
        return Err(invalid(ErrorCode::UnexpectedTag, element));
    }
    Ok(())
}
pub(super) fn end(parent: &Reader<'_>) -> Result<()> {
    if !parent.is_empty() {
        return Err(Error::schema(
            ErrorCode::TrailingData,
            FIELD,
            parent.offset(),
        ));
    }
    Ok(())
}
pub(super) fn number<'a>(parent: &mut Reader<'a>) -> Result<Integer<'a>> {
    parent.read_integer().map_err(encoding)
}
pub(super) fn positive(value: Integer<'_>, element: &Element<'_>) -> Result<()> {
    if value.is_negative() || value.as_u64() == Some(0) {
        return Err(invalid(ErrorCode::MalformedValue, element));
    }
    Ok(())
}
fn default_one(parent: &Reader<'_>, value: Integer<'_>, element: &Element<'_>) -> Result<()> {
    if parent.encoding().is_der() && value.as_u64() == Some(1) {
        return Err(invalid(ErrorCode::DefaultWritten, element));
    }
    Ok(())
}
pub(super) fn algorithm<'a>(parent: &mut Reader<'a>) -> Result<AlgorithmIdentifier<'a>> {
    let element = required(parent, FIELD)?;
    structured_pkix::algorithm::read(parent, &element, FIELD).map_err(Error::pkix)
}
pub(super) fn invalid(code: ErrorCode, element: &Element<'_>) -> Error {
    Error::schema(code, FIELD, element.span().start)
}
pub(super) fn encoding(error: structured_asn1::Error) -> Error {
    Error::encoding(error, FIELD)
}
