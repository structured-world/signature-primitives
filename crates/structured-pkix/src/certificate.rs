//! The certificate: what it says, and the bytes that were signed.

use crate::algorithm::{self, AlgorithmIdentifier};
use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extensions};
use crate::key::PublicKeyInfo;
use crate::name::{self, Name};
use crate::time::{self, Time};
use structured_asn1::{BitString, Element, Integer, Parser, Reader, Span, Tag, universal};

/// Which version of the structure a certificate was written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    /// The original, with no extensions and no unique identifiers.
    V1,
    /// Adds the unique identifiers.
    V2,
    /// Adds extensions, and is what every certificate in use is.
    V3,
}

/// The interval a certificate says it may be relied on within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

impl Validity {
    /// The first moment.
    #[must_use]
    pub fn not_before(self) -> Time {
        self.not_before
    }

    /// The last moment.
    #[must_use]
    pub fn not_after(self) -> Time {
        self.not_after
    }

    /// Whether the interval ends no earlier than it begins.
    ///
    /// A certificate whose interval runs backwards is never valid at any
    /// moment. It is reported rather than refused, because a person holding
    /// such a document is owed an explanation of it.
    #[must_use]
    pub fn is_well_ordered(self) -> bool {
        self.not_before <= self.not_after
    }

    /// Whether a moment lies in the interval, at either end included.
    #[must_use]
    pub fn contains(self, moment: Time) -> bool {
        self.not_before <= moment && moment <= self.not_after
    }

    /// Whether the whole of an interval lies inside this one.
    ///
    /// This, not [`Self::contains`], is the question the product asks. What is
    /// known about when a signature was made is an interval, and resolving it
    /// at one end would report a signature made before a certificate existed,
    /// or before it was revoked, as one made while it was good.
    #[must_use]
    pub fn covers(self, from: Time, to: Time) -> bool {
        // Endpoints that run backwards do not form an interval, and nothing
        // covers what does not exist: reversed evidence bounds must not read
        // as covered just because both moments fall inside the validity.
        from <= to && self.contains(from) && self.contains(to)
    }
}

/// A certificate, read once and kept as it arrived.
#[derive(Debug)]
pub struct Certificate<'a> {
    tbs: TbsCertificate<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature: BitString<'a>,
    der: &'a [u8],
    span: Span,
}

/// The signed part of a certificate: everything the issuer put its name to.
#[derive(Debug)]
pub struct TbsCertificate<'a> {
    version: Version,
    serial: Integer<'a>,
    signature: AlgorithmIdentifier<'a>,
    issuer: Name<'a>,
    validity: Validity,
    subject: Name<'a>,
    public_key: PublicKeyInfo<'a>,
    issuer_unique_id: Option<BitString<'a>>,
    subject_unique_id: Option<BitString<'a>>,
    extensions: Extensions<'a>,
    der: &'a [u8],
    span: Span,
}

impl<'a> Certificate<'a> {
    /// Reads a document that is one certificate and nothing else.
    ///
    /// The parser carries the budget, and outlives the certificate because the
    /// certificate borrows the document it was read from. Several certificates
    /// read with one parser share one budget, which is what keeps a structure
    /// holding a thousand of them from costing a thousand times the work a
    /// caller allowed.
    pub fn read(parser: &'a Parser, document: &'a [u8], base: u64) -> Result<Self> {
        let mut reader = parser.read(document, base).field(FIELD)?;
        let element = reader
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, base))?;
        let certificate = Self::read_element(&reader, &element)?;

        // Bytes after the certificate are a second document sharing a file
        // with the first, and which of them a person is looking at would have
        // no answer.
        if !reader.is_empty() {
            return Err(Error::new(
                ErrorCode::TrailingData,
                FIELD,
                element.span().end(),
            ));
        }
        Ok(certificate)
    }

    /// Reads a certificate from an element inside a larger structure, which is
    /// how the ones carried by a signature are read. The parser is taken from
    /// the parent reader, never passed beside it: it carries the envelope's
    /// shared budget, the extensions keep it so their decodes stay charged to
    /// it, and a fresh parser per embedded certificate is unrepresentable.
    pub fn read_element(parent: &Reader<'a>, element: &Element<'a>) -> Result<Self> {
        let fail = |code| Error::new(code, FIELD, element.span().start);

        // A certificate is DER whatever carries it: RFC 5280 section 4.1
        // defines it in DER, while the CMS envelope handing it over may be
        // BER. The element is re-read under DER, header included, so a
        // spelling only the envelope's leniency accepts, an indefinite or
        // long-form outer length among them, is refused here rather than
        // surviving into signature and path validation.
        let mut outer = parent
            .reread(element, structured_asn1::Encoding::Der)
            .field(FIELD)?;
        let element = &outer
            .expect(Tag::constructed(universal::SEQUENCE))
            .field(FIELD)?;

        let mut inside = outer.enter(element).field(FIELD)?;

        let tbs_element = inside
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| fail(ErrorCode::MissingField))?;
        let tbs = read_tbs(&inside, &tbs_element)?;

        let algorithm_element = inside
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| fail(ErrorCode::MissingField))?;
        let signature_algorithm =
            algorithm::read(&inside, &algorithm_element, SIGNATURE_ALGORITHM)?;
        let signature = inside.read_bit_string().field(SIGNATURE)?;

        if !inside.is_empty() {
            return Err(fail(ErrorCode::TrailingData));
        }

        // The outer identifier is not covered by the signature. Trusting it
        // over the one inside the signed bytes would let anybody rewrite which
        // algorithm a certificate is verified with, so the two are required to
        // agree and the signed one is what the registry is handed.
        //
        // The same semantic comparison as a deferred public operation, with
        // this Reader additionally preserving the parser-local ceiling.
        if !signature_algorithm.matches_in(&tbs.signature, &inside)? {
            return Err(Error::new(
                ErrorCode::AlgorithmMismatch,
                SIGNATURE_ALGORITHM,
                algorithm_element.span().start,
            ));
        }

        Ok(Self {
            tbs,
            signature_algorithm,
            signature,
            der: element.as_bytes(),
            span: element.span(),
        })
    }

    /// The signed part.
    #[must_use]
    pub fn tbs(&self) -> &TbsCertificate<'a> {
        &self.tbs
    }

    /// The algorithm named outside the signed bytes, which
    /// [`Self::read_element`] has already required to agree with the one
    /// inside them.
    #[must_use]
    pub fn signature_algorithm(&self) -> AlgorithmIdentifier<'a> {
        self.signature_algorithm
    }

    /// The signature value.
    #[must_use]
    pub fn signature(&self) -> BitString<'a> {
        self.signature
    }

    /// The whole certificate as it arrived, which is what a fingerprint is
    /// taken of.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.der
    }

    /// Where the certificate sits in the document it was read from.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }

    /// The bytes the issuer signed, exactly as they arrived.
    #[must_use]
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.tbs.der
    }
}

impl<'a> TbsCertificate<'a> {
    /// Which version this was written to.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// The serial number, as encoded.
    ///
    /// Kept as bytes because it identifies the certificate to its issuer and
    /// to a revocation list, and because it outgrows any integer type. The
    /// profile requires it to be positive and at most twenty octets; a
    /// certificate that breaks either rule is read and reports what it says,
    /// since refusing would leave a person holding a document nothing could
    /// explain.
    #[must_use]
    pub fn serial(&self) -> Integer<'a> {
        self.serial
    }

    /// The algorithm named inside the signed bytes.
    #[must_use]
    pub fn signature(&self) -> AlgorithmIdentifier<'a> {
        self.signature
    }

    /// Who issued it.
    #[must_use]
    pub fn issuer(&self) -> &Name<'a> {
        &self.issuer
    }

    /// The interval it says it may be relied on within.
    #[must_use]
    pub fn validity(&self) -> Validity {
        self.validity
    }

    /// Who it was issued to.
    #[must_use]
    pub fn subject(&self) -> &Name<'a> {
        &self.subject
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKeyInfo<'a> {
        self.public_key
    }

    /// The issuer's unique identifier, which only the older versions carry.
    #[must_use]
    pub fn issuer_unique_id(&self) -> Option<BitString<'a>> {
        self.issuer_unique_id
    }

    /// The subject's unique identifier, which only the older versions carry.
    #[must_use]
    pub fn subject_unique_id(&self) -> Option<BitString<'a>> {
        self.subject_unique_id
    }

    /// The extensions, which are empty for anything below version 3.
    #[must_use]
    pub fn extensions(&self) -> &Extensions<'a> {
        &self.extensions
    }

    /// The signed bytes, exactly as they arrived.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.der
    }

    /// Where the signed bytes sit in the document.
    #[must_use]
    pub fn span(&self) -> Span {
        self.span
    }
}

const FIELD: &str = "certificate";
const TBS: &str = "certificate.tbsCertificate";
const VERSION: &str = "certificate.tbsCertificate.version";
const SERIAL: &str = "certificate.tbsCertificate.serialNumber";
const INNER_ALGORITHM: &str = "certificate.tbsCertificate.signature";
const ISSUER: &str = "certificate.tbsCertificate.issuer";
const VALIDITY: &str = "certificate.tbsCertificate.validity";
const NOT_BEFORE: &str = "certificate.tbsCertificate.validity.notBefore";
const NOT_AFTER: &str = "certificate.tbsCertificate.validity.notAfter";
const SUBJECT: &str = "certificate.tbsCertificate.subject";
const PUBLIC_KEY: &str = "certificate.tbsCertificate.subjectPublicKeyInfo";
const ISSUER_UNIQUE_ID: &str = "certificate.tbsCertificate.issuerUniqueID";
const SUBJECT_UNIQUE_ID: &str = "certificate.tbsCertificate.subjectUniqueID";
const EXTENSIONS: &str = "certificate.tbsCertificate.extensions";
const SIGNATURE_ALGORITHM: &str = "certificate.signatureAlgorithm";
const SIGNATURE: &str = "certificate.signature";

fn require(element: &Element<'_>, tag: Tag, field: &'static str) -> Result<()> {
    if element.tag() == tag {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
        field,
        element.span().start,
    ))
}

fn read_tbs<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<TbsCertificate<'a>> {
    let fail = |code| Error::new(code, TBS, element.span().start);
    require(element, Tag::constructed(universal::SEQUENCE), TBS)?;

    let mut inside = parent.enter(element).field(TBS)?;
    let mut next = inside.next_element().field(TBS)?;

    // The version is tagged, so its absence is told from the serial number by
    // the tag rather than by counting fields.
    let version = match next {
        Some(tagged) if tagged.tag() == Tag::context(true, 0) => {
            let version = read_version(&inside, &tagged)?;
            next = inside.next_element().field(TBS)?;
            version
        }
        // Absent means the first version, which is what a certificate from
        // before extensions existed writes.
        _ => Version::V1,
    };

    let serial_element = next.ok_or_else(|| fail(ErrorCode::MissingField))?;
    require(&serial_element, Tag::primitive(universal::INTEGER), SERIAL)?;
    let serial = inside.integer(&serial_element).field(SERIAL)?;

    let signature_element = inside
        .next_element()
        .field(TBS)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    let signature = algorithm::read(&inside, &signature_element, INNER_ALGORITHM)?;

    let issuer_element = inside
        .next_element()
        .field(TBS)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    let issuer = name::read(&inside, &issuer_element, ISSUER)?;
    // RFC 5280 4.1.2.4: the issuer field must contain a non-empty
    // distinguished name. An empty subject is allowed when an alternative
    // name carries the identity (4.1.2.6); an empty issuer names no
    // authority, and two identically empty names compare equal, so a
    // certificate carrying one could chain to a CA with an empty subject.
    if issuer.is_empty() {
        return Err(Error::new(
            ErrorCode::EmptySequence,
            ISSUER,
            issuer_element.span().start,
        ));
    }

    let validity_element = inside
        .next_element()
        .field(TBS)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    let validity = read_validity(&inside, &validity_element)?;

    let subject_element = inside
        .next_element()
        .field(TBS)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    let subject = name::read(&inside, &subject_element, SUBJECT)?;

    let key_element = inside
        .next_element()
        .field(TBS)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    let public_key = PublicKeyInfo::read_element(&inside, &key_element, PUBLIC_KEY)?;

    let Trailing {
        issuer_unique_id,
        subject_unique_id,
        extensions,
    } = read_trailing(&mut inside)?;

    // A field the certificate's own version says it does not have is a
    // structure two readers would describe differently, one reading it and one
    // stopping at the version.
    if !extensions.is_empty() && version != Version::V3 {
        return Err(Error::new(
            ErrorCode::UnexpectedField,
            EXTENSIONS,
            element.span().start,
        ));
    }
    if (issuer_unique_id.is_some() || subject_unique_id.is_some()) && version == Version::V1 {
        return Err(Error::new(
            ErrorCode::UnexpectedField,
            ISSUER_UNIQUE_ID,
            element.span().start,
        ));
    }

    // The subject may be empty only when the identity lives in the
    // alternative name, and then that extension must be present and marked
    // critical (RFC 5280 4.2.1.6). Absent, or present without the mark, the
    // certificate names nobody while reading as a supplied identity.
    if subject.is_empty()
        && !extensions
            .get(crate::oid::SUBJECT_ALT_NAME, inside.memory())?
            .is_some_and(|alternative| alternative.is_critical())
    {
        return Err(Error::new(
            ErrorCode::MissingField,
            SUBJECT,
            subject_element.span().start,
        ));
    }

    Ok(TbsCertificate {
        version,
        serial,
        signature,
        issuer,
        validity,
        subject,
        public_key,
        issuer_unique_id,
        subject_unique_id,
        extensions,
        der: element.as_bytes(),
        span: element.span(),
    })
}

/// The three optional fields the signed part ends with.
struct Trailing<'a> {
    issuer_unique_id: Option<BitString<'a>>,
    subject_unique_id: Option<BitString<'a>>,
    extensions: Extensions<'a>,
}

fn read_trailing<'a>(inside: &mut Reader<'a>) -> Result<Trailing<'a>> {
    let mut issuer_unique_id = None;
    let mut subject_unique_id = None;
    let mut extensions = Extensions::empty(inside.memory());

    // The tag number the last field carried. Each of the three is optional
    // and they are written in the order of their numbers, so a tag at or
    // below this is a repeat or a field written backwards, and either is a
    // structure this schema does not have.
    let mut last_number = 0;

    while let Some(tagged) = inside.next_element().field(TBS)? {
        let (field, number) = match tagged.tag() {
            tag if tag == Tag::context(false, 1) && last_number < 1 => (ISSUER_UNIQUE_ID, 1),
            tag if tag == Tag::context(false, 2) && last_number < 2 => (SUBJECT_UNIQUE_ID, 2),
            tag if tag == Tag::context(true, 3) && last_number < 3 => (EXTENSIONS, 3),
            _ => {
                return Err(Error::new(
                    ErrorCode::UnexpectedField,
                    TBS,
                    tagged.span().start,
                ));
            }
        };
        last_number = number;

        match number {
            1 => issuer_unique_id = Some(inside.bit_string(&tagged).field(field)?),
            2 => subject_unique_id = Some(inside.bit_string(&tagged).field(field)?),
            _ => {
                // Tagged explicitly, so the sequence of extensions is inside
                // this element rather than being it.
                let mut wrapper = inside.enter(&tagged).field(field)?;
                let sequence = wrapper.next_element().field(field)?.ok_or_else(|| {
                    Error::new(ErrorCode::MissingField, field, tagged.span().start)
                })?;
                extensions = extension::read(&wrapper, &sequence, field)?;
                if !wrapper.is_empty() {
                    return Err(Error::new(
                        ErrorCode::TrailingData,
                        field,
                        tagged.span().start,
                    ));
                }
            }
        }
    }

    Ok(Trailing {
        issuer_unique_id,
        subject_unique_id,
        extensions,
    })
}

fn read_version<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<Version> {
    let fail = |code| Error::new(code, VERSION, element.span().start);

    let mut inside = parent.enter(element).field(VERSION)?;
    let value = inside.read_integer().field(VERSION)?;
    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }

    match value.as_u64() {
        // X.690 11.5: DER omits a component equal to its default, and the
        // version defaults to v1. A certificate spelling zero out has written
        // the absent field, which is not DER.
        Some(0) if inside.encoding().is_der() => Err(fail(ErrorCode::MalformedValue)),
        Some(0) => Ok(Version::V1),
        Some(1) => Ok(Version::V2),
        Some(2) => Ok(Version::V3),
        // A version this crate does not know describes fields it does not
        // know, and reading it as the newest one it does know would be
        // guessing at what the issuer meant.
        _ => Err(fail(ErrorCode::UnsupportedVersion)),
    }
}

fn read_validity<'a>(parent: &Reader<'a>, element: &Element<'a>) -> Result<Validity> {
    let fail = |code| Error::new(code, VALIDITY, element.span().start);
    require(element, Tag::constructed(universal::SEQUENCE), VALIDITY)?;

    let mut inside = parent.enter(element).field(VALIDITY)?;
    let before = inside
        .next_element()
        .field(VALIDITY)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    let after = inside
        .next_element()
        .field(VALIDITY)?
        .ok_or_else(|| fail(ErrorCode::MissingField))?;
    if !inside.is_empty() {
        return Err(fail(ErrorCode::TrailingData));
    }

    Ok(Validity {
        not_before: time::read(&before, NOT_BEFORE)?,
        not_after: time::read(&after, NOT_AFTER)?,
    })
}

#[cfg(test)]
mod tests;
