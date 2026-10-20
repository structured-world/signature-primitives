//! Borrowed DSA key components, before bigint or group validation.
//!
//! RFC 3279 §2.3.2 carries optional `Dss-Parms ::= SEQUENCE { p INTEGER,
//! q INTEGER, g INTEGER }` and a DER INTEGER `y` inside subjectPublicKey.
//! [`read`] preserves these sources and effective parameter inheritance;
//! success does not establish a usable DSA group, key strength or signature.
//! <https://www.rfc-editor.org/rfc/rfc3279#section-2.3.2>

use super::same_oid;
use crate::error::{Error, ErrorCode, Located, Result};
use crate::path::WorkingKey;
use structured_asn1::memory::Work;
use structured_asn1::{Element, Encoding, Integer, Oid, ScopedReader, Tag, universal};

const OID: Oid<'static> = Oid::from_bytes(&[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01]);
const FIELD: &str = "subjectPublicKey.dsa";
const PARAMETERS: &str = "subjectPublicKeyInfo.algorithm.parameters";

/// A nonnegative component with its original INTEGER and location.
///
/// Zero is inspectable, not a valid DSA component. Group and range validation
/// belongs to the selected backend, before arithmetic or key acceptance.
#[derive(Debug, Clone, Copy)]
pub struct Component<'a> {
    element: Element<'a>,
    integer: Integer<'a>,
}

impl<'a> Component<'a> {
    /// Borrowed unsigned magnitude, excluding a required positive sign octet.
    /// Zero is represented by the single octet `0x00`.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        match self.integer.as_bytes() {
            [0, rest @ ..] if !rest.is_empty() => rest,
            bytes => bytes,
        }
    }

    /// Original minimal two's-complement encoding, including any sign octet.
    #[must_use]
    pub fn integer(&self) -> Integer<'a> {
        self.integer
    }

    /// Original whole INTEGER element in its source's coordinates.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }
}

/// The domain parameters in force, still borrowing their original source.
#[derive(Debug, Clone, Copy)]
pub struct Parameters<'a> {
    element: Element<'a>,
    p: Component<'a>,
    q: Component<'a>,
    g: Component<'a>,
    inherited: bool,
}

impl<'a> Parameters<'a> {
    /// The encoded prime candidate; primality has not been established.
    #[must_use]
    pub fn p(&self) -> &Component<'a> {
        &self.p
    }

    /// The encoded subgroup-order candidate; no group check is implied.
    #[must_use]
    pub fn q(&self) -> &Component<'a> {
        &self.q
    }

    /// The encoded generator candidate; no range or order check is implied.
    #[must_use]
    pub fn g(&self) -> &Component<'a> {
        &self.g
    }

    /// The whole original Dss-Parms SEQUENCE, including its header.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }

    /// Whether these parameters came from an authority above this key.
    #[must_use]
    pub fn is_inherited(&self) -> bool {
        self.inherited
    }
}

/// The subject's original DSA public component and effective parameters.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a> {
    y: Component<'a>,
    parameters: Option<Parameters<'a>>,
}

impl<'a> PublicKey<'a> {
    /// Original unsigned public component; no mathematical validity is claimed.
    #[must_use]
    pub fn y(&self) -> &Component<'a> {
        &self.y
    }

    /// Effective parameters, or None when neither written nor inherited.
    /// The caller needs independently supplied parameters before verification
    /// in the latter case (RFC 3279 §2.3.2).
    #[must_use]
    pub fn parameters(&self) -> Option<&Parameters<'a>> {
        self.parameters.as_ref()
    }
}

/// Reads DSA structure under the current execution and original source ceilings.
///
/// Accepts only id-dsa. Written NULL is malformed, even if the generic path
/// state carries inherited parameters. Absent parameters remain distinguishable
/// from supplied ones. Parameters use their original encoding; `y` must be DER
/// even under a BER parent. Reader metadata is funded before allocation; all
/// returned views borrow original bytes and retain no storage or execution.
///
/// # Errors
/// Reports another algorithm, malformed unsigned components, missing/extra
/// fields, encoding errors and original located resource failures separately.
/// This does not check primes, group membership, strength or signature validity.
///
/// # Examples
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::{PublicKeyInfo, key::dsa, path::WorkingKey};
/// let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
/// let parser = Parser::der(memory.clone());
/// // id-dsa, omitted parameters; subjectPublicKey contains INTEGER 7.
/// let bytes = b"\x30\x11\x30\x09\x06\x07\x2a\x86\x48\xce\x38\x04\x01\x03\x04\x00\x02\x01\x07";
/// let mut reader = parser.read(bytes, 400).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let info = PublicKeyInfo::read_element(&reader, &element, "key")?;
/// let key = dsa::read(WorkingKey::standing(info), &memory)?;
/// assert_eq!(key.y().as_bytes(), [7]);
/// assert!(key.parameters().is_none());
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn read<'a, W: Work>(key: WorkingKey<'a>, execution: &W) -> Result<PublicKey<'a>> {
    let info = key.key();
    let own = info.algorithm();
    if !same_oid(own.algorithm(), OID, execution, FIELD, own.offset())? {
        return Err(Error::new(ErrorCode::UnexpectedField, FIELD, own.offset()));
    }
    // RFC 3279 §2.3.2: omission means no parameter element at all. Generic
    // RFC5280 NULL inheritance must not repair an invalid DSA spelling.
    if let Some(source) = own.parameters_nested()
        && own.has_null_parameter()
    {
        let (_, written) = source.open(execution, PARAMETERS)?;
        return Err(Error::new(
            ErrorCode::MalformedValue,
            PARAMETERS,
            written.span().start,
        ));
    }
    let parameters = if let Some(source) = key.parameter_source() {
        let (reader, element) = source.open(execution, PARAMETERS)?;
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::new(
                ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                PARAMETERS,
                element.span().start,
            ));
        }
        let mut fields = reader.enter(&element).field(PARAMETERS)?;
        let p = component(&mut fields, PARAMETERS)?;
        let q = component(&mut fields, PARAMETERS)?;
        let g = component(&mut fields, PARAMETERS)?;
        if !fields.is_empty() {
            return Err(Error::new(
                ErrorCode::TrailingData,
                PARAMETERS,
                fields.offset(),
            ));
        }
        Some(Parameters {
            element,
            p,
            q,
            g,
            inherited: own.parameters().is_none(),
        })
    } else {
        None
    };
    let octets = info.whole_octets(FIELD)?;
    let (reader, element) = own
        .nested(octets, info.key_offset())
        .open(execution, FIELD)?;
    // RFC 3279 §2.3.2 requires DER for the INTEGER carried in the bits,
    // independently of the enclosing source's BER permission.
    let y = if reader.encoding().is_der() {
        unsigned(&reader, element, FIELD)?
    } else {
        let mut strict = reader.reread(&element, Encoding::Der).field(FIELD)?;
        component(&mut strict, FIELD)?
    };
    Ok(PublicKey { y, parameters })
}

fn component<'a>(reader: &mut ScopedReader<'a, '_>, field: &'static str) -> Result<Component<'a>> {
    let element = reader
        .expect(Tag::primitive(universal::INTEGER))
        .field(field)?;
    unsigned(reader, element, field)
}

fn unsigned<'a>(
    reader: &ScopedReader<'a, '_>,
    element: Element<'a>,
    field: &'static str,
) -> Result<Component<'a>> {
    if element.tag() != Tag::primitive(universal::INTEGER) {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            field,
            element.span().start,
        ));
    }
    let integer = reader.integer(&element).field(field)?;
    if integer.is_negative() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            field,
            element.span().start,
        ));
    }
    Ok(Component { element, integer })
}
