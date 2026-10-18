//! The elliptic-curve public key a certificate carries, read in place.
//!
//! RFC 5480 §2.1.1 writes the curve as `ECParameters ::= CHOICE { namedCurve
//! OBJECT IDENTIFIER, implicitCurve NULL, specifiedCurve SpecifiedECDomain }`
//! and allows only `namedCurve` in PKIX; §2.2 carries the point as the SEC1
//! octets themselves. [`read`] reports which choice was written rather than
//! refusing the other two, and refuses only a point no curve can have. Which
//! curves are supported, their coordinate widths and whether the point lies on
//! the curve belong to the provider that verifies with the key.
//! <https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1>

use super::same_oid;
use crate::error::{Error, ErrorCode, Located, Result};
use crate::path::WorkingKey;
use structured_asn1::memory::Work;
use structured_asn1::{Element, Oid, Tag, universal};

const FIELD: &str = "subjectPublicKey.ec";
const PARAMETERS: &str = "subjectPublicKeyInfo.algorithm.parameters";

/// Which `ECParameters` choice was written.
#[derive(Debug, Clone, Copy)]
pub enum Curve<'a> {
    /// `namedCurve`, the only choice RFC 5480 §2.1.1 permits in PKIX.
    Named(Oid<'a>),
    /// `implicitCurve`: the curve is known only out of band.
    Implicit,
    /// `specifiedCurve`: explicit domain parameters, kept encoded.
    Specified(Element<'a>),
}

/// A SEC1 point as written (SEC1 v2 §2.3.3).
#[derive(Debug, Clone, Copy)]
pub enum Point<'a> {
    /// `0x04 || X || Y`, with both coordinates of one width.
    Uncompressed {
        /// The x coordinate.
        x: &'a [u8],
        /// The y coordinate.
        y: &'a [u8],
    },
    /// `0x02 || X` or `0x03 || X`, naming the parity of y.
    Compressed {
        /// The x coordinate.
        x: &'a [u8],
        /// Whether y is odd (`0x03`).
        odd: bool,
    },
}

impl Point<'_> {
    /// The coordinate width in octets, to compare with the width of the
    /// curve the caller recognized.
    #[must_use]
    pub fn coordinate_len(self) -> usize {
        match self {
            Self::Uncompressed { x, .. } | Self::Compressed { x, .. } => x.len(),
        }
    }
}

/// An elliptic-curve public key, as the certificate wrote it.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a> {
    curve: Curve<'a>,
    parameters: Element<'a>,
    inherited: bool,
    point: Point<'a>,
    octets: &'a [u8],
    offset: u64,
}

impl<'a> PublicKey<'a> {
    /// The curve choice in force.
    #[must_use]
    pub fn curve(self) -> Curve<'a> {
        self.curve
    }

    /// The original `ECParameters` element the curve was read from.
    #[must_use]
    pub fn parameters(self) -> Element<'a> {
        self.parameters
    }

    /// Whether the parameters were written by an authority above this key
    /// rather than by the key itself (RFC 5280 §6.1.4(e)).
    #[must_use]
    pub fn is_inherited(self) -> bool {
        self.inherited
    }

    /// The point, split into its coordinates.
    #[must_use]
    pub fn point(self) -> Point<'a> {
        self.point
    }

    /// The whole original point encoding, prefix octet included.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.octets
    }

    /// Where the point encoding starts in the whole document.
    #[must_use]
    pub fn offset(self) -> u64 {
        self.offset
    }
}

/// Reads the elliptic-curve key carried by `key` under the current `execution`.
///
/// The key's algorithm must be `id-ecPublicKey`. Its own parameters apply
/// where written; a key that writes none or NULL stands in the parameters
/// inherited along the path, and a lone NULL is `implicitCurve`. Parameters
/// are decoded with their original parser session, offsets, encoding and
/// depth, which may belong to the authority's certificate; `execution` pays
/// for every step. Nothing is copied or allocated.
///
/// # Errors
///
/// `UnexpectedField` for another algorithm, `MissingField` when no parameters
/// are in force, `MalformedValue` for padded key bits or a point that is
/// empty, the point at infinity, the hybrid form RFC 5480 §2.2 forbids or of
/// unequal coordinate widths, and the located encoding or resource error
/// otherwise. A resource refusal happens before the work it would fund.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::{PublicKeyInfo, key::ec, path::WorkingKey};
/// let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
/// let parser = Parser::der(memory.clone());
/// // id-ecPublicKey, prime256v1; compressed point with a one-octet x
/// let spki = b"\x30\x1b\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\
///              \x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x04\x00\x03\x05\x06";
/// let mut reader = parser.read(spki, 0).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let key = PublicKeyInfo::read_element(&reader, &element, "subjectPublicKeyInfo")?;
/// let read = ec::read(WorkingKey::standing(key), &memory)?;
/// assert!(matches!(read.curve(), ec::Curve::Named(_)));
/// assert!(matches!(read.point(), ec::Point::Compressed { odd: true, .. }));
/// assert_eq!(read.point().coordinate_len(), 2);
/// assert_eq!(read.offset(), 26);
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn read<'a, W: Work>(key: WorkingKey<'a>, execution: &W) -> Result<PublicKey<'a>> {
    let info = key.key();
    let own = info.algorithm();
    if !same_oid(
        own.algorithm(),
        crate::oid::EC_PUBLIC_KEY,
        execution,
        FIELD,
        own.offset(),
    )? {
        return Err(Error::new(ErrorCode::UnexpectedField, FIELD, own.offset()));
    }
    // RFC 5280 §6.1.4(e) treats absent and NULL parameters alike for
    // inheritance. Without an authority's parameters, a written NULL is the
    // key's own `implicitCurve` choice.
    let (source, inherited) = match (key.parameter_source(), own.parameters_nested()) {
        (Some(source), _) => (source, own.has_no_parameters()),
        (None, Some(null)) => (null, false),
        (None, None) => {
            return Err(Error::new(
                ErrorCode::MissingField,
                PARAMETERS,
                own.offset(),
            ));
        }
    };
    let (reader, parameters) = source.open(execution, PARAMETERS)?;
    let curve = if parameters.tag() == Tag::primitive(universal::OID) {
        Curve::Named(reader.oid(&parameters).field(PARAMETERS)?)
    } else if parameters.tag() == Tag::primitive(universal::NULL) {
        reader.null(&parameters).field(PARAMETERS)?;
        Curve::Implicit
    } else if parameters.tag() == Tag::constructed(universal::SEQUENCE) {
        Curve::Specified(parameters)
    } else {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            PARAMETERS,
            parameters.span().start,
        ));
    };

    let octets = info.whole_octets(FIELD)?;
    let offset = info.key_offset();
    execution
        .charge_work(1)
        .map_err(|reason| Error::resource(reason, FIELD, offset))?;
    // SEC1 v2 §2.3.3: one prefix octet, then x, then y for the uncompressed
    // form. The single zero octet is the point at infinity, which is not a
    // public key (SEC1 v2 §3.2.2), and RFC 5480 §2.2 forbids the hybrid
    // 0x06/0x07 form. https://www.secg.org/sec1-v2.pdf
    let point = match octets {
        [0x04, coordinates @ ..] if !coordinates.is_empty() && coordinates.len() % 2 == 0 => {
            let (x, y) = coordinates.split_at(coordinates.len() / 2);
            Point::Uncompressed { x, y }
        }
        [prefix @ (0x02 | 0x03), x @ ..] if !x.is_empty() => Point::Compressed {
            x,
            odd: *prefix == 0x03,
        },
        _ => return Err(Error::new(ErrorCode::MalformedValue, FIELD, offset)),
    };
    Ok(PublicKey {
        curve,
        parameters,
        inherited,
        point,
        octets,
        offset,
    })
}
