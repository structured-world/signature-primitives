//! Original DSTU4145Params, read without group arithmetic or inheritance.

use super::{Basis, ByteOrder, Octets, Profile, identify};
use crate::algorithm::{AlgorithmIdentifier, Producer};
use crate::error::Located;
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{Execution, Work};
use structured_asn1::{Element, Encoding, Integer, Oid, ScopedReader, Span, Tag, universal};

const FIELD: &str = "dstu4145.parameters";

/// Original nonnegative ASN.1 INTEGER with its complete encoded range.
#[derive(Debug, Clone, Copy)]
pub struct IntegerField<'a> {
    span: Span,
    value: Integer<'a>,
}

impl<'a> IntegerField<'a> {
    /// Original INTEGER value, not a narrowed backend scalar.
    #[must_use]
    pub const fn value(self) -> Integer<'a> {
        self.value
    }

    /// Original complete INTEGER range, including its tag and header.
    #[must_use]
    pub const fn span(self) -> Span {
        self.span
    }
}

/// Field representation, not a primality or irreducibility assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reduction {
    /// Polynomial x^m + x^k + 1.
    Trinomial(u32),
    /// Polynomial x^m + x^k + x^j + x^l + 1, with k < j < l.
    Pentanomial {
        /// Smallest nonzero reduction exponent.
        k: u32,
        /// Middle reduction exponent.
        j: u32,
        /// Largest reduction exponent, strictly below m.
        l: u32,
    },
    /// Omitted reduction polynomial for an optimal normal basis.
    OptimalNormal,
}

/// A written named-curve OID, including unknown names.
#[derive(Debug, Clone, Copy)]
pub struct NamedCurve<'a> {
    element: Element<'a>,
    identifier: Oid<'a>,
    known: Option<(Basis, u32)>,
}

impl<'a> NamedCurve<'a> {
    /// Exact written identity, never inferred from point width.
    #[must_use]
    pub const fn identifier(self) -> Oid<'a> {
        self.identifier
    }

    /// Original OID element and its source coordinates.
    #[must_use]
    pub const fn element(self) -> Element<'a> {
        self.element
    }

    /// Known field basis and degree, or None for an unsupported curve name.
    /// No mathematical parameters are synthesized for unknown names.
    #[must_use]
    pub const fn known(self) -> Option<(Basis, u32)> {
        self.known
    }
}

/// Written explicit curve components. No point, order or field math is done.
#[derive(Debug, Clone, Copy)]
pub struct ExplicitCurve<'a> {
    element: Element<'a>,
    degree: IntegerField<'a>,
    degree_value: u32,
    field: Span,
    reduction: Reduction,
    a: IntegerField<'a>,
    b: Octets<'a>,
    order: IntegerField<'a>,
    base_point: Octets<'a>,
}

impl<'a> ExplicitCurve<'a> {
    /// Whole original ECBinary SEQUENCE.
    #[must_use]
    pub const fn element(self) -> Element<'a> {
        self.element
    }
    /// Original complete BinaryField range, including reduction exponents.
    #[must_use]
    pub const fn field_span(self) -> Span {
        self.field
    }
    /// Original degree INTEGER.
    #[must_use]
    pub const fn degree(self) -> IntegerField<'a> {
        self.degree
    }
    /// Structural field degree, not a supported-backend assertion.
    #[must_use]
    pub const fn degree_value(self) -> u32 {
        self.degree_value
    }
    /// Polynomial exponents or optimal-normal-basis omission.
    #[must_use]
    pub const fn reduction(self) -> Reduction {
        self.reduction
    }
    /// Coefficient A, constrained to zero or one.
    #[must_use]
    pub const fn a(self) -> IntegerField<'a> {
        self.a
    }
    /// Coefficient B in the selected byte order, still unvalidated mathematically.
    #[must_use]
    pub const fn b(self) -> Octets<'a> {
        self.b
    }
    /// Positive subgroup-order candidate, not a primality assertion.
    #[must_use]
    pub const fn order(self) -> IntegerField<'a> {
        self.order
    }
    /// Compressed original base point; no decompression is attempted.
    #[must_use]
    pub const fn base_point(self) -> Octets<'a> {
        self.base_point
    }
}

/// The actual named or explicit CHOICE, without a guessed fallback.
#[derive(Debug, Clone, Copy)]
pub enum Curve<'a> {
    /// A named curve, possibly unknown to the bounded metadata table.
    Named(NamedCurve<'a>),
    /// Explicit original components.
    Explicit(ExplicitCurve<'a>),
}

impl Curve<'_> {
    /// Field degree when written explicitly or known from the exact curve OID.
    #[must_use]
    pub const fn degree(&self) -> Option<u32> {
        match self {
            Self::Named(curve) => match curve.known {
                Some((_, degree)) => Some(degree),
                None => None,
            },
            Self::Explicit(curve) => Some(curve.degree_value),
        }
    }
}

/// Borrowed original DSTU4145Params. Storage and arithmetic belong to callers.
#[derive(Debug, Clone, Copy)]
pub struct Parameters<'a> {
    element: Element<'a>,
    curve: Curve<'a>,
    dke: Option<Element<'a>>,
    producer: Producer<'a>,
}

impl<'a> Parameters<'a> {
    /// Whole original parameter SEQUENCE, without canonicalization.
    #[must_use]
    pub const fn element(self) -> Element<'a> {
        self.element
    }
    /// Original named or explicit curve.
    #[must_use]
    pub const fn curve(self) -> Curve<'a> {
        self.curve
    }
    /// Written packed 64-octet DKE, or None for normative DKE number one.
    /// Absence never inherits an authority's DKE. Provider selection of the
    /// default is separate from parsing (§§3.11.1 and 3.12 of the profile).
    #[must_use]
    pub const fn dke(self) -> Option<Element<'a>> {
        self.dke
    }
    /// Funds deferred interpretation from the original and current ceilings.
    #[must_use]
    pub fn execution_in<'q, W: Work>(&self, current: &'q W) -> Execution<'q>
    where
        'a: 'q,
    {
        self.producer.execution_in(current)
    }
}

/// Reads key-role parameters under the producing parser and current Work.
///
/// Returns None for actual absence, not NULL and not inherited EC parameters.
/// The pinned profile §§3.10–3.12 requires DER and a 64-octet packed DKE.
/// Unknown named curves remain inspectable with `known() == None`; neither
/// that fact nor readable explicit components permits a provider operation.
/// <https://zakon.rada.gov.ua/laws/show/z1398-12>
///
/// # Errors
/// Another algorithm, malformed/extra fields, unsupported explicit version,
/// written DER DEFAULT, or the original located resource/processing failure.
pub fn read_parameters<'a, W: Work>(
    identifier: AlgorithmIdentifier<'a>,
    current: &W,
) -> Result<Option<Parameters<'a>>> {
    let profile = identify(identifier, current)?
        .ok_or_else(|| Error::new(ErrorCode::UnexpectedField, FIELD, identifier.offset()))?;
    read_known(identifier, profile, current)
}

pub(crate) fn read_known<'a, W: Work>(
    identifier: AlgorithmIdentifier<'a>,
    profile: Profile,
    current: &W,
) -> Result<Option<Parameters<'a>>> {
    let Some(source) = identifier.parameters_nested() else {
        return Ok(None);
    };
    let (reader, element) = source.open(current, FIELD)?;
    let value = if reader.encoding().is_der() {
        fields(&reader, element, profile, identifier.execution_origin())?
    } else {
        let mut strict = reader.reread(&element, Encoding::Der).field(FIELD)?;
        let element = strict
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, strict.offset()))?;
        fields(&strict, element, profile, identifier.execution_origin())?
    };
    Ok(Some(value))
}

fn fields<'a>(
    reader: &ScopedReader<'a, '_>,
    element: Element<'a>,
    profile: Profile,
    producer: Producer<'a>,
) -> Result<Parameters<'a>> {
    require_tag(element, Tag::constructed(universal::SEQUENCE))?;
    let mut inside = reader.enter(&element).field(FIELD)?;
    let first = next(&mut inside)?;
    let curve = if first.tag() == Tag::primitive(universal::OID) {
        let identifier = inside.oid(&first).field(FIELD)?;
        inside
            .charge(identifier.as_bytes().len() as u64 + 1)
            .field(FIELD)?;
        let known = named(identifier);
        if let Some((basis, _)) = known
            && basis != profile.basis()
        {
            return Err(Error::new(
                ErrorCode::MalformedValue,
                FIELD,
                first.span().start,
            ));
        }
        Curve::Named(NamedCurve {
            element: first,
            identifier,
            known,
        })
    } else {
        Curve::Explicit(explicit(&inside, first, profile)?)
    };
    let dke = inside.next_element().field(FIELD)?;
    if let Some(dke) = dke {
        require_tag(dke, Tag::primitive(universal::OCTET_STRING))?;
        if dke.contents().len() != 64 {
            return Err(Error::new(
                ErrorCode::MalformedValue,
                FIELD,
                dke.span().start,
            ));
        }
    }
    exhausted(&inside)?;
    Ok(Parameters {
        element,
        curve,
        dke,
        producer,
    })
}

fn explicit<'a>(
    reader: &ScopedReader<'a, '_>,
    element: Element<'a>,
    profile: Profile,
) -> Result<ExplicitCurve<'a>> {
    require_tag(element, Tag::constructed(universal::SEQUENCE))?;
    let mut inside = reader.enter(&element).field(FIELD)?;
    let field = next(&mut inside)?;
    if field.tag() == Tag::context(true, 0) {
        let mut version = inside.enter(&field).field(FIELD)?;
        let value = integer(&mut version)?;
        exhausted(&version)?;
        let value = number(&version, value)?;
        // X.690 §11.5: DEFAULT zero must not be explicitly written in DER.
        // https://www.itu.int/rec/T-REC-X.690-202102-I/en
        let code = if value == 0 {
            ErrorCode::DefaultWritten
        } else {
            ErrorCode::UnsupportedVersion
        };
        return Err(Error::new(code, FIELD, field.span().start));
    }
    require_tag(field, Tag::constructed(universal::SEQUENCE))?;
    let mut binary = inside.enter(&field).field(FIELD)?;
    let degree = integer(&mut binary)?;
    let degree_value = number(&binary, degree)?;
    if degree_value == 0 {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            degree.span.start,
        ));
    }
    let reduction = if profile.basis() == Basis::OptimalNormal {
        exhausted(&binary)?;
        Reduction::OptimalNormal
    } else {
        let written = next(&mut binary)?;
        let reduction = if written.tag() == Tag::primitive(universal::INTEGER) {
            let k = integer_element(&binary, written)?;
            let k = number(&binary, k)?;
            if k == 0 || k >= degree_value {
                return Err(Error::new(
                    ErrorCode::MalformedValue,
                    FIELD,
                    written.span().start,
                ));
            }
            Reduction::Trinomial(k)
        } else {
            require_tag(written, Tag::constructed(universal::SEQUENCE))?;
            let mut terms = binary.enter(&written).field(FIELD)?;
            let k = integer(&mut terms)?;
            let k = number(&terms, k)?;
            let j = integer(&mut terms)?;
            let j = number(&terms, j)?;
            let l = integer(&mut terms)?;
            let l = number(&terms, l)?;
            exhausted(&terms)?;
            if k == 0 || k >= j || j >= l || l >= degree_value {
                return Err(Error::new(
                    ErrorCode::MalformedValue,
                    FIELD,
                    written.span().start,
                ));
            }
            Reduction::Pentanomial { k, j, l }
        };
        exhausted(&binary)?;
        reduction
    };
    let a = integer(&mut inside)?;
    if number(&inside, a)? > 1 {
        return Err(Error::new(ErrorCode::MalformedValue, FIELD, a.span.start));
    }
    let b_element = next(&mut inside)?;
    let b = field_octets(&inside, b_element, degree_value, profile.byte_order())?;
    let order = integer(&mut inside)?;
    inside.charge(1).field(FIELD)?;
    if order.value.as_bytes() == [0] {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            order.span.start,
        ));
    }
    let point_element = next(&mut inside)?;
    let base_point = field_octets(&inside, point_element, degree_value, profile.byte_order())?;
    exhausted(&inside)?;
    Ok(ExplicitCurve {
        element,
        degree,
        degree_value,
        field: field.span(),
        reduction,
        a,
        b,
        order,
        base_point,
    })
}

pub(crate) fn field_octets<'a>(
    reader: &ScopedReader<'a, '_>,
    element: Element<'a>,
    degree: u32,
    byte_order: ByteOrder,
) -> Result<Octets<'a>> {
    require_tag(element, Tag::primitive(universal::OCTET_STRING))?;
    let bytes = element.contents();
    reader.charge(1).field(FIELD)?;
    if degree == 0 || bytes.len() as u64 != u64::from(degree).div_ceil(8) {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            element.span().start,
        ));
    }
    let unused = (8 - degree % 8) % 8;
    let top = match byte_order {
        ByteOrder::LittleEndian => bytes[bytes.len() - 1],
        ByteOrder::BigEndian => bytes[0],
    };
    if unused != 0 && top >> (8 - unused) != 0 {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            element.contents_span().start,
        ));
    }
    Ok(Octets::new(
        bytes,
        byte_order,
        element.contents_span().start,
    ))
}

fn named(identifier: Oid<'_>) -> Option<(Basis, u32)> {
    let (basis, index) = match identifier.as_bytes() {
        [0x2a, 0x86, 0x24, 2, 1, 1, 1, 1, 3, 1, basis, 2, index] => (*basis, *index),
        [
            0x2a,
            0x86,
            0x24,
            2,
            1,
            1,
            1,
            1,
            3,
            6,
            1..=3,
            basis,
            2,
            index,
        ] => (*basis, *index),
        _ => return None,
    };
    // Pinned OID table, named polynomial and optimal-normal-basis branches.
    // https://zakon.rada.gov.ua/laws/show/z1399-12
    let (basis, degrees): (_, &[u32]) = match basis {
        1 => (
            Basis::Polynomial,
            &[163, 167, 173, 179, 191, 233, 257, 307, 367, 431],
        ),
        2 => (Basis::OptimalNormal, &[173, 179, 191, 233, 431]),
        _ => return None,
    };
    degrees
        .get(usize::from(index))
        .map(|degree| (basis, *degree))
}

fn require_tag(element: Element<'_>, tag: Tag) -> Result<()> {
    if element.tag() != tag {
        return Err(Error::new(
            ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
            FIELD,
            element.span().start,
        ));
    }
    Ok(())
}
fn next<'a>(reader: &mut ScopedReader<'a, '_>) -> Result<Element<'a>> {
    reader
        .next_element()
        .field(FIELD)?
        .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, reader.offset()))
}
fn exhausted(reader: &ScopedReader<'_, '_>) -> Result<()> {
    if !reader.is_empty() {
        return Err(Error::new(ErrorCode::TrailingData, FIELD, reader.offset()));
    }
    Ok(())
}
fn integer<'a>(reader: &mut ScopedReader<'a, '_>) -> Result<IntegerField<'a>> {
    let element = next(reader)?;
    integer_element(reader, element)
}
fn integer_element<'a>(
    reader: &ScopedReader<'a, '_>,
    element: Element<'a>,
) -> Result<IntegerField<'a>> {
    require_tag(element, Tag::primitive(universal::INTEGER))?;
    let value = reader.integer(&element).field(FIELD)?;
    reader.charge(1).field(FIELD)?;
    if value.is_negative() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            element.span().start,
        ));
    }
    Ok(IntegerField {
        span: element.span(),
        value,
    })
}
fn number(reader: &ScopedReader<'_, '_>, value: IntegerField<'_>) -> Result<u32> {
    reader
        .charge(value.value.as_bytes().len() as u64)
        .field(FIELD)?;
    value
        .value
        .as_u32()
        .ok_or_else(|| Error::new(ErrorCode::ValueTooLarge, FIELD, value.span.start))
}
