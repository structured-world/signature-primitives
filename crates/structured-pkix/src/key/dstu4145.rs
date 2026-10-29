//! DSTU 4145 SPKI framing, without point decompression or provider selection.

use super::PublicKeyInfo;
use crate::algorithm::Producer;
use crate::algorithm::dstu4145::{self, Octets, Parameters, Profile, parameters};
use crate::error::Located;
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{Execution, Work};
use structured_asn1::{Element, Encoding, ScopedReader, Tag, universal};

const FIELD: &str = "subjectPublicKey.dstu4145";

/// Original compressed point, key profile and optional written parameters.
///
/// This is inspection data. Missing parameters and unknown named curves stay
/// visible; without a known degree the point's width cannot be qualified.
/// Readability never establishes a usable field, point or signature.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a> {
    profile: Profile,
    parameters: Option<Parameters<'a>>,
    element: Element<'a>,
    point: Octets<'a>,
    producer: Producer<'a>,
}

impl<'a> PublicKey<'a> {
    /// Written key profile; its digest does not constrain a future signature.
    #[must_use]
    pub const fn profile(self) -> Profile {
        self.profile
    }
    /// Written parameters only. No EC-style NULL or absence inheritance occurs.
    #[must_use]
    pub const fn parameters(self) -> Option<Parameters<'a>> {
        self.parameters
    }
    /// Complete original OCTET STRING carried by SPKI's BIT STRING.
    #[must_use]
    pub const fn element(self) -> Element<'a> {
        self.element
    }
    /// Exact compressed point in its declared byte order, not decompressed.
    #[must_use]
    pub const fn point(self) -> Octets<'a> {
        self.point
    }
    /// Degree used to qualify point width, or None for missing/unknown parameters.
    #[must_use]
    pub fn degree(self) -> Option<u32> {
        self.parameters.and_then(|p| p.curve().degree())
    }
    /// Funds deferred point/parameter interpretation against source and current.
    #[must_use]
    pub fn execution_in<'q, W: Work>(&self, current: &'q W) -> Execution<'q>
    where
        'a: 'q,
    {
        self.producer.execution_in(current)
    }
}

/// Reads the actual DER OCTET STRING inside SPKI's unpadded BIT STRING.
///
/// The pinned certificate profile §§3.10, 3.11.1.1–5 and 3.14 requires this
/// wrapper, ceil(m/8) field width and zero unused field bits. The wrapper is
/// not raw EC point bytes and is never stripped by guessing its first byte.
/// Original encoding coordinates, parser ceilings and depth are preserved;
/// returned views borrow the source and retain no storage or account owner.
/// <https://zakon.rada.gov.ua/laws/show/z1398-12>
///
/// # Errors
/// Unknown algorithm, invalid parameters/wrapper/width, or original located
/// resource refusal. Unknown curve names preserve `degree() == None` rather
/// than borrowing an issuer's parameters or guessing from payload length.
pub fn read<'a, W: Work>(info: PublicKeyInfo<'a>, current: &W) -> Result<PublicKey<'a>> {
    let identifier = info.algorithm();
    let profile = dstu4145::identify(identifier, current)?
        .ok_or_else(|| Error::new(ErrorCode::UnexpectedField, FIELD, identifier.offset()))?;
    let parameters = parameters::read_known(identifier, profile, current)?;
    let bits = info.whole_octets(FIELD)?;
    let (reader, element) = identifier
        .nested(bits, info.key_offset())
        .open(current, FIELD)?;
    let degree = parameters.and_then(|p| p.curve().degree());
    let (element, point) = if reader.encoding().is_der() {
        point(&reader, element, degree, profile)?
    } else {
        let mut strict = reader.reread(&element, Encoding::Der).field(FIELD)?;
        let written = strict
            .next_element()
            .field(FIELD)?
            .ok_or_else(|| Error::new(ErrorCode::MissingField, FIELD, strict.offset()))?;
        point(&strict, written, degree, profile)?
    };
    Ok(PublicKey {
        profile,
        parameters,
        element,
        point,
        producer: identifier.execution_origin(),
    })
}

fn point<'a>(
    reader: &ScopedReader<'a, '_>,
    element: Element<'a>,
    degree: Option<u32>,
    profile: Profile,
) -> Result<(Element<'a>, Octets<'a>)> {
    let point = if let Some(degree) = degree {
        parameters::field_octets(reader, element, degree, profile.byte_order())
            .map_err(|error| Error::new(error.code(), FIELD, error.offset()))?
    } else {
        if element.tag() != Tag::primitive(universal::OCTET_STRING) {
            return Err(Error::new(
                ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag),
                FIELD,
                element.span().start,
            ));
        }
        Octets::new(
            element.contents(),
            profile.byte_order(),
            element.contents_span().start,
        )
    };
    Ok((element, point))
}
