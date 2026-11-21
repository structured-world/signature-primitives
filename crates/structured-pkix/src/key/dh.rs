//! Borrowed ANSI X9.42 DH structure (RFC 3279 section 2.3.3).
//!
//! This is not PKCS#3 DH: the OID and parameter order differ. No primality,
//! subgroup, range, strength or key-agreement operation is performed here.

use super::{PublicKeyInfo, dsa::unsigned, same_oid};
use crate::algorithm::AlgorithmIdentifier;
use crate::error::{Error, ErrorCode, Located, Result};
use structured_asn1::memory::Work;
use structured_asn1::{BitString, Element, Encoding, Oid, ScopedReader, Tag, universal};

pub use super::dsa::Component;

/// dhpublicnumber, distinct from PKCS#3 dhKeyAgreement.
pub const IDENTIFIER: Oid<'static> = Oid::from_bytes(&[42, 134, 72, 206, 62, 2, 1]);
const PARAMETERS: &str = "dh.domainParameters";
const PUBLIC: &str = "subjectPublicKey.dh";
const PRIVATE: &str = "privateKey.dh";

/// Recognizes the algorithm only, under original/current work ceilings.
/// Parameters and key bytes are checked by the corresponding readers.
pub fn is_algorithm<W: Work>(algorithm: AlgorithmIdentifier<'_>, work: &W) -> Result<bool> {
    same_oid(
        algorithm.algorithm(),
        IDENTIFIER,
        &algorithm.query_in(work),
        PARAMETERS,
        algorithm.offset(),
    )
}

/// Original optional domain-generation evidence, not verified generation.
#[derive(Debug, Clone, Copy)]
pub struct Validation<'a> {
    element: Element<'a>,
    seed_element: Element<'a>,
    seed: BitString<'a>,
    counter: Component<'a>,
}
impl<'a> Validation<'a> {
    /// Whole original `ValidationParms` SEQUENCE.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }
    /// Original seed, including its unused-bit count.
    #[must_use]
    pub fn seed(&self) -> BitString<'a> {
        self.seed
    }
    /// Physical seed BIT STRING element.
    #[must_use]
    pub fn seed_element(&self) -> Element<'a> {
        self.seed_element
    }
    /// Nonnegative generation counter of arbitrary width.
    #[must_use]
    pub fn pgen_counter(&self) -> &Component<'a> {
        &self.counter
    }
}

/// Written p, g, q and optional j / validation evidence, without inheritance.
#[derive(Debug, Clone, Copy)]
pub struct Parameters<'a> {
    element: Element<'a>,
    p: Component<'a>,
    g: Component<'a>,
    q: Component<'a>,
    j: Option<Component<'a>>,
    validation: Option<Validation<'a>>,
}
impl<'a> Parameters<'a> {
    /// Whole original `DomainParameters` SEQUENCE.
    #[must_use]
    pub fn element(&self) -> Element<'a> {
        self.element
    }
    /// Prime candidate, not a primality assertion.
    #[must_use]
    pub fn p(&self) -> &Component<'a> {
        &self.p
    }
    /// Generator candidate, not a group-membership assertion.
    #[must_use]
    pub fn g(&self) -> &Component<'a> {
        &self.g
    }
    /// Subgroup-order candidate, not a primality assertion.
    #[must_use]
    pub fn q(&self) -> &Component<'a> {
        &self.q
    }
    /// Optional cofactor; no arithmetic relation is established.
    #[must_use]
    pub fn j(&self) -> Option<&Component<'a>> {
        self.j.as_ref()
    }
    /// Optional original generation evidence, with both seed and counter.
    #[must_use]
    pub fn validation(&self) -> Option<&Validation<'a>> {
        self.validation.as_ref()
    }

    /// Read required `DomainParameters` from a dhpublicnumber identifier.
    /// Source encoding, depth and work are retained. Negative INTEGERs, missing
    /// fields, duplicates and trailing fields fail before any backend callback.
    pub fn read<W: Work>(algorithm: AlgorithmIdentifier<'a>, work: &W) -> Result<Self> {
        if !is_algorithm(algorithm, work)? {
            return Err(Error::new(
                ErrorCode::UnexpectedField,
                PARAMETERS,
                algorithm.offset(),
            ));
        }
        let source = algorithm
            .parameters_nested()
            .ok_or_else(|| Error::new(ErrorCode::MissingField, PARAMETERS, algorithm.offset()))?;
        let (reader, element) = source.open(work, PARAMETERS)?;
        if element.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::new(
                ErrorCode::MalformedValue,
                PARAMETERS,
                element.span().start,
            ));
        }
        let mut fields = reader.enter(&element).field(PARAMETERS)?;
        // RFC 3279 section 2.3.3: DH uses p,g,q, whereas DSA uses p,q,g.
        // https://www.rfc-editor.org/rfc/rfc3279.html#section-2.3.3
        let p = component(&mut fields)?;
        let g = component(&mut fields)?;
        let q = component(&mut fields)?;
        let mut next = fields.next_element().field(PARAMETERS)?;
        let j = if let Some(value) =
            next.filter(|value| value.tag() == Tag::primitive(universal::INTEGER))
        {
            let j = unsigned(&fields, value, PARAMETERS)?;
            next = fields.next_element().field(PARAMETERS)?;
            Some(j)
        } else {
            None
        };
        let validation = if let Some(value) = next {
            if value.tag() != Tag::constructed(universal::SEQUENCE) {
                return Err(Error::new(
                    ErrorCode::MalformedValue,
                    PARAMETERS,
                    value.span().start,
                ));
            }
            let mut inside = fields.enter(&value).field(PARAMETERS)?;
            let seed_element = inside
                .expect(Tag::primitive(universal::BIT_STRING))
                .field(PARAMETERS)?;
            let seed = inside.bit_string(&seed_element).field(PARAMETERS)?;
            let counter = component(&mut inside)?;
            end(&inside, PARAMETERS)?;
            Some(Validation {
                element: value,
                seed_element,
                seed,
                counter,
            })
        } else {
            None
        };
        end(&fields, PARAMETERS)?;
        Ok(Self {
            element,
            p,
            g,
            q,
            j,
            validation,
        })
    }
}

/// Original public y and written domain parameters, with no key validation.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a> {
    parameters: Parameters<'a>,
    y: Component<'a>,
}
impl<'a> PublicKey<'a> {
    /// Original domain parameters.
    #[must_use]
    pub fn parameters(&self) -> &Parameters<'a> {
        &self.parameters
    }
    /// Unsigned public value and original INTEGER.
    #[must_use]
    pub fn y(&self) -> &Component<'a> {
        &self.y
    }
}

/// Decode dhpublicnumber SPKI without copying key material or doing arithmetic.
/// Carried y must be a single DER INTEGER even under a BER outer container.
/// Errors distinguish algorithm mismatch, structure/encoding and resources.
pub fn read<'a, W: Work>(key: PublicKeyInfo<'a>, work: &W) -> Result<PublicKey<'a>> {
    let algorithm = key.algorithm();
    let parameters = Parameters::read(algorithm, work)?;
    let bytes = key.whole_octets(PUBLIC)?;
    let (reader, element) = algorithm
        .nested(bytes, key.key_offset())
        .open(work, PUBLIC)?;
    let y = der_integer(&reader, element, PUBLIC)?;
    Ok(PublicKey { parameters, y })
}

/// A borrowed private x and domain parameters. Deliberately has no Debug/Clone.
pub struct PrivateKey<'a> {
    parameters: Parameters<'a>,
    x: Component<'a>,
}
impl<'a> PrivateKey<'a> {
    /// Original domain parameters.
    #[must_use]
    pub fn parameters(&self) -> &Parameters<'a> {
        &self.parameters
    }
    /// Original nonnegative private integer; the source owner must wipe storage.
    #[must_use]
    pub fn x(&self) -> &Component<'a> {
        &self.x
    }

    /// Decode the carried private INTEGER from a producing reader, together
    /// with already decoded domain parameters. The PKCS#8 owner supplies the
    /// secret's reader; parameter decoding uses its original identifier.
    /// This does not validate x's range or consistency with a public key.
    pub fn read(
        parameters: Parameters<'a>,
        reader: &ScopedReader<'a, '_>,
        element: Element<'a>,
    ) -> Result<Self> {
        let x = der_integer(reader, element, PRIVATE)?;
        Ok(Self { parameters, x })
    }
}

fn der_integer<'a>(
    reader: &ScopedReader<'a, '_>,
    element: Element<'a>,
    field: &'static str,
) -> Result<Component<'a>> {
    if reader.encoding().is_der() {
        return unsigned(reader, element, field);
    }
    let mut strict = reader.reread(&element, Encoding::Der).field(field)?;
    let element = strict
        .expect(Tag::primitive(universal::INTEGER))
        .field(field)?;
    unsigned(&strict, element, field)
}
fn component<'a>(reader: &mut ScopedReader<'a, '_>) -> Result<Component<'a>> {
    let element = reader
        .expect(Tag::primitive(universal::INTEGER))
        .field(PARAMETERS)?;
    unsigned(reader, element, PARAMETERS)
}
fn end(reader: &ScopedReader<'_, '_>, field: &'static str) -> Result<()> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::TrailingData, field, reader.offset()))
    }
}
