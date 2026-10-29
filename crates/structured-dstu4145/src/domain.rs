//! Prepared, validated domains and public keys in fixed caller-owned storage.

use crate::{
    Basis, ByteOrder, Error,
    curve::{Curve, Point},
    domains,
    field::{Arithmetic, Normal, Polynomial},
    validation::{self, Custom, Factor, Known, ValidationError, Validator},
    words::Words,
};
use rand_core::TryCryptoRng;
use structured_pkix::algorithm::dstu4145::Reduction;

/// Borrowed explicit numeric components, after any enclosing ASN.1 grammar.
/// Field elements/base point use `byte_order`; the unsigned order is big-endian.
#[derive(Debug, Clone, Copy)]
pub struct Explicit<'a> {
    /// Field degree, required to belong to the standard's applicable table.
    pub degree: u32,
    /// Original polynomial exponents or optimal normal basis.
    pub reduction: Reduction,
    /// Curve coefficient A, exactly zero or one.
    pub a: bool,
    /// Exact-width field representation of nonzero B.
    pub b: &'a [u8],
    /// Unsigned big-endian subgroup order candidate.
    pub order: &'a [u8],
    /// Exact-width compressed base point.
    pub base_point: &'a [u8],
    /// Field-element representation, independent of signature representation.
    pub byte_order: ByteOrder,
}

/// A checked domain. Moving it into a key transfers its fixed storage.
/// Cloning duplicates only inline public parameters when multiple keys need them.
#[derive(Debug, Clone)]
pub struct Domain {
    inner: Inner,
}

#[derive(Debug, Clone)]
enum Inner {
    Polynomial(Prepared<Polynomial>),
    Normal(Prepared<Normal>),
}

#[derive(Debug, Clone)]
struct Prepared<F> {
    curve: Curve<F>,
    base: Point,
    order: Words,
}

/// Validated subgroup public key owning its fixed domain, without Arc or heap.
#[derive(Debug)]
pub struct PublicKey {
    domain: Domain,
    point: Point,
}

impl Domain {
    /// Prepares one of the standard's ten PB or five ONB recommended domains.
    /// Unknown degrees return unsupported, never a nearby curve.
    pub fn named(basis: Basis, degree: usize) -> Result<Self, Error> {
        let spec = domains::named(basis, degree).ok_or(Error::UnsupportedDomain)?;
        let inner = match basis {
            Basis::Polynomial => {
                let row = domains::POLYNOMIALS
                    .iter()
                    .find(|row| row[0] == degree)
                    .ok_or(Error::UnsupportedDomain)?;
                let count = if row[2] == 0 { 1 } else { 3 };
                Inner::Polynomial(named(Polynomial::new(degree, &row[1..=count])?, spec)?)
            }
            Basis::OptimalNormal => Inner::Normal(named(Normal::new(degree)?, spec)?),
        };
        Ok(Self { inner })
    }

    /// Validates explicit domains using standard polynomial/prime-order facts.
    /// Other orders or custom polynomials require [`Self::explicit_with_evidence`].
    /// Base points are always checked, even with a known prime order.
    pub fn explicit(input: Explicit<'_>) -> Result<Self, Error> {
        prepare(input, &mut Known)
    }

    /// Fully validates custom parameters with complete factorization evidence
    /// and caller-supplied cryptographic randomness for primality checks.
    /// No OS entropy source is selected or retained. Known facts need no draws.
    pub fn explicit_with_evidence<R: TryCryptoRng>(
        input: Explicit<'_>,
        factors: &[Factor<'_>],
        random: &mut R,
    ) -> Result<Self, ValidationError<R::Error>> {
        prepare(input, &mut Custom { factors, random })
    }

    /// Exact field degree, not the signature scalar width.
    #[must_use]
    pub fn degree(&self) -> usize {
        match &self.inner {
            Inner::Polynomial(value) => value.curve.field.degree(),
            Inner::Normal(value) => value.curve.field.degree(),
        }
    }

    /// Signing subgroup-order bit length L(n).
    #[must_use]
    pub fn order_bits(&self) -> usize {
        match &self.inner {
            Inner::Polynomial(value) => value.order.bits(),
            Inner::Normal(value) => value.order.bits(),
        }
    }

    /// Decodes, decompresses and validates a complete untrusted public key.
    /// Noncanonical width, off-curve points and wrong subgroups are errors.
    pub fn public_key(self, bytes: &[u8], byte_order: ByteOrder) -> Result<PublicKey, Error> {
        let compressed = element(bytes, self.degree(), byte_order)?;
        let point = match &self.inner {
            Inner::Polynomial(value) => value.public_key(compressed)?,
            Inner::Normal(value) => value.public_key(compressed)?,
        };
        Ok(PublicKey {
            domain: self,
            point,
        })
    }
}

impl PublicKey {
    /// Prepared field degree.
    #[must_use]
    pub fn degree(&self) -> usize {
        self.domain.degree()
    }

    /// Prepared subgroup-order bit length, independent of field degree.
    #[must_use]
    pub fn order_bits(&self) -> usize {
        self.domain.order_bits()
    }
    /// Verifies one native Ukrainian GOST/Kupyna digest without rehashing.
    ///
    /// `hash` is the unmodified digest octet sequence emitted by the selected
    /// Ukrainian PKI hash. Its low-order octet comes first in the profile's
    /// binary H(T); conversion to min(m,LH) bits and the h=0 rule live here.
    /// This interpretation does not follow the key/signature's byte order.
    /// Signature bytes are the OCTET payload, not its DER tag/length.
    /// A standard worked-example H(T) written most-significant-first must be
    /// converted to the profile's digest octets when constructing test data.
    ///
    /// Invalid framing is an error; out-of-range scalars and a computed
    /// mismatch return false. Key/domain checks were completed at preparation.
    pub fn verify_prehash(
        &self,
        hash: &[u8],
        signature: &[u8],
        byte_order: ByteOrder,
    ) -> Result<bool, Error> {
        if hash.is_empty() || hash.len() > 64 {
            return Err(Error::InvalidEncoding);
        }
        let width = signature.len() / 2;
        // The raw standard permits wider zero-padded components (AnnexB.1).
        // Certificate-profile minimum-width enforcement belongs to its reader.
        if signature.len() % 2 != 0 || width < self.domain.order_bits().div_ceil(8) || width > 64 {
            return Err(Error::InvalidEncoding);
        }
        let first = Words::read(&signature[..width], byte_order)?;
        let last = Words::read(&signature[width..], byte_order)?;
        let (r, s) = match byte_order {
            ByteOrder::LittleEndian => (first, last),
            ByteOrder::BigEndian => (last, first),
        };
        let mut digest = Words::read(hash, ByteOrder::LittleEndian)?;
        digest.clear_above(self.domain.degree());
        Ok(match &self.domain.inner {
            Inner::Polynomial(value) => value.verify(self.point, digest, r, s),
            Inner::Normal(value) => value.verify(self.point, digest, r, s),
        })
    }
}

fn named<F: Arithmetic>(field: F, spec: &domains::Spec) -> Result<Prepared<F>, Error> {
    let base = Point {
        x: field.import(spec.x),
        y: field.import(spec.y),
    };
    let b = field.import(spec.b);
    let curve = Curve::new(field, spec.a, b)?;
    // Standard-domain constants are independently qualified as a complete
    // table. Section8 permits reusing their authenticated construction facts.
    Ok(Prepared {
        curve,
        base,
        order: spec.order,
    })
}

fn prepare<V: Validator>(input: Explicit<'_>, validator: &mut V) -> Result<Domain, V::Error> {
    let degree = usize::try_from(input.degree).map_err(|_| Error::UnsupportedDomain)?;
    let inner = match input.reduction {
        Reduction::Trinomial(exponent) => {
            let exponent = usize::try_from(exponent).map_err(|_| Error::InvalidField)?;
            let field = Polynomial::new(degree, &[exponent])?;
            validator.polynomial(&field, &[exponent])?;
            Inner::Polynomial(explicit(field, input, validator)?)
        }
        Reduction::Pentanomial { k, j, l } => {
            let terms = [
                usize::try_from(k).map_err(|_| Error::InvalidField)?,
                usize::try_from(j).map_err(|_| Error::InvalidField)?,
                usize::try_from(l).map_err(|_| Error::InvalidField)?,
            ];
            let field = Polynomial::new(degree, &terms)?;
            validator.polynomial(&field, &terms)?;
            Inner::Polynomial(explicit(field, input, validator)?)
        }
        Reduction::OptimalNormal => {
            Inner::Normal(explicit(Normal::new(degree)?, input, validator)?)
        }
    };
    Ok(Domain { inner })
}

fn explicit<F: Arithmetic, V: Validator>(
    field: F,
    input: Explicit<'_>,
    validator: &mut V,
) -> Result<Prepared<F>, V::Error> {
    let order = Words::read(input.order, ByteOrder::BigEndian)?;
    validation::order_bounds(order, field.degree())?;
    validator.order(order, field.degree())?;
    let b = field.import(element(input.b, field.degree(), input.byte_order)?);
    let compressed = element(input.base_point, field.degree(), input.byte_order)?;
    let curve = Curve::new(field, input.a, b)?;
    let base = curve
        .decompress(compressed)
        .map_err(|_| Error::InvalidDomain)?;
    if base.x.is_zero() || curve.multiply(base, order).is_some() {
        return Err(Error::InvalidDomain.into());
    }
    Ok(Prepared { curve, base, order })
}

fn element(bytes: &[u8], degree: usize, byte_order: ByteOrder) -> Result<Words, Error> {
    if bytes.len() != degree.div_ceil(8) {
        return Err(Error::InvalidEncoding);
    }
    let value = Words::read(bytes, byte_order)?;
    if value.bits() > degree {
        return Err(Error::InvalidEncoding);
    }
    Ok(value)
}

impl<F: Arithmetic> Prepared<F> {
    fn public_key(&self, compressed: Words) -> Result<Point, Error> {
        let point = self.curve.decompress(compressed)?;
        if point.x.is_zero() || self.curve.multiply(point, self.order).is_some() {
            return Err(Error::InvalidKey);
        }
        Ok(point)
    }

    fn verify(&self, public: Point, mut digest: Words, r: Words, s: Words) -> bool {
        if r.is_zero() || s.is_zero() || !r.cmp(self.order).is_lt() || !s.cmp(self.order).is_lt() {
            return false;
        }
        let field = &self.curve.field;
        digest = field.import(digest);
        if digest.is_zero() {
            digest = field.one();
        }
        let left = self.curve.multiply(self.base, s);
        let right = self.curve.multiply(public, r);
        let Some(point) = self.curve.add(left, right) else {
            return false;
        };
        let mut computed = field.export(field.multiply(digest, point.x));
        computed.clear_above(self.order.bits() - 1);
        computed == r
    }
}
