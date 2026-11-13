use crypto_bigint::{
    Odd, Uint,
    modular::{FixedMontyForm, FixedMontyParams},
    nlimbs,
};
use der::{
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Tag, Tagged,
    Writer,
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef, SequenceRef, UintRef},
};
use pkcs8::{PrivateKeyInfo, spki::AlgorithmIdentifier};
use structured_asn1::memory::Work;
use zeroize::{Zeroize, Zeroizing};

use super::{Error, charge};

const DSA_COMPONENT_LIMIT: usize = 512;
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const DSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// The traditional key family named by a PEM label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFamily {
    /// SEC1 EC PRIVATE KEY.
    Ec,
    /// OpenSSL DSA PRIVATE KEY.
    Dsa,
}

/// A checked plan borrowing the original private key until it is written.
pub struct Key<'a> {
    encoding: Encoding<'a>,
    len: usize,
}

type EcInfo<'a> = PrivateKeyInfo<ObjectIdentifier, &'a OctetStringRef, BitStringRef<'a>>;
type DsaInfo<'a> = PrivateKeyInfo<DsaParameters<'a>, DsaOctets<'a>, BitStringRef<'a>>;

enum Encoding<'a> {
    Ec(EcInfo<'a>),
    Dsa(DsaInfo<'a>),
}

impl<'a> Key<'a> {
    /// Validate a DER key and plan its PKCS#8 encoding.
    ///
    /// Pass a family for a recognized PEM label, or `None` for structural
    /// recognition of unlabelled DER. The DSA limit counts unsigned magnitude
    /// octets, and can tighten the fixed 512-octet ceiling. This checks
    /// consistency of DSA key components, without certifying domain parameters
    /// or applying key-acceptance policy.
    pub fn read(
        input: &'a [u8],
        family: Option<KeyFamily>,
        dsa_component_limit: usize,
        work: &impl Work,
    ) -> Result<Self, Error> {
        charge(work, input.len())?;
        let family = match family {
            Some(family) => family,
            None => recognize(input)?,
        };
        let (encoding, len) = match family {
            KeyFamily::Ec => {
                let key = ec(input, work)?;
                let len = key.encoded_len().map_err(|_| Error::InvalidKey)?;
                (Encoding::Ec(key), len)
            }
            KeyFamily::Dsa => {
                let key = dsa(input, dsa_component_limit, work)?;
                let len = key.encoded_len().map_err(|_| Error::InvalidKey)?;
                (Encoding::Dsa(key), len)
            }
        };
        Ok(Self {
            encoding,
            len: usize::try_from(len).map_err(|_| Error::InvalidKey)?,
        })
    }

    /// Exact number of bytes required for the PKCS#8 output.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.len
    }

    /// Encode into caller-owned wiping storage. A short buffer or work refusal
    /// leaves it untouched. Bytes past the encoded prefix are untouched.
    pub fn write<'out>(
        &self,
        output: &'out mut [u8],
        work: &impl Work,
    ) -> Result<&'out [u8], Error> {
        let output = output
            .get_mut(..self.len)
            .ok_or(Error::OutputTooShort { required: self.len })?;
        charge(work, self.len)?;
        // Do not expose a partially written private key on a serialization error.
        let mut guard = WipeOnFailure(output);
        match &self.encoding {
            Encoding::Ec(key) => key.encode_to_slice(guard.0),
            Encoding::Dsa(key) => key.encode_to_slice(guard.0),
        }
        .map_err(|_| Error::InvalidKey)?;
        let written = core::mem::take(&mut guard.0);
        Ok(written)
    }
}

struct WipeOnFailure<'a>(&'a mut [u8]);

impl Drop for WipeOnFailure<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn recognize(input: &[u8]) -> Result<KeyFamily, Error> {
    let sequence = <&SequenceRef>::from_der(input).map_err(|_| Error::NotTraditional)?;
    let mut reader =
        der::SliceReader::new(sequence.as_bytes()).map_err(|_| Error::NotTraditional)?;
    let version = AnyRef::decode(&mut reader).map_err(|_| Error::NotTraditional)?;
    if version.tag() != Tag::Integer {
        return Err(Error::NotTraditional);
    }
    match Tag::peek(&reader).map_err(|_| Error::NotTraditional)? {
        Tag::OctetString => Ok(KeyFamily::Ec),
        Tag::Integer => {
            for _ in 0..5 {
                let component = AnyRef::decode(&mut reader).map_err(|_| Error::NotTraditional)?;
                if component.tag() != Tag::Integer {
                    return Err(Error::NotTraditional);
                }
            }
            if !reader.is_finished() {
                return Err(Error::NotTraditional);
            }
            Ok(KeyFamily::Dsa)
        }
        _ => Err(Error::NotTraditional),
    }
}

fn ec<'a>(input: &'a [u8], work: &impl Work) -> Result<EcInfo<'a>, Error> {
    let key = sec1::EcPrivateKey::from_der(input).map_err(|_| Error::InvalidKey)?;
    // RFC 5915 §3 fixes the scalar octet length to the group order width.
    let width = key.private_key.len();
    let curve = match key.parameters {
        Some(parameters) => parameters.named_curve().ok_or(Error::InvalidKey)?,
        None => match width {
            32 => P256,
            48 => P384,
            66 => P521,
            _ => return Err(Error::InvalidKey),
        },
    };
    macro_rules! validate {
        ($curve:ident, $width:literal) => {{
            if width != $width {
                return Err(Error::InvalidKey);
            }
            let point = key.public_key;
            if let Some(point) = point {
                match point {
                    [2 | 3, ..] if point.len() == 1 + $width => {}
                    [4, ..] if point.len() == 1 + 2 * $width => {}
                    _ => return Err(Error::InvalidKey),
                }
                // Fixed-curve point recovery and scalar multiplication.
                work.charge_work(32 * $width * $width)?;
            }
            let secret =
                $curve::SecretKey::from_slice(key.private_key).map_err(|_| Error::InvalidKey)?;
            if let Some(point) = point {
                let public =
                    $curve::PublicKey::from_sec1_bytes(point).map_err(|_| Error::InvalidKey)?;
                if secret.public_key() != public {
                    return Err(Error::InvalidKey);
                }
            }
        }};
    }
    match curve {
        P256 => validate!(p256, 32),
        P384 => validate!(p384, 48),
        P521 => validate!(p521, 66),
        _ => return Err(Error::InvalidKey),
    }
    // RFC 5480 §2.1.1 and RFC 5958 §2. Keep the original SEC1 octets.
    Ok(PrivateKeyInfo::new(
        AlgorithmIdentifier {
            oid: EC_PUBLIC_KEY,
            parameters: Some(curve),
        },
        OctetStringRef::new(input).map_err(|_| Error::InvalidKey)?,
    ))
}

#[derive(der::Sequence)]
struct TraditionalDsa<'a> {
    version: u8,
    p: UintRef<'a>,
    q: UintRef<'a>,
    g: UintRef<'a>,
    y: UintRef<'a>,
    x: UintRef<'a>,
}

#[derive(der::Sequence)]
struct DsaParameters<'a> {
    p: UintRef<'a>,
    q: UintRef<'a>,
    g: UintRef<'a>,
}

// RFC 3279 §2.3.2 and RFC 5958 §2. Wrap the DER INTEGER directly in the
// PKCS#8 OCTET STRING without materializing another copy of the exponent.
struct DsaOctets<'a>(UintRef<'a>);

impl FixedTag for DsaOctets<'_> {
    const TAG: Tag = Tag::OctetString;
}

impl<'a> DecodeValue<'a> for DsaOctets<'a> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let value = <&OctetStringRef>::decode_value(reader, header)?;
        UintRef::from_der(value.as_bytes()).map(Self)
    }
}

impl EncodeValue for DsaOctets<'_> {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.0.encode(writer)
    }
}

fn dsa<'a>(input: &'a [u8], limit: usize, work: &impl Work) -> Result<DsaInfo<'a>, Error> {
    let key = TraditionalDsa::from_der(input).map_err(|_| Error::InvalidKey)?;
    if key.version != 0 {
        return Err(Error::InvalidKey);
    }
    let width = [key.p, key.q, key.g, key.y, key.x]
        .iter()
        .map(|value| value.as_bytes().len())
        .max()
        .ok_or(Error::InvalidKey)?;
    if width > limit.min(DSA_COMPONENT_LIMIT) {
        return Err(Error::ComponentLimit);
    }
    match width {
        0..=128 => check_dsa::<{ nlimbs(1024) }>(&key, work)?,
        129..=256 => check_dsa::<{ nlimbs(2048) }>(&key, work)?,
        257..=384 => check_dsa::<{ nlimbs(3072) }>(&key, work)?,
        _ => check_dsa::<{ nlimbs(4096) }>(&key, work)?,
    }
    Ok(PrivateKeyInfo::new(
        AlgorithmIdentifier {
            oid: DSA,
            parameters: Some(DsaParameters {
                p: key.p,
                q: key.q,
                g: key.g,
            }),
        },
        DsaOctets(key.x),
    ))
}

fn check_dsa<const LIMBS: usize>(key: &TraditionalDsa<'_>, work: &impl Work) -> Result<(), Error> {
    let bits = Uint::<LIMBS>::BITS;
    let exponent_bits = u32::try_from(key.q.as_bytes().len() * 8).map_err(|_| Error::InvalidKey)?;
    // The selected fixed precision bounds scratch, and public q width bounds
    // the number of exponentiation windows before any bigint work.
    let width = u64::from(bits / 32);
    work.charge_work((u64::from(bits) + 2 * u64::from(exponent_bits)) * width * width)?;
    let read = |value: UintRef<'_>| Uint::<LIMBS>::from_be_slice_truncated(value.as_bytes(), bits);
    let modulus = read(key.p);
    let order = read(key.q);
    let generator = read(key.g);
    let public = read(key.y);
    let secret = Zeroizing::new(read(key.x));
    if order <= Uint::ONE
        || order >= modulus
        || generator <= Uint::ONE
        || generator >= modulus
        || public <= Uint::ONE
        || public >= modulus
        || *secret == Uint::ZERO
        || *secret >= order
    {
        return Err(Error::InvalidKey);
    }
    let modulus = Option::from(Odd::new(modulus)).ok_or(Error::InvalidKey)?;
    // FIPS 186-4 §4.1: y = g^x mod p.
    let params = FixedMontyParams::new_vartime(modulus);
    let generator = FixedMontyForm::new(&generator, &params);
    let expected = generator.pow_bounded_exp(&secret, exponent_bits).retrieve();
    if expected != public {
        return Err(Error::InvalidKey);
    }
    Ok(())
}
