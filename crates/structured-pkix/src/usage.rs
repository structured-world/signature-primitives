//! What a key may be used for.

use crate::error::{Error, ErrorCode, Located, Result};
use crate::extension::{self, Extension};
use structured_asn1::memory::{Memory, OwnedVec};
use structured_asn1::{BitString, Oid};

/// The purposes a key may be used for, as the bits the certificate set.
#[derive(Debug, Clone, Copy)]
pub struct KeyUsage<'a> {
    bits: BitString<'a>,
}

impl<'a> KeyUsage<'a> {
    /// Signing data.
    #[must_use]
    pub fn digital_signature(self) -> bool {
        self.bits.bit(0)
    }

    /// Signing in a way the signer is not meant to be able to deny later,
    /// which is the bit a signature under the Regulation rests on.
    #[must_use]
    pub fn content_commitment(self) -> bool {
        self.bits.bit(1)
    }

    /// Enciphering a key.
    #[must_use]
    pub fn key_encipherment(self) -> bool {
        self.bits.bit(2)
    }

    /// Enciphering data directly.
    #[must_use]
    pub fn data_encipherment(self) -> bool {
        self.bits.bit(3)
    }

    /// Agreeing a key.
    #[must_use]
    pub fn key_agreement(self) -> bool {
        self.bits.bit(4)
    }

    /// Signing certificates, which is what makes a certification authority
    /// one.
    #[must_use]
    pub fn key_cert_sign(self) -> bool {
        self.bits.bit(5)
    }

    /// Signing revocation lists.
    #[must_use]
    pub fn crl_sign(self) -> bool {
        self.bits.bit(6)
    }

    /// Enciphering only, which means something only alongside key agreement.
    #[must_use]
    pub fn encipher_only(self) -> bool {
        self.bits.bit(7)
    }

    /// Deciphering only, on the same terms.
    #[must_use]
    pub fn decipher_only(self) -> bool {
        self.bits.bit(8)
    }

    /// The bits as they were written, for a report that has to say what a
    /// certificate carries rather than what it means.
    #[must_use]
    pub fn bits(self) -> BitString<'a> {
        self.bits
    }

    /// Reads the value of a key usage extension.
    pub fn read(extension: &Extension<'a>, execution: &Memory) -> Result<Self> {
        const FIELD: &str = "extensions.keyUsage";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut reader = extension.reader(execution).field(FIELD)?;
        let bits = reader.read_bit_string().field(FIELD)?;
        if !reader.is_empty() {
            return Err(fail(ErrorCode::TrailingData));
        }

        // The zero walk below touches every content byte, so it is charged
        // to the shared work budget first: a caller bounding work must see
        // an oversized string's scan on the same meter the reads use.
        reader.charge(bits.as_bytes().len() as u64).field(FIELD)?;

        // A key usage with no bit set forbids every use while claiming to
        // permit one, and the schema asks for at least one. Written as a
        // string of zero bits or as zero bytes, it says the same nothing.
        if bits.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(fail(ErrorCode::MalformedValue));
        }

        // DER trims a named bit list to its last set bit, so trailing zero
        // bits are a second spelling of a shorter value; and a set bit past
        // decipherOnly is a bit this schema gives no name. BER carries no
        // trimming rule, and past-the-end bits there read as unset.
        if reader.encoding().is_der() {
            let length = bits.len();
            if !bits.bit(length - 1) {
                return Err(fail(ErrorCode::MalformedValue));
            }
            if length > 9 {
                return Err(fail(ErrorCode::MalformedValue));
            }
        }

        let usage = Self { bits };
        // The meaning of encipherOnly and decipherOnly is undefined in the
        // absence of the keyAgreement bit (RFC 5280 4.2.1.3): a bit with no
        // defined meaning cannot be read as permitting anything.
        if (usage.encipher_only() || usage.decipher_only()) && !usage.key_agreement() {
            return Err(fail(ErrorCode::MalformedValue));
        }
        Ok(usage)
    }
}

/// Further purposes, named by identifier rather than by bit.
#[derive(Debug)]
pub struct ExtendedKeyUsage<'a> {
    purposes: OwnedVec<Oid<'a>>,
    at: u64,
}

impl<'a> ExtendedKeyUsage<'a> {
    /// The purposes, in the order the certificate holds them.
    #[must_use]
    pub fn purposes(&self) -> &[Oid<'a>] {
        &self.purposes
    }

    /// Whether one purpose is among them.
    ///
    /// The identifier that stands for any purpose is not treated as matching
    /// everything here: whether it does is a policy question, and answering it
    /// in the parser would hide the difference between a certificate that
    /// names a purpose and one that names none.
    pub fn has(&self, purpose: Oid<'_>, execution: &Memory) -> Result<bool> {
        for candidate in &self.purposes {
            let work = 1 + candidate.as_bytes().len().max(purpose.as_bytes().len()) as u64;
            execution
                .charge_work(work)
                .map_err(|reason| Error::resource(reason, "extensions.extKeyUsage", self.at))?;
            if *candidate == purpose {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Reads the value of an extended key usage extension.
    pub fn read(extension: &Extension<'a>, execution: &Memory) -> Result<Self> {
        const FIELD: &str = "extensions.extKeyUsage";
        let fail = |code| Error::new(code, FIELD, extension.span().start);

        let mut inside = extension::sequence(extension, FIELD, execution)?;
        let mut purposes = inside.memory().vector();
        let mut seen = inside.memory().map::<Oid<'a>, ()>();
        while !inside.is_empty() {
            let purpose = inside.read_oid().field(FIELD)?;
            // The list is a SEQUENCE OF with no uniqueness constraint, and
            // a repeated purpose permits exactly what one occurrence does:
            // refusing it would block a valid certificate, so the repeat is
            // folded away and the list holds each purpose once. A set
            // rather than a scan, so a long list costs the work its size
            // says and not its square.
            if seen
                .try_insert(purpose, ())
                .map_err(|reason| Error::resource(reason, FIELD, inside.offset()))?
                .is_none()
            {
                purposes
                    .try_push(purpose)
                    .map_err(|reason| Error::resource(reason, FIELD, inside.offset()))?;
            }
        }
        if purposes.is_empty() {
            return Err(fail(ErrorCode::EmptySequence));
        }

        Ok(Self {
            purposes,
            at: extension.span().start,
        })
    }
}

#[cfg(test)]
mod tests;
