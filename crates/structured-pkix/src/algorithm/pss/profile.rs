//! Interpreted PSS fields and RFC4055 key restrictions, without cryptography.

use super::{Mask, Number, Parameters};
use crate::algorithm::{AlgorithmIdentifier, digest};
use crate::{Error, ErrorCode, Result};
use structured_asn1::digest::Resolution;
use structured_asn1::memory::Work;
use structured_asn1::{Element, Parser};

const FIELD: &str = "algorithm.pss.profile";

/// A recognized MGF1 profile, not provider capability or signature validity.
///
/// The two digests are independent. Salt remains an original arbitrary-width
/// INTEGER (or the schema default), not a platform-sized backend parameter.
/// Only trailer 1 is recognized; its original written/default form is retained.
#[derive(Debug, Clone, Copy)]
pub struct Profile<'a> {
    parser: &'a Parser,
    element: Element<'a>,
    hash: digest::Algorithm,
    mask_hash: digest::Algorithm,
    salt: Number<'a>,
    trailer: Number<'a>,
}

impl<'a> Profile<'a> {
    /// Original parameter SEQUENCE; no canonical representation is fabricated.
    #[must_use]
    pub fn element(self) -> Element<'a> {
        self.element
    }

    /// Message digest identity, including the omitted SHA-1 default.
    #[must_use]
    pub fn hash(self) -> digest::Algorithm {
        self.hash
    }

    /// MGF1 digest identity, independently of the message digest.
    #[must_use]
    pub fn mask_hash(self) -> digest::Algorithm {
        self.mask_hash
    }

    /// Original salt octet count; no modulus or provider maximum is imposed.
    #[must_use]
    pub fn salt(self) -> Number<'a> {
        self.salt
    }

    /// Original trailer field (the recognized numeric value is 1).
    #[must_use]
    pub fn trailer(self) -> Number<'a> {
        self.trailer
    }

    /// Whether `signature` satisfies this present key profile.
    ///
    /// RFC4055 §3.3 requires identical message/MGF digests and trailer, but
    /// signature salt >= key minimum, not equality. Both original source
    /// ceilings and current work apply, even for a cheap digest mismatch.
    /// Arbitrary-width nonnegative integers compare without truncation.
    /// This checks restrictions only, not key validity, provider support,
    /// modulus feasibility, policy, or signature mathematics.
    /// <https://www.rfc-editor.org/rfc/rfc4055#section-3.3>
    ///
    /// # Errors
    /// A located terminal resource refusal before comparison.
    pub fn allows<W: Work>(&self, signature: &Self, execution: &W) -> Result<bool> {
        self.charge(execution, 1, self.element.span().start)?;
        signature.charge(execution, 1, signature.element.span().start)?;
        if self.hash != signature.hash || self.mask_hash != signature.mask_hash {
            return Ok(false);
        }
        // The profile constructor accepts only trailer 1. Omitted and written
        // defaults are the same algorithm, independently of their encoding.
        // https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.3
        let minimum = Salt::new(self.salt);
        let used = Salt::new(signature.salt);
        self.charge(
            execution,
            minimum.len() as u64 * 2 + 2,
            number_at(self.salt, self.element),
        )?;
        signature.charge(
            execution,
            used.len() as u64 * 2 + 2,
            number_at(signature.salt, signature.element),
        )?;
        let minimum = minimum.bytes();
        let used = used.bytes();
        if used.len() != minimum.len() {
            return Ok(used.len() > minimum.len());
        }
        Ok(used >= minimum)
    }

    fn charge<W: Work>(&self, execution: &W, amount: u64, at: u64) -> Result<()> {
        execution
            .execution_for(self.parser)
            .charge_work(amount)
            .map_err(|reason| Error::resource(reason, FIELD, at))
    }
}

impl<'a> Parameters<'a> {
    /// Interprets already decoded fields without a second PSS schema pass.
    ///
    /// Written digests reuse the shared digest resolver (SHA-1/SHA-2/SHA3);
    /// schema defaults impose SHA-1 without a fabricated identifier. MGF1
    /// may use a different digest from the message. Unknown digests/mask
    /// functions or nonnegative trailers other than 1 are `Unsupported`,
    /// never a key mismatch. Recognition does not promise backend support.
    /// Negative trailers and invalid known digest parameters are located
    /// malformed errors. Original fields remain available for inspection.
    /// Strict versus recoverable DER spelling is determined by the caller's
    /// earlier `pss::read` or `pss::inspect`; projection does not erase faults
    /// or turn an inspection result into conforming evidence.
    ///
    /// # Errors
    /// Located malformed fields or terminal source/current resource refusal.
    ///
    /// # Examples
    /// ```
    /// use std::sync::Arc;
    /// use structured_asn1::{Parser, digest::Resolution, memory::{Memory, MemoryAccount}};
    /// use structured_pkix::algorithm::{self, digest, pss};
    /// let parser = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(4096, 4096))));
    /// // id-RSASSA-PSS, empty parameters: SHA1, MGF1-SHA1, salt 20, trailer 1.
    /// let bytes = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x00";
    /// let mut reader = parser.read(bytes, 400).unwrap();
    /// let element = reader.next_element().unwrap().unwrap();
    /// let identifier = algorithm::read(&reader, &element, "signatureAlgorithm")?;
    /// let fields = pss::read(identifier, parser.memory())?.unwrap();
    /// let current = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
    /// let Resolution::Supported(profile) = fields.profile(&current)? else { panic!("PSS") };
    /// assert_eq!(profile.hash(), digest::Algorithm::Sha1);
    /// assert_eq!(profile.salt().as_u64(), Some(20));
    /// assert!(profile.allows(&profile, &current)?);
    /// # Ok::<(), structured_pkix::Error>(())
    /// ```
    pub fn profile<W: Work>(&self, execution: &W) -> Result<Resolution<Profile<'a>>> {
        let query = execution.execution_for(self.parser);
        query
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, self.element.span().start))?;
        let hash = match self.hash {
            None => digest::Algorithm::Sha1,
            Some(written) => match read_hash(written.value(), execution)? {
                Resolution::Supported(hash) => hash,
                _ => return Ok(Resolution::Unsupported),
            },
        };
        let mask_hash = match self.mask {
            Mask::DefaultMgf1Sha1 => digest::Algorithm::Sha1,
            Mask::Mgf1 { hash, .. } => match read_hash(hash, execution)? {
                Resolution::Supported(hash) => hash,
                _ => return Ok(Resolution::Unsupported),
            },
            Mask::Other(_) => return Ok(Resolution::Unsupported),
        };
        if let Number::Written(written) = self.trailer {
            let at = written.element().span().start;
            // Sign classification plus the bounded u64 projection, including
            // its own sign check and at most eight magnitude octets.
            query
                .charge_work(10)
                .map_err(|reason| Error::resource(reason, FIELD, at))?;
            if written.value().is_negative() {
                return Err(Error::new(ErrorCode::MalformedValue, FIELD, at));
            }
            if written.value().as_u64() != Some(1) {
                return Ok(Resolution::Unsupported);
            }
        }
        Ok(Resolution::Supported(Profile {
            parser: self.parser,
            element: self.element,
            hash,
            mask_hash,
            salt: self.salt,
            trailer: self.trailer,
        }))
    }
}

/// Checks an original key [`AlgorithmIdentifier`] against a PSS signature profile.
///
/// RFC4055 §3.3: rsaEncryption carries no PSS restrictions; an id-RSASSA-PSS
/// key with absent parameters permits any PSS profile; a present PSS profile
/// sets exact digests/trailer and a minimum salt. The key identifier must be
/// the selected key's original identifier, not the certificate's signature
/// algorithm. No restrictions are inherited from an issuer.
///
/// rsaEncryption requires primitive NULL (RFC4055 §1.2). Other key algorithms
/// and unknown PSS profiles are `Unsupported`; `Supported(false)` means a
/// recognized restriction mismatch. No provider or policy authorization follows
/// from `Supported(true)`.
///
/// # Errors
/// Original located malformed parameters or terminal resource refusal.
/// <https://www.rfc-editor.org/rfc/rfc4055#section-3.3>
pub fn key_allows<W: Work>(
    key: AlgorithmIdentifier<'_>,
    signature: &Profile<'_>,
    execution: &W,
) -> Result<Resolution<bool>> {
    let written = key.algorithm().as_bytes();
    key.query_in(execution)
        .charge_work(written.len() as u64 + 1)
        .map_err(|reason| Error::resource(reason, FIELD, key.offset()))?;
    signature.charge(execution, 1, signature.element.span().start)?;
    // One shared prefix dispatch: do not compare the whole RSA prefix once
    // for each candidate after admitting only one scan.
    match written {
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, last] => match last {
            1 => {
                if !key.has_null_parameter() {
                    return Err(Error::new(
                        ErrorCode::MalformedValue,
                        FIELD,
                        key.parameters_nested()
                            .map_or(key.offset(), super::super::Nested::offset),
                    ));
                }
                return Ok(Resolution::Supported(true));
            }
            10 => {}
            _ => return Ok(Resolution::Unsupported),
        },
        _ => return Ok(Resolution::Unsupported),
    }
    let Some(parameters) = super::read_known(key, execution)? else {
        return Ok(Resolution::Supported(true));
    };
    match parameters.profile(execution)? {
        Resolution::Supported(profile) => profile
            .allows(signature, execution)
            .map(Resolution::Supported),
        _ => Ok(Resolution::Unsupported),
    }
}

fn read_hash<W: Work>(
    identifier: AlgorithmIdentifier<'_>,
    execution: &W,
) -> Result<Resolution<digest::Algorithm>> {
    match digest::algorithm(&identifier, execution)? {
        Resolution::Malformed => Err(Error::new(
            ErrorCode::MalformedValue,
            FIELD,
            identifier.offset(),
        )),
        value => Ok(value),
    }
}

fn number_at(number: Number<'_>, enclosing: Element<'_>) -> u64 {
    match number {
        Number::Default(_) => enclosing.span().start,
        Number::Written(value) => value.element().span().start,
    }
}

enum Salt<'a> {
    Written(&'a [u8]),
    Default,
}

impl<'a> Salt<'a> {
    fn new(number: Number<'a>) -> Self {
        match number {
            Number::Written(value) => Self::Written(value.value().as_bytes()),
            Number::Default(value) => {
                // Parameters has a private constructor; only salt's schema
                // default (20), never trailer's default, reaches this helper.
                debug_assert_eq!(value, 20);
                Self::Default
            }
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Written(bytes) => bytes.len(),
            Self::Default => 1,
        }
    }

    fn bytes(&self) -> &[u8] {
        let bytes = match self {
            Self::Written(bytes) => *bytes,
            Self::Default => &[20],
        };
        // Strict INTEGER decoding already guarantees minimal two's complement;
        // at most one sign zero exists. The schema default is borrowed too.
        let mut start = 0;
        while start + 1 < bytes.len() && bytes[start] == 0 {
            start += 1;
        }
        &bytes[start..]
    }
}
