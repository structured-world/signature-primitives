//! Borrowed Ed25519, Ed448, X25519 and X448 public-key structure.
//!
//! RFC 8410 §§3–4 requires absent parameters and raw whole-octet keys, not
//! nested ASN.1 values. This reader checks identity and framing only. Curve
//! decoding, signature modes, key agreement and certificate usage remain with
//! the caller. RFC 9295 §3 updates keyUsage, not the public-key representation.
//! <https://www.rfc-editor.org/rfc/rfc8410#section-4>

use super::PublicKeyInfo;
use crate::error::{Error, ErrorCode, Result};
use structured_asn1::memory::Work;

const FIELD: &str = "subjectPublicKey.rfc8410";
const PARAMETERS: &str = "subjectPublicKeyInfo.algorithm.parameters";

/// The exact public-key algorithm named by an RFC 8410 SPKI.
///
/// Equal key widths do not make X25519 and Ed25519 interchangeable. This is
/// key identity, not authorization to use a signature or key-agreement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// X25519 key agreement (RFC 7748).
    X25519,
    /// X448 key agreement (RFC 7748).
    X448,
    /// Ed25519 signature public key (RFC 8032).
    Ed25519,
    /// Ed448 signature public key (RFC 8032).
    Ed448,
}

impl Algorithm {
    /// Encoded public-key width, not a mathematical validity check.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::X25519 | Self::Ed25519 => 32,
            Self::X448 => 56,
            Self::Ed448 => 57,
        }
    }
}

/// Original raw public-key bytes with an unambiguous algorithm and location.
///
/// Success does not prove that an Edwards point decodes or that a Montgomery
/// key is contributory. The selected backend performs those checks.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a> {
    algorithm: Algorithm,
    bytes: &'a [u8],
    offset: u64,
}

impl<'a> PublicKey<'a> {
    /// Algorithm named by the original SPKI.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Exact raw key octets, without BIT STRING tag, length or unused-bit octet.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// First key octet in the original source's coordinate system.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

/// Checks RFC 8410 key identity and framing without parsing or copying raw keys.
///
/// Both the original source and current operation fund deferred work. No
/// parser, account, buffer or reference-counted owner is created or retained.
/// Parameters must be absent, including NULL: inheritance cannot repair this
/// algorithm-specific spelling. Key bytes remain uninterpreted, including
/// noncanonical or low-order points whose acceptance belongs to the backend.
///
/// # Errors
/// Reports `UnexpectedField` for another algorithm, `MalformedValue` for
/// parameters, padded bits or wrong width, and original located resource
/// failures. A resource refusal is never a key mismatch or malformed input.
///
/// # Examples
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::{PublicKeyInfo, key::rfc8410};
/// let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
/// let parser = Parser::der(memory.clone());
/// let mut bytes = vec![0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 3, 0x21, 0];
/// bytes.extend([0; 32]); // framing example, not a trusted or usable key
/// let mut reader = parser.read(&bytes, 400).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let spki = PublicKeyInfo::read_element(&reader, &element, "key")?;
/// let key = rfc8410::read(spki, &memory)?;
/// assert_eq!(key.algorithm(), rfc8410::Algorithm::Ed25519);
/// assert_eq!(key.offset(), 412);
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn read<'a, W: Work>(key: PublicKeyInfo<'a>, execution: &W) -> Result<PublicKey<'a>> {
    let identifier = key.algorithm();
    let work = identifier.query_in(execution);
    let at = identifier.offset();
    let charge = |amount| {
        work.charge_work(amount)
            .map_err(|reason| Error::resource(reason, FIELD, at))
    };
    charge(1)?;
    let oid = identifier.algorithm();
    let bytes = oid.as_bytes();
    if bytes.len() != 3 {
        return Err(Error::new(ErrorCode::UnexpectedField, FIELD, at));
    }
    charge(3)?;
    // RFC 8410 §3: these are four distinct OIDs, all with absent parameters.
    // https://www.rfc-editor.org/rfc/rfc8410#section-3
    let algorithm = match bytes {
        [0x2b, 0x65, 0x6e] => Algorithm::X25519,
        [0x2b, 0x65, 0x6f] => Algorithm::X448,
        [0x2b, 0x65, 0x70] => Algorithm::Ed25519,
        [0x2b, 0x65, 0x71] => Algorithm::Ed448,
        _ => return Err(Error::new(ErrorCode::UnexpectedField, FIELD, at)),
    };
    if let Some(parameters) = identifier.parameters_nested() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            PARAMETERS,
            parameters.offset(),
        ));
    }
    let bytes = key.whole_octets(FIELD)?;
    let offset = key.key_offset();
    // RFC 7748 §5 and RFC 8032 §§5.1.2,5.2.2 define these raw widths.
    // Do not interpret the octets as an INTEGER or nested OCTET STRING.
    if bytes.len() != algorithm.public_key_len() {
        return Err(Error::new(ErrorCode::MalformedValue, FIELD, offset));
    }
    Ok(PublicKey {
        algorithm,
        bytes,
        offset,
    })
}
