//! Pure ML-DSA identities and wire sizes, without a cryptographic engine.
//!
//! RFC 9881 §§2–4 defines three distinct PKIX identifiers, all with absent
//! parameters. HashML-DSA and pre-standard Dilithium are different algorithms.
//! For certificate/CRL verification the provider must use pure ML-DSA with an
//! empty context (RFC 9881 §3), not a conventional finalized-message prehash.
//! <https://www.rfc-editor.org/rfc/rfc9881#section-3>

use super::AlgorithmIdentifier;
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::Work;

/// A pure ML-DSA parameter set, not provider capability or policy permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterSet {
    /// ML-DSA-44, OID `2.16.840.1.101.3.4.3.17`.
    MlDsa44,
    /// ML-DSA-65, OID `2.16.840.1.101.3.4.3.18`.
    MlDsa65,
    /// ML-DSA-87, OID `2.16.840.1.101.3.4.3.19`.
    MlDsa87,
}

impl ParameterSet {
    /// Raw public-key width (FIPS 204 table 2; RFC 9881 §4 and appendix B).
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        // RFC9881 appendix A has a 2602 typo for ML-DSA-87; §4, appendix B
        // and the defining FIPS204 table2 all specify 2592.
        // https://doi.org/10.6028/NIST.FIPS.204
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Raw signature width, not an assertion of valid packed coefficients.
    /// FIPS 204 §3.6.2 and table 2 require exact key/signature lengths.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

/// Resolves a retained identifier under original and current work ceilings.
///
/// Returns `None` for another algorithm, including HashML-DSA. A recognized
/// identifier with any parameters, even primitive NULL, is malformed. No
/// cursor, allocation, account clone or byte copy is needed. Provider support,
/// packed-value validation, key usage, context selection and trust are separate.
///
/// # Errors
/// Original located parameter/resource failures; resource refusal precedes
/// classification and is never an unknown algorithm or malformed parameter.
///
/// # Examples
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::algorithm::{self, ml_dsa::{self, ParameterSet}};
/// let work = Memory::new(Arc::new(MemoryAccount::new(1024, 4096)));
/// let source = Parser::der(work.clone());
/// let bytes = b"\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x11";
/// let mut reader = source.read(bytes, 400).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let id = algorithm::read(&reader, &element, "algorithm")?;
/// assert_eq!(ml_dsa::resolve(id, &work)?, Some(ParameterSet::MlDsa44));
/// # Ok::<(), structured_pkix::Error>(())
/// ```
pub fn resolve<W: Work>(
    identifier: AlgorithmIdentifier<'_>,
    execution: &W,
) -> Result<Option<ParameterSet>> {
    let bytes = identifier.algorithm().as_bytes();
    identifier
        .query_in(execution)
        .charge_work(bytes.len() as u64 + 1)
        .map_err(|reason| Error::resource(reason, identifier.field, identifier.offset()))?;
    let value = from_octets(bytes);
    if value.is_some() {
        require_absent(identifier)?;
    }
    Ok(value)
}

/// The caller has already paid for inspecting the original OID.
pub(super) fn from_octets(bytes: &[u8]) -> Option<ParameterSet> {
    match bytes {
        [0x60, 0x86, 0x48, 1, 0x65, 3, 4, 3, last] => from_arc(*last),
        _ => None,
    }
}

/// Shared final arc mapping after a paid, exact sigAlgs prefix match.
pub(super) fn from_arc(last: u8) -> Option<ParameterSet> {
    match last {
        17 => Some(ParameterSet::MlDsa44),
        18 => Some(ParameterSet::MlDsa65),
        19 => Some(ParameterSet::MlDsa87),
        _ => None,
    }
}

pub(super) fn require_absent(identifier: AlgorithmIdentifier<'_>) -> Result<()> {
    // RFC9881§2 forbids even NULL in both SPKI and signature identifiers.
    // https://www.rfc-editor.org/rfc/rfc9881#section-2
    if let Some(parameters) = identifier.parameters_nested() {
        return Err(Error::new(
            ErrorCode::MalformedValue,
            identifier.field,
            parameters.offset(),
        ));
    }
    Ok(())
}
