//! Signature-role profile facts, separate from strict acceptance.

use super::{AlgorithmIdentifier, Scheme, check_parameters, classify, pss};
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::Work;

/// A scoped recognized scheme and its readable parameter-profile diagnostics.
///
/// This is not a validated [`super::Algorithm`] or permission to call a provider.
/// Fixed-scheme recognition survives unwanted parameters; their original bytes
/// remain available through [`Self::identifier`]. No parameter is rewritten.
#[derive(Debug)]
pub struct Inspection<'a, 'parameters> {
    identifier: AlgorithmIdentifier<'a>,
    scheme: Option<Scheme>,
    parameters: Option<&'parameters pss::Parameters<'a>>,
    faults: &'parameters [Error],
}

impl<'a> Inspection<'a, '_> {
    /// Original identifier, including its source, encoding and parameter bytes.
    #[must_use]
    pub const fn identifier(&self) -> AlgorithmIdentifier<'a> {
        self.identifier
    }

    /// Recognized OID identity; unknown OIDs are not inferred from parameters.
    #[must_use]
    pub const fn scheme(&self) -> Option<Scheme> {
        self.scheme
    }

    /// Actual readable PSS parameters, absent for fixed schemes or missing PSS.
    /// Missing mandatory signature parameters have a separate located fault.
    #[must_use]
    pub const fn parameters(&self) -> Option<&pss::Parameters<'a>> {
        self.parameters
    }

    /// Located profile faults, independent of provider support and mathematics.
    /// Empty for unknown algorithms, whose conformance is not assessed here.
    #[must_use]
    pub const fn faults(&self) -> &[Error] {
        self.faults
    }
}

/// Inspects signature-role parameters without weakening [`super::with_algorithm`].
///
/// Uses exactly the strict resolver's recognized OIDs and parameter rules.
/// Readable NULL/absence violations retain their scheme and original fault;
/// this API does not decide whether mathematical verification is appropriate.
/// Fixed cases allocate nothing. PSS uses [`pss::inspect`]'s schema kernel and
/// accounted diagnostics, including readable DER written DEFAULTs. Missing PSS
/// signature parameters retain `Some(Scheme::RsaPss)` plus `MissingField`, with
/// no fabricated parameters (RFC4055 §3.1). Optional PSS key restrictions still
/// use `pss::inspect`, where absence is unrestricted, not a signature fault.
/// <https://www.rfc-editor.org/rfc/rfc4055#section-3.1>
///
/// Original/current ceilings apply before classification or parameter traversal.
/// The callback borrows temporary parameters and diagnostics only for the visit;
/// its result is returned unchanged, including caller-specific errors. Original
/// document views may escape, but temporary descriptor references may not.
///
/// # Errors
/// Malformed or ambiguous PSS grammar and terminal resource/processing refusal
/// prevent the visit. Structural ASN.1 inspection is a separate operation:
/// [`super::super::read_inspection`] does not fabricate a valid identifier from
/// malformed parameter encoding for this function.
///
/// # Examples
/// ```
/// use std::sync::Arc;
/// use structured_asn1::{Parser, memory::{Memory, MemoryAccount}};
/// use structured_pkix::algorithm::{self, digest, signature};
/// let work = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
/// let source = Parser::der(work.clone());
/// // ecdsa-with-SHA256 with a readable but forbidden NULL parameter.
/// let bytes = b"\x30\x0c\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x05\x00";
/// let mut reader = source.read(bytes, 400).unwrap();
/// let element = reader.next_element().unwrap().unwrap();
/// let identifier = algorithm::read(&reader, &element, "signatureAlgorithm")?;
/// signature::with_inspection(identifier, &work, |reading| {
///     assert_eq!(reading.scheme(), Some(signature::Scheme::Ecdsa(digest::Algorithm::Sha256)));
///     assert_eq!(reading.faults()[0].offset(), 412);
/// })?;
/// assert!(signature::with_algorithm(identifier, &work, |_| ()).is_err());
/// # Ok::<(), structured_pkix::Error>(())
/// ```
/// A reference to a temporary diagnostic or PSS descriptor cannot escape:
/// ```compile_fail
/// use structured_pkix::{Error, algorithm::{AlgorithmIdentifier, signature}};
/// use structured_asn1::memory::Memory;
/// fn escape<'a>(id: AlgorithmIdentifier<'a>, work: &Memory) -> &'a [Error] {
///     signature::with_inspection(id, work, |reading| reading.faults()).unwrap()
/// }
/// ```
pub fn with_inspection<'a, W: Work, R>(
    identifier: AlgorithmIdentifier<'a>,
    execution: &W,
    visitor: impl for<'parameters> FnOnce(Inspection<'a, 'parameters>) -> R,
) -> Result<R> {
    let classified = classify(identifier, execution)?;
    let scheme = classified.map(|(scheme, _)| scheme);
    if scheme == Some(Scheme::RsaPss) {
        let reading = pss::inspect_known(identifier, execution)?;
        return Ok(match &reading {
            Some(reading) => visitor(Inspection {
                identifier,
                scheme,
                parameters: Some(reading.parameters_ref()),
                faults: reading.faults(),
            }),
            None => visitor(Inspection {
                identifier,
                scheme,
                parameters: None,
                faults: &[Error::new(
                    ErrorCode::MissingField,
                    identifier.field,
                    identifier.offset(),
                )],
            }),
        });
    }
    let fault = classified.and_then(|(_, rule)| check_parameters(identifier, rule).err());
    Ok(visitor(Inspection {
        identifier,
        scheme,
        parameters: None,
        faults: fault.as_slice(),
    }))
}
