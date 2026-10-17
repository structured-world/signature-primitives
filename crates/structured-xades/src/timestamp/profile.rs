//! Baseline digest rules over the common checker's already parsed fields.

use structured_asn1::{
    Reader,
    memory::{MemoryError, Work},
};
use structured_cms::{
    ess::Version,
    provider::DigestAlgorithm,
    timestamp::{HashAlgorithmReading, ProfileFailure, ProfileInput, ProfileSource},
};
use structured_pkix::AlgorithmIdentifier;

/// Actual timestamp digest use, not an unused advertised algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestUse {
    /// The CMS signer's declared digest.
    Signer,
    /// An actual signed ESS certificate restriction, in original order.
    Certificate {
        /// Original ESS attribute schema.
        version: Version,
        /// Original readable identifier ordinal in that attribute.
        index: usize,
    },
    /// The carried `TSTInfo` message imprint.
    Imprint,
}

/// Baseline refusal before provider or covered-input side effects.
#[derive(Debug)]
pub enum DigestError {
    /// EN319132-1 §6.2.1 unconditionally prohibits this MD5 digest use.
    Prohibited {
        /// Actual field that selected the digest.
        usage: DigestUse,
        /// Original algorithm offset in its explicit profile source domain.
        offset: u64,
    },
    /// Current producing work refused before metadata or OID comparison.
    Resource {
        /// Actual field whose query was refused.
        usage: DigestUse,
        /// Original enclosing field offset, without fabricated XML coordinates.
        offset: u64,
        /// Original admission cause, never interpreted as unsupported/mismatch.
        cause: MemoryError,
    },
}

pub(super) fn check(
    input: &ProfileInput<'_, '_, '_, '_>,
) -> Result<(), ProfileFailure<DigestError>> {
    // The baseline's SHALL NOT applies to actual digest use, including a
    // timestamp's imprint and signed ESS restrictions. Provider support cannot
    // relax it; algorithm-suite SHOULD recommendations are not extra bans.
    // EN319132-1 V1.3.1 §6.2.1:
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf
    written(
        input
            .token
            .signer()
            .digest_algorithm()
            .identifier()
            .expect("timestamp profile runs only after signer faults were refused"),
        input.parent,
        ProfileSource::Envelope,
        DigestUse::Signer,
    )?;
    for attribute in [input.ess.v1(), input.ess.v2()].into_iter().flatten() {
        let mut index = 0;
        while index < attribute.identifiers().len() {
            let usage = DigestUse::Certificate {
                version: attribute.version(),
                index,
            };
            admit(
                input.parent,
                ProfileSource::Envelope,
                usage,
                attribute.element().span().start,
                1,
            )?;
            let identifier = &attribute.identifiers()[index];
            if let DigestAlgorithm::Written(algorithm) = identifier.digest_algorithm() {
                written(algorithm, input.parent, ProfileSource::Envelope, usage)?;
            }
            // ESS's implied SHA1/SHA256 are fixed schema identities, not MD5.
            index += 1;
        }
    }
    if let HashAlgorithmReading::Identifier(algorithm) = input.info.imprint().algorithm() {
        written(
            *algorithm,
            input.reader,
            ProfileSource::Information,
            DigestUse::Imprint,
        )?;
    }
    Ok(())
}

fn written(
    algorithm: AlgorithmIdentifier<'_>,
    parent: &Reader<'_>,
    source: ProfileSource,
    usage: DigestUse,
) -> Result<(), ProfileFailure<DigestError>> {
    // id-md5: RFC1321 §3. The comparison reads at most this fixed OID width;
    // mismatched widths need only metadata admission, never a full OID scan.
    const MD5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 2, 5];
    let offset = algorithm.offset();
    admit(parent, source, usage, offset, 1)?;
    let bytes = algorithm.algorithm().as_bytes();
    if bytes.len() != MD5.len() {
        return Ok(());
    }
    admit(parent, source, usage, offset, MD5.len() as u64)?;
    if bytes == MD5 {
        return Err(ProfileFailure {
            source,
            cause: DigestError::Prohibited { usage, offset },
        });
    }
    Ok(())
}

fn admit(
    parent: &Reader<'_>,
    source: ProfileSource,
    usage: DigestUse,
    offset: u64,
    cost: u64,
) -> Result<(), ProfileFailure<DigestError>> {
    parent
        .execution()
        .charge_work(cost)
        .map_err(|cause| ProfileFailure {
            source,
            cause: DigestError::Resource {
                usage,
                offset,
                cause,
            },
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use structured_asn1::{
        Encoding, Limits, Parser,
        memory::{Memory, MemoryAccount},
    };

    #[test]
    fn prohibited_digest_scan_keeps_current_local_and_aggregate_refusals_distinct() {
        // A current query over retained original identifiers cannot borrow
        // credit from their earlier parse. Insufficient work is terminal before
        // the OID scan, rather than a successful prohibition/allowance decision.
        let bytes = [0x30, 10, 6, 8, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 2, 5];
        let original = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
        let parser = Parser::der(original.clone());
        let mut parent = parser.read(&bytes, 400).unwrap();
        let element = parent.next_element().unwrap().unwrap();
        let algorithm = structured_pkix::algorithm::read(&parent, &element, "digest").unwrap();
        let parsed_work = original.work_used();
        // Each source bridge admits one metadata step before this query.
        for (local, aggregate) in [(1, 100), (9, 100), (100, 1), (100, 9), (10, 10)] {
            let memory = Memory::new(Arc::new(MemoryAccount::new(0, aggregate)));
            let operation = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: local,
                    ..Limits::default()
                },
                memory.clone(),
            );
            let query = operation.read(&[], 900).unwrap();
            let scoped = parser
                .read_query_in(&query, &[], 400, Encoding::Der, 0)
                .unwrap();
            let refusal = written(
                algorithm,
                &scoped,
                ProfileSource::Envelope,
                DigestUse::Signer,
            )
            .unwrap_err();
            assert_eq!(refusal.source, ProfileSource::Envelope);
            if local == 10 && aggregate == 10 {
                assert!(matches!(
                    refusal.cause,
                    DigestError::Prohibited {
                        usage: DigestUse::Signer,
                        offset: 400
                    }
                ));
                assert_eq!(memory.work_used(), 10);
            } else {
                assert!(matches!(
                    refusal.cause,
                    DigestError::Resource {
                        usage: DigestUse::Signer,
                        offset: 400,
                        ..
                    }
                ));
                assert!(memory.work_used() <= 2);
            }
            assert_eq!(memory.used(), 0);
        }
        assert_eq!(original.work_used(), parsed_work);
    }
}
