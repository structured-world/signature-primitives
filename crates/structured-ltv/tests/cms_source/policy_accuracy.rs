//! Effective policy accuracy crosses real CMS evidence into public LTV facts.
use super::*;
use structured_cms::timestamp::{Accuracy, EffectiveAccuracy, PolicyAccuracy};
use structured_ltv::timestamp::{BoundaryRelation, TemporalError};
use structured_pkix::temporal::{Instant, LeapTable};

#[test]
fn policy_accuracy_survives_into_ltv_interval_and_temporal_refusals() {
    // This real token omits accuracy. Its policy accuracy must survive source
    // drop/copy and drive the same public interval used by timestamp paths.
    let memory = memory(1_000_000);
    let deviation = Accuracy::new(2, 3, 4);
    let policy = PolicyAccuracy::new(structured_asn1::Oid::from_bytes(&[43]), deviation).unwrap();
    let evidence =
        token::evidence_with_policy(b"document", b"document", &memory, Some(policy)).unwrap();
    assert_eq!(evidence.facts().accuracy(), None);
    assert_eq!(
        evidence.facts().effective_accuracy(),
        Some(EffectiveAccuracy::CallerPolicy(deviation))
    );
    let retained = evidence.try_copy_in(&memory).unwrap();
    drop(evidence);
    let snapshot = Snapshot {
        document: 1_u8,
        generation: 1_u8,
    };
    let verified = Verified::new(
        ISSUER,
        Location {
            snapshot,
            node: ARCHIVE_TOKEN,
        },
        SIGNATURE,
        ARCHIVE,
        Purpose::Archive,
        retained,
    );
    let utc = LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let expected = structured_cms::timestamp::interval_in(
        verified.evidence().facts().gen_time(),
        Some(deviation),
        &utc,
        &memory,
    )
    .unwrap();
    let interval = verified.interval(&utc, &memory).unwrap();
    assert_eq!(interval.earliest, expected.earliest);
    assert_eq!(interval.latest, expected.latest);
    assert!(interval.earliest < verified.evidence().facts().gen_time().start());
    assert_eq!(
        verified
            .relation(Instant::new(1_800_000_000, 0).unwrap(), &utc, &memory)
            .unwrap(),
        BoundaryRelation::Before
    );
    let empty = Memory::new(std::sync::Arc::new(
        structured_asn1::memory::MemoryAccount::new(0, 0),
    ));
    assert_eq!(
        verified.interval(&utc, &empty),
        Err(TemporalError::Resource(MemoryError::WorkExceeded))
    );
}
