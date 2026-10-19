use super::*;
use crate::material::fixture;
use alloc::sync::Arc;
use alloc::vec::Vec;
use structured_asn1::{
    Parser,
    memory::{Memory, MemoryAccount},
};
use structured_ltv::pki::Participant;

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}

// A fixed artifact census: each entry's artifact, uses and status targets.
struct Fixture<'certificate, 'document> {
    entries: Vec<(ArtifactRef<'certificate, 'document>, Uses, Vec<usize>)>,
}

impl<'certificate, 'document> Census<'certificate, 'document> for Fixture<'certificate, 'document> {
    fn artifact(&self, ordinal: usize) -> ArtifactRef<'certificate, 'document> {
        self.entries[ordinal].0
    }
    fn uses(&self, ordinal: usize) -> Uses {
        self.entries[ordinal].1
    }
    fn targets(&self, ordinal: usize) -> impl Iterator<Item = usize> {
        self.entries[ordinal].2.iter().copied()
    }
}

#[test]
fn references_and_value_containers_keep_distinct_exclusive_ca_rules() {
    // Annex A permits TSA references, unlike ordinary value containers.
    // Union every role before deciding exclusivity, independent of order.
    let signer = Uses::participant(Participant::Signer(0usize));
    let credential = Uses::participant(Participant::Credential {
        signature: 0usize,
        node: 0,
        authority: 0,
    });
    let tsa = Uses::participant(Participant::Timestamp {
        property: 0usize,
        token: 0,
    });
    for (roles, reference, values) in [
        (&[credential][..], true, true),
        (&[tsa][..], false, true),
        (&[credential, tsa][..], false, true),
        (&[tsa, credential][..], false, true),
        (&[credential, signer][..], false, false),
        (&[tsa, signer][..], false, false),
    ] {
        let mut uses = roles[0];
        for &other in &roles[1..] {
            uses.merge(other);
        }
        assert_eq!(exclusive_credential(uses), reference);
        assert_eq!(exclusive(uses), values);
    }
}

#[test]
fn status_classifies_its_actual_target_not_the_crl_signer() {
    // Distinct CA/EE signers and targets deliberately oppose one another.
    // Shared target CA use is not exclusive, even for a credential-only CRL.
    for (version, ca, shared, expected) in [
        (Version::V3, Some(false), false, None),
        (Version::V3, None, false, None),
        (Version::V3, Some(true), false, Some(CaFact::Asserted)),
        (Version::V3, Some(true), true, None),
        (Version::V1, None, false, Some(CaFact::Unstated)),
        (Version::V2, None, false, Some(CaFact::Unstated)),
    ] {
        let target_bytes = fixture::certificate(1, version, ca);
        let signer_bytes = fixture::certificate(2, Version::V3, Some(true));
        let crl_bytes = fixture::crl();
        let source = memory(65_536, 1_000_000);
        let parser = Parser::der(source.clone());
        let target = Certificate::read(&parser, &target_bytes, 100).unwrap();
        let signer = Certificate::read(&parser, &signer_bytes, 900).unwrap();
        let crl = structured_pkix::crl::CertificateList::read(&parser, &crl_bytes, 1800).unwrap();
        let timestamp = Uses::participant(Participant::Timestamp {
            property: 0usize,
            token: 1,
        });
        let mut target_uses = timestamp;
        if shared {
            target_uses.merge(Uses::participant(Participant::Signer(0usize)));
        }
        let census = Fixture {
            entries: alloc::vec![
                (ArtifactRef::Certificate(&target), target_uses, Vec::new()),
                (ArtifactRef::Certificate(&signer), timestamp, Vec::new()),
                (ArtifactRef::Crl(&crl), timestamp, alloc::vec![0]),
            ],
        };
        let work = memory(65_536, 1_000_000);
        let before = source.used();
        let mut scan = CaScan {
            artifacts: &census,
            cache: work.map(),
            work: &work,
        };
        let witness = scan.witness(2, exclusive).unwrap().map(|(fact, index)| {
            assert_eq!(index, 0);
            fact
        });
        assert_eq!(witness, expected);
        assert_eq!(
            scan.witness(1, exclusive).unwrap(),
            Some((CaFact::Asserted, 1))
        );
        assert_eq!(scan.witness(2, exclusive_credential).unwrap(), None);
        drop(scan);
        assert_eq!(work.used(), 0);
        assert_eq!(source.used(), before);
    }
}

#[test]
fn ca_query_refusal_is_never_an_unstated_or_non_ca_fact() {
    // Both decoding and the classification cache are current-operation
    // work/storage. Refusal cannot permit material or fabricate a finding.
    let bytes = fixture::certificate(1, Version::V3, Some(true));
    let source = memory(65_536, 1_000_000);
    let parser = Parser::der(source.clone());
    let certificate = Certificate::read(&parser, &bytes, 100).unwrap();
    let before = source.used();
    let census = Fixture {
        entries: alloc::vec![(
            ArtifactRef::Certificate(&certificate),
            Uses::participant(Participant::Timestamp {
                property: 0usize,
                token: 1,
            }),
            Vec::new(),
        )],
    };
    for work in [memory(0, 1_000_000), memory(65_536, 0)] {
        let mut scan = CaScan {
            artifacts: &census,
            cache: work.map(),
            work: &work,
        };
        match scan.witness(0, exclusive) {
            Err(CaError::Resource(MemoryError::LimitExceeded | MemoryError::WorkExceeded)) => {}
            Err(CaError::Certificate(actual, cause)) => {
                assert!(core::ptr::eq(actual, &raw const certificate));
                assert!(cause.is_resource());
            }
            _ => panic!("current resource refusal must remain terminal"),
        }
        drop(scan);
        assert_eq!(work.used(), 0);
        assert_eq!(source.used(), before);
    }
}
