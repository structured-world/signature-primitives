//! EKU catalogue allocations obey the producing parser's cumulative ceiling.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Parser};
use structured_pkix::extension::Extensions;
use structured_pkix::usage::ExtendedKeyUsage;

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    if value.len() < 128 {
        bytes.push(u8::try_from(value.len()).unwrap());
    } else {
        bytes.push(0x82);
        bytes.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    }
    bytes.extend_from_slice(value);
    bytes
}
fn catalogue() -> Vec<u8> {
    let mut purposes = Vec::new();
    for _ in 0..64 {
        purposes.extend(tlv(6, &[42, 1]));
    }
    let mut extension = tlv(6, &[0x55, 0x1d, 0x25]);
    extension.extend(tlv(4, &tlv(0x30, &purposes)));
    tlv(0x30, &tlv(0x30, &extension))
}

#[test]
fn eku_generic_work_keeps_current_query_through_decode_catalogue_and_later_lookup() {
    // Temporary execution wrappers may disappear, but decoding/growth and
    // subsequent queries must not silently fall back to the aggregate account.
    let bytes = catalogue();
    let storage = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let source = Parser::ber(storage.clone());
    let mut parent = source.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let extension = extensions
        .get(structured_pkix::oid::EXT_KEY_USAGE, &storage)
        .unwrap()
        .unwrap();
    let held = storage.used();
    let before = storage.work_used();
    let current = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let operation = Parser::ber(current.clone());
    let query = operation.read(&[], 900).unwrap();
    let usage = {
        let execution = query.execution();
        ExtendedKeyUsage::read(extension, &execution).unwrap()
    };
    assert_eq!(usage.purposes().len(), 1);
    assert_eq!(storage.used(), held);
    assert_eq!(storage.work_used(), before);
    let full = current.work_used();
    assert!(full > 0);
    assert!(current.used() > 0);
    let limited = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let root = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: u64::try_from(full - 1).unwrap(),
            ..Limits::default()
        },
        limited.clone(),
    );
    let query = root.read(&[], 900).unwrap();
    let error = ExtendedKeyUsage::read(extension, &query.execution()).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "extensions.extKeyUsage");
    assert_eq!(limited.used(), 0);
    assert_eq!(storage.used(), held);
    let denied = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        limited.clone(),
    );
    let query = denied.read(&[], 900).unwrap();
    assert!(
        usage
            .has(usage.purposes()[0], &query.execution())
            .unwrap_err()
            .is_resource()
    );
    drop(usage);
    assert_eq!(current.used(), 0);
}

#[test]
fn generic_lazy_extension_keeps_origin_and_query_depth_before_scalar_decoding() {
    // Current scalar checks share the same original nested-reader kernel as
    // allocating EKU checks. A large aggregate allowance cannot erase depth.
    let mut extension = tlv(6, structured_pkix::oid::BASIC_CONSTRAINTS.as_bytes());
    extension.extend(tlv(4, &[0x30, 0]));
    let bytes = tlv(0x30, &tlv(0x30, &extension));
    let source = Parser::ber(Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24))));
    let mut parent = source.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let extension = extensions
        .get(structured_pkix::oid::BASIC_CONSTRAINTS, source.memory())
        .unwrap()
        .unwrap();
    for (depth, success) in [(3, false), (4, true)] {
        let account = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let operation = Parser::new(
            Encoding::Ber,
            Limits {
                max_depth: depth,
                ..Limits::default()
            },
            account.clone(),
        );
        let query = operation.read(&[], 900).unwrap();
        let result =
            structured_pkix::constraints::BasicConstraints::read(extension, &query.execution());
        if success {
            assert!(!result.unwrap().is_authority());
        } else {
            assert!(result.unwrap_err().is_resource());
        }
        assert_eq!(account.used(), 0);
    }
}

#[test]
fn eku_storage_and_copy_work_cannot_bypass_producing_local_ceiling() {
    // The global work observed on a successful full read includes all actual
    // catalogue allocations. Use one repeatedly queried key so randomized hash
    // collision counts cannot vary between the two measurements. A local ceiling
    // one unit below the total must refuse rather than fund storage via Memory.
    let bytes = catalogue();
    let measured = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let parser = Parser::ber(measured.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let extension = extensions
        .get(structured_pkix::oid::EXT_KEY_USAGE, &parent.execution())
        .unwrap()
        .unwrap();
    let usage = ExtendedKeyUsage::read(extension, &measured).unwrap();
    assert_eq!(usage.purposes().len(), 1);
    let full_work = measured.work_used();
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: u64::try_from(full_work - 1).unwrap(),
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let held = memory.used();
    let extension = extensions
        .get(structured_pkix::oid::EXT_KEY_USAGE, &parent.execution())
        .unwrap()
        .unwrap();
    let error = ExtendedKeyUsage::read(extension, &memory).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "extensions.extKeyUsage");
    assert_eq!(memory.used(), held);
    assert!(memory.work_remaining() > 1000);
}

#[test]
fn alternative_name_catalogue_respects_producing_local_ceiling() {
    // SAN parsing must charge the catalogue growth/copy, not just the DNS
    // grammar and ASN.1 reads, against the original certificate session.
    let mut names = Vec::new();
    for _ in 0..64 {
        names.extend(tlv(0x82, b"example.com"));
    }
    let mut extension = tlv(6, &[0x55, 0x1d, 0x11]);
    extension.extend(tlv(4, &tlv(0x30, &names)));
    let bytes = tlv(0x30, &tlv(0x30, &extension));
    let measured = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let parser = Parser::ber(measured.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let extension = extensions
        .get(structured_pkix::oid::SUBJECT_ALT_NAME, &parent.execution())
        .unwrap()
        .unwrap();
    let decoded = structured_pkix::general_name::read_alternative(extension, &measured).unwrap();
    assert_eq!(decoded.len(), 64);
    let full_work = measured.work_used();
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: u64::try_from(full_work - 1).unwrap(),
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let extension = extensions
        .get(structured_pkix::oid::SUBJECT_ALT_NAME, &parent.execution())
        .unwrap()
        .unwrap();
    let held = memory.used();
    let error = structured_pkix::general_name::read_alternative(extension, &memory).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(error.field(), "extensions.subjectAltName");
    assert_eq!(memory.used(), held);
}

fn assert_local_bound(
    value: &[u8],
    kind: structured_asn1::Oid<'_>,
    expected: usize,
    decode: impl for<'a> Fn(&structured_pkix::Extension<'a>, &Memory) -> structured_pkix::Result<usize>,
) {
    let mut extension = tlv(6, kind.as_bytes());
    extension.extend(tlv(4, value));
    let bytes = tlv(0x30, &tlv(0x30, &extension));
    let measured = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let parser = Parser::ber(measured.clone());
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let extension = extensions.get(kind, &parent.execution()).unwrap().unwrap();
    assert_eq!(decode(extension, &measured).unwrap(), expected);
    let full_work = measured.work_used();
    let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
    let parser = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: u64::try_from(full_work - 1).unwrap(),
            ..Limits::default()
        },
        memory.clone(),
    );
    let mut parent = parser.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let extension = extensions.get(kind, &parent.execution()).unwrap().unwrap();
    let held = memory.used();
    let error = decode(extension, &memory).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(memory.used(), held);
    assert!(memory.work_remaining() > 1000);
}

#[test]
fn information_access_catalogue_growth_obeys_original_local_work() {
    // AIA/SIA lists are a critical-extension interpretation path; their entries
    // cannot allocate/copy outside the parser that admitted their source bytes.
    let mut descriptions = Vec::new();
    for _ in 0..64 {
        let mut pair = tlv(6, &[42]);
        pair.extend(tlv(0x82, b"example.com"));
        descriptions.extend(tlv(0x30, &pair));
    }
    assert_local_bound(
        &tlv(0x30, &descriptions),
        structured_pkix::oid::AUTHORITY_INFO_ACCESS,
        64,
        |extension, memory| {
            structured_pkix::access::InfoAccess::read(extension, memory)
                .map(|value| value.descriptions().len())
        },
    );
}

#[test]
fn distribution_point_catalogue_growth_obeys_original_local_work() {
    // The outer DP catalogue remains attacker-controlled even when every
    // individual name has already passed its own funded decoder.
    let mut points = Vec::new();
    for _ in 0..64 {
        let full_name = tlv(0xa0, &tlv(0x86, b"https://example.com/crl"));
        points.extend(tlv(0x30, &tlv(0xa0, &full_name)));
    }
    assert_local_bound(
        &tlv(0x30, &points),
        structured_pkix::oid::CRL_DISTRIBUTION_POINTS,
        64,
        |extension, memory| {
            structured_pkix::access::DistributionPoints::read(extension, memory)
                .map(|value| value.points().len())
        },
    );
}

#[test]
fn policy_and_qualifier_catalogues_obey_original_local_work() {
    // Both retained policy entries and their nested opaque qualifier entries
    // must be admitted before growth under the same original session ceiling.
    let mut qualifiers = Vec::new();
    for _ in 0..64 {
        let mut qualifier = tlv(6, &[43]);
        qualifier.extend([5, 0]);
        qualifiers.extend(tlv(0x30, &qualifier));
    }
    let mut policy = tlv(6, &[42, 1]);
    policy.extend(tlv(0x30, &qualifiers));
    assert_local_bound(
        &tlv(0x30, &tlv(0x30, &policy)),
        structured_pkix::oid::CERTIFICATE_POLICIES,
        64,
        |extension, memory| {
            structured_pkix::policy::CertificatePolicies::read(extension, memory)
                .map(|value| value.policies()[0].qualifiers().len())
        },
    );
}

#[test]
fn policy_mapping_catalogue_and_dedup_obey_original_local_work() {
    // Pair deduplication and retained mapping growth must share the producing
    // session, rather than using a global-only map to bypass max_work.
    let mut mappings = Vec::new();
    // One repeated pair makes the exact work boundary independent of hash seed.
    for _ in 0..64 {
        let mut pair = tlv(6, &[42, 1]);
        pair.extend(tlv(6, &[43, 1]));
        mappings.extend(tlv(0x30, &pair));
    }
    assert_local_bound(
        &tlv(0x30, &mappings),
        structured_pkix::oid::POLICY_MAPPINGS,
        1,
        |extension, memory| {
            structured_pkix::policy::PolicyMappings::read(extension, memory)
                .map(|value| value.mappings().len())
        },
    );
}

#[test]
fn qualified_statement_catalogue_and_dedup_obey_original_local_work() {
    // Unknown statements stay inspectable; repeated equal payloads still pay
    // hashing/comparison and retained catalogue admission under the local cap.
    let mut statements = Vec::new();
    for _ in 0..64 {
        let mut statement = tlv(6, &[42, 1]);
        statement.extend([5, 0]);
        statements.extend(tlv(0x30, &statement));
    }
    assert_local_bound(
        &tlv(0x30, &statements),
        structured_pkix::oid::QC_STATEMENTS,
        1,
        |extension, memory| {
            structured_pkix::qualified::QcStatements::read(extension, memory)
                .map(|value| value.statements().len())
        },
    );
}

#[test]
fn name_constraint_subtree_catalogue_obeys_original_local_work() {
    // Permitted/excluded subtree vectors are grown directly; unlike empty
    // placeholders they cannot remain funded only by aggregate Memory.
    let mut subtrees = Vec::new();
    for _ in 0..64 {
        subtrees.extend(tlv(0x30, &tlv(0x82, b"example.com")));
    }
    assert_local_bound(
        &tlv(0x30, &tlv(0xa0, &subtrees)),
        structured_pkix::oid::NAME_CONSTRAINTS,
        64,
        |extension, memory| {
            structured_pkix::constraints::NameConstraints::read(extension, memory)
                .map(|value| value.permitted().len())
        },
    );
}
