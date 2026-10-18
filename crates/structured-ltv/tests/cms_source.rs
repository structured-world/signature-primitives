//! Long-term facts over a non-XML source: the unsigned attributes of one CMS
//! `SignerInfo`, identified by original ordinal as a `CAdES` layer would.

mod support;
#[path = "cms_source/token.rs"]
mod token;

use core::cell::Cell;
use p256::ecdsa::SigningKey;
use structured_asn1::{
    Parser,
    memory::{HashWork, Memory, MemoryError},
};
use structured_ltv::material::{Coverage, CoverageError};
use structured_ltv::pki::{
    self, CheckedPath, Counter, CounterReceipts, Credential, CredentialGroup, CredentialReceipts,
    Participant, ParticipantAuthority, ParticipantError, PathOutcome, SignerReceipt,
};
use structured_ltv::source::{Location, Scope, ScopeError, Snapshot, Source};
use structured_ltv::timestamp::{
    Purpose, TimestampPathBinding, TimestampPaths, TimestampRequirements, TimestampScope, Verified,
};
use structured_pkix::{
    Certificate,
    path::{self, Anchor, Interval, ValidationBounds, ValidationContext},
};
use support::{Oracle, certificate, memory};

/// Original ordinal of a `SignerInfo` or one of its unsigned attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Attribute(u16);

impl HashWork for Attribute {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(2)
    }
}

const SIGNATURE: Attribute = Attribute(0);
const COUNTER: Attribute = Attribute(1);
const COUNTER_SIGNER: Attribute = Attribute(2);
const CERTIFICATES: Attribute = Attribute(3);
const REVOCATION: Attribute = Attribute(4);
const ARCHIVE: Attribute = Attribute(5);
const ARCHIVE_TOKEN: Attribute = Attribute(6);
const LATER: Attribute = Attribute(7);

/// One CMS document whose generation changes when its attributes are rewritten.
struct SignedData {
    document: u8,
    generation: Cell<u8>,
}

impl Source for SignedData {
    type Id = Attribute;
    type Document = u8;
    type Generation = u8;
    fn snapshot(&self) -> Snapshot<u8, u8> {
        Snapshot {
            document: self.document,
            generation: self.generation.get(),
        }
    }
}

impl SignedData {
    fn location(&self, node: Attribute) -> Location<Attribute, u8, u8> {
        Location {
            snapshot: self.snapshot(),
            node,
        }
    }
}

struct Signer<'p, 'd> {
    location: Location<Attribute, u8, u8>,
    path: Option<&'p CheckedPath<'d>>,
}

impl<'p, 'd> SignerReceipt<'p, 'd> for Signer<'p, 'd> {
    type Id = Attribute;
    type Document = u8;
    type Generation = u8;
    fn signature(&self) -> Location<Attribute, u8, u8> {
        self.location
    }
    fn path(&self) -> Option<&'p CheckedPath<'d>> {
        self.path
    }
}

struct Counters<'p, 'd> {
    snapshot: Snapshot<u8, u8>,
    entries: Vec<Counter<'p, 'd, Attribute>>,
}

impl<'p, 'd> CounterReceipts<'p, 'd> for Counters<'p, 'd> {
    type Id = Attribute;
    type Document = u8;
    type Generation = u8;
    fn snapshot(&self) -> Snapshot<u8, u8> {
        self.snapshot
    }
    fn signature(&self) -> Attribute {
        SIGNATURE
    }
    fn len(&self) -> usize {
        self.entries.len()
    }
    fn counter(&self, ordinal: usize) -> Counter<'p, 'd, Attribute> {
        self.entries[ordinal]
    }
}

/// A signature without signer-attribute certificates.
struct Credentials {
    snapshot: Snapshot<u8, u8>,
}

struct NoCredentials;

impl<'p, 'd> CredentialGroup<'p, 'd> for NoCredentials {
    type Id = Attribute;
    fn signature(&self) -> Attribute {
        SIGNATURE
    }
    fn len(&self) -> usize {
        0
    }
    fn credential(&self, _: usize) -> Credential<'p, 'd, Attribute> {
        unreachable!("the group is empty")
    }
}

impl CredentialReceipts<'_, '_> for Credentials {
    type Id = Attribute;
    type Document = u8;
    type Generation = u8;
    type Group = NoCredentials;
    fn snapshot(&self) -> Snapshot<u8, u8> {
        self.snapshot
    }
    fn signature(&self) -> Attribute {
        SIGNATURE
    }
    fn root(&self) -> Option<&NoCredentials> {
        None
    }
    fn counters(&self) -> usize {
        0
    }
    fn counter(&self, _: usize) -> (Attribute, &NoCredentials) {
        unreachable!("no counter carries credentials")
    }
}

fn with_checked_path(check: impl FnOnce(&CheckedPath<'_>)) {
    let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let leaf_key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let root_bytes = certificate("Root", "Root", &root_key, &root_key);
    let leaf_bytes = certificate("Leaf", "Root", &leaf_key, &root_key);
    let source = Parser::der(memory(1 << 20));
    let root = Certificate::read(&source, &root_bytes, 400).unwrap();
    let leaf = Certificate::read(&source, &leaf_bytes, 800).unwrap();
    let current = memory(1 << 20);
    let operation = Parser::der(current.clone());
    let query = operation.read(&[], 1200).unwrap();
    let work = query.execution();
    let oracle = Oracle {
        calls: Cell::new(0),
    };
    let context = ValidationContext {
        execution: &work,
        interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
        policy: path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &oracle,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(checked) =
        pki::check_path(&[&leaf], Anchor::from_certificate(&root), &context).unwrap()
    else {
        panic!("actual P256 leaf signature must pass")
    };
    check(&checked);
}

fn requirements(
    data: &SignedData,
    memory: &Memory,
    counters: bool,
) -> TimestampRequirements<Attribute, u8, u8> {
    let scope = TimestampScope::All(data.location(SIGNATURE));
    let entries = memory.vector().into_owned();
    if !counters {
        return TimestampRequirements::new(SIGNATURE, scope, entries);
    }
    let mut signatures = memory.vector();
    signatures.try_push(COUNTER_SIGNER).unwrap();
    TimestampRequirements::with_counters(SIGNATURE, scope, entries, signatures.into_owned(), None)
}

fn bound<'v>(
    required: &'v TimestampRequirements<Attribute, u8, u8>,
    query: &Scope<'_, SignedData, Memory>,
) -> TimestampPaths<'v, 'v, 'v, Attribute, u8, u8> {
    let TimestampPathBinding::Bound(paths) = required.bind_paths(&[], query).unwrap() else {
        panic!("an attribute set without timestamps has no token obligation")
    };
    paths
}

#[test]
fn participant_census_follows_cms_attributes_and_their_exact_receipts() {
    // The same kernel that serves XAdES derives the actors of a CMS signature:
    // the signer and its countersignature attribute, each with its own path.
    // Receipt identity, not equal attribute ordinals, ties later facts to it.
    with_checked_path(|path| {
        let data = SignedData {
            document: 1,
            generation: Cell::new(1),
        };
        let memory = memory(1 << 20);
        let query = Scope::new(&data, data.snapshot(), &memory);
        let signer = Signer {
            location: data.location(SIGNATURE),
            path: Some(path),
        };
        let counters = Counters {
            snapshot: data.snapshot(),
            entries: vec![Counter {
                signature: COUNTER_SIGNER,
                property: COUNTER,
                path,
            }],
        };
        let credentials = Credentials {
            snapshot: data.snapshot(),
        };
        let required = requirements(&data, &memory, true);
        let paths = bound(&required, &query);
        let census = pki::participants(&signer, &counters, &credentials, &paths, &query).unwrap();
        assert_eq!(census.signature(), SIGNATURE);
        assert_eq!(census.entries().len(), 2);
        assert_eq!(
            census.entries()[0].participant(),
            Participant::Signer(SIGNATURE)
        );
        assert_eq!(
            census.entries()[1].participant(),
            Participant::Counter {
                signature: COUNTER_SIGNER,
                property: COUNTER,
            }
        );
        for entry in census.entries() {
            assert!(matches!(entry.authority(),
                ParticipantAuthority::Path(actual) if core::ptr::eq(actual, path)));
        }
        census
            .require_inputs(&signer, &counters, &credentials, &paths, &query)
            .unwrap();
        let equivalent = Credentials {
            snapshot: data.snapshot(),
        };
        assert_eq!(
            census.require_inputs(&signer, &counters, &equivalent, &paths, &query),
            Err(ParticipantError::Foreign {
                signature: SIGNATURE
            })
        );
        drop(census);

        // Obligations derived without the countersignature census cannot
        // silently drop that actor.
        let partial = requirements(&data, &memory, false);
        let partial = bound(&partial, &query);
        assert!(matches!(
            pki::participants(&signer, &counters, &credentials, &partial, &query),
            Err(ParticipantError::CounterTimestamps)
        ));
        let unproven = Signer {
            location: data.location(SIGNATURE),
            path: None,
        };
        assert!(matches!(
            pki::participants(&unproven, &counters, &credentials, &paths, &query),
            Err(ParticipantError::UnprovenSigner)
        ));
        data.generation.set(2);
        assert!(matches!(
            pki::participants(&signer, &counters, &credentials, &paths, &query),
            Err(ParticipantError::Scope(ScopeError::Changed {
                node: SIGNATURE
            }))
        ));
    });
}

#[test]
fn archive_coverage_binds_cms_attribute_selection_to_its_checked_token() {
    // An archive-time-stamp-v3 style input covers whole attributes. Only a
    // successfully checked token over exactly that input, for this archive
    // attribute and purpose, lets the selection count as coverage.
    let data = SignedData {
        document: 1,
        generation: Cell::new(1),
    };
    let memory = memory(1 << 20);
    let query = Scope::new(&data, data.snapshot(), &memory);
    let mut items = memory.map();
    // The signature is visited for its attributes but is not itself an item.
    items.try_insert(SIGNATURE, false).unwrap();
    items.try_insert(CERTIFICATES, true).unwrap();
    items.try_insert(REVOCATION, true).unwrap();
    let coverage = Coverage::new(data.snapshot(), SIGNATURE, ARCHIVE, Purpose::Archive, items);
    let input = b"certificate-values revocation-values";
    assert!(token::evidence(input, b"certificate-values", &memory).is_none());
    let evidence = token::evidence(input, input, &memory).unwrap();
    let other = |property, purpose| {
        let copy = evidence.try_copy_in(&memory).unwrap();
        Verified::new(
            data.location(ARCHIVE_TOKEN),
            SIGNATURE,
            property,
            purpose,
            copy,
        )
    };
    let foreign = other(LATER, Purpose::Archive);
    let validation = other(ARCHIVE, Purpose::ValidationData);
    let archive = Verified::new(
        data.location(ARCHIVE_TOKEN),
        SIGNATURE,
        ARCHIVE,
        Purpose::Archive,
        evidence,
    );
    for (node, covered) in [
        (CERTIFICATES, true),
        (REVOCATION, true),
        (SIGNATURE, false),
        (LATER, false),
    ] {
        assert_eq!(coverage.covers(&archive, node, &query), Ok(covered));
    }
    for wrong in [&foreign, &validation] {
        assert_eq!(
            coverage.covers(wrong, CERTIFICATES, &query),
            Err(CoverageError::Foreign { node: CERTIFICATES })
        );
    }
    data.generation.set(2);
    assert_eq!(
        coverage.covers(&archive, CERTIFICATES, &query),
        Err(CoverageError::Scope(ScopeError::Changed {
            node: CERTIFICATES
        }))
    );
}
