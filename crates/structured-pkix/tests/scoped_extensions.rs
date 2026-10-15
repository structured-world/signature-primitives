//! Deferred extension and role callbacks retain the operation's execution.

use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, Work};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_pkix::extension::{Extensions, Recognizer};
use structured_pkix::oid;

fn memory() -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)))
}

fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut result = vec![tag, u8::try_from(contents.len()).unwrap()];
    result.extend_from_slice(contents);
    result
}

fn constraints_with_temporary_operation<'source>(
    extensions: &Extensions<'source>,
    current: &Memory,
) -> structured_pkix::constraints::NameConstraints<'source> {
    let operation = Parser::der(current.clone());
    let query = operation.read(&[], 900).unwrap();
    extensions
        .name_constraints(&query.execution())
        .unwrap()
        .unwrap()
}

#[test]
fn retained_directory_constraint_keeps_original_name_after_current_operation_ends() {
    // A lazy DirectoryName owns catalogue capacity but borrows original bytes
    // and the original parser, independently of a completed decoding operation.
    let attribute = tlv(
        0x30,
        &[tlv(6, oid::COMMON_NAME.as_bytes()), tlv(12, b"A")].concat(),
    );
    let name = tlv(0x30, &tlv(0x31, &attribute));
    let constraints = tlv(0x30, &tlv(0xa0, &tlv(0x30, &tlv(0xa4, &name))));
    let extension = tlv(
        0x30,
        &[
            tlv(6, oid::NAME_CONSTRAINTS.as_bytes()),
            tlv(4, &constraints),
        ]
        .concat(),
    );
    let bytes = tlv(0x30, &extension);
    let source = Parser::der(memory());
    let mut parent = source.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let old = source.memory().work_used();
    let current = memory();
    let retained = constraints_with_temporary_operation(&extensions, &current);
    let structured_pkix::general_name::GeneralName::Directory(directory) =
        retained.permitted()[0].base()
    else {
        panic!("original directory constraint")
    };
    assert_eq!(directory.as_bytes(), name);
    assert!((bytes.as_ptr_range()).contains(&directory.as_bytes().as_ptr()));
    assert!(current.used() > 0);
    assert_eq!(source.memory().work_used(), old);
    let denied = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = denied.read(&[], 1200).unwrap();
    assert!(
        directory
            .matches(directory, &query.execution())
            .unwrap_err()
            .is_resource()
    );
    drop(retained);
    assert_eq!(current.used(), 0);
}

struct Roles;

impl<W: Work> Recognizer<W> for Roles {
    type Error = MemoryError;
    fn recognizes(&self, _: Oid<'_>, work: &W) -> Result<bool, Self::Error> {
        work.charge_work(1)?;
        Ok(true)
    }
    fn recognizes_other_name(&self, kind: Oid<'_>, work: &W) -> Result<bool, Self::Error> {
        self.recognizes(kind, work)
    }
    fn recognizes_name_constraint(&self, kind: Oid<'_>, work: &W) -> Result<bool, Self::Error> {
        self.recognizes(kind, work)
    }
    fn recognizes_access_method(&self, kind: Oid<'_>, work: &W) -> Result<bool, Self::Error> {
        self.recognizes(kind, work)
    }
    fn recognizes_statement(&self, kind: Oid<'_>, work: &W) -> Result<bool, Self::Error> {
        self.recognizes(kind, work)
    }
}

#[test]
fn all_recognizer_roles_forward_the_same_scoped_work_through_references() {
    // A reference must forward every role with the selected Work type. Falling
    // back to Memory or a default false would silently lose budget or knowledge.
    let current = memory();
    let parser = Parser::new(
        Encoding::Der,
        Limits {
            max_work: 5,
            ..Limits::default()
        },
        current.clone(),
    );
    let reader = parser.read(&[], 900).unwrap();
    let work = reader.execution();
    let roles = &Roles;
    assert!(Recognizer::recognizes(&roles, oid::COMMON_NAME, &work).unwrap());
    assert!(Recognizer::recognizes_other_name(&roles, oid::COMMON_NAME, &work).unwrap());
    assert!(Recognizer::recognizes_name_constraint(&roles, oid::COMMON_NAME, &work).unwrap());
    assert!(Recognizer::recognizes_access_method(&roles, oid::COMMON_NAME, &work).unwrap());
    assert!(Recognizer::recognizes_statement(&roles, oid::COMMON_NAME, &work).unwrap());
    assert_eq!(
        Recognizer::recognizes(&roles, oid::COMMON_NAME, &work),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(current.work_used(), 5);
    let identifiers = [oid::COMMON_NAME];
    assert_eq!(
        Recognizer::recognizes(&identifiers[..], oid::COMMON_NAME, &work),
        Err(MemoryError::WorkExceeded)
    );
    assert_eq!(current.used(), 0);
}

#[test]
fn retained_statement_payload_and_typed_lookup_obey_current_query() {
    // The statement catalogue is already retained on its source account. Each
    // lazy payload read still checks the new operation, before any ASN.1 scan.
    let mut statement = tlv(6, oid::QC_TYPE.as_bytes());
    statement.extend(tlv(0x30, &tlv(6, oid::QCT_ESIGN.as_bytes())));
    let mut extension = tlv(6, oid::QC_STATEMENTS.as_bytes());
    extension.extend(tlv(4, &tlv(0x30, &tlv(0x30, &statement))));
    let bytes = tlv(0x30, &tlv(0x30, &extension));
    let source = Parser::der(memory());
    let mut parent = source.read(&bytes, 400).unwrap();
    let element = parent.next_element().unwrap().unwrap();
    let extensions = Extensions::read_element(&parent, &element, "extensions").unwrap();
    let statements = extensions.qc_statements(source.memory()).unwrap().unwrap();
    let origin_work = source.memory().work_used();
    let current = memory();
    let parser = Parser::der(current.clone());
    let reader = parser.read(&[], 900).unwrap();
    let values = statements.types(&reader.execution()).unwrap();
    assert_eq!(
        &*values,
        &[structured_pkix::qualified::QualifiedType::ElectronicSignature]
    );
    drop(values);
    assert_eq!(current.used(), 0);
    assert_eq!(source.memory().work_used(), origin_work);
    let denied = Parser::new(
        Encoding::Der,
        Limits {
            max_elements: 0,
            ..Limits::default()
        },
        current.clone(),
    );
    let query = denied.read(&[], 1000).unwrap();
    let error = statements.types(&query.execution()).unwrap_err();
    assert!(error.is_resource());
    assert!(error.offset() >= 400);
    assert_eq!(current.used(), 0);
    let error = extensions.qc_statements(&query.execution()).unwrap_err();
    assert!(error.is_resource());
    assert_eq!(current.used(), 0);
}
