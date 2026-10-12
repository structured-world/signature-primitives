use super::{Error, ErrorCode, Limit, Path};
use alloc::format;

#[test]
fn a_root_path_prints_as_the_root() {
    assert_eq!(format!("{}", Path::default()), "/");
    assert!(Path::default().is_root());
}

#[test]
fn a_path_prints_outermost_first() {
    let mut path = Path::default();
    let memory = crate::test_memory();
    path.push(&memory, 0).unwrap();
    path.push(&memory, 2).unwrap();
    path.push(&memory, 1).unwrap();

    assert_eq!(format!("{path}"), "/0/2/1");
    assert_eq!(path.indices(), &[0, 2, 1]);
    assert!(!path.is_root());
}

#[test]
fn a_limit_is_distinguishable_from_a_malformed_document() {
    let limit = Error::new(ErrorCode::LimitExceeded(Limit::Depth), 4, Path::default());
    let malformed = Error::new(ErrorCode::UnexpectedEnd, 4, Path::default());

    assert!(limit.is_limit());
    assert!(!malformed.is_limit());
}

#[test]
fn the_absolute_tag_header_ceiling_is_a_resource_refusal() {
    // A wide tag is not malformed; schema gates must not swallow this ceiling.
    let error = Error::new(ErrorCode::TagTooLarge, 7, Path::default());
    assert!(error.is_limit());
    assert!(error.is_resource());
    assert_eq!(error.code(), ErrorCode::TagTooLarge);
    assert_eq!(error.offset(), 7);
}

#[test]
fn an_error_says_where_without_quoting_the_document() {
    let mut path = Path::default();
    path.push(&crate::test_memory(), 3).unwrap();
    let error = Error::new(ErrorCode::IntegerNotMinimal, 42, path);

    let rendered = format!("{error}");
    assert!(rendered.contains("42"), "{rendered}");
    assert!(rendered.contains("/3"), "{rendered}");
    assert_eq!(error.offset(), 42);
    assert_eq!(error.code(), ErrorCode::IntegerNotMinimal);
}

#[test]
fn each_limit_says_which_budget_ran_out() {
    // The four are distinguishable, because "too deep" and "too many" send a
    // caller lowering a budget to different numbers.
    let rendered: alloc::vec::Vec<_> = [
        Limit::Depth,
        Limit::Elements,
        Limit::ElementLength,
        Limit::Work,
    ]
    .iter()
    .map(|limit| format!("{limit}"))
    .collect();

    let mut unique = rendered.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
}
