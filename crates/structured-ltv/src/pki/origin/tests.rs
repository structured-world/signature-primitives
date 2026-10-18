use super::Origin;

#[test]
fn origin_compares_live_instances_without_copying_their_payload() {
    // Equal payload is not the same selected receipt. The scoped reference
    // keeps identity valid without retaining/cloning an opaque provider.
    let first = [7u8; 8];
    let second = first;
    let origin = Origin::of(&first);
    assert!(origin.matches(&first));
    assert!(!origin.matches(&second));
}
