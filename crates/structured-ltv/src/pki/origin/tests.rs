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

#[test]
fn origin_distinguishes_a_receipt_from_a_wrapper_at_the_same_address() {
    // A repr(C) wrapper starts at its first field's address. The census
    // produced from the inner receipt must not accept the wrapper instead.
    #[repr(C)]
    struct Wrapper {
        inner: [u8; 8],
        tag: u8,
    }
    let wrapper = Wrapper {
        inner: [7; 8],
        tag: 1,
    };
    assert_eq!(
        core::ptr::from_ref(&wrapper).addr(),
        core::ptr::from_ref(&wrapper.inner).addr()
    );
    let origin = Origin::of(&wrapper.inner);
    assert!(origin.matches(&wrapper.inner));
    assert!(!origin.matches(&wrapper));
    assert_eq!(wrapper.tag, 1);
}
