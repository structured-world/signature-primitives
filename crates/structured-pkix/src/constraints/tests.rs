use super::CertificateCount;
use crate::error::ErrorCode;
use crate::fixtures::{
    boolean, context, extension, extension_error, implicit, int, octets, seq, tlv, with_extension,
};
use crate::general_name::GeneralName;
use crate::oid;

#[test]
fn an_authority_is_read_with_the_depth_it_allows() {
    let value = seq(&[boolean(true), int(3)]);
    with_extension(extension(oid::BASIC_CONSTRAINTS, true, &value), |list| {
        let constraints = list.basic_constraints(list.memory()).unwrap().unwrap();
        assert!(constraints.is_authority());
        assert_eq!(
            constraints.path_length(),
            Some(CertificateCount::Certificates(3))
        );
    });
}

#[test]
fn an_empty_basic_constraints_says_not_an_authority() {
    // The flag defaults to false and the encoding rules leave a default out,
    // which is how a certificate issued to a person writes it.
    with_extension(extension(oid::BASIC_CONSTRAINTS, true, &seq(&[])), |list| {
        let constraints = list.basic_constraints(list.memory()).unwrap().unwrap();
        assert!(!constraints.is_authority());
        assert_eq!(constraints.path_length(), None);
    });
}

#[test]
fn a_depth_written_without_the_flag_is_refused() {
    // The path length must not be present unless the authority flag is
    // asserted (RFC 5280 4.2.1.9): without it the value constrains a path
    // below a certificate that says it heads none.
    let error = extension_error!(
        extension(oid::BASIC_CONSTRAINTS, true, &seq(&[int(2)])),
        basic_constraints
    );

    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn a_depth_that_is_not_a_count_is_refused() {
    // A negative depth, which the schema does not have: the field is
    // INTEGER (0..MAX) (RFC 5280 4.2.1.9), so below zero is outside it and
    // names no number of certificates at all.
    let value = seq(&[boolean(true), tlv(0x02, &[0xff])]);
    let error = extension_error!(
        extension(oid::BASIC_CONSTRAINTS, true, &value),
        basic_constraints
    );

    assert_eq!(error.code(), ErrorCode::MalformedValue);
    assert_eq!(error.field(), "extensions.basicConstraints");
}

#[test]
fn a_depth_wider_than_the_counter_is_a_bound_nothing_reaches() {
    // The other side of the same schema: above the type is still inside
    // INTEGER (0..MAX), so the count is understood as one no path reaches
    // rather than refused, which would block an otherwise valid critical
    // extension.
    let value = seq(&[
        boolean(true),
        tlv(0x02, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
    ]);
    with_extension(extension(oid::BASIC_CONSTRAINTS, true, &value), |list| {
        let constraints = list.basic_constraints(list.memory()).unwrap().unwrap();
        assert_eq!(
            constraints.path_length(),
            Some(CertificateCount::BeyondAnyPath)
        );
        assert_eq!(
            constraints
                .path_length()
                .and_then(CertificateCount::certificates),
            None
        );
    });
}

#[test]
fn name_constraints_are_read_as_the_regions_they_name() {
    let permitted = context(0, &[seq(&[implicit(2, b"example.ua")])]);
    let excluded = context(1, &[seq(&[implicit(2, b"forbidden.example.ua")])]);
    with_extension(
        extension(oid::NAME_CONSTRAINTS, true, &seq(&[permitted, excluded])),
        |list| {
            let constraints = list.name_constraints(list.memory()).unwrap().unwrap();
            assert_eq!(constraints.permitted().len(), 1);
            assert_eq!(constraints.excluded().len(), 1);
            assert!(matches!(
                constraints.permitted()[0].base(),
                GeneralName::Dns("example.ua")
            ));
            // The profile fixes both distances, and a certificate that leaves
            // them out is read with the values it fixes.
        },
    );
}

#[test]
fn a_domain_constraint_written_with_a_leading_period_is_read() {
    // The profile writes a domain-name restriction as a name that further
    // labels are added to the left of (RFC 5280 4.2.1.10), and gives the
    // leading period to the mail and location forms rather than this one. It
    // does not say to refuse the period here, issuers write it, and the
    // extension is critical: refusing the value refuses the authority and
    // every certificate under it, over a spelling of the same subtree.
    let permitted = context(0, &[seq(&[implicit(2, b".example.ua")])]);
    with_extension(
        extension(oid::NAME_CONSTRAINTS, true, &seq(&[permitted])),
        |list| {
            let constraints = list.name_constraints(list.memory()).unwrap().unwrap();
            assert!(matches!(
                constraints.permitted()[0].base(),
                GeneralName::Dns(".example.ua")
            ));
        },
    );

    // The period is a form of this position and not of a name: a list of
    // names still holds names.
    let der = seq(&[implicit(2, b".example.ua")]);
    let parser = structured_asn1::Parser::der(crate::fixtures::memory());
    let mut reader = parser.read(&der, 0).unwrap();
    let element = reader.next_element().unwrap().unwrap();
    assert!(crate::general_name::read_all(&reader, &element, "test").is_err());

    // And it is a period before a domain, not a period before anything.
    let permitted = context(0, &[seq(&[implicit(2, b".")])]);
    let error = extension_error!(
        extension(oid::NAME_CONSTRAINTS, true, &seq(&[permitted])),
        name_constraints
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn a_constraint_that_constrains_nothing_is_refused() {
    // Marked critical to say it must be obeyed, while permitting everything
    // and excluding nothing.
    let error = extension_error!(
        extension(oid::NAME_CONSTRAINTS, true, &seq(&[])),
        name_constraints
    );

    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn policy_constraints_are_read_as_the_counts_they_carry() {
    let value = seq(&[implicit(0, &[0x00]), implicit(1, &[0x02])]);
    with_extension(extension(oid::POLICY_CONSTRAINTS, true, &value), |list| {
        let constraints = list.policy_constraints(list.memory()).unwrap().unwrap();
        assert_eq!(
            constraints.require_explicit_policy(),
            Some(CertificateCount::Certificates(0))
        );
        assert_eq!(
            constraints.inhibit_policy_mapping(),
            Some(CertificateCount::Certificates(2))
        );
    });
}

#[test]
fn policy_constraints_with_neither_count_are_refused() {
    let error = extension_error!(
        extension(oid::POLICY_CONSTRAINTS, true, &seq(&[])),
        policy_constraints
    );

    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn the_count_that_stops_the_any_policy_identifier_is_read() {
    with_extension(extension(oid::INHIBIT_ANY_POLICY, true, &int(1)), |list| {
        let inhibit = list.inhibit_any_policy(list.memory()).unwrap().unwrap();
        assert_eq!(inhibit.skip(), CertificateCount::Certificates(1));
    });
}

#[test]
fn a_count_that_is_not_an_integer_is_refused() {
    let error = extension_error!(
        extension(oid::INHIBIT_ANY_POLICY, true, &octets(&[0x01])),
        inhibit_any_policy
    );

    assert_eq!(
        error.code(),
        ErrorCode::Encoding(structured_asn1::ErrorCode::UnexpectedTag)
    );
}

#[test]
fn a_field_of_another_tag_class_is_not_a_policy_constraint() {
    // PRIVATE 0 shares the number and construction of requireExplicitPolicy,
    // and only the class says it is not that field. Reading it as one would
    // turn a schema-invalid extension into an active path constraint.
    let error = extension_error!(
        extension(oid::POLICY_CONSTRAINTS, true, &seq(&[tlv(0xc0, &[0x00])])),
        policy_constraints
    );

    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn a_subtree_address_must_carry_the_mask_beside_it() {
    // In a name constraint an address region is the address and its mask,
    // eight or thirty-two bytes together. A bare four-byte address has no
    // mask and describes no region.
    let error = extension_error!(
        extension(
            oid::NAME_CONSTRAINTS,
            true,
            &seq(&[context(0, &[seq(&[implicit(7, &[192, 0, 2, 1])])])]),
        ),
        name_constraints
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    // And the paired form is a region.
    let paired = [192, 0, 2, 0, 255, 255, 255, 0];
    with_extension(
        extension(
            oid::NAME_CONSTRAINTS,
            true,
            &seq(&[context(0, &[seq(&[implicit(7, &paired)])])]),
        ),
        |list| assert!(list.name_constraints(list.memory()).unwrap().is_some()),
    );
}

#[test]
fn a_nonzero_subtree_minimum_is_refused() {
    // The profile requires the minimum to be zero (RFC 5280 4.2.1.10): a
    // subtree starting below its base asks for a reading this profile does
    // not define, and a critical extension holding one was not understood.
    let subtree = seq(&[implicit(2, b"example.ua"), implicit(0, &[0x01])]);
    let error = extension_error!(
        extension(oid::NAME_CONSTRAINTS, true, &seq(&[context(0, &[subtree])])),
        name_constraints
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn a_subtree_maximum_distance_is_refused() {
    // The profile requires the maximum to be absent (RFC 5280 4.2.1.10): a
    // constraint carrying one asks for a reading this profile does not
    // define, and a critical extension holding it was not understood.
    let subtree = seq(&[implicit(2, b"example.ua"), implicit(1, &[0x02])]);
    let error = extension_error!(
        extension(oid::NAME_CONSTRAINTS, true, &seq(&[context(0, &[subtree])])),
        name_constraints
    );
    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn a_subtree_mask_that_is_not_contiguous_is_refused() {
    // The region form is CIDR (RFC 5280 4.2.1.10, via RFC 4632): the mask
    // is leading one bits and nothing after them. A gap in the mask
    // describes no range this profile defines.
    let holed = [192, 0, 2, 0, 255, 0, 255, 0];
    let error = extension_error!(
        extension(
            oid::NAME_CONSTRAINTS,
            true,
            &seq(&[context(0, &[seq(&[implicit(7, &holed)])])]),
        ),
        name_constraints
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn constraint_fields_written_backwards_are_refused() {
    // Both structures fix the order of their fields, and a field written
    // after one that belongs later is not the schema even when nothing
    // repeats.
    let backwards_subtrees = seq(&[
        context(1, &[seq(&[implicit(2, b"forbidden.example.ua")])]),
        context(0, &[seq(&[implicit(2, b"example.ua")])]),
    ]);
    let error = extension_error!(
        extension(oid::NAME_CONSTRAINTS, true, &backwards_subtrees),
        name_constraints
    );
    assert_eq!(error.code(), ErrorCode::UnexpectedField);

    let backwards_policy = seq(&[implicit(1, &[0x02]), implicit(0, &[0x00])]);
    let error = extension_error!(
        extension(oid::POLICY_CONSTRAINTS, true, &backwards_policy),
        policy_constraints
    );
    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn a_subtree_maximum_before_its_minimum_is_refused() {
    // The subtree fixes the order of its distances too: minimum, then
    // maximum. Backwards is not the schema even with nothing repeated.
    let subtree = seq(&[
        implicit(2, b"example.ua"),
        implicit(1, &[0x02]),
        implicit(0, &[0x00]),
    ]);
    let error = extension_error!(
        extension(oid::NAME_CONSTRAINTS, true, &seq(&[context(0, &[subtree])])),
        name_constraints
    );

    assert_eq!(error.code(), ErrorCode::UnexpectedField);
}

#[test]
fn a_spelled_out_default_constraint_is_refused_under_der() {
    // DER omits a component equal to its default. The CA flag defaults to
    // false and a subtree minimum to zero; writing either out is a second
    // spelling of the absent field.
    let error = extension_error!(
        extension(oid::BASIC_CONSTRAINTS, true, &seq(&[boolean(false)])),
        basic_constraints
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);

    let subtree = seq(&[implicit(2, b"example.ua"), implicit(0, &[0x00])]);
    let error = extension_error!(
        extension(oid::NAME_CONSTRAINTS, true, &seq(&[context(0, &[subtree])])),
        name_constraints
    );
    assert_eq!(error.code(), ErrorCode::MalformedValue);
}

#[test]
fn an_empty_directory_subtree_base_is_the_root() {
    // As an identity an empty name names nobody, but as a subtree base it
    // is the root: an excluded empty base excludes every directory name,
    // and a permitted one permits all.
    let base = context(4, &[seq(&[])]);
    let value = seq(&[context(1, &[seq(&[base])])]);
    with_extension(extension(oid::NAME_CONSTRAINTS, true, &value), |list| {
        let constraints = list.name_constraints(list.memory()).unwrap().unwrap();
        assert_eq!(constraints.excluded().len(), 1);
    });
}
