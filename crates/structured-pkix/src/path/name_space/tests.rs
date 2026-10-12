use super::{Admission, NameSpace};
use crate::constraints::NameConstraints;
use crate::fixtures::{
    CertificateParts, cat, context, extension, ia5, oid as oid_of, printable, seq, set, tlv, utf8,
};
use crate::{Certificate, oid};
use alloc::vec::Vec;
use structured_asn1::Parser;

/// A distinguished name of one common name.
fn named(common: &str) -> Vec<u8> {
    seq(&[set(&[seq(&[oid_of(oid::COMMON_NAME), printable(common)])])])
}

/// A distinguished name of one organization, which is what an authority
/// constrained to one organization's names is written as.
fn organization(name: &str) -> Vec<u8> {
    seq(&[set(&[seq(&[oid_of(oid::ORGANIZATION), printable(name)])])])
}

/// A distinguished name of an organization and a common name under it.
fn under(organization: &str, common: &str) -> Vec<u8> {
    seq(&[
        set(&[seq(&[oid_of(oid::ORGANIZATION), printable(organization)])]),
        set(&[seq(&[oid_of(oid::COMMON_NAME), printable(common)])]),
    ])
}

/// A subtree of one base, which is the only field the profile permits.
fn subtree(base: Vec<u8>) -> Vec<u8> {
    seq(&[base])
}

/// The constraints one certificate carries, read through the crate's own
/// accessor.
fn of<'a>(certificate: &Certificate<'a>) -> NameConstraints<'a> {
    certificate
        .tbs()
        .extensions()
        .name_constraints(certificate.tbs().extensions().memory())
        .expect("the extension this test wrote")
        .expect("a value this test wrote")
}

/// The name-constraints extension value: the permitted subtrees, then the
/// excluded ones, each left out where the test names none.
fn constraints(permitted: &[Vec<u8>], excluded: &[Vec<u8>]) -> Vec<u8> {
    let mut parts = Vec::new();
    if !permitted.is_empty() {
        parts.push(context(0, permitted));
    }
    if !excluded.is_empty() {
        parts.push(context(1, excluded));
    }
    seq(&parts)
}

/// A mail name, as a subtree base or an alternative name.
fn mail(address: &str) -> Vec<u8> {
    tlv(0x81, address.as_bytes())
}

/// A domain name.
fn dns(host: &str) -> Vec<u8> {
    tlv(0x82, host.as_bytes())
}

/// A distinguished name, in the one form that is constructed.
fn directory(name: Vec<u8>) -> Vec<u8> {
    context(4, &[name])
}

/// A location.
fn uri(location: &str) -> Vec<u8> {
    tlv(0x86, location.as_bytes())
}

/// An address, or an address and its mask where the test writes one.
fn address(octets: &[u8]) -> Vec<u8> {
    tlv(0x87, octets)
}

/// A name form this crate matches no constraint against.
fn registered() -> Vec<u8> {
    tlv(0x88, oid::ANY_POLICY.as_bytes())
}

/// A name form defined elsewhere, kept as its identifier and its value.
fn other() -> Vec<u8> {
    tlv(
        0xa0,
        &cat(&[oid_of(oid::ANY_POLICY), context(0, &[utf8("x")])]),
    )
}

/// The verdict on one certificate carrying the given subject and
/// alternative names, against one set of constraints.
///
/// Everything is read here and nothing is handed back, because a certificate
/// and everything read from it borrow the bytes, and the bytes live for as
/// long as this call.
fn admission(
    permitted: &[Vec<u8>],
    excluded: &[Vec<u8>],
    subject: Vec<u8>,
    alternatives: &[Vec<u8>],
) -> Admission {
    let mut extensions = alloc::vec![extension(
        oid::NAME_CONSTRAINTS,
        true,
        &constraints(permitted, excluded),
    )];
    if !alternatives.is_empty() {
        // Critical, because a certificate whose subject is empty carries its
        // identity here and has to mark it so (RFC 5280 4.2.1.6). Whether it
        // is marked changes nothing about where the names sit.
        extensions.push(extension(oid::SUBJECT_ALT_NAME, true, &seq(alternatives)));
    }
    let der = CertificateParts {
        subject,
        extensions: Some(seq(&extensions)),
        ..CertificateParts::default()
    }
    .build();

    let parser = Parser::der(crate::fixtures::memory());
    let certificate = Certificate::read(&parser, &der, 0).expect("a certificate this test wrote");
    let read = certificate
        .tbs()
        .extensions()
        .name_constraints(certificate.tbs().extensions().memory())
        .expect("the extension this test wrote")
        .expect("a value this test wrote");
    let names = certificate
        .tbs()
        .extensions()
        .subject_alt_name(certificate.tbs().extensions().memory())
        .expect("a value this test wrote")
        .unwrap_or_else(|| parser.memory().vector());

    let mut space = NameSpace::new(parser.memory());
    space.narrow(read).unwrap();
    space
        .admits(certificate.tbs().subject(), &names, &(), parser.memory())
        .unwrap()
}

#[test]
fn a_space_nobody_narrowed_admits_every_name() {
    // The common case, and the one that has to cost nothing: no authority
    // above said anything about names, so nothing is out of place.
    let space = NameSpace::new(&crate::fixtures::memory());
    assert!(space.is_open());
    assert_eq!(space.regions(), 0);

    let der = CertificateParts::default().build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = Certificate::read(&parser, &der, 0).unwrap();
    assert_eq!(
        space
            .admits(certificate.tbs().subject(), &[], &(), parser.memory())
            .unwrap(),
        Admission::Admitted
    );
}

#[test]
fn constraint_dispatch_is_admitted_before_a_short_name_comparison() {
    // A borrowed short DNS name has no forming scan; its actual constraint
    // dispatch must still fail after the one-unit presentation charge.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let der = CertificateParts {
        subject: seq(&[]),
        extensions: Some(seq(&[
            extension(
                oid::NAME_CONSTRAINTS,
                true,
                &constraints(&[subtree(dns("example.ua"))], &[]),
            ),
            extension(oid::SUBJECT_ALT_NAME, true, &seq(&[dns("example.ua")])),
        ])),
        ..CertificateParts::default()
    }
    .build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = Certificate::read(&parser, &der, 0).unwrap();
    let names = certificate
        .tbs()
        .extensions()
        .subject_alt_name(parser.memory())
        .unwrap()
        .unwrap();
    let mut space = NameSpace::new(parser.memory());
    space.narrow(of(&certificate)).unwrap();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 1)));
    let error = space
        .admits(certificate.tbs().subject(), &names, &(), &execution)
        .unwrap_err();
    assert!(matches!(error, crate::error::CallbackError::Processing(error) if error.is_resource()));
    assert_eq!(execution.work_used(), 1);
}

#[test]
fn constraint_bytes_are_admitted_before_a_retained_dns_comparison() {
    // Two metadata units permit presentation and dispatch, but must not
    // finance the actual case-insensitive byte comparison in a new account.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let der = CertificateParts {
        subject: seq(&[]),
        extensions: Some(seq(&[
            extension(
                oid::NAME_CONSTRAINTS,
                true,
                &constraints(&[subtree(dns("example.ua"))], &[]),
            ),
            extension(oid::SUBJECT_ALT_NAME, true, &seq(&[dns("example.ua")])),
        ])),
        ..CertificateParts::default()
    }
    .build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = Certificate::read(&parser, &der, 0).unwrap();
    let names = certificate
        .tbs()
        .extensions()
        .subject_alt_name(parser.memory())
        .unwrap()
        .unwrap();
    let mut space = NameSpace::new(parser.memory());
    space.narrow(of(&certificate)).unwrap();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 2)));
    let error = space
        .admits(certificate.tbs().subject(), &names, &(), &execution)
        .unwrap_err();
    assert!(matches!(error, crate::error::CallbackError::Processing(error) if error.is_resource()));
    assert_eq!(execution.work_used(), 2);
}

#[test]
fn a_name_below_the_permitted_one_is_admitted_and_one_beside_it_is_not() {
    // The directory form is the one the profile requires every validator to
    // process: the region is a name, and what is in it begins with that name.
    let base = subtree(directory(organization("Example")));
    assert_eq!(
        admission(
            core::slice::from_ref(&base),
            &[],
            under("Example", "Leaf"),
            &[]
        ),
        Admission::Admitted
    );
    // Its own base is in it, which is what lets an authority constrain a
    // path to itself.
    assert_eq!(
        admission(
            core::slice::from_ref(&base),
            &[],
            organization("Example"),
            &[]
        ),
        Admission::Admitted
    );
    assert_eq!(
        admission(&[base], &[], under("Other", "Leaf"), &[]),
        Admission::NotPermitted
    );
}

#[test]
fn an_excluded_name_is_refused_however_widely_it_was_permitted() {
    // Forbidding beats allowing: a region inside a permitted one that an
    // authority excluded is excluded (RFC 5280 6.1.4 (g)).
    let permitted = subtree(directory(organization("Example")));
    let excluded = subtree(directory(under("Example", "Secret")));
    assert_eq!(
        admission(&[permitted], &[excluded], under("Example", "Secret"), &[]),
        Admission::Excluded
    );
}

#[test]
fn a_constraint_of_one_form_says_nothing_about_a_name_of_another() {
    // A permitted mail region constrains mail names. A certificate that
    // carries no mail name is not outside it: it is not in that space at
    // all (RFC 5280 4.2.1.10).
    assert_eq!(
        admission(
            &[subtree(mail("example.com"))],
            &[],
            named("Example"),
            &[dns("host.example.org")]
        ),
        Admission::Admitted
    );
}

#[test]
fn a_domain_region_holds_what_is_under_it_and_not_what_merely_ends_with_it() {
    // The domain form is a subtree: the domain itself and everything below
    // it. `notexample.com` ends with the same letters and is a different
    // domain, which is the mistake a plain suffix test makes.
    let base = subtree(dns("example.com"));
    for host in ["example.com", "host.example.com", "a.b.example.com"] {
        assert_eq!(
            admission(
                core::slice::from_ref(&base),
                &[],
                named("Leaf"),
                &[dns(host)]
            ),
            Admission::Admitted,
            "{host}"
        );
    }
    for host in ["notexample.com", "example.com.evil.net", "example.co"] {
        assert_eq!(
            admission(
                core::slice::from_ref(&base),
                &[],
                named("Leaf"),
                &[dns(host)]
            ),
            Admission::NotPermitted,
            "{host}"
        );
    }
}

#[test]
fn a_domain_region_is_read_without_regard_to_case() {
    // Host names are compared without regard to case, and a certificate
    // that writes one in capitals is not outside the region because of it.
    assert_eq!(
        admission(
            &[subtree(dns("Example.COM"))],
            &[],
            named("Leaf"),
            &[dns("HOST.example.com")]
        ),
        Admission::Admitted
    );
}

#[test]
fn a_mail_region_naming_a_host_does_not_hold_the_hosts_below_it() {
    // The mail form is not the domain form: without a leading separator the
    // region is one host, and with one it is a domain
    // (RFC 5280 4.2.1.10). Reading the two the same way would let a
    // certificate constrained to one host stand for every host under it.
    assert_eq!(
        admission(
            &[subtree(mail("example.com"))],
            &[],
            named("Leaf"),
            &[mail("someone@example.com")]
        ),
        Admission::Admitted
    );
    assert_eq!(
        admission(
            &[subtree(mail("example.com"))],
            &[],
            named("Leaf"),
            &[mail("someone@mail.example.com")]
        ),
        Admission::NotPermitted
    );
    assert_eq!(
        admission(
            &[subtree(mail(".example.com"))],
            &[],
            named("Leaf"),
            &[mail("someone@mail.example.com")]
        ),
        Admission::Admitted
    );
    // A domain region written with the separator is strictly below it, so
    // the domain's own host is not in it.
    assert_eq!(
        admission(
            &[subtree(mail(".example.com"))],
            &[],
            named("Leaf"),
            &[mail("someone@example.com")]
        ),
        Admission::NotPermitted
    );
}

#[test]
fn a_mail_region_naming_one_mailbox_holds_that_mailbox_and_no_other() {
    // The local part is compared as it is written, because what it means
    // belongs to the host that issues it, and the host part without regard
    // to case.
    let base = subtree(mail("Someone@Example.com"));
    assert_eq!(
        admission(
            core::slice::from_ref(&base),
            &[],
            named("Leaf"),
            &[mail("Someone@EXAMPLE.COM")]
        ),
        Admission::Admitted
    );
    assert_eq!(
        admission(&[base], &[], named("Leaf"), &[mail("someone@example.com")]),
        Admission::NotPermitted
    );
}

#[test]
fn a_mailbox_written_into_the_subject_is_held_to_the_mail_regions() {
    // Certificates exist that carry the mail identity as an attribute of
    // the subject rather than as an alternative name (RFC 5280 4.2.1.10).
    // A constraint that did not reach it would constrain nothing on them.
    let subject = seq(&[set(&[seq(&[
        oid_of(oid::EMAIL_ADDRESS),
        ia5("someone@elsewhere.net"),
    ])])]);
    assert_eq!(
        admission(&[subtree(mail("example.com"))], &[], subject, &[]),
        Admission::NotPermitted
    );
}

#[test]
fn a_location_is_held_by_its_host_and_nothing_else_it_names() {
    // What a location constraint constrains is the host part, and the rest
    // of the location is text this crate never resolves.
    let base = subtree(uri(".example.com"));
    for location in [
        "http://host.example.com/path",
        "https://user@host.example.com:443/path",
        "https://a.b.example.com/",
    ] {
        assert_eq!(
            admission(
                core::slice::from_ref(&base),
                &[],
                named("Leaf"),
                &[uri(location)]
            ),
            Admission::Admitted,
            "{location}"
        );
    }
    // The host is what is compared, so a region's name appearing anywhere
    // else in the location does not put it in the region: not in the path,
    // not in the user information, and not as the beginning of a longer
    // name.
    for location in [
        "http://evil.net/host.example.com",
        "http://host.example.com@evil.net/",
        "http://host.example.com.evil.net/",
    ] {
        assert_eq!(
            admission(
                core::slice::from_ref(&base),
                &[],
                named("Leaf"),
                &[uri(location)]
            ),
            Admission::NotPermitted,
            "{location}"
        );
    }
}

#[test]
fn a_location_that_names_no_server_is_in_no_host_region() {
    // A location without an authority names a resource rather than a server
    // (RFC 3986 3.2), and the separator that introduces an authority is the
    // one right after the scheme. Finding it anywhere else reads a host out
    // of a path: `urn:a//host.example.com/x` names no host at all, and
    // admitting it under a region that permits that host would put a
    // certificate in a space its authority never allowed. Having no host is
    // what a location constraint cannot be applied to, so the refusal is the
    // constraint's (RFC 5280 4.2.1.10) rather than the region's.
    assert_eq!(
        admission(
            &[subtree(uri(".example.com"))],
            &[],
            named("Leaf"),
            &[uri("urn:a//host.example.com/x")]
        ),
        Admission::Unenforceable
    );
}

#[test]
fn a_location_host_written_to_the_root_is_the_same_host() {
    // The reader keeps the closing period of an absolute host name because
    // that is how the location was written (RFC 1034 3.1), and it qualifies
    // the name rather than changing it. A region naming the same host has to
    // hold it, or a certificate is refused over a spelling.
    assert_eq!(
        admission(
            &[subtree(uri("example.com"))],
            &[],
            named("Leaf"),
            &[uri("https://example.com./")]
        ),
        Admission::Admitted
    );
    assert_eq!(
        admission(
            &[subtree(uri(".example.com"))],
            &[],
            named("Leaf"),
            &[uri("https://host.example.com./")]
        ),
        Admission::Admitted
    );
}

#[test]
fn an_address_is_in_a_network_when_the_masked_bytes_agree() {
    let base = subtree(address(&[192, 0, 2, 0, 255, 255, 255, 0]));
    assert_eq!(
        admission(
            core::slice::from_ref(&base),
            &[],
            named("Leaf"),
            &[address(&[192, 0, 2, 77])]
        ),
        Admission::Admitted
    );
    assert_eq!(
        admission(
            core::slice::from_ref(&base),
            &[],
            named("Leaf"),
            &[address(&[192, 0, 3, 77])]
        ),
        Admission::NotPermitted
    );
    // A network of four bytes does not hold a sixteen-byte address, and
    // reading the first four of one as the other would put it in a network
    // nobody named. The widths are fixed by the profile and checked when
    // they were read, so a pair that does not match is two address families
    // and a definite answer rather than an unreadable comparison.
    assert_eq!(
        admission(
            &[base],
            &[],
            named("Leaf"),
            &[address(&[
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            ])]
        ),
        Admission::NotPermitted
    );
}

#[test]
fn a_certificate_with_alternative_names_is_not_held_to_its_legacy_mailbox() {
    // "When constraints are imposed on the rfc822Name name form, but the
    // certificate does not include a subject alternative name, the
    // rfc822Name constraint MUST be applied to the attribute of type
    // emailAddress in the subject distinguished name" (RFC 5280 4.2.1.10).
    // The fallback is for certificates that carry their mail identity in
    // the subject because they carry no alternative names. Applying it to
    // one that does have them refuses a certificate whose actual mail
    // identity is where the region allows it.
    let subject = seq(&[set(&[seq(&[
        oid_of(oid::EMAIL_ADDRESS),
        ia5("someone@elsewhere.net"),
    ])])]);
    assert_eq!(
        admission(
            &[subtree(mail("example.com"))],
            &[],
            subject,
            &[mail("someone@example.com")]
        ),
        Admission::Admitted
    );
}

#[test]
fn a_location_a_uri_constraint_cannot_be_applied_to_lets_no_path_through() {
    // "If a constraint is applied to the uniformResourceIdentifier name form
    // and a subsequent certificate includes a subjectAltName extension with a
    // uniformResourceIdentifier that does not include an authority component
    // with a host name specified as a fully qualified domain name ... then the
    // application MUST reject the certificate" (RFC 5280 4.2.1.10). Reading
    // such a location as merely outside the region lets it past an excluded
    // subtree, which is where nothing else would catch it.
    for location in [
        "urn:example:value",
        "http://192.0.2.1/x",
        "http://[2001:db8::1]/x",
    ] {
        assert_eq!(
            admission(
                &[],
                &[subtree(uri(".example.com"))],
                named("Leaf"),
                &[uri(location)]
            ),
            Admission::Unenforceable,
            "excluded: {location}"
        );
        assert_eq!(
            admission(
                &[subtree(uri(".example.com"))],
                &[],
                named("Leaf"),
                &[uri(location)]
            ),
            Admission::Unenforceable,
            "permitted: {location}"
        );
    }
}

#[test]
fn an_address_of_the_other_family_is_outside_a_network_rather_than_unreadable() {
    // A network of four bytes and an address of sixteen are both well
    // formed, and the address is certainly not in that network. Answering
    // that the comparison could not be made refuses a certificate for
    // carrying an address of a family the exclusion never spoke about.
    let excluded = subtree(address(&[192, 0, 2, 0, 255, 255, 255, 0]));
    let six = address(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(
        admission(&[], &[excluded], named("Leaf"), core::slice::from_ref(&six)),
        Admission::Admitted
    );

    // Permitting only that network still leaves the address outside it,
    // which is a refusal for a reason rather than for want of an answer.
    let permitted = subtree(address(&[192, 0, 2, 0, 255, 255, 255, 0]));
    assert_eq!(
        admission(&[permitted], &[], named("Leaf"), &[six]),
        Admission::NotPermitted
    );
}

#[test]
fn a_region_of_a_form_this_crate_does_not_match_lets_no_path_through() {
    // An unenforceable constraint that let a path through would be a
    // constraint that did nothing, which is the opposite of what the
    // authority marked critical.
    assert_eq!(
        admission(
            &[subtree(registered())],
            &[],
            named("Leaf"),
            &[registered()]
        ),
        Admission::Unenforceable
    );
    assert_eq!(
        admission(&[subtree(other())], &[], named("Leaf"), &[other()]),
        Admission::Unenforceable
    );
}

#[test]
fn a_region_of_an_unmatched_form_still_says_nothing_about_other_forms() {
    // The name the certificate carries is of another form, so the
    // constraint this crate cannot match does not reach it and the answer
    // is not withheld.
    assert_eq!(
        admission(
            &[subtree(registered())],
            &[],
            named("Leaf"),
            &[dns("host.example.com")]
        ),
        Admission::Admitted
    );
}

#[test]
fn every_authority_that_spoke_has_to_admit_the_name() {
    // Two authorities each narrowing the space is an intersection: a name
    // one of them allows and the other does not is not in the space
    // (RFC 5280 6.1.4 (g)).
    let der = CertificateParts {
        subject: under("Example", "Leaf"),
        ..CertificateParts::default()
    }
    .build();
    let parser = Parser::der(crate::fixtures::memory());
    let certificate = Certificate::read(&parser, &der, 0).unwrap();

    let wide = extension(
        oid::NAME_CONSTRAINTS,
        true,
        &constraints(&[subtree(directory(organization("Example")))], &[]),
    );
    let narrow = extension(
        oid::NAME_CONSTRAINTS,
        true,
        &constraints(&[subtree(directory(organization("Elsewhere")))], &[]),
    );

    let carrying = |value: Vec<u8>| {
        CertificateParts {
            extensions: Some(seq(&[value])),
            ..CertificateParts::default()
        }
        .build()
    };
    let wide_der = carrying(wide);
    let narrow_der = carrying(narrow);
    let wide = Certificate::read(&parser, &wide_der, 0).unwrap();
    let narrow = Certificate::read(&parser, &narrow_der, 0).unwrap();
    let mut space = NameSpace::new(parser.memory());
    space.narrow(of(&wide)).unwrap();
    assert_eq!(
        space
            .admits(certificate.tbs().subject(), &[], &(), parser.memory())
            .unwrap(),
        Admission::Admitted
    );
    space.narrow(of(&narrow)).unwrap();
    assert_eq!(space.regions(), 2);
    assert_eq!(
        space
            .admits(certificate.tbs().subject(), &[], &(), parser.memory())
            .unwrap(),
        Admission::NotPermitted
    );
}

#[test]
fn an_empty_subject_carries_no_identity_to_hold_to_the_space() {
    // A certificate whose identity lives in its alternative name has an
    // empty subject (RFC 5280 4.2.1.6), and an empty name sits under every
    // base. Holding it to the space would put every such certificate in
    // every region an authority named.
    let empty = seq(&[]);
    assert_eq!(
        admission(
            &[subtree(directory(organization("Example")))],
            &[],
            empty,
            &[dns("host.example.com")]
        ),
        Admission::Admitted
    );
}

#[test]
fn a_legacy_mailbox_that_is_not_one_lets_no_path_through() {
    // "The format of an rfc822Name is a Mailbox as defined in Section 4.1.2
    // of [RFC2821]" (RFC 5280 4.2.1.6), and the reader holds an alternative
    // name to that. The attribute a subject may carry the same identity in
    // arrives as a directory string and is held to nothing, so a value that
    // is not a mailbox reaches the regions as though it were one. Reading
    // the host out of `user@example.com@evil.net` by its last separator
    // puts it under whoever holds `evil.net`, and a value with no host at
    // all is in no region, which walks it past an excluded subtree where
    // nothing else would catch it.
    for value in [
        "user@example.com@evil.net",
        "notamailbox",
        "@example.com",
        "someone@",
    ] {
        let subject = seq(&[set(&[seq(&[oid_of(oid::EMAIL_ADDRESS), ia5(value)])])]);
        assert_eq!(
            admission(&[], &[subtree(mail("example.com"))], subject, &[]),
            Admission::Unenforceable,
            "excluded: {value}"
        );
        let subject = seq(&[set(&[seq(&[oid_of(oid::EMAIL_ADDRESS), ia5(value)])])]);
        assert_eq!(
            admission(&[subtree(mail("evil.net"))], &[], subject, &[]),
            Admission::Unenforceable,
            "permitted: {value}"
        );
    }
}
