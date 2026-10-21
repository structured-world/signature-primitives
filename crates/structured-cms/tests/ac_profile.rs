//! Original clearance, proxy sets and AA control restrictions at public boundaries.
use std::sync::Arc;
use structured_asn1::memory::{Memory, MemoryAccount};
use structured_asn1::{Encoding, Limits, Oid, Parser};
use structured_cms::ErrorCode;
use structured_cms::attribute::Attribute;
use structured_cms::attribute_certificate::AttributeCertificate;
use structured_cms::attribute_certificate::clearance::{self, Clearance, Syntax};
use structured_cms::attribute_certificate::controls::{self, AaControls};
use structured_cms::attribute_certificate::proxy::{self, Decision, ProxyInfo, Sender, Subject};
use structured_cms::attribute_certificate::target::{CheckError, Membership};
use structured_pkix::{Extensions, general_name::GeneralName};

fn memory(capacity: usize, work: usize) -> Memory {
    Memory::new(Arc::new(MemoryAccount::new(capacity, work)))
}
fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if bytes.len() < 128 {
        result.push(u8::try_from(bytes.len()).unwrap());
    } else if bytes.len() < 256 {
        result.extend([0x81, u8::try_from(bytes.len()).unwrap()]);
    } else {
        result.extend([
            0x82,
            u8::try_from(bytes.len() >> 8).unwrap(),
            u8::try_from(bytes.len() & 255).unwrap(),
        ]);
    }
    result.extend(bytes);
    result
}
fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
fn attribute(kind: Oid<'_>, values: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = values.to_vec();
    sorted.sort();
    seq(&[&tlv(6, kind.as_bytes()), &tlv(0x31, &sorted.concat())])
}
fn attr<'a>(p: &'a Parser, bytes: &'a [u8]) -> Attribute<'a> {
    let mut r = p.read(bytes, 700).unwrap();
    let e = r.next_element().unwrap().unwrap();
    Attribute::read(&r, &e, "attribute").unwrap()
}
fn ext(kind: Oid<'_>, body: &[u8], critical: bool) -> Vec<u8> {
    seq(&[&seq(&[
        &tlv(6, kind.as_bytes()),
        if critical { &[1, 1, 255] } else { &[] },
        &tlv(4, body),
    ])])
}
fn extensions<'a>(p: &'a Parser, bytes: &'a [u8]) -> Extensions<'a> {
    let mut r = p.read(bytes, 700).unwrap();
    let e = r.next_element().unwrap().unwrap();
    Extensions::read_element(&r, &e, "extensions").unwrap()
}
fn clear(legacy: bool, tail: &[u8]) -> Vec<u8> {
    seq(&[&tlv(if legacy { 0x80 } else { 6 }, &[42, 3]), tail])
}
fn category(kind: &[u8], value: &[u8]) -> Vec<u8> {
    seq(&[&tlv(0x80, kind), &tlv(0xa1, value)])
}
fn target(group: bool, name: &[u8]) -> Vec<u8> {
    tlv(if group { 0xa1 } else { 0xa0 }, &tlv(0x82, name))
}
fn group(names: &[&[u8]]) -> Vec<u8> {
    tlv(
        0x30,
        &names
            .iter()
            .flat_map(|n| target(false, n))
            .collect::<Vec<_>>(),
    )
}
fn proxy_read<'a>(p: &'a Parser, bytes: &'a [u8]) -> ProxyInfo<'a> {
    let e = extensions(p, bytes);
    ProxyInfo::read(
        e.get(proxy::IDENTIFIER, p.memory()).unwrap().unwrap(),
        p.memory(),
    )
    .unwrap()
}
fn no_group(
    _: Subject,
    _: &GeneralName<'_>,
    _: &structured_asn1::memory::Execution<'_>,
) -> Result<Membership, ()> {
    panic!("unexpected group lookup")
}

#[test]
fn clearance_default_and_every_policy_class_remain_original() {
    // The default is unclassified, while explicit empty and policy bits differ.
    for legacy in [false, true] {
        for bits in [
            None,
            Some(vec![0]),
            Some(vec![7, 128]),
            Some(vec![0, 1]),
            Some(vec![7, 0, 128]),
        ] {
            let tail = bits
                .as_ref()
                .map(|b| tlv(if legacy { 0x81 } else { 3 }, b))
                .unwrap_or_default();
            let bytes = clear(legacy, &tail);
            let p = Parser::der(memory(1 << 20, 1 << 24));
            let mut r = p.read(&bytes, 300).unwrap();
            let c = Clearance::read(&mut r).unwrap();
            assert_eq!(
                c.syntax,
                if legacy {
                    Syntax::Legacy
                } else {
                    Syntax::Current
                }
            );
            assert_eq!(c.policy.as_bytes(), [42, 3]);
            assert_eq!(
                c.classes_element.map(structured_asn1::Element::contents),
                bits.as_deref()
            );
            assert_eq!(c.has_class(1), bits.is_none());
            assert_eq!(c.element.as_bytes().as_ptr(), bytes.as_ptr());
            if bits == Some(vec![7, 0, 128]) {
                assert!(c.has_class(8));
            }
        }
    }
}
#[test]
fn clearance_both_oids_and_corrected_legacy_registration() {
    // Old registration accepts its corrected syntax; new OID never uses old tags.
    for kind in [clearance::IDENTIFIER, clearance::LEGACY_IDENTIFIER] {
        let bytes = attribute(kind, &[clear(false, &[]), clear(false, &[3, 2, 7, 128])]);
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let a = attr(&p, &bytes);
        assert_eq!(Clearance::read_attribute(&a, p.memory()).unwrap().len(), 2);
        let bytes = attribute(kind, &[clear(true, &[])]);
        let a = attr(&p, &bytes);
        let result = Clearance::read_attribute(&a, p.memory());
        if kind == clearance::IDENTIFIER {
            assert_eq!(result.unwrap_err().code(), ErrorCode::AttributeSyntax);
        } else {
            assert_eq!(result.unwrap()[0].syntax, Syntax::Legacy);
        }
    }
    for (kind, values, code) in [
        (
            clearance::IDENTIFIER,
            vec![],
            ErrorCode::AttributeCardinality,
        ),
        (
            Oid::from_bytes(&[42]),
            vec![clear(false, &[])],
            ErrorCode::UnexpectedContentType,
        ),
    ] {
        let bytes = attribute(kind, &values);
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let a = attr(&p, &bytes);
        assert_eq!(
            Clearance::read_attribute(&a, p.memory())
                .unwrap_err()
                .code(),
            code
        );
    }
}
#[test]
fn categories_preserve_wrappers_opaque_values_and_short_query_storage() {
    // Policy-defined open types remain original DER; metadata survives query drop.
    for legacy in [false, true] {
        let cats = [
            category(&[42], &[2, 1, 7]),
            category(&[43], &tlv(4, b"opaque")),
        ]
        .concat();
        let bytes = attribute(
            clearance::LEGACY_IDENTIFIER,
            &[clear(legacy, &tlv(if legacy { 0xa2 } else { 0x31 }, &cats))],
        );
        let source = memory(1 << 20, 1 << 24);
        let p = Parser::der(source.clone());
        let a = attr(&p, &bytes);
        let query = memory(1 << 20, 1 << 24);
        let result = Clearance::read_attribute(&a, &query).unwrap();
        assert!(query.used() > 0);
        drop(a);
        assert_eq!(result[0].categories.len(), 2);
        for category in &result[0].categories {
            let at = usize::try_from(category.value.span().start - 700).unwrap();
            assert_eq!(category.value.as_bytes().as_ptr(), bytes[at..].as_ptr());
            assert_eq!(category.wrapper.contents(), category.value.as_bytes());
        }
        drop(result);
        assert_eq!(query.used(), 0);
        assert_eq!(source.used(), 0);
    }
}
#[test]
fn clearance_der_defaults_bit_minimality_categories_order_and_schema_refuse() {
    // Named bits must omit trailing zeroes; default-written cannot disguise DER.
    let earlier = category(&[42], &[5, 0]);
    let later = category(&[43], &[5, 0]);
    let bad = [
        seq(&[]),
        clear(false, &[3, 2, 6, 64]),
        clear(false, &[3, 2, 0, 128]),
        clear(false, &[3, 2, 8, 0]),
        clear(false, &[3, 2, 7, 129]),
        clear(false, &[0x81, 2, 7, 128]),
        clear(true, &[3, 2, 7, 128]),
        clear(false, &tlv(0x31, &[later, earlier].concat())),
        clear(false, &tlv(0x31, &category(&[42], &[5, 0, 5, 0]))),
        clear(
            false,
            &tlv(0x31, &seq(&[&tlv(6, &[42]), &tlv(0xa1, &[5, 0])])),
        ),
        clear(false, &tlv(0x31, &category(&[42], &[1, 1, 1]))),
        clear(false, &[0x31, 0, 5, 0]),
        [clear(false, &[]), vec![5, 0]].concat(),
    ];
    for bytes in bad {
        let m = memory(1 << 20, 1 << 24);
        let p = Parser::ber(m.clone());
        let mut r = p.read(&bytes, 40).unwrap();
        assert!(Clearance::read(&mut r).is_err(), "{bytes:x?}");
        drop(r);
        assert_eq!(m.used(), 0);
    }
}
#[test]
fn late_invalid_clearance_value_releases_every_partial_catalogue() {
    // The valid first value allocates category storage before a later refusal.
    let valid = clear(false, &tlv(0x31, &category(&[42], &[5, 0])));
    let invalid = clear(false, &tlv(0x31, &category(&[43], &[5, 0, 5, 0])));
    assert!(valid < invalid);
    let bytes = attribute(clearance::IDENTIFIER, &[valid, invalid]);
    let p = Parser::ber(memory(1 << 20, 1 << 24));
    let a = attr(&p, &bytes);
    let q = memory(1 << 20, 1 << 24);
    assert!(Clearance::read_attribute(&a, &q).is_err());
    assert_eq!(q.used(), 0);
}
#[test]
fn aa_controls_defaults_presence_exclusion_and_arbitrary_path_bound() {
    // Defaults do not erase explicit-empty lists; exclusions override permission.
    let oid = Oid::from_bytes(&[42]);
    for value in [seq(&[]), seq(&[&tlv(0xa0, &[]), &tlv(0xa1, &[])])] {
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let mut r = p.read(&value, 50).unwrap();
        let c = AaControls::read(&mut r).unwrap();
        assert!(c.permit_unspecified);
        assert!(c.allows(oid, p.memory()).unwrap());
        assert!(c.permits_distance(u64::MAX, p.memory()).unwrap());
        assert_eq!(c.permitted_element.is_some(), value.len() > 2);
    }
    let bytes = seq(&[
        &[2, 1, 2],
        &tlv(0xa0, &[6, 1, 42, 6, 1, 43]),
        &tlv(0xa1, &[6, 1, 42]),
        &[1, 1, 0],
    ]);
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let mut r = p.read(&bytes, 50).unwrap();
    let c = AaControls::read(&mut r).unwrap();
    assert!(!c.allows(oid, p.memory()).unwrap());
    assert!(c.allows(Oid::from_bytes(&[43]), p.memory()).unwrap());
    assert!(!c.allows(Oid::from_bytes(&[44]), p.memory()).unwrap());
    assert!(c.permits_distance(2, p.memory()).unwrap());
    assert!(!c.permits_distance(3, p.memory()).unwrap());
    assert_eq!(c.path_length.unwrap().as_u64(), Some(2));
    let bytes = seq(&[&tlv(2, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0])]);
    let mut r = p.read(&bytes, 50).unwrap();
    let c = AaControls::read(&mut r).unwrap();
    assert!(c.permits_distance(u64::MAX, p.memory()).unwrap());
}
#[test]
fn aa_controls_der_complete_schema_and_boolean_default_refuse() {
    // No negatives, misplaced/repeated fields, explicit TRUE, malformed OIDs or tail.
    for bytes in [
        seq(&[&[2, 1, 255]]),
        seq(&[&[2, 2, 0, 1]]),
        seq(&[&[1, 1, 255]]),
        seq(&[&[1, 1, 1]]),
        seq(&[&tlv(0xa0, &[6, 1, 128])]),
        seq(&[&tlv(0xa0, &[5, 0])]),
        seq(&[&tlv(0xa1, &[]), &tlv(0xa0, &[])]),
        seq(&[&tlv(0xa0, &[]), &tlv(0xa0, &[])]),
        seq(&[&[1, 1, 0], &[5, 0]]),
        [seq(&[]), vec![5, 0]].concat(),
    ] {
        let m = memory(1 << 20, 1 << 24);
        let p = Parser::ber(m.clone());
        let mut r = p.read(&bytes, 50).unwrap();
        assert!(AaControls::read(&mut r).is_err(), "{bytes:x?}");
        drop(r);
        assert_eq!(m.used(), 0);
    }
}
#[test]
fn aa_original_extension_both_criticalities_and_paid_query_refusal() {
    // AAControls is a PKC extension; criticality is not unconditionally forbidden.
    for critical in [false, true] {
        let bytes = ext(
            controls::IDENTIFIER,
            &seq(&[&tlv(0xa0, &[6, 1, 42]), &[1, 1, 0]]),
            critical,
        );
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let e = extensions(&p, &bytes);
        let query = memory(1 << 20, 1 << 24);
        let c = AaControls::read_extension(
            e.get(controls::IDENTIFIER, p.memory()).unwrap().unwrap(),
            &query,
        )
        .unwrap();
        drop(e);
        assert!(query.used() > 0);
        assert!(c.allows(Oid::from_bytes(&[42]), &memory(0, 1000)).unwrap());
        assert!(
            c.allows(Oid::from_bytes(&[42]), &memory(0, 0))
                .unwrap_err()
                .is_resource()
        );
        assert!(
            c.permits_distance(0, &memory(0, 0))
                .unwrap_err()
                .is_resource()
        );
        drop(c);
        assert_eq!(query.used(), 0);
    }
}
#[test]
fn proxy_same_set_is_not_a_union_and_holder_still_needs_recipient() {
    // Splitting sender and recipient across sets must never authorize forwarding.
    let bytes = ext(
        proxy::IDENTIFIER,
        &seq(&[&group(&[b"sender.test"]), &group(&[b"recipient.test"])]),
        true,
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let info = proxy_read(&p, &bytes);
    let s = [GeneralName::Dns("sender.test")];
    let r = [GeneralName::Dns("RECIPIENT.TEST")];
    assert_eq!(
        info.check(Sender::Proxy(&s), &r, &[], p.memory(), no_group)
            .unwrap(),
        Decision::Differs
    );
    assert_eq!(
        info.check(Sender::Holder, &r, &[], p.memory(), no_group)
            .unwrap(),
        Decision::Matches { group: 1 }
    );
    assert_eq!(
        info.check(
            Sender::Holder,
            &[GeneralName::Dns("absent.test")],
            &[],
            p.memory(),
            no_group
        )
        .unwrap(),
        Decision::Differs
    );
}
#[test]
fn proxy_every_earlier_hop_must_match_the_same_set() {
    // A valid last sender cannot launder a preceding unauthorized proxy.
    let bytes = ext(
        proxy::IDENTIFIER,
        &seq(&[
            &group(&[b"sender.test", b"recipient.test"]),
            &group(&[b"sender.test", b"recipient.test", b"hop.test"]),
        ]),
        true,
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let info = proxy_read(&p, &bytes);
    let s = [GeneralName::Dns("sender.test")];
    let r = [GeneralName::Dns("recipient.test")];
    let hop = [GeneralName::Dns("hop.test")];
    assert_eq!(
        info.check(Sender::Proxy(&s), &r, &[&hop], p.memory(), no_group)
            .unwrap(),
        Decision::Matches { group: 1 }
    );
    assert_eq!(
        info.check(
            Sender::Holder,
            &r,
            &[&[GeneralName::Dns("bad.test")]],
            p.memory(),
            no_group
        )
        .unwrap(),
        Decision::Differs
    );
}
#[test]
fn proxy_group_unknown_negative_and_callback_cause_are_distinct() {
    // Callback roles preserve which established identity is being tested.
    let bytes = ext(
        proxy::IDENTIFIER,
        &seq(&[&seq(&[&target(true, b"group.test")])]),
        true,
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let info = proxy_read(&p, &bytes);
    let mut seen = Vec::new();
    let r = [GeneralName::Dns("r.test")];
    let s = [GeneralName::Dns("s.test")];
    assert_eq!(
        info.check(Sender::Proxy(&s), &r, &[&s], p.memory(), |role, _, _| {
            seen.push(role);
            Ok::<_, ()>(Membership::Member)
        })
        .unwrap(),
        Decision::Matches { group: 0 }
    );
    assert_eq!(
        seen,
        [
            Subject::Recipient,
            Subject::Sender,
            Subject::Intermediate(0)
        ]
    );
    assert_eq!(
        info.check(Sender::Holder, &r, &[], p.memory(), |_, _, _| Ok::<_, ()>(
            Membership::Unknown
        ))
        .unwrap(),
        Decision::Unproven
    );
    assert_eq!(
        info.check(Sender::Holder, &r, &[], p.memory(), |_, _, _| Ok::<_, ()>(
            Membership::NotMember
        ))
        .unwrap(),
        Decision::Differs
    );
    assert!(matches!(
        info.check(Sender::Holder, &r, &[], p.memory(), |_, _, _| Err("cause")),
        Err(CheckError::Callback {
            source: "cause",
            ..
        })
    ));
}
#[test]
fn proxy_criticality_certificate_preflight_empty_sets_and_processing() {
    // Even a late targetCert blocks success before any membership side effect.
    let cert = tlv(
        0xa2,
        &seq(&[&seq(&[&tlv(0x82, b"issuer.test")]), &[2, 1, 7]]),
    );
    for critical in [false, true] {
        let bytes = ext(
            proxy::IDENTIFIER,
            &seq(&[&group(&[b"recipient.test"]), &seq(&[&cert])]),
            critical,
        );
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let info = proxy_read(&p, &bytes);
        let decision = info
            .check(
                Sender::Holder,
                &[GeneralName::Dns("recipient.test")],
                &[],
                p.memory(),
                no_group,
            )
            .unwrap();
        assert_eq!(
            decision,
            if critical {
                Decision::ProhibitedTargetCertificate { target: 1 }
            } else {
                Decision::NonCritical
            }
        );
    }
    for payload in [seq(&[]), seq(&[&seq(&[])])] {
        let bytes = ext(proxy::IDENTIFIER, &payload, true);
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let info = proxy_read(&p, &bytes);
        assert_eq!(
            info.check(Sender::Holder, &[], &[], p.memory(), no_group)
                .unwrap(),
            Decision::Differs
        );
        assert!(
            matches!(info.check(Sender::Holder,&[],&[],&memory(0,0),no_group),Err(CheckError::Processing(e)) if e.is_resource())
        );
    }
}
#[test]
fn source_current_and_capacity_bounds_refuse_without_partial_storage() {
    // All three decoders inherit their source and current execution, including growth.
    let clearance = attribute(
        clearance::IDENTIFIER,
        &[clear(false, &tlv(0x31, &category(&[42], &[5, 0])))],
    );
    let controls = ext(
        controls::IDENTIFIER,
        &seq(&[&tlv(0xa0, &[6, 1, 42])]),
        false,
    );
    let proxy = ext(
        proxy::IDENTIFIER,
        &seq(&[&group(&[b"recipient.test"])]),
        true,
    );
    for q in [memory(0, 1 << 24), memory(1 << 20, 0)] {
        let p = Parser::der(memory(1 << 20, 1 << 24));
        let a = attr(&p, &clearance);
        assert!(Clearance::read_attribute(&a, &q).unwrap_err().is_resource());
        assert_eq!(q.used(), 0);
        let e = extensions(&p, &controls);
        assert!(
            AaControls::read_extension(
                e.get(controls::IDENTIFIER, p.memory()).unwrap().unwrap(),
                &q
            )
            .unwrap_err()
            .is_resource()
        );
        assert_eq!(q.used(), 0);
        let e = extensions(&p, &proxy);
        assert!(
            ProxyInfo::read(e.get(proxy::IDENTIFIER, p.memory()).unwrap().unwrap(), &q)
                .unwrap_err()
                .is_resource()
        );
        assert_eq!(q.used(), 0);
    }
    let p = Parser::new(
        Encoding::Ber,
        Limits {
            max_work: 1000,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let a = attr(&p, &clearance);
    let source = p.memory();
    source.charge_work(1).unwrap();
    // Repeated queries cannot reset the producing local ceiling through fresh accounts.
    let mut refused = false;
    for _ in 0..100 {
        let q = memory(1 << 20, 1 << 24);
        match Clearance::read_attribute(&a, &q) {
            Ok(v) => drop(v),
            Err(e) => {
                assert!(e.is_resource());
                refused = true;
                break;
            }
        }
        assert_eq!(q.used(), 0);
    }
    assert!(refused);
}
#[test]
fn all_mechanisms_keep_depth_and_der_under_ber() {
    // Schema contexts do not become fresh default-depth parsers during lazy reads.
    for bytes in [
        clear(
            false,
            &tlv(0x31, &category(&[42], &seq(&[&seq(&[&[5, 0]])]))),
        ),
        seq(&[&tlv(0xa0, &[6, 1, 42])]),
    ] {
        let p = Parser::new(
            Encoding::Ber,
            Limits {
                max_depth: 1,
                ..Limits::default()
            },
            memory(1 << 20, 1 << 24),
        );
        let mut r = p.read(&bytes, 500).unwrap();
        if bytes[2] == 6 {
            assert!(Clearance::read(&mut r).unwrap_err().is_resource());
        } else {
            assert!(AaControls::read(&mut r).unwrap_err().is_resource());
        }
    }
    let bytes = clear(false, &[]);
    let long = [
        vec![0x30, 0x81, u8::try_from(bytes.len() - 2).unwrap()],
        bytes[2..].to_vec(),
    ]
    .concat();
    let p = Parser::ber(memory(1 << 20, 1 << 24));
    let mut r = p.read(&long, 50).unwrap();
    assert!(Clearance::read(&mut r).is_err());
}
#[test]
fn actual_ac_clearance_proxy_wiring_preserves_signature_input() {
    // Whole AC -> original Attribute/Extension -> shared readers, without re-encoding.
    let attrs = attribute(clearance::IDENTIFIER, &[clear(false, &[])]);
    let proxy = ext(
        proxy::IDENTIFIER,
        &seq(&[&group(&[b"recipient.test"])]),
        true,
    );
    let algorithm = seq(&[&[6, 1, 42]]);
    let signed = seq(&[
        &[2, 1, 1],
        &seq(&[]),
        &seq(&[&tlv(0x82, b"issuer.test")]),
        &algorithm,
        &[2, 1, 9],
        &seq(&[&tlv(24, b"20261021000000Z"), &tlv(24, b"20271021000000Z")]),
        &seq(&[&attrs]),
        &proxy,
    ]);
    let bytes = seq(&[&signed, &algorithm, &[3, 2, 0, 9]]);
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let mut r = p.read(&bytes, 500).unwrap();
    let ac = AttributeCertificate::read(&mut r).unwrap();
    assert!(
        Clearance::read_attribute(&ac.information().attributes[0], &r.execution()).unwrap()[0]
            .has_class(1)
    );
    let e = ac
        .information()
        .extensions
        .as_ref()
        .unwrap()
        .get(proxy::IDENTIFIER, &r.execution())
        .unwrap()
        .unwrap();
    let info = ProxyInfo::read(e, &r.execution()).unwrap();
    assert_eq!(
        info.check(
            Sender::Holder,
            &[GeneralName::Dns("recipient.test")],
            &[],
            &r.execution(),
            no_group
        )
        .unwrap(),
        Decision::Matches { group: 0 }
    );
    assert_eq!(ac.signed_bytes(), signed);
    let at = usize::try_from(ac.signed_element().span().start - 500).unwrap();
    assert_eq!(ac.signed_bytes().as_ptr(), bytes[at..].as_ptr());
}

#[test]
fn proxy_der_is_not_relaxed_by_a_ber_extension_carrier() {
    // ProxyInfo is an AC field: a BER carrier cannot legalize nonminimal DER.
    let payload = [0x30, 0x81, 0];
    let bytes = ext(proxy::IDENTIFIER, &payload, true);
    let p = Parser::ber(memory(1 << 20, 1 << 24));
    let entries = extensions(&p, &bytes);
    let extension = entries.get(proxy::IDENTIFIER, p.memory()).unwrap().unwrap();
    assert!(ProxyInfo::read(extension, p.memory()).is_err());
}

#[test]
fn all_readers_and_predicates_obey_a_short_foreign_operation_ceiling() {
    // Lazy work retains the source parser but cannot bypass a narrower current query.
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let bytes = attribute(clearance::IDENTIFIER, &[clear(false, &[])]);
    let a = attr(&p, &bytes);
    let cbytes = ext(
        controls::IDENTIFIER,
        &seq(&[&tlv(0xa0, &[6, 1, 42])]),
        false,
    );
    let entries = extensions(&p, &cbytes);
    let extension = entries
        .get(controls::IDENTIFIER, p.memory())
        .unwrap()
        .unwrap();
    let control = AaControls::read_extension(extension, p.memory()).unwrap();
    let pbytes = ext(
        proxy::IDENTIFIER,
        &seq(&[&group(&[b"recipient.test"])]),
        true,
    );
    let pent = extensions(&p, &pbytes);
    let pe = pent.get(proxy::IDENTIFIER, p.memory()).unwrap().unwrap();
    let proxy = ProxyInfo::read(pe, p.memory()).unwrap();
    for operation in 0..5 {
        let q = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 1,
                ..Limits::default()
            },
            memory(1 << 20, 1 << 24),
        );
        let query = q.read(&[], 0).unwrap();
        let work = query.execution();
        let error = match operation {
            0 => Clearance::read_attribute(&a, &work).unwrap_err(),
            1 => AaControls::read_extension(extension, &work).unwrap_err(),
            2 => ProxyInfo::read(pe, &work).unwrap_err(),
            3 => control.allows(Oid::from_bytes(&[42]), &work).unwrap_err(),
            _ => match proxy
                .check(
                    Sender::Holder,
                    &[GeneralName::Dns("recipient.test")],
                    &[],
                    &work,
                    no_group,
                )
                .unwrap_err()
            {
                CheckError::Processing(e) => e,
                CheckError::Callback { .. } => panic!("unexpected callback"),
            },
        };
        assert!(error.is_resource());
        assert!(error.offset() >= 700);
        assert_eq!(q.memory().used(), 0);
    }
}

#[test]
fn proxy_invalid_late_group_and_depth_release_owned_catalogues() {
    // No partially decoded proxy sets survive a later grammar or depth refusal.
    let bytes = ext(
        proxy::IDENTIFIER,
        &seq(&[&group(&[b"recipient.test"]), &seq(&[&[0xa0, 0]])]),
        true,
    );
    let p = Parser::ber(memory(1 << 20, 1 << 24));
    let e = extensions(&p, &bytes);
    let q = memory(1 << 20, 1 << 24);
    assert!(ProxyInfo::read(e.get(proxy::IDENTIFIER, p.memory()).unwrap().unwrap(), &q).is_err());
    assert_eq!(q.used(), 0);
    let bytes = ext(
        proxy::IDENTIFIER,
        &seq(&[&group(&[b"recipient.test"])]),
        true,
    );
    let p = Parser::new(
        Encoding::Ber,
        Limits {
            max_depth: 3,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let e = extensions(&p, &bytes);
    assert!(
        ProxyInfo::read(e.get(proxy::IDENTIFIER, p.memory()).unwrap().unwrap(), &q)
            .unwrap_err()
            .is_resource()
    );
    assert_eq!(q.used(), 0);
}

#[test]
fn unknown_proxy_set_followed_by_excluded_participant_is_negative() {
    // Unknown only survives if every other required participant might still match.
    let bytes = ext(
        proxy::IDENTIFIER,
        &seq(&[&seq(&[&target(true, b"group.test")])]),
        true,
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let info = proxy_read(&p, &bytes);
    assert_eq!(
        info.check(
            Sender::Proxy(&[]),
            &[],
            &[],
            p.memory(),
            |subject, _, _| Ok::<_, ()>(if subject == Subject::Recipient {
                Membership::Unknown
            } else {
                Membership::NotMember
            })
        )
        .unwrap(),
        Decision::Differs
    );
}

#[test]
fn proxy_original_catalogues_outlive_the_short_operation() {
    // Both levels of metadata retain capacity; queried identities remain borrowed.
    let bytes = ext(
        proxy::IDENTIFIER,
        &seq(&[&group(&[b"recipient.test"])]),
        true,
    );
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let e = extensions(&p, &bytes);
    let q = memory(1 << 20, 1 << 24);
    let info = ProxyInfo::read(e.get(proxy::IDENTIFIER, p.memory()).unwrap().unwrap(), &q).unwrap();
    drop(e);
    assert!(q.used() > 0);
    assert_eq!(info.groups().len(), 1);
    assert_eq!(info.targets().len(), 1);
    assert!(info.certificates().is_empty());
    assert!(info.is_critical());
    let at = usize::try_from(info.element().span().start - 700).unwrap();
    assert_eq!(info.element().as_bytes().as_ptr(), bytes[at..].as_ptr());
    drop(info);
    assert_eq!(q.used(), 0);
    assert_eq!(p.memory().used(), 0);
}

#[test]
fn retained_category_opens_its_original_value_at_actual_source_depth() {
    // Policy-specific decoding must not force an adapter to reconstruct a Parser.
    let bytes = clear(false, &tlv(0x31, &category(&[42], &seq(&[&[2, 1, 7]]))));
    let p = Parser::der(memory(1 << 20, 1 << 24));
    let mut reader = p.read(&bytes, 400).unwrap();
    let clearance = Clearance::read(&mut reader).unwrap();
    drop(reader);
    let category = clearance.categories[0];
    drop(clearance);
    assert_eq!(p.memory().used(), 0);
    // Entering a constructed policy value needs paid path metadata, although
    // neither the value reader nor that metadata copies the document bytes.
    let q = memory(2048, 1000);
    let mut nested = category.value_reader(&q).unwrap();
    assert_eq!(nested.depth(), 4);
    let value = nested.next_element().unwrap().unwrap();
    assert_eq!(
        value.as_bytes().as_ptr(),
        category.value.as_bytes().as_ptr()
    );
    assert_eq!(value.span(), category.value.span());
    let mut fields = nested.enter(&value).unwrap();
    assert_eq!(fields.read_integer().unwrap().as_u64(), Some(7));
    assert!(q.used() > 0);
    drop(fields);
    drop(nested);
    let zero = memory(0, 1000);
    let mut nested = category.value_reader(&zero).unwrap();
    let value = nested.next_element().unwrap().unwrap();
    assert!(nested.enter(&value).unwrap_err().is_resource());
    assert_eq!(zero.used(), 0);
    let limited = Parser::new(
        Encoding::Der,
        Limits {
            max_depth: 3,
            ..Limits::default()
        },
        memory(1 << 20, 1 << 24),
    );
    let query = limited.read(&[], 0).unwrap();
    assert!(
        category
            .value_reader(&query.execution())
            .unwrap_err()
            .is_resource()
    );
    // Opening a borrowed cursor does not scan input. The first actual read
    // must refuse before touching a value when current work is exhausted.
    let spent = memory(0, 0);
    let mut nested = category.value_reader(&spent).unwrap();
    assert!(nested.next_element().unwrap_err().is_resource());
    assert_eq!(q.used(), 0);
}
