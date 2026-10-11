use super::{Initial, Overflow, Processing};
use crate::constraints::InhibitAnyPolicy;
use crate::fixtures::{CertificateParts, extension, int, oid as oid_of, seq};
use crate::policy::PolicyMappings;
use crate::{Certificate, oid};
use alloc::vec::Vec;
use structured_asn1::{Oid, Parser};

/// Two policies of this test, which are identifiers no profile gives a
/// meaning to: what matters here is that they are told apart.
const GOLD: Oid<'static> = Oid::from_bytes(&[0x2a, 0x03, 0x04, 0x01]);
const SILVER: Oid<'static> = Oid::from_bytes(&[0x2a, 0x03, 0x04, 0x02]);
const BRONZE: Oid<'static> = Oid::from_bytes(&[0x2a, 0x03, 0x04, 0x03]);

#[test]
fn an_unrepresentable_policy_counter_is_refused_before_allocation() {
    // RFC 5280's initial counters sit one certificate beyond the path.
    // Saturating at the path length would give a different processing model.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(0, 1_000_000)));
    let error = Processing::new(u32::MAX, open(), 16, &execution, 719).unwrap_err();
    let Overflow::Resource(error) = error else {
        panic!("representation refusal is a resource error")
    };
    assert_eq!(
        error.code(),
        crate::ErrorCode::Encoding(structured_asn1::ErrorCode::CapacityOverflow)
    );
    assert_eq!(error.offset(), 719);
    assert_eq!(execution.used(), 0);
    assert_eq!(execution.work_used(), 0);
}

#[test]
fn policy_tree_and_indexes_share_retained_capacity_accounting() {
    // The root retains its capacity. A budget containing exactly that root
    // refuses the first index allocation without growing the tree or losing
    // the original processing offset; dropping the tree releases the root.
    use structured_asn1::memory::{Memory, MemoryAccount};
    let parser = Parser::der(crate::fixtures::memory());
    let step = naming(&[GOLD]);
    let certificate = Certificate::read(&parser, &step.der, 0).unwrap();
    let named = certificate
        .tbs()
        .extensions()
        .certificate_policies(certificate.tbs().extensions().memory())
        .unwrap()
        .unwrap();
    let size = core::mem::size_of::<super::Node<'_>>();
    let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(size, 1_000_000)));
    let mut tree = Processing::new(1, open(), 16, &execution, 717).unwrap();
    assert_eq!(execution.used(), size);
    let error = tree
        .present(Some(&named), false, true, &mut ())
        .unwrap_err();
    let Overflow::Resource(error) = error else {
        panic!("aggregate storage is a resource error")
    };
    assert_eq!(
        error.code(),
        crate::ErrorCode::Encoding(structured_asn1::ErrorCode::LimitExceeded(
            structured_asn1::Limit::Memory
        ))
    );
    assert_eq!(error.offset(), 717);
    assert_eq!(tree.nodes(), 1);
    assert_eq!(execution.used(), size);
    drop(tree);
    assert_eq!(execution.used(), 0);
}

#[test]
fn mapped_expectations_retain_charge_after_temporary_indexes_drop() {
    // Mapping scratch indexes are released on return, but each node's
    // independent expectation copy keeps its capacity charged with the tree.
    let parser = Parser::der(crate::fixtures::memory());
    let step = Says::new(Some(&[GOLD]), Some(&[(GOLD, SILVER)]), None, None);
    let certificate = Certificate::read(&parser, &step.der, 0).unwrap();
    let extensions = certificate.tbs().extensions();
    let named = extensions
        .certificate_policies(extensions.memory())
        .unwrap()
        .unwrap();
    let mappings = extensions
        .policy_mappings(extensions.memory())
        .unwrap()
        .unwrap();
    let execution = crate::fixtures::memory();
    let mut tree = Processing::new(2, open(), 16, &execution, 720).unwrap();
    assert!(tree.present(Some(&named), false, false, &mut ()).unwrap());
    tree.carry(Some(&mappings), None, None, false, &mut ())
        .unwrap();
    let nodes = tree.nodes.as_ref().unwrap();
    assert_eq!(&*nodes[1].expected, &[SILVER]);
    let retained = nodes.capacity() * core::mem::size_of::<super::Node<'_>>()
        + nodes
            .iter()
            .map(|node| node.expected.capacity() * core::mem::size_of::<Oid<'_>>())
            .sum::<usize>();
    assert_eq!(execution.used(), retained);
    drop(tree);
    assert_eq!(execution.used(), 0);
}

#[test]
fn settled_policies_retain_their_allocation_after_tree_release() {
    // Consuming the working tree frees its scratch allocations, while the
    // independently owned policy set remains charged until its own drop.
    let parser = Parser::der(crate::fixtures::memory());
    let step = naming(&[GOLD]);
    let certificate = Certificate::read(&parser, &step.der, 0).unwrap();
    let named = certificate
        .tbs()
        .extensions()
        .certificate_policies(certificate.tbs().extensions().memory())
        .unwrap()
        .unwrap();
    let execution = crate::fixtures::memory();
    let mut tree = Processing::new(1, open(), 16, &execution, 718).unwrap();
    assert!(tree.present(Some(&named), false, true, &mut ()).unwrap());
    let settled = tree.settle(None, &[], &mut ()).unwrap();
    assert_eq!(settled.policies(), &[GOLD]);
    assert!(settled.is_satisfied());
    assert!(execution.used() > 0);
    let charge = execution.used();
    let work = execution.work_used();
    let result = settled.into_policies();
    assert_eq!(&*result, &[GOLD]);
    assert_eq!(execution.used(), charge);
    assert_eq!(execution.work_used(), work);
    drop(result);
    assert_eq!(execution.used(), 0);
}

/// The certificate policies extension value naming these policies.
fn policies(named: &[Oid<'static>]) -> Vec<u8> {
    seq(&named
        .iter()
        .map(|policy| seq(&[oid_of(*policy)]))
        .collect::<Vec<_>>())
}

/// The policy mappings extension value: pairs of what the issuer calls a
/// policy and what it is called below.
fn mappings(pairs: &[(Oid<'static>, Oid<'static>)]) -> Vec<u8> {
    seq(&pairs
        .iter()
        .map(|(issuer, subject)| seq(&[oid_of(*issuer), oid_of(*subject)]))
        .collect::<Vec<_>>())
}

/// The policy constraints extension value.
fn constraints(explicit: Option<u32>, mapping: Option<u32>) -> Vec<u8> {
    let mut parts = Vec::new();
    if let Some(explicit) = explicit {
        parts.push(tagged(0, explicit));
    }
    if let Some(mapping) = mapping {
        parts.push(tagged(1, mapping));
    }
    seq(&parts)
}

/// An integer written under a context tag whose position replaced its own.
fn tagged(number: u8, value: u32) -> Vec<u8> {
    let encoded = int(value);
    let mut out = alloc::vec![0x80 | number];
    out.extend_from_slice(&encoded[1..]);
    out
}

/// Everything one certificate of a test path says about policies, read
/// through the crate's own accessors so the values are the ones a real
/// certificate would produce.
struct Says {
    der: Vec<u8>,
}

impl Says {
    /// A certificate carrying the named extension values.
    fn new(
        named: Option<&[Oid<'static>]>,
        maps: Option<&[(Oid<'static>, Oid<'static>)]>,
        limits: Option<(Option<u32>, Option<u32>)>,
        inhibit: Option<u32>,
    ) -> Self {
        let mut extensions = Vec::new();
        if let Some(named) = named {
            extensions.push(extension(
                oid::CERTIFICATE_POLICIES,
                false,
                &policies(named),
            ));
        }
        if let Some(maps) = maps {
            extensions.push(extension(oid::POLICY_MAPPINGS, true, &mappings(maps)));
        }
        if let Some((explicit, mapping)) = limits {
            extensions.push(extension(
                oid::POLICY_CONSTRAINTS,
                true,
                &constraints(explicit, mapping),
            ));
        }
        if let Some(skip) = inhibit {
            extensions.push(extension(oid::INHIBIT_ANY_POLICY, true, &int(skip)));
        }
        Self {
            der: CertificateParts {
                extensions: (!extensions.is_empty()).then(|| seq(&extensions)),
                ..CertificateParts::default()
            }
            .build(),
        }
    }
}

/// A certificate naming these policies and nothing else.
fn naming(named: &[Oid<'static>]) -> Says {
    Says::new(Some(named), None, None, None)
}

/// Runs a path of certificates through the working out, and answers with the
/// policies it settled on, or `None` where the path failed policy processing.
///
/// The certificates are given in the order they are processed, which is the
/// order the path is read in: the one the anchor issued first, and the one
/// the question is about last.
fn walk(
    steps: &[Says],
    initial: Initial,
    wanted: &'static [Oid<'static>],
) -> Option<Vec<Oid<'static>>> {
    let parser = Parser::der(crate::fixtures::memory());
    let read: Vec<Certificate<'_>> = steps
        .iter()
        .map(|step| {
            Certificate::read(&parser, &step.der, 0).expect("a certificate this test wrote")
        })
        .collect();

    let length = u32::try_from(read.len()).unwrap();
    let mut processing = Processing::new(length, initial, 1_024, &crate::fixtures::memory(), 0)
        .expect("room this test allows");
    let mut last = None;
    for (position, certificate) in read.iter().enumerate() {
        let extensions = certificate.tbs().extensions();
        let named = extensions
            .certificate_policies(extensions.memory())
            .expect("a value this test wrote");
        let final_step = position + 1 == read.len();
        if !processing
            .present(named.as_ref(), false, final_step, &mut ())
            .expect("a tree this test keeps small")
        {
            return None;
        }
        let limits = extensions
            .policy_constraints(extensions.memory())
            .expect("a value this test wrote");
        if final_step {
            last = limits;
            break;
        }
        let maps: Option<PolicyMappings<'_>> = extensions
            .policy_mappings(extensions.memory())
            .expect("a value this test wrote");
        let inhibit: Option<InhibitAnyPolicy> = extensions
            .inhibit_any_policy(extensions.memory())
            .expect("a value this test wrote");
        processing
            .carry(maps.as_ref(), limits, inhibit, false, &mut ())
            .expect("a tree this test keeps small");
    }

    let settled = processing
        .settle(last, wanted, &mut ())
        .expect("a tree this test keeps small");
    settled.is_satisfied().then(|| {
        settled
            .policies()
            .iter()
            .map(|policy| Oid::from_bytes(leak(policy.as_bytes())))
            .collect()
    })
}

/// The identifiers a settled path names are the ones the test wrote, which
/// are constants: matching the bytes back to one of them is what lets an
/// assertion outlive the certificates it was read from.
fn leak(bytes: &[u8]) -> &'static [u8] {
    for policy in [GOLD, SILVER, BRONZE, oid::ANY_POLICY] {
        if policy.as_bytes() == bytes {
            return policy.as_bytes();
        }
    }
    panic!("a policy this test did not write");
}

/// What a validator with no policy of its own starts from.
fn open() -> Initial {
    Initial::default()
}

#[test]
fn a_policy_every_authority_named_is_what_the_path_was_issued_under() {
    let settled = walk(&[naming(&[GOLD]), naming(&[GOLD])], open(), &[])
        .expect("a path that names a policy throughout");
    assert_eq!(settled, alloc::vec![GOLD]);
}

#[test]
fn a_policy_only_one_authority_named_is_not_one_they_agreed_on() {
    // The lower certificate names a policy the one above it never did, so
    // there is no policy every authority along the path named.
    let settled = walk(&[naming(&[SILVER]), naming(&[GOLD])], open(), &[])
        .expect("a path nobody demanded a policy of");
    assert_eq!(settled, []);
}

#[test]
fn a_certificate_that_names_no_policy_ends_the_agreement() {
    // Nothing is agreed below a certificate that says nothing, and the path
    // stands only because nobody demanded that it name a policy
    // (RFC 5280 6.1.3 (e) and (f)).
    let settled = walk(
        &[Says::new(None, None, None, None), naming(&[GOLD])],
        open(),
        &[],
    )
    .expect("a path nobody demanded a policy of");
    assert_eq!(settled, []);
}

#[test]
fn a_path_that_must_name_a_policy_and_names_none_is_not_a_path() {
    // The same path, asked for by a caller that demands a policy of it, is
    // no path at all rather than a path with an empty answer.
    let initial = Initial {
        explicit_policy: true,
        ..open()
    };
    assert!(
        walk(
            &[Says::new(None, None, None, None), naming(&[GOLD])],
            initial,
            &[],
        )
        .is_none()
    );
}

#[test]
fn an_authority_can_demand_that_the_path_below_it_names_a_policy() {
    // The demand is written into a certificate rather than into the caller's
    // question, and binds after as many certificates as it says
    // (RFC 5280 6.1.4 (i)).
    let demanding = Says::new(Some(&[GOLD]), None, Some((Some(0), None)), None);
    assert!(walk(&[demanding, Says::new(None, None, None, None)], open(), &[]).is_none());
}

#[test]
fn a_demand_that_binds_later_than_the_path_is_long_never_binds() {
    // A certificate that demands a policy of the fifth certificate below it
    // says nothing about a path that ends before the fifth.
    let demanding = Says::new(Some(&[GOLD]), None, Some((Some(5), None)), None);
    let settled = walk(&[demanding, Says::new(None, None, None, None)], open(), &[])
        .expect("a demand nothing in this path reached");
    assert_eq!(settled, []);
}

#[test]
fn the_identifier_standing_for_any_policy_carries_what_was_expected() {
    // An authority that names the identifier standing for any policy agrees
    // with whatever the certificate above it named, which is what lets a
    // root that names nothing in particular sit above a policy path
    // (RFC 5280 6.1.3 (d) (2)).
    let settled = walk(&[naming(&[GOLD]), naming(&[oid::ANY_POLICY])], open(), &[])
        .expect("a path whose lower authority accepts any policy");
    assert_eq!(settled, alloc::vec![GOLD]);
}

#[test]
fn a_caller_that_does_not_accept_any_policy_is_answered_without_it() {
    // Where the caller says the identifier standing for any policy is not
    // to be read as agreement, the path below one carries nothing.
    let initial = Initial {
        any_policy: false,
        ..open()
    };
    let settled = walk(&[naming(&[GOLD]), naming(&[oid::ANY_POLICY])], initial, &[])
        .expect("a path nobody demanded a policy of");
    assert_eq!(settled, []);
}

#[test]
fn a_policy_one_authority_maps_to_another_carries_under_the_new_name() {
    // The upper authority calls it gold, the lower one silver, and the
    // mapping says they are the same thing (RFC 5280 6.1.4 (b)).
    let mapping = Says::new(Some(&[GOLD]), Some(&[(GOLD, SILVER)]), None, None);
    let settled = walk(&[naming(&[GOLD]), mapping, naming(&[SILVER])], open(), &[])
        .expect("a path whose middle authority mapped the policy");
    assert_eq!(settled, alloc::vec![SILVER]);
}

#[test]
fn a_mapping_that_is_no_longer_honoured_ends_the_policy_it_would_have_carried() {
    // An authority above can say that mappings below it are not honoured,
    // and then the policy it named stops being agreed on at the mapping
    // (RFC 5280 6.1.4 (b) (2)).
    let forbidding = Says::new(Some(&[GOLD]), None, Some((None, Some(0))), None);
    let mapping = Says::new(Some(&[GOLD]), Some(&[(GOLD, SILVER)]), None, None);
    let settled = walk(&[forbidding, mapping, naming(&[SILVER])], open(), &[])
        .expect("a path nobody demanded a policy of");
    assert_eq!(settled, []);
}

#[test]
fn a_caller_asking_about_one_policy_is_answered_about_that_one() {
    // Two policies were agreed on, and the caller asked about one of them.
    const ASKED: &[Oid<'static>] = &[GOLD];
    let settled = walk(
        &[naming(&[GOLD, SILVER]), naming(&[GOLD, SILVER])],
        open(),
        ASKED,
    )
    .expect("a path that names the policy asked about");
    assert_eq!(settled, alloc::vec![GOLD]);
}

#[test]
fn a_caller_asking_about_a_policy_the_path_never_names_gets_nothing() {
    const ASKED: &[Oid<'static>] = &[BRONZE];
    let settled = walk(&[naming(&[GOLD]), naming(&[GOLD])], open(), ASKED)
        .expect("a path nobody demanded a policy of");
    assert_eq!(settled, []);
}

#[test]
fn a_caller_asking_about_a_policy_a_path_carried_under_any_gets_it() {
    // Every authority accepted any policy, so the one the caller asked
    // about is among what they agreed on, and is answered under the
    // caller's own name for it (RFC 5280 6.1.5 (g) (iii)).
    const ASKED: &[Oid<'static>] = &[GOLD];
    let settled = walk(
        &[naming(&[oid::ANY_POLICY]), naming(&[oid::ANY_POLICY])],
        open(),
        ASKED,
    )
    .expect("a path that accepts any policy");
    assert_eq!(settled, alloc::vec![GOLD]);
}

#[test]
fn pruning_a_policy_tree_requires_admitted_work() {
    // Growing one named branch consumes four existing dispatch admissions.
    // Sweeping the resulting tree must ask again before reading its nodes.
    struct Admissions(usize);
    impl crate::path::Meter for Admissions {
        fn spend(&mut self, _work: u64) -> crate::Result<bool> {
            if self.0 == 0 {
                return Ok(false);
            }
            self.0 -= 1;
            Ok(true)
        }
    }
    let parser = Parser::der(crate::fixtures::memory());
    let step = naming(&[GOLD]);
    let certificate = Certificate::read(&parser, &step.der, 0).unwrap();
    let named = certificate
        .tbs()
        .extensions()
        .certificate_policies(certificate.tbs().extensions().memory())
        .unwrap()
        .unwrap();
    let mut processing = Processing::new(1, open(), 16, &crate::fixtures::memory(), 0).unwrap();
    assert_eq!(
        processing.present(Some(&named), false, true, &mut Admissions(4)),
        Err(Overflow::Limit)
    );
}

#[test]
fn a_tree_that_grows_past_what_it_may_hold_says_so_rather_than_growing() {
    // A certificate set somebody else controls decides how many policies
    // each certificate names, and the tree is as wide as their product. A
    // ceiling of one node has room for the root and nothing else.
    let parser = Parser::der(crate::fixtures::memory());
    let step = naming(&[GOLD, SILVER]);
    let certificate = Certificate::read(&parser, &step.der, 0).unwrap();
    let named = certificate
        .tbs()
        .extensions()
        .certificate_policies(certificate.tbs().extensions().memory())
        .unwrap()
        .unwrap();

    let mut processing =
        Processing::new(1, open(), 1, &crate::fixtures::memory(), 0).expect("room for the root");
    assert_eq!(
        processing.present(Some(&named), false, true, &mut ()),
        Err(Overflow::Limit)
    );
}

#[test]
fn the_same_certificates_settle_the_same_way_twice() {
    // Nothing in the working out depends on anything but the certificates
    // and the caller's question, which is what lets a report made today be
    // made again tomorrow.
    let path = || alloc::vec![naming(&[GOLD, SILVER]), naming(&[GOLD, SILVER])];
    assert_eq!(walk(&path(), open(), &[]), walk(&path(), open(), &[]));
}

/// A path of one certificate, which is what a certificate the anchor issued
/// directly is.
#[test]
fn a_path_of_one_certificate_names_what_that_certificate_names() {
    let settled = walk(&[naming(&[GOLD])], open(), &[])
        .expect("a path of one certificate that names a policy");
    assert_eq!(settled, alloc::vec![GOLD]);
}

#[test]
fn a_caller_asking_about_a_mapped_policy_is_answered_through_the_mapping() {
    // The caller asks about gold. An authority along the path says that
    // below it gold is called silver, and the target names silver. The
    // branch is the caller's policy carried under another name, and the
    // narrowing keeps branches by what they came from rather than by the
    // identifier at the end of them (RFC 5280 6.1.5 (g) (iii) 1): comparing
    // only the last identifier kills the branch and answers a caller who
    // enabled mappings that its own policy was never met.
    const ASKED: &[Oid<'static>] = &[GOLD];
    let mapping = Says::new(Some(&[GOLD]), Some(&[(GOLD, SILVER)]), None, None);
    let settled = walk(
        &[naming(&[GOLD]), mapping, naming(&[SILVER])],
        open(),
        ASKED,
    )
    .expect("a path carrying the asked policy under the name it was mapped to");
    assert_eq!(settled, alloc::vec![SILVER]);
}

#[test]
fn a_tree_too_small_to_name_the_asked_policies_says_so() {
    // The narrowing puts the caller's policies back under the node that
    // carried them as any policy, and that needs room. Discarding the
    // refusal leaves the path answered as though it named nothing, which is
    // a definite wrong answer where the truth is that a bound was reached.
    const ASKED: &[Oid<'static>] = &[GOLD];

    let parser = Parser::der(crate::fixtures::memory());
    let step = naming(&[oid::ANY_POLICY]);
    let certificate = Certificate::read(&parser, &step.der, 0).unwrap();
    let named = certificate
        .tbs()
        .extensions()
        .certificate_policies(certificate.tbs().extensions().memory())
        .unwrap()
        .unwrap();

    // The root and the one node the certificate adds fill the tree.
    let mut processing = Processing::new(1, open(), 2, &crate::fixtures::memory(), 0)
        .expect("room this test allows");
    assert_eq!(
        processing.present(Some(&named), false, true, &mut ()),
        Ok(true)
    );

    assert!(matches!(
        processing.settle(None, ASKED, &mut ()),
        Err(Overflow::Limit)
    ));
}

#[test]
fn the_last_certificate_spends_the_demand_even_where_it_is_self_issued() {
    // The wrap-up decrements the counter without asking who the last
    // certificate was issued to: "If explicit_policy is not 0, decrement
    // explicit_policy by 1" (RFC 5280 6.1.5 (a)). The exemption for a
    // self-issued certificate belongs to the step that walks the path,
    // where it reads "If certificate i is not self-issued" (6.1.4 (h)).
    // Carrying it into the wrap-up leaves the counter one above where the
    // path left it, so a target naming no policy is accepted under an
    // authority that demanded one.
    // The demand binds one certificate further down, which leaves the
    // counter at exactly one when the last certificate is reached: enough
    // for the path to still stand at 6.1.3 (f), and spent by the wrap-up.
    let demanding = Says::new(Some(&[GOLD]), None, Some((Some(1), None)), None);
    let silent = Says::new(None, None, None, None);

    let parser = Parser::der(crate::fixtures::memory());
    let read: Vec<Certificate<'_>> = [&demanding, &silent]
        .iter()
        .map(|step| {
            Certificate::read(&parser, &step.der, 0).expect("a certificate this test wrote")
        })
        .collect();

    let mut processing = Processing::new(2, open(), 1_024, &crate::fixtures::memory(), 0)
        .expect("room this test allows");
    let first = read[0].tbs().extensions();
    assert_eq!(
        processing.present(
            first
                .certificate_policies(first.memory())
                .expect("a value this test wrote")
                .as_ref(),
            false,
            false,
            &mut ()
        ),
        Ok(true)
    );
    let limits = first
        .policy_constraints(first.memory())
        .expect("a value this test wrote");
    processing
        .carry(None, limits, None, false, &mut ())
        .expect("a tree this test keeps small");

    // The target names no policy, and is self-issued. The agreement has
    // ended, and the path stands only on the counter the wrap-up is about
    // to spend.
    assert_eq!(processing.present(None, true, true, &mut ()), Ok(true));
    let settled = processing
        .settle(None, &[], &mut ())
        .expect("a tree this test keeps small");
    assert!(
        !settled.is_satisfied(),
        "an authority demanded a policy and the path names none"
    );
}

#[test]
fn mappings_below_an_ended_agreement_are_not_worked_out_at_all() {
    // A certificate that named no policy ended the agreement, and nothing
    // below can revive it. Metering a later certificate's mappings against
    // a tree that no longer exists refuses the path for room the working
    // out was never going to use, and calls it truncation.
    let parser = Parser::der(crate::fixtures::memory());
    let mapping = Says::new(
        Some(&[GOLD]),
        Some(&[(GOLD, GOLD), (GOLD, SILVER), (GOLD, BRONZE)]),
        None,
        None,
    );
    let certificate = Certificate::read(&parser, &mapping.der, 0).unwrap();
    let mappings = certificate
        .tbs()
        .extensions()
        .policy_mappings(certificate.tbs().extensions().memory())
        .unwrap()
        .unwrap();

    // Room for the root and nothing else, and a first certificate that
    // names no policy, which ends the agreement.
    let mut processing =
        Processing::new(4, open(), 1, &crate::fixtures::memory(), 0).expect("room for the root");
    assert_eq!(processing.present(None, false, false, &mut ()), Ok(true));
    assert_eq!(
        processing.carry(Some(&mappings), None, None, false, &mut ()),
        Ok(()),
        "there is no tree left for the mappings to grow"
    );
}

#[test]
fn a_mapping_that_replaced_another_does_not_go_on_being_counted() {
    // What the meter counts is what the tree holds. A grouping built to
    // apply one certificate's mappings is dropped when it has been applied,
    // and an expectation set that replaces another leaves only itself
    // behind. Counting either for ever makes the meter drift above what is
    // held, until a path that fits is refused for a room it is not using.
    let parser = Parser::der(crate::fixtures::memory());
    let mapping = Says::new(
        Some(&[GOLD]),
        Some(&[(GOLD, GOLD), (GOLD, SILVER), (GOLD, BRONZE)]),
        None,
        None,
    );
    let certificate = Certificate::read(&parser, &mapping.der, 0).unwrap();
    let extensions = certificate.tbs().extensions();
    let named = extensions
        .certificate_policies(extensions.memory())
        .unwrap()
        .unwrap();
    let mappings = extensions
        .policy_mappings(extensions.memory())
        .unwrap()
        .unwrap();

    // Each round the tree really does grow: one node, and the three
    // identifiers that node now expects. What it does not grow by is the
    // grouping used to apply the mapping, which is gone by the time the
    // round ends. Room for four rounds of what is kept is not room for four
    // rounds of what is kept plus four rounds of what was thrown away.
    let mut processing = Processing::new(8, open(), 21, &crate::fixtures::memory(), 0)
        .expect("room this test allows");
    for round in 1..=4 {
        assert_eq!(
            processing.present(Some(&named), false, false, &mut ()),
            Ok(true),
            "round {round}"
        );
        assert_eq!(
            processing.carry(Some(&mappings), None, None, false, &mut ()),
            Ok(()),
            "round {round}: the meter counts what the tree holds"
        );
    }
}

#[test]
fn a_mapping_list_larger_than_the_tree_may_hold_says_so() {
    // One issuer policy may be mapped to many subject policies, and the
    // expectation sets that carries are as large as the list. They are held
    // for as long as the tree is, so they are metered like the tree: a
    // parseable mapping list must not buy memory the caller's bound never
    // sees.
    let parser = Parser::der(crate::fixtures::memory());
    let step = Says::new(
        Some(&[GOLD]),
        Some(&[(GOLD, SILVER), (GOLD, BRONZE), (GOLD, GOLD)]),
        None,
        None,
    );
    let certificate = Certificate::read(&parser, &step.der, 0).unwrap();
    let extensions = certificate.tbs().extensions();
    let named = extensions
        .certificate_policies(extensions.memory())
        .unwrap()
        .unwrap();
    let mappings = extensions
        .policy_mappings(extensions.memory())
        .unwrap()
        .unwrap();

    let mut processing = Processing::new(2, open(), 3, &crate::fixtures::memory(), 0)
        .expect("room this test allows");
    assert_eq!(
        processing.present(Some(&named), false, false, &mut ()),
        Ok(true)
    );
    assert_eq!(
        processing.carry(Some(&mappings), None, None, false, &mut ()),
        Err(Overflow::Limit)
    );
}

#[test]
fn a_tree_grown_past_what_its_expectations_leave_room_for_says_so() {
    // The ceiling is what the tree and its expectations may hold between
    // them, so a mapping that leaves identifiers behind has spent part of
    // it. Growing the tree afterwards against the node count alone spends
    // room the expectations are still holding, and the path settles as
    // though the bound had been kept.
    //
    // Two policies, then a mapping that leaves one identifier expected, and
    // a certificate that continues both branches. Five is room for the
    // three nodes and the mapping while it is applied, and room for four
    // nodes beside the identifier that outlives it.
    let parser = Parser::der(crate::fixtures::memory());
    let first = Says::new(Some(&[GOLD, SILVER]), Some(&[(GOLD, BRONZE)]), None, None);
    let second = naming(&[BRONZE, SILVER]);
    let above = Certificate::read(&parser, &first.der, 0).expect("a certificate this test wrote");
    let below = Certificate::read(&parser, &second.der, 0).expect("a certificate this test wrote");

    let named = above
        .tbs()
        .extensions()
        .certificate_policies(above.tbs().extensions().memory())
        .expect("the extension this test wrote")
        .expect("a value this test wrote");
    let maps: PolicyMappings<'_> = above
        .tbs()
        .extensions()
        .policy_mappings(above.tbs().extensions().memory())
        .expect("the extension this test wrote")
        .expect("a value this test wrote");
    let carried = below
        .tbs()
        .extensions()
        .certificate_policies(below.tbs().extensions().memory())
        .expect("the extension this test wrote")
        .expect("a value this test wrote");

    let mut processing = Processing::new(2, open(), 5, &crate::fixtures::memory(), 0)
        .expect("room this test allows");
    assert_eq!(
        processing.present(Some(&named), false, false, &mut ()),
        Ok(true)
    );
    assert_eq!(
        processing.carry(Some(&maps), None, None, false, &mut ()),
        Ok(())
    );

    // Three nodes and one identifier the mapping left behind: four of the
    // five. The certificate below continues two branches, and only one of
    // them fits.
    assert_eq!(
        processing.present(Some(&carried), false, true, &mut ()),
        Err(Overflow::Limit)
    );
}

#[test]
fn a_caller_asking_about_any_policy_is_answered_with_the_whole_tree() {
    // "If the valid_policy_tree is not NULL and the user-initial-policy-set
    // is any-policy, the intersection is the entire valid_policy_tree"
    // (RFC 5280 6.1.5 (g) (ii)). Naming that identifier is how the profile
    // says a caller is not concerned about policy (6.1.1 (c)), so it is the
    // unrestricted request written out rather than a set of one.
    //
    // Read as a set of one, the narrowing looked for a node already naming
    // it, found the very node standing for it, and killed that node without
    // putting anything back: a path naming exactly what was asked for came
    // back naming nothing.
    let settled = walk(&[naming(&[oid::ANY_POLICY])], open(), &[oid::ANY_POLICY])
        .expect("a path that names the policy the caller asked about");
    assert_eq!(settled, alloc::vec![oid::ANY_POLICY]);

    // The same tree, asked the same way, alongside a policy of its own.
    let settled = walk(
        &[naming(&[GOLD, oid::ANY_POLICY])],
        open(),
        &[oid::ANY_POLICY],
    )
    .expect("a path that names the policy the caller asked about");
    assert!(settled.contains(&oid::ANY_POLICY));
    assert!(settled.contains(&GOLD));
}

#[test]
fn mappings_nobody_will_honour_are_not_charged_for_what_they_would_have_held() {
    // Where an authority above has stopped mappings being honoured, the
    // policy an issuer would have mapped simply ends (RFC 5280 6.1.4 (b)
    // (2)). Only the issuer names are read: nothing is carried down, so
    // nothing is expected afterwards.
    //
    // Charging the subject policies anyway measures room the working out
    // was never going to use, and a certificate naming enough mappings then
    // discards a path whose other branches were never in question.
    let parser = Parser::der(crate::fixtures::memory());
    let step = Says::new(
        Some(&[GOLD, SILVER]),
        Some(&[(GOLD, BRONZE), (GOLD, SILVER)]),
        None,
        None,
    );
    let certificate =
        Certificate::read(&parser, &step.der, 0).expect("a certificate this test wrote");
    let named = certificate
        .tbs()
        .extensions()
        .certificate_policies(certificate.tbs().extensions().memory())
        .expect("the extension this test wrote")
        .expect("a value this test wrote");
    let maps: PolicyMappings<'_> = certificate
        .tbs()
        .extensions()
        .policy_mappings(certificate.tbs().extensions().memory())
        .expect("the extension this test wrote")
        .expect("a value this test wrote");

    // Mappings are not honoured from the outset, and the tree is the root
    // and the two policies named: three of the four the ceiling allows.
    let inhibited = Initial {
        policy_mapping: false,
        ..open()
    };
    let mut processing = Processing::new(2, inhibited, 4, &crate::fixtures::memory(), 0)
        .expect("room this test allows");
    assert_eq!(
        processing.present(Some(&named), false, false, &mut ()),
        Ok(true)
    );
    assert_eq!(
        processing.carry(Some(&maps), None, None, false, &mut ()),
        Ok(())
    );

    // The mapped policies are gone and the one nobody mapped remains.
    let settled = processing
        .settle(None, &[], &mut ())
        .expect("a tree this test keeps small");
    assert_eq!(settled.policies(), &[SILVER]);
}

#[test]
fn the_policies_a_path_names_come_back_in_one_order_whatever_order_they_were_written_in() {
    // What a path was issued under is a set, and the certificates decide
    // what order they wrote it in. Keeping that order makes two settled
    // paths comparable only by searching one set for each member of the
    // other, which is the square of a count the caller's ceiling allows and
    // which the search then repeats against every path it is holding.
    //
    // One order for every set makes that comparison a walk down both.
    let settled = walk(&[naming(&[BRONZE, SILVER, GOLD])], open(), &[])
        .expect("a path nobody demanded a policy of");
    assert_eq!(settled, alloc::vec![GOLD, SILVER, BRONZE]);

    // The same set written the other way round is the same set.
    let other = walk(&[naming(&[GOLD, BRONZE, SILVER])], open(), &[])
        .expect("a path nobody demanded a policy of");
    assert_eq!(settled, other);
}
