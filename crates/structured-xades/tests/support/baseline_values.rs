//! Original complete validation pool for the end-to-end baseline fixture.

use super::super::{XADES, XADES_141, element};
use super::{Tree, timestamp_oracle};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Pool {
    Absent,
    Complete,
    CompleteOnly,
    DeltaOnly,
}

pub(super) fn incorporate(xml: &mut Tree, leaf: &[u8], root: &[u8], pool: Pool) {
    // EN319132-1 6.3(x): all actual signer/TSA/status authority material is
    // incorporated. AnyValidationData is a general pool, so it can carry shared
    // TSA certificates/CRLs without violating ordinary-value placement rules.
    if pool == Pool::Absent {
        return;
    }
    let general = add(xml, 7, XADES_141, "AnyValidationData");
    let certificates = add(xml, general, XADES, "CertificateValues");
    for original in [leaf, root] {
        let node = add(xml, certificates, XADES, "EncapsulatedX509Certificate");
        xml.binary_routes.push((node, original.to_vec()));
    }
    let revocations = add(xml, general, XADES, "RevocationValues");
    let lists = add(xml, revocations, XADES, "CRLValues");
    let (base, delta) = timestamp_oracle::crl_pair();
    for (is_delta, original) in [(false, base), (true, delta)] {
        if (is_delta && pool == Pool::CompleteOnly) || (!is_delta && pool == Pool::DeltaOnly) {
            continue;
        }
        let node = add(xml, lists, XADES, "EncapsulatedCRLValue");
        xml.binary_routes.push((node, original));
    }
}

fn add(xml: &mut Tree, parent: usize, namespace: &'static str, local: &'static str) -> usize {
    let node = xml.nodes.len();
    xml.nodes.push(element(Some(parent), namespace, local));
    node
}
