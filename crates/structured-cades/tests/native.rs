//! Real P-256 CMS/path checks through the complete source-bound format inputs.

#[path = "native/credential_material.rs"]
mod credential_material;
#[path = "native/legacy.rs"]
mod legacy;
#[path = "native/restrictions.rs"]
mod restrictions;
mod support;
use p256::ecdsa::SigningKey;
use std::{cell::Cell, convert::Infallible};
use structured_asn1::{Parser, memory::Work};
use structured_cades::{
    Level, basic, counters, credential, prepare::Preparation, source::Document,
};
use structured_cms::{
    SignedData,
    binding::Scope,
    oid, prepare,
    verify::{ContentMode, DocumentBatch},
};
use structured_ltv::{
    credential::Authentication,
    pki::{self, PathOutcome},
};
use structured_pkix::path::{self, Anchor, Interval, ValidationBounds, ValidationContext};
use support::{Oracle, attribute, certificate, memory, message, signature_octets, signer, tlv};

struct Credentials {
    calls: Cell<usize>,
}
impl<'p, 'd> credential::Provider<'p, 'd> for Credentials {
    type Evidence = ();
    type Error = Infallible;
    fn authenticate(
        &self,
        _: credential::Context<'_, '_, 'd>,
    ) -> Result<Authentication<'p, 'd, ()>, Infallible> {
        self.calls.set(self.calls.get() + 1);
        Ok(Authentication::Unsupported)
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the real root/path/CMS receipts and the three credential preflight variants must share exactly the same visible pipeline"
)]
fn real_root_receipts_and_credential_preflight_cannot_promote_invalid_fields() {
    // Real signature/path mathematics cannot substitute for CAdES format
    // conformance. Incomplete or unprotected credential grammar must refuse
    // BEFORE authentication and cannot issue a complete empty credential set.
    for mode in 0..7 {
        let issuer_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
        let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
        let root = certificate("Root", "Root", &issuer_key, &issuer_key, false);
        let leaf = certificate("Signer", "Root", &key, &issuer_key, false);
        let mut signed = vec![
            attribute(oid::SIGNING_TIME.as_bytes(), &tlv(23, b"260101000000Z")),
            attribute(
                oid::MIME_TYPE.as_bytes(),
                &tlv(12, b"application/octet-stream"),
            ),
        ];
        let mut unsigned = vec![];
        if mode == 6 {
            // A valid V2 hash must not hide a conflicting V1 assertion or
            // supply a signer path through an unproven ESS binding.
            for byte in [1, 2] {
                signed.push(attribute(
                    oid::SIGNING_CERTIFICATE.as_bytes(),
                    &tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(4, &[byte; 20])))),
                ));
            }
        }
        if mode == 1 {
            let claimed = tlv(0xa0, &tlv(0x30, &attribute(&[42, 3], &tlv(12, b"role"))));
            let broken = tlv(0xa1, &tlv(2, &[1]));
            signed.push(attribute(
                oid::SIGNER_ATTRIBUTES_V2.as_bytes(),
                &tlv(0x30, &[claimed, broken].concat()),
            ));
        }
        if mode == 2 {
            let assertion = tlv(0x30, &[tlv(6, &[42, 3]), tlv(5, &[])].concat());
            unsigned.push(attribute(
                oid::SIGNER_ATTRIBUTES_V2.as_bytes(),
                &tlv(0x30, &tlv(0xa2, &tlv(0x30, &assertion))),
            ));
        }
        if mode >= 4 {
            // Each genuine nested signature covers its DIRECT parent's
            // original signature CONTENT, never the root payload or TLV.
            let root_signer = signer(
                Some(oid::DATA.as_bytes()),
                b"sample",
                &leaf,
                &key,
                &signed,
                &[],
            );
            let covered = signature_octets(&root_signer);
            let first = signer(None, &covered, &leaf, &key, &[], &[]);
            let mut grandchild_input = signature_octets(&first);
            if mode == 5 {
                grandchild_input[0] ^= 1;
            }
            let second = signer(None, &grandchild_input, &leaf, &key, &[], &[]);
            let first = signer(
                None,
                &covered,
                &leaf,
                &key,
                &[],
                &[attribute(oid::COUNTERSIGNATURE.as_bytes(), &second)],
            );
            unsigned.push(attribute(oid::COUNTERSIGNATURE.as_bytes(), &first));
        }
        let cms_signer = signer(
            Some(oid::DATA.as_bytes()),
            b"sample",
            &leaf,
            &key,
            &signed,
            &unsigned,
        );
        let bytes = message(
            oid::DATA.as_bytes(),
            if mode == 3 { None } else { Some(b"sample") },
            &[root.clone(), leaf.clone()],
            &[],
            &[cms_signer],
        );
        let account = memory();
        let parser = Parser::ber(account.clone());
        let data = SignedData::read(&parser, &bytes, 400).unwrap();
        assert!(data.faults().is_empty());
        let parent = parser.read(&[], 0).unwrap();
        let work = parent.execution();
        let root = data
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == root)
            .unwrap();
        let leaf = data
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == leaf)
            .unwrap();
        let oracle = Oracle::new();
        let context = ValidationContext {
            execution: &work,
            interval: Interval::at(leaf.tbs().validity().not_before().seconds()),
            policy: path::Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let PathOutcome::Accepted(path) =
            pki::check_path(&[leaf], Anchor::from_certificate(root), &context).unwrap()
        else {
            panic!("actual P256 path must validate");
        };
        let selected = &data.signers()[0];
        let prepare::Preparation::Ready(plan) = prepare::resolve(
            &oracle,
            selected,
            path.members().last().unwrap().key(),
            &parent,
            Scope::Content(oid::DATA),
        )
        .unwrap() else {
            panic!("actual P256 request must resolve");
        };
        let mut requests = work.vector();
        requests.try_push(plan).unwrap();
        let batch = DocumentBatch::prepare(
            &oracle,
            &data,
            requests.into_owned(),
            if mode == 3 {
                ContentMode::Detached
            } else {
                ContentMode::Carried
            },
            &parent,
        )
        .unwrap();
        let checks = if mode == 3 {
            batch
                .run_detached(&mut [b"sa".as_slice(), b"mple".as_slice()])
                .unwrap()
        } else {
            batch.run_carried().unwrap()
        };
        let document = Document::new(&data, &parent).unwrap();
        let prepared = Preparation::read(&document, selected, Level::Basic, &parent).unwrap();
        let binding = basic::bind(
            &prepared,
            &checks,
            &checks.checks()[0],
            leaf,
            Some(&path),
            &oracle,
            &parent,
        )
        .unwrap();
        if mode == 6 {
            assert!(!prepared.basic_format_requirements_met());
            assert!(
                !binding.is_bound(),
                "a valid companion ESS version cannot waive the conflicting version"
            );
            continue;
        }
        assert!(binding.is_bound(), "mathematics and ESS must really pass");
        let counter_checks = counters::bind(&prepared, &parent, |context| {
            context.check(&oracle, leaf, &path)
        })
        .unwrap();
        if mode == 5 {
            assert_eq!(counter_checks.values().len(), 2);
            assert!(matches!(
                counter_checks.values()[0].as_ref().unwrap().outcome(),
                counters::Outcome::Bound
            ));
            assert!(
                counter_checks.paths().is_none(),
                "a valid first counter cannot hide a wrong-parent grandchild"
            );
            assert!(
                counter_checks.values()[1]
                    .as_ref()
                    .unwrap()
                    .content()
                    .is_some(),
                "actual negative payload cause is retained"
            );
            continue;
        }
        let paths = counter_checks.paths().unwrap();
        let handler = Credentials {
            calls: Cell::new(0),
        };
        let credentials = credential::check(&prepared, &binding, &paths, &handler, &parent);
        if mode == 0 || mode == 3 || mode == 4 {
            assert!(prepared.basic_format_requirements_met());
            assert!(credentials.unwrap().complete().is_some());
            assert!(
                basic::basic(&binding, paths, &parent)
                    .unwrap()
                    .all_basic_requirements_met()
            );
        } else {
            assert!(!prepared.basic_format_requirements_met());
            assert!(
                credentials.is_err(),
                "nonconforming credentials cannot mint an empty complete proof"
            );
        }
        assert_eq!(
            handler.calls.get(),
            0,
            "schema/placement preflight precedes handler side effects"
        );
    }
}
