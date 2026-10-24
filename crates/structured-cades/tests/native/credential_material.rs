//! Real independently signed DEV assertions and their material-owner boundary.

use crate::support::{Oracle, attribute, certificate, memory, message, signer, tlv};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use structured_asn1::{Parser, Tag, memory::Work, universal};
use structured_cades::{
    Level, basic, counters, credential,
    material::{
        self,
        credentials::{Completeness, Need, VisitError},
    },
    prepare::Preparation,
    source::Document,
};
use structured_cms::{
    SignedData,
    binding::Scope,
    oid, prepare,
    verify::{ContentMode, DocumentBatch},
};
use structured_ltv::{
    credential::Authentication,
    material::ArtifactRef,
    pki::{self, Authorities, PathOutcome},
};
use structured_pkix::{
    Certificate,
    path::{self, Anchor, Interval, ValidationBounds, ValidationContext},
};

#[derive(Debug)]
enum OwnerError {
    Processing,
    Stop,
}
struct Evidence<'p, 'd> {
    certificate: &'p Certificate<'d>,
}
struct Owner<'p, 'd> {
    certificate: &'p Certificate<'d>,
    key: VerifyingKey,
    authentications: Cell<usize>,
    visits: Cell<usize>,
    mode: usize,
}
impl<'p, 'd> credential::Provider<'p, 'd> for Owner<'p, 'd> {
    type Evidence = Evidence<'p, 'd>;
    type Error = OwnerError;
    fn authenticate(
        &self,
        context: credential::Context<'_, '_, 'd>,
    ) -> Result<Authentication<'p, 'd, Self::Evidence>, OwnerError> {
        // DEV format: P-256 signature over the original message octets under
        // an explicitly pinned raw key. This is a genuine certificate-free
        // authority mechanism, not an always-Yes authentication callback.
        let source = context.value().value.ok_or(OwnerError::Processing)?;
        let mut reader = source
            .reader_in(context.operation())
            .map_err(|_| OwnerError::Processing)?;
        let envelope = reader
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(|_| OwnerError::Processing)?;
        let mut fields = reader
            .enter(&envelope)
            .map_err(|_| OwnerError::Processing)?;
        let message = fields
            .expect(Tag::primitive(universal::OCTET_STRING))
            .map_err(|_| OwnerError::Processing)?;
        let signature = fields
            .expect(Tag::primitive(universal::OCTET_STRING))
            .map_err(|_| OwnerError::Processing)?;
        if !reader.is_empty() || !fields.is_empty() {
            return Err(OwnerError::Processing);
        }
        fields
            .charge(100_000 + message.contents().len() as u64 + signature.contents().len() as u64)
            .map_err(|_| OwnerError::Processing)?;
        let signature =
            Signature::from_der(signature.contents()).map_err(|_| OwnerError::Processing)?;
        self.authentications.set(self.authentications.get() + 1);
        if self
            .key
            .verify_prehash(&Sha256::digest(message.contents()), &signature)
            .is_err()
        {
            return Ok(Authentication::Rejected);
        }
        Ok(Authentication::Authenticated {
            evidence: Evidence {
                certificate: self.certificate,
            },
            authorities: Authorities::CertificateFree,
        })
    }
}
impl<'p, 'd> material::credentials::Provider<Evidence<'p, 'd>> for Owner<'p, 'd> {
    type Error = OwnerError;
    fn visit<'m, 'doc, V>(
        &self,
        credential: &credential::Checked<'m, 'doc, '_, Evidence<'p, 'd>>,
        _: &[material::Open<'doc>],
        operation: &structured_asn1::ScopedReader<'doc, '_>,
        mut visitor: impl for<'value, 'source> FnMut(Need<'value, 'source, 'm, 'doc>) -> Result<(), V>,
    ) -> Result<Completeness, VisitError<OwnerError, V>> {
        let ordinal = self.visits.get();
        self.visits.set(ordinal + 1);
        if self.mode == 4 {
            return Err(VisitError::Processing(OwnerError::Stop));
        }
        if self.mode == 3 {
            let memory = operation.memory();
            let _quota = memory
                .reserve(memory.limit() - memory.used())
                .map_err(|_| VisitError::Processing(OwnerError::Processing))?;
            assert!(visitor(Need::Missing).is_err());
            // A malicious/broken format owner swallows and retries the first
            // callback refusal, then lies about completeness. Core must keep it.
            assert!(visitor(Need::Missing).is_err());
            return Ok(Completeness::Complete);
        }
        if self.mode == 5 && ordinal == 1 {
            return Err(VisitError::Processing(OwnerError::Stop));
        }
        if self.mode == 1 {
            visitor(Need::Missing).map_err(VisitError::Visitor)?;
        } else {
            let credential::Outcome::Authentication(Authentication::Authenticated {
                evidence, ..
            }) = credential.outcome()
            else {
                panic!("only sealed authenticated credentials may reach material interpretation");
            };
            // The callback's document lifetime is independent of this format
            // receipt's certificate source lifetime; borrowed DER must not be
            // retained by the common caller after the callback.
            visitor(Need::Known(ArtifactRef::Certificate(evidence.certificate)))
                .map_err(VisitError::Visitor)?;
        }
        Ok(if self.mode == 2 {
            Completeness::Unsupported
        } else {
            Completeness::Complete
        })
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "each callback mode uses the same visible live real-crypto/source receipt graph and exact rollback baseline"
)]
fn credential_material_needs_the_actual_owner_and_keeps_refusals_sticky() {
    // Certificate-free authentication does not mean material-free. Discover
    // ALL original credentials, reuse their real evidence, retain negatives,
    // and never return a successful prefix after owner/resource refusal.
    for mode in 0..6 {
        let root_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
        let key = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
        let root_bytes = certificate("Root", "Root", &root_key, &root_key, false);
        let leaf_bytes = certificate("Signer", "Root", &key, &root_key, false);
        let protected = b"original independently signed DEV assertion";
        let signature: Signature = key.sign_prehash(&Sha256::digest(protected)).unwrap();
        let assertion = tlv(
            0x30,
            &[
                tlv(6, &[42, 3]),
                tlv(
                    0x30,
                    &[tlv(4, protected), tlv(4, signature.to_der().as_bytes())].concat(),
                ),
            ]
            .concat(),
        );
        let roles = tlv(
            0x30,
            &tlv(0xa2, &tlv(0x30, &[assertion.clone(), assertion].concat())),
        );
        let signed = [
            attribute(oid::SIGNING_TIME.as_bytes(), &tlv(23, b"260101000000Z")),
            attribute(oid::SIGNER_ATTRIBUTES_V2.as_bytes(), &roles),
        ];
        let signature = signer(
            Some(oid::DATA.as_bytes()),
            b"sample",
            &leaf_bytes,
            &key,
            &signed,
            &[],
        );
        let bytes = message(
            oid::DATA.as_bytes(),
            Some(b"sample"),
            &[root_bytes.clone(), leaf_bytes.clone()],
            &[],
            &[signature],
        );
        let memory = memory();
        let parser = Parser::ber(memory.clone());
        let message = SignedData::read(&parser, &bytes, 400).unwrap();
        let operation = parser.read(&[], 0).unwrap();
        let work = operation.execution();
        let root = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == root_bytes)
            .unwrap();
        let leaf = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == leaf_bytes)
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
            panic!("actual P256 path");
        };
        let selected = &message.signers()[0];
        let prepare::Preparation::Ready(plan) = prepare::resolve(
            &oracle,
            selected,
            path.members().last().unwrap().key(),
            &operation,
            Scope::Content(oid::DATA),
        )
        .unwrap() else {
            panic!("actual CMS request");
        };
        let mut requests = work.vector();
        requests.try_push(plan).unwrap();
        let checks = DocumentBatch::prepare(
            &oracle,
            &message,
            requests.into_owned(),
            ContentMode::Carried,
            &operation,
        )
        .unwrap()
        .run_carried()
        .unwrap();
        let document = Document::new(&message, &operation).unwrap();
        let prepared = Preparation::read(&document, selected, Level::Basic, &operation).unwrap();
        assert!(prepared.basic_format_requirements_met());
        let binding = basic::bind(
            &prepared,
            &checks,
            &checks.checks()[0],
            leaf,
            Some(&path),
            &oracle,
            &operation,
        )
        .unwrap();
        let counters = counters::bind(&prepared, &operation, |context| {
            context.check(&oracle, leaf, &path)
        })
        .unwrap();
        let counters = counters.paths().unwrap();
        let owner = Owner {
            certificate: leaf,
            key: VerifyingKey::from(&key),
            authentications: Cell::new(0),
            visits: Cell::new(0),
            mode,
        };
        let authenticated =
            credential::check(&prepared, &binding, &counters, &owner, &operation).unwrap();
        assert_eq!(owner.authentications.get(), 2);
        let complete = authenticated.complete().unwrap();
        let pool = material::Pool::read(&prepared, &operation).unwrap();
        let query = structured_ltv::source::Scope::new(
            &document,
            structured_ltv::source::Source::snapshot(&document),
            &work,
        );
        let index = pool.index(&query).unwrap();
        let baseline = memory.used();
        let result = material::credentials::check(
            &complete,
            &counters,
            prepared.timestamp_requirements(),
            &index,
            &material::credentials::Scope::whole(),
            &owner,
            &operation,
        );
        match mode {
            0 => {
                let report = result.unwrap();
                assert!(report.all_requirements_met());
                assert_eq!(report.entries().len(), 2);
                assert!(
                    report
                        .entries()
                        .iter()
                        .all(|entry| entry.findings().is_empty())
                );
            }
            1 | 2 => {
                let report = result.unwrap();
                assert!(!report.all_requirements_met());
                assert_eq!(report.entries().len(), 2);
            }
            3 => {
                assert!(matches!(
                    result,
                    Err(material::credentials::Error::Resource { .. })
                ));
            }
            4 | 5 => {
                assert!(matches!(
                    result,
                    Err(material::credentials::Error::Provider {
                        cause: OwnerError::Stop,
                        ..
                    })
                ));
            }
            _ => unreachable!(),
        }
        assert_eq!(
            owner.authentications.get(),
            2,
            "material query never reauthenticates the credential"
        );
        assert_eq!(
            memory.used(),
            baseline,
            "all reports/partial findings and quota leases release their retained capacity"
        );
    }
}
