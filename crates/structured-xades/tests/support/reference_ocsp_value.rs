//! Mandatory identifier and optional digest retain the same response pair.

use super::*;
use structured_xades::{
    properties::{CalendarFact, CalendarValue},
    validation::{self, OcspReferenceInput},
};

#[test]
fn ocsp_value_retains_original_pair_and_optional_digest_distinction() {
    // Annex A.1.2 permits identifier-only references but warns of substitution.
    // Neither absent digest nor a matching digest overrides wrong time/key.
    with_authenticated_ocsp(|signed, envelope, operation, verifier, memory, bytes| {
        for with_digest in [false, true] {
            let (mut xml, prepared) =
                ocsp_reference_fixture_with_digest(bytes, memory, with_digest);
            let refs = &prepared.validation_references()[0];
            let keys = KeyDigest {
                key: signed.signer().tbs().public_key().key().as_bytes(),
                resolves: Cell::new(0),
                hashes: Cell::new(0),
                supported: true,
                fail: false,
            };
            let provider = Oracle::new(Mode::Ready);
            let actual = OcspReferenceInput { envelope, signed };
            let held = memory.used();
            let check = || {
                validation::check_ocsp_envelope_reference(
                    &xml, refs, 0, actual, &keys, &provider, operation,
                )
                .unwrap()
                .unwrap()
            };
            let report = check();
            assert!(report.identifies_response());
            assert!(core::ptr::eq(report.references(), refs));
            assert_eq!(report.entry(), 0);
            assert!(core::ptr::eq(report.actual().envelope, envelope));
            assert!(core::ptr::eq(
                report.actual().signed.response(),
                signed.response()
            ));
            assert!(core::ptr::eq(
                report.actual().signed.signer(),
                signed.signer()
            ));
            assert_eq!(
                report.digest(),
                Some(if with_digest {
                    ReferenceDigest::Compared(Agreement::Matches)
                } else {
                    ReferenceDigest::IdentifierOnly
                })
            );
            assert_eq!(provider.started.get(), usize::from(with_digest));
            assert_eq!(provider.one_shot.get(), 0);
            let CalendarFact::Value(matching) = xml.calendar_routes[0].1 else {
                panic!("complete original time")
            };
            for time in [
                CalendarValue {
                    second: 1,
                    ..matching
                },
                CalendarValue {
                    timezone_minutes: None,
                    ..matching
                },
            ] {
                xml.calendar_routes[0].1 = CalendarFact::Value(time);
                let report = validation::check_ocsp_envelope_reference(
                    &xml, refs, 0, actual, &keys, &provider, operation,
                )
                .unwrap()
                .unwrap();
                assert!(!report.identifies_response());
                assert_eq!(
                    report.digest(),
                    Some(if with_digest {
                        ReferenceDigest::Compared(Agreement::Matches)
                    } else {
                        ReferenceDigest::IdentifierOnly
                    })
                );
            }
            assert_eq!(verifier.calls.get(), 1);
            assert_eq!(memory.used(), held);
        }
    });
}

#[test]
fn ocsp_value_never_promotes_disagreement_or_unavailable_capability() {
    // A successful half is insufficient: preserve a differing key/digest and
    // unsupported key or envelope hash without promoting either to identity.
    use validation::{ReferenceIdentifier, ResponderIdentifier};
    enum Case {
        WrongKey,
        WrongDigest,
        KeyUnavailable,
        DigestUnavailable,
    }
    with_authenticated_ocsp(|signed, envelope, operation, verifier, memory, bytes| {
        for case in [
            Case::WrongKey,
            Case::WrongDigest,
            Case::KeyUnavailable,
            Case::DigestUnavailable,
        ] {
            let (mut xml, prepared) = ocsp_reference_fixture(bytes, memory);
            let refs = &prepared.validation_references()[0];
            let (method, value) = refs.entries()[0].digest().unwrap();
            let ReferenceIdentifier::Ocsp {
                responder: ResponderIdentifier::Key(key),
                ..
            } = refs.entries()[0].identifier()
            else {
                panic!("original key selector")
            };
            for (node, bytes) in &mut xml.binary_routes {
                if matches!(case, Case::WrongKey) && *node == key {
                    *bytes.last_mut().unwrap() = 0x34;
                }
                if matches!(case, Case::WrongDigest) && *node == value {
                    bytes[0] ^= 1;
                }
            }
            let keys = KeyDigest {
                key: signed.signer().tbs().public_key().key().as_bytes(),
                resolves: Cell::new(0),
                hashes: Cell::new(0),
                supported: !matches!(case, Case::KeyUnavailable),
                fail: false,
            };
            // The original written method remains unchanged even when the
            // selected provider cannot execute it.
            assert!(
                xml.digest_algorithms
                    .iter()
                    .any(|(node, _)| *node == method)
            );
            let provider = Oracle::new(if matches!(case, Case::DigestUnavailable) {
                Mode::Unsupported
            } else {
                Mode::Ready
            });
            let held = memory.used();
            let report = validation::check_ocsp_envelope_reference(
                &xml,
                refs,
                0,
                OcspReferenceInput { envelope, signed },
                &keys,
                &provider,
                operation,
            )
            .unwrap()
            .unwrap();
            assert!(!report.identifies_response());
            let expected = match case {
                Case::WrongDigest => Agreement::Differs,
                Case::DigestUnavailable => Agreement::Unsupported,
                _ => Agreement::Matches,
            };
            assert_eq!(report.digest(), Some(ReferenceDigest::Compared(expected)));
            assert_eq!(verifier.calls.get(), 1);
            assert_eq!(memory.used(), held);
        }
    });
}
