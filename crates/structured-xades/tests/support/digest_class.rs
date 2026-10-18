//! Selected-provider classification controls, not cryptographic-math oracles.

use super::*;
use core::{cmp::Ordering, convert::Infallible};
use structured_asn1::digest::{Digest, Resolution};
use structured_cms::stream::Source;
use structured_xades::{
    certificate::{Agreement, DigestProvider},
    digest,
    hashes::HashClass,
};

const ALIAS: &str = "urn:fixture:resolved-hash";

struct Forbidden {
    selected: HashClass,
    resolved: Cell<usize>,
}

impl DigestProvider<'_, Tree> for Forbidden {
    fn classify(&self, identity: &HashClass) -> HashClass {
        *identity
    }

    fn resolve<W: Work>(
        &self,
        _: &Access<'_, Tree, W>,
        _: usize,
    ) -> Result<Resolution<HashClass>, MemoryError> {
        self.resolved.set(self.resolved.get() + 1);
        Ok(Resolution::Supported(self.selected))
    }
}

impl Digest<'_> for Forbidden {
    type Identity = HashClass;
    type State = ();
    type Output = [u8; 16];
    type Error = MemoryError;
    fn width(&self, _: &HashClass) -> Option<usize> {
        Some(16)
    }
    fn compare<W: Work>(
        &self,
        _: &HashClass,
        _: &HashClass,
        _: &W,
    ) -> Result<Ordering, MemoryError> {
        panic!("prohibited identity must not reach renewal comparison")
    }
    fn start<W: Work>(&self, _: &HashClass, _: &W) -> Result<Resolution<()>, MemoryError> {
        panic!("a prohibited resolved hash must not create digest state")
    }
    fn update<W: Work>(&self, (): &mut (), _: &[u8], _: &W) -> Result<(), MemoryError> {
        panic!("prohibited hash update")
    }
    fn finish<W: Work>(&self, (): (), _: &W) -> Result<[u8; 16], MemoryError> {
        panic!("prohibited hash finish")
    }
    fn matches<W: Work>(
        &self,
        _: &HashClass,
        _: &[u8; 16],
        _: &[u8],
        _: &W,
    ) -> Result<bool, MemoryError> {
        panic!("prohibited hash output comparison")
    }
}

struct Unread;
impl Source for Unread {
    type Error = Infallible;
    fn stream<W: Work>(&mut self, _: &mut impl Receiver, _: &W) -> Result<(), Infallible> {
        panic!("prohibited digest must not read caller content")
    }
}

fn expected(class: HashClass) -> Agreement {
    match class {
        HashClass::Md5 => Agreement::ProhibitedAlgorithm,
        HashClass::Intrinsic => Agreement::MalformedMethod,
        HashClass::OtherKnown => panic!("this is not a forbidden test capability"),
    }
}

#[test]
fn certificate_digest_alias_cannot_hide_a_prohibited_or_non_digest_identity() {
    // Wire spelling and output width are not hash identity. These are provider
    // control tests: refusal MUST precede any primitive, not validate MD5 math.
    for selected in [HashClass::Md5, HashClass::Intrinsic] {
        let memory = funded();
        let bytes = candidate_certificate();
        let parser = structured_asn1::Parser::der(memory.clone());
        let certificate = structured_pkix::Certificate::read(&parser, &bytes, 900).unwrap();
        let (mut xml, _) = certificate_tree();
        xml.digest_algorithm = Some(ALIAS);
        xml.binary = vec![0; 16];
        let signed = signed_roles(&xml, &memory).unwrap();
        let references =
            certificate::read(&Access::new(&xml, xml.snapshot(), &memory), &signed).unwrap();
        let provider = Forbidden {
            selected,
            resolved: Cell::new(0),
        };
        assert_eq!(
            certificate::compare(&xml, &references, 0, &certificate, &provider, &memory).unwrap(),
            expected(selected)
        );
        assert_eq!(provider.resolved.get(), 1);
    }
}

#[test]
fn streaming_digest_alias_is_rejected_before_state_or_content_io() {
    // The incremental path must enforce the SAME identity rule even when the
    // alias URI and declared 16-byte output pass syntax/width preflight.
    for selected in [HashClass::Md5, HashClass::Intrinsic] {
        let memory = funded();
        let (mut xml, [_, _, _, method, value, _]) = certificate_tree();
        xml.digest_algorithm = Some(ALIAS);
        xml.binary = vec![0; 16];
        let provider = Forbidden {
            selected,
            resolved: Cell::new(0),
        };
        let reference = digest::Reference {
            snapshot: xml.snapshot(),
            method,
            value,
        };
        assert_eq!(
            digest::check(&xml, reference, &mut Unread, &provider, &memory).unwrap(),
            expected(selected)
        );
        assert_eq!(provider.resolved.get(), 1);
    }
}
