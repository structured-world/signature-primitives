//! AC profile projection into the existing PKIX CRL evidence processor.
use super::{Profile, Revocation};
use structured_asn1::memory::{Execution, Work};
use structured_asn1::{Integer, Span};
use structured_pkix::crl::{RevocationScheme, RevocationTarget, TargetKind};
use structured_pkix::general_name::GeneralName;
use structured_pkix::{Extensions, Name};

impl<'a> RevocationTarget<'a> for Profile<'_, 'a> {
    fn execution_in<'op, W: Work>(&'op self, work: &'op W) -> Execution<'op>
    where
        'a: 'op,
    {
        work.execution_for(self.certificate().parser)
    }
    fn issuer(&self) -> &Name<'a> {
        // Profile construction established exactly one directoryName issuer.
        match self.certificate().information().issuer.names.as_deref() {
            Some([GeneralName::Directory(name)]) => name,
            _ => unreachable!("checked AC profile has one directory issuer"),
        }
    }
    fn serial(&self) -> Integer<'a> {
        self.certificate().information().serial
    }
    fn extensions(&self) -> Option<&Extensions<'a>> {
        self.certificate().information().extensions.as_ref()
    }
    fn kind(&self) -> TargetKind {
        TargetKind::Attribute
    }
    fn revocation_scheme(&self) -> RevocationScheme {
        match self.revocation() {
            Revocation::Required => RevocationScheme::Available,
            Revocation::NoRevAvailable => RevocationScheme::NoRevAvail,
        }
    }
    fn encoded(&self) -> &'a [u8] {
        self.certificate().element().as_bytes()
    }
    fn span(&self) -> Span {
        self.certificate().element().span()
    }
}
