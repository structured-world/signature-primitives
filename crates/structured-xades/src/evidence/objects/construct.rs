//! Initial imprint issuance from the same exact original object sources.

use super::{ObjectError, Objects};
use crate::{timestamp::TimestampXml, xml::Xml};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_cms::{
    digest::{DigestError, DigestOutput, PassError, SingleDigest},
    stream::{RangesError, Receiver, Source},
};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};

/// The two ERS formats use the same single-group bare tree for a new seal.
pub struct InitialImprint<'p, P: AsnDigest<'p>> {
    hashes: OwnedVec<DigestOutput<'p, P>>,
    root: DigestOutput<'p, P>,
}

impl<'p, P: AsnDigest<'p>> InitialImprint<'p, P> {
    /// Complete binary ascending first list. Repeated digests are preserved.
    pub fn hashes(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.hashes.iter().map(DigestOutput::as_bytes)
    }

    /// Selected provider's finalized imprint for the RFC 3161 request.
    #[must_use]
    pub fn root(&self) -> &DigestOutput<'p, P> {
        &self.root
    }
}

/// Failure to produce an initial group imprint.
#[derive(Debug)]
pub enum InitialError<E, N, PE> {
    /// The provider did not recognize the selected digest.
    Algorithm,
    /// Digest preparation failed.
    Digest(DigestError<PE>),
    /// The sorted digest list could not be reduced into its root.
    Reduction(PassError<RangesError, PE>),
    /// Replaying one original object refused.
    Object(PassError<ObjectError<E, N>, PE>),
    /// Current capacity or work refused.
    Resource(MemoryError),
}

/// Original XML-owner and digest-provider causes for a seal request.
pub type InitialResult<T, X, PE> = Result<T, InitialError<<X as Xml>::Error, <X as Xml>::Id, PE>>;

impl<X: TimestampXml> Objects<'_, X> {
    /// Stream each original object once and issue its complete initial group
    /// imprint. Initial seal and verification use the same object inventory.
    /// ETSI TS 119 132-3 §5.2.2.1 uses RFC 4998 §4.2 or RFC 6283 §3.2.
    /// <https://www.etsi.org/deliver/etsi_ts/119100_119199/11913203/01.01.01_60/ts_11913203v010101p.pdf>
    pub fn initial_imprint<'p, P: AsnDigest<'p>, W: Work>(
        &mut self,
        provider: &'p P,
        algorithm: Algorithm,
        work: &W,
    ) -> InitialResult<InitialImprint<'p, P>, X, P::Error> {
        let resource = InitialError::Resource;
        let digest = || {
            work.charge_work(1).map_err(resource)?;
            let identity = provider
                .identity(algorithm)
                .ok_or(InitialError::Algorithm)?;
            SingleDigest::prepare(provider, identity, work, "xades.ers.imprint", 0)
                .map_err(InitialError::Digest)
        };
        let mut hashes = work.vector();
        hashes
            .try_reserve_exact(self.items.len())
            .map_err(resource)?;
        for source in self.sources() {
            let output = digest()?.run(source, work).map_err(InitialError::Object)?;
            let actual = output.as_bytes().len();
            if actual != algorithm.width() {
                return Err(InitialError::Digest(DigestError::OutputWidth {
                    expected: algorithm.width(),
                    actual,
                }));
            }
            hashes.try_push(output).map_err(resource)?;
        }
        // This object catalogue always includes SignedInfo and SignatureValue.
        debug_assert!(hashes.len() >= 2);
        hashes
            .try_sort_unstable_by(|left, right| {
                work.charge_work(algorithm.width() as u64)?;
                Ok::<_, MemoryError>(left.as_bytes().cmp(right.as_bytes()))
            })
            .map_err(|cause| resource(cause.into()))?;
        let root = digest()?
            .run(&mut Hashes(&hashes), work)
            .map_err(InitialError::Reduction)?;
        Ok(InitialImprint {
            hashes: hashes.into_owned(),
            root,
        })
    }
}

struct Hashes<'a, 'p, P: AsnDigest<'p>>(&'a [DigestOutput<'p, P>]);

impl<'p, P: AsnDigest<'p>> Source for Hashes<'_, 'p, P> {
    type Error = RangesError;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        for output in self.0 {
            work.charge_work(1).map_err(RangesError::Resource)?;
            receiver
                .write(output.as_bytes())
                .map_err(RangesError::Receiver)?;
        }
        Ok(())
    }
}
