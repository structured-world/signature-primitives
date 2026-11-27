//! Checked draft emission and original inputs for RFC 6283 renewals.

use super::{CanonicalInput, Record, XmlRecordXml, imprint};
use crate::{
    evidence::{EditPlan, Format, Placement, Renewal, SealingWriter, XML_ERS},
    produce::{Emit, Error},
};
use core::fmt::Write;
use structured_asn1::memory::Work;
use structured_cms::stream::{Receiver, Source};

/// Methods for a new XMLERS chain. Use an existing schema-compatible method
/// node when the algorithm has parameters, preserving the exact original node.
pub struct Methods<'a, N> {
    /// The digest method element's original identity, or its canonical URI.
    pub digest: Method<'a, N>,
    /// The canonicalization method's original identity, or its canonical URI.
    pub canonicalization: Method<'a, N>,
}

/// A wire algorithm or a complete method element supplied by the XML owner.
#[derive(Clone, Copy)]
pub enum Method<'a, N> {
    /// Algorithm URI for a method with no parameter children.
    Uri(&'a str),
    /// Copy this original XMLERS method, including all its parameters.
    Original(N),
}

/// A new RFC 6283 archive stamp in a new or existing chain.
pub struct Archive<'a, N> {
    /// A new chain requires both methods. Within-chain renewal uses the
    /// original chain methods and must supply `None`.
    pub methods: Option<Methods<'a, N>>,
    /// For a new seal, pass the sole digest of the protected group from
    /// `InitialImprint::root`. The original full per-object list is also
    /// accepted. Hash-tree renewal supplies the complete binary ascending list
    /// of object hashes and the prior-sequence hash. Within-chain timestamp
    /// renewal supplies an empty slice.
    pub first_hashes: &'a [&'a [u8]],
    /// Complete DER RFC 3161 token. The actual enclosure is verified after
    /// staging, before it can authorize committing this XML transaction.
    pub token: &'a [u8],
}

/// A replayable original renewal stream. It includes the protected validation
/// material already staged for the earlier timestamp, where applicable.
pub struct RenewalInput<'a, X: XmlRecordXml>(imprint::Prior<'a, X>);

impl<X: XmlRecordXml> Source for RenewalInput<'_, X> {
    type Error = super::ImprintError<X::Error, X::Id>;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        self.0.stream(receiver, work)
    }
}

impl<X: XmlRecordXml> Record<X> {
    /// Original preimage for issuing a renewal token, sharing the same replay
    /// as verification. Hash-tree renewal specifies the new chain's method
    /// and also hashes each original protected object separately.
    pub fn renewal_input<'a>(
        &'a self,
        xml: &'a X,
        method: RenewalMethod<X::Id>,
    ) -> Option<RenewalInput<'a, X>> {
        let (input, method) = match method {
            RenewalMethod::Timestamp => {
                let tail = self.chains().last()?;
                (
                    CanonicalInput::Timestamp(tail.stamps().last()?),
                    tail.canonicalization,
                )
            }
            RenewalMethod::HashTree(method) => (
                CanonicalInput::Sequence {
                    node: self.sequence(),
                    chains: self.chains(),
                },
                method,
            ),
        };
        Some(RenewalInput(imprint::Prior {
            xml,
            snapshot: self.snapshot(),
            method,
            input,
        }))
    }
}

/// Canonicalization selected by an RFC 6283 renewal.
#[derive(Clone, Copy)]
pub enum RenewalMethod<N> {
    /// Preserve the current chain's original canonicalization method.
    Timestamp,
    /// Use the new canonicalization method from this XML source.
    HashTree(N),
}

impl<N, D, G> EditPlan<N, D, G>
where
    N: Copy + Eq + structured_asn1::memory::HashWork,
    D: Copy + Eq,
    G: Copy + Eq,
{
    /// Stage a new XMLERS record or one constrained RFC 6283 renewal.
    /// The initial list may carry the `XAdES` group digest. Hash-tree renewal
    /// always carries the complete per-object and prior-sequence list.
    /// The original material preparation belongs to the unpublished XML
    /// transaction. Call `authorize_commit` with verified staged evidence.
    pub fn write_xml<B, W>(
        &self,
        writer: &mut B,
        archive: Archive<'_, N>,
        work: &W,
    ) -> Result<(), Error<B::Error>>
    where
        B: SealingWriter<Id = N, Document = D, Generation = G>,
        W: Work,
    {
        if self.format() != Format::Xml || archive.token.is_empty() {
            return Err(Error::Value("TimeStampToken"));
        }
        let renewal = match self.placement() {
            Placement::Renew(_, renewal) => Some(renewal),
            _ => None,
        };
        let new_chain = renewal != Some(Renewal::Timestamp);
        let invalid_list = match renewal {
            None => archive.first_hashes.is_empty(),
            Some(Renewal::HashTree) => archive.first_hashes.len() < 2,
            Some(Renewal::Timestamp) => !archive.first_hashes.is_empty(),
        };
        if new_chain != archive.methods.is_some() || invalid_list {
            return Err(Error::Value("ArchiveTimeStampChain"));
        }
        admit_hashes(archive.first_hashes, work)?;
        let mut emit = self.start(writer, work)?;
        let new_record = renewal.is_none();
        if new_record {
            emit.begin(XML_ERS, "EvidenceRecord")?;
            emit.attribute("Version", "1.0")?;
            emit.begin(XML_ERS, "ArchiveTimeStampSequence")?;
        }
        let order = self.xml_order.unwrap_or(1);
        if let Some(methods) = archive.methods {
            emit.begin(XML_ERS, "ArchiveTimeStampChain")?;
            emit.attribute("Order", Decimal::new(order).as_str())?;
            method(&mut emit, "DigestMethod", methods.digest)?;
            method(
                &mut emit,
                "CanonicalizationMethod",
                methods.canonicalization,
            )?;
        }
        emit_stamp(
            &mut emit,
            if new_chain { 1 } else { order },
            archive.first_hashes,
            archive.token,
        )?;
        if new_chain {
            emit.end()?;
        }
        if new_record {
            emit.end()?;
            emit.end()?;
        }
        self.finish(&mut emit)
    }
}

fn admit_hashes<E, W: Work>(hashes: &[&[u8]], work: &W) -> Result<(), Error<E>> {
    if let Some(first) = hashes.first() {
        let mut previous = *first;
        for &digest in hashes {
            work.charge_work(1).map_err(Error::Resource)?;
            if digest.is_empty() || digest.len() != first.len() {
                return Err(Error::Value("DigestValue"));
            }
            work.charge_work(digest.len() as u64)
                .map_err(Error::Resource)?;
            if previous > digest {
                return Err(Error::Value("HashTree"));
            }
            previous = digest;
        }
    }
    Ok(())
}

fn method<B: SealingWriter, W: Work>(
    emit: &mut Emit<'_, B, W>,
    name: &'static str,
    supplied: Method<'_, B::Id>,
) -> Result<(), Error<B::Error>> {
    match supplied {
        Method::Original(node) => emit.writer.method(node, emit.work).map_err(Error::Writer),
        Method::Uri(uri) => {
            emit.begin(XML_ERS, name)?;
            emit.attribute("Algorithm", uri)?;
            emit.end()
        }
    }
}

fn emit_stamp<B: SealingWriter, W: Work>(
    emit: &mut Emit<'_, B, W>,
    order: i32,
    hashes: &[&[u8]],
    token: &[u8],
) -> Result<(), Error<B::Error>> {
    emit.begin(XML_ERS, "ArchiveTimeStamp")?;
    emit.attribute("Order", Decimal::new(order).as_str())?;
    if !hashes.is_empty() {
        emit.begin(XML_ERS, "HashTree")?;
        emit.begin(XML_ERS, "Sequence")?;
        emit.attribute("Order", "1")?;
        for hash in hashes {
            emit.binary(XML_ERS, "DigestValue", hash)?;
        }
        emit.end()?;
        emit.end()?;
    }
    emit.begin(XML_ERS, "TimeStamp")?;
    emit.begin(XML_ERS, "TimeStampToken")?;
    emit.attribute("Type", "RFC3161")?;
    emit.event(crate::produce::Event::Binary(token))?;
    emit.end()?;
    emit.end()?;
    emit.end()
}

struct Decimal {
    bytes: [u8; 10],
    len: usize,
}

impl Decimal {
    fn new(value: i32) -> Self {
        debug_assert!(value > 0);
        let mut decimal = Self {
            bytes: [0; 10],
            len: 0,
        };
        write!(&mut decimal, "{value}").expect("positive i32 fits ten decimal digits");
        decimal
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).expect("decimal formatter emits ASCII")
    }
}

impl Write for Decimal {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        let end = self.len + value.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}
