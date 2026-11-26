//! Original RFC 4998 payload and verification via the common CMS ERS engine.

use super::{Format, ObjectError, Objects, Records};
use crate::{
    binary::{self, BinaryXml, Location},
    timestamp::TimestampXml,
    xml::Xml,
};
use structured_asn1::{Encoding, Reader, memory::Execution};
use structured_cms::{
    evidence::{
        EvidenceRecord, Membership, PriorSequence,
        verify::{self, Authorities, Decision, Historical},
    },
    provider::SignatureProvider,
    timestamp::TokenExtension,
};
use structured_pkix::temporal::{Instant, LeapTable};

/// Source/structure refusal before any cryptographic claim can be made.
#[derive(Debug)]
pub enum Asn1Error<E, N, D, G, V> {
    /// Source-bound member selection failed.
    Selection(super::Error<E, N>),
    /// The original group's protected objects could not be selected.
    Objects(ObjectError<E, N>),
    /// The original base64/reader/record or scoped visitor failed.
    Binary(binary::Error<E, Asn1ReadingError<V>, N, D, G>),
}

/// ASN.1 record grammar or scoped callback refusal.
#[derive(Debug)]
pub enum Asn1ReadingError<V> {
    /// Original parse failure in the decoded binary source.
    Record(structured_cms::Error),
    /// ETSI TS 119 132-3 §5.2.2.1 mandates an initial reduced hash tree.
    MissingTree,
    /// The declared encryption must be handled before a proof can be accepted.
    Encrypted,
    /// Original opaque visitor refusal.
    Visitor(V),
}

/// Scoped record result preserving the XML owner's original types.
pub type Asn1Result<T, X, V> = Result<
    T,
    Asn1Error<<X as Xml>::Error, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, V>,
>;

/// Original record check result, preserving common historical and source causes.
pub type Asn1Verification<'a, 'source, X, PE, RE, AE, HE> = Result<
    Asn1Report<'a, 'source, X>,
    verify::VerificationError<ObjectError<<X as Xml>::Error, <X as Xml>::Id>, PE, RE, AE, HE>,
>;

/// Complete RFC 4998 report tied to its actual XML enclosure.
pub struct Asn1Report<'a, 'source, X: Xml> {
    location: Location<X::Id, X::Document, X::Generation>,
    signature: X::Id,
    index: usize,
    report: verify::Report<'a, 'source>,
}

impl<'a, 'source, X: Xml> Asn1Report<'a, 'source, X> {
    /// Common original timestamp and renewal reports without rechecking.
    #[must_use]
    pub fn report(&self) -> &verify::Report<'a, 'source> {
        &self.report
    }

    /// Retain complete positive verification from this original enclosure.
    #[must_use]
    pub fn verified(&self) -> Option<super::Verified<X::Id, X::Document, X::Generation>> {
        let verified = self.report.verified()?;
        let record = verified.record();
        Some(super::Verified {
            location: self.location,
            signature: self.signature,
            index: self.index,
            chains: record.chains().len(),
            stamps: record.timestamps().len(),
            xml_tail: None,
        })
    }
}

/// Parsed original RFC 4998 member and its privately selected XML object group.
pub struct Asn1<'view, 'source, 'xml, X: TimestampXml> {
    location: Location<X::Id, X::Document, X::Generation>,
    signature: X::Id,
    index: usize,
    reader: &'view Reader<'source>,
    record: EvidenceRecord<'source>,
    objects: Objects<'xml, X>,
}

impl<'source, X: TimestampXml> Asn1<'_, 'source, '_, X> {
    /// Original member that supplied this exact binary record.
    #[must_use]
    pub fn location(&self) -> Location<X::Id, X::Document, X::Generation> {
        self.location
    }

    /// Original reader and record for certificate selection and carried material.
    #[must_use]
    pub fn original(&self) -> (&Reader<'source>, &EvidenceRecord<'source>) {
        (self.reader, &self.record)
    }

    /// Exact original prior sequence for issuing an ASN.1 hash-tree renewal.
    pub fn hash_tree_renewal(&self) -> structured_cms::Result<PriorSequence<'_, 'source>> {
        PriorSequence::for_renewal(&self.record, self.reader)
    }

    /// Previous token, including its original `SignedData`. Its bytes and
    /// producing reader are the input to RFC 4998 time-stamp renewal.
    #[must_use]
    pub fn timestamp_renewal(&self) -> Option<structured_cms::evidence::Original<'source>> {
        self.record
            .timestamps()
            .last()
            .map(structured_cms::evidence::ArchiveTimeStamp::timestamp_source)
    }

    /// Verify every timestamp and renewal against the original protected group.
    /// Trust, historical path/status and algorithm longevity are explicit caller
    /// decisions made for the exact selected actors through the common engine.
    #[expect(
        clippy::result_large_err,
        reason = "binary and XML origins and original causes survive refusal"
    )]
    pub fn verify<'a, P, PE, A, RE, HE>(
        &'a mut self,
        provider: &'a P,
        authorities: &'a A,
        utc: &LeapTable<'a>,
        reference: Instant,
        recognizes: impl FnMut(usize, &TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
        historical: impl FnMut(Historical<'_, 'a>, &Execution<'_>) -> Result<Decision, HE>,
    ) -> Asn1Verification<'a, 'source, X, PE, RE, A::Error, HE>
    where
        'source: 'a,
        P: for<'operation> SignatureProvider<'operation, Error = PE>,
        A: Authorities<'source>,
    {
        let report = self.record.verify(
            provider,
            self.reader,
            authorities,
            utc,
            reference,
            self.objects.sources(),
            Membership::Group,
            recognizes,
            historical,
        )?;
        Ok(Asn1Report {
            location: self.location,
            signature: self.signature,
            index: self.index,
            report,
        })
    }
}

impl<X: TimestampXml + BinaryXml> Records<'_, X> {
    /// Decode one original ASN.1 member, keeping its decoded source and common
    /// verification inside the visitor. Encoded storage cannot escape by borrow.
    pub fn with_asn1<'xml, T, V>(
        &self,
        xml: &'xml X,
        index: usize,
        operation: &Reader<'_>,
        visitor: impl for<'view, 'source> FnOnce(Asn1<'view, 'source, 'xml, X>) -> Result<T, V>,
    ) -> Asn1Result<T, X, V> {
        let member = self
            .members
            .get(index)
            .ok_or(Asn1Error::Selection(super::Error::Index(index)))?;
        if self.format != Some(Format::Asn1) {
            return Err(Asn1Error::Selection(super::Error::Unexpected(member.node)));
        }
        let location = Location {
            snapshot: self.snapshot(),
            node: member.node,
        };
        let objects = self
            .objects(xml, index, &operation.execution())
            .map_err(Asn1Error::Objects)?;
        // RFC 4998 §5.2 requires DER for the renewal preimage, not for the
        // enclosure. The common engine projects the original prefix into DER.
        // https://www.rfc-editor.org/rfc/rfc4998.html#section-5.2
        binary::with_reader_as(xml, location, operation, Encoding::Ber, |reader| {
            let record = EvidenceRecord::read_from(reader).map_err(Asn1ReadingError::Record)?;
            if record.encryption_info().is_some() {
                return Err(Asn1ReadingError::Encrypted);
            }
            if record.timestamps()[0].reduced_tree().is_none() {
                return Err(Asn1ReadingError::MissingTree);
            }
            visitor(Asn1 {
                location,
                signature: self.signature(),
                index,
                reader,
                record,
                objects,
            })
            .map_err(Asn1ReadingError::Visitor)
        })
        .map_err(Asn1Error::Binary)
    }
}
