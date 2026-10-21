//! Original ESS certificate bindings and signed validation-set restrictions.

use crate::attribute::same_encoding;
use crate::provider::{DigestAlgorithm, ImpliedDigest};
use crate::signer::{SignerInfo, required};
use crate::{Error, ErrorCode, Octets, Result, oid};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Integer, Reader, Span, Tag, universal};
use structured_pkix::general_name::{self, GeneralName};

mod check;
pub use check::{Binding, BindingError, Bindings};

/// The signed attribute's schema, not the CMS content digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// SHA-1 is mandatory in `ESSCertID` (RFC2634 §5.4.1).
    V1,
    /// `ESSCertIDv2` carries an algorithm or omits its SHA-256 default.
    V2,
}

impl Version {
    /// The attribute identifier that selects this schema.
    #[must_use]
    pub fn identifier(self) -> structured_asn1::Oid<'static> {
        match self {
            Self::V1 => oid::SIGNING_CERTIFICATE,
            Self::V2 => oid::SIGNING_CERTIFICATE_V2,
        }
    }
    fn field(self) -> &'static str {
        match self {
            Self::V1 => "signerInfo.signedAttrs.signingCertificate",
            Self::V2 => "signerInfo.signedAttrs.signingCertificateV2",
        }
    }
}

/// Optional issuerSerial is never silently discarded after a read failure.
#[derive(Debug)]
pub enum IssuerReading<'a> {
    /// The schema field was not written.
    Absent,
    /// Original names and serial, including a separately reported profile fault.
    Present(IssuerSerial<'a>),
    /// The original field was written but could not be interpreted uniquely.
    /// Its diagnostic is retained in the enclosing signing-certificate faults.
    Unreadable(Element<'a>),
}

/// Agreement of the optional signed issuer/serial restriction alone.
/// Hash agreement, retained faults and certificate trust remain separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerAgreement {
    /// No optional restriction was written; this says nothing about the hash.
    Unstated,
    /// A readable directoryName and serial identify this certificate's issuer.
    Matches,
    /// Readable written restrictions identify something else.
    Differs,
    /// The written restriction has no uniquely readable identity.
    Unreadable,
}

/// Original certificate issuer names and serial, without normalization/copying.
#[derive(Debug)]
pub struct IssuerSerial<'a> {
    names: OwnedVec<GeneralName<'a>>,
    serial: Integer<'a>,
    names_element: Element<'a>,
    element: Element<'a>,
}

impl<'a> IssuerSerial<'a> {
    /// Every written issuer name, in its original order.
    #[must_use]
    pub fn names(&self) -> &[GeneralName<'a>] {
        &self.names
    }
    /// Original serial-number contents, without re-encoding.
    #[must_use]
    pub fn serial(&self) -> Integer<'a> {
        self.serial
    }
    /// Exact original `GeneralNames` element for independently retained evidence.
    #[must_use]
    pub fn names_element(&self) -> &Element<'a> {
        &self.names_element
    }
    /// Original issuerSerial location.
    #[must_use]
    pub fn span(&self) -> Span {
        self.element.span()
    }

    fn matches_with<'c, 'p>(
        &self,
        certificate: &structured_pkix::Certificate<'c>,
        parent: &'p Reader<'_>,
        prepared: &mut Option<structured_pkix::Ordered<'c, structured_asn1::memory::Execution<'p>>>,
        field: &'static str,
        metadata_at: u64,
    ) -> Result<IssuerAgreement> {
        let execution = parent.execution();
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, field, metadata_at))?;
        let at = self.element.span().start;
        let serial = self.serial.as_bytes();
        let actual = certificate.tbs().serial().as_bytes();
        execution
            .charge_work(1 + serial.len().max(actual.len()) as u64)
            .map_err(|reason| Error::resource(reason, field, at))?;
        if serial != actual {
            return Ok(IssuerAgreement::Differs);
        }
        for name in &self.names {
            execution
                .charge_work(1)
                .map_err(|reason| Error::resource(reason, field, at))?;
            if let GeneralName::Directory(name) = name {
                let actual = match &*prepared {
                    Some(actual) => actual,
                    None => prepared.insert(
                        certificate
                            .tbs()
                            .issuer()
                            .ordered_in(parent)
                            .map_err(Error::pkix)?,
                    ),
                };
                let asked = name.ordered_in(parent).map_err(Error::pkix)?;
                if asked.order(actual, &execution).map_err(Error::pkix)?
                    == core::cmp::Ordering::Equal
                {
                    return Ok(IssuerAgreement::Matches);
                }
            }
        }
        Ok(IssuerAgreement::Differs)
    }
}

/// Original standalone ESS issuer hint and independently retained diagnostics.
///
/// This reads the `IssuerSerial` type referenced by RFC5035 §4 and by
/// `SigningCertificateV2/IssuerSerialV2` in ETSI EN319132-1 §5.2.2. It shares
/// the signing-certificate reader's kernel. A readable value with faults is
/// inspection data, not a conforming issuer assertion or certificate proof.
/// <https://www.rfc-editor.org/rfc/rfc5035#section-4>
#[derive(Debug)]
pub struct IssuerSerialReading<'a> {
    field: &'static str,
    value: IssuerSerial<'a>,
    faults: OwnedVec<Error>,
}

impl<'a> IssuerSerialReading<'a> {
    /// Reads the original element using its producing reader and current budget.
    ///
    /// `field` identifies the original enclosing protocol field. No replacement
    /// parser, manufactured signing-certificate container or re-encoding is
    /// needed. Syntax that cannot produce a reading and resource/processing
    /// refusals are errors; readable cardinality/trailing violations remain
    /// located faults. Every fault must be considered before acceptance.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>, field: &'static str) -> Result<Self> {
        let mut faults = parent.execution().vector();
        let value = read_issuer_serial(parent, element, field, &mut faults)?;
        Ok(Self {
            field,
            value,
            faults: faults.into_owned(),
        })
    }

    /// Original parsed issuer hint; obtaining it performs no new traversal.
    #[must_use]
    pub fn value(&self) -> &IssuerSerial<'a> {
        &self.value
    }

    /// All original diagnostics, distinct from resource/processing failures.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }

    /// Compares the original standalone hint through the existing ESS core.
    /// The current query funds comparison; original Name sources retain their
    /// lazy-decoding limits. It need not be the earlier hint/certificate session.
    /// Original diagnostics, digest/key binding, path and trust stay separate.
    pub fn matches_certificate(
        &self,
        certificate: &structured_pkix::Certificate<'_>,
        parent: &Reader<'_>,
    ) -> Result<IssuerAgreement> {
        self.value.matches_with(
            certificate,
            parent,
            &mut None,
            self.field,
            self.value.element.span().start,
        )
    }

    /// Moves the original view and diagnostic ownership without copying storage.
    ///
    /// The borrowed hint keeps its source lifetime; diagnostics independently
    /// retain their allocation charge until freed, even after the parser drops.
    #[must_use]
    pub fn into_parts(self) -> (IssuerSerial<'a>, OwnedVec<Error>) {
        (self.value, self.faults)
    }
}

/// One readable certificate identifier; hash verification is a separate step.
#[derive(Debug)]
pub struct CertificateId<'a> {
    digest: DigestAlgorithm<'a>,
    hashed: Octets<'a>,
    issuer: IssuerReading<'a>,
    element: Element<'a>,
    field: &'static str,
}

impl<'a> CertificateId<'a> {
    /// Original written identity or the exact schema-supplied identity.
    #[must_use]
    pub fn digest_algorithm(&self) -> DigestAlgorithm<'a> {
        self.digest
    }
    /// Logical certHash octets over the complete original DER certificate.
    #[must_use]
    pub fn hashed(&self) -> &Octets<'a> {
        &self.hashed
    }
    /// Absence, readable value and unreadable written field remain distinct.
    #[must_use]
    pub fn issuer_serial(&self) -> &IssuerReading<'a> {
        &self.issuer
    }
    /// Original identifier element, without serialization.
    #[must_use]
    pub fn element(&self) -> &Element<'a> {
        &self.element
    }

    /// Compares issuer/serial using the current producing query ceilings.
    ///
    /// The certificate can come from another retained source session; its
    /// canonical issuer is prepared once for this query, without re-decoding
    /// the certificate or creating a replacement Parser. Resource refusal is
    /// separate from Differs, Unstated and Unreadable. This does not check the
    /// certificate hash, signature, path, profile faults or trust.
    pub fn matches_issuer(
        &self,
        certificate: &structured_pkix::Certificate<'_>,
        parent: &Reader<'_>,
    ) -> Result<IssuerAgreement> {
        self.matches_issuer_with(certificate, parent, &mut None)
    }

    fn matches_issuer_with<'c, 'p>(
        &self,
        certificate: &structured_pkix::Certificate<'c>,
        parent: &'p Reader<'_>,
        prepared: &mut Option<structured_pkix::Ordered<'c, structured_asn1::memory::Execution<'p>>>,
    ) -> Result<IssuerAgreement> {
        if let IssuerReading::Present(issuer) = &self.issuer {
            return issuer.matches_with(
                certificate,
                parent,
                prepared,
                self.field,
                self.element.span().start,
            );
        }
        parent
            .execution()
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, self.field, self.element.span().start))?;
        Ok(match self.issuer {
            IssuerReading::Absent => IssuerAgreement::Unstated,
            _ => IssuerAgreement::Unreadable,
        })
    }
}

/// Later identifiers must remain in the signed restriction set even if unreadable.
#[derive(Debug)]
pub enum CertificateReading<'a> {
    /// Index into [`SigningCertificate::identifiers`], without one allocation
    /// per identifier or inflating every unreadable restriction's metadata.
    Read(usize),
    /// Original unreadable restriction; never treated as an absent restriction.
    Unreadable(Element<'a>),
}

/// One signing-certificate value, preserving the whole signed validation set.
/// V1 and V2 values are evaluated independently (RFC5035 §2).
#[derive(Debug)]
pub struct SigningCertificate<'a> {
    version: Version,
    certificates: OwnedVec<CertificateReading<'a>>,
    identifiers: OwnedVec<CertificateId<'a>>,
    policies: Option<Element<'a>>,
    faults: OwnedVec<Error>,
    element: Element<'a>,
}

/// Both independently evaluated ESS attributes, with placement/cardinality
/// diagnostics separate from certificate/hash/path checking.
#[derive(Debug)]
pub struct SigningAttributes<'a> {
    parser: &'a structured_asn1::Parser,
    signer: &'a [u8],
    signer_start: u64,
    signed_attributes_present: bool,
    v1: Option<SigningCertificate<'a>>,
    v2: Option<SigningCertificate<'a>>,
    faults: OwnedVec<Error>,
}

impl<'a> SigningAttributes<'a> {
    pub(crate) fn require_signer(
        &self,
        signer: &SignerInfo<'_>,
        parent: &Reader<'_>,
    ) -> Result<()> {
        signer.require_session(parent, "signerInfo.signedAttrs")?;
        // One Parser can read independent buffers at the same base. Physical
        // offsets alone therefore cannot identify the source of this reading;
        // compare the original borrowed encoding identity as well, in O(1).
        if !core::ptr::eq(self.parser, parent.parser())
            || self.signer_start != signer.span().start
            || !core::ptr::eq(self.signer, signer.as_bytes())
        {
            return Err(Error::pkix(structured_pkix::Error::new(
                structured_pkix::ErrorCode::ForeignReader,
                "signerInfo.signedAttrs",
                signer.span().start,
            )));
        }
        Ok(())
    }

    /// Reads the recognized signed fields using original value provenance.
    ///
    /// RFC5035 §§3/5 require one instance and one value in signed attributes.
    /// Byte-identical repeats retain one reading plus a cardinality fault;
    /// conflicting values refuse selection. Unsigned instances are retained
    /// as placement faults, never used as certificate bindings. No resolver,
    /// hash state, signature or caller payload is accessed during this step.
    /// <https://www.rfc-editor.org/rfc/rfc5035#section-3>
    pub fn read(signer: &SignerInfo<'a>, parent: &Reader<'a>) -> Result<Self> {
        signer.require_session(parent, "signerInfo.signedAttrs")?;
        let execution = parent.execution();
        execution.charge_work(1).map_err(|reason| {
            Error::resource(reason, "signerInfo.signedAttrs", signer.span().start)
        })?;
        let mut faults = execution.vector();
        if let Some(unsigned) = signer.unsigned_attributes() {
            for version in [Version::V1, Version::V2] {
                for result in unsigned.all_in(version.identifier(), parent) {
                    let attribute = result?;
                    let field = match version {
                        Version::V1 => "signerInfo.unsignedAttrs.signingCertificate",
                        Version::V2 => "signerInfo.unsignedAttrs.signingCertificateV2",
                    };
                    record(
                        Error::schema(ErrorCode::AttributePlacement, field, attribute.span().start),
                        &mut faults,
                        field,
                    )?;
                }
            }
        }
        let v1 = read_attribute(signer, parent, Version::V1, &mut faults)?;
        let v2 = read_attribute(signer, parent, Version::V2, &mut faults)?;
        if v1.is_none()
            && let Some(v2) = &v2
        {
            // RFC5035 §§1/2 retains mandatory V1 compatibility when SHA-1
            // is used for certificate identification. V2 is independent, not
            // a waiver of the companion attribute. This checks declared
            // identities, without granting the selected provider permission
            // to accept SHA-1 or bypassing parameter validation.
            // https://www.rfc-editor.org/rfc/rfc5035#section-2
            for identifier in v2.identifiers() {
                execution.charge_work(1).map_err(|reason| {
                    Error::resource(reason, Version::V2.field(), identifier.element.span().start)
                })?;
                if let DigestAlgorithm::Written(algorithm) = identifier.digest {
                    execution
                        .charge_work(
                            algorithm
                                .algorithm()
                                .as_bytes()
                                .len()
                                .min(oid::SHA1.as_bytes().len()) as u64,
                        )
                        .map_err(|reason| {
                            Error::resource(reason, Version::V2.field(), algorithm.offset())
                        })?;
                    if algorithm.algorithm() == oid::SHA1 {
                        record(
                            Error::schema(
                                ErrorCode::MissingField,
                                Version::V1.field(),
                                identifier.element.span().start,
                            ),
                            &mut faults,
                            Version::V1.field(),
                        )?;
                        break;
                    }
                }
            }
        }
        Ok(Self {
            parser: parent.parser(),
            signer: signer.as_bytes(),
            signer_start: signer.span().start,
            signed_attributes_present: signer.signed_attributes().is_some(),
            v1,
            v2,
            faults: faults.into_owned(),
        })
    }

    /// Whether any signed attributes existed, independently of ESS presence.
    #[must_use]
    pub fn signed_attributes_present(&self) -> bool {
        self.signed_attributes_present
    }
    /// Original V1 signer/path restrictions, when written.
    #[must_use]
    pub fn v1(&self) -> Option<&SigningCertificate<'a>> {
        self.v1.as_ref()
    }
    /// Independently evaluated original V2 signer/path restrictions.
    #[must_use]
    pub fn v2(&self) -> Option<&SigningCertificate<'a>> {
        self.v2.as_ref()
    }
    /// Placement and identical-repetition diagnostics; nested schema faults
    /// remain with each [`SigningCertificate::faults`] collection.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }
}

fn read_attribute<'a, W: Work>(
    signer: &SignerInfo<'a>,
    parent: &Reader<'a>,
    version: Version,
    faults: &mut OwnedVec<Error, W>,
) -> Result<Option<SigningCertificate<'a>>> {
    let Some(attributes) = signer.signed_attributes() else {
        return Ok(None);
    };
    let field = version.field();
    let mut first: Option<&crate::attribute::Attribute<'a>> = None;
    for result in attributes.all_in(version.identifier(), parent) {
        let attribute = result?;
        if let Some(earlier) = first {
            if !same_encoding(
                parent,
                earlier.as_bytes(),
                attribute.as_bytes(),
                field,
                attribute.span().start,
            )? {
                return Err(Error::schema(
                    ErrorCode::DuplicateAttribute,
                    field,
                    attribute.span().start,
                ));
            }
            record(
                Error::schema(ErrorCode::DuplicateAttribute, field, attribute.span().start),
                faults,
                field,
            )?;
        } else {
            first = Some(attribute);
        }
    }
    let Some(attribute) = first else {
        return Ok(None);
    };
    let Some(value) = attribute.values().first() else {
        return Err(Error::schema(
            ErrorCode::AttributeCardinality,
            field,
            attribute.span().start,
        ));
    };
    for extra in &attribute.values()[1..] {
        if !same_encoding(
            parent,
            value.as_bytes(),
            extra.as_bytes(),
            field,
            extra.span().start,
        )? {
            return Err(Error::schema(
                ErrorCode::AttributeCardinality,
                field,
                extra.span().start,
            ));
        }
        record(
            Error::schema(ErrorCode::AttributeCardinality, field, extra.span().start),
            faults,
            field,
        )?;
    }
    let mut reader = attribute
        .value_reader_in(0, parent, field)?
        .ok_or_else(|| Error::schema(ErrorCode::MissingField, field, attribute.span().start))?;
    let original = required(&mut reader, field)?;
    SigningCertificate::read(&reader, &original, version).map(Some)
}

impl<'a> SigningCertificate<'a> {
    /// Reads the original value with inherited depth/local and aggregate work.
    ///
    /// The first identifier must be readable to name the signer. Later malformed
    /// identifiers/policies remain original restrictions plus retained faults;
    /// no resource failure becomes a readable fault or an omitted restriction.
    /// This reading establishes neither certificate hash agreement nor trust.
    pub fn read(parent: &Reader<'a>, element: &Element<'a>, version: Version) -> Result<Self> {
        let field = version.field();
        require_sequence(element, field)?;
        let mut outer = parent
            .enter(element)
            .map_err(|error| Error::encoding(error, field))?;
        let certs = required(&mut outer, field)?;
        require_sequence(&certs, field)?;
        let mut list = outer
            .enter(&certs)
            .map_err(|error| Error::encoding(error, field))?;
        let execution = parent.execution();
        let mut faults = execution.vector();
        let mut certificates = execution.vector();
        let mut identifiers = execution.vector();
        let first = required(&mut list, field)?;
        let signer = read_identifier(&list, &first, version, &mut faults)?;
        identifiers
            .try_push(signer)
            .map_err(|reason| Error::resource(reason, field, first.span().start))?;
        certificates
            .try_push(CertificateReading::Read(0))
            .map_err(|reason| Error::resource(reason, field, first.span().start))?;
        while let Some(entry) = list
            .next_element()
            .map_err(|error| Error::encoding(error, field))?
        {
            let reading = match read_identifier(&list, &entry, version, &mut faults) {
                Ok(identifier) => {
                    let index = identifiers.len();
                    identifiers
                        .try_push(identifier)
                        .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
                    CertificateReading::Read(index)
                }
                Err(error) => {
                    record(error, &mut faults, field)?;
                    CertificateReading::Unreadable(entry)
                }
            };
            certificates
                .try_push(reading)
                .map_err(|reason| Error::resource(reason, field, entry.span().start))?;
        }
        let policies = outer
            .next_element()
            .map_err(|error| Error::encoding(error, field))?;
        if let Some(policies) = &policies
            && let Err(error) = validate_policies(&outer, policies, field)
        {
            record(error, &mut faults, field)?;
        }
        if !outer.is_empty() {
            record(
                Error::schema(ErrorCode::TrailingData, field, outer.offset()),
                &mut faults,
                field,
            )?;
        }
        Ok(Self {
            version,
            certificates: certificates.into_owned(),
            identifiers: identifiers.into_owned(),
            policies,
            faults: faults.into_owned(),
            element: *element,
        })
    }

    /// Which independently evaluated attribute selected this value.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }
    /// First signer identity and all subsequent signed restrictions in order.
    #[must_use]
    pub fn certificates(&self) -> &[CertificateReading<'a>] {
        &self.certificates
    }
    /// Flat readable identities referenced by the original-order catalogue.
    #[must_use]
    pub fn identifiers(&self) -> &[CertificateId<'a>] {
        &self.identifiers
    }
    /// The required first certificate identity, without a repeated lookup.
    #[must_use]
    pub fn signer(&self) -> &CertificateId<'a> {
        // read() refuses an unreadable/missing first identifier before
        // exposing this value; subsequent identities never move this slot.
        &self.identifiers[0]
    }
    /// Original optional policy terms, including any separately reported fault.
    #[must_use]
    pub fn policies(&self) -> Option<&Element<'a>> {
        self.policies.as_ref()
    }
    /// Readable schema/profile faults with original source locations.
    #[must_use]
    pub fn faults(&self) -> &[Error] {
        &self.faults
    }
    /// Original source element.
    #[must_use]
    pub fn element(&self) -> &Element<'a> {
        &self.element
    }
}

fn read_identifier<'a, W: Work>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    version: Version,
    faults: &mut OwnedVec<Error, W>,
) -> Result<CertificateId<'a>> {
    let field = version.field();
    require_sequence(element, field)?;
    let mut inside = parent
        .enter(element)
        .map_err(|error| Error::encoding(error, field))?;
    let mut next = required(&mut inside, field)?;
    // RFC2634 §5.4.1 mandates SHA-1 for V1. RFC5035 §4's ASN.1 DEFAULT
    // mandates SHA-256 for omitted V2 hashAlgorithm, not SHA-1 (the original
    // prose's SHA-1 description is corrected by erratum2364). These have no
    // encoded AlgorithmIdentifier, so do not fabricate DER/NULL parameters.
    // https://www.rfc-editor.org/rfc/rfc5035#section-4
    let mut digest = DigestAlgorithm::Implied {
        algorithm: match version {
            Version::V1 => ImpliedDigest::EssSha1,
            Version::V2 => ImpliedDigest::EssV2Sha256,
        },
        field,
        span: element.span(),
    };
    if version == Version::V2 && next.tag() == Tag::constructed(universal::SEQUENCE) {
        let algorithm =
            structured_pkix::algorithm::read(&inside, &next, field).map_err(Error::pkix)?;
        inside
            .charge(
                1 + algorithm
                    .algorithm()
                    .as_bytes()
                    .len()
                    .max(oid::SHA256.as_bytes().len()) as u64,
            )
            .map_err(|error| Error::encoding(error, field))?;
        // X.690 §11.5: DER omits only the exact ASN.1 default. Written
        // SHA-256 with NULL is not this absent-parameter default value;
        // selected-provider SHA-2 parameter rules remain a separate step.
        if algorithm.algorithm() == oid::SHA256 && algorithm.parameters().is_none() {
            record(
                Error::schema(ErrorCode::DefaultWritten, field, next.span().start),
                faults,
                field,
            )?;
        }
        digest = DigestAlgorithm::Written(algorithm);
        next = required(&mut inside, field)?;
    } else if version == Version::V2 && next.tag() == Tag::primitive(universal::OID) {
        let kind = inside
            .oid(&next)
            .map_err(|error| Error::encoding(error, field))?;
        inside
            .charge(1 + kind.as_bytes().len().max(oid::SHA256.as_bytes().len()) as u64)
            .map_err(|error| Error::encoding(error, field))?;
        // Recovery is not specified by ESS. The exact bare default OID has
        // the same one SHA-256 reading either as a malformed identifier or
        // extra data beside the default; any other bare OID is ambiguous.
        if kind != oid::SHA256 {
            return Err(Error::schema(
                ErrorCode::AttributeSyntax,
                field,
                next.span().start,
            ));
        }
        record(
            Error::schema(ErrorCode::AttributeSyntax, field, next.span().start),
            faults,
            field,
        )?;
        next = required(&mut inside, field)?;
    }
    let hashed = Octets::read(&inside, &next, field)?;
    let issuer = match inside
        .next_element()
        .map_err(|error| Error::encoding(error, field))?
    {
        None => IssuerReading::Absent,
        Some(issuer) => match read_issuer_serial(&inside, &issuer, field, faults) {
            Ok(value) => IssuerReading::Present(value),
            Err(error) => {
                record(error, faults, field)?;
                IssuerReading::Unreadable(issuer)
            }
        },
    };
    if !inside.is_empty() {
        record(
            Error::schema(ErrorCode::TrailingData, field, inside.offset()),
            faults,
            field,
        )?;
    }
    Ok(CertificateId {
        digest,
        hashed,
        issuer,
        element: *element,
        field,
    })
}

fn read_issuer_serial<'a, W: Work>(
    parent: &Reader<'a>,
    element: &Element<'a>,
    field: &'static str,
    faults: &mut OwnedVec<Error, W>,
) -> Result<IssuerSerial<'a>> {
    require_sequence(element, field)?;
    let mut inside = parent
        .enter(element)
        .map_err(|error| Error::encoding(error, field))?;
    let names_element = required(&mut inside, field)?;
    require_sequence(&names_element, field)?;
    let serial = inside
        .read_integer()
        .map_err(|error| Error::encoding(error, field))?;
    if !inside.is_empty() {
        record(
            Error::schema(ErrorCode::TrailingData, field, inside.offset()),
            faults,
            field,
        )?;
    }
    let mut list = inside
        .enter(&names_element)
        .map_err(|error| Error::encoding(error, field))?;
    let mut names = parent.execution().vector();
    while let Some(name) = list
        .next_element()
        .map_err(|error| Error::encoding(error, field))?
    {
        let value = general_name::read(&list, &name, field).map_err(Error::pkix)?;
        names
            .try_push(value)
            .map_err(|reason| Error::resource(reason, field, name.span().start))?;
    }
    // RFC5035 §4: public-key certificates require exactly their issuer in
    // the directoryName choice. Other readable names are retained as faults,
    // never collapsed into a different issuer or an absent optional field.
    // https://www.rfc-editor.org/rfc/rfc5035#section-4
    if !matches!(&*names, [GeneralName::Directory(_)]) {
        record(
            Error::schema(
                ErrorCode::AttributeSyntax,
                field,
                names_element.span().start,
            ),
            faults,
            field,
        )?;
    }
    Ok(IssuerSerial {
        names: names.into_owned(),
        serial,
        names_element,
        element: *element,
    })
}

fn record<W: Work>(
    error: Error,
    faults: &mut OwnedVec<Error, W>,
    field: &'static str,
) -> Result<()> {
    if error.is_terminal() {
        return Err(error);
    }
    let at = error.offset();
    faults
        .try_push(error)
        .map_err(|reason| Error::resource(reason, field, at))
}

fn require_sequence(element: &Element<'_>, field: &'static str) -> Result<()> {
    if element.tag() != Tag::constructed(universal::SEQUENCE) {
        return Err(Error::schema(
            ErrorCode::UnexpectedTag,
            field,
            element.span().start,
        ));
    }
    Ok(())
}

fn validate_policies(
    parent: &Reader<'_>,
    element: &Element<'_>,
    field: &'static str,
) -> Result<()> {
    require_sequence(element, field)?;
    let mut list = parent
        .enter(element)
        .map_err(|error| Error::encoding(error, field))?;
    while let Some(policy) = list
        .next_element()
        .map_err(|error| Error::encoding(error, field))?
    {
        require_sequence(&policy, field)?;
        let mut information = list
            .enter(&policy)
            .map_err(|error| Error::encoding(error, field))?;
        information
            .read_oid()
            .map_err(|error| Error::encoding(error, field))?;
        if let Some(qualifiers) = information
            .next_element()
            .map_err(|error| Error::encoding(error, field))?
        {
            require_sequence(&qualifiers, field)?;
            let mut members = information
                .enter(&qualifiers)
                .map_err(|error| Error::encoding(error, field))?;
            if members.is_empty() {
                return Err(Error::schema(
                    ErrorCode::AttributeSyntax,
                    field,
                    qualifiers.span().start,
                ));
            }
            while let Some(member) = members
                .next_element()
                .map_err(|error| Error::encoding(error, field))?
            {
                require_sequence(&member, field)?;
                let mut pair = members
                    .enter(&member)
                    .map_err(|error| Error::encoding(error, field))?;
                let kind = pair
                    .read_oid()
                    .map_err(|error| Error::encoding(error, field))?;
                let qualifier = required(&mut pair, field)?;
                let work = 2
                    + kind
                        .as_bytes()
                        .len()
                        .min(structured_pkix::oid::CPS_QUALIFIER.as_bytes().len())
                        as u64
                    + kind
                        .as_bytes()
                        .len()
                        .min(structured_pkix::oid::USER_NOTICE_QUALIFIER.as_bytes().len())
                        as u64;
                pair.charge(work)
                    .map_err(|error| Error::encoding(error, field))?;
                if (kind == structured_pkix::oid::CPS_QUALIFIER
                    || kind == structured_pkix::oid::USER_NOTICE_QUALIFIER)
                    && !structured_pkix::policy::qualifier_understood(&pair, kind, &qualifier)
                        .map_err(Error::pkix)?
                {
                    return Err(Error::schema(
                        ErrorCode::AttributeSyntax,
                        field,
                        qualifier.span().start,
                    ));
                }
                if !pair.is_empty() {
                    return Err(Error::schema(ErrorCode::TrailingData, field, pair.offset()));
                }
            }
        }
        if !information.is_empty() {
            return Err(Error::schema(
                ErrorCode::TrailingData,
                field,
                information.offset(),
            ));
        }
    }
    Ok(())
}
