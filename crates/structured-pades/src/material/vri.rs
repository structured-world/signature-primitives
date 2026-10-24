//! Normative VRI naming over the complete original decoded Contents value.

use crate::{
    container::Container,
    error::{Error, ErrorKind},
    model::admit,
};
use structured_asn1::memory::Work;
use structured_cms::digest::{DigestBatch, DigestError, PassError};
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
pub(super) mod sources;
mod status;
pub use sources::{Association, Associations, SourceError};
pub use status::{StatusBinding, StatusError};

/// One exact signature VRI selected by the normative whole-Contents name.
/// The actual parsed historical owner and root container cannot be replaced
/// with caller-supplied signature octets or another VRI's timestamp.
pub struct Binding<'b, 'v, 'a, 's, D, G> {
    parsed: &'b super::Parsed<'v, 's, D, G>,
    root: &'b Container<'a, 's, D, G>,
    vri: &'b super::Vri,
}

impl<'v, 's, D: Copy + Eq, G: Copy + Eq> super::Parsed<'v, 's, D, G> {
    /// Selects this signature's actual optional VRI. A named VRI for another
    /// signature remains in the source census but cannot bind to this root.
    pub fn bind_signature_vri<'b, 'a, 'p, P: AsnDigest<'p>>(
        &'b self,
        root: &'b Container<'a, 's, D, G>,
        provider: &'p P,
        operation: &impl Work,
    ) -> Result<Option<Binding<'b, 'v, 'a, 's, D, G>>, BindingError<P::Error>> {
        let signature = root.signature();
        let owner = signature.owner();
        let location = signature.location();
        let work = owner.value.session.query(operation);
        admit(&work, location, 1).map_err(BindingError::Pdf)?;
        if !core::ptr::eq(owner.value.session, self.owner.session)
            || owner.value.stamp != self.owner.stamp
        {
            return Err(BindingError::Pdf(Error {
                kind: ErrorKind::Foreign,
                location,
            }));
        }
        if self.owner.vri.is_empty() {
            return Ok(None);
        }
        let name = root
            .vri_name(provider, &work)
            .map_err(BindingError::Name)?
            .ok_or(BindingError::UnsupportedName)?;
        let matched = self.owner.vri_names.get(&name, &work).map_err(|cause| {
            BindingError::Pdf(Error {
                kind: ErrorKind::Resource(cause),
                location,
            })
        })?;
        Ok(matched.map(|&ordinal| Binding {
            parsed: self,
            root,
            vri: &self.owner.vri[ordinal],
        }))
    }
}

/// Source/refusal versus selected-provider inability to name an actual VRI.
#[derive(Debug)]
pub enum BindingError<E> {
    /// Original producing/current PDF scope refused.
    Pdf(Error),
    /// Whole original Contents hashing failed with its unchanged cause.
    Name(NameError<E>),
    /// Selected provider does not expose the prescribed SHA-1 identity.
    UnsupportedName,
}

/// Located original input/profile/provider failure of an actual VRI TS.
#[derive(Debug)]
pub enum TimestampError<'a, P, R> {
    /// Original PDF association or original/current resource refusal.
    Pdf(Error),
    /// Original unreadable carried value; no second parse is attempted.
    Material {
        /// Physical stream enclosing the logical carried refusal.
        location: crate::source::Location,
        /// Exact first-read cause, including its logical source coordinates.
        cause: &'a super::MaterialError,
    },
    /// Original carried reader refused before timestamp/provider execution.
    Encoding(structured_asn1::Error),
    /// Common timestamp check preserves the original opaque/source cause.
    Check(
        structured_cms::timestamp::ProfileCheckError<
            structured_cms::octets::SourceError,
            P,
            R,
            structured_cades::Error,
        >,
    ),
}

/// Actual signature-octet imprint, token mathematics and selected TSA facts.
pub struct Time<'q, 'certificate, D, G> {
    checks: structured_cms::timestamp::CheckedTimestamp<'q>,
    certificate: &'q structured_pkix::Certificate<'certificate>,
    key: structured_pkix::path::WorkingKey<'certificate>,
    snapshot: structured_ltv::source::Snapshot<D, G>,
    root: crate::timestamp::Node,
    property: crate::timestamp::Node,
    token: crate::timestamp::Node,
    session: &'q crate::Session,
}
impl<'q, 'd, D: Copy, G: Copy> Time<'q, 'd, D, G> {
    /// Complete original common facts, independently of path/trust acceptance.
    #[must_use]
    pub fn checks(&self) -> &structured_cms::timestamp::CheckedTimestamp<'q> {
        &self.checks
    }
    /// Issues a validation-data actor only for actual successful common
    /// evidence. This receipt asserts neither DSS coverage nor trusted time.
    pub fn into_actor(
        self,
    ) -> Option<
        structured_ltv::timestamp::CheckedActor<
            'q,
            'd,
            crate::timestamp::Node,
            D,
            G,
            crate::timestamp::Pades,
        >,
    > {
        let root = self.root;
        self.issue(root)
    }
    fn issue(
        self,
        root: crate::timestamp::Node,
    ) -> Option<
        structured_ltv::timestamp::CheckedActor<
            'q,
            'd,
            crate::timestamp::Node,
            D,
            G,
            crate::timestamp::Pades,
        >,
    > {
        let evidence = self.checks.into_evidence()?;
        let verified = structured_ltv::timestamp::Verified::new(
            crate::timestamp::ISSUER,
            structured_ltv::source::Location {
                snapshot: self.snapshot,
                node: self.token,
            },
            root,
            self.property,
            structured_ltv::timestamp::Purpose::ValidationData,
            evidence,
        );
        Some(structured_ltv::timestamp::CheckedActor::new(
            crate::timestamp::ISSUER,
            verified,
            self.certificate,
            self.key,
        ))
    }
}
impl<'q, 'd, D: Copy + Eq, G: Copy + Eq> Time<'q, 'd, D, G> {
    /// Retains an independently checked VRI TSA as a historical obligation of
    /// another signature in the SAME original PDF. This changes only the LTV
    /// census namespace; it does not assert coverage of that other signature.
    pub fn into_historical_actor(
        self,
        root: crate::signature::Signature<'_, '_, D, G>,
        operation: &impl Work,
    ) -> crate::Result<
        Option<
            structured_ltv::timestamp::CheckedActor<
                'q,
                'd,
                crate::timestamp::Node,
                D,
                G,
                crate::timestamp::Pades,
            >,
        >,
    > {
        let work = self.session.query(operation);
        let location = root.location();
        admit(&work, location, 1)?;
        if !core::ptr::eq(self.session, root.owner().value.session)
            || self.snapshot != root.owner().value.stamp.snapshot
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            });
        }
        Ok(self.issue(crate::timestamp::Node::of(location)))
    }
}

impl<'v, D: Copy + Eq, G: Copy + Eq> Binding<'_, 'v, '_, '_, D, G> {
    /// Actual matching original VRI, preserving its independent TU/TS method.
    #[must_use]
    pub fn vri(&self) -> &super::Vri {
        self.vri
    }

    /// Checks the existing parsed TS over the root CMS encryptedDigest
    /// content octets, not the complete CMS value, PDF bytes or VRI name.
    /// EN319142-1 §5.4.2.3 note1 defines this exact input. A TU-only or
    /// subsequent-DTS method returns None without invoking crypto callbacks.
    /// <https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
    #[expect(
        clippy::result_large_err,
        reason = "the common scoped timestamp error retains its original map, provider cause and enclosing material source without an error allocation"
    )]
    pub fn check_timestamp<'q, 'certificate, P, PE, RE>(
        &'q self,
        root: &'q structured_cms::SignedData<'_>,
        parent: &'q structured_asn1::Reader<'q>,
        provider: &'q P,
        context: &'q structured_cms::timestamp::CheckContext<'certificate, 'q>,
        recognizes: impl FnMut(
            &structured_cms::timestamp::TokenExtension<'_>,
            &structured_asn1::memory::Execution<'_>,
        ) -> Result<bool, RE>,
    ) -> Result<Option<Time<'q, 'certificate, D, G>>, TimestampError<'q, PE, RE>>
    where
        'v: 'q,
        'certificate: 'q,
        P: for<'scope> structured_cms::provider::SignatureProvider<'scope, Error = PE>,
    {
        let execution = parent.execution();
        let work = self.parsed.owner.session.query(&execution);
        let location = self.vri.location;
        admit(&work, location, 1).map_err(TimestampError::Pdf)?;
        self.root
            .require(root, parent)
            .map_err(TimestampError::Pdf)?;
        if root.signers().len() != 1 {
            return Err(TimestampError::Pdf(Error {
                kind: ErrorKind::Syntax(crate::error::Syntax::Container),
                location,
            }));
        }
        let Some(ordinal) = self.vri.timestamp else {
            return Ok(None);
        };
        let item = &self.parsed.owner.items[ordinal];
        let token = match &self.parsed.values[ordinal] {
            super::Value::Timestamp(value) => &value.token,
            super::Value::Unreadable(cause) => {
                return Err(TimestampError::Material {
                    location: item.location,
                    cause,
                });
            }
            _ => {
                return Err(TimestampError::Pdf(Error {
                    kind: ErrorKind::Foreign,
                    location,
                }));
            }
        };
        let reader = item
            .session
            .carried(item.as_bytes(), &parent.execution())
            .map_err(TimestampError::Encoding)?;
        let mut input = root.signers()[0].signature();
        let checks = token
            .check_historical_input_with_profile(
                provider,
                &reader,
                context,
                &mut structured_cms::timestamp::RawInput::new(&mut input),
                recognizes,
                |input| crate::timestamp::profile(&input),
            )
            .map_err(TimestampError::Check)?;
        Ok(Some(Time {
            checks,
            certificate: context.certificate,
            key: context.key,
            snapshot: self.parsed.owner.stamp.snapshot,
            root: crate::timestamp::Node::of(self.root.signature().location()),
            property: crate::timestamp::Node::dss(self.vri.location, self.parsed.owner.revision),
            token: crate::timestamp::Node::dss(item.location, self.parsed.owner.revision),
            session: self.parsed.owner.session,
        }))
    }
}

/// Uppercase hexadecimal SHA-1 name over the prescribed original input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Name(pub(super) [u8; 40]);
impl structured_asn1::memory::HashWork for Name {
    fn hash_work(&self) -> Result<u64, structured_asn1::memory::MemoryError> {
        Ok(41)
    }
}
impl Name {
    /// Exact decoded PDF name bytes, without a slash or alternative casing.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 40] {
        &self.0
    }
}

/// Original resource, provider or digest-output contract failure.
#[derive(Debug)]
pub enum NameError<E> {
    /// The original status signature is not a whole-octet BIT STRING.
    PaddedSignature,
    /// Original PDF source/current operation refused.
    Pdf(Error),
    /// Original digest preparation or memo query failed.
    Digest(DigestError<E>),
    /// Original complete Contents pass/provider failure.
    Pass(PassError<structured_cms::stream::RangesError, E>),
    /// Selected SHA-1 backend returned an inconsistent output width.
    Width(usize),
    /// The successful batch lost its single prepared request.
    LostRequest,
}

impl<D: Copy + Eq, G: Copy + Eq> Container<'_, '_, D, G> {
    /// EN319142-1 §5.4.2.2(a) hashes all decoded Contents bytes, INCLUDING its
    /// unused padding, not just the parsed DER extent. SHA-1 here identifies
    /// a VRI dictionary; it does not grant a signature-algorithm permission.
    /// <https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
    pub fn vri_name<'p, P: AsnDigest<'p>, W: Work>(
        &self,
        provider: &'p P,
        operation: &W,
    ) -> Result<Option<Name>, NameError<P::Error>> {
        let location = self.signature().contents();
        let work = self.signature().owner().value.session.query(operation);
        name_for_ranges(provider, &mut [self.contents()], &work, location)
    }
}

fn name_for_ranges<'p, P: AsnDigest<'p>, const N: usize>(
    provider: &'p P,
    ranges: &mut [&[u8]; N],
    work: &impl Work,
    location: crate::source::Location,
) -> Result<Option<Name>, NameError<P::Error>> {
    admit(work, location, 1).map_err(NameError::Pdf)?;
    let Some(identity) = provider.identity(Algorithm::Sha1) else {
        return Ok(None);
    };
    let mut identities = work.vector();
    identities.try_push(identity).map_err(|cause| {
        NameError::Pdf(Error {
            kind: ErrorKind::Resource(cause),
            location,
        })
    })?;
    let batch = DigestBatch::prepare(
        provider,
        identities.into_owned(),
        work,
        "pades.vri",
        location.span().start,
    )
    .map_err(NameError::Digest)?;
    let memo = batch.run(ranges, work).map_err(NameError::Pass)?;
    let output = memo
        .for_request(0, work)
        .map_err(NameError::Digest)?
        .ok_or(NameError::LostRequest)?;
    let bytes = output.as_bytes();
    if bytes.len() != 20 {
        return Err(NameError::Width(bytes.len()));
    }
    admit(work, location, 40).map_err(NameError::Pdf)?;
    let mut name = [0; 40];
    for (pair, byte) in name.as_chunks_mut::<2>().0.iter_mut().zip(bytes.iter()) {
        pair[0] = b"0123456789ABCDEF"[usize::from(byte >> 4)];
        pair[1] = b"0123456789ABCDEF"[usize::from(byte & 15)];
    }
    Ok(Some(Name(name)))
}
