//! Complete document timestamp checks over their original PDF `ByteRange`.

use crate::{
    arena::Kind,
    bytes::Form,
    container::Container,
    document::Document,
    error::{Error, ErrorKind, ReadFailure, Syntax},
    model::{admit, get, unsigned},
    range::RangeSource,
    signature::{Coverage, CoveredError, Signature, SubFilter},
    source::Location,
};
use structured_asn1::{
    Reader, Span,
    memory::{Execution, HashWork, MemoryError, Work},
};
use structured_cms::{
    provider::SignatureProvider,
    timestamp::{
        AsyncRawInput, CheckContext, CheckedTimestamp, ProfileCheckError, ProfileFailure,
        ProfileSource, Token, TokenExtension,
    },
};
use structured_ltv::{
    source::Location as Original,
    timestamp::{CheckedActor, Purpose, Verified},
};
use structured_pkix::{Certificate, path::WorkingKey};

pub mod coverage;
mod requirements;
pub mod sources;
pub use requirements::{DocumentTimestamp, Requirements, VriTimestamp};

/// Original PDF node identity, retaining decoded and inner CMS domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    carrier: Location,
    member: Member,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Member {
    Pdf,
    Cms(Span),
    MissingContents,
    Dss(usize),
}
impl Node {
    /// Original physical enclosure, without logical-offset fabrication.
    #[must_use]
    pub fn span(self) -> Span {
        self.carrier.enclosing()
    }
    /// Original PDF coordinate domain, including a decoded object's identity.
    #[must_use]
    pub fn pdf_location(self) -> Location {
        self.carrier
    }
    /// Optional original CMS coordinates inside the physical PDF enclosure.
    /// These are logical carried-source offsets, not contiguous file offsets.
    #[must_use]
    pub fn cms_span(self) -> Option<Span> {
        match self.member {
            Member::Cms(span) => Some(span),
            Member::Pdf | Member::MissingContents | Member::Dss(_) => None,
        }
    }
    /// A source occurrence required Contents but contained no such value.
    #[must_use]
    pub fn is_missing_contents(self) -> bool {
        self.member == Member::MissingContents
    }
    /// Historical DSS interpretation window, including all indirect stream
    /// controls and dictionary/xref placement. Body bytes alone are not proof.
    #[must_use]
    pub fn material_revision(self) -> Option<usize> {
        match self.member {
            Member::Dss(revision) => Some(revision),
            _ => None,
        }
    }
    pub(crate) fn of(location: Location) -> Self {
        Self {
            carrier: location,
            member: Member::Pdf,
        }
    }
    pub(crate) fn missing_contents(carrier: Location) -> Self {
        Self {
            carrier,
            member: Member::MissingContents,
        }
    }
    pub(crate) fn dss(carrier: Location, revision: usize) -> Self {
        Self {
            carrier,
            member: Member::Dss(revision),
        }
    }
    pub(crate) fn inside(carrier: Location, member: structured_cades::source::Node) -> Self {
        Self {
            carrier,
            member: Member::Cms(member.span()),
        }
    }
}
impl HashWork for Node {
    fn hash_work(&self) -> Result<u64, MemoryError> {
        Ok(match (self.carrier.source(), self.member) {
            (crate::source::Source::File, Member::Pdf | Member::MissingContents) => 4,
            (crate::source::Source::File, Member::Cms(_)) => 6,
            (crate::source::Source::Decoded { .. }, Member::Pdf | Member::MissingContents) => 8,
            (crate::source::Source::Decoded { .. }, Member::Cms(_)) => 10,
            (crate::source::Source::File, Member::Dss(_)) => 5,
            (crate::source::Source::Decoded { .. }, Member::Dss(_)) => 9,
        })
    }
}
impl core::hash::Hash for Node {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        match self.carrier.source() {
            crate::source::Source::File => 0_u8.hash(state),
            crate::source::Source::Decoded {
                stream,
                revision,
                stage,
            } => {
                1_u8.hash(state);
                stream.start.hash(state);
                stream.length.hash(state);
                revision.hash(state);
                stage.hash(state);
            }
        }
        self.carrier.span().start.hash(state);
        self.carrier.span().length.hash(state);
        match self.member {
            Member::Pdf => 0_u8.hash(state),
            Member::Cms(span) => {
                1_u8.hash(state);
                span.start.hash(state);
                span.length.hash(state);
            }
            Member::MissingContents => 2_u8.hash(state),
            Member::Dss(revision) => {
                3_u8.hash(state);
                revision.hash(state);
            }
        }
    }
}

/// Issuer boundary for PDF-derived LTV evidence; callers cannot mint this value.
pub struct Pades {
    _private: (),
}
pub(crate) const ISSUER: Pades = Pades { _private: () };

pub(crate) fn profile(
    input: &structured_cms::timestamp::ProfileInput<'_, '_, '_, '_>,
) -> Result<(), ProfileFailure<structured_cades::Error>> {
    // EN319142-1 §6.2.1 excludes MD5 for both token-signature and imprint
    // hashing. VRI TS and document TS share this exact pre-provider rule.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf
    let fail = |source, cause| ProfileFailure { source, cause };
    let md5 = structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 2, 5]);
    input
        .parent
        .charge(
            1 + input
                .token
                .signer()
                .digest_algorithm()
                .algorithm()
                .as_bytes()
                .len() as u64,
        )
        .map_err(|cause| {
            fail(
                ProfileSource::Envelope,
                structured_cades::Error::Encoding {
                    field: "pades.timestamp",
                    cause,
                },
            )
        })?;
    if input.token.signer().digest_algorithm().algorithm() == md5 {
        return Err(fail(
            ProfileSource::Envelope,
            structured_cades::Error::Syntax {
                code: structured_cms::ErrorCode::InvalidLocation,
                field: "pades.timestamp.md5",
                at: input.token.signer().span().start,
            },
        ));
    }
    if let structured_cms::timestamp::HashAlgorithmReading::Identifier(algorithm) =
        input.info.imprint().algorithm()
    {
        input
            .reader
            .charge(1 + algorithm.algorithm().as_bytes().len() as u64)
            .map_err(|cause| {
                fail(
                    ProfileSource::Information,
                    structured_cades::Error::Encoding {
                        field: "pades.timestamp",
                        cause,
                    },
                )
            })?;
        if algorithm.algorithm() == md5 {
            return Err(fail(
                ProfileSource::Information,
                structured_cades::Error::Syntax {
                    code: structured_cms::ErrorCode::InvalidLocation,
                    field: "pades.timestamp.md5",
                    at: input.info.imprint().span().start,
                },
            ));
        }
    }
    Ok(())
}

/// Original PDF/profile or common timestamp execution refusal.
#[derive(Debug)]
pub enum TimestampError<E, P, R> {
    /// Original PDF source/profile/provenance failure.
    Pdf(ReadFailure<E>),
    /// Complete common timestamp/profile check failed with its original cause.
    Check(ProfileCheckError<CoveredError<E>, P, R, structured_cades::Error>),
}

/// Complete original document timestamp answers and their exact selected TSA.
/// Negative answers remain visible and cannot expose a successful actor.
pub struct DocumentTime<'q, 'a, 's, 'd, D, G> {
    signature: Signature<'a, 's, D, G>,
    checks: CheckedTimestamp<'q>,
    certificate: &'q Certificate<'d>,
    key: WorkingKey<'d>,
}

impl<'q, 'a, 's, 'd, D: Copy + Eq, G: Copy + Eq> DocumentTime<'q, 'a, 's, 'd, D, G> {
    /// Original complete token facts, independently of trust/path acceptance.
    #[must_use]
    pub fn checks(&self) -> &CheckedTimestamp<'q> {
        &self.checks
    }
    /// Actual timestamp signature dictionary, not a replacement caller span.
    #[must_use]
    pub fn signature(&self) -> Signature<'a, 's, D, G> {
        self.signature
    }

    /// Retains this timestamp's actual TSA and evidence only when its checked
    /// original ranges cover the requested signature's original Contents.
    /// The LTV receipt's purpose is archival; trusted-time selection remains
    /// separate from the fact that the complete earlier signature is covered.
    pub fn into_actor(
        self,
        covered: Signature<'_, 's, D, G>,
        operation: &impl Work,
    ) -> crate::Result<Option<CheckedActor<'q, 'd, Node, D, G, Pades>>> {
        if !self.associated(covered, operation)? {
            return Ok(None);
        }
        let location = self.signature.location();
        let owner = self.signature.owner();
        let work = owner.value.session.query(operation);
        let Coverage::Revision(archive) = self.signature.coverage() else {
            return Ok(None);
        };
        let Coverage::Revision(subject) = covered.coverage() else {
            return Ok(None);
        };
        if subject > archive || covered.contents().source() != crate::source::Source::File {
            return Ok(None);
        }
        let needed = covered.contents().span();
        let mut complete = false;
        for span in self.signature.ranges() {
            admit(&work, location, 1)?;
            if span.start <= needed.start
                && span.start + span.length >= needed.start + needed.length
            {
                complete = true;
                break;
            }
        }
        if !complete {
            return Ok(None);
        }
        Ok(self.issue(covered))
    }

    /// Retains an earlier DTS authority as a historical obligation of the same
    /// original document. This does NOT claim coverage of the selected root;
    /// B-T selection separately checks the actual original `ByteRange`.
    pub fn into_historical_actor(
        self,
        root: Signature<'_, 's, D, G>,
        operation: &impl Work,
    ) -> crate::Result<Option<CheckedActor<'q, 'd, Node, D, G, Pades>>> {
        if !self.associated(root, operation)? {
            return Ok(None);
        }
        Ok(self.issue(root))
    }

    fn associated(
        &self,
        root: Signature<'_, 's, D, G>,
        operation: &impl Work,
    ) -> crate::Result<bool> {
        let owner = self.signature.owner();
        let target = root.owner();
        let work = owner.value.session.query(operation);
        let location = self.signature.location();
        admit(&work, location, 1)?;
        if !core::ptr::eq(owner.value.session, target.value.session)
            || owner.value.stamp != target.value.stamp
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            });
        }
        Ok(matches!(self.signature.coverage(), Coverage::Revision(_))
            && matches!(root.coverage(), Coverage::Revision(_)))
    }

    fn issue(
        self,
        covered: Signature<'_, 's, D, G>,
    ) -> Option<CheckedActor<'q, 'd, Node, D, G, Pades>> {
        let location = self.signature.location();
        let owner = self.signature.owner();
        let evidence = self.checks.into_evidence()?;
        let property = Node::of(location);
        let verified = Verified::new(
            ISSUER,
            Original {
                snapshot: owner.value.stamp.snapshot,
                node: Node::of(self.signature.contents()),
            },
            Node::of(covered.location()),
            property,
            Purpose::Archive,
            evidence,
        );
        Some(CheckedActor::new(
            ISSUER,
            verified,
            self.certificate,
            self.key,
        ))
    }
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// Applies the original PDF DTS declaration before provider callbacks,
    /// then verifies the original carried token over asynchronous file ranges.
    /// EN319142-1 §§5.4.3/6.3 requires exact whole-revision coverage and forbids
    /// Cert/Reference/Changes/R/authentication metadata on this dictionary.
    /// <https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf>
    ///
    /// # Panics
    /// Panics if the inspected timestamp loses its original `Contents` member.
    #[expect(
        clippy::result_large_err,
        reason = "timestamp and profile failures retain original mapped context and opaque causes without an error-path allocation"
    )]
    pub async fn check_timestamp<'q, 'a, 'token, 'certificate, P, PE, RE>(
        &'q self,
        container: &'q Container<'a, 's, S::Document, S::Generation>,
        token: &'q Token<'token>,
        provider: &'q P,
        parent: &Reader<'q>,
        context: &'q CheckContext<'certificate, 'q>,
        recognizes: impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<
        DocumentTime<'q, 'a, 's, 'certificate, S::Document, S::Generation>,
        TimestampError<S::Error, PE, RE>,
    >
    where
        'token: 'q,
        'certificate: 'q,
        's: 'q,
        'a: 'q,
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        let pdf = TimestampError::Pdf;
        let signature = container.signature();
        let location = signature.location();
        let work = parent.execution();
        container
            .require(token.message(), parent)
            .map_err(|cause| pdf(cause.into()))?;
        self.check(&work, location)
            .map_err(|cause| pdf(cause.into()))?;
        let malformed = malformed_timestamp::<S::Error, PE, RE>;
        if !signature.is_document_timestamp()
            || signature.sub_filter() != Some(SubFilter::Rfc3161)
            || !matches!(signature.coverage(), Coverage::Revision(_))
        {
            return Err(malformed(location));
        }
        let reading = signature.owner();
        let arena = &reading.value.arena;
        let node = signature.node();
        crate::direct::visit(arena, node, &work, |location| Err(malformed(location))).map_err(
            |cause| match cause {
                crate::direct::VisitError::Processing(cause) => pdf(cause.into()),
                crate::direct::VisitError::Callback(cause) => cause,
            },
        )?;
        let filter = get(arena, node, b"Filter", &work).map_err(|cause| pdf(cause.into()))?;
        if filter.is_none_or(|node| !matches!(arena.nodes[node.0].kind, Kind::Name(_))) {
            return Err(malformed(location));
        }
        let Coverage::Revision(revision) = signature.coverage() else {
            return Err(malformed(location));
        };
        let graph = self.graph(revision, &work).await.map_err(pdf)?;
        let fields = self.fields(&graph, &work).await.map_err(pdf)?;
        let transforms = self
            .transforms(signature, &graph, &work)
            .await
            .map_err(pdf)?;
        let placement = self
            .signature_placement(signature, &graph, &fields, &transforms, &work)
            .map_err(pdf)?;
        if !placement.all_requirements_met() {
            return Err(malformed(location));
        }
        if !reading.value.faults().is_empty()
            || !matches!(
                arena.nodes[get(arena, node, b"Contents", &work)
                    .map_err(|cause| pdf(cause.into()))?
                    .expect("inspected Contents")
                    .0]
                    .kind,
                Kind::String(Form::Hexadecimal)
            )
        {
            return Err(malformed(signature.contents()));
        }
        if let Some(version) = get(arena, node, b"V", &work).map_err(|cause| pdf(cause.into()))?
            && unsigned(arena, version, &work).map_err(|cause| pdf(cause.into()))? != 0
        {
            return Err(malformed(arena.nodes[version.0].location));
        }
        for key in [
            b"Cert".as_slice(),
            b"Reference",
            b"Changes",
            b"R",
            b"Prop_AuthTime",
            b"Prop_AuthType",
        ] {
            if let Some(value) = get(arena, node, key, &work).map_err(|cause| pdf(cause.into()))? {
                return Err(malformed(arena.nodes[value.0].location));
            }
        }
        let mut covered = self.covered(signature, &work).map_err(pdf)?;
        let checks = token
            .check_historical_async_with_profile(
                provider,
                parent,
                context,
                &mut AsyncRawInput::new(&mut covered),
                recognizes,
                |input| profile(&input),
            )
            .await
            .map_err(TimestampError::Check)?;
        self.check(&work, location)
            .map_err(|cause| pdf(cause.into()))?;
        Ok(DocumentTime {
            signature,
            checks,
            certificate: context.certificate,
            key: context.key,
        })
    }
}

fn malformed_timestamp<S, P, R>(location: crate::source::Location) -> TimestampError<S, P, R> {
    TimestampError::Pdf(
        Error {
            kind: ErrorKind::Syntax(Syntax::Container),
            location,
        }
        .into(),
    )
}
