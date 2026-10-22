//! Source-selected timestamp checks. The selected input is derived here;
//! callers select providers, original certificates and independently checked
//! paths, never replacement signature bytes or a writable successful receipt.

use crate::basic::{BindError, PathRestriction};
use crate::prepare::{Preparation, Timestamp};
use crate::source::{DocumentId, Node};
use crate::{Cades, Error, ISSUER};
use structured_asn1::{
    Reader,
    memory::{Execution, OwnedVec, Work},
    value::OwnedOid,
};
use structured_cms::{
    octets::Piece,
    provider::{SignatureAnswer, SignatureProvider},
    stream::{Receiver, Refused, Source},
    timestamp::{
        self as tsp, CheckContext, ProfileCheckError, ProfileFailure, ProfileSource, Token,
    },
    verify::ContentAgreement,
};
use structured_ltv::{
    pki::CheckedPath,
    timestamp::{CheckedActor, Purpose, Verified},
};
use structured_pkix::temporal::LeapTable;

/// Explicit UTC facts and optional caller-established comparison instant.
/// No clock or tolerance is discovered implicitly. Without a usable reference
/// the common TSP result keeps Unverified timeliness and cannot issue evidence;
/// archived signature/math facts remain available independently in the report.
pub struct CheckTime<'a, 'document> {
    /// Qualified correction table covering every temporal comparison.
    pub utc: &'a LeapTable<'document>,
    /// Actual caller-supplied reference, never derived from the token itself.
    pub reference: Option<structured_pkix::temporal::Instant>,
}

mod archive;
pub mod historical;
pub mod references;
mod requirements;
pub use archive::{
    ArchiveCheckError, ArchiveChecked, ArchiveError, ArchiveStreamError, ArchiveView, NoDetached,
    ScopeError as ArchiveScopeError,
};

/// Source/refusal or opaque caller cause. Unreadable occurrences stay in the
/// preparation's full census and cannot become successful missing entries.
#[derive(Debug)]
pub enum VisitError<E> {
    /// Original source/ASN.1/resource failure before the visitor.
    Processing(Error),
    /// Original occurrence has no readable encapsulated value.
    Unreadable {
        /// Actual original property.
        property: Node,
    },
    /// Caller failure, unchanged and without a successful partial return.
    Callback(E),
}

/// Borrows exactly one original prepared token under current execution.
/// No envelope is reparsed; retained evidence owns its own storage.
pub fn with_token<'m, 'd, R, E>(
    prepared: &Preparation<'m, 'd>,
    ordinal: usize,
    operation: &Reader<'d>,
    visitor: impl for<'scope> FnOnce(Context<'scope, 'm, 'd>) -> Result<R, E>,
) -> Result<R, VisitError<E>> {
    prepared
        .document()
        .message()
        .require_session(operation, "cades.timestamp")
        .map_err(|cause| VisitError::Processing(Error::Cms(cause)))?;
    operation
        .charge(1)
        .map_err(|cause| VisitError::Processing(Error::encoding(cause, "cades.timestamp")))?;
    let entry = prepared.timestamps().get(ordinal).ok_or_else(|| {
        VisitError::Processing(Error::Foreign {
            at: prepared.signer().span().start,
        })
    })?;
    let source = entry.source().ok_or(VisitError::Unreadable {
        property: entry.property(),
    })?;
    let reader = source
        .reader_in(operation)
        .map_err(VisitError::Processing)?;
    let Some(Some(index)) = prepared.parsed.ordinals.get(ordinal) else {
        return Err(VisitError::Unreadable {
            property: entry.property(),
        });
    };
    let token = &prepared.parsed.models[*index].token;
    visitor(Context {
        prepared,
        ordinal,
        entry,
        token,
        reader: &reader,
    })
    .map_err(VisitError::Callback)
}

/// Short original token view. Any references into its movable parsed model are
/// restricted to this callback, independently of original document lifetimes.
pub struct Context<'scope, 'model, 'document> {
    prepared: &'scope Preparation<'model, 'document>,
    ordinal: usize,
    entry: &'scope Timestamp<'document>,
    token: &'scope Token<'document>,
    reader: &'scope Reader<'document>,
}

pub(crate) fn with_existing<'m, 'd, R, E>(
    prepared: &Preparation<'m, 'd>,
    ordinal: usize,
    token: &Token<'d>,
    operation: &Reader<'d>,
    visitor: impl for<'scope> FnOnce(Context<'scope, 'm, 'd>) -> Result<R, E>,
) -> Result<R, VisitError<E>> {
    prepared
        .document()
        .message()
        .require_session(operation, "cades.timestamp")
        .map_err(|cause| VisitError::Processing(Error::Cms(cause)))?;
    operation
        .charge(1)
        .map_err(|cause| VisitError::Processing(Error::encoding(cause, "cades.timestamp")))?;
    let entry = prepared.timestamps().get(ordinal).ok_or_else(|| {
        VisitError::Processing(Error::Foreign {
            at: prepared.signer().span().start,
        })
    })?;
    let source = entry.source().ok_or(VisitError::Unreadable {
        property: entry.property(),
    })?;
    let reader = source
        .reader_in(operation)
        .map_err(VisitError::Processing)?;
    visitor(Context {
        prepared,
        ordinal,
        entry,
        token,
        reader: &reader,
    })
    .map_err(VisitError::Callback)
}

/// Complete mathematical/content result, without borrowing a temporary signer.
#[derive(Debug)]
pub enum Signature {
    /// Original completed CMS content and signature answers, including None.
    Checked {
        /// Separate payload-to-signed-attribute agreement.
        content: ContentAgreement,
        /// Actual selected-provider arithmetic.
        signature: Option<SignatureAnswer>,
    },
    /// Original selected provider did not implement this mechanism.
    Unsupported(structured_cms::prepare::Part),
    /// Original algorithm/schema failure, unchanged and located.
    Malformed(structured_cms::Error),
}

/// Independently retained completed facts, including negative outcomes. A
/// successful actor is private and requires the common Evidence plus all
/// signed ESS path restrictions; public diagnostics cannot manufacture one.
pub struct Checked<'model, 'document, 'path> {
    /// Original CMS result, independently of authority/path acceptance.
    pub signature: Signature,
    /// Actual selected-certificate SID/hint comparison.
    pub identifier: structured_cms::directory::CertificateAgreement,
    /// Both independent original ESS hash bindings.
    pub bindings: structured_cms::ess::Bindings,
    /// Original exclusive EKU and optional TSA-name answers.
    pub authority: tsp::AuthorityFacts,
    /// Complete original format-selected input agreement.
    pub imprint: tsp::ImprintAgreement,
    /// Original readable scalar accuracy failure, never clamped.
    pub accuracy: Option<tsp::DeviationError>,
    /// Original freshness/reference result, including Unverified/Uncertain.
    pub timeliness: tsp::Timeliness,
    /// Every original unknown critical identifier, with retained storage charge.
    pub unknown_critical: OwnedVec<OwnedOid>,
    /// Signed later-identifier restrictions against the actual selected path.
    pub restrictions: PathRestriction,
    actor: Option<CheckedActor<'path, 'document, Node, DocumentId<'model, 'document>, (), Cades>>,
}

impl<'m, 'd, 'p> Checked<'m, 'd, 'p> {
    /// Original successfully bound actor, or explicit absence of proof.
    #[must_use]
    pub fn actor(&self) -> Option<&CheckedActor<'p, 'd, Node, DocumentId<'m, 'd>, (), Cades>> {
        self.actor.as_ref()
    }
    /// Moves the independently retained evidence without copying/re-hashing.
    #[must_use]
    pub fn into_actor(self) -> Option<CheckedActor<'p, 'd, Node, DocumentId<'m, 'd>, (), Cades>> {
        self.actor
    }
}

/// A format-selected source pass, preserving its original acquisition cause.
#[derive(Debug)]
pub enum InputError<E> {
    /// Original explicit detached source failed.
    Detached(E),
    /// Original carried source/segment traversal failed.
    Carried(structured_cms::octets::SourceError),
    /// Original metadata admission failed before accessing a fragment.
    Resource(structured_asn1::memory::MemoryError),
    /// Common stream holds the original refused receiver cause.
    Receiver(Refused),
}

/// The original complete timestamp/common/profile failure.
#[derive(Debug)]
pub enum CheckError<SE, PE, RE, FE = core::convert::Infallible> {
    /// Actual MD5 use violates the format independently of provider support.
    ForbiddenDigest {
        /// Original algorithm enclosure.
        at: u64,
    },
    /// Requested entry does not cover this kind of input, or a path has no
    /// actual target. Refused before provider/source side effects.
    Selection(Error),
    /// Known validation-values syntax is malformed. The original unchanged
    /// causes remain available from this context's retained properties.
    Material {
        /// Actual containing timestamp attribute, in the original source.
        property: Node,
    },
    /// Original input/callback/processing failure and its source maps.
    Check(ProfileCheckError<SE, PE, RE, ProfileError<PE, FE>>),
}

/// Original source-specific baseline preflight failure.
#[derive(Debug)]
pub enum ProfileError<PE, E> {
    /// Located profile/placement violation on the actual archive TSA signer.
    Cades(structured_cms::Error),
    /// Actual signed ESS/path restriction execution refused.
    Restriction(BindError<PE>),
    /// The format prohibits actual MD5 use (§6.2.1), independently of support.
    Md5 {
        /// Original declared algorithm position.
        at: u64,
    },
    /// The actual archive/content profile's independent original cause.
    Input(E),
}

struct Pieces<'s, 'd>(&'s [Piece<'d>]);
impl Source for Pieces<'_, '_> {
    type Error = InputError<core::convert::Infallible>;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        for piece in self.0 {
            work.charge_work(1).map_err(InputError::Resource)?;
            receiver
                .write(piece.as_bytes())
                .map_err(InputError::Receiver)?;
        }
        Ok(())
    }
}

enum ContentInput<'s, 'd, S> {
    Carried(&'s structured_cms::Octets<'d>),
    Counter(&'s [Piece<'d>]),
    Detached(&'s mut S),
}
impl<S: Source> Source for ContentInput<'_, '_, S> {
    type Error = InputError<S::Error>;
    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), Self::Error> {
        match self {
            Self::Carried(source) => source.stream(receiver, work).map_err(InputError::Carried),
            Self::Detached(source) => source.stream(receiver, work).map_err(InputError::Detached),
            Self::Counter(pieces) => {
                for piece in *pieces {
                    work.charge_work(1).map_err(InputError::Resource)?;
                    receiver
                        .write(piece.as_bytes())
                        .map_err(InputError::Receiver)?;
                }
                Ok(())
            }
        }
    }
}

impl<'m, 'd> Context<'_, 'm, 'd> {
    /// First-read original legacy validation models and unchanged diagnostics.
    /// This does not reparse the timestamp or a material field.
    #[must_use]
    pub fn properties(&self) -> Option<&crate::properties::Properties<'d>> {
        let index = self.prepared.parsed.ordinals.get(self.ordinal)?.as_ref()?;
        self.prepared.parsed.models[*index].properties.as_ref()
    }
    /// Original envelope for pool selection/inspection without another parse.
    #[must_use]
    pub fn token(&self) -> &Token<'d> {
        self.token
    }
    /// Current original envelope reader for original CMS queries.
    #[must_use]
    pub fn reader(&self) -> &Reader<'d> {
        self.reader
    }

    /// Checks a content timestamp against the actual original carried input.
    /// At a counter this is the parent's signature octets; at the root this is
    /// eContent. An absent root eContent requires the separate explicit detached
    /// operation, and never silently selects the signature or empty bytes.
    #[expect(
        clippy::result_large_err,
        reason = "carried-content failures retain original envelope/information maps without allocating while reporting resource refusal"
    )]
    pub fn check_content<'a, 'p, P, PE, RE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        recognizes: impl FnMut(&tsp::TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<Checked<'m, 'd, 'p>, CheckError<InputError<core::convert::Infallible>, PE, RE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        if self.entry.purpose() != Purpose::Content {
            return Err(CheckError::Selection(Error::Foreign {
                at: self.entry.property().span().start,
            }));
        }
        let original = if let Some(pieces) = self
            .prepared
            .counter_content_input(self.ordinal, self.reader)
            .map_err(CheckError::Selection)?
        {
            ContentInput::<NoDetached>::Counter(pieces)
        } else {
            let source = self
                .prepared
                .document()
                .message()
                .content()
                .content()
                .ok_or_else(|| {
                    CheckError::Selection(Error::Foreign {
                        at: self.entry.property().span().start,
                    })
                })?;
            ContentInput::Carried(source)
        };
        self.check(
            provider,
            path,
            certificate_parent,
            time,
            &mut { original },
            recognizes,
        )
    }

    /// Checks an explicit detached root content input. A counter, signature
    /// timestamp or original carried payload refuses before source/provider use.
    #[expect(
        clippy::result_large_err,
        reason = "detached acquisition cause and both original source maps must survive the failed pass without a new allocation"
    )]
    pub fn check_detached_content<'a, 'p, P, S: Source, PE, RE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        detached: &mut S,
        recognizes: impl FnMut(&tsp::TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<Checked<'m, 'd, 'p>, CheckError<InputError<S::Error>, PE, RE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        if self.entry.purpose() != Purpose::Content
            || self.entry.owner() != Node::of(self.prepared.signer().span())
            || !self.prepared.document().message().content().is_detached()
        {
            return Err(CheckError::Selection(Error::Foreign {
                at: self.entry.property().span().start,
            }));
        }
        self.check(
            provider,
            path,
            certificate_parent,
            time,
            &mut ContentInput::Detached(detached),
            recognizes,
        )
    }

    /// Check a root OR nested counter's signature timestamp over that actual
    /// owner's signature CONTENT octets. Whole `SignerInfo` encodings, parent
    /// signatures and caller replacement bytes cannot enter this operation.
    /// EN319122-1 §5.3 and RFC5652 §11.4 define these different coverages.
    /// <https://www.rfc-editor.org/rfc/rfc5652#section-11.4>
    #[expect(
        clippy::result_large_err,
        reason = "original signature-input and nested token refusals carry their source maps even on memory exhaustion"
    )]
    pub fn check_signature<'a, 'p, P, PE, RE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        recognizes: impl FnMut(&tsp::TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<Checked<'m, 'd, 'p>, CheckError<InputError<core::convert::Infallible>, PE, RE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        if self.entry.purpose() != Purpose::Signature {
            return Err(CheckError::Selection(Error::Foreign {
                at: self.entry.property().span().start,
            }));
        }
        let pieces = self
            .prepared
            .signature_input(self.ordinal, self.reader)
            .map_err(CheckError::Selection)?
            .ok_or_else(|| {
                CheckError::Selection(Error::Foreign {
                    at: self.entry.property().span().start,
                })
            })?;
        self.check(
            provider,
            path,
            certificate_parent,
            time,
            &mut Pieces(pieces),
            recognizes,
        )
    }

    #[expect(
        clippy::result_large_err,
        reason = "dispatch preserves the complete mapped refusal from the one common profile check"
    )]
    fn check<'a, 'p, P, S: Source, PE, RE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        covered: &mut S,
        recognizes: impl FnMut(&tsp::TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
    ) -> Result<Checked<'m, 'd, 'p>, CheckError<S::Error, PE, RE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        self.check_profile(
            provider,
            path,
            certificate_parent,
            time,
            covered,
            (recognizes, |_| {
                Ok::<(), ProfileFailure<core::convert::Infallible>>(())
            }),
        )
    }

    #[expect(
        clippy::result_large_err,
        reason = "the shared profile refusal owns envelope and information provenance; boxing during refusal would require additional admitted storage"
    )]
    fn check_profile<'a, 'p, P, S: Source, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        covered: &mut S,
        callbacks: (
            impl FnMut(&tsp::TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
            impl for<'view, 'scope> FnOnce(
                tsp::ProfileInput<'view, 'd, 'a, 'scope>,
            ) -> Result<(), ProfileFailure<FE>>,
        ),
    ) -> Result<Checked<'m, 'd, 'p>, CheckError<S::Error, PE, RE, FE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        self.check_computed_profile(
            provider,
            path,
            certificate_parent,
            time,
            &mut tsp::RawInput::new(covered),
            callbacks,
        )
    }

    #[expect(
        clippy::result_large_err,
        reason = "mapped original causes remain unboxed on an exhausted account"
    )]
    fn check_computed_profile<'a, 'p, P, S, PE, RE, FE>(
        &'a self,
        provider: &'a P,
        path: &'p CheckedPath<'d>,
        certificate_parent: &Reader<'d>,
        time: &CheckTime<'_, 'd>,
        covered: &mut S,
        callbacks: (
            impl FnMut(&tsp::TokenExtension<'_>, &Execution<'_>) -> Result<bool, RE>,
            impl for<'view, 'scope> FnOnce(
                tsp::ProfileInput<'view, 'd, 'a, 'scope>,
            ) -> Result<(), ProfileFailure<FE>>,
        ),
    ) -> Result<Checked<'m, 'd, 'p>, CheckError<S::Error, PE, RE, FE>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
        S: tsp::ComputedInput<P, PE>,
    {
        let (recognizes, profile) = callbacks;
        if self
            .properties()
            .is_some_and(|properties| !properties.faults().is_empty())
        {
            return Err(CheckError::Material {
                property: self.entry.property(),
            });
        }
        let digest = self.token.signer().digest_algorithm();
        self.reader
            .charge(1 + digest.algorithm().as_bytes().len().min(8) as u64)
            .map_err(|cause| {
                CheckError::Selection(Error::encoding(cause, "cades.timestamp.digestAlgorithm"))
            })?;
        // EN319122-1 §6.2.1: actual MD5 use is forbidden independently of
        // provider capabilities. This gate precedes ESS/digest/source work.
        // https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf
        if digest.algorithm()
            == structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 2, 5])
        {
            return Err(CheckError::ForbiddenDigest {
                at: digest.offset(),
            });
        }
        let Some(target) = path.members().last() else {
            return Err(CheckError::Selection(Error::Foreign {
                at: self.entry.property().span().start,
            }));
        };
        let certificate = target.certificate();
        let key = target.key();
        let selection = CheckContext {
            certificate,
            certificate_parent,
            key,
            requested: None,
            utc: time.utc,
            reference: time.reference,
            window: None,
        };
        let restriction = core::cell::Cell::new(PathRestriction::Unproven);
        let checked = self
            .token
            .check_input_with_profile(
                provider,
                self.reader,
                &selection,
                covered,
                recognizes,
                |input| {
                    if self.entry.purpose() == Purpose::Archive
                        && self.entry.preservation_kind().is_none()
                    {
                        Self::archive_profile(&input)?;
                    }
                    restriction.set(Self::profile_rules(&input, path, provider)?);
                    profile(input).map_err(|cause| ProfileFailure {
                        source: cause.source,
                        cause: ProfileError::Input(cause.cause),
                    })
                },
            )
            .map_err(CheckError::Check)?;
        Ok(self.checked(checked, restriction.get(), certificate, key))
    }
    fn checked<'p>(
        &self,
        mut checked: tsp::CheckedTimestamp<'_>,
        restriction: PathRestriction,
        certificate: &'p structured_pkix::Certificate<'d>,
        key: structured_pkix::path::WorkingKey<'d>,
    ) -> Checked<'m, 'd, 'p> {
        let actor = match checked.take_evidence() {
            Some(evidence)
                if matches!(
                    restriction,
                    PathRestriction::Unstated | PathRestriction::Matches
                ) =>
            {
                let verified = Verified::new(
                    ISSUER,
                    self.prepared.document().locate(
                        self.entry
                            .value()
                            .expect("with_token requires original value")
                            .span(),
                    ),
                    self.entry.owner(),
                    self.entry.property(),
                    self.entry.purpose(),
                    evidence,
                );
                Some(CheckedActor::new(ISSUER, verified, certificate, key))
            }
            _ => None,
        };
        let signature = match checked.signature {
            tsp::TokenSignature::Checked(value) => {
                let (_, _, content, signature) = value.into_parts();
                Signature::Checked { content, signature }
            }
            tsp::TokenSignature::Unsupported(part) => Signature::Unsupported(part),
            tsp::TokenSignature::Malformed(cause) => Signature::Malformed(cause),
        };
        Checked {
            signature,
            identifier: checked.identifier,
            bindings: checked.bindings,
            authority: checked.authority,
            imprint: checked.imprint,
            accuracy: checked.accuracy_error,
            timeliness: checked.timeliness,
            unknown_critical: checked.unknown_critical,
            restrictions: restriction,
            actor,
        }
    }
    fn archive_profile<PE, FE>(
        input: &tsp::ProfileInput<'_, 'd, '_, '_>,
    ) -> Result<(), ProfileFailure<ProfileError<PE, FE>>> {
        // EN319122-1 §5.5.2 permits the hash index only in
        // unsigned attributes of this archive TSA signer.
        // Reuse the ESS reading of this very check; a valid
        // unsigned index cannot hide a prohibited signed copy.
        let faults = structured_cms::cades::findings_from_reading(
            input.token.signer(),
            structured_cms::cades::Role::ArchiveTimestamp,
            input.ess,
            input.parent,
        )
        .map_err(|cause| ProfileFailure {
            source: ProfileSource::Envelope,
            cause: ProfileError::Cades(cause),
        })?;
        if let Some(cause) = faults.into_iter().next() {
            return Err(ProfileFailure {
                source: ProfileSource::Envelope,
                cause: ProfileError::Cades(cause),
            });
        }
        Ok(())
    }
    fn profile_rules<'a, P, PE, FE>(
        input: &tsp::ProfileInput<'_, 'd, 'a, '_>,
        path: &CheckedPath<'d>,
        provider: &'a P,
    ) -> Result<PathRestriction, ProfileFailure<ProfileError<PE, FE>>>
    where
        P: for<'scope> SignatureProvider<'scope, Error = PE>,
    {
        // Admit each metadata/OID comparison before inspecting it. A known
        // forbidden digest is not Unsupported and no content source runs.
        let md5 = structured_asn1::Oid::from_bytes(&[42, 134, 72, 134, 247, 13, 2, 5]);
        for attribute in [input.ess.v1(), input.ess.v2()].into_iter().flatten() {
            for certificate in attribute.identifiers() {
                input.parent.charge(1).map_err(|cause| ProfileFailure {
                    source: ProfileSource::Envelope,
                    cause: ProfileError::Restriction(BindError::Processing(Error::encoding(
                        cause,
                        "cades.timestamp.ess",
                    ))),
                })?;
                if let structured_cms::provider::DigestAlgorithm::Written(algorithm) =
                    certificate.digest_algorithm()
                {
                    input
                        .parent
                        .charge(1 + algorithm.algorithm().as_bytes().len().min(8) as u64)
                        .map_err(|cause| ProfileFailure {
                            source: ProfileSource::Envelope,
                            cause: ProfileError::Restriction(BindError::Processing(
                                Error::encoding(cause, "cades.timestamp.ess"),
                            )),
                        })?;
                    if algorithm.algorithm() == md5 {
                        return Err(ProfileFailure {
                            source: ProfileSource::Envelope,
                            cause: ProfileError::Md5 {
                                at: algorithm.offset(),
                            },
                        });
                    }
                }
            }
        }
        input.reader.charge(12).map_err(|cause| ProfileFailure {
            source: ProfileSource::Information,
            cause: ProfileError::Restriction(BindError::Processing(Error::encoding(
                cause,
                "cades.timestamp",
            ))),
        })?;
        if let tsp::HashAlgorithmReading::Identifier(identifier) = input.info.imprint().algorithm()
            && identifier.algorithm() == md5
        {
            return Err(ProfileFailure {
                source: ProfileSource::Information,
                cause: ProfileError::Md5 {
                    at: identifier.offset(),
                },
            });
        }
        let result = crate::basic::restrictions(input.ess, Some(path), provider, input.parent)
            .map_err(|cause| ProfileFailure {
                source: ProfileSource::Envelope,
                cause: ProfileError::Restriction(cause),
            })?;
        Ok(result)
    }
}
