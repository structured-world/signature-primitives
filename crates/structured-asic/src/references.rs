//! Scoped package URI lookup, independent of XML origin and authentication.

mod checks;
pub use checks::Checks;

use crate::{
    error::{Error as ArchiveError, resource},
    uri::{self, Part},
    zip::{Member, Names},
};
use structured_asn1::{memory::Work, range::RangeSource};
use structured_xades::{
    binary::{self, OwnedBinaryXml},
    certificate::{Agreement, DigestProvider},
    digest,
    reference::{LexicalSource, VisitError},
    scalar::{self, UriValue, UriXml},
    xml::{Access, AccessError, Name, Xml},
};

/// All original manifest URI bindings. Construction resolves every original
/// instruction, including malformed/ambiguous ones, without dropping siblings.
/// This is inspection only; it does not attest that XML was produced from the
/// selected base member or that a signature authenticated the manifest.
pub struct Catalogue<'v, 's, N, D, G, S: RangeSource> {
    base: Member<'v, 's, S>,
    reading: crate::manifest::Reading<N, D, G>,
    signatures: structured_asn1::memory::OwnedVec<Target<'v, 's, S>>,
    objects: structured_asn1::memory::OwnedVec<Target<'v, 's, S>>,
}

/// Source/member, XML and storage admission failures retain their actual role.
#[derive(Debug)]
pub enum ResolveError<E, N, SE> {
    /// Actual original archive view or current/source query refused.
    Archive(ArchiveError<SE>),
    /// Original XML lexical/source interpretation or target lookup refused.
    Reference(AccessError<VisitError<E, ArchiveError<SE>>, N>),
    /// Source-scoped retained metadata could not be admitted.
    Storage {
        /// Original owning XML instruction.
        node: N,
        /// Exact refusal cause.
        cause: structured_asn1::memory::MemoryError,
    },
}

/// Full original manifest catalogue or its unchanged processing failure.
pub type ResolveResult<'v, 's, X, S> = Result<
    Catalogue<'v, 's, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, S>,
    ResolveError<<X as Xml>::Error, <X as Xml>::Id, <S as RangeSource>::Error>,
>;
type MemberResult<'v, 's, S> = crate::error::SourceResult<Option<Member<'v, 's, S>>, S>;

/// Resolves every URI under the original manifest generation and the same
/// current/archive execution. No decoder or provider state is started here.
pub fn resolve_manifest<'v, 's, X: UriXml, S: RangeSource, W: Work>(
    base: Member<'v, 's, S>,
    reading: crate::manifest::Reading<X::Id, X::Document, X::Generation>,
    xml: &X,
    work: &W,
) -> ResolveResult<'v, 's, X, S> {
    let execution = base.session().query(work);
    base.archive()
        .admit(&execution, base.central_span())
        .map_err(ResolveError::Archive)?;
    let access = Access::new(xml, reading.snapshot(), &execution);
    // The original XML owner sees its generation/query before any retained
    // catalogue allocation, even when the reading contains no instructions.
    access.inspect(reading.root(), |_| ()).map_err(|cause| {
        ResolveError::Reference(match cause {
            AccessError::Xml(cause) => AccessError::Xml(VisitError::Processing(cause)),
            AccessError::Changed { node } => AccessError::Changed { node },
            AccessError::Resource { node, cause } => AccessError::Resource { node, cause },
        })
    })?;
    let mut signatures = execution.vector();
    let mut objects = execution.vector();
    signatures
        .try_reserve_exact(reading.signatures().len())
        .map_err(|cause| ResolveError::Storage {
            node: reading.root(),
            cause,
        })?;
    objects
        .try_reserve_exact(reading.objects().len())
        .map_err(|cause| ResolveError::Storage {
            node: reading.root(),
            cause,
        })?;
    for node in reading.signatures() {
        let target = resolve(&base, &access, *node).map_err(ResolveError::Reference)?;
        signatures
            .try_push(target)
            .map_err(|cause| ResolveError::Storage { node: *node, cause })?;
    }
    for object in reading.objects() {
        let target = resolve(&base, &access, object.node).map_err(ResolveError::Reference)?;
        objects
            .try_push(target)
            .map_err(|cause| ResolveError::Storage {
                node: object.node,
                cause,
            })?;
    }
    base.archive()
        .admit(&execution, base.central_span())
        .map_err(ResolveError::Archive)?;
    Ok(Catalogue {
        base,
        reading,
        signatures: signatures.into_owned(),
        objects: objects.into_owned(),
    })
}

impl<'v, 's, N: Copy, D: Copy + Eq, G: Copy + Eq, S: RangeSource> Catalogue<'v, 's, N, D, G, S> {
    /// Original selected base occurrence, without a claim of XML production.
    #[must_use]
    pub fn base(&self) -> &Member<'v, 's, S> {
        &self.base
    }
    /// Complete original schema reading, including all faults/extensions.
    #[must_use]
    pub fn reading(&self) -> &crate::manifest::Reading<N, D, G> {
        &self.reading
    }
    /// Every original signature-file target, preserving duplicate `SigReference`.
    #[must_use]
    pub fn signatures(&self) -> &[Target<'v, 's, S>] {
        &self.signatures
    }
    /// Every original data target in exact `DataObjectReference` order.
    #[must_use]
    pub fn objects(&self) -> &[Target<'v, 's, S>] {
        &self.objects
    }

    /// Selects an original whole member only when the signature-file singleton
    /// and exact-name candidate are both unambiguous. All negatives remain in
    /// the catalogue; None cannot become a fallback signature or ERS object.
    pub fn signature_member<W: Work>(&self, work: &W) -> MemberResult<'v, 's, S> {
        self.base.archive().admit(work, self.base.central_span())?;
        if self.signatures.len() != 1 {
            return Ok(None);
        }
        unique(&self.signatures[0], work)
    }
    /// Selects one original whole data member. None includes an out-of-range
    /// caller ordinal and a retained negative/ambiguous original target.
    pub fn object_member<W: Work>(&self, ordinal: usize, work: &W) -> MemberResult<'v, 's, S> {
        self.base.archive().admit(work, self.base.central_span())?;
        let Some(target) = self.objects.get(ordinal) else {
            return Ok(None);
        };
        unique(target, work)
    }
    /// Produces the exact original ERS group only if EVERY object has one whole
    /// input. Repeated original references remain repeated group occurrences.
    /// No successful subset or partial group is returned for a negative target.
    pub fn group<W: Work>(
        &self,
        work: &W,
    ) -> crate::zip::Acquisition<Option<crate::evidence::Group<'v, 's, S>>, S> {
        let archive = self.base.archive();
        let execution = self.base.session().query(work);
        let fail = |cause| crate::zip::ReadFailure::Processing {
            member: self.base.id(),
            cause,
        };
        archive
            .admit(&execution, self.base.central_span())
            .map_err(fail)?;
        if self.objects.is_empty() {
            return Ok(None);
        }
        let mut members = execution.vector();
        for target in &self.objects {
            archive
                .admit(&execution, self.base.central_span())
                .map_err(fail)?;
            let Some(member) = unique(target, &execution).map_err(fail)? else {
                return Ok(None);
            };
            members
                .try_push(member.id())
                .map_err(|cause| fail(resource(self.base.central_span(), cause)))?;
        }
        crate::evidence::Group::new(archive, members.into_owned(), &execution).map(Some)
    }
}

fn unique<'v, 's, S: RangeSource, W: Work>(
    target: &Target<'v, 's, S>,
    work: &W,
) -> Result<Option<Member<'v, 's, S>>, ArchiveError<S::Error>> {
    if let Target::Members {
        names,
        part: Part::Whole,
    } = target
        && names.len() == 1
    {
        names.member(0, work)
    } else {
        Ok(None)
    }
}

/// Why no digest was attempted for an original instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unchecked {
    /// The enclosing operation did not execute this original object's digest.
    NotExecuted,
    /// Resolution did not select exactly one whole original member.
    Input,
    /// `DigestMethod` is missing or ambiguous in the retained schema reading.
    Method,
    /// `DigestValue` is missing or ambiguous in the retained schema reading.
    Value,
}

/// Independent completed hash fact, never an authenticated manifest verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestReading {
    /// Original selection/schema does not permit a unique full input.
    Unchecked(Unchecked),
    /// The selected provider completed the existing common digest check.
    Checked(Agreement),
}

/// Actual source lookup and digest facts for one original XML instruction.
/// These stable IDs can survive a scoped XML view; no DOM borrow is retained.
pub struct ObjectCheck<'v, 's, N, D, G, S: RangeSource> {
    snapshot: structured_xades::xml::Snapshot<D, G>,
    root: N,
    object: crate::manifest::Object<N>,
    target: Target<'v, 's, S>,
    digest: DigestReading,
}
impl<'v, 's, N: Copy, D: Copy, G: Copy, S: RangeSource> ObjectCheck<'v, 's, N, D, G, S> {
    /// Exact original XML document/generation used by the digest method/value.
    #[must_use]
    pub fn snapshot(&self) -> structured_xades::xml::Snapshot<D, G> {
        self.snapshot
    }
    /// Exact manifest root, not another sibling manifest with the same URI.
    #[must_use]
    pub fn root(&self) -> N {
        self.root
    }
    /// The original instruction and all singleton/rootfile distinctions.
    #[must_use]
    pub fn object(&self) -> crate::manifest::Object<N> {
        self.object
    }
    /// Complete exact-name candidate range and URI component outcome.
    #[must_use]
    pub fn target(&self) -> &Target<'v, 's, S> {
        &self.target
    }
    /// Actual common digest answer, independent of XML origin/authentication.
    #[must_use]
    pub fn digest(&self) -> DigestReading {
        self.digest
    }
}

/// Original XML, source, callback and logical digest refusals stay distinct.
#[derive(Debug)]
pub enum CheckError<E, PE, N, D, G, SE, SD, SG> {
    /// Original XML node/URI or ZIP source lookup refusal.
    Reference(AccessError<VisitError<E, ArchiveError<SE>>, N>),
    /// The original selected member cannot provide a complete input stream.
    Input(crate::zip::ReadFailure<SE, SD, SG>),
    /// Existing shared XML digest error with original value-node provenance.
    Digest(ObjectDigestError<E, PE, N, D, G, SE, SD, SG>),
}
/// Original XML value location and unchanged native digest/source refusal.
pub type ObjectDigestError<E, PE, N, D, G, SE, SD, SG> =
    binary::Error<E, digest::Error<crate::zip::ReadFailure<SE, SD, SG>, PE>, N, D, G>;

/// Complete original fact or original typed processing failure.
pub type CheckResult<'v, 's, X, S, PE> = Result<
    Option<ObjectCheck<'v, 's, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation, S>>,
    CheckError<
        <X as Xml>::Error,
        PE,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
        <S as RangeSource>::Error,
        <S as RangeSource>::Document,
        <S as RangeSource>::Generation,
    >,
>;

/// Checks one original manifest instruction through the existing XML digest
/// provider and sealed member stream. Invalid/ambiguous targets remain facts;
/// no first-name selection, whole-member promotion of fragments, or implicit
/// external fetch is performed. This does not attest ZIP-to-XML provenance.
///
/// # Panics
/// An internal immutable name-catalogue invariant fails if its unique
/// original candidate cannot be selected from that same catalogue.
pub async fn check_object<'p, 'v, 's, X, S, P, W>(
    base: &Member<'v, 's, S>,
    reading: &crate::manifest::Reading<X::Id, X::Document, X::Generation>,
    ordinal: usize,
    xml: &X,
    provider: &'p P,
    work: &W,
) -> CheckResult<'v, 's, X, S, P::Error>
where
    X: UriXml + OwnedBinaryXml,
    S: RangeSource,
    P: DigestProvider<'p, X>,
    W: Work,
{
    let access = Access::new(xml, reading.snapshot(), work);
    // Even an out-of-range ordinal observes its original generation/query.
    access.inspect(reading.root(), |_| ()).map_err(|cause| {
        CheckError::Reference(match cause {
            AccessError::Xml(cause) => AccessError::Xml(VisitError::Processing(cause)),
            AccessError::Resource { node, cause } => AccessError::Resource { node, cause },
            AccessError::Changed { node } => AccessError::Changed { node },
        })
    })?;
    let Some(object) = reading.objects().get(ordinal).copied() else {
        return Ok(None);
    };
    let target = resolve(base, &access, object.node).map_err(CheckError::Reference)?;
    let answer = match (object.method, object.value) {
        (crate::manifest::Slot::One(method), crate::manifest::Slot::One(value)) => {
            if let Target::Members {
                names,
                part: Part::Whole,
            } = &target
                && names.len() == 1
            {
                let member = names
                    .member(0, work)
                    .map_err(|cause| {
                        CheckError::Reference(AccessError::Xml(VisitError::Visitor(cause)))
                    })?
                    .expect("the immutable exact candidate range contains one original member");
                let mut source = member.source(work).map_err(CheckError::Input)?;
                DigestReading::Checked(
                    digest::check_xml_async(
                        xml,
                        digest::Reference {
                            snapshot: reading.snapshot(),
                            method,
                            value,
                        },
                        &mut source,
                        provider,
                        work,
                    )
                    .await
                    .map_err(CheckError::Digest)?,
                )
            } else {
                DigestReading::Unchecked(Unchecked::Input)
            }
        }
        (crate::manifest::Slot::One(_), _) => DigestReading::Unchecked(Unchecked::Value),
        _ => DigestReading::Unchecked(Unchecked::Method),
    };
    base.archive()
        .admit(work, base.central_span())
        .map_err(|cause| CheckError::Reference(AccessError::Xml(VisitError::Visitor(cause))))?;
    Ok(Some(ObjectCheck {
        snapshot: reading.snapshot(),
        root: reading.root(),
        object,
        target,
        digest: answer,
    }))
}

/// Original URI outcome. A candidate range preserves every duplicated member;
/// a fragment/query never becomes proof of a whole-member digest input.
pub enum Target<'v, 's, S: RangeSource> {
    /// The original optional URI attribute is absent.
    Absent,
    /// The owner found malformed/complex lexical content.
    Malformed,
    /// The owner cannot establish the anyURI datatype.
    Unsupported,
    /// A path-empty reference into the containing original XML document.
    SameDocument(Part),
    /// The package root, independent of an empty or missing ZIP filename.
    Root(Part),
    /// Exact original candidate range, possibly empty or ambiguous.
    Members {
        /// All original occurrences of the exact decoded ZIP name.
        names: Names<'v, 's, S>,
        /// Original query/fragment presence.
        part: Part,
    },
    /// Completed URI interpretation failure, distinct from missing candidates.
    Negative(uri::Negative),
}

/// XML node provenance and original ZIP/source causes remain independent.
pub type ErrorOf<X, S> = AccessError<
    VisitError<<X as Xml>::Error, ArchiveError<<S as RangeSource>::Error>>,
    <X as Xml>::Id,
>;

/// Resolves the complete original URI attribute within its lexical visitor.
/// This does not attest that `access` was produced from `base`: only the scoped
/// producing owner can establish that association. No acquisition, signature
/// check, XML reparse or normalized-name substitution takes place here.
pub fn resolve<'v, 's, X: UriXml, S: RangeSource, W: Work>(
    base: &Member<'v, 's, S>,
    access: &Access<'_, X, W>,
    node: X::Id,
) -> Result<Target<'v, 's, S>, ErrorOf<X, S>> {
    scalar::with_uri(
        access,
        node,
        LexicalSource::Attribute(Name {
            namespace: "",
            local: "URI",
        }),
        |value| {
            let work = access.execution();
            let archive = base.archive();
            archive.admit(work, base.central_span())?;
            let target = match value {
                UriValue::Absent => Target::Absent,
                UriValue::ComplexContent | UriValue::Malformed => Target::Malformed,
                UriValue::Unsupported => Target::Unsupported,
                UriValue::Valid(value) => match uri::resolve(base.name(), value, work)
                    .map_err(|cause| resource(base.central_span(), cause))?
                {
                    uri::Target::SameDocument(part) => Target::SameDocument(part),
                    uri::Target::Root(part) => Target::Root(part),
                    uri::Target::Negative(cause) => Target::Negative(cause),
                    uri::Target::Member { name, part } => Target::Members {
                        names: archive.find(name.as_ref(), work)?,
                        part,
                    },
                },
            };
            archive.admit(work, base.central_span())?;
            Ok(target)
        },
    )
}
