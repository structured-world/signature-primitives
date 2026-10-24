//! Original CMS/TST validation material, reusing existing first-read grammars.

use crate::{
    Asic, ISSUER,
    content::Content,
    error::{Error as ArchiveError, resource},
    source::{DocumentId, Node},
    zip::MemberId,
};
use structured_asn1::{
    Reader, Span,
    memory::{Execution, OwnedVec, Work},
    range::RangeSource,
};
use structured_cades::properties::Properties;
use structured_cms::{
    SignedData,
    signed::{CertificateChoice, revocation},
};
use structured_ltv::{
    material::{ArtifactRef, ArtifactSource, Occurrence},
    source::{Location, Query},
};

/// Actual enclosing position, independently of whether a later archive covers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Original `SignedData` certificate choice.
    Certificate(usize),
    /// Original `SignedData` CRL/other-revocation choice.
    Revocation(usize),
    /// Original certificate-values attribute member, with signed/unsigned role.
    CertificateValues {
        /// Original root `SignerInfo` ordinal.
        signer: usize,
        /// Original certificate ordinal in its values attribute.
        ordinal: usize,
        /// Whether the original values attribute is in `unsignedAttrs`.
        unsigned: bool,
    },
    /// Original revocation-values CRL member, with signed/unsigned role.
    CrlValues {
        /// Original root `SignerInfo` ordinal.
        signer: usize,
        /// Original CRL ordinal in its values attribute.
        ordinal: usize,
        /// Whether the original values attribute is in `unsignedAttrs`.
        unsigned: bool,
    },
    /// Original revocation-values bare `BasicOCSPResponse` member.
    OcspValues {
        /// Original root `SignerInfo` ordinal.
        signer: usize,
        /// Original basic-response ordinal in its values attribute.
        ordinal: usize,
        /// Whether the original values attribute is in `unsignedAttrs`.
        unsigned: bool,
    },
}
/// Original uninterpreted or malformed material remains visible.
#[derive(Debug)]
pub enum Finding {
    /// Open certificate choice, not a fabricated X.509 certificate.
    Certificate {
        /// Original `SignedData` certificate-choice ordinal.
        choice: usize,
        /// Original logical member enclosure, not a fabricated ZIP position.
        span: Span,
    },
    /// Unsupported original CMS revocation format.
    Revocation {
        /// Original `SignedData` revocation-choice ordinal.
        choice: usize,
        /// Original logical member enclosure.
        span: Span,
    },
    /// Original known revocation syntax failed; processing refusals are terminal.
    RevocationSyntax {
        /// Original `SignedData` revocation-choice ordinal.
        choice: usize,
        /// Original logical member enclosure.
        span: Span,
        /// Exact original shared grammar failure.
        cause: revocation::Error,
    },
    /// Original attributes could not be read as validation-value syntax.
    Properties {
        /// Actual original root `SignerInfo` ordinal.
        signer: usize,
        /// Exact original attribute-reading failure.
        cause: structured_cades::Error,
    },
}
/// Original source, grammar and capacity failures retain their classes.
#[derive(Debug)]
pub enum Error<E> {
    /// Actual source/current operation refused.
    Archive(ArchiveError<E>),
    /// Existing common CMS/PKIX revocation processing refused.
    Revocation(revocation::Error),
    /// Existing common attribute-value processing refused.
    Properties(structured_cades::Error),
    /// Existing original CMS reader/session refused.
    Cms(structured_cms::Error),
}
struct Status<'a> {
    choice: usize,
    value: revocation::Reading<'a>,
}
struct Owner<'a> {
    signer: usize,
    unsigned: Option<Span>,
    properties: Properties<'a>,
}
/// Complete original material at this one actual member. Models and source
/// bytes are borrowed/moved, never reparsed to construct an artifact index.
pub struct Pool<'a, 'v, 's, S: RangeSource> {
    content: &'a Content<'v, 's, S>,
    message: &'a SignedData<'a>,
    statuses: OwnedVec<Status<'a>>,
    owners: OwnedVec<Owner<'a>>,
    findings: OwnedVec<Finding>,
}
impl<'v, 's, S: RangeSource> Content<'v, 's, S> {
    /// Reads every original certificate/revocation choice and every signer's
    /// validation values through the existing CMS/CAdES kernels. This applies
    /// to carried TST `SignedData` without asserting that it is a `CAdES` signature.
    ///
    /// # Panics
    /// An internal CMS invariant fails if its retained revocation catalogue
    /// cannot supply a reader for an ordinal taken from that same catalogue.
    pub fn material<'a>(
        &'a self,
        message: &'a SignedData<'a>,
        parent: &Reader<'a>,
    ) -> Result<Pool<'a, 'v, 's, S>, Error<S::Error>> {
        let work = parent.execution();
        self.require(message, parent, &work)
            .map_err(Error::Archive)?;
        let refusal = |cause| Error::Archive(resource(self.enclosure(), cause));
        let mut findings = work.vector();
        let mut statuses = work.vector();
        let mut owners = work.vector();
        for (choice, value) in message.certificate_choices().iter().enumerate() {
            work.charge_work(1).map_err(refusal)?;
            let span = match value {
                CertificateChoice::X509(_) => continue,
                CertificateChoice::Extended(value)
                | CertificateChoice::AttributeV1(value)
                | CertificateChoice::AttributeV2(value)
                | CertificateChoice::Other(value) => value.span(),
            };
            findings
                .try_push(Finding::Certificate { choice, span })
                .map_err(refusal)?;
        }
        for (choice, value) in message.revocations().iter().enumerate() {
            work.charge_work(1).map_err(refusal)?;
            let reader = message
                .revocation_reader_in(parent, choice)
                .map_err(Error::Cms)?
                .expect("existing original revocation ordinal");
            match revocation::read(&reader, value) {
                Ok(revocation::Reading::Open { .. }) => findings
                    .try_push(Finding::Revocation {
                        choice,
                        span: value.span(),
                    })
                    .map_err(refusal)?,
                Ok(value) => statuses
                    .try_push(Status { choice, value })
                    .map_err(refusal)?,
                Err(cause) if cause.is_terminal() => return Err(Error::Revocation(cause)),
                Err(cause) => findings
                    .try_push(Finding::RevocationSyntax {
                        choice,
                        span: value.span(),
                        cause,
                    })
                    .map_err(refusal)?,
            }
        }
        for (signer, value) in message.signers().iter().enumerate() {
            work.charge_work(1).map_err(refusal)?;
            match Properties::read(value, parent) {
                Ok(properties) => owners
                    .try_push(Owner {
                        signer,
                        unsigned: value
                            .unsigned_attributes()
                            .map(|attributes| attributes.element().span()),
                        properties,
                    })
                    .map_err(refusal)?,
                Err(cause) if cause.is_terminal() => return Err(Error::Properties(cause)),
                Err(cause) => findings
                    .try_push(Finding::Properties { signer, cause })
                    .map_err(refusal)?,
            }
        }
        self.member()
            .archive()
            .admit(&work, self.enclosure())
            .map_err(Error::Archive)?;
        Ok(Pool {
            content: self,
            message,
            statuses: statuses.into_owned(),
            owners: owners.into_owned(),
            findings: findings.into_owned(),
        })
    }
}
/// Existing exact-artifact index, in the actual borrowed archive identity domain.
pub type Index<'a, 'q, 'v, 's, S> = structured_ltv::material::Index<
    'a,
    Node,
    DocumentId<'v, 's, S>,
    (),
    Placement,
    Finding,
    Execution<'q>,
    Asic,
>;
type IndexOf<'a, 'q, 'v, 's, S, O> = structured_ltv::material::Index<
    'a,
    Node,
    DocumentId<'v, 's, S>,
    (),
    Placement,
    O,
    Execution<'q>,
    Asic,
>;
impl<'a, 'v, 's, S: RangeSource> Pool<'a, 'v, 's, S> {
    /// Actual original complete material source.
    #[must_use]
    pub fn member(&self) -> MemberId<S::Document, S::Generation> {
        self.content.member().id()
    }
    /// All malformed/open original source choices, never a successful subset.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    /// Existing attribute inspections retain every readable syntax/open finding.
    pub fn properties(&self) -> impl Iterator<Item = (usize, &Properties<'a>)> {
        self.owners
            .iter()
            .map(|owner| (owner.signer, &owner.properties))
    }
    /// Builds the SAME exact-artifact index. All occurrences are located at
    /// their complete original member: an A.7 reference protects that complete
    /// member, not a guessed contiguous physical position of an inner value.
    pub fn index<'p, 'q, W: Work>(
        &'p self,
        work: &'q W,
    ) -> Result<Index<'p, 'q, 'v, 's, S>, structured_ltv::material::IndexError<Node>>
    where
        'v: 'q,
        'a: 'p,
    {
        let archive = self.content.member().archive();
        let query = archive.ltv_query(work);
        let node = Node::Root;
        let mut index = structured_ltv::material::Index::new(ISSUER, node, &self.findings, &query)?;
        let mut ordinal = 0usize;
        self.append(&mut index, &query, &mut ordinal)?;
        Ok(index)
    }
    fn append<'p, 'q, O>(
        &'p self,
        index: &mut IndexOf<'p, 'q, 'v, 's, S, O>,
        query: &crate::source::Query<'q, 'v, 's, S>,
        ordinal: &mut usize,
    ) -> Result<(), structured_ltv::material::IndexError<Node>>
    where
        'a: 'p,
    {
        let node = Node::Root;
        let mut add = |artifact: ArtifactRef<'_, 'p>, placement| {
            index.admit(query)?;
            let location = Location {
                snapshot: query.snapshot(),
                node: Node::Member(self.member().ordinal()),
            };
            let source = ArtifactSource::Material(*ordinal);
            *ordinal =
                ordinal
                    .checked_add(1)
                    .ok_or(structured_ltv::material::IndexError::Resource {
                        signature: node,
                        cause: structured_asn1::memory::MemoryError::WorkExceeded,
                    })?;
            index.insert(
                ISSUER,
                artifact,
                Occurrence::new(source, location, placement),
                query,
            )
        };
        for (choice, value) in self.message.certificate_choices().iter().enumerate() {
            query
                .admit(node, 1)
                .map_err(structured_ltv::material::IndexError::Scope)?;
            if let CertificateChoice::X509(certificate) = value {
                add(
                    ArtifactRef::Certificate(&self.message.certificates()[*certificate]),
                    Placement::Certificate(choice),
                )?;
            }
        }
        for status in &self.statuses {
            query
                .admit(node, 1)
                .map_err(structured_ltv::material::IndexError::Scope)?;
            match &status.value {
                revocation::Reading::Crl(value) => add(
                    ArtifactRef::Crl(value),
                    Placement::Revocation(status.choice),
                )?,
                revocation::Reading::Ocsp(value) => add(
                    ArtifactRef::Ocsp(value),
                    Placement::Revocation(status.choice),
                )?,
                revocation::Reading::Open { .. } => {
                    unreachable!("open choices are retained as findings")
                }
            }
        }
        for owner in &self.owners {
            query
                .admit(node, 1)
                .map_err(structured_ltv::material::IndexError::Scope)?;
            let Some(values) = owner.properties.legacy_values() else {
                continue;
            };
            let unsigned = |property: Span| {
                owner.unsigned.is_some_and(|span| {
                    property.start >= span.start && property.end() <= span.end()
                })
            };
            for entry in values.certificates() {
                add(
                    ArtifactRef::Certificate(&entry.value),
                    Placement::CertificateValues {
                        signer: owner.signer,
                        ordinal: entry.ordinal,
                        unsigned: unsigned(entry.property.span()),
                    },
                )?;
            }
            for entry in values.crls() {
                add(
                    ArtifactRef::Crl(&entry.value),
                    Placement::CrlValues {
                        signer: owner.signer,
                        ordinal: entry.ordinal,
                        unsigned: unsigned(entry.property.span()),
                    },
                )?;
            }
            for entry in values.ocsp_responses() {
                add(
                    ArtifactRef::Ocsp(&entry.value),
                    Placement::OcspValues {
                        signer: owner.signer,
                        ordinal: entry.ordinal,
                        unsigned: unsigned(entry.property.span()),
                    },
                )?;
            }
        }
        Ok(())
    }
}

/// Every original CMS/TST source slot, including unreadable/unprocessed files.
pub struct SourceSlot<'p, 'a, 'v, 's, S: RangeSource> {
    member: MemberId<S::Document, S::Generation>,
    pool: Option<&'p Pool<'a, 'v, 's, S>>,
}
impl<'p, 'a, 'v, 's, S: RangeSource> SourceSlot<'p, 'a, 'v, 's, S> {
    /// Original physical member occurrence, never caller-supplied success order.
    #[must_use]
    pub fn member(&self) -> MemberId<S::Document, S::Generation> {
        self.member
    }
    /// Actual completed first-read material, absent for an unprocessed source.
    #[must_use]
    pub fn pool(&self) -> Option<&'p Pool<'a, 'v, 's, S>> {
        self.pool
    }
}
/// Original open/malformed material finding with its exact source member.
pub struct Open<'p, D, G> {
    /// Actual original source occurrence.
    pub member: MemberId<D, G>,
    /// Original retained cause, not a clone or a replacement diagnostic.
    pub finding: &'p Finding,
}
/// Full original carrier source census and one reusable exact-artifact index.
/// Participant completeness, source-negative semantics and usable status remain
/// independent. Missing carrier pools cannot become successful source coverage.
pub struct Sources<'p, 'a, 'v, 's, S: RangeSource> {
    archive: &'v crate::zip::Archive<'s, S>,
    slots: OwnedVec<SourceSlot<'p, 'a, 'v, 's, S>>,
    open: OwnedVec<Open<'p, S::Document, S::Generation>>,
    complete: bool,
}
/// Caller misassociation and original processing remain terminal.
#[derive(Debug)]
pub enum SourcesError<E> {
    /// Actual source/current operation refused.
    Archive(ArchiveError<E>),
    /// A pool belongs to another archive or a non-CMS/TST original member.
    Foreign,
    /// Several supplied pools describe the same actual original source.
    Duplicate,
}
impl<'p, 'a, 'v, 's, S: RangeSource> Sources<'p, 'a, 'v, 's, S> {
    /// Derives slot order from the actual original census, not the caller's
    /// successful pool list. Every `CAdES`/TST file remains a source obligation.
    ///
    /// # Panics
    /// An internal census invariant fails if its own bounded ordinal is absent.
    pub fn read<W: Work>(
        census: &crate::layout::Census<'v, 's, S>,
        pools: &[&'p Pool<'a, 'v, 's, S>],
        work: &W,
    ) -> Result<Self, SourcesError<S::Error>> {
        use crate::layout::Role;
        let archive = census.archive();
        let execution = archive.session().query(work);
        archive
            .admit(&execution, archive.directory_span())
            .map_err(SourcesError::Archive)?;
        let refusal = |cause| SourcesError::Archive(resource(archive.directory_span(), cause));
        let mut selected = execution.map();
        for (index, pool) in pools.iter().enumerate() {
            execution.charge_work(1).map_err(refusal)?;
            if !core::ptr::eq(pool.content.member().archive(), archive) {
                return Err(SourcesError::Foreign);
            }
            let role = census
                .occurrence(pool.member().ordinal(), &execution)
                .map_err(SourcesError::Archive)?
                .map(|(_, role)| role);
            if !matches!(role, Some(Role::Cades | Role::Timestamp)) {
                return Err(SourcesError::Foreign);
            }
            if selected
                .try_insert(pool.member().ordinal(), index)
                .map_err(refusal)?
                .is_some()
            {
                return Err(SourcesError::Duplicate);
            }
        }
        let mut slots = execution.vector();
        let mut open = execution.vector();
        let mut complete = true;
        for ordinal in 0..census.len() {
            let (member, role) = census
                .occurrence(ordinal, &execution)
                .map_err(SourcesError::Archive)?
                .expect("original census bounds its ordinal");
            if !matches!(role, Role::Cades | Role::Timestamp) {
                continue;
            }
            let pool = selected
                .get(&ordinal, &execution)
                .map_err(refusal)?
                .map(|index| pools[*index]);
            if let Some(pool) = pool {
                for finding in pool.findings() {
                    open.try_push(Open {
                        member: member.id(),
                        finding,
                    })
                    .map_err(refusal)?;
                }
            } else {
                complete = false;
            }
            slots
                .try_push(SourceSlot {
                    member: member.id(),
                    pool,
                })
                .map_err(refusal)?;
        }
        archive
            .admit(&execution, archive.directory_span())
            .map_err(SourcesError::Archive)?;
        Ok(Self {
            archive,
            slots: slots.into_owned(),
            open: open.into_owned(),
            complete,
        })
    }
    /// All original carrier slots, retaining missing and negative sources.
    #[must_use]
    pub fn slots(&self) -> &[SourceSlot<'p, 'a, 'v, 's, S>] {
        &self.slots
    }
    /// Every original carrier has a completed first-read pool. This does not
    /// assert conformance or complete participant/path/status interpretation.
    #[must_use]
    pub fn all_sources_inspected(&self) -> bool {
        self.complete
    }
    /// Original malformed/open carrier findings, without replacing their causes.
    #[must_use]
    pub fn open(&self) -> &[Open<'p, S::Document, S::Generation>] {
        &self.open
    }
    /// One exact-artifact index over all available original pools. The full
    /// source census remains alongside it, so a missing source is never erased.
    pub fn index<'g, 'q, W: Work>(
        &'g self,
        work: &'q W,
    ) -> SourcesIndexResult<'g, 'q, 'p, 'v, 's, S>
    where
        'v: 'q,
        'a: 'g,
        'p: 'g,
    {
        let query = self.archive.ltv_query(work);
        let mut index =
            structured_ltv::material::Index::new(ISSUER, Node::Root, &self.open, &query)?;
        let mut ordinal = 0usize;
        for slot in &self.slots {
            index.admit(&query)?;
            if let Some(pool) = slot.pool {
                pool.append(&mut index, &query, &mut ordinal)?;
            }
        }
        Ok(index)
    }
}

/// Exact source-census material index, retaining borrowed original findings.
pub type SourcesIndexResult<'g, 'q, 'p, 'v, 's, S> = Result<
    IndexOf<
        'g,
        'q,
        'v,
        's,
        S,
        Open<'p, <S as RangeSource>::Document, <S as RangeSource>::Generation>,
    >,
    structured_ltv::material::IndexError<Node>,
>;
