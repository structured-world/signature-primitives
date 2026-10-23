//! Original root/token validation material, parsed once and indexed by the
//! existing exact-artifact LTV core. Reading never authenticates a status.

use crate::{
    Cades, Error, ISSUER,
    prepare::Preparation,
    source::{DocumentId, Node, Original},
};
use structured_asn1::{
    Reader,
    memory::{OwnedVec, Work},
};
use structured_cms::{SignedData, signed::CertificateChoice, timestamp::Token};
use structured_ltv::{
    material::{self, ArtifactRef, ArtifactSource, CarriedOrigin, Occurrence},
    source::Query,
};
use structured_pkix::{crl::CertificateList, ocsp::BasicResponse};

mod checks;
pub mod credentials;
mod legacy;
mod proof;
pub use checks::{CheckError, Checks, Finding, check_participants, check_participants_preserved};

/// Refusal to construct material scope for an actual checked archive owner.
#[derive(Debug)]
pub enum ArchiveIndexError {
    /// Negative timestamp facts cannot establish an archive's owner.
    Unproven,
    /// Original source, current query or indexed storage refused.
    Index(material::IndexError<Node>),
    /// The archive's exact token/coverage/source binding refused.
    Coverage(material::CoverageError<Node>),
}

/// Exact format-defined validation-values placement, without inventing a
/// root certificate CHOICE or a whole OCSP envelope around a basic body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyLocation {
    /// Actual signer which carries the attribute (including TSA signers).
    pub signature: Node,
    /// Original certificate/revocation-values attribute.
    pub property: Node,
    /// Member ordinal within that attribute's applicable SEQUENCE OF.
    pub member: usize,
    /// Actual outer timestamp carrier, or root/counter placement.
    pub token: Option<usize>,
    /// Observed unsigned placement, never a caller-configurable allowance.
    pub unsigned: bool,
}

/// Actual TS101733 long-term-validation member, never a root/TSA CHOICE alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoeLocation {
    /// Original owner signer, including an actual counter when applicable.
    pub signature: Node,
    /// Original long-term-validation unsigned attribute.
    pub property: Node,
    /// Original preparation proof ordinal.
    pub proof: usize,
    /// Original member within the certificate or revocation extra set.
    pub member: usize,
}

/// Real original material container; an OCSP envelope and the basic body it
/// carries are never confused with an invented envelope around supplied bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Original root `SignedData` certificate CHOICE ordinal.
    RootCertificate(usize),
    /// Original root `SignedData` revocation CHOICE ordinal.
    RootRevocation(usize),
    /// Certificate CHOICE of one original root/counter timestamp token.
    TokenCertificate {
        /// Original preparation timestamp ordinal.
        token: usize,
        /// Original certificate CHOICE ordinal.
        choice: usize,
    },
    /// Revocation CHOICE of one original root/counter timestamp token.
    TokenRevocation {
        /// Original preparation timestamp ordinal.
        token: usize,
        /// Original revocation CHOICE ordinal.
        choice: usize,
    },
    /// Actual Annex A certificate-values member.
    CertificateValues(LegacyLocation),
    /// Actual complete/delta CRL in Annex A revocation-values.
    CrlValues(LegacyLocation),
    /// Actual bare `BasicOCSPResponse` in Annex A revocation-values.
    OcspValues(LegacyLocation),
    /// Actual OID-owned open values in Annex A revocation-values.
    OtherRevocationValues(LegacyLocation),
    /// Actual `extraCertificates` member of a `PoE` enclosure.
    PoeCertificate(PoeLocation),
    /// Actual `extraRevocation` member of a `PoE` enclosure.
    PoeRevocation(PoeLocation),
}

/// Uninterpreted material remains available to its owner. A known syntax
/// failure retains its original cause rather than becoming an unknown OID.
pub struct Open<'a> {
    /// Untouched original encoding, retaining unknown values without reparse.
    pub element: structured_asn1::Element<'a>,
    /// Whole physical original enclosure and protecting document identity.
    pub node: Node,
    /// Original container placement, independently of usability or coverage.
    pub placement: Placement,
    /// An unknown format has no schema failure; a known malformed value does.
    pub cause: Option<Error>,
}

struct Crl<'d> {
    value: CertificateList<'d>,
    node: Node,
    placement: Placement,
}
struct Ocsp<'d> {
    value: BasicResponse<'d>,
    node: Node,
    placement: Placement,
}

/// Complete original source pool. Every readable timestamp envelope is held
/// once; CRL/OCSP models are parsed once, and index creation never replays them.
pub struct Pool<'prepared, 'model, 'document> {
    prepared: &'prepared Preparation<'model, 'document>,
    tokens: &'prepared crate::prepare::tokens::Cache<'model, 'document>,
    token_faults: &'prepared [(Node, crate::prepare::ReadError)],
    crls: OwnedVec<Crl<'document>>,
    ocsp: OwnedVec<Ocsp<'document>>,
    open: OwnedVec<Open<'document>>,
    related: OwnedVec<legacy::Related<'document>>,
    legacy_slots: Option<legacy::Slots>,
    proof_slots: OwnedVec<proof::Slot>,
}

/// Existing exact-artifact core in this original `CAdES` identity domain.
pub type Index<'source, 'model, 'document, W> = material::Index<
    'source,
    Node,
    DocumentId<'model, 'document>,
    (),
    Placement,
    Open<'document>,
    W,
    Cades,
>;

impl<'p, 'm, 'd> Pool<'p, 'm, 'd> {
    /// Read the entire original source pool, preserving unreadable token and
    /// known material findings. Resource/depth/processing refusal is terminal,
    /// releases partial models and never returns a successful partial pool.
    pub fn read(prepared: &'p Preparation<'m, 'd>, operation: &Reader<'d>) -> crate::Result<Self> {
        prepared
            .document()
            .message()
            .require_session(operation, "cades.material")?;
        let work = operation.execution();
        let tokens = &prepared.parsed;
        let mut crls = work.vector();
        let mut ocsp = work.vector();
        let mut open = work.vector();
        collect(
            prepared.document().message(),
            None,
            operation,
            &mut crls,
            &mut ocsp,
            &mut open,
        )?;
        for ordinal in 0..prepared.timestamps().len() {
            work.charge_work(1).map_err(|cause| {
                Error::resource(cause, "cades.material", prepared.signer().span().start)
            })?;
            let Some(model) = tokens.token(ordinal) else {
                continue;
            };
            collect(
                model.token.message(),
                Some(model.ordinal),
                operation,
                &mut crls,
                &mut ocsp,
                &mut open,
            )?;
        }
        let related = legacy::read_related(prepared, operation)?;
        legacy::append_open(prepared, tokens, &related, &mut open, &work)?;
        let proof_slots = proof::collect(prepared, operation, &mut crls, &mut ocsp, &mut open)?;
        let mut out = Self {
            prepared,
            tokens,
            token_faults: &prepared.parsed.faults,
            crls: crls.into_owned(),
            ocsp: ocsp.into_owned(),
            open: open.into_owned(),
            related,
            legacy_slots: None,
            proof_slots,
        };
        out.legacy_slots = legacy::slots(&out, &work)?;
        Ok(out)
    }
    /// Same source preparation; the pool cannot be relabelled to another root.
    #[must_use]
    pub fn prepared(&self) -> &'p Preparation<'m, 'd> {
        self.prepared
    }
    /// Every unreadable original timestamp and its retained failure.
    #[must_use]
    pub fn token_faults(&self) -> &[(Node, crate::prepare::ReadError)] {
        self.token_faults
    }
    /// Every original unknown or known-malformed material enclosure.
    #[must_use]
    pub fn open(&self) -> &[Open<'d>] {
        &self.open
    }
    /// Number of original readable complete/delta CRL values, without parsing.
    #[must_use]
    pub fn crls(&self) -> usize {
        self.crls.len()
            + self
                .legacy_slots
                .as_ref()
                .map_or(0, |slots| slots.crls.len())
    }
    /// One original parsed CRL under current metadata admission. Authentication
    /// and status processing reuse this model; they must not reparse its bytes.
    pub fn crl<W: Work>(
        &self,
        ordinal: usize,
        work: &W,
    ) -> crate::Result<Option<&CertificateList<'d>>> {
        work.charge_work(1).map_err(|cause| {
            Error::resource(
                cause,
                "cades.material.crl",
                self.prepared.signer().span().start,
            )
        })?;
        if ordinal < self.crls.len() {
            return Ok(Some(&self.crls[ordinal].value));
        }
        legacy::crl(self, ordinal - self.crls.len(), work)
    }
    /// Number of original readable basic responses in their real wire format.
    #[must_use]
    pub fn ocsp_responses(&self) -> usize {
        self.ocsp.len()
            + self
                .legacy_slots
                .as_ref()
                .map_or(0, |slots| slots.ocsp.len())
    }
    /// One first-read basic response, from a whole RFC5940 envelope or actual
    /// Annex A revocation-values. The index retains its real placement.
    pub fn ocsp<W: Work>(
        &self,
        ordinal: usize,
        work: &W,
    ) -> crate::Result<Option<&BasicResponse<'d>>> {
        work.charge_work(1).map_err(|cause| {
            Error::resource(
                cause,
                "cades.material.ocsp",
                self.prepared.signer().span().start,
            )
        })?;
        if ordinal < self.ocsp.len() {
            return Ok(Some(&self.ocsp[ordinal].value));
        }
        legacy::ocsp(self, ordinal - self.ocsp.len(), work)
    }
    /// Original timestamp envelopes, indexed by original preparation ordinal.
    /// This paid query reuses the parsed envelope rather than reparsing it.
    pub fn token<W: Work>(&self, ordinal: usize, work: &W) -> crate::Result<Option<&Token<'d>>> {
        work.charge_work(1).map_err(|cause| {
            Error::resource(cause, "cades.material", self.prepared.signer().span().start)
        })?;
        Ok(self.tokens.token(ordinal).map(|model| model.token))
    }
    /// Visit a previously parsed original token with the current operation.
    /// Uses its saved parser/encoding/depth, with no second envelope parse.
    pub fn with_token<R, E>(
        &self,
        ordinal: usize,
        operation: &Reader<'d>,
        visitor: impl for<'scope> FnOnce(crate::timestamp::Context<'scope, 'm, 'd>) -> Result<R, E>,
    ) -> Result<R, crate::timestamp::VisitError<E>> {
        operation.charge(1).map_err(|cause| {
            crate::timestamp::VisitError::Processing(Error::encoding(cause, "cades.timestamp"))
        })?;
        let entry = self.prepared.timestamps().get(ordinal).ok_or_else(|| {
            crate::timestamp::VisitError::Processing(Error::Foreign {
                at: self.prepared.signer().span().start,
            })
        })?;
        let token = self
            .token(ordinal, &operation.execution())
            .map_err(crate::timestamp::VisitError::Processing)?
            .ok_or_else(|| crate::timestamp::VisitError::Unreadable {
                property: entry.property(),
            })?;
        crate::timestamp::with_existing(self.prepared, ordinal, token, operation, visitor)
    }
    /// Build material scope for the actual successful archive owner, including
    /// a historical counter or parallel root. Sources are the same original
    /// pool; no signature is replayed and no parsed artifact is cloned.
    pub fn index_for_archive<'source, Q>(
        &'source self,
        archive: crate::timestamp::ArchiveView<'_, 'm, 'd, '_>,
        query: &Q,
    ) -> Result<Index<'source, 'm, 'd, Q::Work>, ArchiveIndexError>
    where
        Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
        'd: 'source,
    {
        let actor = archive
            .timestamp()
            .actor()
            .ok_or(ArchiveIndexError::Unproven)?;
        let evidence = actor.verified();
        let snapshot = self
            .prepared
            .document()
            .locate(self.prepared.signer().span())
            .snapshot;
        if evidence.token().snapshot != snapshot || query.snapshot() != snapshot {
            return Err(ArchiveIndexError::Index(material::IndexError::Foreign {
                signature: evidence.signature(),
            }));
        }
        archive
            .coverage()
            .require_evidence(evidence, archive.coverage().subject(), query)
            .map_err(ArchiveIndexError::Coverage)?;
        self.index_for_signature(evidence.signature(), query)
            .map_err(ArchiveIndexError::Index)
    }

    fn index_for_signature<'source, Q>(
        &'source self,
        signature: Node,
        query: &Q,
    ) -> Result<Index<'source, 'm, 'd, Q::Work>, material::IndexError<Node>>
    where
        Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
        'd: 'source,
    {
        let mut index = Index::new(ISSUER, signature, &self.open, query)?;
        certificates(
            self.prepared.document().message(),
            None,
            self.prepared,
            &mut index,
            query,
        )?;
        for ordinal in 0..self.prepared.timestamps().len() {
            query
                .admit(signature, 1)
                .map_err(material::IndexError::Scope)?;
            let Some(token) = self.tokens.token(ordinal) else {
                continue;
            };
            certificates(
                token.token.message(),
                Some(token.ordinal),
                self.prepared,
                &mut index,
                query,
            )?;
        }
        for crl in &self.crls {
            query
                .admit(signature, 1)
                .map_err(material::IndexError::Scope)?;
            if matches!(crl.placement, Placement::PoeRevocation(_)) {
                continue;
            }
            index.insert(
                ISSUER,
                ArtifactRef::Crl(&crl.value),
                revocation_occurrence(self.prepared, crl.node, crl.placement)?,
                query,
            )?;
        }
        for response in &self.ocsp {
            query
                .admit(signature, 1)
                .map_err(material::IndexError::Scope)?;
            if matches!(response.placement, Placement::PoeRevocation(_)) {
                continue;
            }
            index.insert(
                ISSUER,
                ArtifactRef::Ocsp(&response.value),
                revocation_occurrence(self.prepared, response.node, response.placement)?,
                query,
            )?;
        }
        let next = legacy::index(self, &mut index, query)?;
        proof::index(self, &mut index, query, next)?;
        Ok(index)
    }

    /// Build the one exact-artifact index from actual root/token locations.
    /// Models remain borrowed; no certificate/CRL/status byte copy or parser
    /// replay occurs. The current query funds all new hashing/probing/storage.
    pub fn index<'source, Q>(
        &'source self,
        query: &Q,
    ) -> Result<Index<'source, 'm, 'd, Q::Work>, material::IndexError<Node>>
    where
        Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
        'd: 'source,
    {
        let signature = self
            .prepared
            .document()
            .locate(self.prepared.signer().span());
        if query.snapshot() != signature.snapshot {
            return Err(material::IndexError::Foreign {
                signature: signature.node,
            });
        }
        self.index_for_signature(signature.node, query)
    }
}

fn certificates<'s, 'm, 'd, Q>(
    message: &'s SignedData<'d>,
    token: Option<usize>,
    prepared: &Preparation<'m, 'd>,
    index: &mut Index<'s, 'm, 'd, Q::Work>,
    query: &Q,
) -> Result<(), material::IndexError<Node>>
where
    Q: Query<Id = Node, Document = DocumentId<'m, 'd>, Generation = ()>,
    'd: 's,
{
    for (choice, entry) in message.certificate_choices().iter().enumerate() {
        index.admit(query)?;
        if let CertificateChoice::X509(ordinal) = entry {
            let value = &message.certificates()[*ordinal];
            let placement = match token {
                Some(token) => Placement::TokenCertificate { token, choice },
                None => Placement::RootCertificate(choice),
            };
            let source = match token {
                Some(token) => ArtifactSource::TokenCertificate {
                    token,
                    certificate: *ordinal,
                },
                None => ArtifactSource::Material(choice),
            };
            let enclosure = if let Some(token) = token {
                token_enclosure(prepared, token)?
            } else {
                Node::of(value.span())
            };
            index.insert(
                ISSUER,
                ArtifactRef::Certificate(value),
                Occurrence::new(
                    source,
                    prepared.document().locate(enclosure.span()),
                    placement,
                ),
                query,
            )?;
        }
    }
    Ok(())
}

fn token_enclosure(
    prepared: &Preparation<'_, '_>,
    token: usize,
) -> Result<Node, material::IndexError<Node>> {
    let Some(value) = prepared
        .timestamps()
        .get(token)
        .and_then(crate::prepare::Timestamp::value)
    else {
        return Err(material::IndexError::Foreign {
            signature: Node::of(prepared.signer().span()),
        });
    };
    Ok(Node::of(value.span()))
}

fn revocation_occurrence<'m, 'd>(
    prepared: &Preparation<'m, 'd>,
    node: Node,
    placement: Placement,
) -> Result<Occurrence<Node, DocumentId<'m, 'd>, (), Placement>, material::IndexError<Node>> {
    let signature = Node::of(prepared.signer().span());
    let (source, enclosure) = match placement {
        Placement::RootRevocation(ordinal) => {
            let ordinal = prepared
                .document()
                .message()
                .certificate_choices()
                .len()
                .checked_add(ordinal)
                .ok_or(material::IndexError::Resource {
                    signature,
                    cause: structured_asn1::memory::MemoryError::CapacityOverflow,
                })?;
            (ArtifactSource::Material(ordinal), node)
        }
        Placement::TokenRevocation { token, choice } => (
            ArtifactSource::TokenRevocation(CarriedOrigin { token, choice }),
            token_enclosure(prepared, token)?,
        ),
        Placement::RootCertificate(_)
        | Placement::TokenCertificate { .. }
        | Placement::CertificateValues(_)
        | Placement::CrlValues(_)
        | Placement::OcspValues(_)
        | Placement::OtherRevocationValues(_)
        | Placement::PoeCertificate(_)
        | Placement::PoeRevocation(_) => {
            return Err(material::IndexError::Foreign { signature });
        }
    };
    // The real token carrier is the whole-item archive coverage boundary.
    // ArtifactSource+Placement retain the exact inner value ordinal; no ASN.1
    // inner offset is passed off as a separate top-level source or pool slot.
    let location = Original {
        snapshot: prepared.document().locate(enclosure.span()).snapshot,
        node: enclosure,
    };
    Ok(Occurrence::new(source, location, placement))
}

fn collect<'d, W: Work>(
    message: &SignedData<'d>,
    token: Option<usize>,
    operation: &Reader<'d>,
    crls: &mut OwnedVec<Crl<'d>, W>,
    ocsp: &mut OwnedVec<Ocsp<'d>, W>,
    open: &mut OwnedVec<Open<'d>, W>,
) -> crate::Result<()> {
    for (choice, certificate) in message.certificate_choices().iter().enumerate() {
        operation
            .charge(1)
            .map_err(|cause| Error::encoding(cause, "cades.material"))?;
        let element = match certificate {
            CertificateChoice::X509(_) => continue,
            CertificateChoice::Extended(element)
            | CertificateChoice::AttributeV1(element)
            | CertificateChoice::AttributeV2(element)
            | CertificateChoice::Other(element) => *element,
        };
        let placement = match token {
            Some(token) => Placement::TokenCertificate { token, choice },
            None => Placement::RootCertificate(choice),
        };
        push_open(open, element, placement, None)?;
    }
    for (choice, element) in message.revocations().iter().enumerate() {
        operation
            .charge(1)
            .map_err(|cause| Error::encoding(cause, "cades.material"))?;
        let placement = match token {
            Some(token) => Placement::TokenRevocation { token, choice },
            None => Placement::RootRevocation(choice),
        };
        let reader = message
            .revocation_reader_in(operation, choice)?
            .ok_or(Error::Foreign {
                at: element.span().start,
            })?;
        proof::revocation(&reader, element, placement, operation, crls, ocsp, open)?;
    }
    Ok(())
}

fn push_open<'a, W: Work>(
    out: &mut OwnedVec<Open<'a>, W>,
    element: structured_asn1::Element<'a>,
    placement: Placement,
    cause: Option<Error>,
) -> crate::Result<()> {
    out.try_push(Open {
        element,
        node: Node::of(element.span()),
        placement,
        cause,
    })
    .map_err(|cause| Error::resource(cause, "cades.material", element.span().start))
}
