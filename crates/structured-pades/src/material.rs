//! Revision-bound DSS/VRI material over actual decoded PDF stream objects.

use crate::arena::{Kind, NodeId};
use crate::document::{Document, Reading};
use crate::error::{Error, ErrorKind, ReadFailure, Syntax};
use crate::model::{admit, get};
use crate::range::{RangeSource, Stamp};
use crate::source::Location;
use structured_asn1::memory::{Memory, OwnedMap, OwnedVec, Work};
mod history;
mod membership;
mod parsed;
pub use history::{History, HistoryError, ParsedHistory, Unified};
pub mod checks;
pub mod credentials;
pub mod vri;
pub use parsed::{MaterialIndex, Parsed, Placement, TimestampValue, TokenChoice, Value};

/// Syntax of a validation object, independent of authentication or usability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindOf {
    /// An X.509 certificate stream.
    Certificate,
    /// A whole X.509 `CertificateList` stream.
    Crl,
    /// A whole RFC6960 `OCSPResponse` stream.
    Ocsp,
    /// A VRI RFC3161 time-stamp token stream.
    Timestamp,
}

/// Whole-DER material, retaining its actual stream definition and historical
/// visibility. An OCSP value is the complete `OCSPResponse`, never just its body.
pub struct Item<'s> {
    kind: KindOf,
    bytes: OwnedVec<u8, Memory>,
    location: Location,
    number: u64,
    generation: u16,
    session: &'s crate::Session,
}

impl Item<'_> {
    /// Format named by the original DSS/VRI array.
    #[must_use]
    pub fn kind(&self) -> KindOf {
        self.kind
    }
    /// Whole original decoded DER value, without re-encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Physical encoded stream enclosure of these logical DER bytes.
    #[must_use]
    pub fn location(&self) -> Location {
        self.location
    }
    /// Indirect identity selected in the material's historical revision.
    #[must_use]
    pub fn identity(&self) -> (u64, u16) {
        (self.number, self.generation)
    }

    /// Opens this exact retained material using original and current budgets.
    pub fn read<'a, W: Work + 'a>(
        &'a self,
        operation: &W,
    ) -> Result<(Decoded<'a>, structured_asn1::Reader<'a>), MaterialError> {
        let mut reader = self
            .session
            .carried(&self.bytes, operation)
            .map_err(MaterialError::Encoding)?;
        if self.kind == KindOf::Timestamp {
            let token = structured_cms::timestamp::Token::read_from(&mut reader)
                .map_err(MaterialError::Cms)?;
            if !reader.is_empty() {
                return Err(MaterialError::Pdf(Error {
                    kind: ErrorKind::Syntax(Syntax::Stream),
                    location: self.location,
                }));
            }
            return Ok((Decoded::Timestamp(token), reader));
        }
        let element = reader
            .next_element()
            .map_err(MaterialError::Encoding)?
            .ok_or(MaterialError::Pdf(Error {
                kind: ErrorKind::Syntax(Syntax::Stream),
                location: self.location,
            }))?;
        if element.as_bytes().len() != self.bytes.len() {
            return Err(MaterialError::Pdf(Error {
                kind: ErrorKind::Syntax(Syntax::Stream),
                location: self.location,
            }));
        }
        let decoded = match self.kind {
            KindOf::Certificate => Decoded::Certificate(
                structured_pkix::Certificate::read_element(&reader, &element)
                    .map_err(MaterialError::Pkix)?,
            ),
            KindOf::Crl => Decoded::Crl(
                structured_pkix::crl::CertificateList::read_element(&reader, &element)
                    .map_err(MaterialError::Pkix)?,
            ),
            KindOf::Ocsp => Decoded::Ocsp(
                structured_pkix::ocsp::Response::read_element(&reader, &element)
                    .map_err(MaterialError::Pkix)?,
            ),
            KindOf::Timestamp => unreachable!("timestamp decoded before element consumption"),
        };
        Ok((decoded, reader))
    }
}

/// Original material parser result; parsing does not establish issuer trust.
pub enum Decoded<'a> {
    /// Actual parsed certificate, without a path/trust result.
    Certificate(structured_pkix::Certificate<'a>),
    /// Actual parsed CRL, without issuer authentication or status usability.
    Crl(structured_pkix::crl::CertificateList<'a>),
    /// Whole response, retaining unsigned protocol failures separately.
    Ocsp(structured_pkix::ocsp::Response<'a>),
    /// Parsed VRI timestamp, without an imprint or authority assertion.
    Timestamp(structured_cms::timestamp::Token<'a>),
}

/// Original error coordinates remain logical within [`Item::location`].
#[derive(Debug)]
pub enum MaterialError {
    /// PDF material placement or extent violation.
    Pdf(Error),
    /// Original carried DER syntax or resource refusal.
    Encoding(structured_asn1::Error),
    /// Original certificate/status syntax or resource refusal.
    Pkix(structured_pkix::Error),
    /// Original VRI timestamp syntax or resource refusal.
    Cms(structured_cms::Error),
}

/// Terminal material failure retaining the actual encoded item's enclosure.
#[derive(Debug)]
pub struct MaterialFailure {
    /// Original encoded stream body, independent of inner logical offsets.
    pub location: Location,
    /// Unchanged grammar, resource or caller-misuse cause.
    pub cause: MaterialError,
}
impl MaterialError {
    /// Processing/resource/source misuse is never a malformed-value finding.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::Pdf(cause) => matches!(
                cause.kind,
                ErrorKind::Resource(_) | ErrorKind::Limit(_) | ErrorKind::Foreign
            ),
            Self::Encoding(cause) => cause.is_resource(),
            Self::Pkix(cause) => {
                cause.is_resource() || cause.code() == structured_pkix::ErrorCode::ForeignReader
            }
            Self::Cms(cause) => cause.is_terminal(),
        }
    }
}

/// One original VRI dictionary. Material indices refer only to THIS owning
/// historical material set; a later DSS cannot fill an earlier VRI silently.
pub struct Vri {
    name: [u8; 40],
    location: Location,
    certs: OwnedVec<usize, Memory>,
    crls: OwnedVec<usize, Memory>,
    ocsp: OwnedVec<usize, Memory>,
    update: Option<crate::date::Date>,
    timestamp: Option<usize>,
    incorporated: bool,
}

/// Original VRI generation-time method, without asserting its trusted time.
#[derive(Debug, Clone, Copy)]
pub enum GenerationTime {
    /// Written TU is a claimed label, not a timestamp proof.
    Claimed(crate::date::Date),
    /// Written TS points into this same historical Validation item pool.
    Token(usize),
    /// Neither field was written; a covering subsequent document timestamp
    /// must still be established from its actual source and checked input.
    DocumentTimestampRequired,
}

impl Vri {
    /// Every referenced certificate/status value is also present in the
    /// corresponding DSS array in this SAME historical revision. This checks
    /// exact decoded values, not just object-number equality or a later DSS.
    #[must_use]
    pub fn all_material_in_dss(&self) -> bool {
        self.incorporated
    }
    /// Uppercase SHA-1 name written in the original VRI index.
    #[must_use]
    pub fn name(&self) -> &[u8; 40] {
        &self.name
    }
    /// Actual original VRI dictionary key location.
    #[must_use]
    pub fn location(&self) -> Location {
        self.location
    }
    /// Certificate occurrences in the same historical validation owner.
    #[must_use]
    pub fn certificates(&self) -> &[usize] {
        &self.certs
    }
    /// CRL occurrences in the same historical validation owner.
    #[must_use]
    pub fn crls(&self) -> &[usize] {
        &self.crls
    }
    /// OCSP occurrences in the same historical validation owner.
    #[must_use]
    pub fn ocsp(&self) -> &[usize] {
        &self.ocsp
    }
    /// Whether TU, rather than TS, was written in this original VRI.
    #[must_use]
    pub fn update_time(&self) -> Option<crate::date::Date> {
        self.update
    }
    /// Actual VRI timestamp item in the same validation owner.
    #[must_use]
    pub fn timestamp(&self) -> Option<usize> {
        self.timestamp
    }
    /// EN319142-1 §5.4.2.3(c)'s three distinct methods. This preserves the
    /// unmet subsequent-timestamp obligation instead of fabricating a time.
    #[must_use]
    pub fn generation_time(&self) -> GenerationTime {
        if let Some(value) = self.update {
            return GenerationTime::Claimed(value);
        }
        if let Some(value) = self.timestamp {
            return GenerationTime::Token(value);
        }
        GenerationTime::DocumentTimestampRequired
    }
}

/// Complete material occurrence census in one explicitly selected revision.
/// Absence is represented independently of an empty but present dictionary.
pub struct Validation<'s, D, G> {
    session: &'s crate::Session,
    stamp: Stamp<D, G>,
    revision: usize,
    present: bool,
    items: OwnedVec<Item<'s>, Memory>,
    vri: OwnedVec<Vri, Memory>,
    vri_names: OwnedMap<vri::Name, usize, Memory>,
    incorporated: bool,
}

impl<D: Copy + Eq, G: Copy + Eq> Validation<'_, D, G> {
    /// Immutable source identity of all retained material occurrences.
    #[must_use]
    pub fn stamp(&self) -> Stamp<D, G> {
        self.stamp
    }
    /// Historical ordinal, never an implicit latest-revision selection.
    #[must_use]
    pub fn revision(&self) -> usize {
        self.revision
    }
    /// Distinguishes an absent DSS from an explicitly present empty one.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.present
    }
    /// All original DSS and VRI material occurrences, without copying.
    #[must_use]
    pub fn items(&self) -> &[Item<'_>] {
        &self.items
    }
    /// Every original VRI, independently of whether its name matches a signature.
    #[must_use]
    pub fn vri(&self) -> &[Vri] {
        &self.vri
    }
    /// All original VRI validation values also occur in their corresponding
    /// DSS arrays in this revision, independently of DER readability/trust.
    #[must_use]
    pub fn all_vri_material_in_dss(&self) -> bool {
        self.incorporated
    }
}

impl<'s, S: RangeSource> Document<'s, S> {
    async fn dss_items<W: Work, Q: Work>(
        &self,
        revision: usize,
        dss: &Reading<'s, S::Document, S::Generation>,
        items: &mut OwnedVec<Item<'s>, W>,
        work: &Q,
    ) -> Result<(), ReadFailure<S::Error>> {
        for (key, kind) in [
            (b"Certs".as_slice(), KindOf::Certificate),
            (b"CRLs", KindOf::Crl),
            (b"OCSPs", KindOf::Ocsp),
        ] {
            if let Some(array) = get(&dss.value.arena, dss.value.root, key, work)? {
                let Some(references) = array_references(self, dss, array, work).await? else {
                    continue;
                };
                for &(number, generation) in &references {
                    let item = material(self, revision, number, generation, kind, work).await?;
                    items.try_push(item).map_err(|cause| Error {
                        kind: ErrorKind::Resource(cause),
                        location: dss.value.root().location(),
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Reads the historical catalog's DSS/VRI and every referenced material
    /// stream using the common DER readers. This performs no status selection,
    /// authentication, network retrieval or latest-revision substitution.
    ///
    /// # Panics
    /// Panics if the checked original file extent cannot be retained as a location.
    pub async fn validation<W: Work>(
        &self,
        revision: usize,
        operation: &W,
    ) -> Result<Validation<'s, S::Document, S::Generation>, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let root = self.root(revision, &work).await?;
        let dss = self.select(root, b"DSS", &work).await?;
        let present = dss.is_some();
        let mut items = work.vector();
        let mut vri = work.vector();
        let mut vri_names = work.map();
        let mut incorporated = true;
        if let Some(dss) = dss {
            type_name(self, &dss, dss.value.root, b"DSS", &work).await?;
            self.dss_items(revision, &dss, &mut items, &work).await?;
            let membership =
                membership::Membership::new(&items, dss.value.root().location(), &work)?;
            if let Some(index_owner) = self.select(dss, b"VRI", &work).await? {
                let Kind::Dictionary(_, fields) =
                    index_owner.value.arena.nodes[index_owner.value.root.0].kind
                else {
                    return Err(Error {
                        kind: ErrorKind::Syntax(Syntax::Dictionary),
                        location: index_owner.value.root().location(),
                    }
                    .into());
                };
                for ordinal in fields.start..fields.start + fields.length {
                    admit(&work, index_owner.value.root().location(), 1)?;
                    let entry = index_owner.value.arena.fields[ordinal];
                    let resolved;
                    let (owner, node) = if let Kind::Reference { number, generation } =
                        index_owner.value.arena.nodes[entry.value.0].kind
                    {
                        resolved = self.object(revision, number, generation, &work).await?;
                        let Some(owner) = &resolved else { continue };
                        if matches!(owner.value.arena.nodes[owner.value.root.0].kind, Kind::Null) {
                            continue;
                        }
                        (owner, owner.value.root)
                    } else {
                        (&index_owner, entry.value)
                    };
                    let (name, location) = vri_name(&index_owner.value.arena, entry.key, &work)?;
                    let (certs, crls, ocsp, update, timestamp) =
                        vri_members(self, owner, node, &mut items, &work).await?;
                    if vri_names
                        .try_insert(vri::Name(name), vri.len())
                        .map_err(|cause| Error {
                            kind: ErrorKind::Resource(cause),
                            location,
                        })?
                        .is_some()
                    {
                        return Err(Error {
                            kind: ErrorKind::Syntax(Syntax::Dictionary),
                            location,
                        }
                        .into());
                    }
                    let member_incorporated =
                        incorporation(&membership, &items, [&certs, &crls, &ocsp], &work)?;
                    if !member_incorporated {
                        incorporated = false;
                    }
                    vri.try_push(Vri {
                        name,
                        location,
                        certs,
                        crls,
                        ocsp,
                        update,
                        timestamp,
                        incorporated: member_incorporated,
                    })
                    .map_err(|cause| Error {
                        kind: ErrorKind::Resource(cause),
                        location,
                    })?;
                }
            }
        }
        self.check(
            &work,
            Location::new(crate::source::Source::File, 0, self.stamp.length).expect("file range"),
        )?;
        Ok(Validation {
            session: self.session,
            stamp: self.stamp,
            revision,
            present,
            items: items.into_owned(),
            vri: vri.into_owned(),
            vri_names: vri_names.into_owned(),
            incorporated,
        })
    }
}

fn incorporation<W: Work>(
    membership: &membership::Membership<W>,
    items: &[Item<'_>],
    pools: [&[usize]; 3],
    work: &impl Work,
) -> crate::Result<bool> {
    let mut complete = true;
    for pool in pools {
        for &ordinal in pool {
            if !membership.contains(items, &items[ordinal], work)? {
                complete = false;
            }
        }
    }
    Ok(complete)
}

fn vri_name(
    arena: &crate::arena::Arena<impl Work>,
    key_node: NodeId,
    work: &impl Work,
) -> crate::Result<([u8; 40], Location)> {
    let Kind::Name(key) = arena.nodes[key_node.0].kind else {
        unreachable!("dictionary name")
    };
    let location = arena.nodes[key_node.0].location;
    if key.length != 40 {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Name),
            location,
        });
    }
    admit(work, location, 40)?;
    let mut name = [0_u8; 40];
    for (output, &byte) in name.iter_mut().zip(&arena.names[key.start..key.start + 40]) {
        if !matches!(byte, b'0'..=b'9' | b'A'..=b'F') {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Name),
                location,
            });
        }
        *output = byte;
    }
    Ok((name, location))
}

async fn array_references<S: RangeSource>(
    document: &Document<'_, S>,
    owner: &Reading<'_, S::Document, S::Generation>,
    node: NodeId,
    work: &impl Work,
) -> Result<Option<OwnedVec<(u64, u16), Memory>>, ReadFailure<S::Error>> {
    let Some(selected) = document.resolve_value(owner, node, work).await? else {
        return Ok(None);
    };
    let (owner, node) = selected.parts();
    let arena = &owner.value.arena;
    let Kind::Array(children) = arena.nodes[node.0].kind else {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Dictionary),
            location: arena.nodes[node.0].location,
        }
        .into());
    };
    let mut output = work.vector();
    let mut next = children.first;
    while let Some(index) = next {
        admit(work, arena.nodes[node.0].location, 1)?;
        let link = arena.links[index];
        next = link.next;
        let Kind::Reference { number, generation } = arena.nodes[link.value.0].kind else {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Object),
                location: arena.nodes[link.value.0].location,
            }
            .into());
        };
        output
            .try_push((number, generation))
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location: arena.nodes[link.value.0].location,
            })?;
    }
    Ok(Some(output.into_owned()))
}

async fn material<'s, S: RangeSource>(
    document: &Document<'s, S>,
    revision: usize,
    number: u64,
    generation: u16,
    kind: KindOf,
    work: &impl Work,
) -> Result<Item<'s>, ReadFailure<S::Error>> {
    let reading = document
        .object(revision, number, generation, work)
        .await?
        .ok_or(Error {
            kind: ErrorKind::Syntax(Syntax::Object),
            location: Location::new(crate::source::Source::File, 0, 0).expect("file point"),
        })?;
    material_reading(document, &reading, number, generation, kind, work).await
}

async fn material_reading<'s, S: RangeSource>(
    document: &Document<'s, S>,
    reading: &Reading<'s, S::Document, S::Generation>,
    number: u64,
    generation: u16,
    kind: KindOf,
    work: &impl Work,
) -> Result<Item<'s>, ReadFailure<S::Error>> {
    let decoded = document.stream_data(reading, false, work).await?;
    let item = Item {
        kind,
        bytes: decoded.bytes,
        location: Location::new(
            crate::source::Source::File,
            decoded.body.start,
            decoded.body.length,
        )
        .expect("checked stream extent"),
        number,
        generation,
        session: document.session,
    };
    Ok(item)
}

type VriMembers = (
    OwnedVec<usize>,
    OwnedVec<usize>,
    OwnedVec<usize>,
    Option<crate::date::Date>,
    Option<usize>,
);

async fn vri_members<'s, S: RangeSource, W: Work>(
    document: &Document<'s, S>,
    owner: &Reading<'s, S::Document, S::Generation>,
    node: NodeId,
    items: &mut OwnedVec<Item<'s>, W>,
    work: &impl Work,
) -> Result<VriMembers, ReadFailure<S::Error>> {
    let location = owner.value.arena.nodes[node.0].location;
    type_name(document, owner, node, b"VRI", work).await?;
    let mut certs = work.vector();
    let mut crls = work.vector();
    let mut ocsp = work.vector();
    for (key, kind, output) in [
        (b"Cert".as_slice(), KindOf::Certificate, &mut certs),
        (b"CRL", KindOf::Crl, &mut crls),
        (b"OCSP", KindOf::Ocsp, &mut ocsp),
    ] {
        if let Some(array) = get(&owner.value.arena, node, key, work)? {
            let Some(references) = array_references(document, owner, array, work).await? else {
                continue;
            };
            if references.is_empty() {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::Dictionary),
                    location,
                }
                .into());
            }
            for &(number, generation) in &references {
                let item =
                    material(document, owner.revision, number, generation, kind, work).await?;
                let index = items.len();
                output.try_push(index).map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
                items.try_push(item).map_err(|cause| Error {
                    kind: ErrorKind::Resource(cause),
                    location,
                })?;
            }
        }
    }
    let (update, timestamp) = vri_generation(document, owner, node, items, work).await?;
    Ok((
        certs.into_owned(),
        crls.into_owned(),
        ocsp.into_owned(),
        update,
        timestamp,
    ))
}

async fn vri_generation<'s, S: RangeSource, W: Work>(
    document: &Document<'s, S>,
    owner: &Reading<'s, S::Document, S::Generation>,
    node: NodeId,
    items: &mut OwnedVec<Item<'s>, W>,
    work: &impl Work,
) -> Result<(Option<crate::date::Date>, Option<usize>), ReadFailure<S::Error>> {
    let location = owner.value.arena.nodes[node.0].location;
    let update = if let Some(value) = get(&owner.value.arena, node, b"TU", work)? {
        document.resolve_value(owner, value, work).await?
    } else {
        None
    };
    let timestamp_node = get(&owner.value.arena, node, b"TS", work)?;
    let timestamp = if let Some(value) = timestamp_node {
        document.resolve_value(owner, value, work).await?
    } else {
        None
    };
    // EN319142-1 §5.4.2.3(c) also permits a subsequent document timestamp;
    // inspection preserves that unfulfilled method when both fields are absent.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf
    if update.is_some() && timestamp.is_some() {
        return Err(Error {
            kind: ErrorKind::Syntax(Syntax::Dictionary),
            location,
        }
        .into());
    }
    let update = if let Some(value) = update {
        let (owner, node) = value.parts();
        let bytes = document.string(owner, node, 22, work).await?;
        Some(crate::date::Date::read(
            &bytes,
            owner.value.arena.nodes[node.0].location,
            work,
        )?)
    } else {
        None
    };
    let timestamp = if let Some(value) = timestamp {
        let node = timestamp_node.expect("a resolved timestamp has an original field");
        let Kind::Reference { number, generation } = owner.value.arena.nodes[node.0].kind else {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Stream),
                location: owner.value.arena.nodes[node.0].location,
            }
            .into());
        };
        let (reading, _) = value.parts();
        let item = material_reading(
            document,
            reading,
            number,
            generation,
            KindOf::Timestamp,
            work,
        )
        .await?;
        let index = items.len();
        items.try_push(item).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
        Some(index)
    } else {
        None
    };
    Ok((update, timestamp))
}

async fn type_name<'s, S: RangeSource>(
    document: &Document<'s, S>,
    owner: &Reading<'s, S::Document, S::Generation>,
    dictionary: NodeId,
    expected: &[u8],
    work: &impl Work,
) -> Result<(), ReadFailure<S::Error>> {
    // EN319142-1 §§5.4.2.2–5.4.2.3 constrain a written Type. ISO32000-1
    // §§7.3.9–7.3.10 retain indirect-name and absent/null equivalence.
    // https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf
    let Some(node) = get(&owner.value.arena, dictionary, b"Type", work)? else {
        return Ok(());
    };
    let Some(selected) = document.resolve_value(owner, node, work).await? else {
        return Ok(());
    };
    let (owner, node) = selected.parts();
    let arena = &owner.value.arena;
    let value = arena.nodes[node.0];
    admit(work, value.location, expected.len() as u64 + 1)?;
    if matches!(value.kind, Kind::Null) {
        return Ok(());
    }
    if let Kind::Name(name) = value.kind
        && name.length == expected.len()
        && &arena.names[name.start..name.start + name.length] == expected
    {
        return Ok(());
    }
    Err(Error {
        kind: ErrorKind::Syntax(Syntax::Dictionary),
        location: value.location,
    }
    .into())
}
