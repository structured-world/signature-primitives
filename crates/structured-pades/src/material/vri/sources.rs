//! Complete historical VRI-name associations, without success filtering.

use super::{Name, NameError, status::status_name};
use crate::{
    container::{Container, ErrorOf},
    material::{HistoryError, ParsedHistory, Value},
    model::admit,
    query::Query,
    range::RangeSource,
    source::Location,
    timestamp::{
        Node,
        sources::{Models, Slot},
    },
};
use structured_asn1::memory::{OwnedMap, OwnedVec, Work};
use structured_ltv::source::{Query as _, ScopeError};
use structured_pkix::{algorithm::digest::AsnDigest, signature::SignatureValue};

/// One original VRI occurrence's normative nominal association. SHA-1 names
/// identify inputs; they do not authenticate a signature or certificate status.
pub struct Association {
    revision: usize,
    ordinal: usize,
    location: Location,
    named: bool,
    timely: bool,
}
impl Association {
    /// Original historical interpretation window.
    #[must_use]
    pub fn revision(&self) -> usize {
        self.revision
    }
    /// Original VRI ordinal in that window.
    #[must_use]
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    /// Original VRI key, retaining physical/logical source coordinates.
    #[must_use]
    pub fn location(&self) -> Location {
        self.location
    }
    /// At least one prescribed original signature input has this name.
    #[must_use]
    pub fn has_named_input(&self) -> bool {
        self.named
    }
    /// The named signature exists in the permitted historical window.
    #[must_use]
    pub fn all_placement_requirements_met(&self) -> bool {
        self.timely
    }
}
/// Every original VRI occurrence, including negative nominal associations.
pub struct Associations {
    values: OwnedVec<Association>,
    complete: bool,
}
impl Associations {
    /// Source order is historical revision followed by original VRI ordinal.
    #[must_use]
    pub fn entries(&self) -> &[Association] {
        &self.values
    }
    /// All original VRI names and incremental placement requirements hold.
    /// Imprint mathematics, generation time and trust are separate facts.
    #[must_use]
    pub fn all_requirements_met(&self) -> bool {
        self.complete
    }
}

/// Original source/metadata/hash cause, never an unassociated-name finding.
#[derive(Debug)]
pub enum SourceError<E, P> {
    /// Original historical material or index refusal.
    History(HistoryError),
    /// Original PDF source scope refused.
    Scope(ScopeError<Node>),
    /// Original PDF input/container processing refused.
    Contents(ErrorOf<E>),
    /// Prescribed name hashing refused with its original provider cause.
    Name(NameError<P>),
    /// Actual common material metadata query refused.
    Cms(structured_cades::Error),
    /// The selected provider cannot name SHA-1 inputs.
    UnsupportedName,
}
impl<E, P> From<HistoryError> for SourceError<E, P> {
    fn from(cause: HistoryError) -> Self {
        Self::History(cause)
    }
}

struct Row {
    value: Association,
    name: Name,
}
struct Available {
    dictionary: Option<usize>,
    status: Option<usize>,
}
struct Table<W: Work> {
    heads: OwnedMap<Name, Available, W>,
    rows: OwnedVec<Row, W>,
}
enum StatusNameError<P> {
    Unsupported,
    Name(NameError<P>),
}
enum NamingError<P> {
    Scope(ScopeError<Node>),
    Name(NameError<P>),
    Unsupported,
}
impl<P> From<StatusNameError<P>> for NamingError<P> {
    fn from(value: StatusNameError<P>) -> Self {
        match value {
            StatusNameError::Unsupported => Self::Unsupported,
            StatusNameError::Name(cause) => Self::Name(cause),
        }
    }
}
impl<E, P> From<NamingError<P>> for SourceError<E, P> {
    fn from(value: NamingError<P>) -> Self {
        match value {
            NamingError::Scope(cause) => Self::Scope(cause),
            NamingError::Name(cause) => Self::Name(cause),
            NamingError::Unsupported => Self::UnsupportedName,
        }
    }
}
impl<E, P> From<StatusNameError<P>> for SourceError<E, P> {
    fn from(cause: StatusNameError<P>) -> Self {
        match cause {
            StatusNameError::Unsupported => Self::UnsupportedName,
            StatusNameError::Name(cause) => Self::Name(cause),
        }
    }
}
impl<E, P> From<crate::Error> for SourceError<E, P> {
    fn from(cause: crate::Error) -> Self {
        Self::Name(NameError::Pdf(cause))
    }
}
impl<W: Work> Table<W> {
    fn mark(
        &mut self,
        name: Name,
        available: usize,
        dictionary: bool,
        work: &W,
        location: Location,
    ) -> crate::Result<()> {
        let resource = |cause| crate::Error {
            kind: crate::ErrorKind::Resource(cause),
            location,
        };
        if let Some(value) = self.heads.get_mut(&name, work).map_err(resource)? {
            admit(work, location, 1)?;
            let earliest = if dictionary {
                &mut value.dictionary
            } else {
                &mut value.status
            };
            if earliest.is_none_or(|previous| available < previous) {
                *earliest = Some(available);
            }
        }
        Ok(())
    }
    fn status<'p, P: AsnDigest<'p>>(
        &mut self,
        signature: SignatureValue<'_>,
        available: usize,
        provider: &'p P,
        work: &W,
        location: Location,
    ) -> Result<(), StatusNameError<P::Error>> {
        let name = match status_name(signature, provider, work, location) {
            Ok(Some(name)) => name,
            Ok(None) => return Err(StatusNameError::Unsupported),
            Err(NameError::PaddedSignature) => return Ok(()),
            Err(cause) => return Err(StatusNameError::Name(cause)),
        };
        self.mark(name, available, false, work, location)
            .map_err(|cause| StatusNameError::Name(NameError::Pdf(cause)))
    }
}

fn model_names<'q, 'p, P: AsnDigest<'p>, S: RangeSource>(
    table: &mut Table<structured_asn1::memory::Execution<'q>>,
    models: &Models<'_, '_, '_, '_, S::Document, S::Generation>,
    provider: &'p P,
    query: &Query<'q, '_, S>,
    location: Location,
) -> Result<(), NamingError<P::Error>> {
    let work = query.execution();
    for (ordinal, model) in models.values.iter().enumerate() {
        query
            .admit(Node::of(location), 1)
            .map_err(NamingError::Scope)?;
        let Some(Slot::Value(container)) = models
            .sources
            .get(ordinal, work)
            .map_err(|cause| NamingError::Name(NameError::Pdf(cause)))?
        else {
            continue;
        };
        let signature = container.signature();
        let name = container
            .vri_name(provider, work)
            .map_err(NamingError::Name)?
            .ok_or(NamingError::Unsupported)?;
        table
            .mark(
                name,
                signature.defined_revision(),
                true,
                work,
                signature.location(),
            )
            .map_err(|cause| NamingError::Name(NameError::Pdf(cause)))?;
        let crate::timestamp::sources::Model::Known { revocations, .. } = model else {
            continue;
        };
        for value in revocations {
            query
                .admit(Node::of(location), 1)
                .map_err(NamingError::Scope)?;
            match &value.value {
                Ok(structured_cms::signed::revocation::Reading::Crl(value)) => table.status(
                    value.signature_value(),
                    signature.defined_revision(),
                    provider,
                    work,
                    signature.location(),
                )?,
                Ok(structured_cms::signed::revocation::Reading::Ocsp(value)) => table.status(
                    value.signature_value(),
                    signature.defined_revision(),
                    provider,
                    work,
                    signature.location(),
                )?,
                _ => {}
            }
        }
    }
    Ok(())
}

fn historical_names<'q, 'p, P: AsnDigest<'p>, S: RangeSource>(
    table: &mut Table<structured_asn1::memory::Execution<'q>>,
    history: &ParsedHistory<'_, '_, '_, S::Document, S::Generation>,
    revision: usize,
    provider: &'p P,
    query: &Query<'q, '_, S>,
    location: Location,
) -> Result<(), NamingError<P::Error>> {
    let work = query.execution();
    for (revision, parsed) in history.revisions()[..=revision].iter().enumerate() {
        for (ordinal, value) in parsed.values().iter().enumerate() {
            query
                .admit(Node::of(location), 1)
                .map_err(NamingError::Scope)?;
            let location = parsed.owner.items()[ordinal].location();
            match value {
                Value::Crl(value) => {
                    table.status(value.signature_value(), revision, provider, work, location)?;
                }
                Value::Ocsp {
                    basic: Ok(Some(value)),
                    ..
                } => table.status(value.signature_value(), revision, provider, work, location)?,
                Value::Timestamp(value) => {
                    for value in &value.revocations {
                        query
                            .admit(Node::of(location), 1)
                            .map_err(NamingError::Scope)?;
                        match &value.value {
                            Ok(structured_cms::signed::revocation::Reading::Crl(value)) => table
                                .status(
                                    value.signature_value(),
                                    revision,
                                    provider,
                                    work,
                                    location,
                                )?,
                            Ok(structured_cms::signed::revocation::Reading::Ocsp(value)) => table
                                .status(
                                value.signature_value(),
                                revision,
                                provider,
                                work,
                                location,
                            )?,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn finish_table<'q, S: RangeSource, E>(
    table: Table<structured_asn1::memory::Execution<'q>>,
    query: &Query<'q, '_, S>,
    location: Location,
) -> Result<Associations, NamingError<E>> {
    let work = query.execution();
    let resource = |cause| {
        NamingError::Name(NameError::Pdf(crate::Error {
            kind: crate::ErrorKind::Resource(cause),
            location,
        }))
    };
    let mut values = work.vector();
    values
        .try_reserve_exact(table.rows.len())
        .map_err(resource)?;
    let mut complete = true;
    for mut row in table.rows {
        query
            .admit(Node::of(location), 1)
            .map_err(NamingError::Scope)?;
        let available = table
            .heads
            .get(&row.name, work)
            .map_err(resource)?
            .expect("original VRI name");
        row.value.named = available.dictionary.is_some() || available.status.is_some();
        // EN319142-1 §5.4.2.2: VRI is incremental, and a signature
        // dictionary in an update precedes its associated VRI update.
        row.value.timely = row.value.revision > 0
            && (available
                .dictionary
                .is_some_and(|revision| row.value.revision > revision)
                || available
                    .status
                    .is_some_and(|revision| row.value.revision >= revision));
        if !row.value.timely {
            complete = false;
        }
        values.try_push(row.value).map_err(resource)?;
    }
    Ok(Associations {
        values: values.into_owned(),
        complete,
    })
}

fn seed_table<'q, S: RangeSource, E>(
    history: &ParsedHistory<'_, '_, '_, S::Document, S::Generation>,
    revision: usize,
    location: Location,
    query: &Query<'q, '_, S>,
) -> Result<Table<structured_asn1::memory::Execution<'q>>, NamingError<E>> {
    let work = query.execution();
    let resource = |cause| {
        NamingError::Name(NameError::Pdf(crate::Error {
            kind: crate::ErrorKind::Resource(cause),
            location,
        }))
    };
    let mut table = Table {
        heads: work.map(),
        rows: work.vector(),
    };
    for (revision, parsed) in history.revisions()[..=revision].iter().enumerate() {
        for (ordinal, vri) in parsed.owner.vri().iter().enumerate() {
            query
                .admit(Node::dss(vri.location(), revision), 41)
                .map_err(NamingError::Scope)?;
            table
                .heads
                .try_insert(
                    Name(*vri.name()),
                    Available {
                        dictionary: None,
                        status: None,
                    },
                )
                .map_err(resource)?;
            table
                .rows
                .try_push(Row {
                    value: Association {
                        revision,
                        ordinal,
                        location: vri.location(),
                        named: false,
                        timely: false,
                    },
                    name: Name(*vri.name()),
                })
                .map_err(resource)?;
        }
    }
    Ok(table)
}

#[expect(
    clippy::result_large_err,
    reason = "historical association failures preserve original item and nested format causes without allocating a refusal envelope"
)]
pub(in crate::material) async fn associate<'p, P, S>(
    history: &ParsedHistory<'_, '_, '_, S::Document, S::Generation>,
    root: &Container<'_, '_, S::Document, S::Generation>,
    pool: &structured_cades::material::Pool<'_, '_, '_>,
    models: &Models<'_, '_, '_, '_, S::Document, S::Generation>,
    provider: &'p P,
    query: &Query<'_, '_, S>,
    revision: usize,
) -> Result<Associations, SourceError<S::Error, P::Error>>
where
    S: RangeSource,
    P: AsnDigest<'p>,
{
    let work = query.execution();
    let location = root.signature().location();
    let mut table = seed_table(history, revision, location, query).map_err(SourceError::from)?;
    if table.rows.is_empty() {
        return Ok(Associations {
            values: work.vector().into_owned(),
            complete: true,
        });
    }
    let name = root
        .vri_name(provider, work)
        .map_err(SourceError::Name)?
        .ok_or(SourceError::UnsupportedName)?;
    table.mark(
        name,
        root.signature().defined_revision(),
        true,
        work,
        location,
    )?;
    let catalogue = root.signature().catalogue();
    for ordinal in 0..catalogue.len() {
        query
            .admit(Node::of(location), 1)
            .map_err(SourceError::Scope)?;
        let signature = catalogue.get(ordinal).expect("bounded original signature");
        if signature.location() == location
            || signature.is_document_timestamp()
            || signature.defined_revision() > revision
        {
            continue;
        }
        if !matches!(
            signature.sub_filter(),
            Some(
                crate::signature::SubFilter::CadesDetached
                    | crate::signature::SubFilter::Pkcs7Detached
            )
        ) {
            continue;
        }
        let container = match query.document().container(signature, work).await {
            Ok(value) => value,
            Err(cause) if cause.is_terminal() => return Err(SourceError::Contents(cause)),
            Err(_) => continue,
        };
        let name = container
            .vri_name(provider, work)
            .map_err(SourceError::Name)?
            .ok_or(SourceError::UnsupportedName)?;
        table.mark(
            name,
            signature.defined_revision(),
            true,
            work,
            signature.location(),
        )?;
    }
    let available = root.signature().defined_revision();
    for ordinal in 0..pool.crls() {
        let crl = pool
            .crl(ordinal, work)
            .map_err(SourceError::Cms)?
            .expect("bounded actual CRL");
        table.status(crl.signature_value(), available, provider, work, location)?;
    }
    for ordinal in 0..pool.ocsp_responses() {
        let ocsp = pool
            .ocsp(ordinal, work)
            .map_err(SourceError::Cms)?
            .expect("bounded actual basic response");
        table.status(ocsp.signature_value(), available, provider, work, location)?;
    }
    model_names(&mut table, models, provider, query, location).map_err(SourceError::from)?;
    historical_names(&mut table, history, revision, provider, query, location)
        .map_err(SourceError::from)?;
    finish_table(table, query, location).map_err(SourceError::from)
}
