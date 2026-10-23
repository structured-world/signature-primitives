//! The eight format-selected sources; callers never supply component hashes.
use super::{Eight, InputError, Tree, batch, derived_result};
use crate::{Error, evidence::View, preservation::Kind, source::Node, timestamp::ContentInput};
use core::cmp::Ordering;
use structured_asn1::{
    Element, Reader, Span,
    memory::{OwnedVec, Work},
};
use structured_cms::{
    digest::{DigestBatch, DigestMemo},
    stream::{Source, StreamError},
};
use structured_pkix::{
    algorithm::digest::{Algorithm, AsnDigest},
    temporal::LeapTable,
};

const FIELD: &str = "cades.longTermValidation.input";

fn processing<SE, PE>(cause: Error) -> InputError<SE, PE> {
    InputError::Processing(cause)
}

fn ranges<'p, P: AsnDigest<'p>, W: Work, SE, const N: usize>(
    pending: DigestBatch<'p, P>,
    mut ranges: [&[u8]; N],
    work: &W,
    at: u64,
) -> Result<DigestMemo<'p, P>, InputError<SE, P::Error>> {
    pending.run(&mut ranges, work).map_err(|cause| match cause {
        StreamError::Source(structured_cms::stream::RangesError::Resource(cause)) => {
            processing(Error::resource(cause, FIELD, at))
        }
        StreamError::Source(structured_cms::stream::RangesError::Receiver(cause)) => {
            InputError::Receiver(cause)
        }
        StreamError::Callback(cause) => InputError::Digest(cause),
        StreamError::Processing(cause) => processing(Error::Cms(cause)),
    })
}

fn projected<'p, P: AsnDigest<'p>, W: Work, SE>(
    pending: DigestBatch<'p, P>,
    source: &mut structured_cms::encoding::DerFields<'_>,
    work: &W,
    at: u64,
) -> Result<DigestMemo<'p, P>, InputError<SE, P::Error>> {
    pending.run(source, work).map_err(|cause| match cause {
        StreamError::Source(structured_cms::encoding::ProjectionError::Resource(cause)) => {
            processing(Error::resource(cause, FIELD, at))
        }
        StreamError::Source(structured_cms::encoding::ProjectionError::Receiver(cause)) => {
            InputError::Receiver(cause)
        }
        StreamError::Callback(cause) => InputError::Digest(cause),
        StreamError::Processing(cause) => processing(Error::Cms(cause)),
    })
}

fn tree<'p, 'd, P: AsnDigest<'p>, W: Work, SE>(
    provider: &'p P,
    algorithms: &[Algorithm],
    elements: &[Element<'d>],
    pending: DigestBatch<'p, P>,
    work: &W,
    at: u64,
) -> Result<DigestMemo<'p, P>, InputError<SE, P::Error>> {
    let mut items = work.vector();
    items
        .try_reserve_exact(elements.len())
        .map_err(|cause| processing(Error::resource(cause, FIELD, at)))?;
    for element in elements {
        work.charge_work(1)
            .map_err(|cause| processing(Error::resource(cause, FIELD, element.span().start)))?;
        let hashed = ranges(
            batch(provider, algorithms, work, element.span().start)?,
            [element.as_bytes()],
            work,
            element.span().start,
        )?;
        items
            .try_push(hashed)
            .map_err(|cause| processing(Error::resource(cause, FIELD, element.span().start)))?;
    }
    derived_result(pending.run_requests(
        &mut Tree::<P, SE>::new(provider, items.into_owned(), algorithms, at),
        work,
    ))
}

/// Enumerate members of an already parsed original field; no certificate,
/// revocation, signer or proof grammar is decoded again.
fn members<'d>(
    mut fields: structured_asn1::ScopedReader<'d, '_>,
    field: Option<Span>,
    out: &mut OwnedVec<Element<'d>, impl Work>,
) -> Result<(), Error> {
    let Some(field) = field else {
        return Ok(());
    };
    while let Some(element) = fields
        .next_element()
        .map_err(|cause| Error::encoding(cause, FIELD))?
    {
        if element.span() != field {
            continue;
        }
        let mut inside = fields
            .enter(&element)
            .map_err(|cause| Error::encoding(cause, FIELD))?;
        while let Some(member) = inside
            .next_element()
            .map_err(|cause| Error::encoding(cause, FIELD))?
        {
            out.try_push(member)
                .map_err(|cause| Error::resource(cause, FIELD, member.span().start))?;
        }
        return Ok(());
    }
    Err(Error::Foreign { at: field.start })
}
fn extra_members<'d>(
    mut fields: structured_asn1::ScopedReader<'d, '_>,
    out: &mut OwnedVec<Element<'d>, impl Work>,
) -> Result<(), Error> {
    while let Some(member) = fields
        .next_element()
        .map_err(|cause| Error::encoding(cause, FIELD))?
    {
        out.try_push(member)
            .map_err(|cause| Error::resource(cause, FIELD, member.span().start))?;
    }
    Ok(())
}

impl<'m, 'd> View<'_, 'm, 'd> {
    pub(in crate::evidence) fn admit_poe_algorithms(
        &self,
        algorithms: &[Algorithm],
        operation: &Reader<'d>,
    ) -> Result<(), Error> {
        let work = operation.execution();
        let message = self.prepared.document().message();
        message
            .require_session(operation, FIELD)
            .map_err(Error::Cms)?;
        for algorithm in algorithms {
            let mut found = false;
            for written in message.digest_algorithms() {
                match structured_pkix::algorithm::digest::algorithm(written, &work)
                    .map_err(Error::Pkix)?
                {
                    structured_asn1::digest::Resolution::Supported(value)
                        if value == *algorithm =>
                    {
                        found = true;
                        break;
                    }
                    structured_asn1::digest::Resolution::Malformed => {
                        work.charge_work(1 + written.algorithm().as_bytes().len().min(9) as u64)
                            .map_err(|cause| Error::resource(cause, FIELD, written.offset()))?;
                        if written.algorithm() == algorithm.identifier() {
                            return Err(Error::Syntax {
                                code: structured_cms::ErrorCode::AlgorithmSyntax,
                                field: FIELD,
                                at: written.offset(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            if !found {
                return Err(Error::Syntax {
                    code: structured_cms::ErrorCode::AlgorithmProtection,
                    field: FIELD,
                    at: self.required().property.span().start,
                });
            }
        }
        Ok(())
    }
    /// The same literal content pass serves every actual proof algorithm.
    /// Counters cover their PARENT signature content; roots cover carried or
    /// explicitly supplied detached content, never the counter's own signature.
    #[cfg(test)]
    pub(in crate::evidence) fn components<'p, P: AsnDigest<'p>, S: Source, W: Work>(
        &self,
        provider: &'p P,
        algorithms: &[Algorithm],
        operation: &Reader<'d>,
        detached: Option<&mut S>,
        utc: &LeapTable<'_>,
        current: &W,
    ) -> Result<Eight<'p, P>, InputError<S::Error, P::Error>> {
        self.components_in(provider, algorithms, operation, detached, utc, &[], current)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Actual detached source, original/current execution and sealed later-proof coverage must remain distinct."
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "All eight normative sources form one source-bound ledger and a single content pass across the selected algorithms."
    )]
    pub(in crate::evidence) fn components_in<'p, P: AsnDigest<'p>, S: Source, W: Work>(
        &self,
        provider: &'p P,
        algorithms: &[Algorithm],
        operation: &Reader<'d>,
        detached: Option<&mut S>,
        utc: &LeapTable<'_>,
        later: &[crate::timestamp::historical::Later<'_, 'm, 'd>],
        current: &W,
    ) -> Result<Eight<'p, P>, InputError<S::Error, P::Error>> {
        let poe = self.poe().ok_or(InputError::Foreign)?;
        let work = current.execution_for(operation.parser());
        let at = poe.element().span().start;
        let resource = |cause| processing(Error::resource(cause, FIELD, at));
        let message = self.prepared.document().message();
        message
            .require_session(operation, FIELD)
            .map_err(|cause| processing(Error::Cms(cause)))?;
        let signer = self
            .prepared
            .signer_encoding(self.required().signature, operation)
            .map_err(processing)?;
        work.charge_work(1).map_err(resource)?;
        // TS101733 §6.5.1 defines Hs over the signedAttrs encoding. It has
        // no H(empty) default when that mandatory CAdES source is absent.
        // https://www.etsi.org/deliver/etsi_ts/101700_101799/101733/02.02.01_60/ts_101733v020201p.pdf
        let protected = signer.signed().ok_or(InputError::MissingSignedAttributes)?;
        let parent = signer
            .source()
            .reader_in(&work)
            .map_err(|cause| processing(Error::Cms(cause)))?;
        let fields = signer.elements();
        let mut identity = fields
            .identity_der(&parent)
            .map_err(|cause| processing(Error::Cms(cause)))?;
        let mut signature = fields
            .signature_der(&parent)
            .map_err(|cause| processing(Error::Cms(cause)))?;
        let mut certificates = work.vector();
        let mut revocations = work.vector();
        members(
            message
                .fields_source()
                .reader_in(&work)
                .map_err(|cause| processing(Error::Cms(cause)))?,
            message.certificate_field(),
            &mut certificates,
        )
        .map_err(processing)?;
        members(
            message
                .fields_source()
                .reader_in(&work)
                .map_err(|cause| processing(Error::Cms(cause)))?,
            message.revocation_field(),
            &mut revocations,
        )
        .map_err(processing)?;
        if let Some(extra) = poe.certificates() {
            extra_members(
                extra
                    .fields_source()
                    .reader_in(&work)
                    .map_err(|cause| processing(Error::Cms(cause)))?,
                &mut certificates,
            )
            .map_err(processing)?;
        }
        if let Some(extra) = poe.revocations() {
            extra_members(
                extra
                    .fields_source()
                    .reader_in(&work)
                    .map_err(|cause| processing(Error::Cms(cause)))?,
                &mut revocations,
            )
            .map_err(processing)?;
        }
        let mut unsigned = work.vector();
        for ordinal in 0..signer.attributes() {
            work.charge_work(1).map_err(resource)?;
            let attribute = signer.attribute(ordinal).ok_or(InputError::Foreign)?;
            if attribute.span == self.required().property.span() {
                continue;
            }
            work.charge_work(1 + attribute.kind.as_bytes().len().min(11) as u64)
                .map_err(resource)?;
            // EN319122-1 §5.5.3: validate later ATSv3/AnnexB mechanisms
            // first, then ignore them in the historical PoE input. Admission
            // requires their SAME source-bound successful coverage of this
            // actual PoE, never merely a later genTime or written OID.
            let augmentation = attribute.kind == structured_cms::oid::ARCHIVE_TIMESTAMP_V3
                || matches!(
                    Kind::from_oid(attribute.kind),
                    Some(Kind::EvidenceRecordInternal | Kind::EvidenceRecordExternal)
                );
            if augmentation && !later.is_empty() {
                let original = self
                    .prepared
                    .timestamps()
                    .get(self.entry.timestamps.start)
                    .ok_or(InputError::Foreign)?;
                let mut excluded = false;
                for candidate in self.prepared.timestamps() {
                    work.charge_work(1).map_err(resource)?;
                    if candidate.property().span() != attribute.span {
                        continue;
                    }
                    for proof in later {
                        work.charge_work(1).map_err(resource)?;
                        if proof
                            .permits(self.prepared, candidate, original, operation)
                            .map_err(InputError::Augmentation)?
                        {
                            excluded = true;
                            break;
                        }
                    }
                    if excluded {
                        break;
                    }
                }
                if excluded {
                    continue;
                }
            }
            if Kind::from_oid(attribute.kind) == Some(Kind::LongTermValidation) {
                // §6.5.1 orders PoE by poeDate, not DER SET wire order or
                // token genTime. An unreadable/ambiguous PoE cannot be skipped.
                let mut earlier = None;
                for entry in &self.prepared.parsed.proofs.entries {
                    work.charge_work(1).map_err(resource)?;
                    if entry.required.signature == self.required().signature
                        && entry.required.property == Node::of(attribute.span)
                    {
                        if let crate::prepare::proofs::Body::Poe(value) = &entry.body {
                            earlier = Some(value);
                        }
                        break;
                    }
                }
                let earlier = earlier.ok_or(InputError::Foreign)?;
                match earlier
                    .compare_date(poe, utc, &work)
                    .map_err(InputError::Date)?
                {
                    Ordering::Less => {}
                    Ordering::Greater => continue,
                    Ordering::Equal => return Err(InputError::Foreign),
                }
            }
            unsigned.try_push(attribute.element).map_err(resource)?;
        }
        // All known field syntax and catalogue membership precede the first
        // provider state and caller content read, including material late in
        // the source and algorithms whose output widths happen to coincide.
        // §6.5.1 Hc/Hr/Hu use WHOLE encodings as received/stored,
        // including legal BER. Only Hv/Ht above select DER projection.
        // https://www.etsi.org/deliver/etsi_ts/101700_101799/101733/02.02.01_60/ts_101733v020201p.pdf
        self.admit_poe_algorithms(algorithms, operation)
            .map_err(processing)?;
        let mut covered = work.vector();
        let count = certificates
            .len()
            .checked_add(revocations.len())
            .and_then(|count| count.checked_add(unsigned.len()))
            .and_then(|count| count.checked_add(6))
            .ok_or(InputError::Foreign)?;
        covered.try_reserve_exact(count).map_err(resource)?;
        for element in certificates
            .iter()
            .chain(&*revocations)
            .chain(&*unsigned)
            .chain(&fields.identity)
            .chain(&fields.signature)
        {
            covered.try_push(element.span()).map_err(resource)?;
        }
        if let Some((span, _)) = signer.signed() {
            covered.try_push(span).map_err(resource)?;
        }
        let mut content = if let Some(parent) = self
            .prepared
            .counter_parent(self.required().signature, operation)
            .map_err(processing)?
        {
            ContentInput::<S>::Counter(
                self.prepared
                    .signature_of(parent, operation)
                    .map_err(processing)?,
            )
        } else if let Some(content) = message.content().content() {
            ContentInput::Carried(content)
        } else {
            ContentInput::Detached(detached.ok_or(InputError::Foreign)?)
        };
        // Admission above precedes all caller I/O. Each component has exactly
        // one source pass across the complete selected digest request batch.
        Eight::build(
            provider,
            algorithms,
            &work,
            at,
            covered.into_owned(),
            |index, pending, work| match index {
                0 => {
                    let kind = message.content().kind();
                    let length =
                        structured_asn1::length::DerLength::new(kind.as_bytes().len() as u64);
                    ranges(
                        pending,
                        [&[6][..], length.as_bytes(), kind.as_bytes()],
                        work,
                        at,
                    )
                }
                1 => pending
                    .run(&mut content, work)
                    .map_err(|cause| match cause {
                        StreamError::Source(cause) => InputError::Content(cause),
                        StreamError::Callback(cause) => InputError::Digest(cause),
                        StreamError::Processing(cause) => processing(Error::Cms(cause)),
                    }),
                2 => tree(provider, algorithms, &certificates, pending, work, at),
                3 => tree(provider, algorithms, &revocations, pending, work, at),
                4 => projected(pending, &mut identity, work, at),
                5 => {
                    let (span, contents) = protected;
                    let length = structured_asn1::length::DerLength::new(contents.len() as u64);
                    ranges(
                        pending,
                        [&[0x31][..], length.as_bytes(), contents],
                        work,
                        span.start,
                    )
                }
                6 => projected(pending, &mut signature, work, at),
                7 => tree(provider, algorithms, &unsigned, pending, work, at),
                _ => unreachable!("Eight invokes exactly the eight schema components"),
            },
        )
    }
}
