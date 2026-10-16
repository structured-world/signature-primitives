//! Original B-B field/header/selected-key facts without repeated cryptography.

use crate::attributes::{self, AttributeXml};
use crate::binary::{self, BinaryXml, Location};
use crate::certificate::{self, CheckedPathCertificate};
use crate::hashes::ParticipantHashes;
use crate::header;
use crate::pki::CounterPaths;
use crate::prepare::Fields;
use crate::scalar::ScalarXml;
use crate::xml::{Access, AccessError, Xml};
use structured_asn1::{
    Reader,
    memory::{MemoryError, OwnedVec, Work},
};

#[path = "hints.rs"]
mod hints;

/// Privately constructed original receipts to combine. Their public input
/// slots permit selecting contexts, never writing a successful fact. `basic`
/// verifies source/catalogue/whole-counter agreement before source callbacks.
#[derive(Clone, Copy)]
pub struct BasicInput<'receipt, 'prepared, 'path, 'document, N, D, G> {
    /// Original root declared attributes, URI/OID and zoned claimed-time checks.
    pub fields: &'receipt Fields<'prepared, N, D, G>,
    /// Root AND every incorporated counter's actual-use MD5 guard.
    pub hashes: &'receipt ParticipantHashes<N, D, G>,
    /// Actual selected key and all certificate digests against the checked path.
    pub certificate: &'receipt CheckedPathCertificate<'path, 'document, N, D, G>,
    /// Complete original counter/key/path catalogue.
    pub counters: &'receipt CounterPaths<'path, 'document, N, D, G>,
}

/// Original certificate-reference catalogue that supplied a written issuer hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintSource {
    /// Protected `SigningCertificateV2`, with its original certificate ordinal.
    Protected(usize),
    /// Ordinary or attribute unsigned reference in the same preparation.
    ValidationReference {
        /// Original property ordinal, retaining its role in the preparation.
        property: usize,
        /// Original certificate ordinal within that property.
        entry: usize,
    },
}

/// Original DER `IssuerSerialV2` hint diagnostics, retaining source and capacity.
pub struct Hint<N, D, G> {
    location: Location<N, D, G>,
    faults: OwnedVec<structured_cms::Error>,
    source: HintSource,
}
impl<N: Copy, D: Copy, G: Copy> Hint<N, D, G> {
    /// Original protected/unsigned catalogue and ordinals, not inferred authority.
    #[must_use]
    pub fn source(&self) -> HintSource {
        self.source
    }
    /// Original XML binary enclosure; inner offsets remain decoded coordinates.
    #[must_use]
    pub fn location(&self) -> Location<N, D, G> {
        self.location
    }
    /// Complete common hint diagnostics, without cloning or discarding them.
    #[must_use]
    pub fn faults(&self) -> &[structured_cms::Error] {
        &self.faults
    }
}

/// Completed original root/counter field/header/key/digest facts. Negative key,
/// digest, inclusion and readable hint outcomes remain available. This does not
/// claim timestamp chronology, material completeness, arbitrary open-format
/// semantics or application policy/trust acceptance, and is not a B-T/LT/LTA.
pub struct Basic<'receipt, 'prepared, 'path, 'document, N, D, G> {
    input: BasicInput<'receipt, 'prepared, 'path, 'document, N, D, G>,
    included: Option<Location<N, D, G>>,
    hints: OwnedVec<Hint<N, D, G>>,
    hints_clean: bool,
}

impl<'r, 'p, 'v, 'd, N: Copy, D: Copy, G: Copy> Basic<'r, 'p, 'v, 'd, N, D, G> {
    /// Same original receipt inputs, without re-verifying or copying them.
    #[must_use]
    pub fn inputs(&self) -> &BasicInput<'r, 'p, 'v, 'd, N, D, G> {
        &self.input
    }
    /// Actual exact-DER signing-certificate occurrence in the original `KeyInfo`.
    #[must_use]
    pub fn included(&self) -> Option<Location<N, D, G>> {
        self.included
    }
    /// Every present original protected/ordinary/attribute issuer hint and its
    /// retained diagnostics. Catalogue roles remain available through its source.
    #[must_use]
    pub fn hints(&self) -> &[Hint<N, D, G>] {
        &self.hints
    }
    /// Only the completed field/header/selected-key/digest conditions above.
    /// This constant-time getter does not scan attacker-sized hint catalogues.
    #[must_use]
    pub fn all_root_requirements_met(&self) -> bool {
        self.input.certificate.is_bound() && self.included.is_some() && self.hints_clean
    }
}

/// Original refusal at its actual processing boundary, never a negative key or
/// certificate comparison and never a successful partial basic report.
#[derive(Debug)]
pub enum BasicError<E, N, D, G> {
    /// Receipts belong to a different source/selection/catalogue/counter set.
    Foreign {
        /// Original selected root.
        signature: N,
    },
    /// Original live-source/current-operation refusal.
    Access(AccessError<E, N>),
    /// Original counter attribute/scalar/source refusal.
    Attributes(attributes::Error<E, N>),
    /// Exact original certificate-inclusion binary/metadata refusal.
    Inclusion(binary::Error<E, header::InclusionError, N, D, G>),
    /// Original optional hint's decoding/DER/schema/callback refusal.
    Hint(binary::Error<E, certificate::IssuerError<core::convert::Infallible>, N, D, G>),
    /// Metadata/retained-catalogue admission failed before work.
    Resource {
        /// Original selecting node.
        node: N,
        /// Exact resource cause.
        cause: MemoryError,
    },
}

/// Typed original-source basic assembly result.
pub type BasicResult<'receipt, 'prepared, 'path, 'document, X> = Result<
    Basic<
        'receipt,
        'prepared,
        'path,
        'document,
        <X as Xml>::Id,
        <X as Xml>::Document,
        <X as Xml>::Generation,
    >,
    BasicError<<X as Xml>::Error, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
>;
type InputFor<'r, 'p, 'v, 'd, X> =
    BasicInput<'r, 'p, 'v, 'd, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>;
type ProcessingResult<T, X> = Result<
    T,
    BasicError<<X as Xml>::Error, <X as Xml>::Id, <X as Xml>::Document, <X as Xml>::Generation>,
>;

/// Combine already checked root fields, every counter, selected key/path and
/// hash restrictions; check exact original header inclusion and each optional
/// protected/ordinary/attribute `IssuerSerialV2` DER hint once. No root/counter/path verification, certificate
/// digest or original URI/dateTime normalization is repeated.
///
/// EN319132-1 V1.3.1 §§5.2.2/6.2.1/6.3(a,h–l) keep these conditions distinct;
/// an issuer hint or `KeyInfo` count cannot replace certificate/key/digest binding.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
pub fn basic<'r, 'p, 'v, 'd, X: BinaryXml + AttributeXml + ScalarXml>(
    input: InputFor<'r, 'p, 'v, 'd, X>,
    xml: &X,
    operation: &Reader<'_>,
) -> BasicResult<'r, 'p, 'v, 'd, X> {
    let prepared = input.fields.prepared();
    let layout = prepared.bound().containers();
    let signature = layout.signature();
    let work = operation.execution();
    let access = Access::new(xml, layout.snapshot(), &work);
    require_sources(&input, &access)?;
    attributes::check_counters(prepared, input.counters, &access)
        .map_err(BasicError::Attributes)?;
    let included = header::included(
        xml,
        prepared.header(),
        input.certificate.selected().certificate(),
        &work,
    )
    .map_err(BasicError::Inclusion)?;
    let hints = hints::check(prepared, xml, operation)?;
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(BasicError::Access)?;
    Ok(Basic {
        input,
        included,
        hints: hints.items,
        hints_clean: hints.clean,
    })
}

fn require_sources<X: Xml, W: Work>(
    input: &InputFor<'_, '_, '_, '_, X>,
    access: &Access<'_, X, W>,
) -> ProcessingResult<(), X> {
    let prepared = input.fields.prepared();
    let layout = prepared.bound().containers();
    let signature = layout.signature();
    let foreign = || BasicError::Foreign { signature };
    if input.hashes.snapshot() != access.snapshot()
        || input.counters.snapshot() != access.snapshot()
        || !core::ptr::eq(
            input.certificate.selected().reference(),
            prepared.certificates(),
        )
    {
        return Err(foreign());
    }
    access
        .query(signature, |_, _, _| Ok(()))
        .map_err(BasicError::Access)?;
    let resource = |cause| BasicError::Resource {
        node: signature,
        cause,
    };
    if !access
        .equal_id(signature, input.hashes.signature())
        .map_err(resource)?
        || !access
            .equal_id(signature, input.counters.signature())
            .map_err(resource)?
        || input.hashes.counters().len() != input.counters.actors().len()
    {
        return Err(foreign());
    }
    for (hash, actor) in input.hashes.counters().iter().zip(input.counters.actors()) {
        if !access
            .equal_id(
                hash.signature(),
                actor.signer().counter().original().child(),
            )
            .map_err(resource)?
        {
            return Err(foreign());
        }
    }
    Ok(())
}
