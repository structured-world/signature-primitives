//! `XAdES` construction over an XML owner's unpublished staging transaction.
//!
//! Construction is not a validation receipt. After signing or augmentation,
//! run the existing preparation and baseline assessments over the resulting
//! generation. This module does not serialize XML, sign, fetch evidence, read
//! a clock or choose application trust. See [`Writer`] for the mutation boundary.

use crate::{
    container::{DS, XADES},
    xml::Name,
};
use structured_asn1::memory::{MemoryError, Work};

mod basic;
mod material;
mod timestamp;
pub use basic::{Basic, BasicReferences, DataObject, ReferenceKind};
pub use material::write_material;
pub use material::{Material, MaterialKind, Materials};
pub use timestamp::{Timestamp, TimestampKind};

mod augmentation;
pub use augmentation::{
    Augmentation, Checked, CheckedFor, InputResult, PreparationError, Presence, ResponseCheck,
    ResponseError, ResponseResult, Transaction,
};

/// XML-owned lexical validation requested by the shared property generator.
/// The owner reuses its existing XML Schema 1.0 datatype kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datatype {
    /// XML character data; no extra schema facet.
    String,
    /// Unique XML ID/NCName, registered in the owner's ID domain.
    Id,
    /// Complete XML Schema anyURI with its whitespace processing.
    AnyUri,
    /// XML Schema dateTime with a required explicit timezone. This is a claimed
    /// instant, not clock acquisition or authenticated temporal evidence.
    ZonedDateTime,
}
/// Borrowed construction text and the datatype the owner must validate.
#[derive(Debug, Clone, Copy)]
pub struct Value<'a> {
    /// Complete supplied lexical value, never markup.
    pub lexical: &'a str,
    /// Generic XML datatype selected by the shared property rules.
    pub datatype: Datatype,
}

/// One balanced XML construction instruction. Names are expanded; the owner
/// selects prefixes and escapes values without changing their semantics.
#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    /// Append a new element and enter it.
    Begin(Name<'static>),
    /// Set an attribute on the current new element, before its children.
    Attribute(Name<'static>, Value<'a>),
    /// Append character data, not markup.
    Text(Value<'a>),
    /// Append the base64Binary representation of these exact complete bytes.
    /// No line wrapping, decoding, re-encoding of ASN.1, or payload substitution.
    Binary(&'a [u8]),
    /// Close the most recently begun element.
    End,
}

/// XML-owned staging capability, not a second DOM or signing dispatcher.
///
/// The caller opens an unpublished transaction at the precise insertion point.
/// Any failure discards its entire draft. Successful emission leaves the draft
/// unpublished until original signed inputs, earlier archive inputs, namespace
/// context and generation invariants are checked by that owner and existing
/// shared validators. Augmentation may append unsigned properties, never edit
/// previously protected subtrees or add an Object after an earlier archive.
///
/// Each callback checks XML syntax, datatype/ID rules, actual source/generation,
/// and its compiled policy. It admits ALL scanning, base64/escaping, allocation
/// capacity and tree growth through `work` before doing them. Attribute strings
/// and binary slices cannot escape this call unless copied with retained charge.
/// A callback's success is not cryptographic evidence or attained baseline level.
pub trait Writer {
    /// Original XML, policy, allocation or processing refusal.
    type Error;
    /// Execute this event in the current unpublished transaction.
    fn write<W: Work>(&mut self, event: Event<'_>, work: &W) -> Result<(), Self::Error>;
}

/// Construction refused without publishing a partial draft.
#[derive(Debug)]
pub enum Error<E> {
    /// Original XML-owner callback cause, unchanged.
    Writer(E),
    /// Original capacity or work refusal before processing.
    Resource(MemoryError),
    /// A required new value is absent or violates its format syntax.
    Value(&'static str),
    /// Source document, generation, selected signature or insertion point differs.
    Foreign,
    /// The existing shared stage report has unmet conditions or lacks LT data.
    Prerequisites,
}

pub(crate) const fn name(namespace: &'static str, local: &'static str) -> Name<'static> {
    Name { namespace, local }
}
pub(crate) const fn attr(local: &'static str) -> Name<'static> {
    name("", local)
}

pub(crate) fn same_parent<N: Copy + Eq + structured_asn1::memory::HashWork, W: Work>(
    left: Option<N>,
    right: Option<N>,
    work: &W,
) -> Result<bool, MemoryError> {
    match (left, right) {
        (Some(left), Some(right)) => structured_ltv::source::equal_id(left, right, work),
        (None, None) => Ok(true),
        (Some(_), None) | (None, Some(_)) => Ok(false),
    }
}

pub(crate) struct Emit<'a, B: Writer, W: Work> {
    pub writer: &'a mut B,
    pub work: &'a W,
}
impl<B: Writer, W: Work> Emit<'_, B, W> {
    pub fn event(&mut self, event: Event<'_>) -> Result<(), Error<B::Error>> {
        self.work.charge_work(1).map_err(Error::Resource)?;
        self.writer.write(event, self.work).map_err(Error::Writer)
    }
    pub fn begin(
        &mut self,
        namespace: &'static str,
        local: &'static str,
    ) -> Result<(), Error<B::Error>> {
        self.event(Event::Begin(name(namespace, local)))
    }
    pub fn end(&mut self) -> Result<(), Error<B::Error>> {
        self.event(Event::End)
    }
    pub fn attribute(&mut self, local: &'static str, value: &str) -> Result<(), Error<B::Error>> {
        let datatype = match local {
            "Id" => Datatype::Id,
            "Target" | "ObjectReference" | "Algorithm" => Datatype::AnyUri,
            _ => Datatype::String,
        };
        self.event(Event::Attribute(
            attr(local),
            Value {
                lexical: value,
                datatype,
            },
        ))
    }
    pub fn text(
        &mut self,
        namespace: &'static str,
        local: &'static str,
        value: &str,
    ) -> Result<(), Error<B::Error>> {
        self.begin(namespace, local)?;
        self.event(Event::Text(Value {
            lexical: value,
            datatype: Datatype::String,
        }))?;
        self.end()
    }
    pub fn binary(
        &mut self,
        namespace: &'static str,
        local: &'static str,
        value: &[u8],
    ) -> Result<(), Error<B::Error>> {
        self.begin(namespace, local)?;
        self.event(Event::Binary(value))?;
        self.end()
    }
    pub fn digest(&mut self, method: &str, value: &[u8]) -> Result<(), Error<B::Error>> {
        self.begin(DS, "DigestMethod")?;
        self.attribute("Algorithm", method)?;
        self.end()?;
        self.binary(DS, "DigestValue", value)
    }
}
