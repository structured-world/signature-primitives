use super::{ALT_SIGNATURE_ALGORITHM, ALT_SIGNATURE_VALUE, SUBJECT_ALT_PUBLIC_KEY_INFO};
use super::{Attribute, Component, Components, FIELD, required, single};
use crate::algorithm;
use crate::error::Located;
use crate::hybrid::components;
use crate::signature::SignatureValue;
use crate::{Error, ErrorCode, PublicKeyInfo, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, ScopedReader, Tag, universal};

pub(super) fn read<'a>(
    parent: &ScopedReader<'a, '_>,
    set: &Element<'a>,
) -> Result<(OwnedVec<Attribute<'a>>, Components<'a>)> {
    let mut values = parent.enter(set).field(FIELD)?;
    let execution = parent.execution();
    let mut attributes = execution.vector();
    let mut seen = execution.map();
    let mut components = Components::empty(set.span().start);
    let mut previous: Option<&[u8]> = None;
    while let Some(entry) = values.next_element().field(FIELD)? {
        // X.690§11.6 applies to the IMPLICIT SET OF attributes as well.
        // https://www.rfc-editor.org/rfc/rfc2986#section-4.1
        if let Some(previous) = previous
            && !crate::der::set_ordered(&values, previous, &entry, FIELD)?
        {
            return Err(Error::new(
                ErrorCode::MalformedValue,
                FIELD,
                entry.span().start,
            ));
        }
        previous = Some(entry.as_bytes());
        if entry.tag() != Tag::constructed(universal::SEQUENCE) {
            return Err(Error::new(
                ErrorCode::MalformedValue,
                FIELD,
                entry.span().start,
            ));
        }
        let mut attribute = values.enter(&entry).field(FIELD)?;
        let oid = required(&mut attribute, Tag::primitive(universal::OID))?;
        let oid = attribute.oid(&oid).field(FIELD)?;
        if seen
            .try_insert(oid, ())
            .map_err(|e| Error::resource(e, FIELD, entry.span().start))?
            .is_some()
        {
            return Err(Error::new(
                ErrorCode::DuplicateExtension,
                "request.attributes",
                entry.span().start,
            ));
        }
        let set = required(&mut attribute, Tag::constructed(universal::SET))?;
        if set.contents().is_empty() {
            return Err(Error::new(
                ErrorCode::EmptySequence,
                FIELD,
                set.span().start,
            ));
        }
        components::end(&attribute)?;
        super::super::identifier_work(oid, &attribute.execution(), entry.span().start)?;
        let value = Attribute {
            kind: oid,
            element: entry,
            values: set,
        };
        decode(&attribute, value, &mut components)?;
        attributes
            .try_push(value)
            .map_err(|e| Error::resource(e, FIELD, entry.span().start))?;
    }
    Ok((attributes.into_owned(), components))
}

fn decode<'a>(
    reader: &ScopedReader<'a, '_>,
    attribute: Attribute<'a>,
    components: &mut Components<'a>,
) -> Result<()> {
    let entry = attribute.element;
    let set = attribute.values;
    if attribute.kind == SUBJECT_ALT_PUBLIC_KEY_INFO {
        components.key = Component::read(
            entry.span(),
            None,
            set.as_bytes(),
            "request.subjectAltPublicKeyInfo",
            || {
                let (reader, value) = single(reader, &set)?;
                PublicKeyInfo::read_element(&reader, &value, FIELD)
            },
        )?;
    } else if attribute.kind == ALT_SIGNATURE_ALGORITHM {
        components.algorithm = Component::read(
            entry.span(),
            None,
            set.as_bytes(),
            "request.altSignatureAlgorithm",
            || {
                let (reader, value) = single(reader, &set)?;
                algorithm::read(&reader, &value, FIELD)
            },
        )?;
    } else if attribute.kind == ALT_SIGNATURE_VALUE {
        components.signature = Component::read(
            entry.span(),
            None,
            set.as_bytes(),
            "request.altSignatureValue",
            || {
                let mut reader = reader.enter(&set).field(FIELD)?;
                let value = SignatureValue::read(&mut reader, FIELD)?;
                components::end(&reader)?;
                Ok(value)
            },
        )?;
    }
    Ok(())
}
