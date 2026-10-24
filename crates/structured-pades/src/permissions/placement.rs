//! Original signature-field and certification placement, independent of math.

use super::Transforms;
use crate::{
    document::{Document, Graph},
    error::{Error, ErrorKind, ReadFailure, Syntax},
    fields::Fields,
    model::admit,
    object::Type,
    range::RangeSource,
    signature::Signature,
};
use structured_asn1::memory::Work;

/// Original signature's normative field/certification association.
pub struct Placement {
    field: Option<usize>,
    certification: bool,
    first: bool,
    permissions: Option<bool>,
    complete: bool,
}
impl Placement {
    /// Original field ordinal in the complete historical `AcroForm` census.
    #[must_use]
    pub fn field(&self) -> Option<usize> {
        self.field
    }
    /// Actual signed Reference includes a `DocMDP` transformation.
    #[must_use]
    pub fn is_certification(&self) -> bool {
        self.certification
    }
    /// No other author-signed field existed in this signed snapshot.
    #[must_use]
    pub fn is_first_signed_field(&self) -> bool {
        self.first
    }
    /// Whether a present catalog Perms.DocMDP selects this exact certification.
    /// Absence is allowed: ISO32000-1 distinguishes detection from prevention.
    #[must_use]
    pub fn catalog_permission_binding(&self) -> Option<bool> {
        self.permissions
    }
    /// All original field and certification placement requirements hold.
    #[must_use]
    pub fn all_requirements_met(&self) -> bool {
        self.complete
    }
}

impl<'s, S: RangeSource> Document<'s, S> {
    /// ISO32000-1 §12.8.2.2.1 requires `DocMDP` in the first signed field;
    /// §12.8.4 makes the catalog reference the prevention mechanism. It is
    /// not a prerequisite for a signed transform's modification detection.
    /// <https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf>
    pub fn signature_placement<W: Work>(
        &self,
        signature: Signature<'_, 's, S::Document, S::Generation>,
        graph: &Graph<'s, S::Document, S::Generation>,
        fields: &Fields<'_, 's, S::Document, S::Generation>,
        transforms: &Transforms,
        operation: &W,
    ) -> Result<Placement, ReadFailure<S::Error>> {
        let work = self.session.query(operation);
        let location = signature.location();
        self.check(&work, location)?;
        if !core::ptr::eq(fields.graph, graph)
            || !core::ptr::eq(graph.session, self.session)
            || graph.stamp != self.stamp
            || transforms.location() != location
        {
            return Err(Error {
                kind: ErrorKind::Foreign,
                location,
            }
            .into());
        }
        let field = fields.signature(location, &work)?;
        let certification = transforms.permission().is_some();
        let mut first = true;
        for (ordinal, entry) in fields.values().iter().enumerate() {
            admit(&work, location, 1)?;
            if !entry.is_signature() || Some(ordinal) == field {
                continue;
            }
            let Some(value) = fields.value(ordinal, &work)? else {
                continue;
            };
            if value.direct().kind() == Type::Null {
                continue;
            }
            if value.direct().kind() != Type::Dictionary {
                return Err(Error {
                    kind: ErrorKind::Syntax(Syntax::Dictionary),
                    location: value.direct().location(),
                }
                .into());
            }
            // EN319142-1 §5.4.3 excludes document timestamp dictionaries
            // from DocMDP evaluation. Their own format/math remains separate.
            if let Some(kind) = value.get(b"Type", &work)?
                && kind.direct().name_equals(b"DocTimeStamp", &work)?
            {
                continue;
            }
            first = false;
        }
        let permissions = if let Some(perms) = graph.root().get(b"Perms", &work)? {
            perms
                .get(b"DocMDP", &work)?
                .map(|value| value.direct().location() == location)
        } else {
            None
        };
        let complete = field.is_some()
            && (!certification || first)
            && match permissions {
                Some(true) => certification,
                Some(false) => !certification,
                None => true,
            };
        self.check(&work, location)?;
        Ok(Placement {
            field,
            certification,
            first,
            permissions,
            complete,
        })
    }
}
