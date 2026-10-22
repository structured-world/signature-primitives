//! RFC5755 §7.4 restrictions along one explicitly supplied AA certificate path.
//!
//! [`AaPath::read`] collects restrictions from an already authenticated
//! leaf-first path. [`validate`] combines that same census with the common
//! PKIX validator and a separately selected trusted AA CA. Its returned
//! [`ValidatedPath`] can authenticate AC issuance without repeating path
//! signatures. Trust selection, revocation and application authorization
//! remain caller obligations.
//! <https://www.rfc-editor.org/rfc/rfc5755#section-7.4>

use super::{Check, Reason, charge, refused};
use crate::attribute_certificate::controls::{self, AaControls};
use crate::{Error, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Oid, Span};
use structured_pkix::Certificate;

pub(super) mod validated;
pub use validated::{
    Issued, PathCheck, PathError, PathResult, ValidatedPath, validate, validate_with_key,
};

/// One original control and its position in the supplied leaf-first path.
#[derive(Debug)]
struct Control<'a> {
    position: usize,
    value: AaControls<'a>,
}

/// Complete restriction census from the AA issuer through the chosen AA CA.
#[derive(Debug)]
pub struct AaPath<'p, 'a> {
    certificates: &'p [&'p Certificate<'a>],
    controls: OwnedVec<Control<'a>>,
}

/// Completed per-attribute intersection, not an application permission verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Every applicable control permits this attribute type.
    Permitted,
    /// The attribute must be ignored for authorization under this AA path.
    Excluded {
        /// Original certificate position carrying the first excluding control.
        certificate: usize,
        /// Original `AAControls` extension value, not the AC attribute's location.
        source: Span,
    },
}

impl<'p, 'a> AaPath<'p, 'a> {
    /// Collect every control before returning a usable attribute query.
    ///
    /// Every PKC below the selected final AA CA must contain `AAControls`; the AA
    /// CA's own control is optional but applies if present. An array containing
    /// just the directly trusted AA issuer therefore need not have a control.
    /// The distance excludes the target AA issuer and self-issued intermediate
    /// PKCs, as RFC5280 §4.2.1.9 prescribes for pathLenConstraint.
    ///
    /// Malformed/control-resource failures are terminal `Result` errors. A missing
    /// control or excessive distance produces a completed located rejection;
    /// no successful prefix census is returned. Certificate path authenticity
    /// and final-AA selection are preconditions supplied by the caller.
    pub fn read<W: Work>(certificates: &'p [&'p Certificate<'a>], work: &W) -> Result<Check<Self>> {
        let Some(last) = certificates.len().checked_sub(1) else {
            // No source exists for an empty caller-supplied path.
            return Ok(Check::Rejected(super::Rejection {
                reason: Reason::EmptyPath,
                source: None,
            }));
        };
        charge(work, 1, certificates[0].span().start)?;
        let mut controls = work.vector().into_owned();
        let mut distance = 0;
        for (position, certificate) in certificates.iter().enumerate() {
            let execution = certificate.execution_in(work);
            charge(&execution, 1, certificate.span().start)?;
            let extension = certificate
                .tbs()
                .extensions()
                .get(controls::IDENTIFIER, &execution)
                .map_err(Error::pkix)?;
            if let Some(extension) = extension {
                // Reserve output before decoding the nested variable-sized
                // catalogue; a capacity failure cannot leave an unretained read.
                // Both owners originate in this same sealed Work account;
                // rebinding can refuse only an account mismatch, not resources.
                let Ok(mut scoped) = controls.with_execution(&execution) else {
                    unreachable!("control storage retains this operation's account");
                };
                scoped
                    .try_reserve(1)
                    .map_err(|e| Error::resource(e, super::FIELD, extension.span().start))?;
                let value = AaControls::read_extension(extension, &execution)?;
                if !value.permits_distance(distance, &execution)? {
                    return Ok(refused(Reason::ControlDistance, value.element.span()));
                }
                scoped
                    .try_push(Control { position, value })
                    .map_err(|e| Error::resource(e, super::FIELD, extension.span().start))?;
                controls = scoped.into_owned();
            } else if position != last {
                return Ok(refused(Reason::MissingControls, certificate.span()));
            }
            if position != 0
                && position != last
                && !certificate
                    .tbs()
                    .subject()
                    .matches(certificate.tbs().issuer(), &execution)
                    .map_err(Error::pkix)?
            {
                // At most one increment per supplied slice entry, bounded by
                // its representable length, without a new caller policy limit.
                distance += 1;
            }
        }
        Ok(Check::Accepted(Self {
            certificates,
            controls: controls.into_owned(),
        }))
    }

    /// Exact supplied path, including its explicitly chosen final AA CA.
    #[must_use]
    pub fn certificates(&self) -> &[&Certificate<'a>] {
        self.certificates
    }

    /// Intersect all controls for one attribute, retaining the denying source.
    ///
    /// Call this for every actual attribute after decryption, including encAttrs
    /// itself (§7.4). An exclusion means ignore this attribute for authorization,
    /// not that every other attribute or the complete AC must be discarded.
    /// Original stored controls keep their capacity charges; current Work pays
    /// the traversal and each deferred comparison. No result is cached across
    /// requests and no failed query becomes a successful permission.
    pub fn allows<W: Work>(&self, attribute: Oid<'_>, work: &W) -> Result<Permission> {
        charge(work, 1, self.certificates[0].span().start)?;
        for control in &self.controls {
            charge(work, 1, control.value.element.span().start)?;
            if !control.value.allows(attribute, work)? {
                return Ok(Permission::Excluded {
                    certificate: control.position,
                    source: control.value.element.span(),
                });
            }
        }
        Ok(Permission::Permitted)
    }
}
