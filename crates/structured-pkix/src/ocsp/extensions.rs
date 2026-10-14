//! Critical demands have response-wide or selected-assertion scope.

use super::{BasicResponse, SingleResponse};
use crate::{Error, Result, oid};
use structured_asn1::memory::Memory;
use structured_asn1::{Oid, Span};

/// Supported extension processing, separate from application acceptance.
#[derive(Debug, Clone, Copy)]
pub enum ExtensionProcessing<'a> {
    /// All critical demands in this scope were understood. Unsupported optional
    /// noncritical extensions remain available in the original model.
    Understood,
    /// A critical demand is unsupported, with its original identifier/location.
    Unsupported {
        /// Original extension identifier.
        kind: Oid<'a>,
        /// Original extension location.
        span: Span,
    },
}

pub(super) struct Processed<'a> {
    pub(super) processing: ExtensionProcessing<'a>,
    pub(super) nonce: Option<&'a [u8]>,
}

impl<'a> BasicResponse<'a> {
    /// Process response-wide critical demands before using any assertion.
    /// RFC6960 §4.4 makes optional extension support explicit. This core
    /// supports nonce; other optional noncritical values remain opaque.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.4>
    pub fn check_extensions(&self, execution: &Memory) -> Result<ExtensionProcessing<'a>> {
        self.process_extensions(execution)
            .map(|facts| facts.processing)
    }

    pub(super) fn process_extensions(&self, execution: &Memory) -> Result<Processed<'a>> {
        execution.charge_work(1).map_err(|reason| {
            Error::resource(reason, "ocspResponse.extensions", self.span.start)
        })?;
        let mut nonce = None;
        for extension in self.extensions.iter(execution) {
            let extension = extension?;
            // The common iterator already admitted the metadata step.
            execution.charge_work(10).map_err(|reason| {
                Error::resource(reason, "ocspResponse.extensions", extension.span().start)
            })?;
            if extension.kind() == oid::OCSP_NONCE {
                nonce = Some(super::nonce::read(extension, execution)?);
            } else if extension.is_critical() {
                return Ok(Processed {
                    processing: ExtensionProcessing::Unsupported {
                        kind: extension.kind(),
                        span: extension.span(),
                    },
                    nonce,
                });
            }
        }
        Ok(Processed {
            processing: ExtensionProcessing::Understood,
            nonce,
        })
    }
}

impl<'a> SingleResponse<'a> {
    /// Process this assertion's critical demands, independently of unrelated
    /// assertions. No optional single-extension semantics are advertised
    /// by this core, so unknown critical demands remain unsupported facts.
    pub fn check_extensions(&self, execution: &Memory) -> Result<ExtensionProcessing<'a>> {
        execution.charge_work(1).map_err(|reason| {
            Error::resource(
                reason,
                "ocspResponse.singleResponse.extensions",
                self.span.start,
            )
        })?;
        if let Some(extension) = self.extensions.criticals(execution).next() {
            let extension = extension?;
            return Ok(ExtensionProcessing::Unsupported {
                kind: extension.kind(),
                span: extension.span(),
            });
        }
        Ok(ExtensionProcessing::Understood)
    }
}
