//! Critical demands have response-wide or selected-assertion scope.

use super::{BasicResponse, SingleResponse, retention};
use crate::temporal::Reading;
use crate::{Error, Result, oid};
use structured_asn1::memory::Work;
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
    pub(super) extended_revoke: bool,
}

pub(super) struct ProcessedSingle<'a> {
    pub(super) processing: ExtensionProcessing<'a>,
    pub(super) archive_cutoff: Option<Reading>,
}

impl<'a> BasicResponse<'a> {
    /// Process response-wide critical demands before using any assertion.
    /// RFC6960 §4.4 makes optional extension support explicit. This core
    /// supports nonce and the extended revoked definition; other optional
    /// noncritical values remain opaque.
    /// <https://www.rfc-editor.org/rfc/rfc6960#section-4.4>
    pub fn check_extensions<W: Work>(&self, execution: &W) -> Result<ExtensionProcessing<'a>> {
        self.process_extensions(execution)
            .map(|facts| facts.processing)
    }

    pub(super) fn process_extensions<W: Work>(&self, execution: &W) -> Result<Processed<'a>> {
        execution.charge_work(1).map_err(|reason| {
            Error::resource(reason, "ocspResponse.extensions", self.span.start)
        })?;
        let mut nonce = None;
        let mut extended_revoke = false;
        for extension in self.extensions.iter(execution) {
            let extension = extension?;
            // The common iterator already admitted the metadata step.
            execution.charge_work(10).map_err(|reason| {
                Error::resource(reason, "ocspResponse.extensions", extension.span().start)
            })?;
            if extension.kind() == oid::OCSP_NONCE {
                nonce = Some(super::nonce::read(extension, execution)?);
            } else if extension.kind() == oid::OCSP_EXTENDED_REVOKE {
                retention::extended_revoke(extension, execution)?;
                extended_revoke = true;
            } else if extension.is_critical() {
                return Ok(Processed {
                    processing: ExtensionProcessing::Unsupported {
                        kind: extension.kind(),
                        span: extension.span(),
                    },
                    nonce,
                    extended_revoke,
                });
            }
        }
        Ok(Processed {
            processing: ExtensionProcessing::Understood,
            nonce,
            extended_revoke,
        })
    }
}

impl<'a> SingleResponse<'a> {
    /// Process this assertion's critical demands, independently of unrelated
    /// assertions. This core supports the archive cutoff; other critical
    /// demands remain unsupported facts.
    pub fn check_extensions<W: Work>(&self, execution: &W) -> Result<ExtensionProcessing<'a>> {
        self.process_extensions(execution)
            .map(|facts| facts.processing)
    }

    pub(super) fn process_extensions<W: Work>(&self, execution: &W) -> Result<ProcessedSingle<'a>> {
        const FIELD: &str = "ocspResponse.singleResponse.extensions";
        execution
            .charge_work(1)
            .map_err(|reason| Error::resource(reason, FIELD, self.span.start))?;
        let mut archive_cutoff = None;
        for extension in self.extensions.iter(execution) {
            let extension = extension?;
            // The common iterator already admitted the metadata step.
            execution
                .charge_work(10)
                .map_err(|reason| Error::resource(reason, FIELD, extension.span().start))?;
            if extension.kind() == oid::OCSP_ARCHIVE_CUTOFF {
                archive_cutoff = Some(retention::archive_cutoff(extension, execution)?);
            } else if extension.kind() == oid::OCSP_EXTENDED_REVOKE {
                return Err(retention::misplaced(extension));
            } else if extension.is_critical() {
                return Ok(ProcessedSingle {
                    processing: ExtensionProcessing::Unsupported {
                        kind: extension.kind(),
                        span: extension.span(),
                    },
                    archive_cutoff,
                });
            }
        }
        Ok(ProcessedSingle {
            processing: ExtensionProcessing::Understood,
            archive_cutoff,
        })
    }
}
