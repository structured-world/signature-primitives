//! Request extension recognition is broader than critical token recognition.

use super::{RecognitionError, Request};
use crate::Error;
use structured_asn1::{
    Oid, Reader,
    memory::{Execution, OwnedVec, Work},
};
use structured_pkix::Extension;

impl<'a> Request<'a> {
    /// Reports every requested extension the supplied handler does not recognize.
    ///
    /// RFC3161 §2.4.1 requires server recognition regardless of criticality.
    /// This is not a certificate-understands or token-critical-only query.
    /// The common fallible catalogue iterator admits each metadata access;
    /// the handler must independently admit its data-dependent decoding work.
    /// No empty/partial successful list is returned after processing or handler
    /// refusal. Recognition itself does not grant policy/algorithm permission.
    /// <https://www.rfc-editor.org/rfc/rfc3161#section-2.4.1>
    pub fn unrecognized_extensions<E>(
        &self,
        parent: &Reader<'_>,
        mut recognizes: impl FnMut(&Extension<'a>, &Execution<'_>) -> Result<bool, E>,
    ) -> Result<OwnedVec<Oid<'a>>, RecognitionError<E>> {
        const FIELD: &str = "timeStampReq.extensions";
        if !self.same_session(parent) {
            return Err(RecognitionError::Processing(Error::pkix(
                structured_pkix::Error::new(
                    structured_pkix::ErrorCode::ForeignReader,
                    FIELD,
                    self.span().start,
                ),
            )));
        }
        let work = parent.execution();
        let mut unknown = work.vector();
        if let Some(extensions) = self.extensions() {
            for entry in extensions.iter(&work) {
                let entry =
                    entry.map_err(|source| RecognitionError::Processing(Error::pkix(source)))?;
                if !recognizes(entry, &work).map_err(|source| RecognitionError::Callback {
                    span: entry.span(),
                    source,
                })? {
                    unknown.try_push(entry.kind()).map_err(|reason| {
                        RecognitionError::Processing(Error::resource(
                            reason,
                            FIELD,
                            entry.span().start,
                        ))
                    })?;
                }
            }
        }
        Ok(unknown.into_owned())
    }
}
