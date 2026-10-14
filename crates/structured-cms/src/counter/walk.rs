//! Iterative, caller-selected countersignature processing over original inputs.

use super::{Cursor, FIELD};
use crate::{Error, Octets, signer::SignerInfo};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Reader, Span};

/// One direct value, with the exact parent signature it countersigns.
pub enum Visit<'s, 'a> {
    /// Readable original `SignerInfo`; conformance faults remain in that model.
    Signer {
        /// Original parsed child, borrowed only during this visitor call.
        signer: &'s SignerInfo<'a>,
        /// Original logical parent signature octets, never its signed payload.
        signature: &'s Octets<'a>,
        /// Original parent signer range, for stable relationship identity.
        parent: Span,
    },
    /// An unreadable independent value; later direct values remain accessible.
    Malformed {
        /// Original located processing diagnostic, with its storage ownership.
        source: Error,
        /// Original parent signer range.
        parent: Span,
    },
}

/// A traversal did not complete, independently of a visitor's semantic answers.
#[derive(Debug)]
pub enum WalkError<E> {
    /// Common source-located work/storage/depth refusal.
    Processing(Error),
    /// Original visitor failure, including backend/resource causes.
    Callback {
        /// Original parent signer whose signature this value covered.
        parent: Span,
        /// Original child start, or the malformed value's diagnostic position.
        at: u64,
        /// Caller failure, never converted to invalid/unsupported/absence.
        source: E,
    },
}

/// Processes all nested countersignature values with an admitted iterative stack.
///
/// RFC5652 §11.4 permits repeated attributes/values and nested countersignatures.
/// Values are visited depth first in original sibling order, with O(depth)
/// active frames. This order implies no chronology or application priority.
/// Only unsigned countersignatures are visited: callers must separately retain
/// misplaced signed attributes and unreadable values for protocol diagnostics. Each visitor receives the ORIGINAL child's producing Reader;
/// parsing its parameters must not reset enclosing depth or local work.
///
/// Callers select keys/providers and can run `prepare::resolve` with
/// `Scope::CounterSignature` and the shared verification batch against the
/// supplied parent signature. This operation asserts neither root-signature
/// validity nor trust/identity and makes no implicit key selection or I/O.
/// Visitors admit their own data-dependent work/storage in the supplied Reader.
/// Returned values must not borrow the temporary child model/Reader; they may
/// borrow original document bytes or own independently admitted evidence.
///
/// A semantic parse failure is delivered as a separate malformed event; a
/// resource or visitor failure aborts and drops all temporary/collected values.
/// Visitor external side effects cannot be rolled back by this operation.
/// No successful partial catalogue is exposed. Retained result capacity owns
/// its original charge independently of the parser and traversal frames.
/// <https://www.rfc-editor.org/rfc/rfc5652#section-11.4>
pub fn walk<'a, R, E>(
    root: &SignerInfo<'a>,
    parent: &Reader<'a>,
    mut visitor: impl FnMut(Visit<'_, 'a>, &Reader<'a>) -> core::result::Result<R, E>,
) -> core::result::Result<OwnedVec<R>, WalkError<E>> {
    let execution = parent.execution();
    let mut ancestors = execution.vector();
    let mut results = execution.vector();
    let mut current = Frame {
        owned: None,
        cursor: Cursor::default(),
    };
    loop {
        let (signer, reader) = match &current.owned {
            Some((signer, reader)) => (signer, reader),
            None => (root, parent),
        };
        let candidate = current.cursor.next(signer, reader);
        let Some(candidate) = candidate else {
            if ancestors.is_empty() {
                break;
            }
            execution.charge_work(1).map_err(|reason| {
                WalkError::Processing(Error::resource(reason, FIELD, signer.span().start))
            })?;
            if let Some(frame) = ancestors.pop() {
                current = frame;
            }
            continue;
        };
        let parent_span = signer.span();
        match candidate {
            Ok((child, child_reader)) => {
                let at = child.span().start;
                let refusal = |reason| WalkError::Processing(Error::resource(reason, FIELD, at));
                let descend = child.unsigned_attributes().is_some();
                if descend {
                    ancestors.try_reserve(1).map_err(refusal)?;
                }
                results.try_reserve(1).map_err(refusal)?;
                let result = visitor(
                    Visit::Signer {
                        signer: &child,
                        signature: signer.signature(),
                        parent: parent_span,
                    },
                    &child_reader,
                )
                .map_err(|source| WalkError::Callback {
                    parent: parent_span,
                    at,
                    source,
                })?;
                results.try_push(result).map_err(refusal)?;
                if descend {
                    ancestors.try_push(current).map_err(refusal)?;
                    current = Frame {
                        owned: Some((child, child_reader)),
                        cursor: Cursor::default(),
                    };
                }
            }
            Err(error) if error.is_terminal() => return Err(WalkError::Processing(error)),
            Err(error) => {
                let at = error.offset();
                let refusal = |reason| WalkError::Processing(Error::resource(reason, FIELD, at));
                results.try_reserve(1).map_err(refusal)?;
                let result = visitor(
                    Visit::Malformed {
                        source: error,
                        parent: parent_span,
                    },
                    reader,
                )
                .map_err(|source| WalkError::Callback {
                    parent: parent_span,
                    at,
                    source,
                })?;
                results.try_push(result).map_err(refusal)?;
            }
        }
    }
    Ok(results.into_owned())
}

// None denotes only the borrowed root; descendants own exactly one active
// decoded signer and cursor. No sibling catalogue or self-reference is stored.
struct Frame<'a> {
    owned: Option<(SignerInfo<'a>, Reader<'a>)>,
    cursor: Cursor,
}
