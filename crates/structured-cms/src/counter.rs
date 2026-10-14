//! Lazy direct countersignatures without a recursive traversal or new parser.

use crate::signer::SignerInfo;
use crate::{Error, ErrorCode, Result};
use structured_asn1::Reader;
use structured_asn1::memory::Work;

mod walk;
pub use walk::{Visit, WalkError, walk};

const FIELD: &str = "signerInfo.unsignedAttrs.countersignature";

/// Direct unsigned countersignature values in original encoded order.
///
/// RFC5652 §11.4 permits repeated instances, multiple nonempty values and
/// nesting. This iterator decodes one direct value at a time. Malformed values
/// do not erase later siblings; a resource refusal is yielded once then stops.
/// <https://www.rfc-editor.org/rfc/rfc5652#section-11.4>
pub struct Countersignatures<'s, 'a> {
    signer: &'s SignerInfo<'a>,
    parent: &'s Reader<'a>,
    cursor: Cursor,
}

// Numeric state can move with its owner without references into that owner.
#[derive(Default)]
struct Cursor {
    attribute: usize,
    active: Option<usize>,
    value: usize,
    stopped: bool,
}

impl<'s, 'a> Countersignatures<'s, 'a> {
    pub(crate) fn new(signer: &'s SignerInfo<'a>, parent: &'s Reader<'a>) -> Self {
        Self {
            signer,
            parent,
            cursor: Cursor::default(),
        }
    }
}

impl Cursor {
    fn next<'a>(
        &mut self,
        signer: &SignerInfo<'a>,
        parent: &Reader<'a>,
    ) -> Option<Result<(SignerInfo<'a>, Reader<'a>)>> {
        if self.stopped {
            return None;
        }
        if let Err(error) = signer.require_session(parent, FIELD) {
            self.stopped = true;
            return Some(Err(error));
        }
        let Some(attributes) = signer.unsigned_attributes() else {
            self.stopped = true;
            return None;
        };
        loop {
            let at = self.active.map_or(signer.span().start, |index| {
                attributes.items()[index].span().start
            });
            if let Err(reason) = parent.execution().charge_work(1) {
                self.stopped = true;
                return Some(Err(Error::resource(reason, FIELD, at)));
            }
            if let Some(index) = self.active {
                let attribute = &attributes.items()[index];
                if self.value < attribute.values().len() {
                    let index = self.value;
                    self.value += 1;
                    let value = (|| {
                        let Some(mut reader) = attribute.value_reader_in(index, parent, FIELD)?
                        else {
                            return Err(Error::schema(ErrorCode::MissingField, FIELD, at));
                        };
                        let element = crate::signer::required(&mut reader, FIELD)?;
                        let signer = SignerInfo::read(&reader, &element)?;
                        Ok((signer, reader))
                    })();
                    if value.as_ref().is_err_and(Error::is_terminal) {
                        self.stopped = true;
                    }
                    return Some(value);
                }
                self.active = None;
            }
            let attribute = match attributes.next_matching(
                crate::oid::COUNTERSIGNATURE,
                &parent.execution(),
                &mut self.attribute,
                &mut self.stopped,
            ) {
                Some(Ok(attribute)) => attribute,
                Some(Err(error)) => return Some(Err(error)),
                None => return None,
            };
            if attribute.values().is_empty() {
                return Some(Err(Error::schema(
                    ErrorCode::AttributeCardinality,
                    FIELD,
                    attribute.span().start,
                )));
            }
            self.active = Some(self.attribute - 1);
            self.value = 0;
        }
    }
}

impl<'a> Iterator for Countersignatures<'_, 'a> {
    type Item = Result<SignerInfo<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.cursor
            .next(self.signer, self.parent)
            .map(|reading| reading.map(|(signer, _reader)| signer))
    }
}
impl core::iter::FusedIterator for Countersignatures<'_, '_> {}
