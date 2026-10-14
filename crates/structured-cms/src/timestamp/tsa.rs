//! Original explicit TSA names using the common `GeneralName` semantics.

use super::record;
use crate::{Error, ErrorCode, Result};
use structured_asn1::memory::{OwnedVec, Work};
use structured_asn1::{Element, Reader, Span};
use structured_pkix::general_name::{self, GeneralName};

const FIELD: &str = "tstInfo.tsa";

/// Present TSA wrapper and its readable name, or explicitly unreadable contents.
/// An unreadable present wrapper is distinct from an absent optional field.
#[derive(Debug)]
pub struct TsaReading<'a> {
    wrapper: Element<'a>,
    element: Option<Element<'a>>,
    name: Option<GeneralName<'a>>,
}

impl<'a> TsaReading<'a> {
    pub(super) fn read<W: Work>(
        parent: &Reader<'a>,
        wrapper: &Element<'a>,
        faults: &mut OwnedVec<Error, W>,
    ) -> Result<Self> {
        let mut inside = parent
            .enter(wrapper)
            .map_err(|error| Error::encoding(error, FIELD))?;
        let first = match inside
            .next_element()
            .map_err(|error| Error::encoding(error, FIELD))
        {
            Ok(Some(first)) => first,
            Ok(None) => {
                record(
                    faults,
                    Error::schema(ErrorCode::MissingField, FIELD, wrapper.span().start),
                )?;
                return Ok(Self {
                    wrapper: *wrapper,
                    element: None,
                    name: None,
                });
            }
            Err(error) => {
                record(faults, error)?;
                return Ok(Self {
                    wrapper: *wrapper,
                    element: None,
                    name: None,
                });
            }
        };
        let reading = match general_name::read(&inside, &first, FIELD).map_err(Error::pkix) {
            Ok(name) => Ok(name),
            Err(error) if error.is_terminal() => return Err(error),
            Err(error) => Err(error),
        };
        let mut duplicate = None;
        while let Some(extra) = inside
            .next_element()
            .map_err(|error| Error::encoding(error, FIELD))?
        {
            let at = extra.span().start;
            inside
                .execution()
                .charge_work(1 + first.as_bytes().len().min(extra.as_bytes().len()) as u64)
                .map_err(|reason| Error::resource(reason, FIELD, at))?;
            if first.as_bytes() != extra.as_bytes() && !same_name(&inside, &reading, &extra)? {
                return Err(Error::schema(ErrorCode::TrailingData, FIELD, at));
            }
            duplicate.get_or_insert(at);
        }
        if let Some(at) = duplicate {
            record(faults, Error::schema(ErrorCode::DuplicateField, FIELD, at))?;
        }
        let name = match reading {
            Ok(name) => Some(name),
            Err(error) => {
                record(faults, error)?;
                None
            }
        };
        Ok(Self {
            wrapper: *wrapper,
            element: Some(first),
            name,
        })
    }

    /// Whole original explicit [0] wrapper range.
    #[must_use]
    pub fn span(&self) -> Span {
        self.wrapper.span()
    }
    /// First original encoded name, absent if its header was unreadable/missing.
    #[must_use]
    pub fn element(&self) -> Option<&Element<'a>> {
        self.element.as_ref()
    }
    /// Common decoded name; None means present-but-unreadable, never absence.
    #[must_use]
    pub fn name(&self) -> Option<&GeneralName<'a>> {
        self.name.as_ref()
    }
}

fn same_name(
    parent: &Reader<'_>,
    first: &Result<GeneralName<'_>>,
    extra: &Element<'_>,
) -> Result<bool> {
    let Ok(first) = first else {
        return Ok(false);
    };
    let other = match general_name::read(parent, extra, FIELD).map_err(Error::pkix) {
        Ok(other) => other,
        Err(error) if error.is_terminal() => return Err(error),
        Err(_) => return Ok(false),
    };
    general_name::matches(parent, first, &other, extra.span().start, FIELD).map_err(Error::pkix)
}
