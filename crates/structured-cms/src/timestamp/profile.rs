//! Parse-once profile inspection, separate from common timestamp semantics.

use super::{CheckError, InfoCheckError, InfoError, MappedCheckError, Token, TokenInfo};
use crate::{
    Error,
    content_source::{ContentError, SourceMap},
    ess::SigningAttributes,
};
use core::convert::Infallible;
use structured_asn1::Reader;

/// The coordinate domain of a profile's original refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileSource {
    /// Original CMS/ESS envelope fields use the producing outer reader/map.
    Envelope,
    /// Original carried `TSTInfo` fields use its own reader/map.
    Information,
}

/// Exact caller-owned cause and the source from which its coordinates came.
/// The common core does not rewrite an opaque error or invent its location.
#[derive(Debug)]
pub struct ProfileFailure<E> {
    /// Actual coordinate domain; never apply an inner map to an outer field.
    pub source: ProfileSource,
    /// Original independent cause. It cannot borrow a temporary joined source.
    pub cause: E,
}

/// Original already decoded fields, scoped to one profile invocation.
/// These are structural facts, not successful mathematics, authority or trust.
/// Outer and carried sources can have different coordinate systems even when
/// they share an execution account. Scans, copies and parameter queries must
/// admit their work through the corresponding reader's current execution.
///
/// An information view cannot escape into an independently retained result or
/// error: its bytes may belong to a temporary joined buffer.
///
/// ```compile_fail
/// use structured_cms::timestamp::{ProfileInput, TokenInfo};
/// fn escape<'a>(input: ProfileInput<'_, 'a, 'a, '_>) -> &'a TokenInfo<'a> {
///     input.info
/// }
/// ```
pub struct ProfileInput<'view, 'document, 'envelope, 'information> {
    /// Same original token being checked, without a second envelope parse.
    pub token: &'view Token<'document>,
    /// Original CMS/ESS producing reader with current operation funding.
    pub parent: &'view Reader<'envelope>,
    /// Outer source map for a logically joined envelope. None means the outer
    /// reader already uses original coordinates, not an absent original source.
    pub envelope: Option<&'view SourceMap>,
    /// Same original signed ESS attributes used by the subsequent binding.
    pub ess: &'view SigningAttributes<'envelope>,
    /// Same original information reading used by the subsequent complete check.
    pub info: &'view TokenInfo<'information>,
    /// Producing carried-source reader, including original depth and ceilings.
    pub reader: &'view Reader<'information>,
    /// Original projection for coordinates derived from that carried reader.
    pub source: &'view SourceMap,
}

/// Extended profile execution refusal. Existing public common error enums are
/// unchanged, including their exhaustive matching surface.
#[derive(Debug)]
pub enum ProfileCheckError<SE, PE, RE, FE> {
    /// Unchanged common processing/provider/source/recognition failure.
    Common(CheckError<SE, PE, RE>),
    /// Terminal profile refusal before cryptographic/content callbacks.
    Profile {
        /// Original cause and its explicit coordinate domain.
        source: ProfileFailure<FE>,
        /// Independent inner map, surviving the joined information buffer.
        /// Use this only for Information; Envelope uses original outer
        /// coordinates or the mapped wrapper's separately retained envelope.
        context: SourceMap,
    },
}

/// A profile check in a logical envelope retains both independent source maps.
#[derive(Debug)]
pub enum MappedProfileCheckError<SE, PE, RE, FE> {
    /// Original source/session refusal before map allocation or dispatch.
    Preflight(CheckError<SE, PE, RE>),
    /// Outer-map admission failed at its original physical enclosure.
    Provenance(Error),
    /// Original extended cause with its separately retained outer coordinates.
    Execution {
        /// Original CMS envelope map, never the carried-information map.
        envelope: SourceMap,
        /// Unchanged common/profile cause and any retained inner context.
        source: ProfileCheckError<SE, PE, RE, FE>,
    },
}

pub(super) enum InformationFailure<SE, PE, RE, FE> {
    Common(InfoCheckError<SE, PE, RE>),
    Profile(ProfileFailure<FE>),
}

impl<SE, PE, RE, FE> From<CheckError<SE, PE, RE>> for ProfileCheckError<SE, PE, RE, FE> {
    fn from(value: CheckError<SE, PE, RE>) -> Self {
        Self::Common(value)
    }
}

impl<SE, PE, RE, FE> From<InfoCheckError<SE, PE, RE>> for InformationFailure<SE, PE, RE, FE> {
    fn from(value: InfoCheckError<SE, PE, RE>) -> Self {
        Self::Common(value)
    }
}

impl<SE, PE, RE> ProfileCheckError<SE, PE, RE, Infallible> {
    pub(super) fn into_common(self) -> CheckError<SE, PE, RE> {
        match self {
            Self::Common(source) => source,
            Self::Profile { source, .. } => match source.cause {},
        }
    }
}

impl<SE, PE, RE> MappedProfileCheckError<SE, PE, RE, Infallible> {
    pub(super) fn into_common(self) -> MappedCheckError<SE, PE, RE> {
        match self {
            Self::Preflight(source) => MappedCheckError::Preflight(source),
            Self::Provenance(source) => MappedCheckError::Provenance(source),
            Self::Execution { envelope, source } => MappedCheckError::Execution {
                envelope,
                source: source.into_common(),
            },
        }
    }
}

pub(super) fn information_error<SE, PE, RE, FE>(
    error: ContentError<InfoError<InformationFailure<SE, PE, RE, FE>>>,
) -> ProfileCheckError<SE, PE, RE, FE> {
    let common = |source| ProfileCheckError::Common(CheckError::Information(source));
    match error {
        ContentError::Processing(source) => common(ContentError::Processing(source)),
        ContentError::Decoding { source, context } => {
            common(ContentError::Decoding { source, context })
        }
        ContentError::Callback {
            source: InfoError::Processing(source),
            context,
        } => common(ContentError::Callback {
            source: InfoError::Processing(source),
            context,
        }),
        ContentError::Callback {
            source: InfoError::Callback(InformationFailure::Common(source)),
            context,
        } => common(ContentError::Callback {
            source: InfoError::Callback(source),
            context,
        }),
        ContentError::Callback {
            source: InfoError::Callback(InformationFailure::Profile(source)),
            context,
        } => ProfileCheckError::Profile { source, context },
    }
}
