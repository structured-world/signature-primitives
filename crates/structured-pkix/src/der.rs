//! Holding a range to the distinguished rules.
//!
//! Certificates are not the only structure whose schema fixes its encoding
//! regardless of the envelope carrying it. A signed message is BER, and the
//! attributes inside it that a signature covers "MUST be DER encoded, even if
//! the rest of the structure is BER encoded" (RFC 5652 5.3). The walk that
//! decides that question already exists here, so it is exposed rather than
//! written a second time: two answers to what counts as DER is one answer more
//! than a product can defend.

use crate::error::{Error, ErrorCode, Result};
use structured_asn1::{Element, Reader};

/// Whether a range and everything under it is DER.
///
/// Definite lengths in their shortest form, primitive encodings where the
/// distinguished rules require them, assigned universal types, and the members
/// of a set in ascending order of their encodings (X.690 11.6).
///
/// The reader decides which rules apply to the outermost header, so a caller
/// holding a range to DER inside a BER document reads it again under DER first;
/// [`structured_asn1::Reader::reread`] is what that is for.
///
/// # Errors
///
/// Reports which rule was broken and where.
pub fn conforms<'a>(parent: &Reader<'a>, element: &Element<'a>, field: &'static str) -> Result<()> {
    crate::name::walk_der(parent, element, field, crate::name::Strings::Checked)
}

/// Whether two members of a set are in the order the distinguished rules put
/// them in.
///
/// "The encodings of the component values of a set-of value shall appear in
/// ascending order" (X.690 11.6), comparing octet by octet with the shorter
/// encoding treated as though padded with zeros.
///
/// It is separate from [`conforms`] because a set is not always written under
/// a set's own tag: a signed message writes its attributes under a context tag
/// and signs them under `SET OF`, so the ordering is the schema's to check
/// where the tag no longer says so.
///
/// `parent` supplies the current execution account and original parser-local
/// cumulative ceiling. Before comparison, one work unit per possible octet
/// pair is admitted: the longer length, because X.690 compares the shorter
/// encoding with virtual zero padding. A minimum of one unit covers an empty
/// comparison. This is an upper bound; an unequal pair may stop the walk early.
/// `parent` must belong to the session and source that produced `next`; this
/// is a caller precondition, not a provenance check.
///
/// # Errors
/// Returns a resource refusal at `next`'s original offset before comparing
/// bytes. `Ok(false)` means incorrect order, independently of resource errors.
pub fn set_ordered(
    parent: &Reader<'_>,
    previous: &[u8],
    next: &Element<'_>,
    field: &'static str,
) -> Result<bool> {
    let work = previous.len().max(next.as_bytes().len()).max(1) as u64;
    parent
        .charge(work)
        .map_err(|error| Error::new(ErrorCode::Encoding(error.code()), field, next.span().start))?;
    Ok(crate::name::der_set_ordered(previous, next.as_bytes()))
}
