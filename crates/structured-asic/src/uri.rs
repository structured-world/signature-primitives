//! Package references retain ZIP identity without a filesystem interpretation.

use structured_asn1::memory::{MemoryError, OwnedVec, Work};

/// A query or fragment cannot prove whole-member coverage merely by selecting
/// the same physical ZIP entry. Its original XML location remains the selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// Neither component was written.
    Whole,
    /// A query was written, including an explicitly empty query.
    Query,
    /// A fragment was written, including an explicitly empty fragment.
    Fragment,
    /// Both components were written.
    QueryAndFragment,
}

/// Completed resolution facts, independent of signature mathematics and trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negative {
    /// Scheme, authority or a relative path escaping the package base.
    Outside,
    /// Invalid percent encoding, control character or relative first segment.
    Malformed,
    /// Percent-decoded name is not UTF-8.
    Encoding,
}

/// A lexical reference after package resolution. Exact lookup may still find
/// zero or several original members; this value never chooses a duplicate.
#[derive(Debug)]
pub enum Target<'uri> {
    /// A path-empty reference selects its original containing document.
    SameDocument(Part),
    /// The package root, which is not an empty-name member.
    Root(Part),
    /// A complete exact ZIP filename with independently retained capacity.
    Member {
        /// ZIP bytes after exactly one URI decoding, without case folding.
        name: MemberName<'uri>,
        /// Presence of a query/fragment, not a fabricated whole-object proof.
        part: Part,
    },
    /// A completed negative outcome, never a resource refusal or missing entry.
    Negative(Negative),
}

/// The common root-relative, unescaped form borrows the owner's existing URI
/// view. Joining/decoding alone needs a funded buffer; lookup need not retain it.
#[derive(Debug)]
pub enum MemberName<'uri> {
    /// No allocation, copy or account reference-count increment.
    Borrowed(&'uri [u8]),
    /// Actual retained capacity for a joined or percent-decoded name.
    Owned(OwnedVec<u8>),
}
impl AsRef<[u8]> for MemberName<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }
}

/// Resolves an original schema-normalized URI against its original ZIP name.
/// EN319162-1 V1.1.1 A.6 overrides ODF1.2 part3 §3.7 for META-INF references:
/// their base is the package root. Its explicit `/document.xml` form is allowed.
/// <https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf>
/// <https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html>
pub fn resolve<'uri, W: Work>(
    source_path: &[u8],
    uri: &'uri str,
    work: &W,
) -> Result<Target<'uri>, MemoryError> {
    let cost = source_path
        .len()
        .checked_add(uri.len())
        .and_then(|n| n.checked_mul(16))
        .and_then(|n| n.checked_add(1))
        .ok_or(MemoryError::WorkExceeded)?;
    work.charge_work(u64::try_from(cost).map_err(|_| MemoryError::WorkExceeded)?)?;
    let bytes = uri.as_bytes();
    if !lexical(bytes) {
        return Ok(Target::Negative(Negative::Malformed));
    }
    // RFC3986 §2.4: split components before decoding. An escaped delimiter
    // must not become a query/fragment or initiate a second path resolution.
    let fragment = bytes.iter().position(|byte| *byte == b'#');
    let before_fragment = &bytes[..fragment.unwrap_or(bytes.len())];
    let query = before_fragment.iter().position(|byte| *byte == b'?');
    let path = &before_fragment[..query.unwrap_or(before_fragment.len())];
    let part = match (query.is_some(), fragment.is_some()) {
        (false, false) => Part::Whole,
        (true, false) => Part::Query,
        (false, true) => Part::Fragment,
        (true, true) => Part::QueryAndFragment,
    };
    if path.is_empty() {
        return Ok(Target::SameDocument(part));
    }
    if path.starts_with(b"//") {
        return Ok(Target::Negative(Negative::Outside));
    }
    let first = &path[..match path.iter().position(|byte| *byte == b'/') {
        Some(at) => at,
        None => path.len(),
    }];
    if first.contains(&b':') {
        return Ok(Target::Negative(Negative::Outside));
    }
    let mut base = if source_path.starts_with(b"META-INF/") || path[0] == b'/' {
        &[][..]
    } else {
        match source_path.iter().rposition(|byte| *byte == b'/') {
            Some(at) => &source_path[..=at],
            None => &[],
        }
    };
    let mut path = if path[0] == b'/' { &path[1..] } else { path };
    // ODF §3.7 steps7-12 process these leading lexical components before
    // converting IRI bytes. Existing ZIP base components are never URI-decoded.
    loop {
        if path.starts_with(b"./") {
            path = &path[2..];
            continue;
        }
        if path == b"." {
            path = &[];
            break;
        }
        if path == b".." || path.starts_with(b"../") {
            if base.is_empty() {
                return Ok(Target::Negative(Negative::Outside));
            }
            let without_separator = &base[..base.len() - 1];
            base = match without_separator.iter().rposition(|byte| *byte == b'/') {
                Some(at) => &base[..=at],
                None => &[],
            };
            path = if path.len() == 2 { &[] } else { &path[3..] };
            continue;
        }
        break;
    }
    if base.is_empty() && !path.contains(&b'%') {
        if path.is_empty() {
            return Ok(Target::Root(part));
        }
        return Ok(Target::Member {
            name: MemberName::Borrowed(path),
            part,
        });
    }
    decoded_name(base, path, part, work)
}

/// Resolves an internal OPC relationship whose source is the package root.
pub(crate) fn opc_root<'a, W: Work>(
    reference: &'a str,
    target: bool,
    work: &W,
) -> Result<Option<MemberName<'a>>, MemoryError> {
    // ECMA-376-2 §§6.4.1, 6.5.2 and RFC 3986 §5.2.4: resolve lexical
    // dot segments against the package root before mapping the part name.
    // §§6.2.2.2 and 7.3.4 preserve escapes in the ASCII ZIP item name.
    // https://www.ecma-international.org/publications-and-standards/standards/ecma-376/
    // https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4
    let reference = reference.as_bytes();
    let cost = (reference.len() as u64)
        .checked_mul(12)
        .and_then(|cost| cost.checked_add(1))
        .ok_or(MemoryError::WorkExceeded)?;
    work.charge_work(cost)?;
    let path = if let Some(path) = reference.strip_prefix(b"/") {
        path
    } else if target {
        reference
    } else {
        return Ok(None);
    };
    if path.is_empty()
        || path.starts_with(b"/")
        || !lexical(path)
        || path.iter().any(|byte| matches!(byte, b' ' | b'?' | b'#'))
        || (!reference.starts_with(b"/")
            && path
                .split(|&byte| byte == b'/')
                .next()
                .is_some_and(|first| first.contains(&b':')))
    {
        return Ok(None);
    }
    let has_dots = path
        .split(|&byte| byte == b'/')
        .any(|part| matches!(part, b"." | b".."));
    if !has_dots && path.is_ascii() {
        return Ok(opc_part(path).then_some(MemberName::Borrowed(path)));
    }
    if has_dots && (!target || path.ends_with(b"/.") || path.ends_with(b"/..")) {
        return Ok(None);
    }
    let mut name = work.vector();
    for segment in path.split(|&byte| byte == b'/') {
        match segment {
            b"." => continue,
            b".." => {
                while let Some(byte) = name.pop() {
                    if byte == b'/' {
                        break;
                    }
                }
                continue;
            }
            [] => return Ok(None),
            _ => {}
        }
        if !name.is_empty() {
            name.try_push(b'/')?;
        }
        opc_append(&mut name, segment)?;
    }
    Ok(if opc_part(&name) {
        Some(MemberName::Owned(name.into_owned()))
    } else {
        None
    })
}

fn opc_append<W: Work>(output: &mut OwnedVec<u8, W>, segment: &[u8]) -> Result<(), MemoryError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    if segment.is_ascii() {
        return output.try_extend_from_slice(segment);
    }
    for &byte in segment {
        if byte.is_ascii() {
            output.try_push(byte)?;
        } else {
            output.try_extend_from_slice(&[
                b'%',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 15)],
            ])?;
        }
    }
    Ok(())
}

fn opc_part(path: &[u8]) -> bool {
    path.split(|&byte| byte == b'/').all(|segment| {
        !segment.is_empty()
            && !segment.ends_with(b".")
            && !segment.windows(3).any(|escape| {
                if escape[0] != b'%' {
                    return false;
                }
                match (hex(escape[1]), hex(escape[2])) {
                    (Some(hi), Some(lo)) => {
                        let byte = hi * 16 + lo;
                        byte.is_ascii_alphanumeric()
                            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/' | b'\\')
                    }
                    _ => true,
                }
            })
    })
}

fn decoded_name<'uri, W: Work>(
    base: &[u8],
    path: &'uri [u8],
    part: Part,
    work: &W,
) -> Result<Target<'uri>, MemoryError> {
    let maximum = base
        .len()
        .checked_add(path.len())
        .ok_or(MemoryError::LimitExceeded)?;
    let mut name = work.vector();
    name.try_reserve_exact(maximum)?;
    name.try_extend_from_slice(base)?;
    let mut rest = path;
    while let Some(at) = rest.iter().position(|byte| *byte == b'%') {
        name.try_extend_from_slice(&rest[..at])?;
        if rest.len() - at < 3 {
            return Ok(Target::Negative(Negative::Malformed));
        }
        let (Some(high), Some(low)) = (hex(rest[at + 1]), hex(rest[at + 2])) else {
            return Ok(Target::Negative(Negative::Malformed));
        };
        // '+' is an ordinary URI path octet, never form-encoded whitespace.
        name.try_push(high * 16 + low)?;
        rest = &rest[at + 3..];
    }
    name.try_extend_from_slice(rest)?;
    if core::str::from_utf8(&name).is_err() {
        return Ok(Target::Negative(Negative::Encoding));
    }
    if name.is_empty() {
        return Ok(Target::Root(part));
    }
    Ok(Target::Member {
        name: MemberName::Owned(name.into_owned()),
        part,
    })
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn lexical(bytes: &[u8]) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if byte < 0x20 || byte == 0x7f || byte == b'\\' {
            return false;
        }
        if byte == b'%' {
            if bytes.len() - at < 3 {
                return false;
            }
            if hex(bytes[at + 1]).is_none() || hex(bytes[at + 2]).is_none() {
                return false;
            }
            at += 3;
        } else {
            at += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests;
