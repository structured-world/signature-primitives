//! RFC 5280 §7.4 URI identity, with iterative linear path normalization.

use crate::error::{Error, ErrorCode, Result};
use structured_asn1::memory::{Memory, MemoryError, OwnedVec};

const FIELD: &str = "certificateList.scope.uri";

fn default_port(scheme: &[u8]) -> Option<&'static [u8]> {
    // RFC9110 §4.2.3, RFC4516 §3, RFC1738 §3.2.1.
    match scheme {
        b"http" => Some(b"80"),
        b"https" => Some(b"443"),
        b"ldap" => Some(b"389"),
        b"ftp" => Some(b"21"),
        _ => None,
    }
}

fn percent_octets(raw: &[u8], execution: &Memory, at: u64) -> Result<OwnedVec<u8>> {
    let fail = |reason| Error::resource(reason, FIELD, at);
    let mut bytes = execution.vector();
    bytes.try_reserve_exact(raw.len()).map_err(fail)?;
    let mut input = raw;
    while let Some((&byte, rest)) = input.split_first() {
        if byte == b'%' {
            let decoded = hex(rest[0]) * 16 + hex(rest[1]);
            if unreserved(decoded) {
                bytes.try_push(decoded).map_err(fail)?;
            } else {
                bytes
                    .try_extend_from_slice(&[
                        b'%',
                        rest[0].to_ascii_uppercase(),
                        rest[1].to_ascii_uppercase(),
                    ])
                    .map_err(fail)?;
            }
            input = &rest[2..];
        } else {
            bytes.try_push(byte).map_err(fail)?;
            input = rest;
        }
    }
    Ok(bytes)
}

pub(super) fn matches(left: &str, right: &str, execution: &Memory, at: u64) -> Result<bool> {
    let left = normalize(left, execution, at)?;
    let right = normalize(right, execution, at)?;
    execution
        .charge_work(left.len().max(right.len()) as u64)
        .map_err(|reason| Error::resource(reason, FIELD, at))?;
    Ok(left == right)
}

fn normalize(raw: &str, execution: &Memory, at: u64) -> Result<OwnedVec<u8>> {
    let fail = |reason| Error::resource(reason, FIELD, at);
    // Constant-many component/grammar scans plus one push/pop per path byte.
    // Admission precedes validation, percent decoding and component discovery;
    // collection methods separately admit storage and each output copy.
    let work = u64::try_from(raw.len())
        .ok()
        .and_then(|n| n.checked_mul(32))
        .and_then(|n| n.checked_add(256))
        .ok_or_else(|| fail(MemoryError::WorkExceeded))?;
    execution.charge_work(work).map_err(fail)?;
    if !crate::general_name::is_cps_uri(raw) {
        return Err(Error::new(ErrorCode::MalformedValue, FIELD, at));
    }
    // Component delimiters are reserved and never decoded by generic percent
    // normalization. Unreserved octets decode; remaining escape hex is upper.
    // RFC3987 §§5.3.2.1/5.3.2.3; RFC3986 §§2.1–2.3.
    // https://www.rfc-editor.org/rfc/rfc3987#section-5.3.2
    let mut bytes = percent_octets(raw.as_bytes(), execution, at)?;
    let colon = bytes
        .iter()
        .position(|byte| *byte == b':')
        .expect("validated scheme");
    bytes[..colon].make_ascii_lowercase();
    let scheme = &bytes[..colon];
    let default_port = default_port(scheme);
    let mut output = execution.vector();
    output
        .try_reserve_exact(
            raw.len()
                .checked_add(1)
                .ok_or_else(|| fail(MemoryError::CapacityOverflow))?,
        )
        .map_err(fail)?;
    output
        .try_extend_from_slice(&bytes[..=colon])
        .map_err(fail)?;
    let mut tail = &bytes[colon + 1..];
    let authority = tail.starts_with(b"//");
    if authority {
        let rest = &tail[2..];
        let end = rest
            .iter()
            .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
            .unwrap_or(rest.len());
        let mut host = &rest[..end];
        tail = &rest[end..];
        output.try_extend_from_slice(b"//").map_err(fail)?;
        if let Some(end) = host.iter().position(|byte| *byte == b'@') {
            output.try_extend_from_slice(&host[..=end]).map_err(fail)?;
            host = &host[end + 1..];
        }
        let port_at = if host.starts_with(b"[") {
            let close = host
                .iter()
                .position(|byte| *byte == b']')
                .expect("validated literal");
            (close + 1 < host.len()).then_some(close + 1)
        } else {
            host.iter().position(|byte| *byte == b':')
        };
        let hostname = &host[..port_at.unwrap_or(host.len())];
        let mut escape = 0;
        for &byte in hostname {
            // Keep normalized escape hex upper even inside a lowercase host.
            let byte = if escape > 0 {
                escape -= 1;
                byte
            } else if byte == b'%' {
                escape = 2;
                byte
            } else {
                byte.to_ascii_lowercase()
            };
            output.try_push(byte).map_err(fail)?;
        }
        if let Some(index) = port_at {
            let port = &host[index + 1..];
            let first = port
                .iter()
                .position(|byte| *byte != b'0')
                .unwrap_or(port.len());
            let omitted =
                default_port.is_some_and(|default| port.is_empty() || &port[first..] == default);
            if !omitted {
                output.try_extend_from_slice(&host[index..]).map_err(fail)?;
            }
        }
    }
    let path_end = tail
        .iter()
        .position(|byte| matches!(byte, b'?' | b'#'))
        .unwrap_or(tail.len());
    let path = &tail[..path_end];
    if authority && default_port.is_some() && path.is_empty() {
        output.try_push(b'/').map_err(fail)?;
    } else {
        path_segments(path, &mut output, at)?;
    }
    let suffix = &tail[path_end..];
    if scheme == b"ldap" && suffix.starts_with(b"?") {
        ldap_query(&suffix[1..], &mut output, at)?;
    } else {
        output.try_extend_from_slice(suffix).map_err(fail)?;
    }
    Ok(output)
}

fn path_segments(mut input: &[u8], output: &mut OwnedVec<u8>, at: u64) -> Result<()> {
    let fail = |reason| Error::resource(reason, FIELD, at);
    let begin = output.len();
    // RFC3986 §5.2.4: every octet is pushed at most once and popped at most
    // once. No prefix/suffix rescanning or recursive segment processing.
    // https://www.rfc-editor.org/rfc/rfc3986#section-5.2.4
    while !input.is_empty() {
        if input.starts_with(b"../") {
            input = &input[3..];
        } else if input.starts_with(b"./") || input.starts_with(b"/./") {
            input = &input[2..];
        } else if input == b"/." {
            output.try_push(b'/').map_err(fail)?;
            break;
        } else if input.starts_with(b"/../") || input == b"/.." {
            while output.len() > begin {
                if output.pop() == Some(b'/') {
                    break;
                }
            }
            if input == b"/.." {
                output.try_push(b'/').map_err(fail)?;
                break;
            }
            input = &input[3..];
        } else if matches!(input, b"." | b"..") {
            break;
        } else {
            let skip = usize::from(input[0] == b'/');
            let end = input[skip..]
                .iter()
                .position(|byte| *byte == b'/')
                .map_or(input.len(), |index| index + skip);
            output.try_extend_from_slice(&input[..end]).map_err(fail)?;
            input = &input[end..];
        }
    }
    Ok(())
}

fn ldap_query(input: &[u8], output: &mut OwnedVec<u8>, at: u64) -> Result<()> {
    let fail = |reason| Error::resource(reason, FIELD, at);
    let fragment = input
        .iter()
        .position(|byte| *byte == b'#')
        .unwrap_or(input.len());
    let mut fields = [&[][..]; 4];
    for (index, value) in input[..fragment].split(|byte| *byte == b'?').enumerate() {
        if index == fields.len() {
            return Err(Error::new(ErrorCode::MalformedValue, FIELD, at));
        }
        fields[index] = value;
    }
    // Generic PKIX DP comparison uses RFC4516 §3's general defaults, not
    // referral-specific DN/server substitution. No host is invented.
    // https://www.rfc-editor.org/rfc/rfc4516#section-3
    if decoded_equal(fields[0], b"*") {
        fields[0] = b"";
    }
    if decoded_equal(fields[1], b"base") {
        fields[1] = b"";
    }
    if decoded_equal(fields[2], b"(objectClass=*)") {
        fields[2] = b"";
    }
    if let Some(last) = fields.iter().rposition(|value| !value.is_empty()) {
        for (index, value) in fields[..=last].iter().enumerate() {
            output.try_push(b'?').map_err(fail)?;
            if index == 1 {
                for &byte in *value {
                    output.try_push(byte.to_ascii_lowercase()).map_err(fail)?;
                }
            } else {
                output.try_extend_from_slice(value).map_err(fail)?;
            }
        }
    }
    output
        .try_extend_from_slice(&input[fragment..])
        .map_err(fail)?;
    Ok(())
}

fn decoded_equal(mut input: &[u8], expected: &[u8]) -> bool {
    for &expected in expected {
        let Some((&byte, rest)) = input.split_first() else {
            return false;
        };
        let byte = if byte == b'%' {
            let byte = hex(rest[0]) * 16 + hex(rest[1]);
            input = &rest[2..];
            byte
        } else {
            input = rest;
            byte
        };
        if !byte.eq_ignore_ascii_case(&expected) {
            return false;
        }
    }
    input.is_empty()
}
fn hex(byte: u8) -> u8 {
    if byte.is_ascii_digit() {
        byte - b'0'
    } else {
        byte.to_ascii_lowercase() - b'a' + 10
    }
}
fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    #[test]
    fn many_segments_and_wide_ports_remain_linear_and_do_not_narrow_to_integers() {
        // A normalizer must not repeatedly rescan a growing suffix, and a
        // default port with arbitrary leading zeroes needs no integer cast.
        let port = alloc::string::String::from("0").repeat(1000) + "80";
        let path = alloc::string::String::from("/a").repeat(1000) + "/.";
        let left = alloc::format!("http://EXAMPLE.com:{port}{path}");
        let right = alloc::format!("http://example.com{}/", &path[..path.len() - 2]);
        let execution = crate::fixtures::memory();
        assert!(super::matches(&left, &right, &execution, 900).unwrap());
        assert!(execution.work_used() <= 128 * (left.len() + right.len()) + 1024);
        assert_eq!(execution.used(), 0);
    }

    #[test]
    fn iterative_paths_preserve_rfc_segment_and_component_boundaries() {
        // RFC3986 §5.2.4 examples and reserved escapes prevent both false
        // equality and quadratic rescanning for long parent-segment tails.
        let execution = crate::fixtures::memory();
        for (raw, expected) in [
            (
                "http://example.com/a/b/c/./../../g",
                "http://example.com/a/g",
            ),
            ("http://example.com/a/%2e%2e/b", "http://example.com/b"),
            ("http://example.com/a//b/..", "http://example.com/a//"),
            ("ldap:///??one", "ldap:///??one"),
            ("custom://EXAMPLE.com:080/a", "custom://example.com:080/a"),
            (
                "http://user:@EXAMPLE.com/a?q=%2f#",
                "http://user:@example.com/a?q=%2F#",
            ),
        ] {
            let result = super::normalize(raw, &execution, 900).unwrap();
            assert_eq!(&*result, expected.as_bytes());
        }
    }

    #[test]
    fn uri_resource_refusal_is_not_mismatch_and_releases_partial_storage() {
        // Zero work refuses before scans; insufficient temporary storage
        // refuses before allocation. Success drops every scratch allocation.
        use structured_asn1::memory::{Memory, MemoryAccount};
        for (storage, work) in [(0, 1_000_000), (1_000_000, 0), (20, 1_000_000)] {
            let execution = Memory::new(alloc::sync::Arc::new(MemoryAccount::new(storage, work)));
            let error = super::matches(
                "http://EXAMPLE.com/a",
                "http://example.com/a",
                &execution,
                900,
            )
            .unwrap_err();
            assert!(error.is_resource());
            assert_eq!(error.offset(), 900);
            assert_eq!(execution.used(), 0);
        }
        let execution = crate::fixtures::memory();
        assert!(
            super::matches(
                "http://EXAMPLE.com/a",
                "http://example.com/a",
                &execution,
                900
            )
            .unwrap()
        );
        assert_eq!(execution.used(), 0);
    }

    #[test]
    fn percent_component_preserves_reserved_delimiters() {
        // The generic pass cannot convert percent-encoded reserved delimiters
        // into structural components before URI identity comparison.
        let execution = crate::fixtures::memory();
        let actual = super::percent_octets(b"%7e/%2f/%2e%2e?q=%3f", &execution, 0).unwrap();
        assert_eq!(&*actual, b"~/%2F/..?q=%3F");
    }
}
