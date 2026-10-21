//! Allocation-free MIME media types and original header-field framing.

use structured_asn1::memory::{MemoryError, Work};

mod headers;
pub use headers::media_type_or_headers;

#[derive(Clone, Copy)]
enum Phase {
    TypeStart,
    Type,
    Slash,
    SubtypeStart,
    Subtype,
    Parameters,
    AttributeStart,
    Attribute,
    Equals,
    ValueStart,
    Value,
    AfterValue,
}

#[derive(Clone, Copy)]
enum Context {
    Normal,
    Comment { depth: usize, escaped: bool },
    Quoted { escaped: bool },
}

/// Incremental allocation-free RFC2045 media-type syntax.
///
/// The default consumes original MIME octets and requires CRLF folding.
/// `XML_NORMALIZED = true` additionally accepts XML's already normalized LF.
/// This does not resolve registered media types or compare their semantics.
///
/// ```
/// use std::sync::Arc;
/// use structured_asn1::memory::{Memory, MemoryAccount};
/// use structured_cms::mime::Syntax;
/// let work = Memory::new(Arc::new(MemoryAccount::new(0, 1000)));
/// let mut value = Syntax::<false>::new();
/// assert!(value.feed("text/plain; charset=", &work).unwrap());
/// assert!(!value.complete());
/// assert!(value.feed("utf-8", &work).unwrap());
/// assert!(value.complete());
/// ```
pub struct Syntax<const XML_NORMALIZED: bool = false> {
    valid: bool,
    phase: Phase,
    context: Context,
    folding: u8,
}

impl<const XML_NORMALIZED: bool> Syntax<XML_NORMALIZED> {
    /// Begins a value without allocation or input work.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            valid: true,
            phase: Phase::TypeStart,
            context: Context::Normal,
            folding: 0,
        }
    }

    // RFC2045 §5.1 token/tspecials plus RFC822 §3.3/3.4 comments,
    // quoted-pair and folding. This is MIME syntax, not HTTP's restricted-name
    // grammar, registration lookup or media-type equivalence/normalization.
    // https://www.rfc-editor.org/rfc/rfc2045.html#section-5.1
    // https://www.rfc-editor.org/rfc/rfc822.html#section-3.3
    fn byte(&mut self, byte: u8) -> bool {
        if !byte.is_ascii() || (byte == b'\n' && self.folding != 1 && !XML_NORMALIZED) {
            return false;
        }
        if self.folding != 0 {
            if self.folding == 1 && byte == b'\n' {
                self.folding = 2;
                return true;
            }
            if self.folding == 2 && matches!(byte, b' ' | b'\t') {
                self.folding = 0;
                return true;
            }
            return false;
        }
        match self.context {
            Context::Comment { depth, escaped } => {
                if matches!(byte, b'\r' | b'\n') {
                    self.context = Context::Comment {
                        depth,
                        escaped: false,
                    };
                    self.folding = if byte == b'\r' { 1 } else { 2 };
                } else if escaped {
                    self.context = Context::Comment {
                        depth,
                        escaped: false,
                    };
                } else if byte == b'\\' {
                    self.context = Context::Comment {
                        depth,
                        escaped: true,
                    };
                } else if byte == b'(' {
                    let Some(depth) = depth.checked_add(1) else {
                        return false;
                    };
                    self.context = Context::Comment {
                        depth,
                        escaped: false,
                    };
                } else if byte == b')' {
                    self.context = if depth == 1 {
                        Context::Normal
                    } else {
                        Context::Comment {
                            depth: depth - 1,
                            escaped: false,
                        }
                    };
                }
                true
            }
            Context::Quoted { escaped } => {
                if matches!(byte, b'\r' | b'\n') {
                    self.context = Context::Quoted { escaped: false };
                    self.folding = if byte == b'\r' { 1 } else { 2 };
                } else if escaped {
                    self.context = Context::Quoted { escaped: false };
                } else if byte == b'\\' {
                    self.context = Context::Quoted { escaped: true };
                } else if byte == b'"' {
                    self.context = Context::Normal;
                    self.phase = Phase::AfterValue;
                }
                true
            }
            Context::Normal => self.normal(byte),
        }
    }

    fn normal(&mut self, byte: u8) -> bool {
        match byte {
            b' ' | b'\t' => {
                self.gap();
                true
            }
            b'\r' | b'\n' => {
                self.gap();
                // XML 1.0 §2.11 normalizes physical CRLF to LF before
                // Node::Text; character references can still carry CRLF.
                // https://www.w3.org/TR/REC-xml/#sec-line-ends
                self.folding = if byte == b'\r' { 1 } else { 2 };
                true
            }
            b'(' => {
                self.gap();
                self.context = Context::Comment {
                    depth: 1,
                    escaped: false,
                };
                true
            }
            b'"' if matches!(self.phase, Phase::ValueStart) => {
                self.context = Context::Quoted { escaped: false };
                true
            }
            b'/' if matches!(self.phase, Phase::Type | Phase::Slash) => {
                self.phase = Phase::SubtypeStart;
                true
            }
            b';' if matches!(
                self.phase,
                Phase::Subtype | Phase::Parameters | Phase::Value | Phase::AfterValue
            ) =>
            {
                self.phase = Phase::AttributeStart;
                true
            }
            b'=' if matches!(self.phase, Phase::Attribute | Phase::Equals) => {
                self.phase = Phase::ValueStart;
                true
            }
            _ if token(byte) => {
                self.phase = match self.phase {
                    Phase::TypeStart | Phase::Type => Phase::Type,
                    Phase::SubtypeStart | Phase::Subtype => Phase::Subtype,
                    Phase::AttributeStart | Phase::Attribute => Phase::Attribute,
                    Phase::ValueStart | Phase::Value => Phase::Value,
                    _ => return false,
                };
                true
            }
            _ => false,
        }
    }

    fn gap(&mut self) {
        self.phase = match self.phase {
            Phase::Type => Phase::Slash,
            Phase::Subtype => Phase::Parameters,
            Phase::Attribute => Phase::Equals,
            Phase::Value => Phase::AfterValue,
            other => other,
        };
    }

    /// Admits the whole fragment before changing state, then consumes it.
    /// Syntax failure is sticky across subsequent fragments. Resource failure
    /// leaves the state unchanged. Input may be borrowed str or byte slices.
    pub fn feed<W: Work>(
        &mut self,
        value: impl AsRef<[u8]>,
        execution: &W,
    ) -> Result<bool, MemoryError> {
        let value = value.as_ref();
        // Each byte has bounded scalar dispatch only. Comment nesting is an
        // iterative counter, never stack frames, allocations or recursive calls.
        let cost = u64::try_from(value.len())
            .ok()
            .and_then(|n| n.checked_mul(4))
            .ok_or(MemoryError::WorkExceeded)?;
        execution.charge_work(cost)?;
        if !self.valid {
            return Ok(false);
        }
        for &byte in value {
            if !self.byte(byte) {
                self.valid = false;
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// A complete MIME value, with no open parameter, quote, comment or fold.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.valid
            && self.folding == 0
            && matches!(self.context, Context::Normal)
            && matches!(
                self.phase,
                Phase::Subtype | Phase::Parameters | Phase::Value | Phase::AfterValue
            )
    }
}

fn token(byte: u8) -> bool {
    matches!(byte, 33..=126)
        && !matches!(
            byte,
            b'(' | b')'
                | b'<'
                | b'>'
                | b'@'
                | b','
                | b';'
                | b':'
                | b'\\'
                | b'"'
                | b'/'
                | b'['
                | b']'
                | b'?'
                | b'='
        )
}

impl<const XML_NORMALIZED: bool> Default for Syntax<XML_NORMALIZED> {
    fn default() -> Self {
        Self::new()
    }
}
