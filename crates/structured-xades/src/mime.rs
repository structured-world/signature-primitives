//! Allocation-free RFC 2045 value syntax across original XML text fragments.

use crate::properties::{Error, PropertyResult};
use crate::xml::{Access, Node, Xml};
use structured_asn1::memory::{MemoryError, Work};

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

struct Parser {
    phase: Phase,
    context: Context,
    folding: u8,
}

impl Parser {
    fn new() -> Self {
        Self {
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
        if !byte.is_ascii() {
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
                if byte == b'\r' {
                    self.context = Context::Comment {
                        depth,
                        escaped: false,
                    };
                    self.folding = 1;
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
                if byte == b'\r' {
                    self.context = Context::Quoted { escaped: false };
                    self.folding = 1;
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
            b'\r' => {
                self.gap();
                self.folding = 1;
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

    fn feed<W: Work>(&mut self, value: &str, execution: &W) -> Result<bool, MemoryError> {
        // Each byte has bounded scalar dispatch only. Comment nesting is an
        // iterative counter, never stack frames, allocations or recursive calls.
        let cost = u64::try_from(value.len())
            .ok()
            .and_then(|n| n.checked_mul(4))
            .ok_or(MemoryError::WorkExceeded)?;
        execution.charge_work(cost)?;
        for byte in value.bytes() {
            if !self.byte(byte) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn complete(&self) -> bool {
        self.folding == 0
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

pub(crate) fn check<X: Xml, W: Work>(
    access: &Access<'_, X, W>,
    parent: X::Id,
) -> PropertyResult<(), X> {
    let malformed = || Error::Lexical {
        node: parent,
        local: "MimeType",
    };
    let mut parser = Parser::new();
    let mut child = access.first_child(parent).map_err(Error::Access)?;
    while let Some(node) = child {
        let read = access
            .inspect(node, |value| match value {
                Node::Element(_) => Err(Error::Unexpected { node }),
                Node::Other => Ok(()),
                Node::Text(text) => {
                    let accepted = access
                        .query(node, |_, _, work| Ok(parser.feed(text, work)))
                        .map_err(Error::Access)?
                        .map_err(|cause| Error::Resource { node, cause })?;
                    if accepted { Ok(()) } else { Err(malformed()) }
                }
            })
            .map_err(Error::Access)?;
        read?;
        child = access.next_sibling(parent, node).map_err(Error::Access)?;
    }
    if !parser.complete() {
        return Err(malformed());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use structured_asn1::memory::{Memory, MemoryAccount};

    #[test]
    fn complete_mime_values_keep_rfc2045_tokens_comments_and_quotes() {
        // HTTP restricted-name parsers are not oracles for this older grammar.
        let work = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
        for input in [
            "text/plain",
            " (outer(inner)) text / plain ; charset = \"utf-8\" (end)",
            "x.foo/bar`~|{}; name=\"a;\\\"b\"",
            "text/plain; x=\"\"",
            "text/plain; x=one\r\n \t; y=two",
        ] {
            let mut parser = Parser::new();
            assert!(parser.feed(input, &work).unwrap(), "{input:?}");
            assert!(parser.complete(), "{input:?}");
        }
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn truncated_and_malformed_values_are_not_default_text_plain() {
        // Mandatory subtype/parameter components and delimiters never default.
        let work = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
        for input in [
            "",
            "text",
            "text/",
            "text//plain",
            "text/plain;",
            "text/plain;x",
            "text/plain;x=",
            "text/plain;x=\"open",
            "text/plain (open",
            "te(comment)xt/plain",
            "text/pläin",
            "text/plain\r\nX",
            "text/plain; x=one two",
        ] {
            let mut parser = Parser::new();
            assert!(
                !parser.feed(input, &work).unwrap() || !parser.complete(),
                "{input:?}"
            );
        }
    }

    #[test]
    fn fragments_share_state_and_work_refuses_before_state_mutation() {
        // Fragment boundaries, including a quoted-pair and folding, add no
        // lexical boundary. Current work refusal must precede every byte scan.
        let work = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
        let mut parser = Parser::new();
        for fragment in [
            "text/",
            "plain (a(",
            "b)) ;x=\"a\\",
            "\"b\"",
            "\r",
            "\n",
            " ",
        ] {
            assert!(parser.feed(fragment, &work).unwrap());
        }
        assert!(parser.complete());
        let empty = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        let mut parser = Parser::new();
        assert_eq!(
            parser.feed("text/plain", &empty),
            Err(MemoryError::WorkExceeded)
        );
        assert!(parser.feed("image/png", &work).unwrap());
        assert!(parser.complete());
    }

    #[test]
    fn deeply_nested_comments_use_no_recursive_stack_or_storage() {
        // Attacker-controlled comment depth is only an iterative scalar counter;
        // every opening/closing byte is funded before traversal.
        let input = alloc::format!("{}{}text/plain", "(".repeat(30_000), ")".repeat(30_000));
        let work = Memory::new(Arc::new(MemoryAccount::new(0, input.len() * 4)));
        let mut parser = Parser::new();
        assert!(parser.feed(&input, &work).unwrap());
        assert!(parser.complete());
        assert_eq!(work.used(), 0);
        assert_eq!(work.charge_work(1), Err(MemoryError::WorkExceeded));
    }
}
