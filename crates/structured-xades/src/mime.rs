//! Allocation-free RFC 2045 value syntax across original XML text fragments.

use crate::properties::{Error, PropertyResult};
use crate::xml::{Access, Node, Xml};
use structured_asn1::memory::Work;
type Parser = structured_cms::mime::Syntax<true>;

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
    use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

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
    fn xml_normalized_folds_survive_fragment_boundaries() {
        // XML 1.0 §2.11 replaces CRLF with LF before Node::Text. Folding
        // still requires following whitespace, including inside MIME strings.
        let work = Memory::new(Arc::new(MemoryAccount::new(0, 100_000)));
        for fragments in [
            ["text/plain;", "\n", " x=one"],
            ["text/plain; x=\"one", "\n", " two\""],
            ["text/plain (one", "\n", " two)"],
        ] {
            let mut parser = Parser::new();
            for fragment in fragments {
                assert!(parser.feed(fragment, &work).unwrap());
            }
            assert!(parser.complete());
        }
        for input in ["text/plain\n", "text/plain\nX", "text/plain\n\n x=one"] {
            let mut parser = Parser::new();
            assert!(!parser.feed(input, &work).unwrap() || !parser.complete());
        }
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
