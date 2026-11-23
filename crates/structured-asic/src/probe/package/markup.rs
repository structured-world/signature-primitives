//! Restricted, bounded package metadata over the same lexical XML reader.

use super::super::{Error, Finding, charge, xml};
use core::ops::Range;
use structured_asn1::{
    Span,
    memory::{Execution, MemoryError, OwnedVec, Work},
};
use xmlparser::{ElementEnd, StrSpan, Token, Tokenizer};

#[derive(Clone, Copy, PartialEq, Eq)]
struct TextSpan {
    start: usize,
    end: usize,
}

impl TextSpan {
    fn of(span: StrSpan<'_>) -> Self {
        Self {
            start: span.start(),
            end: span.end(),
        }
    }
    fn get(self, text: &str) -> &str {
        &text[self.start..self.end]
    }
}

struct Attribute {
    name: Name,
    value: TextSpan,
    namespace: Option<TextSpan>,
}

#[derive(Clone, Copy)]
struct Name {
    prefix: TextSpan,
    local: TextSpan,
}

impl Name {
    fn new(prefix: StrSpan<'_>, local: StrSpan<'_>) -> Self {
        Self {
            prefix: TextSpan::of(prefix),
            local: TextSpan::of(local),
        }
    }

    fn matches(self, other: Self, text: &str, work: &Execution<'_>) -> Result<bool, MemoryError> {
        let left = (self.prefix.get(text), self.local.get(text));
        let right = (other.prefix.get(text), other.local.get(text));
        work.charge_work(
            (left.0.len().min(right.0.len()) + left.1.len().min(right.1.len())) as u64 + 1,
        )?;
        Ok(left == right)
    }
}

pub(super) struct Node {
    name: Name,
    namespace: Option<TextSpan>,
    attrs: Range<usize>,
    parent: Option<usize>,
}

pub(super) struct Document<'s, 'q> {
    input: xml::Input<'s, 'q>,
    nodes: OwnedVec<Node, Execution<'q>>,
    attrs: OwnedVec<Attribute, Execution<'q>>,
}

impl Document<'_, '_> {
    pub(super) fn root(&self, local: &str, namespace: &str) -> bool {
        self.nodes
            .first()
            .is_some_and(|node| self.is(node, local, namespace))
    }

    pub(super) fn entries<'d>(
        &'d self,
        local: &'d str,
        namespace: &'d str,
    ) -> impl Iterator<Item = &'d Node> {
        self.nodes
            .iter()
            .filter(move |node| node.parent == Some(0) && self.is(node, local, namespace))
    }

    pub(super) fn has_element(&self, local: &str, namespace: &str) -> bool {
        self.nodes
            .iter()
            .any(|node| self.is(node, local, namespace))
    }

    pub(super) fn attribute(
        &self,
        node: &Node,
        local: &str,
        namespace: Option<&str>,
    ) -> Option<&str> {
        let text = self.input.text.as_str();
        let mut found = self.attrs[node.attrs.clone()].iter().filter(|attribute| {
            attribute.name.local.get(text) == local
                && (attribute.name.prefix.get(text).is_empty() == namespace.is_none())
                && attribute.namespace.map(|span| span.get(text)) == namespace
        });
        let first = found.next()?;
        found.next().is_none().then(|| first.value.get(text))
    }

    fn is(&self, node: &Node, local: &str, namespace: &str) -> bool {
        let text = self.input.text.as_str();
        node.name.local.get(text) == local
            && node.namespace.map(|span| span.get(text)) == Some(namespace)
    }
}

pub(super) fn read<'s, 'q, E>(
    bytes: &'s [u8],
    range: Span,
    work: &Execution<'q>,
) -> Result<Option<Document<'s, 'q>>, Error<E>> {
    charge(
        work,
        Span {
            start: range.start,
            length: bytes.len() as u64,
        },
        24,
    )?;
    let failed = |cause| Error::Resource { range, cause };
    let input = match xml::input(bytes, work).map_err(failed)? {
        Ok(input) if input.complete() => input,
        _ => return Ok(None),
    };
    let text = input.text.as_str();
    let mut markup = Markup {
        nodes: work.vector(),
        attrs: work.vector(),
        stack: work.vector(),
        pending: None,
    };
    if !markup.read(text, &input, work).map_err(failed)? {
        return Ok(None);
    }
    Ok(Some(Document {
        input,
        nodes: markup.nodes,
        attrs: markup.attrs,
    }))
}

struct Markup<'q> {
    nodes: OwnedVec<Node, Execution<'q>>,
    attrs: OwnedVec<Attribute, Execution<'q>>,
    stack: OwnedVec<usize, Execution<'q>>,
    pending: Option<Node>,
}

impl Markup<'_> {
    fn read(
        &mut self,
        text: &str,
        input: &xml::Input<'_, '_>,
        work: &Execution<'_>,
    ) -> Result<bool, MemoryError> {
        for token in Tokenizer::from(text) {
            match token {
                Ok(Token::Declaration {
                    encoding, version, ..
                }) if input.declaration(encoding.map(|value| value.as_str()), version.as_str())
                    == Finding::Framing => {}
                Ok(Token::ElementStart { prefix, local, .. }) => {
                    let start = self.attrs.len();
                    if self.stack.is_empty() && !self.nodes.is_empty() {
                        return Ok(false);
                    }
                    self.pending = Some(Node {
                        name: Name::new(prefix, local),
                        namespace: None,
                        attrs: start..start,
                        parent: self.stack.last().copied(),
                    });
                }
                Ok(Token::Attribute {
                    prefix,
                    local,
                    value,
                    ..
                }) => {
                    if !self.attribute(Name::new(prefix, local), TextSpan::of(value), text, work)? {
                        return Ok(false);
                    }
                }
                Ok(Token::ElementEnd {
                    end: ElementEnd::Open | ElementEnd::Empty,
                    ..
                }) => {
                    let open = matches!(
                        token,
                        Ok(Token::ElementEnd {
                            end: ElementEnd::Open,
                            ..
                        })
                    );
                    if !self.open(text, work, open)? {
                        return Ok(false);
                    }
                }
                Ok(Token::ElementEnd {
                    end: ElementEnd::Close(prefix, local),
                    ..
                }) => {
                    let Some(index) = self.stack.pop() else {
                        return Ok(false);
                    };
                    if !self.nodes[index]
                        .name
                        .matches(Name::new(prefix, local), text, work)?
                    {
                        return Ok(false);
                    }
                }
                Ok(Token::Comment { .. } | Token::ProcessingInstruction { .. }) => {}
                Ok(Token::Text { text, .. }) if text.as_str().trim_ascii().is_empty() => {}
                _ => return Ok(false),
            }
        }
        Ok(self.pending.is_none() && self.stack.is_empty() && !self.nodes.is_empty())
    }

    fn attribute(
        &mut self,
        name: Name,
        value: TextSpan,
        text: &str,
        work: &Execution<'_>,
    ) -> Result<bool, MemoryError> {
        let Some(node) = &mut self.pending else {
            return Ok(false);
        };
        // This bounded probe only asserts metadata independent of replacement
        // text and attribute-value coercion. The owner can inspect the full XML.
        if value.get(text).contains(['&', '\t', '\r', '\n']) {
            return Ok(false);
        }
        for earlier in &self.attrs[node.attrs.clone()] {
            if earlier.name.matches(name, text, work)? {
                return Ok(false);
            }
        }
        self.attrs.try_push(Attribute {
            name,
            value,
            namespace: None,
        })?;
        node.attrs.end += 1;
        Ok(true)
    }

    fn open(&mut self, text: &str, work: &Execution<'_>, open: bool) -> Result<bool, MemoryError> {
        let Some(mut node) = self.pending.take() else {
            return Ok(false);
        };
        node.namespace = self.binding(&node, node.name.prefix.get(text), text, work)?;
        if !node.name.prefix.get(text).is_empty() && node.namespace.is_none() {
            return Ok(false);
        }
        for index in node.attrs.clone() {
            let attr = &self.attrs[index];
            let prefix = attr.name.prefix.get(text);
            if !prefix.is_empty() && !matches!(prefix, "xmlns" | "xml") {
                let Some(namespace) = self.binding(&node, prefix, text, work)? else {
                    return Ok(false);
                };
                self.attrs[index].namespace = Some(namespace);
            }
        }
        let index = self.nodes.len();
        self.nodes.try_push(node)?;
        if open {
            self.stack.try_push(index)?;
        }
        Ok(true)
    }

    fn binding<'a>(
        &'a self,
        mut node: &'a Node,
        prefix: &str,
        text: &str,
        work: &Execution<'_>,
    ) -> Result<Option<TextSpan>, MemoryError> {
        loop {
            work.charge_work(1)?;
            for attribute in &self.attrs[node.attrs.clone()] {
                let local = attribute.name.local.get(text);
                work.charge_work((prefix.len().min(local.len()) + 6) as u64)?;
                if xml::is_binding(prefix, attribute.name.prefix.get(text), local) {
                    return Ok(Some(attribute.value));
                }
            }
            let Some(parent) = node.parent else {
                return Ok(None);
            };
            node = &self.nodes[parent];
        }
    }
}
