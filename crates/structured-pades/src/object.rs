//! Original PDF object views over flat, independently accounted storage.

use crate::Session;
use crate::arena::{Arena, Kind, NodeId};
use crate::bytes::Form;
use crate::error::{Error, ErrorKind, Result, Syntax, Unsupported};
use crate::range::Stamp;
use crate::source::Location;
use structured_asn1::memory::{Execution, Memory, Work};

/// PDF object category, independent of any application/schema interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    /// PDF null object.
    Null,
    /// PDF true/false object.
    Boolean,
    /// An integer spelling, possibly wider than a particular scalar query.
    Integer,
    /// A real spelling; no binary floating-point rounding is implied.
    Real,
    /// A PDF byte-name, with original escape spelling retained separately.
    Name,
    /// A literal or hexadecimal byte string.
    String,
    /// Original ordered array members.
    Array,
    /// Original dictionary key/value members.
    Dictionary,
    /// An indirect object reference, not an automatically resolved value.
    Reference,
}

/// One bounded object reading. Owning buffers have independent actual-capacity
/// charges; source queries continue to require the original session and the
/// current operation. This does not assert a valid PDF file or `PAdES` signature.
pub struct Value<'s, D, G> {
    pub(crate) arena: Arena<Memory>,
    pub(crate) root: NodeId,
    pub(crate) session: &'s Session,
    pub(crate) stamp: Stamp<D, G>,
    pub(crate) end: u64,
}

impl<'s, D: Copy + Eq, G: Copy + Eq> Value<'s, D, G> {
    /// Original source identity and generation used for every node.
    #[must_use]
    pub fn stamp(&self) -> Stamp<D, G> {
        self.stamp
    }

    /// First original byte following the root value, before unrelated input.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Readable format violations preserved during unique-value inspection.
    /// An empty list alone does not establish PDF/PAdES conformance.
    #[must_use]
    pub fn faults(&self) -> &[crate::error::Fault] {
        &self.arena.faults
    }

    /// Root metadata, without traversal, allocation or interpretation.
    #[must_use]
    pub fn root(&self) -> Object<'_, 's, D, G> {
        Object {
            owner: self,
            node: self.root,
        }
    }
}

/// A stable view into its owning reading. Node handles cannot be constructed
/// publicly, moved between owners or used after their owning storage drops.
#[derive(Clone, Copy)]
pub struct Object<'a, 's, D, G> {
    pub(crate) owner: &'a Value<'s, D, G>,
    pub(crate) node: NodeId,
}

impl<'a, 's, D: Copy + Eq, G: Copy + Eq> Object<'a, 's, D, G> {
    /// Original range and coordinate domain; never a re-encoded value.
    #[must_use]
    pub fn location(self) -> Location {
        self.owner.arena.nodes[self.node.0].location
    }

    /// Category already established by the bounded grammar.
    #[must_use]
    pub fn kind(self) -> Type {
        match self.owner.arena.nodes[self.node.0].kind {
            Kind::Null => Type::Null,
            Kind::Boolean(_) => Type::Boolean,
            Kind::Integer(_) => Type::Integer,
            Kind::Real { .. } => Type::Real,
            Kind::Name(_) => Type::Name,
            Kind::String(_) => Type::String,
            Kind::Array(_) => Type::Array,
            Kind::Dictionary(_, _) => Type::Dictionary,
            Kind::Reference { .. } => Type::Reference,
        }
    }

    /// Original boolean scalar. This O(1) metadata getter does not traverse
    /// source data or decide whether the enclosing schema accepts a boolean.
    #[must_use]
    pub fn boolean(self) -> Option<bool> {
        if let Kind::Boolean(value) = self.owner.arena.nodes[self.node.0].kind {
            Some(value)
        } else {
            None
        }
    }

    /// Exact original encoded string body and spelling. Decoding is a separate
    /// paid source query; this getter never materializes a potentially large
    /// value or mistakes literal/hex delimiters for signature content octets.
    #[must_use]
    ///
    /// # Panics
    /// Panics if a parsed string's internally retained delimiters are invalid.
    pub fn string_body(self) -> Option<(Form, Location)> {
        if let Kind::String(form) = self.owner.arena.nodes[self.node.0].kind {
            let original = self.location();
            debug_assert!(original.span().length >= 2);
            Some((
                form,
                Location::new(
                    original.source(),
                    original.span().start + 1,
                    original.span().length - 2,
                )
                .expect("parsed string delimiters"),
            ))
        } else {
            None
        }
    }

    /// Original indirect identity, without resolution, implicit I/O or fallback
    /// to a different generation's object.
    #[must_use]
    pub fn reference(self) -> Option<(u64, u16)> {
        if let Kind::Reference { number, generation } = self.owner.arena.nodes[self.node.0].kind {
            Some((number, generation))
        } else {
            None
        }
    }

    /// Queries an integer as a nonnegative u64 under current/original work.
    /// A wider valid integer is explicitly unsupported for THIS query; it is
    /// not saturated, clamped or relabelled malformed during object reading.
    pub fn unsigned(self, operation: &impl Work) -> Result<u64> {
        let location = self.location();
        let work = self.owner.session.query(operation);
        work.charge_work(1).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
        let Kind::Integer(value) = self.owner.arena.nodes[self.node.0].kind else {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Number),
                location,
            });
        };
        let Some(magnitude) = value.magnitude else {
            return Err(Error {
                kind: ErrorKind::Unsupported(Unsupported::NumericRange),
                location,
            });
        };
        if value.negative && magnitude != 0 {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Number),
                location,
            });
        }
        Ok(magnitude)
    }

    /// Compares a decoded PDF name with caller bytes, paying before traversal.
    /// PDF names have byte identity, without case/Unicode normalization.
    pub fn name_equals(self, expected: &[u8], operation: &impl Work) -> Result<bool> {
        let location = self.location();
        let work = self.owner.session.query(operation);
        work.charge_work(1).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location,
        })?;
        let Kind::Name(name) = self.owner.arena.nodes[self.node.0].kind else {
            return Ok(false);
        };
        if name.length != expected.len() {
            return Ok(false);
        }
        work.charge_work(name.length as u64)
            .map_err(|cause| Error {
                kind: ErrorKind::Resource(cause),
                location,
            })?;
        Ok(&self.owner.arena.names[name.start..name.start + name.length] == expected)
    }

    /// Queries a dictionary by its decoded byte-name through the paid index.
    /// Null entries are absent; an equal repeated value retains its FIRST
    /// original encoding and a separate format fault. Conflicts never reach
    /// this getter. This lookup does not resolve indirect references.
    pub fn get(self, key: &[u8], operation: &impl Work) -> Result<Option<Self>> {
        let Kind::Dictionary(_, fields) = self.owner.arena.nodes[self.node.0].kind else {
            return Err(Error {
                kind: ErrorKind::Syntax(Syntax::Dictionary),
                location: self.location(),
            });
        };
        let work = self.owner.session.query(operation);
        work.charge_work(1).map_err(|cause| Error {
            kind: ErrorKind::Resource(cause),
            location: self.location(),
        })?;
        Ok(
            crate::dictionary::lookup(&self.owner.arena, fields, key, &work, self.location())?.map(
                |node| Self {
                    owner: self.owner,
                    node,
                },
            ),
        )
    }

    /// Original direct member traversal. Dictionaries expose alternating key
    /// and value nodes in wire order, arrays expose their ordered elements.
    /// Constructor is allocation-free; each step pays before accessing a link.
    /// After its first resource error the iterator is fused.
    pub fn members<'q>(self, operation: &'q impl Work) -> Option<Members<'a, 's, 'q, D, G>>
    where
        's: 'q,
    {
        let (Kind::Array(children) | Kind::Dictionary(children, _)) =
            self.owner.arena.nodes[self.node.0].kind
        else {
            return None;
        };
        Some(Members {
            object: self,
            next: children.first,
            work: self.owner.session.query(operation),
        })
    }
}

/// A fallible original-member iterator with no independently retained clone.
pub struct Members<'a, 's, 'q, D, G> {
    object: Object<'a, 's, D, G>,
    next: Option<usize>,
    work: Execution<'q>,
}

impl<'a, 's, D: Copy + Eq, G: Copy + Eq> Iterator for Members<'a, 's, '_, D, G> {
    type Item = Result<Object<'a, 's, D, G>>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next?;
        if let Err(cause) = self.work.charge_work(1) {
            self.next = None;
            return Some(Err(Error {
                kind: ErrorKind::Resource(cause),
                location: self.object.location(),
            }));
        }
        let link = self.object.owner.arena.links[next];
        self.next = link.next;
        Some(Ok(Object {
            owner: self.object.owner,
            node: link.value,
        }))
    }
}

impl<D: Copy + Eq, G: Copy + Eq> core::iter::FusedIterator for Members<'_, '_, '_, D, G> {}
