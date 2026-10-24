use super::super::support::{File, Input, finish, memory, zip};
use super::*;
use std::future::{Future, poll_fn};
use std::{
    pin::pin,
    task::{Context, Poll, Waker},
};
use structured_asic::{
    Limits, Session,
    xml::producer::{self, Factory, Parsed, Source, Types, Visitor},
    zip::Archive,
};
use structured_asn1::memory::OwnedVec;
use structured_asn1::range::RangeSource;
use structured_xades::{
    binary::{BinaryXml, Decoded, OwnedBinaryXml, OwnedDecoded},
    scalar::{Datatype, Fact, ScalarXml, UriValue, UriXml},
};

const XML:&[u8]=br#"<ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SigReference URI="META-INF/evidence.ers"/><DataObjectReference URI="document.bin"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference></ASiCManifest>"#;

// A one-literal independent fixture owner. It rejects every other complete
// input and projects exactly this XML, not arbitrary separately supplied nodes.
// This exercises the producer contract, not a production XML/DSig engine.
struct Fixture {
    calls: Cell<usize>,
    pointer: Cell<usize>,
}
struct Document<'a, W: Work> {
    input: OwnedVec<u8>,
    arena: OwnedVec<u8, W>,
    tree: Tree,
    work: &'a W,
}
impl Types for Fixture {
    type Id = usize;
    type Document = usize;
    type Generation = u64;
    type Error = Failure;
}
impl<W: Work> Types for Document<'_, W> {
    type Id = usize;
    type Document = usize;
    type Generation = u64;
    type Error = Failure;
}
impl Factory for Fixture {
    type Parsed<'a, W: Work + 'a> = Document<'a, W>;
    fn parse<'a, W: Work + 'a>(
        &'a self,
        input: OwnedVec<u8>,
        work: &'a W,
    ) -> impl core::future::Future<Output = Result<Document<'a, W>, Failure>> + 'a {
        core::future::ready((|| {
            work.charge_work(input.len() as u64)
                .map_err(Failure::Resource)?;
            self.calls.set(self.calls.get() + 1);
            self.pointer.set(input.as_ptr() as usize);
            if input.as_ref() != XML {
                return Err(Failure::Unsupported);
            }
            let mut arena = work.vector();
            arena.try_reserve_exact(64).map_err(Failure::Resource)?;
            for _ in 0..64 {
                arena.try_push(0).map_err(Failure::Resource)?;
            }
            let tree =
                super::native::manifest_tree(&[0; 32], "META-INF/evidence.ers", "document.bin");
            Ok(Document {
                input,
                arena,
                tree,
                work,
            })
        })())
    }
}
impl<W: Work> Parsed for Document<'_, W> {
    type View<'a>
        = &'a Tree
    where
        Self: 'a;
    fn view(&self) -> &Tree {
        assert_eq!(self.input.as_ref(), XML);
        assert_eq!(self.arena.len(), 64);
        assert!(self.work.memory().used() >= self.input.capacity() + self.arena.capacity());
        &self.tree
    }
    fn root(&self) -> usize {
        0
    }
}
impl Xml for &Tree {
    type Id = usize;
    type Document = usize;
    type Generation = u64;
    type Error = Failure;
    fn snapshot(&self) -> Snapshot<usize, u64> {
        Tree::snapshot(self)
    }
    fn inspect<R, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
        v: impl for<'a> FnOnce(Node<'a>) -> R,
    ) -> Result<R, Failure> {
        Tree::inspect(self, s, n, w, v)
    }
    fn attribute<R, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        name: Name<'_>,
        w: &W,
        v: impl for<'a> FnOnce(Option<&'a str>) -> R,
    ) -> Result<R, Failure> {
        Tree::attribute(self, s, n, name, w, v)
    }
    fn first_child<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
    ) -> Result<Option<usize>, Failure> {
        Tree::first_child(self, s, n, w)
    }
    fn next_sibling<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        p: usize,
        n: usize,
        w: &W,
    ) -> Result<Option<usize>, Failure> {
        Tree::next_sibling(self, s, p, n, w)
    }
}
impl ScalarXml for &Tree {
    fn scalar<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        source: LexicalSource<'_>,
        d: Datatype,
        w: &W,
    ) -> Result<Fact, Failure> {
        Tree::scalar(self, s, n, source, d, w)
    }
}
impl QNameXml for &Tree {
    fn with_qname<R, VE, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        source: LexicalSource<'_>,
        w: &W,
        v: impl for<'a> FnOnce(QNameReading<'a>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Failure, VE>> {
        Tree::with_qname(self, s, n, source, w, v)
    }
}
impl AttributeXml for &Tree {
    fn visit_attributes<VE, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
        v: impl for<'a> FnMut(Name<'a>) -> Result<(), VE>,
    ) -> Result<(), VisitError<Failure, VE>> {
        Tree::visit_attributes(self, s, n, w, v)
    }
}
impl UriXml for &Tree {
    fn with_uri<R, VE, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        source: LexicalSource<'_>,
        w: &W,
        v: impl for<'a> FnOnce(UriValue<'a>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Failure, VE>> {
        Tree::with_uri(self, s, n, source, w, v)
    }
}
impl BinaryXml for &Tree {
    fn with_octets<R, C, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
        v: impl for<'a> FnOnce(&'a [u8]) -> Result<R, C>,
    ) -> Result<Result<R, C>, Failure> {
        Tree::with_octets(self, s, n, w, v)
    }
    fn with_binary<R, C>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        r: &structured_asn1::Reader<'_>,
        v: impl for<'a> FnOnce(Decoded<'a>) -> Result<R, C>,
    ) -> Result<Result<R, C>, Failure> {
        Tree::with_binary(self, s, n, r, v)
    }
}
impl OwnedBinaryXml for &Tree {
    fn decode_owned<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
    ) -> Result<OwnedVec<u8>, Failure> {
        Tree::decode_owned(self, s, n, w)
    }
    fn decode_binary_owned(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        r: &structured_asn1::Reader<'_>,
    ) -> Result<OwnedDecoded, Failure> {
        Tree::decode_binary_owned(self, s, n, r)
    }
}

struct Probe<'a> {
    entered: &'a Cell<bool>,
    cancel: bool,
    refuse: bool,
}
impl<'v, 's, S: RangeSource> Visitor<'v, 's, Fixture, S> for Probe<'_> {
    type Output = usize;
    type Error = u8;
    async fn visit<X, W: Work>(self, source: Source<'_, 'v, 's, X, S, W>) -> Result<usize, u8>
    where
        X: Xml<Id = usize, Document = usize, Generation = u64, Error = Failure>
            + ScalarXml
            + AttributeXml
            + UriXml
            + OwnedBinaryXml,
    {
        self.entered.set(true);
        let manifest = source.manifest().map_err(|_| 1)?;
        let snapshot = manifest.source().snapshot();
        assert_eq!(snapshot, source.snapshot());
        assert!(manifest.catalogue().reading().faults().is_empty());
        if self.refuse {
            return Err(7);
        }
        if self.cancel {
            return std::future::pending().await;
        }
        let mut pending = true;
        poll_fn(|cx| {
            if pending {
                pending = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        assert_eq!(manifest.source().snapshot(), snapshot);
        assert!(
            manifest
                .catalogue()
                .signature_member(source.execution())
                .map_err(|_| 2)?
                .is_some()
        );
        assert!(
            manifest
                .catalogue()
                .object_member(0, source.execution())
                .map_err(|_| 3)?
                .is_some()
        );
        Ok(manifest.catalogue().objects().len())
    }
}

#[test]
fn actual_complete_member_produces_the_async_manifest_scope_without_buffer_copy() {
    // Bytes/CRC precede the actual owner; the AST, funded arena and moved input
    // stay alive across await. Completed output contains no temporary borrow.
    let input = Input::new(
        zip(&[
            File::stored(b"META-INF/ASiCManifest.xml", XML),
            File::stored(b"META-INF/evidence.ers", b""),
            File::stored(b"document.bin", b"data"),
        ])
        .bytes,
        11,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let baseline = work.used();
    let entered = Cell::new(false);
    let factory = Fixture {
        calls: Cell::new(0),
        pointer: Cell::new(0),
    };
    let member = archive.member(0, &work).unwrap().unwrap();
    assert_eq!(
        finish(member.with_xml(
            &factory,
            Probe {
                entered: &entered,
                cancel: false,
                refuse: false
            },
            &work
        ))
        .unwrap(),
        1
    );
    assert!(entered.get());
    assert_eq!(factory.calls.get(), 1);
    assert_ne!(factory.pointer.get(), 0);
    assert_eq!(work.used(), baseline);
    assert!(matches!(
        finish(member.with_xml(
            &factory,
            Probe {
                entered: &entered,
                cancel: false,
                refuse: true
            },
            &work
        )),
        Err(producer::Error::Visit(7))
    ));
    assert_eq!(work.used(), baseline);
    drop(archive);
    assert_eq!(work.used(), 0);
}

#[test]
fn cancelling_a_suspended_owner_view_releases_input_ast_and_instruction_catalogues() {
    // Cancellation while the visitor borrows its owner must release every
    // scoped allocation, rather than pinning an arena or leaking a charge.
    let input = Input::new(
        zip(&[
            File::stored(b"META-INF/ASiCManifest.xml", XML),
            File::stored(b"META-INF/evidence.ers", b""),
            File::stored(b"document.bin", b"data"),
        ])
        .bytes,
        17,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let baseline = work.used();
    let member = archive.member(0, &work).unwrap().unwrap();
    let entered = Cell::new(false);
    let factory = Fixture {
        calls: Cell::new(0),
        pointer: Cell::new(0),
    };
    {
        let mut future = pin!(member.with_xml(
            &factory,
            Probe {
                entered: &entered,
                cancel: true,
                refuse: false
            },
            &work
        ));
        let mut cx = Context::from_waker(Waker::noop());
        while !entered.get() {
            assert!(future.as_mut().poll(&mut cx).is_pending());
        }
        assert!(work.used() > baseline + XML.len());
    }
    assert_eq!(work.used(), baseline);
    drop(archive);
    assert_eq!(work.used(), 0);
}
