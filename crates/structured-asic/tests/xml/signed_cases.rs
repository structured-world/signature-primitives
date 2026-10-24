use super::super::support::{File, Input, finish, memory, zip};
use super::*;
use structured_asic::{
    Limits, Session,
    xml::producer::{
        self, Source, Types,
        signed::{
            self, MemberReference, MemberReferences, Resource, Resources, SignatureFactory,
            SignatureParsed, SignatureVisitor,
        },
    },
    zip::Archive,
};
use structured_asn1::{memory::OwnedVec, range::RangeSource};
use structured_cms::stream::Receiver;
use structured_xades::{
    binary::{BinaryXml, Decoded, OwnedBinaryXml, OwnedDecoded},
    binding::{Coverage, Reference, SignatureXml, Status, Target},
    reference::{
        Boolean, Completeness, Descriptor, LexicalSource, ObjectLocation, Parent, ReferenceXml,
        Replay, ReplayOutcome, Resolution,
    },
    scalar::{Datatype, Fact, ScalarXml, UriValue, UriXml},
};

const XML:&[u8]=br#"<XAdESSignatures xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature><ds:SignedInfo><ds:Reference URI="document.bin"/></ds:SignedInfo><ds:Object><ds:Signature/></ds:Object></ds:Signature><ds:Signature/></XAdESSignatures>"#;

// Exact-literal structural fixture with EXPLICITLY UNCHECKED mathematics.
// It proves owning async/source/census behavior, not an XMLDSig engine.
struct Factory {
    cancel: bool,
}
struct Document<'v, 's, S: RangeSource> {
    input: OwnedVec<u8>,
    payload: OwnedVec<u8>,
    resource: Resource<'v, 's, S>,
    tree: Tree,
}
struct View<'a, 'v, 's, S: RangeSource> {
    document: &'a Document<'v, 's, S>,
}
impl Types for Factory {
    type Id = usize;
    type Document = usize;
    type Generation = u64;
    type Error = Failure;
}
impl<S: RangeSource> Types for Document<'_, '_, S> {
    type Id = usize;
    type Document = usize;
    type Generation = u64;
    type Error = Failure;
}
impl<'v, 's, S: RangeSource> SignatureParsed<'v, 's, S> for Document<'v, 's, S> {
    type View<'a>
        = View<'a, 'v, 's, S>
    where
        Self: 'a;
    fn view(&self) -> Self::View<'_> {
        assert_eq!(self.input.as_ref(), XML);
        assert_eq!(self.payload.as_ref(), b"original object");
        View { document: self }
    }
    fn root(&self) -> usize {
        0
    }
}
impl<'v, 's, S: RangeSource> SignatureFactory<'v, 's, S> for Factory {
    type Parsed<'a, W: Work + 'a>
        = Document<'v, 's, S>
    where
        Self: 'a,
        'v: 'a,
        's: 'a,
        's: 'v,
        S: 's + 'v + 'a;
    async fn parse_signed<'a, W: Work + 'a>(
        &'a self,
        input: OwnedVec<u8>,
        resources: &'a Resources<'v, 's, S>,
        work: &'a W,
    ) -> Result<Self::Parsed<'a, W>, Failure>
    where
        'v: 'a,
        's: 'a,
        's: 'v,
        S: 's + 'v + 'a,
    {
        work.charge_work(input.len() as u64)
            .map_err(Failure::Resource)?;
        if input.as_ref() != XML {
            return Err(Failure::Unsupported);
        }
        let loaded = resources
            .load(resources.base(), "document.bin", work)
            .await
            .map_err(|_| Failure::Unsupported)?;
        let signed::Lookup::Loaded(loaded) = loaded else {
            return Err(Failure::Unsupported);
        };
        let (payload, resource) = loaded.into_parts();
        if self.cancel {
            return std::future::pending().await;
        }
        let mut tree = Tree::new(ASI, "XAdESSignatures");
        let first = tree.element(0, DS, "Signature");
        let info = tree.element(first, DS, "SignedInfo");
        tree.element(info, DS, "Reference");
        let object = tree.element(first, DS, "Object");
        tree.element(object, DS, "Signature");
        tree.element(0, DS, "Signature");
        Ok(Document {
            input,
            payload,
            resource,
            tree,
        })
    }
}
impl<S: RangeSource> Xml for View<'_, '_, '_, S> {
    type Id = usize;
    type Document = usize;
    type Generation = u64;
    type Error = Failure;
    fn snapshot(&self) -> Snapshot<usize, u64> {
        self.document.tree.snapshot()
    }
    fn inspect<R, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
        v: impl for<'a> FnOnce(Node<'a>) -> R,
    ) -> Result<R, Failure> {
        self.document.tree.inspect(s, n, w, v)
    }
    fn attribute<R, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        name: Name<'_>,
        w: &W,
        v: impl for<'a> FnOnce(Option<&'a str>) -> R,
    ) -> Result<R, Failure> {
        self.document.tree.attribute(s, n, name, w, v)
    }
    fn first_child<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
    ) -> Result<Option<usize>, Failure> {
        self.document.tree.first_child(s, n, w)
    }
    fn next_sibling<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        p: usize,
        n: usize,
        w: &W,
    ) -> Result<Option<usize>, Failure> {
        self.document.tree.next_sibling(s, p, n, w)
    }
}
impl<S: RangeSource> QNameXml for View<'_, '_, '_, S> {
    fn with_qname<R, VE, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        source: LexicalSource<'_>,
        w: &W,
        v: impl for<'a> FnOnce(QNameReading<'a>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Failure, VE>> {
        self.document.tree.with_qname(s, n, source, w, v)
    }
}
impl<S: RangeSource> AttributeXml for View<'_, '_, '_, S> {
    fn visit_attributes<VE, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
        v: impl for<'a> FnMut(Name<'a>) -> Result<(), VE>,
    ) -> Result<(), VisitError<Failure, VE>> {
        self.document.tree.visit_attributes(s, n, w, v)
    }
}
impl<S: RangeSource> ScalarXml for View<'_, '_, '_, S> {
    fn scalar<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        source: LexicalSource<'_>,
        d: Datatype,
        w: &W,
    ) -> Result<Fact, Failure> {
        self.document.tree.scalar(s, n, source, d, w)
    }
}
impl<S: RangeSource> UriXml for View<'_, '_, '_, S> {
    fn with_uri<R, VE, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        source: LexicalSource<'_>,
        w: &W,
        v: impl for<'a> FnOnce(UriValue<'a>) -> Result<R, VE>,
    ) -> Result<R, VisitError<Failure, VE>> {
        self.document.tree.with_uri(s, n, source, w, v)
    }
}
impl<S: RangeSource> BinaryXml for View<'_, '_, '_, S> {
    fn with_octets<R, C, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
        v: impl for<'a> FnOnce(&'a [u8]) -> Result<R, C>,
    ) -> Result<Result<R, C>, Failure> {
        self.document.tree.with_octets(s, n, w, v)
    }
    fn with_binary<R, C>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        r: &structured_asn1::Reader<'_>,
        v: impl for<'a> FnOnce(Decoded<'a>) -> Result<R, C>,
    ) -> Result<Result<R, C>, Failure> {
        self.document.tree.with_binary(s, n, r, v)
    }
}
impl<S: RangeSource> OwnedBinaryXml for View<'_, '_, '_, S> {
    fn decode_owned<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
    ) -> Result<OwnedVec<u8>, Failure> {
        self.document.tree.decode_owned(s, n, w)
    }
    fn decode_binary_owned(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        r: &structured_asn1::Reader<'_>,
    ) -> Result<OwnedDecoded, Failure> {
        self.document.tree.decode_binary_owned(s, n, r)
    }
}
impl<S: RangeSource> SignatureXml for View<'_, '_, '_, S> {
    fn signature_status<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
    ) -> Result<Status, Failure> {
        self.document.tree.row(s, n, w)?;
        Ok(Status::Unchecked)
    }
    fn reference_count<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
    ) -> Result<usize, Failure> {
        self.document.tree.row(s, n, w)?;
        Ok(usize::from(n == 1))
    }
    fn reference<R, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        _ordinal: usize,
        w: &W,
        v: impl for<'a> FnOnce(Reference<'a, usize>) -> R,
    ) -> Result<R, Failure> {
        self.document.tree.row(s, n, w)?;
        Ok(v(Reference {
            node: 3,
            target: None,
            kind: None,
            status: Status::Unchecked,
            coverage: Coverage::Transformed,
        }))
    }
    fn qualifying_target<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
    ) -> Result<Target<usize>, Failure> {
        self.document.tree.row(s, n, w)?;
        Ok(Target::Missing)
    }
}
impl<S: RangeSource> ReferenceXml for View<'_, '_, '_, S> {
    fn visit_authenticated_references<VE, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
        _v: impl for<'a> FnMut(Descriptor<'a, usize>) -> Result<(), VE>,
    ) -> Result<Completeness<usize>, VisitError<Failure, VE>> {
        self.document
            .tree
            .row(s, n, w)
            .map_err(VisitError::Processing)?;
        Ok(Completeness::Unchecked(n))
    }
    fn resolve_reference<R, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        _p: usize,
        _source: LexicalSource<'_>,
        w: &W,
        _v: impl for<'a> FnOnce(Descriptor<'a, usize>) -> R,
    ) -> Result<Resolution<R>, Failure> {
        self.document.tree.row(s, n, w)?;
        Ok(Resolution::Unauthenticated)
    }
    fn boolean_attribute<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        _a: Name<'_>,
        w: &W,
    ) -> Result<Boolean, Failure> {
        self.document.tree.row(s, n, w)?;
        Ok(Boolean::Absent)
    }
    fn replay_reference<W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        _r: usize,
        _mode: Replay<usize>,
        _receiver: &mut impl Receiver,
        w: &W,
    ) -> Result<ReplayOutcome<Failure>, Failure> {
        self.document.tree.row(s, n, w)?;
        Err(Failure::Unsupported)
    }
}
impl<'v, 's, S: RangeSource> MemberReferences<'v, 's, S> for View<'_, 'v, 's, S> {
    fn visit_member_references<VE, W: Work>(
        &self,
        s: Snapshot<usize, u64>,
        n: usize,
        w: &W,
        mut visit: impl for<'a> FnMut(MemberReference<'a, 'v, 's, usize, S>) -> Result<(), VE>,
    ) -> Result<Completeness<usize>, VisitError<Failure, VE>> {
        self.document
            .tree
            .row(s, n, w)
            .map_err(VisitError::Processing)?;
        if n == 1 {
            visit(MemberReference {
                descriptor: Descriptor {
                    reference: Reference {
                        node: 3,
                        target: None,
                        kind: None,
                        status: Status::Unchecked,
                        coverage: Coverage::Transformed,
                    },
                    parent: Parent::SignedInfo(n),
                    object_location: ObjectLocation::Detached,
                },
                resource: Some(&self.document.resource),
            })
            .map_err(VisitError::Visitor)?;
        }
        Ok(Completeness::Unchecked(n))
    }
}
struct Read<'a> {
    fail: bool,
    cancel: bool,
    entered: &'a Cell<bool>,
}
impl<'v, 's: 'v, S: RangeSource + 's> SignatureVisitor<'v, 's, Factory, S> for Read<'_> {
    type Output = signed::Facts<'v, 's, usize, usize, u64, S>;
    type Error = u8;
    async fn visit<X, W: Work>(
        self,
        source: Source<'_, 'v, 's, X, S, W>,
    ) -> Result<Self::Output, u8>
    where
        X: Xml<Id = usize, Document = usize, Generation = u64, Error = Failure>
            + ScalarXml
            + AttributeXml
            + UriXml
            + OwnedBinaryXml
            + MemberReferences<'v, 's, S>,
    {
        self.entered.set(true);
        let facts = source.signatures().map_err(|_| 1)?;
        if self.fail {
            return Err(7);
        }
        if self.cancel {
            return std::future::pending().await;
        }
        let mut pending = true;
        std::future::poll_fn(|cx| {
            if pending {
                pending = false;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        })
        .await;
        Ok(facts)
    }
}

#[test]
fn complete_signature_scope_keeps_nested_unchecked_census_and_actual_resource() {
    // Actual moved input/resource/verification state survive await. Unchecked
    // math and incomplete reference traversal cannot become a successful level.
    let input = Input::new(
        zip(&[
            File::stored(b"META-INF/signatures.xml", XML),
            File::stored(b"document.bin", b"original object"),
        ])
        .bytes,
        7,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let entered = Cell::new(false);
    let member = archive.member(0, &work).unwrap().unwrap();
    let facts = finish(member.with_signed_xml(
        &Factory { cancel: false },
        Read {
            fail: false,
            cancel: false,
            entered: &entered,
        },
        &work,
    ))
    .unwrap();
    assert!(entered.get());
    assert_eq!(facts.signatures().len(), 3);
    assert_eq!(facts.member().id(), member.id());
    assert!(
        facts
            .signatures()
            .iter()
            .all(|signature| signature.status == Status::Unchecked
                && matches!(signature.completeness, Completeness::Unchecked(_)))
    );
    assert_eq!(facts.signatures()[0].references.len(), 1);
    assert_eq!(
        facts.signatures()[0].references[0].input.unwrap().ordinal(),
        1
    );
    assert!(facts.signatures()[1].references.is_empty());
    assert!(facts.signatures()[2].references.is_empty());
    assert!(!facts.signatures()[1].occurrence.direct);
    assert_eq!(facts.signatures()[1].occurrence.enclosing, Some(1));
    let levels = facts.levels::<(), _>(&[], &work).unwrap();
    assert_eq!(levels.answers().len(), 3);
    assert!(!levels.all_roots_requested_level_met());
    drop(levels);
    drop(facts);
    let baseline = work.used();
    assert!(matches!(
        finish(member.with_signed_xml(
            &Factory { cancel: false },
            Read {
                fail: true,
                cancel: false,
                entered: &entered
            },
            &work
        )),
        Err(producer::Error::Visit(7))
    ));
    assert_eq!(work.used(), baseline);
    {
        use std::{
            future::Future,
            pin::pin,
            task::{Context, Waker},
        };
        entered.set(false);
        let factory = Factory { cancel: false };
        let mut future = pin!(member.with_signed_xml(
            &factory,
            Read {
                fail: false,
                cancel: true,
                entered: &entered
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
