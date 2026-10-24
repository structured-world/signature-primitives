use super::super::support::{File, Input, finish, memory, zip};
use super::*;
use structured_asic::{
    Limits, Session,
    archive::{FindingKind, Graph},
    layout::Census,
    xml::producer::{Factory, Facts, Parsed, Source, Types, Visitor},
    zip::Archive,
};
use structured_asn1::{memory::OwnedVec, range::RangeSource};
use structured_xades::{
    binary::OwnedBinaryXml,
    scalar::{ScalarXml, UriXml},
};

// Each independently written literal has a deliberately narrow fixture
// projector. No generic XML parser or native XMLDSig conformance is claimed.
const OLD:&[u8]=br#"<ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SigReference URI="META-INF/timestamp0.tst"/><DataObjectReference URI="document.bin"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference></ASiCManifest>"#;
const NEW:&[u8]=br#"<ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SigReference URI="META-INF/timestamp1.tst"/><DataObjectReference URI="document.bin"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference><DataObjectReference URI="META-INF/prior-ASiCArchiveManifest-old.xml" Rootfile="true"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference><DataObjectReference URI="META-INF/timestamp0.tst"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference></ASiCManifest>"#;
const DROP:&[u8]=br#"<ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SigReference URI="META-INF/timestamp1.tst"/><DataObjectReference URI="META-INF/prior-ASiCArchiveManifest-old.xml" Rootfile="true"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference><DataObjectReference URI="META-INF/timestamp0.tst"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference></ASiCManifest>"#;
const CYCLE:&[u8]=br#"<ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SigReference URI="META-INF/timestamp1.tst"/><DataObjectReference URI="META-INF/ASiCArchiveManifest.xml" Rootfile="true"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference></ASiCManifest>"#;
const PLAIN:&[u8]=br#"<ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SigReference URI="META-INF/timestamp0.tst"/><DataObjectReference URI="document.bin"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference></ASiCManifest>"#;
const SIMPLE:&[u8]=br#"<ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SigReference URI="META-INF/timestamp1.tst"/><DataObjectReference URI="document.bin"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference><DataObjectReference URI="META-INF/timestamp.tst"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference></ASiCManifest>"#;
const ALL:&[u8]=br#"<ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SigReference URI="META-INF/timestamp1.tst"/><DataObjectReference URI="document.bin"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference><DataObjectReference URI="META-INF/ASiCManifest.xml"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference><DataObjectReference URI="META-INF/timestamp0.tst"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></DataObjectReference></ASiCManifest>"#;

struct Literal {
    bytes: &'static [u8],
}
struct Document {
    input: OwnedVec<u8>,
    tree: Tree,
}
impl Types for Literal {
    type Id = usize;
    type Document = usize;
    type Generation = u64;
    type Error = Failure;
}
impl Types for Document {
    type Id = usize;
    type Document = usize;
    type Generation = u64;
    type Error = Failure;
}
impl Parsed for Document {
    type View<'a> = &'a Tree;
    fn view(&self) -> &Tree {
        assert!(!self.input.is_empty());
        &self.tree
    }
    fn root(&self) -> usize {
        0
    }
}
fn object(tree: &mut Tree, uri: &'static str, rootfile: bool) {
    let node = tree.element(0, ASI, "DataObjectReference");
    tree.rows[node].attributes.push((
        Name {
            namespace: "",
            local: "URI",
        },
        uri,
    ));
    if rootfile {
        tree.rows[node].attributes.push((
            Name {
                namespace: "",
                local: "Rootfile",
            },
            "true",
        ));
    }
    let method = tree.element(node, DS, "DigestMethod");
    tree.rows[method].attributes.push((
        Name {
            namespace: "",
            local: "Algorithm",
        },
        "http://www.w3.org/2001/04/xmlenc#sha256",
    ));
    let value = tree.element(node, DS, "DigestValue");
    tree.rows[value].binary = Some(vec![0; 32]);
}
impl Factory for Literal {
    type Parsed<'a, W: Work + 'a> = Document;
    fn parse<'a, W: Work + 'a>(
        &'a self,
        input: OwnedVec<u8>,
        work: &'a W,
    ) -> impl core::future::Future<Output = Result<Document, Failure>> + 'a {
        core::future::ready((|| {
            work.charge_work(input.len() as u64)
                .map_err(Failure::Resource)?;
            if input.as_ref() != self.bytes {
                return Err(Failure::Unsupported);
            }
            let mut tree = Tree::new(ASI, "ASiCManifest");
            let sig = tree.element(0, ASI, "SigReference");
            tree.rows[sig].attributes.push((
                Name {
                    namespace: "",
                    local: "URI",
                },
                if self.bytes == OLD || self.bytes == PLAIN {
                    "META-INF/timestamp0.tst"
                } else {
                    "META-INF/timestamp1.tst"
                },
            ));
            if [OLD, NEW, PLAIN, ALL, SIMPLE].contains(&self.bytes) {
                object(&mut tree, "document.bin", false);
            }
            if self.bytes == NEW || self.bytes == DROP {
                object(
                    &mut tree,
                    "META-INF/prior-ASiCArchiveManifest-old.xml",
                    true,
                );
                object(&mut tree, "META-INF/timestamp0.tst", false);
            } else if self.bytes == CYCLE {
                object(&mut tree, "META-INF/ASiCArchiveManifest.xml", true);
            } else if self.bytes == ALL {
                object(&mut tree, "META-INF/ASiCManifest.xml", false);
                object(&mut tree, "META-INF/timestamp0.tst", false);
            } else if self.bytes == SIMPLE {
                object(&mut tree, "META-INF/timestamp.tst", false);
            }
            Ok(Document { input, tree })
        })())
    }
}

#[test]
fn preceding_census_keeps_plain_manifest_tsa_outside_archive_node_sequence() {
    // A covered ordinary-manifest TSA is still an obligation. Omitting its
    // producing inspection must prevent a complete preceding-TSA claim.
    use structured_asic::archive::{AssertionScope, InputAssociation};
    use structured_asic::layout::{Form, Inspection, Rules};
    for omit in [false, true] {
        let input = Input::new(
            zip(&[
                File::stored(b"META-INF/ASiCArchiveManifest.xml", ALL),
                File::stored(b"META-INF/timestamp1.tst", b"unchecked"),
                File::stored(b"document.bin", b"data"),
                File::stored(b"META-INF/ASiCManifest.xml", PLAIN),
                File::stored(b"META-INF/timestamp0.tst", b"unchecked"),
            ])
            .bytes,
            13,
        );
        let work = memory();
        let session = Session::new(Limits::default(), work.clone());
        let archive = finish(Archive::read(&input, &session, &work)).unwrap();
        let census = Census::read(&archive, &work).unwrap();
        let layout = Inspection::read(
            &census,
            Form::ExtendedCadesAndAssertions,
            Rules::AdditionalPart2,
            &work,
        )
        .unwrap();
        let mut facts = work.vector();
        facts
            .try_push(
                finish(archive.member(0, &work).unwrap().unwrap().with_xml(
                    &Literal { bytes: ALL },
                    Retain,
                    &work,
                ))
                .unwrap(),
            )
            .unwrap();
        if !omit {
            facts
                .try_push(
                    finish(archive.member(3, &work).unwrap().unwrap().with_xml(
                        &Literal { bytes: PLAIN },
                        Retain,
                        &work,
                    ))
                    .unwrap(),
                )
                .unwrap();
        }
        let graph = Graph::inspect(&census, facts.into_owned(), &work).unwrap();
        assert!(graph.geometry_complete());
        assert_eq!(graph.nodes().len(), 1);
        let inputs = graph.timestamp_inputs(0, &layout, &work).unwrap();
        assert_eq!(inputs.entries().len(), 2);
        let prior = &inputs.entries()[1];
        assert_eq!(prior.token.ordinal(), 4);
        assert_eq!(prior.scope, AssertionScope::Declared);
        assert_eq!(inputs.complete(), !omit);
        if omit {
            assert!(matches!(prior.association, InputAssociation::Missing));
        } else {
            assert!(
                matches!(prior.association,InputAssociation::Known{member,purpose:structured_ltv::timestamp::Purpose::Content} if member.ordinal()==3)
            );
        }
        assert_eq!(
            graph.requirements(0, &layout, &work).unwrap().is_some(),
            !omit
        );
        drop(inputs);
        drop(graph);
        drop(layout);
        drop(census);
        drop(archive);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn simple_timestamp_input_requires_explicit_simple_form() {
    // Naming alone cannot create the implied S data association under an E
    // interpretation, and no earlier timestamp disappears from the census.
    use structured_asic::archive::InputAssociation;
    use structured_asic::layout::{Form, Inspection, Principal, Rules};
    let input = Input::new(
        zip(&[
            File::stored(b"META-INF/ASiCArchiveManifest.xml", SIMPLE),
            File::stored(b"META-INF/timestamp1.tst", b"unchecked"),
            File::stored(b"document.bin", b"data"),
            File::stored(b"META-INF/timestamp.tst", b"unchecked"),
        ])
        .bytes,
        13,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let census = Census::read(&archive, &work).unwrap();
    let mut facts = work.vector();
    facts
        .try_push(
            finish(archive.member(0, &work).unwrap().unwrap().with_xml(
                &Literal { bytes: SIMPLE },
                Retain,
                &work,
            ))
            .unwrap(),
        )
        .unwrap();
    let graph = Graph::inspect(&census, facts.into_owned(), &work).unwrap();
    for form in [
        Form::Simple(Principal::Timestamp),
        Form::ExtendedCadesAndAssertions,
    ] {
        let layout = Inspection::read(&census, form, Rules::AdditionalPart2, &work).unwrap();
        let inputs = graph.timestamp_inputs(0, &layout, &work).unwrap();
        assert_eq!(inputs.entries().len(), 2);
        assert_eq!(
            inputs.complete(),
            form == Form::Simple(Principal::Timestamp)
        );
        if form == Form::Simple(Principal::Timestamp) {
            assert!(
                matches!(inputs.entries()[1].association,InputAssociation::Known{member,..} if member.ordinal()==2)
            );
        } else {
            assert!(matches!(
                inputs.entries()[1].association,
                InputAssociation::Missing
            ));
        }
    }
    drop(graph);
    drop(census);
    drop(archive);
    assert_eq!(work.used(), 0);
}
struct Retain;
impl<'v, 's: 'v, S: RangeSource + 's> Visitor<'v, 's, Literal, S> for Retain {
    type Output = Facts<'v, 's, usize, usize, u64, S>;
    type Error = u8;
    fn visit<X, W: Work>(
        self,
        source: Source<'_, 'v, 's, X, S, W>,
    ) -> impl core::future::Future<Output = Result<Self::Output, u8>>
    where
        X: Xml<Id = usize, Document = usize, Generation = u64, Error = Failure>
            + ScalarXml
            + AttributeXml
            + UriXml
            + OwnedBinaryXml,
    {
        core::future::ready(
            source
                .manifest()
                .map(structured_asic::xml::producer::Manifest::into_facts)
                .map_err(|_| 1),
        )
    }
}

#[test]
fn archive_rootfile_graph_uses_original_links_and_all_prior_obligations() {
    // Source order is deliberately NEW before OLD. A renamed prior manifest,
    // its actual TST and every previous object must survive in the new set.
    // Syntax-only timestamp payloads deliberately do not establish mathematics.
    for (bytes, missing, expected) in [
        (NEW, false, None),
        (DROP, false, Some(FindingKind::Dropped)),
        (CYCLE, false, Some(FindingKind::Cycle)),
        (NEW, true, Some(FindingKind::Uninspected)),
    ] {
        let input = Input::new(
            zip(&[
                File::stored(b"META-INF/ASiCArchiveManifest.xml", bytes),
                File::stored(b"META-INF/timestamp1.tst", b"unchecked"),
                File::stored(b"document.bin", b"data"),
                File::stored(b"META-INF/prior-ASiCArchiveManifest-old.xml", OLD),
                File::stored(b"META-INF/timestamp0.tst", b"unchecked"),
            ])
            .bytes,
            13,
        );
        let work = memory();
        let session = Session::new(Limits::default(), work.clone());
        let archive = finish(Archive::read(&input, &session, &work)).unwrap();
        let census = Census::read(&archive, &work).unwrap();
        let mut facts = work.vector();
        facts
            .try_push(
                finish(archive.member(0, &work).unwrap().unwrap().with_xml(
                    &Literal { bytes },
                    Retain,
                    &work,
                ))
                .unwrap(),
            )
            .unwrap();
        if !missing {
            facts
                .try_push(
                    finish(archive.member(3, &work).unwrap().unwrap().with_xml(
                        &Literal { bytes: OLD },
                        Retain,
                        &work,
                    ))
                    .unwrap(),
                )
                .unwrap();
        }
        let graph = Graph::inspect(&census, facts.into_owned(), &work).unwrap();
        assert_eq!(graph.nodes().len(), 2);
        assert_eq!(graph.latest(), Some(0));
        if let Some(kind) = expected {
            assert!(!graph.geometry_complete());
            assert!(graph.findings().iter().any(|finding| finding.kind == kind));
        } else {
            assert!(graph.geometry_complete());
            assert_eq!(graph.order(), &[1, 0]);
            assert_eq!(graph.nodes()[1].member().ordinal(), 3);
            assert!(
                graph
                    .declares_all(
                        &[
                            archive.member(2, &work).unwrap().unwrap().id(),
                            archive.member(3, &work).unwrap().unwrap().id(),
                            archive.member(4, &work).unwrap().unwrap().id()
                        ],
                        &work
                    )
                    .unwrap()
            );
            assert!(
                !graph
                    .declares_all(&[archive.member(1, &work).unwrap().unwrap().id()], &work)
                    .unwrap()
            );
            assert!(
                graph
                    .facts()
                    .iter()
                    .all(|facts| facts.object_digests().is_none())
            );
        }
        drop(graph);
        drop(census);
        drop(archive);
        assert_eq!(work.used(), 0);
    }
}
