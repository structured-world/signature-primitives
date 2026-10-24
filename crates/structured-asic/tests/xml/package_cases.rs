use super::super::support::{File, Input, finish, memory, zip};
use super::*;
use structured_asic::{
    Limits, Session,
    package::{self, Format, RootMedia},
    xml::producer::{Factory, Parsed, Source, Types, Visitor},
    zip::Archive,
};
use structured_asn1::{memory::OwnedVec, range::RangeSource};
use structured_xades::{
    binary::OwnedBinaryXml,
    scalar::{ScalarXml, UriXml},
};

// Literal-only projections exercise the actual producing boundary, not a
// generic XML parser. Full-path percent signs remain literal ZIP filename data.
const ODF:&[u8]=br#"<manifest xmlns="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" xmlns:m="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" m:version="1.2"><file-entry m:full-path="/" m:media-type="application/test"/><file-entry m:full-path="file%20name" m:media-type="text/plain"/></manifest>"#;
const BAD:&[u8]=br#"<manifest xmlns="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" xmlns:m="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" m:version="1.2"><file-entry m:full-path="missing" m:media-type="text/"/><file-entry m:full-path="mimetype" m:media-type=""/><file-entry m:full-path="dup" m:media-type="text/plain"/><file-entry m:full-path="dup" m:media-type="text/plain"/></manifest>"#;
const OCF:&[u8]=br#"<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container" version="1.0"><rootfiles><rootfile full-path="file%20name" media-type="text/plain"/></rootfiles></container>"#;
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
fn entry(
    tree: &mut Tree,
    parent: usize,
    namespace: &'static str,
    path: &'static str,
    media: &'static str,
    ocf: bool,
) {
    let node = tree.element(
        parent,
        namespace,
        if ocf { "rootfile" } else { "file-entry" },
    );
    let attr = if ocf { "" } else { namespace };
    tree.rows[node].attributes.push((
        Name {
            namespace: attr,
            local: "full-path",
        },
        path,
    ));
    tree.rows[node].attributes.push((
        Name {
            namespace: attr,
            local: "media-type",
        },
        media,
    ));
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
            let mut tree = if self.bytes == OCF {
                Tree::new(xml::OCF, "container")
            } else {
                Tree::new(package::ODF, "manifest")
            };
            if self.bytes == OCF {
                tree.rows[0].attributes.push((
                    Name {
                        namespace: "",
                        local: "version",
                    },
                    "1.0",
                ));
                let group = tree.element(0, xml::OCF, "rootfiles");
                entry(
                    &mut tree,
                    group,
                    xml::OCF,
                    "file%20name",
                    "text/plain",
                    true,
                );
            } else {
                tree.rows[0].attributes.push((
                    Name {
                        namespace: package::ODF,
                        local: "version",
                    },
                    "1.2",
                ));
                if self.bytes == ODF {
                    entry(&mut tree, 0, package::ODF, "/", "application/test", false);
                    entry(
                        &mut tree,
                        0,
                        package::ODF,
                        "file%20name",
                        "text/plain",
                        false,
                    );
                } else if self.bytes == BAD {
                    entry(&mut tree, 0, package::ODF, "missing", "text/", false);
                    entry(&mut tree, 0, package::ODF, "mimetype", "", false);
                    entry(&mut tree, 0, package::ODF, "dup", "text/plain", false);
                    entry(&mut tree, 0, package::ODF, "dup", "text/plain", false);
                } else {
                    return Err(Failure::Unsupported);
                }
            }
            Ok(Document { input, tree })
        })())
    }
}
struct Read(Format);
impl<'v, 's: 'v, S: RangeSource + 's> Visitor<'v, 's, Literal, S> for Read {
    type Output = package::Reading<'v, 's, usize, usize, u64, S>;
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
        core::future::ready(source.package(self.0).map_err(|_| 1))
    }
}

#[test]
fn producing_odf_inventory_preserves_exact_names_and_complete_root_media() {
    // ODF full-path is not percent-decoded. Exact media bytes are compared on
    // a complete CRC-checked stream, including mismatched/ambiguous cases.
    for (media, duplicate, expected) in [
        (b"application/test".as_slice(), false, RootMedia::Matches),
        (b"Application/test".as_slice(), false, RootMedia::Differs),
        (b"application/test".as_slice(), true, RootMedia::Unavailable),
    ] {
        let mut files = vec![
            File::stored(b"META-INF/manifest.xml", ODF),
            File::stored(b"mimetype", media),
            File::stored(b"file%20name", b"data"),
        ];
        if duplicate {
            files.push(File::stored(b"mimetype", media));
        }
        let input = Input::new(zip(&files).bytes, 7);
        let work = memory();
        let session = Session::new(Limits::default(), work.clone());
        let archive = finish(Archive::read(&input, &session, &work)).unwrap();
        let source = archive.member(0, &work).unwrap().unwrap();
        let reading =
            finish(source.with_xml(&Literal { bytes: ODF }, Read(Format::Odf), &work)).unwrap();
        assert!(reading.faults().is_empty());
        assert_eq!(reading.entries().len(), 2);
        let package::Target::Members(names) = reading.entries()[1].target() else {
            panic!("original filename must resolve");
        };
        assert_eq!(names.len(), 1);
        assert_eq!(
            names.member(0, &work).unwrap().unwrap().name(),
            b"file%20name"
        );
        assert_eq!(finish(reading.check_root_media(&work)).unwrap(), expected);
        let zero = Memory::new(Arc::new(MemoryAccount::new(0, 0)));
        assert!(finish(reading.check_root_media(&zero)).is_err());
        drop(reading);
        drop(archive);
        assert_eq!(work.used(), 0);
    }
}

#[test]
fn inventory_keeps_missing_ambiguous_forbidden_and_undeclared_occurrences() {
    // Invalid declarations do not erase later siblings or invent a unique ZIP
    // occurrence. All unlisted physical files retain their own obligations.
    let input = Input::new(
        zip(&[
            File::stored(b"META-INF/manifest.xml", BAD),
            File::stored(b"mimetype", b"application/test"),
            File::stored(b"dup", b"a"),
            File::stored(b"dup", b"b"),
            File::stored(b"unlisted", b"c"),
        ])
        .bytes,
        11,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let reading = finish(archive.member(0, &work).unwrap().unwrap().with_xml(
        &Literal { bytes: BAD },
        Read(Format::Odf),
        &work,
    ))
    .unwrap();
    assert_eq!(reading.entries().len(), 4);
    for kind in [
        package::FaultKind::Target,
        package::FaultKind::Media,
        package::FaultKind::Forbidden,
        package::FaultKind::Duplicate,
        package::FaultKind::Undeclared,
        package::FaultKind::Missing,
    ] {
        assert!(
            reading.faults().iter().any(|fault| fault.kind == kind),
            "{kind:?}"
        );
    }
    assert_eq!(
        finish(reading.check_root_media(&work)).unwrap(),
        RootMedia::Unavailable
    );
    drop(reading);
    drop(archive);
    assert_eq!(work.used(), 0);
}

#[test]
fn ocf_rootfiles_are_source_bound_without_odf_inventory_obligations() {
    // OCF rootfiles does not inherit ODF's all-files declaration rule or its
    // root/mimetype rule. Original container document identity survives AST drop.
    let input = Input::new(
        zip(&[
            File::stored(b"META-INF/container.xml", OCF),
            File::stored(b"file%20name", b"a"),
            File::stored(b"other", b"b"),
        ])
        .bytes,
        13,
    );
    let work = memory();
    let session = Session::new(Limits::default(), work.clone());
    let archive = finish(Archive::read(&input, &session, &work)).unwrap();
    let reading = finish(archive.member(0, &work).unwrap().unwrap().with_xml(
        &Literal { bytes: OCF },
        Read(Format::Ocf),
        &work,
    ))
    .unwrap();
    assert!(reading.faults().is_empty());
    assert_eq!(reading.entries().len(), 1);
    assert_eq!(reading.source().id().ordinal(), 0);
    assert_eq!(
        finish(reading.check_root_media(&work)).unwrap(),
        RootMedia::NotApplicable
    );
    drop(reading);
    drop(archive);
    assert_eq!(work.used(), 0);
}
