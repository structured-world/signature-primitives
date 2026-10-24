//! Native public-API checks over real PDF `ByteRange` and P-256 signatures.

extern crate alloc;
#[path = "support/credentials.rs"]
mod credentials;
#[path = "support/crl.rs"]
mod crl_fixture;
#[path = "support/crypto.rs"]
mod crypto;
#[cfg(feature = "interop-tests")]
#[path = "support/oracle.rs"]
mod oracle;
mod support;
use core::fmt::Write as _;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use structured_ltv::{
    pki::{self, PathOutcome},
    source::Snapshot,
};
use structured_pades::{
    Limits, Session,
    document::Document,
    prepare::{Level, Preparation},
    range::Slice,
};
use structured_pkix::path::{self, Anchor, Interval, ValidationBounds, ValidationContext};

type Unassessed<'a> = structured_pades::baseline::Seal<'a, 'a, 'a, 'a, 'a, 'a, 'a, u8, u8, ()>;

fn upper_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        write!(output, "{byte:02X}").unwrap();
    }
    output
}

fn signed_pdf(root: &[u8], leaf: &[u8], key: &SigningKey, counter: bool) -> support::Pdf {
    signed_pdf_with_permission(root, leaf, key, counter, None)
}

fn signed_pdf_with_permission(
    root: &[u8],
    leaf: &[u8],
    key: &SigningKey,
    counter: bool,
    permission: Option<&str>,
) -> support::Pdf {
    signed_pdf_options(
        root,
        leaf,
        key,
        counter,
        permission,
        credentials::Case::Absent,
    )
}

fn signed_pdf_options(
    root: &[u8],
    leaf: &[u8],
    key: &SigningKey,
    counter: bool,
    permission: Option<&str>,
    assertion: credentials::Case,
) -> support::Pdf {
    // Fixed-width trusted placeholders are filled before hashing. Only the
    // original Contents string is excluded; offsets and xref remain unchanged.
    const CAPACITY: usize = 4096;
    let reference = permission.map(|permission| format!("/Reference [<< /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /V /1.2 /P {permission} >> >>] ")).unwrap_or_default();
    let dictionary = format!(
        "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /M (D:20260101000000Z) {reference}/ByteRange [0 0000000000 0000000000 0000000000] /Contents <{}> >>",
        "0".repeat(CAPACITY * 2)
    );
    let mut pdf = support::Pdf::new(&[
        (1, b"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>"),
        (2, b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>"),
        (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] /Resources << >> /Annots [5 0 R] >>"),
        (4, b"<< /Fields [5 0 R] /SigFlags 3 >>"),
        (5, b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature) /V 6 0 R /P 3 0 R /Rect [0 0 1 1] >>"),
        (6, dictionary.as_bytes()),
    ]);
    let start = pdf
        .bytes
        .windows(b"/Contents <".len())
        .position(|bytes| bytes == b"/Contents <")
        .unwrap()
        + b"/Contents ".len();
    let end = start + CAPACITY * 2 + 2;
    let numbers = format!("{start:010} {end:010} {:010}", pdf.bytes.len() - end);
    let placeholder = b"0000000000 0000000000 0000000000";
    let at = pdf
        .bytes
        .windows(placeholder.len())
        .position(|bytes| bytes == placeholder)
        .unwrap();
    pdf.bytes[at..at + placeholder.len()].copy_from_slice(numbers.as_bytes());
    let input = [&pdf.bytes[..start], &pdf.bytes[end..]].concat();
    let extra = credentials::attributes(assertion, key);
    let mut signer = crypto::signer(
        Some(structured_cms::oid::DATA.as_bytes()),
        &input,
        leaf,
        key,
        &extra,
        &[],
    );
    if counter {
        let signature = crypto::signature_octets(&signer);
        let child = crypto::signer(None, &signature, leaf, key, &[], &[]);
        let attribute = crypto::attribute(structured_cms::oid::COUNTERSIGNATURE.as_bytes(), &child);
        signer = crypto::signer(
            Some(structured_cms::oid::DATA.as_bytes()),
            &input,
            leaf,
            key,
            &extra,
            &[attribute],
        );
    }
    let cms = crypto::message(
        structured_cms::oid::DATA.as_bytes(),
        None,
        &[root.to_vec(), leaf.to_vec()],
        &[],
        &[signer],
    );
    assert!(cms.len() <= CAPACITY);
    for (index, byte) in cms.iter().enumerate() {
        pdf.bytes[start + 1 + 2 * index] = b"0123456789ABCDEF"[usize::from(byte >> 4)];
        pdf.bytes[start + 2 + 2 * index] = b"0123456789ABCDEF"[usize::from(byte & 15)];
    }
    pdf
}

#[test]
fn doc_mdp_permission_is_a_number_without_fractional_truncation() {
    // ISO32000-1 Table254 declares P as a NUMBER, not an integer object.
    // Numeric 2.000 is valid; 2.5 cannot silently truncate to permission 2.
    let issuer = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let signer = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let root = crypto::certificate("Root", "Root", &issuer, &issuer, false);
    let leaf = crypto::certificate("Signer", "Root", &signer, &issuer, false);
    for spelling in ["2", "2.000", "+0002.000", "2.5"] {
        let pdf = signed_pdf_with_permission(&root, &leaf, &signer, false, Some(spelling));
        let source = Slice::new(
            &pdf.bytes,
            Snapshot {
                document: 1u8,
                generation: 0u8,
            },
        );
        let session = Session::new(Limits::default(), crypto::memory());
        let work = session.execution();
        let document = support::ready(Document::read(&source, &session, &work)).unwrap();
        let catalogue = support::ready(document.catalogue(&work)).unwrap();
        let graph = support::ready(document.graph(0, &work)).unwrap();
        let result = support::ready(document.transforms(catalogue.get(0).unwrap(), &graph, &work));
        if spelling == "2.5" {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap().permission(),
                Some(structured_pades::permissions::Permission::FormFill)
            );
        }
    }
}

fn append_timestamp(
    pdf: &mut support::Pdf,
    root: &[u8],
    tsa: &[u8],
    key: &SigningKey,
    dss: Option<usize>,
) {
    append_timestamp_with_fields(pdf, root, tsa, key, dss, &[]);
}

fn append_timestamp_with_fields(
    pdf: &mut support::Pdf,
    root: &[u8],
    tsa: &[u8],
    key: &SigningKey,
    dss: Option<usize>,
    extra_fields: &[usize],
) {
    // The actual incremental revision is finalized before RFC 3161 hashing.
    // Earlier signatures and timestamps remain physically untouched.
    const CAPACITY: usize = 4096;
    let dictionary = format!(
        "<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161 /V 0 /ByteRange [0 0000000000 0000000000 0000000000] /Contents <{}> >>",
        "0".repeat(CAPACITY * 2)
    );
    let catalog = match dss {
        Some(number) => {
            format!("<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R /DSS {number} 0 R >>")
        }
        None => "<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>".to_owned(),
    };
    let before = pdf.bytes.len();
    let ordinal = pdf
        .bytes
        .windows(b"/Type /DocTimeStamp".len())
        .filter(|bytes| *bytes == b"/Type /DocTimeStamp")
        .count();
    let field = 11 + ordinal * 2;
    let mut fields = "5 0 R".to_owned();
    for field in extra_fields {
        write!(fields, " {field} 0 R").unwrap();
    }
    for previous in 0..=ordinal {
        write!(fields, " {} 0 R", 11 + previous * 2).unwrap();
    }
    let form = format!("<< /Fields [{fields}] /SigFlags 3 >>");
    let widget = format!(
        "<< /FT /Sig /T (DocumentTime{ordinal}) /V {} 0 R >>",
        field + 1
    );
    pdf.append(&[
        (1, catalog.as_bytes()),
        (4, form.as_bytes()),
        (field, widget.as_bytes()),
        (field + 1, dictionary.as_bytes()),
    ]);
    let start = before
        + pdf.bytes[before..]
            .windows(b"/Contents <".len())
            .position(|bytes| bytes == b"/Contents <")
            .unwrap()
        + b"/Contents ".len();
    let end = start + CAPACITY * 2 + 2;
    let numbers = format!("{start:010} {end:010} {:010}", pdf.bytes.len() - end);
    let placeholder = b"0000000000 0000000000 0000000000";
    let at = before
        + pdf.bytes[before..]
            .windows(placeholder.len())
            .position(|bytes| bytes == placeholder)
            .unwrap();
    pdf.bytes[at..at + placeholder.len()].copy_from_slice(numbers.as_bytes());
    let mut digest = Sha256::new();
    digest.update(&pdf.bytes[..start]);
    digest.update(&pdf.bytes[end..]);
    let token = timestamp_token_serial(
        &digest.finalize(),
        root,
        tsa,
        key,
        u8::try_from(10 + ordinal).unwrap(),
    );
    assert!(token.len() <= CAPACITY);
    for (index, byte) in token.iter().enumerate() {
        pdf.bytes[start + 1 + 2 * index] = b"0123456789ABCDEF"[usize::from(byte >> 4)];
        pdf.bytes[start + 2 + 2 * index] = b"0123456789ABCDEF"[usize::from(byte & 15)];
    }
}

fn append_approval(pdf: &mut support::Pdf, root: &[u8], leaf: &[u8], key: &SigningKey) {
    const CAPACITY: usize = 4096;
    let dictionary = format!(
        "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /M (D:20260101000000Z) /ByteRange [0 0000000000 0000000000 0000000000] /Contents <{}> >>",
        "0".repeat(CAPACITY * 2)
    );
    let before = pdf.bytes.len();
    pdf.append(&[
        (4, b"<< /Fields [5 0 R 11 0 R 21 0 R] /SigFlags 3 >>"),
        (21, b"<< /FT /Sig /T (Approval) /V 22 0 R >>"),
        (22, dictionary.as_bytes()),
    ]);
    let start = before
        + pdf.bytes[before..]
            .windows(b"/Contents <".len())
            .position(|bytes| bytes == b"/Contents <")
            .unwrap()
        + b"/Contents ".len();
    let end = start + CAPACITY * 2 + 2;
    let numbers = format!("{start:010} {end:010} {:010}", pdf.bytes.len() - end);
    let placeholder = b"0000000000 0000000000 0000000000";
    let at = before
        + pdf.bytes[before..]
            .windows(placeholder.len())
            .position(|bytes| bytes == placeholder)
            .unwrap();
    pdf.bytes[at..at + placeholder.len()].copy_from_slice(numbers.as_bytes());
    let input = [&pdf.bytes[..start], &pdf.bytes[end..]].concat();
    let signer = crypto::signer(
        Some(structured_cms::oid::DATA.as_bytes()),
        &input,
        leaf,
        key,
        &[],
        &[],
    );
    let cms = crypto::message(
        structured_cms::oid::DATA.as_bytes(),
        None,
        &[root.to_vec(), leaf.to_vec()],
        &[],
        &[signer],
    );
    assert!(cms.len() <= CAPACITY);
    for (index, byte) in cms.iter().enumerate() {
        pdf.bytes[start + 1 + 2 * index] = b"0123456789ABCDEF"[usize::from(byte >> 4)];
        pdf.bytes[start + 2 + 2 * index] = b"0123456789ABCDEF"[usize::from(byte & 15)];
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the later approval and earlier/later timestamp authorities retain their original certificate, reader and actor borrows in one end-to-end scope"
)]
fn each_approval_root_keeps_its_own_revision_and_timestamp_coverage() {
    // A valid earlier DTS exists but cannot prove a later approval signature.
    // Only the actual subsequent timestamp may issue its covering actor.
    let issuer = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let signer = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let timestamp_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = crypto::certificate("Root", "Root", &issuer, &issuer, false);
    let leaf = crypto::certificate("Signer", "Root", &signer, &issuer, false);
    let tsa = crypto::certificate("TSA", "Root", &timestamp_key, &issuer, true);
    for later in [false, true] {
        let mut pdf = signed_pdf(&root, &leaf, &signer, false);
        append_timestamp(&mut pdf, &root, &tsa, &timestamp_key, None);
        append_approval(&mut pdf, &root, &leaf, &signer);
        if later {
            append_timestamp_with_fields(&mut pdf, &root, &tsa, &timestamp_key, None, &[21]);
        }
        let source = Slice::new(
            &pdf.bytes,
            Snapshot {
                document: 1u8,
                generation: 0u8,
            },
        );
        let session = Session::new(Limits::default(), crypto::memory());
        let work = session.execution();
        let document = support::ready(Document::read(&source, &session, &work)).unwrap();
        let catalogue = support::ready(document.catalogue(&work)).unwrap();
        assert_eq!(catalogue.len(), 3 + usize::from(later));
        let approval = catalogue.get(2).unwrap();
        let container = support::ready(document.container(approval, &work)).unwrap();
        let (message, parent) = container.read(&work).unwrap();
        let original = structured_cades::source::Document::new(&message, &parent).unwrap();
        let common = structured_cades::prepare::Preparation::read(
            &original,
            &message.signers()[0],
            structured_cades::Level::Basic,
            &parent,
        )
        .unwrap();
        let prepared = support::ready(Preparation::read(
            &document,
            &container,
            &common,
            Level::Basic,
            &parent,
            &work,
        ))
        .unwrap();
        assert!(
            prepared.all_basic_format_requirements_met(),
            "{:?}",
            prepared.findings()
        );
        let oracle = crypto::Oracle::new();
        let signer_certificate = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == leaf)
            .unwrap();
        let signer_anchor = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == root)
            .unwrap();
        let context = ValidationContext {
            execution: &work,
            interval: Interval::between(
                signer_certificate.tbs().validity().not_before().seconds(),
                signer_certificate.tbs().validity().not_after().seconds(),
            ),
            policy: path::Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let PathOutcome::Accepted(signer_path) = pki::check_path(
            &[signer_certificate],
            Anchor::from_certificate(signer_anchor),
            &context,
        )
        .unwrap() else {
            panic!("the later approval requires its own real path")
        };
        let mathematical = support::ready(prepared.verify(
            &document,
            &oracle,
            signer_path.members().last().unwrap().key(),
            &parent,
        ))
        .unwrap();
        assert!(mathematical.input_verified());
        let binding = mathematical
            .bind(signer_certificate, Some(&signer_path), &oracle, &parent)
            .unwrap();
        assert!(binding.binding().is_bound());
        let counters = structured_cades::counters::bind(&common, &parent, |context| {
            context.check(&oracle, signer_certificate, &signer_path)
        })
        .unwrap();
        let basic =
            structured_pades::basic::basic(&binding, counters.paths().unwrap(), &parent).unwrap();
        assert!(basic.all_basic_requirements_met());
        let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        for ordinal in 0..catalogue.len() {
            let signature = catalogue.get(ordinal).unwrap();
            if !signature.is_document_timestamp() {
                continue;
            }
            let timestamp = support::ready(document.container(signature, &work)).unwrap();
            let (token, reader) = timestamp.read_timestamp(&work).unwrap();
            let certificate = token
                .message()
                .certificates()
                .iter()
                .find(|value| value.as_bytes() == tsa)
                .unwrap();
            let anchor = token
                .message()
                .certificates()
                .iter()
                .find(|value| value.as_bytes() == root)
                .unwrap();
            let context = ValidationContext {
                execution: &work,
                interval: Interval::between(
                    certificate.tbs().validity().not_before().seconds(),
                    certificate.tbs().validity().not_after().seconds(),
                ),
                policy: path::Policy::default(),
                bounds: ValidationBounds::default(),
                verifier: &oracle,
                watch: &(),
                recognizer: &(),
            };
            let PathOutcome::Accepted(path) =
                pki::check_path(&[certificate], Anchor::from_certificate(anchor), &context)
                    .unwrap()
            else {
                panic!("actual independent TSA path")
            };
            let context = structured_cms::timestamp::CheckContext {
                certificate,
                certificate_parent: &reader,
                key: path.members().last().unwrap().key(),
                requested: None,
                utc: &utc,
                reference: None,
                window: None,
            };
            let checked = support::ready(document.check_timestamp(
                &timestamp,
                &token,
                &oracle,
                &reader,
                &context,
                |_, _| Ok::<_, core::convert::Infallible>(true),
            ))
            .unwrap();
            assert_eq!(
                checked.into_actor(approval, &work).unwrap().is_some(),
                signature.defined_revision() > approval.defined_revision()
            );
        }
    }
}

fn timestamp_token(imprint: &[u8], root: &[u8], tsa: &[u8], key: &SigningKey) -> Vec<u8> {
    timestamp_token_serial(imprint, root, tsa, key, 9)
}

fn timestamp_token_serial(
    imprint: &[u8],
    root: &[u8],
    tsa: &[u8],
    key: &SigningKey,
    serial: u8,
) -> Vec<u8> {
    let info = crypto::tlv(
        0x30,
        &[
            vec![2, 1, 1],
            crypto::tlv(6, &[42, 3]),
            crypto::tlv(
                0x30,
                &[
                    crypto::tlv(
                        0x30,
                        &crypto::tlv(6, structured_cms::oid::SHA256.as_bytes()),
                    ),
                    crypto::tlv(4, imprint),
                ]
                .concat(),
            ),
            vec![2, 1, serial],
            crypto::tlv(24, b"20260101000100Z"),
            crypto::tlv(0x30, &[]),
        ]
        .concat(),
    );
    let signer = crypto::signer(
        Some(structured_cms::oid::TST_INFO.as_bytes()),
        &info,
        tsa,
        key,
        &[],
        &[],
    );
    crypto::message(
        structured_cms::oid::TST_INFO.as_bytes(),
        Some(&info),
        &[root.to_vec(), tsa.to_vec()],
        &[],
        &[signer],
    )
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "VRI naming, the signature-octet imprint, the actual TSA path and the resulting actor are qualified against one original source lifetime"
)]
fn vri_timestamp_hashes_signature_content_not_the_complete_cms_or_vri_name() {
    // Both tokens have valid TSA mathematics; only the prescribed original
    // encryptedDigest imprint may issue a bound VRI actor. SHA-1 naming also
    // includes all original zero padding, independently of that TS imprint.
    let issuer = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let signer = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let timestamp_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = crypto::certificate("Root", "Root", &issuer, &issuer, false);
    let leaf = crypto::certificate("Signer", "Root", &signer, &issuer, false);
    let tsa = crypto::certificate("TSA", "Root", &timestamp_key, &issuer, true);
    for wrong_input in [false, true] {
        let mut pdf = signed_pdf(&root, &leaf, &signer, false);
        let start = pdf
            .bytes
            .windows(b"/Contents <".len())
            .position(|bytes| bytes == b"/Contents <")
            .unwrap()
            + b"/Contents <".len();
        let contents: Vec<u8> = pdf.bytes[start..start + 8192]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |byte: u8| {
                    if byte <= b'9' {
                        byte - b'0'
                    } else {
                        byte - b'A' + 10
                    }
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect();
        let name = upper_hex(&sha1::Sha1::digest(&contents));
        let parser = structured_asn1::Parser::der(crypto::memory());
        let mut reader = parser.read(&contents, 0).unwrap();
        let length = reader.next_element().unwrap().unwrap().as_bytes().len();
        let mut reader = parser.read(&contents[..length], 0).unwrap();
        let (content, parent) = structured_cms::ContentInfo::read(&mut reader).unwrap();
        let message = structured_cms::SignedData::read_element(&parent, content.content()).unwrap();
        let signature = crypto::signature_octets(message.signers()[0].as_bytes());
        let input = if wrong_input {
            message.as_bytes()
        } else {
            &signature
        };
        let timestamp = timestamp_token(&Sha256::digest(input), &root, &tsa, &timestamp_key);
        let dss = format!("<< /Type /DSS /VRI << /{name} << /TS 8 0 R >> >> >>");
        let mut stream = format!("<< /Length {} >>\nstream\n", timestamp.len()).into_bytes();
        stream.extend_from_slice(&timestamp);
        stream.extend_from_slice(b"\nendstream");
        pdf.append(&[
            (
                1,
                b"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R /DSS 7 0 R >>",
            ),
            (7, dss.as_bytes()),
            (8, &stream),
        ]);
        let source = Slice::new(
            &pdf.bytes,
            Snapshot {
                document: 1u8,
                generation: 0u8,
            },
        );
        let session = Session::new(Limits::default(), crypto::memory());
        let work = session.execution();
        let document = support::ready(Document::read(&source, &session, &work)).unwrap();
        let catalogue = support::ready(document.catalogue(&work)).unwrap();
        let container =
            support::ready(document.container(catalogue.get(0).unwrap(), &work)).unwrap();
        let (message, parent) = container.read(&work).unwrap();
        let validation = support::ready(document.validation(1, &work)).unwrap();
        let parsed = validation.parse(&work).unwrap();
        let oracle = crypto::Oracle::new();
        let naming = structured_cms::provider::ProviderSession::new(crypto::NameHash);
        let binding = parsed
            .bind_signature_vri(&container, &naming, &work)
            .unwrap()
            .unwrap();
        let ordinal = binding.vri().timestamp().unwrap();
        let structured_pades::material::Value::Timestamp(value) = &parsed.values()[ordinal] else {
            panic!("actual TS stream")
        };
        let token = value.token();
        let certificate = token
            .message()
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == tsa)
            .unwrap();
        let anchor = token
            .message()
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == root)
            .unwrap();
        let interval = Interval::between(
            certificate.tbs().validity().not_before().seconds(),
            certificate.tbs().validity().not_after().seconds(),
        );
        let path_context = ValidationContext {
            execution: &work,
            interval,
            policy: path::Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let PathOutcome::Accepted(path) = pki::check_path(
            &[certificate],
            Anchor::from_certificate(anchor),
            &path_context,
        )
        .unwrap() else {
            panic!("actual VRI TSA path")
        };
        let (decoded, certificate_parent) = validation.items()[ordinal].read(&work).unwrap();
        let structured_pades::material::Decoded::Timestamp(_) = decoded else {
            panic!("original TS reader")
        };
        let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let timestamp_request = structured_cms::timestamp::CheckContext {
            certificate,
            certificate_parent: &certificate_parent,
            key: path.members().last().unwrap().key(),
            requested: None,
            utc: &utc,
            reference: None,
            window: None,
        };
        let checked = binding
            .check_timestamp(&message, &parent, &oracle, &timestamp_request, |_, _| {
                Ok::<_, core::convert::Infallible>(true)
            })
            .unwrap()
            .unwrap();
        let actor = checked.into_actor();
        assert_eq!(actor.is_some(), !wrong_input);
        if wrong_input {
            continue;
        }
        let actor = actor.unwrap();
        let root = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == root)
            .unwrap();
        let leaf = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == leaf)
            .unwrap();
        let inner = structured_cades::source::Document::new(&message, &parent).unwrap();
        let common = structured_cades::prepare::Preparation::read(
            &inner,
            &message.signers()[0],
            structured_cades::Level::Basic,
            &parent,
        )
        .unwrap();
        let prepared = support::ready(Preparation::read(
            &document,
            &container,
            &common,
            Level::Basic,
            &parent,
            &work,
        ))
        .unwrap();
        let path_options = ValidationContext {
            execution: &work,
            interval,
            policy: path::Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let PathOutcome::Accepted(signer_path) =
            pki::check_path(&[leaf], Anchor::from_certificate(root), &path_options).unwrap()
        else {
            panic!("actual original VRI root path")
        };
        let mathematical = support::ready(prepared.verify(
            &document,
            &oracle,
            signer_path.members().last().unwrap().key(),
            &parent,
        ))
        .unwrap();
        let root_binding = mathematical
            .bind(leaf, Some(&signer_path), &oracle, &parent)
            .unwrap();
        let counters = structured_cades::counters::bind(&common, &parent, |context| {
            context.check(&oracle, leaf, &signer_path)
        })
        .unwrap();
        let basic =
            structured_pades::basic::basic(&root_binding, counters.paths().unwrap(), &parent)
                .unwrap();
        let history =
            support::ready(document.validation_history(container.signature(), &work)).unwrap();
        let required = document
            .timestamp_requirements(&basic, &history, &work)
            .unwrap();
        assert!(required.document_timestamps().is_empty());
        assert_eq!(required.vri_timestamps().len(), 1);
        assert_eq!(required.vri_timestamps()[0].revision, 1);
        let pki::TimestampBinding::Bound(receipt) =
            path.bind_timestamp(&actor, &utc, &work).unwrap()
        else {
            panic!("VRI TS must retain its actual TSA identity and generation interval")
        };
        let query = document.query(&work);
        let receipts = [&receipt];
        assert!(matches!(
            required.all().bind_paths(&receipts, &query).unwrap(),
            structured_ltv::timestamp::TimestampPathBinding::Bound(_)
        ));
    }
}

#[test]
fn actual_document_timestamp_binds_original_revision_and_root() {
    // A real TSA signature authenticates the exact incremental ByteRange.
    // Only the checked original input can produce a covering actor receipt.
    let issuer = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let signer = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let timestamp_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = crypto::certificate("Root", "Root", &issuer, &issuer, false);
    let leaf = crypto::certificate("Signer", "Root", &signer, &issuer, false);
    let tsa = crypto::certificate("TSA", "Root", &timestamp_key, &issuer, true);
    let mut pdf = signed_pdf(&root, &leaf, &signer, false);
    append_timestamp(&mut pdf, &root, &tsa, &timestamp_key, None);
    let source = Slice::new(
        &pdf.bytes,
        Snapshot {
            document: 1u8,
            generation: 0u8,
        },
    );
    let session = Session::new(Limits::default(), crypto::memory());
    let work = session.execution();
    let document = support::ready(Document::read(&source, &session, &work)).unwrap();
    let catalogue = support::ready(document.catalogue(&work)).unwrap();
    let original = catalogue.get(0).unwrap();
    let timestamp = catalogue.get(1).unwrap();
    let container = support::ready(document.container(timestamp, &work)).unwrap();
    let (token, parent) = container.read_timestamp(&work).unwrap();
    let certificate = token
        .message()
        .certificates()
        .iter()
        .find(|value| value.as_bytes() == tsa)
        .unwrap();
    let anchor = token
        .message()
        .certificates()
        .iter()
        .find(|value| value.as_bytes() == root)
        .unwrap();
    let oracle = crypto::Oracle::new();
    let interval = Interval::at(certificate.tbs().validity().not_before().seconds());
    let path_context = ValidationContext {
        execution: &work,
        interval,
        policy: path::Policy::default(),
        bounds: ValidationBounds::default(),
        verifier: &oracle,
        watch: &(),
        recognizer: &(),
    };
    let PathOutcome::Accepted(path) = pki::check_path(
        &[certificate],
        Anchor::from_certificate(anchor),
        &path_context,
    )
    .unwrap() else {
        panic!("actual TSA path must validate")
    };
    let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
    let context = structured_cms::timestamp::CheckContext {
        certificate,
        certificate_parent: &parent,
        key: path.members().last().unwrap().key(),
        requested: None,
        utc: &utc,
        reference: None,
        window: None,
    };
    let checked = support::ready(document.check_timestamp(
        &container,
        &token,
        &oracle,
        &parent,
        &context,
        |_, _| Ok::<_, core::convert::Infallible>(true),
    ))
    .unwrap();
    assert!(checked.into_actor(original, &work).unwrap().is_some());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "current and historical indexes share the same original preparation and live timestamp path receipts through both negative assessments"
)]
fn actual_pdf_range_and_signer_binding_do_not_require_forbidden_cms_signing_time() {
    // A correct PAdES root forbids CMS signing-time even though CAdES B-B
    // requires it. The PDF M field supplies the claimed UTC time instead.
    for missing_generation_method in [false, true] {
        let issuer = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
        let signer = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
        let root = crypto::certificate("Root", "Root", &issuer, &issuer, false);
        let leaf = crypto::certificate("Signer", "Root", &signer, &issuer, false);
        let mut pdf = signed_pdf(&root, &leaf, &signer, false);
        let start = pdf
            .bytes
            .windows(b"/Contents <".len())
            .position(|bytes| bytes == b"/Contents <")
            .unwrap()
            + b"/Contents <".len();
        let contents: Vec<u8> = pdf.bytes[start..start + 8192]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |byte: u8| {
                    if byte <= b'9' {
                        byte - b'0'
                    } else {
                        byte - b'A' + 10
                    }
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect();
        let name = upper_hex(&sha1::Sha1::digest(&contents));
        let tsa_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
        let tsa = crypto::certificate("TSA", "Root", &tsa_key, &issuer, true);
        append_timestamp(&mut pdf, &root, &tsa, &tsa_key, None);
        let dss = if missing_generation_method {
            format!("<< /Type /DSS /VRI << /{name} << >> >> >>")
        } else {
            "<< /Type /DSS >>".to_owned()
        };
        pdf.append(&[
            (
                1,
                b"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R /DSS 9 0 R >>",
            ),
            (9, dss.as_bytes()),
        ]);
        let source = Slice::new(
            &pdf.bytes,
            Snapshot {
                document: 1u8,
                generation: 0u8,
            },
        );
        let memory = crypto::memory();
        let session = Session::new(Limits::default(), memory);
        let work = session.execution();
        let document = support::ready(Document::read(&source, &session, &work)).unwrap();
        let catalogue = support::ready(document.catalogue(&work)).unwrap();
        let signature = catalogue.get(0).unwrap();
        let container = support::ready(document.container(signature, &work)).unwrap();
        let (message, parent) = container.read(&work).unwrap();
        let cms_document = structured_cades::source::Document::new(&message, &parent).unwrap();
        let common = structured_cades::prepare::Preparation::read(
            &cms_document,
            &message.signers()[0],
            structured_cades::Level::Basic,
            &parent,
        )
        .unwrap();
        let prepared = support::ready(Preparation::read(
            &document,
            &container,
            &common,
            Level::Basic,
            &parent,
            &work,
        ))
        .unwrap();
        assert!(
            prepared.all_basic_format_requirements_met(),
            "{:?}",
            prepared.findings()
        );
        let root = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == root)
            .unwrap();
        let leaf = message
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == leaf)
            .unwrap();
        let oracle = crypto::Oracle::new();
        let context = ValidationContext {
            execution: &work,
            interval: Interval::between(
                leaf.tbs().validity().not_before().seconds(),
                leaf.tbs().validity().not_after().seconds(),
            ),
            policy: path::Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let PathOutcome::Accepted(path) =
            pki::check_path(&[leaf], Anchor::from_certificate(root), &context).unwrap()
        else {
            panic!("native original certificate path must validate")
        };
        let mathematical = support::ready(prepared.verify(
            &document,
            &oracle,
            path.members().last().unwrap().key(),
            &parent,
        ))
        .unwrap();
        assert!(mathematical.input_verified());
        let binding = mathematical
            .bind(leaf, Some(&path), &oracle, &parent)
            .unwrap();
        assert!(binding.binding().is_bound());
        let counters = structured_cades::counters::bind(&common, &parent, |context| {
            context.check(&oracle, leaf, &path)
        })
        .unwrap();
        let basic =
            structured_pades::basic::basic(&binding, counters.paths().unwrap(), &parent).unwrap();
        assert!(basic.all_basic_requirements_met());
        let material = support::ready(document.validation_history(signature, &work)).unwrap();
        assert!(!material.revisions()[0].is_present());
        assert!(!material.revisions()[1].is_present());
        assert!(material.revisions()[2].is_present());
        assert!(material.revisions()[2].all_vri_material_in_dss());
        // A later DSS cannot repair the original DTS's historical LT window.
        let required = document
            .timestamp_requirements(&basic, &material, &work)
            .unwrap();
        let historical = required.at_source_revision(0, &work).unwrap();
        assert_eq!(historical.revision(), Some(1));
        assert_eq!(historical.document_timestamps().len(), 1);
        assert!(required.at_source_revision(1, &work).is_err());
        assert!(historical.at_source_revision(0, &work).is_err());
        let parsed = material.parse(&work).unwrap();
        let pool = structured_cades::material::Pool::read(&common, &parent).unwrap();
        let query = document.query(&work);
        let sources = support::ready(document.timestamp_sources(&required, &work)).unwrap();
        let models = sources.parse(&work).unwrap();
        let naming = structured_cms::provider::ProviderSession::new(crypto::NameHash);
        let current =
            support::ready(parsed.index(&basic, &pool, &models, &naming, &query)).unwrap();
        assert_eq!(current.revision(), 2);
        // An earlier valid DTS cannot provide generation time for a later VRI.
        // TU/TS absence stays readable but cannot become completed source facts.
        assert_eq!(
            current.all_source_requirements_met(),
            !missing_generation_method
        );
        let timestamp_token = models.token(0, &work).unwrap().unwrap();
        let timestamp_parent = models.reader(0, &work).unwrap().unwrap();
        let certificate = timestamp_token
            .message()
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == tsa)
            .unwrap();
        let anchor = timestamp_token
            .message()
            .certificates()
            .iter()
            .find(|value| value.as_bytes() == root.as_bytes())
            .unwrap();
        let timestamp_context = ValidationContext {
            execution: &work,
            interval: Interval::between(
                certificate.tbs().validity().not_before().seconds(),
                certificate.tbs().validity().not_after().seconds(),
            ),
            policy: path::Policy::default(),
            bounds: ValidationBounds::default(),
            verifier: &oracle,
            watch: &(),
            recognizer: &(),
        };
        let PathOutcome::Accepted(timestamp_path) = pki::check_path(
            &[certificate],
            Anchor::from_certificate(anchor),
            &timestamp_context,
        )
        .unwrap() else {
            panic!("actual whole-generation TSA path")
        };
        let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
        let context = structured_cms::timestamp::CheckContext {
            certificate,
            certificate_parent: &timestamp_parent,
            key: timestamp_path.members().last().unwrap().key(),
            requested: None,
            utc: &utc,
            reference: None,
            window: None,
        };
        let structured_pades::timestamp::sources::Slot::Value(timestamp_container) =
            sources.get(0, &work).unwrap().unwrap()
        else {
            panic!("actual original DTS source")
        };
        let checked = support::ready(document.check_timestamp(
            timestamp_container,
            timestamp_token,
            &oracle,
            &timestamp_parent,
            &context,
            |_, _| Ok::<_, core::convert::Infallible>(true),
        ))
        .unwrap();
        let actor = checked.into_actor(signature, &work).unwrap().unwrap();
        let pki::TimestampBinding::Bound(tsa_receipt) =
            timestamp_path.bind_timestamp(&actor, &utc, &work).unwrap()
        else {
            panic!("actual TSA signer/key and complete generation interval")
        };
        let paths = [&tsa_receipt];
        let structured_ltv::timestamp::TimestampPathBinding::Bound(paths) =
            required.all().bind_paths(&paths, &query).unwrap()
        else {
            panic!("all original timestamp obligations must bind")
        };
        let timed =
            structured_pades::baseline::timestamped(&basic, &required, &paths, &query).unwrap();
        assert!(timed.all_static_time_requirements_met());
        let sources = support::ready(document.timestamp_sources(&historical, &work)).unwrap();
        let models = sources.parse(&work).unwrap();
        let original =
            support::ready(parsed.index(&basic, &pool, &models, &naming, &query)).unwrap();
        assert_eq!(original.revision(), 1);
        assert!(!original.all_source_requirements_met());
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "all source, credential and archive combinations retain live PKI and CRL receipts through the complete LT and LTA composition"
)]
fn full_lt_and_lta_link_actual_tsa_status_material_and_original_revision() {
    // Real PDF/CMS/TSA signatures and an authenticated complete CRL establish
    // every actor/material input. Unassessed protection stays negative even
    // when the same signature has a successful complete LT report.
    let issuer = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let signer = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let timestamp_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root_bytes = crypto::certificate("Root", "Root", &issuer, &issuer, false);
    let leaf_bytes = crypto::certificate("Signer", "Root", &signer, &issuer, false);
    let tsa_bytes = crypto::certificate("TSA", "Root", &timestamp_key, &issuer, true);
    for counter in [false, true] {
        for assertion in [
            credentials::Case::Absent,
            credentials::Case::Valid,
            credentials::Case::Invalid,
        ] {
            for mode in 0..3 {
                let bad_last = mode == 1;
                let mut pdf =
                    signed_pdf_options(&root_bytes, &leaf_bytes, &signer, counter, None, assertion);
                let crl = crl_fixture::crl(&issuer);
                let crl_parser = structured_asn1::Parser::der(crypto::memory());
                let original_crl =
                    structured_pkix::crl::CertificateList::read(&crl_parser, &crl, 0).unwrap();
                let named_signature =
                    crypto::tlv(4, original_crl.signature_value().octets().unwrap());
                let vri_name = upper_hex(&sha1::Sha1::digest(&named_signature));
                let dss = format!(
                    "<< /Type /DSS /CRLs [10 0 R] /VRI << /{vri_name} << /CRL [10 0 R] /TU (D:20260101000000Z) >> >> >>"
                );
                let mut stream = format!("<< /Length {} >>\nstream\n", crl.len()).into_bytes();
                stream.extend_from_slice(&crl);
                stream.extend_from_slice(b"\nendstream");
                pdf.append(&[
                    (
                        1,
                        b"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R /DSS 9 0 R >>",
                    ),
                    (9, dss.as_bytes()),
                    (10, &stream),
                ]);
                append_timestamp(&mut pdf, &root_bytes, &tsa_bytes, &timestamp_key, Some(9));
                if mode != 0 {
                    append_timestamp(&mut pdf, &root_bytes, &tsa_bytes, &timestamp_key, Some(9));
                }
                if bad_last {
                    let start = pdf
                        .bytes
                        .windows(b"/Contents <".len())
                        .rposition(|bytes| bytes == b"/Contents <")
                        .unwrap()
                        + b"/Contents <".len();
                    pdf.bytes[start] = b'0';
                }
                let source = Slice::new(
                    &pdf.bytes,
                    Snapshot {
                        document: 1u8,
                        generation: 0u8,
                    },
                );
                let session = Session::new(Limits::default(), crypto::memory());
                let work = session.execution();
                let document = support::ready(Document::read(&source, &session, &work)).unwrap();
                let catalogue = support::ready(document.catalogue(&work)).unwrap();
                let signature = catalogue.get(0).unwrap();
                let container = support::ready(document.container(signature, &work)).unwrap();
                let (message, parent) = container.read(&work).unwrap();
                let inner = structured_cades::source::Document::new(&message, &parent).unwrap();
                let common = structured_cades::prepare::Preparation::read(
                    &inner,
                    &message.signers()[0],
                    structured_cades::Level::Basic,
                    &parent,
                )
                .unwrap();
                let prepared = support::ready(Preparation::read(
                    &document,
                    &container,
                    &common,
                    Level::Archival,
                    &parent,
                    &work,
                ))
                .unwrap();
                let root = message
                    .certificates()
                    .iter()
                    .find(|value| value.as_bytes() == root_bytes)
                    .unwrap();
                let leaf = message
                    .certificates()
                    .iter()
                    .find(|value| value.as_bytes() == leaf_bytes)
                    .unwrap();
                let oracle = crypto::Oracle::new();
                let interval = Interval::between(
                    leaf.tbs().validity().not_before().seconds(),
                    leaf.tbs().validity().not_after().seconds(),
                );
                let context = ValidationContext {
                    execution: &work,
                    interval,
                    policy: path::Policy::default(),
                    bounds: ValidationBounds::default(),
                    verifier: &oracle,
                    watch: &(),
                    recognizer: &(),
                };
                let PathOutcome::Accepted(path) =
                    pki::check_path(&[leaf], Anchor::from_certificate(root), &context).unwrap()
                else {
                    panic!("actual original root path")
                };
                let mathematical = support::ready(prepared.verify(
                    &document,
                    &oracle,
                    path.members().last().unwrap().key(),
                    &parent,
                ))
                .unwrap();
                let bound = mathematical
                    .bind(leaf, Some(&path), &oracle, &parent)
                    .unwrap();
                let counters = structured_cades::counters::bind(&common, &parent, |context| {
                    context.check(&oracle, leaf, &path)
                })
                .unwrap();
                let basic =
                    structured_pades::basic::basic(&bound, counters.paths().unwrap(), &parent)
                        .unwrap();
                // EN319142-1 §6.3 excludes CAdES attributes absent from Table1,
                // including countersignature. Its genuine math/path still remains available.
                assert!(bound.binding().is_bound());
                assert_eq!(
                    basic.all_basic_requirements_met(),
                    !counter,
                    "counter={counter}, mode={mode}, findings={:?}",
                    prepared.findings()
                );
                assert_eq!(
                    pki::CounterReceipts::len(basic.counters()),
                    usize::from(counter)
                );
                let history =
                    support::ready(document.validation_history(signature, &work)).unwrap();
                let required = document
                    .timestamp_requirements(&basic, &history, &work)
                    .unwrap();
                let query = document.query(&work);
                if bad_last {
                    // A broken later envelope remains a required original occurrence.
                    // Current assessment never substitutes the earlier valid DTS.
                    assert_eq!(required.document_timestamps().len(), 2);
                    let sources =
                        support::ready(document.timestamp_sources(&required, &work)).unwrap();
                    assert!(matches!(
                        sources.get(1, &work).unwrap().unwrap(),
                        structured_pades::timestamp::sources::Slot::Unreadable(_)
                    ));
                    let reports: [Option<&Unassessed<'_>>; 2] = [None, None];
                    let seals =
                        structured_pades::baseline::seals(&required, &reports, &query).unwrap();
                    let current = structured_pades::baseline::assess(
                        structured_pades::baseline::Selection::Current,
                        None,
                        &seals,
                        &query,
                    )
                    .unwrap();
                    assert_eq!(current.ordinal(), Some(1));
                    assert_eq!(current.revision(), Some(3));
                    assert!(!current.all_profile_requirements_met());
                    let earlier = structured_pades::baseline::assess(
                        structured_pades::baseline::Selection::AtSource(0),
                        None,
                        &seals,
                        &query,
                    )
                    .unwrap();
                    assert_eq!(earlier.ordinal(), Some(0));
                    assert_eq!(earlier.revision(), Some(2));
                    assert_eq!(seals.len(), 2);
                    continue;
                }
                let parsed = history.parse(&work).unwrap();
                let naming = structured_cms::provider::ProviderSession::new(crypto::NameHash);
                let status_vri = parsed.revisions()[1]
                    .bind_status_vri(0, &naming, &work)
                    .unwrap()
                    .unwrap();
                assert_eq!(status_vri.vri().name().as_slice(), vri_name.as_bytes());
                assert_eq!(status_vri.item(), 0);
                assert_eq!(
                    status_vri.signature().as_bytes(),
                    original_crl.signature_value().as_bytes()
                );
                let sources = support::ready(document.timestamp_sources(&required, &work)).unwrap();
                let models = sources.parse(&work).unwrap();
                let pool = structured_cades::material::Pool::read(&common, &parent).unwrap();
                let query = document.query(&work);
                let material =
                    support::ready(parsed.index(&basic, &pool, &models, &naming, &query)).unwrap();
                let token = models.token(0, &work).unwrap().unwrap();
                let token_parent = models.reader(0, &work).unwrap().unwrap();
                let tsa = token
                    .message()
                    .certificates()
                    .iter()
                    .find(|value| value.as_bytes() == tsa_bytes)
                    .unwrap();
                let context = ValidationContext {
                    execution: &work,
                    interval,
                    policy: path::Policy::default(),
                    bounds: ValidationBounds::default(),
                    verifier: &oracle,
                    watch: &(),
                    recognizer: &(),
                };
                let PathOutcome::Accepted(tsa_path) =
                    pki::check_path(&[tsa], Anchor::from_certificate(root), &context).unwrap()
                else {
                    panic!("actual original TSA path")
                };
                let utc = structured_pkix::temporal::LeapTable::new(0, 2_000_000_000, &[]).unwrap();
                let context = structured_cms::timestamp::CheckContext {
                    certificate: tsa,
                    certificate_parent: &token_parent,
                    key: tsa_path.members().last().unwrap().key(),
                    requested: None,
                    utc: &utc,
                    reference: None,
                    window: None,
                };
                let timestamp_parents: Vec<_> = (0..required.document_timestamps().len())
                    .map(|ordinal| models.reader(ordinal, &work).unwrap().unwrap())
                    .collect();
                let mut actors = Vec::new();
                for (ordinal, reader) in timestamp_parents.iter().enumerate() {
                    let structured_pades::timestamp::sources::Slot::Value(timestamp_container) =
                        sources.get(ordinal, &work).unwrap().unwrap()
                    else {
                        panic!("actual original DTS source")
                    };
                    let token = models.token(ordinal, &work).unwrap().unwrap();
                    let checked = support::ready(document.check_timestamp(
                        timestamp_container,
                        token,
                        &oracle,
                        reader,
                        &context,
                        |_, _| Ok::<_, core::convert::Infallible>(true),
                    ))
                    .unwrap();
                    actors.push(checked.into_actor(signature, &work).unwrap().unwrap());
                }
                let receipts: Vec<_> = actors
                    .iter()
                    .map(|actor| {
                        let pki::TimestampBinding::Bound(receipt) =
                            tsa_path.bind_timestamp(actor, &utc, &work).unwrap()
                        else {
                            panic!("actual static TSA signer/key/interval")
                        };
                        receipt
                    })
                    .collect();
                let tsa_paths: Vec<_> = receipts.iter().collect();
                let structured_ltv::timestamp::TimestampPathBinding::Bound(paths) =
                    required.all().bind_paths(&tsa_paths, &query).unwrap()
                else {
                    panic!("complete original TSA census")
                };
                let timed =
                    structured_pades::baseline::timestamped(&basic, &required, &paths, &query)
                        .unwrap();
                assert_eq!(timed.all_static_time_requirements_met(), !counter);
                if counter {
                    assert!(
                        matches!(basic.authenticate_credentials(&credentials::Empty, &query),
            Err(structured_pades::credential::Error::Nonconforming { location }) if location == signature.location())
                    );
                    continue;
                }
                let owner = credentials::Owner {
                    certificate: leaf,
                    key: *signer.verifying_key(),
                    authentications: core::cell::Cell::new(0),
                    visits: core::cell::Cell::new(0),
                };
                let authenticated = basic.authenticate_credentials(&owner, &query).unwrap();
                let expected = if assertion == credentials::Case::Absent {
                    0
                } else {
                    2
                };
                assert_eq!(authenticated.common().root().len(), expected);
                assert_eq!(owner.authentications.get(), expected);
                if assertion == credentials::Case::Invalid {
                    assert!(authenticated.complete(&work).unwrap().is_none());
                    assert!(matches!(
                        authenticated.common().root()[1].outcome(),
                        structured_cades::credential::Outcome::Authentication(
                            structured_ltv::credential::Authentication::Rejected
                        )
                    ));
                    continue;
                }
                let credentials = authenticated.complete(&work).unwrap().unwrap();
                let participants = basic.participants(&credentials, &paths, &query).unwrap();
                assert_eq!(
                    participants.entries().len(),
                    1 + usize::from(counter) + actors.len() + expected
                );
                let crl = parsed.revisions()[1]
                    .values()
                    .iter()
                    .find_map(|value| match value {
                        structured_pades::material::Value::Crl(value) => Some(value),
                        _ => None,
                    })
                    .unwrap();
                let structured_pkix::crl::Authentication::Authenticated(crl) = crl
                    .authenticate(
                        root,
                        structured_pkix::path::WorkingKey::standing(root.tbs().public_key()),
                        &oracle,
                        &work,
                    )
                    .unwrap()
                else {
                    panic!("actual complete CRL authentication")
                };
                let at = crl.crl().tbs().this_update().instant().into();
                let evaluation = structured_pkix::crl::Evaluation {
                    now: at,
                    utc: &utc,
                    execution: &work,
                    origin: structured_pkix::crl::SourceOrigin::Cached,
                };
                let structured_pkix::crl::CompleteEvidence::Facts(signer_status) =
                    crl.evaluate(leaf, &evaluation).unwrap()
                else {
                    panic!("actual signer CRL target")
                };
                let structured_pkix::crl::CompleteEvidence::Facts(tsa_status) =
                    crl.evaluate(tsa, &evaluation).unwrap()
                else {
                    panic!("actual TSA CRL target")
                };
                let authorities = pki::CrlAuthorities::Complete(pki::CrlAuthority::Anchor);
                let pki::CrlReadingBinding::Bound(signer_status) = path
                    .bind_crl_reading(
                        0,
                        pki::CrlReading::Complete(&signer_status),
                        authorities,
                        &utc,
                        &work,
                    )
                    .unwrap()
                else {
                    panic!("actual signer status authority")
                };
                let pki::CrlReadingBinding::Bound(tsa_status) = tsa_path
                    .bind_crl_reading(
                        0,
                        pki::CrlReading::Complete(&tsa_status),
                        authorities,
                        &utc,
                        &work,
                    )
                    .unwrap()
                else {
                    panic!("actual TSA status authority")
                };
                let signer_entries = [pki::MemberStatus::CrlReading(&signer_status)];
                let tsa_entries = [pki::MemberStatus::CrlReading(&tsa_status)];
                let signer_statuses = path.status_census(at, &signer_entries, &work).unwrap();
                let tsa_statuses = tsa_path.status_census(at, &tsa_entries, &work).unwrap();
                let supplied = [
                    pki::AuthorityNode {
                        statuses: &signer_statuses,
                        responders: &[],
                    },
                    pki::AuthorityNode {
                        statuses: &tsa_statuses,
                        responders: &[],
                    },
                ];
                let mut roots = vec![&signer_statuses; 1 + usize::from(counter)];
                roots.extend((0..actors.len()).map(|_| &tsa_statuses));
                let inputs = participants
                    .close_statuses(&roots, &supplied, &query)
                    .unwrap();
                let x509 = material
                    .check_participants(&inputs, &paths, &query)
                    .unwrap();
                assert!(x509.all_x509_requirements_met());
                let credential_material = structured_pades::material::credentials::check(
                    &basic,
                    &credentials,
                    required.all(),
                    &material,
                    &structured_pades::material::credentials::Scope::whole(),
                    &owner,
                    &query,
                )
                .unwrap();
                let long_term = structured_pades::baseline::long_term(
                    &timed,
                    &x509,
                    &credential_material,
                    &query,
                )
                .unwrap();
                assert!(long_term.all_material_requirements_met());
                let archive = actors.len() - 1;
                let actor = &actors[archive];
                let prior = required.before_archive(archive, actor, &work).unwrap();
                let structured_ltv::timestamp::TimestampPathBinding::Bound(prior_paths) =
                    prior.bind_paths(&tsa_paths[..archive], &query).unwrap()
                else {
                    panic!("the archive's own TSA is not preceding material")
                };
                let prior_participants = basic
                    .participants(&credentials, &prior_paths, &query)
                    .unwrap();
                let mut prior_roots = vec![&signer_statuses; 1 + usize::from(counter)];
                prior_roots.extend((0..archive).map(|_| &tsa_statuses));
                let prior_inputs = prior_participants
                    .close_statuses(&prior_roots, &supplied, &query)
                    .unwrap();
                let coverage = required
                    .material_coverage(archive, actor, &material, &query)
                    .unwrap();
                let prior_x509 = material
                    .archived_participants(&prior_inputs, &coverage, actor, &query)
                    .unwrap();
                let prior_credentials = structured_pades::material::credentials::check(
                    &basic,
                    &credentials,
                    &prior,
                    &material,
                    &structured_pades::material::credentials::Scope::Before {
                        coverage: &coverage,
                        actor,
                    },
                    &owner,
                    &query,
                )
                .unwrap();
                let seal = structured_pades::baseline::archive_material(
                    &prior_x509,
                    &prior_credentials,
                    &query,
                )
                .unwrap();
                assert!(seal.all_material_covered());
                let mut reports = vec![None; actors.len()];
                reports[archive] = Some(&seal);
                let seals = structured_pades::baseline::seals(&required, &reports, &query).unwrap();
                let profile = structured_pades::baseline::assess(
                    structured_pades::baseline::Selection::Current,
                    Some(&long_term),
                    &seals,
                    &query,
                )
                .unwrap();
                assert_eq!(profile.ordinal(), Some(archive));
                assert_eq!(profile.revision(), Some(2 + archive));
                assert_eq!(profile.all_profile_requirements_met(), !counter);
                let reports = vec![None; actors.len()];
                let seals = structured_pades::baseline::seals(&required, &reports, &query).unwrap();
                let missing = structured_pades::baseline::assess(
                    structured_pades::baseline::Selection::Current,
                    Some(&long_term),
                    &seals,
                    &query,
                )
                .unwrap();
                assert_eq!(missing.all_long_term_requirements_met(), !counter);
                assert_eq!(missing.material_covered(), None);
                assert!(!missing.all_profile_requirements_met());
                assert_eq!(owner.authentications.get(), expected);
                assert_eq!(owner.visits.get(), expected * 2);
            }
        }
    }
}
