//! Independent native test oracles, never a library/runtime backend.

use super::{append_timestamp, crypto, signed_pdf, support};
use p256::ecdsa::SigningKey;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use structured_ltv::source::Snapshot;
use structured_pades::{Limits, Session, document::Document, range::Slice};

fn directory() -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(root).unwrap();
    for ordinal in 0u64.. {
        let directory = root.join(format!("pades-oracle-{}-{ordinal}", std::process::id()));
        match fs::create_dir(&directory) {
            Ok(()) => return directory,
            Err(cause) if cause.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(cause) => panic!("cannot create oracle output: {cause}"),
        }
    }
    unreachable!("the test cannot exhaust u64 directory ordinals")
}

fn succeeds(command: &mut Command) {
    let output = command.output().expect("required independent test oracle");
    assert!(
        output.status.success(),
        "{command:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn verification_command(
    ordinal: usize,
    cms: &Path,
    data: &Path,
    verified: &Path,
    root_pem: &Path,
) -> Command {
    let mut command = Command::new("openssl");
    if ordinal == 0 {
        command
            .args([
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-binary",
                "-noverify",
                "-in",
            ])
            .arg(cms)
            .arg("-content")
            .arg(data)
            .arg("-out")
            .arg(verified);
    } else {
        command
            .args(["ts", "-verify", "-token_in", "-in"])
            .arg(cms)
            .arg("-data")
            .arg(data)
            .arg("-CAfile")
            .arg(root_pem);
    }
    command
}

#[test]
fn qpdf_and_openssl_verify_original_incremental_pdf_cms_and_timestamp_inputs() {
    // qpdf checks independent PDF/xref interpretation. OpenSSL checks real
    // ECDSA CMS mathematics and RFC3161 imprints; neither supplies runtime code.
    let issuer = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let signer = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let timestamp_key = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let root = crypto::certificate("Root", "Root", &issuer, &issuer, false);
    let leaf = crypto::certificate("Signer", "Root", &signer, &issuer, false);
    let tsa = crypto::certificate("TSA", "Root", &timestamp_key, &issuer, true);
    let mut pdf = signed_pdf(&root, &leaf, &signer, false);
    pdf.append(&[
        (
            1,
            b"<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R /DSS 9 0 R >>",
        ),
        (9, b"<< /Type /DSS >>"),
    ]);
    append_timestamp(&mut pdf, &root, &tsa, &timestamp_key, Some(9));
    append_timestamp(&mut pdf, &root, &tsa, &timestamp_key, Some(9));
    let directory = directory();
    eprintln!("independent oracle outputs: {}", directory.display());
    let file = directory.join("signed.pdf");
    fs::write(&file, &pdf.bytes).unwrap();
    succeeds(Command::new("qpdf").arg("--check").arg(&file));
    let root_der = directory.join("root.der");
    let root_pem = directory.join("root.pem");
    fs::write(&root_der, root).unwrap();
    succeeds(
        Command::new("openssl")
            .args(["x509", "-inform", "DER", "-in"])
            .arg(&root_der)
            .arg("-out")
            .arg(&root_pem),
    );
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
    assert_eq!(catalogue.len(), 3);
    assert!(catalogue.failures().is_empty());
    for ordinal in 0..catalogue.len() {
        let signature = catalogue.get(ordinal).unwrap();
        let container = support::ready(document.container(signature, &work)).unwrap();
        let cms = directory.join(format!("signature-{ordinal}.der"));
        let data = directory.join(format!("input-{ordinal}.bin"));
        let verified = directory.join(format!("verified-{ordinal}.bin"));
        fs::write(&cms, container.der()).unwrap();
        let mut input = Vec::new();
        for span in signature.ranges() {
            let start = usize::try_from(span.start).unwrap();
            let length = usize::try_from(span.length).unwrap();
            input.extend_from_slice(&pdf.bytes[start..start + length]);
        }
        fs::write(&data, &input).unwrap();
        succeeds(&mut verification_command(
            ordinal, &cms, &data, &verified, &root_pem,
        ));
        if ordinal == 0 {
            assert_eq!(fs::read(&verified).unwrap(), input);
        }
        input[0] ^= 1;
        fs::write(&data, input).unwrap();
        let mut command = verification_command(ordinal, &cms, &data, &verified, &root_pem);
        let output = command.output().unwrap();
        assert!(
            !output.status.success(),
            "modified original input must fail: {command:?}"
        );
    }
    // The normal project cleanup command owns these outputs, including failed
    // fixtures retained for diagnosis: they all live under Cargo's target dir.
}
